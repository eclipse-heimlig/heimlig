use crate::client;
use crate::common::jobs;
use crate::common::jobs::{ClientId, Request, RequestType, Response};
use crate::hsm::keystore::KeyStore;
use core::cell::RefCell;
use core::future::{pending, poll_fn, ready};
use core::ops::{Deref, DerefMut};
use core::pin::{pin, Pin};
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering::SeqCst;
use core::task::Poll;
use embassy_futures::select::select_array;
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::mutex::Mutex;
use futures::future::{join, select, Either};
use futures::{FutureExt, Sink, SinkExt, Stream, StreamExt};
use heapless::Vec;

use super::util::join_vec;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Error {
    /// Queue specific error
    Send,
    /// Job specific error
    Job(jobs::Error),
}

/// HSM core that waits for [Request]s from clients and send [Response]s once they are ready.   
pub struct Core<
    'data,
    'keystore,
    M: RawMutex, // TODO: Get rid of embassy specific mutex outside of integration code
    ReqSrc: Stream<Item = Request<'data>>,
    RespSink: Sink<Response<'data>>,
    ReqSink: Sink<Request<'data>>,
    RespSrc: Stream<Item = Response<'data>>,
    const MAX_REQUEST_TYPES: usize = 8,
    const MAX_CLIENTS: usize = 8,
    const MAX_WORKERS: usize = 8,
> {
    key_store: Option<&'keystore Mutex<M, &'keystore mut (dyn KeyStore + Send)>>,
    clients: Vec<Mutex<M, RefCell<ClientChannel<'data, ReqSrc, RespSink>>>, MAX_CLIENTS>,
    workers: Vec<WorkerChannel<'data, ReqSink, RespSrc, M, MAX_REQUEST_TYPES>, MAX_WORKERS>,
    last_client_id: AtomicUsize,
    last_worker_id: AtomicUsize,
}

struct ClientChannel<'data, ReqSrc: Stream<Item = Request<'data>>, RespSink: Sink<Response<'data>>>
{
    requests: futures::stream::Peekable<ReqSrc>,
    responses: RespSink,
}

/// Associate request types with request sink and response source of the responsible worker
struct WorkerChannel<
    'data,
    ReqSink: Sink<Request<'data>>,
    RespSrc: Stream<Item = Response<'data>>,
    M: RawMutex,
    const MAX_REQUEST_TYPES_PER_WORKER: usize,
> {
    pub req_types: Vec<RequestType, MAX_REQUEST_TYPES_PER_WORKER>,
    pub requests: Mutex<M, RefCell<ReqSink>>,
    pub responses: Mutex<M, RefCell<futures::stream::Peekable<RespSrc>>>,
}

pub struct Builder<
    'data,
    'keystore,
    M: RawMutex, // TODO: Get rid of embassy specific mutex outside of integration code
    ReqSrc: Stream<Item = Request<'data>>,
    RespSink: Sink<Response<'data>>,
    ReqSink: Sink<Request<'data>>,
    RespSrc: Stream<Item = Response<'data>>,
    const MAX_REQUEST_TYPES: usize = 8,
    const MAX_CLIENTS: usize = 8,
    const MAX_WORKERS: usize = 8,
> {
    key_store: Option<&'keystore Mutex<M, &'keystore mut (dyn KeyStore + Send)>>,
    clients: Vec<Mutex<M, RefCell<ClientChannel<'data, ReqSrc, RespSink>>>, MAX_CLIENTS>,
    workers: Vec<WorkerChannel<'data, ReqSink, RespSrc, M, MAX_REQUEST_TYPES>, MAX_WORKERS>,
}

impl<
        'data,
        'keystore,
        M: RawMutex,
        ReqSrc: Stream<Item = Request<'data>> + Unpin,
        RespSink: Sink<Response<'data>> + Unpin,
        ReqSink: Sink<Request<'data>> + Unpin,
        RespSrc: Stream<Item = Response<'data>> + Unpin,
        const MAX_REQUESTS_PER_WORKER: usize,
        const MAX_CLIENTS: usize,
        const MAX_WORKERS: usize,
    > Default
    for Builder<
        'data,
        'keystore,
        M,
        ReqSrc,
        RespSink,
        ReqSink,
        RespSrc,
        MAX_REQUESTS_PER_WORKER,
        MAX_CLIENTS,
        MAX_WORKERS,
    >
{
    fn default() -> Self {
        Builder::new()
    }
}

impl<
        'data,
        'keystore,
        M: RawMutex,
        ReqSrc: Stream<Item = Request<'data>> + Unpin,
        RespSink: Sink<Response<'data>> + Unpin,
        ReqSink: Sink<Request<'data>> + Unpin,
        RespSrc: Stream<Item = Response<'data>> + Unpin,
        const MAX_REQUESTS_PER_WORKER: usize,
        const MAX_CLIENTS: usize,
        const MAX_WORKERS: usize,
    >
    Builder<
        'data,
        'keystore,
        M,
        ReqSrc,
        RespSink,
        ReqSink,
        RespSrc,
        MAX_REQUESTS_PER_WORKER,
        MAX_CLIENTS,
        MAX_WORKERS,
    >
{
    pub fn new() -> Builder<
        'data,
        'keystore,
        M,
        ReqSrc,
        RespSink,
        ReqSink,
        RespSrc,
        MAX_REQUESTS_PER_WORKER,
        MAX_CLIENTS,
        MAX_WORKERS,
    > {
        Builder {
            key_store: None,
            clients: Default::default(),
            workers: Default::default(),
        }
    }

    pub fn with_keystore(
        mut self,
        key_store: &'keystore Mutex<M, &'keystore mut (dyn KeyStore + Send)>,
    ) -> Self {
        self.key_store = Some(key_store);
        self
    }

    pub fn with_client(mut self, requests: ReqSrc, responses: RespSink) -> Self {
        if self
            .clients
            .push(Mutex::new(RefCell::new(ClientChannel {
                requests: requests.peekable(),
                responses,
            })))
            .is_err()
        {
            panic!("Failed to add client channel");
        };
        self
    }

    pub fn with_worker(
        mut self,
        req_types: &[RequestType],
        requests: ReqSink,
        responses: RespSrc,
    ) -> Self {
        for channel in &mut self.workers {
            for req_type in req_types {
                if channel.req_types.contains(req_type) {
                    panic!("Channel for given request type already exists");
                }
            }
        }
        if self
            .workers
            .push(WorkerChannel {
                req_types: Vec::from_slice(req_types)
                    .expect("Maximum number of request types for single worker exceeded"),
                requests: Mutex::new(RefCell::new(requests)),
                responses: Mutex::new(RefCell::new(responses.peekable())),
            })
            .is_err()
        {
            panic!("Failed to add worker channel");
        };
        self
    }

    pub fn build(
        self,
    ) -> Core<
        'data,
        'keystore,
        M,
        ReqSrc,
        RespSink,
        ReqSink,
        RespSrc,
        MAX_REQUESTS_PER_WORKER,
        MAX_CLIENTS,
        MAX_WORKERS,
    > {
        Core {
            key_store: self.key_store,
            clients: self.clients,
            workers: self.workers,
            last_client_id: AtomicUsize::new(0),
            last_worker_id: AtomicUsize::new(0),
        }
    }
}

impl<
        'data,
        'keystore,
        M: RawMutex,
        ReqSrc: Stream<Item = Request<'data>> + Unpin,
        RespSink: Sink<Response<'data>> + Unpin,
        ReqSink: Sink<Request<'data>> + Unpin,
        RespSrc: Stream<Item = Response<'data>> + Unpin,
        const MAX_REQUESTS_PER_WORKER: usize,
        const MAX_CLIENTS: usize,
        const MAX_WORKERS: usize,
    >
    Core<
        'data,
        'keystore,
        M,
        ReqSrc,
        RespSink,
        ReqSink,
        RespSrc,
        MAX_REQUESTS_PER_WORKER,
        MAX_CLIENTS,
        MAX_WORKERS,
    >
{
    pub async fn execute(&mut self) -> Result<(), Error> {
        select(
            pin!(self.process_client_requests()),
            pin!(self.process_worker_responses()),
        )
        .await;
        Ok(())
    }

    /// Search all input channels for a new request and process it.
    /// Channels are processed in a round-robin fashion.
    async fn process_client_requests(&self) {
        let number_of_clients = self.clients.len();
        let (left, right) = self
            .clients
            .split_at((self.last_client_id.load(SeqCst) + 1) % number_of_clients);
        let clients_iterator = right.into_iter().chain(left.into_iter());

        let client_mutexes = Vec::<_, MAX_CLIENTS>::from_iter(
            clients_iterator.map(|client| client.try_lock().unwrap()),
        );

        let mut client_refs = Vec::<_, MAX_CLIENTS>::from_iter(
            client_mutexes.iter().map(|client| client.borrow_mut()),
        );

        let mut client_futures =
            Vec::<_, MAX_CLIENTS>::from_iter(client_refs.iter_mut().map(|client| {
                let requests = Pin::new(&mut client.requests);
                requests
                    .peek()
                    .map(|request| {
                        let request_type = request.expect("requests stream died").get_type();
                        let worker_channel = self
                            .workers
                            .iter()
                            .find(|c| c.req_types.contains(&request_type))
                            .expect("Failed to find worker channel for request type");
                        worker_channel
                    })
                    .then(|worker_channel| {
                        worker_channel
                            .requests
                            .lock()
                            .map(move |x| (worker_channel, x))
                    })
                    .then(|(worker_channel, requests)| {
                        poll_fn(move |cx| {
                            requests
                                .try_borrow_mut()
                                .expect("futures are expected to be polled sequentially")
                                .poll_ready_unpin(cx)
                                .map(|_| worker_channel)
                        })
                    })
                    .left_future()
            }));
        for _ in client_futures.len()..client_futures.capacity() {
            unsafe { client_futures.push_unchecked(pending().right_future()) };
        }

        let (worker_channel, client_index) = select_array(
            client_futures
                .into_array::<MAX_CLIENTS>()
                .map_err(|_| ())
                .expect("vec was extended up to capacity"),
        )
        .await;

        drop(client_refs);

        assert!(client_index < number_of_clients);
        self.last_client_id.store(
            (client_index + self.last_client_id.load(SeqCst) + 1) % number_of_clients,
            SeqCst,
        );
        let request = self.clients[client_index]
            .lock()
            .await
            .borrow_mut()
            .requests
            .next()
            .await
            .expect("request stream died");
        worker_channel
            .requests
            .lock()
            .await
            .borrow_mut()
            .send(request)
            .await
            .map_err(|_| ())
            .expect("request sink died");
    }

    async fn process_worker_responses(&self) {
        let number_of_workers = self.workers.len();
        let (left, right) = self
            .workers
            .split_at((self.last_worker_id.load(SeqCst) + 1) % number_of_workers);
        let workers_iterator = right.into_iter().chain(left.into_iter());

        let worker_mutexes = Vec::<_, MAX_WORKERS>::from_iter(
            workers_iterator.map(|worker| worker.responses.try_lock().unwrap()),
        );

        let mut worker_refs = Vec::<_, MAX_WORKERS>::from_iter(
            worker_mutexes.iter().map(|worker| worker.borrow_mut()),
        );

        let mut worker_futures =
            Vec::<_, MAX_WORKERS>::from_iter(worker_refs.iter_mut().map(|worker| {
                let responses = Pin::new(worker.deref_mut());
                responses
                    .peek()
                    .map(|response| {
                        let client_channel = &self.clients
                            [response.expect("response stream died").get_client_id() as usize];
                        client_channel
                    })
                    .then(|client_channel| client_channel.lock().map(move |x| (client_channel, x)))
                    .then(|(client_channel, client_channel_guard)| {
                        poll_fn(move |cx| {
                            client_channel_guard
                                .borrow_mut()
                                .responses
                                .poll_ready_unpin(cx)
                                .map(|_| client_channel)
                        })
                    })
                    .left_future()
            }));
        for _ in worker_futures.len()..worker_futures.capacity() {
            unsafe { worker_futures.push_unchecked(pending().right_future()) };
        }

        let (client_channel, worker_index) = select_array(
            worker_futures
                .into_array::<MAX_WORKERS>()
                .map_err(|_| ())
                .expect("vec was extended up to capacity"),
        )
        .await;

        drop(worker_refs);

        assert!(worker_index < number_of_workers);
        self.last_worker_id.store(
            (worker_index + self.last_worker_id.load(SeqCst) + 1) % number_of_workers,
            SeqCst,
        );
        let response = self.workers[worker_index]
            .responses
            .lock()
            .await
            .borrow_mut()
            .next()
            .await
            .expect("request stream died");
        client_channel
            .lock()
            .await
            .borrow_mut()
            .responses
            .send(response)
            .await
            .map_err(|_| ())
            .expect("request sink died");
    }

    async fn process_request(&mut self, request: Request<'data>) -> Result<(), Error> {
        match request {
            Request::ImportKey {
                client_id,
                request_id,
                key_id,
                data,
            } => {
                let response = {
                    if let Some(key_store) = self.key_store {
                        match key_store
                            .try_lock()
                            .expect("Failed to lock key store")
                            .deref_mut()
                            .import(key_id, data)
                        {
                            Ok(()) => Response::ImportKey {
                                client_id,
                                request_id,
                            },
                            Err(e) => Response::Error {
                                client_id,
                                request_id,
                                error: jobs::Error::KeyStore(e),
                            },
                        }
                    } else {
                        Response::Error {
                            client_id,
                            request_id,
                            error: jobs::Error::NoKeyStore,
                        }
                    }
                };
                self.send_to_client(response).await?;
            }
            _ => {
                let channel = self
                    .workers
                    .iter_mut()
                    .find(|c| c.req_types.contains(&request.get_type()))
                    .expect("Failed to find worker channel for request type");
                channel
                    .requests
                    .lock()
                    .await
                    .get_mut()
                    .send(request)
                    .await
                    .map_err(|_e| Error::Send)?;
            }
        }
        Ok(())
    }

    async fn send_to_client(&mut self, response: Response<'data>) -> Result<(), Error> {
        let client_id = response.get_client_id();
        if let Some(client) = self.clients.get(client_id as usize) {
            client
                .lock()
                .await
                .borrow_mut()
                .responses
                .send(response)
                .await
                .map_err(|_e| Error::Send)?;
        } else {
            panic!("Invalid internal client ID");
        }
        Ok(())
    }
}
