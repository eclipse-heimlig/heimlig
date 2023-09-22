use crate::common::jobs;
use crate::common::jobs::{ClientId, Request, RequestType, Response};
use crate::hsm::keystore::KeyStore;
use core::ops::DerefMut;
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::mutex::Mutex;
use futures::{Sink, SinkExt, Stream, StreamExt};
use heapless::Vec;

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
    clients: Vec<ClientChannel<'data, ReqSrc, RespSink>, MAX_CLIENTS>,
    workers: Vec<WorkerChannel<'data, ReqSink, RespSrc, MAX_REQUEST_TYPES>, MAX_WORKERS>,
}

struct ClientChannel<'data, ReqSrc: Stream<Item = Request<'data>>, RespSink: Sink<Response<'data>>>
{
    requests: ReqSrc,
    responses: RespSink,
}

/// Associate request types with request sink and response source of the responsible worker
struct WorkerChannel<
    'data,
    ReqSink: Sink<Request<'data>>,
    RespSrc: Stream<Item = Response<'data>>,
    const MAX_REQUEST_TYPES_PER_WORKER: usize,
> {
    pub req_types: Vec<RequestType, MAX_REQUEST_TYPES_PER_WORKER>,
    pub requests: ReqSink,
    pub responses: RespSrc,
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
    clients: Vec<ClientChannel<'data, ReqSrc, RespSink>, MAX_CLIENTS>,
    workers: Vec<WorkerChannel<'data, ReqSink, RespSrc, MAX_REQUEST_TYPES>, MAX_WORKERS>,
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
            .push(ClientChannel {
                requests,
                responses,
            })
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
        for channel in &self.workers {
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
                requests,
                responses,
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
        self.process_worker_responses().await?;
        self.process_client_requests().await?;
        Ok(())
    }

    /// Search all input channels for a new request and process it.
    /// Channels are processed in a round-robin fashion.
    ///
    /// # Returns
    ///
    /// * `Ok(true)` if a [Request] was found and successfully processed.
    /// * `Ok(false)` if no [Request] was found in any input [ClientChannel].
    /// * `Err(core::Error)` if a processing error occurred.
    async fn process_client_requests(&mut self) -> Result<(), Error> {
        for (client_id, client) in &mut self.clients.iter_mut().enumerate() {
            let request = client.requests.next().await;
            if let Some(mut request) = request {
                request.set_client_id(client_id as ClientId);
                return self.process_request(request).await;
            }
        }
        Ok(()) // Nothing to process
    }

    async fn process_worker_responses(&mut self) -> Result<(), Error> {
        let workers_len = self.workers.len();
        for worker_index in 0..workers_len {
            let worker = self.workers.get_mut(worker_index);
            if let Some(worker) = worker {
                let response = worker.responses.next().await;
                if let Some(response) = response {
                    self.send_to_client(response).await?;
                }
            } else {
                panic!("Invalid internal worker ID");
            }
        }
        Ok(()) // Nothing to process
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
                    .send(request)
                    .await
                    .map_err(|_e| Error::Send)?;
            }
        }
        Ok(())
    }

    async fn send_to_client(&mut self, response: Response<'data>) -> Result<(), Error> {
        let client_id = response.get_client_id();
        if let Some(client) = self.clients.get_mut(client_id as usize) {
            client
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
