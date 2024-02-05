use crate::common::jobs;
use crate::common::jobs::{ClientId, Request, RequestId, RequestType, Response};
use crate::hsm::keystore;
use core::future::poll_fn;
use core::ops::DerefMut;
use core::pin::Pin;
use embassy_futures::select::select_slice;
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::mutex::Mutex;
use futures::{FutureExt, Sink, SinkExt, Stream, StreamExt};
use heapless::Vec;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// Error sending message through queue
    Send,
    /// Futures Stream was terminated
    StreamTerminated,
    /// Maximum number of clients that can be added to a core was exceeded
    TooManyClients,
    /// Maximum number of workers that can be added to a core was exceeded
    TooManyWorkers,
    /// Tried to add worker for invalid request type
    InvalidRequestType,
    /// A channel for the given request type already exists
    ChannelForRequestExists,
    /// Maximum number of request types for a single worker exceeded
    TooManyRequestTypes,
    /// An internal error occurred
    Internal(InternalError),
}

/// Internal errors that a client should not be able to trigger.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum InternalError {
    // The internal client ID was invalid for the internal list of client channels.
    InvalidClientId(ClientId),
    // The internal worker ID was invalid for the internal list of worker channels.
    InvalidWorkerId(WorkerId),
    /// An empty client request queue was encountered even though a previous check made sure that it was non-empty.
    EmptyClientRequestQueue(ClientId),
    /// An empty worker response queue was encountered even though a previous check made sure that it was non-empty.
    EmptyWorkerResponseQueue(WorkerId),
    /// The core encountered a request type it cannot handle
    UnexpectedCoreRequest(RequestType),
    // The client ID of the response that was determined to be processed next did not match the one in the response queue.
    ClientIdMismatch(ClientId, ClientId),
}

/// Used to index list of workers
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WorkerId(pub u32);

impl From<u32> for WorkerId {
    fn from(value: u32) -> Self {
        WorkerId(value)
    }
}

impl From<usize> for WorkerId {
    fn from(value: usize) -> Self {
        WorkerId(value as u32)
    }
}

impl WorkerId {
    pub fn idx(&self) -> usize {
        self.0 as usize
    }
}

enum Job {
    /// A client request should be forwarded to a worker
    ForwardRequest(ClientId, WorkerId),
    /// A worker response should be forwarded to a client
    ForwardResponse(ClientId, WorkerId),
    /// The incoming request can be handled on the core without contacting a dedicated worker
    ProcessOnCore(ClientId),
    /// The incoming request has no worker to handle it
    RespondNoWorkerForRequest(ClientId),
}

// TODO: Can be made configurable once `generic_const_exprs` is stable
// https://doc.rust-lang.org/beta/unstable-book/language-features/generic-const-exprs.html
/// Maximum number of allowed clients
pub const MAX_CLIENTS: usize = 8;
/// Maximum number of allowed workers
pub const MAX_WORKERS: usize = 16;
// TODO: Can be made configurable once `core::mem::variant_count` is stable
// https://github.com/rust-lang/rust/issues/73662
/// Maximum number of different request types handles by a worker
const MAX_REQUEST_TYPES: usize = 8;

/// HSM core that waits for [Request]s from clients and send [Response]s once they are ready.   
pub struct Core<
    'data,
    'keystore,
    M: RawMutex, // TODO: Get rid of embassy specific mutex outside of integration code
    ReqSrc: Stream<Item = Request<'data>>,
    RespSink: Sink<Response<'data>>,
    ReqSink: Sink<Request<'data>>,
    RespSrc: Stream<Item = Response<'data>>,
    KeyStore: keystore::KeyStore,
> {
    key_store: Option<&'keystore Mutex<M, &'keystore mut KeyStore>>,
    clients: Vec<ClientChannel<'data, ReqSrc, RespSink, M>, MAX_CLIENTS>,
    workers: Vec<WorkerChannel<'data, ReqSink, RespSrc, M>, MAX_WORKERS>,
    last_client_id: usize,
    last_worker_id: usize,
}

struct ClientChannel<
    'data,
    ReqSrc: Stream<Item = Request<'data>>,
    RespSink: Sink<Response<'data>>,
    M: RawMutex, // TODO: Get rid of embassy specific mutex outside of integration code
> {
    id: ClientId, // Used to index list of clients in Core
    requests: Mutex<M, futures::stream::Peekable<ReqSrc>>,
    responses: Mutex<M, RespSink>,
}

/// Associate request types with request sink and response source of the responsible worker
struct WorkerChannel<
    'data,
    ReqSink: Sink<Request<'data>>,
    RespSrc: Stream<Item = Response<'data>>,
    M: RawMutex, // TODO: Get rid of embassy specific mutex outside of integration code
> {
    pub id: WorkerId, // Used to index list of workers in Core
    pub req_types: Vec<RequestType, MAX_REQUEST_TYPES>,
    pub requests: Mutex<M, ReqSink>,
    pub responses: Mutex<M, futures::stream::Peekable<RespSrc>>,
}

pub struct Builder<
    'data,
    'keystore,
    M: RawMutex, // TODO: Get rid of embassy specific mutex outside of integration code
    ReqSrc: Stream<Item = Request<'data>>,
    RespSink: Sink<Response<'data>>,
    ReqSink: Sink<Request<'data>>,
    RespSrc: Stream<Item = Response<'data>>,
    KeyStore: keystore::KeyStore,
> {
    key_store: Option<&'keystore Mutex<M, &'keystore mut KeyStore>>,
    clients: Vec<ClientChannel<'data, ReqSrc, RespSink, M>, MAX_CLIENTS>,
    workers: Vec<WorkerChannel<'data, ReqSink, RespSrc, M>, MAX_WORKERS>,
}

impl<
        'data,
        'keystore,
        M: RawMutex,
        ReqSrc: Stream<Item = Request<'data>> + Unpin,
        RespSink: Sink<Response<'data>> + Unpin,
        ReqSink: Sink<Request<'data>> + Unpin,
        RespSrc: Stream<Item = Response<'data>> + Unpin,
        KeyStore: keystore::KeyStore,
    > Default for Builder<'data, 'keystore, M, ReqSrc, RespSink, ReqSink, RespSrc, KeyStore>
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
        KeyStore: keystore::KeyStore,
    > Builder<'data, 'keystore, M, ReqSrc, RespSink, ReqSink, RespSrc, KeyStore>
{
    pub fn new() -> Self {
        Builder {
            key_store: None,
            clients: Default::default(),
            workers: Default::default(),
        }
    }

    pub fn with_keystore(
        mut self,
        key_store: &'keystore Mutex<M, &'keystore mut KeyStore>,
    ) -> Self {
        self.key_store = Some(key_store);
        self
    }

    pub fn with_client(mut self, requests: ReqSrc, responses: RespSink) -> Result<Self, Error> {
        self.clients
            .push(ClientChannel {
                id: ClientId::from(self.clients.len() as u32),
                requests: Mutex::new(requests.peekable()),
                responses: Mutex::new(responses),
            })
            .map_err(|_| Error::TooManyClients)?;
        Ok(self)
    }

    pub fn with_worker(
        mut self,
        req_types: &[RequestType],
        requests: ReqSink,
        responses: RespSrc,
    ) -> Result<Self, Error> {
        if req_types.iter().any(|r| r.is_handled_by_core()) {
            return Err(Error::InvalidRequestType);
        }
        for channel in &mut self.workers {
            for req_type in req_types {
                if channel.req_types.contains(req_type) {
                    return Err(Error::ChannelForRequestExists);
                }
            }
        }
        self.workers
            .push(WorkerChannel {
                id: self.workers.len().into(),
                req_types: Vec::from_slice(req_types).map_err(|_| Error::TooManyRequestTypes)?,
                requests: Mutex::new(requests),
                responses: Mutex::new(responses.peekable()),
            })
            .map_err(|_| Error::TooManyWorkers)?;
        Ok(self)
    }

    pub fn build(self) -> Core<'data, 'keystore, M, ReqSrc, RespSink, ReqSink, RespSrc, KeyStore> {
        Core {
            key_store: self.key_store,
            clients: self.clients,
            workers: self.workers,
            last_client_id: 0,
            last_worker_id: 0,
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
        KeyStore: keystore::KeyStore,
    > Core<'data, 'keystore, M, ReqSrc, RespSink, ReqSink, RespSrc, KeyStore>
{
    /// Drive the core to process the next client request or forward the next worker response.
    /// This method is supposed to be called by a system task that owns the core.
    pub async fn execute(&mut self) -> Result<(), Error> {
        match self.next_job().await? {
            Job::ForwardRequest(client_id, worker_id) => {
                self.forward_request(client_id, worker_id).await
            }
            Job::ForwardResponse(client_id, worker_id) => {
                self.forward_response(client_id, worker_id).await
            }
            Job::ProcessOnCore(client_id) => self.process_on_core(client_id).await,
            Job::RespondNoWorkerForRequest(client_id) => {
                self.respond_no_worker_for_request(client_id).await
            }
        }
    }

    /// Asynchronously consider all incoming queues (client requests and worker responses) to determine if any progress can be made.
    /// If so, the found job will be returned to be performed by the caller.
    async fn next_job(&self) -> Result<Job, Error> {
        let mut workers: Vec<_, MAX_WORKERS> = self.workers.iter().collect();
        let mut clients: Vec<_, MAX_CLIENTS> = self.clients.iter().collect();
        workers.rotate_left(self.last_worker_id);
        clients.rotate_left(self.last_client_id);

        // Futures to handle worker responses
        let process_response = workers.iter().map(|worker| async {
            // Check for incoming response from worker channels
            let mut responses = worker.responses.lock().await;
            let response = Pin::new(responses.deref_mut())
                .peek()
                .await
                .ok_or(Error::StreamTerminated)?;

            // Find client for received response
            let client_id = response.get_client_id();
            let client = self
                .clients
                .get(client_id.idx())
                .ok_or(Error::Internal(InternalError::InvalidClientId(client_id)))?;
            let mut responses = client.responses.lock().await;

            // Check if client queue has room to accept the response
            poll_fn(move |cx| responses.deref_mut().poll_ready_unpin(cx))
                .await
                .map_err(|_| Error::StreamTerminated)?;
            Ok(Job::ForwardResponse(client_id, worker.id))
        });

        // Futures to handle client requests
        let process_requests = clients.iter().map(|client| async {
            // Check for incoming requests from client channels
            let mut requests = client.requests.lock().await;
            let request = Pin::new(requests.deref_mut())
                .peek()
                .await
                .ok_or(Error::StreamTerminated)?;
            let request_type = request.get_type();
            if request_type.is_handled_by_core() {
                return Ok(Job::ProcessOnCore(client.id));
            }

            // Find worker for received request
            let worker = match self
                .workers
                .iter()
                .find(|w| w.req_types.contains(&request_type))
            {
                None => return Ok(Job::RespondNoWorkerForRequest(client.id)),
                Some(worker) => worker,
            };
            let mut requests = worker.requests.lock().await;

            // Check if worker queue has room to accept the request
            poll_fn(move |cx| requests.deref_mut().poll_ready_unpin(cx))
                .await
                .map_err(|_| Error::StreamTerminated)?;
            Ok(Job::ForwardRequest(client.id, worker.id))
        });

        // Collect and execute all futures
        let mut jobs: Vec<_, { MAX_WORKERS + MAX_CLIENTS }> = process_response
            .map(|f| f.left_future())
            .chain(process_requests.map(|f| f.right_future()))
            .collect();
        select_slice(&mut jobs).await.0
    }

    async fn forward_response(
        &mut self,
        client_id: ClientId,
        worker_id: WorkerId,
    ) -> Result<(), Error> {
        let response = self
            .workers
            .get(worker_id.idx())
            .ok_or(Error::Internal(InternalError::InvalidWorkerId(worker_id)))?
            .responses
            .lock()
            .await
            .deref_mut()
            .next()
            .await
            .ok_or(Error::Internal(InternalError::EmptyWorkerResponseQueue(
                worker_id,
            )))?;
        if client_id != response.get_client_id() {
            // Mismatch of computed and response client IDs
            return Err(Error::Internal(InternalError::ClientIdMismatch(
                client_id,
                response.get_client_id(),
            )));
        }
        self.send_to_client(response).await
    }

    async fn forward_request(
        &mut self,
        client_id: ClientId,
        worker_id: WorkerId,
    ) -> Result<(), Error> {
        let mut request = self
            .clients
            .get(client_id.idx())
            .ok_or(Error::Internal(InternalError::InvalidClientId(client_id)))?
            .requests
            .lock()
            .await
            .deref_mut()
            .next()
            .await
            .ok_or(Error::Internal(InternalError::EmptyClientRequestQueue(
                client_id,
            )))?;

        // Fill client ID field that will be used to send back the response later
        request.set_client_id(client_id);

        self.workers
            .get(worker_id.idx())
            .ok_or(Error::Internal(InternalError::InvalidWorkerId(worker_id)))?
            .requests
            .lock()
            .await
            .deref_mut()
            .send(request)
            .await
            .map_err(|_e| Error::Send)
    }

    async fn process_on_core(&mut self, client_id: ClientId) -> Result<(), Error> {
        let Some(client) = self.clients.get(client_id.idx()) else {
            return Err(Error::Internal(InternalError::InvalidClientId(client_id)));
        };
        let request = client
            .requests
            .lock()
            .await
            .deref_mut()
            .next()
            .await
            .ok_or(Error::Internal(InternalError::EmptyClientRequestQueue(
                client_id,
            )))?;
        let response = match request {
            Request::IsKeyAvailable {
                client_id,
                request_id,
                key_id,
            } => match self.key_store {
                None => Ok(Self::no_key_store_response(client_id, request_id)),
                Some(key_store) => {
                    let is_available = key_store.lock().await.deref_mut().is_key_available(key_id);
                    Ok(Response::IsKeyAvailable {
                        client_id,
                        request_id,
                        is_available,
                    })
                }
            },
            Request::ImportSymmetricKey {
                client_id,
                request_id,
                key_id,
                data,
                overwrite,
            } => match self.key_store {
                None => Ok(Self::no_key_store_response(client_id, request_id)),
                Some(key_store) => {
                    let result = key_store
                        .lock()
                        .await
                        .deref_mut()
                        .import_symmetric_key(key_id, data, overwrite);
                    match result {
                        Ok(()) => Ok(Response::ImportSymmetricKey {
                            client_id,
                            request_id,
                        }),
                        Err(e) => Ok(Self::key_store_error_response(client_id, request_id, e)),
                    }
                }
            },
            Request::ImportKeyPair {
                client_id,
                request_id,
                key_id,
                public_key,
                private_key,
                overwrite,
            } => match self.key_store {
                None => Ok(Self::no_key_store_response(client_id, request_id)),
                Some(key_store) => {
                    let result = key_store.lock().await.deref_mut().import_key_pair(
                        key_id,
                        public_key,
                        private_key,
                        overwrite,
                    );
                    match result {
                        Ok(()) => Ok(Response::ImportKeyPair {
                            client_id,
                            request_id,
                        }),
                        Err(e) => Ok(Self::key_store_error_response(client_id, request_id, e)),
                    }
                }
            },
            Request::ExportSymmetricKey {
                client_id,
                request_id,
                key_id,
                data,
            } => match self.key_store {
                None => Ok(Self::no_key_store_response(client_id, request_id)),
                Some(key_store) => {
                    let exported_key = key_store
                        .lock()
                        .await
                        .deref_mut()
                        .export_symmetric_key(key_id, data);
                    match exported_key {
                        Ok(written) => {
                            let written_len = written.len();
                            Ok(Response::ExportSymmetricKey {
                                client_id,
                                request_id,
                                key: &mut data[..written_len],
                            })
                        }
                        Err(e) => Ok(Self::key_store_error_response(client_id, request_id, e)),
                    }
                }
            },
            Request::ExportPublicKey {
                client_id,
                request_id,
                key_id,
                public_key,
            } => match self.key_store {
                None => Ok(Self::no_key_store_response(client_id, request_id)),
                Some(key_store) => {
                    let exported_key = key_store
                        .lock()
                        .await
                        .deref_mut()
                        .export_public_key(key_id, public_key);
                    match exported_key {
                        Ok(written) => {
                            let exported_key_len = written.len();
                            Ok(Response::ExportPublicKey {
                                client_id,
                                request_id,
                                public_key: &mut public_key[..exported_key_len],
                            })
                        }
                        Err(e) => Ok(Self::key_store_error_response(client_id, request_id, e)),
                    }
                }
            },
            Request::ExportPrivateKey {
                client_id,
                request_id,
                key_id,
                private_key,
            } => match self.key_store {
                None => Ok(Self::no_key_store_response(client_id, request_id)),
                Some(key_store) => {
                    let exported_key = key_store
                        .lock()
                        .await
                        .deref_mut()
                        .export_private_key(key_id, private_key);
                    match exported_key {
                        Ok(written) => {
                            let written_len = written.len();
                            Ok(Response::ExportPrivateKey {
                                client_id,
                                request_id,
                                private_key: &mut private_key[..written_len],
                            })
                        }
                        Err(e) => Ok(Self::key_store_error_response(client_id, request_id, e)),
                    }
                }
            },
            _ => Err(Error::Internal(InternalError::UnexpectedCoreRequest(
                request.get_type(),
            ))),
        }?;
        self.send_to_client(response).await
    }

    async fn respond_no_worker_for_request(&mut self, client_id: ClientId) -> Result<(), Error> {
        let Some(client) = self.clients.get(client_id.idx()) else {
            return Err(Error::Internal(InternalError::InvalidClientId(client_id)));
        };
        // Remove request from queue even tough we cannot handle it
        let request = client
            .requests
            .lock()
            .await
            .deref_mut()
            .next()
            .await
            .ok_or(Error::Internal(InternalError::EmptyClientRequestQueue(
                client_id,
            )))?;
        let response = Response::Error {
            client_id,
            request_id: request.get_request_id(),
            error: jobs::Error::NoWorkerForRequest,
        };
        self.send_to_client(response).await
    }

    async fn send_to_client(&mut self, response: Response<'data>) -> Result<(), Error> {
        let client_id = response.get_client_id();
        self.clients
            .get(client_id.idx())
            .ok_or(Error::Internal(InternalError::InvalidClientId(client_id)))?
            .responses
            .lock()
            .await
            .deref_mut()
            .send(response)
            .await
            .map_err(|_e| Error::Send)
    }

    fn no_key_store_response(client_id: ClientId, request_id: RequestId) -> Response<'data> {
        Response::Error {
            client_id,
            request_id,
            error: jobs::Error::NoKeyStore,
        }
    }

    fn key_store_error_response(
        client_id: ClientId,
        request_id: RequestId,
        error: keystore::Error,
    ) -> Response<'data> {
        Response::Error {
            client_id,
            request_id,
            error: jobs::Error::KeyStore(error),
        }
    }
}
