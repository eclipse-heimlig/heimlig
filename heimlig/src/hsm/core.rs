use crate::common::jobs;
use crate::common::jobs::{Request, RequestType, Response};
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
    M: RawMutex,
    ReqSrc: Stream<Item = Request<'data>>,
    RespSink: Sink<Response<'data>>,
    ReqSink: Sink<Request<'data>>,
    RespSrc: Stream<Item = Response<'data>>,
    const MAX_REQUEST_TYPES: usize = 8,
    const MAX_WORKERS: usize = 8,
> {
    key_store: Option<&'keystore Mutex<M, &'keystore mut (dyn KeyStore + Send)>>,
    client: ClientChannel<'data, ReqSrc, RespSink>, // TODO: Support multiple clients
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

impl<
        'data,
        'keystore,
        M: RawMutex,
        ReqSrc: Stream<Item = Request<'data>> + Unpin,
        RespSink: Sink<Response<'data>> + Unpin,
        ReqSink: Sink<Request<'data>> + Unpin,
        RespSrc: Stream<Item = Response<'data>> + Unpin,
        const MAX_REQUESTS_PER_WORKER: usize,
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
        MAX_WORKERS,
    >
{
    /// Create a new HSM core.
    /// The core accepts requests and forwards the responses once they are ready.
    ///
    /// # Arguments
    ///
    /// * `key_store`: The [KeyStore] to hold cryptographic key material.
    /// * `requests`: Source from where the core received requests.
    /// * `responses`: Sink to where the core sends responses.
    pub fn new(
        key_store: Option<&'keystore Mutex<M, &'keystore mut (dyn KeyStore + Send)>>,
        requests: ReqSrc,
        responses: RespSink,
    ) -> Self {
        Self {
            key_store,
            client: ClientChannel {
                requests,
                responses,
            },
            workers: Default::default(),
        }
    }

    pub fn add_worker_channel(
        &mut self,
        req_types: &[RequestType],
        requests: ReqSink,
        responses: RespSrc,
    ) {
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
    }

    pub async fn execute(&mut self) -> Result<(), Error> {
        self.process_worker_responses().await?;
        self.process_client_requests().await?;
        Ok(())
    }

    async fn process_worker_responses(&mut self) -> Result<(), Error> {
        for channel in &mut self.workers {
            if let Some(response) = channel.responses.next().await {
                self.client
                    .responses
                    .send(response)
                    .await
                    .map_err(|_e| Error::Send)?;
            }
        }
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
        let request = self.client.requests.next().await;
        if let Some(request) = request {
            return self.process(request).await;
        }
        Ok(()) // Nothing to process
    }

    async fn process(&mut self, request: Request<'data>) -> Result<(), Error> {
        match request {
            Request::ImportKey { key_id, data } => {
                let response = {
                    if let Some(key_store) = self.key_store {
                        match key_store
                            .try_lock()
                            .expect("Failed to lock key store")
                            .deref_mut()
                            .import(key_id, data)
                        {
                            Ok(()) => Response::ImportKey,
                            Err(e) => Response::Error(jobs::Error::KeyStore(e)),
                        }
                    } else {
                        Response::Error(jobs::Error::NoKeyStore)
                    }
                };
                self.client
                    .responses
                    .send(response)
                    .await
                    .map_err(|_e| Error::Send)?;
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
}
