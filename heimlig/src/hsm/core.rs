use crate::common::jobs::{Request, RequestType, Response};
use crate::common::queues::{RequestSink, ResponseSink};
use crate::common::{jobs, queues};
use crate::hsm::keystore::KeyStore;
use core::ops::DerefMut;
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::mutex::Mutex;
use heapless::Vec;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Error {
    /// Queue specific error
    Queue(queues::Error),
    /// Job specific error
    Job(jobs::Error),
}

/// HSM core that waits for [Request]s from clients and send [Response]s once they are ready.   
pub struct Core<
    'data,
    'keystore,
    M: RawMutex,
    ReqSrc: Iterator<Item = (usize, Request<'data>)>,
    RespSink: ResponseSink<'data>,
    ReqSink: RequestSink<'data>,
    RespSrc: Iterator<Item = (usize, Response<'data>)>,
    const MAX_REQUEST_TYPES: usize = 8,
    const MAX_WORKERS: usize = 8,
> {
    key_store: Option<&'keystore Mutex<M, &'keystore mut (dyn KeyStore + Send)>>,
    client: ClientChannel<'data, ReqSrc, RespSink>, // TODO: Support multiple clients
    workers: Vec<WorkerChannel<'data, ReqSink, RespSrc, MAX_REQUEST_TYPES>, MAX_WORKERS>,
}

struct ClientChannel<
    'data,
    ReqSrc: Iterator<Item = (usize, Request<'data>)>,
    RespSink: ResponseSink<'data>,
> {
    requests: ReqSrc,
    responses: RespSink,
}

/// Associate request types with request sink and response source of the responsible worker
struct WorkerChannel<
    'data,
    ReqSink: RequestSink<'data>,
    RespSrc: Iterator<Item = (usize, Response<'data>)>,
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
        ReqSrc: Iterator<Item = (usize, Request<'data>)>,
        RespSink: ResponseSink<'data>,
        ReqSink: RequestSink<'data>,
        RespSrc: Iterator<Item = (usize, Response<'data>)>,
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

    pub fn execute(&mut self) -> Result<(), Error> {
        self.process_worker_responses()?;
        self.process_client_requests()?;
        self.process_worker_responses()?;
        Ok(())
    }

    fn process_worker_responses(&mut self) -> Result<(), Error> {
        for channel in &mut self.workers {
            if self.client.responses.ready() {
                if let Some((_id, response)) = channel.responses.next() {
                    self.client.responses.send(response).map_err(Error::Queue)?
                }
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
    fn process_client_requests(&mut self) -> Result<(), Error> {
        if !self.client.responses.ready() {
            return Err(Error::Queue(queues::Error::NotReady));
        }
        let request = self.client.requests.next();
        if let Some((request_id, request)) = request {
            return self.process(request_id, request);
        }
        Ok(()) // Nothing to process
    }

    // TODO: Move request ID into Request struct
    fn process(&mut self, _request_id: usize, request: Request<'data>) -> Result<(), Error> {
        let req_type = request.get_type();
        match req_type {
            RequestType::ImportKey => match request {
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
                    self.client.responses.send(response).map_err(Error::Queue)?;
                }
                _ => panic!("Mismatch of request type and content"),
            },
            _ => {
                let channel = self
                    .workers
                    .iter_mut()
                    .find(|c| c.req_types.contains(&req_type))
                    .expect("Failed to find worker channel for request type");
                channel.requests.send(request).map_err(Error::Queue)?;
            }
        }
        Ok(())
    }
}
