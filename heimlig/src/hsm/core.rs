use crate::common::jobs;
use crate::common::jobs::{Request, RequestType, Response};
use crate::common::queues::{Error, RequestSink, ResponseSink};
use crate::hsm::keystore::KeyStore;
use core::cell::RefCell;
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::mutex::Mutex;
use heapless::Vec;

/// HSM core that waits for [Request]s from [Channel]s and send [Response]s once they are ready.   
pub struct Core<
    'data,
    'keystore,
    M: RawMutex,
    K: KeyStore,
    ReqSrc: Iterator<Item = (usize, Request<'data>)>,
    RespSink: ResponseSink<'data>,
    ReqSink: RequestSink<'data>,
    RespSrc: Iterator<Item = (usize, Response<'data>)>,
    const MAX_REQUEST_TYPES_PER_WORKER: usize = 8,
    const MAX_WORKERS: usize = 8,
> {
    key_store: &'keystore Mutex<M, RefCell<Option<K>>>,
    // TODO: Support multiple client channels like worker channels
    client_requests: ReqSrc,
    client_responses: RespSink,
    worker_channels: Vec<
        WorkerChannel<'data, ReqSink, RespSrc, MAX_REQUEST_TYPES_PER_WORKER, MAX_WORKERS>,
        MAX_WORKERS,
    >,
}

/// Associate request types with request sink and response source of the responsible worker
struct WorkerChannel<
    'data,
    ReqSink: RequestSink<'data>,
    RespSrc: Iterator<Item = (usize, Response<'data>)>,
    const MAX_REQUEST_TYPES_PER_WORKER: usize,
    const MAX_WORKERS: usize,
> {
    pub req_types: Vec<RequestType, MAX_REQUEST_TYPES_PER_WORKER>,
    pub requests: ReqSink,
    pub responses: RespSrc,
}

impl<
        'data,
        'keystore,
        M: RawMutex,
        K: KeyStore,
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
        K,
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
    /// * `rng`: Random number generator (RNG) used to seed the core RNG.
    /// * `response_channels`: List of [Channel]s to send responses back to the clients.
    /// * `key_store`: The [KeyStore] to hold cryptographic key material.
    pub fn new(
        key_store: &'keystore Mutex<M, RefCell<Option<K>>>,
        client_requests: ReqSrc,
        client_responses: RespSink,
    ) -> Self {
        Self {
            key_store,
            client_requests,
            client_responses,
            worker_channels: Default::default(),
        }
    }

    pub fn add_worker_channel(
        &mut self,
        req_types: &[RequestType],
        requests: ReqSink,
        responses: RespSrc,
    ) {
        for channel in &self.worker_channels {
            for req_type in req_types {
                if channel.req_types.contains(req_type) {
                    panic!("Channel for given request type already exists");
                }
            }
        }
        if self
            .worker_channels
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
        for channel in &mut self.worker_channels {
            if self.client_responses.ready() {
                if let Some((_id, response)) = channel.responses.next() {
                    self.client_responses.send(response)?
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
    /// * `Ok(false)` if no [Request] was found in any input [Channel].
    /// * `Err(core::Error)` if a processing error occurred.
    fn process_client_requests(&mut self) -> Result<(), Error> {
        if !self.client_responses.ready() {
            return Err(Error::NotReady);
        }
        let request = self.client_requests.next();
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
                    let response = match self
                        .key_store
                        .try_lock()
                        .expect("Failed to lock key store")
                        .borrow_mut()
                        .as_mut()
                        .unwrap() // TODO: Handle no key store case
                        .import(key_id, data)
                    {
                        Ok(()) => Response::ImportKey,
                        Err(e) => Response::Error(jobs::Error::KeyStore(e)),
                    };
                    self.client_responses.send(response)?;
                }
                _ => panic!("Mismatch of request type and content"),
            },
            _ => {
                let channel = self
                    .worker_channels
                    .iter_mut()
                    .find(|c| c.req_types.contains(&req_type))
                    .expect("Failed to find worker channel for request type");
                channel.requests.send(request)?;
            }
        }
        Ok(())
    }
}
