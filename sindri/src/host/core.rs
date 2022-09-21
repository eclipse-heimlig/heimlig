use crate::common::jobs::{Request, Response};
use crate::common::pool::Pool;
use crate::crypto::rng::{EntropySource, Rng};
use crate::host::scheduler::{Job, Scheduler};
use crate::host::workers::chachapoly_worker::ChachaPolyWorker;
use crate::host::workers::rng_worker::RngWorker;
use heapless::Vec;

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Error {
    Busy,
    UnknownChannelId,
    SendResponse,
}

pub struct Core<
    'a,
    E: EntropySource,
    const MAX_CLIENTS: usize = 8,
    const MAX_PENDING_RESPONSES: usize = 16,
> {
    scheduler: Scheduler<E>,
    channels: Vec<(&'a mut dyn Sender, &'a mut dyn Receiver), MAX_CLIENTS>,
    last_channel_id: usize,
}

pub trait Sender {
    /// Send a response through this channel back to the requester.
    fn send(&mut self, response: Response) -> Result<(), Error>;
}

pub trait Receiver {
    /// Receive a request from the client API through this channel.
    fn recv(&mut self) -> Option<Request>;
}

impl<'a, E: EntropySource, const MAX_CLIENTS: usize> Core<'a, E, MAX_CLIENTS> {
    /// Create a new HSM core. The core accepts requests and forwards the responses once they are ready.
    ///
    /// # Arguments
    ///
    /// * `rng`: Random number generator (RNG) used to seed the core RNG.
    /// * `response_channels`: List of channels to send responses back to the clients.
    pub fn new(
        pool: &'static Pool,
        rng: Rng<E>,
        channels: Vec<(&'a mut dyn Sender, &'a mut dyn Receiver), MAX_CLIENTS>,
    ) -> Core<'a, E, MAX_CLIENTS> {
        Core {
            scheduler: Scheduler {
                pool,
                rng_worker: RngWorker { pool, rng },
                chachapoly_worker: ChachaPolyWorker { pool },
            },
            channels,
            last_channel_id: 0,
        }
    }

    /// Search all input channels for a new request and process it. Channel processing is done in a round-robin fashion.
    ///
    /// # Returns
    ///
    /// * `Ok(true)` if a request was found and successfully process
    /// * `Ok(false)` if no request was found in any input channel
    /// * `Err(core::Error)` if a processing error occurred
    pub async fn process_next(&mut self) -> Result<(), Error> {
        let total_channels = self.channels.len();
        for channel_id in 0..total_channels {
            // Go through channels starting after the last used channel
            let channel_id = (channel_id + self.last_channel_id + 1) % total_channels;
            let (_sender, receiver) = &mut self.channels[channel_id];
            if let Some(request) = receiver.recv() {
                self.last_channel_id = channel_id;
                return self.process(channel_id, request).await;
            }
        }
        Ok(()) // Nothing to process
    }

    async fn process(&mut self, channel_id: usize, request: Request) -> Result<(), Error> {
        // Schedule job
        let job = Job {
            channel_id,
            request,
        };
        // TODO: Retrieve result asynchronously
        let result = self.scheduler.schedule(job).await;

        // Send response
        let (sender, _receiver) = self
            .channels
            .get_mut(result.channel_id)
            .ok_or(Error::UnknownChannelId)?;
        sender.send(result.response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::pool::Memory;
    use crate::crypto::rng;
    use crate::host::core::Sender;
    use heapless::spsc::{Consumer, Producer, Queue};

    const QUEUE_SIZE: usize = 8;

    struct RequestSender<'a, const QUEUE_SIZE: usize> {
        sender: Producer<'a, Request, QUEUE_SIZE>,
    }

    struct ResponseReceiver<'a, const QUEUE_SIZE: usize> {
        receiver: Consumer<'a, Response, QUEUE_SIZE>,
    }

    struct RequestReceiver<'a> {
        receiver: Consumer<'a, Request, QUEUE_SIZE>,
    }

    struct ResponseSender<'a> {
        sender: Producer<'a, Response, QUEUE_SIZE>,
    }

    impl<'a> RequestSender<'a, QUEUE_SIZE> {
        fn send(&mut self, request: Request) -> Result<(), Request> {
            self.sender.enqueue(request)
        }
    }

    impl<'a> ResponseReceiver<'a, QUEUE_SIZE> {
        fn recv(&mut self) -> Option<Response> {
            self.receiver.dequeue()
        }
    }

    impl<'a> Receiver for RequestReceiver<'a> {
        fn recv(&mut self) -> Option<Request> {
            self.receiver.dequeue()
        }
    }

    impl<'a> Sender for ResponseSender<'a> {
        fn send(&mut self, response: Response) -> Result<(), Error> {
            self.sender
                .enqueue(response)
                .map_err(|_response| Error::SendResponse)
        }
    }

    #[futures_test::test]
    async fn multiple_clients() {
        // Memory pool
        static mut MEMORY: Memory = [0; Pool::required_memory()];
        static POOL: Pool = Pool::new();
        POOL.init(unsafe { &mut MEMORY }).unwrap();

        // RNG
        let entropy = rng::test::TestEntropySource::default();
        let rng = Rng::new(entropy, None);

        // Queues
        let mut client1_to_host: Queue<Request, QUEUE_SIZE> = Queue::<Request, QUEUE_SIZE>::new();
        let mut client2_to_host: Queue<Request, QUEUE_SIZE> = Queue::<Request, QUEUE_SIZE>::new();
        let mut host_to_client1: Queue<Response, QUEUE_SIZE> = Queue::<Response, QUEUE_SIZE>::new();
        let mut host_to_client2: Queue<Response, QUEUE_SIZE> = Queue::<Response, QUEUE_SIZE>::new();
        let (c1_req_tx, c1_req_rx) = client1_to_host.split();
        let (c2_req_tx, c2_req_rx) = client2_to_host.split();
        let (c1_resp_tx, c1_resp_rx) = host_to_client1.split();
        let (c2_resp_tx, c2_resp_rx) = host_to_client2.split();

        // Channels
        let mut request_sender1 = RequestSender { sender: c1_req_tx };
        let mut request_sender2 = RequestSender { sender: c2_req_tx };
        let mut response_receiver1 = ResponseReceiver {
            receiver: c1_resp_rx,
        };
        let mut response_receiver2 = ResponseReceiver {
            receiver: c2_resp_rx,
        };

        let mut request_receiver1 = RequestReceiver {
            receiver: c1_req_rx,
        };
        let mut response_sender1 = ResponseSender { sender: c1_resp_tx };
        let mut request_receiver2 = RequestReceiver {
            receiver: c2_req_rx,
        };
        let mut response_sender2 = ResponseSender { sender: c2_resp_tx };
        let mut channels = Vec::<(&mut dyn Sender, &mut dyn Receiver), 2>::new();
        if channels
            .push((&mut response_sender1, &mut request_receiver1))
            .is_err()
            || channels
                .push((&mut response_sender2, &mut request_receiver2))
                .is_err()
        {
            panic!("List of return channels is too small");
        }

        // Core
        let mut core = Core::new(&POOL, rng, channels);

        // Send request from client 1
        let size = 65; // Exceed size of a small chunk
        request_sender1
            .send(Request::GetRandom { size })
            .expect("failed to send request");
        core.process_next()
            .await
            .expect("failed to process next request");
        if response_receiver2.recv().is_some() {
            panic!("Received unexpected response to client 2");
        }
        match response_receiver1.recv() {
            Some(response) => match response {
                Response::GetRandom { data } => {
                    assert_eq!(data.len(), size)
                }
                _ => {
                    panic!("Unexpected response type");
                }
            },
            None => {
                panic!("Failed to receive expected response");
            }
        }

        // Send request from client 2
        request_sender2
            .send(Request::GetRandom { size })
            .expect("failed to send request");
        core.process_next()
            .await
            .expect("failed to process next request");
        if response_receiver1.recv().is_some() {
            panic!("Received unexpected response to client 1");
        }
        match response_receiver2.recv() {
            Some(response) => match response {
                Response::GetRandom { data } => {
                    assert_eq!(data.len(), size)
                }
                _ => {
                    panic!("Unexpected response type");
                }
            },
            None => {
                panic!("Failed to receive expected response");
            }
        }
    }
}
