use crate::common::jobs::{Request, Response};
use crate::common::pool::Pool;
use crate::crypto::rng::{EntropySource, Rng};
use crate::host::keystore::KeyStore;
use crate::host::scheduler::{Job, Scheduler};
use heapless::Vec;

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Error {
    /// No [Channel] found for given ID.
    UnknownChannelId,
    /// Attempted to push to a full queue.
    QueueFull,
}

pub trait Sender {
    /// Send a [Response] to the client through this channel.
    fn send(&mut self, response: Response) -> Result<(), Error>;
}

pub trait Receiver {
    /// Attempt to receive a [Request] from the client through this channel.
    fn recv(&mut self) -> Option<Request>;
}

/// The core-side of a bidirectional channel between the HSM core and a client.
pub struct Channel<'a> {
    sender: &'a mut dyn Sender,
    receiver: &'a mut dyn Receiver,
}

impl<'a> Channel<'a> {
    /// Create a new core-side end of a channel.
    pub fn new(sender: &'a mut dyn Sender, receiver: &'a mut dyn Receiver) -> Self {
        Channel { sender, receiver }
    }

    /// Send a [Response] to the client through this channel.
    pub fn send(&mut self, response: Response) -> Result<(), Error> {
        self.sender.send(response)
    }

    /// Attempt to receive a [Request] from the client through this channel.
    pub fn recv(&mut self) -> Option<Request> {
        self.receiver.recv()
    }
}

/// HSM core that waits for [Request]s from [Channel]s and send [Response]s once they are ready.   
pub struct Core<
    'a,
    E: EntropySource,
    const MAX_CLIENTS: usize = 8,
    const MAX_PENDING_RESPONSES: usize = 16,
> {
    scheduler: Scheduler<'a, E>,
    channels: Vec<Channel<'a>, MAX_CLIENTS>,
    last_channel_id: usize,
}

impl<'a, E: EntropySource, const MAX_CLIENTS: usize> Core<'a, E, MAX_CLIENTS> {
    /// Create a new HSM core.
    /// The core accepts requests and forwards the responses once they are ready.
    ///
    /// # Arguments
    ///
    /// * `rng`: Random number generator (RNG) used to seed the core RNG.
    /// * `response_channels`: List of [Channel]s to send responses back to the clients.
    /// * `key_store`: The [KeyStore] to hold cryptographic key material.
    pub fn new(
        pool: &'a Pool,
        rng: Rng<E>,
        channels: Vec<Channel<'a>, MAX_CLIENTS>,
        key_store: Option<&'a mut dyn KeyStore>,
    ) -> Core<'a, E, MAX_CLIENTS> {
        Core {
            scheduler: Scheduler::new(pool, rng, key_store),
            channels,
            last_channel_id: 0,
        }
    }

    /// Create a new HSM core.
    /// This variant does not configure a [KeyStore] so this core will not be able to store
    /// cryptographic material.
    ///
    /// # Arguments
    ///
    /// * `rng`: Random number generator (RNG) used to seed the core RNG.
    /// * `response_channels`: List of [Channel]s to send responses back to the clients.
    pub fn new_without_key_store(
        pool: &'a Pool,
        rng: Rng<E>,
        channels: Vec<Channel<'a>, MAX_CLIENTS>,
    ) -> Core<'a, E, MAX_CLIENTS> {
        Self::new(pool, rng, channels, None)
    }

    /// Search all input channels for a new request and process it.
    /// Channels are processed in a round-robin fashion.
    ///
    /// # Returns
    ///
    /// * `Ok(true)` if a [Request] was found and successfully processed.
    /// * `Ok(false)` if no [Request] was found in any input [Channel].
    /// * `Err(core::Error)` if a processing error occurred.
    pub fn process_next(&mut self) -> Result<(), Error> {
        let total_channels = self.channels.len();
        for channel_id in 0..total_channels {
            // Go through channels starting after the last used channel
            let channel_id = (channel_id + self.last_channel_id + 1) % total_channels;
            let channel = &mut self.channels[channel_id];
            if let Some(request) = channel.receiver.recv() {
                self.last_channel_id = channel_id;
                return self.process(channel_id, request);
            }
        }
        Ok(()) // Nothing to process
    }

    fn process(&mut self, channel_id: usize, request: Request) -> Result<(), Error> {
        // Schedule job
        let job = Job {
            channel_id,
            request,
        };
        // TODO: Retrieve result asynchronously
        let result = self.scheduler.schedule(job);

        // Send response
        let channel = self
            .channels
            .get_mut(result.channel_id)
            .ok_or(Error::UnknownChannelId)?;
        channel.sender.send(result.response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::pool::Memory;
    use crate::config;
    use crate::config::keystore::{KEY1, KEY2, KEY3};
    use crate::crypto::rng;
    use crate::host::core::Sender;
    use crate::host::keystore::MemoryKeyStore;
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
                .map_err(|_response| Error::QueueFull)
        }
    }

    #[test]
    fn multiple_clients() {
        // Memory pool
        static mut MEMORY: Memory = [0; Pool::required_memory()];
        let pool = Pool::try_from(unsafe { &mut MEMORY }).unwrap();

        // RNG
        let entropy = rng::test::TestEntropySource::default();
        let rng = Rng::new(entropy, None);

        // Queues
        let mut client1_to_host: Queue<Request, QUEUE_SIZE> = Queue::new();
        let mut client2_to_host: Queue<Request, QUEUE_SIZE> = Queue::new();
        let mut host_to_client1: Queue<Response, QUEUE_SIZE> = Queue::new();
        let mut host_to_client2: Queue<Response, QUEUE_SIZE> = Queue::new();
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
        let mut channels = Vec::<Channel, 2>::new();
        if channels
            .push(Channel::new(&mut response_sender1, &mut request_receiver1))
            .is_err()
            || channels
                .push(Channel::new(&mut response_sender2, &mut request_receiver2))
                .is_err()
        {
            panic!("Failed to create list of channels");
        }

        // Core
        let key_infos = [KEY1, KEY2, KEY3];
        let mut key_store = MemoryKeyStore::<
            { config::keystore::TOTAL_SIZE },
            { config::keystore::NUM_KEYS },
        >::try_new(&key_infos)
        .expect("failed to create key store");
        let mut core = Core::new(&pool, rng, channels, Some(&mut key_store));

        // Send request from client 1
        let size = 65; // Exceed size of a small chunk
        request_sender1
            .send(Request::GetRandom { size })
            .expect("failed to send request");
        core.process_next().expect("failed to process next request");
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
        core.process_next().expect("failed to process next request");
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
