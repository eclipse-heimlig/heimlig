use crate::common::jobs::{Request, Response};
use crate::common::pool::PoolChunk;
use crate::crypto::rng::{EntropySource, Rng};
use crate::host::scheduler::{Job, Scheduler};
use heapless::pool::Pool;
use heapless::{LinearMap, Vec};

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Error {
    Busy,
    UnknownId,
}

pub struct Core<
    'a,
    E: EntropySource,
    const MAX_CLIENTS: usize = 8,
    const MAX_PENDING_RESPONSES: usize = 16,
> {
    scheduler: Scheduler<E>,
    response_channels: Vec<&'a mut dyn Sender, MAX_CLIENTS>,
    requester_to_job_ids: LinearMap<u32, u32, MAX_PENDING_RESPONSES>,
    request_counter: u32,
}

pub trait Sender {
    /// Unique ID of the sender. Used to determine the proper response channel once a request has been processed.
    fn get_id(&self) -> u32;

    /// Send a response through this channel back to the requester.
    fn send(&mut self, response: Response);
}

impl<'a, E: EntropySource, const MAX_CLIENTS: usize> Core<'a, E, MAX_CLIENTS> {
    /// Create a new HSM core. The core accepts requests and forwards the responses once they are ready.
    ///
    /// # Arguments
    ///
    /// * `rng`: Random number generator (RNG) used to seed the core RNG.
    /// * `response_channels`: List of channels to send responses back to the clients.
    pub fn new(
        pool: Pool<PoolChunk>,
        rng: Rng<E>,
        response_channels: Vec<&mut dyn Sender, MAX_CLIENTS>,
    ) -> Core<E, MAX_CLIENTS> {
        Core {
            scheduler: Scheduler { pool, rng },
            response_channels,
            requester_to_job_ids: Default::default(),
            request_counter: 0,
        }
    }

    pub async fn process(&mut self, requester_id: u32, request: Request) -> Result<(), Error> {
        let job = self.new_job(request);

        // Associate job ID with sender ID to determine response channel later
        if self
            .requester_to_job_ids
            .insert(job.id, requester_id)
            .is_err()
        {
            return Err(Error::Busy);
        }

        // TODO: retrieve response asynchronously
        let result = self.scheduler.schedule(job).await;

        // Get sender ID for job ID and send response
        if let Some(requester_id) = self.requester_to_job_ids.remove(&result.id) {
            if let Some(response_channel) = self
                .response_channels
                .iter_mut()
                .find(|s| s.get_id() == requester_id)
            {
                response_channel.send(result.response);
            }
            Ok(())
        } else {
            Err(Error::UnknownId)
        }
    }

    fn new_job(&mut self, request: Request) -> Job {
        self.request_counter += 1; // Wrapping OK. Counter is used for IDs only.
        Job {
            id: self.request_counter,
            request,
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use crate::common::jobs::{Request, Response};
    use crate::common::pool::{PoolChunk, MAX_CHUNKS, POOL_CHUNK_SIZE};
    use crate::crypto::rng;
    use crate::host::core::{Core, Sender};
    use heapless::spsc::{Consumer, Producer, Queue};

    const QUEUE_SIZE: usize = 8;

    struct ResponseReceiver<'a> {
        receiver: Consumer<'a, Response, QUEUE_SIZE>,
    }

    struct ResponseSender<'a> {
        id: u32,
        sender: Producer<'a, Response, QUEUE_SIZE>,
    }

    impl<'ch> Sender for ResponseSender<'ch> {
        fn get_id(&self) -> u32 {
            self.id
        }

        fn send(&mut self, response: Response) {
            let _response = self.sender.enqueue(response);
        }
    }

    impl<'ch> ResponseReceiver<'ch> {
        fn recv(&mut self) -> Option<Response> {
            self.receiver.dequeue()
        }
    }

    #[futures_test::test]
    async fn multiple_clients() {
        // Memory pool
        static mut MEMORY: [u8; MAX_CHUNKS * POOL_CHUNK_SIZE] = [0; MAX_CHUNKS * POOL_CHUNK_SIZE];
        let pool = heapless::pool::Pool::<PoolChunk>::new();
        unsafe {
            pool.grow(&mut MEMORY);
        }

        // RNG
        let entropy = rng::test::TestEntropySource::default();
        let rng = rng::Rng::new(entropy, None);

        // Queue
        let mut host_to_client1: Queue<Response, QUEUE_SIZE> = Queue::<Response, QUEUE_SIZE>::new();
        let mut host_to_client2: Queue<Response, QUEUE_SIZE> = Queue::<Response, QUEUE_SIZE>::new();
        let (h2c1_p, h2c1_c) = host_to_client1.split();
        let (h2c2_p, h2c2_c) = host_to_client2.split();
        let mut response_receiver1 = ResponseReceiver { receiver: h2c1_c };
        let mut response_receiver2 = ResponseReceiver { receiver: h2c2_c };
        let mut response_sender1 = ResponseSender {
            id: 0,
            sender: h2c1_p,
        };
        let mut response_sender2 = ResponseSender {
            id: 1,
            sender: h2c2_p,
        };
        let mut response_channels = heapless::Vec::<&mut dyn Sender, 2>::new();
        if response_channels.push(&mut response_sender1).is_err()
            || response_channels.push(&mut response_sender2).is_err()
        {
            panic!("List of return channels not large enough");
        }

        // Create core
        let mut core = Core::new(pool, rng, response_channels);

        // Send request from client 0
        let size = 32;
        let request = Request::GetRandom { size };
        assert!(matches!(core.process(0, request.clone()).await, Ok(())));
        if response_receiver2.recv().is_some() {
            panic!("Received unexpected response");
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

        // Send request from client 1
        assert!(matches!(core.process(1, request).await, Ok(())));
        if response_receiver1.recv().is_some() {
            panic!("Received unexpected response");
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
