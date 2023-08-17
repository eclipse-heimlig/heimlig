use crate::common::jobs::{OutParam, Request, Response};

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Error {
    /// Attempted to push to a full queue.
    QueueFull,
}

/// Client-side of a bidirectional channel between a client and the HSM core.
pub trait Channel {
    /// Send a [Request] to the HSM core through this channel.
    fn send(&mut self, request: Request) -> Result<(), Error>;
    /// Attempt to receive a [Response] from the HSM core through this channel.
    fn recv(&mut self) -> Option<Response>;
}

/// An interface to send [Request]s to the HSM core and receive [Response]es from it.
pub struct Api<'a, C: Channel> {
    channel: &'a mut C,
}

impl<'a, C: Channel> Api<'a, C> {
    /// Create a new instance of the HSM API.
    pub fn new(channel: &'a mut C) -> Self {
        Api { channel }
    }

    /// Request to fill `data` with random bytes.
    pub fn get_random(&mut self, data: OutParam) -> Result<(), Error> {
        self.channel.send(Request::GetRandom { data })
    }

    /// Attempt to poll a response and return it.
    pub fn recv_response(&mut self) -> Option<Response> {
        self.channel.recv()
    }
}

#[cfg(test)]
mod test {
    use crate::client::api::{Api, Channel, Error};
    use crate::common::jobs::{ExternalMemory, OutParam, Request, Response};
    use crate::common::pool::{Memory, Pool};
    use heapless::spsc::{Consumer, Producer, Queue};

    const QUEUE_SIZE: usize = 8;

    struct HeaplessChannel<'a, const QUEUE_SIZE: usize> {
        sender: Producer<'a, Request, QUEUE_SIZE>,
        receiver: Consumer<'a, Response, QUEUE_SIZE>,
    }

    impl<'a> Channel for HeaplessChannel<'a, QUEUE_SIZE> {
        fn send(&mut self, request: Request) -> Result<(), Error> {
            self.sender
                .enqueue(request)
                .map_err(|_request| Error::QueueFull)
        }

        fn recv(&mut self) -> Option<Response> {
            self.receiver.dequeue()
        }
    }

    #[test]
    fn send_request() {
        static mut MEMORY: Memory = [0; Pool::required_memory()];
        let pool =
            Pool::try_from(unsafe { &mut MEMORY }).expect("failed to initialize memory pool");
        let mut request_queue: Queue<Request, QUEUE_SIZE> = Queue::new();
        let mut response_queue: Queue<Response, QUEUE_SIZE> = Queue::new();
        let (req_tx, mut req_rx) = request_queue.split();
        let (mut resp_tx, resp_rx) = response_queue.split();
        let mut channel = HeaplessChannel {
            sender: req_tx,
            receiver: resp_rx,
        };
        let mut api = Api::new(&mut channel);

        // Send request
        let random_len = 16;
        let data = pool.alloc(random_len).expect("failed to allocate");
        api.get_random(OutParam::new(ExternalMemory::from_slice(data.as_slice())))
            .expect("failed to call randomness API");
        let request = req_rx.dequeue().expect("failed to receive request");
        let random_buffer = match request {
            Request::GetRandom { data } => data,
            _ => panic!("Unexpected request type"),
        };

        assert_eq!(random_buffer.as_slice().len(), random_len);

        // Receive response
        resp_tx
            .enqueue(Response::GetRandom {
                data: random_buffer,
            })
            .expect("failed to send response");
        let response = api.recv_response().expect("failed to receive response");
        match response {
            Response::GetRandom { data } => assert_eq!(data.as_slice().len(), random_len),
            _ => panic!("Unexpected response type"),
        }
    }
}
