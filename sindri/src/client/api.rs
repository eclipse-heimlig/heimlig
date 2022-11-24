use crate::common::jobs::{Request, Response};

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Error {
    SendRequest,
    RecvResponse,
}

pub trait Sender {
    /// Send a request to the HSM core through this channel.
    fn send(&mut self, request: Request) -> Result<(), Error>;
}

pub trait Receiver {
    /// Receive a response from the HSM core through this channel.
    fn recv(&mut self) -> Option<Response>;
}

pub struct HsmApi<'a> {
    pub request_channel: &'a mut dyn Sender,
    pub response_channel: &'a mut dyn Receiver,
}

impl<'a> HsmApi<'a> {
    pub fn get_random(&mut self, size: usize) -> Result<(), Error> {
        self.request_channel.send(Request::GetRandom { size })
    }

    pub fn recv_response(&mut self) -> Option<Response> {
        self.response_channel.recv()
    }
}

#[cfg(test)]
mod test {
    use crate::client::api::{Error, HsmApi, Receiver, Sender};
    use crate::common::jobs::{Request, Response};
    use crate::common::pool::{Memory, Pool};
    use heapless::spsc::{Consumer, Producer, Queue};

    const QUEUE_SIZE: usize = 8;

    struct RequestSender<'a, const QUEUE_SIZE: usize> {
        sender: Producer<'a, Request, QUEUE_SIZE>,
    }

    struct ResponseReceiver<'a, const QUEUE_SIZE: usize> {
        receiver: Consumer<'a, Response, QUEUE_SIZE>,
    }

    impl<'a> Sender for RequestSender<'a, QUEUE_SIZE> {
        fn send(&mut self, request: Request) -> Result<(), Error> {
            self.sender
                .enqueue(request)
                .map_err(|_request| Error::SendRequest)
        }
    }

    impl<'a> Receiver for ResponseReceiver<'a, QUEUE_SIZE> {
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
        let mut hsm = HsmApi {
            request_channel: &mut RequestSender { sender: req_tx },
            response_channel: &mut ResponseReceiver { receiver: resp_rx },
        };

        // Send request
        let random_len = 16;
        hsm.get_random(random_len)
            .expect("failed to call randomness API");
        let request = req_rx.dequeue().expect("failed to receive request");
        match request {
            Request::GetRandom { size } => assert_eq!(size, random_len),
            _ => panic!("Unexpected request type"),
        }

        // Receive response
        let data = pool.alloc(random_len).expect("failed to allocate");
        resp_tx
            .enqueue(Response::GetRandom { data })
            .expect("failed to send response");
        let response = hsm.recv_response().expect("failed to receive response");
        match response {
            Response::GetRandom { data } => assert_eq!(data.len(), random_len),
            _ => panic!("Unexpected response type"),
        }
    }
}
