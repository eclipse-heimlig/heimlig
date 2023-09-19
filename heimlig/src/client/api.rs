use crate::common::jobs::{Request, Response};
use crate::common::queues;
use crate::common::queues::RequestSink;

/// An interface to send [Request]s to the HSM core and receive [Response]es from it.
pub struct Api<'a, Req: RequestSink<'a>, Resp: Iterator<Item = Response<'a>>> {
    requests: Req,
    responses: Resp,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Error {
    Queue(queues::Error),
}

impl<'a, Req: RequestSink<'a>, Resp: Iterator<Item = Response<'a>>> Api<'a, Req, Resp> {
    /// Create a new instance of the HSM API.
    pub fn new(requests: Req, responses: Resp) -> Self {
        Api {
            requests,
            responses,
        }
    }

    /// Request `size` many random bytes.
    pub fn get_random(&mut self, output: &'a mut [u8]) -> Result<(), Error> {
        if !self.requests.ready() {
            return Err(Error::Queue(queues::Error::NotReady));
        }
        self.requests
            .send(Request::GetRandom { output })
            .map_err(Error::Queue)
    }

    /// Attempt to poll a response and return it.
    pub fn recv_response(&mut self) -> Option<Response> {
        self.responses.next()
    }
}

#[cfg(test)]
mod test {
    use crate::client::api::{Api, RequestSink};
    use crate::common::jobs::{Request, Response};
    use crate::common::queues;
    use heapless::spsc::{Consumer, Producer, Queue};

    const QUEUE_SIZE: usize = 8;

    struct RequestQueueSink<'ch, 'a> {
        producer: Producer<'ch, Request<'a>, QUEUE_SIZE>,
    }

    impl<'a> RequestSink<'a> for RequestQueueSink<'_, 'a> {
        fn send(&mut self, request: Request<'a>) -> Result<(), queues::Error> {
            self.producer
                .enqueue(request)
                .map_err(|_| queues::Error::Enqueue)
        }

        fn ready(&self) -> bool {
            self.producer.ready()
        }
    }

    struct ResponseQueueSource<'ch, 'a> {
        consumer: Consumer<'ch, Response<'a>, QUEUE_SIZE>,
    }

    impl<'a> Iterator for ResponseQueueSource<'_, 'a> {
        type Item = Response<'a>;

        fn next(&mut self) -> Option<Self::Item> {
            self.consumer.dequeue()
        }
    }

    #[test]
    fn send_request() {
        const REQUEST_SIZE: usize = 16;
        let mut random_output = [0u8; REQUEST_SIZE];
        let mut random_output_response = [0u8; REQUEST_SIZE];

        let mut requests = Queue::<Request, QUEUE_SIZE>::new();
        let mut responses = Queue::<Response, QUEUE_SIZE>::new();

        let (requests_tx, mut requests_rx) = requests.split();
        let (mut responses_tx, responses_rx) = responses.split();

        let requests = RequestQueueSink {
            producer: requests_tx,
        };

        let responses = ResponseQueueSource {
            consumer: responses_rx,
        };

        let mut api = Api::new(requests, responses);

        // Send request
        api.get_random(&mut random_output)
            .expect("failed to call randomness API");
        let request = requests_rx.dequeue().expect("failed to receive request");
        match request {
            Request::GetRandom { output } => assert_eq!(output.len(), REQUEST_SIZE),
            _ => panic!("Unexpected request type"),
        }

        // Receive response
        responses_tx
            .enqueue(Response::GetRandom {
                data: &mut random_output_response,
            })
            .expect("failed to send response");
        let response = api.recv_response().expect("failed to receive response");
        match response {
            Response::GetRandom { data } => assert_eq!(data.len(), REQUEST_SIZE),
            _ => panic!("Unexpected response type"),
        }
    }
}
