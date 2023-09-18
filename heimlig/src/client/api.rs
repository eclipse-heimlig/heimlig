use crate::common::jobs::{Request, Response};
use crate::common::queues;
use futures::{Sink, SinkExt, Stream, StreamExt};

/// An interface to send [Request]s to the HSM core and receive [Response]es from it.
pub struct Api<'data, Req: Sink<Request<'data>>, Resp: Stream<Item = Response<'data>>> {
    requests: Req,
    responses: Resp,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Error {
    Queue(queues::Error),
}

impl<
        'data,
        Req: Sink<Request<'data>> + core::marker::Unpin,
        Resp: Stream<Item = Response<'data>> + core::marker::Unpin,
    > Api<'data, Req, Resp>
{
    /// Create a new instance of the HSM API.
    pub fn new(requests: Req, responses: Resp) -> Self {
        Api {
            requests,
            responses,
        }
    }

    /// Request `size` many random bytes.
    pub async fn get_random(&mut self, output: &'data mut [u8]) -> Result<(), Error> {
        self.requests
            .send(Request::GetRandom { output })
            .await
            .map_err(|_e| Error::Queue(queues::Error::Enqueue))
    }

    /// Attempt to poll a response and return it.
    pub async fn recv_response(&mut self) -> Option<Response> {
        self.responses.next().await
    }
}

#[cfg(test)]
mod test {
    use crate::client::api::Api;
    use crate::common::jobs::{Request, Response};
    use core::cell::RefCell;
    use core::pin::Pin;
    use core::task::Context;
    use core::task::Poll;
    use embassy_sync::blocking_mutex;
    use embassy_sync::blocking_mutex::raw::NoopRawMutex;
    use embassy_sync::blocking_mutex::raw::RawMutex;
    use embassy_sync::waitqueue::WakerRegistration;
    use heapless::spsc::{Consumer, Producer, Queue};

    const QUEUE_SIZE: usize = 8;

    struct RequestQueueSink<'ch, 'data, M: RawMutex + Unpin> {
        producer: Producer<'ch, Request<'data>, QUEUE_SIZE>,
        receiver_waker: blocking_mutex::Mutex<M, RefCell<WakerRegistration>>,
        sender_waker: blocking_mutex::Mutex<M, RefCell<WakerRegistration>>,
    }

    impl<'data, M: RawMutex + Unpin> futures::Sink<Request<'data>> for RequestQueueSink<'_, 'data, M> {
        type Error = ();

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            if self.producer.ready() {
                Poll::Ready(Ok(()))
            } else {
                self.sender_waker.lock(|w| w.borrow_mut().wake());
                Poll::Pending
            }
        }

        fn start_send(self: Pin<&mut Self>, request: Request<'data>) -> Result<(), Self::Error> {
            self.receiver_waker.lock(|w| w.borrow_mut().wake());
            let _request = self.get_mut().producer.enqueue(request);
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    impl<'ch, 'data, M: RawMutex + Unpin> RequestQueueSink<'ch, 'data, M> {
        pub fn new(requests: Producer<'ch, Request<'data>, QUEUE_SIZE>) -> Self {
            RequestQueueSink {
                producer: requests,
                receiver_waker: blocking_mutex::Mutex::new(RefCell::new(WakerRegistration::new())),
                sender_waker: blocking_mutex::Mutex::new(RefCell::new(WakerRegistration::new())),
            }
        }
    }

    struct ResponseQueueSource<'ch, 'data, M: RawMutex + Unpin> {
        consumer: Consumer<'ch, Response<'data>, QUEUE_SIZE>,
        senders_waker: blocking_mutex::Mutex<M, RefCell<WakerRegistration>>,
    }

    impl<'data, M: RawMutex + Unpin> futures::Stream for ResponseQueueSource<'_, 'data, M> {
        type Item = Response<'data>;

        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            self.senders_waker.lock(|w| w.borrow_mut().wake());
            // No need to return pending and wake a receiver waker as dequeue() always returns directly
            Poll::Ready(self.get_mut().consumer.dequeue())
        }
    }

    impl<'ch, 'data, M: RawMutex + Unpin> ResponseQueueSource<'ch, 'data, M> {
        pub fn new(responses: Consumer<'ch, Response<'data>, QUEUE_SIZE>) -> Self {
            ResponseQueueSource {
                consumer: responses,
                senders_waker: blocking_mutex::Mutex::new(RefCell::new(WakerRegistration::new())),
            }
        }
    }

    #[async_std::test]
    async fn send_request() {
        const REQUEST_SIZE: usize = 16;
        let mut random_output = [0u8; REQUEST_SIZE];
        let mut random_output_response = [0u8; REQUEST_SIZE];

        let mut requests = Queue::<Request, QUEUE_SIZE>::new();
        let mut responses = Queue::<Response, QUEUE_SIZE>::new();

        let (requests_tx, mut requests_rx) = requests.split();
        let (mut responses_tx, responses_rx) = responses.split();

        let requests: RequestQueueSink<NoopRawMutex> = RequestQueueSink::new(requests_tx);
        let responses: ResponseQueueSource<NoopRawMutex> = ResponseQueueSource::new(responses_rx);

        let mut api = Api::new(requests, responses);

        // Send request
        api.get_random(&mut random_output)
            .await
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
        let response = api
            .recv_response()
            .await
            .expect("failed to receive response");
        match response {
            Response::GetRandom { data } => assert_eq!(data.len(), REQUEST_SIZE),
            _ => panic!("Unexpected response type"),
        }
    }
}
