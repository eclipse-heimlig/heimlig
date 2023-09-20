use crate::common::jobs::{Request, Response};
use futures::{Sink, SinkExt, Stream, StreamExt};

/// An interface to send [Request]s to the HSM core and receive [Response]es from it.
pub struct Api<'data, Req: Sink<Request<'data>>, Resp: Stream<Item = Response<'data>>> {
    requests: Req,
    responses: Resp,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Error {
    Send,
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
            .map_err(|_e| Error::Send)
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
    use crate::integration::embassy::{RequestQueueSink, ResponseQueueSource};
    use embassy_sync::blocking_mutex::raw::NoopRawMutex;
    use heapless::spsc::Queue;

    const QUEUE_SIZE: usize = 8;

    #[async_std::test]
    async fn send_request() {
        const REQUEST_SIZE: usize = 16;
        let mut random_output = [0u8; REQUEST_SIZE];
        let mut random_output_response = [0u8; REQUEST_SIZE];

        let mut requests = Queue::<Request, QUEUE_SIZE>::new();
        let mut responses = Queue::<Response, QUEUE_SIZE>::new();

        let (requests_tx, mut requests_rx) = requests.split();
        let (mut responses_tx, responses_rx) = responses.split();

        let requests: RequestQueueSink<NoopRawMutex, QUEUE_SIZE> =
            RequestQueueSink::new(requests_tx);
        let responses: ResponseQueueSource<NoopRawMutex, QUEUE_SIZE> =
            ResponseQueueSource::new(responses_rx);

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
