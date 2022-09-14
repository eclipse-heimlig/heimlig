pub mod test {
    use heapless::spsc::{Consumer, Producer, Queue};
    use heapless::Vec;
    use sindri::client::api::HsmApi;
    use sindri::common::jobs::{Request, Response};
    use sindri::common::pool::{Memory, Pool};
    use sindri::crypto::rng::{EntropySource, Rng};
    use sindri::host::core::Core;
    use sindri::{client, host};

    const QUEUE_SIZE: usize = 8;

    struct RequestSender<'a, const QUEUE_SIZE: usize> {
        sender: Producer<'a, Request, QUEUE_SIZE>,
    }

    struct ResponseReceiver<'a, const QUEUE_SIZE: usize> {
        receiver: Consumer<'a, Response, QUEUE_SIZE>,
    }

    struct ResponseSender<'a> {
        id: u32,
        sender: Producer<'a, Response, QUEUE_SIZE>,
    }

    #[derive(Default)]
    pub struct TestEntropySource {}

    impl<'a> client::api::Sender for RequestSender<'a, QUEUE_SIZE> {
        fn send(&mut self, request: Request) -> Result<(), client::api::Error> {
            self.sender
                .enqueue(request)
                .map_err(|_request| client::api::Error::SendRequest)
        }
    }

    impl<'a> client::api::Receiver for ResponseReceiver<'a, QUEUE_SIZE> {
        fn recv(&mut self) -> Option<Response> {
            self.receiver.dequeue()
        }
    }

    impl<'ch> host::core::Sender for ResponseSender<'ch> {
        fn get_id(&self) -> u32 {
            self.id
        }

        fn send(&mut self, response: Response) -> Result<(), host::core::Error> {
            self.sender
                .enqueue(response)
                .map_err(|_response| host::core::Error::SendResponse)
        }
    }

    impl EntropySource for TestEntropySource {
        fn random_seed(&mut self) -> [u8; 32] {
            [0u8; 32]
        }
    }

    #[futures_test::test]
    async fn api_core_communication() {
        // Pool
        static mut MEMORY: Memory = [0; Pool::required_memory()];
        static POOL: Pool = Pool::new();
        POOL.init(unsafe { &mut MEMORY })
            .expect("failed to initialize memory pool");

        // RNG
        let entropy = TestEntropySource::default();
        let rng = Rng::new(entropy, None);

        // Queues
        let mut request_queue: Queue<Request, QUEUE_SIZE> = Queue::new();
        let mut response_queue: Queue<Response, QUEUE_SIZE> = Queue::new();
        let (req_tx, mut req_rx) = request_queue.split();
        let (resp_tx, resp_rx) = response_queue.split();
        let mut hsm = HsmApi {
            request_channel: &mut RequestSender { sender: req_tx },
            response_channel: &mut ResponseReceiver { receiver: resp_rx },
        };
        let channel_id = 0;
        let mut response_sender = ResponseSender {
            id: channel_id,
            sender: resp_tx,
        };
        let mut response_channels = Vec::<&mut dyn host::core::Sender, 2>::new();
        if response_channels.push(&mut response_sender).is_err() {
            panic!("List of return channels is too small");
        }

        // Core
        let mut core = Core::new(&POOL, rng, response_channels);

        // Send request
        let random_len = 16;
        hsm.get_random(random_len)
            .expect("failed to call randomness API");
        let request = req_rx.dequeue().expect("failed to receive request");
        match request {
            Request::GetRandom { size } => assert_eq!(size, random_len),
            _ => panic!("Unexpected request type"),
        }
        core.process(channel_id, request)
            .await
            .expect("failed to process request");

        // Receive response
        let response = hsm.recv_response().expect("failed to receive response");
        match response {
            Response::GetRandom { data } => assert_eq!(data.len(), random_len),
            _ => panic!("Unexpected response type"),
        }
    }
}
