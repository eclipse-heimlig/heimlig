mod test {
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
        sender: Producer<'a, Response, QUEUE_SIZE>,
    }

    struct RequestReceiver<'a> {
        receiver: Consumer<'a, Request, QUEUE_SIZE>,
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

    impl<'a> host::core::Sender for ResponseSender<'a> {
        fn send(&mut self, response: Response) -> Result<(), host::core::Error> {
            self.sender
                .enqueue(response)
                .map_err(|_response| host::core::Error::SendResponse)
        }
    }

    impl<'a> host::core::Receiver for RequestReceiver<'a> {
        fn recv(&mut self) -> Option<Request> {
            self.receiver.dequeue()
        }
    }

    impl EntropySource for TestEntropySource {
        fn random_seed(&mut self) -> [u8; 32] {
            [0u8; 32]
        }
    }

    #[test]
    fn api_core_communication() {
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
        let (req_tx, req_rx) = request_queue.split();
        let (resp_tx, resp_rx) = response_queue.split();
        let mut hsm = HsmApi {
            request_channel: &mut RequestSender { sender: req_tx },
            response_channel: &mut ResponseReceiver { receiver: resp_rx },
        };
        let mut request_receiver = RequestReceiver { receiver: req_rx };
        let mut response_sender = ResponseSender { sender: resp_tx };
        let mut channels =
            Vec::<(&mut dyn host::core::Sender, &mut dyn host::core::Receiver), 2>::new();
        if channels
            .push((&mut response_sender, &mut request_receiver))
            .is_err()
        {
            panic!("List of return channels is too small");
        }

        // Core
        let mut core = Core::new(&POOL, rng, channels);

        // Send request
        let random_size = 16;
        hsm.get_random(random_size)
            .expect("failed to call randomness API");
        core.process_next().expect("failed to process next request");

        // Receive response
        let response = hsm.recv_response().expect("failed to receive response");
        match response {
            Response::GetRandom { data } => assert_eq!(data.len(), random_size),
            _ => panic!("Unexpected response type"),
        }
    }
}
