mod test {
    use heapless::spsc::{Consumer, Producer, Queue};
    use heapless::Vec;
    use sindri::client::api::HsmApi;
    use sindri::common::jobs::{Request, Response};
    use sindri::common::pool::{Memory, Pool};
    use sindri::config::keystore::{KEY1, KEY2, KEY3};
    use sindri::crypto::rng::{EntropySource, Rng};
    use sindri::host::core::{Channel, Core};
    use sindri::host::keystore::MemoryKeyStore;
    use sindri::{client, config, host};

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
                .map_err(|_request| client::api::Error::QueueFull)
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
                .map_err(|_response| host::core::Error::QueueFull)
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
        let pool = Pool::try_from(unsafe { &mut MEMORY }).unwrap();

        // RNG
        let entropy = TestEntropySource::default();
        let rng = Rng::new(entropy, None);

        // Queues
        let mut request_queue: Queue<Request, QUEUE_SIZE> = Queue::new();
        let mut response_queue: Queue<Response, QUEUE_SIZE> = Queue::new();
        let (req_tx, req_rx) = request_queue.split();
        let (resp_tx, resp_rx) = response_queue.split();
        let mut request_sender = RequestSender { sender: req_tx };
        let mut response_receiver = ResponseReceiver { receiver: resp_rx };
        let mut request_receiver = RequestReceiver { receiver: req_rx };
        let mut response_sender = ResponseSender { sender: resp_tx };
        let mut hsm = HsmApi::new(&mut request_sender, &mut response_receiver);
        let mut channels = Vec::<Channel, 2>::new();
        if channels
            .push(Channel::new(&mut response_sender, &mut request_receiver))
            .is_err()
        {
            panic!("List of return channels is too small");
        }

        // Core
        let key_infos = [KEY1, KEY2, KEY3];
        let mut key_store = MemoryKeyStore::<
            { config::keystore::TOTAL_SIZE },
            { config::keystore::NUM_KEYS },
        >::try_new(&key_infos)
        .expect("failed to create key store");
        let mut core = Core::new(&pool, rng, channels, Some(&mut key_store));

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
