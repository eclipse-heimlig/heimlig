mod test {
    use heapless::spsc::{Consumer, Producer, Queue};
    use heimlig::client::api::Api;
    use heimlig::common::jobs::{Request, Response};
    use heimlig::common::pool::{Memory, Pool};
    use heimlig::config::keystore::{KEY1, KEY2, KEY3};
    use heimlig::crypto::rng::{EntropySource, Rng};
    use heimlig::hsm::core::Core;
    use heimlig::hsm::keystore::MemoryKeyStore;
    use heimlig::{client, config, hsm};

    #[derive(Default)]
    pub struct TestEntropySource {}

    impl EntropySource for TestEntropySource {
        fn random_seed(&mut self) -> [u8; 32] {
            [0u8; 32]
        }
    }

    struct ChannelClientSide<'a, const QUEUE_SIZE: usize> {
        sender: Producer<'a, Request, QUEUE_SIZE>,
        receiver: Consumer<'a, Response, QUEUE_SIZE>,
    }

    struct ChannelCoreSide<'a, const QUEUE_SIZE: usize> {
        sender: Producer<'a, Response, QUEUE_SIZE>,
        receiver: Consumer<'a, Request, QUEUE_SIZE>,
    }

    const QUEUE_SIZE: usize = 8;

    impl<'a> client::api::Channel for ChannelClientSide<'a, QUEUE_SIZE> {
        fn send(&mut self, request: Request) -> Result<(), client::api::Error> {
            self.sender
                .enqueue(request)
                .map_err(|_request| client::api::Error::QueueFull)
        }

        fn recv(&mut self) -> Option<Response> {
            self.receiver.dequeue()
        }
    }

    impl<'a> hsm::core::Channel for ChannelCoreSide<'a, QUEUE_SIZE> {
        fn send(&mut self, response: Response) -> Result<(), hsm::core::Error> {
            self.sender
                .enqueue(response)
                .map_err(|_response| hsm::core::Error::QueueFull)
        }

        fn recv(&mut self) -> Option<Request> {
            self.receiver.dequeue()
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

        // Channels
        let mut client_side = ChannelClientSide {
            sender: req_tx,
            receiver: resp_rx,
        };
        let core_side = ChannelCoreSide {
            sender: resp_tx,
            receiver: req_rx,
        };
        let mut channels = heapless::Vec::<_, 1>::new();
        let _ = channels.push(core_side);

        // Core
        let key_infos = [KEY1, KEY2, KEY3];
        let mut key_store = MemoryKeyStore::<
            { config::keystore::TOTAL_SIZE },
            { config::keystore::NUM_KEYS },
        >::try_new(&key_infos)
        .expect("failed to create key store");
        let mut core = Core::new(&pool, rng, channels, Some(&mut key_store));

        // Api
        let mut api = Api::new(&mut client_side);

        // Send request
        let random_size = 16;
        api.get_random(random_size)
            .expect("failed to call randomness API");
        core.process_next().expect("failed to process next request");

        // Receive response
        let response = api.recv_response().expect("failed to receive response");
        match response {
            Response::GetRandom { data } => assert_eq!(data.len(), random_size),
            _ => panic!("Unexpected response type"),
        }
    }
}
