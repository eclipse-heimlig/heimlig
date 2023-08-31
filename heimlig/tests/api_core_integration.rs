mod test {
    use heapless::spsc::{Consumer, Producer, Queue};
    use heimlig::client::api::{Api, RequestSink};
    use heimlig::common::jobs::{Request, Response};
    use heimlig::config;
    use heimlig::config::keystore::{KEY1, KEY2, KEY3};
    use heimlig::crypto::rng::{EntropySource, Rng};
    use heimlig::hsm::core::{Core, ResponseSink};
    use heimlig::hsm::keystore::MemoryKeyStore;

    #[derive(Default)]
    pub struct TestEntropySource {}

    impl EntropySource for TestEntropySource {
        fn random_seed(&mut self) -> [u8; 32] {
            [0u8; 32]
        }
    }

    const QUEUE_SIZE: usize = 8;

    struct RequestQueueSink<'ch, 'a> {
        producer: Producer<'ch, Request<'a>, QUEUE_SIZE>,
    }

    impl<'a> RequestSink<'a> for RequestQueueSink<'_, 'a> {
        fn send(&mut self, request: Request<'a>) -> Result<(), heimlig::client::api::Error> {
            self.producer
                .enqueue(request)
                .map_err(|_| heimlig::client::api::Error::QueueFull)
        }

        fn ready(&self) -> bool {
            self.producer.ready()
        }
    }

    struct RequestQueueSource<'ch, 'a> {
        consumer: Consumer<'ch, Request<'a>, QUEUE_SIZE>,
    }

    impl<'a> Iterator for RequestQueueSource<'_, 'a> {
        type Item = Request<'a>;

        fn next(&mut self) -> Option<Self::Item> {
            self.consumer.dequeue()
        }
    }

    struct ResponseQueueSink<'ch, 'a> {
        producer: Producer<'ch, Response<'a>, QUEUE_SIZE>,
    }

    impl<'a> ResponseSink<'a> for ResponseQueueSink<'_, 'a> {
        fn send(&mut self, response: Response<'a>) -> Result<(), heimlig::hsm::core::Error> {
            self.producer
                .enqueue(response)
                .map_err(|_| heimlig::hsm::core::Error::QueueFull)
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
    fn api_core_communication() {
        const REQUEST_SIZE: usize = 16;
        let mut random_output = [0u8; REQUEST_SIZE];
        // RNG
        let entropy = TestEntropySource::default();
        let rng = Rng::new(entropy, None);

        // Queues
        let mut requests = Queue::<Request, QUEUE_SIZE>::new();
        let mut responses = Queue::<Response, QUEUE_SIZE>::new();

        let (requests_tx, requests_rx) = requests.split();
        let (responses_tx, responses_rx) = responses.split();

        let requests_source = RequestQueueSource {
            consumer: requests_rx,
        };
        let requests_sink = RequestQueueSink {
            producer: requests_tx,
        };

        let responses_sink = ResponseQueueSink {
            producer: responses_tx,
        };
        let responses_source = ResponseQueueSource {
            consumer: responses_rx,
        };

        // Core
        let key_infos = [KEY1, KEY2, KEY3];
        let key_store = MemoryKeyStore::<
            { config::keystore::TOTAL_SIZE },
            { config::keystore::NUM_KEYS },
        >::try_new(&key_infos)
        .expect("failed to create key store");
        let mut core = Core::new(rng, requests_source.enumerate(), responses_sink, key_store);

        // Api
        let mut api = Api::new(requests_sink, responses_source);

        // Send request
        api.get_random(&mut random_output)
            .expect("failed to call randomness API");
        core.process_next().expect("failed to process next request");

        // Receive response
        let response = api.recv_response().expect("failed to receive response");
        match response {
            Response::GetRandom { data } => assert_eq!(data.len(), REQUEST_SIZE),
            _ => panic!("Unexpected response type"),
        }
    }
}
