mod tests {
    use core::iter::Enumerate;
    use embassy_sync::blocking_mutex::raw::{NoopRawMutex, RawMutex};
    use embassy_sync::mutex::Mutex;
    use heapless::spsc::{Consumer, Producer, Queue};
    use heimlig::common::jobs;
    use heimlig::common::jobs::{Request, RequestType, Response};
    use heimlig::common::limits::MAX_RANDOM_SIZE;
    use heimlig::common::queues::{Error, RequestSink, ResponseSink};
    use heimlig::config;
    use heimlig::config::keystore::{KEY1, KEY2, KEY3};
    use heimlig::crypto::chacha20poly1305::{KEY_SIZE, NONCE_SIZE};
    use heimlig::crypto::rng::{EntropySource, Rng};
    use heimlig::hsm::core::Core;
    use heimlig::hsm::keystore::{KeyStore, MemoryKeyStore};
    use heimlig::hsm::workers::chachapoly_worker::ChaChaPolyWorker;
    use heimlig::hsm::workers::rng_worker::RngWorker;

    const QUEUE_SIZE: usize = 8;
    const PLAINTEXT_SIZE: usize = 36;
    const AAD_SIZE: usize = 33;
    const TAG_SIZE: usize = 16;

    #[derive(Default)]
    pub struct TestEntropySource {
        counter: u64,
    }

    impl EntropySource for TestEntropySource {
        fn random_seed(&mut self) -> [u8; 32] {
            let mut dest = [0u8; 32];
            for byte in &mut dest {
                *byte = self.counter as u8;
                self.counter += 1
            }
            dest
        }
    }

    struct RequestQueueSource<'ch, 'data> {
        consumer: Consumer<'ch, Request<'data>, QUEUE_SIZE>,
    }

    struct ResponseQueueSink<'ch, 'data> {
        producer: Producer<'ch, Response<'data>, QUEUE_SIZE>,
    }

    struct ResponseQueueSource<'ch, 'data> {
        consumer: Consumer<'ch, Response<'data>, QUEUE_SIZE>,
    }

    struct RequestQueueSink<'ch, 'data> {
        producer: Producer<'ch, Request<'data>, QUEUE_SIZE>,
    }

    impl<'data> Iterator for RequestQueueSource<'_, 'data> {
        type Item = Request<'data>;

        fn next(&mut self) -> Option<Self::Item> {
            self.consumer.dequeue()
        }
    }

    impl<'data> ResponseSink<'data> for ResponseQueueSink<'_, 'data> {
        fn send(&mut self, response: Response<'data>) -> Result<(), Error> {
            self.producer.enqueue(response).map_err(|_| Error::Enqueue)
        }
        fn ready(&self) -> bool {
            self.producer.ready()
        }
    }

    impl<'data> Iterator for ResponseQueueSource<'_, 'data> {
        type Item = Response<'data>;

        fn next(&mut self) -> Option<Self::Item> {
            self.consumer.dequeue()
        }
    }

    impl<'data> RequestSink<'data> for RequestQueueSink<'_, 'data> {
        fn send(&mut self, response: Request<'data>) -> Result<(), Error> {
            self.producer.enqueue(response).map_err(|_| Error::Enqueue)
        }
        fn ready(&self) -> bool {
            self.producer.ready()
        }
    }

    fn init_rng() -> Rng<TestEntropySource> {
        Rng::new(TestEntropySource::default(), None)
    }

    fn split_client_queues<'ch, 'data>(
        client_requests: &'ch mut Queue<Request<'data>, QUEUE_SIZE>,
        client_responses: &'ch mut Queue<Response<'data>, QUEUE_SIZE>,
    ) -> (
        Producer<'ch, Request<'data>, QUEUE_SIZE>,
        Consumer<'ch, Response<'data>, QUEUE_SIZE>,
        RequestQueueSource<'ch, 'data>,
        ResponseQueueSink<'ch, 'data>,
    ) {
        let (client_requests_tx, client_requests_rx): (
            Producer<Request, QUEUE_SIZE>,
            Consumer<Request, QUEUE_SIZE>,
        ) = client_requests.split();
        let (client_responses_tx, client_responses_rx) = client_responses.split();
        let client_requests_rx = RequestQueueSource {
            consumer: client_requests_rx,
        };
        let client_responses_tx = ResponseQueueSink {
            producer: client_responses_tx,
        };
        (
            client_requests_tx,
            client_responses_rx,
            client_requests_rx,
            client_responses_tx,
        )
    }

    fn split_worker_queues<'ch, 'data>(
        requests: &'ch mut Queue<Request<'data>, QUEUE_SIZE>,
        responses: &'ch mut Queue<Response<'data>, QUEUE_SIZE>,
    ) -> (
        RequestQueueSource<'ch, 'data>,
        RequestQueueSink<'ch, 'data>,
        ResponseQueueSource<'ch, 'data>,
        ResponseQueueSink<'ch, 'data>,
    ) {
        let (requests_tx, requests_rx): (
            Producer<Request, QUEUE_SIZE>,
            Consumer<Request, QUEUE_SIZE>,
        ) = requests.split();
        let (response_tx, response_rx): (
            Producer<Response, QUEUE_SIZE>,
            Consumer<Response, QUEUE_SIZE>,
        ) = responses.split();
        let requests_rx = RequestQueueSource {
            consumer: requests_rx,
        };
        let requests_tx = RequestQueueSink {
            producer: requests_tx,
        };
        let response_rx = ResponseQueueSource {
            consumer: response_rx,
        };
        let response_tx = ResponseQueueSink {
            producer: response_tx,
        };
        (requests_rx, requests_tx, response_rx, response_tx)
    }

    fn alloc_chachapoly_vars() -> (
        [u8; KEY_SIZE],
        [u8; NONCE_SIZE],
        [u8; PLAINTEXT_SIZE],
        [u8; AAD_SIZE],
        [u8; TAG_SIZE],
    ) {
        let key: [u8; KEY_SIZE] = *b"Fortuna Major or Oddsbodikins???";
        let nonce: [u8; NONCE_SIZE] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let plaintext: [u8; PLAINTEXT_SIZE] = *b"I solemnly swear I am up to no good!";
        let aad: [u8; AAD_SIZE] = *b"When in doubt, go to the library.";
        let tag: [u8; TAG_SIZE] = [0u8; TAG_SIZE];
        (key, nonce, plaintext, aad, tag)
    }

    fn init_core<'keystore, 'ch, 'data, M: RawMutex>(
        key_store: Option<&'keystore Mutex<M, &'keystore mut (dyn KeyStore + Send)>>,
        client_requests: RequestQueueSource<'ch, 'data>,
        client_responses: ResponseQueueSink<'ch, 'data>,
    ) -> Core<
        'data,
        'keystore,
        M,
        Enumerate<RequestQueueSource<'ch, 'data>>,
        ResponseQueueSink<'ch, 'data>,
        RequestQueueSink<'ch, 'data>,
        Enumerate<ResponseQueueSource<'ch, 'data>>,
    > {
        Core::new(key_store, client_requests.enumerate(), client_responses)
    }

    fn init_key_store(
    ) -> MemoryKeyStore<{ config::keystore::TOTAL_SIZE }, { config::keystore::NUM_KEYS }> {
        let key_infos = [KEY1, KEY2, KEY3];
        MemoryKeyStore::<{ config::keystore::TOTAL_SIZE }, { config::keystore::NUM_KEYS }>::try_new(
            &key_infos,
        )
        .expect("failed to create key store")
    }
    #[test]
    fn get_random() {
        const REQUEST_SIZE: usize = 16;
        let mut random_output = [0u8; REQUEST_SIZE];
        let rng = init_rng();
        let mut client_requests = Queue::<Request, QUEUE_SIZE>::new();
        let mut client_responses = Queue::<Response, QUEUE_SIZE>::new();
        let mut rng_requests = Queue::<Request, QUEUE_SIZE>::new();
        let mut rng_responses = Queue::<Response, QUEUE_SIZE>::new();
        let (mut req_client_tx, mut resp_client_rx, client_requests_rx, client_responses_tx) =
            split_client_queues(&mut client_requests, &mut client_responses);
        let (rng_requests_rx, rng_requests_tx, rng_responses_rx, rng_responses_tx) =
            split_worker_queues(&mut rng_requests, &mut rng_responses);
        let mut key_store = init_key_store();
        let key_store: Option<Mutex<NoopRawMutex, &mut (dyn KeyStore + Send)>> =
            Some(Mutex::new(&mut key_store));
        let mut rng_worker = RngWorker {
            rng,
            requests: rng_requests_rx.enumerate(),
            responses: rng_responses_tx,
        };
        let mut core =
            init_core::<NoopRawMutex>(key_store.as_ref(), client_requests_rx, client_responses_tx);
        core.add_worker_channel(
            &[RequestType::GetRandom],
            rng_requests_tx,
            rng_responses_rx.enumerate(),
        );
        let request = Request::GetRandom {
            output: &mut random_output,
        };
        req_client_tx
            .enqueue(request)
            .expect("failed to send request");
        core.execute().expect("failed to forward request");
        rng_worker.execute().expect("failed to process request");
        core.execute().expect("failed to forward response");
        match resp_client_rx.dequeue() {
            Some(response) => match response {
                Response::GetRandom { data } => assert_eq!(data.len(), REQUEST_SIZE),
                _ => panic!("Unexpected response type {:?}", response),
            },
            None => panic!("Failed to receive expected response"),
        }
    }

    #[test]
    fn get_random_request_too_large() {
        const REQUEST_SIZE: usize = MAX_RANDOM_SIZE + 1;
        let mut random_output = [0u8; REQUEST_SIZE];
        let rng = init_rng();
        let mut client_requests = Queue::<Request, QUEUE_SIZE>::new();
        let mut client_responses = Queue::<Response, QUEUE_SIZE>::new();
        let mut rng_requests = Queue::<Request, QUEUE_SIZE>::new();
        let mut rng_responses = Queue::<Response, QUEUE_SIZE>::new();
        let (mut req_client_tx, mut resp_client_rx, client_requests_rx, client_responses_tx) =
            split_client_queues(&mut client_requests, &mut client_responses);
        let (rng_requests_rx, rng_requests_tx, rng_responses_rx, rng_responses_tx) =
            split_worker_queues(&mut rng_requests, &mut rng_responses);
        let mut key_store = init_key_store();
        let key_store: Option<Mutex<NoopRawMutex, &mut (dyn KeyStore + Send)>> =
            Some(Mutex::new(&mut key_store));
        let mut rng_worker = RngWorker {
            rng,
            requests: rng_requests_rx.enumerate(),
            responses: rng_responses_tx,
        };
        let mut core =
            init_core::<NoopRawMutex>(key_store.as_ref(), client_requests_rx, client_responses_tx);
        core.add_worker_channel(
            &[RequestType::GetRandom],
            rng_requests_tx,
            rng_responses_rx.enumerate(),
        );
        let request = Request::GetRandom {
            output: &mut random_output,
        };
        req_client_tx
            .enqueue(request)
            .expect("failed to send request");
        core.execute().expect("failed to forward request");
        rng_worker.execute().expect("failed to process request");
        core.execute().expect("failed to forward response");
        match resp_client_rx.dequeue() {
            Some(response) => match response {
                Response::Error(jobs::Error::RequestTooLarge) => {}
                _ => panic!("Unexpected response type {:?}", response),
            },
            None => panic!("Failed to receive expected response"),
        }
    }

    #[test]
    fn encrypt_chachapoly() {
        let (key, nonce, mut plaintext, aad, mut tag) = alloc_chachapoly_vars();
        let org_plaintext = plaintext;
        let mut client_requests = Queue::<Request, QUEUE_SIZE>::new();
        let mut client_responses = Queue::<Response, QUEUE_SIZE>::new();
        let mut chachapoly_requests = Queue::<Request, QUEUE_SIZE>::new();
        let mut chachapoly_responses = Queue::<Response, QUEUE_SIZE>::new();
        let (mut req_client_tx, mut resp_client_rx, client_requests_rx, client_responses_tx) =
            split_client_queues(&mut client_requests, &mut client_responses);
        let (
            chachapoly_requests_rx,
            chachapoly_requests_tx,
            chachapoly_responses_rx,
            chachapoly_responses_tx,
        ) = split_worker_queues(&mut chachapoly_requests, &mut chachapoly_responses);
        let mut key_store = init_key_store();
        let key_store: Option<Mutex<NoopRawMutex, &mut (dyn KeyStore + Send)>> =
            Some(Mutex::new(&mut key_store));
        let mut chacha_worker = ChaChaPolyWorker {
            key_store: key_store.as_ref(),
            requests: chachapoly_requests_rx.enumerate(),
            responses: chachapoly_responses_tx,
        };
        let mut core =
            init_core::<NoopRawMutex>(key_store.as_ref(), client_requests_rx, client_responses_tx);
        core.add_worker_channel(
            &[
                RequestType::EncryptChaChaPoly,
                RequestType::EncryptChaChaPolyExternalKey,
                RequestType::DecryptChaChaPoly,
                RequestType::DecryptChaChaPolyExternalKey,
            ],
            chachapoly_requests_tx,
            chachapoly_responses_rx.enumerate(),
        );

        // Import key
        let request = Request::ImportKey {
            key_id: KEY3.id,
            data: &key,
        };
        req_client_tx
            .enqueue(request)
            .expect("failed to send request");
        core.execute().expect("failed to process next request");
        let response = resp_client_rx
            .dequeue()
            .expect("Failed to receive expected response");
        match response {
            Response::ImportKey {} => {}
            _ => panic!("Unexpected response type"),
        };

        // Encrypt data
        let request = Request::EncryptChaChaPoly {
            key_id: KEY3.id,
            nonce: &nonce,
            plaintext: &mut plaintext,
            aad: &aad,
            tag: &mut tag,
        };
        req_client_tx
            .enqueue(request)
            .expect("failed to send request");

        core.execute().expect("failed to forward request");
        chacha_worker.execute().expect("failed to process request");
        core.execute().expect("failed to forward response");
        let (ciphertext, tag) = match resp_client_rx
            .dequeue()
            .expect("Failed to receive expected response")
        {
            Response::EncryptChaChaPoly { ciphertext, tag } => (ciphertext, tag),
            _ => panic!("Unexpected response type"),
        };

        // Decrypt data
        let request = Request::DecryptChaChaPoly {
            key_id: KEY3.id,
            nonce: &nonce,
            ciphertext,
            aad: &aad,
            tag,
        };
        req_client_tx
            .enqueue(request)
            .expect("failed to send request");
        core.execute().expect("failed to forward request");
        chacha_worker.execute().expect("failed to process request");
        core.execute().expect("failed to forward response");
        let plaintext = match resp_client_rx
            .dequeue()
            .expect("Failed to receive expected response")
        {
            Response::DecryptChaChaPoly { plaintext } => plaintext,
            resp => panic!("Unexpected response type {:?}", resp),
        };
        assert_eq!(plaintext, org_plaintext);
    }

    #[test]
    fn encrypt_chachapoly_external_key() {
        let (key, nonce, mut plaintext, aad, mut tag) = alloc_chachapoly_vars();
        let org_plaintext = plaintext;
        let mut client_requests = Queue::<Request, QUEUE_SIZE>::new();
        let mut client_responses = Queue::<Response, QUEUE_SIZE>::new();
        let mut chachapoly_requests = Queue::<Request, QUEUE_SIZE>::new();
        let mut chachapoly_responses = Queue::<Response, QUEUE_SIZE>::new();
        let (mut req_client_tx, mut resp_client_rx, client_requests_rx, client_responses_tx) =
            split_client_queues(&mut client_requests, &mut client_responses);
        let (
            chachapoly_requests_rx,
            chachapoly_requests_tx,
            chachapoly_responses_rx,
            chachapoly_responses_tx,
        ) = split_worker_queues(&mut chachapoly_requests, &mut chachapoly_responses);
        let mut key_store = init_key_store();
        let key_store: Option<Mutex<NoopRawMutex, &mut (dyn KeyStore + Send)>> =
            Some(Mutex::new(&mut key_store));
        let mut chacha_worker = ChaChaPolyWorker {
            key_store: key_store.as_ref(),
            requests: chachapoly_requests_rx.enumerate(),
            responses: chachapoly_responses_tx,
        };
        let mut core =
            init_core::<NoopRawMutex>(key_store.as_ref(), client_requests_rx, client_responses_tx);
        core.add_worker_channel(
            &[
                RequestType::EncryptChaChaPoly,
                RequestType::EncryptChaChaPolyExternalKey,
                RequestType::DecryptChaChaPoly,
                RequestType::DecryptChaChaPolyExternalKey,
            ],
            chachapoly_requests_tx,
            chachapoly_responses_rx.enumerate(),
        );

        // Encrypt data
        let request = Request::EncryptChaChaPolyExternalKey {
            key: &key,
            nonce: &nonce,
            aad: &aad,
            plaintext: &mut plaintext,
            tag: &mut tag,
        };
        req_client_tx
            .enqueue(request)
            .expect("failed to send request");
        core.execute().expect("failed to forward request");
        chacha_worker.execute().expect("failed to process request");
        core.execute().expect("failed to forward response");
        let (ciphertext, tag) = match resp_client_rx
            .dequeue()
            .expect("Failed to receive expected response")
        {
            Response::EncryptChaChaPoly { ciphertext, tag } => (ciphertext, tag),
            _ => panic!("Unexpected response type"),
        };

        // Decrypt data
        let request = Request::DecryptChaChaPolyExternalKey {
            key: &key,
            nonce: &nonce,
            ciphertext,
            aad: &aad,
            tag,
        };
        req_client_tx
            .enqueue(request)
            .expect("failed to send request");
        core.execute().expect("failed to forward request");
        chacha_worker.execute().expect("failed to process request");
        core.execute().expect("failed to forward response");
        let plaintext = match resp_client_rx
            .dequeue()
            .expect("Failed to receive expected response")
        {
            Response::DecryptChaChaPoly { plaintext } => plaintext,
            _ => panic!("Unexpected response type"),
        };
        assert_eq!(plaintext, org_plaintext)
    }
}
