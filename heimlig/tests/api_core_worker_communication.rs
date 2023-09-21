mod tests {
    use embassy_sync::blocking_mutex::raw::{NoopRawMutex, RawMutex};
    use embassy_sync::mutex::Mutex;
    use heapless::spsc::{Consumer, Producer, Queue};
    use heimlig::client::api::Api;
    use heimlig::client::api::SymmetricEncryptionAlgorithm::ChaCha20Poly1305;
    use heimlig::common::jobs;
    use heimlig::common::jobs::{Request, RequestType, Response};
    use heimlig::common::limits::MAX_RANDOM_SIZE;
    use heimlig::config;
    use heimlig::config::keystore::{KEY1, KEY2, KEY3};
    use heimlig::crypto::chacha20poly1305::{KEY_SIZE, NONCE_SIZE};
    use heimlig::crypto::rng::{EntropySource, Rng};
    use heimlig::hsm::core::Core;
    use heimlig::hsm::keystore::{KeyStore, MemoryKeyStore};
    use heimlig::hsm::workers::chachapoly_worker::ChaChaPolyWorker;
    use heimlig::hsm::workers::rng_worker::RngWorker;
    use heimlig::integration::embassy::{
        RequestQueueSink, RequestQueueSource, ResponseQueueSink, ResponseQueueSource,
    };

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

    fn init_rng() -> Rng<TestEntropySource> {
        Rng::new(TestEntropySource::default(), None)
    }

    fn split_queues<'ch, 'data>(
        requests: &'ch mut Queue<Request<'data>, QUEUE_SIZE>,
        responses: &'ch mut Queue<Response<'data>, QUEUE_SIZE>,
    ) -> (
        RequestQueueSource<'ch, 'data, NoopRawMutex, QUEUE_SIZE>,
        RequestQueueSink<'ch, 'data, NoopRawMutex, QUEUE_SIZE>,
        ResponseQueueSource<'ch, 'data, NoopRawMutex, QUEUE_SIZE>,
        ResponseQueueSink<'ch, 'data, NoopRawMutex, QUEUE_SIZE>,
    ) {
        let (requests_tx, requests_rx): (
            Producer<Request, QUEUE_SIZE>,
            Consumer<Request, QUEUE_SIZE>,
        ) = requests.split();
        let (response_tx, response_rx): (
            Producer<Response, QUEUE_SIZE>,
            Consumer<Response, QUEUE_SIZE>,
        ) = responses.split();
        let requests_rx = RequestQueueSource::new(requests_rx);
        let requests_tx = RequestQueueSink::new(requests_tx);
        let response_rx = ResponseQueueSource::new(response_rx);
        let response_tx = ResponseQueueSink::new(response_tx);
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

    fn init_core<'keystore, 'ch, 'data, M: RawMutex + Unpin>(
        key_store: Option<&'keystore Mutex<M, &'keystore mut (dyn KeyStore + Send)>>,
        client_requests: RequestQueueSource<'ch, 'data, M, QUEUE_SIZE>,
        client_responses: ResponseQueueSink<'ch, 'data, M, QUEUE_SIZE>,
    ) -> Core<
        'data,
        'keystore,
        M,
        RequestQueueSource<'ch, 'data, M, QUEUE_SIZE>,
        ResponseQueueSink<'ch, 'data, M, QUEUE_SIZE>,
        RequestQueueSink<'ch, 'data, M, QUEUE_SIZE>,
        ResponseQueueSource<'ch, 'data, M, QUEUE_SIZE>,
    > {
        Core::new(key_store, client_requests, client_responses)
    }

    fn init_key_store(
    ) -> MemoryKeyStore<{ config::keystore::TOTAL_SIZE }, { config::keystore::NUM_KEYS }> {
        let key_infos = [KEY1, KEY2, KEY3];
        MemoryKeyStore::<{ config::keystore::TOTAL_SIZE }, { config::keystore::NUM_KEYS }>::try_new(
            &key_infos,
        )
        .expect("failed to create key store")
    }

    #[async_std::test]
    async fn get_random() {
        const REQUEST_SIZE: usize = 16;
        let mut random_output = [0u8; REQUEST_SIZE];
        let rng = init_rng();
        let mut client_requests = Queue::<Request, QUEUE_SIZE>::new();
        let mut client_responses = Queue::<Response, QUEUE_SIZE>::new();
        let mut rng_requests = Queue::<Request, QUEUE_SIZE>::new();
        let mut rng_responses = Queue::<Response, QUEUE_SIZE>::new();
        let (req_client_rx, req_client_tx, resp_client_rx, resp_client_tx) =
            split_queues(&mut client_requests, &mut client_responses);
        let (rng_requests_rx, rng_requests_tx, rng_responses_rx, rng_responses_tx) =
            split_queues(&mut rng_requests, &mut rng_responses);
        let mut key_store = init_key_store();
        let key_store: Option<Mutex<NoopRawMutex, &mut (dyn KeyStore + Send)>> =
            Some(Mutex::new(&mut key_store));
        let mut rng_worker = RngWorker {
            rng,
            requests: rng_requests_rx,
            responses: rng_responses_tx,
        };
        let mut core = init_core::<NoopRawMutex>(key_store.as_ref(), req_client_rx, resp_client_tx);
        core.add_worker_channel(&[RequestType::GetRandom], rng_requests_tx, rng_responses_rx);
        let mut api = Api::new(req_client_tx, resp_client_rx);

        let org_request_id = api
            .get_random(&mut random_output)
            .await
            .expect("failed to send request");
        core.execute().await.expect("failed to forward request");
        rng_worker
            .execute()
            .await
            .expect("failed to process request");
        core.execute().await.expect("failed to forward response");
        match api.recv_response().await {
            None => panic!("Failed to receive expected response"),
            Some(response) => match response {
                Response::GetRandom { request_id, data } => {
                    assert_eq!(request_id, org_request_id);
                    assert_eq!(data.len(), REQUEST_SIZE)
                }
                _ => panic!("Unexpected response type {:?}", response),
            },
        }
    }

    #[async_std::test]
    async fn get_random_request_too_large() {
        const REQUEST_SIZE: usize = MAX_RANDOM_SIZE + 1;
        let mut random_output = [0u8; REQUEST_SIZE];
        let rng = init_rng();
        let mut client_requests = Queue::<Request, QUEUE_SIZE>::new();
        let mut client_responses = Queue::<Response, QUEUE_SIZE>::new();
        let mut rng_requests = Queue::<Request, QUEUE_SIZE>::new();
        let mut rng_responses = Queue::<Response, QUEUE_SIZE>::new();
        let (req_client_rx, req_client_tx, resp_client_rx, resp_client_tx) =
            split_queues(&mut client_requests, &mut client_responses);
        let (rng_requests_rx, rng_requests_tx, rng_responses_rx, rng_responses_tx) =
            split_queues(&mut rng_requests, &mut rng_responses);
        let mut key_store = init_key_store();
        let key_store: Option<Mutex<NoopRawMutex, &mut (dyn KeyStore + Send)>> =
            Some(Mutex::new(&mut key_store));
        let mut rng_worker = RngWorker {
            rng,
            requests: rng_requests_rx,
            responses: rng_responses_tx,
        };
        let mut core = init_core::<NoopRawMutex>(key_store.as_ref(), req_client_rx, resp_client_tx);
        core.add_worker_channel(&[RequestType::GetRandom], rng_requests_tx, rng_responses_rx);
        let mut api = Api::new(req_client_tx, resp_client_rx);

        let org_request_id = api
            .get_random(&mut random_output)
            .await
            .expect("failed to send request");
        core.execute().await.expect("failed to forward request");
        rng_worker
            .execute()
            .await
            .expect("failed to process request");
        core.execute().await.expect("failed to forward response");
        match api.recv_response().await {
            None => panic!("Failed to receive expected response"),
            Some(response) => match response {
                Response::Error { request_id, error } => {
                    assert_eq!(request_id, org_request_id);
                    assert_eq!(error, jobs::Error::RequestTooLarge);
                }
                _ => panic!("Unexpected response type {:?}", response),
            },
        }
    }

    #[async_std::test]
    async fn encrypt_chachapoly() {
        let (key, nonce, mut plaintext, aad, mut tag) = alloc_chachapoly_vars();
        let org_plaintext = plaintext;
        let mut client_requests = Queue::<Request, QUEUE_SIZE>::new();
        let mut client_responses = Queue::<Response, QUEUE_SIZE>::new();
        let mut chachapoly_requests = Queue::<Request, QUEUE_SIZE>::new();
        let mut chachapoly_responses = Queue::<Response, QUEUE_SIZE>::new();
        let (req_client_rx, req_client_tx, resp_client_rx, resp_client_tx) =
            split_queues(&mut client_requests, &mut client_responses);
        let (
            chachapoly_requests_rx,
            chachapoly_requests_tx,
            chachapoly_responses_rx,
            chachapoly_responses_tx,
        ) = split_queues(&mut chachapoly_requests, &mut chachapoly_responses);
        let mut key_store = init_key_store();
        let key_store: Option<Mutex<NoopRawMutex, &mut (dyn KeyStore + Send)>> =
            Some(Mutex::new(&mut key_store));
        let mut chacha_worker = ChaChaPolyWorker {
            key_store: key_store.as_ref(),
            requests: chachapoly_requests_rx,
            responses: chachapoly_responses_tx,
        };
        let mut core = init_core::<NoopRawMutex>(key_store.as_ref(), req_client_rx, resp_client_tx);
        core.add_worker_channel(
            &[
                RequestType::EncryptChaChaPoly,
                RequestType::EncryptChaChaPolyExternalKey,
                RequestType::DecryptChaChaPoly,
                RequestType::DecryptChaChaPolyExternalKey,
            ],
            chachapoly_requests_tx,
            chachapoly_responses_rx,
        );
        let mut api = Api::new(req_client_tx, resp_client_rx);

        // Import key
        let org_request_id = api
            .import_key(KEY3.id, &key)
            .await
            .expect("failed to send request");
        core.execute()
            .await
            .expect("failed to process next request");
        let response = api
            .recv_response()
            .await
            .expect("Failed to receive expected response");
        match response {
            Response::ImportKey { request_id } => {
                assert_eq!(org_request_id, request_id)
            }
            _ => panic!("Unexpected response type"),
        };

        // Encrypt data
        let org_request_id = api
            .encrypt(
                ChaCha20Poly1305,
                KEY3.id,
                &nonce,
                &mut plaintext,
                &aad,
                &mut tag,
            )
            .await
            .expect("failed to send request");
        core.execute().await.expect("failed to forward request");
        chacha_worker
            .execute()
            .await
            .expect("failed to process request");
        core.execute().await.expect("failed to forward response");
        let (request_id, ciphertext, tag) = match api
            .recv_response()
            .await
            .expect("Failed to receive expected response")
        {
            Response::EncryptChaChaPoly {
                request_id,
                ciphertext,
                tag,
            } => (request_id, ciphertext, tag),
            _ => panic!("Unexpected response type"),
        };
        assert_eq!(request_id, org_request_id);

        // Decrypt data
        let org_request_id = api
            .decrypt(ChaCha20Poly1305, KEY3.id, &nonce, ciphertext, &aad, tag)
            .await
            .expect("failed to send request");
        core.execute().await.expect("failed to forward request");
        chacha_worker
            .execute()
            .await
            .expect("failed to process request");
        core.execute().await.expect("failed to forward response");
        let (request_id, plaintext) = match api
            .recv_response()
            .await
            .expect("Failed to receive expected response")
        {
            Response::DecryptChaChaPoly {
                request_id,
                plaintext,
            } => (request_id, plaintext),
            resp => panic!("Unexpected response type {:?}", resp),
        };
        assert_eq!(request_id, org_request_id);
        assert_eq!(plaintext, org_plaintext);
    }

    #[async_std::test]
    async fn encrypt_chachapoly_external_key() {
        let (key, nonce, mut plaintext, aad, mut tag) = alloc_chachapoly_vars();
        let org_plaintext = plaintext;
        let mut client_requests = Queue::<Request, QUEUE_SIZE>::new();
        let mut client_responses = Queue::<Response, QUEUE_SIZE>::new();
        let mut chachapoly_requests = Queue::<Request, QUEUE_SIZE>::new();
        let mut chachapoly_responses = Queue::<Response, QUEUE_SIZE>::new();
        let (req_client_rx, req_client_tx, resp_client_rx, resp_client_tx) =
            split_queues(&mut client_requests, &mut client_responses);
        let (
            chachapoly_requests_rx,
            chachapoly_requests_tx,
            chachapoly_responses_rx,
            chachapoly_responses_tx,
        ) = split_queues(&mut chachapoly_requests, &mut chachapoly_responses);
        let mut key_store = init_key_store();
        let key_store: Option<Mutex<NoopRawMutex, &mut (dyn KeyStore + Send)>> =
            Some(Mutex::new(&mut key_store));
        let mut chacha_worker = ChaChaPolyWorker {
            key_store: key_store.as_ref(),
            requests: chachapoly_requests_rx,
            responses: chachapoly_responses_tx,
        };
        let mut core = init_core::<NoopRawMutex>(key_store.as_ref(), req_client_rx, resp_client_tx);
        core.add_worker_channel(
            &[
                RequestType::EncryptChaChaPoly,
                RequestType::EncryptChaChaPolyExternalKey,
                RequestType::DecryptChaChaPoly,
                RequestType::DecryptChaChaPolyExternalKey,
            ],
            chachapoly_requests_tx,
            chachapoly_responses_rx,
        );
        let mut api = Api::new(req_client_tx, resp_client_rx);

        // Encrypt data
        let org_request_id = api
            .encrypt_external_key(
                ChaCha20Poly1305,
                &key,
                &nonce,
                &mut plaintext,
                &aad,
                &mut tag,
            )
            .await
            .expect("failed to send request");
        core.execute().await.expect("failed to forward request");
        chacha_worker
            .execute()
            .await
            .expect("failed to process request");
        core.execute().await.expect("failed to forward response");
        let (request_id, ciphertext, tag) = match api
            .recv_response()
            .await
            .expect("Failed to receive expected response")
        {
            Response::EncryptChaChaPoly {
                request_id,
                ciphertext,
                tag,
            } => (request_id, ciphertext, tag),
            _ => panic!("Unexpected response type"),
        };
        assert_eq!(request_id, org_request_id);

        // Decrypt data
        let org_request_id = api
            .decrypt_external_key(ChaCha20Poly1305, &key, &nonce, ciphertext, &aad, tag)
            .await
            .expect("failed to send request");
        core.execute().await.expect("failed to forward request");
        chacha_worker
            .execute()
            .await
            .expect("failed to process request");
        core.execute().await.expect("failed to forward response");
        let (request_id, plaintext) = match api
            .recv_response()
            .await
            .expect("Failed to receive expected response")
        {
            Response::DecryptChaChaPoly {
                request_id,
                plaintext,
            } => (request_id, plaintext),
            _ => panic!("Unexpected response type"),
        };
        assert_eq!(request_id, org_request_id);
        assert_eq!(plaintext, org_plaintext)
    }
}
