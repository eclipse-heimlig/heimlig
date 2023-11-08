mod tests {
    use embassy_sync::blocking_mutex::raw::NoopRawMutex;
    use embassy_sync::mutex::Mutex;
    use futures::future::join;
    use heimlig::client::api::Api;
    use heimlig::client::api::SymmetricEncryptionAlgorithm::ChaCha20Poly1305;
    use heimlig::common::jobs;
    use heimlig::common::jobs::{Error, Request, RequestType, Response};
    use heimlig::common::limits::MAX_RANDOM_SIZE;
    use heimlig::config;
    use heimlig::config::keystore::{KEY1, KEY2, KEY3};
    use heimlig::crypto::chacha20poly1305::{KEY_SIZE, NONCE_SIZE};
    use heimlig::crypto::rng::{EntropySource, Rng};
    use heimlig::hsm::core::Builder;
    use heimlig::hsm::keystore::{KeyStore, MemoryKeyStore};
    use heimlig::hsm::workers::chachapoly_worker::ChaChaPolyWorker;
    use heimlig::hsm::workers::rng_worker::RngWorker;
    use heimlig::integration::embassy::{
        AsyncQueue, RequestQueueSink, RequestQueueSource, ResponseQueueSink, ResponseQueueSource,
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

    fn init_key_store(
    ) -> MemoryKeyStore<{ config::keystore::TOTAL_SIZE }, { config::keystore::NUM_KEYS }> {
        let key_infos = [KEY1, KEY2, KEY3];
        MemoryKeyStore::<{ config::keystore::TOTAL_SIZE }, { config::keystore::NUM_KEYS }>::try_new(
            &key_infos,
        )
        .expect("failed to create key store")
    }

    fn split_queues<'ch, 'data>(
        requests: &'ch mut AsyncQueue<Request<'data>, QUEUE_SIZE>,
        responses: &'ch mut AsyncQueue<Response<'data>, QUEUE_SIZE>,
    ) -> (
        RequestQueueSource<'ch, 'data, QUEUE_SIZE>,
        RequestQueueSink<'ch, 'data, QUEUE_SIZE>,
        ResponseQueueSource<'ch, 'data, QUEUE_SIZE>,
        ResponseQueueSink<'ch, 'data, QUEUE_SIZE>,
    ) {
        let (requests_tx, requests_rx) = requests.split();
        let (response_tx, response_rx) = responses.split();
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

    #[async_std::test]
    async fn get_random() {
        const REQUEST_SIZE: usize = 16;
        let mut random_output = [0u8; REQUEST_SIZE];
        let rng = init_rng();
        let mut client_requests = AsyncQueue::<Request, QUEUE_SIZE>::new();
        let mut client_responses = AsyncQueue::<Response, QUEUE_SIZE>::new();
        let mut rng_requests = AsyncQueue::<Request, QUEUE_SIZE>::new();
        let mut rng_responses = AsyncQueue::<Response, QUEUE_SIZE>::new();
        let (req_client_rx, req_client_tx, resp_client_rx, resp_client_tx) =
            split_queues(&mut client_requests, &mut client_responses);
        let (rng_requests_rx, rng_requests_tx, rng_responses_rx, rng_responses_tx) =
            split_queues(&mut rng_requests, &mut rng_responses);
        let mut rng_worker = RngWorker {
            rng,
            requests: rng_requests_rx,
            responses: rng_responses_tx,
        };
        let mut core = Builder::<
            NoopRawMutex,
            RequestQueueSource<'_, '_, QUEUE_SIZE>,
            ResponseQueueSink<'_, '_, QUEUE_SIZE>,
            RequestQueueSink<'_, '_, QUEUE_SIZE>,
            ResponseQueueSource<'_, '_, QUEUE_SIZE>,
        >::default()
        .with_client(req_client_rx, resp_client_tx)
        .expect("failed to add client")
        .with_worker(&[RequestType::GetRandom], rng_requests_tx, rng_responses_rx)
        .expect("failed to add worker")
        .build();
        let mut api = Api::new(req_client_tx, resp_client_rx);

        let org_request_id = api
            .get_random(&mut random_output)
            .await
            .expect("failed to send request");
        let (core_res, worker_res) = join(core.execute(), rng_worker.execute()).await;
        core_res.expect("failed to forward request");
        worker_res.expect("failed to process request");
        core.execute().await.expect("failed to forward response");
        match api.recv_response().await {
            None => panic!("Failed to receive expected response"),
            Some(response) => match response {
                Response::GetRandom {
                    client_id: _client_id,
                    request_id,
                    data,
                } => {
                    assert_eq!(request_id, org_request_id);
                    assert_eq!(data.len(), REQUEST_SIZE);
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
        let mut client_requests = AsyncQueue::<Request, QUEUE_SIZE>::new();
        let mut client_responses = AsyncQueue::<Response, QUEUE_SIZE>::new();
        let mut rng_requests = AsyncQueue::<Request, QUEUE_SIZE>::new();
        let mut rng_responses = AsyncQueue::<Response, QUEUE_SIZE>::new();
        let (req_client_rx, req_client_tx, resp_client_rx, resp_client_tx) =
            split_queues(&mut client_requests, &mut client_responses);
        let (rng_requests_rx, rng_requests_tx, rng_responses_rx, rng_responses_tx) =
            split_queues(&mut rng_requests, &mut rng_responses);
        let mut rng_worker = RngWorker {
            rng,
            requests: rng_requests_rx,
            responses: rng_responses_tx,
        };
        let mut core = Builder::<
            NoopRawMutex,
            RequestQueueSource<'_, '_, QUEUE_SIZE>,
            ResponseQueueSink<'_, '_, QUEUE_SIZE>,
            RequestQueueSink<'_, '_, QUEUE_SIZE>,
            ResponseQueueSource<'_, '_, QUEUE_SIZE>,
        >::default()
        .with_client(req_client_rx, resp_client_tx)
        .expect("failed to add client")
        .with_worker(&[RequestType::GetRandom], rng_requests_tx, rng_responses_rx)
        .expect("failed to add worker")
        .build();
        let mut api = Api::new(req_client_tx, resp_client_rx);

        let org_request_id = api
            .get_random(&mut random_output)
            .await
            .expect("failed to send request");
        let (core_res, worker_res) = join(core.execute(), rng_worker.execute()).await;
        core_res.expect("failed to forward request");
        worker_res.expect("failed to process request");
        core.execute().await.expect("failed to forward response");
        match api.recv_response().await {
            None => panic!("Failed to receive expected response"),
            Some(response) => match response {
                Response::Error {
                    client_id: _client_id,
                    request_id,
                    error,
                } => {
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
        let mut client_requests = AsyncQueue::<Request, QUEUE_SIZE>::new();
        let mut client_responses = AsyncQueue::<Response, QUEUE_SIZE>::new();
        let mut chachapoly_requests = AsyncQueue::<Request, QUEUE_SIZE>::new();
        let mut chachapoly_responses = AsyncQueue::<Response, QUEUE_SIZE>::new();
        let (req_client_rx, req_client_tx, resp_client_rx, resp_client_tx) =
            split_queues(&mut client_requests, &mut client_responses);
        let (
            chachapoly_requests_rx,
            chachapoly_requests_tx,
            chachapoly_responses_rx,
            chachapoly_responses_tx,
        ) = split_queues(&mut chachapoly_requests, &mut chachapoly_responses);
        let mut key_store = init_key_store();
        let key_store: Mutex<NoopRawMutex, &mut (dyn KeyStore + Send)> = Mutex::new(&mut key_store);
        let mut chacha_worker = ChaChaPolyWorker {
            key_store: Some(&key_store),
            requests: chachapoly_requests_rx,
            responses: chachapoly_responses_tx,
        };
        let mut core = Builder::<
            NoopRawMutex,
            RequestQueueSource<'_, '_, QUEUE_SIZE>,
            ResponseQueueSink<'_, '_, QUEUE_SIZE>,
            RequestQueueSink<'_, '_, QUEUE_SIZE>,
            ResponseQueueSource<'_, '_, QUEUE_SIZE>,
        >::default()
        .with_keystore(&key_store)
        .with_client(req_client_rx, resp_client_tx)
        .expect("failed to add client")
        .with_worker(
            &[
                RequestType::EncryptChaChaPoly,
                RequestType::EncryptChaChaPolyExternalKey,
                RequestType::DecryptChaChaPoly,
                RequestType::DecryptChaChaPolyExternalKey,
            ],
            chachapoly_requests_tx,
            chachapoly_responses_rx,
        )
        .expect("failed to add worker")
        .build();
        let mut api = Api::new(req_client_tx, resp_client_rx);

        // Import key
        let org_request_id = api
            .import_symmetric_key(KEY2.id, &key)
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
            Response::ImportSymmetricKey {
                client_id: _client_id,
                request_id,
            } => {
                assert_eq!(org_request_id, request_id)
            }
            _ => panic!("Unexpected response type"),
        };

        // Encrypt data
        let org_request_id = api
            .encrypt(
                ChaCha20Poly1305,
                KEY2.id,
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
                client_id: _client_id,
                request_id,
                ciphertext,
                tag,
            } => (request_id, ciphertext, tag),
            _ => panic!("Unexpected response type"),
        };
        assert_eq!(request_id, org_request_id);

        // Decrypt data
        let org_request_id = api
            .decrypt(ChaCha20Poly1305, KEY2.id, &nonce, ciphertext, &aad, tag)
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
                client_id: _client_id,
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
        let mut client_requests = AsyncQueue::<Request, QUEUE_SIZE>::new();
        let mut client_responses = AsyncQueue::<Response, QUEUE_SIZE>::new();
        let mut chachapoly_requests = AsyncQueue::<Request, QUEUE_SIZE>::new();
        let mut chachapoly_responses = AsyncQueue::<Response, QUEUE_SIZE>::new();
        let (req_client_rx, req_client_tx, resp_client_rx, resp_client_tx) =
            split_queues(&mut client_requests, &mut client_responses);
        let (
            chachapoly_requests_rx,
            chachapoly_requests_tx,
            chachapoly_responses_rx,
            chachapoly_responses_tx,
        ) = split_queues(&mut chachapoly_requests, &mut chachapoly_responses);

        let mut key_store = init_key_store();
        let key_store: Mutex<NoopRawMutex, &mut (dyn KeyStore + Send)> = Mutex::new(&mut key_store);
        let mut chacha_worker = ChaChaPolyWorker {
            key_store: Some(&key_store),
            requests: chachapoly_requests_rx,
            responses: chachapoly_responses_tx,
        };
        let mut core = Builder::<
            NoopRawMutex,
            RequestQueueSource<'_, '_, QUEUE_SIZE>,
            ResponseQueueSink<'_, '_, QUEUE_SIZE>,
            RequestQueueSink<'_, '_, QUEUE_SIZE>,
            ResponseQueueSource<'_, '_, QUEUE_SIZE>,
        >::default()
        .with_keystore(&key_store)
        .with_client(req_client_rx, resp_client_tx)
        .expect("failed to add client")
        .with_worker(
            &[
                RequestType::EncryptChaChaPoly,
                RequestType::EncryptChaChaPolyExternalKey,
                RequestType::DecryptChaChaPoly,
                RequestType::DecryptChaChaPolyExternalKey,
            ],
            chachapoly_requests_tx,
            chachapoly_responses_rx,
        )
        .expect("failed to add worker")
        .build();
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
                client_id: _client_id,
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
                client_id: _client_id,
                request_id,
                plaintext,
            } => (request_id, plaintext),
            _ => panic!("Unexpected response type"),
        };
        assert_eq!(request_id, org_request_id);
        assert_eq!(plaintext, org_plaintext)
    }

    #[async_std::test]
    async fn multiple_clients() {
        const REQUEST1_SIZE: usize = 16;
        const REQUEST2_SIZE: usize = 17;
        let mut random_output1 = [0u8; REQUEST1_SIZE];
        let mut random_output2 = [0u8; REQUEST2_SIZE];
        let rng = init_rng();
        let mut client1_requests = AsyncQueue::<Request, QUEUE_SIZE>::new();
        let mut client1_responses = AsyncQueue::<Response, QUEUE_SIZE>::new();
        let mut client2_requests = AsyncQueue::<Request, QUEUE_SIZE>::new();
        let mut client2_responses = AsyncQueue::<Response, QUEUE_SIZE>::new();
        let mut rng_requests = AsyncQueue::<Request, QUEUE_SIZE>::new();
        let mut rng_responses = AsyncQueue::<Response, QUEUE_SIZE>::new();
        let (req_client1_rx, req_client1_tx, resp_client1_rx, resp_client1_tx) =
            split_queues(&mut client1_requests, &mut client1_responses);
        let (req_client2_rx, req_client2_tx, resp_client2_rx, resp_client2_tx) =
            split_queues(&mut client2_requests, &mut client2_responses);
        let (rng_requests_rx, rng_requests_tx, rng_responses_rx, rng_responses_tx) =
            split_queues(&mut rng_requests, &mut rng_responses);
        let mut rng_worker = RngWorker {
            rng,
            requests: rng_requests_rx,
            responses: rng_responses_tx,
        };
        let mut core = Builder::<
            NoopRawMutex,
            RequestQueueSource<'_, '_, QUEUE_SIZE>,
            ResponseQueueSink<'_, '_, QUEUE_SIZE>,
            RequestQueueSink<'_, '_, QUEUE_SIZE>,
            ResponseQueueSource<'_, '_, QUEUE_SIZE>,
        >::default()
        .with_client(req_client1_rx, resp_client1_tx)
        .expect("failed to add client 1")
        .with_client(req_client2_rx, resp_client2_tx)
        .expect("failed to add client 2")
        .with_worker(&[RequestType::GetRandom], rng_requests_tx, rng_responses_rx)
        .expect("failed to add worker")
        .build();
        let mut api1 = Api::new(req_client1_tx, resp_client1_rx);
        let mut api2 = Api::new(req_client2_tx, resp_client2_rx);

        let org_request1_id = api1
            .get_random(&mut random_output1)
            .await
            .expect("failed to send request");
        let org_request2_id = api2
            .get_random(&mut random_output2)
            .await
            .expect("failed to send request");
        for _ in 0..2 {
            core.execute().await.expect("failed to forward request");
            rng_worker
                .execute()
                .await
                .expect("failed to process request");
            core.execute().await.expect("failed to forward response");
        }
        let client1_id = match api1.recv_response().await {
            None => panic!("Failed to receive expected response"),
            Some(response) => match response {
                Response::GetRandom {
                    client_id,
                    request_id,
                    data,
                } => {
                    assert_eq!(request_id, org_request1_id);
                    assert_eq!(data.len(), REQUEST1_SIZE);
                    client_id
                }
                _ => panic!("Unexpected response type {:?}", response),
            },
        };
        let client2_id = match api2.recv_response().await {
            None => panic!("Failed to receive expected response"),
            Some(response) => match response {
                Response::GetRandom {
                    client_id,
                    request_id,
                    data,
                } => {
                    assert_eq!(request_id, org_request2_id);
                    assert_eq!(data.len(), REQUEST2_SIZE);
                    client_id
                }
                _ => panic!("Unexpected response type {:?}", response),
            },
        };
        assert_ne!(client1_id, client2_id);
    }

    #[async_std::test]
    async fn no_worker_for_request() {
        const REQUEST_SIZE: usize = 16;
        let mut random_output = [0u8; REQUEST_SIZE];
        let mut client_requests = AsyncQueue::<Request, QUEUE_SIZE>::new();
        let mut client_responses = AsyncQueue::<Response, QUEUE_SIZE>::new();
        let (req_client_rx, req_client_tx, resp_client_rx, resp_client_tx) =
            split_queues(&mut client_requests, &mut client_responses);
        let mut core = Builder::<
            NoopRawMutex,
            RequestQueueSource<'_, '_, QUEUE_SIZE>,
            ResponseQueueSink<'_, '_, QUEUE_SIZE>,
            RequestQueueSink<'_, '_, QUEUE_SIZE>,
            ResponseQueueSource<'_, '_, QUEUE_SIZE>,
        >::default()
        .with_client(req_client_rx, resp_client_tx)
        .expect("failed to add client")
        .build();
        let mut api = Api::new(req_client_tx, resp_client_rx);

        let org_request_id = api
            .get_random(&mut random_output)
            .await
            .expect("failed to send request");
        core.execute().await.expect("failed to forward request");
        match api.recv_response().await {
            None => panic!("Failed to receive expected response"),
            Some(response) => match response {
                Response::Error {
                    client_id: _client_id,
                    request_id,
                    error,
                } => {
                    assert_eq!(request_id, org_request_id);
                    match error {
                        Error::NoWorkerForRequest => {}
                        _ => {
                            panic!("Unexpected error type {:?}", error)
                        }
                    }
                }
                _ => panic!("Unexpected response type {:?}", response),
            },
        }
    }
}
