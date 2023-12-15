mod tests {
    use embassy_sync::blocking_mutex::raw::NoopRawMutex;
    use embassy_sync::mutex::Mutex;
    use futures::future::join;
    use heimlig::client::api::Api;
    use heimlig::client::api::SymmetricEncryptionAlgorithm::{AesCbc, AesGcm, ChaCha20Poly1305};
    use heimlig::common::jobs::{Error, Request, RequestType, Response};
    use heimlig::common::limits::MAX_RANDOM_SIZE;
    use heimlig::crypto;
    use heimlig::crypto::rng::{EntropySource, Rng};
    use heimlig::hsm::core::Builder;
    use heimlig::hsm::keystore::{KeyId, KeyInfo, KeyPermissions, KeyStore, KeyType};
    use heimlig::hsm::workers::aes_worker::AesWorker;
    use heimlig::hsm::workers::chachapoly_worker::ChaChaPolyWorker;
    use heimlig::hsm::workers::ecc_worker::EccWorker;
    use heimlig::hsm::workers::rng_worker::RngWorker;
    use heimlig::integration::embassy::{
        AsyncQueue, RequestQueueSink, RequestQueueSource, ResponseQueueSink, ResponseQueueSource,
    };
    use heimlig::integration::memory_key_store::MemoryKeyStore;
    use sha2::{Digest, Sha256};

    const QUEUE_SIZE: usize = 8;
    const PLAINTEXT_SIZE: usize = 36;
    const PLAINTEXT_PADDED_SIZE: usize = 48;
    const AAD_SIZE: usize = 33;
    const TAG_SIZE: usize = 16;

    pub const NUM_KEYS: usize = 3;
    pub const TOTAL_KEY_SIZE: usize =
        SYM_128_KEY.ty.key_size() + SYM_256_KEY.ty.key_size() + ASYM_NIST_P256_KEY.ty.key_size();
    const SYM_128_KEY: KeyInfo = KeyInfo {
        id: KeyId(0),
        ty: KeyType::Symmetric128Bits,
        permissions: KeyPermissions {
            import: true,
            export: false,
            overwrite: false,
            delete: false,
        },
    };
    const SYM_256_KEY: KeyInfo = KeyInfo {
        id: KeyId(1),
        ty: KeyType::Symmetric256Bits,
        permissions: KeyPermissions {
            import: true,
            export: true,
            overwrite: false,
            delete: false,
        },
    };
    const ASYM_NIST_P256_KEY: KeyInfo = KeyInfo {
        id: KeyId(2),
        ty: KeyType::EccKeypairNistP256,
        permissions: KeyPermissions {
            import: true,
            export: true,
            overwrite: false,
            delete: false,
        },
    };

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

    fn init_key_store(key_infos: &[KeyInfo]) -> MemoryKeyStore<{ TOTAL_KEY_SIZE }, { NUM_KEYS }> {
        MemoryKeyStore::<{ TOTAL_KEY_SIZE }, { NUM_KEYS }>::try_new(key_infos)
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

    #[allow(clippy::type_complexity)]
    fn alloc_chachapoly_vars() -> (
        [u8; crypto::chacha20poly1305::KEY_SIZE],
        [u8; crypto::chacha20poly1305::NONCE_SIZE],
        [u8; PLAINTEXT_SIZE],
        [u8; AAD_SIZE],
        [u8; TAG_SIZE],
    ) {
        let key: [u8; crypto::chacha20poly1305::KEY_SIZE] = *b"Fortuna Major or Oddsbodikins???";
        let nonce: [u8; crypto::chacha20poly1305::NONCE_SIZE] =
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let plaintext: [u8; PLAINTEXT_SIZE] = *b"I solemnly swear I am up to no good!";
        let aad: [u8; AAD_SIZE] = *b"When in doubt, go to the library.";
        let tag: [u8; TAG_SIZE] = [0u8; TAG_SIZE];
        (key, nonce, plaintext, aad, tag)
    }

    #[allow(clippy::type_complexity)]
    fn alloc_aes_gcm_vars() -> (
        [u8; crypto::aes::KEY256_SIZE],
        [u8; crypto::aes::GCM_NONCE_SIZE],
        [u8; PLAINTEXT_SIZE],
        [u8; AAD_SIZE],
        [u8; TAG_SIZE],
    ) {
        let key: [u8; crypto::aes::KEY256_SIZE] = *b"Fortuna Major or Oddsbodikins???";
        let nonce: [u8; crypto::aes::GCM_NONCE_SIZE] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let plaintext: [u8; PLAINTEXT_SIZE] = *b"I solemnly swear I am up to no good!";
        let aad: [u8; AAD_SIZE] = *b"When in doubt, go to the library.";
        let tag: [u8; TAG_SIZE] = [0u8; TAG_SIZE];
        (key, nonce, plaintext, aad, tag)
    }

    fn alloc_aes_cbc_vars() -> (
        [u8; crypto::aes::KEY256_SIZE],
        [u8; crypto::aes::IV_SIZE],
        usize,
        [u8; PLAINTEXT_PADDED_SIZE],
    ) {
        let key: [u8; crypto::aes::KEY256_SIZE] = *b"Fortuna Major or Oddsbodikins???";
        let iv: [u8; crypto::aes::IV_SIZE] =
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let mut buffer: [u8; PLAINTEXT_PADDED_SIZE] = [0u8; PLAINTEXT_PADDED_SIZE];
        buffer[..PLAINTEXT_SIZE].copy_from_slice(b"I solemnly swear I am up to no good!");
        (key, iv, PLAINTEXT_SIZE, buffer)
    }

    #[async_std::test]
    async fn get_random() {
        const REQUEST_SIZE: usize = 16;
        const KEY_INFOS: [KeyInfo; 3] = [SYM_128_KEY, SYM_256_KEY, ASYM_NIST_P256_KEY];
        let mut random_output = [0u8; REQUEST_SIZE];
        let mut client_requests = AsyncQueue::<Request, QUEUE_SIZE>::new();
        let mut client_responses = AsyncQueue::<Response, QUEUE_SIZE>::new();
        let mut rng_requests = AsyncQueue::<Request, QUEUE_SIZE>::new();
        let mut rng_responses = AsyncQueue::<Response, QUEUE_SIZE>::new();
        let (req_client_rx, req_client_tx, resp_client_rx, resp_client_tx) =
            split_queues(&mut client_requests, &mut client_responses);
        let (rng_requests_rx, rng_requests_tx, rng_responses_rx, rng_responses_tx) =
            split_queues(&mut rng_requests, &mut rng_responses);
        let rng = Mutex::new(Rng::new(TestEntropySource::default(), None));
        let mut key_store = init_key_store(&KEY_INFOS);
        let key_store: Mutex<NoopRawMutex, &mut (dyn KeyStore + Send)> = Mutex::new(&mut key_store);
        let mut rng_worker = RngWorker {
            rng: &rng,
            key_store: &key_store,
            requests: rng_requests_rx,
            responses: rng_responses_tx,
        };
        let mut core = Builder::<
            NoopRawMutex,
            TestEntropySource,
            RequestQueueSource<'_, '_, QUEUE_SIZE>,
            ResponseQueueSink<'_, '_, QUEUE_SIZE>,
            RequestQueueSink<'_, '_, QUEUE_SIZE>,
            ResponseQueueSource<'_, '_, QUEUE_SIZE>,
        >::default()
        .with_client(req_client_rx, resp_client_tx)
        .expect("failed to add client")
        .with_worker(
            &[RequestType::GetRandom, RequestType::GenerateSymmetricKey],
            rng_requests_tx,
            rng_responses_rx,
        )
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
        let Some(response) = api.recv_response().await else {
            panic!("Failed to receive expected response")
        };
        let Response::GetRandom {
            client_id: _client_id,
            request_id,
            data,
        } = response
        else {
            panic!("Unexpected response type {:?}", response)
        };
        assert_eq!(request_id, org_request_id);
        assert_eq!(data.len(), REQUEST_SIZE);
    }

    #[async_std::test]
    async fn get_random_request_too_large() {
        const REQUEST_SIZE: usize = MAX_RANDOM_SIZE + 1;
        const KEY_INFOS: [KeyInfo; 3] = [SYM_128_KEY, SYM_256_KEY, ASYM_NIST_P256_KEY];
        let mut random_output = [0u8; REQUEST_SIZE];
        let mut client_requests = AsyncQueue::<Request, QUEUE_SIZE>::new();
        let mut client_responses = AsyncQueue::<Response, QUEUE_SIZE>::new();
        let mut rng_requests = AsyncQueue::<Request, QUEUE_SIZE>::new();
        let mut rng_responses = AsyncQueue::<Response, QUEUE_SIZE>::new();
        let (req_client_rx, req_client_tx, resp_client_rx, resp_client_tx) =
            split_queues(&mut client_requests, &mut client_responses);
        let (rng_requests_rx, rng_requests_tx, rng_responses_rx, rng_responses_tx) =
            split_queues(&mut rng_requests, &mut rng_responses);
        let rng = Mutex::new(Rng::new(TestEntropySource::default(), None));
        let mut key_store = init_key_store(&KEY_INFOS);
        let key_store: Mutex<NoopRawMutex, &mut (dyn KeyStore + Send)> = Mutex::new(&mut key_store);
        let mut rng_worker = RngWorker {
            rng: &rng,
            key_store: &key_store,
            requests: rng_requests_rx,
            responses: rng_responses_tx,
        };
        let mut core = Builder::<
            NoopRawMutex,
            TestEntropySource,
            RequestQueueSource<'_, '_, QUEUE_SIZE>,
            ResponseQueueSink<'_, '_, QUEUE_SIZE>,
            RequestQueueSink<'_, '_, QUEUE_SIZE>,
            ResponseQueueSource<'_, '_, QUEUE_SIZE>,
        >::default()
        .with_client(req_client_rx, resp_client_tx)
        .expect("failed to add client")
        .with_worker(
            &[RequestType::GetRandom, RequestType::GenerateSymmetricKey],
            rng_requests_tx,
            rng_responses_rx,
        )
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
        let Some(response) = api.recv_response().await else {
            panic!("Failed to receive expected response")
        };
        let Response::Error {
            client_id: _client_id,
            request_id,
            error,
        } = response
        else {
            panic!("Unexpected response type {:?}", response)
        };
        assert_eq!(request_id, org_request_id);
        assert_eq!(error, Error::RequestTooLarge);
    }

    #[async_std::test]
    async fn generate_symmetric_key() {
        const KEY_INFOS: [KeyInfo; 3] = [SYM_128_KEY, SYM_256_KEY, ASYM_NIST_P256_KEY];
        const KEY_INFO: KeyInfo = KEY_INFOS[1];
        let mut large_key_buffer = [0u8; 2 * KEY_INFO.ty.key_size()];
        let mut client_requests = AsyncQueue::<Request, QUEUE_SIZE>::new();
        let mut client_responses = AsyncQueue::<Response, QUEUE_SIZE>::new();
        let mut rng_requests = AsyncQueue::<Request, QUEUE_SIZE>::new();
        let mut rng_responses = AsyncQueue::<Response, QUEUE_SIZE>::new();
        let (req_client_rx, req_client_tx, resp_client_rx, resp_client_tx) =
            split_queues(&mut client_requests, &mut client_responses);
        let (rng_requests_rx, rng_requests_tx, rng_responses_rx, rng_responses_tx) =
            split_queues(&mut rng_requests, &mut rng_responses);
        let rng = Mutex::new(Rng::new(TestEntropySource::default(), None));
        let mut key_store = init_key_store(&KEY_INFOS);
        let key_store: Mutex<NoopRawMutex, &mut (dyn KeyStore + Send)> = Mutex::new(&mut key_store);
        let mut rng_worker = RngWorker {
            rng: &rng,
            key_store: &key_store,
            requests: rng_requests_rx,
            responses: rng_responses_tx,
        };
        let mut core = Builder::<
            NoopRawMutex,
            TestEntropySource,
            RequestQueueSource<'_, '_, QUEUE_SIZE>,
            ResponseQueueSink<'_, '_, QUEUE_SIZE>,
            RequestQueueSink<'_, '_, QUEUE_SIZE>,
            ResponseQueueSource<'_, '_, QUEUE_SIZE>,
        >::default()
        .with_keystore(&key_store)
        .with_client(req_client_rx, resp_client_tx)
        .expect("failed to add client")
        .with_worker(
            &[RequestType::GetRandom, RequestType::GenerateSymmetricKey],
            rng_requests_tx,
            rng_responses_rx,
        )
        .expect("failed to add worker")
        .build();
        let mut api = Api::new(req_client_tx, resp_client_rx);

        // Generate key
        let org_request_id = api
            .generate_symmetric_key(KEY_INFO.id, false)
            .await
            .expect("failed to send request");
        let (core_res, worker_res) = join(core.execute(), rng_worker.execute()).await;
        core_res.expect("failed to forward request");
        worker_res.expect("failed to process request");
        core.execute().await.expect("failed to forward response");
        let Some(response) = api.recv_response().await else {
            panic!("Failed to receive expected response")
        };
        let Response::GenerateSymmetricKey {
            client_id: _,
            request_id,
        } = response
        else {
            panic!("Unexpected response type {:?}", response)
        };
        assert_eq!(request_id, org_request_id);

        // Check key existence
        let org_request_id = api
            .is_key_available(KEY_INFO.id)
            .await
            .expect("failed to send request");
        core.execute().await.expect("failed to process request");
        let Some(response) = api.recv_response().await else {
            panic!("Failed to receive expected response")
        };
        let Response::IsKeyAvailable {
            client_id: _,
            request_id,
            is_available,
        } = response
        else {
            panic!("Unexpected response type {:?}", response)
        };
        assert_eq!(request_id, org_request_id);
        assert!(is_available);

        // Export key
        let org_request_id = api
            .export_symmetric_key(KEY_INFO.id, &mut large_key_buffer)
            .await
            .expect("failed to send request");
        core.execute().await.expect("failed to process request");
        let Some(response) = api.recv_response().await else {
            panic!("Failed to receive expected response")
        };
        let Response::ExportSymmetricKey {
            client_id: _,
            request_id,
            key,
        } = response
        else {
            panic!("Unexpected response type {:?}", response)
        };
        assert_eq!(request_id, org_request_id);
        assert_eq!(key.len(), KEY_INFO.ty.key_size()); // Large buffer was only used partially
    }

    #[async_std::test]
    async fn chachapoly_encrypt_in_place() {
        const KEY_INFOS: [KeyInfo; 3] = [SYM_128_KEY, SYM_256_KEY, ASYM_NIST_P256_KEY];
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
        let mut key_store = init_key_store(&KEY_INFOS);
        let key_store: Mutex<NoopRawMutex, &mut (dyn KeyStore + Send)> = Mutex::new(&mut key_store);
        let mut chacha_worker = ChaChaPolyWorker {
            key_store: &key_store,
            requests: chachapoly_requests_rx,
            responses: chachapoly_responses_tx,
        };
        let mut core = Builder::<
            NoopRawMutex,
            TestEntropySource,
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
            .import_symmetric_key(SYM_256_KEY.id, &key, false)
            .await
            .expect("failed to send request");
        core.execute()
            .await
            .expect("failed to process next request");
        let response = api
            .recv_response()
            .await
            .expect("Failed to receive expected response");
        let Response::ImportSymmetricKey {
            client_id: _client_id,
            request_id,
        } = response
        else {
            panic!("Unexpected response type")
        };
        assert_eq!(org_request_id, request_id);

        // Encrypt data
        let org_request_id = api
            .encrypt_in_place(
                ChaCha20Poly1305,
                SYM_256_KEY.id,
                &nonce,
                plaintext.len(),
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
        let Response::EncryptChaChaPoly {
            client_id: _,
            request_id,
            buffer,
            tag,
        } = api
            .recv_response()
            .await
            .expect("Failed to receive expected response")
        else {
            panic!("Unexpected response type")
        };
        assert_eq!(request_id, org_request_id);

        // Decrypt data
        let org_request_id = api
            .decrypt_in_place(ChaCha20Poly1305, SYM_256_KEY.id, &nonce, buffer, &aad, tag)
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
                buffer,
            } => (request_id, buffer),
            resp => panic!("Unexpected response type {:?}", resp),
        };
        assert_eq!(request_id, org_request_id);
        assert_eq!(plaintext, org_plaintext);
    }

    #[async_std::test]
    async fn chachapoly_encrypt_in_place_external_key() {
        const KEY_INFOS: [KeyInfo; 3] = [SYM_128_KEY, SYM_256_KEY, ASYM_NIST_P256_KEY];
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
        let mut key_store = init_key_store(&KEY_INFOS);
        let key_store: Mutex<NoopRawMutex, &mut (dyn KeyStore + Send)> = Mutex::new(&mut key_store);
        let mut chacha_worker = ChaChaPolyWorker {
            key_store: &key_store,
            requests: chachapoly_requests_rx,
            responses: chachapoly_responses_tx,
        };
        let mut core = Builder::<
            NoopRawMutex,
            TestEntropySource,
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
            .encrypt_in_place_external_key(
                ChaCha20Poly1305,
                &key,
                &nonce,
                plaintext.len(),
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
        let Response::EncryptChaChaPoly {
            client_id: _client_id,
            request_id,
            buffer,
            tag,
        } = api
            .recv_response()
            .await
            .expect("Failed to receive expected response")
        else {
            panic!("Unexpected response type")
        };
        assert_eq!(request_id, org_request_id);

        // Decrypt data
        let org_request_id = api
            .decrypt_in_place_external_key(ChaCha20Poly1305, &key, &nonce, buffer, &aad, tag)
            .await
            .expect("failed to send request");
        core.execute().await.expect("failed to forward request");
        chacha_worker
            .execute()
            .await
            .expect("failed to process request");
        core.execute().await.expect("failed to forward response");
        let Response::DecryptChaChaPoly {
            client_id: _client_id,
            request_id,
            buffer: plaintext,
        } = api
            .recv_response()
            .await
            .expect("Failed to receive expected response")
        else {
            panic!("Unexpected response type")
        };
        assert_eq!(request_id, org_request_id);
        assert_eq!(plaintext, org_plaintext)
    }

    #[async_std::test]
    async fn aes_gcm_encrypt_in_place() {
        const KEY_INFOS: [KeyInfo; 3] = [SYM_128_KEY, SYM_256_KEY, ASYM_NIST_P256_KEY];
        let (key, nonce, mut plaintext, aad, mut tag) = alloc_aes_gcm_vars();
        let org_plaintext = plaintext;
        let mut client_requests = AsyncQueue::<Request, QUEUE_SIZE>::new();
        let mut client_responses = AsyncQueue::<Response, QUEUE_SIZE>::new();
        let mut aes_gcm_requests = AsyncQueue::<Request, QUEUE_SIZE>::new();
        let mut aes_gcm_responses = AsyncQueue::<Response, QUEUE_SIZE>::new();
        let (req_client_rx, req_client_tx, resp_client_rx, resp_client_tx) =
            split_queues(&mut client_requests, &mut client_responses);
        let (aes_gcm_requests_rx, aes_gcm_requests_tx, aes_gcm_responses_rx, aes_gcm_responses_tx) =
            split_queues(&mut aes_gcm_requests, &mut aes_gcm_responses);
        let mut key_store = init_key_store(&KEY_INFOS);
        let key_store: Mutex<NoopRawMutex, &mut (dyn KeyStore + Send)> = Mutex::new(&mut key_store);
        let mut aes_gcm_worker = AesWorker {
            key_store: &key_store,
            requests: aes_gcm_requests_rx,
            responses: aes_gcm_responses_tx,
        };
        let mut core = Builder::<
            NoopRawMutex,
            TestEntropySource,
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
                RequestType::EncryptAesGcm,
                RequestType::EncryptAesGcmExternalKey,
                RequestType::DecryptAesGcm,
                RequestType::DecryptAesGcmExternalKey,
            ],
            aes_gcm_requests_tx,
            aes_gcm_responses_rx,
        )
        .expect("failed to add worker")
        .build();
        let mut api = Api::new(req_client_tx, resp_client_rx);

        // Import key
        let org_request_id = api
            .import_symmetric_key(SYM_256_KEY.id, &key, false)
            .await
            .expect("failed to send request");
        core.execute()
            .await
            .expect("failed to process next request");
        let response = api
            .recv_response()
            .await
            .expect("Failed to receive expected response");
        let Response::ImportSymmetricKey {
            client_id: _client_id,
            request_id,
        } = response
        else {
            panic!("Unexpected response type")
        };
        assert_eq!(org_request_id, request_id);

        // Encrypt data
        let org_request_id = api
            .encrypt_in_place(
                AesGcm,
                SYM_256_KEY.id,
                &nonce,
                plaintext.len(),
                &mut plaintext,
                &aad,
                &mut tag,
            )
            .await
            .expect("failed to send request");
        core.execute().await.expect("failed to forward request");
        aes_gcm_worker
            .execute()
            .await
            .expect("failed to process request");
        core.execute().await.expect("failed to forward response");
        let Response::EncryptAesGcm {
            client_id: _,
            request_id,
            buffer,
            tag,
        } = api
            .recv_response()
            .await
            .expect("Failed to receive expected response")
        else {
            panic!("Unexpected response type")
        };
        assert_eq!(request_id, org_request_id);

        // Decrypt data
        let org_request_id = api
            .decrypt_in_place(AesGcm, SYM_256_KEY.id, &nonce, buffer, &aad, tag)
            .await
            .expect("failed to send request");
        core.execute().await.expect("failed to forward request");
        aes_gcm_worker
            .execute()
            .await
            .expect("failed to process request");
        core.execute().await.expect("failed to forward response");
        let Response::DecryptAesGcm {
            client_id: _client_id,
            request_id,
            buffer: plaintext,
        } = api
            .recv_response()
            .await
            .expect("Failed to receive expected response")
        else {
            panic!("Unexpected response type")
        };
        assert_eq!(request_id, org_request_id);
        assert_eq!(plaintext, org_plaintext);
    }

    #[async_std::test]
    async fn aes_gcm_encrypt_in_place_external_key() {
        const KEY_INFOS: [KeyInfo; 3] = [SYM_128_KEY, SYM_256_KEY, ASYM_NIST_P256_KEY];
        let (key, nonce, mut plaintext, aad, mut tag) = alloc_aes_gcm_vars();
        let org_plaintext = plaintext;
        let mut client_requests = AsyncQueue::<Request, QUEUE_SIZE>::new();
        let mut client_responses = AsyncQueue::<Response, QUEUE_SIZE>::new();
        let mut aes_gcm_requests = AsyncQueue::<Request, QUEUE_SIZE>::new();
        let mut aes_gcm_responses = AsyncQueue::<Response, QUEUE_SIZE>::new();
        let (req_client_rx, req_client_tx, resp_client_rx, resp_client_tx) =
            split_queues(&mut client_requests, &mut client_responses);
        let (aes_gcm_requests_rx, aes_gcm_requests_tx, aes_gcm_responses_rx, aes_gcm_responses_tx) =
            split_queues(&mut aes_gcm_requests, &mut aes_gcm_responses);

        let mut key_store = init_key_store(&KEY_INFOS);
        let key_store: Mutex<NoopRawMutex, &mut (dyn KeyStore + Send)> = Mutex::new(&mut key_store);
        let mut aes_gcm_worker = AesWorker {
            key_store: &key_store,
            requests: aes_gcm_requests_rx,
            responses: aes_gcm_responses_tx,
        };
        let mut core = Builder::<
            NoopRawMutex,
            TestEntropySource,
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
                RequestType::EncryptAesGcm,
                RequestType::EncryptAesGcmExternalKey,
                RequestType::DecryptAesGcm,
                RequestType::DecryptAesGcmExternalKey,
            ],
            aes_gcm_requests_tx,
            aes_gcm_responses_rx,
        )
        .expect("failed to add worker")
        .build();
        let mut api = Api::new(req_client_tx, resp_client_rx);

        // Encrypt data
        let org_request_id = api
            .encrypt_in_place_external_key(
                AesGcm,
                &key,
                &nonce,
                plaintext.len(),
                &mut plaintext,
                &aad,
                &mut tag,
            )
            .await
            .expect("failed to send request");
        core.execute().await.expect("failed to forward request");
        aes_gcm_worker
            .execute()
            .await
            .expect("failed to process request");
        core.execute().await.expect("failed to forward response");
        let Response::EncryptAesGcm {
            client_id: _client_id,
            request_id,
            buffer,
            tag,
        } = api
            .recv_response()
            .await
            .expect("Failed to receive expected response")
        else {
            panic!("Unexpected response type")
        };
        assert_eq!(request_id, org_request_id);

        // Decrypt data
        let org_request_id = api
            .decrypt_in_place_external_key(AesGcm, &key, &nonce, buffer, &aad, tag)
            .await
            .expect("failed to send request");
        core.execute().await.expect("failed to forward request");
        aes_gcm_worker
            .execute()
            .await
            .expect("failed to process request");
        core.execute().await.expect("failed to forward response");
        let Response::DecryptAesGcm {
            client_id: _client_id,
            request_id,
            buffer: plaintext,
        } = api
            .recv_response()
            .await
            .expect("Failed to receive expected response")
        else {
            panic!("Unexpected response type")
        };
        assert_eq!(request_id, org_request_id);
        assert_eq!(plaintext, org_plaintext)
    }

    #[async_std::test]
    async fn aes_cbc_encrypt_in_place() {
        const KEY_INFOS: [KeyInfo; 3] = [SYM_128_KEY, SYM_256_KEY, ASYM_NIST_P256_KEY];
        let (key, iv, plaintext_size, mut buffer) = alloc_aes_cbc_vars();
        let org_buffer = buffer;
        let mut client_requests = AsyncQueue::<Request, QUEUE_SIZE>::new();
        let mut client_responses = AsyncQueue::<Response, QUEUE_SIZE>::new();
        let mut aes_cbc_requests = AsyncQueue::<Request, QUEUE_SIZE>::new();
        let mut aes_cbc_responses = AsyncQueue::<Response, QUEUE_SIZE>::new();
        let (req_client_rx, req_client_tx, resp_client_rx, resp_client_tx) =
            split_queues(&mut client_requests, &mut client_responses);
        let (aes_cbc_requests_rx, aes_cbc_requests_tx, aes_cbc_responses_rx, aes_cbc_responses_tx) =
            split_queues(&mut aes_cbc_requests, &mut aes_cbc_responses);
        let mut key_store = init_key_store(&KEY_INFOS);
        let key_store: Mutex<NoopRawMutex, &mut (dyn KeyStore + Send)> = Mutex::new(&mut key_store);
        let mut aes_cbc_worker = AesWorker {
            key_store: &key_store,
            requests: aes_cbc_requests_rx,
            responses: aes_cbc_responses_tx,
        };
        let mut core = Builder::<
            NoopRawMutex,
            TestEntropySource,
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
                RequestType::EncryptAesCbc,
                RequestType::EncryptAesCbcExternalKey,
                RequestType::DecryptAesCbc,
                RequestType::DecryptAesCbcExternalKey,
            ],
            aes_cbc_requests_tx,
            aes_cbc_responses_rx,
        )
        .expect("failed to add worker")
        .build();
        let mut api = Api::new(req_client_tx, resp_client_rx);

        // Import key
        let org_request_id = api
            .import_symmetric_key(SYM_256_KEY.id, &key, false)
            .await
            .expect("failed to send request");
        core.execute()
            .await
            .expect("failed to process next request");
        let response = api
            .recv_response()
            .await
            .expect("Failed to receive expected response");
        let Response::ImportSymmetricKey {
            client_id: _client_id,
            request_id,
        } = response
        else {
            panic!("Unexpected response type")
        };
        assert_eq!(org_request_id, request_id);

        // Encrypt data
        let org_request_id = api
            .encrypt_in_place(
                AesCbc,
                SYM_256_KEY.id,
                &iv,
                plaintext_size,
                &mut buffer,
                &[],
                &mut [],
            )
            .await
            .expect("failed to send request");
        core.execute().await.expect("failed to forward request");
        aes_cbc_worker
            .execute()
            .await
            .expect("failed to process request");
        core.execute().await.expect("failed to forward response");
        let Response::EncryptAesCbc {
            client_id: _,
            request_id,
            buffer,
        } = api
            .recv_response()
            .await
            .expect("Failed to receive expected response")
        else {
            panic!("Unexpected response type")
        };
        assert_eq!(request_id, org_request_id);

        // Decrypt data
        let org_request_id = api
            .decrypt_in_place(AesCbc, SYM_256_KEY.id, &iv, buffer, &[], &[])
            .await
            .expect("failed to send request");
        core.execute().await.expect("failed to forward request");
        aes_cbc_worker
            .execute()
            .await
            .expect("failed to process request");
        core.execute().await.expect("failed to forward response");
        let Response::DecryptAesCbc {
            client_id: _client_id,
            request_id,
            plaintext,
        } = api
            .recv_response()
            .await
            .expect("Failed to receive expected response")
        else {
            panic!("Unexpected response type")
        };
        assert_eq!(request_id, org_request_id);
        let org_plaintext = &org_buffer[..PLAINTEXT_SIZE];
        assert_eq!(plaintext, org_plaintext);
    }

    #[async_std::test]
    async fn aes_cbc_encrypt_in_place_external_key() {
        const KEY_INFOS: [KeyInfo; 3] = [SYM_128_KEY, SYM_256_KEY, ASYM_NIST_P256_KEY];
        let (key, iv, plaintext_size, mut buffer) = alloc_aes_cbc_vars();
        let org_buffer = buffer;
        let mut client_requests = AsyncQueue::<Request, QUEUE_SIZE>::new();
        let mut client_responses = AsyncQueue::<Response, QUEUE_SIZE>::new();
        let mut aes_cbc_requests = AsyncQueue::<Request, QUEUE_SIZE>::new();
        let mut aes_cbc_responses = AsyncQueue::<Response, QUEUE_SIZE>::new();
        let (req_client_rx, req_client_tx, resp_client_rx, resp_client_tx) =
            split_queues(&mut client_requests, &mut client_responses);
        let (aes_cbc_requests_rx, aes_cbc_requests_tx, aes_cbc_responses_rx, aes_cbc_responses_tx) =
            split_queues(&mut aes_cbc_requests, &mut aes_cbc_responses);
        let mut key_store = init_key_store(&KEY_INFOS);
        let key_store: Mutex<NoopRawMutex, &mut (dyn KeyStore + Send)> = Mutex::new(&mut key_store);
        let mut aes_cbc_worker = AesWorker {
            key_store: &key_store,
            requests: aes_cbc_requests_rx,
            responses: aes_cbc_responses_tx,
        };
        let mut core = Builder::<
            NoopRawMutex,
            TestEntropySource,
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
                RequestType::EncryptAesCbc,
                RequestType::EncryptAesCbcExternalKey,
                RequestType::DecryptAesCbc,
                RequestType::DecryptAesCbcExternalKey,
            ],
            aes_cbc_requests_tx,
            aes_cbc_responses_rx,
        )
        .expect("failed to add worker")
        .build();
        let mut api = Api::new(req_client_tx, resp_client_rx);

        // Encrypt data
        let org_request_id = api
            .encrypt_in_place_external_key(
                AesCbc,
                &key,
                &iv,
                plaintext_size,
                &mut buffer,
                &[],
                &mut [],
            )
            .await
            .expect("failed to send request");
        core.execute().await.expect("failed to forward request");
        aes_cbc_worker
            .execute()
            .await
            .expect("failed to process request");
        core.execute().await.expect("failed to forward response");
        let Response::EncryptAesCbc {
            client_id: _client_id,
            request_id,
            buffer,
        } = api
            .recv_response()
            .await
            .expect("Failed to receive expected response")
        else {
            panic!("Unexpected response type")
        };
        assert_eq!(request_id, org_request_id);

        // Decrypt data
        let org_request_id = api
            .decrypt_in_place_external_key(AesCbc, &key, &iv, buffer, &[], &[])
            .await
            .expect("failed to send request");
        core.execute().await.expect("failed to forward request");
        aes_cbc_worker
            .execute()
            .await
            .expect("failed to process request");
        core.execute().await.expect("failed to forward response");
        let Response::DecryptAesCbc {
            client_id: _client_id,
            request_id,
            plaintext,
        } = api
            .recv_response()
            .await
            .expect("Failed to receive expected response")
        else {
            panic!("Unexpected response type")
        };
        assert_eq!(request_id, org_request_id);
        let org_plaintext = &org_buffer[..PLAINTEXT_SIZE];
        assert_eq!(plaintext, org_plaintext)
    }

    #[async_std::test]
    async fn sign_verify_nist_p256() {
        const KEY_INFOS: [KeyInfo; 3] = [SYM_128_KEY, SYM_256_KEY, ASYM_NIST_P256_KEY];
        const KEY_INFO: KeyInfo = KEY_INFOS[2];
        let mut large_public_key_buffer = [0u8; 2 * KEY_INFO.ty.public_key_size()];
        let mut large_private_key_buffer = [0u8; 2 * KEY_INFO.ty.private_key_size()];
        let mut signature = [0u8; KEY_INFO.ty.signature_size()];
        let mut signature_external_key = [0u8; KEY_INFO.ty.signature_size()];
        let message: &[u8] = b"But my patience isn't limitless... unlike my authority.";
        let digest = Sha256::digest(message);
        let mut client_requests = AsyncQueue::<Request, QUEUE_SIZE>::new();
        let mut client_responses = AsyncQueue::<Response, QUEUE_SIZE>::new();
        let mut ecc_requests = AsyncQueue::<Request, QUEUE_SIZE>::new();
        let mut ecc_responses = AsyncQueue::<Response, QUEUE_SIZE>::new();
        let (req_client_rx, req_client_tx, resp_client_rx, resp_client_tx) =
            split_queues(&mut client_requests, &mut client_responses);
        let (ecc_requests_rx, ecc_requests_tx, ecc_responses_rx, ecc_responses_tx) =
            split_queues(&mut ecc_requests, &mut ecc_responses);
        let rng = Mutex::new(Rng::new(TestEntropySource::default(), None));
        let mut key_store = init_key_store(&KEY_INFOS);
        let key_store: Mutex<NoopRawMutex, &mut (dyn KeyStore + Send)> = Mutex::new(&mut key_store);
        let mut ecc_worker = EccWorker {
            rng: &rng,
            key_store: &key_store,
            requests: ecc_requests_rx,
            responses: ecc_responses_tx,
        };
        let mut core = Builder::<
            NoopRawMutex,
            TestEntropySource,
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
                RequestType::GenerateKeyPair,
                RequestType::Sign,
                RequestType::Verify,
                RequestType::SignExternalKey,
                RequestType::VerifyExternalKey,
            ],
            ecc_requests_tx,
            ecc_responses_rx,
        )
        .expect("failed to add worker")
        .build();
        let mut api = Api::new(req_client_tx, resp_client_rx);

        // Generate key
        let org_request_id = api
            .generate_key_pair(KEY_INFO.id, false)
            .await
            .expect("failed to send request");
        let (core_res, worker_res) = join(core.execute(), ecc_worker.execute()).await;
        core_res.expect("failed to forward request");
        worker_res.expect("failed to process request");
        core.execute().await.expect("failed to forward response");
        let Some(response) = api.recv_response().await else {
            panic!("Failed to receive expected response")
        };
        let Response::GenerateKeyPair {
            client_id: _client_id,
            request_id,
        } = response
        else {
            panic!("Unexpected response type {:?}", response)
        };
        assert_eq!(request_id, org_request_id);

        // Check key existence
        let org_request_id = api
            .is_key_available(KEY_INFO.id)
            .await
            .expect("failed to send request");
        core.execute().await.expect("failed to process request");
        let Some(response) = api.recv_response().await else {
            panic!("Failed to receive expected response")
        };
        let Response::IsKeyAvailable {
            client_id: _,
            request_id,
            is_available,
        } = response
        else {
            panic!("Unexpected response type {:?}", response)
        };
        assert_eq!(request_id, org_request_id);
        assert!(is_available);

        // Export public key
        let org_request_id = api
            .export_public_key(KEY_INFO.id, &mut large_public_key_buffer)
            .await
            .expect("failed to send request");
        core.execute().await.expect("failed to process request");
        let Some(response) = api.recv_response().await else {
            panic!("Failed to receive expected response")
        };
        let Response::ExportPublicKey {
            client_id: _,
            request_id,
            public_key,
        } = response
        else {
            panic!("Unexpected response type {:?}", response)
        };
        assert_eq!(request_id, org_request_id);
        assert_eq!(public_key.len(), KEY_INFO.ty.public_key_size()); // Large buffer was only used partially

        // Export private key
        let org_request_id = api
            .export_private_key(KEY_INFO.id, &mut large_private_key_buffer)
            .await
            .expect("failed to send request");
        core.execute().await.expect("failed to process request");
        let Some(response) = api.recv_response().await else {
            panic!("Failed to receive expected response")
        };
        let Response::ExportPrivateKey {
            client_id: _,
            request_id,
            private_key,
        } = response
        else {
            panic!("Unexpected response type {:?}", response)
        };
        assert_eq!(request_id, org_request_id);
        assert_eq!(private_key.len(), KEY_INFO.ty.private_key_size()); // Large buffer was only used partially

        // Sign message.
        let org_request_id = api
            .sign(KEY_INFO.id, message, false, &mut signature)
            .await
            .expect("failed to send request");
        core.execute().await.expect("failed to process request");
        ecc_worker
            .execute()
            .await
            .expect("failed to process request");
        core.execute().await.expect("failed to forward response");
        let Some(response) = api.recv_response().await else {
            panic!("Failed to receive expected response")
        };
        let Response::Sign {
            client_id: _,
            request_id,
            signature,
        } = response
        else {
            panic!("Unexpected response type {:?}", response)
        };
        assert_eq!(request_id, org_request_id);

        // Verify message.
        let org_request_id = api
            .verify(KEY_INFO.id, message, false, signature)
            .await
            .expect("failed to send request");
        core.execute().await.expect("failed to forward request");
        ecc_worker
            .execute()
            .await
            .expect("failed to process request");
        core.execute().await.expect("failed to forward response");
        let Some(response) = api.recv_response().await else {
            panic!("Failed to receive expected response")
        };
        let Response::Verify {
            client_id: _,
            request_id,
            verified,
        } = response
        else {
            panic!("Unexpected response type {:?}", response)
        };
        assert_eq!(request_id, org_request_id);
        assert!(verified);

        // Sign digest with external key.
        let org_request_id = api
            .sign_external_key(
                private_key,
                digest.as_slice(),
                true,
                &mut signature_external_key,
            )
            .await
            .expect("failed to send request");
        core.execute().await.expect("failed to process request");
        ecc_worker
            .execute()
            .await
            .expect("failed to process request");
        core.execute().await.expect("failed to forward response");
        let Some(response) = api.recv_response().await else {
            panic!("Failed to receive expected response")
        };
        let Response::Sign {
            client_id: _,
            request_id,
            signature: signature_external_key,
        } = response
        else {
            panic!("Unexpected response type {:?}", response)
        };
        assert_eq!(request_id, org_request_id);

        assert_eq!(signature, signature_external_key);

        // Verify digest with external key.
        let org_request_id = api
            .verify_external_key(public_key, digest.as_slice(), true, signature_external_key)
            .await
            .expect("failed to send request");
        core.execute().await.expect("failed to forward request");
        ecc_worker
            .execute()
            .await
            .expect("failed to process request");
        core.execute().await.expect("failed to forward response");
        let Some(response) = api.recv_response().await else {
            panic!("Failed to receive expected response")
        };
        let Response::Verify {
            client_id: _,
            request_id,
            verified,
        } = response
        else {
            panic!("Unexpected response type {:?}", response)
        };
        assert_eq!(request_id, org_request_id);
        assert!(verified);
    }

    #[async_std::test]
    async fn multiple_clients() {
        const REQUEST1_SIZE: usize = 16;
        const REQUEST2_SIZE: usize = 17;
        const KEY_INFOS: [KeyInfo; 3] = [SYM_128_KEY, SYM_256_KEY, ASYM_NIST_P256_KEY];
        let mut random_output1 = [0u8; REQUEST1_SIZE];
        let mut random_output2 = [0u8; REQUEST2_SIZE];
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
        let rng = Mutex::new(Rng::new(TestEntropySource::default(), None));
        let mut key_store = init_key_store(&KEY_INFOS);
        let key_store: Mutex<NoopRawMutex, &mut (dyn KeyStore + Send)> = Mutex::new(&mut key_store);
        let mut rng_worker = RngWorker {
            rng: &rng,
            key_store: &key_store,
            requests: rng_requests_rx,
            responses: rng_responses_tx,
        };
        let mut core = Builder::<
            NoopRawMutex,
            TestEntropySource,
            RequestQueueSource<'_, '_, QUEUE_SIZE>,
            ResponseQueueSink<'_, '_, QUEUE_SIZE>,
            RequestQueueSink<'_, '_, QUEUE_SIZE>,
            ResponseQueueSource<'_, '_, QUEUE_SIZE>,
        >::default()
        .with_client(req_client1_rx, resp_client1_tx)
        .expect("failed to add client 1")
        .with_client(req_client2_rx, resp_client2_tx)
        .expect("failed to add client 2")
        .with_worker(
            &[RequestType::GetRandom, RequestType::GenerateSymmetricKey],
            rng_requests_tx,
            rng_responses_rx,
        )
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
        let Some(response) = api1.recv_response().await else {
            panic!("Failed to receive expected response")
        };
        let Response::GetRandom {
            client_id: client1_id,
            request_id,
            data,
        } = response
        else {
            panic!("Unexpected response type {:?}", response)
        };
        assert_eq!(request_id, org_request1_id);
        assert_eq!(data.len(), REQUEST1_SIZE);
        let Some(response) = api2.recv_response().await else {
            panic!("Failed to receive expected response")
        };
        let Response::GetRandom {
            client_id: client2_id,
            request_id,
            data,
        } = response
        else {
            panic!("Unexpected response type {:?}", response)
        };
        assert_eq!(request_id, org_request2_id);
        assert_eq!(data.len(), REQUEST2_SIZE);
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
            TestEntropySource,
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
        let Some(response) = api.recv_response().await else {
            panic!("Failed to receive expected response")
        };
        let Response::Error {
            client_id: _client_id,
            request_id,
            error,
        } = response
        else {
            panic!("Unexpected response type {:?}", response)
        };
        assert_eq!(request_id, org_request_id);
        let Error::NoWorkerForRequest = error else {
            panic!("Unexpected error type {:?}", error)
        };
    }
}
