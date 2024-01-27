mod tests {
    use embassy_sync::{blocking_mutex::raw::NoopRawMutex, mutex::Mutex};
    use heimlig::{
        client::api::{
            Api,
            SymmetricAlgorithm::{AesCbc, AesGcm, ChaCha20Poly1305},
        },
        common::{
            jobs::{Error, HashAlgorithm, Request, RequestType, Response},
            limits::MAX_RANDOM_SIZE,
        },
        crypto,
        hsm::{
            core::{Builder, Core},
            keystore::{KeyId, KeyInfo, KeyPermissions, KeyStore, KeyType},
            workers::{
                aes_worker::AesWorker, chachapoly_worker::ChaChaPolyWorker, ecc_worker::EccWorker,
                hmac_worker::HmacWorker, rng_worker::RngWorker,
            },
        },
        integration::{
            embassy::{
                AsyncQueue, RequestQueueSink, RequestQueueSource, ResponseQueueSink,
                ResponseQueueSource,
            },
            memory_key_store::MemoryKeyStore,
        },
    };
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
    use sha2::{Digest, Sha256};

    const QUEUE_SIZE: usize = 8;
    pub const NUM_KEYS: usize = 3;
    pub const TOTAL_KEY_SIZE: usize =
        SYM_128_KEY.ty.key_size() + SYM_256_KEY.ty.key_size() + ASYM_NIST_P256_KEY.ty.key_size();
    const SYM_128_KEY: KeyInfo = KeyInfo {
        id: KeyId(0),
        ty: KeyType::Symmetric128Bits,
        permissions: KeyPermissions {
            import: true,
            export_private: false,
            overwrite: false,
            delete: false,
        },
    };
    const SYM_256_KEY: KeyInfo = KeyInfo {
        id: KeyId(1),
        ty: KeyType::Symmetric256Bits,
        permissions: KeyPermissions {
            import: true,
            export_private: true,
            overwrite: false,
            delete: false,
        },
    };
    const ASYM_NIST_P256_KEY: KeyInfo = KeyInfo {
        id: KeyId(2),
        ty: KeyType::EccKeypairNistP256,
        permissions: KeyPermissions {
            import: true,
            export_private: true,
            overwrite: false,
            delete: false,
        },
    };
    const KEY_INFOS: [KeyInfo; 3] = [SYM_128_KEY, SYM_256_KEY, ASYM_NIST_P256_KEY];

    fn init_key_store(key_infos: &[KeyInfo]) -> MemoryKeyStore<{ TOTAL_KEY_SIZE }, { NUM_KEYS }> {
        MemoryKeyStore::<{ TOTAL_KEY_SIZE }, { NUM_KEYS }>::try_new(key_infos)
            .expect("failed to create key store")
    }

    fn init_rng() -> Mutex<NoopRawMutex, ChaCha20Rng> {
        Mutex::new(ChaCha20Rng::from_seed([0u8; 32]))
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

    macro_rules! get_response_from_worker {
        ($api:expr, $core:expr, $worker:expr) => {{
            $core.execute().await.expect("failed to forward request");
            $worker.execute().await.expect("failed to process request");
            $core.execute().await.expect("failed to forward response");
            let Some(response) = $api.recv_response().await else {
                panic!("Failed to receive expected response")
            };

            response
        }};
    }

    async fn get_response_from_core<'data>(
        api: &mut Api<
            'data,
            RequestQueueSink<'_, 'data, QUEUE_SIZE>,
            ResponseQueueSource<'_, 'data, QUEUE_SIZE>,
        >,
        core: &mut Core<
            'data,
            '_,
            NoopRawMutex,
            RequestQueueSource<'_, 'data, QUEUE_SIZE>,
            ResponseQueueSink<'_, 'data, QUEUE_SIZE>,
            RequestQueueSink<'_, 'data, QUEUE_SIZE>,
            ResponseQueueSource<'_, 'data, QUEUE_SIZE>,
        >,
    ) -> Response<'data> {
        core.execute().await.expect("failed to process request");
        let Some(response) = api.recv_response().await else {
            panic!("Failed to receive expected response")
        };

        response
    }

    async fn check_key_availability<'data>(
        api: &mut Api<
            'data,
            RequestQueueSink<'_, 'data, QUEUE_SIZE>,
            ResponseQueueSource<'_, 'data, QUEUE_SIZE>,
        >,
        core: &mut Core<
            'data,
            '_,
            NoopRawMutex,
            RequestQueueSource<'_, 'data, QUEUE_SIZE>,
            ResponseQueueSink<'_, 'data, QUEUE_SIZE>,
            RequestQueueSink<'_, 'data, QUEUE_SIZE>,
            ResponseQueueSource<'_, 'data, QUEUE_SIZE>,
        >,
        key_id: KeyId,
    ) {
        let org_request_id = api
            .is_key_available(key_id)
            .await
            .expect("failed to send request");
        let Response::IsKeyAvailable {
            client_id: _,
            request_id,
            is_available,
        } = get_response_from_core(api, core).await
        else {
            panic!("Unexpected response type")
        };
        assert_eq!(request_id, org_request_id);
        assert!(is_available);
    }

    async fn import_symmetric_key<'data>(
        api: &mut Api<
            'data,
            RequestQueueSink<'_, 'data, QUEUE_SIZE>,
            ResponseQueueSource<'_, 'data, QUEUE_SIZE>,
        >,
        core: &mut Core<
            'data,
            '_,
            NoopRawMutex,
            RequestQueueSource<'_, 'data, QUEUE_SIZE>,
            ResponseQueueSink<'_, 'data, QUEUE_SIZE>,
            RequestQueueSink<'_, 'data, QUEUE_SIZE>,
            ResponseQueueSource<'_, 'data, QUEUE_SIZE>,
        >,
        key_id: KeyId,
        key: &'data [u8],
    ) {
        let org_request_id = api
            .import_symmetric_key(key_id, key, false)
            .await
            .expect("failed to send request");
        let Response::ImportSymmetricKey {
            client_id: _client_id,
            request_id,
        } = get_response_from_core(api, core).await
        else {
            panic!("Unexpected response type")
        };
        assert_eq!(org_request_id, request_id);
    }

    fn allocate_channel<'data>() -> (
        AsyncQueue<Request<'data>, QUEUE_SIZE>,
        AsyncQueue<Response<'data>, QUEUE_SIZE>,
    ) {
        (
            AsyncQueue::<Request, QUEUE_SIZE>::new(),
            AsyncQueue::<Response, QUEUE_SIZE>::new(),
        )
    }

    fn init_core<'data, 'ch, 'keystore>(
        request_types: &[RequestType],
        client_requests: &'ch mut AsyncQueue<Request<'data>, QUEUE_SIZE>,
        client_responses: &'ch mut AsyncQueue<Response<'data>, QUEUE_SIZE>,
        worker_requests: &'ch mut AsyncQueue<Request<'data>, QUEUE_SIZE>,
        worker_responses: &'ch mut AsyncQueue<Response<'data>, QUEUE_SIZE>,
        key_store: Option<&'keystore Mutex<NoopRawMutex, &'keystore mut (dyn KeyStore + Send)>>,
    ) -> (
        Api<
            'data,
            RequestQueueSink<'ch, 'data, QUEUE_SIZE>,
            ResponseQueueSource<'ch, 'data, QUEUE_SIZE>,
        >,
        Core<
            'data,
            'keystore,
            NoopRawMutex,
            RequestQueueSource<'ch, 'data, QUEUE_SIZE>,
            ResponseQueueSink<'ch, 'data, QUEUE_SIZE>,
            RequestQueueSink<'ch, 'data, QUEUE_SIZE>,
            ResponseQueueSource<'ch, 'data, QUEUE_SIZE>,
        >,
        RequestQueueSource<'ch, 'data, QUEUE_SIZE>,
        ResponseQueueSink<'ch, 'data, QUEUE_SIZE>,
    ) {
        let (req_client_rx, req_client_tx, resp_client_rx, resp_client_tx) =
            split_queues(client_requests, client_responses);
        let (req_worker_rx, req_worker_tx, resp_worker_rx, resp_worker_tx) =
            split_queues(worker_requests, worker_responses);
        let core_builder = Builder::<
            NoopRawMutex,
            RequestQueueSource<'_, '_, QUEUE_SIZE>,
            ResponseQueueSink<'_, '_, QUEUE_SIZE>,
            RequestQueueSink<'_, '_, QUEUE_SIZE>,
            ResponseQueueSource<'_, '_, QUEUE_SIZE>,
        >::default();

        let core_builder = if let Some(key_store) = key_store {
            core_builder.with_keystore(key_store)
        } else {
            core_builder
        };

        let core = core_builder
            .with_client(req_client_rx, resp_client_tx)
            .expect("failed to add client")
            .with_worker(request_types, req_worker_tx, resp_worker_rx)
            .expect("failed to add worker")
            .build();

        let api = Api::new(req_client_tx, resp_client_rx);

        (api, core, req_worker_rx, resp_worker_tx)
    }

    #[async_std::test]
    async fn get_random() {
        const REQUEST_SIZE: usize = 16;
        let mut random_output = [0u8; REQUEST_SIZE];

        let (mut client_requests, mut client_responses) = allocate_channel();
        let (mut worker_requests, mut worker_responses) = allocate_channel();
        let (mut api, mut core, req_worker_rx, resp_worker_tx) = init_core(
            &[RequestType::GetRandom, RequestType::GenerateSymmetricKey],
            &mut client_requests,
            &mut client_responses,
            &mut worker_requests,
            &mut worker_responses,
            None,
        );
        let rng = init_rng();
        let mut key_store = init_key_store(&KEY_INFOS);
        let key_store: Mutex<NoopRawMutex, &mut (dyn KeyStore + Send)> = Mutex::new(&mut key_store);
        let mut rng_worker = RngWorker {
            rng: &rng,
            key_store: &key_store,
            requests: req_worker_rx,
            responses: resp_worker_tx,
        };

        let org_request_id = api
            .get_random(&mut random_output)
            .await
            .expect("failed to send request");
        let Response::GetRandom {
            client_id: _client_id,
            request_id,
            data,
        } = get_response_from_worker!(api, core, rng_worker)
        else {
            panic!("Unexpected response type")
        };
        assert_eq!(request_id, org_request_id);
        assert_eq!(data.len(), REQUEST_SIZE);
    }

    #[async_std::test]
    async fn get_random_request_too_large() {
        const REQUEST_SIZE: usize = MAX_RANDOM_SIZE + 1;
        let mut random_output = [0u8; REQUEST_SIZE];

        let (mut client_requests, mut client_responses) = allocate_channel();
        let (mut worker_requests, mut worker_responses) = allocate_channel();
        let (mut api, mut core, req_worker_rx, resp_worker_tx) = init_core(
            &[RequestType::GetRandom, RequestType::GenerateSymmetricKey],
            &mut client_requests,
            &mut client_responses,
            &mut worker_requests,
            &mut worker_responses,
            None,
        );
        let rng = init_rng();
        let mut key_store = init_key_store(&KEY_INFOS);
        let key_store: Mutex<NoopRawMutex, &mut (dyn KeyStore + Send)> = Mutex::new(&mut key_store);
        let mut worker = RngWorker {
            rng: &rng,
            key_store: &key_store,
            requests: req_worker_rx,
            responses: resp_worker_tx,
        };

        let org_request_id = api
            .get_random(&mut random_output)
            .await
            .expect("failed to send request");
        let Response::Error {
            client_id: _client_id,
            request_id,
            error,
        } = get_response_from_worker!(api, core, worker)
        else {
            panic!("Unexpected response type")
        };
        assert_eq!(request_id, org_request_id);
        assert_eq!(error, Error::RequestTooLarge);
    }

    #[async_std::test]
    async fn generate_symmetric_key() {
        const KEY_INFO: KeyInfo = KEY_INFOS[1];
        let mut large_key_buffer = [0u8; 2 * KEY_INFO.ty.key_size()];

        let (mut client_requests, mut client_responses) = allocate_channel();
        let (mut worker_requests, mut worker_responses) = allocate_channel();
        let mut key_store = init_key_store(&KEY_INFOS);
        let key_store: Mutex<NoopRawMutex, &mut (dyn KeyStore + Send)> = Mutex::new(&mut key_store);
        let (mut api, mut core, req_worker_rx, resp_worker_tx) = init_core(
            &[RequestType::GetRandom, RequestType::GenerateSymmetricKey],
            &mut client_requests,
            &mut client_responses,
            &mut worker_requests,
            &mut worker_responses,
            Some(&key_store),
        );
        let rng = init_rng();
        let mut worker = RngWorker {
            rng: &rng,
            key_store: &key_store,
            requests: req_worker_rx,
            responses: resp_worker_tx,
        };

        // Generate key
        let org_request_id = api
            .generate_symmetric_key(KEY_INFO.id, false)
            .await
            .expect("failed to send request");
        let Response::GenerateSymmetricKey {
            client_id: _,
            request_id,
        } = get_response_from_worker!(api, core, worker)
        else {
            panic!("Unexpected response type")
        };
        assert_eq!(request_id, org_request_id);

        check_key_availability(&mut api, &mut core, KEY_INFO.id).await;

        // Export key
        let org_request_id = api
            .export_symmetric_key(KEY_INFO.id, &mut large_key_buffer)
            .await
            .expect("failed to send request");
        let Response::ExportSymmetricKey {
            client_id: _,
            request_id,
            key,
        } = get_response_from_core(&mut api, &mut core).await
        else {
            panic!("Unexpected response type")
        };
        assert_eq!(request_id, org_request_id);
        assert_eq!(key.len(), KEY_INFO.ty.key_size()); // Large buffer was only used partially
    }

    #[async_std::test]
    async fn chachapoly_encrypt_in_place() {
        let key = *b"Fortuna Major or Oddsbodikins???";
        let nonce = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let aad = *b"When in doubt, go to the library.";
        let mut tag = [0u8; crypto::chacha20poly1305::TAG_SIZE];
        let mut tag_external_key = tag.clone();
        let mut plaintext = *b"I solemnly swear I am up to no good!";
        let mut plaintext_external_key = plaintext;
        let org_plaintext = plaintext;

        let (mut client_requests, mut client_responses) = allocate_channel();
        let (mut worker_requests, mut worker_responses) = allocate_channel();
        let mut key_store = init_key_store(&KEY_INFOS);
        let key_store: Mutex<NoopRawMutex, &mut (dyn KeyStore + Send)> = Mutex::new(&mut key_store);
        let (mut api, mut core, req_worker_rx, resp_worker_tx) = init_core(
            &[
                RequestType::EncryptChaChaPoly,
                RequestType::EncryptChaChaPolyExternalKey,
                RequestType::DecryptChaChaPoly,
                RequestType::DecryptChaChaPolyExternalKey,
            ],
            &mut client_requests,
            &mut client_responses,
            &mut worker_requests,
            &mut worker_responses,
            Some(&key_store),
        );
        let mut worker = ChaChaPolyWorker {
            key_store: &key_store,
            requests: req_worker_rx,
            responses: resp_worker_tx,
        };

        import_symmetric_key(&mut api, &mut core, SYM_256_KEY.id, &key).await;

        // Encrypt data with imported key
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
        let Response::EncryptChaChaPoly {
            client_id: _,
            request_id,
            buffer,
            tag,
        } = get_response_from_worker!(api, core, worker)
        else {
            panic!("Unexpected response type")
        };
        assert_eq!(request_id, org_request_id);

        // Encrypt data with external key
        let org_request_id = api
            .encrypt_in_place_external_key(
                ChaCha20Poly1305,
                &key,
                &nonce,
                plaintext_external_key.len(),
                &mut plaintext_external_key,
                &aad,
                &mut tag_external_key,
            )
            .await
            .expect("failed to send request");
        let Response::EncryptChaChaPoly {
            client_id: _client_id,
            request_id,
            buffer: buffer_external_key,
            tag: tag_external_key,
        } = get_response_from_worker!(api, core, worker)
        else {
            panic!("Unexpected response type")
        };
        assert_eq!(request_id, org_request_id);

        assert_eq!(buffer, buffer_external_key);
        assert_eq!(tag, tag_external_key);

        // Decrypt data with imported key
        let org_request_id = api
            .decrypt_in_place(ChaCha20Poly1305, SYM_256_KEY.id, &nonce, buffer, &aad, tag)
            .await
            .expect("failed to send request");

        let Response::DecryptChaChaPoly {
            client_id: _client_id,
            request_id,
            buffer,
        } = get_response_from_worker!(api, core, worker)
        else {
            panic!("Unexpected response type")
        };
        assert_eq!(request_id, org_request_id);
        assert_eq!(buffer, org_plaintext);

        // Decrypt data with external key
        let org_request_id = api
            .decrypt_in_place_external_key(
                ChaCha20Poly1305,
                &key,
                &nonce,
                buffer_external_key,
                &aad,
                tag,
            )
            .await
            .expect("failed to send request");
        let Response::DecryptChaChaPoly {
            client_id: _client_id,
            request_id,
            buffer: buffer_external_key,
        } = get_response_from_worker!(api, core, worker)
        else {
            panic!("Unexpected response type")
        };
        assert_eq!(request_id, org_request_id);
        assert_eq!(buffer_external_key, org_plaintext);
    }

    #[async_std::test]
    async fn aes_gcm_encrypt_in_place() {
        let key = *b"Open sesame! ...";
        let iv = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let aad = *b"Never gonna give you up, Never gonna let you down!";
        let mut tag = [0u8; crypto::aes::GCM_TAG_SIZE];
        let mut tag_external_key = tag;
        let mut plaintext = *b"Hello, World!";
        let mut plaintext_external_key = plaintext;
        let org_plaintext = plaintext;

        let (mut client_requests, mut client_responses) = allocate_channel();
        let (mut worker_requests, mut worker_responses) = allocate_channel();
        let mut key_store = init_key_store(&KEY_INFOS);
        let key_store: Mutex<NoopRawMutex, &mut (dyn KeyStore + Send)> = Mutex::new(&mut key_store);
        let (mut api, mut core, req_worker_rx, resp_worker_tx) = init_core(
            &[
                RequestType::EncryptAesGcm,
                RequestType::EncryptAesGcmExternalKey,
                RequestType::DecryptAesGcm,
                RequestType::DecryptAesGcmExternalKey,
            ],
            &mut client_requests,
            &mut client_responses,
            &mut worker_requests,
            &mut worker_responses,
            Some(&key_store),
        );
        let mut worker = AesWorker {
            key_store: &key_store,
            requests: req_worker_rx,
            responses: resp_worker_tx,
        };

        import_symmetric_key(&mut api, &mut core, SYM_128_KEY.id, &key).await;

        // Encrypt data with imported key
        let org_request_id = api
            .encrypt_in_place(
                AesGcm,
                SYM_128_KEY.id,
                &iv,
                plaintext.len(),
                &mut plaintext,
                &aad,
                &mut tag,
            )
            .await
            .expect("failed to send request");
        let Response::EncryptAesGcm {
            client_id: _,
            request_id,
            buffer,
            tag,
        } = get_response_from_worker!(api, core, worker)
        else {
            panic!("Unexpected response type")
        };
        assert_eq!(request_id, org_request_id);

        // Encrypt data with external key
        let org_request_id = api
            .encrypt_in_place_external_key(
                AesGcm,
                &key,
                &iv,
                plaintext_external_key.len(),
                &mut plaintext_external_key,
                &aad,
                &mut tag_external_key,
            )
            .await
            .expect("failed to send request");
        let Response::EncryptAesGcm {
            client_id: _client_id,
            request_id,
            buffer: buffer_external_key,
            tag: tag_external_key,
        } = get_response_from_worker!(api, core, worker)
        else {
            panic!("Unexpected response type")
        };
        assert_eq!(request_id, org_request_id);

        assert_eq!(buffer, buffer_external_key);
        assert_eq!(tag, tag_external_key);

        // Decrypt data with imported key
        let org_request_id = api
            .decrypt_in_place(AesGcm, SYM_128_KEY.id, &iv, buffer, &aad, tag)
            .await
            .expect("failed to send request");
        let Response::DecryptAesGcm {
            client_id: _client_id,
            request_id,
            buffer: plaintext,
        } = get_response_from_worker!(api, core, worker)
        else {
            panic!("Unexpected response type")
        };
        assert_eq!(request_id, org_request_id);
        assert_eq!(plaintext, org_plaintext);

        // Decrypt data with external key
        let org_request_id = api
            .decrypt_in_place_external_key(
                AesGcm,
                &key,
                &iv,
                buffer_external_key,
                &aad,
                tag_external_key,
            )
            .await
            .expect("failed to send request");
        let Response::DecryptAesGcm {
            client_id: _client_id,
            request_id,
            buffer: plaintext_external_key,
        } = get_response_from_worker!(api, core, worker)
        else {
            panic!("Unexpected response type")
        };
        assert_eq!(request_id, org_request_id);
        assert_eq!(plaintext_external_key, org_plaintext)
    }

    #[async_std::test]
    async fn aes_cbc_encrypt_in_place() {
        let key = *b"Or was it 'open quinoa' instead?";
        let iv = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let org_plaintext = *b"Hi!";
        let plaintext_size = org_plaintext.len();
        let mut buffer = [0u8; 16];
        buffer[..plaintext_size].copy_from_slice(&org_plaintext);
        let mut buffer_external_key = buffer;

        let (mut client_requests, mut client_responses) = allocate_channel();
        let (mut worker_requests, mut worker_responses) = allocate_channel();
        let mut key_store = init_key_store(&KEY_INFOS);
        let key_store: Mutex<NoopRawMutex, &mut (dyn KeyStore + Send)> = Mutex::new(&mut key_store);
        let (mut api, mut core, req_worker_rx, resp_worker_tx) = init_core(
            &[
                RequestType::EncryptAesCbc,
                RequestType::EncryptAesCbcExternalKey,
                RequestType::DecryptAesCbc,
                RequestType::DecryptAesCbcExternalKey,
            ],
            &mut client_requests,
            &mut client_responses,
            &mut worker_requests,
            &mut worker_responses,
            Some(&key_store),
        );
        let mut worker = AesWorker {
            key_store: &key_store,
            requests: req_worker_rx,
            responses: resp_worker_tx,
        };

        import_symmetric_key(&mut api, &mut core, SYM_256_KEY.id, &key).await;

        // Encrypt data with imported key
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
        let Response::EncryptAesCbc {
            client_id: _,
            request_id,
            buffer,
        } = get_response_from_worker!(api, core, worker)
        else {
            panic!("Unexpected response type")
        };
        assert_eq!(request_id, org_request_id);

        // Encrypt data with external key
        let org_request_id = api
            .encrypt_in_place_external_key(
                AesCbc,
                &key,
                &iv,
                plaintext_size,
                &mut buffer_external_key,
                &[],
                &mut [],
            )
            .await
            .expect("failed to send request");
        let Response::EncryptAesCbc {
            client_id: _client_id,
            request_id,
            buffer: buffer_external_key,
        } = get_response_from_worker!(api, core, worker)
        else {
            panic!("Unexpected response type")
        };
        assert_eq!(request_id, org_request_id);

        assert_eq!(buffer, buffer_external_key);

        // Decrypt data with imported key
        let org_request_id = api
            .decrypt_in_place(AesCbc, SYM_256_KEY.id, &iv, buffer, &[], &[])
            .await
            .expect("failed to send request");
        let Response::DecryptAesCbc {
            client_id: _client_id,
            request_id,
            plaintext,
        } = get_response_from_worker!(api, core, worker)
        else {
            panic!("Unexpected response type")
        };
        assert_eq!(request_id, org_request_id);
        assert_eq!(plaintext, org_plaintext);

        // Decrypt data with external key
        let org_request_id = api
            .decrypt_in_place_external_key(AesCbc, &key, &iv, buffer_external_key, &[], &[])
            .await
            .expect("failed to send request");
        let Response::DecryptAesCbc {
            client_id: _client_id,
            request_id,
            plaintext: plaintext_external_key,
        } = get_response_from_worker!(api, core, worker)
        else {
            panic!("Unexpected response type")
        };
        assert_eq!(request_id, org_request_id);
        assert_eq!(plaintext_external_key, org_plaintext);
    }

    #[async_std::test]
    async fn aes_cmac_calculate_verify() {
        let key: [u8; crypto::aes::KEY256_SIZE] = *b"Fortuna Major or Oddsbodikins???";
        let message = *b"I solemnly swear I am up to no good!";
        let mut tag = [0u8; crypto::aes::CMAC_TAG_SIZE];
        let mut tag_external_key = [0u8; crypto::aes::CMAC_TAG_SIZE];

        let (mut client_requests, mut client_responses) = allocate_channel();
        let (mut worker_requests, mut worker_responses) = allocate_channel();
        let mut key_store = init_key_store(&KEY_INFOS);
        let key_store: Mutex<NoopRawMutex, &mut (dyn KeyStore + Send)> = Mutex::new(&mut key_store);
        let (mut api, mut core, req_worker_rx, resp_worker_tx) = init_core(
            &[
                RequestType::CalculateAesCmac,
                RequestType::CalculateAesCmacExternalKey,
                RequestType::VerifyAesCmac,
                RequestType::VerifyAesCmacExternalKey,
            ],
            &mut client_requests,
            &mut client_responses,
            &mut worker_requests,
            &mut worker_responses,
            Some(&key_store),
        );
        let mut worker = AesWorker {
            key_store: &key_store,
            requests: req_worker_rx,
            responses: resp_worker_tx,
        };

        import_symmetric_key(&mut api, &mut core, SYM_256_KEY.id, &key).await;

        // Calculate CMAC tag with imported key
        let org_request_id = api
            .calculate_aes_cmac(SYM_256_KEY.id, &message, &mut tag)
            .await
            .expect("failed to send request");
        let Response::CalculateAesCmac {
            client_id: _,
            request_id,
            tag,
        } = get_response_from_worker!(api, core, worker)
        else {
            panic!("Unexpected response type")
        };
        assert_eq!(request_id, org_request_id);

        // Calculate CMAC tag with external key
        let org_request_id = api
            .calculate_aes_cmac_external_key(&key, &message, &mut tag_external_key)
            .await
            .expect("failed to send request");
        let Response::CalculateAesCmac {
            client_id: _,
            request_id,
            tag: tag_external_key,
        } = get_response_from_worker!(api, core, worker)
        else {
            panic!("Unexpected response type")
        };
        assert_eq!(request_id, org_request_id);

        assert_eq!(tag, tag_external_key);

        // Verify CMAC tag with imported key.
        let org_request_id = api
            .verify_aes_cmac(SYM_256_KEY.id, &message, tag)
            .await
            .expect("failed to send request");
        let Response::VerifyAesCmac {
            client_id: _client_id,
            request_id,
            verified,
        } = get_response_from_worker!(api, core, worker)
        else {
            panic!("Unexpected response type")
        };
        assert_eq!(request_id, org_request_id);
        assert!(verified);

        // Verify CMAC external key.
        let org_request_id = api
            .verify_aes_cmac_external_key(&key, &message, tag_external_key)
            .await
            .expect("failed to send request");
        let Response::VerifyAesCmac {
            client_id: _client_id,
            request_id,
            verified,
        } = get_response_from_worker!(api, core, worker)
        else {
            panic!("Unexpected response type")
        };
        assert_eq!(request_id, org_request_id);
        assert!(verified);
    }

    #[async_std::test]
    async fn sign_verify_nist_p256() {
        const KEY_INFO: KeyInfo = KEY_INFOS[2];
        let mut large_public_key_buffer = [0u8; 2 * KEY_INFO.ty.public_key_size()];
        let mut large_private_key_buffer = [0u8; 2 * KEY_INFO.ty.private_key_size()];
        let mut signature = [0u8; KEY_INFO.ty.signature_size()];
        let mut signature_external_key = [0u8; KEY_INFO.ty.signature_size()];
        let message: &[u8] = b"But my patience isn't limitless... unlike my authority.";
        let digest = Sha256::digest(message);

        let (mut client_requests, mut client_responses) = allocate_channel();
        let (mut worker_requests, mut worker_responses) = allocate_channel();
        let mut key_store = init_key_store(&KEY_INFOS);
        let key_store: Mutex<NoopRawMutex, &mut (dyn KeyStore + Send)> = Mutex::new(&mut key_store);
        let (mut api, mut core, req_worker_rx, resp_worker_tx) = init_core(
            &[
                RequestType::GenerateKeyPair,
                RequestType::Sign,
                RequestType::Verify,
                RequestType::SignExternalKey,
                RequestType::VerifyExternalKey,
            ],
            &mut client_requests,
            &mut client_responses,
            &mut worker_requests,
            &mut worker_responses,
            Some(&key_store),
        );
        let rng = init_rng();
        let mut worker = EccWorker {
            rng: &rng,
            key_store: &key_store,
            requests: req_worker_rx,
            responses: resp_worker_tx,
        };

        // Generate key
        let org_request_id = api
            .generate_key_pair(KEY_INFO.id, false)
            .await
            .expect("failed to send request");
        let Response::GenerateKeyPair {
            client_id: _client_id,
            request_id,
        } = get_response_from_worker!(api, core, worker)
        else {
            panic!("Unexpected response type")
        };
        assert_eq!(request_id, org_request_id);

        check_key_availability(&mut api, &mut core, KEY_INFO.id).await;

        // Export public key
        let org_request_id = api
            .export_public_key(KEY_INFO.id, &mut large_public_key_buffer)
            .await
            .expect("failed to send request");
        let Response::ExportPublicKey {
            client_id: _,
            request_id,
            public_key,
        } = get_response_from_core(&mut api, &mut core).await
        else {
            panic!("Unexpected response type")
        };
        assert_eq!(request_id, org_request_id);
        assert_eq!(public_key.len(), KEY_INFO.ty.public_key_size()); // Large buffer was only used partially

        // Export private key
        let org_request_id = api
            .export_private_key(KEY_INFO.id, &mut large_private_key_buffer)
            .await
            .expect("failed to send request");
        let Response::ExportPrivateKey {
            client_id: _,
            request_id,
            private_key,
        } = get_response_from_core(&mut api, &mut core).await
        else {
            panic!("Unexpected response type")
        };
        assert_eq!(request_id, org_request_id);
        assert_eq!(private_key.len(), KEY_INFO.ty.private_key_size()); // Large buffer was only used partially

        // Sign message with generated key
        let org_request_id = api
            .sign(KEY_INFO.id, message, false, &mut signature)
            .await
            .expect("failed to send request");
        let Response::Sign {
            client_id: _,
            request_id,
            signature,
        } = get_response_from_worker!(api, core, worker)
        else {
            panic!("Unexpected response type")
        };
        assert_eq!(request_id, org_request_id);

        // Verify message with generated key
        let org_request_id = api
            .verify(KEY_INFO.id, message, false, signature)
            .await
            .expect("failed to send request");
        let Response::Verify {
            client_id: _,
            request_id,
            verified,
        } = get_response_from_worker!(api, core, worker)
        else {
            panic!("Unexpected response type")
        };
        assert_eq!(request_id, org_request_id);
        assert!(verified);

        // Sign digest with external key
        let org_request_id = api
            .sign_external_key(
                private_key,
                digest.as_slice(),
                true,
                &mut signature_external_key,
            )
            .await
            .expect("failed to send request");
        let Response::Sign {
            client_id: _,
            request_id,
            signature: signature_external_key,
        } = get_response_from_worker!(api, core, worker)
        else {
            panic!("Unexpected response type")
        };
        assert_eq!(request_id, org_request_id);

        assert_eq!(signature, signature_external_key);

        // Verify digest with external key
        let org_request_id = api
            .verify_external_key(public_key, digest.as_slice(), true, signature_external_key)
            .await
            .expect("failed to send request");
        let Response::Verify {
            client_id: _,
            request_id,
            verified,
        } = get_response_from_worker!(api, core, worker)
        else {
            panic!("Unexpected response type")
        };
        assert_eq!(request_id, org_request_id);
        assert!(verified);
    }

    #[async_std::test]
    async fn calculate_verify_hmac_sha3_512() {
        let key: [u8; crypto::aes::KEY256_SIZE] = *b"Guardian of the Third Age Istar.";
        let message: &[u8] = b"You Shall Not Pass!";
        let mut tag = [0u8; crypto::hmac::HMAC_SHA3_512_SIZE];
        let mut tag_external_key = [0u8; crypto::hmac::HMAC_SHA3_512_SIZE];
        let hash_algorithm = HashAlgorithm::Sha3_512;

        let (mut client_requests, mut client_responses) = allocate_channel();
        let (mut worker_requests, mut worker_responses) = allocate_channel();
        let mut key_store = init_key_store(&KEY_INFOS);
        let key_store: Mutex<NoopRawMutex, &mut (dyn KeyStore + Send)> = Mutex::new(&mut key_store);
        let (mut api, mut core, req_worker_rx, resp_worker_tx) = init_core(
            &[
                RequestType::CalculateHmac,
                RequestType::CalculateHmacExternalKey,
                RequestType::VerifyHmac,
                RequestType::VerifyHmacExternalKey,
            ],
            &mut client_requests,
            &mut client_responses,
            &mut worker_requests,
            &mut worker_responses,
            Some(&key_store),
        );
        let mut worker = HmacWorker {
            key_store: &key_store,
            requests: req_worker_rx,
            responses: resp_worker_tx,
        };

        import_symmetric_key(&mut api, &mut core, SYM_256_KEY.id, &key).await;

        // Calculate HMAC tag with imported key
        let org_request_id = api
            .calculate_hmac(SYM_256_KEY.id, hash_algorithm, &message, &mut tag)
            .await
            .expect("failed to send request");
        let Response::CalculateHmac {
            client_id: _,
            request_id,
            tag,
        } = get_response_from_worker!(api, core, worker)
        else {
            panic!("Unexpected response type")
        };
        assert_eq!(request_id, org_request_id);

        // Calculate HMAC tag with external key
        let org_request_id = api
            .calculate_hmac_external_key(&key, hash_algorithm, &message, &mut tag_external_key)
            .await
            .expect("failed to send request");
        let Response::CalculateHmac {
            client_id: _,
            request_id,
            tag: tag_external_key,
        } = get_response_from_worker!(api, core, worker)
        else {
            panic!("Unexpected response type")
        };
        assert_eq!(request_id, org_request_id);

        assert_eq!(tag, tag_external_key);

        // Verify HMAC tag with imported key
        let org_request_id = api
            .verify_hmac(SYM_256_KEY.id, hash_algorithm, &message, tag)
            .await
            .expect("failed to send request");
        let Response::VerifyHmac {
            client_id: _client_id,
            request_id,
            verified,
        } = get_response_from_worker!(api, core, worker)
        else {
            panic!("Unexpected response type")
        };
        assert_eq!(request_id, org_request_id);
        assert!(verified);

        // Verify HMAC tag with external key
        let org_request_id = api
            .verify_hmac_external_key(&key, hash_algorithm, &message, tag_external_key)
            .await
            .expect("failed to send request");
        let Response::VerifyHmac {
            client_id: _client_id,
            request_id,
            verified,
        } = get_response_from_worker!(api, core, worker)
        else {
            panic!("Unexpected response type")
        };
        assert_eq!(request_id, org_request_id);
        assert!(verified);
    }

    #[async_std::test]
    async fn multiple_clients() {
        const REQUEST1_SIZE: usize = 16;
        const REQUEST2_SIZE: usize = 17;
        let mut random_output1 = [0u8; REQUEST1_SIZE];
        let mut random_output2 = [0u8; REQUEST2_SIZE];

        let (mut client1_requests, mut client1_responses) = allocate_channel();
        let (mut client2_requests, mut client2_responses) = allocate_channel();
        let (mut worker_requests, mut worker_responses) = allocate_channel();

        let (req_client1_rx, req_client1_tx, resp_client1_rx, resp_client1_tx) =
            split_queues(&mut client1_requests, &mut client1_responses);
        let (req_client2_rx, req_client2_tx, resp_client2_rx, resp_client2_tx) =
            split_queues(&mut client2_requests, &mut client2_responses);
        let (rng_requests_rx, rng_requests_tx, rng_responses_rx, rng_responses_tx) =
            split_queues(&mut worker_requests, &mut worker_responses);
        let rng = init_rng();
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

        let (mut client_requests, mut client_responses) = allocate_channel();

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
        let Response::Error {
            client_id: _client_id,
            request_id,
            error,
        } = get_response_from_core(&mut api, &mut core).await
        else {
            panic!("Unexpected response type")
        };
        assert_eq!(request_id, org_request_id);
        assert_eq!(error, Error::NoWorkerForRequest);
    }
}
