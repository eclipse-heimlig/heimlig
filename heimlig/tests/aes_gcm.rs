#[macro_use]
mod common;

pub use common::*;
use embassy_sync::{blocking_mutex::raw::NoopRawMutex, mutex::Mutex};
use heimlig::{
    client::api::SymmetricAlgorithm::AesGcm,
    common::jobs::{RequestType, Response},
    crypto,
    hsm::{keystore::KeyStore, workers::aes_worker::AesWorker},
};

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
