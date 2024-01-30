#[macro_use]
mod common;

pub use common::*;
use embassy_sync::{blocking_mutex::raw::NoopRawMutex, mutex::Mutex};
use heimlig::{
    client::api::SymmetricAlgorithm::AesCbc,
    common::jobs::{RequestType, Response},
    hsm::{keystore::KeyStore, workers::aes_worker::AesWorker},
};

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
