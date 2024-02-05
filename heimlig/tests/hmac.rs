#[macro_use]
mod common;

pub use common::*;
use embassy_sync::{blocking_mutex::raw::NoopRawMutex, mutex::Mutex};
use heimlig::{
    common::jobs::{HashAlgorithm, RequestType, Response},
    crypto,
    hsm::workers::hmac_worker::HmacWorker,
};

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
    let key_store: Mutex<NoopRawMutex, _> = Mutex::new(&mut key_store);
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
