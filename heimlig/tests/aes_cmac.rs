#[macro_use]
mod common;

pub use common::*;
use embassy_sync::{blocking_mutex::raw::NoopRawMutex, mutex::Mutex};
use heimlig::{
    common::jobs::{RequestType, Response},
    crypto,
    hsm::{keystore::KeyStore, workers::aes_worker::AesWorker},
};

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
