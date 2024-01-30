#[macro_use]
mod common;

pub use common::*;
use embassy_sync::{blocking_mutex::raw::NoopRawMutex, mutex::Mutex};
use heimlig::{
    common::jobs::{RequestType, Response},
    hsm::{keystore::KeyStore, workers::ecc_worker::EccWorker},
};
use sha2::{Digest, Sha256};

#[async_std::test]
async fn sign_verify_nist_p256() {
    let mut large_public_key_buffer = [0u8; 2 * ASYM_NIST_P256_KEY.ty.public_key_size()];
    let mut large_private_key_buffer = [0u8; 2 * ASYM_NIST_P256_KEY.ty.private_key_size()];
    let mut signature = [0u8; ASYM_NIST_P256_KEY.ty.signature_size()];
    let mut signature_external_key = [0u8; ASYM_NIST_P256_KEY.ty.signature_size()];
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
        .generate_key_pair(ASYM_NIST_P256_KEY.id, false)
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

    check_key_availability(&mut api, &mut core, ASYM_NIST_P256_KEY.id).await;

    // Export public key
    let org_request_id = api
        .export_public_key(ASYM_NIST_P256_KEY.id, &mut large_public_key_buffer)
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
    assert_eq!(public_key.len(), ASYM_NIST_P256_KEY.ty.public_key_size()); // Large buffer was only used partially

    // Export private key
    let org_request_id = api
        .export_private_key(ASYM_NIST_P256_KEY.id, &mut large_private_key_buffer)
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
    assert_eq!(private_key.len(), ASYM_NIST_P256_KEY.ty.private_key_size()); // Large buffer was only used partially

    // Sign message with generated key
    let org_request_id = api
        .sign(ASYM_NIST_P256_KEY.id, message, false, &mut signature)
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
        .verify(ASYM_NIST_P256_KEY.id, message, false, signature)
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
