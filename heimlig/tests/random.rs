#[macro_use]
mod common;

pub use common::*;
use embassy_sync::{blocking_mutex::raw::NoopRawMutex, mutex::Mutex};
use heimlig::{
    common::{
        jobs::{Error, RequestType, Response},
        limits::MAX_RANDOM_SIZE,
    },
    hsm::{keystore::KeyStore, workers::rng_worker::RngWorker},
};

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
