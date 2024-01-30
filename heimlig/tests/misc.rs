#[macro_use]
mod common;

pub use common::*;
use embassy_sync::{blocking_mutex::raw::NoopRawMutex, mutex::Mutex};
use heimlig::{
    client::api::Api,
    common::jobs::{Error, RequestType, Response},
    hsm::core::Builder,
    hsm::{keystore::KeyStore, workers::rng_worker::RngWorker},
    integration::embassy::{
        RequestQueueSink, RequestQueueSource, ResponseQueueSink, ResponseQueueSource,
    },
};

#[async_std::test]
async fn generate_symmetric_key() {
    let mut large_key_buffer = [0u8; 2 * SYM_256_KEY.ty.key_size()];

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
        .generate_symmetric_key(SYM_256_KEY.id, false)
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

    check_key_availability(&mut api, &mut core, SYM_256_KEY.id).await;

    // Export key
    let org_request_id = api
        .export_symmetric_key(SYM_256_KEY.id, &mut large_key_buffer)
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
    assert_eq!(key.len(), SYM_256_KEY.ty.key_size()); // Large buffer was only used partially
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
