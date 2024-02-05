use embassy_sync::{blocking_mutex::raw::NoopRawMutex, mutex::Mutex};
use heimlig::{
    client::api::Api,
    common::jobs::{Request, RequestType, Response},
    hsm::{
        core::{self, Builder},
        keystore::{KeyId, KeyInfo, KeyPermissions, KeyType},
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

pub const QUEUE_SIZE: usize = 8;
pub const NUM_KEYS: usize = 3;
pub const TOTAL_KEY_SIZE: usize =
    SYM_128_KEY.ty.key_size() + SYM_256_KEY.ty.key_size() + ASYM_NIST_P256_KEY.ty.key_size();
pub const SYM_128_KEY: KeyInfo = KeyInfo {
    id: KeyId(0),
    ty: KeyType::Symmetric128Bits,
    permissions: KeyPermissions {
        import: true,
        export_private: false,
        overwrite: false,
        delete: false,
    },
};
pub const SYM_256_KEY: KeyInfo = KeyInfo {
    id: KeyId(1),
    ty: KeyType::Symmetric256Bits,
    permissions: KeyPermissions {
        import: true,
        export_private: true,
        overwrite: false,
        delete: false,
    },
};
pub const ASYM_NIST_P256_KEY: KeyInfo = KeyInfo {
    id: KeyId(2),
    ty: KeyType::EccKeypairNistP256,
    permissions: KeyPermissions {
        import: true,
        export_private: true,
        overwrite: false,
        delete: false,
    },
};
pub const KEY_INFOS: [KeyInfo; 3] = [SYM_128_KEY, SYM_256_KEY, ASYM_NIST_P256_KEY];

pub fn init_key_store(key_infos: &[KeyInfo]) -> MemoryKeyStore<{ TOTAL_KEY_SIZE }, { NUM_KEYS }> {
    MemoryKeyStore::<{ TOTAL_KEY_SIZE }, { NUM_KEYS }>::try_new(key_infos)
        .expect("failed to create key store")
}

pub fn init_rng() -> Mutex<NoopRawMutex, ChaCha20Rng> {
    Mutex::new(ChaCha20Rng::from_seed([0u8; 32]))
}

pub fn split_queues<'ch, 'data>(
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

type Core<'data, 'keystore, 'ch> = core::Core<
    'data,
    'keystore,
    NoopRawMutex,
    RequestQueueSource<'ch, 'data, QUEUE_SIZE>,
    ResponseQueueSink<'ch, 'data, QUEUE_SIZE>,
    RequestQueueSink<'ch, 'data, QUEUE_SIZE>,
    ResponseQueueSource<'ch, 'data, QUEUE_SIZE>,
    MemoryKeyStore<{ TOTAL_KEY_SIZE }, { NUM_KEYS }>,
>;

pub async fn get_response_from_core<'data>(
    api: &mut Api<
        'data,
        RequestQueueSink<'_, 'data, QUEUE_SIZE>,
        ResponseQueueSource<'_, 'data, QUEUE_SIZE>,
    >,
    core: &mut Core<'data, '_, '_>,
) -> Response<'data> {
    core.execute().await.expect("failed to process request");
    let Some(response) = api.recv_response().await else {
        panic!("Failed to receive expected response")
    };
    response
}

pub async fn check_key_availability<'data>(
    api: &mut Api<
        'data,
        RequestQueueSink<'_, 'data, QUEUE_SIZE>,
        ResponseQueueSource<'_, 'data, QUEUE_SIZE>,
    >,
    core: &mut Core<'data, '_, '_>,
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

pub async fn import_symmetric_key<'data>(
    api: &mut Api<
        'data,
        RequestQueueSink<'_, 'data, QUEUE_SIZE>,
        ResponseQueueSource<'_, 'data, QUEUE_SIZE>,
    >,
    core: &mut Core<'data, '_, '_>,
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

pub fn allocate_channel<'data>() -> (
    AsyncQueue<Request<'data>, QUEUE_SIZE>,
    AsyncQueue<Response<'data>, QUEUE_SIZE>,
) {
    (
        AsyncQueue::<Request, QUEUE_SIZE>::new(),
        AsyncQueue::<Response, QUEUE_SIZE>::new(),
    )
}

pub fn init_core<'data, 'ch, 'keystore>(
    request_types: &[RequestType],
    client_requests: &'ch mut AsyncQueue<Request<'data>, QUEUE_SIZE>,
    client_responses: &'ch mut AsyncQueue<Response<'data>, QUEUE_SIZE>,
    worker_requests: &'ch mut AsyncQueue<Request<'data>, QUEUE_SIZE>,
    worker_responses: &'ch mut AsyncQueue<Response<'data>, QUEUE_SIZE>,
    key_store: Option<
        &'keystore Mutex<
            NoopRawMutex,
            &'keystore mut MemoryKeyStore<{ TOTAL_KEY_SIZE }, { NUM_KEYS }>,
        >,
    >,
) -> (
    Api<
        'data,
        RequestQueueSink<'ch, 'data, QUEUE_SIZE>,
        ResponseQueueSource<'ch, 'data, QUEUE_SIZE>,
    >,
    Core<'data, 'keystore, 'ch>,
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
        MemoryKeyStore<{ TOTAL_KEY_SIZE }, { NUM_KEYS }>,
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
