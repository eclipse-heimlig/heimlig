#![feature(type_alias_impl_trait)] // Required for embassy

use core::cell::RefCell;
use embassy_executor::Spawner;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use embassy_time::Duration;
use embassy_time::Timer;
use heimlig::client::api::Api;
use heimlig::common::jobs::{RequestType, Response};
use heimlig::crypto::rng;
use heimlig::crypto::rng::Rng;
use heimlig::hsm::core::{Builder, Core};
use heimlig::hsm::workers::rng_worker::RngWorker;
use heimlig::integration::embassy::{
    RequestQueue, RequestQueueSink, RequestQueueSource, ResponseQueue, ResponseQueueSink,
    ResponseQueueSource,
};
use log::{error, info};
use rand::RngCore;

// Request and response queues between tasks
const QUEUE_SIZE: usize = 8;
static mut CLIENT_TO_CORE: RequestQueue<QUEUE_SIZE> = RequestQueue::<QUEUE_SIZE>::new();
static mut CORE_TO_CLIENT: ResponseQueue<QUEUE_SIZE> = ResponseQueue::<QUEUE_SIZE>::new();
static mut CORE_TO_RNG_WORKER: RequestQueue<QUEUE_SIZE> = RequestQueue::<QUEUE_SIZE>::new();
static mut RNG_WORKER_TO_CORE: ResponseQueue<QUEUE_SIZE> = ResponseQueue::<QUEUE_SIZE>::new();

// Globals initialized in one task but used in another
static CORE: Mutex<
    CriticalSectionRawMutex,
    RefCell<
        Option<
            Core<
                CriticalSectionRawMutex,
                RequestQueueSource<QUEUE_SIZE>,
                ResponseQueueSink<QUEUE_SIZE>,
                RequestQueueSink<QUEUE_SIZE>,
                ResponseQueueSource<QUEUE_SIZE>,
            >,
        >,
    >,
> = Mutex::new(RefCell::new(None));
static RNG_WORKER: Mutex<
    CriticalSectionRawMutex,
    RefCell<
        Option<
            RngWorker<EntropySource, RequestQueueSource<QUEUE_SIZE>, ResponseQueueSink<QUEUE_SIZE>>,
        >,
    >,
> = Mutex::new(RefCell::new(None));

struct EntropySource {}

impl rng::EntropySource for EntropySource {
    fn random_seed(&mut self) -> [u8; 32] {
        let mut data = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut data);
        data
    }
}

#[embassy_executor::task]
async fn core_task() {
    loop {
        {
            let core = CORE.try_lock().expect("Failed to lock core");
            let mut core = core.borrow_mut();
            let core = core.as_mut().expect("Core was not initialized");
            core.execute().await.expect("failed to forward request");
        }
        Timer::after(Duration::from_millis(100)).await;
    }
}

#[embassy_executor::task]
async fn worker_task() {
    loop {
        {
            let rng_worker = RNG_WORKER.try_lock().expect("Failed to lock RNG worker");
            let mut rng_worker = rng_worker.borrow_mut();
            let rng_worker = rng_worker.as_mut().expect("Core was not initialized");
            rng_worker
                .execute()
                .await
                .expect("failed to process request");
        }
        Timer::after(Duration::from_millis(100)).await;
    }
}

#[embassy_executor::task]
async fn client_task(
    response_rx: ResponseQueueSource<'static, 'static, QUEUE_SIZE>,
    requests_tx: RequestQueueSink<'static, 'static, QUEUE_SIZE>,
) {
    // Api
    let mut api = Api::new(requests_tx, response_rx);

    loop {
        // Send request
        Timer::after(Duration::from_millis(1000)).await;
        let random_output = Box::leak(Box::new([0u8; 16]));
        let request_size = random_output.len();
        let request_id = api
            .get_random(random_output.as_mut_slice())
            .await
            .expect("failed to call randomness API");
        info!(target: "CLIENT", "--> request:  random data (id={}) (size={})", request_id.as_u32(), request_size);

        // Receive response
        loop {
            match api.recv_response().await {
                None => Timer::after(Duration::from_millis(10)).await, // Continue waiting for response
                Some(response) => {
                    match response {
                        Response::GetRandom {
                            client_id: _client_id,
                            request_id,
                            data,
                        } => {
                            info!(target: "CLIENT",
                                "<-- response: random data (id={}) (size={}): {}",
                                request_id.as_u32(),
                                data.len(),
                                hex::encode(&data)
                            );
                            // release the memory
                            drop(unsafe { Box::from_raw(data) });
                            break; // Send next request
                        }
                        _ => error!(target: "CLIENT", "Unexpected response type"),
                    };
                }
            }
        }
    }
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    simple_logger::SimpleLogger::new()
        .init()
        .expect("failed to initialize logger");

    // Queues
    // Unsafe: Access to mutable static only happens here. Static lifetime is required by embassy tasks.
    let (client_req_tx, core_req_rx) = unsafe { CLIENT_TO_CORE.split() };
    let (core_resp_tx, client_resp_rx) = unsafe { CORE_TO_CLIENT.split() };
    let (core_req_tx, rng_req_rx) = unsafe { CORE_TO_RNG_WORKER.split() };
    let (rng_resp_tx, core_resp_rx) = unsafe { RNG_WORKER_TO_CORE.split() };

    let rng = Rng::new(EntropySource {}, None);
    let rng_worker = RngWorker {
        rng,
        requests: rng_req_rx,
        responses: rng_resp_tx,
    };
    RNG_WORKER
        .try_lock()
        .expect("Failed to lock RNG_WORKER")
        .replace(Some(rng_worker));
    let core: Core<
        CriticalSectionRawMutex,
        RequestQueueSource<'_, '_, QUEUE_SIZE>,
        ResponseQueueSink<'_, '_, QUEUE_SIZE>,
        RequestQueueSink<'_, '_, QUEUE_SIZE>,
        ResponseQueueSource<'_, '_, QUEUE_SIZE>,
    > = Builder::new()
        .with_client(core_req_rx, core_resp_tx)
        .expect("failed to add client")
        .with_worker(&[RequestType::GetRandom], core_req_tx, core_resp_rx)
        .expect("failed to add worker")
        .build();
    CORE.try_lock()
        .expect("Failed to lock CORE")
        .replace(Some(core));

    // Start tasks
    spawner
        .spawn(core_task())
        .expect("Failed to spawn core task");
    spawner
        .spawn(worker_task())
        .expect("Failed to spawn worker task");
    spawner
        .spawn(client_task(client_resp_rx, client_req_tx))
        .expect("Failed to spawn client task");
}
