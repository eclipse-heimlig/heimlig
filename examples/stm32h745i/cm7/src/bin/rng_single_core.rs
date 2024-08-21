#![no_std]
#![no_main]
#![feature(impl_trait_in_assoc_type)]

use defmt::*;
use embassy_executor::Spawner;
use embassy_stm32::bind_interrupts;
use embassy_stm32::gpio::{Level, Output, Speed};
use embassy_stm32::peripherals::RNG;
use embassy_stm32::rng::{InterruptHandler, Rng};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::mutex::Mutex;
use embassy_time::{Duration, Timer};
use heimlig::client::api::Api;
use heimlig::common::jobs::{RequestType, Response};
use heimlig::hsm::core::Builder;
use heimlig::hsm::keystore::KeyInfo;
use heimlig::hsm::workers::rng_worker::RngWorker;
use heimlig::integration::embassy::{
    RequestQueue, RequestQueueSink, RequestQueueSource, ResponseQueue, ResponseQueueSink,
    ResponseQueueSource,
};
use heimlig::integration::memory_key_store::MemoryKeyStore;

use {defmt_rtt as _, panic_probe as _};

bind_interrupts!(struct Irqs {
    RNG => InterruptHandler<RNG>;
});

// Shared memory pool
static mut MEMORY: [u8; 256] = [0; 256];

const QUEUE_SIZE: usize = 8;
static mut CLIENT_TO_CORE: RequestQueue<QUEUE_SIZE> = RequestQueue::<QUEUE_SIZE>::new();
static mut CORE_TO_CLIENT: ResponseQueue<QUEUE_SIZE> = ResponseQueue::<QUEUE_SIZE>::new();
static mut CORE_TO_RNG_WORKER: RequestQueue<QUEUE_SIZE> = RequestQueue::<QUEUE_SIZE>::new();
static mut RNG_WORKER_TO_CORE: ResponseQueue<QUEUE_SIZE> = ResponseQueue::<QUEUE_SIZE>::new();

// Key store info
const NUM_KEYS: usize = 0;
const TOTAL_KEY_SIZE: usize = 0;
const KEY_INFOS: &[KeyInfo] = &[];

#[embassy_executor::task]
async fn hsm_task(
    core_req_rx: RequestQueueSource<'static, 'static, QUEUE_SIZE>,
    core_resp_tx: ResponseQueueSink<'static, 'static, QUEUE_SIZE>,
    core_req_tx: RequestQueueSink<'static, 'static, QUEUE_SIZE>,
    core_resp_rx: ResponseQueueSource<'static, 'static, QUEUE_SIZE>,
    rng_req_rx: RequestQueueSource<'static, 'static, QUEUE_SIZE>,
    rng_resp_tx: ResponseQueueSink<'static, 'static, QUEUE_SIZE>,
    rng: Rng<'static, RNG>,
) {
    info!("HSM task started");
    let mut key_store = MemoryKeyStore::<{ TOTAL_KEY_SIZE }, { NUM_KEYS }>::try_new(KEY_INFOS)
        .expect("failed to create key store");
    let key_store: Mutex<NoopRawMutex, _> = Mutex::new(&mut key_store);
    let rng: Mutex<NoopRawMutex, _> = Mutex::new(rng);
    let mut rng_worker = RngWorker {
        key_store: Some(&key_store),
        rng: &rng,
        requests: rng_req_rx,
        responses: rng_resp_tx,
    };
    let mut core = Builder::<
        NoopRawMutex,
        RequestQueueSource<'_, '_, QUEUE_SIZE>,
        ResponseQueueSink<'_, '_, QUEUE_SIZE>,
        RequestQueueSink<'_, '_, QUEUE_SIZE>,
        ResponseQueueSource<'_, '_, QUEUE_SIZE>,
        MemoryKeyStore<{ TOTAL_KEY_SIZE }, { NUM_KEYS }>,
    >::new()
    .with_client(core_req_rx, core_resp_tx)
    .expect("failed to add client")
    .with_worker(&[RequestType::GetRandom], core_req_tx, core_resp_rx)
    .expect("failed to add worker")
    .build();

    loop {
        core.execute().await.expect("failed to forward request");
        rng_worker
            .execute()
            .await
            .expect("failed to process request");
        Timer::after(Duration::from_millis(100)).await;
    }
}

#[embassy_executor::task]
async fn client_task(
    req_tx: RequestQueueSink<'static, 'static, QUEUE_SIZE>,
    resp_rx: ResponseQueueSource<'static, 'static, QUEUE_SIZE>,
    mut led: Output<'static, embassy_stm32::peripherals::PJ2>,
) {
    info!("Client task started");

    // Memory
    let pool = heapless::pool::Pool::<[u8; 16]>::new();
    // Safety: we are the only users of MEMORY
    pool.grow(unsafe { &mut MEMORY });

    // Api
    let mut api = Api::new(req_tx, resp_rx);

    loop {
        // Send requests
        Timer::after(Duration::from_millis(1000)).await;
        led.set_high();

        let mut random_buffer_alloc = pool
            .alloc()
            .expect("Failed to allocate buffer for random data")
            .init([0; 16]);
        // Safety: we forget about the box below, so it doesn't get dropped!
        let random_buffer = unsafe {
            core::slice::from_raw_parts_mut(
                random_buffer_alloc.as_mut_ptr(),
                random_buffer_alloc.len(),
            )
        };
        // Avoid releasing the allocation; unfortunately with current version of heapless, we
        // cannot unleak this. heapless::pool::Box would need to implement an interface similar to
        // std::Box::from_raw.
        core::mem::forget(random_buffer_alloc);
        let request_size = random_buffer.len();
        let request_id = api
            .get_random(random_buffer)
            .await
            .expect("failed to call randomness API");
        info!(
            "--> request:  random data (id={}) (size={})",
            request_id.as_u32(),
            request_size
        );

        // Receive response
        loop {
            if let Some(response) = api.recv_response().await {
                match response {
                    Response::GetRandom {
                        client_id: _,
                        request_id,
                        data,
                    } => {
                        info!(
                            "<-- response: random data (id={}) (size={}): {}",
                            request_id.as_u32(),
                            data.len(),
                            data
                        );
                        break;
                    }
                    _ => error!("Unexpected response type"),
                }
            }
            Timer::after(Duration::from_millis(100)).await;
            led.set_low();
        }
    }
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    info!("Main task started");

    // Random number generator
    let peripherals = embassy_stm32::init(Default::default());
    let rng = Rng::new(peripherals.RNG, Irqs);
    let led = Output::new(peripherals.PJ2, Level::High, Speed::Low);

    // Queues
    // Unsafe: Access to mutable static only happens here. Static lifetime is required by embassy tasks.
    let (client_req_tx, core_req_rx) = unsafe { CLIENT_TO_CORE.split() };
    let (core_resp_tx, client_resp_rx) = unsafe { CORE_TO_CLIENT.split() };
    let (core_req_tx, rng_req_rx) = unsafe { CORE_TO_RNG_WORKER.split() };
    let (rng_resp_tx, core_resp_rx) = unsafe { RNG_WORKER_TO_CORE.split() };

    // Start tasks
    spawner
        .spawn(hsm_task(
            core_req_rx,
            core_resp_tx,
            core_req_tx,
            core_resp_rx,
            rng_req_rx,
            rng_resp_tx,
            rng,
        ))
        .expect("Failed to spawn HSM task");
    spawner
        .spawn(client_task(client_req_tx, client_resp_rx, led))
        .expect("Failed to spawn client task");
}
