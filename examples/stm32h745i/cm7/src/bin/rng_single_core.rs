#![no_std]
#![no_main]
#![feature(type_alias_impl_trait)]

use core::cell::RefCell;
use core::iter::Enumerate;
use defmt::*;
use embassy_executor::Spawner;
use embassy_stm32::bind_interrupts;
use embassy_stm32::gpio::{Level, Output, Speed};
use embassy_stm32::peripherals::RNG;
use embassy_stm32::rng::{InterruptHandler, Rng};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::mutex::Mutex;
use embassy_time::{Duration, Timer};
use heapless::spsc::{Consumer, Producer, Queue};
use heimlig::client::api::Api;
use heimlig::common::jobs::{Request, RequestType, Response};
use heimlig::common::queues;
use heimlig::common::queues::{RequestSink, ResponseSink};
use heimlig::crypto::rng;
use heimlig::hsm::core::Core;
use heimlig::hsm::keystore::NoKeyStore;
use heimlig::hsm::workers::rng_worker::RngWorker;
use rand_core::RngCore;

use {defmt_rtt as _, panic_probe as _};

bind_interrupts!(struct Irqs {
    RNG => InterruptHandler<RNG>;
});

// Shared memory pool
static mut MEMORY: [u8; 256] = [0; 256];

const QUEUE_SIZE: usize = 8;
static mut CLIENT_TO_CORE: Queue<Request, QUEUE_SIZE> = Queue::new();
static mut CORE_TO_CLIENT: Queue<Response, QUEUE_SIZE> = Queue::new();
static mut CORE_TO_RNG_WORKER: Queue<Response, QUEUE_SIZE> = Queue::new();
static mut RNG_WORKER_TO_CORE: Queue<Request, QUEUE_SIZE> = Queue::new();

struct EntropySource {
    rng: Rng<'static, RNG>,
}

impl rng::EntropySource for EntropySource {
    fn random_seed(&mut self) -> [u8; 32] {
        let mut buf = [0u8; 32];
        self.rng.fill_bytes(&mut buf);
        info!("New random seed (size={}, data={:02x})", buf.len(), buf);
        buf
    }
}
struct RequestQueueSink<'ch, 'a> {
    producer: Producer<'ch, Request<'a>, QUEUE_SIZE>,
}

impl<'a> RequestSink<'a> for RequestQueueSink<'_, 'a> {
    fn send(&mut self, request: Request<'a>) -> Result<(), queues::Error> {
        self.producer
            .enqueue(request)
            .map_err(|_| queues::Error::Enqueue)
    }

    fn ready(&self) -> bool {
        self.producer.ready()
    }
}

struct RequestQueueSource<'ch, 'a> {
    consumer: Consumer<'ch, Request<'a>, QUEUE_SIZE>,
}

impl<'a> Iterator for RequestQueueSource<'_, 'a> {
    type Item = Request<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.consumer.dequeue()
    }
}

struct ResponseQueueSink<'ch, 'a> {
    producer: Producer<'ch, Response<'a>, QUEUE_SIZE>,
}

impl<'a> ResponseSink<'a> for ResponseQueueSink<'_, 'a> {
    fn send(&mut self, response: Response<'a>) -> Result<(), queues::Error> {
        self.producer
            .enqueue(response)
            .map_err(|_| queues::Error::Enqueue)
    }
    fn ready(&self) -> bool {
        self.producer.ready()
    }
}

struct ResponseQueueSource<'ch, 'a> {
    consumer: Consumer<'ch, Response<'a>, QUEUE_SIZE>,
}

impl<'a> Iterator for ResponseQueueSource<'_, 'a> {
    type Item = Response<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.consumer.dequeue()
    }
}

#[embassy_executor::task]
async fn hsm_task(
    client_req_rx: Consumer<'static, Request<'_>, QUEUE_SIZE>,
    client_resp_tx: Producer<'static, Response<'_>, QUEUE_SIZE>,
    rng_req_tx: Producer<'static, Request<'_>, QUEUE_SIZE>,
    rng_req_rx: Consumer<'static, Request<'_>, QUEUE_SIZE>,
    rng_resp_tx: Producer<'static, Response<'_>, QUEUE_SIZE>,
    rng_resp_rx: Consumer<'static, Response<'_>, QUEUE_SIZE>,
    rng: Rng<'static, RNG>,
) {
    info!("HSM task started");

    // Channels
    let client_requests = RequestQueueSource {
        consumer: client_req_rx,
    };
    let client_responses = ResponseQueueSink {
        producer: client_resp_tx,
    };
    let rng_requests_rx = RequestQueueSource {
        consumer: rng_req_rx,
    };
    let rng_requests_tx = RequestQueueSink {
        producer: rng_req_tx,
    };
    let rng_responses_rx = ResponseQueueSource {
        consumer: rng_resp_rx,
    };
    let rng_responses_tx = ResponseQueueSink {
        producer: rng_resp_tx,
    };

    let rng = rng::Rng::new(EntropySource { rng }, None);
    let mut rng_worker = RngWorker {
        rng,
        requests: rng_requests_rx.enumerate(),
        responses: rng_responses_tx,
    };
    let key_store = NoKeyStore {};
    let key_store = Mutex::new(RefCell::new(Some(key_store)));
    let mut core: Core<
        NoopRawMutex,
        NoKeyStore,
        Enumerate<RequestQueueSource<'_, '_>>,
        ResponseQueueSink<'_, '_>,
        RequestQueueSink<'_, '_>,
        Enumerate<ResponseQueueSource<'_, '_>>,
    > = Core::new(&key_store, client_requests.enumerate(), client_responses);
    core.add_worker_channel(
        &[RequestType::GetRandom],
        rng_requests_tx,
        rng_responses_rx.enumerate(),
    );

    loop {
        core.execute().expect("failed to forward request");
        rng_worker.execute().expect("failed to process request");
        Timer::after(Duration::from_millis(100)).await;
    }
}

#[embassy_executor::task]
async fn client_task(
    resp_rx: Consumer<'static, Response<'_>, QUEUE_SIZE>,
    req_tx: Producer<'static, Request<'_>, QUEUE_SIZE>,
    mut led: Output<'static, embassy_stm32::peripherals::PJ2>,
) {
    info!("Client task started");

    // Memory
    let pool = heapless::pool::Pool::<[u8; 16]>::new();
    // Safety: we are the only users of MEMORY
    pool.grow(unsafe { &mut MEMORY });

    // Channel
    let requests_sink = RequestQueueSink { producer: req_tx };
    let responses_source = ResponseQueueSource { consumer: resp_rx };

    // Api
    let mut api = Api::new(requests_sink, responses_source);

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
        info!(
            "Sending request: random data (size={})",
            random_buffer.len()
        );
        api.get_random(random_buffer)
            .expect("failed to call randomness API");

        // Receive response
        loop {
            if let Some(response) = api.recv_response() {
                match response {
                    Response::GetRandom { data } => {
                        info!(
                            "Received response: random data (size={}): {:02x}",
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
    let (client_req_tx, client_req_rx) = unsafe { CLIENT_TO_CORE.split() };
    let (client_resp_tx, client_resp_rx) = unsafe { CORE_TO_CLIENT.split() };
    let (rng_resp_tx, rng_resp_rx) = unsafe { CORE_TO_RNG_WORKER.split() };
    let (rng_req_tx, rng_req_rx) = unsafe { RNG_WORKER_TO_CORE.split() };

    // Start tasks
    spawner
        .spawn(hsm_task(
            client_req_rx,
            client_resp_tx,
            rng_req_tx,
            rng_req_rx,
            rng_resp_tx,
            rng_resp_rx,
            rng,
        ))
        .expect("Failed to spawn HSM task");
    spawner
        .spawn(client_task(client_resp_rx, client_req_tx, led))
        .expect("Failed to spawn client task");
}
