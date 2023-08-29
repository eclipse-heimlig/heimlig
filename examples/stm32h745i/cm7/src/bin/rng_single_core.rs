#![no_std]
#![no_main]
#![feature(type_alias_impl_trait)]

use defmt::*;
use embassy_executor::Spawner;
use embassy_stm32::bind_interrupts;
use embassy_stm32::gpio::{Level, Output, Speed};
use embassy_stm32::peripherals::RNG;
use embassy_stm32::rng::{InterruptHandler, Rng};
use embassy_time::{Duration, Timer};
use heapless::spsc::{Consumer, Producer, Queue};
use heimlig::client::api::{Api, RequestSink};
use heimlig::common::jobs::{Request, Response};
use heimlig::crypto::rng;
use heimlig::hsm::core::{Core, ResponseSink};
use rand_core::RngCore;

use {defmt_rtt as _, panic_probe as _};

bind_interrupts!(struct Irqs {
    RNG => InterruptHandler<RNG>;
});

// Shared memory pool
static mut MEMORY: [u8; 256] = [0; 256];

const QUEUE_SIZE: usize = 8;
static mut CLIENT_TO_HSM: Queue<Request, QUEUE_SIZE> = Queue::<Request, QUEUE_SIZE>::new();
static mut HSM_TO_CLIENT: Queue<Response, QUEUE_SIZE> = Queue::<Response, QUEUE_SIZE>::new();

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
    fn send(&mut self, request: Request<'a>) -> Result<(), heimlig::client::api::Error> {
        self.producer
            .enqueue(request)
            .map_err(|_| heimlig::client::api::Error::QueueFull)
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
    fn send(&mut self, response: Response<'a>) -> Result<(), heimlig::hsm::core::Error> {
        self.producer
            .enqueue(response)
            .map_err(|_| heimlig::hsm::core::Error::QueueFull)
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
    req_rx: Consumer<'static, Request<'_>, QUEUE_SIZE>,
    resp_tx: Producer<'static, Response<'_>, QUEUE_SIZE>,
    rng: Rng<'static, RNG>,
) {
    info!("HSM task started");

    // Channel
    let requests_source = RequestQueueSource { consumer: req_rx };
    let responses_sink = ResponseQueueSink { producer: resp_tx };

    let rng = rng::Rng::new(EntropySource { rng }, None);
    let mut core = Core::new_without_key_store(rng, requests_source.enumerate(), responses_sink);

    loop {
        core.process_next().expect("failed to process next request");
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
    let (req_tx, req_rx) = unsafe { CLIENT_TO_HSM.split() };
    let (resp_tx, resp_rx) = unsafe { HSM_TO_CLIENT.split() };

    // Start tasks
    spawner
        .spawn(hsm_task(req_rx, resp_tx, rng))
        .expect("failed to spawn HSM task");
    spawner
        .spawn(client_task(resp_rx, req_tx, led))
        .expect("failed to spawn client task");
}
