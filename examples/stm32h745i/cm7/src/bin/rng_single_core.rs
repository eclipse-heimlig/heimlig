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
use heimlig::client;
use heimlig::client::api::Api;
use heimlig::common::jobs::{Request, Response};
use heimlig::common::pool::Memory;
use heimlig::common::pool::Pool;
use heimlig::crypto::rng;
use heimlig::hsm;
use heimlig::hsm::core::Core;
use rand_core::RngCore;

use {defmt_rtt as _, panic_probe as _};

bind_interrupts!(struct Irqs {
    RNG => InterruptHandler<RNG>;
});

// Shared memory pool
static mut MEMORY: Memory = [0; Pool::required_memory()];

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

struct ChannelClientSide<'a, const QUEUE_SIZE: usize> {
    sender: Producer<'a, Request, QUEUE_SIZE>,
    receiver: Consumer<'a, Response, QUEUE_SIZE>,
}

struct ChannelCoreSide<'a> {
    sender: Producer<'a, Response, QUEUE_SIZE>,
    receiver: Consumer<'a, Request, QUEUE_SIZE>,
}

impl<'a> client::api::Channel for ChannelClientSide<'a, QUEUE_SIZE> {
    fn send(&mut self, request: Request) -> Result<(), client::api::Error> {
        self.sender
            .enqueue(request)
            .map_err(|_request| client::api::Error::QueueFull)
    }

    fn recv(&mut self) -> Option<Response> {
        self.receiver.dequeue()
    }
}

impl<'a> hsm::core::Channel for ChannelCoreSide<'a> {
    fn send(&mut self, response: Response) -> Result<(), hsm::core::Error> {
        self.sender
            .enqueue(response)
            .map_err(|_response| hsm::core::Error::QueueFull)
    }

    fn recv(&mut self) -> Option<Request> {
        self.receiver.dequeue()
    }
}

#[embassy_executor::task]
async fn hsm_task(
    req_rx: Consumer<'static, Request, QUEUE_SIZE>,
    resp_tx: Producer<'static, Response, QUEUE_SIZE>,
    rng: Rng<'static, RNG>,
) {
    info!("HSM task started");

    // Channel
    let core_side = ChannelCoreSide {
        sender: resp_tx,
        receiver: req_rx,
    };
    let mut channels = heapless::Vec::<_, 1>::new();
    let _ = channels.push(core_side);

    let rng = rng::Rng::new(EntropySource { rng }, None);
    let pool = Pool::try_from(unsafe { &mut MEMORY }).expect("failed to initialize memory pool");
    let mut core = Core::new_without_key_store(&pool, rng, channels);

    loop {
        core.process_next().expect("failed to process next request");
        Timer::after(Duration::from_millis(100)).await;
    }
}

#[embassy_executor::task]
async fn client_task(
    resp_rx: Consumer<'static, Response, QUEUE_SIZE>,
    req_tx: Producer<'static, Request, QUEUE_SIZE>,
    mut led: Output<'static, embassy_stm32::peripherals::PJ2>,
) {
    info!("Client task started");

    // Channel
    let mut core_side = ChannelClientSide {
        sender: req_tx,
        receiver: resp_rx,
    };

    // Api
    let mut api = Api::new(&mut core_side);

    loop {
        // Send requests
        Timer::after(Duration::from_millis(1000)).await;
        led.set_high();
        let random_size = 16;
        info!("Sending request: random data (size={})", random_size);
        api.get_random(random_size)
            .expect("failed to call randomness API");

        // Receive response
        loop {
            if let Some(response) = api.recv_response() {
                match response {
                    Response::GetRandom { data } => {
                        info!(
                            "Received response: random data (size={}): {:02x}",
                            data.len(),
                            data.as_slice()
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
