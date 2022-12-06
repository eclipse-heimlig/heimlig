#![no_std]
#![no_main]
#![feature(type_alias_impl_trait)]

use core::cell::RefCell;
use cortex_m::interrupt::{self, Mutex};
use defmt::*;
use embassy_executor::Spawner;
use embassy_stm32::gpio::{Level, Output, Speed};
use embassy_stm32::rng::Rng;
use embassy_time::{Duration, Timer};
use heapless::spsc::{Consumer, Producer, Queue};
use rand_core::RngCore;
use sindri::client;
use sindri::client::api::Api;
use sindri::common::jobs::{Request, Response};
use sindri::common::pool::Memory;
use sindri::common::pool::Pool;
use sindri::crypto::rng;
use sindri::host;
use sindri::host::core::Core;
use {defmt_rtt as _, panic_probe as _};

// Shared memory pool
static mut MEMORY: Memory = [0; Pool::required_memory()];

const QUEUE_SIZE: usize = 8;
static mut CLIENT_TO_HOST: Queue<Request, QUEUE_SIZE> = Queue::<Request, QUEUE_SIZE>::new();
static mut HOST_TO_CLIENT: Queue<Response, QUEUE_SIZE> = Queue::<Response, QUEUE_SIZE>::new();

static RNG: Mutex<RefCell<Option<Rng<embassy_stm32::peripherals::RNG>>>> =
    Mutex::new(RefCell::new(None));

struct EntropySource {}

impl rng::EntropySource for EntropySource {
    fn random_seed(&mut self) -> [u8; 32] {
        let mut buf = [0u8; 32];
        interrupt::free(|cs| match RNG.borrow(cs).borrow_mut().take() {
            Some(mut rng) => {
                rng.fill_bytes(&mut buf);
            }
            None => defmt::panic!("HW_RNG_INSTANCE is not initialized"),
        });
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

impl<'a> host::core::Channel for ChannelCoreSide<'a> {
    fn send(&mut self, response: Response) -> Result<(), host::core::Error> {
        self.sender
            .enqueue(response)
            .map_err(|_response| host::core::Error::QueueFull)
    }

    fn recv(&mut self) -> Option<Request> {
        self.receiver.dequeue()
    }
}

#[embassy_executor::task]
async fn host_task(
    req_rx: Consumer<'static, Request, QUEUE_SIZE>,
    resp_tx: Producer<'static, Response, QUEUE_SIZE>,
) {
    info!("Host task started");

    // Channel
    let core_side = ChannelCoreSide {
        sender: resp_tx,
        receiver: req_rx,
    };
    let mut channels = heapless::Vec::<_, 1>::new();
    let _ = channels.push(core_side);

    let rng = rng::Rng::new(EntropySource {}, None);
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
    let rng = Rng::new(peripherals.RNG);
    let led = Output::new(peripherals.PJ2, Level::High, Speed::Low);
    interrupt::free(|cs| RNG.borrow(cs).replace(Some(rng)));

    // Queues
    // Unsafe: Access to mutable static only happens here. Static lifetime is required by embassy tasks.
    let (req_tx, req_rx) = unsafe { CLIENT_TO_HOST.split() };
    let (resp_tx, resp_rx) = unsafe { HOST_TO_CLIENT.split() };

    // Start tasks
    spawner
        .spawn(host_task(req_rx, resp_tx))
        .expect("failed to spawn host task");
    spawner
        .spawn(client_task(resp_rx, req_tx, led))
        .expect("failed to spawn client task");
}