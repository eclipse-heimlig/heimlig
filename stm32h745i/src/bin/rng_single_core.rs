#![no_std]
#![no_main]
#![feature(type_alias_impl_trait)]

use core::cell::RefCell;
use cortex_m::interrupt::{self, Mutex};
use defmt::*;
use embassy::executor::Spawner;
use embassy::time::{Duration, Timer};
use embassy_stm32::Peripherals;
use embassy_stm32::peripherals::RNG as PeripheralRNG;
use embassy_stm32::rng::Rng;
use heapless::spsc::{Consumer, Producer, Queue};
use rand_core::RngCore;
use sindri::common::jobs::{Request, Response};
use sindri::crypto::rng;
use sindri::host::core::{Core, Error, Sender};
use {defmt_rtt as _, panic_probe as _};

const MAX_CLIENTS: usize = 1;
const QUEUE_SIZE: usize = 8;
static mut CLIENT_TO_HOST: Queue<Request, QUEUE_SIZE> = Queue::<Request, QUEUE_SIZE>::new();
static mut HOST_TO_CLIENT: Queue<Response, QUEUE_SIZE> = Queue::<Response, QUEUE_SIZE>::new();

static HW_RNG_INSTANCE: Mutex<RefCell<Option<PeripheralRNG>>> = Mutex::new(RefCell::new(None));

struct EntropySource {}

impl rng::EntropySource for EntropySource {
    fn random_seed(&mut self) -> [u8; 32] {
        let mut buf = [0u8; 32];

        interrupt::free(|cs| {
            match HW_RNG_INSTANCE.borrow(cs).borrow_mut().take() {
                Some(p_rng) => {
                    let mut rng = Rng::new(p_rng);
                    rng.fill_bytes(&mut buf);
                },
                None => defmt::panic!("HW_RNG_INSTANCE is not initialized"),
            }
        });

        info!("New random seed (size={}, data={:02x})", buf.len(), buf);

        buf
    }
}

struct RequestReceiver<'a> {
    receiver: Consumer<'a, Request, QUEUE_SIZE>,
}

struct RequestSender<'a> {
    sender: Producer<'a, Request, QUEUE_SIZE>,
}

struct ResponseReceiver<'a> {
    receiver: Consumer<'a, Response, QUEUE_SIZE>,
}

struct ResponseSender<'a> {
    id: u32,
    sender: Producer<'a, Response, QUEUE_SIZE>,
}

impl<'ch> RequestReceiver<'ch> {
    fn recv(&mut self) -> Option<Request> {
        self.receiver.dequeue()
    }
}

impl<'ch> RequestSender<'ch> {
    fn send(&mut self, request: Request) {
        let request = self.sender.enqueue(request);
        if request.is_err() {
            warn!("Queue is full. Dropping request.")
        }
    }
}

impl<'ch> ResponseReceiver<'ch> {
    fn recv(&mut self) -> Option<Response> {
        self.receiver.dequeue()
    }
}

impl<'ch> Sender for ResponseSender<'ch> {
    fn get_id(&self) -> u32 {
        self.id
    }

    fn send(&mut self, response: Response) {
        let response = self.sender.enqueue(response);
        if response.is_err() {
            warn!("Queue is full. Dropping response.")
        }
    }
}

#[embassy::task]
async fn client_send(mut sender: RequestSender<'static>) {
    loop {
        let size = 16;
        let request = Request::GetRandom { size };
        info!("Sending request: random data (size={})", size);
        sender.send(request);
        Timer::after(Duration::from_secs(1)).await;
    }
}

#[embassy::task]
async fn client_recv(mut receiver: ResponseReceiver<'static>) {
    loop {
        match receiver.recv() {
            Some(response) => match response {
                Response::Error(_e) => {
                    error!("Received response: Error")
                }
                Response::GetRandom { data } => {
                    info!("Received response: random data (size={}, data={:02x})", data.len(), data.as_slice());
                }
            },
            None => {
                Timer::after(Duration::from_millis(100)).await;
            }
        }
    }
}

#[embassy::task]
async fn host_recv_resp(
    mut sender: ResponseSender<'static>,
    mut receiver: RequestReceiver<'static>,
) {
    let rng = rng::Rng::new(EntropySource {}, None);
    let mut response_channels = heapless::Vec::<&mut dyn Sender, MAX_CLIENTS>::new();
    if response_channels.push(&mut sender).is_err() {
        error!("List of return channels not large enough");
    }
    let mut core = Core::new(rng, response_channels);

    loop {
        match receiver.recv() {
            Some(request) => match request {
                Request::GetRandom { size } => {
                    info!("Received request: random data (size={})", size);
                    match core.process(0, request).await {
                        Ok(_) => {
                            info!("Request processed successfully");
                        }
                        Err(e) => {
                            match e {
                                Error::Busy => error!("Failed to process request: Busy"),
                                Error::UnknownId => error!("Failed to process request: UnknownId"),
                            }
                        }
                    };
                }
            },
            None => {
                Timer::after(Duration::from_millis(100)).await;
            }
        }
    }
}

#[embassy::main]
async fn main(spawner: Spawner, p: Peripherals) {

    interrupt::free(|cs| HW_RNG_INSTANCE.borrow(cs).replace(Some(p.RNG)));

    // TODO: Unsafe: Access to static queues must be protected across tasks/cores
    let (c2h_p, c2h_c) = unsafe { CLIENT_TO_HOST.split() };
    let (h2c_p, h2c_c) = unsafe { HOST_TO_CLIENT.split() };
    let request_receiver = RequestReceiver { receiver: c2h_c };
    let request_sender = RequestSender { sender: c2h_p };
    let response_receiver = ResponseReceiver { receiver: h2c_c };
    let response_sender = ResponseSender {
        id: 0,
        sender: h2c_p,
    };

    // Start tasks
    spawner
        .spawn(host_recv_resp(response_sender, request_receiver))
        .expect("[MAIN] Failed to spawn host task");
    spawner
        .spawn(client_recv(response_receiver))
        .expect("[MAIN] Failed to spawn client receiver task");
    spawner
        .spawn(client_send(request_sender))
        .expect("[MAIN] Failed to spawn client sender task");
}
