#![feature(type_alias_impl_trait)] // Required for embassy

use embassy_executor::Spawner;
use embassy_time::Duration;
use embassy_time::Timer;
use heapless::spsc::{Consumer, Producer, Queue};
use heapless::Vec;
use log::{error, info};
use rand::RngCore;
use sindri::client;
use sindri::client::api::Api;
use sindri::common::jobs::{Request, Response};
use sindri::common::pool::Memory;
use sindri::common::pool::Pool;
use sindri::crypto::rng;
use sindri::crypto::rng::Rng;
use sindri::host;
use sindri::host::core::{Channel, Core};

// Shared memory pool
static mut MEMORY: Memory = [0; Pool::required_memory()];

// Request and response queues between tasks
const QUEUE_SIZE: usize = 8;
static mut CLIENT_TO_HOST: Queue<Request, QUEUE_SIZE> = Queue::<Request, QUEUE_SIZE>::new();
static mut HOST_TO_CLIENT: Queue<Response, QUEUE_SIZE> = Queue::<Response, QUEUE_SIZE>::new();

struct RequestSender<'a, const QUEUE_SIZE: usize> {
    sender: Producer<'a, Request, QUEUE_SIZE>,
}

struct ResponseReceiver<'a, const QUEUE_SIZE: usize> {
    receiver: Consumer<'a, Response, QUEUE_SIZE>,
}

struct ResponseSender<'a> {
    sender: Producer<'a, Response, QUEUE_SIZE>,
}

struct RequestReceiver<'a> {
    receiver: Consumer<'a, Request, QUEUE_SIZE>,
}

struct EntropySource {}

impl<'a> client::api::Sender for RequestSender<'a, QUEUE_SIZE> {
    fn send(&mut self, request: Request) -> Result<(), client::api::Error> {
        self.sender
            .enqueue(request)
            .map_err(|_request| client::api::Error::QueueFull)
    }
}

impl<'a> client::api::Receiver for ResponseReceiver<'a, QUEUE_SIZE> {
    fn recv(&mut self) -> Option<Response> {
        self.receiver.dequeue()
    }
}

impl<'a> host::core::Sender for ResponseSender<'a> {
    fn send(&mut self, response: Response) -> Result<(), host::core::Error> {
        self.sender
            .enqueue(response)
            .map_err(|_response| host::core::Error::QueueFull)
    }
}

impl<'a> host::core::Receiver for RequestReceiver<'a> {
    fn recv(&mut self) -> Option<Request> {
        self.receiver.dequeue()
    }
}

impl rng::EntropySource for EntropySource {
    fn random_seed(&mut self) -> [u8; 32] {
        let mut data = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut data);
        data
    }
}

#[embassy_executor::task]
async fn host_task(
    pool: Pool,
    req_rx: Consumer<'static, Request, QUEUE_SIZE>,
    resp_tx: Producer<'static, Response, QUEUE_SIZE>,
) {
    let mut request_receiver = RequestReceiver { receiver: req_rx };
    let mut response_sender = ResponseSender { sender: resp_tx };
    let mut channels = Vec::<Channel<_, _>, 2>::new();
    if channels
        .push(Channel::new(&mut response_sender, &mut request_receiver))
        .is_err()
    {
        panic!("List of return channels is too small");
    }
    let rng = Rng::new(EntropySource {}, None);
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
) {
    let mut request_sender = RequestSender { sender: req_tx };
    let mut response_receiver = ResponseReceiver { receiver: resp_rx };
    let mut hsm = Api::new(&mut request_sender, &mut response_receiver);

    loop {
        // Send request
        Timer::after(Duration::from_millis(1000)).await;
        let random_size = 16;
        info!(target: "CLIENT", "Sending request: random data (size={})", random_size);
        hsm.get_random(random_size)
            .expect("failed to call randomness API");

        // Receive response
        loop {
            match hsm.recv_response() {
                None => Timer::after(Duration::from_millis(10)).await, // Continue waiting for response
                Some(response) => {
                    match response {
                        Response::GetRandom { data } => {
                            info!(target: "CLIENT",
                                "Received response: random data (size={}): {}",
                                data.len(),
                                hex::encode(data.as_slice())
                            );
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

    // Pool
    let pool = Pool::try_from(unsafe { &mut MEMORY }).expect("failed to initialize memory pool");

    // Queues
    // Unsafe: Access to mutable static only happens here. Static lifetime is required by embassy tasks.
    let (req_tx, req_rx) = unsafe { CLIENT_TO_HOST.split() };
    let (resp_tx, resp_rx) = unsafe { HOST_TO_CLIENT.split() };

    // Start tasks
    spawner
        .spawn(host_task(pool, req_rx, resp_tx))
        .expect("failed to spawn host task");
    spawner
        .spawn(client_task(resp_rx, req_tx))
        .expect("failed to spawn client task");
}
