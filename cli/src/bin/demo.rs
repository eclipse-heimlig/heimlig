#![feature(type_alias_impl_trait)] // Required for embassy

use clap::Parser;
use embassy::executor::Spawner;
use embassy::time::Duration;
use embassy::time::Timer;
use heapless::spsc::{Consumer, Producer, Queue};
use log::{error, info};
use rand::RngCore;
use sindri::common::jobs::{Request, Response};
use sindri::crypto::rng;
use sindri::host::core::Core;
use std::path::PathBuf;

const QUEUE_SIZE: usize = 8;
static mut CLIENT_TO_HOST: Queue<Request, QUEUE_SIZE> = Queue::<Request, QUEUE_SIZE>::new();
static mut HOST_TO_CLIENT: Queue<Response, QUEUE_SIZE> = Queue::<Response, QUEUE_SIZE>::new();

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Unix domain socket path
    #[clap(short, long, default_value = "sindri.sock")]
    socket: PathBuf,
}

struct EntropySource {}

impl rng::EntropySource for EntropySource {
    fn random_seed(&mut self) -> [u8; 32] {
        let mut data = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut data);
        data
    }
}

#[embassy::task]
async fn client_send(mut producer: Producer<'static, Request, QUEUE_SIZE>) {
    loop {
        let size = 16;
        let request = Request::GetRandom { size };
        info!(target: "CLIENT", "Sending request: random data (size={})", size);
        let response = producer.enqueue(request);
        match response {
            Ok(()) => {}
            Err(ref e) => {
                error!(target: "CLIENT", "Failed to send request: {:?}", e);
            }
        }
        drop(response);
        Timer::after(Duration::from_secs(1)).await;
    }
}

#[embassy::task]
async fn client_recv(mut consumer: Consumer<'static, Response, QUEUE_SIZE>) {
    loop {
        let response = consumer.dequeue();
        match &response {
            Some(response) => match response {
                Response::Error(e) => {
                    error!(target: "CLIENT", "Received response: Error: {:?}", e)
                }
                Response::GetRandom { data } => {
                    info!(target: "CLIENT",
                        "Received response: random data (size={}): {}",
                        data.len(),
                        hex::encode(data)
                    );
                }
            },
            None => {}
        }
        drop(response);
        Timer::after(Duration::from_millis(100)).await;
    }
}

#[embassy::task]
async fn host_recv_resp(
    mut consumer: Consumer<'static, Request, QUEUE_SIZE>,
    mut producer: Producer<'static, Response, QUEUE_SIZE>,
) {
    // instantiate core
    let rng = rng::Rng::new(EntropySource {}, None);
    let mut core = Core::new(rng);

    loop {
        let request = consumer.dequeue();
        match request {
            Some(request) => match request {
                Request::GetRandom { size } => {
                    info!(target: "HOST", "Received request: random data (size={})", size);
                    match core.process(&mut producer, request).await {
                        Ok(_) => {}
                        Err(e) => {
                            error!(target: "HOST", "Failed to process request: {:?}", e);
                        }
                    };
                }
            },
            None => {}
        }
        Timer::after(Duration::from_millis(100)).await;
    }
}

#[embassy::main]
async fn main(spawner: Spawner) {
    simple_logger::SimpleLogger::new()
        .init()
        .expect("[MAIN] Failed to initialize logger");
    let _args = Args::parse();

    // Unsafe: Access to mutable static only happens here. Static lifetime is required by embassy tasks.
    let (p1, c1) = unsafe { CLIENT_TO_HOST.split() };
    let (p2, c2) = unsafe { HOST_TO_CLIENT.split() };

    // Start tasks
    spawner
        .spawn(host_recv_resp(c1, p2))
        .expect("[MAIN] Failed to spawn host task");
    spawner
        .spawn(client_recv(c2))
        .expect("[MAIN] Failed to spawn client receiver task");
    spawner
        .spawn(client_send(p1))
        .expect("[MAIN] Failed to spawn client sender task");
}
