#![feature(type_alias_impl_trait)] // Required for embassy

use embassy_executor::Spawner;
use embassy_time::Duration;
use embassy_time::Timer;
use heapless::spsc::{Consumer, Producer, Queue};
use heimlig::client::api::Api;
use heimlig::client::api::RequestSink;
use heimlig::common::jobs::{Request, Response};
use heimlig::crypto::rng;
use heimlig::crypto::rng::Rng;
use heimlig::hsm::core::Core;
use heimlig::hsm::core::ResponseSink;
use log::{error, info};
use rand::RngCore;

// Request and response queues between tasks
const QUEUE_SIZE: usize = 8;
static mut CLIENT_TO_HSM: Queue<Request, QUEUE_SIZE> = Queue::new();
static mut HSM_TO_CLIENT: Queue<Response, QUEUE_SIZE> = Queue::new();

struct EntropySource {}

impl rng::EntropySource for EntropySource {
    fn random_seed(&mut self) -> [u8; 32] {
        let mut data = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut data);
        data
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
) {
    // Channel
    let requests_source = RequestQueueSource { consumer: req_rx };
    let responses_sink = ResponseQueueSink { producer: resp_tx };

    let rng = Rng::new(EntropySource {}, None);
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
) {
    // Channel
    let requests_sink = RequestQueueSink { producer: req_tx };
    let responses_source = ResponseQueueSource { consumer: resp_rx };

    // Api
    let mut api = Api::new(requests_sink, responses_source);

    loop {
        // Send request
        Timer::after(Duration::from_millis(1000)).await;
        let random_output = Box::leak(Box::new([0u8; 16]));
        info!(target: "CLIENT", "Sending request: random data (size={})", random_output.len());
        api.get_random(random_output.as_mut_slice())
            .expect("failed to call randomness API");

        // Receive response
        loop {
            match api.recv_response() {
                None => Timer::after(Duration::from_millis(10)).await, // Continue waiting for response
                Some(response) => {
                    match response {
                        Response::GetRandom { data } => {
                            info!(target: "CLIENT",
                                "Received response: random data (size={}): {}",
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
    let (req_tx, req_rx) = unsafe { CLIENT_TO_HSM.split() };
    let (resp_tx, resp_rx) = unsafe { HSM_TO_CLIENT.split() };

    // Start tasks
    spawner
        .spawn(hsm_task(req_rx, resp_tx))
        .expect("failed to spawn HSM task");
    spawner
        .spawn(client_task(resp_rx, req_tx))
        .expect("failed to spawn client task");
}
