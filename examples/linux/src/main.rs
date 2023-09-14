#![feature(type_alias_impl_trait)] // Required for embassy

use core::cell::RefCell;
use core::iter::Enumerate;
use embassy_executor::Spawner;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use embassy_time::Duration;
use embassy_time::Timer;
use heapless::spsc::{Consumer, Producer, Queue};
use heimlig::client::api::Api;
use heimlig::common::jobs::{Request, RequestType, Response};
use heimlig::common::queues;
use heimlig::common::queues::{RequestSink, ResponseSink};
use heimlig::crypto::rng;
use heimlig::crypto::rng::Rng;
use heimlig::hsm::core::Core;
use heimlig::hsm::keystore::NoKeyStore;
use heimlig::hsm::workers::rng_worker::RngWorker;
use log::{error, info};
use rand::RngCore;

// Request and response queues between tasks
const QUEUE_SIZE: usize = 8;
static mut CLIENT_TO_CORE: Queue<Request, QUEUE_SIZE> = Queue::new();
static mut CORE_TO_CLIENT: Queue<Response, QUEUE_SIZE> = Queue::new();
static mut CORE_TO_RNG_WORKER: Queue<Response, QUEUE_SIZE> = Queue::new();
static mut RNG_WORKER_TO_CORE: Queue<Request, QUEUE_SIZE> = Queue::new();

// Globals initialized in one task but used in another
static CORE: Mutex<
    CriticalSectionRawMutex,
    RefCell<
        Option<
            Core<
                CriticalSectionRawMutex,
                NoKeyStore,
                Enumerate<RequestQueueSource<'static, 'static>>,
                ResponseQueueSink<'static, 'static>,
                RequestQueueSink<'static, 'static>,
                Enumerate<ResponseQueueSource<'static, 'static>>,
            >,
        >,
    >,
> = Mutex::new(RefCell::new(None));
static KEY_STORE: Mutex<CriticalSectionRawMutex, RefCell<Option<NoKeyStore>>> =
    Mutex::new(RefCell::new(None));
static RNG_WORKER: Mutex<
    CriticalSectionRawMutex,
    RefCell<Option<RngWorker<EntropySource, Enumerate<RequestQueueSource>, ResponseQueueSink>>>,
> = Mutex::new(RefCell::new(None));

struct EntropySource {}

impl rng::EntropySource for EntropySource {
    fn random_seed(&mut self) -> [u8; 32] {
        let mut data = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut data);
        data
    }
}

struct RequestQueueSink<'ch, 'data> {
    producer: Producer<'ch, Request<'data>, QUEUE_SIZE>,
}

impl<'data> RequestSink<'data> for RequestQueueSink<'_, 'data> {
    fn send(&mut self, request: Request<'data>) -> Result<(), queues::Error> {
        self.producer
            .enqueue(request)
            .map_err(|_| queues::Error::Enqueue)
    }

    fn ready(&self) -> bool {
        self.producer.ready()
    }
}

struct RequestQueueSource<'ch, 'data> {
    consumer: Consumer<'ch, Request<'data>, QUEUE_SIZE>,
}

impl<'data> Iterator for RequestQueueSource<'_, 'data> {
    type Item = Request<'data>;

    fn next(&mut self) -> Option<Self::Item> {
        self.consumer.dequeue()
    }
}

struct ResponseQueueSink<'ch, 'data> {
    producer: Producer<'ch, Response<'data>, QUEUE_SIZE>,
}

impl<'data> ResponseSink<'data> for ResponseQueueSink<'_, 'data> {
    fn send(&mut self, response: Response<'data>) -> Result<(), queues::Error> {
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
async fn core_task() {
    loop {
        {
            let core = CORE.try_lock().expect("Failed to lock core");
            let mut core = core.borrow_mut();
            let core = core.as_mut().expect("Core was not initialized");
            core.execute().expect("failed to forward request");
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
            rng_worker.execute().expect("failed to process request");
        }
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
    let (client_req_tx, client_req_rx) = unsafe { CLIENT_TO_CORE.split() };
    let (client_resp_tx, client_resp_rx) = unsafe { CORE_TO_CLIENT.split() };
    let (rng_resp_tx, rng_resp_rx) = unsafe { CORE_TO_RNG_WORKER.split() };
    let (rng_req_tx, rng_req_rx) = unsafe { RNG_WORKER_TO_CORE.split() };

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

    let rng = Rng::new(EntropySource {}, None);
    let rng_worker = RngWorker {
        rng,
        requests: rng_requests_rx.enumerate(),
        responses: rng_responses_tx,
    };
    RNG_WORKER
        .try_lock()
        .expect("Failed to lock RNG_WORKER")
        .replace(Some(rng_worker));
    KEY_STORE
        .try_lock()
        .expect("Failed to lock KEY_STORE")
        .replace(Some(NoKeyStore {}));
    let mut core: Core<
        CriticalSectionRawMutex,
        NoKeyStore,
        Enumerate<RequestQueueSource<'_, '_>>,
        ResponseQueueSink<'_, '_>,
        RequestQueueSink<'_, '_>,
        Enumerate<ResponseQueueSource<'_, '_>>,
    > = Core::new(&KEY_STORE, client_requests.enumerate(), client_responses);
    core.add_worker_channel(
        &[RequestType::GetRandom],
        rng_requests_tx,
        rng_responses_rx.enumerate(),
    );
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
