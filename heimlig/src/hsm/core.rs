use crate::common::jobs::{Request, Response};
use crate::crypto::rng::{EntropySource, Rng};
use crate::hsm::keystore::{KeyStore, NoKeyStore};
use crate::hsm::scheduler::{Job, Scheduler};

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Error {
    /// No [Channel] found for given ID.
    UnknownChannelId,
    /// Attempted to push to a full queue.
    QueueFull,
}

/// Sink where the responses from the Core can be pushed to
pub trait ResponseSink<'a> {
    /// Send a [Response] to the client through this sink.
    fn send(&mut self, response: Response<'a>) -> Result<(), Error>;
    fn ready(&self) -> bool;
}

/// HSM core that waits for [Request]s from [Channel]s and send [Response]s once they are ready.   
pub struct Core<
    'a,
    E: EntropySource,
    K: KeyStore,
    Req: Iterator<Item = (usize, Request<'a>)>,
    Resp: ResponseSink<'a>,
> {
    scheduler: Scheduler<E, K>,
    requests_source: Req,
    responses_sink: Resp,
}

impl<'a, E: EntropySource, Req: Iterator<Item = (usize, Request<'a>)>, Resp: ResponseSink<'a>>
    Core<'a, E, NoKeyStore, Req, Resp>
{
    /// Create a new HSM core.
    /// This variant does not configure a [KeyStore] so this core will not be able to store
    /// cryptographic material.
    ///
    /// # Arguments
    ///
    /// * `rng`: Random number generator (RNG) used to seed the core RNG.
    /// * `response_channels`: List of [Channel]s to send responses back to the clients.
    pub fn new_without_key_store(rng: Rng<E>, requests_source: Req, responses_sink: Resp) -> Self {
        Self::new(rng, requests_source, responses_sink, NoKeyStore)
    }
}

impl<
        'a,
        E: EntropySource,
        K: KeyStore,
        Req: Iterator<Item = (usize, Request<'a>)>,
        Resp: ResponseSink<'a>,
    > Core<'a, E, K, Req, Resp>
{
    /// Create a new HSM core.
    /// The core accepts requests and forwards the responses once they are ready.
    ///
    /// # Arguments
    ///
    /// * `rng`: Random number generator (RNG) used to seed the core RNG.
    /// * `response_channels`: List of [Channel]s to send responses back to the clients.
    /// * `key_store`: The [KeyStore] to hold cryptographic key material.
    pub fn new(rng: Rng<E>, requests_source: Req, responses_sink: Resp, key_store: K) -> Self {
        Self {
            scheduler: Scheduler::new(rng, key_store),
            requests_source,
            responses_sink,
        }
    }

    /// Search all input channels for a new request and process it.
    /// Channels are processed in a round-robin fashion.
    ///
    /// # Returns
    ///
    /// * `Ok(true)` if a [Request] was found and successfully processed.
    /// * `Ok(false)` if no [Request] was found in any input [Channel].
    /// * `Err(core::Error)` if a processing error occurred.
    pub fn process_next(&mut self) -> Result<(), Error> {
        if self.responses_sink.ready() {
            let maybe_request = self.requests_source.next();
            if let Some((request_id, request)) = maybe_request {
                return self.process(request_id, request);
            }
            Ok(()) // Nothing to process
        } else {
            Err(Error::QueueFull)
        }
    }

    fn process(&mut self, request_id: usize, request: Request<'a>) -> Result<(), Error> {
        // Schedule job
        let job = Job {
            request_id,
            request,
        };
        // TODO: Retrieve result asynchronously
        let result = self.scheduler.schedule(job);

        self.responses_sink.send(result.response).expect(
            "We checked response sink not full at beggining of process_next, this should not fail.",
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use crate::config::keystore::{KEY1, KEY2, KEY3};
    use crate::crypto::rng;
    use crate::hsm::keystore::MemoryKeyStore;
    use heapless::spsc::{Consumer, Producer, Queue};

    const QUEUE_SIZE: usize = 8;

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
        fn send(&mut self, response: Response<'a>) -> Result<(), Error> {
            self.producer
                .enqueue(response)
                .map_err(|_| Error::QueueFull)
        }
        fn ready(&self) -> bool {
            self.producer.ready()
        }
    }

    #[test]
    fn multiple_clients() {
        const REQUEST_SIZE: usize = 16;
        let mut random_output = [0u8; REQUEST_SIZE];

        // RNG
        let entropy = rng::test::TestEntropySource::default();
        let rng = Rng::new(entropy, None);

        // Queues
        let mut requests = Queue::<Request, QUEUE_SIZE>::new();
        let mut responses = Queue::<Response, QUEUE_SIZE>::new();

        let (mut requests_tx, requests_rx) = requests.split();
        let (responses_tx, mut responses_rx) = responses.split();

        let requests_source = RequestQueueSource {
            consumer: requests_rx,
        };

        let responses_sink = ResponseQueueSink {
            producer: responses_tx,
        };

        // Core
        let key_infos = [KEY1, KEY2, KEY3];
        let key_store = MemoryKeyStore::<
            { config::keystore::TOTAL_SIZE },
            { config::keystore::NUM_KEYS },
        >::try_new(&key_infos)
        .expect("failed to create key store");

        let mut core = Core::new(rng, requests_source.enumerate(), responses_sink, key_store);

        requests_tx
            .enqueue(Request::GetRandom {
                output: &mut random_output,
            })
            .expect("failed to send request");

        core.process_next().expect("failed to process next request");

        match responses_rx.dequeue() {
            Some(response) => match response {
                Response::GetRandom { data } => {
                    assert_eq!(data.len(), REQUEST_SIZE)
                }
                _ => {
                    panic!("Unexpected response type {:?}", response);
                }
            },
            None => {
                panic!("Failed to receive expected response");
            }
        }
    }
}
