use crate::common::jobs;
use crate::common::jobs::{Request, Response};
use crate::config::keystore::MAX_KEY_SIZE;
use crate::crypto::rng::{EntropySource, Rng};
use crate::hsm::keystore::{KeyStore, NoKeyStore};
use crate::hsm::workers::chachapoly_worker::ChachaPolyWorker;
use crate::hsm::workers::rng_worker::RngWorker;
use zeroize::Zeroizing;

/// HSM core that waits for [Request]s from [Channel]s and send [Response]s once they are ready.   
pub struct Core<
    'a,
    E: EntropySource,
    K: KeyStore,
    Req: Iterator<Item = (usize, Request<'a>)>,
    Resp: ResponseSink<'a>,
> {
    requests_source: Req,
    responses_sink: Resp,
    key_store: K,
    rng_worker: RngWorker<E>,
    chachapoly_worker: ChachaPolyWorker,
}

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
            requests_source,
            responses_sink,
            key_store,
            rng_worker: RngWorker { rng },
            chachapoly_worker: ChachaPolyWorker {},
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
            let request = self.requests_source.next();
            if let Some((request_id, request)) = request {
                return self.process(request_id, request);
            }
            Ok(()) // Nothing to process
        } else {
            Err(Error::QueueFull)
        }
    }

    // TODO: Move request ID into Request struct
    fn process(&mut self, _request_id: usize, request: Request<'a>) -> Result<(), Error> {
        // Schedule job
        // TODO: Retrieve result asynchronously
        let response = match request {
            Request::ImportKey { id, data } => match self.key_store.store(id, data) {
                Ok(_) => Response::ImportKey,
                Err(e) => Response::Error(jobs::Error::KeyStore(e)),
            },
            Request::GetRandom { output } => self.rng_worker.get_random(output),
            Request::EncryptChaChaPoly {
                key_id,
                nonce,
                aad,
                plaintext,
                tag,
            } => {
                let mut key = Zeroizing::new([0u8; MAX_KEY_SIZE]);
                match self.key_store.get(key_id, key.as_mut()) {
                    Ok(size) => {
                        let key = &key[..size];
                        self.chachapoly_worker
                            .encrypt(key, nonce, aad, plaintext, tag)
                    }
                    Err(e) => Response::Error(jobs::Error::KeyStore(e)),
                }
            }
            Request::EncryptChaChaPolyExternalKey {
                key,
                nonce,
                aad,
                plaintext,
                tag,
            } => self
                .chachapoly_worker
                .encrypt_external_key(key, nonce, aad, plaintext, tag),
            Request::DecryptChaChaPoly {
                key_id,
                nonce,
                aad,
                ciphertext,
                tag,
            } => {
                let mut key = Zeroizing::new([0u8; MAX_KEY_SIZE]);
                match self.key_store.get(key_id, key.as_mut()) {
                    Ok(size) => {
                        let key = &key[..size];
                        self.chachapoly_worker
                            .decrypt(key, nonce, aad, ciphertext, tag)
                    }
                    Err(e) => Response::Error(jobs::Error::KeyStore(e)),
                }
            }
            Request::DecryptChaChaPolyExternalKey {
                key,
                nonce,
                aad,
                ciphertext,
                tag,
            } => self
                .chachapoly_worker
                .decrypt_external_key(key, nonce, aad, ciphertext, tag),
        };

        self.responses_sink.send(response).expect(
            "We checked response sink not full at beginning of process_next, this should not fail.",
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::limits::MAX_RANDOM_SIZE;
    use crate::config;
    use crate::config::keystore::{KEY1, KEY2, KEY3};
    use crate::crypto::chacha20poly1305::{KEY_SIZE, NONCE_SIZE};
    use crate::crypto::rng::test::TestEntropySource;
    use crate::hsm::keystore::MemoryKeyStore;
    use core::iter::Enumerate;
    use heapless::spsc::{Consumer, Producer, Queue};

    const QUEUE_SIZE: usize = 8;
    const PLAINTEXT_SIZE: usize = 36;
    const AAD_SIZE: usize = 33;
    const TAG_SIZE: usize = 16;

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

    fn init_rng() -> Rng<TestEntropySource> {
        Rng::new(TestEntropySource::default(), None)
    }

    fn split_queues<'ch, 'data>(
        requests: &'ch mut Queue<Request<'data>, 8>,
        responses: &'ch mut Queue<Response<'data>, 8>,
    ) -> (
        Producer<'ch, Request<'data>, 8>,
        Consumer<'ch, Response<'data>, 8>,
        RequestQueueSource<'ch, 'data>,
        ResponseQueueSink<'ch, 'data>,
    ) {
        let (requests_tx, requests_rx): (Producer<Request, 8>, Consumer<Request, 8>) =
            requests.split();
        let (responses_tx, responses_rx) = responses.split();
        let requests_source = RequestQueueSource {
            consumer: requests_rx,
        };
        let responses_sink = ResponseQueueSink {
            producer: responses_tx,
        };
        (requests_tx, responses_rx, requests_source, responses_sink)
    }

    fn init_core<'ch, 'data>(
        rng: Rng<TestEntropySource>,
        requests_source: RequestQueueSource<'ch, 'data>,
        responses_sink: ResponseQueueSink<'ch, 'data>,
    ) -> Core<
        'data,
        TestEntropySource,
        MemoryKeyStore<{ config::keystore::TOTAL_SIZE }, { config::keystore::NUM_KEYS }>,
        Enumerate<RequestQueueSource<'ch, 'data>>,
        ResponseQueueSink<'ch, 'data>,
    > {
        let key_infos = [KEY1, KEY2, KEY3];
        let key_store = MemoryKeyStore::<
            { config::keystore::TOTAL_SIZE },
            { config::keystore::NUM_KEYS },
        >::try_new(&key_infos)
        .expect("failed to create key store");
        Core::new(rng, requests_source.enumerate(), responses_sink, key_store)
    }

    fn alloc_chachapoly_vars(buffer: &mut [u8]) -> (&[u8], &[u8], &[u8], &mut [u8], &mut [u8]) {
        const KEY: &[u8; KEY_SIZE] = b"Fortuna Major or Oddsbodikins???";
        const NONCE: &[u8; NONCE_SIZE] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        const PLAINTEXT: &[u8; PLAINTEXT_SIZE] = b"I solemnly swear I am up to no good!";
        const AAD: &[u8; AAD_SIZE] = b"When in doubt, go to the library.";
        let (key, buffer) = buffer.split_at_mut(KEY.len());
        key.copy_from_slice(KEY);
        let (nonce, buffer) = buffer.split_at_mut(NONCE.len());
        nonce.copy_from_slice(NONCE);
        let (aad, buffer) = buffer.split_at_mut(AAD.len());
        aad.copy_from_slice(AAD);
        let (plaintext, buffer) = buffer.split_at_mut(PLAINTEXT.len());
        plaintext.copy_from_slice(PLAINTEXT);
        let (tag, _buffer) = buffer.split_at_mut(TAG_SIZE);
        (key, nonce, aad, plaintext, tag)
    }

    #[test]
    fn get_random() {
        const REQUEST_SIZE: usize = 16;
        let mut random_output = [0u8; REQUEST_SIZE];
        let rng = init_rng();
        let mut requests = Queue::<Request, QUEUE_SIZE>::new();
        let mut responses = Queue::<Response, QUEUE_SIZE>::new();
        let (mut requests_tx, mut responses_rx, requests_source, responses_sink) =
            split_queues(&mut requests, &mut responses);
        let mut core = init_core(rng, requests_source, responses_sink);

        let request = Request::GetRandom {
            output: &mut random_output,
        };
        requests_tx
            .enqueue(request)
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

    #[test]
    fn get_random_request_too_large() {
        const REQUEST_SIZE: usize = MAX_RANDOM_SIZE + 1;
        let mut random_output = [0u8; REQUEST_SIZE];
        let rng = init_rng();
        let mut requests = Queue::<Request, QUEUE_SIZE>::new();
        let mut responses = Queue::<Response, QUEUE_SIZE>::new();
        let (mut requests_tx, mut responses_rx, requests_source, responses_sink) =
            split_queues(&mut requests, &mut responses);
        let mut core = init_core(rng, requests_source, responses_sink);

        let request = Request::GetRandom {
            output: &mut random_output,
        };
        requests_tx
            .enqueue(request)
            .expect("failed to send request");
        core.process_next().expect("failed to process next request");
        let response = responses_rx
            .dequeue()
            .expect("Failed to receive expected response");
        match response {
            Response::Error(jobs::Error::RequestTooLarge) => {}
            _ => {
                panic!("Unexpected response type {:?}", response);
            }
        }
    }

    #[test]
    fn encrypt_chachapoly() {
        let rng = init_rng();
        let mut memory1 = [0; KEY_SIZE + NONCE_SIZE + PLAINTEXT_SIZE + AAD_SIZE + TAG_SIZE];
        let mut memory2 = [0; KEY_SIZE + NONCE_SIZE + PLAINTEXT_SIZE + AAD_SIZE + TAG_SIZE];
        let mut requests = Queue::<Request, QUEUE_SIZE>::new();
        let mut responses = Queue::<Response, QUEUE_SIZE>::new();
        let (mut requests_tx, mut responses_rx, requests_source, responses_sink) =
            split_queues(&mut requests, &mut responses);
        let mut core = init_core(rng, requests_source, responses_sink);

        // Import key
        let (key, nonce, aad, plaintext, tag) = alloc_chachapoly_vars(&mut memory1);
        let request = Request::ImportKey {
            id: KEY3.id,
            data: key,
        };
        requests_tx
            .enqueue(request)
            .expect("failed to send request");
        core.process_next().expect("failed to process next request");
        let response = responses_rx
            .dequeue()
            .expect("Failed to receive expected response");
        match response {
            Response::ImportKey {} => {}
            _ => {
                panic!("Unexpected response type");
            }
        };

        // Encrypt data
        let request = Request::EncryptChaChaPoly {
            key_id: KEY3.id,
            nonce,
            aad,
            plaintext,
            tag,
        };
        requests_tx
            .enqueue(request)
            .expect("failed to send request");
        core.process_next().expect("failed to process next request");
        let (ciphertext, tag) = match responses_rx
            .dequeue()
            .expect("Failed to receive expected response")
        {
            Response::EncryptChaChaPoly { ciphertext, tag } => (ciphertext, tag),
            _ => {
                panic!("Unexpected response type");
            }
        };

        // Decrypt data
        let (_key, nonce, aad, org_plaintext, _tag) = alloc_chachapoly_vars(&mut memory2);
        let request = Request::DecryptChaChaPoly {
            key_id: KEY3.id,
            nonce,
            aad,
            ciphertext,
            tag,
        };
        requests_tx
            .enqueue(request)
            .expect("failed to send request");
        core.process_next().expect("failed to process next request");
        let plaintext = match responses_rx
            .dequeue()
            .expect("Failed to receive expected response")
        {
            Response::DecryptChaChaPoly { plaintext } => plaintext,
            resp => {
                panic!("Unexpected response type {:?}", resp);
            }
        };
        assert_eq!(plaintext, org_plaintext);
    }

    #[test]
    fn encrypt_chachapoly_external_key() {
        let rng = init_rng();
        let mut memory1 = [0; KEY_SIZE + NONCE_SIZE + PLAINTEXT_SIZE + AAD_SIZE + TAG_SIZE];
        let mut memory2 = [0; KEY_SIZE + NONCE_SIZE + PLAINTEXT_SIZE + AAD_SIZE + TAG_SIZE];
        let mut requests = Queue::<Request, QUEUE_SIZE>::new();
        let mut responses = Queue::<Response, QUEUE_SIZE>::new();
        let (mut requests_tx, mut responses_rx, requests_source, responses_sink) =
            split_queues(&mut requests, &mut responses);
        let mut core = init_core(rng, requests_source, responses_sink);

        // Encrypt data
        let (key, nonce, aad, plaintext, tag) = alloc_chachapoly_vars(&mut memory1);
        let request = Request::EncryptChaChaPolyExternalKey {
            key,
            nonce,
            aad,
            plaintext,
            tag,
        };
        requests_tx
            .enqueue(request)
            .expect("failed to send request");
        core.process_next().expect("failed to process next request");
        let (ciphertext, tag) = match responses_rx
            .dequeue()
            .expect("Failed to receive expected response")
        {
            Response::EncryptChaChaPoly { ciphertext, tag } => (ciphertext, tag),
            _ => {
                panic!("Unexpected response type");
            }
        };

        // Decrypt data
        let (key, nonce, aad, org_plaintext, _tag) = alloc_chachapoly_vars(&mut memory2);
        let request = Request::DecryptChaChaPolyExternalKey {
            key,
            nonce,
            aad,
            ciphertext,
            tag,
        };
        requests_tx
            .enqueue(request)
            .expect("failed to send request");
        core.process_next().expect("failed to process next request");
        let plaintext = match responses_rx
            .dequeue()
            .expect("Failed to receive expected response")
        {
            Response::DecryptChaChaPoly { plaintext } => plaintext,
            _ => {
                panic!("Unexpected response type");
            }
        };
        assert_eq!(plaintext, org_plaintext)
    }
}
