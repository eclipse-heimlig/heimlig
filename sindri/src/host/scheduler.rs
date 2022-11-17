use crate::common::jobs::{Request, Response};
use crate::common::pool::Pool;
use crate::crypto::rng::{EntropySource, Rng};
use crate::host::workers::chachapoly_worker::ChachaPolyWorker;
use crate::host::workers::rng_worker::RngWorker;

/// A job for the HSM to compute a cryptographic task.
pub struct Job {
    /// ID of the channel over which this job should be answered.
    pub channel_id: usize,
    /// The [Request] containing the details for a cryptographic task.
    pub request: Request,
}

/// The result of a cryptographic task to be sent back over a channel.
pub struct JobResult {
    /// ID of the channel over which this result should be transferred.
    pub channel_id: usize,
    /// The [Response] containing the result of the cryptographic task.
    pub response: Response,
}

/// Scheduler to distribute jobs to proper workers.
pub struct Scheduler<'a, E: EntropySource> {
    rng_worker: RngWorker<'a, E>,
    chachapoly_worker: ChachaPolyWorker<'a>,
}

impl<'a, E: EntropySource> Scheduler<'a, E> {
    /// Create a new scheduler.
    pub fn new(pool: &'a Pool, rng: Rng<E>) -> Self {
        Scheduler {
            rng_worker: RngWorker { pool, rng },
            chachapoly_worker: ChachaPolyWorker { pool },
        }
    }
}

impl<'a, E: EntropySource> Scheduler<'a, E> {
    /// Schedules a [Job] to be processed by a worker.
    // TODO: Retrieve response from worker asynchronously and notify caller
    pub fn schedule(&mut self, job: Job) -> JobResult {
        let response = match job.request {
            Request::GetRandom { size } => self.rng_worker.get_random(size),
            Request::EncryptChaChaPoly {
                key,
                nonce,
                aad,
                plaintext,
            } => self.chachapoly_worker.encrypt(key, nonce, aad, plaintext),
            Request::DecryptChaChaPoly {
                key,
                nonce,
                aad,
                ciphertext,
                tag,
            } => self
                .chachapoly_worker
                .decrypt(key, nonce, aad, ciphertext, tag),
        };
        JobResult {
            channel_id: job.channel_id,
            response,
        }
    }
}

#[cfg(test)]
pub(crate) mod test {
    use crate::common::jobs::{Error, Request, Response};
    use crate::common::limits::MAX_RANDOM_SIZE;
    use crate::common::pool::{Memory, Pool, PoolChunk};
    use crate::crypto::chacha20poly1305::{KEY_SIZE, NONCE_SIZE};
    use crate::crypto::rng::test::TestEntropySource;
    use crate::crypto::rng::Rng;
    use crate::host::scheduler::Job;
    use crate::host::scheduler::Scheduler;

    fn init_scheduler(pool: &Pool) -> Scheduler<TestEntropySource> {
        let entropy = TestEntropySource::default();
        let rng = Rng::new(entropy, None);
        Scheduler::new(pool, rng)
    }

    #[test]
    fn get_random() {
        static mut MEMORY: Memory = [0; Pool::required_memory()];
        let pool = Pool::try_from(unsafe { &mut MEMORY }).unwrap();
        let mut scheduler = init_scheduler(&pool);
        let request = Request::GetRandom { size: 32 };
        let job = Job {
            channel_id: 0,
            request,
        };
        match scheduler.schedule(job).response {
            Response::GetRandom {
                data: response_data,
            } => {
                assert_eq!(response_data.len(), 32)
            }
            _ => {
                panic!("Unexpected response type");
            }
        };
    }

    #[test]
    fn get_random_request_too_large() {
        static mut MEMORY: Memory = [0; Pool::required_memory()];
        let pool = Pool::try_from(unsafe { &mut MEMORY }).unwrap();
        let mut scheduler = init_scheduler(&pool);
        let request = Request::GetRandom {
            size: MAX_RANDOM_SIZE + 1,
        };
        let job = Job {
            channel_id: 0,
            request,
        };
        let result = scheduler.schedule(job);
        assert!(matches!(
            result.response,
            Response::Error(Error::RequestTooLarge)
        ))
    }

    #[test]
    fn encrypt_chachapoly() {
        static mut MEMORY: Memory = [0; Pool::required_memory()];
        let pool = Pool::try_from(unsafe { &mut MEMORY }).unwrap();
        let mut scheduler = init_scheduler(&pool);

        let alloc_vars = || -> (PoolChunk, PoolChunk, PoolChunk, PoolChunk) {
            const KEY: &[u8; KEY_SIZE] = b"Fortuna Major or Oddsbodikins???";
            const NONCE: &[u8; NONCE_SIZE] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
            const PLAINTEXT: &[u8] = b"I solemnly swear I am up to no good!";
            const AAD: &[u8] = b"When in doubt, go to the library.";
            let key = pool.alloc(KEY.len()).unwrap();
            let mut nonce = pool.alloc(NONCE_SIZE).unwrap();
            nonce.as_slice_mut().copy_from_slice(NONCE);
            let mut aad = pool.alloc(AAD.len()).unwrap();
            aad.as_slice_mut().copy_from_slice(AAD);
            let mut plaintext = pool.alloc(PLAINTEXT.len()).unwrap();
            plaintext.as_slice_mut().copy_from_slice(PLAINTEXT);
            (key, nonce, aad, plaintext)
        };

        let (key, nonce, aad, plaintext) = alloc_vars();
        let request = Request::EncryptChaChaPoly {
            key,
            nonce,
            aad: Some(aad),
            plaintext,
        };
        let job = Job {
            channel_id: 0,
            request,
        };
        match scheduler.schedule(job).response {
            Response::EncryptChaChaPoly { ciphertext, tag } => {
                let (key, nonce, aad, org_plaintext) = alloc_vars();
                let request = Request::DecryptChaChaPoly {
                    key,
                    nonce,
                    aad: Some(aad),
                    ciphertext,
                    tag,
                };
                let job = Job {
                    channel_id: 0,
                    request,
                };
                match scheduler.schedule(job).response {
                    Response::DecryptChaChaPoly { plaintext } => {
                        assert_eq!(plaintext.as_slice(), org_plaintext.as_slice())
                    }
                    _ => {
                        panic!("Unexpected response type");
                    }
                }
            }
            _ => {
                panic!("Unexpected response type");
            }
        };
    }
}
