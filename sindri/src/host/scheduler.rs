use crate::common::jobs::{Request, Response};
use crate::common::pool::Pool;
use crate::crypto::rng::EntropySource;
use crate::host::workers::chachapoly_worker::ChachaPolyWorker;
use crate::host::workers::rng_worker::RngWorker;

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Error {
    Alloc,
    RequestTooLarge,
    Encrypt,
}

pub struct Job {
    pub channel_id: usize,
    pub request: Request,
}

pub struct JobResult {
    pub channel_id: usize,
    pub response: Response,
}

pub struct Scheduler<E: EntropySource> {
    pub pool: &'static Pool,
    pub rng_worker: RngWorker<E>,
    pub chachapoly_worker: ChachaPolyWorker,
}

// TODO: Retrieve response asynchronously
impl<E: EntropySource> Scheduler<E> {
    pub async fn schedule(&mut self, job: Job) -> JobResult {
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
    use crate::common::jobs::{Request, Response};
    use crate::common::limits::MAX_RANDOM_SIZE;
    use crate::common::pool::{Memory, Pool, PoolChunk};
    use crate::crypto::chacha20poly1305::{KEY_SIZE, NONCE_SIZE};
    use crate::crypto::rng::test::TestEntropySource;
    use crate::crypto::rng::Rng;
    use crate::host::scheduler::Scheduler;
    use crate::host::scheduler::{Error, Job};
    use crate::host::workers::chachapoly_worker::ChachaPolyWorker;
    use crate::host::workers::rng_worker::RngWorker;

    fn init_scheduler(
        memory: &'static mut Memory,
        pool: &'static Pool,
    ) -> Scheduler<TestEntropySource> {
        pool.init(memory).unwrap();
        let entropy = TestEntropySource::default();
        let rng = Rng::new(entropy, None);
        let rng_worker = RngWorker::<TestEntropySource> { pool, rng };
        let chachapoly_worker = ChachaPolyWorker { pool };
        Scheduler {
            pool,
            rng_worker,
            chachapoly_worker,
        }
    }

    #[futures_test::test]
    async fn get_random() {
        static mut MEMORY: Memory = [0; Pool::required_memory()];
        static POOL: Pool = Pool::new();
        let mut scheduler = init_scheduler(unsafe { &mut MEMORY }, &POOL);
        let request = Request::GetRandom { size: 32 };
        let job = Job {
            channel_id: 0,
            request,
        };
        match scheduler.schedule(job).await.response {
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

    #[futures_test::test]
    async fn get_random_request_too_large() {
        static mut MEMORY: Memory = [0; Pool::required_memory()];
        static POOL: Pool = Pool::new();
        let mut scheduler = init_scheduler(unsafe { &mut MEMORY }, &POOL);
        let request = Request::GetRandom {
            size: MAX_RANDOM_SIZE + 1,
        };
        let job = Job {
            channel_id: 0,
            request,
        };
        let result = scheduler.schedule(job).await;
        assert!(matches!(
            result.response,
            Response::Error(Error::RequestTooLarge)
        ))
    }

    #[futures_test::test]
    async fn encrypt_chachapoly() {
        static mut MEMORY: Memory = [0; Pool::required_memory()];
        static POOL: Pool = Pool::new();
        let mut scheduler = init_scheduler(unsafe { &mut MEMORY }, &POOL);

        fn alloc_vars() -> (PoolChunk, PoolChunk, PoolChunk, PoolChunk) {
            const KEY: &[u8; KEY_SIZE] = b"Fortuna Major or Oddsbodikins???";
            const NONCE: &[u8; NONCE_SIZE] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
            const PLAINTEXT: &[u8] = b"I solemnly swear I am up to no good!";
            const AAD: &[u8] = b"When in doubt, go to the library.";
            let key = POOL.alloc(KEY.len()).unwrap();
            let mut nonce = POOL.alloc(NONCE_SIZE).unwrap();
            nonce.as_slice_mut().copy_from_slice(NONCE);
            let mut aad = POOL.alloc(AAD.len()).unwrap();
            aad.as_slice_mut().copy_from_slice(AAD);
            let mut plaintext = POOL.alloc(PLAINTEXT.len()).unwrap();
            plaintext.as_slice_mut().copy_from_slice(PLAINTEXT);
            (key, nonce, aad, plaintext)
        }

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
        match scheduler.schedule(job).await.response {
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
                match scheduler.schedule(job).await.response {
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
