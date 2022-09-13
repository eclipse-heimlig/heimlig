use crate::common::jobs::Response::GetRandom;
use crate::common::jobs::{Request, Response};
use crate::common::limits::MAX_RANDOM_SIZE;
use crate::common::pool::{Pool, PoolChunk};
use crate::crypto::chacha20poly1305::{chacha20poly1305_decrypt, chacha20poly1305_encrypt};
use crate::crypto::rng::{EntropySource, Rng};
use rand_core::RngCore;

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Error {
    Alloc,
    RequestTooLarge,
    Encrypt,
}

pub struct Job {
    pub id: u32,
    pub request: Request,
}

pub struct JobResult {
    pub id: u32,
    pub response: Response,
}

pub struct Scheduler<E: EntropySource> {
    pub pool: &'static Pool,
    pub rng: Rng<E>, // TODO: Have the RNG as a singleton available everywhere?
}

// TODO: Async: Scheduler should communicate with worker tasks over queues
impl<E: EntropySource> Scheduler<E> {
    pub async fn schedule(&mut self, job: Job) -> JobResult {
        let response = match job.request {
            Request::GetRandom { size } => self.proc_random(size),
            Request::EncryptChaChaPoly {
                key,
                nonce,
                aad,
                plaintext,
            } => self.proc_chachapoly_encrypt(key, nonce, aad, plaintext),
            Request::DecryptChaChaPoly {
                key,
                nonce,
                aad,
                ciphertext,
                tag,
            } => self.proc_chachapoly_decrypt(key, nonce, aad, ciphertext, tag),
        };
        JobResult {
            id: job.id,
            response,
        }
    }

    fn proc_random(&mut self, size: usize) -> Response {
        if size >= MAX_RANDOM_SIZE {
            return Response::Error(Error::RequestTooLarge);
        }
        match self.pool.alloc(size) {
            Err(_) => Response::Error(Error::Alloc),
            Ok(mut chunk) => {
                self.rng.fill_bytes(chunk.as_slice_mut());
                GetRandom { data: chunk }
            }
        }
    }

    fn proc_chachapoly_encrypt(
        &mut self,
        key: PoolChunk,
        nonce: PoolChunk,
        aad: Option<PoolChunk>,
        mut ciphertext: PoolChunk,
    ) -> Response {
        match self.pool.alloc(crate::crypto::chacha20poly1305::TAG_SIZE) {
            Err(_) => Response::Error(Error::Alloc),
            Ok(mut tag) => {
                let aad = match &aad {
                    Some(aad) => aad.as_slice(),
                    None => &[] as &[u8],
                };
                match chacha20poly1305_encrypt(
                    key.as_slice(),
                    nonce.as_slice(),
                    aad,
                    ciphertext.as_slice_mut(),
                    tag.as_slice_mut(),
                ) {
                    Ok(_) => Response::EncryptChaChaPoly { ciphertext, tag },
                    Err(_) => Response::Error(Error::Encrypt),
                }
            }
        }
    }

    fn proc_chachapoly_decrypt(
        &mut self,
        key: PoolChunk,
        nonce: PoolChunk,
        aad: Option<PoolChunk>,
        mut plaintext: PoolChunk,
        tag: PoolChunk,
    ) -> Response {
        let aad = match &aad {
            Some(aad) => aad.as_slice(),
            None => &[] as &[u8],
        };
        match chacha20poly1305_decrypt(
            key.as_slice(),
            nonce.as_slice(),
            aad,
            plaintext.as_slice_mut(),
            tag.as_slice(),
        ) {
            Ok(_) => Response::DecryptChaChaPoly { plaintext },
            Err(_) => Response::Error(Error::Encrypt),
        }
    }
}

#[cfg(test)]
pub(crate) mod test {
    use crate::common::jobs::{Request, Response};
    use crate::common::limits::MAX_RANDOM_SIZE;
    use crate::common::pool::{Memory, Pool, PoolChunk};
    use crate::crypto::chacha20poly1305::{KEY_SIZE, NONCE_SIZE};
    use crate::crypto::rng::{EntropySource, Rng};
    use crate::host::scheduler::Scheduler;
    use crate::host::scheduler::{Error, Job};

    #[derive(Default)]
    pub struct TestEntropySource {}

    impl EntropySource for TestEntropySource {
        fn random_seed(&mut self) -> [u8; 32] {
            [0u8; 32]
        }
    }

    fn init_scheduler(
        memory: &'static mut Memory,
        pool: &'static Pool,
    ) -> Scheduler<TestEntropySource> {
        pool.init(memory).unwrap();
        let entropy = TestEntropySource::default();
        let rng = Rng::new(entropy, None);
        Scheduler { pool, rng }
    }

    #[futures_test::test]
    async fn get_random() {
        static mut MEMORY: Memory = [0; Pool::required_memory()];
        static POOL: Pool = Pool::new();
        let mut scheduler = init_scheduler(unsafe { &mut MEMORY }, &POOL);
        let request = Request::GetRandom { size: 32 };
        let job = Job { id: 0, request };
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
        let job = Job { id: 0, request };
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
        let job = Job { id: 0, request };
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
                let job = Job { id: 0, request };
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
