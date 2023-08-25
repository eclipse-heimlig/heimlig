#[cfg(test)]
mod tests;

use crate::common::jobs;
use crate::common::jobs::{Request, Response};
use crate::common::scrub_on_drop::ScrubOnDrop;
use crate::config::keystore::MAX_KEY_SIZE;
use crate::crypto::rng::{EntropySource, Rng};
use crate::hsm::keystore;
use crate::hsm::keystore::KeyStore;
use crate::hsm::workers::chachapoly_worker::ChachaPolyWorker;
use crate::hsm::workers::rng_worker::RngWorker;

/// A job for the HSM to compute a cryptographic task.
pub struct Job<'a> {
    /// ID of the channel over which this job should be answered.
    pub request_id: usize,
    /// The [Request] containing the details for a cryptographic task.
    pub request: Request<'a>,
}

/// The result of a cryptographic task to be sent back over a channel.
pub struct JobResult<'a> {
    /// ID of the channel over which this result should be transferred.
    pub request_id: usize,
    /// The [Response] containing the result of the cryptographic task.
    pub response: Response<'a>,
}

/// Scheduler to distribute jobs to proper workers.
pub struct Scheduler<E: EntropySource, K: KeyStore> {
    key_store: Option<K>,
    rng_worker: RngWorker<E>,
    chachapoly_worker: ChachaPolyWorker,
}

impl<E: EntropySource, K: KeyStore> Scheduler<E, K> {
    /// Create a new scheduler.
    pub fn new(rng: Rng<E>, key_store: Option<K>) -> Self {
        Scheduler {
            key_store,
            rng_worker: RngWorker { rng },
            chachapoly_worker: ChachaPolyWorker {},
        }
    }
}

impl<E: EntropySource, K: KeyStore> Scheduler<E, K> {
    /// Schedules a [Job] to be processed by a worker.
    // TODO: Retrieve response from worker asynchronously and notify caller
    pub fn schedule<'a>(&mut self, job: Job<'a>) -> JobResult<'a> {
        let response = match job.request {
            Request::ImportKey { id, data } => match &mut self.key_store {
                Some(key_store) => match key_store.store(id, data) {
                    Ok(_) => Response::ImportKey,
                    Err(e) => Response::Error(jobs::Error::KeyStore(e)),
                },
                None => Response::Error(jobs::Error::KeyStore(keystore::Error::KeyNotFound)),
            },
            Request::GetRandom { output } => self.rng_worker.get_random(output),
            Request::EncryptChaChaPoly {
                key_id,
                nonce,
                aad,
                plaintext,
                tag,
            } => {
                let mut key: ScrubOnDrop<MAX_KEY_SIZE> = ScrubOnDrop::new();
                match &self.key_store {
                    Some(key_store) => match key_store.get(key_id, &mut key.data) {
                        Ok(size) => {
                            let key = &key.data[..size];
                            self.chachapoly_worker
                                .encrypt(key, nonce, aad, plaintext, tag)
                        }
                        Err(e) => Response::Error(jobs::Error::KeyStore(e)),
                    },
                    None => Response::Error(jobs::Error::KeyStore(keystore::Error::KeyNotFound)),
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
                let mut key: ScrubOnDrop<MAX_KEY_SIZE> = ScrubOnDrop::new();
                match &self.key_store {
                    Some(key_store) => match key_store.get(key_id, &mut key.data) {
                        Ok(size) => {
                            let key = &key.data[..size];
                            self.chachapoly_worker
                                .decrypt(key, nonce, aad, ciphertext, tag)
                        }
                        Err(e) => Response::Error(jobs::Error::KeyStore(e)),
                    },
                    None => Response::Error(jobs::Error::KeyStore(keystore::Error::KeyNotFound)),
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
        JobResult {
            request_id: job.request_id,
            response,
        }
    }
}
