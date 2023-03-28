#[cfg(test)]
mod tests;

use crate::common::jobs;
use crate::common::jobs::{Request, Response};
use crate::common::pool::Pool;
use crate::common::scrub_on_drop::ScrubOnDrop;
use crate::config::keystore::MAX_KEY_SIZE;
use crate::crypto::rng::{EntropySource, Rng};
use crate::hsm::keystore;
use crate::hsm::keystore::KeyStore;
use crate::hsm::workers::chachapoly_worker::ChachaPolyWorker;
use crate::hsm::workers::rng_worker::RngWorker;

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
    key_store: Option<&'a mut dyn KeyStore>,
    rng_worker: RngWorker<'a, E>,
    chachapoly_worker: ChachaPolyWorker<'a>,
}

impl<'a, E: EntropySource> Scheduler<'a, E> {
    /// Create a new scheduler.
    pub fn new(pool: &'a Pool, rng: Rng<E>, key_store: Option<&'a mut dyn KeyStore>) -> Self {
        Scheduler {
            key_store,
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
            Request::ImportKey { id, data } => match &mut self.key_store {
                Some(key_store) => match key_store.store(id, data.as_slice()) {
                    Ok(_) => Response::ImportKey,
                    Err(e) => Response::Error(jobs::Error::KeyStore(e)),
                },
                None => Response::Error(jobs::Error::KeyStore(keystore::Error::KeyNotFound)),
            },
            Request::GetRandom { size } => self.rng_worker.get_random(size),
            Request::EncryptChaChaPoly {
                key_id,
                nonce,
                aad,
                plaintext,
            } => {
                let mut key: ScrubOnDrop<MAX_KEY_SIZE> = ScrubOnDrop::new();
                match &self.key_store {
                    Some(key_store) => match key_store.get(key_id, &mut key.data) {
                        Ok(size) => {
                            let key = &key.data[..size];
                            self.chachapoly_worker.encrypt(key, nonce, aad, plaintext)
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
            } => self
                .chachapoly_worker
                .encrypt_external_key(key, nonce, aad, plaintext),
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
            channel_id: job.channel_id,
            response,
        }
    }
}
