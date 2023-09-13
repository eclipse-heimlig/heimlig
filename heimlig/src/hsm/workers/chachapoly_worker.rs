use crate::common::jobs::{Error, Request, Response};
use crate::common::queues;
use crate::common::queues::ResponseSink;
use crate::config::keystore::MAX_KEY_SIZE;
use crate::hsm::keystore::KeyStore;
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::mutex::Mutex;
use zeroize::Zeroizing;

pub struct ChaChaPolyWorker<
    'data,
    'keystore,
    M: RawMutex,
    K: KeyStore,
    ReqSrc: Iterator<Item = (usize, Request<'data>)>,
    RespSink: ResponseSink<'data>,
> {
    pub key_store: &'keystore Mutex<M, K>,
    pub requests: ReqSrc,
    pub responses: RespSink,
}

impl<
        'data,
        'keystore,
        M: RawMutex,
        K: KeyStore,
        ReqSrc: Iterator<Item = (usize, Request<'data>)>,
        RespSink: ResponseSink<'data>,
    > ChaChaPolyWorker<'data, 'keystore, M, K, ReqSrc, RespSink>
{
    // TODO: Do not use core errors here? Export errors in trait as typedef?
    pub fn execute(&mut self) -> Result<(), queues::Error> {
        if self.responses.ready() {
            let mut key_buffer = Zeroizing::new([0u8; MAX_KEY_SIZE]);
            let response = match self.requests.next() {
                None => {
                    None // Nothing to process
                }
                Some((
                    _request_id,
                    Request::DecryptChaChaPoly {
                        key_id,
                        nonce,
                        aad,
                        ciphertext,
                        tag,
                    },
                )) => match self
                    .key_store
                    .try_lock()
                    .expect("Failed to lock key store")
                    .export(key_id, key_buffer.as_mut_slice())
                {
                    Ok(key) => Some(self.decrypt(key, nonce, aad, ciphertext, tag)),
                    Err(e) => Some(Response::Error(Error::KeyStore(e))),
                },
                Some((
                    _request_id,
                    Request::EncryptChaChaPoly {
                        key_id,
                        nonce,
                        aad,
                        plaintext,
                        tag,
                    },
                )) => match self
                    .key_store
                    .try_lock()
                    .expect("Failed to lock key store")
                    .export(key_id, key_buffer.as_mut_slice())
                {
                    Ok(key) => Some(self.encrypt(key, nonce, aad, plaintext, tag)),
                    Err(e) => Some(Response::Error(Error::KeyStore(e))),
                },
                Some((
                    _request_id,
                    Request::EncryptChaChaPolyExternalKey {
                        key,
                        nonce,
                        aad,
                        plaintext,
                        tag,
                    },
                )) => Some(self.encrypt_external_key(key, nonce, aad, plaintext, tag)),
                Some((
                    _request_id,
                    Request::DecryptChaChaPolyExternalKey {
                        key,
                        nonce,
                        aad,
                        ciphertext,
                        tag,
                    },
                )) => Some(self.decrypt_external_key(key, nonce, aad, ciphertext, tag)),
                _ => {
                    panic!("Encountered unexpected request"); // Integration error. Return error here instead?
                }
            };
            if let Some(response) = response {
                return self.responses.send(response);
            }
            Ok(())
        } else {
            Err(queues::Error::QueueFull)
        }
    }
    pub fn encrypt_external_key<'a>(
        &mut self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &'a mut [u8],
        tag: &'a mut [u8],
    ) -> Response<'a> {
        self.encrypt(key, nonce, aad, ciphertext, tag)
    }

    pub fn encrypt<'a>(
        &mut self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &'a mut [u8],
        tag: &'a mut [u8],
    ) -> Response<'a> {
        match crate::crypto::chacha20poly1305::encrypt_in_place_detached(
            key, nonce, aad, ciphertext,
        ) {
            Ok(computed_tag) => {
                if computed_tag.len() != tag.len() {
                    return Response::Error(Error::Crypto(crate::crypto::Error::InvalidTagSize));
                }
                tag.copy_from_slice(computed_tag.as_slice());
                Response::EncryptChaChaPoly { ciphertext, tag }
            }
            Err(e) => Response::Error(Error::Crypto(e)),
        }
    }

    pub fn decrypt_external_key<'a>(
        &mut self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &'a mut [u8],
        tag: &[u8],
    ) -> Response<'a> {
        self.decrypt(key, nonce, aad, plaintext, tag)
    }

    pub fn decrypt<'a>(
        &mut self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &'a mut [u8],
        tag: &[u8],
    ) -> Response<'a> {
        match crate::crypto::chacha20poly1305::decrypt_in_place_detached(
            key, nonce, aad, plaintext, tag,
        ) {
            Ok(()) => Response::DecryptChaChaPoly { plaintext },
            Err(e) => Response::Error(Error::Crypto(e)),
        }
    }
}
