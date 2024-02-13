use crate::common::jobs::{ClientId, Error, Request, RequestId, Response};
use crate::crypto;
use crate::crypto::ecdsa::{
    nist_p256_generate_key_pair, nist_p256_sign, nist_p256_sign_prehashed, nist_p256_verify,
    nist_p256_verify_prehashed, nist_p384_generate_key_pair, nist_p384_sign,
    nist_p384_sign_prehashed, nist_p384_verify, nist_p384_verify_prehashed,
};
use crate::hsm::keystore;
use crate::hsm::keystore::{Curve, KeyId, KeyInfo, KeyType};
use core::ops::DerefMut;
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::mutex::Mutex;
use futures::{Sink, SinkExt, Stream, StreamExt};
use rand_chacha::rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

pub struct EccWorker<
    'data,
    'rng,
    'keystore,
    M: RawMutex,
    R: CryptoRng + RngCore,
    ReqSrc: Stream<Item = Request<'data>>,
    RespSink: Sink<Response<'data>>,
    KeyStore: keystore::KeyStore + keystore::InsecureKeyStore + Send,
> {
    pub rng: &'rng Mutex<M, R>,
    pub key_store: &'keystore Mutex<M, &'keystore mut KeyStore>,
    pub requests: ReqSrc,
    pub responses: RespSink,
}

impl<
        'data,
        'rng,
        'keystore,
        M: RawMutex,
        R: CryptoRng + RngCore,
        ReqSrc: Stream<Item = Request<'data>> + Unpin,
        RespSink: Sink<Response<'data>> + Unpin,
        KeyStore: keystore::KeyStore + keystore::InsecureKeyStore + Send,
    > EccWorker<'data, 'rng, 'keystore, M, R, ReqSrc, RespSink, KeyStore>
{
    /// Drive the worker to process the next request.
    /// This method is supposed to be called by a system task that owns this worker.
    pub async fn execute(&mut self) -> Result<(), Error> {
        let request = self.requests.next().await.ok_or(Error::StreamTerminated)?;
        let response = match request {
            Request::GenerateKeyPair {
                client_id,
                request_id,
                key_id,
                overwrite,
            } => {
                self.generate_key_pair(client_id, request_id, key_id, overwrite)
                    .await
            }
            Request::Sign {
                client_id,
                request_id,
                key_id,
                message,
                prehashed,
                signature,
            } => {
                self.sign(client_id, request_id, key_id, message, prehashed, signature)
                    .await
            }
            Request::SignExternalKey {
                client_id,
                request_id,
                private_key,
                message,
                prehashed,
                signature,
            } => {
                self.sing_external_key(
                    client_id,
                    request_id,
                    private_key,
                    message,
                    prehashed,
                    signature,
                )
                .await
            }
            Request::Verify {
                client_id,
                request_id,
                key_id,
                message,
                prehashed,
                signature,
            } => {
                self.verify(client_id, request_id, key_id, message, prehashed, signature)
                    .await
            }
            Request::VerifyExternalKey {
                client_id,
                request_id,
                public_key,
                message,
                prehashed,
                signature,
            } => {
                self.verify_external_key(
                    client_id, request_id, public_key, message, prehashed, signature,
                )
                .await
            }
            _ => Err(Error::UnexpectedRequestType)?,
        };
        self.responses
            .send(response)
            .await
            .map_err(|_e| Error::Send)
    }

    async fn generate_key_pair(
        &mut self,
        client_id: ClientId,
        request_id: RequestId,
        key_id: KeyId,
        overwrite: bool,
    ) -> Response<'data> {
        let mut locked_key_store = self.key_store.lock().await;
        let key_info = keystore::KeyStore::get_key_info(*locked_key_store, key_id);
        let mut private_key_bytes = Zeroizing::new([0u8; KeyType::MAX_PRIVATE_KEY_SIZE]);
        let mut public_key_bytes = Zeroizing::new([0u8; KeyType::MAX_PUBLIC_KEY_SIZE]);

        let ((private_key, public_key), key_info) = match key_info {
            Err(e) => {
                return Response::Error {
                    client_id,
                    request_id,
                    error: Error::KeyStore(e),
                };
            }
            Ok(key_info) => match key_info.ty {
                KeyType::Asymmetric(Curve::NistP256) => {
                    let (private_key, public_key) =
                        nist_p256_generate_key_pair(self.rng.lock().await.deref_mut());
                    (
                        move_key_pair(
                            private_key,
                            public_key,
                            private_key_bytes.as_mut_slice(),
                            public_key_bytes.as_mut_slice(),
                        ),
                        key_info,
                    )
                }
                KeyType::Asymmetric(Curve::NistP384) => {
                    let (private_key, public_key) =
                        nist_p384_generate_key_pair(self.rng.lock().await.deref_mut());
                    (
                        move_key_pair(
                            private_key,
                            public_key,
                            private_key_bytes.as_mut_slice(),
                            public_key_bytes.as_mut_slice(),
                        ),
                        key_info,
                    )
                }
                _ => {
                    return Response::Error {
                        client_id,
                        request_id,
                        error: Error::KeyStore(keystore::Error::InvalidKeyType),
                    };
                }
            },
        };

        // Check overwrite permission
        if keystore::KeyStore::is_key_available(*locked_key_store, key_id)
            && (!overwrite || !key_info.permissions.overwrite)
        {
            return Response::Error {
                client_id,
                request_id,
                error: Error::KeyStore(keystore::Error::NotAllowed),
            };
        }

        match locked_key_store.import_key_pair_insecure(key_info.id, public_key, private_key) {
            Ok(()) => Response::GenerateKeyPair {
                client_id,
                request_id,
            },
            Err(e) => Response::Error {
                client_id,
                request_id,
                error: Error::KeyStore(e),
            },
        }
    }

    async fn sign(
        &mut self,
        client_id: ClientId,
        request_id: RequestId,
        key_id: KeyId,
        message: &[u8],
        prehashed: bool,
        signature: &'data mut [u8],
    ) -> Response<'data> {
        let mut key_buffer = Zeroizing::new([0u8; KeyType::MAX_PRIVATE_KEY_SIZE]);
        let private_key_and_info = self
            .export_private_key_and_key_info(key_id, key_buffer.as_mut_slice())
            .await;

        let result = match private_key_and_info {
            Err(e) => {
                return Response::Error {
                    client_id,
                    request_id,
                    error: Error::KeyStore(e),
                };
            }
            Ok((private_key, key_info)) => match key_info.ty {
                KeyType::Asymmetric(Curve::NistP256) => {
                    if prehashed {
                        nist_p256_sign_prehashed(private_key, message, signature)
                    } else {
                        nist_p256_sign(private_key, message, signature)
                    }
                }
                KeyType::Asymmetric(Curve::NistP384) => {
                    if prehashed {
                        nist_p384_sign_prehashed(private_key, message, signature)
                    } else {
                        nist_p384_sign(private_key, message, signature)
                    }
                }
                _ => {
                    return Response::Error {
                        client_id,
                        request_id,
                        error: Error::KeyStore(keystore::Error::InvalidKeyType),
                    };
                }
            },
        };

        match result {
            Err(e) => Response::Error {
                client_id,
                request_id,
                error: Error::Crypto(e),
            },
            Ok(_) => Response::Sign {
                client_id,
                request_id,
                signature,
            },
        }
    }

    async fn sing_external_key(
        &mut self,
        client_id: ClientId,
        request_id: RequestId,
        private_key: &[u8],
        message: &[u8],
        prehashed: bool,
        signature: &'data mut [u8],
    ) -> Response<'data> {
        let result = match private_key.len() {
            crypto::ecdsa::NIST_P256_PRIVATE_KEY_SIZE => {
                if prehashed {
                    nist_p256_sign_prehashed(private_key, message, signature)
                } else {
                    nist_p256_sign(private_key, message, signature)
                }
            }
            crypto::ecdsa::NIST_P384_PRIVATE_KEY_SIZE => {
                if prehashed {
                    nist_p384_sign_prehashed(private_key, message, signature)
                } else {
                    nist_p384_sign(private_key, message, signature)
                }
            }
            _ => {
                return Response::Error {
                    client_id,
                    request_id,
                    error: Error::Crypto(crypto::Error::InvalidPrivateKey),
                };
            }
        };

        match result {
            Err(e) => Response::Error {
                client_id,
                request_id,
                error: Error::Crypto(e),
            },
            Ok(_) => Response::Sign {
                client_id,
                request_id,
                signature,
            },
        }
    }

    async fn verify(
        &mut self,
        client_id: ClientId,
        request_id: RequestId,
        key_id: KeyId,
        message: &[u8],
        prehashed: bool,
        signature: &[u8],
    ) -> Response<'data> {
        let mut key_buffer = Zeroizing::new([0u8; KeyType::MAX_PUBLIC_KEY_SIZE]);
        let public_key_and_info = self
            .export_public_key_and_key_info(key_id, key_buffer.as_mut_slice())
            .await;

        let result = match public_key_and_info {
            Err(e) => {
                return Response::Error {
                    client_id,
                    request_id,
                    error: Error::KeyStore(e),
                };
            }
            Ok((public_key, key_info)) => match key_info.ty {
                KeyType::Asymmetric(Curve::NistP256) => {
                    if prehashed {
                        nist_p256_verify_prehashed(public_key, message, signature)
                    } else {
                        nist_p256_verify(public_key, message, signature)
                    }
                }
                KeyType::Asymmetric(Curve::NistP384) => {
                    if prehashed {
                        nist_p384_verify_prehashed(public_key, message, signature)
                    } else {
                        nist_p384_verify(public_key, message, signature)
                    }
                }
                _ => {
                    return Response::Error {
                        client_id,
                        request_id,
                        error: Error::KeyStore(keystore::Error::InvalidKeyType),
                    };
                }
            },
        };

        match result {
            Err(crypto::Error::InvalidSignature) => Response::Verify {
                client_id,
                request_id,
                verified: false,
            },
            Err(e) => Response::Error {
                client_id,
                request_id,
                error: Error::Crypto(e),
            },
            Ok(_) => Response::Verify {
                client_id,
                request_id,
                verified: true,
            },
        }
    }

    async fn verify_external_key(
        &mut self,
        client_id: ClientId,
        request_id: RequestId,
        public_key: &[u8],
        message: &[u8],
        prehashed: bool,
        signature: &[u8],
    ) -> Response<'data> {
        let result = match public_key.len() {
            crypto::ecdsa::NIST_P256_PUBLIC_KEY_SIZE => {
                if prehashed {
                    nist_p256_verify_prehashed(public_key, message, signature)
                } else {
                    nist_p256_verify(public_key, message, signature)
                }
            }
            crypto::ecdsa::NIST_P384_PUBLIC_KEY_SIZE => {
                if prehashed {
                    nist_p384_verify_prehashed(public_key, message, signature)
                } else {
                    nist_p384_verify(public_key, message, signature)
                }
            }
            _ => {
                return Response::Error {
                    client_id,
                    request_id,
                    error: Error::Crypto(crypto::Error::InvalidPrivateKey),
                };
            }
        };

        match result {
            Err(crypto::Error::InvalidSignature) => Response::Verify {
                client_id,
                request_id,
                verified: false,
            },
            Err(e) => Response::Error {
                client_id,
                request_id,
                error: Error::Crypto(e),
            },
            Ok(_) => Response::Verify {
                client_id,
                request_id,
                verified: true,
            },
        }
    }

    async fn export_private_key_and_key_info<'a>(
        &mut self,
        key_id: KeyId,
        key_buffer: &'a mut [u8],
    ) -> Result<(&'a [u8], KeyInfo), keystore::Error> {
        // Lock keystore only once
        let locked_key_store = self.key_store.lock().await;

        Ok((
            locked_key_store.export_private_key_insecure(key_id, key_buffer)?,
            keystore::KeyStore::get_key_info(*locked_key_store, key_id)?,
        ))
    }

    async fn export_public_key_and_key_info<'a>(
        &mut self,
        key_id: KeyId,
        key_buffer: &'a mut [u8],
    ) -> Result<(&'a [u8], KeyInfo), keystore::Error> {
        // Lock keystore only once
        let locked_key_store = self.key_store.lock().await;

        Ok((
            locked_key_store.export_public_key(key_id, key_buffer)?,
            keystore::KeyStore::get_key_info(*locked_key_store, key_id)?,
        ))
    }
}

fn move_key_pair<'a, const N: usize, const M: usize>(
    mut private_key: [u8; N],
    mut public_key: [u8; M],
    private_key_bytes: &'a mut [u8],
    public_key_bytes: &'a mut [u8],
) -> (&'a [u8], &'a [u8]) {
    let private_key_result = &mut private_key_bytes[..private_key.len()];
    private_key_result.copy_from_slice(&private_key);
    let public_key_result = &mut public_key_bytes[..public_key.len()];
    public_key_result.copy_from_slice(&public_key);

    private_key.zeroize();
    public_key.zeroize();

    (private_key_result, public_key_result)
}
