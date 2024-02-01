use crate::{
    common::jobs::{ClientId, Error, HashAlgorithm, Request, RequestId, Response},
    crypto::hmac::{
        hmac_sha2_256_calculate, hmac_sha2_256_verify, hmac_sha2_384_calculate,
        hmac_sha2_384_verify, hmac_sha2_512_calculate, hmac_sha2_512_verify,
        hmac_sha3_256_calculate, hmac_sha3_256_verify, hmac_sha3_384_calculate,
        hmac_sha3_384_verify, hmac_sha3_512_calculate, hmac_sha3_512_verify,
    },
    hsm::keystore::{self, KeyId, KeyInfo, KeyStore, KeyType},
};
use embassy_sync::{blocking_mutex::raw::RawMutex, mutex::Mutex};
use futures::{Sink, SinkExt, Stream, StreamExt};
use zeroize::Zeroizing;

pub struct HmacWorker<
    'data,
    'keystore,
    M: RawMutex,
    ReqSrc: Stream<Item = Request<'data>>,
    RespSink: Sink<Response<'data>>,
> {
    pub key_store: &'keystore Mutex<M, &'keystore mut (dyn KeyStore + Send)>,
    pub requests: ReqSrc,
    pub responses: RespSink,
}

impl<
        'data,
        'rng,
        'keystore,
        M: RawMutex,
        ReqSrc: Stream<Item = Request<'data>> + Unpin,
        RespSink: Sink<Response<'data>> + Unpin,
    > HmacWorker<'data, 'keystore, M, ReqSrc, RespSink>
{
    /// Drive the worker to process the next request.
    /// This method is supposed to be called by a system task that owns this worker.
    pub async fn execute(&mut self) -> Result<(), Error> {
        let request = self.requests.next().await.ok_or(Error::StreamTerminated)?;
        let response = match request {
            Request::CalculateHmac {
                client_id,
                request_id,
                key_id,
                hash_algorithm,
                message,
                tag,
            } => {
                self.calculate_hmac(client_id, request_id, key_id, hash_algorithm, message, tag)
                    .await
            }
            Request::CalculateHmacExternalKey {
                client_id,
                request_id,
                key,
                hash_algorithm,
                message,
                tag,
            } => {
                self.calculate_hmac_external_key(
                    client_id,
                    request_id,
                    key,
                    hash_algorithm,
                    message,
                    tag,
                )
                .await
            }
            Request::VerifyHmac {
                client_id,
                request_id,
                key_id,
                hash_algorithm,
                message,
                tag,
            } => {
                self.verify_hmac(client_id, request_id, key_id, hash_algorithm, message, tag)
                    .await
            }
            Request::VerifyHmacExternalKey {
                client_id,
                request_id,
                key,
                hash_algorithm,
                message,
                tag,
            } => {
                self.verify_hmac_external_key(
                    client_id,
                    request_id,
                    key,
                    hash_algorithm,
                    message,
                    tag,
                )
                .await
            }
            _ => Err(Error::UnexpectedRequestType)?,
        };
        self.responses.send(response).await.map_err(|_| Error::Send)
    }

    async fn calculate_hmac(
        &mut self,
        client_id: ClientId,
        request_id: RequestId,
        key_id: KeyId,
        hash_algorithm: HashAlgorithm,
        message: &[u8],
        tag: &'data mut [u8],
    ) -> Response<'data> {
        let mut key_buffer = Zeroizing::new([0u8; KeyType::MAX_SYMMETRIC_KEY_SIZE]);
        let key_and_info = self
            .export_key_and_key_info(key_id, key_buffer.as_mut_slice())
            .await;
        let result = match key_and_info {
            Err(e) => {
                return Response::Error {
                    client_id,
                    request_id,
                    error: Error::KeyStore(e),
                }
            }
            Ok((key, key_info)) => {
                if !key_info.ty.is_symmetric() {
                    return Response::Error {
                        client_id,
                        request_id,
                        error: Error::KeyStore(keystore::Error::InvalidKeyType),
                    };
                }
                match hash_algorithm {
                    HashAlgorithm::Sha2_256 => hmac_sha2_256_calculate(key, message, tag),
                    HashAlgorithm::Sha2_384 => hmac_sha2_384_calculate(key, message, tag),
                    HashAlgorithm::Sha2_512 => hmac_sha2_512_calculate(key, message, tag),
                    HashAlgorithm::Sha3_256 => hmac_sha3_256_calculate(key, message, tag),
                    HashAlgorithm::Sha3_384 => hmac_sha3_384_calculate(key, message, tag),
                    HashAlgorithm::Sha3_512 => hmac_sha3_512_calculate(key, message, tag),
                }
            }
        };
        match result {
            Err(e) => Response::Error {
                client_id,
                request_id,
                error: Error::Crypto(e),
            },
            Ok(()) => Response::CalculateHmac {
                client_id,
                request_id,
                tag,
            },
        }
    }

    async fn calculate_hmac_external_key(
        &mut self,
        client_id: ClientId,
        request_id: RequestId,
        key: &[u8],
        hash_algorithm: HashAlgorithm,
        message: &[u8],
        tag: &'data mut [u8],
    ) -> Response<'data> {
        let result = match hash_algorithm {
            HashAlgorithm::Sha2_256 => hmac_sha2_256_calculate(key, message, tag),
            HashAlgorithm::Sha2_384 => hmac_sha2_384_calculate(key, message, tag),
            HashAlgorithm::Sha2_512 => hmac_sha2_512_calculate(key, message, tag),
            HashAlgorithm::Sha3_256 => hmac_sha3_256_calculate(key, message, tag),
            HashAlgorithm::Sha3_384 => hmac_sha3_384_calculate(key, message, tag),
            HashAlgorithm::Sha3_512 => hmac_sha3_512_calculate(key, message, tag),
        };
        match result {
            Err(e) => Response::Error {
                client_id,
                request_id,
                error: Error::Crypto(e),
            },
            Ok(()) => Response::CalculateHmac {
                client_id,
                request_id,
                tag,
            },
        }
    }

    async fn verify_hmac(
        &mut self,
        client_id: ClientId,
        request_id: RequestId,
        key_id: KeyId,
        hash_algorithm: HashAlgorithm,
        message: &[u8],
        tag: &[u8],
    ) -> Response<'data> {
        let mut key_buffer = Zeroizing::new([0u8; KeyType::MAX_SYMMETRIC_KEY_SIZE]);
        let key_and_info = self
            .export_key_and_key_info(key_id, key_buffer.as_mut_slice())
            .await;
        let result = match key_and_info {
            Err(e) => {
                return Response::Error {
                    client_id,
                    request_id,
                    error: Error::KeyStore(e),
                }
            }
            Ok((key, key_info)) => {
                if !key_info.ty.is_symmetric() {
                    return Response::Error {
                        client_id,
                        request_id,
                        error: Error::KeyStore(keystore::Error::InvalidKeyType),
                    };
                }
                match hash_algorithm {
                    HashAlgorithm::Sha2_256 => hmac_sha2_256_verify(key, message, tag),
                    HashAlgorithm::Sha2_384 => hmac_sha2_384_verify(key, message, tag),
                    HashAlgorithm::Sha2_512 => hmac_sha2_512_verify(key, message, tag),
                    HashAlgorithm::Sha3_256 => hmac_sha3_256_verify(key, message, tag),
                    HashAlgorithm::Sha3_384 => hmac_sha3_384_verify(key, message, tag),
                    HashAlgorithm::Sha3_512 => hmac_sha3_512_verify(key, message, tag),
                }
            }
        };
        match result {
            Err(e) => Response::Error {
                client_id,
                request_id,
                error: Error::Crypto(e),
            },
            Ok(verified) => Response::VerifyHmac {
                client_id,
                request_id,
                verified,
            },
        }
    }

    async fn verify_hmac_external_key(
        &mut self,
        client_id: ClientId,
        request_id: RequestId,
        key: &[u8],
        hash_algorithm: HashAlgorithm,
        message: &[u8],
        tag: &[u8],
    ) -> Response<'data> {
        let result = match hash_algorithm {
            HashAlgorithm::Sha2_256 => hmac_sha2_256_verify(key, message, tag),
            HashAlgorithm::Sha2_384 => hmac_sha2_384_verify(key, message, tag),
            HashAlgorithm::Sha2_512 => hmac_sha2_512_verify(key, message, tag),
            HashAlgorithm::Sha3_256 => hmac_sha3_256_verify(key, message, tag),
            HashAlgorithm::Sha3_384 => hmac_sha3_384_verify(key, message, tag),
            HashAlgorithm::Sha3_512 => hmac_sha3_512_verify(key, message, tag),
        };
        match result {
            Err(e) => Response::Error {
                client_id,
                request_id,
                error: Error::Crypto(e),
            },
            Ok(verified) => Response::VerifyHmac {
                client_id,
                request_id,
                verified,
            },
        }
    }

    async fn export_key_and_key_info<'a>(
        &mut self,
        key_id: KeyId,
        key_buffer: &'a mut [u8],
    ) -> Result<(&'a [u8], KeyInfo), keystore::Error> {
        // Lock keystore only once
        let locked_key_store = self.key_store.lock().await;
        Ok((
            locked_key_store.export_symmetric_key_insecure(key_id, key_buffer)?,
            locked_key_store.get_key_info(key_id)?,
        ))
    }
}
