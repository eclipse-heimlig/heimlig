use crate::common::jobs::{ClientId, Error, Request, RequestId, Response};
use crate::common::limits::MAX_RANDOM_SIZE;
use crate::hsm::keystore;
use crate::hsm::keystore::{KeyId, KeyStore};
use core::ops::Deref;
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::mutex::Mutex;
use futures::{Sink, SinkExt, Stream, StreamExt};
use rand_chacha::rand_core::{CryptoRng, RngCore};

pub struct RngWorker<
    'data,
    'rng,
    'keystore,
    M: RawMutex,
    R: CryptoRng + RngCore,
    ReqSrc: Stream<Item = Request<'data>>,
    RespSink: Sink<Response<'data>>,
> {
    pub rng: &'rng Mutex<M, R>,
    // TODO: Move sym. key generation to own worker and get rid of key store here?
    pub key_store: &'keystore Mutex<M, &'keystore mut (dyn KeyStore + Send)>,
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
    > RngWorker<'data, 'rng, 'keystore, M, R, ReqSrc, RespSink>
{
    /// Drive the worker to process the next request.
    /// This method is supposed to be called by a system task that owns this worker.
    pub async fn execute(&mut self) -> Result<(), Error> {
        let request = self.requests.next().await.ok_or(Error::StreamTerminated)?;
        let response = match request {
            Request::GetRandom {
                client_id,
                request_id,
                output,
            } => self.get_random(client_id, request_id, output).await,
            Request::GenerateSymmetricKey {
                client_id,
                request_id,
                key_id,
                overwrite,
            } => {
                self.generate_symmetric_key(client_id, request_id, key_id, overwrite)
                    .await
            }
            _ => Err(Error::UnexpectedRequestType)?,
        };
        self.responses
            .send(response)
            .await
            .map_err(|_e| Error::Send)
    }

    async fn get_random(
        &mut self,
        client_id: ClientId,
        request_id: RequestId,
        output: &'data mut [u8],
    ) -> Response<'data> {
        if output.len() >= MAX_RANDOM_SIZE {
            return Response::Error {
                client_id,
                request_id,
                error: Error::RequestTooLarge,
            };
        }
        self.rng.lock().await.fill_bytes(output);
        Response::GetRandom {
            client_id,
            request_id,
            data: output,
        }
    }

    async fn generate_symmetric_key(
        &mut self,
        client_id: ClientId,
        request_id: RequestId,
        key_id: KeyId,
        overwrite: bool,
    ) -> Response<'data> {
        // Own variable needed to break mutex lock immediately
        let key_info = self.key_store.lock().await.deref().get_key_info(key_id);
        match key_info {
            Err(e) => Response::Error {
                client_id,
                request_id,
                error: Error::KeyStore(e),
            },
            Ok(key_info) => {
                let mut key = [0u8; keystore::KeyType::MAX_SYMMETRIC_KEY_SIZE];
                let key = &mut key[0..key_info.ty.key_size()];
                self.rng.lock().await.fill_bytes(key);
                let mut locked_key_store = self.key_store.lock().await;

                // Check overwrite permission
                if locked_key_store.is_key_available(key_id)
                    && (!overwrite || !key_info.permissions.overwrite)
                {
                    return Response::Error {
                        client_id,
                        request_id,
                        error: Error::KeyStore(keystore::Error::NotAllowed),
                    };
                }

                match locked_key_store.import_symmetric_key_unchecked(key_id, key) {
                    Ok(_) => Response::GenerateSymmetricKey {
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
        }
    }
}
