use crate::common::jobs::{ClientId, Error, Request, RequestId, Response};
use crate::crypto::ecc::generate_key_pair;
use crate::crypto::rng::{EntropySource, Rng};
use crate::hsm::keystore;
use crate::hsm::keystore::{KeyId, KeyInfo, KeyStore, KeyType};
use core::ops::{Deref, DerefMut};
use elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use elliptic_curve::{AffinePoint, CurveArithmetic, FieldBytesSize};
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::mutex::{Mutex, MutexGuard};
use futures::{Sink, SinkExt, Stream, StreamExt};
use p256::NistP256;
use p384::NistP384;

pub struct EccWorker<
    'data,
    'rng,
    'keystore,
    M: RawMutex,
    E: EntropySource,
    ReqSrc: Stream<Item = Request<'data>>,
    RespSink: Sink<Response<'data>>,
> {
    pub rng: &'rng Mutex<M, Rng<E>>,
    pub key_store: &'keystore Mutex<M, &'keystore mut (dyn KeyStore + Send)>,
    pub requests: ReqSrc,
    pub responses: RespSink,
}

impl<
        'data,
        'rng,
        'keystore,
        M: RawMutex,
        E: EntropySource,
        ReqSrc: Stream<Item = Request<'data>> + Unpin,
        RespSink: Sink<Response<'data>> + Unpin,
    > EccWorker<'data, 'rng, 'keystore, M, E, ReqSrc, RespSink>
{
    /// Drive the worker to process the next request.
    /// This method is supposed to be called by a system task that owns this worker.
    pub async fn execute(&mut self) -> Result<(), Error> {
        match self.requests.next().await {
            None => Ok(()), // Nothing to process
            Some(request) => {
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
                    _ => Err(Error::UnexpectedRequestType)?,
                };
                self.responses
                    .send(response)
                    .await
                    .map_err(|_e| Error::Send)
            }
        }
    }

    async fn generate_key_pair(
        &mut self,
        client_id: ClientId,
        request_id: RequestId,
        key_id: KeyId,
        overwrite: bool,
    ) -> Response<'data> {
        let locked_key_store = self.key_store.lock().await;
        let key_info = locked_key_store.deref().get_key_info(key_id);
        match key_info {
            Err(e) => Response::Error {
                client_id,
                request_id,
                error: Error::KeyStore(e),
            },
            Ok(key_info) => match key_info.ty {
                KeyType::EccKeypairNistP256 => {
                    self.generate_key_pair_internal::<NistP256>(
                        locked_key_store,
                        client_id,
                        request_id,
                        key_info,
                        overwrite,
                    )
                    .await
                }
                KeyType::EccKeypairNistP384 => {
                    self.generate_key_pair_internal::<NistP384>(
                        locked_key_store,
                        client_id,
                        request_id,
                        key_info,
                        overwrite,
                    )
                    .await
                }
                _ => Response::Error {
                    client_id,
                    request_id,
                    error: Error::KeyStore(keystore::Error::InvalidKeyType),
                },
            },
        }
    }

    async fn generate_key_pair_internal<C>(
        &mut self,
        mut locked_key_store: MutexGuard<'_, M, &mut (dyn KeyStore + Send)>,
        client_id: ClientId,
        request_id: RequestId,
        key_info: KeyInfo,
        overwrite: bool,
    ) -> Response<'data>
    where
        C: CurveArithmetic,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        FieldBytesSize<C>: ModulusSize,
    {
        let (public_key, private_key) =
            generate_key_pair::<_, C>(self.rng.lock().await.deref_mut());

        // Write public key
        let mut public_key_bytes = [0u8; KeyType::MAX_PUBLIC_KEY_SIZE];
        let public_key_bytes = &mut public_key_bytes[..key_info.ty.public_key_size()];
        let public_key_encoded = &public_key.to_encoded_point(false);
        assert!(
            !public_key_encoded.is_compressed()
                && !public_key_encoded.is_compact()
                && !public_key_encoded.is_identity(),
            "expected uncompressed public key point"
        );
        let sec1_bytes = public_key_encoded.as_bytes();
        assert_eq!(sec1_bytes.len(), 1 + key_info.ty.public_key_size()); // Includes 0x04 prefix
        public_key_bytes.copy_from_slice(&sec1_bytes[1..]); // Skip prefix

        // Write private key
        let private_key_bytes = private_key.to_bytes();
        assert_eq!(private_key_bytes.len(), key_info.ty.private_key_size());

        // Import key pair into key store
        match locked_key_store.import_key_pair(
            key_info.id,
            public_key_bytes,
            private_key_bytes.as_slice(),
            overwrite,
        ) {
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
}
