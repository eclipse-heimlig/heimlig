use crate::common::jobs::{ClientId, Error, Request, RequestId, Response};
use crate::crypto;
use crate::crypto::ecc::generate_key_pair;
use crate::crypto::rng::{EntropySource, Rng};
use crate::hsm::keystore;
use crate::hsm::keystore::{KeyId, KeyInfo, KeyStore, KeyType};
use core::ops::{Deref, DerefMut};
use elliptic_curve::sec1::{self, FromEncodedPoint, ModulusSize, ToEncodedPoint};
use elliptic_curve::{AffinePoint, CurveArithmetic, FieldBytesSize};
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::mutex::Mutex;
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
                    } => self.generate_key_pair(client_id, request_id, key_id).await,
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
                let key_exists = self.key_store.lock().await.deref().is_stored(key_id);
                if key_exists && !key_info.permissions.overwrite {
                    return Response::Error {
                        client_id,
                        request_id,
                        error: Error::KeyStore(keystore::Error::NotAllowed),
                    };
                }
                if !key_info.ty.is_asymmetric() {
                    return Response::Error {
                        client_id,
                        request_id,
                        error: Error::KeyStore(keystore::Error::InvalidKeyType),
                    };
                }
                match key_info.ty {
                    KeyType::EccKeypairNistP256 => {
                        self.generate_key_pair_internal::<NistP256>(client_id, request_id, key_info)
                            .await
                    }
                    KeyType::EccKeypairNistP384 => {
                        self.generate_key_pair_internal::<NistP384>(client_id, request_id, key_info)
                            .await
                    }
                    _ => Response::Error {
                        client_id,
                        request_id,
                        error: Error::KeyStore(keystore::Error::InvalidKeyType),
                    },
                }
            }
        }
    }

    async fn generate_key_pair_internal<C>(
        &mut self,
        client_id: ClientId,
        request_id: RequestId,
        key_info: KeyInfo,
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
        let public_key_coordinates = public_key_encoded.coordinates();
        match public_key_coordinates {
            sec1::Coordinates::Uncompressed { x, y } => {
                // TODO: Check if SEC1 encoded keys might be shorter than asserted here
                assert_eq!(x.len(), y.len());
                assert!(public_key_bytes.len() >= x.len() + y.len());
                public_key_bytes[..x.len()].copy_from_slice(x.as_slice());
                public_key_bytes[x.len()..x.len() + y.len()].copy_from_slice(y.as_slice());
            }
            _ => {
                return Response::Error {
                    client_id,
                    request_id,
                    error: Error::Crypto(crypto::Error::InvalidPublicKey),
                };
            }
        };

        // Write private key
        let private_key_bytes = private_key.to_bytes();
        assert_eq!(
            private_key_bytes.len(),
            KeyType::EccKeypairNistP256.private_key_size()
        );

        // Import key pair into key store
        match self.key_store.lock().await.import_key_pair(
            key_info.id,
            public_key_bytes,
            private_key_bytes.as_slice(),
        ) {
            Ok(_) => Response::GenerateKeyPair {
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
