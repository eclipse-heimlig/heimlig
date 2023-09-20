use crate::common::jobs::{Request, Response};
use crate::hsm::keystore::KeyId;
use futures::{Sink, SinkExt, Stream, StreamExt};

/// An interface to send [Request]s to the HSM core and receive [Response]es from it.
pub struct Api<'data, Req: Sink<Request<'data>>, Resp: Stream<Item = Response<'data>>> {
    requests: Req,
    responses: Resp,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Error {
    Send,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum SymmetricEncryptionAlgorithm {
    ChaCha20Poly1305,
}

impl<
        'data,
        Req: Sink<Request<'data>> + core::marker::Unpin,
        Resp: Stream<Item = Response<'data>> + core::marker::Unpin,
    > Api<'data, Req, Resp>
{
    /// Create a new instance of the HSM API.
    pub fn new(requests: Req, responses: Resp) -> Self {
        Api {
            requests,
            responses,
        }
    }

    /// Attempt to poll a response and return it.
    pub async fn recv_response<'api>(&'api mut self) -> Option<Response<'data>> {
        self.responses.next().await
    }

    /// Request random bytes and write to provided buffer.
    pub async fn get_random(&mut self, output: &'data mut [u8]) -> Result<(), Error> {
        self.requests
            .send(Request::GetRandom { output })
            .await
            .map_err(|_e| Error::Send)
    }

    pub async fn import_key(&mut self, key_id: KeyId, data: &'data [u8]) -> Result<(), Error> {
        self.requests
            .send(Request::ImportKey { key_id, data })
            .await
            .map_err(|_e| Error::Send)
    }

    pub async fn encrypt(
        &mut self,
        algorithm: SymmetricEncryptionAlgorithm,
        key_id: KeyId,
        nonce: &'data [u8],
        plaintext: &'data mut [u8],
        aad: &'data [u8],
        tag: &'data mut [u8],
    ) -> Result<(), Error> {
        match algorithm {
            SymmetricEncryptionAlgorithm::ChaCha20Poly1305 => self
                .requests
                .send(Request::EncryptChaChaPoly {
                    key_id,
                    nonce,
                    plaintext,
                    aad,
                    tag,
                })
                .await
                .map_err(|_e| Error::Send),
        }
    }

    pub async fn encrypt_external_key(
        &mut self,
        algorithm: SymmetricEncryptionAlgorithm,
        key: &'data [u8],
        nonce: &'data [u8],
        plaintext: &'data mut [u8],
        aad: &'data [u8],
        tag: &'data mut [u8],
    ) -> Result<(), Error> {
        match algorithm {
            SymmetricEncryptionAlgorithm::ChaCha20Poly1305 => self
                .requests
                .send(Request::EncryptChaChaPolyExternalKey {
                    key,
                    nonce,
                    plaintext,
                    aad,
                    tag,
                })
                .await
                .map_err(|_e| Error::Send),
        }
    }

    pub async fn decrypt(
        &mut self,
        algorithm: SymmetricEncryptionAlgorithm,
        key_id: KeyId,
        nonce: &'data [u8],
        ciphertext: &'data mut [u8],
        aad: &'data [u8],
        tag: &'data [u8],
    ) -> Result<(), Error> {
        match algorithm {
            SymmetricEncryptionAlgorithm::ChaCha20Poly1305 => self
                .requests
                .send(Request::DecryptChaChaPoly {
                    key_id,
                    nonce,
                    ciphertext,
                    aad,
                    tag,
                })
                .await
                .map_err(|_e| Error::Send),
        }
    }

    pub async fn decrypt_external_key(
        &mut self,
        algorithm: SymmetricEncryptionAlgorithm,
        key: &'data [u8],
        nonce: &'data [u8],
        ciphertext: &'data mut [u8],
        aad: &'data [u8],
        tag: &'data [u8],
    ) -> Result<(), Error> {
        match algorithm {
            SymmetricEncryptionAlgorithm::ChaCha20Poly1305 => self
                .requests
                .send(Request::DecryptChaChaPolyExternalKey {
                    key,
                    nonce,
                    ciphertext,
                    aad,
                    tag,
                })
                .await
                .map_err(|_e| Error::Send),
        }
    }
}
