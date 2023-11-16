use crate::common::jobs::{ClientId, Request, RequestId, Response};
use crate::hsm::keystore::KeyId;
use futures::{Sink, SinkExt, Stream, StreamExt};

/// An interface to send [Request]s to the HSM core and receive [Response]es from it.
pub struct Api<'data, Req: Sink<Request<'data>>, Resp: Stream<Item = Response<'data>>> {
    requests: Req,
    responses: Resp,
    request_id_counter: RequestId,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    Send,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SymmetricEncryptionAlgorithm {
    ChaCha20Poly1305,
}

impl<
        'data,
        ReqSink: Sink<Request<'data>> + core::marker::Unpin,
        RespSrc: Stream<Item = Response<'data>> + core::marker::Unpin,
    > Api<'data, ReqSink, RespSrc>
{
    /// Create a new instance of the HSM API.
    pub fn new(requests: ReqSink, responses: RespSrc) -> Self {
        Api {
            requests,
            responses,
            request_id_counter: RequestId::default(),
        }
    }

    /// Attempt to poll a response and return it.
    pub async fn recv_response<'api>(&'api mut self) -> Option<Response<'data>> {
        self.responses.next().await
    }

    /// Request random bytes and write to provided buffer.
    pub async fn get_random(&mut self, output: &'data mut [u8]) -> Result<RequestId, Error> {
        let request = Request::GetRandom {
            client_id: ClientId::default(),
            request_id: RequestId::default(),
            output,
        };
        self.send_request(request).await
    }

    pub async fn generate_symmetric_key(&mut self, key_id: KeyId) -> Result<RequestId, Error> {
        let request = Request::GenerateSymmetricKey {
            client_id: ClientId::default(),
            request_id: RequestId::default(),
            key_id,
        };
        self.send_request(request).await
    }

    pub async fn generate_key_pair(&mut self, key_id: KeyId) -> Result<RequestId, Error> {
        let request = Request::GenerateKeyPair {
            client_id: ClientId::default(),
            request_id: RequestId::default(),
            key_id,
        };
        self.send_request(request).await
    }

    pub async fn import_symmetric_key(
        &mut self,
        key_id: KeyId,
        data: &'data [u8],
    ) -> Result<RequestId, Error> {
        let request = Request::ImportSymmetricKey {
            client_id: ClientId::default(),
            request_id: RequestId::default(),
            key_id,
            data,
        };
        self.send_request(request).await
    }

    pub async fn import_key_pair(
        &mut self,
        key_id: KeyId,
        public_key: &'data [u8],
        private_key: &'data [u8],
    ) -> Result<RequestId, Error> {
        let request = Request::ImportKeyPair {
            client_id: ClientId::default(),
            request_id: RequestId::default(),
            key_id,
            public_key,
            private_key,
        };
        self.send_request(request).await
    }

    pub async fn encrypt(
        &mut self,
        algorithm: SymmetricEncryptionAlgorithm,
        key_id: KeyId,
        nonce: &'data [u8],
        plaintext: &'data mut [u8],
        aad: &'data [u8],
        tag: &'data mut [u8],
    ) -> Result<RequestId, Error> {
        match algorithm {
            SymmetricEncryptionAlgorithm::ChaCha20Poly1305 => {
                let request = Request::EncryptChaChaPoly {
                    client_id: ClientId::default(),
                    request_id: RequestId::default(),
                    key_id,
                    nonce,
                    plaintext,
                    aad,
                    tag,
                };
                self.send_request(request).await
            }
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
    ) -> Result<RequestId, Error> {
        match algorithm {
            SymmetricEncryptionAlgorithm::ChaCha20Poly1305 => {
                let request = Request::EncryptChaChaPolyExternalKey {
                    client_id: ClientId::default(),
                    request_id: RequestId::default(),
                    key,
                    nonce,
                    plaintext,
                    aad,
                    tag,
                };
                self.send_request(request).await
            }
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
    ) -> Result<RequestId, Error> {
        match algorithm {
            SymmetricEncryptionAlgorithm::ChaCha20Poly1305 => {
                let request = Request::DecryptChaChaPoly {
                    client_id: ClientId::default(),
                    request_id: RequestId::default(),
                    key_id,
                    nonce,
                    ciphertext,
                    aad,
                    tag,
                };
                self.send_request(request).await
            }
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
    ) -> Result<RequestId, Error> {
        match algorithm {
            SymmetricEncryptionAlgorithm::ChaCha20Poly1305 => {
                let request = Request::DecryptChaChaPolyExternalKey {
                    client_id: ClientId::default(),
                    request_id: RequestId::default(),
                    key,
                    nonce,
                    ciphertext,
                    aad,
                    tag,
                };
                self.send_request(request).await
            }
        }
    }

    async fn send_request(
        &mut self,
        mut request_without_id: Request<'data>,
    ) -> Result<RequestId, Error> {
        let request_id = self.next_request_id();
        request_without_id.set_request_id(request_id);
        self.requests
            .send(request_without_id)
            .await
            .map_err(|_e| Error::Send)?;
        Ok(request_id)
    }

    /// Increments the requiest ID counter and returns the old value.
    fn next_request_id(&mut self) -> RequestId {
        let id = self.request_id_counter;
        self.request_id_counter.increment();
        id
    }
}
