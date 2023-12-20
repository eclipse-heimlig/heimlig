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
pub enum SymmetricAlgorithm {
    ChaCha20Poly1305,
    AesGcm,
    AesCbc,
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

    /// Generate an symmetric key pair and store it in the HSM.
    pub async fn generate_symmetric_key(
        &mut self,
        key_id: KeyId,
        overwrite: bool,
    ) -> Result<RequestId, Error> {
        let request = Request::GenerateSymmetricKey {
            client_id: ClientId::default(),
            request_id: RequestId::default(),
            key_id,
            overwrite,
        };
        self.send_request(request).await
    }

    /// Generate an asymmetric key pair and store it in the HSM.
    pub async fn generate_key_pair(
        &mut self,
        key_id: KeyId,
        overwrite: bool,
    ) -> Result<RequestId, Error> {
        let request = Request::GenerateKeyPair {
            client_id: ClientId::default(),
            request_id: RequestId::default(),
            key_id,
            overwrite,
        };
        self.send_request(request).await
    }

    /// Import a symmetric key into the HSM.
    pub async fn import_symmetric_key(
        &mut self,
        key_id: KeyId,
        data: &'data [u8],
        overwrite: bool,
    ) -> Result<RequestId, Error> {
        let request = Request::ImportSymmetricKey {
            client_id: ClientId::default(),
            request_id: RequestId::default(),
            key_id,
            data,
            overwrite,
        };
        self.send_request(request).await
    }

    /// Import an asymmetric key pair into the HSM.
    pub async fn import_key_pair(
        &mut self,
        key_id: KeyId,
        public_key: &'data [u8],
        private_key: &'data [u8],
        overwrite: bool,
    ) -> Result<RequestId, Error> {
        let request = Request::ImportKeyPair {
            client_id: ClientId::default(),
            request_id: RequestId::default(),
            key_id,
            public_key,
            private_key,
            overwrite,
        };
        self.send_request(request).await
    }

    /// Export an symmetric private key that is stored in the HSM.
    pub async fn export_symmetric_key(
        &mut self,
        key_id: KeyId,
        data: &'data mut [u8],
    ) -> Result<RequestId, Error> {
        let request = Request::ExportSymmetricKey {
            client_id: ClientId::default(),
            request_id: RequestId::default(),
            key_id,
            data,
        };
        self.send_request(request).await
    }

    /// Export an asymmetric public key that is stored in the HSM.
    pub async fn export_public_key(
        &mut self,
        key_id: KeyId,
        public_key: &'data mut [u8],
    ) -> Result<RequestId, Error> {
        let request = Request::ExportPublicKey {
            client_id: ClientId::default(),
            request_id: RequestId::default(),
            key_id,
            public_key,
        };
        self.send_request(request).await
    }

    /// Export an asymmetric private key that is stored in the HSM.
    /// This function only works for keys whose permission allow their private half to be exported.   
    pub async fn export_private_key(
        &mut self,
        key_id: KeyId,
        private_key: &'data mut [u8],
    ) -> Result<RequestId, Error> {
        let request = Request::ExportPrivateKey {
            client_id: ClientId::default(),
            request_id: RequestId::default(),
            key_id,
            private_key,
        };
        self.send_request(request).await
    }

    /// Check whether a key for the given `KeyId` is stored in the HSM
    pub async fn is_key_available(&mut self, key_id: KeyId) -> Result<RequestId, Error> {
        let request = Request::IsKeyAvailable {
            client_id: ClientId::default(),
            request_id: RequestId::default(),
            key_id,
        };
        self.send_request(request).await
    }

    /// Symmetrically encrypt a buffer in-place using a key stored in the HSM.
    ///
    /// # Arguments
    ///
    /// * `algorithm`: The `SymmetricEncryptionAlgorithm` to be used
    /// * `key_id`: The key identifier to use
    /// * `nonce`: The 'Number used once' to use
    /// * `plaintext_size`: Used for algorithms that require padding (e.g. AES-CBC) only.
    /// Indicates the size of the actual plaintext located in `buffer` starting from the beginning.
    /// * `buffer`: The buffer containing the plaintext and room for padding (if needed)
    /// * `aad`: 'Additional authenticated data' to be used for tag computation
    /// * `tag`: Buffer for the generated tag
    #[allow(clippy::too_many_arguments)]
    pub async fn encrypt_in_place(
        &mut self,
        algorithm: SymmetricAlgorithm,
        key_id: KeyId,
        nonce: &'data [u8],
        plaintext_size: usize,
        buffer: &'data mut [u8],
        aad: &'data [u8],
        tag: &'data mut [u8],
    ) -> Result<RequestId, Error> {
        let request = match algorithm {
            SymmetricAlgorithm::ChaCha20Poly1305 => Request::EncryptChaChaPoly {
                client_id: ClientId::default(),
                request_id: RequestId::default(),
                key_id,
                nonce,
                buffer,
                aad,
                tag,
            },
            SymmetricAlgorithm::AesGcm => Request::EncryptAesGcm {
                client_id: Default::default(),
                request_id: Default::default(),
                key_id,
                iv: nonce,
                buffer,
                aad,
                tag,
            },
            SymmetricAlgorithm::AesCbc => Request::EncryptAesCbc {
                client_id: Default::default(),
                request_id: Default::default(),
                key_id,
                iv: nonce,
                buffer,
                plaintext_size,
            },
        };
        self.send_request(request).await
    }

    /// Symmetrically encrypt a buffer in-place using a caller-provided key.
    ///
    /// # Arguments
    ///
    /// * `algorithm`: The `SymmetricEncryptionAlgorithm` to be used
    /// * `key`: The key to use
    /// * `nonce`: The 'Number used once' to use
    /// * `plaintext_size`: Used for algorithms that require padding (e.g. AES-CBC) only.
    /// Indicates the size of the actual plaintext located in `buffer` starting from the beginning.
    /// * `buffer`: The buffer containing the plaintext and room for padding (if needed)
    /// * `aad`: 'Additional authenticated data' to be used for tag computation
    /// * `tag`: Buffer for the generated tag
    #[allow(clippy::too_many_arguments)]
    pub async fn encrypt_in_place_external_key(
        &mut self,
        algorithm: SymmetricAlgorithm,
        key: &'data [u8],
        nonce: &'data [u8],
        plaintext_size: usize,
        buffer: &'data mut [u8],
        aad: &'data [u8],
        tag: &'data mut [u8],
    ) -> Result<RequestId, Error> {
        let request = match algorithm {
            SymmetricAlgorithm::ChaCha20Poly1305 => Request::EncryptChaChaPolyExternalKey {
                client_id: ClientId::default(),
                request_id: RequestId::default(),
                key,
                nonce,
                buffer,
                aad,
                tag,
            },
            SymmetricAlgorithm::AesGcm => Request::EncryptAesGcmExternalKey {
                client_id: Default::default(),
                request_id: Default::default(),
                key,
                iv: nonce,
                buffer,
                aad,
                tag,
            },
            SymmetricAlgorithm::AesCbc => Request::EncryptAesCbcExternalKey {
                client_id: Default::default(),
                request_id: Default::default(),
                key,
                iv: nonce,
                buffer,
                plaintext_size,
            },
        };
        self.send_request(request).await
    }

    /// Symmetrically decrypt a buffer in-place using a key stored in the HSM.
    ///
    /// # Arguments
    ///
    /// * `algorithm`: The `SymmetricEncryptionAlgorithm` to be used
    /// * `key_id`: The key identifier to use
    /// * `nonce`: The 'Number used once' to use
    /// * `buffer`: The buffer containing the plaintext and room for padding (if needed)
    /// * `aad`: 'Additional authenticated data' to be used for tag computation
    /// * `tag`: The authentication tag used to authenticate the data
    pub async fn decrypt_in_place(
        &mut self,
        algorithm: SymmetricAlgorithm,
        key_id: KeyId,
        nonce: &'data [u8],
        buffer: &'data mut [u8],
        aad: &'data [u8],
        tag: &'data [u8],
    ) -> Result<RequestId, Error> {
        let request = match algorithm {
            SymmetricAlgorithm::ChaCha20Poly1305 => Request::DecryptChaChaPoly {
                client_id: ClientId::default(),
                request_id: RequestId::default(),
                key_id,
                nonce,
                buffer,
                aad,
                tag,
            },
            SymmetricAlgorithm::AesGcm => Request::DecryptAesGcm {
                client_id: Default::default(),
                request_id: Default::default(),
                key_id,
                iv: nonce,
                buffer,
                aad,
                tag,
            },
            SymmetricAlgorithm::AesCbc => Request::DecryptAesCbc {
                client_id: Default::default(),
                request_id: Default::default(),
                key_id,
                iv: nonce,
                buffer,
            },
        };
        self.send_request(request).await
    }

    /// Symmetrically decrypt a buffer in-place using a caller-provided key.
    ///
    /// # Arguments
    ///
    /// * `algorithm`: The `SymmetricEncryptionAlgorithm` to be used
    /// * `key`: The key to use
    /// * `nonce`: The 'Number used once' to use
    /// * `plaintext_size`: Used for algorithms that require padding (e.g. AES-CBC) only.
    /// Indicates the size of the actual plaintext located in `buffer` starting from the beginning.
    /// * `buffer`: The buffer containing the plaintext and room for padding (if needed)
    /// * `aad`: 'Additional authenticated data' to be used for tag computation
    /// * `tag`: The authentication tag used to authenticate the data
    pub async fn decrypt_in_place_external_key(
        &mut self,
        algorithm: SymmetricAlgorithm,
        key: &'data [u8],
        nonce: &'data [u8],
        buffer: &'data mut [u8],
        aad: &'data [u8],
        tag: &'data [u8],
    ) -> Result<RequestId, Error> {
        let request = match algorithm {
            SymmetricAlgorithm::ChaCha20Poly1305 => Request::DecryptChaChaPolyExternalKey {
                client_id: ClientId::default(),
                request_id: RequestId::default(),
                key,
                nonce,
                buffer,
                aad,
                tag,
            },
            SymmetricAlgorithm::AesGcm => Request::DecryptAesGcmExternalKey {
                client_id: Default::default(),
                request_id: Default::default(),
                key,
                iv: nonce,
                buffer,
                aad,
                tag,
            },
            SymmetricAlgorithm::AesCbc => Request::DecryptAesCbcExternalKey {
                client_id: Default::default(),
                request_id: Default::default(),
                key,
                iv: nonce,
                buffer,
            },
        };
        self.send_request(request).await
    }

    /// Sign a prehashed message using a key stored in the HSM
    pub async fn sign(
        &mut self,
        key_id: KeyId,
        message: &'data [u8],
        prehashed: bool,
        signature: &'data mut [u8],
    ) -> Result<RequestId, Error> {
        let request = Request::Sign {
            client_id: ClientId::default(),
            request_id: RequestId::default(),
            key_id,
            message,
            prehashed,
            signature,
        };
        self.send_request(request).await
    }

    /// Sign a prehashed message using a caller-provided key
    pub async fn sign_external_key(
        &mut self,
        private_key: &'data [u8],
        message: &'data [u8],
        prehashed: bool,
        signature: &'data mut [u8],
    ) -> Result<RequestId, Error> {
        let request = Request::SignExternalKey {
            client_id: ClientId::default(),
            request_id: RequestId::default(),
            private_key,
            message,
            prehashed,
            signature,
        };
        self.send_request(request).await
    }

    /// Verify a prehashed message using a key stored in the HSM
    pub async fn verify(
        &mut self,
        key_id: KeyId,
        message: &'data [u8],
        prehashed: bool,
        signature: &'data [u8],
    ) -> Result<RequestId, Error> {
        let request = Request::Verify {
            client_id: ClientId::default(),
            request_id: RequestId::default(),
            key_id,
            message,
            prehashed,
            signature,
        };
        self.send_request(request).await
    }

    /// Verify a prehashed message using a caller-provided key
    pub async fn verify_external_key(
        &mut self,
        public_key: &'data [u8],
        message: &'data [u8],
        prehashed: bool,
        signature: &'data [u8],
    ) -> Result<RequestId, Error> {
        let request = Request::VerifyExternalKey {
            client_id: ClientId::default(),
            request_id: RequestId::default(),
            public_key,
            message,
            prehashed,
            signature,
        };
        self.send_request(request).await
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
