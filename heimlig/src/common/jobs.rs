use crate::hsm::keystore;
use crate::hsm::keystore::KeyId;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// No worker found for received request type.
    NoWorkerForRequest,
    /// A worker encountered a request type that it cannot handle.  
    UnexpectedRequestType,
    /// The amount of requested data was too large.
    RequestTooLarge,
    /// No key store present.
    NoKeyStore,
    /// Failed to send through channel.
    Send,
    /// A cryptographic error occurred.
    Crypto(crate::crypto::Error),
    /// A key store error occurred.
    KeyStore(keystore::Error),
}

/// Used to distinguish multiple clients
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ClientId(pub u32);

impl From<u32> for ClientId {
    fn from(value: u32) -> Self {
        ClientId(value)
    }
}

impl From<ClientId> for u32 {
    fn from(value: ClientId) -> Self {
        value.0
    }
}

impl ClientId {
    pub fn idx(&self) -> usize {
        self.0 as usize
    }
}

/// Used to match requests and responses
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RequestId(pub u32);

impl From<u32> for RequestId {
    fn from(value: u32) -> Self {
        RequestId(value)
    }
}

impl From<RequestId> for u32 {
    fn from(value: RequestId) -> Self {
        value.as_u32()
    }
}

impl RequestId {
    pub fn increment(&mut self) {
        self.0 = self.0.wrapping_add(1);
    }
}

impl RequestId {
    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RequestType {
    GetRandom,
    GenerateSymmetricKey,
    GenerateKeyPair,
    ImportSymmetricKey,
    ImportKeyPair,
    ExportSymmetricKey,
    ExportPublicKey,
    ExportPrivateKey,
    IsKeyAvailable,
    EncryptChaChaPoly,
    EncryptChaChaPolyExternalKey,
    DecryptChaChaPoly,
    DecryptChaChaPolyExternalKey,
    Sign,
    SignExternalKey,
    Verify,
    VerifyExternalKey,
    EncryptAesCbc,
    EncryptAesCbcExternalKey,
    DecryptAesCbc,
    DecryptAesCbcExternalKey,
}

/// A request for the HSM to perform a cryptographic task.
#[derive(Debug)]
pub enum Request<'data> {
    GetRandom {
        client_id: ClientId,
        request_id: RequestId,
        output: &'data mut [u8],
    },
    GenerateSymmetricKey {
        client_id: ClientId,
        request_id: RequestId,
        key_id: KeyId,
        overwrite: bool,
    },
    GenerateKeyPair {
        client_id: ClientId,
        request_id: RequestId,
        key_id: KeyId,
        overwrite: bool,
    },
    ImportSymmetricKey {
        client_id: ClientId,
        request_id: RequestId,
        key_id: KeyId,
        data: &'data [u8],
        overwrite: bool,
    },
    ImportKeyPair {
        client_id: ClientId,
        request_id: RequestId,
        key_id: KeyId,
        public_key: &'data [u8],
        private_key: &'data [u8],
        overwrite: bool,
    },
    ExportSymmetricKey {
        client_id: ClientId,
        request_id: RequestId,
        key_id: KeyId,
        data: &'data mut [u8],
    },
    ExportPublicKey {
        client_id: ClientId,
        request_id: RequestId,
        key_id: KeyId,
        public_key: &'data mut [u8],
    },
    ExportPrivateKey {
        client_id: ClientId,
        request_id: RequestId,
        key_id: KeyId,
        private_key: &'data mut [u8],
    },
    IsKeyAvailable {
        client_id: ClientId,
        request_id: RequestId,
        key_id: KeyId,
    },
    EncryptChaChaPoly {
        client_id: ClientId,
        request_id: RequestId,
        key_id: KeyId,
        nonce: &'data [u8],
        buffer: &'data mut [u8],
        aad: &'data [u8],
        tag: &'data mut [u8],
    },
    EncryptChaChaPolyExternalKey {
        client_id: ClientId,
        request_id: RequestId,
        key: &'data [u8],
        nonce: &'data [u8],
        buffer: &'data mut [u8],
        aad: &'data [u8],
        tag: &'data mut [u8],
    },
    DecryptChaChaPoly {
        client_id: ClientId,
        request_id: RequestId,
        key_id: KeyId,
        nonce: &'data [u8],
        buffer: &'data mut [u8],
        aad: &'data [u8],
        tag: &'data [u8],
    },
    DecryptChaChaPolyExternalKey {
        client_id: ClientId,
        request_id: RequestId,
        key: &'data [u8],
        nonce: &'data [u8],
        buffer: &'data mut [u8],
        aad: &'data [u8],
        tag: &'data [u8],
    },
    EncryptAesCbc {
        client_id: ClientId,
        request_id: RequestId,
        key_id: KeyId,
        nonce: &'data [u8],
        buffer: &'data mut [u8],
        aad: &'data [u8],
        tag: &'data mut [u8],
    },
    EncryptAesCbcExternalKey {
        client_id: ClientId,
        request_id: RequestId,
        key: &'data [u8],
        nonce: &'data [u8],
        buffer: &'data mut [u8],
        aad: &'data [u8],
        tag: &'data mut [u8],
    },
    DecryptAesCbc {
        client_id: ClientId,
        request_id: RequestId,
        key_id: KeyId,
        nonce: &'data [u8],
        buffer: &'data mut [u8],
        aad: &'data [u8],
        tag: &'data [u8],
    },
    DecryptAesCbcExternalKey {
        client_id: ClientId,
        request_id: RequestId,
        key: &'data [u8],
        nonce: &'data [u8],
        buffer: &'data mut [u8],
        aad: &'data [u8],
        tag: &'data [u8],
    },
    Sign {
        client_id: ClientId,
        request_id: RequestId,
        key_id: KeyId,
        message: &'data [u8],
        prehashed: bool,
        signature: &'data mut [u8],
    },
    SignExternalKey {
        client_id: ClientId,
        request_id: RequestId,
        private_key: &'data [u8],
        message: &'data [u8],
        prehashed: bool,
        signature: &'data mut [u8],
    },
    Verify {
        client_id: ClientId,
        request_id: RequestId,
        key_id: KeyId,
        message: &'data [u8],
        prehashed: bool,
        signature: &'data [u8],
    },
    VerifyExternalKey {
        client_id: ClientId,
        request_id: RequestId,
        public_key: &'data [u8],
        message: &'data [u8],
        prehashed: bool,
        signature: &'data [u8],
    },
}

impl RequestType {
    /// A request that does not require processing by a worker.
    /// Key management (import/export) operations are an example of this type of request.
    pub fn is_handled_by_core(&self) -> bool {
        matches!(
            self,
            RequestType::ImportSymmetricKey
                | RequestType::ImportKeyPair
                | RequestType::ExportSymmetricKey
                | RequestType::ExportPublicKey
                | RequestType::ExportPrivateKey
                | RequestType::IsKeyAvailable
        )
    }

    /// A request that requires processing by a worker.
    pub fn is_handled_by_worker(&self) -> bool {
        !self.is_handled_by_core()
    }
}

/// A response from the HSM containing the results of a cryptographic task.
#[derive(Debug)]
pub enum Response<'data> {
    Error {
        client_id: ClientId,
        request_id: RequestId,
        error: Error,
    },
    GetRandom {
        client_id: ClientId,
        request_id: RequestId,
        data: &'data mut [u8],
    },
    GenerateSymmetricKey {
        client_id: ClientId,
        request_id: RequestId,
    },
    GenerateKeyPair {
        client_id: ClientId,
        request_id: RequestId,
    },
    ImportSymmetricKey {
        client_id: ClientId,
        request_id: RequestId,
    },
    ImportKeyPair {
        client_id: ClientId,
        request_id: RequestId,
    },
    ExportSymmetricKey {
        client_id: ClientId,
        request_id: RequestId,
        key: &'data [u8],
    },
    ExportPublicKey {
        client_id: ClientId,
        request_id: RequestId,
        public_key: &'data [u8],
    },
    ExportPrivateKey {
        client_id: ClientId,
        request_id: RequestId,
        private_key: &'data [u8],
    },
    IsKeyAvailable {
        client_id: ClientId,
        request_id: RequestId,
        is_available: bool,
    },
    EncryptChaChaPoly {
        client_id: ClientId,
        request_id: RequestId,
        buffer: &'data mut [u8],
        tag: &'data mut [u8],
    },
    DecryptChaChaPoly {
        client_id: ClientId,
        request_id: RequestId,
        buffer: &'data mut [u8],
    },
    EncryptAesCbc {
        client_id: ClientId,
        request_id: RequestId,
        buffer: &'data mut [u8],
        tag: &'data mut [u8],
    },
    DecryptAesCbc {
        client_id: ClientId,
        request_id: RequestId,
        buffer: &'data mut [u8],
    },
    Sign {
        client_id: ClientId,
        request_id: RequestId,
        signature: &'data mut [u8],
    },
    Verify {
        client_id: ClientId,
        request_id: RequestId,
        verified: bool,
    },
}

impl<'data> Request<'data> {
    pub fn get_type(&self) -> RequestType {
        match self {
            Request::GetRandom { .. } => RequestType::GetRandom,
            Request::GenerateSymmetricKey { .. } => RequestType::GenerateSymmetricKey,
            Request::GenerateKeyPair { .. } => RequestType::GenerateKeyPair,
            Request::ImportSymmetricKey { .. } => RequestType::ImportSymmetricKey,
            Request::ImportKeyPair { .. } => RequestType::ImportKeyPair,
            Request::ExportSymmetricKey { .. } => RequestType::ExportSymmetricKey,
            Request::ExportPublicKey { .. } => RequestType::ExportPublicKey,
            Request::ExportPrivateKey { .. } => RequestType::ExportPrivateKey,
            Request::IsKeyAvailable { .. } => RequestType::IsKeyAvailable,
            Request::EncryptChaChaPoly { .. } => RequestType::EncryptChaChaPoly,
            Request::EncryptChaChaPolyExternalKey { .. } => {
                RequestType::EncryptChaChaPolyExternalKey
            }
            Request::DecryptChaChaPoly { .. } => RequestType::DecryptChaChaPoly,
            Request::DecryptChaChaPolyExternalKey { .. } => {
                RequestType::DecryptChaChaPolyExternalKey
            }
            Request::EncryptAesCbc { .. } => RequestType::EncryptAesCbc,
            Request::EncryptAesCbcExternalKey { .. } => RequestType::EncryptAesCbcExternalKey,
            Request::DecryptAesCbc { .. } => RequestType::DecryptAesCbc,
            Request::DecryptAesCbcExternalKey { .. } => RequestType::DecryptAesCbcExternalKey,
            Request::Sign { .. } => RequestType::Sign,
            Request::SignExternalKey { .. } => RequestType::SignExternalKey,
            Request::Verify { .. } => RequestType::Verify,
            Request::VerifyExternalKey { .. } => RequestType::VerifyExternalKey,
        }
    }

    pub fn set_client_id(&mut self, new_client_id: ClientId) {
        match self {
            Request::GetRandom { client_id, .. } => *client_id = new_client_id,
            Request::GenerateSymmetricKey { client_id, .. } => *client_id = new_client_id,
            Request::GenerateKeyPair { client_id, .. } => *client_id = new_client_id,
            Request::ImportSymmetricKey { client_id, .. } => *client_id = new_client_id,
            Request::ImportKeyPair { client_id, .. } => *client_id = new_client_id,
            Request::ExportSymmetricKey { client_id, .. } => *client_id = new_client_id,
            Request::ExportPublicKey { client_id, .. } => *client_id = new_client_id,
            Request::ExportPrivateKey { client_id, .. } => *client_id = new_client_id,
            Request::IsKeyAvailable { client_id, .. } => *client_id = new_client_id,
            Request::EncryptChaChaPoly { client_id, .. } => *client_id = new_client_id,
            Request::EncryptChaChaPolyExternalKey { client_id, .. } => *client_id = new_client_id,
            Request::DecryptChaChaPoly { client_id, .. } => *client_id = new_client_id,
            Request::DecryptChaChaPolyExternalKey { client_id, .. } => *client_id = new_client_id,
            Request::EncryptAesCbc { client_id, .. } => *client_id = new_client_id,
            Request::EncryptAesCbcExternalKey { client_id, .. } => *client_id = new_client_id,
            Request::DecryptAesCbc { client_id, .. } => *client_id = new_client_id,
            Request::DecryptAesCbcExternalKey { client_id, .. } => *client_id = new_client_id,
            Request::Sign { client_id, .. } => *client_id = new_client_id,
            Request::SignExternalKey { client_id, .. } => *client_id = new_client_id,
            Request::Verify { client_id, .. } => *client_id = new_client_id,
            Request::VerifyExternalKey { client_id, .. } => *client_id = new_client_id,
        }
    }

    pub fn set_request_id(&mut self, new_request_id: RequestId) {
        match self {
            Request::GetRandom { request_id, .. } => *request_id = new_request_id,
            Request::GenerateSymmetricKey { request_id, .. } => *request_id = new_request_id,
            Request::GenerateKeyPair { request_id, .. } => *request_id = new_request_id,
            Request::ImportSymmetricKey { request_id, .. } => *request_id = new_request_id,
            Request::ImportKeyPair { request_id, .. } => *request_id = new_request_id,
            Request::ExportSymmetricKey { request_id, .. } => *request_id = new_request_id,
            Request::ExportPublicKey { request_id, .. } => *request_id = new_request_id,
            Request::ExportPrivateKey { request_id, .. } => *request_id = new_request_id,
            Request::IsKeyAvailable { request_id, .. } => *request_id = new_request_id,
            Request::EncryptChaChaPoly { request_id, .. } => *request_id = new_request_id,
            Request::EncryptChaChaPolyExternalKey { request_id, .. } => {
                *request_id = new_request_id
            }
            Request::DecryptChaChaPoly { request_id, .. } => *request_id = new_request_id,
            Request::DecryptChaChaPolyExternalKey { request_id, .. } => {
                *request_id = new_request_id
            }
            Request::EncryptAesCbc { request_id, .. } => *request_id = new_request_id,
            Request::EncryptAesCbcExternalKey { request_id, .. } => *request_id = new_request_id,
            Request::DecryptAesCbc { request_id, .. } => *request_id = new_request_id,
            Request::DecryptAesCbcExternalKey { request_id, .. } => *request_id = new_request_id,
            Request::Sign { request_id, .. } => *request_id = new_request_id,
            Request::SignExternalKey { request_id, .. } => *request_id = new_request_id,
            Request::Verify { request_id, .. } => *request_id = new_request_id,
            Request::VerifyExternalKey { request_id, .. } => *request_id = new_request_id,
        }
    }
}

impl<'data> Response<'data> {
    pub fn get_client_id(&self) -> ClientId {
        *match self {
            Response::Error { client_id, .. } => client_id,
            Response::GetRandom { client_id, .. } => client_id,
            Response::GenerateSymmetricKey { client_id, .. } => client_id,
            Response::GenerateKeyPair { client_id, .. } => client_id,
            Response::ImportSymmetricKey { client_id, .. } => client_id,
            Response::ImportKeyPair { client_id, .. } => client_id,
            Response::ExportSymmetricKey { client_id, .. } => client_id,
            Response::ExportPublicKey { client_id, .. } => client_id,
            Response::ExportPrivateKey { client_id, .. } => client_id,
            Response::IsKeyAvailable { client_id, .. } => client_id,
            Response::EncryptChaChaPoly { client_id, .. } => client_id,
            Response::DecryptChaChaPoly { client_id, .. } => client_id,
            Response::EncryptAesCbc { client_id, .. } => client_id,
            Response::DecryptAesCbc { client_id, .. } => client_id,
            Response::Sign { client_id, .. } => client_id,
            Response::Verify { client_id, .. } => client_id,
        }
    }
}
