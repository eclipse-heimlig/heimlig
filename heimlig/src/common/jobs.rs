use crate::hsm::keystore;
use crate::hsm::keystore::{KeyId, KeyType};

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
    /// Futures Stream was terminated
    StreamTerminated,
    /// A cryptographic error occurred.
    Crypto(crate::crypto::Error),
    /// A key store error occurred.
    KeyStore(keystore::Error),
}

impl From<keystore::Error> for Error {
    fn from(value: keystore::Error) -> Self {
        Self::KeyStore(value)
    }
}

impl From<crate::crypto::Error> for Error {
    fn from(value: crate::crypto::Error) -> Self {
        Self::Crypto(value)
    }
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
pub enum HashAlgorithm {
    Sha2_256,
    Sha2_384,
    Sha2_512,
    Sha3_256,
    Sha3_384,
    Sha3_512,
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
    EncryptAesGcm,
    EncryptAesGcmExternalKey,
    DecryptAesGcm,
    DecryptAesGcmExternalKey,
    EncryptAesCbc,
    EncryptAesCbcExternalKey,
    DecryptAesCbc,
    DecryptAesCbcExternalKey,
    CalculateAesCmac,
    CalculateAesCmacExternalKey,
    VerifyAesCmac,
    VerifyAesCmacExternalKey,
    CalculateHmac,
    CalculateHmacExternalKey,
    VerifyHmac,
    VerifyHmacExternalKey,
    Sign,
    SignExternalKey,
    Verify,
    VerifyExternalKey,
    Ecdh,
    EcdhExternalPrivateKey,
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
    EncryptAesGcm {
        client_id: ClientId,
        request_id: RequestId,
        key_id: KeyId,
        iv: &'data [u8],
        buffer: &'data mut [u8],
        aad: &'data [u8],
        tag: &'data mut [u8],
    },
    EncryptAesGcmExternalKey {
        client_id: ClientId,
        request_id: RequestId,
        key: &'data [u8],
        iv: &'data [u8],
        buffer: &'data mut [u8],
        aad: &'data [u8],
        tag: &'data mut [u8],
    },
    DecryptAesGcm {
        client_id: ClientId,
        request_id: RequestId,
        key_id: KeyId,
        iv: &'data [u8],
        buffer: &'data mut [u8],
        aad: &'data [u8],
        tag: &'data [u8],
    },
    DecryptAesGcmExternalKey {
        client_id: ClientId,
        request_id: RequestId,
        key: &'data [u8],
        iv: &'data [u8],
        buffer: &'data mut [u8],
        aad: &'data [u8],
        tag: &'data [u8],
    },
    EncryptAesCbc {
        client_id: ClientId,
        request_id: RequestId,
        key_id: KeyId,
        iv: &'data [u8],
        buffer: &'data mut [u8],
        plaintext_size: usize,
    },
    EncryptAesCbcExternalKey {
        client_id: ClientId,
        request_id: RequestId,
        key: &'data [u8],
        iv: &'data [u8],
        buffer: &'data mut [u8],
        plaintext_size: usize,
    },
    DecryptAesCbc {
        client_id: ClientId,
        request_id: RequestId,
        key_id: KeyId,
        iv: &'data [u8],
        buffer: &'data mut [u8],
    },
    DecryptAesCbcExternalKey {
        client_id: ClientId,
        request_id: RequestId,
        key: &'data [u8],
        iv: &'data [u8],
        buffer: &'data mut [u8],
    },
    CalculateAesCmac {
        client_id: ClientId,
        request_id: RequestId,
        key_id: KeyId,
        message: &'data [u8],
        tag: &'data mut [u8],
    },
    CalculateAesCmacExternalKey {
        client_id: ClientId,
        request_id: RequestId,
        key: &'data [u8],
        message: &'data [u8],
        tag: &'data mut [u8],
    },
    VerifyAesCmac {
        client_id: ClientId,
        request_id: RequestId,
        key_id: KeyId,
        message: &'data [u8],
        tag: &'data [u8],
    },
    VerifyAesCmacExternalKey {
        client_id: ClientId,
        request_id: RequestId,
        key: &'data [u8],
        message: &'data [u8],
        tag: &'data [u8],
    },
    CalculateHmac {
        client_id: ClientId,
        request_id: RequestId,
        key_id: KeyId,
        hash_algorithm: HashAlgorithm,
        message: &'data [u8],
        tag: &'data mut [u8],
    },
    CalculateHmacExternalKey {
        client_id: ClientId,
        request_id: RequestId,
        key: &'data [u8],
        hash_algorithm: HashAlgorithm,
        message: &'data [u8],
        tag: &'data mut [u8],
    },
    VerifyHmac {
        client_id: ClientId,
        request_id: RequestId,
        key_id: KeyId,
        hash_algorithm: HashAlgorithm,
        message: &'data [u8],
        tag: &'data [u8],
    },
    VerifyHmacExternalKey {
        client_id: ClientId,
        request_id: RequestId,
        key: &'data [u8],
        hash_algorithm: HashAlgorithm,
        message: &'data [u8],
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
    Ecdh {
        client_id: ClientId,
        request_id: RequestId,
        public_key: &'data [u8],
        private_key_id: KeyId,
        shared_secret: &'data mut [u8],
    },
    EcdhExternalPrivateKey {
        client_id: ClientId,
        request_id: RequestId,
        key_type: KeyType,
        public_key: &'data [u8],
        private_key: &'data [u8],
        shared_secret: &'data mut [u8],
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

// All slices are mutable here as the borrow checker should guarantee to the client that it has
// exclusive access to the underlying memory and can safely deallocate it.
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
        key: &'data mut [u8],
    },
    ExportPublicKey {
        client_id: ClientId,
        request_id: RequestId,
        public_key: &'data mut [u8],
    },
    ExportPrivateKey {
        client_id: ClientId,
        request_id: RequestId,
        private_key: &'data mut [u8],
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
    EncryptAesGcm {
        client_id: ClientId,
        request_id: RequestId,
        buffer: &'data mut [u8],
        tag: &'data mut [u8],
    },
    DecryptAesGcm {
        client_id: ClientId,
        request_id: RequestId,
        buffer: &'data mut [u8],
    },
    EncryptAesCbc {
        client_id: ClientId,
        request_id: RequestId,
        buffer: &'data mut [u8],
    },
    DecryptAesCbc {
        client_id: ClientId,
        request_id: RequestId,
        plaintext: &'data mut [u8], // Subslice of original buffer without padding
    },
    CalculateAesCmac {
        client_id: ClientId,
        request_id: RequestId,
        tag: &'data mut [u8],
    },
    VerifyAesCmac {
        client_id: ClientId,
        request_id: RequestId,
        verified: bool,
    },
    CalculateHmac {
        client_id: ClientId,
        request_id: RequestId,
        tag: &'data mut [u8],
    },
    VerifyHmac {
        client_id: ClientId,
        request_id: RequestId,
        verified: bool,
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
    Ecdh {
        client_id: ClientId,
        request_id: RequestId,
        shared_secret: &'data mut [u8],
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
            Request::EncryptAesGcm { .. } => RequestType::EncryptAesGcm,
            Request::EncryptAesGcmExternalKey { .. } => RequestType::EncryptAesGcmExternalKey,
            Request::DecryptAesGcm { .. } => RequestType::DecryptAesGcm,
            Request::DecryptAesGcmExternalKey { .. } => RequestType::DecryptAesGcmExternalKey,
            Request::EncryptAesCbc { .. } => RequestType::EncryptAesCbc,
            Request::EncryptAesCbcExternalKey { .. } => RequestType::EncryptAesCbcExternalKey,
            Request::DecryptAesCbc { .. } => RequestType::DecryptAesCbc,
            Request::DecryptAesCbcExternalKey { .. } => RequestType::DecryptAesCbcExternalKey,
            Request::CalculateAesCmac { .. } => RequestType::CalculateAesCmac,
            Request::CalculateAesCmacExternalKey { .. } => RequestType::CalculateAesCmacExternalKey,
            Request::VerifyAesCmac { .. } => RequestType::VerifyAesCmac,
            Request::VerifyAesCmacExternalKey { .. } => RequestType::VerifyAesCmacExternalKey,
            Request::CalculateHmac { .. } => RequestType::CalculateHmac,
            Request::CalculateHmacExternalKey { .. } => RequestType::CalculateHmacExternalKey,
            Request::VerifyHmac { .. } => RequestType::VerifyHmac,
            Request::VerifyHmacExternalKey { .. } => RequestType::VerifyHmacExternalKey,
            Request::Sign { .. } => RequestType::Sign,
            Request::SignExternalKey { .. } => RequestType::SignExternalKey,
            Request::Verify { .. } => RequestType::Verify,
            Request::VerifyExternalKey { .. } => RequestType::VerifyExternalKey,
            Request::Ecdh { .. } => RequestType::Ecdh,
            Request::EcdhExternalPrivateKey { .. } => RequestType::EcdhExternalPrivateKey,
        }
    }

    pub fn get_client_id(&self) -> ClientId {
        *match self {
            Request::GetRandom { client_id, .. } => client_id,
            Request::GenerateSymmetricKey { client_id, .. } => client_id,
            Request::GenerateKeyPair { client_id, .. } => client_id,
            Request::ImportSymmetricKey { client_id, .. } => client_id,
            Request::ImportKeyPair { client_id, .. } => client_id,
            Request::ExportSymmetricKey { client_id, .. } => client_id,
            Request::ExportPublicKey { client_id, .. } => client_id,
            Request::ExportPrivateKey { client_id, .. } => client_id,
            Request::IsKeyAvailable { client_id, .. } => client_id,
            Request::EncryptChaChaPoly { client_id, .. } => client_id,
            Request::EncryptChaChaPolyExternalKey { client_id, .. } => client_id,
            Request::DecryptChaChaPoly { client_id, .. } => client_id,
            Request::DecryptChaChaPolyExternalKey { client_id, .. } => client_id,
            Request::EncryptAesGcm { client_id, .. } => client_id,
            Request::EncryptAesGcmExternalKey { client_id, .. } => client_id,
            Request::DecryptAesGcm { client_id, .. } => client_id,
            Request::DecryptAesGcmExternalKey { client_id, .. } => client_id,
            Request::EncryptAesCbc { client_id, .. } => client_id,
            Request::EncryptAesCbcExternalKey { client_id, .. } => client_id,
            Request::DecryptAesCbc { client_id, .. } => client_id,
            Request::DecryptAesCbcExternalKey { client_id, .. } => client_id,
            Request::CalculateAesCmac { client_id, .. } => client_id,
            Request::CalculateAesCmacExternalKey { client_id, .. } => client_id,
            Request::VerifyAesCmac { client_id, .. } => client_id,
            Request::VerifyAesCmacExternalKey { client_id, .. } => client_id,
            Request::CalculateHmac { client_id, .. } => client_id,
            Request::CalculateHmacExternalKey { client_id, .. } => client_id,
            Request::VerifyHmac { client_id, .. } => client_id,
            Request::VerifyHmacExternalKey { client_id, .. } => client_id,
            Request::Sign { client_id, .. } => client_id,
            Request::SignExternalKey { client_id, .. } => client_id,
            Request::Verify { client_id, .. } => client_id,
            Request::VerifyExternalKey { client_id, .. } => client_id,
            Request::Ecdh { client_id, .. } => client_id,
            Request::EcdhExternalPrivateKey { client_id, .. } => client_id,
        }
    }

    pub fn get_request_id(&self) -> RequestId {
        *match self {
            Request::GetRandom { request_id, .. } => request_id,
            Request::GenerateSymmetricKey { request_id, .. } => request_id,
            Request::GenerateKeyPair { request_id, .. } => request_id,
            Request::ImportSymmetricKey { request_id, .. } => request_id,
            Request::ImportKeyPair { request_id, .. } => request_id,
            Request::ExportSymmetricKey { request_id, .. } => request_id,
            Request::ExportPublicKey { request_id, .. } => request_id,
            Request::ExportPrivateKey { request_id, .. } => request_id,
            Request::IsKeyAvailable { request_id, .. } => request_id,
            Request::EncryptChaChaPoly { request_id, .. } => request_id,
            Request::EncryptChaChaPolyExternalKey { request_id, .. } => request_id,
            Request::DecryptChaChaPoly { request_id, .. } => request_id,
            Request::DecryptChaChaPolyExternalKey { request_id, .. } => request_id,
            Request::EncryptAesGcm { request_id, .. } => request_id,
            Request::EncryptAesGcmExternalKey { request_id, .. } => request_id,
            Request::DecryptAesGcm { request_id, .. } => request_id,
            Request::DecryptAesGcmExternalKey { request_id, .. } => request_id,
            Request::EncryptAesCbc { request_id, .. } => request_id,
            Request::EncryptAesCbcExternalKey { request_id, .. } => request_id,
            Request::DecryptAesCbc { request_id, .. } => request_id,
            Request::DecryptAesCbcExternalKey { request_id, .. } => request_id,
            Request::CalculateAesCmac { request_id, .. } => request_id,
            Request::CalculateAesCmacExternalKey { request_id, .. } => request_id,
            Request::VerifyAesCmac { request_id, .. } => request_id,
            Request::VerifyAesCmacExternalKey { request_id, .. } => request_id,
            Request::CalculateHmac { request_id, .. } => request_id,
            Request::CalculateHmacExternalKey { request_id, .. } => request_id,
            Request::VerifyHmac { request_id, .. } => request_id,
            Request::VerifyHmacExternalKey { request_id, .. } => request_id,
            Request::Sign { request_id, .. } => request_id,
            Request::SignExternalKey { request_id, .. } => request_id,
            Request::Verify { request_id, .. } => request_id,
            Request::VerifyExternalKey { request_id, .. } => request_id,
            Request::Ecdh { request_id, .. } => request_id,
            Request::EcdhExternalPrivateKey { request_id, .. } => request_id,
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
            Request::EncryptAesGcm { client_id, .. } => *client_id = new_client_id,
            Request::EncryptAesGcmExternalKey { client_id, .. } => *client_id = new_client_id,
            Request::DecryptAesGcm { client_id, .. } => *client_id = new_client_id,
            Request::DecryptAesGcmExternalKey { client_id, .. } => *client_id = new_client_id,
            Request::EncryptAesCbc { client_id, .. } => *client_id = new_client_id,
            Request::EncryptAesCbcExternalKey { client_id, .. } => *client_id = new_client_id,
            Request::DecryptAesCbc { client_id, .. } => *client_id = new_client_id,
            Request::DecryptAesCbcExternalKey { client_id, .. } => *client_id = new_client_id,
            Request::CalculateAesCmac { client_id, .. } => *client_id = new_client_id,
            Request::CalculateAesCmacExternalKey { client_id, .. } => *client_id = new_client_id,
            Request::VerifyAesCmac { client_id, .. } => *client_id = new_client_id,
            Request::VerifyAesCmacExternalKey { client_id, .. } => *client_id = new_client_id,
            Request::CalculateHmac { client_id, .. } => *client_id = new_client_id,
            Request::CalculateHmacExternalKey { client_id, .. } => *client_id = new_client_id,
            Request::VerifyHmac { client_id, .. } => *client_id = new_client_id,
            Request::VerifyHmacExternalKey { client_id, .. } => *client_id = new_client_id,
            Request::Sign { client_id, .. } => *client_id = new_client_id,
            Request::SignExternalKey { client_id, .. } => *client_id = new_client_id,
            Request::Verify { client_id, .. } => *client_id = new_client_id,
            Request::VerifyExternalKey { client_id, .. } => *client_id = new_client_id,
            Request::Ecdh { client_id, .. } => *client_id = new_client_id,
            Request::EcdhExternalPrivateKey { client_id, .. } => *client_id = new_client_id,
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
            Request::EncryptAesGcm { request_id, .. } => *request_id = new_request_id,
            Request::EncryptAesGcmExternalKey { request_id, .. } => *request_id = new_request_id,
            Request::DecryptAesGcm { request_id, .. } => *request_id = new_request_id,
            Request::DecryptAesGcmExternalKey { request_id, .. } => *request_id = new_request_id,
            Request::EncryptAesCbc { request_id, .. } => *request_id = new_request_id,
            Request::EncryptAesCbcExternalKey { request_id, .. } => *request_id = new_request_id,
            Request::DecryptAesCbc { request_id, .. } => *request_id = new_request_id,
            Request::DecryptAesCbcExternalKey { request_id, .. } => *request_id = new_request_id,
            Request::CalculateAesCmac { request_id, .. } => *request_id = new_request_id,
            Request::CalculateAesCmacExternalKey { request_id, .. } => *request_id = new_request_id,
            Request::VerifyAesCmac { request_id, .. } => *request_id = new_request_id,
            Request::VerifyAesCmacExternalKey { request_id, .. } => *request_id = new_request_id,
            Request::CalculateHmac { request_id, .. } => *request_id = new_request_id,
            Request::CalculateHmacExternalKey { request_id, .. } => *request_id = new_request_id,
            Request::VerifyHmac { request_id, .. } => *request_id = new_request_id,
            Request::VerifyHmacExternalKey { request_id, .. } => *request_id = new_request_id,
            Request::Sign { request_id, .. } => *request_id = new_request_id,
            Request::SignExternalKey { request_id, .. } => *request_id = new_request_id,
            Request::Verify { request_id, .. } => *request_id = new_request_id,
            Request::VerifyExternalKey { request_id, .. } => *request_id = new_request_id,
            Request::Ecdh { request_id, .. } => *request_id = new_request_id,
            Request::EcdhExternalPrivateKey { request_id, .. } => *request_id = new_request_id,
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
            Response::EncryptAesGcm { client_id, .. } => client_id,
            Response::DecryptAesGcm { client_id, .. } => client_id,
            Response::EncryptAesCbc { client_id, .. } => client_id,
            Response::DecryptAesCbc { client_id, .. } => client_id,
            Response::CalculateAesCmac { client_id, .. } => client_id,
            Response::VerifyAesCmac { client_id, .. } => client_id,
            Response::CalculateHmac { client_id, .. } => client_id,
            Response::VerifyHmac { client_id, .. } => client_id,
            Response::Sign { client_id, .. } => client_id,
            Response::Verify { client_id, .. } => client_id,
            Response::Ecdh { client_id, .. } => client_id,
        }
    }

    pub fn get_request_id(&self) -> RequestId {
        *match self {
            Response::Error { request_id, .. } => request_id,
            Response::GetRandom { request_id, .. } => request_id,
            Response::GenerateSymmetricKey { request_id, .. } => request_id,
            Response::GenerateKeyPair { request_id, .. } => request_id,
            Response::ImportSymmetricKey { request_id, .. } => request_id,
            Response::ImportKeyPair { request_id, .. } => request_id,
            Response::ExportSymmetricKey { request_id, .. } => request_id,
            Response::ExportPublicKey { request_id, .. } => request_id,
            Response::ExportPrivateKey { request_id, .. } => request_id,
            Response::IsKeyAvailable { request_id, .. } => request_id,
            Response::EncryptChaChaPoly { request_id, .. } => request_id,
            Response::DecryptChaChaPoly { request_id, .. } => request_id,
            Response::EncryptAesGcm { request_id, .. } => request_id,
            Response::DecryptAesGcm { request_id, .. } => request_id,
            Response::EncryptAesCbc { request_id, .. } => request_id,
            Response::DecryptAesCbc { request_id, .. } => request_id,
            Response::CalculateAesCmac { request_id, .. } => request_id,
            Response::VerifyAesCmac { request_id, .. } => request_id,
            Response::CalculateHmac { request_id, .. } => request_id,
            Response::VerifyHmac { request_id, .. } => request_id,
            Response::Sign { request_id, .. } => request_id,
            Response::Verify { request_id, .. } => request_id,
            Response::Ecdh { request_id, .. } => request_id,
        }
    }
}
