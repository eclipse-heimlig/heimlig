use crate::hsm::keystore;
use crate::hsm::keystore::KeyId;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// A cryptographic error occurred.
    Crypto(crate::crypto::Error),
    /// The amount of requested data was too large.
    RequestTooLarge,
    /// No key store present.
    NoKeyStore,
    /// A key store error occurred.
    KeyStore(keystore::Error),
    /// Failed to send through channel.
    Send,
    /// No worker found for received request type.
    NoWorkerForRequest,
    /// A worker encountered a request type that it cannot handle.  
    UnexpectedRequestType,
}

/// Used to distinguish multiple clients
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ClientId(pub u32);

impl From<u32> for ClientId {
    fn from(value: u32) -> Self {
        ClientId(value)
    }
}

impl From<usize> for ClientId {
    fn from(value: usize) -> Self {
        ClientId(value as u32)
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
    ImportSymmetricKey,
    ImportKeyPair,
    GetRandom,
    EncryptChaChaPoly,
    EncryptChaChaPolyExternalKey,
    DecryptChaChaPoly,
    DecryptChaChaPolyExternalKey,
}

/// A request for the HSM to perform a cryptographic task.
#[derive(Eq, PartialEq, Debug)]
pub enum Request<'data> {
    ImportSymmetricKey {
        client_id: ClientId,
        request_id: RequestId,
        key_id: KeyId,
        data: &'data [u8],
    },
    ImportKeyPair {
        client_id: ClientId,
        request_id: RequestId,
        key_id: KeyId,
        public_key: &'data [u8],
        private_key: &'data [u8],
    },
    GetRandom {
        client_id: ClientId,
        request_id: RequestId,
        output: &'data mut [u8],
    },
    EncryptChaChaPoly {
        client_id: ClientId,
        request_id: RequestId,
        key_id: KeyId,
        nonce: &'data [u8],
        plaintext: &'data mut [u8],
        aad: &'data [u8],
        tag: &'data mut [u8],
    },
    EncryptChaChaPolyExternalKey {
        client_id: ClientId,
        request_id: RequestId,
        key: &'data [u8],
        nonce: &'data [u8],
        plaintext: &'data mut [u8],
        aad: &'data [u8],
        tag: &'data mut [u8],
    },
    DecryptChaChaPoly {
        client_id: ClientId,
        request_id: RequestId,
        key_id: KeyId,
        nonce: &'data [u8],
        ciphertext: &'data mut [u8],
        aad: &'data [u8],
        tag: &'data [u8],
    },
    DecryptChaChaPolyExternalKey {
        client_id: ClientId,
        request_id: RequestId,
        key: &'data [u8],
        nonce: &'data [u8],
        ciphertext: &'data mut [u8],
        aad: &'data [u8],
        tag: &'data [u8],
    },
}

impl RequestType {
    /// A core-only request does not require a worker. Key management (import/export) is an example
    /// of this type of request.
    pub fn is_for_core_only(&self) -> bool {
        match self {
            RequestType::ImportSymmetricKey => true,
            RequestType::ImportKeyPair => true,
            _ => false,
        }
    }
}

/// A response from the HSM containing the results of a cryptographic task.
#[derive(Eq, PartialEq, Debug)]
pub enum Response<'data> {
    ImportSymmetricKey {
        client_id: ClientId,
        request_id: RequestId,
    },
    ImportKeyPair {
        client_id: ClientId,
        request_id: RequestId,
    },
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
    EncryptChaChaPoly {
        client_id: ClientId,
        request_id: RequestId,
        ciphertext: &'data mut [u8],
        tag: &'data mut [u8],
    },
    DecryptChaChaPoly {
        client_id: ClientId,
        request_id: RequestId,
        plaintext: &'data mut [u8],
    },
}

impl<'data> Request<'data> {
    pub fn get_type(&self) -> RequestType {
        match self {
            Request::ImportSymmetricKey { .. } => RequestType::ImportSymmetricKey,
            Request::ImportKeyPair { .. } => RequestType::ImportKeyPair,
            Request::GetRandom { .. } => RequestType::GetRandom,
            Request::EncryptChaChaPoly { .. } => RequestType::EncryptChaChaPoly,
            Request::EncryptChaChaPolyExternalKey { .. } => {
                RequestType::EncryptChaChaPolyExternalKey
            }
            Request::DecryptChaChaPoly { .. } => RequestType::DecryptChaChaPoly,
            Request::DecryptChaChaPolyExternalKey { .. } => {
                RequestType::DecryptChaChaPolyExternalKey
            }
        }
    }

    pub fn set_client_id(&mut self, new_client_id: ClientId) {
        match self {
            Request::ImportSymmetricKey { client_id, .. } => *client_id = new_client_id,
            Request::ImportKeyPair { client_id, .. } => *client_id = new_client_id,
            Request::GetRandom { client_id, .. } => *client_id = new_client_id,
            Request::EncryptChaChaPoly { client_id, .. } => *client_id = new_client_id,
            Request::EncryptChaChaPolyExternalKey { client_id, .. } => *client_id = new_client_id,
            Request::DecryptChaChaPoly { client_id, .. } => *client_id = new_client_id,
            Request::DecryptChaChaPolyExternalKey { client_id, .. } => *client_id = new_client_id,
        }
    }
}

impl<'data> Response<'data> {
    pub fn get_client_id(&self) -> ClientId {
        *match self {
            Response::ImportSymmetricKey { client_id, .. } => client_id,
            Response::ImportKeyPair { client_id, .. } => client_id,
            Response::Error { client_id, .. } => client_id,
            Response::GetRandom { client_id, .. } => client_id,
            Response::EncryptChaChaPoly { client_id, .. } => client_id,
            Response::DecryptChaChaPoly { client_id, .. } => client_id,
        }
    }
}
