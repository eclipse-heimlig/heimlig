use crate::hsm::keystore;
use crate::hsm::keystore::KeyId;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Error {
    /// The amount of requested data was too large.
    RequestTooLarge,
    /// A cryptographic error occurred.
    Crypto(crate::crypto::Error),
    /// No key store present.
    NoKeyStore,
    /// A key store error occurred.
    KeyStore(keystore::Error),
    /// Failed to send through channel
    Send,
}

/// Used to distinguish multiple clients
pub type ClientId = u32;

/// Used to match requests and responses
pub type RequestId = u32;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum RequestType {
    ImportKey,
    GetRandom,
    EncryptChaChaPoly,
    EncryptChaChaPolyExternalKey,
    DecryptChaChaPoly,
    DecryptChaChaPolyExternalKey,
}

/// A request for the HSM to perform a cryptographic task.
#[derive(Eq, PartialEq, Debug)]
pub enum Request<'a> {
    ImportKey {
        client_id: ClientId,
        request_id: RequestId,
        key_id: KeyId,
        data: &'a [u8],
    },
    GetRandom {
        client_id: ClientId,
        request_id: RequestId,
        output: &'a mut [u8],
    },
    EncryptChaChaPoly {
        client_id: ClientId,
        request_id: RequestId,
        key_id: KeyId,
        nonce: &'a [u8],
        plaintext: &'a mut [u8],
        aad: &'a [u8],
        tag: &'a mut [u8],
    },
    EncryptChaChaPolyExternalKey {
        client_id: ClientId,
        request_id: RequestId,
        key: &'a [u8],
        nonce: &'a [u8],
        plaintext: &'a mut [u8],
        aad: &'a [u8],
        tag: &'a mut [u8],
    },
    DecryptChaChaPoly {
        client_id: ClientId,
        request_id: RequestId,
        key_id: KeyId,
        nonce: &'a [u8],
        ciphertext: &'a mut [u8],
        aad: &'a [u8],
        tag: &'a [u8],
    },
    DecryptChaChaPolyExternalKey {
        client_id: ClientId,
        request_id: RequestId,
        key: &'a [u8],
        nonce: &'a [u8],
        ciphertext: &'a mut [u8],
        aad: &'a [u8],
        tag: &'a [u8],
    },
}

impl<'data> Request<'data> {
    pub fn get_type(&self) -> RequestType {
        match self {
            Request::ImportKey { .. } => RequestType::ImportKey,
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
            Request::ImportKey {
                ref mut client_id, ..
            } => *client_id = new_client_id,
            Request::GetRandom {
                ref mut client_id, ..
            } => *client_id = new_client_id,
            Request::EncryptChaChaPoly {
                ref mut client_id, ..
            } => *client_id = new_client_id,
            Request::EncryptChaChaPolyExternalKey {
                ref mut client_id, ..
            } => *client_id = new_client_id,
            Request::DecryptChaChaPoly {
                ref mut client_id, ..
            } => *client_id = new_client_id,
            Request::DecryptChaChaPolyExternalKey {
                ref mut client_id, ..
            } => *client_id = new_client_id,
        }
    }
}

/// A response from the HSM containing the results of a cryptographic task.
#[derive(Eq, PartialEq, Debug)]
pub enum Response<'a> {
    ImportKey {
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
        data: &'a mut [u8],
    },
    EncryptChaChaPoly {
        client_id: ClientId,
        request_id: RequestId,
        ciphertext: &'a mut [u8],
        tag: &'a mut [u8],
    },
    DecryptChaChaPoly {
        client_id: ClientId,
        request_id: RequestId,
        plaintext: &'a mut [u8],
    },
}

impl<'data> Response<'data> {
    pub fn get_client_id(&self) -> ClientId {
        *match self {
            Response::ImportKey { client_id, .. } => client_id,
            Response::Error { client_id, .. } => client_id,
            Response::GetRandom { client_id, .. } => client_id,
            Response::EncryptChaChaPoly { client_id, .. } => client_id,
            Response::DecryptChaChaPoly { client_id, .. } => client_id,
        }
    }
}
