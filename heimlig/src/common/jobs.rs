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
        request_id: RequestId,
        key_id: KeyId,
        data: &'a [u8],
    },
    GetRandom {
        request_id: RequestId,
        output: &'a mut [u8],
    },
    EncryptChaChaPoly {
        request_id: RequestId,
        key_id: KeyId,
        nonce: &'a [u8],
        plaintext: &'a mut [u8],
        aad: &'a [u8],
        tag: &'a mut [u8],
    },
    EncryptChaChaPolyExternalKey {
        request_id: RequestId,
        key: &'a [u8],
        nonce: &'a [u8],
        plaintext: &'a mut [u8],
        aad: &'a [u8],
        tag: &'a mut [u8],
    },
    DecryptChaChaPoly {
        request_id: RequestId,
        key_id: KeyId,
        nonce: &'a [u8],
        ciphertext: &'a mut [u8],
        aad: &'a [u8],
        tag: &'a [u8],
    },
    DecryptChaChaPolyExternalKey {
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
}

/// A response from the HSM containing the results of a cryptographic task.
#[derive(Eq, PartialEq, Debug)]
pub enum Response<'a> {
    ImportKey {
        request_id: RequestId,
    },
    Error {
        request_id: RequestId,
        error: Error,
    },
    GetRandom {
        request_id: RequestId,
        data: &'a mut [u8],
    },
    EncryptChaChaPoly {
        request_id: RequestId,
        ciphertext: &'a mut [u8],
        tag: &'a mut [u8],
    },
    DecryptChaChaPoly {
        request_id: RequestId,
        plaintext: &'a mut [u8],
    },
}
