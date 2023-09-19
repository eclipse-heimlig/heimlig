use crate::hsm::keystore;
use crate::hsm::keystore::Id;

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
        key_id: Id,
        data: &'a [u8],
    },
    GetRandom {
        output: &'a mut [u8],
    },
    EncryptChaChaPoly {
        key_id: Id,
        nonce: &'a [u8],
        plaintext: &'a mut [u8],
        aad: &'a [u8],
        tag: &'a mut [u8],
    },
    EncryptChaChaPolyExternalKey {
        key: &'a [u8],
        nonce: &'a [u8],
        plaintext: &'a mut [u8],
        aad: &'a [u8],
        tag: &'a mut [u8],
    },
    DecryptChaChaPoly {
        key_id: Id,
        nonce: &'a [u8],
        ciphertext: &'a mut [u8],
        aad: &'a [u8],
        tag: &'a [u8],
    },
    DecryptChaChaPolyExternalKey {
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
    ImportKey,
    Error(Error),
    GetRandom {
        data: &'a mut [u8],
    },
    EncryptChaChaPoly {
        ciphertext: &'a mut [u8],
        tag: &'a mut [u8],
    },
    DecryptChaChaPoly {
        plaintext: &'a mut [u8],
    },
}
