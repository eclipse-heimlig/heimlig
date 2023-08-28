use crate::hsm::keystore;
use crate::hsm::keystore::Id;

use crate::crypto::chacha20poly1305::TAG_SIZE;

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Error {
    /// The amount of requested data was too large.
    RequestTooLarge,
    /// A cryptographic error occurred.
    Crypto(crate::crypto::Error),
    /// A key store error occurred.
    KeyStore(keystore::Error),
}

/// A request for the HSM to perform a cryptographic task.
#[derive(Eq, PartialEq, Debug)]
pub enum Request<'a> {
    ImportKey {
        id: Id,
        data: &'a [u8],
    },
    GetRandom {
        output: &'a mut [u8],
    },
    EncryptChaChaPoly {
        key_id: Id,
        nonce: &'a [u8],
        aad: Option<&'a [u8]>,
        plaintext: &'a mut [u8],
        tag: &'a mut [u8; TAG_SIZE],
    },
    EncryptChaChaPolyExternalKey {
        key: &'a [u8],
        nonce: &'a [u8],
        aad: Option<&'a [u8]>,
        plaintext: &'a mut [u8],
        tag: &'a mut [u8; TAG_SIZE],
    },
    DecryptChaChaPoly {
        key_id: Id,
        nonce: &'a [u8],
        aad: Option<&'a [u8]>,
        ciphertext: &'a mut [u8],
        tag: &'a [u8; TAG_SIZE],
    },
    DecryptChaChaPolyExternalKey {
        key: &'a [u8],
        nonce: &'a [u8],
        aad: Option<&'a [u8]>,
        ciphertext: &'a mut [u8],
        tag: &'a [u8],
    },
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
        tag: &'a mut [u8; TAG_SIZE],
    },
    DecryptChaChaPoly {
        plaintext: &'a mut [u8],
    },
}
