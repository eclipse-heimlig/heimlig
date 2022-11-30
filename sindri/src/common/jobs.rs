use crate::common::pool::PoolChunk;
use crate::host::keystore;
use crate::host::keystore::Id;

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Error {
    /// Failed to allocate memory.
    Alloc,
    /// The amount of requested data was too large.
    RequestTooLarge,
    /// A cryptographic error occurred.
    Crypto(crate::crypto::Error),
    /// A key store error occurred.
    KeyStore(keystore::Error),
}

/// A request for the HSM to perform a cryptographic task.
#[derive(Eq, PartialEq, Debug)]
pub enum Request {
    ImportKey {
        id: Id,
        data: PoolChunk,
    },
    GetRandom {
        size: usize,
    },
    EncryptChaChaPoly {
        key_id: Id,
        nonce: PoolChunk,
        aad: Option<PoolChunk>,
        plaintext: PoolChunk,
    },
    EncryptChaChaPolyExternalKey {
        key: PoolChunk,
        nonce: PoolChunk,
        aad: Option<PoolChunk>,
        plaintext: PoolChunk,
    },
    DecryptChaChaPoly {
        key_id: Id,
        nonce: PoolChunk,
        aad: Option<PoolChunk>,
        ciphertext: PoolChunk,
        tag: PoolChunk,
    },
    DecryptChaChaPolyExternalKey {
        key: PoolChunk,
        nonce: PoolChunk,
        aad: Option<PoolChunk>,
        ciphertext: PoolChunk,
        tag: PoolChunk,
    },
}

/// A response from the HSM containing the results of a cryptographic task.
#[derive(Eq, PartialEq, Debug)]
pub enum Response {
    ImportKey,
    Error(Error),
    GetRandom {
        data: PoolChunk,
    },
    EncryptChaChaPoly {
        ciphertext: PoolChunk,
        tag: PoolChunk,
    },
    DecryptChaChaPoly {
        plaintext: PoolChunk,
    },
}
