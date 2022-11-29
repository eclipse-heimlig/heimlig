use crate::common::pool::PoolChunk;

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Error {
    /// Failed to allocate memory.
    Alloc,
    /// The amount of requested data was too large.
    RequestTooLarge,
    /// A cryptographic error occurred.
    Crypto(crate::crypto::Error),
}

/// A request for the HSM to perform a cryptographic task.
#[derive(Eq, PartialEq, Debug)]
pub enum Request {
    GetRandom {
        size: usize,
    },
    EncryptChaChaPoly {
        key: PoolChunk,
        nonce: PoolChunk,
        aad: Option<PoolChunk>,
        plaintext: PoolChunk,
    },
    DecryptChaChaPoly {
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
