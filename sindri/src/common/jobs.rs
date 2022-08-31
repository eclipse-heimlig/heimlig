use crate::common::pool::PoolChunk;
use crate::host::scheduler;

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

#[derive(Eq, PartialEq, Debug)]
pub enum Response {
    Error(scheduler::Error),
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
