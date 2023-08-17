use core::ptr::NonNull;

use crate::hsm::keystore;
use crate::hsm::keystore::Id;

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

/// Shared memory representation.
#[derive(Eq, PartialEq, Debug)]
pub struct ExternalMemory {
    /// Pointer to memory.
    ptr: *const u8,
    /// Memory size.
    size: usize,
}

impl ExternalMemory {
    pub fn new(ptr: *const u8, size: usize) -> Self {
        Self { ptr, size }
    }

    pub fn from_slice(data: &[u8]) -> Self {
        Self::new(data.as_ptr(), data.len())
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.ptr, self.size) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.ptr as *mut _, self.size) }
    }
}

impl Default for ExternalMemory {
    fn default() -> Self {
        Self {
            ptr: NonNull::<u8>::dangling().as_ptr(),
            size: 0,
        }
    }
}

/// Shared memory input parameter.
#[derive(Eq, PartialEq, Debug, Default)]
pub struct InParam {
    /// Shared memory.
    memory: ExternalMemory,
}

impl InParam {
    pub fn new(memory: ExternalMemory) -> Self {
        Self { memory }
    }

    pub fn as_slice(&self) -> &[u8] {
        self.memory.as_slice()
    }
}

/// Shared memory output parameter.
#[derive(Eq, PartialEq, Debug, Default)]
pub struct OutParam {
    /// Shared memory.
    memory: ExternalMemory,
}

impl OutParam {
    pub fn new(memory: ExternalMemory) -> Self {
        Self { memory }
    }

    pub fn as_slice(&self) -> &[u8] {
        self.memory.as_slice()
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.memory.as_mut_slice()
    }
}

/// Shared memory in/out parameter.
#[derive(Eq, PartialEq, Debug, Default)]
pub struct InOutParam {
    /// Shared memory.
    memory: ExternalMemory,
}

impl InOutParam {
    pub fn new(memory: ExternalMemory) -> Self {
        Self { memory }
    }

    pub fn as_slice(&self) -> &[u8] {
        self.memory.as_slice()
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.memory.as_mut_slice()
    }
}

/// A request for the HSM to perform a cryptographic task.
#[derive(Eq, PartialEq, Debug)]
pub enum Request {
    ImportKey {
        id: Id,
        data: InParam,
    },
    GetRandom {
        data: OutParam,
    },
    EncryptChaChaPoly {
        key_id: Id,
        nonce: InParam,
        aad: Option<InParam>,
        plaintext: InOutParam,
        tag: OutParam,
    },
    EncryptChaChaPolyExternalKey {
        key: InParam,
        nonce: InParam,
        aad: Option<InParam>,
        plaintext: InOutParam,
        tag: OutParam,
    },
    DecryptChaChaPoly {
        key_id: Id,
        nonce: InParam,
        aad: Option<InParam>,
        ciphertext: InOutParam,
        tag: InParam,
    },
    DecryptChaChaPolyExternalKey {
        key: InParam,
        nonce: InParam,
        aad: Option<InParam>,
        ciphertext: InOutParam,
        tag: InParam,
    },
}

/// A response from the HSM containing the results of a cryptographic task.
#[derive(Eq, PartialEq, Debug)]
pub enum Response {
    ImportKey,
    Error(Error),
    GetRandom {
        data: OutParam,
    },
    EncryptChaChaPoly {
        ciphertext: InOutParam,
        tag: OutParam,
    },
    DecryptChaChaPoly {
        plaintext: InOutParam,
    },
}
