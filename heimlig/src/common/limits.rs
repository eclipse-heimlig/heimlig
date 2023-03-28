use crate::common::pool::Pool;

// Configurable limits that control resource usage

/// Maximum number of random bytes that can be requested at once.
pub const MAX_RANDOM_SIZE: usize = Pool::MAX_ALLOC_SIZE;

/// Maximum plaintext length for symmetric encryption.
pub const MAX_PLAINTEXT_SIZE: usize = Pool::MAX_ALLOC_SIZE;

/// Maximum ciphertext length for symmetric encryption.
pub const MAX_CIPHERTEXT_SIZE: usize = Pool::MAX_ALLOC_SIZE;
