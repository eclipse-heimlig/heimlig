mod cbc_mode;
mod ccm_mode;
mod gcm_mode;

use aes::{
    cipher::{BlockSizeUser, KeySizeUser, Unsigned},
    Aes128, Aes192, Aes256,
};
use aes_gcm::{AeadCore, Aes128Gcm};

pub use cbc_mode::{
    aes128cbc_decrypt, aes128cbc_encrypt, aes192cbc_decrypt, aes192cbc_encrypt, aes256cbc_decrypt,
    aes256cbc_encrypt,
};
pub use ccm_mode::{
    aes128ccm_decrypt, aes128ccm_encrypt, aes192ccm_decrypt, aes192ccm_encrypt, aes256ccm_decrypt,
    aes256ccm_encrypt,
};
pub use gcm_mode::{aes128gcm_decrypt, aes128gcm_encrypt, aes256gcm_decrypt, aes256gcm_encrypt};

/// Size of the key in bytes for AES128-based algorithms.
pub const KEY128_SIZE: usize = <Aes128 as KeySizeUser>::KeySize::USIZE;
/// Size of the key in bytes for AES192-based algorithms.
pub const KEY192_SIZE: usize = <Aes192 as KeySizeUser>::KeySize::USIZE;
/// Size of the key in bytes for AES256-based algorithms.
pub const KEY256_SIZE: usize = <Aes256 as KeySizeUser>::KeySize::USIZE;
/// Size of the blocksize in bytes for AES-based algorithms.
pub const BLOCK_SIZE: usize = <Aes128 as BlockSizeUser>::BlockSize::USIZE;
/// Size of the initialization vector in bytes for AES-based algorithms.
pub const IV_SIZE: usize = BLOCK_SIZE;
/// Size of the supported nonce in bytes for AES-GCM algorithms.
pub const GCM_NONCE_SIZE: usize = <Aes128Gcm as AeadCore>::NonceSize::USIZE;
/// Size of the supported authentication tag in bytes for AES-GCM algorithms.
pub const GCM_TAG_SIZE: usize = <Aes128Gcm as AeadCore>::TagSize::USIZE;
/// Size of the supported nonce in bytes for AES-CCM algorithms.
pub const CCM_NONCE_SIZE: usize = ccm_mode::SupportedNonceSize::USIZE;
/// Size of the supported authentication tag in bytes for AES-CCM algorithms.
pub const CCM_TAG_SIZE: usize = ccm_mode::SupportedTagSize::USIZE;

/// AES errors.
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Error {
    /// Invalid size of the key.
    InvalidKeySize,
    /// Invalid size of the nonce or the initialization vector.
    InvalidIvSize,
    /// Size of the provided plaintext or ciphertext is invalid.
    InvalidBufferSize,
    /// Provided plaintext or ciphertext is not padded.
    InvalidPadding,
    /// Error during the encryption.
    Encrypt,
    /// Error during the decryption.
    Decrypt,
    /// Allocation error.
    Alloc,
}

/// Validation of key and initialization vector/nonce sizes.
fn check_sizes(key: &[u8], iv: &[u8], key_size: usize, iv_size: usize) -> Result<(), Error> {
    if key.len() != key_size {
        return Err(Error::InvalidKeySize);
    }
    if iv.len() != iv_size {
        return Err(Error::InvalidIvSize);
    }
    Ok(())
}
