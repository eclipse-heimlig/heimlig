pub mod cbc;
pub mod ccm;
pub mod gcm;

use aes::{
    cipher::{BlockSizeUser, KeySizeUser, Unsigned},
    Aes128, Aes192, Aes256,
};
use aes_gcm::{AeadCore, Aes128Gcm};

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
pub const CCM_NONCE_SIZE: usize = ccm::SupportedNonceSize::USIZE;
/// Size of the supported authentication tag in bytes for AES-CCM algorithms.
pub const CCM_TAG_SIZE: usize = ccm::SupportedTagSize::USIZE;
