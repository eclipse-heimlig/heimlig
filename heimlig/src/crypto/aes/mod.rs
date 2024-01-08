pub mod cbc;
pub mod ccm;
pub mod gcm;

use aes::{
    cipher::{BlockSizeUser, KeySizeUser, Unsigned},
    Aes128, Aes192, Aes256,
};

/// Size of the key in bytes for AES128-based algorithms.
pub const KEY128_SIZE: usize = <Aes128 as KeySizeUser>::KeySize::USIZE;
/// Size of the key in bytes for AES192-based algorithms.
pub const KEY192_SIZE: usize = <Aes192 as KeySizeUser>::KeySize::USIZE;
/// Size of the key in bytes for AES256-based algorithms.
pub const KEY256_SIZE: usize = <Aes256 as KeySizeUser>::KeySize::USIZE;
/// Size of the block size in bytes for AES-based algorithms.
pub const BLOCK_SIZE: usize = <Aes128 as BlockSizeUser>::BlockSize::USIZE;
/// Size of the initialization vector in bytes for AES-based algorithms.
pub const IV_SIZE: usize = <Aes128 as BlockSizeUser>::BlockSize::USIZE;
/// Size of the supported initialization vector (IV) in bytes for AES-GCM algorithms.
pub const GCM_IV_SIZE: usize = gcm::SupportedIvSize::USIZE;
/// Size of the supported authentication tag in bytes for AES-GCM algorithms.
pub const GCM_TAG_SIZE: usize = gcm::SupportedTagSize::USIZE;
/// Size of the supported nonce in bytes for AES-CCM algorithms.
pub const CCM_NONCE_SIZE: usize = ccm::SupportedNonceSize::USIZE;
/// Size of the supported authentication tag in bytes for AES-CCM algorithms.
pub const CCM_TAG_SIZE: usize = ccm::SupportedTagSize::USIZE;

#[cfg(test)]
mod test {
    use super::*;

    pub const KEY128: &[u8; KEY128_SIZE] = b"Open sesame! ...";
    pub const KEY192: &[u8; KEY192_SIZE] = b"Open sesame! ... Please!";
    pub const KEY256: &[u8; KEY256_SIZE] = b"Or was it 'open quinoa' instead?";
    pub const CBC_IV: &[u8; IV_SIZE] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    pub const GCM_IV: &[u8; GCM_IV_SIZE] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    pub const PLAINTEXT: &[u8] = b"Hello, World!";
    pub const PLAINTEXT_NOT_PADDED: &[u8] = PLAINTEXT;
    pub const PLAINTEXT_PADDED: &[u8] = b"Greetings, Rustaceans!!!!!!!!!!!";
    pub const AAD: &[u8] = b"Never gonna give you up, Never gonna let you down!";
}
