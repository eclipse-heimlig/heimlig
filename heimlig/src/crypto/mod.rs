pub mod aes;
pub mod chacha20poly1305;
mod ecc;
pub mod ecdh;
pub mod ecdsa;
pub mod hash;
pub mod rng;
pub mod x25519;

/// Common errors.
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Error {
    /// Invalid size of the key.
    InvalidKeySize,
    /// Invalid size of the nonce or the initialization vector.
    InvalidIvSize,
    /// Size of the provided tag is invalid.
    InvalidTagSize,
    /// Size of the provided buffer is invalid.
    InvalidBufferSize,
    /// Provided plaintext or ciphertext is not padded.
    InvalidPadding,
    /// Error during encryption.
    Encrypt,
    /// Error during decryption.
    Decrypt,
    /// Invalid private key format.
    InvalidPrivateKey,
    /// Invalid public key format.
    InvalidPublicKey,
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

/// Validation of key, initialization vector/nonce and tag sizes.
fn check_sizes_with_tag(
    key: &[u8],
    iv: &[u8],
    tag: &[u8],
    key_size: usize,
    iv_size: usize,
    tag_size: usize,
) -> Result<(), Error> {
    if key.len() != key_size {
        return Err(Error::InvalidKeySize);
    }
    if iv.len() != iv_size {
        return Err(Error::InvalidIvSize);
    }
    if tag.len() != tag_size {
        return Err(Error::InvalidTagSize);
    }
    Ok(())
}
