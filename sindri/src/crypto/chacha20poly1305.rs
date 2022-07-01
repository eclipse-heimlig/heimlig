use crate::common::limits::{MAX_CIPHERTEXT_SIZE, MAX_PLAINTEXT_SIZE};

use chacha20poly1305::{
    aead::{generic_array::typenum::Unsigned, AeadCore, AeadInPlace, NewAead},
    ChaCha20Poly1305,
};
use heapless::Vec;

/// Size of the key in bytes for ChaCha20-Poly1305 algorithms
pub const KEY_SIZE: usize = <ChaCha20Poly1305 as NewAead>::KeySize::USIZE;
/// Size of the supported nonce in bytes for ChaCha20-Poly1305 algorithms.
pub const NONCE_SIZE: usize = <ChaCha20Poly1305 as AeadCore>::NonceSize::USIZE;
/// Size of the supported authentication tag in bytes for ChaCha20-Poly1305 algorithms.
pub const TAG_SIZE: usize = <ChaCha20Poly1305 as AeadCore>::TagSize::USIZE;

/// ChaCha20-Poly1305 errors.
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
    /// Error during the encryoption.
    Encryption,
    /// Error during the decryption.
    Decryption,
    /// Allocation error.
    Alloc,
}

pub fn chacha20poly1305_encrypt(
    key: &[u8],
    nonce: &[u8],
    associated_data: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8, { MAX_CIPHERTEXT_SIZE + TAG_SIZE }>, Error> {
    check_sizes(key, nonce)?;

    let mut ciphertext_and_tag = Vec::new();
    ciphertext_and_tag
        .extend_from_slice(plaintext)
        .map_err(|_| Error::Alloc)?;

    let tag = ChaCha20Poly1305::new(key.into())
        .encrypt_in_place_detached(nonce.into(), associated_data, &mut ciphertext_and_tag)
        .map_err(|_| Error::Encryption)?;
    ciphertext_and_tag
        .extend_from_slice(&tag)
        .map_err(|_| Error::Alloc)?;

    Ok(ciphertext_and_tag)
}

pub fn chacha20poly1305_decrypt(
    key: &[u8],
    nonce: &[u8],
    associated_data: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<Vec<u8, MAX_PLAINTEXT_SIZE>, Error> {
    check_sizes(key, nonce)?;
    if ciphertext_and_tag.len() < TAG_SIZE {
        return Err(Error::InvalidBufferSize);
    }

    let (ciphertext, tag) = ciphertext_and_tag.split_at(ciphertext_and_tag.len() - TAG_SIZE);

    let mut plaintext = Vec::new();
    plaintext
        .extend_from_slice(ciphertext)
        .map_err(|_| Error::Alloc)?;

    ChaCha20Poly1305::new(key.into())
        .decrypt_in_place_detached(nonce.into(), associated_data, &mut plaintext, tag.into())
        .map_err(|_| Error::Decryption)?;

    Ok(plaintext)
}

/// Validation of key and initialization vector/nonce sizes.
fn check_sizes(key: &[u8], iv: &[u8]) -> Result<(), Error> {
    if key.len() != KEY_SIZE {
        return Err(Error::InvalidKeySize);
    }
    if iv.len() != NONCE_SIZE {
        return Err(Error::InvalidIvSize);
    }
    Ok(())
}

#[cfg(test)]
pub mod test {
    use super::*;

    const KEY: &[u8; KEY_SIZE] = b"Fortuna Major or Oddsbodikins???";
    const NONCE: &[u8; NONCE_SIZE] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    const PLAINTEXT: &[u8] = b"I solemnly swear I am up to no good!";
    const AAD: &[u8] = b"When in doubt, go to the library.";

    macro_rules! define_chacha20poly1305_encrypt_decrypt_test {
        (
        $test_name:ident,
        $encryptor:tt,
        $decryptor:tt,
        $key:tt,
        $nonce:tt,
        $associated_data:expr,
        $plaintext:tt,
        $ciphertext:tt
    ) => {
            #[test]
            fn $test_name() {
                let encrypted = $encryptor($key, $nonce, $associated_data, $plaintext)
                    .expect("encryption error");
                let decrypted = $decryptor($key, $nonce, $associated_data, &encrypted)
                    .expect("decryption error");
                assert_eq!(encrypted, $ciphertext, "ciphertext mismatch");
                assert_eq!(decrypted, $plaintext, "plaintext mismatch");
            }
        };
    }

    define_chacha20poly1305_encrypt_decrypt_test!(
        test_chacha20poly1305_no_aad_encrypt_decrypt,
        chacha20poly1305_encrypt,
        chacha20poly1305_decrypt,
        KEY,
        NONCE,
        &[],
        PLAINTEXT,
        [
            // ciphertext
            0xa1, 0x99, 0xf7, 0x68, 0x17, 0x92, 0x90, 0xae, 0xfe, 0x29, 0x7f, 0xdd, 0x3f, 0x16,
            0x2b, 0x56, 0x67, 0x72, 0x40, 0x75, 0x1e, 0xdf, 0xe2, 0xae, 0x99, 0x3f, 0x51, 0xcd,
            0x60, 0x2f, 0x1a, 0xaa, 0x64, 0x08, 0xe9, 0x13, // tag
            0x3b, 0xfa, 0x42, 0x5d, 0x52, 0xcd, 0xa0, 0xcc, 0x82, 0x5c, 0x1f, 0x3f, 0xa0, 0xc4,
            0xe8, 0x35,
        ]
    );

    define_chacha20poly1305_encrypt_decrypt_test!(
        test_chacha20poly1305_with_aad_encrypt_decrypt,
        chacha20poly1305_encrypt,
        chacha20poly1305_decrypt,
        KEY,
        NONCE,
        AAD,
        PLAINTEXT,
        [
            // ciphertext
            0xa1, 0x99, 0xf7, 0x68, 0x17, 0x92, 0x90, 0xae, 0xfe, 0x29, 0x7f, 0xdd, 0x3f, 0x16,
            0x2b, 0x56, 0x67, 0x72, 0x40, 0x75, 0x1e, 0xdf, 0xe2, 0xae, 0x99, 0x3f, 0x51, 0xcd,
            0x60, 0x2f, 0x1a, 0xaa, 0x64, 0x08, 0xe9, 0x13, // tag
            0x35, 0xfe, 0x5e, 0x5f, 0x2d, 0x16, 0x9a, 0x5e, 0x51, 0xf7, 0x56, 0x48, 0x13, 0x80,
            0xbc, 0xd4,
        ]
    );

    #[test]
    fn test_chacha20poly1305_errors() {
        for size in [0, 1, 8, 16, 24, 256] {
            let mut wrong_key: Vec<u8, 256> = Vec::new();
            wrong_key.resize(size, 0).expect("Allocation error");
            assert_eq!(
                chacha20poly1305_encrypt(&wrong_key, NONCE, &[], PLAINTEXT),
                Err(Error::InvalidKeySize)
            );
            let mut zeros: Vec<u8, { MAX_PLAINTEXT_SIZE + TAG_SIZE }> = Vec::new();
            zeros
                .resize(PLAINTEXT.len() + TAG_SIZE, 0)
                .expect("Allocation error");
            assert_eq!(
                chacha20poly1305_decrypt(&wrong_key, NONCE, &[], &zeros),
                Err(Error::InvalidKeySize)
            );
        }

        for size in [0, 1, 10, 16, 32] {
            let mut wrong_nonce: Vec<u8, 32> = Vec::new();
            wrong_nonce.resize(size, 0).expect("Allocation error");
            assert_eq!(
                chacha20poly1305_encrypt(KEY, &wrong_nonce, &[], PLAINTEXT),
                Err(Error::InvalidIvSize)
            );
            let mut zeros: Vec<u8, { MAX_PLAINTEXT_SIZE + TAG_SIZE }> = Vec::new();
            zeros
                .resize(PLAINTEXT.len() + TAG_SIZE, 0)
                .expect("Allocation error");
            assert_eq!(
                chacha20poly1305_decrypt(KEY, &wrong_nonce, &[], &zeros),
                Err(Error::InvalidIvSize)
            );
        }

        for size in [0, 1, TAG_SIZE - 1] {
            const MAX_SIZE: usize = TAG_SIZE - 1;
            let mut wrong_ciphertext: Vec<u8, MAX_SIZE> = Vec::new();
            wrong_ciphertext.resize(size, 0).expect("Allocation error");
            assert_eq!(
                chacha20poly1305_decrypt(KEY, NONCE, &[], &wrong_ciphertext),
                Err(Error::InvalidBufferSize)
            );
        }

        let mut corrupted_ciphertext =
            chacha20poly1305_encrypt(KEY, NONCE, &[], PLAINTEXT).expect("encryption error");
        corrupted_ciphertext[0] += 1;
        assert_eq!(
            chacha20poly1305_decrypt(KEY, NONCE, &[], &corrupted_ciphertext),
            Err(Error::Decryption)
        );
    }
}
