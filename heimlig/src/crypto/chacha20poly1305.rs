use crate::crypto::{check_sizes, check_sizes_with_tag, Error};
use chacha20poly1305::{
    aead::{generic_array::typenum::Unsigned, AeadCore},
    AeadInPlace, ChaCha20Poly1305, KeyInit, KeySizeUser, Tag,
};

/// Size of the key in bytes for ChaCha20-Poly1305 algorithms
pub const KEY_SIZE: usize = <ChaCha20Poly1305 as KeySizeUser>::KeySize::USIZE;
/// Size of the supported nonce in bytes for ChaCha20-Poly1305 algorithms.
pub const NONCE_SIZE: usize = <ChaCha20Poly1305 as AeadCore>::NonceSize::USIZE;
/// Size of the supported authentication tag in bytes for ChaCha20-Poly1305 algorithms.
pub const TAG_SIZE: usize = <ChaCha20Poly1305 as AeadCore>::TagSize::USIZE;

/// Encrypt data with the ChaCha20Poly1305 stream cipher.
///
/// # Arguments
///
/// * `key`: The key to be used for encryption. Must be exactly [KEY_SIZE] bytes long.
/// * `nonce`: The nonce to be sued for encryption. The nonce __must not__ be reused for any given
/// key used. The nonce must have a size of exactly [NONCE_SIZE] bytes.
/// * `associated_data`: The additional associated data (AAD) to be authenticated during encryption.
/// This data will not be part of the ciphertext output.
/// * `buffer`: The buffer holding the plaintext.
/// After successful execution, this buffer will hold the ciphertext
///
/// returns: The authenticate [Tag] (on success) or an error value (on error).
pub fn encrypt_in_place_detached(
    key: &[u8],
    nonce: &[u8],
    associated_data: &[u8],
    buffer: &mut [u8],
) -> Result<Tag, Error> {
    check_sizes(key, nonce, KEY_SIZE, NONCE_SIZE)?;
    ChaCha20Poly1305::new(key.into())
        .encrypt_in_place_detached(nonce.into(), associated_data, buffer)
        .map_err(|_| Error::Encrypt)
}

/// Decrypt data with the ChaCha20Poly1305 stream cipher.
///
/// # Arguments
///
/// * `key`: The key to be used for decryption. Must be exactly [KEY_SIZE] bytes long.
/// * `nonce`: The nonce to be sued for decryption. The nonce __must not__ be reused for any given
/// key used. The nonce must have a size of exactly [NONCE_SIZE] bytes.
/// * `associated_data`: The additional associated data (AAD) to be authenticated during decryption.
/// This data will not be part of the plaintext output.
/// * `buffer`: The buffer holding the ciphertext.
/// After successful execution, this buffer will hold the plaintext
/// * `tag`: The tag (signature) to authenticate the input data with.
///
/// returns: An empty [Result] (on success) or an error value (on error).
pub fn decrypt_in_place_detached(
    key: &[u8],
    nonce: &[u8],
    associated_data: &[u8],
    buffer: &mut [u8],
    tag: &[u8],
) -> Result<(), Error> {
    check_sizes_with_tag(key, nonce, tag, KEY_SIZE, NONCE_SIZE, TAG_SIZE)?;
    ChaCha20Poly1305::new(key.into())
        .decrypt_in_place_detached(nonce.into(), associated_data, buffer, tag.into())
        .map_err(|_| Error::Decrypt)?;
    Ok(())
}

#[cfg(test)]
mod test {
    extern crate alloc;
    use super::*;
    use alloc::borrow::ToOwned;
    use heapless::Vec;

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
        $ciphertext:tt,
        $tag:tt
    ) => {
            #[test]
            fn $test_name() {
                let mut buffer = $plaintext.to_owned();
                let tag = $encryptor($key, $nonce, $associated_data, &mut buffer)
                    .expect("encryption error");
                assert_eq!(buffer, $ciphertext, "ciphertext mismatch");
                assert_eq!(tag.as_slice(), $tag, "tag mismatch");
                $decryptor($key, $nonce, $associated_data, &mut buffer, &tag)
                    .expect("decryption error");
                assert_eq!(buffer, $plaintext, "plaintext mismatch");
            }
        };
    }

    define_chacha20poly1305_encrypt_decrypt_test!(
        test_chacha20poly1305_no_aad_encrypt_decrypt,
        encrypt_in_place_detached,
        decrypt_in_place_detached,
        KEY,
        NONCE,
        &[],
        PLAINTEXT,
        [
            // ciphertext
            0xa1, 0x99, 0xf7, 0x68, 0x17, 0x92, 0x90, 0xae, 0xfe, 0x29, 0x7f, 0xdd, 0x3f, 0x16,
            0x2b, 0x56, 0x67, 0x72, 0x40, 0x75, 0x1e, 0xdf, 0xe2, 0xae, 0x99, 0x3f, 0x51, 0xcd,
            0x60, 0x2f, 0x1a, 0xaa, 0x64, 0x08, 0xe9, 0x13,
        ],
        [
            // tag
            0x3b, 0xfa, 0x42, 0x5d, 0x52, 0xcd, 0xa0, 0xcc, 0x82, 0x5c, 0x1f, 0x3f, 0xa0, 0xc4,
            0xe8, 0x35,
        ]
    );

    define_chacha20poly1305_encrypt_decrypt_test!(
        test_chacha20poly1305_with_aad_encrypt_decrypt,
        encrypt_in_place_detached,
        decrypt_in_place_detached,
        KEY,
        NONCE,
        AAD,
        PLAINTEXT,
        [
            // ciphertext
            0xa1, 0x99, 0xf7, 0x68, 0x17, 0x92, 0x90, 0xae, 0xfe, 0x29, 0x7f, 0xdd, 0x3f, 0x16,
            0x2b, 0x56, 0x67, 0x72, 0x40, 0x75, 0x1e, 0xdf, 0xe2, 0xae, 0x99, 0x3f, 0x51, 0xcd,
            0x60, 0x2f, 0x1a, 0xaa, 0x64, 0x08, 0xe9, 0x13,
        ],
        [
            // tag
            0x35, 0xfe, 0x5e, 0x5f, 0x2d, 0x16, 0x9a, 0x5e, 0x51, 0xf7, 0x56, 0x48, 0x13, 0x80,
            0xbc, 0xd4,
        ]
    );

    #[test]
    fn test_chacha20poly1305_errors() {
        for size in [0, 1, 8, 16, 24, 256] {
            let mut wrong_key: Vec<u8, 256> = Vec::new();
            wrong_key.resize(size, 0).expect("Allocation error");
            let mut buffer = PLAINTEXT.to_owned();
            assert_eq!(
                encrypt_in_place_detached(&wrong_key, NONCE, &[], &mut buffer),
                Err(Error::InvalidSymmetricKeySize)
            );
            let tag = [0u8; TAG_SIZE];
            assert_eq!(
                decrypt_in_place_detached(&wrong_key, NONCE, &[], &mut buffer, &tag),
                Err(Error::InvalidSymmetricKeySize)
            );
        }

        for size in [0, 1, 10, 16, 32] {
            let mut wrong_nonce: Vec<u8, 32> = Vec::new();
            wrong_nonce.resize(size, 0).expect("Allocation error");
            let mut buffer = PLAINTEXT.to_owned();
            assert_eq!(
                encrypt_in_place_detached(KEY, &wrong_nonce, &[], &mut buffer),
                Err(Error::InvalidIvSize)
            );
            let tag = [0u8; TAG_SIZE];
            assert_eq!(
                decrypt_in_place_detached(KEY, &wrong_nonce, &[], &mut buffer, &tag),
                Err(Error::InvalidIvSize)
            );
        }

        for size in [0, 1, TAG_SIZE - 1] {
            const MAX_SIZE: usize = TAG_SIZE - 1;
            let mut wrong_tag: Vec<u8, MAX_SIZE> = Vec::new();
            wrong_tag.resize(size, 0).expect("Allocation error");
            let mut buffer = PLAINTEXT.to_owned();
            assert_eq!(
                decrypt_in_place_detached(KEY, NONCE, &[], &mut buffer, &wrong_tag),
                Err(Error::InvalidTagSize)
            );
        }

        let mut buffer = PLAINTEXT.to_owned();
        let tag =
            encrypt_in_place_detached(KEY, NONCE, &[], &mut buffer).expect("encryption error");
        buffer[0] += 1; // Corrupt ciphertext
        assert_eq!(
            decrypt_in_place_detached(KEY, NONCE, &[], &mut buffer, &tag),
            Err(Error::Decrypt)
        );
    }
}
