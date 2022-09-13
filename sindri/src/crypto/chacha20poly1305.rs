use chacha20poly1305::{
    aead::{generic_array::typenum::Unsigned, AeadCore},
    AeadInPlace, ChaCha20Poly1305, KeyInit, KeySizeUser,
};

/// Size of the key in bytes for ChaCha20-Poly1305 algorithms
pub const KEY_SIZE: usize = <ChaCha20Poly1305 as KeySizeUser>::KeySize::USIZE;
/// Size of the supported nonce in bytes for ChaCha20-Poly1305 algorithms.
pub const NONCE_SIZE: usize = <ChaCha20Poly1305 as AeadCore>::NonceSize::USIZE;
/// Size of the supported authentication tag in bytes for ChaCha20-Poly1305 algorithms.
pub const TAG_SIZE: usize = <ChaCha20Poly1305 as AeadCore>::TagSize::USIZE;

/// ChaCha20-Poly1305 errors.
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Error {
    /// Invalid size of the key.
    InvalidKeySize,
    /// Invalid size of the nonce.
    InvalidNonceSize,
    /// Invalid size of the tag.
    InvalidTagSize,
    /// Provided plaintext or ciphertext is not padded.
    InvalidPadding,
    /// Error during the encryption.
    Encryption,
    /// Error during the decryption.
    Decryption,
    /// Allocation error.
    Alloc,
}

pub fn chacha20poly1305_encrypt_in_place_detached(
    key: &[u8],
    nonce: &[u8],
    associated_data: &[u8],
    plaintext: &mut [u8],
    tag: &mut [u8],
) -> Result<(), Error> {
    check_sizes(key, nonce, tag)?;

    let computed_tag = ChaCha20Poly1305::new(key.into())
        .encrypt_in_place_detached(nonce.into(), associated_data, plaintext)
        .map_err(|_| Error::Encryption)?;
    tag.copy_from_slice(computed_tag.as_slice());
    Ok(())
}

pub fn chacha20poly1305_decrypt_in_place_detached(
    key: &[u8],
    nonce: &[u8],
    associated_data: &[u8],
    ciphertext: &mut [u8],
    tag: &[u8],
) -> Result<(), Error> {
    check_sizes(key, nonce, tag)?;
    ChaCha20Poly1305::new(key.into())
        .decrypt_in_place_detached(nonce.into(), associated_data, ciphertext, tag.into())
        .map_err(|_| Error::Decryption)?;
    Ok(())
}

/// Validation of key, nonce and tag sizes.
fn check_sizes(key: &[u8], nonce: &[u8], tag: &[u8]) -> Result<(), Error> {
    if key.len() != KEY_SIZE {
        return Err(Error::InvalidKeySize);
    }
    if nonce.len() != NONCE_SIZE {
        return Err(Error::InvalidNonceSize);
    }
    if tag.len() < TAG_SIZE {
        return Err(Error::InvalidTagSize);
    }
    Ok(())
}

#[cfg(test)]
pub mod test {
    use super::*;
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
                let mut plaintext_ciphertext = [0u8; PLAINTEXT.len()];
                plaintext_ciphertext.copy_from_slice($plaintext);
                let mut tag = [0u8; TAG_SIZE];
                $encryptor(
                    $key,
                    $nonce,
                    $associated_data,
                    &mut plaintext_ciphertext,
                    &mut tag,
                )
                .expect("encryption error");
                assert_eq!(plaintext_ciphertext, $ciphertext, "ciphertext mismatch");
                assert_eq!(tag, $tag, "ciphertext mismatch");
                $decryptor(
                    $key,
                    $nonce,
                    $associated_data,
                    &mut plaintext_ciphertext,
                    &tag,
                )
                .expect("decryption error");
                assert_eq!(plaintext_ciphertext, $plaintext, "plaintext mismatch");
            }
        };
    }

    define_chacha20poly1305_encrypt_decrypt_test!(
        test_chacha20poly1305_no_aad_encrypt_decrypt,
        chacha20poly1305_encrypt_in_place_detached,
        chacha20poly1305_decrypt_in_place_detached,
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
        chacha20poly1305_encrypt_in_place_detached,
        chacha20poly1305_decrypt_in_place_detached,
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
            let mut plaintext_ciphertext = [0u8; PLAINTEXT.len()];
            plaintext_ciphertext.copy_from_slice(PLAINTEXT);
            let mut tag = [0u8; TAG_SIZE];
            assert_eq!(
                chacha20poly1305_encrypt_in_place_detached(
                    &wrong_key,
                    NONCE,
                    &[],
                    &mut plaintext_ciphertext,
                    &mut tag
                ),
                Err(Error::InvalidKeySize)
            );
            assert_eq!(
                chacha20poly1305_decrypt_in_place_detached(
                    &wrong_key,
                    NONCE,
                    &[],
                    &mut plaintext_ciphertext,
                    &tag
                ),
                Err(Error::InvalidKeySize)
            );
        }

        for size in [0, 1, 10, 16, 32] {
            let mut wrong_nonce: Vec<u8, 32> = Vec::new();
            wrong_nonce.resize(size, 0).expect("Allocation error");
            let mut plaintext_ciphertext = [0u8; PLAINTEXT.len()];
            plaintext_ciphertext.copy_from_slice(PLAINTEXT);
            let mut tag = [0u8; TAG_SIZE];
            assert_eq!(
                chacha20poly1305_encrypt_in_place_detached(
                    KEY,
                    &wrong_nonce,
                    &[],
                    &mut plaintext_ciphertext,
                    &mut tag
                ),
                Err(Error::InvalidNonceSize)
            );
            assert_eq!(
                chacha20poly1305_decrypt_in_place_detached(
                    KEY,
                    &wrong_nonce,
                    &[],
                    &mut plaintext_ciphertext,
                    &tag
                ),
                Err(Error::InvalidNonceSize)
            );
        }

        for size in [0, 1, TAG_SIZE - 1] {
            const MAX_SIZE: usize = TAG_SIZE - 1;
            let mut wrong_tag: Vec<u8, MAX_SIZE> = Vec::new();
            wrong_tag.resize(size, 0).expect("Allocation error");
            let mut ciphertext = [0u8; PLAINTEXT.len()];
            ciphertext.copy_from_slice(PLAINTEXT);
            assert_eq!(
                chacha20poly1305_decrypt_in_place_detached(
                    KEY,
                    NONCE,
                    &[],
                    &mut ciphertext,
                    &wrong_tag
                ),
                Err(Error::InvalidTagSize)
            );
        }

        let mut plaintext = [0u8; PLAINTEXT.len()];
        plaintext.copy_from_slice(PLAINTEXT);
        let mut tag = [0u8; TAG_SIZE];
        chacha20poly1305_encrypt_in_place_detached(KEY, NONCE, &[], &mut plaintext, &mut tag)
            .expect("encryption error");
        let mut corrupted_ciphertext = [0u8; PLAINTEXT.len()];
        corrupted_ciphertext.copy_from_slice(&plaintext);
        corrupted_ciphertext[0] += 1;
        assert_eq!(
            chacha20poly1305_decrypt_in_place_detached(
                KEY,
                NONCE,
                &[],
                &mut corrupted_ciphertext,
                &tag
            ),
            Err(Error::Decryption)
        );
    }
}
