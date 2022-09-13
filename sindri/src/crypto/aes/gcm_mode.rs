use super::*;

use aes_gcm::aead::Tag;
use aes_gcm::{AeadInPlace, Aes128Gcm, Aes256Gcm, KeyInit};

/// AES-GCM encryption: generic over an underlying AES implementation.
fn aes_gcm_encrypt<'a, C>(
    key: &[u8],
    nonce: &[u8],
    associated_data: &[u8],
    plaintext: &'a mut [u8],
) -> Result<Tag<C>, Error>
where
    C: KeyInit + AeadInPlace,
{
    check_sizes(key, nonce, C::KeySize::USIZE, C::NonceSize::USIZE)?;
    C::new(key.into())
        .encrypt_in_place_detached(nonce.into(), associated_data, plaintext)
        .map_err(|_| Error::Encrypt)
}

/// AES-GCM decryption: generic over an underlying AES implementation.
fn aes_gcm_decrypt<'a, C>(
    key: &[u8],
    nonce: &[u8],
    associated_data: &[u8],
    ciphertext: &'a mut [u8],
    tag: &[u8],
) -> Result<(), Error>
where
    C: KeyInit + AeadInPlace,
{
    check_sizes_with_tag(
        key,
        nonce,
        tag,
        C::KeySize::USIZE,
        C::NonceSize::USIZE,
        C::TagSize::USIZE,
    )?;
    C::new(key.into())
        .decrypt_in_place_detached(nonce.into(), associated_data, ciphertext, tag.into())
        .map_err(|_| Error::Decrypt)
}

macro_rules! define_aes_gcm_impl {
    (
        $encryptor:ident,
        $decryptor:ident,
        $core:tt
    ) => {
        pub fn $encryptor<'a>(
            key: &[u8],
            nonce: &[u8],
            aad: &[u8],
            plaintext: &'a mut [u8],
        ) -> Result<Tag<$core>, Error> {
            aes_gcm_encrypt::<$core>(key, nonce, aad, plaintext)
        }

        pub fn $decryptor(
            key: &[u8],
            nonce: &[u8],
            aad: &[u8],
            ciphertext: &mut [u8],
            tag: &[u8],
        ) -> Result<(), Error> {
            aes_gcm_decrypt::<$core>(key, nonce, aad, ciphertext, tag)
        }
    };
}

define_aes_gcm_impl!(aes128gcm_encrypt, aes128gcm_decrypt, Aes128Gcm);
define_aes_gcm_impl!(aes256gcm_encrypt, aes256gcm_decrypt, Aes256Gcm);

#[cfg(test)]
pub mod test {
    use super::*;
    use heapless::Vec;

    const KEY128: &[u8; KEY128_SIZE] = b"Open sesame! ...";
    const KEY256: &[u8; KEY256_SIZE] = b"Or was it 'open quinoa' instead?";
    const NONCE: &[u8; GCM_NONCE_SIZE] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    const PLAINTEXT: &[u8] = b"Hello, World!";
    const AAD: &[u8] = b"Never gonna give you up, Never gonna let you down!";

    macro_rules! define_aes_gcm_encrypt_decrypt_test {
        (
        $test_name:ident,
        $cipher:ty,
        $key:tt,
        $nonce:tt,
        $associated_data:expr,
        $plaintext:tt,
        $ciphertext:tt,
        $tag:tt
    ) => {
            #[test]
            fn $test_name() {
                let mut buffer = [0u8; $plaintext.len()];
                buffer.copy_from_slice($plaintext);
                let tag = aes_gcm_encrypt::<$cipher>($key, $nonce, $associated_data, &mut buffer)
                    .expect("encryption error");
                assert_eq!(buffer, $ciphertext, "ciphertext mismatch");
                assert_eq!(tag.as_slice(), $tag, "tag mismatch");
                aes_gcm_decrypt::<$cipher>($key, $nonce, $associated_data, &mut buffer, &tag)
                    .expect("decryption error");
                assert_eq!(buffer, $plaintext, "plaintext mismatch");
            }
        };
    }

    define_aes_gcm_encrypt_decrypt_test!(
        test_aes128gcm_no_aad_encrypt_decrypt,
        Aes128Gcm,
        KEY128,
        NONCE,
        &[],
        PLAINTEXT,
        [
            // ciphertext
            0xbb, 0xfe, 0x8, 0x2b, 0x97, 0x86, 0xd4, 0xe4, 0xa4, 0xec, 0x19, 0xdb, 0x63,
        ],
        [
            // tag
            0x40, 0xce, 0x93, 0x5a, 0x71, 0x5e, 0x63, 0x9, 0xb, 0x11, 0xad, 0x51, 0x4d, 0xe8, 0x23,
            0x50,
        ]
    );

    define_aes_gcm_encrypt_decrypt_test!(
        test_aes256gcm_no_aad_encrypt_decrypt,
        Aes256Gcm,
        KEY256,
        NONCE,
        &[],
        PLAINTEXT,
        [
            // ciphertext
            0xab, 0xe2, 0x9e, 0x5a, 0x8d, 0xd3, 0xbd, 0x62, 0xc9, 0x46, 0x71, 0x8e, 0x50,
        ],
        [
            // tag
            0xa8, 0xcb, 0x47, 0x81, 0xad, 0x51, 0x89, 0x1f, 0x23, 0x78, 0x11, 0xcb, 0x9f, 0xc5,
            0xbf, 0x8b,
        ]
    );

    define_aes_gcm_encrypt_decrypt_test!(
        test_aes128gcm_with_aad_encrypt_decrypt,
        Aes128Gcm,
        KEY128,
        NONCE,
        AAD,
        PLAINTEXT,
        [
            // ciphertext
            0xbb, 0xfe, 0x08, 0x2b, 0x97, 0x86, 0xd4, 0xe4, 0xa4, 0xec, 0x19, 0xdb, 0x63,
        ],
        [
            // tag
            0x15, 0x6d, 0x9e, 0xd9, 0x50, 0x1d, 0x7a, 0x51, 0x77, 0x44, 0x98, 0x97, 0x7d, 0x54,
            0x1c, 0x19,
        ]
    );

    define_aes_gcm_encrypt_decrypt_test!(
        test_aes256gcm_with_aad_encrypt_decrypt,
        Aes256Gcm,
        KEY256,
        NONCE,
        AAD,
        PLAINTEXT,
        [
            // ciphertext
            0xab, 0xe2, 0x9e, 0x5a, 0x8d, 0xd3, 0xbd, 0x62, 0xc9, 0x46, 0x71, 0x8e, 0x50,
        ],
        [
            // tag
            0xc2, 0xb4, 0x2e, 0x65, 0x8f, 0xa9, 0xfc, 0xc4, 0x2d, 0xaf, 0x8e, 0x22, 0xd3, 0xc5,
            0x8b, 0x6c,
        ]
    );

    macro_rules! define_aes_gcm_errors_test {
        (
        $test_name:ident,
        $cipher:ty,
        $key:tt,
        $nonce:tt,
        $plaintext:tt,
        $wrong_key_sizes:tt
    ) => {
            #[test]
            fn $test_name() {
                for size in $wrong_key_sizes {
                    let mut buffer = [0u8; $plaintext.len()];
                    buffer.copy_from_slice($plaintext);
                    let mut wrong_key: Vec<u8, 256> = Vec::new();
                    wrong_key.resize(size, 0).expect("Allocation error");
                    assert_eq!(
                        aes_gcm_encrypt::<$cipher>(&wrong_key, $nonce, &[], &mut buffer),
                        Err(Error::InvalidKeySize)
                    );
                    let tag = [0u8; GCM_TAG_SIZE];
                    assert_eq!(
                        aes_gcm_decrypt::<$cipher>(&wrong_key, $nonce, &[], &mut buffer, &tag),
                        Err(Error::InvalidKeySize)
                    );
                }

                for size in [0, 1, 10, 16, 32] {
                    let mut buffer = [0u8; $plaintext.len()];
                    buffer.copy_from_slice($plaintext);
                    let mut wrong_nonce: Vec<u8, 32> = Vec::new();
                    wrong_nonce.resize(size, 0).expect("Allocation error");
                    assert_eq!(
                        aes_gcm_encrypt::<$cipher>($key, &wrong_nonce, &[], &mut buffer),
                        Err(Error::InvalidIvSize)
                    );
                    let tag = [0u8; GCM_TAG_SIZE];
                    assert_eq!(
                        aes_gcm_decrypt::<$cipher>($key, &wrong_nonce, &[], &mut buffer, &tag),
                        Err(Error::InvalidIvSize)
                    );
                }

                for size in [0, 1, GCM_TAG_SIZE - 1] {
                    let mut buffer = [0u8; $plaintext.len()];
                    buffer.copy_from_slice($plaintext);
                    let mut short_tag: Vec<u8, { GCM_TAG_SIZE - 1 }> = Vec::new();
                    short_tag.resize(size, 0).expect("Allocation error");
                    assert_eq!(
                        aes_gcm_decrypt::<$cipher>($key, $nonce, &[], &mut buffer, &short_tag),
                        Err(Error::InvalidTagSize)
                    );
                }

                let mut corrupted_ciphertext = [0u8; $plaintext.len()];
                corrupted_ciphertext.copy_from_slice($plaintext);
                corrupted_ciphertext[0] += 1;
                let tag = [0u8; GCM_TAG_SIZE];
                assert_eq!(
                    aes_gcm_decrypt::<$cipher>($key, $nonce, &[], &mut corrupted_ciphertext, &tag),
                    Err(Error::Decrypt)
                );
            }
        };
    }

    define_aes_gcm_errors_test!(
        test_aes128gcm_errors,
        Aes128Gcm,
        KEY128,
        NONCE,
        PLAINTEXT,
        [0, 1, 8, 24, 32, 128]
    );

    define_aes_gcm_errors_test!(
        test_aes256gcm_errors,
        Aes256Gcm,
        KEY256,
        NONCE,
        PLAINTEXT,
        [0, 1, 8, 16, 24, 256]
    );
}
