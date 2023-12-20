use crate::crypto::{check_sizes_with_tag, Error};
use aes::{cipher::typenum::Same, cipher::Unsigned};
use aes_gcm::{
    aead::consts::{U12, U16},
    AeadInPlace, Aes128Gcm, Aes256Gcm, KeyInit,
};
use zeroize::Zeroize;

pub type SupportedIvSize = U12;
pub type SupportedTagSize = U16;

/// AES-GCM encryption: generic over an underlying AES implementation.
fn encrypt_in_place_detached<C>(
    key: &[u8],
    iv: &[u8],
    associated_data: &[u8],
    buffer: &mut [u8],
    tag: &mut [u8],
) -> Result<(), Error>
where
    C: KeyInit + AeadInPlace,
    C::NonceSize: Same<SupportedIvSize>,
    C::TagSize: Same<SupportedTagSize>,
{
    check_sizes_with_tag(
        key,
        iv,
        tag,
        C::KeySize::USIZE,
        C::NonceSize::USIZE,
        C::TagSize::USIZE,
    )?;
    let mut computed_tag = C::new(key.into())
        .encrypt_in_place_detached(iv.into(), associated_data, buffer)
        .map_err(|_| Error::Encrypt)?;
    tag.copy_from_slice(&computed_tag);
    computed_tag.zeroize();
    Ok(())
}

/// AES-GCM decryption: generic over an underlying AES implementation.
fn decrypt_in_place_detached<C>(
    key: &[u8],
    iv: &[u8],
    associated_data: &[u8],
    buffer: &mut [u8],
    tag: &[u8],
) -> Result<(), Error>
where
    C: KeyInit + AeadInPlace,
    C::NonceSize: Same<SupportedIvSize>,
    C::TagSize: Same<SupportedTagSize>,
{
    check_sizes_with_tag(
        key,
        iv,
        tag,
        C::KeySize::USIZE,
        C::NonceSize::USIZE,
        C::TagSize::USIZE,
    )?;
    C::new(key.into())
        .decrypt_in_place_detached(iv.into(), associated_data, buffer, tag.into())
        .map_err(|_| Error::Decrypt)
}

macro_rules! define_aes_gcm_impl {
    (
        $encryptor:ident,
        $decryptor:ident,
        $core:tt
    ) => {
        pub fn $encryptor(
            key: &[u8],
            iv: &[u8],
            aad: &[u8],
            buffer: &mut [u8],
            tag: &mut [u8],
        ) -> Result<(), Error> {
            encrypt_in_place_detached::<$core>(key, iv, aad, buffer, tag)
        }

        pub fn $decryptor(
            key: &[u8],
            iv: &[u8],
            aad: &[u8],
            buffer: &mut [u8],
            tag: &[u8],
        ) -> Result<(), Error> {
            decrypt_in_place_detached::<$core>(key, iv, aad, buffer, tag)
        }
    };
}

define_aes_gcm_impl!(
    aes128gcm_encrypt_in_place_detached,
    aes128gcm_decrypt_in_place_detached,
    Aes128Gcm
);
define_aes_gcm_impl!(
    aes256gcm_encrypt_in_place_detached,
    aes256gcm_decrypt_in_place_detached,
    Aes256Gcm
);

#[cfg(test)]
mod test {
    extern crate alloc;
    use super::*;
    use crate::crypto::aes::{GCM_IV_SIZE, GCM_TAG_SIZE, KEY128_SIZE, KEY256_SIZE};
    use alloc::borrow::ToOwned;
    use heapless::Vec;

    const KEY128: &[u8; KEY128_SIZE] = b"Open sesame! ...";
    const KEY256: &[u8; KEY256_SIZE] = b"Or was it 'open quinoa' instead?";
    const IV: &[u8; GCM_IV_SIZE] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    const PLAINTEXT: &[u8] = b"Hello, World!";
    const AAD: &[u8] = b"Never gonna give you up, Never gonna let you down!";

    macro_rules! define_aes_gcm_encrypt_decrypt_test {
        (
        $test_name:ident,
        $cipher:ty,
        $key:tt,
        $iv:tt,
        $associated_data:expr,
        $plaintext:tt,
        $ciphertext:tt,
        $tag:tt
    ) => {
            #[test]
            fn $test_name() {
                let mut buffer = $plaintext.to_owned();
                let mut tag = $tag.to_owned();
                encrypt_in_place_detached::<$cipher>(
                    $key,
                    $iv,
                    $associated_data,
                    &mut buffer,
                    &mut tag,
                )
                .expect("encryption error");
                assert_eq!(buffer, $ciphertext, "ciphertext mismatch");
                assert_eq!(tag.as_slice(), $tag, "tag mismatch");
                decrypt_in_place_detached::<$cipher>(
                    $key,
                    $iv,
                    $associated_data,
                    &mut buffer,
                    &tag,
                )
                .expect("decryption error");
                assert_eq!(buffer, $plaintext, "plaintext mismatch");
            }
        };
    }

    define_aes_gcm_encrypt_decrypt_test!(
        test_aes128gcm_no_aad_encrypt_decrypt,
        Aes128Gcm,
        KEY128,
        IV,
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
        IV,
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
        IV,
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
        IV,
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
        $iv:tt,
        $plaintext:tt,
        $wrong_key_sizes:tt
    ) => {
            #[test]
            fn $test_name() {
                for size in $wrong_key_sizes {
                    let mut buffer = $plaintext.to_owned();
                    let mut tag = [0u8; GCM_TAG_SIZE];
                    let mut wrong_key: Vec<u8, 256> = Vec::new();
                    wrong_key.resize(size, 0).expect("Allocation error");
                    assert_eq!(
                        encrypt_in_place_detached::<$cipher>(
                            &wrong_key,
                            $iv,
                            &[],
                            &mut buffer,
                            &mut tag
                        ),
                        Err(Error::InvalidSymmetricKeySize)
                    );
                    assert_eq!(
                        decrypt_in_place_detached::<$cipher>(
                            &wrong_key,
                            $iv,
                            &[],
                            &mut buffer,
                            &tag
                        ),
                        Err(Error::InvalidSymmetricKeySize)
                    );
                }

                for size in [0, 1, 10, 16, 32] {
                    let mut buffer = $plaintext.to_owned();
                    let mut tag = [0u8; GCM_TAG_SIZE];
                    let mut wrong_iv: Vec<u8, 32> = Vec::new();
                    wrong_iv.resize(size, 0).expect("Allocation error");
                    assert_eq!(
                        encrypt_in_place_detached::<$cipher>(
                            $key,
                            &wrong_iv,
                            &[],
                            &mut buffer,
                            &mut tag
                        ),
                        Err(Error::InvalidIvSize)
                    );
                    assert_eq!(
                        decrypt_in_place_detached::<$cipher>(
                            $key,
                            &wrong_iv,
                            &[],
                            &mut buffer,
                            &tag
                        ),
                        Err(Error::InvalidIvSize)
                    );
                }

                for size in [0, 1, GCM_TAG_SIZE - 1] {
                    let mut buffer = $plaintext.to_owned();
                    let mut short_tag: Vec<u8, { GCM_TAG_SIZE - 1 }> = Vec::new();
                    short_tag.resize(size, 0).expect("Allocation error");
                    assert_eq!(
                        decrypt_in_place_detached::<$cipher>(
                            $key,
                            $iv,
                            &[],
                            &mut buffer,
                            &short_tag
                        ),
                        Err(Error::InvalidTagSize)
                    );
                }

                let mut buffer = $plaintext.to_owned();
                let mut tag = [0u8; GCM_TAG_SIZE];
                encrypt_in_place_detached::<$cipher>($key, $iv, &[], &mut buffer, &mut tag)
                    .expect("encryption error");
                buffer[0] += 1; // Corrupt ciphertext
                assert_eq!(
                    decrypt_in_place_detached::<$cipher>($key, $iv, &[], &mut buffer, &tag),
                    Err(Error::Decrypt)
                );
            }
        };
    }

    define_aes_gcm_errors_test!(
        test_aes128gcm_errors,
        Aes128Gcm,
        KEY128,
        IV,
        PLAINTEXT,
        [0, 1, 8, 24, 32, 128]
    );

    define_aes_gcm_errors_test!(
        test_aes256gcm_errors,
        Aes256Gcm,
        KEY256,
        IV,
        PLAINTEXT,
        [0, 1, 8, 16, 24, 256]
    );
}
