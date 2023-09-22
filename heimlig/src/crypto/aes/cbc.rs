use crate::crypto::{check_sizes, Error};
use aes::{
    cipher::{
        block_padding::Padding, BlockCipher, BlockDecryptMut, BlockEncryptMut, BlockSizeUser,
        KeyInit, KeyIvInit, Unsigned,
    },
    Aes128, Aes192, Aes256,
};
use cbc::cipher::block_padding::PadType;

/// Returns buffer size after padding to a multiple of the block size of the chosen cipher.
///
/// # Arguments
///
/// * `unpadded_size`: Size of the unpadded ciphertext in bytes.
///
/// returns: Size of the padded ciphertext in bytes.
pub const fn padded_size<C, P>(unpadded_size: usize) -> usize
where
    C: BlockSizeUser,
    P: Padding<C::BlockSize>,
{
    let tail = unpadded_size % C::BlockSize::USIZE;
    match P::TYPE {
        PadType::NoPadding => unpadded_size,
        PadType::Ambiguous if tail == 0 => unpadded_size,
        PadType::Reversible | PadType::Ambiguous => {
            (unpadded_size - tail).saturating_add(C::BlockSize::USIZE)
        }
    }
}

/// AES-CBC encryption: generic over an underlying AES implementation.
fn encrypt_in_place<'data, C, P>(
    key: &[u8],
    iv: &[u8],
    buffer: &'data mut [u8],
    plaintext_len: usize,
) -> Result<&'data [u8], Error>
where
    C: BlockEncryptMut + BlockCipher + KeyInit,
    P: Padding<C::BlockSize>,
{
    check_sizes(key, iv, C::KeySize::USIZE, C::BlockSize::USIZE)?;
    cbc::Encryptor::<C>::new(key.into(), iv.into())
        .encrypt_padded_mut::<P>(buffer, plaintext_len)
        .map_err(|_| Error::InvalidBufferSize)
}

/// AES-CBC decryption: generic over an underlying AES implementation.
fn decrypt_in_place<'data, C, P>(
    key: &[u8],
    iv: &[u8],
    buffer: &'data mut [u8],
) -> Result<&'data [u8], Error>
where
    C: BlockDecryptMut + BlockCipher + KeyInit,
    P: Padding<C::BlockSize>,
{
    check_sizes(key, iv, C::KeySize::USIZE, C::BlockSize::USIZE)?;
    cbc::Decryptor::<C>::new(key.into(), iv.into())
        .decrypt_padded_mut::<P>(buffer)
        .map_err(|_| Error::InvalidPadding)
}

macro_rules! define_aes_cbc_impl {
    (
        $encryptor:ident,
        $decryptor:ident,
        $core:tt
    ) => {
        pub fn $encryptor<'data, P>(
            key: &[u8],
            iv: &[u8],
            buffer: &'data mut [u8],
            plaintext_len: usize,
        ) -> Result<&'data [u8], Error>
        where
            P: Padding<<$core as BlockSizeUser>::BlockSize>,
        {
            encrypt_in_place::<$core, P>(key, iv, buffer, plaintext_len)
        }

        pub fn $decryptor<'data, P>(
            key: &[u8],
            iv: &[u8],
            buffer: &'data mut [u8],
        ) -> Result<&'data [u8], Error>
        where
            P: Padding<<$core as BlockSizeUser>::BlockSize>,
        {
            decrypt_in_place::<$core, P>(key, iv, buffer)
        }
    };
}

define_aes_cbc_impl!(aes128cbc_encrypt, aes128cbc_decrypt, Aes128);
define_aes_cbc_impl!(aes192cbc_encrypt, aes192cbc_decrypt, Aes192);
define_aes_cbc_impl!(aes256cbc_encrypt, aes256cbc_decrypt, Aes256);

#[cfg(test)]
mod test {
    extern crate alloc;
    use super::*;
    use crate::crypto::aes::{BLOCK_SIZE, IV_SIZE, KEY128_SIZE, KEY192_SIZE, KEY256_SIZE};
    use aes::cipher::block_padding::{NoPadding, Pkcs7};
    use alloc::borrow::ToOwned;
    use heapless::Vec;

    const KEY128: &[u8; KEY128_SIZE] = b"Open sesame! ...";
    const KEY192: &[u8; KEY192_SIZE] = b"Open sesame! ... Please!";
    const KEY256: &[u8; KEY256_SIZE] = b"Or was it 'open quinoa' instead?";
    const IV: &[u8; IV_SIZE] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    const PLAINTEXT_NOT_PADDED: &[u8] = b"Hello, World!";
    const PLAINTEXT_PADDED: &[u8] = b"Greetings, Rustaceans!!!!!!!!!!!";

    #[test]
    fn padding_sizes() {
        for size in 0..33 {
            assert_eq!(size, padded_size::<Aes128, NoPadding>(size));
        }
        for size in 0..16 {
            assert_eq!(16, padded_size::<Aes128, Pkcs7>(size));
        }
        for size in 16..32 {
            assert_eq!(32, padded_size::<Aes128, Pkcs7>(size));
        }
        // Corner case should not overflow
        for size in usize::MAX - 15..=usize::MAX {
            assert_eq!(usize::MAX, padded_size::<Aes128, Pkcs7>(size));
        }
        padded_size::<Aes128, Pkcs7>(usize::MAX);
        assert_eq!(48, padded_size::<Aes128, Pkcs7>(33));
    }

    macro_rules! define_aes_cbc_encrypt_decrypt_test {
        (
        $test_name:ident,
        $cipher:ty,
        $padding: ty,
        $key:tt,
        $iv:tt,
        $plaintext:tt,
        $ciphertext:tt
    ) => {
            #[test]
            fn $test_name() {
                const PADDED_LEN: usize = padded_size::<$cipher, $padding>($plaintext.len());
                let mut buffer = [0u8; PADDED_LEN];
                buffer[..$plaintext.len()].copy_from_slice($plaintext);
                let encrypted =
                    encrypt_in_place::<$cipher, $padding>($key, $iv, &mut buffer, $plaintext.len())
                        .expect("encryption error");
                assert_eq!(encrypted, $ciphertext, "ciphertext mismatch");
                let enc_len = encrypted.len();
                let decrypted =
                    decrypt_in_place::<$cipher, $padding>($key, $iv, &mut buffer[..enc_len])
                        .expect("decryption error");
                assert_eq!(decrypted, $plaintext, "plaintext mismatch");
            }
        };
    }

    define_aes_cbc_encrypt_decrypt_test!(
        test_aes128cbc_encrypt_decrypt_nopadding,
        Aes128,
        NoPadding,
        KEY128,
        IV,
        PLAINTEXT_PADDED,
        [
            0x1b, 0x07, 0xde, 0x3d, 0xf2, 0x24, 0x0b, 0x38, 0x33, 0x42, 0xe4, 0xd4, 0x6b, 0x83,
            0xdc, 0x37, 0xd1, 0x44, 0xea, 0x35, 0x6a, 0x13, 0x34, 0x80, 0x86, 0xc0, 0x86, 0xce,
            0x06, 0x82, 0x1f, 0xd7,
        ]
    );

    define_aes_cbc_encrypt_decrypt_test!(
        test_aes192cbc_encrypt_decrypt_nopadding,
        Aes192,
        NoPadding,
        KEY192,
        IV,
        PLAINTEXT_PADDED,
        [
            0x1c, 0x0c, 0x08, 0xe6, 0x4f, 0x2f, 0x02, 0xd1, 0x61, 0xd2, 0xba, 0xf0, 0x04, 0x27,
            0x6e, 0xb6, 0x56, 0xab, 0x52, 0xf3, 0x56, 0xf5, 0xb5, 0x20, 0x67, 0x92, 0x91, 0xcb,
            0xf9, 0xca, 0x81, 0x8a,
        ]
    );

    define_aes_cbc_encrypt_decrypt_test!(
        test_aes256cbc_encrypt_decrypt_nopadding,
        Aes256,
        NoPadding,
        KEY256,
        IV,
        PLAINTEXT_PADDED,
        [
            0xd8, 0x4e, 0xbc, 0xf9, 0x1b, 0x4a, 0x10, 0xe8, 0xc9, 0x68, 0xb8, 0x93, 0xe6, 0xa5,
            0xc8, 0x0f, 0x6b, 0xa9, 0x7e, 0xdc, 0x09, 0x90, 0x6f, 0x7b, 0xfb, 0x04, 0x35, 0xa1,
            0xe9, 0x6b, 0x92, 0x1e,
        ]
    );

    define_aes_cbc_encrypt_decrypt_test!(
        test_aes128cbc_encrypt_decrypt_pkcs7,
        Aes128,
        Pkcs7,
        KEY128,
        IV,
        PLAINTEXT_NOT_PADDED,
        [
            0xd1, 0x04, 0x10, 0xd2, 0xb2, 0xa7, 0x3c, 0x65, 0xcc, 0xc8, 0xc9, 0xa7, 0x8d, 0x01,
            0x86, 0xc7,
        ]
    );

    define_aes_cbc_encrypt_decrypt_test!(
        test_aes192cbc_encrypt_decrypt_pkcs7,
        Aes192,
        Pkcs7,
        KEY192,
        IV,
        PLAINTEXT_NOT_PADDED,
        [
            0x4f, 0x99, 0xa8, 0x90, 0xfa, 0x4e, 0xe9, 0xfe, 0x94, 0x5d, 0x29, 0x96, 0xb3, 0xee,
            0x5e, 0x4d,
        ]
    );

    define_aes_cbc_encrypt_decrypt_test!(
        test_aes256cbc_encrypt_decrypt_pkcs7,
        Aes256,
        Pkcs7,
        KEY256,
        IV,
        PLAINTEXT_NOT_PADDED,
        [
            0x60, 0x53, 0xee, 0xb8, 0x14, 0xe1, 0x2c, 0x59, 0x7b, 0xf1, 0x1c, 0xad, 0x4d, 0x70,
            0x34, 0x1d,
        ]
    );

    macro_rules! define_aes_cbc_wrong_key_test {
        (
        $test_name:ident,
        $cipher:ty,
        $padding: ty,
        $iv:tt,
        $plaintext:tt,
        $wrong_key_sizes:tt
    ) => {
            #[test]
            fn $test_name() {
                const PADDED_LEN: usize = ($plaintext.len() / BLOCK_SIZE + 1) * BLOCK_SIZE;
                let mut buffer = [0u8; PADDED_LEN];
                buffer[..$plaintext.len()].copy_from_slice($plaintext);
                for size in $wrong_key_sizes {
                    let mut key: Vec<u8, 256> = Vec::new();
                    key.resize(size, 0).expect("Allocation error");
                    assert_eq!(
                        encrypt_in_place::<$cipher, $padding>(
                            &key,
                            $iv,
                            &mut buffer,
                            $plaintext.len()
                        ),
                        Err(Error::InvalidSymmetricKeySize)
                    );
                    assert_eq!(
                        decrypt_in_place::<$cipher, $padding>(&key, $iv, &mut buffer),
                        Err(Error::InvalidSymmetricKeySize)
                    );
                }
            }
        };
    }

    define_aes_cbc_wrong_key_test!(
        test_aes128cbc_wrong_key,
        Aes128,
        NoPadding,
        IV,
        PLAINTEXT_PADDED,
        [0, 1, 8, 24, 32, 128]
    );

    define_aes_cbc_wrong_key_test!(
        test_aes192cbc_wrong_key,
        Aes192,
        NoPadding,
        IV,
        PLAINTEXT_PADDED,
        [0, 1, 8, 16, 32, 192]
    );

    define_aes_cbc_wrong_key_test!(
        test_aes256cbc_wrong_key,
        Aes256,
        NoPadding,
        IV,
        PLAINTEXT_PADDED,
        [0, 1, 8, 16, 24, 256]
    );

    macro_rules! define_aes_cbc_errors_test {
        (
        $test_name:ident,
        $cipher:ty,
        $key:tt,
        $wrong_key_sizes:tt
    ) => {
            #[test]
            fn $test_name() {
                for size in $wrong_key_sizes {
                    let mut buffer = PLAINTEXT_PADDED.to_owned();
                    let mut wrong_key: Vec<u8, 256> = Vec::new();
                    wrong_key.resize(size, 0).expect("Allocation error");
                    assert_eq!(
                        encrypt_in_place::<$cipher, Pkcs7>(
                            &wrong_key,
                            IV,
                            &mut buffer,
                            PLAINTEXT_PADDED.len()
                        ),
                        Err(Error::InvalidSymmetricKeySize)
                    );
                    assert_eq!(
                        decrypt_in_place::<$cipher, Pkcs7>(&wrong_key, IV, &mut buffer),
                        Err(Error::InvalidSymmetricKeySize)
                    );
                }

                for size in [0, 1, 10, 12, 32] {
                    let mut buffer = PLAINTEXT_PADDED.to_owned();
                    let mut wrong_iv: Vec<u8, 32> = Vec::new();
                    wrong_iv.resize(size, 0).expect("Allocation error");
                    assert_eq!(
                        encrypt_in_place::<$cipher, Pkcs7>(
                            $key,
                            &wrong_iv,
                            &mut buffer,
                            PLAINTEXT_PADDED.len()
                        ),
                        Err(Error::InvalidIvSize)
                    );
                    assert_eq!(
                        decrypt_in_place::<$cipher, Pkcs7>($key, &wrong_iv, &mut buffer),
                        Err(Error::InvalidIvSize)
                    );
                }

                for size in [1, 15, 17, 65] {
                    let mut not_padded_buffer: Vec<u8, 65> = Vec::new();
                    not_padded_buffer.resize(size, 0).expect("Allocation error");
                    assert_eq!(
                        encrypt_in_place::<$cipher, NoPadding>(
                            $key,
                            IV,
                            &mut not_padded_buffer,
                            size
                        ),
                        Err(Error::InvalidBufferSize)
                    );
                    assert_eq!(
                        decrypt_in_place::<$cipher, NoPadding>($key, IV, &mut not_padded_buffer),
                        Err(Error::InvalidPadding)
                    );
                }
            }
        };
    }

    define_aes_cbc_errors_test!(
        test_aes128cbc_errors,
        Aes128,
        KEY128,
        [0, 1, 8, 24, 32, 128]
    );

    define_aes_cbc_errors_test!(
        test_aes192cbc_errors,
        Aes192,
        KEY192,
        [0, 1, 8, 16, 32, 192]
    );

    define_aes_cbc_errors_test!(
        test_aes256cbc_errors,
        Aes256,
        KEY256,
        [0, 1, 8, 16, 24, 256]
    );
}
