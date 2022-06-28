use crate::common::limits::{MAX_CIPHERTEXT_SIZE, MAX_PLAINTEXT_SIZE};
use aes::cipher::{
    block_padding::{PadType, Padding},
    BlockCipher, BlockDecryptMut, BlockEncryptMut, BlockSizeUser, KeyInit, KeyIvInit, KeySizeUser,
    Unsigned,
};
use aes_gcm::{aead::NewAead, AeadCore, AeadInPlace};

use aes::{Aes128, Aes192, Aes256};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use heapless::Vec;

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
pub const NONCE_SIZE: usize = <Aes128Gcm as AeadCore>::NonceSize::USIZE;
/// Size of the supported authentication tag in bytes for AES-GCM algorithms.
pub const TAG_SIZE: usize = <Aes128Gcm as AeadCore>::TagSize::USIZE;

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
    /// Error during the encryoption.
    Encryption,
    /// Error during the decryption.
    Decryption,
    /// Allocation error.
    Alloc,
}

/// AES-GCM encryption: generic over an underlying AES implementation.
fn aes_gcm_encrypt<C>(
    key: &[u8],
    nonce: &[u8],
    associated_data: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8, { MAX_CIPHERTEXT_SIZE + TAG_SIZE }>, Error>
where
    C: NewAead + AeadInPlace,
{
    check_sizes(key, nonce, C::KeySize::USIZE, C::NonceSize::USIZE)?;

    let key = aes_gcm::Key::from_slice(key);
    let nonce = aes_gcm::Nonce::from_slice(nonce);
    let mut ciphertext_and_tag = Vec::new();
    ciphertext_and_tag
        .extend_from_slice(plaintext)
        .map_err(|_| Error::Alloc)?;

    let tag = C::new(key)
        .encrypt_in_place_detached(nonce, associated_data, &mut ciphertext_and_tag)
        .map_err(|_| Error::Encryption)?;
    ciphertext_and_tag
        .extend_from_slice(&tag)
        .map_err(|_| Error::Alloc)?;

    Ok(ciphertext_and_tag)
}

/// AES-GCM decryption: generic over an underlying AES implementation.
fn aes_gcm_decrypt<C>(
    key: &[u8],
    nonce: &[u8],
    associated_data: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<Vec<u8, MAX_PLAINTEXT_SIZE>, Error>
where
    C: NewAead + AeadInPlace,
{
    check_sizes(key, nonce, C::KeySize::USIZE, C::NonceSize::USIZE)?;
    if ciphertext_and_tag.len() < C::TagSize::USIZE {
        return Err(Error::InvalidBufferSize);
    }
    let key = aes_gcm::Key::from_slice(key);
    let nonce = aes_gcm::Nonce::from_slice(nonce);
    let (ciphertext, tag) =
        ciphertext_and_tag.split_at(ciphertext_and_tag.len() - C::TagSize::USIZE);
    let mut plaintext = Vec::new();
    plaintext
        .extend_from_slice(ciphertext)
        .map_err(|_| Error::Alloc)?;
    C::new(key)
        .decrypt_in_place_detached(nonce, associated_data, &mut plaintext, tag.into())
        .map_err(|_| Error::Decryption)?;
    Ok(plaintext)
}

/// AES-CBC encryption: generic over an underlying AES implementation.
fn aes_cbc_encrypt<C, P>(
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8, MAX_CIPHERTEXT_SIZE>, Error>
where
    C: BlockEncryptMut + BlockCipher + KeyInit,
    P: Padding<C::BlockSize>,
{
    check_sizes(key, iv, C::KeySize::USIZE, C::BlockSize::USIZE)?;

    let key = aes::cipher::Key::<cbc::Encryptor<C>>::from_slice(key);
    let iv = aes::cipher::Iv::<cbc::Encryptor<C>>::from_slice(iv);
    let mut ciphertext = Vec::new();
    let ciphertext_size = get_padded_size::<C, P>(plaintext.len());
    ciphertext
        .extend_from_slice(plaintext)
        .map_err(|_| Error::Alloc)?;
    ciphertext
        .resize(ciphertext_size, 0)
        .map_err(|_| Error::Alloc)?;

    cbc::Encryptor::<C>::new(key, iv)
        .encrypt_padded_mut::<P>(&mut ciphertext, plaintext.len())
        .map_err(|_| Error::InvalidPadding)?;

    Ok(ciphertext)
}

/// AES-CBC decryption: generic over an underlying AES implementation.
fn aes_cbc_decrypt<C, P>(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8, MAX_PLAINTEXT_SIZE>, Error>
where
    C: BlockDecryptMut + BlockCipher + KeyInit,
    P: Padding<C::BlockSize>,
{
    check_sizes(key, iv, C::KeySize::USIZE, C::BlockSize::USIZE)?;

    let key = aes::cipher::Key::<cbc::Decryptor<C>>::from_slice(key);
    let iv = aes::cipher::Iv::<cbc::Decryptor<C>>::from_slice(iv);
    let mut plaintext = Vec::new();
    plaintext
        .extend_from_slice(ciphertext)
        .map_err(|_| Error::Alloc)?;

    let plaintext_size = cbc::Decryptor::<C>::new(key, iv)
        .decrypt_padded_mut::<P>(&mut plaintext)
        .map_err(|_| Error::InvalidPadding)?
        .len();

    plaintext
        .resize(plaintext_size, 0)
        .map_err(|_| Error::Alloc)?;

    Ok(plaintext)
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

/// Returns buffer size after the padding.
fn get_padded_size<C, P>(unpadded_size: usize) -> usize
where
    C: BlockSizeUser,
    P: Padding<C::BlockSize>,
{
    let tail = unpadded_size % C::BlockSize::USIZE;

    match P::TYPE {
        PadType::NoPadding => unpadded_size,
        PadType::Ambiguous if tail == 0 => unpadded_size,
        PadType::Reversible | PadType::Ambiguous => unpadded_size - tail + C::BlockSize::USIZE,
    }
}

macro_rules! define_aes_gcm_impl {
    (
        $encryptor:ident,
        $decryptor:ident,
        $core:tt
    ) => {
        pub fn $encryptor(
            key: &[u8],
            nonce: &[u8],
            aad: &[u8],
            plaintext: &[u8],
        ) -> Result<Vec<u8, { MAX_PLAINTEXT_SIZE + TAG_SIZE }>, Error> {
            aes_gcm_encrypt::<$core>(key, nonce, aad, plaintext)
        }

        pub fn $decryptor(
            key: &[u8],
            nonce: &[u8],
            aad: &[u8],
            ciphertext: &[u8],
        ) -> Result<Vec<u8, MAX_PLAINTEXT_SIZE>, Error> {
            aes_gcm_decrypt::<$core>(key, nonce, aad, ciphertext)
        }
    };
}

define_aes_gcm_impl!(aes128gcm_encrypt, aes128gcm_decrypt, Aes128Gcm);
define_aes_gcm_impl!(aes256gcm_encrypt, aes256gcm_decrypt, Aes256Gcm);

define_aes_gcm_impl!(aes128ccm_encrypt, aes128ccm_decrypt, Aes128Gcm);
define_aes_gcm_impl!(aes256ccm_encrypt, aes256ccm_decrypt, Aes256Gcm);

macro_rules! define_aes_cbc_impl {
    (
        $encryptor:ident,
        $decryptor:ident,
        $core:tt
    ) => {
        pub fn $encryptor<P>(
            key: &[u8],
            iv: &[u8],
            plaintext: &[u8],
        ) -> Result<Vec<u8, MAX_CIPHERTEXT_SIZE>, Error>
        where
            P: Padding<<$core as BlockSizeUser>::BlockSize>,
        {
            aes_cbc_encrypt::<$core, P>(key, iv, plaintext)
        }

        pub fn $decryptor<P>(
            key: &[u8],
            iv: &[u8],
            ciphertext: &[u8],
        ) -> Result<Vec<u8, MAX_PLAINTEXT_SIZE>, Error>
        where
            P: Padding<<$core as BlockSizeUser>::BlockSize>,
        {
            aes_cbc_decrypt::<$core, P>(key, iv, ciphertext)
        }
    };
}

define_aes_cbc_impl!(aes128cbc_encrypt, aes128cbc_decrypt, Aes128);
define_aes_cbc_impl!(aes192cbc_encrypt, aes192cbc_decrypt, Aes192);
define_aes_cbc_impl!(aes256cbc_encrypt, aes256cbc_decrypt, Aes256);

#[cfg(test)]
pub mod test {
    use super::*;

    use aes::cipher::block_padding::{NoPadding, Pkcs7};

    const KEY128: &[u8; KEY128_SIZE] = b"Open sesame! ...";
    const KEY192: &[u8; KEY192_SIZE] = b"Open sesame! ... Please!";
    const KEY256: &[u8; KEY256_SIZE] = b"Or was it 'open quinoa' instead?";
    const NONCE: &[u8; NONCE_SIZE] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    const IV: &[u8; IV_SIZE] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    const PLAINTEXT: &[u8] = b"Hello, World!";
    const PLAINTEXT_PADDED: &[u8] = b"Greetings, Rustaceans!!!!!!!!!!!";
    const AAD: &[u8] = b"Never gonna give you up, Never gonna let you down!";

    macro_rules! define_aes_gcm_encrypt_decrypt_test {
        (
        $test_name:ident,
        $cipher:ty,
        $key:tt,
        $nonce:tt,
        $associated_data:expr,
        $plaintext:tt,
        $ciphertext:tt
    ) => {
            #[test]
            fn $test_name() {
                let encrypted =
                    aes_gcm_encrypt::<$cipher>($key, $nonce, $associated_data, $plaintext)
                        .expect("encryption error");
                let decrypted =
                    aes_gcm_decrypt::<$cipher>($key, $nonce, $associated_data, &encrypted)
                        .expect("decryption error");
                assert_eq!(encrypted, $ciphertext, "ciphertext mismatch");
                assert_eq!(decrypted, $plaintext, "plaintext mismatch");
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
                    let mut wrong_key: Vec<u8, 256> = Vec::new();
                    wrong_key.resize(size, 0).expect("Allocation error");
                    assert_eq!(
                        aes_gcm_encrypt::<$cipher>(&wrong_key, $nonce, &[], $plaintext),
                        Err(Error::InvalidKeySize)
                    );
                    let mut zeros: Vec<u8, { MAX_PLAINTEXT_SIZE + TAG_SIZE }> = Vec::new();
                    zeros
                        .resize($plaintext.len() + TAG_SIZE, 0)
                        .expect("Allocation error");
                    assert_eq!(
                        aes_gcm_decrypt::<$cipher>(&wrong_key, $nonce, &[], &zeros),
                        Err(Error::InvalidKeySize)
                    );
                }

                for size in [0, 1, 10, 16, 32] {
                    let mut wrong_nonce: Vec<u8, 32> = Vec::new();
                    wrong_nonce.resize(size, 0).expect("Allocation error");
                    assert_eq!(
                        aes_gcm_encrypt::<$cipher>($key, &wrong_nonce, &[], $plaintext),
                        Err(Error::InvalidIvSize)
                    );
                    let mut zeros: Vec<u8, { MAX_PLAINTEXT_SIZE + TAG_SIZE }> = Vec::new();
                    zeros
                        .resize($plaintext.len() + TAG_SIZE, 0)
                        .expect("Allocation error");
                    assert_eq!(
                        aes_gcm_decrypt::<$cipher>($key, &wrong_nonce, &[], &zeros),
                        Err(Error::InvalidIvSize)
                    );
                }

                for size in [0, 1, TAG_SIZE - 1] {
                    const MAX_SIZE: usize = TAG_SIZE - 1;
                    let mut wrong_ciphertext: Vec<u8, MAX_SIZE> = Vec::new();
                    wrong_ciphertext.resize(size, 0).expect("Allocation error");
                    assert_eq!(
                        aes_gcm_decrypt::<$cipher>($key, $nonce, &[], &wrong_ciphertext),
                        Err(Error::InvalidBufferSize)
                    );
                }

                let mut corrupted_ciphertext =
                    aes_gcm_encrypt::<$cipher>($key, $nonce, &[], $plaintext)
                        .expect("encryption error");
                corrupted_ciphertext[0] += 1;
                assert_eq!(
                    aes_gcm_decrypt::<$cipher>($key, $nonce, &[], &corrupted_ciphertext),
                    Err(Error::Decryption)
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

    macro_rules! define_aes_cbc_encrypt_decrypt_test {
        (
        $test_name:ident,
        $cipher:ty,
        $padding: ty,
        $key:tt,
        $iv:tt,
        $plaintext:tt,
        $encrypted_plaintext:tt
    ) => {
            #[test]
            fn $test_name() {
                let encrypted = aes_cbc_encrypt::<$cipher, $padding>($key, $iv, $plaintext)
                    .expect("encryption error");
                let decrypted = aes_cbc_decrypt::<$cipher, $padding>($key, $iv, &encrypted)
                    .expect("decryption error");
                assert_eq!(encrypted, $encrypted_plaintext, "ciphertext mismatch");
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
        PLAINTEXT,
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
        PLAINTEXT,
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
        PLAINTEXT,
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
                for size in $wrong_key_sizes {
                    let mut key: Vec<u8, 256> = Vec::new();
                    key.resize(size, 0).expect("Allocation error");
                    assert_eq!(
                        aes_cbc_encrypt::<$cipher, $padding>(&key, $iv, $plaintext),
                        Err(Error::InvalidKeySize)
                    );
                    assert_eq!(
                        aes_cbc_decrypt::<$cipher, $padding>(&key, $iv, $plaintext),
                        Err(Error::InvalidKeySize)
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
                    let mut wrong_key: Vec<u8, 256> = Vec::new();
                    wrong_key.resize(size, 0).expect("Allocation error");
                    assert_eq!(
                        aes_cbc_encrypt::<$cipher, Pkcs7>(&wrong_key, IV, &PLAINTEXT_PADDED),
                        Err(Error::InvalidKeySize)
                    );
                    let mut zeros: Vec<u8, { PLAINTEXT_PADDED.len() }> = Vec::new();
                    zeros
                        .resize(PLAINTEXT_PADDED.len(), 0)
                        .expect("Allocation error");
                    assert_eq!(
                        aes_cbc_decrypt::<$cipher, Pkcs7>(&wrong_key, IV, &zeros),
                        Err(Error::InvalidKeySize)
                    );
                }

                for size in [0, 1, 10, 12, 32] {
                    let mut wrong_iv: Vec<u8, 32> = Vec::new();
                    wrong_iv.resize(size, 0).expect("Allocation error");
                    assert_eq!(
                        aes_cbc_encrypt::<$cipher, Pkcs7>($key, &wrong_iv, &PLAINTEXT_PADDED),
                        Err(Error::InvalidIvSize)
                    );
                    let mut zeros: Vec<u8, { PLAINTEXT_PADDED.len() }> = Vec::new();
                    zeros
                        .resize(PLAINTEXT_PADDED.len(), 0)
                        .expect("Allocation error");
                    assert_eq!(
                        aes_cbc_decrypt::<$cipher, Pkcs7>($key, &wrong_iv, &zeros),
                        Err(Error::InvalidIvSize)
                    );
                }

                for size in [1, 15, 17, 65] {
                    let mut not_padded_buffer: Vec<u8, 65> = Vec::new();
                    not_padded_buffer.resize(size, 0).expect("Allocation error");
                    assert_eq!(
                        aes_cbc_encrypt::<$cipher, NoPadding>($key, IV, &not_padded_buffer),
                        Err(Error::InvalidPadding)
                    );
                    assert_eq!(
                        aes_cbc_decrypt::<$cipher, NoPadding>($key, IV, &not_padded_buffer),
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
