use super::*;

use crate::common::limits::{MAX_CIPHERTEXT_SIZE, MAX_PLAINTEXT_SIZE};
use aes::{
    cipher::{BlockCipher, BlockEncrypt, BlockSizeUser, KeyInit, KeySizeUser, Unsigned},
    Aes128, Aes192, Aes256,
};
use ccm::{
    aead::{generic_array::ArrayLength, AeadInPlace, NewAead},
    consts::{U13, U16},
    Ccm, NonceSize, TagSize,
};
use heapless::Vec;

pub type SupportedNonceSize = U13;
pub type SupportedTagSize = U16;

fn aes_ccm_encrypt<C, M, N>(
    key: &[u8],
    nonce: &[u8],
    associated_data: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8, { MAX_CIPHERTEXT_SIZE + CCM_TAG_SIZE }>, Error>
where
    C: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt + KeySizeUser + KeyInit,
    M: ArrayLength<u8> + TagSize,
    N: ArrayLength<u8> + NonceSize,
{
    check_sizes(key, nonce, C::KeySize::USIZE, N::USIZE)?;

    // TODO: avoid stack allocation
    let mut ciphertext_and_tag = Vec::new();
    ciphertext_and_tag
        .extend_from_slice(plaintext)
        .map_err(|_| Error::Alloc)?;

    let tag = Ccm::<C, M, N>::new(key.into())
        .encrypt_in_place_detached(nonce.into(), associated_data, &mut ciphertext_and_tag)
        .map_err(|_| Error::Encrypt)?;
    ciphertext_and_tag
        .extend_from_slice(&tag)
        .map_err(|_| Error::Alloc)?;

    Ok(ciphertext_and_tag)
}

fn aes_ccm_decrypt<C, M, N>(
    key: &[u8],
    nonce: &[u8],
    associated_data: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<Vec<u8, MAX_PLAINTEXT_SIZE>, Error>
where
    C: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt + KeySizeUser + KeyInit,
    M: ArrayLength<u8> + TagSize,
    N: ArrayLength<u8> + NonceSize,
{
    check_sizes(key, nonce, C::KeySize::USIZE, N::USIZE)?;
    if ciphertext_and_tag.len() < M::USIZE {
        return Err(Error::InvalidBufferSize);
    }

    let (ciphertext, tag) = ciphertext_and_tag.split_at(ciphertext_and_tag.len() - M::USIZE);

    // TODO: avoid stack allocation
    let mut plaintext = Vec::new();
    plaintext
        .extend_from_slice(ciphertext)
        .map_err(|_| Error::Alloc)?;

    Ccm::<C, M, N>::new(key.into())
        .decrypt_in_place_detached(nonce.into(), associated_data, &mut plaintext, tag.into())
        .map_err(|_| Error::Decrypt)?;

    Ok(plaintext)
}

macro_rules! define_aes_ccm_impl {
    (
        $encryptor:ident,
        $decryptor:ident,
        $core:tt,
        $tag_size: tt,
        $nonce_size: tt,
    ) => {
        pub fn $encryptor(
            key: &[u8],
            nonce: &[u8],
            aad: &[u8],
            plaintext: &[u8],
        ) -> Result<Vec<u8, { MAX_CIPHERTEXT_SIZE + CCM_TAG_SIZE }>, Error> {
            aes_ccm_encrypt::<$core, $tag_size, $nonce_size>(key, nonce, aad, plaintext)
        }

        pub fn $decryptor(
            key: &[u8],
            nonce: &[u8],
            aad: &[u8],
            ciphertext: &[u8],
        ) -> Result<Vec<u8, MAX_PLAINTEXT_SIZE>, Error> {
            aes_ccm_decrypt::<$core, $tag_size, $nonce_size>(key, nonce, aad, ciphertext)
        }
    };
}

define_aes_ccm_impl!(
    aes128ccm_encrypt,
    aes128ccm_decrypt,
    Aes128,
    SupportedTagSize,
    SupportedNonceSize,
);
define_aes_ccm_impl!(
    aes192ccm_encrypt,
    aes192ccm_decrypt,
    Aes192,
    SupportedTagSize,
    SupportedNonceSize,
);
define_aes_ccm_impl!(
    aes256ccm_encrypt,
    aes256ccm_decrypt,
    Aes256,
    SupportedTagSize,
    SupportedNonceSize,
);

#[cfg(test)]
pub mod test {
    use super::*;

    const KEY128: &[u8; KEY128_SIZE] = b"Open sesame! ...";
    const KEY192: &[u8; KEY192_SIZE] = b"Open sesame! ... Please!";
    const KEY256: &[u8; KEY256_SIZE] = b"Or was it 'open quinoa' instead?";
    const NONCE: &[u8; CCM_NONCE_SIZE] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];
    const PLAINTEXT: &[u8] = b"Hello, World!";
    const AAD: &[u8] = b"Never gonna give you up, Never gonna let you down!";

    macro_rules! define_aes_ccm_encrypt_decrypt_test {
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

    define_aes_ccm_encrypt_decrypt_test!(
        test_aes128ccm_no_aad_encrypt_decrypt,
        aes128ccm_encrypt,
        aes128ccm_decrypt,
        KEY128,
        NONCE,
        &[],
        PLAINTEXT,
        [
            // ciphertext
            0xe5, 0x13, 0x1b, 0xda, 0x54, 0x91, 0xdb, 0xf9, 0x65, 0xd5, 0x76, 0x13, 0xb2,
            // tag
            0xc9, 0x39, 0xcf, 0x5f, 0x96, 0x81, 0xaf, 0x95, 0x18, 0x8a, 0xa2, 0xf9, 0x6e, 0x45,
            0xfa, 0xa8,
        ]
    );

    define_aes_ccm_encrypt_decrypt_test!(
        test_aes192ccm_no_aad_encrypt_decrypt,
        aes192ccm_encrypt,
        aes192ccm_decrypt,
        KEY192,
        NONCE,
        &[],
        PLAINTEXT,
        [
            // ciphertext
            0xdc, 0x6d, 0x32, 0x5a, 0xa3, 0x31, 0xab, 0xa2, 0xa6, 0xf9, 0x9f, 0x4d, 0x6a,
            // tag
            0x6c, 0x4d, 0xf5, 0x6f, 0x93, 0xd6, 0x7f, 0xe0, 0x15, 0x41, 0x10, 0x9a, 0xa2, 0x25,
            0xc3, 0xe4,
        ]
    );

    define_aes_ccm_encrypt_decrypt_test!(
        test_aes256ccm_no_aad_encrypt_decrypt,
        aes256ccm_encrypt,
        aes256ccm_decrypt,
        KEY256,
        NONCE,
        &[],
        PLAINTEXT,
        [
            // ciphertext
            0xed, 0xbe, 0x18, 0xc0, 0x34, 0xf1, 0xce, 0x6e, 0xfa, 0x18, 0x55, 0x10, 0xaa,
            // tag
            0xce, 0x01, 0xf6, 0xce, 0x27, 0x5a, 0x30, 0x7f, 0xf3, 0x1c, 0x3d, 0x63, 0x8c, 0x85,
            0x10, 0xac,
        ]
    );

    define_aes_ccm_encrypt_decrypt_test!(
        test_aes128ccm_with_aad_encrypt_decrypt,
        aes128ccm_encrypt,
        aes128ccm_decrypt,
        KEY128,
        NONCE,
        AAD,
        PLAINTEXT,
        [
            // ciphertext
            0xe5, 0x13, 0x1b, 0xda, 0x54, 0x91, 0xdb, 0xf9, 0x65, 0xd5, 0x76, 0x13, 0xb2,
            // tag
            0x2b, 0xa3, 0xe1, 0xa5, 0x9c, 0xa5, 0xed, 0x75, 0x2a, 0x2f, 0xa2, 0x8c, 0x66, 0xcb,
            0x38, 0x85,
        ]
    );

    define_aes_ccm_encrypt_decrypt_test!(
        test_aes192ccm_with_aad_encrypt_decrypt,
        aes192ccm_encrypt,
        aes192ccm_decrypt,
        KEY192,
        NONCE,
        AAD,
        PLAINTEXT,
        [
            // ciphertext
            0xdc, 0x6d, 0x32, 0x5a, 0xa3, 0x31, 0xab, 0xa2, 0xa6, 0xf9, 0x9f, 0x4d, 0x6a,
            // tag
            0x12, 0xec, 0xe0, 0x51, 0x6b, 0x83, 0x16, 0x73, 0x19, 0x1d, 0x5c, 0x3d, 0x3f, 0x12,
            0xe4, 0x0f,
        ]
    );

    define_aes_ccm_encrypt_decrypt_test!(
        test_aes256ccm_with_aad_encrypt_decrypt,
        aes256ccm_encrypt,
        aes256ccm_decrypt,
        KEY256,
        NONCE,
        AAD,
        PLAINTEXT,
        [
            // ciphertext
            0xed, 0xbe, 0x18, 0xc0, 0x34, 0xf1, 0xce, 0x6e, 0xfa, 0x18, 0x55, 0x10, 0xaa,
            // tag
            0x11, 0xd1, 0x9f, 0xf1, 0xa8, 0x90, 0xd7, 0x75, 0x13, 0xf6, 0xff, 0x31, 0x7a, 0xc0,
            0x3b, 0x57,
        ]
    );

    macro_rules! define_aes_ccm_errors_test {
        (
        $test_name:ident,
        $encryptor:tt,
        $decryptor:tt,
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
                        $encryptor(&wrong_key, $nonce, &[], $plaintext),
                        Err(Error::InvalidKeySize)
                    );
                    let mut zeros: Vec<u8, { MAX_PLAINTEXT_SIZE + CCM_TAG_SIZE }> = Vec::new();
                    zeros
                        .resize($plaintext.len() + CCM_TAG_SIZE, 0)
                        .expect("Allocation error");
                    assert_eq!(
                        $decryptor(&wrong_key, $nonce, &[], &zeros),
                        Err(Error::InvalidKeySize)
                    );
                }

                for size in [0, 1, 7, 8, 9, 10, 11, 12, 16, 32] {
                    let mut wrong_nonce: Vec<u8, 32> = Vec::new();
                    wrong_nonce.resize(size, 0).expect("Allocation error");
                    assert_eq!(
                        $encryptor($key, &wrong_nonce, &[], $plaintext),
                        Err(Error::InvalidIvSize)
                    );
                    let mut zeros: Vec<u8, { MAX_PLAINTEXT_SIZE + CCM_TAG_SIZE }> = Vec::new();
                    zeros
                        .resize($plaintext.len() + CCM_TAG_SIZE, 0)
                        .expect("Allocation error");
                    assert_eq!(
                        $decryptor($key, &wrong_nonce, &[], &zeros),
                        Err(Error::InvalidIvSize)
                    );
                }

                for size in [0, 1, CCM_TAG_SIZE - 1] {
                    const MAX_SIZE: usize = CCM_TAG_SIZE - 1;
                    let mut wrong_ciphertext: Vec<u8, MAX_SIZE> = Vec::new();
                    wrong_ciphertext.resize(size, 0).expect("Allocation error");
                    assert_eq!(
                        $decryptor($key, $nonce, &[], &wrong_ciphertext),
                        Err(Error::InvalidBufferSize)
                    );
                }

                let mut corrupted_ciphertext =
                    $encryptor($key, $nonce, &[], $plaintext).expect("encryption error");
                corrupted_ciphertext[0] += 1;
                assert_eq!(
                    $decryptor($key, $nonce, &[], &corrupted_ciphertext),
                    Err(Error::Decrypt)
                );
            }
        };
    }

    define_aes_ccm_errors_test!(
        test_aes128ccm_errors,
        aes128ccm_encrypt,
        aes128ccm_decrypt,
        KEY128,
        NONCE,
        PLAINTEXT,
        [0, 1, 8, 24, 32, 128]
    );
    define_aes_ccm_errors_test!(
        test_aes192ccm_errors,
        aes192ccm_encrypt,
        aes192ccm_decrypt,
        KEY192,
        NONCE,
        PLAINTEXT,
        [0, 1, 8, 16, 32, 192]
    );

    define_aes_ccm_errors_test!(
        test_aes256ccm_errors,
        aes256ccm_encrypt,
        aes256ccm_decrypt,
        KEY256,
        NONCE,
        PLAINTEXT,
        [0, 1, 8, 16, 24, 256]
    );
}
