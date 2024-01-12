use super::CMAC_TAG_SIZE;
use crate::crypto::Error;
use aes::{
    cipher::crypto_common::KeyInit,
    cipher::{
        typenum::{consts::U256, IsLess, Le, NonZero},
        Block, BlockCipher, BlockEncryptMut,
    },
    Aes128, Aes192, Aes256,
};
use cmac::{Cmac, Mac};
use dbl::Dbl;

fn check_tag_size(tag: &[u8]) -> Result<(), Error> {
    if tag.len() != CMAC_TAG_SIZE {
        return Err(Error::InvalidTagSize);
    }

    Ok(())
}

fn aes_cmac_calculate<C>(key: &[u8], message: &[u8], tag: &mut [u8]) -> Result<(), Error>
where
    C: BlockCipher + BlockEncryptMut + Clone,
    Block<C>: Dbl,
    C::BlockSize: IsLess<U256>,
    Le<C::BlockSize, U256>: NonZero,
    Cmac<C>: KeyInit,
{
    check_tag_size(tag)?;

    let mut cmac =
        <Cmac<C> as Mac>::new_from_slice(key).map_err(|_| Error::InvalidSymmetricKeySize)?;
    cmac.update(message);

    tag.copy_from_slice(&cmac.finalize().into_bytes());

    Ok(())
}

fn aes_cmac_verify<C>(key: &[u8], message: &[u8], tag: &[u8]) -> Result<bool, Error>
where
    C: BlockCipher + BlockEncryptMut + Clone,
    Block<C>: Dbl,
    C::BlockSize: IsLess<U256>,
    Le<C::BlockSize, U256>: NonZero,
    Cmac<C>: KeyInit,
{
    check_tag_size(tag)?;

    let mut cmac =
        <Cmac<C> as Mac>::new_from_slice(key).map_err(|_| Error::InvalidSymmetricKeySize)?;
    cmac.update(message);

    Ok(cmac.verify(tag.into()).is_ok())
}

macro_rules! define_aes_cmac_impl {
    (
        $core:tt,
        $calculate:ident,
        $verify:ident,
        $key_size:ident,
        $doc:expr
    ) => {
        #[doc = concat!($doc, " calculate tag.")]
        ///
        /// # Arguments
        ///
        /// * `key`: A slice containing key bytes.
        #[doc = concat!("The key slice has to be `", stringify!($key_size), "` bytes long.")]
        /// * `message`: A slice containing the message to calculate the tag for.
        /// * `tag`: A mutable slice where the computed tag will be stored.
        ///   The tag slice length has to be `CMAC_TAG_SIZE` bytes long.
        ///
        /// # Errors
        ///
        /// The function returns an error if:
        /// * `InvalidSymmetricKeySize`:
        #[doc = concat!("The length of the `key` is not `", stringify!($key_size), "` bytes.")]
        /// * `InvalidTagSize`: The length of the `tag` is not `CMAC_TAG_SIZE` bytes.
        pub fn $calculate(key: &[u8], message: &[u8], tag: &mut [u8]) -> Result<(), Error> {
            aes_cmac_calculate::<$core>(key, message, tag)
        }

        #[doc = concat!($doc, " verify tag.")]
        ///
        /// # Arguments
        ///
        /// * `key`: A slice containing key bytes.
        #[doc = concat!("The key slice has to be `", stringify!($key_size), "` bytes long.")]
        /// * `message`: A slice containing the message to verify.
        /// * `tag`: A slice containing the tag to verify.
        ///   The tag slice length has to be `CMAC_TAG_SIZE` bytes long.
        ///
        /// # Returns
        ///
        /// Verification result.
        ///
        /// # Errors
        ///
        /// The function returns an error if:
        /// * `InvalidSymmetricKeySize`:
        #[doc = concat!("The length of the `key` is not `", stringify!($key_size), "` bytes.")]
        /// * `InvalidTagSize`: The length of the `tag` is not `CMAC_TAG_SIZE` bytes.
        pub fn $verify(key: &[u8], message: &[u8], tag: &[u8]) -> Result<bool, Error> {
            aes_cmac_verify::<$core>(key, message, tag)
        }
    };
}

define_aes_cmac_impl!(
    Aes128,
    aes128_cmac_calculate,
    aes128_cmac_verify,
    KEY128_SIZE,
    "AES128-CMAC"
);
define_aes_cmac_impl!(
    Aes192,
    aes192_cmac_calculate,
    aes192_cmac_verify,
    KEY192_SIZE,
    "AES192-CMAC"
);
define_aes_cmac_impl!(
    Aes256,
    aes256_cmac_calculate,
    aes256_cmac_verify,
    KEY256_SIZE,
    "AES256-CMAC"
);

#[cfg(test)]
mod test {
    use super::*;
    use crate::crypto::aes::{test::*, CMAC_TAG_SIZE, KEY128_SIZE, KEY192_SIZE, KEY256_SIZE};

    macro_rules! define_aes_cmac_calculate_verify_test {
        (
        $test_name:ident,
        $calculate:ident,
        $verify:ident,
        $key:tt,
        $message:tt,
        $expected_tag:tt
    ) => {
            #[test]
            fn $test_name() {
                let mut tag = [0u8; CMAC_TAG_SIZE];
                $calculate($key, $message, &mut tag).expect("failed to calculate CMAC tag");
                assert_eq!(tag, $expected_tag, "unexpected tag value");

                let result = $verify($key, $message, &tag).expect("failed to verify CMAC tag");
                assert!(result, "correct tag was not verified");

                tag[0] ^= 0x1;

                let result = $verify($key, $message, &tag).expect("failed to verify CMAC tag");
                assert!(!result, "incorrect tag was verified");
            }
        };
    }

    define_aes_cmac_calculate_verify_test!(
        aes128_cmac_calculate_verify_test,
        aes128_cmac_calculate,
        aes128_cmac_verify,
        KEY128,
        PLAINTEXT,
        [
            0x26, 0xfd, 0x0e, 0x67, 0x93, 0x47, 0xa2, 0x5d, 0xd7, 0xb1, 0xe1, 0x9a, 0xf8, 0xbb,
            0xd4, 0x7e
        ]
    );
    define_aes_cmac_calculate_verify_test!(
        aes192_cmac_calculate_verify_test,
        aes192_cmac_calculate,
        aes192_cmac_verify,
        KEY192,
        PLAINTEXT,
        [
            0x35, 0x66, 0xb0, 0xf1, 0x9c, 0xc7, 0x84, 0x20, 0x88, 0x9b, 0xcd, 0xfb, 0x65, 0xc0,
            0x04, 0x4a
        ]
    );
    define_aes_cmac_calculate_verify_test!(
        aes256_cmac_calculate_verify_test,
        aes256_cmac_calculate,
        aes256_cmac_verify,
        KEY256,
        PLAINTEXT,
        [
            0xa6, 0x02, 0xd7, 0x9d, 0xbc, 0x67, 0xb2, 0xc8, 0x16, 0xd7, 0x25, 0x28, 0xb3, 0xca,
            0x6e, 0xb8,
        ]
    );

    macro_rules! define_aes_cmac_error_test {
        (
        $test_name:ident,
        $calculate:ident,
        $verify:ident,
        $key_size:ident
    ) => {
            #[test]
            fn $test_name() {
                let mut buffer = [0u8; 64];

                // Invalid key size.
                for size in [0, 1, 16, 24, 32, 48, 64] {
                    if size == $key_size {
                        continue;
                    }
                    let invalid_key = &buffer[..size];

                    assert_eq!(
                        $calculate(invalid_key, PLAINTEXT, &mut [0u8; CMAC_TAG_SIZE]),
                        Err(Error::InvalidSymmetricKeySize)
                    );

                    assert_eq!(
                        $verify(invalid_key, PLAINTEXT, &mut [0u8; CMAC_TAG_SIZE]),
                        Err(Error::InvalidSymmetricKeySize)
                    );
                }

                // Invalid tag size.
                for size in [0, 1, 15, 17, 24, 32, 48, 64] {
                    let invalid_tag = &mut buffer[..size];
                    assert_eq!(
                        $calculate(&[0u8; $key_size], PLAINTEXT, invalid_tag),
                        Err(Error::InvalidTagSize)
                    );

                    assert_eq!(
                        $verify(&[0u8; $key_size], PLAINTEXT, invalid_tag),
                        Err(Error::InvalidTagSize)
                    );
                }
            }
        };
    }

    define_aes_cmac_error_test!(
        aes128_cmac_error_test,
        aes128_cmac_calculate,
        aes128_cmac_verify,
        KEY128_SIZE
    );
    define_aes_cmac_error_test!(
        aes192_cmac_error_test,
        aes192_cmac_calculate,
        aes192_cmac_verify,
        KEY192_SIZE
    );
    define_aes_cmac_error_test!(
        aes256_cmac_error_test,
        aes256_cmac_calculate,
        aes256_cmac_verify,
        KEY256_SIZE
    );
}
