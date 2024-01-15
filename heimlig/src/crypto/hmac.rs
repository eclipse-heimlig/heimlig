use crate::crypto::Error;
use hmac::{
    digest::{
        block_buffer::Eager,
        core_api::{BlockSizeUser, BufferKindUser, CoreProxy, FixedOutputCore, UpdateCore},
        typenum::{IsLess, Le, NonZero, Unsigned, U256},
        HashMarker, OutputSizeUser,
    },
    Hmac, Mac,
};
use sha2::{Sha256, Sha384, Sha512};
use sha3::{Sha3_256, Sha3_384, Sha3_512};

type TagSize<D> = <D as OutputSizeUser>::OutputSize;

fn check_tag_size<D>(tag: &[u8]) -> Result<(), Error>
where
    D: OutputSizeUser,
{
    if tag.len() != TagSize::<D>::USIZE {
        return Err(Error::InvalidTagSize);
    }

    Ok(())
}

fn hmac_calculate<D>(key: &[u8], message: &[u8], tag: &mut [u8]) -> Result<(), Error>
where
    D: CoreProxy + OutputSizeUser,
    D::Core: HashMarker
        + UpdateCore
        + FixedOutputCore
        + BufferKindUser<BufferKind = Eager>
        + Default
        + Clone,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    check_tag_size::<D>(tag)?;

    let mut core = Hmac::<D>::new_from_slice(key).expect("HMAC supports any key size");
    core.update(message);

    tag.copy_from_slice(&core.finalize().into_bytes());

    Ok(())
}

fn hmac_verify<D>(key: &[u8], message: &[u8], tag: &[u8]) -> Result<bool, Error>
where
    D: CoreProxy + OutputSizeUser,
    D::Core: HashMarker
        + UpdateCore
        + FixedOutputCore
        + BufferKindUser<BufferKind = Eager>
        + Default
        + Clone,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    check_tag_size::<D>(tag)?;

    let mut core = Hmac::<D>::new_from_slice(key).expect("HMAC supports any key size");
    core.update(message);

    Ok(core.verify(tag.into()).is_ok())
}

macro_rules! define_hmac_impl {
    (
        $digest:tt,
        $calculate:ident,
        $verify:ident,
        $tag_size:ident,
        $doc:expr
    ) => {
        #[doc = concat!("HMAC-",$doc, "tag size in bytes.")]
        pub const $tag_size: usize = TagSize::<$digest>::USIZE;

        #[doc = concat!("HMAC-",$doc, " calculation.")]
        ///
        /// # Arguments
        ///
        /// * `key`: A slice containing key bytes.
        /// * `message`: A slice containing the message to calculate the HMAC for.
        /// * `tag`: A mutable slice where the computed tag will be stored.
        #[doc = concat!("The `tag` slice length has to be `", stringify!($tag_size), "` bytes long).")]
        ///
        /// # Errors
        ///
        /// The function returns an error if:
        /// * `InvalidTagSize`:
        #[doc = concat!("The `tag` slice length is not `", stringify!($tag_size), "` bytes long.")]
        pub fn $calculate(key: &[u8], message: &[u8], tag: &mut [u8]) -> Result<(), Error> {
            hmac_calculate::<$digest>(key, message, tag)
        }

        #[doc = concat!("HMAC-",$doc, " verification.")]
        ///
        /// # Arguments
        ///
        /// * `key`: A slice containing key bytes.
        /// * `message`: A slice containing the message to veify.
        /// * `tag`: A slice containing the HMAC to verify.
        #[doc = concat!("The `tag` slice length has to be `", stringify!($tag_size), "` bytes long).")]
        ///
        /// # Returns
        ///
        /// Verification result.
        ///
        /// # Errors
        ///
        /// The function returns an error if:
        /// * `InvalidTagSize`:
        #[doc = concat!("The `tag` slice length is not `", stringify!($tag_size), "` bytes long.")]
        pub fn $verify(key: &[u8], message: &[u8], tag: &[u8]) -> Result<bool, Error> {
            hmac_verify::<$digest>(key, message, tag)
        }
    };
}

define_hmac_impl!(
    Sha256,
    hmac_sha2_256_calculate,
    hmac_sha2_256_verify,
    HMAC_SHA2_256_SIZE,
    "SHA-256"
);
define_hmac_impl!(
    Sha384,
    hmac_sha2_384_calculate,
    hmac_sha2_384_verify,
    HMAC_SHA2_384_SIZE,
    "SHA-384"
);
define_hmac_impl!(
    Sha512,
    hmac_sha2_512_calculate,
    hmac_sha2_512_verify,
    HMAC_SHA2_512_SIZE,
    "SHA-512"
);
define_hmac_impl!(
    Sha3_256,
    hmac_sha3_256_calculate,
    hmac_sha3_256_verify,
    HMAC_SHA3_256_SIZE,
    "SHA3-256"
);
define_hmac_impl!(
    Sha3_384,
    hmac_sha3_384_calculate,
    hmac_sha3_384_verify,
    HMAC_SHA3_384_SIZE,
    "SHA3-384"
);
define_hmac_impl!(
    Sha3_512,
    hmac_sha3_512_calculate,
    hmac_sha3_512_verify,
    HMAC_SHA3_512_SIZE,
    "SHA3-512"
);

#[cfg(test)]
mod test {
    use super::*;

    pub const KEY: &[u8; 7] = b"Gandalf";
    pub const MESSAGE: &[u8; 67] =
        b"All we have to decide is what to do with the time that is given us.";

    macro_rules! define_hmac_calculate_verify_test {
        (
        $test_name:ident,
        $calculate:ident,
        $verify:ident,
        $tag_size:ident,
        $key:tt,
        $message:tt,
        $expected_tag:tt
    ) => {
            #[test]
            fn $test_name() {
                let mut tag = [0u8; $tag_size];
                $calculate($key, $message, &mut tag).expect("failed to calculate the tag");
                assert_eq!(tag, $expected_tag, "unexpected tag value");

                let result = $verify($key, $message, &tag).expect("failed to verify the tag");
                assert!(result, "the correct tag was not verified");

                tag[0] ^= 0x1;

                let result = $verify($key, $message, &tag).expect("failed to verify the tag");
                assert!(!result, "the incorrect tag was verified");
            }
        };
    }

    define_hmac_calculate_verify_test!(
        hmac_sha256_calculate_verify_test,
        hmac_sha2_256_calculate,
        hmac_sha2_256_verify,
        HMAC_SHA2_256_SIZE,
        KEY,
        MESSAGE,
        [
            0x28, 0xba, 0xaf, 0x70, 0x52, 0x45, 0xf7, 0x56, 0x67, 0xa7, 0x74, 0x30, 0xa0, 0x07,
            0x11, 0x91, 0x88, 0xec, 0x4a, 0x84, 0x6d, 0xd5, 0xc0, 0x9a, 0xc8, 0xbb, 0xad, 0x7f,
            0x6b, 0xa9, 0x21, 0x11,
        ]
    );
    define_hmac_calculate_verify_test!(
        hmac_sha384_calculate_verify_test,
        hmac_sha2_384_calculate,
        hmac_sha2_384_verify,
        HMAC_SHA2_384_SIZE,
        KEY,
        MESSAGE,
        [
            0xc2, 0xe6, 0xe1, 0x00, 0x07, 0x84, 0x10, 0x91, 0x55, 0xfb, 0x65, 0x46, 0x55, 0x5e,
            0xd0, 0x37, 0xbf, 0x54, 0x11, 0x3d, 0xdb, 0x57, 0x7f, 0xf3, 0xc1, 0xb1, 0x38, 0x06,
            0x51, 0x77, 0x2c, 0x95, 0xb2, 0x7a, 0x36, 0x31, 0xf8, 0x64, 0xa7, 0x4c, 0xbc, 0xc4,
            0xe4, 0xa4, 0x44, 0x1d, 0x32, 0x5e,
        ]
    );
    define_hmac_calculate_verify_test!(
        hmac_sha512_calculate_verify_test,
        hmac_sha2_512_calculate,
        hmac_sha2_512_verify,
        HMAC_SHA2_512_SIZE,
        KEY,
        MESSAGE,
        [
            0x4c, 0xe3, 0x0c, 0x67, 0xa8, 0xe5, 0xbb, 0xe7, 0xd2, 0x15, 0xc7, 0x36, 0xe2, 0x98,
            0x78, 0xc0, 0x7a, 0x27, 0x2b, 0x6c, 0x33, 0x3d, 0x42, 0x19, 0x92, 0x84, 0x51, 0xd3,
            0x6b, 0x4d, 0xe3, 0xe2, 0x30, 0xa1, 0x39, 0xcb, 0x72, 0x26, 0x3d, 0x2a, 0x40, 0xc9,
            0x23, 0x8d, 0x50, 0xca, 0xe7, 0x90, 0x90, 0xe3, 0x9a, 0xba, 0xbb, 0x97, 0x3b, 0x38,
            0x2f, 0xe4, 0x70, 0x24, 0xaa, 0xd9, 0xa7, 0xe5,
        ]
    );
    define_hmac_calculate_verify_test!(
        hmac_sha3_256_calculate_verify_test,
        hmac_sha3_256_calculate,
        hmac_sha3_256_verify,
        HMAC_SHA3_256_SIZE,
        KEY,
        MESSAGE,
        [
            0x0b, 0x3b, 0xd9, 0x10, 0xfe, 0x68, 0x01, 0x9c, 0x4b, 0xad, 0xd6, 0x07, 0xa7, 0x58,
            0xa5, 0xd4, 0xab, 0x83, 0x6f, 0xb1, 0x63, 0x8a, 0xce, 0x7f, 0x84, 0xef, 0x61, 0xf2,
            0x96, 0x6f, 0x50, 0x13,
        ]
    );
    define_hmac_calculate_verify_test!(
        hmac_sha3_384_calculate_verify_test,
        hmac_sha3_384_calculate,
        hmac_sha3_384_verify,
        HMAC_SHA3_384_SIZE,
        KEY,
        MESSAGE,
        [
            0xbc, 0x3b, 0x5f, 0x1b, 0xce, 0x29, 0x86, 0x9b, 0x68, 0xec, 0x14, 0x2d, 0xeb, 0xf3,
            0x07, 0xc7, 0x2c, 0x4c, 0xe1, 0x5e, 0x6a, 0x89, 0x85, 0x4d, 0xbd, 0x34, 0xae, 0x1a,
            0x91, 0x87, 0xbf, 0xe6, 0xfc, 0x2f, 0x9d, 0xe3, 0x41, 0x17, 0xf1, 0x0f, 0xbb, 0xa0,
            0x8e, 0x24, 0x8a, 0xa2, 0xe8, 0x37,
        ]
    );
    define_hmac_calculate_verify_test!(
        hmac_sha3_512_calculate_verify_test,
        hmac_sha3_512_calculate,
        hmac_sha3_512_verify,
        HMAC_SHA3_512_SIZE,
        KEY,
        MESSAGE,
        [
            0x39, 0x04, 0x24, 0xb8, 0x25, 0x3f, 0x1b, 0x52, 0xfb, 0x0d, 0x37, 0x8c, 0x30, 0x62,
            0xb1, 0xcc, 0x6a, 0x23, 0x79, 0x1e, 0xe5, 0xff, 0x55, 0x28, 0x89, 0x14, 0x93, 0x19,
            0xa8, 0x94, 0x92, 0xa9, 0x9a, 0xde, 0xa6, 0xa3, 0xe5, 0xb6, 0x1d, 0x50, 0x0a, 0x0e,
            0xcb, 0xca, 0x1c, 0x72, 0x09, 0xd1, 0xbe, 0x4a, 0x68, 0x42, 0x28, 0x42, 0xeb, 0x94,
            0x9a, 0x31, 0x79, 0x37, 0x72, 0x33, 0x2c, 0x20,
        ]
    );

    macro_rules! define_hmac_error_test {
        (
        $test_name:ident,
        $calculate:ident,
        $verify:ident,
        $tag_size:ident
    ) => {
            #[test]
            fn $test_name() {
                let mut buffer = [0u8; 128];

                // Invalid tag size.
                for size in [0, 1, 16, 24, 32, 48, 64, 128] {
                    if size == $tag_size {
                        continue;
                    }

                    let invalid_tag = &mut buffer[..size];
                    assert_eq!(
                        $calculate(KEY, MESSAGE, invalid_tag),
                        Err(Error::InvalidTagSize)
                    );

                    assert_eq!(
                        $verify(KEY, MESSAGE, invalid_tag),
                        Err(Error::InvalidTagSize)
                    );
                }
            }
        };
    }

    define_hmac_error_test!(
        hmac_sha2_256_error_test,
        hmac_sha2_256_calculate,
        hmac_sha2_256_verify,
        HMAC_SHA2_256_SIZE
    );
    define_hmac_error_test!(
        hmac_sha2_384_error_test,
        hmac_sha2_384_calculate,
        hmac_sha2_384_verify,
        HMAC_SHA2_384_SIZE
    );
    define_hmac_error_test!(
        hmac_sha2_512_error_test,
        hmac_sha2_512_calculate,
        hmac_sha2_512_verify,
        HMAC_SHA2_512_SIZE
    );
    define_hmac_error_test!(
        hmac_sha3_256_error_test,
        hmac_sha3_256_calculate,
        hmac_sha3_256_verify,
        HMAC_SHA3_256_SIZE
    );
    define_hmac_error_test!(
        hmac_sha3_384_error_test,
        hmac_sha3_384_calculate,
        hmac_sha3_384_verify,
        HMAC_SHA3_384_SIZE
    );
    define_hmac_error_test!(
        hmac_sha3_512_error_test,
        hmac_sha3_512_calculate,
        hmac_sha3_512_verify,
        HMAC_SHA3_512_SIZE
    );
}
