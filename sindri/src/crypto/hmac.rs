use crate::crypto::hash::{SHA256_SIZE, SHA384_SIZE, SHA512_SIZE};
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384, Sha512};

// Minimal size of HMAC-SHA-256 key in bytes.
pub const MIN_HMAC_SHA256_KEY_SIZE: usize = SHA256_SIZE;
// Size of HMAC-SHA-384 key in bytes.
pub const MIN_HMAC_SHA384_KEY_SIZE: usize = SHA384_SIZE;
// Size of HMAC-SHA-512 key in bytes.
pub const MIN_HMAC_SHA512_KEY_SIZE: usize = SHA512_SIZE;

/// HMAC errors
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Error {
    /// Invalid size of the key.
    InvalidKeySize,
}

macro_rules! define_hmac_impl {
    (
        $hmac:ident,
        $core:tt,
        $digest_size: expr
    ) => {
        pub fn $hmac(key: &[u8], message: &[u8]) -> Result<[u8; $digest_size], Error> {
            if key.len() < $digest_size {
                return Err(Error::InvalidKeySize);
            }

            let mut hmac = Hmac::<$core>::new_from_slice(key).map_err(|_| Error::InvalidKeySize)?;
            hmac.update(message);
            Ok(hmac.finalize().into_bytes().into())
        }
    };
}

define_hmac_impl!(hmac_sha256, Sha256, SHA256_SIZE);
define_hmac_impl!(hmac_sha384, Sha384, SHA384_SIZE);
define_hmac_impl!(hmac_sha512, Sha512, SHA512_SIZE);

#[cfg(test)]
pub mod test {
    use super::*;
    use heapless::Vec;

    const KEY: &[u8] = b"The ability to speak does not make you intelligent. Qui-Gon Jinn.";
    const MESSAGE: &[u8] = b"Jar Jar Binks";

    macro_rules! define_hmac_input_output_test {
        (
        $test: ident,
        $hmac: tt,
        $output: expr
    ) => {
            #[test]
            pub fn $test() {
                let output = $hmac(KEY, MESSAGE).expect("HMAC failed");
                assert_eq!(&output, $output, "output mismatch");
            }
        };
    }

    define_hmac_input_output_test!(
        test_hmac_sha256_input_output,
        hmac_sha256,
        &[
            0xc3, 0x72, 0x87, 0x54, 0x54, 0x94, 0x8e, 0xcb, 0xbf, 0x46, 0xf3, 0xa6, 0x98, 0xd8,
            0x75, 0x24, 0x7e, 0xc1, 0xbb, 0x59, 0x42, 0x50, 0xa0, 0xa6, 0x32, 0x8b, 0x87, 0xf6,
            0x86, 0x5f, 0x0e, 0xf0,
        ]
    );
    define_hmac_input_output_test!(
        test_hmac_sha384_input_output,
        hmac_sha384,
        &[
            0x7c, 0x46, 0xa1, 0xe9, 0x44, 0xe0, 0xf2, 0x73, 0x21, 0x4d, 0xc7, 0xcd, 0x91, 0x77,
            0x85, 0xdb, 0x2a, 0xc3, 0x87, 0xeb, 0x97, 0xfc, 0x95, 0x82, 0x21, 0xef, 0x87, 0x1e,
            0xc4, 0xed, 0x1d, 0xce, 0x2c, 0xdd, 0x5a, 0x30, 0x32, 0xe0, 0xe2, 0x47, 0x19, 0x47,
            0x02, 0x77, 0x4e, 0xa9, 0x03, 0xd5,
        ]
    );
    define_hmac_input_output_test!(
        test_hmac_sha512_input_output,
        hmac_sha512,
        &[
            0xe1, 0x78, 0x85, 0xc3, 0xe5, 0x5a, 0x3e, 0x7f, 0xc4, 0xfa, 0x3b, 0x7d, 0xa1, 0xaa,
            0x62, 0x0b, 0x42, 0xd1, 0xf2, 0x91, 0x38, 0xbc, 0xd9, 0x6b, 0x9a, 0x8d, 0xd1, 0x41,
            0xea, 0x6c, 0xe6, 0x5c, 0xd4, 0x96, 0x42, 0xc7, 0x6c, 0x3c, 0x87, 0x73, 0x92, 0x65,
            0x50, 0x4c, 0xd1, 0xa4, 0x29, 0xd2, 0x8d, 0x78, 0x50, 0xa4, 0x29, 0xfe, 0x81, 0x03,
            0x5d, 0x14, 0x34, 0x10, 0x7f, 0x3f, 0x83, 0x90,
        ]
    );

    macro_rules! define_hmac_wrong_key_test {
        (
        $test: ident,
        $hmac: tt,
        $wrong_key_sizes: tt
    ) => {
            #[test]
            pub fn $test() {
                for size in $wrong_key_sizes {
                    const MAX_SIZE: usize = 512;
                    let mut wrong_key: Vec<u8, MAX_SIZE> = Vec::new();
                    wrong_key.resize(size, 0).expect("Allocation error");
                    assert_eq!($hmac(&wrong_key, MESSAGE), Err(Error::InvalidKeySize));
                }
            }
        };
    }

    define_hmac_wrong_key_test!(test_hmac_sha256_errors, hmac_sha256, [0, 1, 13]);
    define_hmac_wrong_key_test!(test_hmac_sha384_errors, hmac_sha384, [0, 1, 13, 32]);
    define_hmac_wrong_key_test!(test_hmac_sha512_errors, hmac_sha512, [0, 1, 13, 32, 48]);
}
