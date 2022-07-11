use aes::{Aes128, Aes192, Aes256};
use cmac::{
    digest::{crypto_common::typenum::Unsigned, OutputSizeUser},
    Cmac, Mac,
};

pub use crate::crypto::aes::{KEY128_SIZE, KEY192_SIZE, KEY256_SIZE};

/// Size of the output in bytes for AES-CMAC algorithms.
pub const AES_CMAC_OUTPUT_SIZE: usize = <Cmac<Aes128> as OutputSizeUser>::OutputSize::USIZE;

/// AES-CMAC errors.
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Error {
    /// Invalid size of the key.
    InvalidKeySize,
}

macro_rules! define_aes_cmac_impl {
    (
        $cmac:ident,
        $core:tt
    ) => {
        pub fn $cmac(key: &[u8], message: &[u8]) -> Result<[u8; AES_CMAC_OUTPUT_SIZE], Error> {
            let mut mac = Cmac::<$core>::new_from_slice(key).map_err(|_| Error::InvalidKeySize)?;
            mac.update(message);
            Ok(mac.finalize().into_bytes().into())
        }
    };
}

define_aes_cmac_impl!(aes128_cmac, Aes128);
define_aes_cmac_impl!(aes192_cmac, Aes192);
define_aes_cmac_impl!(aes256_cmac, Aes256);

#[cfg(test)]
pub mod test {
    use super::*;
    use heapless::Vec;

    const KEY128: &[u8; KEY128_SIZE] = b"Open sesame! ...";
    const KEY192: &[u8; KEY192_SIZE] = b"Open sesame! ... Please!";
    const KEY256: &[u8; KEY256_SIZE] = b"Or was it 'open quinoa' instead?";
    const MESSAGE: &[u8] = b"This world doesn't need a hero. It needs a professional.";

    macro_rules! define_aes_cmac_input_output_test {
        (
        $test_name:ident,
        $cmac:tt,
        $key:tt,
        $message:tt,
        $mac:tt
    ) => {
            #[test]
            fn $test_name() {
                let mac = $cmac($key, MESSAGE).expect("AES-CMAC error");
                assert_eq!(mac, $mac, "MAC mismatch");
            }
        };
    }

    define_aes_cmac_input_output_test!(
        test_aes128_cmac_input_output,
        aes128_cmac,
        KEY128,
        MESSAGE,
        [
            0xdc, 0x74, 0x0c, 0x8a, 0x89, 0x51, 0x3d, 0x39, 0x42, 0xc6, 0xe4, 0xef, 0x86, 0xf7,
            0xda, 0x46,
        ]
    );

    define_aes_cmac_input_output_test!(
        test_aes192_cmac_input_output,
        aes192_cmac,
        KEY192,
        MESSAGE,
        [
            0xd2, 0xf6, 0x38, 0x79, 0x92, 0x1e, 0x28, 0x33, 0xad, 0x2e, 0xe2, 0x66, 0xf5, 0xad,
            0x87, 0xb7,
        ]
    );

    define_aes_cmac_input_output_test!(
        test_aes256_cmac_input_output,
        aes256_cmac,
        KEY256,
        MESSAGE,
        [
            0xc7, 0xf7, 0x48, 0x38, 0xfc, 0x35, 0xac, 0x19, 0xfd, 0x7c, 0xa1, 0xb8, 0x55, 0x3d,
            0x5f, 0xe9,
        ]
    );

    macro_rules! define_aes_cmac_wrong_key_test {
        (
        $test: ident,
        $cmac: tt,
        $wrong_key_sizes: tt
    ) => {
            #[test]
            pub fn $test() {
                for size in $wrong_key_sizes {
                    const MAX_SIZE: usize = 256;
                    let mut wrong_key: Vec<u8, MAX_SIZE> = Vec::new();
                    wrong_key.resize(size, 0).expect("Allocation error");
                    assert_eq!($cmac(&wrong_key, MESSAGE), Err(Error::InvalidKeySize));
                }
            }
        };
    }

    define_aes_cmac_wrong_key_test!(
        test_aes128_cmac_wrong_key,
        aes128_cmac,
        [0, 1, 8, 24, 32, 128]
    );
    define_aes_cmac_wrong_key_test!(
        test_aes192_cmac_wrong_key,
        aes192_cmac,
        [0, 1, 8, 16, 32, 192]
    );
    define_aes_cmac_wrong_key_test!(
        test_aes256_cmac_wrong_key,
        aes256_cmac,
        [0, 1, 8, 16, 24, 256]
    );
}
