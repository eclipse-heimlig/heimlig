use sha2::{
    digest::crypto_common::{typenum::Unsigned, OutputSizeUser},
    Digest, Sha256, Sha384, Sha512,
};

// Size of SHA-256 digest in bytes.
pub const SHA256_SIZE: usize = <Sha256 as OutputSizeUser>::OutputSize::USIZE;
// Size of SHA-384 digest in bytes.
pub const SHA384_SIZE: usize = <Sha384 as OutputSizeUser>::OutputSize::USIZE;
// Size of SHA-512 digest in bytes.
pub const SHA512_SIZE: usize = <Sha512 as OutputSizeUser>::OutputSize::USIZE;

pub fn sha256(input: &[u8]) -> [u8; SHA256_SIZE] {
    Sha256::digest(input).into()
}

pub fn sha384(input: &[u8]) -> [u8; SHA384_SIZE] {
    Sha384::digest(input).into()
}

pub fn sha512(input: &[u8]) -> [u8; SHA512_SIZE] {
    Sha512::digest(input).into()
}

#[cfg(test)]
pub mod test {
    use super::*;

    const INPUT: &[u8] = b"Hello, World!";

    macro_rules! define_hash_test_input_output_impl {
        (
        $test: ident,
        $hash: tt,
        $output: expr
    ) => {
            #[test]
            pub fn $test() {
                let output = $hash(INPUT);
                assert_eq!(&output, $output, "output mismatch");
            }
        };
    }

    define_hash_test_input_output_impl!(
        test_sha256_input_output,
        sha256,
        &[
            0xdf, 0xfd, 0x60, 0x21, 0xbb, 0x2b, 0xd5, 0xb0, 0xaf, 0x67, 0x62, 0x90, 0x80, 0x9e,
            0xc3, 0xa5, 0x31, 0x91, 0xdd, 0x81, 0xc7, 0xf7, 0x0a, 0x4b, 0x28, 0x68, 0x8a, 0x36,
            0x21, 0x82, 0x98, 0x6f,
        ]
    );
    define_hash_test_input_output_impl!(
        test_sha384_input_output,
        sha384,
        &[
            0x54, 0x85, 0xcc, 0x9b, 0x33, 0x65, 0xb4, 0x30, 0x5d, 0xfb, 0x4e, 0x83, 0x37, 0xe0,
            0xa5, 0x98, 0xa5, 0x74, 0xf8, 0x24, 0x2b, 0xf1, 0x72, 0x89, 0xe0, 0xdd, 0x6c, 0x20,
            0xa3, 0xcd, 0x44, 0xa0, 0x89, 0xde, 0x16, 0xab, 0x4a, 0xb3, 0x08, 0xf6, 0x3e, 0x44,
            0xb1, 0x17, 0x0e, 0xb5, 0xf5, 0x15,
        ]
    );
    define_hash_test_input_output_impl!(
        test_sha512_input_output,
        sha512,
        &[
            0x37, 0x4d, 0x79, 0x4a, 0x95, 0xcd, 0xcf, 0xd8, 0xb3, 0x59, 0x93, 0x18, 0x5f, 0xef,
            0x9b, 0xa3, 0x68, 0xf1, 0x60, 0xd8, 0xda, 0xf4, 0x32, 0xd0, 0x8b, 0xa9, 0xf1, 0xed,
            0x1e, 0x5a, 0xbe, 0x6c, 0xc6, 0x92, 0x91, 0xe0, 0xfa, 0x2f, 0xe0, 0x00, 0x6a, 0x52,
            0x57, 0x0e, 0xf1, 0x8c, 0x19, 0xde, 0xf4, 0xe6, 0x17, 0xc3, 0x3c, 0xe5, 0x2e, 0xf0,
            0xa6, 0xe5, 0xfb, 0xe3, 0x18, 0xcb, 0x03, 0x87,
        ]
    );
}
