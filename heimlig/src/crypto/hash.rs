use sha2::{Digest, Sha256, Sha384, Sha512};
use sha3::{Sha3_256, Sha3_384, Sha3_512};

/// Digest size of SHA-256
pub const SHA256_SIZE: usize = 32;
/// Digest size of SHA-384
pub const SHA384_SIZE: usize = 48;
/// Digest size of SHA-512
pub const SHA512_SIZE: usize = 64;
/// Digest size of BLAKE3
pub const BLAKE3_SIZE: usize = 32;

pub fn sha256<T: AsRef<[u8]>>(input: T) -> [u8; SHA256_SIZE] {
    Sha256::digest(input.as_ref()).into()
}

pub fn sha384<T: AsRef<[u8]>>(input: T) -> [u8; SHA384_SIZE] {
    Sha384::digest(input.as_ref()).into()
}

pub fn sha512<T: AsRef<[u8]>>(input: T) -> [u8; SHA512_SIZE] {
    Sha512::digest(input.as_ref()).into()
}

pub fn sha3_256<T: AsRef<[u8]>>(input: T) -> [u8; SHA256_SIZE] {
    Sha3_256::digest(input.as_ref()).into()
}

pub fn sha3_384<T: AsRef<[u8]>>(input: T) -> [u8; SHA384_SIZE] {
    Sha3_384::digest(input.as_ref()).into()
}

pub fn sha3_512<T: AsRef<[u8]>>(input: T) -> [u8; SHA512_SIZE] {
    Sha3_512::digest(input.as_ref()).into()
}

pub fn blake3<T: AsRef<[u8]>>(input: T) -> [u8; BLAKE3_SIZE] {
    blake3::hash(input.as_ref()).into()
}

#[cfg(test)]
mod test {
    use super::*;

    const HELLO_WORLD: &[u8] = b"Hello, World!";

    #[test]
    fn test_sha256() {
        let output = sha256(HELLO_WORLD);
        let expected =
            hex::decode("dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f")
                .expect("Failed to decode hex string");
        assert_eq!(output, expected.as_slice());
    }

    #[test]
    fn test_sha384() {
        let output = sha384(HELLO_WORLD);
        let expected = hex::decode("5485cc9b3365b4305dfb4e8337e0a598a574f8242bf17289e0dd6c20a3cd44a089de16ab4ab308f63e44b1170eb5f515").expect("Failed to decode hex string");
        assert_eq!(output, expected.as_slice());
    }

    #[test]
    fn test_sha512() {
        let output = sha512(HELLO_WORLD);
        let expected = hex::decode("374d794a95cdcfd8b35993185fef9ba368f160d8daf432d08ba9f1ed1e5abe6cc69291e0fa2fe0006a52570ef18c19def4e617c33ce52ef0a6e5fbe318cb0387").expect("Failed to decode hex string");
        assert_eq!(output, expected.as_slice());
    }

    #[test]
    fn test_sha3_256() {
        let output = sha3_256(HELLO_WORLD);
        let expected =
            hex::decode("1af17a664e3fa8e419b8ba05c2a173169df76162a5a286e0c405b460d478f7ef")
                .expect("Failed to decode hex string");
        assert_eq!(output, expected.as_slice());
    }

    #[test]
    fn test_sha3_384() {
        let output = sha3_384(HELLO_WORLD);
        let expected = hex::decode("aa9ad8a49f31d2ddcabbb7010a1566417cff803fef50eba239558826f872e468c5743e7f026b0a8e5b2d7a1cc465cdbe").expect("Failed to decode hex string");
        assert_eq!(output, expected.as_slice());
    }

    #[test]
    fn test_sha3_512() {
        let output = sha3_512(HELLO_WORLD);
        let expected = hex::decode("38e05c33d7b067127f217d8c856e554fcff09c9320b8a5979ce2ff5d95dd27ba35d1fba50c562dfd1d6cc48bc9c5baa4390894418cc942d968f97bcb659419ed").expect("Failed to decode hex string");
        assert_eq!(output, expected.as_slice());
    }

    #[test]
    fn test_blake3() {
        let output = blake3(HELLO_WORLD);
        let expected =
            hex::decode("288a86a79f20a3d6dccdca7713beaed178798296bdfa7913fa2a62d9727bf8f8")
                .expect("Failed to decode hex string");
        assert_eq!(output, expected.as_slice());
    }
}
