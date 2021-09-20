use sha2::{Digest, Sha256, Sha384, Sha512};

pub const SHA256_SIZE: usize = 32;
pub const SHA384_SIZE: usize = 48;
pub const SHA512_SIZE: usize = 64;

pub fn sha256<T: AsRef<[u8]>>(input: T) -> [u8; SHA256_SIZE] {
    Sha256::digest(input.as_ref()).into()
}

pub fn sha384<T: AsRef<[u8]>>(input: T) -> [u8; SHA384_SIZE] {
    Sha384::digest(input.as_ref()).into()
}

pub fn sha512<T: AsRef<[u8]>>(input: T) -> [u8; SHA512_SIZE] {
    Sha512::digest(input.as_ref()).into()
}

#[cfg(test)]
const HELLO_WORLD: &[u8] = b"Hello, World!";

#[test]
fn test_sha256() {
    let output = sha256(HELLO_WORLD);
    let expected = hex::decode("dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f")
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
