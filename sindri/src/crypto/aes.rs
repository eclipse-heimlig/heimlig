use aes_gcm::aead::NewAead;
use aes_gcm::{AeadInPlace, Aes128Gcm, Aes256Gcm, Key, Nonce};
use alloc::vec;
use alloc::vec::Vec;

pub const KEY128_SIZE: usize = 16;
pub const KEY256_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Error {
    InvalidKeySize,
    InvalidNonceSize,
    InvalidBufferSize,
    Encryption,
    Decryption,
    Alloc,
}

pub fn aes128gcm_encrypt<K, N, P>(key: K, nonce: N, plaintext: P) -> Result<Vec<u8>, Error>
where
    K: AsRef<[u8]>,
    N: AsRef<[u8]>,
    P: AsRef<[u8]>,
{
    check_sizes(&key, &nonce, KEY128_SIZE)?;
    let key = Key::from_slice(key.as_ref());
    let nonce = Nonce::from_slice(nonce.as_ref());
    let mut ciphertext_and_tag = vec![];
    ciphertext_and_tag
        .try_reserve_exact(plaintext.as_ref().len() + TAG_SIZE)
        .map_err(|_| Error::Alloc)?;
    ciphertext_and_tag.extend_from_slice(plaintext.as_ref());
    let tag = Aes128Gcm::new(key)
        .encrypt_in_place_detached(nonce, vec![].as_slice(), &mut ciphertext_and_tag)
        .map_err(|_| Error::Encryption)?;
    ciphertext_and_tag.extend_from_slice(tag.as_ref());
    Ok(ciphertext_and_tag)
}

pub fn aes128gcm_decrypt<K, N, C>(key: K, nonce: N, ciphertext_and_tag: C) -> Result<Vec<u8>, Error>
where
    K: AsRef<[u8]>,
    N: AsRef<[u8]>,
    C: AsRef<[u8]>,
{
    check_sizes(&key, &nonce, KEY128_SIZE)?;
    if ciphertext_and_tag.as_ref().len() < TAG_SIZE {
        return Err(Error::InvalidBufferSize);
    }
    let key = Key::from_slice(key.as_ref());
    let nonce = Nonce::from_slice(nonce.as_ref());
    let (ciphertext, tag) = ciphertext_and_tag
        .as_ref()
        .split_at(ciphertext_and_tag.as_ref().len() - TAG_SIZE);
    let mut plaintext = vec![];
    plaintext
        .try_reserve_exact(ciphertext.len())
        .map_err(|_| Error::Alloc)?;
    plaintext.extend_from_slice(ciphertext);
    match Aes128Gcm::new(key)
        .decrypt_in_place_detached(nonce, vec![].as_slice(), &mut plaintext, tag.into())
        .map_err(|_| Error::Decryption)
    {
        Ok(()) => Ok(plaintext),
        Err(e) => Err(e),
    }
}

pub fn aes256gcm_encrypt<K, N, P>(key: K, nonce: N, plaintext: P) -> Result<Vec<u8>, Error>
where
    K: AsRef<[u8]>,
    N: AsRef<[u8]>,
    P: AsRef<[u8]>,
{
    check_sizes(&key, &nonce, KEY256_SIZE)?;
    let key = Key::from_slice(key.as_ref());
    let nonce = Nonce::from_slice(nonce.as_ref());
    let mut ciphertext_and_tag = vec![];
    ciphertext_and_tag
        .try_reserve_exact(plaintext.as_ref().len() + TAG_SIZE)
        .map_err(|_| Error::Alloc)?;
    ciphertext_and_tag.extend_from_slice(plaintext.as_ref());
    let tag = Aes256Gcm::new(key)
        .encrypt_in_place_detached(nonce, vec![].as_slice(), &mut ciphertext_and_tag)
        .map_err(|_| Error::Encryption)?;
    ciphertext_and_tag.extend_from_slice(tag.as_ref());
    Ok(ciphertext_and_tag)
}

pub fn aes256gcm_decrypt<K, N, C>(key: K, nonce: N, ciphertext_and_tag: C) -> Result<Vec<u8>, Error>
where
    K: AsRef<[u8]>,
    N: AsRef<[u8]>,
    C: AsRef<[u8]>,
{
    check_sizes(&key, &nonce, KEY256_SIZE)?;
    if ciphertext_and_tag.as_ref().len() < TAG_SIZE {
        return Err(Error::InvalidBufferSize);
    }
    let key = Key::from_slice(key.as_ref());
    let nonce = Nonce::from_slice(nonce.as_ref());
    let (ciphertext, tag) = ciphertext_and_tag
        .as_ref()
        .split_at(ciphertext_and_tag.as_ref().len() - TAG_SIZE);
    let mut plaintext = vec![];
    plaintext
        .try_reserve_exact(ciphertext.len())
        .map_err(|_| Error::Alloc)?;
    plaintext.extend_from_slice(ciphertext);
    match Aes256Gcm::new(key)
        .decrypt_in_place_detached(nonce, vec![].as_slice(), &mut plaintext, tag.into())
        .map_err(|_| Error::Decryption)
    {
        Ok(()) => Ok(plaintext),
        Err(e) => Err(e),
    }
}

fn check_sizes<K: AsRef<[u8]>, N: AsRef<[u8]>>(
    key: &K,
    nonce: &N,
    key_size: usize,
) -> Result<(), Error> {
    if key.as_ref().len() != key_size {
        return Err(Error::InvalidKeySize);
    }
    if nonce.as_ref().len() != NONCE_SIZE {
        return Err(Error::InvalidNonceSize);
    }
    Ok(())
}

#[cfg(test)]
pub mod test {
    use super::*;

    const KEY128: &[u8; KEY128_SIZE] = b"Open sesame! ...";
    const KEY256: &[u8; KEY256_SIZE] = b"Or was it 'open quinoa' instead?";
    const NONCE: &[u8; NONCE_SIZE] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    const PLAINTEXT: &[u8] = b"Hello, World!";

    #[test]
    fn aes128gcm_encrypt_decrypt() {
        let expected_encrypted: &[u8; PLAINTEXT.len() + TAG_SIZE] = &[
            // ciphertext
            0xbb, 0xfe, 0x8, 0x2b, 0x97, 0x86, 0xd4, 0xe4, 0xa4, 0xec, 0x19, 0xdb, 0x63,
            // tag
            0x40, 0xce, 0x93, 0x5a, 0x71, 0x5e, 0x63, 0x9, 0xb, 0x11, 0xad, 0x51, 0x4d, 0xe8, 0x23,
            0x50,
        ];
        let encrypted = aes128gcm_encrypt(KEY128, NONCE, PLAINTEXT).expect("encryption error");
        let decrypted = aes128gcm_decrypt(KEY128, NONCE, &encrypted).expect("decryption error");
        assert_eq!(encrypted, expected_encrypted, "ciphertext mismatch");
        assert_eq!(decrypted, PLAINTEXT, "plaintext mismatch");
    }

    #[test]
    fn test_aes256gcm() {
        let expected_encrypted: &[u8; PLAINTEXT.len() + TAG_SIZE] = &[
            // ciphertext
            0xab, 0xe2, 0x9e, 0x5a, 0x8d, 0xd3, 0xbd, 0x62, 0xc9, 0x46, 0x71, 0x8e, 0x50,
            // tag
            0xa8, 0xcb, 0x47, 0x81, 0xad, 0x51, 0x89, 0x1f, 0x23, 0x78, 0x11, 0xcb, 0x9f, 0xc5,
            0xbf, 0x8b,
        ];
        let encrypted = aes256gcm_encrypt(KEY256, NONCE, PLAINTEXT).expect("Encryption error");
        let decrypted = aes256gcm_decrypt(KEY256, NONCE, &encrypted).expect("Decryption error");
        assert_eq!(encrypted, expected_encrypted, "ciphertext mismatch");
        assert_eq!(decrypted, PLAINTEXT, "plaintext mismatch");
    }
}
