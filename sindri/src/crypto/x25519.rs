use rand::{CryptoRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};

/// Size of X25519 secret in bytes.
pub const X25519_SECRET_SIZE: usize = 32;
/// Size of X25519 public key in bytes.
pub const X25519_PUBLIC_KEY_SIZE: usize = 32;
/// Size of X25519 shared secret in bytes.
pub const X25519_SHARED_SECRET_SIZE: usize = 32;

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Error {
    /// Invalid secret.
    InvalidSecret,
    /// Invalid public key.
    InvalidPublicKey,
}

/// Generate secret for X25519.
pub fn generate_secret_x25519<R>(rng: &mut R) -> [u8; X25519_SECRET_SIZE]
where
    R: CryptoRng + RngCore,
{
    StaticSecret::new(rng).to_bytes()
}

/// Calculate public key from the secret for X25519.
pub fn calculate_public_key_x25519(secret: &[u8]) -> Result<[u8; X25519_PUBLIC_KEY_SIZE], Error> {
    let secret: [u8; X25519_SECRET_SIZE] = secret.try_into().map_err(|_| Error::InvalidSecret)?;
    Ok(PublicKey::from(&StaticSecret::from(secret)).to_bytes())
}

/// Calculate shared secret from the secret and remote public key for X25519.
pub fn calculate_shared_secret_x25519(
    secret: &[u8],
    remote_public_key: &[u8],
) -> Result<[u8; X25519_SHARED_SECRET_SIZE], Error> {
    let public_key = TryInto::<[u8; X25519_PUBLIC_KEY_SIZE]>::try_into(remote_public_key)
        .map_err(|_| Error::InvalidPublicKey)?
        .into();
    let secret = StaticSecret::from(
        TryInto::<[u8; X25519_SECRET_SIZE]>::try_into(secret).map_err(|_| Error::InvalidSecret)?,
    );
    Ok(secret.diffie_hellman(&public_key).to_bytes())
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::crypto::rng;
    use heapless::Vec;

    const LOCAL_SECRET: &[u8; X25519_SECRET_SIZE] = b"The best pirate I've ever seen!!";
    const LOCAL_PUBLIC_KEY: &[u8; X25519_PUBLIC_KEY_SIZE] = &[
        0xf6, 0xdc, 0xa1, 0x58, 0x55, 0x82, 0x3d, 0xa0, 0x7d, 0xb6, 0x2e, 0x0a, 0x64, 0x10, 0x7f,
        0xf6, 0xfc, 0x95, 0xab, 0xe6, 0x4b, 0x4e, 0xb5, 0xc4, 0xf6, 0x88, 0xe7, 0x5e, 0xed, 0x2d,
        0x78, 0x45,
    ];
    // "_____ Captain Jack Sparrow _____"
    const REMOTE_PUBLIC_KEY: &[u8; X25519_PUBLIC_KEY_SIZE] = &[
        0x96, 0xae, 0x61, 0x71, 0x78, 0x2d, 0x6f, 0xb7, 0xad, 0x8d, 0x0f, 0xcd, 0x6e, 0x60, 0x80,
        0x8b, 0x99, 0x7c, 0x9c, 0x61, 0xe5, 0xca, 0xd2, 0x0c, 0x76, 0xe4, 0x9b, 0x37, 0xed, 0xce,
        0x59, 0x0c,
    ];

    const SHARED_SECRET: &[u8; X25519_SHARED_SECRET_SIZE] = &[
        0x46, 0x97, 0x4d, 0xf5, 0xf1, 0x42, 0xd6, 0xd3, 0x33, 0x1f, 0xe7, 0x7f, 0x46, 0xd6, 0x57,
        0x62, 0xe0, 0x42, 0xde, 0xab, 0x5c, 0xe2, 0x64, 0x92, 0xf0, 0x02, 0x94, 0xcc, 0x96, 0x99,
        0xba, 0x3e,
    ];

    #[test]
    pub fn test_x25519_generate_secret() {
        let entropy = rng::test::TestEntropySource::default();
        let mut rng = rng::Rng::new(entropy, None);

        let alice_secret = generate_secret_x25519(&mut rng);
        let alice_public_key = calculate_public_key_x25519(&alice_secret).unwrap();

        let bob_secret = generate_secret_x25519(&mut rng);
        let bob_public_key = calculate_public_key_x25519(&bob_secret).unwrap();

        let alice_shared_key =
            calculate_shared_secret_x25519(&alice_secret, &bob_public_key).unwrap();
        let bob_shared_key =
            calculate_shared_secret_x25519(&bob_secret, &alice_public_key).unwrap();

        assert_eq!(alice_shared_key, bob_shared_key);
    }

    #[test]
    pub fn test_x25519_calculate_public_key() {
        let public_key = calculate_public_key_x25519(LOCAL_SECRET).unwrap();
        assert_eq!(&public_key, LOCAL_PUBLIC_KEY);
    }

    #[test]
    pub fn test_x25519_calculate_shared_secret() {
        let shared_secret =
            calculate_shared_secret_x25519(LOCAL_SECRET, REMOTE_PUBLIC_KEY).unwrap();
        assert_eq!(&shared_secret, SHARED_SECRET);
    }

    #[test]
    pub fn test_x25519_errors() {
        const MAX_SIZE: usize = 32;
        for size in [0, 1, 4, 16] {
            let mut wrong_secret: Vec<u8, MAX_SIZE> = Vec::new();
            wrong_secret.resize(size, 0).unwrap();

            assert_eq!(
                calculate_public_key_x25519(&wrong_secret),
                Err(Error::InvalidSecret)
            );

            assert_eq!(
                calculate_shared_secret_x25519(&wrong_secret, REMOTE_PUBLIC_KEY),
                Err(Error::InvalidSecret)
            );
        }

        for size in [0, 1, 4, 16] {
            let mut wrong_public_key: Vec<u8, MAX_SIZE> = Vec::new();
            wrong_public_key.resize(size, 0).unwrap();

            assert_eq!(
                calculate_shared_secret_x25519(LOCAL_SECRET, &wrong_public_key),
                Err(Error::InvalidPublicKey)
            );
        }
    }
}
