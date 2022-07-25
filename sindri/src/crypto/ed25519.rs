use ed25519_dalek::{ExpandedSecretKey, PublicKey, SecretKey, Signature, Verifier};
use rand::{CryptoRng, RngCore};

/// Size of the secret in bytes for Ed25519-based algorithms.
pub const ED25519_SECRET_SIZE: usize = ed25519_dalek::SECRET_KEY_LENGTH;
/// Size of the public key in bytes for Ed25519-based algorithms.
pub const ED25519_PUBLIC_KEY_SIZE: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;
/// Size of Ed25519 signature in bytes.
pub const ED25519_SIGNATURE_SIZE: usize = ed25519_dalek::SIGNATURE_LENGTH;

/// Ed25519 errors.
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Error {
    /// Invalid secret.
    InvalidSecret,
    /// Invalid public key.
    InvalidPublicKey,
    ///Invalid signature format.
    InvalidSignatureFormat,
}

/// Calculate public key from secret for Ed25519.
pub fn calculate_public_key_ed25519(secret: &[u8]) -> Result<[u8; ED25519_PUBLIC_KEY_SIZE], Error> {
    Ok(
        PublicKey::from(&SecretKey::from_bytes(secret).map_err(|_| Error::InvalidSecret)?)
            .to_bytes(),
    )
}

/// Calculate secret and public key for Ed25519.
pub fn generate_keypair_ed25519<R>(
    rng: &mut R,
) -> ([u8; ED25519_SECRET_SIZE], [u8; ED25519_PUBLIC_KEY_SIZE])
where
    R: CryptoRng + RngCore,
{
    let mut secret = [0u8; ED25519_SECRET_SIZE];
    rng.fill_bytes(&mut secret);

    (secret, calculate_public_key_ed25519(&secret).unwrap())
}

/// Sign message with Ed25519.
pub fn sign_ed25519(
    secret: &[u8],
    public_key: &[u8],
    message: &[u8],
) -> Result<[u8; ED25519_SIGNATURE_SIZE], Error> {
    let private_key =
        ExpandedSecretKey::from(&SecretKey::from_bytes(secret).map_err(|_| Error::InvalidSecret)?);
    let public_key = PublicKey::from_bytes(public_key).map_err(|_| Error::InvalidPublicKey)?;
    Ok(private_key.sign(message, &public_key).to_bytes())
}

/// Verify the signature of the message with Ed25519.
pub fn verify_ed25519(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, Error> {
    let signature = Signature::from_bytes(signature).map_err(|_| Error::InvalidSignatureFormat)?;
    let public_key = PublicKey::from_bytes(public_key).map_err(|_| Error::InvalidPublicKey)?;
    Ok(public_key.verify(message, &signature).is_ok())
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::crypto::rng;
    use heapless::Vec;

    const SECRET: &[u8; ED25519_SECRET_SIZE] = b"Luke, I'm your father. Nooooo!!!";
    const PUBLIC_KEY: &[u8; ED25519_PUBLIC_KEY_SIZE] = &[
        0x61, 0x57, 0x3e, 0xac, 0x28, 0xf3, 0x75, 0xe4, 0xdf, 0x40, 0x64, 0x91, 0x9c, 0x2e, 0x48,
        0xf4, 0x2b, 0x55, 0xd8, 0x3e, 0xb0, 0x95, 0x24, 0xb4, 0x48, 0xd1, 0x92, 0x53, 0xea, 0x89,
        0xe8, 0xb9,
    ];
    const MESSAGE: &[u8] = b"A long time ago in a galaxy far, far away.... STAR WARS";
    const SIGNATURE: &[u8; ED25519_SIGNATURE_SIZE] = &[
        0x31, 0x11, 0x59, 0x7c, 0xa6, 0x7f, 0x46, 0xc0, 0xc6, 0xd2, 0x74, 0xcb, 0xdc, 0x33, 0x02,
        0x69, 0x2d, 0xde, 0x0a, 0x4a, 0x1e, 0xc0, 0x8c, 0xea, 0xa0, 0x41, 0x55, 0x1f, 0x5d, 0xfa,
        0xe2, 0xcc, 0x3f, 0xdb, 0x67, 0x5f, 0x0a, 0x34, 0x0d, 0xf2, 0x31, 0x6f, 0x80, 0xe8, 0x8d,
        0x90, 0x2d, 0x66, 0x83, 0xdf, 0x9b, 0x2d, 0xc0, 0x34, 0x5a, 0xd1, 0xe6, 0x75, 0xb8, 0x34,
        0x17, 0x6d, 0x4e, 0x06,
    ];

    #[test]
    pub fn test_ed25519_calculate_public_key() {
        let public_key =
            calculate_public_key_ed25519(SECRET).expect("failed to calculate public key");
        assert_eq!(&public_key, PUBLIC_KEY);
    }

    #[test]
    pub fn test_ed25519_generate_keypair() {
        let entropy = rng::test::TestEntropySource::default();
        let mut rng = rng::Rng::new(entropy, None);
        let (secret, public_key) = generate_keypair_ed25519(&mut rng);

        let signature = sign_ed25519(&secret, &public_key, MESSAGE).expect("signing failed");
        assert!(verify_ed25519(&public_key, MESSAGE, &signature).expect("verification failed"));
    }

    #[test]
    pub fn test_ed25519_sign_verify() {
        let signature = sign_ed25519(SECRET, PUBLIC_KEY, MESSAGE).expect("signing failed");
        assert_eq!(&signature, SIGNATURE);
        assert!(verify_ed25519(PUBLIC_KEY, MESSAGE, &signature).expect("verification failed"));
    }

    #[test]
    pub fn test_ed25519_errors() {
        for size in [0, 1, 4, 16, 64] {
            let mut wrong_secret: Vec<u8, 64> = Vec::new();
            wrong_secret.resize(size, 0).unwrap();
            assert_eq!(
                sign_ed25519(&wrong_secret, PUBLIC_KEY, MESSAGE),
                Err(Error::InvalidSecret)
            );

            assert_eq!(
                calculate_public_key_ed25519(&wrong_secret),
                Err(Error::InvalidSecret)
            );
        }

        for size in [0, 1, 4, 16, 64] {
            let mut wrong_public_key: Vec<u8, 64> = Vec::new();
            wrong_public_key.resize(size, 0).unwrap();
            assert_eq!(
                sign_ed25519(SECRET, &wrong_public_key, MESSAGE),
                Err(Error::InvalidPublicKey)
            );
            assert_eq!(
                verify_ed25519(&wrong_public_key, MESSAGE, SIGNATURE),
                Err(Error::InvalidPublicKey)
            );
        }

        for size in [0, 1, 4, 16, 32] {
            let mut wrong_signature: Vec<u8, 64> = Vec::new();
            wrong_signature.resize(size, 0).unwrap();
            assert_eq!(
                verify_ed25519(PUBLIC_KEY, MESSAGE, &wrong_signature),
                Err(Error::InvalidSignatureFormat)
            );
        }

        assert_eq!(
            verify_ed25519(PUBLIC_KEY, &MESSAGE[..MESSAGE.len() - 1], SIGNATURE)
                .expect("verification failed"),
            false
        );

        let mut wrong_signature = SIGNATURE.clone();
        wrong_signature[0] ^= 1;
        assert_eq!(
            verify_ed25519(PUBLIC_KEY, MESSAGE, &wrong_signature).expect("verification failed"),
            false
        );
    }
}
