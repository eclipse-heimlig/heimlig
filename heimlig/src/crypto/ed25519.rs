use crate::crypto::Error;
use ed25519_dalek::{SecretKey, Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Ed25519 signature size in bytes.
pub const SIGNATURE_SIZE: usize = ed25519_dalek::SIGNATURE_LENGTH;
/// Ed25519 private key size in bytes.
pub const PRIVATE_KEY_SIZE: usize = ed25519_dalek::SECRET_KEY_LENGTH;
/// Ed25519 public key size in bytes.
pub const PUBLIC_KEY_SIZE: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;

/// Signs the message using the Ed25519 algorithm.
///
/// # Arguments
///
/// * `private_key`: A slice containing private key bytes.
///   The private key has to be `PRIVATE_KEY_SIZE` bytes long.
/// * `message`: A slice containing the message to sign bytes.
/// * `signature`: A mutable slice where the computed signature will be stored.
///   The signature slice length has to be `SIGNATURE_SIZE` bytes long.
///
/// # Errors
///
/// The function returns an error if:
/// * `InvalidBufferSize`: The length of the `signature` is not `SIGNATURE_SIZE` bytes.
/// * `InvalidPrivateKey`: The length of the `private_key` is not `PRIVATE_KEY_SIZE` bytes.
pub fn ed25519_sign(private_key: &[u8], message: &[u8], signature: &mut [u8]) -> Result<(), Error> {
    if signature.len() != SIGNATURE_SIZE {
        return Err(Error::InvalidBufferSize);
    }

    let signing_key = SigningKey::from_bytes(
        &SecretKey::try_from(private_key).map_err(|_| Error::InvalidPrivateKey)?,
    );

    signature.copy_from_slice(&signing_key.sign(message).to_bytes());

    Ok(())
}

/// Verifies the message signature using the Ed25519 algorithm.
///
/// # Arguments
///
/// * `public_key`: A slice containing public key bytes.
///   The public key has to have the valid format.
/// * `message`: A slice containing the message to verify bytes.
/// * `signature`: A slice containing signature to verify bytes.
///   The signature slice length has to be `SIGNATURE_SIZE` bytes long.
///
/// # Errors
///
/// The function returns an error if:
/// * `InvalidPublicKey`: `public_key` has invalid format.
/// * `InvalidSignature`: Signature verification fails.
pub fn ed25519_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error> {
    let verifying_key = VerifyingKey::try_from(public_key).map_err(|_| Error::InvalidPublicKey)?;
    let signature = Signature::from_slice(signature).map_err(|_| Error::InvalidSignature)?;

    verifying_key
        .verify(message, &signature)
        .map_err(|_| Error::InvalidSignature)?;

    Ok(())
}

/// Computes the public key for the given private key for Ed25519 algorithm.
///
/// # Arguments
///
/// * `private_key`: A slice containing the private key bytes. The private key has to
///   be `PRIVATE_KEY_SIZE` bytes long.
/// * `public_key`: A mutable slice where the computed public key will be stored. The
///   public key slice length has be `PUBLIC_KEY_SIZE` bytes long.
///
/// # Errors
///
/// The function returns an error if:
/// * `InvalidBufferSize`: The length of the `public_key` is not `PUBLIC_KEY_SIZE` bytes.
/// * `InvalidPrivateKey`: The length of the `private_key` is not `PRIVATE_KEY_SIZE` bytes.
pub fn ed25519_calculate_public_key(
    private_key: &[u8],
    public_key: &mut [u8],
) -> Result<(), Error> {
    if public_key.len() != PUBLIC_KEY_SIZE {
        return Err(Error::InvalidBufferSize);
    }

    let signing_key = SigningKey::from_bytes(
        &SecretKey::try_from(private_key).map_err(|_| Error::InvalidPrivateKey)?,
    );

    public_key.copy_from_slice(signing_key.verifying_key().as_bytes());

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    const MESSAGE: &[u8] =
        b"Know thy self, know thy enemy. A thousand battles, a thousand victories.";

    #[test]
    fn test_ed25519_sign_verify() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);

        let signing_key = SigningKey::generate(&mut rng);
        let private_key = signing_key.to_bytes();

        let mut signature = [0u8; SIGNATURE_SIZE];
        ed25519_sign(&private_key, MESSAGE, &mut signature).expect("signing error");

        let mut public_key = [0u8; PUBLIC_KEY_SIZE];
        ed25519_calculate_public_key(&private_key, &mut public_key)
            .expect("public key calculation error");

        ed25519_verify(&public_key, MESSAGE, &signature).expect("verifying error");
    }

    #[test]
    fn test_ed25519_size_errors() {
        const BUFF_SIZE: usize = 128;
        const INVALID_PRIVATE_KEY_LEN: [usize; 6] = [0, 1, 31, 33, 64, 128];
        const INVALID_PUBLIC_KEY_LEN: [usize; 6] = INVALID_PRIVATE_KEY_LEN;
        const INVALID_SIGNATURE_LEN: [usize; 6] = [0, 1, 32, 63, 65, 128];

        let private_key_buffer = [0u8; BUFF_SIZE];
        let mut public_key_buffer = [0u8; BUFF_SIZE];
        let mut signature_buffer = [0u8; BUFF_SIZE];

        for len in INVALID_PRIVATE_KEY_LEN {
            assert_eq!(
                ed25519_sign(
                    &private_key_buffer[..len],
                    MESSAGE,
                    &mut signature_buffer[..SIGNATURE_SIZE],
                ),
                Err(Error::InvalidPrivateKey)
            );
        }

        for len in INVALID_SIGNATURE_LEN {
            assert_eq!(
                ed25519_sign(
                    &private_key_buffer[..PRIVATE_KEY_SIZE],
                    MESSAGE,
                    &mut signature_buffer[..len],
                ),
                Err(Error::InvalidBufferSize)
            );
        }

        for len in INVALID_PUBLIC_KEY_LEN {
            assert_eq!(
                ed25519_verify(
                    &public_key_buffer[..len],
                    MESSAGE,
                    &signature_buffer[..SIGNATURE_SIZE],
                ),
                Err(Error::InvalidPublicKey)
            );
        }

        for len in INVALID_SIGNATURE_LEN {
            assert_eq!(
                ed25519_verify(
                    &public_key_buffer[..PUBLIC_KEY_SIZE],
                    MESSAGE,
                    &signature_buffer[..len],
                ),
                Err(Error::InvalidSignature)
            );
        }

        for len in INVALID_PRIVATE_KEY_LEN {
            assert_eq!(
                ed25519_calculate_public_key(
                    &private_key_buffer[..len],
                    &mut public_key_buffer[..PUBLIC_KEY_SIZE],
                ),
                Err(Error::InvalidPrivateKey)
            );
        }

        for len in INVALID_PUBLIC_KEY_LEN {
            assert_eq!(
                ed25519_calculate_public_key(
                    &private_key_buffer[..PRIVATE_KEY_SIZE],
                    &mut public_key_buffer[..len],
                ),
                Err(Error::InvalidBufferSize)
            );
        }
    }

    #[test]
    fn test_ed25519_invalid_signature() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);

        let signing_key = SigningKey::generate(&mut rng);
        let private_key = signing_key.to_bytes();

        let mut signature = [0u8; SIGNATURE_SIZE];
        ed25519_sign(&private_key, MESSAGE, &mut signature).expect("signing error");

        let mut public_key = [0u8; PUBLIC_KEY_SIZE];
        ed25519_calculate_public_key(&private_key, &mut public_key)
            .expect("public key calculation error");

        signature[0] = signature[0] ^ 0xFF;

        assert_eq!(
            ed25519_verify(&public_key, MESSAGE, &signature),
            Err(Error::InvalidSignature)
        );
    }
}
