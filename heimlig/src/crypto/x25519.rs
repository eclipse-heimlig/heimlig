use crate::crypto::Error;
use x25519_dalek::{PublicKey, StaticSecret};

/// X25519 key size in bytes.
pub const KEY_SIZE: usize = 32;

/// Checks that slice length is `KEY_SIZE` bytes. Otherwise, returns an error.
fn check_size(slice: &[u8]) -> Result<(), ()> {
    if slice.len() == KEY_SIZE {
        Ok(())
    } else {
        Err(())
    }
}

/// Converts slice to [u8; `KEY_SIZE`]. Returns an error if slice has wrong length.
fn try_to_array(slice: &[u8]) -> Result<[u8; KEY_SIZE], ()> {
    check_size(slice)
        .map(|_| <[u8; KEY_SIZE]>::try_from(slice).expect("unexpected slice size after check"))
}

/// Computes the shared secret using the X25519 key exchange algorithm.
///
/// # Arguments
///
/// * `private_key`: A slice containing this peer private key bytes.
///   The private key has to be `KEY_SIZE` bytes long.
/// * `public_key`: A slice containing the other peer public key bytes.
///   The public key has to be `KEY_SIZE` bytes long.
/// * `shared_secret`: A mutable slice where the computed shared secret will be
///   stored. The shared secret slice length has to be `KEY_SIZE` bytes long.
///
/// # Errors
///
/// The function returns an error if:
/// * `InvalidPrivateKey`: The length of the `private_key` is not `KEY_SIZE` bytes.
/// * `InvalidPublicKey`: The length of the `public_key` is not `KEY_SIZE` bytes.
/// * `InvalidBufferSize`: The length of the `shared_secret` is not `KEY_SIZE` bytes.
pub fn x25519_calculate_shared_secret(
    private_key: &[u8],
    public_key: &[u8],
    shared_secret: &mut [u8],
) -> Result<(), Error> {
    let private_key =
        StaticSecret::from(try_to_array(private_key).or(Err(Error::InvalidPrivateKey))?);
    let public_key = PublicKey::from(try_to_array(public_key).or(Err(Error::InvalidPublicKey))?);
    check_size(shared_secret).or(Err(Error::InvalidBufferSize))?;

    shared_secret.copy_from_slice(private_key.diffie_hellman(&public_key).as_bytes());

    Ok(())
}

/// Computes the public key for the given private key for X25519 key exchange algorithm.
///
/// # Arguments
///
/// * `private_key`: A slice containing the private key bytes. The private key has to
///   be `KEY_SIZE` bytes long.
/// * `public_key`: A mutable slice where the computed public key will be stored. The
///   public key slice length has to be `KEY_SIZE` bytes long.
///
/// # Errors
///
/// The function returns an error if:
/// * `InvalidPrivateKey`: The length of the `private_key` is not `KEY_SIZE` bytes.
/// * `InvalidBufferSize`: The length of the `public_key` is not `KEY_SIZE` bytes.
pub fn x25519_calculate_public_key(private_key: &[u8], public_key: &mut [u8]) -> Result<(), Error> {
    let private_key =
        StaticSecret::from(try_to_array(private_key).or(Err(Error::InvalidPrivateKey))?);
    check_size(public_key).or(Err(Error::InvalidBufferSize))?;

    public_key.copy_from_slice(PublicKey::from(&private_key).as_bytes());

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_x25519_shared_key() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);

        // Alice's keys
        let alice_private_key = StaticSecret::random_from_rng(&mut rng);
        let mut alice_public_key = [0u8; KEY_SIZE];
        x25519_calculate_public_key(alice_private_key.as_bytes(), &mut alice_public_key)
            .expect("Alice public key error");

        // Bob's keys
        let bob_private_key = StaticSecret::random_from_rng(&mut rng);
        let mut bob_public_key = [0u8; KEY_SIZE];
        x25519_calculate_public_key(bob_private_key.as_bytes(), &mut bob_public_key)
            .expect("Bob public key error");

        // Alice's shared secret
        let mut alice_shared_secret = [0u8; KEY_SIZE];
        x25519_calculate_shared_secret(
            alice_private_key.as_bytes(),
            &bob_public_key,
            &mut alice_shared_secret,
        )
        .expect("Alice shared secret error");

        // Bob's shared secret
        let mut bob_shared_secret = [0u8; KEY_SIZE];
        x25519_calculate_shared_secret(
            bob_private_key.as_bytes(),
            &alice_public_key,
            &mut bob_shared_secret,
        )
        .expect("Bob shared secret error");

        assert_eq!(alice_shared_secret, bob_shared_secret);
    }

    #[test]
    fn test_x25519_errors() {
        const BUFF_SIZE: usize = 64;
        const INVALID_KEY_LEN: [usize; 5] = [0, 1, 31, 33, 64];

        let private_key_buffer = [0u8; BUFF_SIZE];
        let mut public_key_buffer = [0u8; BUFF_SIZE];
        let mut shared_key_buffer = [0u8; BUFF_SIZE];

        for len in INVALID_KEY_LEN {
            assert_eq!(
                x25519_calculate_shared_secret(
                    &private_key_buffer[..len],
                    &public_key_buffer[..KEY_SIZE],
                    &mut shared_key_buffer[..KEY_SIZE]
                ),
                Err(Error::InvalidPrivateKey)
            );
        }

        for len in INVALID_KEY_LEN {
            assert_eq!(
                x25519_calculate_shared_secret(
                    &private_key_buffer[..KEY_SIZE],
                    &public_key_buffer[..len],
                    &mut shared_key_buffer[..KEY_SIZE]
                ),
                Err(Error::InvalidPublicKey)
            );
        }

        for len in INVALID_KEY_LEN {
            assert_eq!(
                x25519_calculate_shared_secret(
                    &private_key_buffer[..KEY_SIZE],
                    &public_key_buffer[..KEY_SIZE],
                    &mut shared_key_buffer[..len]
                ),
                Err(Error::InvalidBufferSize)
            );
        }

        for len in INVALID_KEY_LEN {
            assert_eq!(
                x25519_calculate_public_key(
                    &private_key_buffer[..len],
                    &mut public_key_buffer[..KEY_SIZE],
                ),
                Err(Error::InvalidPrivateKey)
            );
        }

        for len in INVALID_KEY_LEN {
            assert_eq!(
                x25519_calculate_public_key(
                    &private_key_buffer[..KEY_SIZE],
                    &mut public_key_buffer[..len],
                ),
                Err(Error::InvalidBufferSize)
            );
        }
    }
}
