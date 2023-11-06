pub use crate::crypto::ecc::generate_key_pair;
use elliptic_curve::ecdh::{diffie_hellman, SharedSecret};
use elliptic_curve::{Curve, CurveArithmetic, PublicKey, SecretKey};

/// Derive a shared secret from a private key and a public key. If another peer wants to derive the
/// same secret, he has to switch out the keys with their respective partner keys.
/// That is, if two peers `A` and `B` have generated their respective key pairs
/// `(public_A, private_A)` and `(public_B, private_B)`,
/// then the following condition must hold:
///
/// ```text
/// derive_shared_secret(private_A, public_B) == derive_shared_secret(private_B, public_A)
/// ```
pub fn derive_shared_secret<C>(private: &SecretKey<C>, public: &PublicKey<C>) -> SharedSecret<C>
where
    C: Curve + CurveArithmetic,
{
    diffie_hellman(private.to_nonzero_scalar(), public.as_affine())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::crypto::rng;
    use p256::NistP256;
    use p384::NistP384;

    #[test]
    fn test_p256() {
        let entropy = rng::test::TestEntropySource::default();
        let mut rng = rng::Rng::new(entropy, None);
        let (local_public, local_private) = generate_key_pair::<_, NistP256>(&mut rng);
        let (remote_public, remote_private) = generate_key_pair::<_, NistP256>(&mut rng);
        let local_secret = derive_shared_secret(&local_private, &remote_public);
        let remote_secret = derive_shared_secret(&remote_private, &local_public);
        assert_eq!(
            local_secret.raw_secret_bytes(),
            remote_secret.raw_secret_bytes()
        );
    }

    #[test]
    fn test_p384() {
        let entropy = rng::test::TestEntropySource::default();
        let mut rng = rng::Rng::new(entropy, None);
        let (local_public, local_private) = generate_key_pair::<_, NistP384>(&mut rng);
        let (remote_public, remote_private) = generate_key_pair::<_, NistP384>(&mut rng);
        let local_secret = derive_shared_secret(&local_private, &remote_public);
        let remote_secret = derive_shared_secret(&remote_private, &local_public);
        assert_eq!(
            local_secret.raw_secret_bytes(),
            remote_secret.raw_secret_bytes()
        );
    }
}
