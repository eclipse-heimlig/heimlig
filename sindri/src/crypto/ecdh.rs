use elliptic_curve::ecdh::{EphemeralSecret, SharedSecret};
use elliptic_curve::weierstrass::Curve;
use elliptic_curve::zeroize::Zeroize;
use elliptic_curve::{AffinePoint, ProjectiveArithmetic, PublicKey, Scalar};
use rand::{CryptoRng, RngCore};

#[derive(Debug)]
pub enum Error {
    KeyGeneration,
}

/// Generate a public-private key pair for an ECDH key exchange.   
///
/// # Arguments
///
/// * `rng`: Random number generator to use for key generation.
pub fn gen_key_pair<R, C>(rng: &mut R) -> Result<(PublicKey<C>, EphemeralSecret<C>), Error>
where
    R: CryptoRng + RngCore,
    C: Curve + ProjectiveArithmetic,
    AffinePoint<C>: Zeroize,
    Scalar<C>: Zeroize,
    SharedSecret<C>: for<'a> From<&'a AffinePoint<C>>,
{
    let private = EphemeralSecret::random(rng);
    let public = private.public_key();
    Ok((public, private))
}

/// Derive a shared secret from a private key and a public key.
/// If another peer wants to derive the same secret, he has to switch out the keys with their
/// respective partner keys.
/// That is, if two peers called A and B have generated their respective key pairs, it holds that
///     derive_shared_secret(private_A, public_B) == derive_shared_secret(private_B, public_A)
pub fn derive_shared_secret<C>(
    private: EphemeralSecret<C>,
    public: &PublicKey<C>,
) -> SharedSecret<C>
where
    C: Curve + ProjectiveArithmetic,
    AffinePoint<C>: Zeroize,
    Scalar<C>: Zeroize,
    SharedSecret<C>: for<'a> From<&'a AffinePoint<C>>,
{
    private.diffie_hellman(public)
}

#[cfg(test)]
mod test {
    use super::*;

    fn ecdh_secrets_match<C>() -> Result<(), Error>
    where
        C: Curve + ProjectiveArithmetic,
        AffinePoint<C>: Zeroize,
        Scalar<C>: Zeroize,
        SharedSecret<C>: for<'a> From<&'a AffinePoint<C>>,
    {
        use crate::crypto::rng;

        let mut source = rng::test::TestEntropySource::default();
        let mut rng = rng::Rng::new(&mut source, None);
        let (local_public, local_private) = gen_key_pair::<_, C>(&mut rng)?;
        let (remote_public, remote_private) = gen_key_pair::<_, C>(&mut rng)?;
        let local_secret = local_private.diffie_hellman(&remote_public);
        let remote_secret = remote_private.diffie_hellman(&local_public);
        assert_eq!(local_secret.as_bytes(), remote_secret.as_bytes());
        Ok(())
    }

    #[test]
    fn test_p256() -> Result<(), Error> {
        ecdh_secrets_match::<p256::NistP256>()
    }
}
