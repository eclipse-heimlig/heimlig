use elliptic_curve::weierstrass::Curve;
use elliptic_curve::zeroize::Zeroize;
use elliptic_curve::{ProjectiveArithmetic, PublicKey, Scalar, SecretKey};
use rand::{CryptoRng, RngCore};

/// Generate an elliptic curve key pair.   
///
/// # Arguments
///
/// * `rng`: Random number generator to use for key generation.
pub fn gen_key_pair<R, C>(rng: &mut R) -> (PublicKey<C>, SecretKey<C>)
where
    R: CryptoRng + RngCore,
    C: Curve + ProjectiveArithmetic,
    Scalar<C>: Zeroize,
{
    let private = SecretKey::<C>::random(rng);
    let public = private.public_key();
    (public, private)
}
