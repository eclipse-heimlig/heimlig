use ecdsa::elliptic_curve::generic_array::ArrayLength;
use ecdsa::elliptic_curve::ops::Invert;
use ecdsa::elliptic_curve::rand_core::{CryptoRng, RngCore};
use ecdsa::elliptic_curve::zeroize::Zeroize;
use ecdsa::elliptic_curve::{
    AffinePoint, FieldSize, ProjectiveArithmetic, PublicKey, Scalar, SecretKey,
};
use ecdsa::hazmat::{DigestPrimitive, FromDigest, SignPrimitive, VerifyPrimitive};
use ecdsa::signature::digest::Digest;
use ecdsa::signature::{DigestSigner, Signer, Verifier};
use ecdsa::{Curve, Signature, SignatureSize, SigningKey, VerifyingKey};

#[derive(Debug)]
pub enum Error {
    Sign,
}

pub fn gen_key_pair<R, C>(rng: &mut R) -> (PublicKey<C>, SecretKey<C>)
where
    R: CryptoRng + RngCore,
    C: Curve + ProjectiveArithmetic,
    Scalar<C>: FromDigest<C> + Invert<Output = Scalar<C>> + SignPrimitive<C> + Zeroize,
    SignatureSize<C>: ArrayLength<u8>,
{
    let private = SecretKey::<C>::random(rng);
    let public = private.public_key();
    (public, private)
}

pub fn sign<C>(key: &SecretKey<C>, message: &[u8]) -> Signature<C>
where
    C: Curve + ProjectiveArithmetic + DigestPrimitive,
    Scalar<C>: FromDigest<C> + Invert<Output = Scalar<C>> + SignPrimitive<C> + Zeroize,
    SignatureSize<C>: ArrayLength<u8>,
    SigningKey<C>: DigestSigner<<C>::Digest, Signature<C>>,
{
    let key: SigningKey<C> = key.into();
    key.sign(message)
}

pub fn verify<C>(key: &PublicKey<C>, message: &[u8], signature: &Signature<C>) -> bool
where
    C: Curve + ProjectiveArithmetic + DigestPrimitive,
    C::Digest: Digest<OutputSize = FieldSize<C>>,
    AffinePoint<C>: VerifyPrimitive<C>,
    Scalar<C>: FromDigest<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    let key: VerifyingKey<C> = key.into();
    if key.verify(message, &signature).is_ok() {
        return true;
    }
    false
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::crypto::rng;
    use p256::NistP256;

    #[test]
    fn sign_verify_p256() {
        let source = rng::test::TestEntropySource::default();
        let mut rng = rng::Rng::new(source, None);
        let message = "Hello, World!";
        let (signer, verifier) = gen_key_pair::<_, NistP256>(&mut rng);
        let signature = sign(&signer, message.as_ref());
        assert!(verify(&verifier, message.as_ref(), signature.as_ref()));
    }
}
