use ecdsa::elliptic_curve::generic_array::ArrayLength;
use ecdsa::elliptic_curve::ops::{Invert, Reduce};
use ecdsa::elliptic_curve::{
    AffinePoint, FieldSize, ProjectiveArithmetic, PublicKey, Scalar, SecretKey,
};
use ecdsa::hazmat::{DigestPrimitive, SignPrimitive, VerifyPrimitive};
use ecdsa::signature::digest::{Digest, FixedOutput};
use ecdsa::signature::{DigestSigner, Signer, Verifier};
use ecdsa::{PrimeCurve, Signature, SignatureSize, SigningKey, VerifyingKey};
use elliptic_curve::subtle::CtOption;

pub use crate::crypto::ecc::gen_key_pair;

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Error {
    Sign,
}

pub fn sign<C>(key: &SecretKey<C>, message: &[u8]) -> Signature<C>
where
    C: PrimeCurve + ProjectiveArithmetic + DigestPrimitive,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + Reduce<C::UInt> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
    SigningKey<C>: DigestSigner<C::Digest, Signature<C>>,
{
    let key: SigningKey<C> = key.into();
    key.sign(message)
}

pub fn verify<C>(key: &PublicKey<C>, message: &[u8], signature: &Signature<C>) -> bool
where
    C: PrimeCurve + ProjectiveArithmetic + DigestPrimitive,
    C::Digest: Digest + FixedOutput<OutputSize = FieldSize<C>>,
    AffinePoint<C>: VerifyPrimitive<C>,
    Scalar<C>: Reduce<C::UInt>,
    SignatureSize<C>: ArrayLength<u8>,
{
    let key: VerifyingKey<C> = key.into();
    key.verify(message, signature).is_ok()
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::crypto::rng;

    #[test]
    fn sign_verify_p256() {
        let entropy = rng::test::TestEntropySource::default();
        let mut rng = rng::Rng::new(entropy, None);
        let (public, private) = gen_key_pair::<_, p256::NistP256>(&mut rng);
        let message = "Hello, World!";
        let signature = sign(&private, message.as_ref());
        assert!(verify(&public, message.as_ref(), &signature));
    }

    #[test]
    fn sign_verify_p384() {
        let entropy = rng::test::TestEntropySource::default();
        let mut rng = rng::Rng::new(entropy, None);
        let (public, private) = gen_key_pair::<_, p384::NistP384>(&mut rng);
        let message = "Hello, World!";
        let signature = sign(&private, message.as_ref());
        assert!(verify(&public, message.as_ref(), &signature));
    }
}
