use crate::crypto::Error;

use ecdsa::{
    elliptic_curve::{
        generic_array::{typenum::Unsigned, ArrayLength, GenericArray},
        ops::Invert,
        sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint},
        subtle::CtOption,
        AffinePoint, Curve, CurveArithmetic, FieldBytesSize, Scalar, SecretKey,
    },
    hazmat::{DigestPrimitive, SignPrimitive},
    signature::{
        digest::Digest,
        hazmat::{PrehashSigner, PrehashVerifier},
        DigestSigner,
    },
    EncodedPoint, PrimeCurve, Signature, SignatureSize, SigningKey, VerifyingKey,
};
use p256::NistP256;
use p384::NistP384;
use rand_chacha::rand_core::{CryptoRng, RngCore};

type PrivateKeySize<C> = FieldBytesSize<C>;
type PrivateKeyBytes<C> = GenericArray<u8, PrivateKeySize<C>>;
type PublicKeySize<C> = <FieldBytesSize<C> as ModulusSize>::UntaggedPointSize;
type PublicKeyBytes<C> = GenericArray<u8, PublicKeySize<C>>;
type DigestSize<C> = FieldBytesSize<C>;

fn check_digest_and_signature_sizes<C>(digest: &[u8], signature: &[u8]) -> Result<(), Error>
where
    C: Curve,
    SignatureSize<C>: ArrayLength<u8>,
{
    if signature.len() != SignatureSize::<C>::USIZE {
        return Err(Error::InvalidSignatureSize);
    }

    if digest.len() != DigestSize::<C>::USIZE {
        return Err(Error::InvalidDigestSize);
    }

    Ok(())
}

fn sign<C>(private_key: &[u8], message: &[u8], signature: &mut [u8]) -> Result<(), Error>
where
    C: Curve + CurveArithmetic + DigestPrimitive,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
    SigningKey<C>: DigestSigner<C::Digest, Signature<C>>,
{
    sign_prehashed(
        private_key,
        &C::Digest::new_with_prefix(message).finalize(),
        signature,
    )?;

    Ok(())
}

fn sign_prehashed<C>(private_key: &[u8], digest: &[u8], signature: &mut [u8]) -> Result<(), Error>
where
    C: Curve + CurveArithmetic + DigestPrimitive,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
    SigningKey<C>: DigestSigner<C::Digest, Signature<C>>,
{
    check_digest_and_signature_sizes::<C>(digest, signature)?;

    let signing_key =
        SigningKey::<C>::from_slice(private_key).map_err(|_| Error::InvalidPrivateKey)?;

    let output: Signature<C> = signing_key
        .sign_prehash(digest)
        .map_err(|_| Error::InvalidDigestSize)?;
    signature.copy_from_slice(&output.to_bytes());

    Ok(())
}

fn verify<C>(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error>
where
    C: PrimeCurve + CurveArithmetic + DigestPrimitive,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
    SignatureSize<C>: ArrayLength<u8>,
    VerifyingKey<C>: PrehashVerifier<Signature<C>>,
{
    verify_prehashed::<C>(
        public_key,
        &C::Digest::new_with_prefix(message).finalize(),
        signature,
    )
}

fn verify_prehashed<C>(public_key: &[u8], digest: &[u8], signature: &[u8]) -> Result<(), Error>
where
    C: PrimeCurve + CurveArithmetic + DigestPrimitive,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
    SignatureSize<C>: ArrayLength<u8>,
    VerifyingKey<C>: PrehashVerifier<Signature<C>>,
{
    check_digest_and_signature_sizes::<C>(digest, signature)?;

    if public_key.len() != PublicKeySize::<C>::USIZE {
        return Err(Error::InvalidPublicKey);
    }

    let verifying_key = VerifyingKey::<C>::from_encoded_point(
        &EncodedPoint::<C>::from_untagged_bytes(public_key.into()),
    )
    .map_err(|_| Error::InvalidPublicKey)?;

    let signature =
        Signature::<C>::from_bytes(signature.into()).map_err(|_| Error::InvalidSignature)?;

    verifying_key
        .verify_prehash(digest, &signature)
        .map_err(|_| Error::InvalidSignature)
}

fn generate_key_pair<R, C>(rng: &mut R) -> (PrivateKeyBytes<C>, PublicKeyBytes<C>)
where
    R: CryptoRng + RngCore,
    C: Curve + CurveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    let secret_key = SecretKey::<C>::random(rng);
    let public_key = secret_key.public_key();

    let encoded_point = public_key.to_encoded_point(false);

    (
        secret_key.to_bytes(),
        // Uncompressed encoded elliptic curve point consists of the one-byte tag 0x04
        // that is followed by concatenated X and Y coordinates as described in
        // SEC 1: Elliptic Curve Cryptography (Version 2.0)
        // section 2.3.3 Elliptic-Curve-Point-to-Octet-String Conversion (page 10).
        PublicKeyBytes::<C>::clone_from_slice(&encoded_point.as_bytes()[1..]),
    )
}

macro_rules! define_nist_impl {
    (
        $curve:tt,
        $sign:ident,
        $sign_prehashed:ident,
        $verify:ident,
        $verify_prehashed:ident,
        $generate_key_pair:ident,
        $signature_size:ident,
        $signature_size_str:expr,
        $digest_size:ident,
        $digest_size_str:expr,
        $private_key_size:ident,
        $private_key_size_str:expr,
        $public_key_size:ident,
        $public_key_size_str:expr,
        $doc:expr
    ) => {
        #[doc=$doc]
        /// signature size in bytes.
        pub const $signature_size: usize = SignatureSize::<$curve>::USIZE;

        #[doc=$doc]
        /// digest size in bytes.
        pub const $digest_size: usize = DigestSize::<$curve>::USIZE;

        #[doc=$doc]
        /// private key size in bytes.
        pub const $private_key_size: usize = PrivateKeySize::<$curve>::USIZE;

        #[doc=$doc]
        /// public key size in bytes.
        pub const $public_key_size: usize = PublicKeySize::<$curve>::USIZE;

        #[doc=$doc]
        /// signing the message function.
        ///
        ///  # Arguments
        ///
        /// * `private_key`: A slice containing private key bytes.
        ///   The private key has to be `
        #[doc=$private_key_size_str]
        /// ` bytes long.
        /// * `message`: A slice containing the message to sign bytes.
        /// * `signature`: A mutable slice where the computed signature will be stored.
        ///   The signature slice length has to be `
        #[doc=$signature_size_str]
        /// ` bytes long.
        ///
        /// # Errors
        ///
        /// The function returns an error if:
        /// * `InvalidSignatureSize`: The length of the `signature` is not `
        #[doc=$signature_size_str]
        /// ` bytes.
        /// * `InvalidPrivateKey`: The length of the `private_key` is not `
        #[doc=$private_key_size_str]
        /// ` bytes.
        pub fn $sign(
            private_key: &[u8],
            message: &[u8],
            signature: &mut [u8],
        ) -> Result<(), Error> {
            sign::<$curve>(private_key, message, signature)
        }

        #[doc=$doc]
        /// signing prehashed message function.
        ///
        ///  # Arguments
        ///
        /// * `private_key`: A slice containing private key bytes.
        ///   The private key has to be `
        #[doc=$private_key_size_str]
        /// ` bytes long.
        /// * `digest`: A slice containing the digest to sign bytes.
        ///    The digest has to be `
        #[doc=$digest_size_str]
        /// ` bytes long.
        /// * `signature`: A mutable slice where the computed signature will be stored.
        ///   The signature slice length has to be `
        #[doc=$signature_size_str]
        /// ` bytes long.
        ///
        /// # Errors
        ///
        /// The function returns an error if:
        /// * `InvalidSignatureSize`: The length of the `signature` is not `
        #[doc=$signature_size_str]
        /// ` bytes.
        /// * `InvalidDigest`: The length of the `digest` is not `
        #[doc=$digest_size_str]
        /// ` bytes.
        /// * `InvalidPrivateKey`: The length of the `private_key` is not `
        #[doc=$private_key_size_str]
        /// ` bytes.
        pub fn $sign_prehashed(
            private_key: &[u8],
            digest: &[u8],
            signature: &mut [u8],
        ) -> Result<(), Error> {
            sign_prehashed::<$curve>(private_key, digest, signature)
        }

        #[doc=$doc]
        /// verifying signature of the message function.
        ///
        ///  # Arguments
        ///
        /// * `public_key`: A slice containing public key bytes.
        ///   The public key has to be `
        #[doc=$public_key_size_str]
        /// ` bytes long.
        /// * `message`: A slice containing the message to verify bytes.
        /// * `signature`: A slice containing the signature to verify bytes.
        ///   The signature slice length has to be `
        #[doc=$signature_size_str]
        /// ` bytes long.
        ///
        /// # Errors
        ///
        /// The function returns an error if:
        /// * `InvalidSignatureSize`: The length of the `signature` is not `
        #[doc=$signature_size_str]
        /// ` bytes.
        /// * `InvalidSignature`: `signature` contains invalid bytes.
        /// * `InvalidPublicKey`: The length of the `public_key` is not `
        #[doc=$public_key_size_str]
        /// ` bytes or `public_key` contains invalid bytes.
        pub fn $verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error> {
            verify::<$curve>(public_key, message, signature)
        }

        #[doc=$doc]
        /// verifying signature of prehashed message function.
        ///
        ///  # Arguments
        ///
        /// * `public_key`: A slice containing public key bytes.
        ///   The public key has to be `
        #[doc=$public_key_size_str]
        /// ` bytes long.
        /// * `digest`: A slice containing the digest to verify bytes.
        ///    The digest has to be `
        #[doc=$digest_size_str]
        /// ` bytes long.
        /// * `signature`: A slice containing the signature to verify bytes.
        ///   The signature slice length has to be `
        #[doc=$signature_size_str]
        /// ` bytes long.
        ///
        /// # Errors
        ///
        /// The function returns an error if:
        /// * `InvalidSignature`: The length of the `signature` is not `
        #[doc=$signature_size_str]
        /// ` bytes.
        /// * `InvalidSignature`: `signature` contains invalid bytes.
        /// * `InvalidDigest`: The length of the `digest` is not `
        #[doc=$digest_size_str]
        /// ` bytes.
        /// * `InvalidPublicKey`: The length of the `public_key` is not `
        #[doc=$public_key_size_str]
        /// ` bytes or `public_key` contains invalid bytes.
        pub fn $verify_prehashed(
            public_key: &[u8],
            digest: &[u8],
            signature: &[u8],
        ) -> Result<(), Error> {
            verify_prehashed::<$curve>(public_key, digest, signature)
        }

        #[doc=$doc]
        /// generate key pair function.
        ///
        ///  # Arguments
        ///
        /// * `rng`: A mutable reference to a random number generator that implements
        ///   `CryptoRng` and `RngCore`.
        ///
        /// # Returns
        ///
        /// A tuple containing the generated private key and its corresponding public key.
        /// The private and the public keys are represented as a fixed-size arrays of `
        #[doc=$private_key_size_str]
        /// ` and `
        #[doc=$public_key_size_str]
        /// ` bytes accordingly.
        pub fn $generate_key_pair<R>(
            rng: &mut R,
        ) -> ([u8; $private_key_size], [u8; $public_key_size])
        where
            R: CryptoRng + RngCore,
        {
            let (private_key, public_key) = generate_key_pair::<_, $curve>(rng);

            let mut private_key_bytes = [0; $private_key_size];
            let mut public_key_bytes = [0; $public_key_size];

            private_key_bytes.copy_from_slice(&private_key);
            public_key_bytes.copy_from_slice(&public_key);

            (private_key_bytes, public_key_bytes)
        }
    };

    (
        $curve:tt,
        $sign:ident,
        $sign_prehashed:ident,
        $verify:ident,
        $verify_prehashed:ident,
        $generate_key_pair:ident,
        $signature_size:ident,
        $digest_size:ident,
        $private_key_size:ident,
        $public_key_size:ident,
        $doc:expr
    ) => {
        define_nist_impl!(
            $curve,
            $sign,
            $sign_prehashed,
            $verify,
            $verify_prehashed,
            $generate_key_pair,
            $signature_size,
            stringify!($signature_size),
            $digest_size,
            stringify!($digest_size),
            $private_key_size,
            stringify!($private_key_size),
            $public_key_size,
            stringify!($public_key_size),
            $doc
        );
    };
}

define_nist_impl!(
    NistP256,
    nist_p256_sign,
    nist_p256_sign_prehashed,
    nist_p256_verify,
    nist_p256_verify_prehashed,
    nist_p256_generate_key_pair,
    NIST_P256_SIGNATURE_SIZE,
    NIST_P256_DIGEST_SIZE,
    NIST_P256_PRIVATE_KEY_SIZE,
    NIST_P256_PUBLIC_KEY_SIZE,
    "NIST P-256"
);

define_nist_impl!(
    NistP384,
    nist_p384_sign,
    nist_p384_sign_prehashed,
    nist_p384_verify,
    nist_p384_verify_prehashed,
    nist_p384_generate_key_pair,
    NIST_P384_SIGNATURE_SIZE,
    NIST_P384_DIGEST_SIZE,
    NIST_P384_PRIVATE_KEY_SIZE,
    NIST_P384_PUBLIC_KEY_SIZE,
    "NIST P-384"
);

#[cfg(test)]
mod test {
    use super::*;
    use rand_chacha::rand_core::SeedableRng;

    const MESSAGE: &[u8] =
        b"You have to understand the rules in the first place if you're going to break them.";

    macro_rules! define_nist_sign_verify_test {
        (
            $test_name:ident,
            $curve:tt,
            $sign:ident,
            $sign_prehashed:ident,
            $verify:ident,
            $verify_prehashed:ident,
            $generate_key_pair:ident,
            $signature_size:ident,
            $digest_size:ident
        ) => {
            #[test]
            fn $test_name() {
                let mut rng = rand_chacha::ChaCha20Rng::from_seed([0u8; 32]);

                let (private_key, public_key) = $generate_key_pair(&mut rng);

                let mut signature_message = [0u8; $signature_size];
                let mut signature_prehashed_message = [0u8; $signature_size];
                let digest =
                    <$curve as DigestPrimitive>::Digest::new_with_prefix(MESSAGE).finalize();

                $sign(&private_key, MESSAGE, &mut signature_message)
                    .expect("signing of the message failed");
                $sign_prehashed(
                    &private_key,
                    digest.as_slice(),
                    &mut signature_prehashed_message,
                )
                .expect("signing of prehashed message failed");

                assert_eq!(signature_message, signature_prehashed_message);

                $verify(&public_key, MESSAGE, &signature_message)
                    .expect("verifying signature of the message failed");
                $verify_prehashed(&public_key, digest.as_slice(), &signature_prehashed_message)
                    .expect("verifying signature of prehashed message failed");
            }
        };
    }

    define_nist_sign_verify_test!(
        nist_p256_sign_verify_test,
        NistP256,
        nist_p256_sign,
        nist_p256_sign_prehashed,
        nist_p256_verify,
        nist_p256_verify_prehashed,
        nist_p256_generate_key_pair,
        NIST_P256_SIGNATURE_SIZE,
        NIST_P256_DIGEST_SIZE
    );

    define_nist_sign_verify_test!(
        nist_p384_sign_verify_test,
        NistP384,
        nist_p384_sign,
        nist_p384_sign_prehashed,
        nist_p384_verify,
        nist_p384_verify_prehashed,
        nist_p384_generate_key_pair,
        NIST_P384_SIGNATURE_SIZE,
        NIST_P384_DIGEST_SIZE
    );

    macro_rules! define_nist_error_test {
        (
            $test_name:ident,
            $curve:tt,
            $sign:ident,
            $sign_prehashed:ident,
            $verify:ident,
            $verify_prehashed:ident,
            $generate_key_pair:ident,
            $signature_size:ident,
            $digest_size:ident,
            $private_key_size:ident,
            $public_key_size:ident
        ) => {
            #[test]
            fn $test_name() {
                let mut buffer = [0u8; 128];

                let mut signature = [0u8; $signature_size];

                let mut rng = rand_chacha::ChaCha20Rng::from_seed([0u8; 32]);
                let (private_key, public_key) = $generate_key_pair(&mut rng);

                let digest =
                    <$curve as DigestPrimitive>::Digest::new_with_prefix(MESSAGE).finalize();

                // Invalid private key size.
                for size in [0, 1, 16, 32, 48, 64] {
                    if size == $private_key_size {
                        continue;
                    }
                    let invalid_private_key = &buffer[..size];
                    assert_eq!(
                        $sign(invalid_private_key, MESSAGE, &mut signature),
                        Err(Error::InvalidPrivateKey)
                    );

                    assert_eq!(
                        $sign_prehashed(invalid_private_key, digest.as_slice(), &mut signature),
                        Err(Error::InvalidPrivateKey)
                    );
                }

                // Invalid public key size.
                for size in [0, 1, 16, 32, 48, 64, 96, 128] {
                    if size == $public_key_size {
                        continue;
                    }
                    let invalid_public_key = &buffer[..size];
                    assert_eq!(
                        $verify(invalid_public_key, MESSAGE, &signature),
                        Err(Error::InvalidPublicKey)
                    );

                    assert_eq!(
                        $verify_prehashed(invalid_public_key, digest.as_slice(), &signature),
                        Err(Error::InvalidPublicKey)
                    );
                }

                // Invalid signature size.
                for size in [0, 1, 16, 32, 48, 64] {
                    if size == $signature_size {
                        continue;
                    }
                    let invalid_signature = &mut buffer[..size];
                    assert_eq!(
                        $sign(&private_key, MESSAGE, invalid_signature),
                        Err(Error::InvalidSignatureSize)
                    );

                    assert_eq!(
                        $sign_prehashed(&private_key, digest.as_slice(), invalid_signature),
                        Err(Error::InvalidSignatureSize)
                    );

                    assert_eq!(
                        $verify(&public_key, MESSAGE, invalid_signature),
                        Err(Error::InvalidSignatureSize)
                    );

                    assert_eq!(
                        $verify_prehashed(&public_key, digest.as_slice(), invalid_signature),
                        Err(Error::InvalidSignatureSize)
                    );
                }

                // Invalid digest size.
                for size in [0, 1, 16, 32, 48, 64] {
                    if size == $digest_size {
                        continue;
                    }
                    let invalid_digest = &buffer[..size];
                    assert_eq!(
                        $sign_prehashed(&private_key, invalid_digest, &mut signature),
                        Err(Error::InvalidDigestSize)
                    );

                    assert_eq!(
                        $verify_prehashed(&public_key, invalid_digest, &mut signature),
                        Err(Error::InvalidDigestSize)
                    );
                }

                // Invalid signature.
                $sign(&private_key, MESSAGE, &mut signature).expect("signing failed");
                signature[0] ^= 1;
                assert_eq!(
                    $verify(&public_key, MESSAGE, &signature),
                    Err(Error::InvalidSignature)
                );
                assert_eq!(
                    $verify_prehashed(&public_key, digest.as_slice(), &signature),
                    Err(Error::InvalidSignature)
                );
            }
        };
    }

    define_nist_error_test!(
        nist_p256_error_test,
        NistP256,
        nist_p256_sign,
        nist_p256_sign_prehashed,
        nist_p256_verify,
        nist_p256_verify_prehashed,
        nist_p256_generate_key_pair,
        NIST_P256_SIGNATURE_SIZE,
        NIST_P256_DIGEST_SIZE,
        NIST_P256_PRIVATE_KEY_SIZE,
        NIST_P256_PUBLIC_KEY_SIZE
    );

    define_nist_error_test!(
        nist_p384_error_test,
        NistP384,
        nist_p384_sign,
        nist_p384_sign_prehashed,
        nist_p384_verify,
        nist_p384_verify_prehashed,
        nist_p384_generate_key_pair,
        NIST_P384_SIGNATURE_SIZE,
        NIST_P384_DIGEST_SIZE,
        NIST_P384_PRIVATE_KEY_SIZE,
        NIST_P384_PUBLIC_KEY_SIZE
    );
}
