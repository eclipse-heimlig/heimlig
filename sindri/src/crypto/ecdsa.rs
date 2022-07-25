use ecdsa::{
    elliptic_curve::{
        generic_array::typenum::Unsigned, sec1::ModulusSize, sec1::ToEncodedPoint, FieldSize,
        SecretKey,
    },
    signature::{Signer, Verifier},
    Signature, SignatureSize, SigningKey, VerifyingKey,
};
use rand::{CryptoRng, RngCore};

pub use p256::NistP256;
pub use p384::NistP384;

/// Size of the private key in bytes for NIST-P-256-based algorithms.
pub const NIST_P256_PRIVATE_KEY_SIZE: usize = FieldSize::<NistP256>::USIZE;
/// Size of the private key in bytes for NIST-P-384-based algorithms.
pub const NIST_P384_PRIVATE_KEY_SIZE: usize = FieldSize::<NistP384>::USIZE;
/// Size of the public key in bytes for NIST-P-256-based algorithms.
pub const NIST_P256_PUBLIC_KEY_SIZE: usize =
    <FieldSize<NistP256> as ModulusSize>::CompressedPointSize::USIZE;
/// Size of the public key in bytes for NIST-P-384-based algorithms.
pub const NIST_P384_PUBLIC_KEY_SIZE: usize =
    <FieldSize<NistP384> as ModulusSize>::CompressedPointSize::USIZE;
/// Size of the signature in bytes for NIST-P-256-based algorithms.
pub const NIST_P256_SIGNATURE_SIZE: usize = SignatureSize::<NistP256>::USIZE;
/// Size of the signature in bytes for NIST-P-384-based algorithms.
pub const NIST_P384_SIGNATURE_SIZE: usize = SignatureSize::<NistP384>::USIZE;

// the trait `ProjectiveArithmetic` is not implemented for `p521::NistP521`
// pub use p521::NistP521;

/// ECDSA errors
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Error {
    /// Invalid private key.
    InvalidPrivateKey,
    /// Invalid public key.
    InvalidPublicKey,
    /// Invalid sinature format.
    InvalidSignatureFormat,
}

macro_rules! define_ecdsa_impl {
    (
        $calculate_public_key:ident,
        $generate_keypair:ident,
        $sign:ident,
        $verify:ident,
        $curve:tt,
        $private_key_size:expr,
        $public_key_size:expr,
        $signature_size:expr
    ) => {
        pub fn $calculate_public_key(private_key: &[u8]) -> Result<[u8; $public_key_size], Error> {
            Ok(SecretKey::<$curve>::from_be_bytes(private_key)
                .map_err(|_| Error::InvalidPrivateKey)?
                .public_key()
                .to_encoded_point(true)
                .as_bytes()
                .try_into()
                .unwrap())
        }

        pub fn $generate_keypair<R>(
            rng: &mut R,
        ) -> ([u8; $private_key_size], [u8; $public_key_size])
        where
            R: CryptoRng + RngCore,
        {
            let private_key = SecretKey::<$curve>::random(rng).to_be_bytes().into();
            (private_key, $calculate_public_key(&private_key).unwrap())
        }

        pub fn $sign(private_key: &[u8], message: &[u8]) -> Result<[u8; $signature_size], Error> {
            Ok(SigningKey::<$curve>::from_bytes(private_key)
                .map_err(|_| Error::InvalidPrivateKey)?
                .sign(message)
                .as_ref()
                .try_into()
                .unwrap())
        }

        pub fn $verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, Error> {
            let signature =
                Signature::try_from(signature).map_err(|_| Error::InvalidSignatureFormat)?;
            Ok(VerifyingKey::<$curve>::from_sec1_bytes(public_key)
                .map_err(|_| Error::InvalidPublicKey)?
                .verify(message, &signature)
                .is_ok())
        }
    };
}

define_ecdsa_impl!(
    calculate_public_key_nist_p256,
    generate_keypair_nist_p256,
    sign_nist_p256,
    verify_nist_p256,
    NistP256,
    NIST_P256_PRIVATE_KEY_SIZE,
    NIST_P256_PUBLIC_KEY_SIZE,
    NIST_P256_SIGNATURE_SIZE
);
define_ecdsa_impl!(
    calculate_public_key_nist_p384,
    generate_keypair_nist_p384,
    sign_nist_p384,
    verify_nist_p384,
    NistP384,
    NIST_P384_PRIVATE_KEY_SIZE,
    NIST_P384_PUBLIC_KEY_SIZE,
    NIST_P384_SIGNATURE_SIZE
);

pub fn func() {
    SigningKey::<NistP256>::from_bytes(&[]).unwrap().sign(&[]);
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::crypto::rng;
    use heapless::Vec;

    const MESSAGE: &[u8] = b"Data is the pollution problem of the information age, and protecting privacy is the environmental challenge.";

    const PRIVATE_KEY_NIST_P256: &[u8; NIST_P256_PRIVATE_KEY_SIZE] =
        &b"Bruce Schneier is Chuck Norris!!";
    const PUBLIC_KEY_NIST_P256: &[u8; NIST_P256_PUBLIC_KEY_SIZE] = &[
        0x03, 0xbb, 0xca, 0xc0, 0x1b, 0x98, 0xb5, 0xa1, 0x59, 0xfc, 0x3e, 0xd7, 0x10, 0x3d, 0xaa,
        0x37, 0x41, 0x40, 0x58, 0x9e, 0x4d, 0x6f, 0x89, 0xe5, 0x00, 0x2e, 0xf7, 0x22, 0x98, 0xeb,
        0x73, 0xb9, 0xbd,
    ];
    const SIGNATURE_NIST_P256: &[u8; NIST_P256_SIGNATURE_SIZE] = &[
        0x9c, 0x38, 0xf6, 0xda, 0x3d, 0x7b, 0x38, 0xeb, 0xb7, 0xc2, 0x29, 0x61, 0xc0, 0xa5, 0x05,
        0xaf, 0x75, 0xaa, 0xef, 0x32, 0x31, 0x27, 0x20, 0xd4, 0x6d, 0xcd, 0xbe, 0x8e, 0xf2, 0xd5,
        0x2b, 0xfd, 0x6e, 0xb9, 0x4b, 0xe6, 0x79, 0x9b, 0x19, 0xfa, 0x52, 0xba, 0x8c, 0xbb, 0x25,
        0xb1, 0xf2, 0x54, 0x72, 0xd6, 0xec, 0xfd, 0xb1, 0x0f, 0x52, 0x2d, 0xdd, 0x13, 0xec, 0xbd,
        0x84, 0x89, 0xb8, 0x90,
    ];

    const PRIVATE_KEY_NIST_P384: &[u8; NIST_P384_PRIVATE_KEY_SIZE] =
        &b"Bruce Schneier is Chuck Norris of cryptography!!";
    const PUBLIC_KEY_NIST_P384: &[u8; NIST_P384_PUBLIC_KEY_SIZE] = &[
        0x03, 0x2c, 0xb7, 0xa8, 0xed, 0x97, 0xb0, 0xc5, 0x55, 0x30, 0x59, 0xaa, 0xad, 0x11, 0x54,
        0xbe, 0x1f, 0x63, 0x01, 0x9f, 0xe8, 0x8b, 0x60, 0x45, 0xb4, 0x01, 0xed, 0xe5, 0x1d, 0x74,
        0xfb, 0x25, 0x9c, 0xbe, 0x25, 0x20, 0x98, 0xe5, 0x45, 0x46, 0xff, 0x17, 0x68, 0xd3, 0x00,
        0x3a, 0x16, 0x9f, 0x70,
    ];
    const SIGNATURE_NIST_P384: &[u8; NIST_P384_SIGNATURE_SIZE] = &[
        0x90, 0x45, 0x1a, 0xef, 0x8c, 0x6a, 0x7d, 0x03, 0xc0, 0x51, 0x2d, 0x24, 0x63, 0xda, 0x92,
        0xa7, 0xe2, 0x53, 0x22, 0x7b, 0xdd, 0x02, 0x74, 0xc9, 0x07, 0xe5, 0xe7, 0xaa, 0x20, 0x7f,
        0x4d, 0xf7, 0xea, 0x78, 0x19, 0x7b, 0x76, 0x88, 0x7c, 0x85, 0xc8, 0x1c, 0x44, 0x16, 0x43,
        0x94, 0xcd, 0x83, 0xec, 0x49, 0xa4, 0x7d, 0xa1, 0xf9, 0xaa, 0x03, 0x59, 0xbe, 0x95, 0x4d,
        0x17, 0xaa, 0x5c, 0xe9, 0xb7, 0x5a, 0x6b, 0x44, 0xde, 0xb9, 0x7c, 0x9b, 0x5d, 0x83, 0x3f,
        0xef, 0x8c, 0xaa, 0x10, 0x04, 0xd3, 0xf4, 0x23, 0x9f, 0x71, 0x8e, 0x4b, 0xba, 0xdd, 0xe8,
        0x84, 0x63, 0xe7, 0x51, 0xa8, 0xfc,
    ];

    macro_rules! define_ecdsa_calculate_public_key_test {
        (
        $test: ident,
        $calculate_public_key: tt,
        $private_key: tt,
        $public_key:tt
    ) => {
            #[test]
            pub fn $test() {
                let public_key =
                    $calculate_public_key($private_key).expect("failed to calculate public key");
                assert_eq!(&public_key, $public_key);
            }
        };
    }

    define_ecdsa_calculate_public_key_test!(
        test_nist_p256_calculate_public_key,
        calculate_public_key_nist_p256,
        PRIVATE_KEY_NIST_P256,
        PUBLIC_KEY_NIST_P256
    );
    define_ecdsa_calculate_public_key_test!(
        test_nist_p384_calculate_public_key,
        calculate_public_key_nist_p384,
        PRIVATE_KEY_NIST_P384,
        PUBLIC_KEY_NIST_P384
    );

    macro_rules! define_ecdsa_generate_key_test {
        (
        $test: ident,
        $generate_keypair: tt,
        $sign: tt,
        $verify:tt
    ) => {
            #[test]
            pub fn $test() {
                let entropy = rng::test::TestEntropySource::default();
                let mut rng = rng::Rng::new(entropy, None);
                let (private_key, public_key) = $generate_keypair(&mut rng);

                let signature = $sign(&private_key, MESSAGE).expect("failed to sign");
                assert!($verify(&public_key, MESSAGE, &signature).expect("failed to verify"));
            }
        };
    }

    define_ecdsa_generate_key_test!(
        test_nist_p256_generate_key,
        generate_keypair_nist_p256,
        sign_nist_p256,
        verify_nist_p256
    );
    define_ecdsa_generate_key_test!(
        test_nist_p384_generate_key,
        generate_keypair_nist_p384,
        sign_nist_p384,
        verify_nist_p384
    );

    macro_rules! define_ecdsa_sign_verify_test {
        (
        $test: ident,
        $sign: tt,
        $verify:tt,
        $private_key: tt,
        $public_key:tt,
        $signature:tt
    ) => {
            #[test]
            pub fn $test() {
                let signature = $sign($private_key, MESSAGE).expect("failed to sign");
                assert_eq!(&signature, $signature);
                assert!($verify($public_key, MESSAGE, $signature).expect("failed to verify"));
            }
        };
    }

    define_ecdsa_sign_verify_test!(
        test_nist_p256_sign_verify,
        sign_nist_p256,
        verify_nist_p256,
        PRIVATE_KEY_NIST_P256,
        PUBLIC_KEY_NIST_P256,
        SIGNATURE_NIST_P256
    );
    define_ecdsa_sign_verify_test!(
        test_nist_p384_sign_verify,
        sign_nist_p384,
        verify_nist_p384,
        PRIVATE_KEY_NIST_P384,
        PUBLIC_KEY_NIST_P384,
        SIGNATURE_NIST_P384
    );

    macro_rules! define_ecdsa_verification_failure_test {
        (
        $test: ident,
        $sign: tt,
        $verify:tt,
        $private_key: tt,
        $public_key:tt,
        $signature:tt
    ) => {
            #[test]
            pub fn $test() {
                assert_eq!(
                    $verify($public_key, &MESSAGE[..MESSAGE.len() - 1], $signature)
                        .expect("verification failed"),
                    false
                );

                let mut wrong_signature = $signature.clone();
                wrong_signature[0] ^= 1;
                assert_eq!(
                    $verify($public_key, &MESSAGE, &wrong_signature).expect("verification failed"),
                    false
                );
            }
        };
    }

    define_ecdsa_verification_failure_test!(
        test_nist_p256_verification_failure,
        sign_nist_p256,
        verify_nist_p256,
        PRIVATE_KEY_NIST_P256,
        PUBLIC_KEY_NIST_P256,
        SIGNATURE_NIST_P256
    );
    define_ecdsa_verification_failure_test!(
        test_nist_p384_verification_failure,
        sign_nist_p384,
        verify_nist_p384,
        PRIVATE_KEY_NIST_P384,
        PUBLIC_KEY_NIST_P384,
        SIGNATURE_NIST_P384
    );

    macro_rules! define_ecdsa_errors_test {
        (
        $test: ident,
        $calculate_public_key:tt,
        $sign: tt,
        $verify:tt,
        $private_key: tt,
        $public_key:tt,
        $signature:tt,
        $wrong_private_key_sizes:tt,
        $wrong_public_key_sizes:tt,
        $wrong_signature_sizes:tt
    ) => {
            #[test]
            pub fn $test() {
                const MAX_SIZE: usize = 96;
                for size in $wrong_private_key_sizes {
                    let mut wrong_private_key: Vec<u8, MAX_SIZE> = Vec::new();
                    wrong_private_key.resize(size, 0).unwrap();
                    assert_eq!(
                        $sign(&wrong_private_key, MESSAGE),
                        Err(Error::InvalidPrivateKey)
                    );

                    assert_eq!(
                        $calculate_public_key(&wrong_private_key),
                        Err(Error::InvalidPrivateKey)
                    );
                }

                for size in $wrong_public_key_sizes {
                    let mut wrong_public_key: Vec<u8, MAX_SIZE> = Vec::new();
                    wrong_public_key.resize(size, 0).unwrap();
                    assert_eq!(
                        $verify(&wrong_public_key, MESSAGE, $signature),
                        Err(Error::InvalidPublicKey)
                    );
                }

                for size in $wrong_signature_sizes {
                    let mut wrong_signature: Vec<u8, MAX_SIZE> = Vec::new();
                    wrong_signature.resize(size, 0).unwrap();
                    assert_eq!(
                        $verify($public_key, MESSAGE, &wrong_signature),
                        Err(Error::InvalidSignatureFormat)
                    );
                }
            }
        };
    }

    define_ecdsa_errors_test!(
        test_nist_p256_errors,
        calculate_public_key_nist_p256,
        sign_nist_p256,
        verify_nist_p256,
        PRIVATE_KEY_NIST_P256,
        PUBLIC_KEY_NIST_P256,
        SIGNATURE_NIST_P256,
        [0, 1, 4, 16, 33, 48, 49, 64],
        [0, 1, 4, 16, 32, 48, 49, 64],
        [0, 1, 4, 16, 32, 33, 48, 49]
    );
    define_ecdsa_errors_test!(
        test_nist_p384_errors,
        calculate_public_key_nist_p384,
        sign_nist_p384,
        verify_nist_p384,
        PRIVATE_KEY_NIST_P384,
        PUBLIC_KEY_NIST_P384,
        SIGNATURE_NIST_P384,
        [0, 1, 4, 16, 32, 33, 49, 64, 96],
        [0, 1, 4, 16, 32, 33, 48, 64, 96],
        [0, 1, 4, 16, 32, 33, 48, 49, 64]
    );
}
