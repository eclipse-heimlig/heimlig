use crate::common::jobs;
use crate::crypto;
use crate::hsm::keystore;

/// Raw version of jobs::Error
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum JobErrorRaw {
    /// No worker found for received request type.
    NoWorkerForRequest,
    /// A worker encountered a request type that it cannot handle.  
    UnexpectedRequestType,
    /// The amount of requested data was too large.
    RequestTooLarge,
    /// No key store present.
    NoKeyStore,
    /// Failed to send through channel.
    Send,
    /// A cryptographic error occurred.
    Crypto(CryptoErrorRaw),
    /// A key store error occurred.
    KeyStore(KeyStoreErrorRaw),
}

/// Raw version of crypto::Error
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CryptoErrorRaw {
    /// Error during encryption.
    Encrypt,
    /// Error during decryption.
    Decrypt,
    /// Invalid size of the symmetric key.
    InvalidSymmetricKeySize,
    /// Invalid size of the nonce or the initialization vector.
    InvalidIvSize,
    /// Size of the provided tag is invalid.
    InvalidTagSize,
    /// Size of the provided buffer is invalid.
    InvalidBufferSize,
    /// Provided plaintext or ciphertext is not padded.
    InvalidPadding,
    /// Invalid private key format.
    InvalidPrivateKey,
    /// Invalid public key format.
    InvalidPublicKey,
    /// Invalid signature.
    InvalidSignature,
}

/// Raw version of keystore::Error
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum KeyStoreErrorRaw {
    /// The operation is not permitted
    NotAllowed,
    /// The requested key was not found.
    KeyNotFound,
    /// The key store cannot handle the amount of requested keys.
    KeyStoreTooSmall,
    /// Attempted to create a key store with duplicate storage IDs.
    DuplicateIds,
    /// The requested ID is not defined.
    InvalidKeyId,
    /// The type of the key (symmetric/asymmetric) does not match.
    InvalidKeyType,
    /// Size of the provided buffer is invalid.
    InvalidBufferSize,
}

impl From<jobs::Error> for JobErrorRaw {
    fn from(value: jobs::Error) -> Self {
        match value {
            jobs::Error::NoWorkerForRequest => JobErrorRaw::NoWorkerForRequest,
            jobs::Error::UnexpectedRequestType => JobErrorRaw::UnexpectedRequestType,
            jobs::Error::Crypto(e) => JobErrorRaw::Crypto(e.into()),
            jobs::Error::RequestTooLarge => JobErrorRaw::RequestTooLarge,
            jobs::Error::NoKeyStore => JobErrorRaw::NoKeyStore,
            jobs::Error::KeyStore(e) => JobErrorRaw::KeyStore(e.into()),
            jobs::Error::Send => JobErrorRaw::Send,
        }
    }
}

impl From<crypto::Error> for CryptoErrorRaw {
    fn from(value: crypto::Error) -> Self {
        match value {
            crypto::Error::Encrypt => CryptoErrorRaw::Encrypt,
            crypto::Error::Decrypt => CryptoErrorRaw::Decrypt,
            crypto::Error::InvalidSymmetricKeySize => CryptoErrorRaw::InvalidSymmetricKeySize,
            crypto::Error::InvalidIvSize => CryptoErrorRaw::InvalidIvSize,
            crypto::Error::InvalidTagSize => CryptoErrorRaw::InvalidTagSize,
            crypto::Error::InvalidBufferSize => CryptoErrorRaw::InvalidBufferSize,
            crypto::Error::InvalidPadding => CryptoErrorRaw::InvalidPadding,
            crypto::Error::InvalidPrivateKey => CryptoErrorRaw::InvalidPrivateKey,
            crypto::Error::InvalidPublicKey => CryptoErrorRaw::InvalidPublicKey,
            crypto::Error::InvalidSignature => CryptoErrorRaw::InvalidSignature,
        }
    }
}

impl From<keystore::Error> for KeyStoreErrorRaw {
    fn from(value: keystore::Error) -> Self {
        match value {
            keystore::Error::NotAllowed => KeyStoreErrorRaw::NotAllowed,
            keystore::Error::KeyNotFound => KeyStoreErrorRaw::KeyNotFound,
            keystore::Error::KeyStoreTooSmall => KeyStoreErrorRaw::KeyStoreTooSmall,
            keystore::Error::DuplicateIds => KeyStoreErrorRaw::DuplicateIds,
            keystore::Error::InvalidKeyId => KeyStoreErrorRaw::InvalidKeyId,
            keystore::Error::InvalidKeyType => KeyStoreErrorRaw::InvalidKeyType,
            keystore::Error::InvalidBufferSize => KeyStoreErrorRaw::InvalidBufferSize,
        }
    }
}
