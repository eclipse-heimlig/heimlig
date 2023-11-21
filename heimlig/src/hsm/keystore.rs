use const_default::ConstDefault;

/// Identifier to reference HSM keys
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct KeyId(pub u32);

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
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

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum KeyType {
    Symmetric128Bits,
    Symmetric192Bits,
    Symmetric256Bits,
    EccKeypairNistP256,
    EccKeypairNistP384,
}

#[derive(ConstDefault, Copy, Clone, Debug, Default)]
pub struct KeyPermissions {
    /// Whether or not the key can be set with outside data.
    pub import: bool,
    /// Whether or not private key material can be exported. Both symmetric keys and private
    /// asymmetric keys are considered private. Public keys are always exportable.
    pub export: bool,
    /// Whether or not the key can be overwritten (either through import or generation).
    pub overwrite: bool,
    /// Whether or not the key can be deleted
    pub delete: bool,
}

#[derive(Copy, Clone, Debug)]
pub struct KeyInfo {
    pub id: KeyId,
    pub ty: KeyType,
    pub permissions: KeyPermissions,
}

impl From<KeyId> for u32 {
    fn from(value: KeyId) -> Self {
        value.0
    }
}

impl From<u32> for KeyId {
    fn from(value: u32) -> Self {
        KeyId(value)
    }
}

impl KeyType {
    pub const MAX_SYMMETRIC_KEY_SIZE: usize = KeyType::Symmetric256Bits.key_size();
    pub const MAX_PUBLIC_KEY_SIZE: usize = KeyType::EccKeypairNistP384.public_key_size();
    pub const MAX_PRIVATE_KEY_SIZE: usize = KeyType::EccKeypairNistP384.private_key_size();

    pub const fn is_symmetric(&self) -> bool {
        matches!(
            self,
            KeyType::Symmetric128Bits | KeyType::Symmetric192Bits | KeyType::Symmetric256Bits
        )
    }

    pub const fn is_asymmetric(&self) -> bool {
        !self.is_symmetric()
    }

    pub const fn curve_size(&self) -> usize {
        match self {
            KeyType::EccKeypairNistP256 => 32,
            KeyType::EccKeypairNistP384 => 48,
            _ => 0,
        }
    }

    pub const fn public_key_size(&self) -> usize {
        2 * self.curve_size()
    }

    pub const fn private_key_size(&self) -> usize {
        self.curve_size()
    }

    pub const fn key_size(&self) -> usize {
        match self {
            KeyType::Symmetric128Bits => 16,
            KeyType::Symmetric192Bits => 24,
            KeyType::Symmetric256Bits => 32,
            _ => self.public_key_size() + self.private_key_size(),
        }
    }
}

pub trait KeyStore {
    fn get_key_info(&self, id: KeyId) -> Result<KeyInfo, Error>;

    /// Write symmetric key to storage.
    fn import_symmetric_key(
        &mut self,
        id: KeyId,
        data: &[u8],
        overwrite: bool,
    ) -> Result<(), Error>;

    /// Write asymmetric key pair to storage.
    fn import_key_pair(
        &mut self,
        id: KeyId,
        public_key: &[u8],
        private_key: &[u8],
        overwrite: bool,
    ) -> Result<(), Error>;

    /// Read symmetric key from storage.
    ///
    /// returns: The number of bytes written to `dest` or and error.
    fn export_symmetric_key<'data>(
        &self,
        id: KeyId,
        dest: &'data mut [u8],
    ) -> Result<&'data [u8], Error>;

    /// Read asymmetric public key from storage.
    ///
    /// returns: The number of bytes written to `dest` or and error.
    fn export_public_key<'data>(
        &self,
        id: KeyId,
        dest: &'data mut [u8],
    ) -> Result<&'data [u8], Error>;

    /// Read asymmetric private key from storage.
    ///
    /// returns: The number of bytes written to `dest` or and error.
    fn export_private_key<'data>(
        &self,
        id: KeyId,
        dest: &'data mut [u8],
    ) -> Result<&'data [u8], Error>;

    /// Read symmetric key from storage.
    ///
    /// Unlike `export()`, this function exports keys even if their permissions do not allow so.
    /// It is supposed to be used by workers who need to use to do their work and is not reachable
    /// from outside Heimlig. Workers operate inside Heimlig and are trusted.  
    ///
    /// returns: The number of bytes written to `dest` or and error.
    fn export_symmetric_key_unchecked<'data>(
        &self,
        id: KeyId,
        dest: &'data mut [u8],
    ) -> Result<&'data [u8], Error>;

    /// Read asymmetric private key from storage.
    ///
    /// Unlike `export()`, this function exports keys even if their permissions do not allow so.
    /// It is supposed to be used by workers who need to use to do their work and is not reachable
    /// from outside Heimlig. Workers operate inside Heimlig and are trusted.  
    ///
    /// returns: The number of bytes written to `dest` or and error.
    fn export_private_key_unchecked<'data>(
        &self,
        id: KeyId,
        dest: &'data mut [u8],
    ) -> Result<&'data [u8], Error>;

    /// Delete the key for given ID.
    ///
    /// return: An error, if the key could not be found.
    fn delete(&mut self, id: KeyId) -> Result<(), Error>;

    /// Returns whether or not a key for the given 'id' is present in the store.
    fn is_stored(&self, id: KeyId) -> bool;

    /// Get the size of a key.
    fn size(&self, id: KeyId) -> Result<usize, Error>;
}
