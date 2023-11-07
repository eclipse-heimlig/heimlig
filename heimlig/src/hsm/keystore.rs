use const_default::ConstDefault;
use heapless::Vec;

/// Identifier to reference HSM keys
pub type KeyId = u32;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum KeyType {
    Symmetric128Bits,
    Symmetric192Bits,
    Symmetric256Bits,
    EccKeypairNistP256,
    EccKeypairNistP384,
}

#[derive(Copy, ConstDefault, Clone, Debug, Default)]
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

impl KeyType {
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

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// The operation is not permitted
    NotAllowed,
    /// The requested ID is not defined.
    InvalidKeyId,
    /// The type of the key (symmetric/asymmetric) does not match.
    InvalidKeyType,
    /// The provided memory buffer was too small.
    InvalidBufferSize,
    /// The requested key was not found.
    KeyNotFound,
    /// The key store cannot handle the amount of requested keys.
    KeyStoreTooSmall,
    /// Attempted to create a key store with duplicate storage IDs.
    DuplicateIds,
}

pub trait KeyStore {
    fn get_key_info(&self, id: KeyId) -> Result<KeyInfo, Error>;

    /// Write symmetric key to storage.
    fn import_symmetric_key(&mut self, id: KeyId, data: &[u8]) -> Result<(), Error>;

    /// Write asymmetric key pair to storage.
    fn import_key_pair(
        &mut self,
        id: KeyId,
        public_key: &[u8],
        private_key: &[u8],
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

/// Internal layout data structure of the key store. Keys are saved at an offset in the internal key
/// buffer. The public and private keys of an asymmetric keys are concatenated.
#[derive(Copy, Clone, Debug)]
struct KeyLayout {
    /// Static information about this key
    info: KeyInfo,
    /// Offset at which this key start in the internal key buffer of the store.
    offset: usize,
    /// The real size of this key (in contrast to its maximum size)
    actual_size: usize,
}

pub struct MemoryKeyStore<const STORAGE_SIZE: usize, const MAX_KEYS: usize> {
    storage: [u8; STORAGE_SIZE],
    layout: Vec<KeyLayout, MAX_KEYS>, // Sorted by key ID
}

impl<const STORAGE_SIZE: usize, const MAX_KEYS: usize> MemoryKeyStore<STORAGE_SIZE, MAX_KEYS> {
    pub fn try_new(key_infos: &[KeyInfo]) -> Result<Self, Error> {
        // Check input sizes
        let total_size: usize = key_infos
            .iter()
            .map(|key_info| key_info.ty.key_size())
            .sum();
        if key_infos.len() > MAX_KEYS || total_size > STORAGE_SIZE {
            return Err(Error::KeyStoreTooSmall);
        }

        // Sort by key ID
        let mut key_infos: Vec<_, MAX_KEYS> = key_infos.iter().collect();
        key_infos.sort_unstable_by_key(|key_info| key_info.id);

        // Check for duplicate IDs
        if key_infos.windows(2).any(|w| w[0].id == w[1].id) {
            return Err(Error::DuplicateIds);
        }

        // Create new key store
        let mut key_store = MemoryKeyStore {
            storage: [0u8; STORAGE_SIZE],
            layout: Default::default(),
        };
        let mut offset = 0;
        for key_info in key_infos.into_iter() {
            key_store
                .layout
                .push(KeyLayout {
                    info: *key_info,
                    offset,
                    actual_size: 0,
                })
                .expect("too many key definitions");
            offset += key_info.ty.key_size();
        }
        Ok(key_store)
    }

    fn get_key_layout(&self, id: KeyId) -> Option<&KeyLayout> {
        let index = self
            .layout
            .as_slice()
            .binary_search_by_key(&id, |key_layout| key_layout.info.id)
            .ok()?;
        self.layout.get(index)
    }
}

impl<const STORAGE_SIZE: usize, const NUM_KEYS: usize> KeyStore
    for MemoryKeyStore<STORAGE_SIZE, NUM_KEYS>
{
    fn get_key_info(&self, id: KeyId) -> Result<KeyInfo, Error> {
        match self.get_key_layout(id) {
            None => Err(Error::InvalidKeyId),
            Some(key_layout) => Ok(key_layout.info),
        }
    }

    fn import_symmetric_key(&mut self, id: KeyId, data: &[u8]) -> Result<(), Error> {
        match self
            .layout
            .iter_mut()
            .find(|key_layout| key_layout.info.id == id)
        {
            None => Err(Error::InvalidKeyId),
            Some(key_layout) => {
                if !key_layout.info.ty.is_symmetric() {
                    return Err(Error::InvalidKeyType);
                }
                if !key_layout.info.permissions.import {
                    return Err(Error::NotAllowed);
                }
                if data.len() > key_layout.info.ty.key_size() {
                    return Err(Error::InvalidBufferSize);
                }
                let offset = key_layout.offset;
                let size = data.len();
                let dest = &mut self.storage[offset..(offset + size)];
                dest.copy_from_slice(data);
                key_layout.actual_size = data.len();
                Ok(())
            }
        }
    }

    fn import_key_pair(
        &mut self,
        id: KeyId,
        public_key: &[u8],
        private_key: &[u8],
    ) -> Result<(), Error> {
        match self
            .layout
            .iter_mut()
            .find(|key_layout| key_layout.info.id == id)
        {
            None => Err(Error::InvalidKeyId),
            Some(key_layout) => {
                if !key_layout.info.ty.is_asymmetric() {
                    return Err(Error::InvalidKeyType);
                }
                if !key_layout.info.permissions.import {
                    return Err(Error::NotAllowed);
                }
                if (public_key.len() != 2 * private_key.len())
                    || (public_key.len() + private_key.len() > key_layout.info.ty.key_size())
                {
                    return Err(Error::InvalidBufferSize);
                }
                // Copy public key
                {
                    let offset = key_layout.offset;
                    let size = public_key.len();
                    let dest = &mut self.storage[offset..(offset + size)];
                    dest.copy_from_slice(public_key);
                }
                // Copy private key
                {
                    let offset = key_layout.offset + public_key.len();
                    let size = private_key.len();
                    let dest = &mut self.storage[offset..(offset + size)];
                    dest.copy_from_slice(private_key);
                }
                key_layout.actual_size = public_key.len() + private_key.len();
                Ok(())
            }
        }
    }

    fn export_symmetric_key<'data>(
        &self,
        id: KeyId,
        dest: &'data mut [u8],
    ) -> Result<&'data [u8], Error> {
        match self.get_key_layout(id) {
            None => Err(Error::InvalidKeyId),
            Some(key_layout) => {
                if !key_layout.info.permissions.export {
                    return Err(Error::NotAllowed);
                }
                self.export_symmetric_key_unchecked(id, dest)
            }
        }
    }

    fn export_public_key<'data>(
        &self,
        id: KeyId,
        dest: &'data mut [u8],
    ) -> Result<&'data [u8], Error> {
        match self.get_key_layout(id) {
            None => Err(Error::InvalidKeyId),
            Some(key_layout) => {
                if !key_layout.info.ty.is_asymmetric() {
                    return Err(Error::InvalidKeyType);
                }
                if key_layout.actual_size == 0 {
                    return Err(Error::KeyNotFound);
                }
                // When saving a key, we ensure the public key is twice as long as the private key
                assert_eq!(key_layout.actual_size % 3, 0);
                let private_key_size = key_layout.actual_size / 3;
                let public_key_size = 2 * private_key_size;
                if dest.len() < public_key_size {
                    return Err(Error::InvalidBufferSize);
                }
                let offset = key_layout.offset;
                let src = &self.storage[offset..(offset + public_key_size)];
                let dest = &mut dest[..src.len()];
                dest.copy_from_slice(src);
                Ok(dest)
            }
        }
    }

    fn export_private_key<'data>(
        &self,
        id: KeyId,
        dest: &'data mut [u8],
    ) -> Result<&'data [u8], Error> {
        match self.get_key_layout(id) {
            None => Err(Error::InvalidKeyId),
            Some(key_layout) => {
                if !key_layout.info.permissions.export {
                    return Err(Error::NotAllowed);
                }
                self.export_private_key_unchecked(id, dest)
            }
        }
    }

    fn export_symmetric_key_unchecked<'data>(
        &self,
        id: KeyId,
        dest: &'data mut [u8],
    ) -> Result<&'data [u8], Error> {
        match self.get_key_layout(id) {
            None => Err(Error::InvalidKeyId),
            Some(key_layout) => {
                if !key_layout.info.ty.is_symmetric() {
                    return Err(Error::InvalidKeyType);
                }
                if key_layout.actual_size == 0 {
                    return Err(Error::KeyNotFound);
                }
                if dest.len() < key_layout.actual_size {
                    return Err(Error::InvalidBufferSize);
                }
                let offset = key_layout.offset;
                let size = key_layout.actual_size;
                let src = &self.storage[offset..(offset + size)];
                let dest = &mut dest[..src.len()];
                dest.copy_from_slice(src);
                Ok(dest)
            }
        }
    }

    fn export_private_key_unchecked<'data>(
        &self,
        id: KeyId,
        dest: &'data mut [u8],
    ) -> Result<&'data [u8], Error> {
        match self.get_key_layout(id) {
            None => Err(Error::InvalidKeyId),
            Some(key_layout) => {
                if !key_layout.info.ty.is_asymmetric() {
                    return Err(Error::InvalidKeyType);
                }
                if key_layout.actual_size == 0 {
                    return Err(Error::KeyNotFound);
                }
                // When saving a key, we ensure the public key is twice as long as the private key
                assert_eq!(key_layout.actual_size % 3, 0);
                let private_key_size = key_layout.actual_size / 3;
                let public_key_size = 2 * private_key_size;
                if dest.len() < private_key_size {
                    return Err(Error::InvalidBufferSize);
                }
                let offset = key_layout.offset + public_key_size;
                let src = &self.storage[offset..(offset + private_key_size)];
                let dest = &mut dest[..src.len()];
                dest.copy_from_slice(src);
                Ok(dest)
            }
        }
    }

    fn delete(&mut self, id: KeyId) -> Result<(), Error> {
        match self
            .layout
            .iter_mut()
            .find(|key_layout| key_layout.info.id == id)
        {
            None => Err(Error::InvalidKeyId),
            Some(key_layout) => {
                if !key_layout.info.permissions.delete {
                    return Err(Error::NotAllowed);
                }
                if key_layout.actual_size == 0 {
                    return Err(Error::KeyNotFound);
                }
                let offset = key_layout.offset;
                let size = key_layout.actual_size;
                let key = &mut self.storage[offset..(offset + size)];
                key.fill(0);
                key_layout.actual_size = 0;
                Ok(())
            }
        }
    }

    fn is_stored(&self, id: KeyId) -> bool {
        match self.get_key_layout(id) {
            None => false,
            Some(key_layout) => key_layout.actual_size > 0,
        }
    }

    fn size(&self, id: KeyId) -> Result<usize, Error> {
        match self.get_key_layout(id) {
            None => Err(Error::InvalidKeyId),
            Some(key_layout) => {
                if key_layout.actual_size == 0 {
                    return Err(Error::KeyNotFound);
                }
                Ok(key_layout.actual_size)
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod test {
    use crate::config;
    use crate::hsm::keystore::{
        Error, KeyId, KeyInfo, KeyPermissions, KeyStore, KeyType, MemoryKeyStore,
    };

    #[test]
    fn store_get_delete() {
        const UNKNOWN_KEY_ID: KeyId = 1;
        const KEY1_INFO: KeyInfo = KeyInfo {
            id: 5,
            ty: KeyType::Symmetric128Bits,
            permissions: KeyPermissions {
                import: true,
                export: true,
                overwrite: false,
                delete: true,
            },
        };
        const KEY2_INFO: KeyInfo = KeyInfo {
            id: 3,
            ty: KeyType::EccKeypairNistP256,
            permissions: KeyPermissions {
                import: true,
                export: true,
                overwrite: false,
                delete: true,
            },
        };
        let key_infos: [KeyInfo; 2] = [KEY1_INFO, KEY2_INFO];
        let mut src_buffer = [0u8; KEY2_INFO.ty.key_size()];
        let mut dest_buffer = [0u8; KEY2_INFO.ty.key_size()];
        let mut key_store =
            MemoryKeyStore::<{ config::keystore::TOTAL_SIZE }, 2>::try_new(&key_infos)
                .expect("failed to create key store");
        for id in 0..10 {
            assert!(!key_store.is_stored(id));
            assert!(key_store.size(id).is_err());
            assert!(key_store.export_public_key(id, &mut dest_buffer).is_err());
            assert!(key_store.export_private_key(id, &mut dest_buffer).is_err());
        }

        // Store first key
        src_buffer.fill(1);
        assert!(key_store
            .import_symmetric_key(KEY1_INFO.id, &src_buffer[0..KEY1_INFO.ty.key_size()])
            .is_ok());
        assert!(key_store.is_stored(KEY1_INFO.id));
        assert_eq!(
            key_store
                .export_symmetric_key(KEY1_INFO.id, &mut dest_buffer)
                .expect("failed to retrieve key from store")
                .len(),
            KEY1_INFO.ty.key_size()
        );
        assert!(dest_buffer[0..KEY1_INFO.ty.key_size()]
            .iter()
            .all(|byte| *byte == 1));
        assert!(dest_buffer[KEY1_INFO.ty.key_size()..]
            .iter()
            .all(|byte| *byte == 0));

        // Store second key
        src_buffer.fill(2);
        assert!(key_store
            .import_key_pair(
                KEY2_INFO.id,
                &src_buffer[0..KEY2_INFO.ty.public_key_size()],
                &src_buffer[KEY2_INFO.ty.public_key_size()..]
            )
            .is_ok());
        assert!(key_store.is_stored(KEY2_INFO.id));
        assert!(key_store.is_stored(KEY1_INFO.id));
        assert_eq!(
            key_store
                .export_public_key(
                    KEY2_INFO.id,
                    &mut dest_buffer[..KEY2_INFO.ty.public_key_size()]
                )
                .expect("failed to retrieve key from store")
                .len(),
            KEY2_INFO.ty.public_key_size()
        );
        assert_eq!(
            key_store
                .export_private_key(
                    KEY2_INFO.id,
                    &mut dest_buffer[KEY2_INFO.ty.public_key_size()..]
                )
                .expect("failed to retrieve key from store")
                .len(),
            KEY2_INFO.ty.private_key_size()
        );
        assert!(dest_buffer[0..KEY2_INFO.ty.key_size()]
            .iter()
            .all(|byte| *byte == 2));
        assert!(dest_buffer[KEY2_INFO.ty.key_size()..]
            .iter()
            .all(|byte| *byte == 0));

        // Delete keys
        assert_eq!(key_store.delete(UNKNOWN_KEY_ID), Err(Error::InvalidKeyId));
        assert!(key_store.delete(KEY1_INFO.id).is_ok());
        assert!(!key_store.is_stored(KEY1_INFO.id));
        assert!(key_store.delete(KEY2_INFO.id).is_ok());
        assert!(!key_store.is_stored(KEY2_INFO.id));
    }

    #[test]
    fn permissions() {
        const KEY1_INFO: KeyInfo = KeyInfo {
            id: 0,
            ty: KeyType::Symmetric128Bits,
            permissions: KeyPermissions {
                import: true,
                export: false,
                overwrite: false,
                delete: false,
            },
        };
        let key_infos: [KeyInfo; 1] = [KEY1_INFO];
        let src_buffer = [0u8; KEY1_INFO.ty.key_size()];
        let mut dest_buffer = [0u8; KEY1_INFO.ty.key_size()];
        let mut key_store =
            MemoryKeyStore::<{ config::keystore::TOTAL_SIZE }, 2>::try_new(&key_infos)
                .expect("failed to create key store");
        assert!(key_store
            .import_symmetric_key(KEY1_INFO.id, &src_buffer)
            .is_ok());
        match key_store.export_symmetric_key(KEY1_INFO.id, &mut dest_buffer) {
            Ok(_) => panic!("Operation should have failed"),
            Err(e) => assert_eq!(e, Error::NotAllowed),
        }
        match key_store.delete(KEY1_INFO.id) {
            Ok(_) => panic!("Operation should have failed"),
            Err(e) => assert_eq!(e, Error::NotAllowed),
        }
    }
}
