use const_default::ConstDefault;
use heapless::Vec;

/// Identifier to reference HSM keys
pub type KeyId = u32;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum KeyType {
    Symmetric,
    Asymmetric,
}

#[derive(Copy, ConstDefault, Clone, Debug, Default)]
pub struct KeyPermissions {
    /// Whether or not the key can be set with outside data.
    pub import: bool,
    /// Whether or not private key material can be exported. Both symmetric keys and the private key
    /// of an asymmetric key pair are considered private. Public keys are always exportable.
    pub export: bool,
    /// Whether or not the key can be overwritten (either through import or generation).
    pub overwrite: bool,
    /// Whether or not the key can be deleted
    pub delete: bool,
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

#[derive(Copy, Clone, Debug)]
pub struct KeyInfo {
    pub id: KeyId,
    pub ty: KeyType,
    pub permissions: KeyPermissions,
    pub max_size: usize,
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
    layout: Vec<KeyLayout, MAX_KEYS>,
}

impl<const STORAGE_SIZE: usize, const MAX_KEYS: usize> MemoryKeyStore<STORAGE_SIZE, MAX_KEYS> {
    pub fn try_new(key_infos: &[KeyInfo]) -> Result<Self, Error> {
        // Check input sizes
        let total_size: usize = key_infos.iter().map(|key_info| key_info.max_size).sum();
        if key_infos.len() > MAX_KEYS || total_size > STORAGE_SIZE {
            return Err(Error::KeyStoreTooSmall);
        }

        // Check for duplicate IDs
        let key_ids: Vec<_, MAX_KEYS> = key_infos.iter().map(|key_info| key_info.id).collect();
        if (1..key_ids.len()).any(|i| key_ids[i..].contains(&key_ids[i - 1])) {
            return Err(Error::DuplicateIds);
        }

        // Create new key store
        let mut key_store = MemoryKeyStore {
            storage: [0u8; STORAGE_SIZE],
            layout: Default::default(),
        };
        let mut offset = 0;
        for key_info in key_infos.iter() {
            key_store
                .layout
                .push(KeyLayout {
                    info: *key_info,
                    offset,
                    actual_size: 0,
                })
                .expect("invalid keystore config");
            offset += key_info.max_size;
        }
        Ok(key_store)
    }
}

impl<const STORAGE_SIZE: usize, const NUM_KEYS: usize> KeyStore
    for MemoryKeyStore<STORAGE_SIZE, NUM_KEYS>
{
    fn import_symmetric_key(&mut self, id: KeyId, data: &[u8]) -> Result<(), Error> {
        match self
            .layout
            .iter_mut()
            .find(|key_layout| key_layout.info.id == id)
        {
            None => Err(Error::InvalidKeyId),
            Some(key_layout) => {
                if key_layout.info.ty != KeyType::Symmetric {
                    return Err(Error::InvalidKeyType);
                }
                if !key_layout.info.permissions.import {
                    return Err(Error::NotAllowed);
                }
                if data.len() > key_layout.info.max_size {
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
                if key_layout.info.ty != KeyType::Asymmetric {
                    return Err(Error::InvalidKeyType);
                }
                if !key_layout.info.permissions.import {
                    return Err(Error::NotAllowed);
                }
                if (public_key.len() != 2 * private_key.len())
                    || (public_key.len() + private_key.len() > key_layout.info.max_size)
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
        match self
            .layout
            .iter()
            .find(|key_layout| key_layout.info.id == id)
        {
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
        match self
            .layout
            .iter()
            .find(|key_layout| key_layout.info.id == id)
        {
            None => Err(Error::InvalidKeyId),
            Some(key_layout) => {
                if key_layout.info.ty != KeyType::Asymmetric {
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
        match self
            .layout
            .iter()
            .find(|key_layout| key_layout.info.id == id)
        {
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
        match self
            .layout
            .iter()
            .find(|key_layout| key_layout.info.id == id)
        {
            None => Err(Error::InvalidKeyId),
            Some(key_layout) => {
                if key_layout.info.ty != KeyType::Symmetric {
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
        match self
            .layout
            .iter()
            .find(|key_layout| key_layout.info.id == id)
        {
            None => Err(Error::InvalidKeyId),
            Some(key_layout) => {
                if key_layout.info.ty != KeyType::Asymmetric {
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
        match self
            .layout
            .iter()
            .find(|key_layout| key_layout.info.id == id)
        {
            None => false,
            Some(key_layout) => key_layout.actual_size > 0,
        }
    }

    fn size(&self, id: KeyId) -> Result<usize, Error> {
        match self
            .layout
            .iter()
            .find(|key_layout| key_layout.info.id == id)
        {
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
        const CURVE_SIZE: usize = 32;
        const PUBLIC_KEY_SIZE: usize = 2 * CURVE_SIZE;
        const PRIVATE_KEY_SIZE: usize = CURVE_SIZE;
        const UNKNOWN_KEY_ID: KeyId = 1;
        const KEY1_ID: KeyId = 5;
        const KEY2_ID: KeyId = 3;
        const KEY1_SIZE: usize = 16;
        const KEY2_SIZE: usize = PUBLIC_KEY_SIZE + PRIVATE_KEY_SIZE;
        let key1_info = KeyInfo {
            id: KEY1_ID,
            ty: KeyType::Symmetric,
            permissions: KeyPermissions {
                import: true,
                export: true,
                overwrite: false,
                delete: true,
            },
            max_size: KEY1_SIZE,
        };
        let key2_info = KeyInfo {
            id: KEY2_ID,
            ty: KeyType::Asymmetric,
            permissions: KeyPermissions {
                import: true,
                export: true,
                overwrite: false,
                delete: true,
            },
            max_size: KEY2_SIZE,
        };
        let key_infos: [KeyInfo; 2] = [key1_info, key2_info];
        let mut src_buffer = [0u8; KEY2_SIZE];
        let mut dest_buffer = [0u8; KEY2_SIZE];
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
            .import_symmetric_key(KEY1_ID, &src_buffer[0..KEY1_SIZE])
            .is_ok());
        assert!(key_store.is_stored(KEY1_ID));
        assert_eq!(
            key_store
                .export_symmetric_key(KEY1_ID, &mut dest_buffer)
                .expect("failed to retrieve key from store")
                .len(),
            KEY1_SIZE
        );
        assert!(dest_buffer[0..KEY1_SIZE].iter().all(|byte| *byte == 1));
        assert!(dest_buffer[KEY1_SIZE..].iter().all(|byte| *byte == 0));

        // Store second key
        src_buffer.fill(2);
        assert!(key_store
            .import_key_pair(
                KEY2_ID,
                &src_buffer[0..PUBLIC_KEY_SIZE],
                &src_buffer[PUBLIC_KEY_SIZE..]
            )
            .is_ok());
        assert!(key_store.is_stored(KEY2_ID));
        assert!(key_store.is_stored(KEY1_ID));
        assert_eq!(
            key_store
                .export_public_key(KEY2_ID, &mut dest_buffer[..PUBLIC_KEY_SIZE])
                .expect("failed to retrieve key from store")
                .len(),
            2 * (KEY2_SIZE / 3)
        );
        assert_eq!(
            key_store
                .export_private_key(KEY2_ID, &mut dest_buffer[PUBLIC_KEY_SIZE..])
                .expect("failed to retrieve key from store")
                .len(),
            KEY2_SIZE / 3
        );
        assert!(dest_buffer[0..KEY2_SIZE].iter().all(|byte| *byte == 2));
        assert!(dest_buffer[KEY2_SIZE..].iter().all(|byte| *byte == 0));

        // Delete keys
        assert_eq!(key_store.delete(UNKNOWN_KEY_ID), Err(Error::InvalidKeyId));
        assert!(key_store.delete(KEY1_ID).is_ok());
        assert!(!key_store.is_stored(KEY1_ID));
        assert!(key_store.delete(KEY2_ID).is_ok());
        assert!(!key_store.is_stored(KEY2_ID));
    }

    #[test]
    fn permissions() {
        const KEY1_ID: KeyId = 0;
        const KEY1_SIZE: usize = 16;
        let key1_info = KeyInfo {
            id: KEY1_ID,
            ty: KeyType::Symmetric,
            permissions: KeyPermissions {
                import: true,
                export: false,
                overwrite: false,
                delete: false,
            },
            max_size: KEY1_SIZE,
        };
        let key_infos: [KeyInfo; 1] = [key1_info];
        let src_buffer = [0u8; KEY1_SIZE];
        let mut dest_buffer = [0u8; KEY1_SIZE];
        let mut key_store =
            MemoryKeyStore::<{ config::keystore::TOTAL_SIZE }, 2>::try_new(&key_infos)
                .expect("failed to create key store");
        assert!(key_store.import_symmetric_key(KEY1_ID, &src_buffer).is_ok());
        match key_store.export_symmetric_key(KEY1_ID, &mut dest_buffer) {
            Ok(_) => panic!("Operation should have failed"),
            Err(e) => assert_eq!(e, Error::NotAllowed),
        }
        match key_store.delete(KEY1_ID) {
            Ok(_) => panic!("Operation should have failed"),
            Err(e) => assert_eq!(e, Error::NotAllowed),
        }
    }
}
