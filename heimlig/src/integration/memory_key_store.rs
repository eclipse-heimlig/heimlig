use crate::hsm::keystore::{Error, KeyId, KeyInfo, KeyStore};
use heapless::Vec;

pub struct MemoryKeyStore<const STORAGE_SIZE: usize, const MAX_KEYS: usize> {
    storage: [u8; STORAGE_SIZE],
    layout: SortedKeyStoreLayout<STORAGE_SIZE, MAX_KEYS>,
}

impl<const STORAGE_SIZE: usize, const MAX_KEYS: usize> MemoryKeyStore<STORAGE_SIZE, MAX_KEYS> {
    pub fn try_new(key_infos: &[KeyInfo]) -> Result<Self, Error> {
        Ok(Self {
            storage: [0u8; STORAGE_SIZE],
            layout: SortedKeyStoreLayout::try_from(key_infos)?,
        })
    }
}

impl<const STORAGE_SIZE: usize, const NUM_KEYS: usize> KeyStore
    for MemoryKeyStore<STORAGE_SIZE, NUM_KEYS>
{
    fn get_key_info(&self, id: KeyId) -> Result<KeyInfo, Error> {
        match self.layout.get(id) {
            None => Err(Error::InvalidKeyId),
            Some(key_layout) => Ok(key_layout.info),
        }
    }

    fn import_symmetric_key(&mut self, id: KeyId, data: &[u8]) -> Result<(), Error> {
        match self.layout.get_mut(id) {
            None => Err(Error::InvalidKeyId),
            Some(key_layout) => {
                if !key_layout.info.ty.is_symmetric() {
                    return Err(Error::InvalidKeyType);
                }
                if !key_layout.info.permissions.import {
                    return Err(Error::NotAllowed);
                }
                if data.len() != key_layout.info.ty.key_size() {
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
        match self.layout.get_mut(id) {
            None => Err(Error::InvalidKeyId),
            Some(key_layout) => {
                if !key_layout.info.ty.is_asymmetric() {
                    return Err(Error::InvalidKeyType);
                }
                if !key_layout.info.permissions.import {
                    return Err(Error::NotAllowed);
                }
                if (public_key.len() != 2 * private_key.len())
                    || (public_key.len() + private_key.len() != key_layout.info.ty.key_size())
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
        match self.layout.get(id) {
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
        match self.layout.get(id) {
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
        match self.layout.get(id) {
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
        match self.layout.get(id) {
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
        match self.layout.get(id) {
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
        match self.layout.get_mut(id) {
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
        match self.layout.get(id) {
            None => false,
            Some(key_layout) => key_layout.actual_size > 0,
        }
    }

    fn size(&self, id: KeyId) -> Result<usize, Error> {
        match self.layout.get(id) {
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

/// Keeps a sorted list of `KeyLayout`s
#[derive(Default)]
struct SortedKeyStoreLayout<const STORAGE_SIZE: usize, const MAX_KEYS: usize> {
    inner: Vec<KeyLayout, MAX_KEYS>,
}

impl<const STORAGE_SIZE: usize, const MAX_KEYS: usize>
    SortedKeyStoreLayout<STORAGE_SIZE, MAX_KEYS>
{
    pub fn get(&self, id: KeyId) -> Option<&KeyLayout> {
        let index = self
            .inner
            .binary_search_by_key(&id, |key_layout| key_layout.info.id)
            .ok()?;
        self.inner.get(index)
    }

    pub fn get_mut(&mut self, id: KeyId) -> Option<&mut KeyLayout> {
        let index = self
            .inner
            .binary_search_by_key(&id, |key_layout| key_layout.info.id)
            .ok()?;
        self.inner.get_mut(index)
    }
}

impl<const STORAGE_SIZE: usize, const MAX_KEYS: usize> TryFrom<&[KeyInfo]>
    for SortedKeyStoreLayout<STORAGE_SIZE, MAX_KEYS>
{
    type Error = Error;

    fn try_from(key_infos: &[KeyInfo]) -> Result<Self, Self::Error> {
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

        // Create new sorted key layout
        let mut ret = Self::default();
        let mut offset = 0;
        for key_info in key_infos {
            let key_layout = KeyLayout {
                info: *key_info,
                offset,
                actual_size: 0,
            };
            ret.inner
                .push(key_layout)
                .expect("too many key definitions");
            offset += key_info.ty.key_size();
        }
        Ok(ret)
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::hsm::keystore::{Error, KeyId, KeyInfo, KeyPermissions, KeyStore, KeyType};

    const TOTAL_KEY_SIZE: usize = KEY1_INFO.ty.key_size() + KEY2_INFO.ty.key_size();
    const KEY1_INFO: KeyInfo = KeyInfo {
        id: KeyId(5),
        ty: KeyType::Symmetric128Bits,
        permissions: KeyPermissions {
            import: true,
            export: true,
            overwrite: false,
            delete: true,
        },
    };
    const KEY2_INFO: KeyInfo = KeyInfo {
        id: KeyId(3),
        ty: KeyType::EccKeypairNistP256,
        permissions: KeyPermissions {
            import: true,
            export: true,
            overwrite: false,
            delete: true,
        },
    };

    #[test]
    fn store_get_delete() {
        const UNKNOWN_KEY_ID: KeyId = KeyId(1);

        let key_infos: [KeyInfo; 2] = [KEY1_INFO, KEY2_INFO];
        let mut src_buffer = [0u8; KEY2_INFO.ty.key_size()];
        let mut dest_buffer = [0u8; KEY2_INFO.ty.key_size()];
        let mut key_store = MemoryKeyStore::<{ TOTAL_KEY_SIZE }, 2>::try_new(&key_infos)
            .expect("failed to create key store");
        for key_id in 0..10 {
            let key_id: KeyId = key_id.into();
            assert!(!key_store.is_stored(key_id));
            assert!(key_store.size(key_id).is_err());
            assert!(key_store
                .export_public_key(key_id, &mut dest_buffer)
                .is_err());
            assert!(key_store
                .export_private_key(key_id, &mut dest_buffer)
                .is_err());
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
        const NO_EXPORT_NO_OVERWRITE_NO_DELETE: KeyInfo = KeyInfo {
            id: KeyId(0),
            ty: KeyType::Symmetric128Bits,
            permissions: KeyPermissions {
                import: true,
                export: false,
                overwrite: false,
                delete: false,
            },
        };
        let key_infos: [KeyInfo; 1] = [NO_EXPORT_NO_OVERWRITE_NO_DELETE];
        let src_buffer = [0u8; NO_EXPORT_NO_OVERWRITE_NO_DELETE.ty.key_size()];
        let mut dest_buffer = [0u8; NO_EXPORT_NO_OVERWRITE_NO_DELETE.ty.key_size()];
        let mut key_store = MemoryKeyStore::<{ TOTAL_KEY_SIZE }, 2>::try_new(&key_infos)
            .expect("failed to create key store");
        assert!(key_store
            .import_symmetric_key(NO_EXPORT_NO_OVERWRITE_NO_DELETE.id, &src_buffer)
            .is_ok());
        match key_store.export_symmetric_key(NO_EXPORT_NO_OVERWRITE_NO_DELETE.id, &mut dest_buffer)
        {
            Ok(_) => panic!("Operation should have failed"),
            Err(e) => assert_eq!(e, Error::NotAllowed),
        }
        match key_store.delete(NO_EXPORT_NO_OVERWRITE_NO_DELETE.id) {
            Ok(_) => panic!("Operation should have failed"),
            Err(e) => assert_eq!(e, Error::NotAllowed),
        }
    }
}
