pub type Id = u32;

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Error {
    /// The requested ID is not defined.
    InvalidKeyId,
    /// The requested key was not found.
    KeyNotFound,
    /// The provided memory buffer was too small.
    BufferTooSmall,
    /// The provided memory buffer was too large.
    BufferTooLarge,
    /// The key store cannot handle the amount of requested keys.
    KeyStoreTooSmall,
    /// Attempted to create a key store with duplicate storage IDs.
    DuplicateIds,
}

pub trait KeyStore {
    /// Returns whether or not a key for the given 'id' is present in the store.
    fn is_stored(&self, id: Id) -> bool;

    /// Get the size if a key.
    fn size(&self, id: Id) -> Result<usize, Error>;

    /// Write key from `src` to storage.
    /// Storing a key of size 0 has the same effect as deleting the key.
    fn store(&mut self, id: Id, src: &[u8]) -> Result<(), Error>;

    /// Read key from storage and write it to `dest`.
    ///
    /// returns: The number of bytes written to `dest` or and error.
    fn get(&self, id: Id, dest: &mut [u8]) -> Result<usize, Error>;

    /// Delete the key belonging to `id`.
    ///
    /// return: An error, if the key could not be found.
    fn delete(&mut self, id: Id) -> Result<(), Error> {
        self.store(id, &[])
    }
}

#[derive(Debug)]
pub struct KeyInfo {
    id: Id,
    max_size: usize,
}

#[derive(Debug)]
struct KeyInfoInternal {
    id: Id,
    offset: usize,
    max_size: usize,
    actual_size: usize,
}

pub struct MemoryKeyStore<const STORAGE_SIZE: usize, const MAX_ITEMS: usize> {
    storage: [u8; STORAGE_SIZE],
    items: heapless::Vec<KeyInfoInternal, MAX_ITEMS>,
}

impl<const STORAGE_SIZE: usize, const MAX_ITEMS: usize> MemoryKeyStore<STORAGE_SIZE, MAX_ITEMS> {
    pub fn try_new(ids_and_sizes: &[KeyInfo]) -> Result<Self, Error> {
        // Check input sizes
        let total_size: usize = ids_and_sizes.iter().map(|key_info| key_info.max_size).sum();
        if ids_and_sizes.len() > MAX_ITEMS || total_size > STORAGE_SIZE {
            return Err(Error::KeyStoreTooSmall);
        }

        // Check for duplicate IDs
        let mut sorted_ids_and_sizes: heapless::Vec<&KeyInfo, MAX_ITEMS> =
            ids_and_sizes.iter().collect();
        sorted_ids_and_sizes.sort_unstable_by_key(|key_info| key_info.id);
        let sorted_ids1 = sorted_ids_and_sizes.iter().map(|key_info| key_info.id);
        let sorted_ids2 = sorted_ids_and_sizes.iter().map(|key_info| key_info.id);
        for (id1, id2) in sorted_ids1.zip(sorted_ids2.skip(1)) {
            if id1 == id2 {
                return Err(Error::DuplicateIds);
            }
        }

        // Create new key store
        let mut key_store = MemoryKeyStore {
            storage: [0u8; STORAGE_SIZE],
            items: Default::default(),
        };
        let mut offset = 0;
        for key_info in sorted_ids_and_sizes.iter() {
            key_store
                .items
                .push(KeyInfoInternal {
                    id: key_info.id,
                    offset,
                    max_size: key_info.max_size,
                    actual_size: 0,
                })
                .expect("invalid keystore config");
            offset += key_info.max_size;
        }
        Ok(key_store)
    }
}

impl<const STORAGE_SIZE: usize, const NUM_ITEMS: usize> KeyStore
    for MemoryKeyStore<STORAGE_SIZE, NUM_ITEMS>
{
    fn is_stored(&self, id: Id) -> bool {
        match self.items.iter().find(|key_info| key_info.id == id) {
            None => false,
            Some(key_info) => key_info.actual_size > 0,
        }
    }

    fn size(&self, id: Id) -> Result<usize, Error> {
        match self.items.iter().find(|key_info| key_info.id == id) {
            None => Err(Error::InvalidKeyId),
            Some(key_info) => {
                if key_info.actual_size == 0 {
                    return Err(Error::KeyNotFound);
                }
                Ok(key_info.actual_size)
            }
        }
    }

    fn store(&mut self, id: Id, src: &[u8]) -> Result<(), Error> {
        match self.items.iter_mut().find(|key_info| key_info.id == id) {
            None => Err(Error::InvalidKeyId),
            Some(key_info) => {
                if src.len() > key_info.max_size {
                    return Err(Error::BufferTooLarge);
                }

                // Scrub block
                self.storage[key_info.offset..(key_info.offset + key_info.max_size)].fill(0);

                // Store key
                let dest = &mut self.storage[key_info.offset..(key_info.offset + src.len())];
                dest.copy_from_slice(src);
                key_info.actual_size = src.len();
                Ok(())
            }
        }
    }

    fn get(&self, id: Id, dest: &mut [u8]) -> Result<usize, Error> {
        match self.items.iter().find(|key_info| key_info.id == id) {
            None => Err(Error::InvalidKeyId),
            Some(key_info) => {
                if key_info.actual_size == 0 {
                    return Err(Error::KeyNotFound);
                }
                if dest.len() < key_info.actual_size {
                    return Err(Error::BufferTooSmall);
                }
                let src = &self.storage[key_info.offset..(key_info.offset + key_info.actual_size)];
                dest[..src.len()].copy_from_slice(src);
                Ok(src.len())
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod test {
    use crate::config;
    use crate::host::keystore::{Error, Id, KeyInfo, KeyStore, MemoryKeyStore};

    #[test]
    fn store_get_delete() {
        const UNKNOWN_KEY_ID: Id = 1;
        const KEY1_ID: Id = 5;
        const KEY1_SIZE: usize = 16;
        let key1_info = KeyInfo {
            id: KEY1_ID,
            max_size: KEY1_SIZE,
        };
        const KEY2_ID: Id = 3;
        const KEY2_SIZE: usize = 64;
        let key2_info = KeyInfo {
            id: KEY2_ID,
            max_size: KEY2_SIZE,
        };
        let ids_and_sizes: [KeyInfo; 2] = [key1_info, key2_info];
        let mut dest_buffer = [0u8; KEY2_SIZE];
        let mut src_buffer = [0u8; KEY2_SIZE];
        let mut key_store =
            MemoryKeyStore::<{ config::keystore::TOTAL_SIZE }, 2>::try_new(&ids_and_sizes)
                .expect("failed to create key store");
        for id in 0..10 {
            assert!(!key_store.is_stored(id));
            assert!(key_store.size(id).is_err());
            assert!(key_store.get(id, &mut dest_buffer).is_err());
        }

        // Store first key
        src_buffer.fill(1);
        assert!(key_store.store(KEY1_ID, &src_buffer[0..KEY1_SIZE]).is_ok());
        assert!(key_store.is_stored(KEY1_ID));
        assert_eq!(
            key_store
                .get(KEY1_ID, &mut dest_buffer)
                .expect("failed to retrieve key from store"),
            KEY1_SIZE
        );
        assert!(dest_buffer[0..KEY1_SIZE].iter().all(|byte| *byte == 1));
        assert!(dest_buffer[KEY1_SIZE..].iter().all(|byte| *byte == 0));

        // Store second key
        src_buffer.fill(2);
        assert!(key_store.store(KEY2_ID, &src_buffer[0..KEY2_SIZE]).is_ok());
        assert!(key_store.is_stored(KEY2_ID));
        assert!(key_store.is_stored(KEY1_ID));
        assert_eq!(
            key_store
                .get(KEY2_ID, &mut dest_buffer)
                .expect("failed to retrieve key from store"),
            KEY2_SIZE
        );
        assert!(dest_buffer[0..KEY2_SIZE].iter().all(|byte| *byte == 2));
        assert!(dest_buffer[KEY2_SIZE..].iter().all(|byte| *byte == 0));

        // Delete keys
        assert_eq!(key_store.delete(UNKNOWN_KEY_ID), Err(Error::InvalidKeyId));
        assert!(key_store.delete(KEY1_ID).is_ok());
        assert!(!key_store.is_stored(KEY1_ID));
        assert!(key_store.store(KEY2_ID, &[]).is_ok());
        assert!(!key_store.is_stored(KEY2_ID));
    }
}
