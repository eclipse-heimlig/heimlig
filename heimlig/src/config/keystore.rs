use crate::hsm::keystore::KeyInfo;

/// Maximum number of items in the key store
pub const NUM_KEYS: usize = 3;
/// Maximum size of a key in the key store
pub const MAX_KEY_SIZE: usize = 128;
/// Total size of the key store
pub const TOTAL_SIZE: usize = 16 + 32 + 128;

pub const KEY1: KeyInfo = KeyInfo {
    id: 0,
    max_size: 16,
};
pub const KEY2: KeyInfo = KeyInfo {
    id: 1,
    max_size: 32,
};
pub const KEY3: KeyInfo = KeyInfo {
    id: 2,
    max_size: 128,
};
