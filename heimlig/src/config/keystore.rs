use crate::hsm::keystore::{KeyInfo, KeyPermissions, KeyType};

/// Maximum number of items in the key store
pub const NUM_KEYS: usize = 3;
/// Maximum size of a key in the key store
pub const MAX_KEY_SIZE: usize = 128;
/// Total size of the key store
pub const TOTAL_SIZE: usize = 16 + 32 + 128;

pub const KEY1: KeyInfo = KeyInfo {
    id: 0,
    ty: KeyType::Symmetric128Bits,
    permissions: KeyPermissions {
        import: true,
        export: false,
        overwrite: false,
        delete: false,
    },
};
pub const KEY2: KeyInfo = KeyInfo {
    id: 1,
    ty: KeyType::Symmetric256Bits,
    permissions: KeyPermissions {
        import: true,
        export: false,
        overwrite: false,
        delete: false,
    },
};
pub const KEY3: KeyInfo = KeyInfo {
    id: 2,
    ty: KeyType::EccKeypairNistP256,
    permissions: KeyPermissions {
        import: true,
        export: false,
        overwrite: false,
        delete: false,
    },
};
