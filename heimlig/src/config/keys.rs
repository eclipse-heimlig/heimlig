use crate::hsm::keystore::{KeyInfo, KeyPermissions, KeyType};

// TODO: Move all this to integration code

/// Maximum number of items in the key store
pub const NUM_KEYS: usize = 3;
/// Maximum size of a key in the key store
pub const MAX_KEY_SIZE: usize = 128;
/// Total size of the key store
pub const TOTAL_SIZE: usize = 16 + 32 + 128;

pub const SYM_128_KEY: KeyInfo = KeyInfo {
    id: 0,
    ty: KeyType::Symmetric128Bits,
    permissions: KeyPermissions {
        import: true,
        export: false,
        overwrite: false,
        delete: false,
    },
};
pub const SYM_256_KEY: KeyInfo = KeyInfo {
    id: 1,
    ty: KeyType::Symmetric256Bits,
    permissions: KeyPermissions {
        import: true,
        export: true,
        overwrite: false,
        delete: false,
    },
};
pub const ASYM_NIST_P256_KEY: KeyInfo = KeyInfo {
    id: 2,
    ty: KeyType::EccKeypairNistP256,
    permissions: KeyPermissions {
        import: true,
        export: true,
        overwrite: false,
        delete: false,
    },
};
