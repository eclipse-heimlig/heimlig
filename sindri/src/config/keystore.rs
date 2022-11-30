/// Maximum number of items in the key store
pub const NUM_ITEMS: usize = 12;
/// List of item sizes in the key store
pub const ITEM_SIZES: [usize; NUM_ITEMS] = [16, 16, 16, 32, 32, 32, 64, 64, 64, 128, 128, 128];
/// Total size of the key store
pub const TOTAL_SIZE: usize = 3 * 16 + 3 * 32 + 3 * 64 + 3 * 128;
