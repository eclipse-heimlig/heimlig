// Configuration of sizes used in sindri::common::Pool

/// Maximum number of allocatable small chunks
pub const SMALL_CHUNKS: usize = 16;
/// Maximum number of allocatable medium sized chunks
pub const MEDIUM_CHUNKS: usize = 8;
/// Maximum number of allocatable big chunks
pub const BIG_CHUNKS: usize = 4;
/// Size of stack allocated chunks
pub const STACK_CHUNK_SIZE: usize = 32; // Allocated on the stack instead of the pool
/// Size of small chunks
pub const SMALL_CHUNK_SIZE: usize = 128;
/// Size of medium sized chunks
pub const MEDIUM_CHUNK_SIZE: usize = 512;
/// Size of big chunks
pub const BIG_CHUNK_SIZE: usize = 1500; // Ethernet MTU
