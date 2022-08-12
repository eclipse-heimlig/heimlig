pub const POOL_CHUNK_SIZE: usize = 1024;
pub const MAX_CHUNKS: usize = 8;
pub type PoolChunk = heapless::Vec<u8, POOL_CHUNK_SIZE>;
