use core::mem;
use core::ops::{Deref, DerefMut};
use heapless::pool::{Box, Init, Node};

// TODO: Make configurable by integration code
pub const SMALL_CHUNKS: usize = 16;
pub const MEDIUM_CHUNKS: usize = 8;
pub const BIG_CHUNKS: usize = 4;
pub const SMALL_CHUNK_SIZE: usize = 64;
pub const MEDIUM_CHUNK_SIZE: usize = 512;
pub const BIG_CHUNK_SIZE: usize = 1500; // Ethernet MTU

pub type Memory = [u8; Pool::required_memory()];
type SmallChunk = heapless::Vec<u8, SMALL_CHUNK_SIZE>;
type MediumChunk = heapless::Vec<u8, MEDIUM_CHUNK_SIZE>;
type BigChunk = heapless::Vec<u8, BIG_CHUNK_SIZE>;

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Error {
    Alloc,
    BufferSize,
}

#[derive(Eq, PartialEq, Debug)]
pub enum PoolChunk {
    SmallChunk(Box<SmallChunk, Init>),
    MediumChunk(Box<MediumChunk, Init>),
    BigChunk(Box<BigChunk, Init>),
}

impl PoolChunk {
    pub fn len(&self) -> usize {
        match self {
            PoolChunk::SmallChunk(s) => s.len(),
            PoolChunk::MediumChunk(m) => m.len(),
            PoolChunk::BigChunk(b) => b.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn as_slice(&self) -> &[u8] {
        match self {
            PoolChunk::SmallChunk(s) => s.deref().as_slice(),
            PoolChunk::MediumChunk(m) => m.deref().as_slice(),
            PoolChunk::BigChunk(b) => b.deref().as_slice(),
        }
    }

    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        match self {
            PoolChunk::SmallChunk(s) => &mut s.deref_mut()[..],
            PoolChunk::MediumChunk(m) => &mut m.deref_mut()[..],
            PoolChunk::BigChunk(b) => &mut b.deref_mut()[..],
        }
    }
}

/// Set of pools to handle different size requirements. It offers the same portability guarantees like heapless::pool
/// (https://docs.rs/heapless/latest/heapless/pool/index.html#portability)
/// TODO: Replace with a multi-core safe allocator that operates on static memory.
pub struct Pool {
    small: heapless::pool::Pool<SmallChunk>,
    medium: heapless::pool::Pool<MediumChunk>,
    big: heapless::pool::Pool<BigChunk>,
}

impl Default for Pool {
    fn default() -> Self {
        Pool::new()
    }
}

impl Pool {
    pub const fn new() -> Self {
        let small = heapless::pool::Pool::<SmallChunk>::new();
        let medium = heapless::pool::Pool::<MediumChunk>::new();
        let big = heapless::pool::Pool::<BigChunk>::new();
        Pool { small, medium, big }
    }

    pub fn init(&self, memory: &'static mut Memory) -> Result<(), Error> {
        let small_size = Self::required_small_memory();
        let medium_size = Self::required_medium_memory();
        let big_size = Self::required_big_memory();
        if memory.len() < small_size + medium_size + big_size {
            return Err(Error::BufferSize);
        }
        let (small_mem, remainder) = memory.split_at_mut(small_size);
        let (medium_mem, big_mem) = remainder.split_at_mut(medium_size);
        self.small.grow(small_mem);
        self.medium.grow(medium_mem);
        self.big.grow(big_mem);
        Ok(())
    }

    /// Allocate and initialize a memory chunk from the pool. The size of the chunk is at least as large as the required size.
    pub fn alloc(&self, size: usize) -> Result<PoolChunk, Error> {
        if size <= SMALL_CHUNK_SIZE {
            if let Some(chunk) = self.small.alloc() {
                let mut chunk = chunk.init(Default::default());
                chunk
                    .resize_default(size)
                    .expect("Failed to allocate guaranteed capacity");
                return Ok(PoolChunk::SmallChunk(chunk));
            }
        }
        if size <= MEDIUM_CHUNK_SIZE {
            if let Some(chunk) = self.medium.alloc() {
                let mut chunk = chunk.init(Default::default());
                chunk
                    .resize_default(size)
                    .expect("Failed to allocate guaranteed capacity");
                return Ok(PoolChunk::MediumChunk(chunk));
            }
        }
        if size <= BIG_CHUNK_SIZE {
            if let Some(chunk) = self.big.alloc() {
                let mut chunk = chunk.init(Default::default());
                chunk
                    .resize_default(size)
                    .expect("Failed to allocate guaranteed capacity");
                return Ok(PoolChunk::BigChunk(chunk));
            }
        }
        Err(Error::Alloc)
    }

    pub const fn required_memory() -> usize {
        // Account for extra space required due to element alignment
        Self::required_small_memory() + Self::required_medium_memory() + Self::required_big_memory()
    }

    const fn required_small_memory() -> usize {
        SMALL_CHUNKS * mem::size_of::<Node<SmallChunk>>() + mem::align_of::<Node<SmallChunk>>()
    }

    const fn required_medium_memory() -> usize {
        MEDIUM_CHUNKS * mem::size_of::<Node<MediumChunk>>() + mem::align_of::<Node<MediumChunk>>()
    }

    const fn required_big_memory() -> usize {
        BIG_CHUNKS * mem::size_of::<Node<BigChunk>>() + mem::align_of::<Node<BigChunk>>()
    }
}

#[cfg(test)]
mod test {
    use crate::common::pool::{
        Memory, Pool, PoolChunk, BIG_CHUNKS, BIG_CHUNK_SIZE, MEDIUM_CHUNKS, MEDIUM_CHUNK_SIZE,
        SMALL_CHUNKS, SMALL_CHUNK_SIZE,
    };

    #[test]
    fn alloc_all_sizes() {
        static mut MEMORY: Memory = [0; Pool::required_memory()];
        static POOL: Pool = Pool::new();
        POOL.init(unsafe { &mut MEMORY }).unwrap();
        assert!(matches!(
            POOL.alloc(SMALL_CHUNK_SIZE).unwrap(),
            PoolChunk::SmallChunk(_)
        ));
        assert!(matches!(
            POOL.alloc(MEDIUM_CHUNK_SIZE).unwrap(),
            PoolChunk::MediumChunk(_)
        ));
        assert!(matches!(
            POOL.alloc(BIG_CHUNK_SIZE).unwrap(),
            PoolChunk::BigChunk(_)
        ));
    }

    #[test]
    fn alloc_too_many_small_chunks() {
        static mut MEMORY: Memory = [0; Pool::required_memory()];
        static POOL: Pool = Pool::new();
        POOL.init(unsafe { &mut MEMORY }).unwrap();
        for _ in 0..SMALL_CHUNKS {
            assert!(matches!(
                POOL.alloc(SMALL_CHUNK_SIZE).unwrap(),
                PoolChunk::SmallChunk(_)
            ));
        }
        // We have exhausted all small chunks. Next allocations are promoted to medium chunks
        for _ in 0..MEDIUM_CHUNKS {
            assert!(matches!(
                POOL.alloc(SMALL_CHUNK_SIZE).unwrap(),
                PoolChunk::MediumChunk(_)
            ));
        }
        // We have exhausted all medium chunks. Next allocations are promoted to big chunks
        for _ in 0..BIG_CHUNKS {
            assert!(matches!(
                POOL.alloc(SMALL_CHUNK_SIZE).unwrap(),
                PoolChunk::BigChunk(_)
            ));
        }
        // No more chunks available
        assert!(POOL.alloc(SMALL_CHUNK_SIZE).is_err());
    }
}
