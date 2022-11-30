use crate::config;
use core::mem;
use core::ops::{Deref, DerefMut};
use heapless::pool::{Box, Init, Node};

pub type Memory = [u8; Pool::required_memory()];
type StackChunk = heapless::Vec<u8, { config::pool::STACK_CHUNK_SIZE }>;
type SmallChunk = heapless::Vec<u8, { config::pool::SMALL_CHUNK_SIZE }>;
type MediumChunk = heapless::Vec<u8, { config::pool::MEDIUM_CHUNK_SIZE }>;
type BigChunk = heapless::Vec<u8, { config::pool::BIG_CHUNK_SIZE }>;

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Error {
    /// Failed to allocate memory.
    Alloc,
    /// The provided memory buffer was too small.
    BufferTooSmall,
}

/// A chunk of memory allocated from a [Pool].
#[derive(Eq, PartialEq, Debug)]
pub enum PoolChunk {
    /// A chunk of size [STACK_CHUNK_SIZE] allocated on the stack.
    StackChunk(StackChunk),
    /// A chunk of size [SMALL_CHUNK_SIZE] allocated from a [Pool].
    SmallChunk(Box<SmallChunk, Init>),
    /// A chunk of size [MEDIUM_CHUNK_SIZE] allocated from a [Pool].
    MediumChunk(Box<MediumChunk, Init>),
    /// A chunk of size [BIG_CHUNK_SIZE] allocated from a [Pool].
    BigChunk(Box<BigChunk, Init>),
}

/// PoolChunk data is zeroed out when it goes out of scope
impl Drop for PoolChunk {
    fn drop(&mut self) {
        match self {
            PoolChunk::StackChunk(st) => st.fill(0),
            PoolChunk::SmallChunk(s) => s.fill(0),
            PoolChunk::MediumChunk(m) => m.fill(0),
            PoolChunk::BigChunk(b) => b.fill(0),
        }
    }
}

impl PoolChunk {
    pub fn len(&self) -> usize {
        match self {
            PoolChunk::StackChunk(st) => st.len(),
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
            PoolChunk::StackChunk(st) => st.as_slice(),
            PoolChunk::SmallChunk(s) => s.deref().as_slice(),
            PoolChunk::MediumChunk(m) => m.deref().as_slice(),
            PoolChunk::BigChunk(b) => b.deref().as_slice(),
        }
    }

    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        match self {
            PoolChunk::StackChunk(st) => st.deref_mut(),
            PoolChunk::SmallChunk(s) => &mut s.deref_mut()[..],
            PoolChunk::MediumChunk(m) => &mut m.deref_mut()[..],
            PoolChunk::BigChunk(b) => &mut b.deref_mut()[..],
        }
    }
}

// TODO: Replace with a multi-core safe allocator that operates on static memory.
/// Memory pool providing [PoolChunk]s of different sizes.
/// The portability guarantees are the same as
/// [heapless::pool](https://docs.rs/heapless/latest/heapless/pool/index.html#portability).
pub struct Pool {
    small: heapless::pool::Pool<SmallChunk>,
    medium: heapless::pool::Pool<MediumChunk>,
    big: heapless::pool::Pool<BigChunk>,
}

impl TryFrom<&'static mut Memory> for Pool {
    type Error = Error;

    /// Attempt to create a pool from a given static [Memory] region.
    ///
    /// # Arguments
    ///
    /// * `memory`: Static memory region to be used by this pool.
    /// The size must be equal or greater than the return values of [required_memory()](Pool::required_memory()).
    /// After this call, modifying the memory from outside the pool is unsafe.
    ///
    /// returns: The created [Pool] or an [Error] if the memory region is too small.
    ///
    /// # Examples
    ///
    /// ```
    /// use sindri::common::pool::{Memory, Pool};
    /// static mut MEMORY: Memory = [0; Pool::required_memory()];
    /// let pool = Pool::try_from(unsafe { &mut MEMORY }).expect("failed to initialize memory pool");
    /// ```
    fn try_from(memory: &'static mut Memory) -> Result<Self, Self::Error> {
        let small_size = Self::required_small_memory();
        let medium_size = Self::required_medium_memory();
        let big_size = Self::required_big_memory();
        if memory.len() < small_size + medium_size + big_size {
            return Err(Error::BufferTooSmall);
        }

        let pool = Pool {
            small: heapless::pool::Pool::<SmallChunk>::new(),
            medium: heapless::pool::Pool::<MediumChunk>::new(),
            big: heapless::pool::Pool::<BigChunk>::new(),
        };
        let (small_mem, remainder) = memory.split_at_mut(small_size);
        let (medium_mem, big_mem) = remainder.split_at_mut(medium_size);
        pool.small.grow(small_mem);
        pool.medium.grow(medium_mem);
        pool.big.grow(big_mem);
        Ok(pool)
    }
}

impl Pool {
    pub const MAX_ALLOC_SIZE: usize = config::pool::BIG_CHUNK_SIZE;

    /// Allocate and initialize a memory chunk from the pool.
    /// Requests for chunks smaller or equal than `STACK_CHUNK_SIZE` will use the stack instead of
    /// the pool as copying small chunks in memory is considered acceptable.
    ///
    /// # Arguments
    ///
    /// * `size`: The minimum number of bytes that the allocated chunk must hold.
    ///
    /// returns: The requested [PoolChunk] or [Error::Alloc].
    pub fn alloc(&self, size: usize) -> Result<PoolChunk, Error> {
        if size <= config::pool::STACK_CHUNK_SIZE {
            // Do not use the pool but allocate on the stack
            let mut chunk = StackChunk::new();
            chunk
                .resize_default(size)
                .expect("Failed to allocate guaranteed capacity");
            return Ok(PoolChunk::StackChunk(chunk));
        }
        if size <= config::pool::SMALL_CHUNK_SIZE {
            if let Some(chunk) = self.small.alloc() {
                let mut chunk = chunk.init(Default::default());
                chunk
                    .resize_default(size)
                    .expect("Failed to allocate guaranteed capacity");
                return Ok(PoolChunk::SmallChunk(chunk));
            }
        }
        if size <= config::pool::MEDIUM_CHUNK_SIZE {
            if let Some(chunk) = self.medium.alloc() {
                let mut chunk = chunk.init(Default::default());
                chunk
                    .resize_default(size)
                    .expect("Failed to allocate guaranteed capacity");
                return Ok(PoolChunk::MediumChunk(chunk));
            }
        }
        if size <= config::pool::BIG_CHUNK_SIZE {
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

    /// Returns the amount of bytes required for a successful call to `init()`.
    pub const fn required_memory() -> usize {
        // Account for extra space required due to element alignment
        Self::required_small_memory() + Self::required_medium_memory() + Self::required_big_memory()
    }

    const fn required_small_memory() -> usize {
        config::pool::SMALL_CHUNKS * mem::size_of::<Node<SmallChunk>>()
            + mem::align_of::<Node<SmallChunk>>()
    }

    const fn required_medium_memory() -> usize {
        config::pool::MEDIUM_CHUNKS * mem::size_of::<Node<MediumChunk>>()
            + mem::align_of::<Node<MediumChunk>>()
    }

    const fn required_big_memory() -> usize {
        config::pool::BIG_CHUNKS * mem::size_of::<Node<BigChunk>>()
            + mem::align_of::<Node<BigChunk>>()
    }
}

#[cfg(test)]
mod test {
    use crate::common::pool::{Memory, Pool, PoolChunk};
    use crate::config::pool::{
        BIG_CHUNKS, BIG_CHUNK_SIZE, MEDIUM_CHUNKS, MEDIUM_CHUNK_SIZE, SMALL_CHUNKS,
        SMALL_CHUNK_SIZE,
    };

    #[test]
    fn alloc_all_sizes() {
        static mut MEMORY: Memory = [0; Pool::required_memory()];
        let pool = Pool::try_from(unsafe { &mut MEMORY }).unwrap();
        assert!(matches!(
            pool.alloc(SMALL_CHUNK_SIZE).unwrap(),
            PoolChunk::SmallChunk(_)
        ));
        assert!(matches!(
            pool.alloc(MEDIUM_CHUNK_SIZE).unwrap(),
            PoolChunk::MediumChunk(_)
        ));
        assert!(matches!(
            pool.alloc(BIG_CHUNK_SIZE).unwrap(),
            PoolChunk::BigChunk(_)
        ));
    }

    #[test]
    fn alloc_too_many_small_chunks() {
        static mut MEMORY: Memory = [0; Pool::required_memory()];
        let pool = Pool::try_from(unsafe { &mut MEMORY }).unwrap();
        for _ in 0..SMALL_CHUNKS {
            assert!(matches!(
                pool.alloc(SMALL_CHUNK_SIZE).unwrap(),
                PoolChunk::SmallChunk(_)
            ));
        }
        // We have exhausted all small chunks. Next allocations are promoted to medium chunks
        for _ in 0..MEDIUM_CHUNKS {
            assert!(matches!(
                pool.alloc(SMALL_CHUNK_SIZE).unwrap(),
                PoolChunk::MediumChunk(_)
            ));
        }
        // We have exhausted all medium chunks. Next allocations are promoted to big chunks
        for _ in 0..BIG_CHUNKS {
            assert!(matches!(
                pool.alloc(SMALL_CHUNK_SIZE).unwrap(),
                PoolChunk::BigChunk(_)
            ));
        }
        // No more chunks available
        assert!(pool.alloc(SMALL_CHUNK_SIZE).is_err());
    }
}
