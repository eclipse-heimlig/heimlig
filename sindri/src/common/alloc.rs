use crate::common::alloc::Error::Alloc;
use alloc::collections::TryReserveError;
use alloc::vec::Vec;

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Error {
    Alloc(TryReserveError),
}

// TODO: Remove this function if no allocator is needed
pub fn alloc_vec(size: usize) -> Result<Vec<u8>, Error> {
    let mut data: Vec<u8> = Vec::new();
    data.try_reserve_exact(size).map_err(Alloc)?;
    data.resize(size, 0);
    Ok(data)
}
