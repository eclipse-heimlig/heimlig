use crate::host::scheduler;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

pub const MAX_RANDOM_DATA: usize = 1024;

#[derive(Deserialize, Serialize, Debug)]
pub enum Request {
    GetRandom { size: usize },
}

#[derive(Deserialize, Serialize, Debug)]
pub enum Response {
    Error(scheduler::Error),
    GetRandom { data: Vec<u8> },
}

impl TryFrom<&[u8]> for Request {
    type Error = postcard::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        postcard::from_bytes(value)
    }
}

impl TryFrom<&[u8]> for Response {
    type Error = postcard::Error;

    fn try_from(value: &[u8]) -> Result<Self, <Response as TryFrom<&[u8]>>::Error> {
        postcard::from_bytes(value)
    }
}

impl TryInto<Vec<u8>> for Request {
    type Error = postcard::Error;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        // TODO: Avoid allocation by using rkyv, bincode or to_slice
        postcard::to_allocvec(&self)
    }
}

impl TryInto<Vec<u8>> for Response {
    type Error = postcard::Error;

    fn try_into(self) -> Result<Vec<u8>, <Response as TryInto<Vec<u8>>>::Error> {
        // TODO: Avoid allocation by using rkyv, bincode or to_slice
        postcard::to_allocvec(&self)
    }
}
