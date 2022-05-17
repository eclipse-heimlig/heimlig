use crate::host::scheduler;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

pub const MAX_RANDOM_DATA: usize = 1024;

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Error {
    Decode(postcard::Error),
    Encode(postcard::Error),
}

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
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Error> {
        postcard::from_bytes(value).map_err(Error::Decode)
    }
}

impl TryFrom<&[u8]> for Response {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Error> {
        postcard::from_bytes(value).map_err(Error::Decode)
    }
}

impl TryInto<Vec<u8>> for Request {
    type Error = Error;

    fn try_into(self) -> Result<Vec<u8>, Error> {
        postcard::to_allocvec(&self).map_err(Error::Encode) // TODO: Avoid allocation by using rkyv or bincode
    }
}

impl TryInto<Vec<u8>> for Response {
    type Error = Error;

    fn try_into(self) -> Result<Vec<u8>, Error> {
        postcard::to_allocvec(&self).map_err(Error::Encode) // TODO: Avoid allocation by using rkyv or bincode
    }
}
