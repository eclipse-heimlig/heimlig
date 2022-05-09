use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

pub const MAX_RANDOM_DATA: usize = 1024;

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub enum Error {
    NotInitialized,
    Alloc,
    RequestedDataExceedsLimit,
}

#[derive(Deserialize, Serialize)]
pub enum CryptoRequest {
    GetRandom { size: usize },
}

#[derive(Deserialize, Serialize)]
pub enum CryptoResponse {
    Error(Error),
    GetRandom { data: Vec<u8> },
}
