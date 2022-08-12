use crate::common::pool::PoolChunk;
use crate::host::scheduler;
use heapless::pool::{Box, Init};

#[derive(Clone, Debug)]
pub enum Request {
    GetRandom { size: usize },
}

#[derive(Debug)]
pub enum Response {
    Error(scheduler::Error),
    GetRandom { data: Box<PoolChunk, Init> },
}
