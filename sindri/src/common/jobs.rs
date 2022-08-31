use crate::common::pool::PoolChunk;
use crate::host::scheduler;

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Request {
    GetRandom { size: usize },
}

#[derive(Eq, PartialEq, Debug)]
pub enum Response {
    Error(scheduler::Error),
    GetRandom { data: PoolChunk },
}
