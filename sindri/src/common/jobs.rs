use crate::common::limits::MAX_RANDOM_SIZE;
use crate::host::scheduler;
use heapless::Vec;

#[derive(Clone, Debug)]
pub enum Request {
    GetRandom { size: usize },
}

#[derive(Clone, Debug)]
pub enum Response {
    Error(scheduler::Error),
    GetRandom { data: Vec<u8, MAX_RANDOM_SIZE> },
}
