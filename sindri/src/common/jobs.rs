use crate::host::scheduler;
use alloc::vec::Vec;

pub const MAX_RANDOM_DATA: usize = 1024;

#[derive(Debug)]
pub enum Request {
    GetRandom { size: usize },
}

#[derive(Debug)]
pub enum Response {
    Error(scheduler::Error),
    GetRandom { data: Vec<u8> },
}
