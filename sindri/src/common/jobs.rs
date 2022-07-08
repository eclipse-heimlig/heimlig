use crate::host::scheduler;
use heapless::{Vec, pool::Box};
use crate::common::limits::MAX_RANDOM_SIZE;

pub const POOL_CHUNK_SIZE: usize = 128;
pub const MAX_CHUNKS: usize = 8;


pub static mut POOL: heapless::pool::Pool<PoolChunk> = heapless::pool::Pool::<PoolChunk>::new();

#[derive(Clone, Debug)]
pub enum Request {
    GetRandom { size: usize },
}

#[derive(Clone, Debug)]
pub struct PoolChunk {
    data: [u8; POOL_CHUNK_SIZE]
}

#[derive(Debug)]
pub struct ResponseData {
    size: usize,
    chunk_list: Vec<Box<PoolChunk>, MAX_CHUNKS>
}

#[derive(Debug)]
pub enum Response {
    Error(scheduler::Error),
    GetRandom { response_data: ResponseData },
}

impl ResponseData {
    pub fn new() -> ResponseData {
        ResponseData {
            size: 0,
            chunk_list: Default::default(),
        }
    }

    pub fn len(self) -> usize {
        return self.size;
    } 

/*
    pub fn alloc(&mut self, size: usize) -> bool {
        self.size = size;
        let mut left = size;
        match unsafe {
            POOL.alloc()
        } {
            None => {
                self.chunk_list = None;
                return false;
            },
            Some(b) => {
                let mut chunk = b.init(PoolChunk { next: None, data: [0u8; POOL_CHUNK_SIZE] });
                loop {
                    if left <= POOL_CHUNK_SIZE {
                        break;
                    }
                    match unsafe {
                        POOL.alloc()
                    } {
                        None => {
                            self.chunk_list = None;
                            return false;
                        },
                        Some(b2) => {
                            let mut next_chunk = b2.init(PoolChunk { next: 
None, data: [0u8; POOL_CHUNK_SIZE] });
                            next_chunk.next = Some(&chunk);
                            chunk = next_chunk;
                            left -= POOL_CHUNK_SIZE;
                        }d
                    }       
                }
                self.chunk_list = Some(&chunk);
        
            } 
        }
        return true;
    }
*/

    pub fn alloc(&mut self, size: usize) -> bool {
        self.size = size;
        let mut left = size;
        loop {
            match unsafe {
                POOL.alloc()
            } {
                None => {
                    self.chunk_list.clear();
                    return false;
                },
                Some(b2) => {
                    let b2 = b2.init(PoolChunk { data: [0u8; POOL_CHUNK_SIZE] });
                    match self.chunk_list.push(b2) {
                        Ok(_) => {
                            if left <= POOL_CHUNK_SIZE {
                                break;
                            }
                            left -= POOL_CHUNK_SIZE;

                        },
                        Err(_) => {
                            self.chunk_list.clear();
                            return false;
                        }
                    } 
                }
            }       
        }
        return true;
    }

/*
    pub fn copy_from_vec(&mut self, vec: Vec<u8, MAX_RANDOM_SIZE>)
    {
        match self.chunk_list {
            None => {
                return;
            },
            Some(first_chunk) => {
                let mut chunk = first_chunk;
                let mut cnt: usize = 0;
                for elem in vec.iter()
                {
                    chunk.data[cnt] = *elem;
                    cnt += 1;
                    if cnt == POOL_CHUNK_SIZE {
                        match chunk.next {
                            None => {
                                return;
                            },
                            Some(next_chunk) => {
                                chunk = next_chunk;
                                cnt = 0;
                            }
                        }
                    }
                }
            }
        }
    }
*/

    pub fn copy_from_vec(&mut self, vec: &Vec<u8, MAX_RANDOM_SIZE>)
    {
        if (vec.len() + POOL_CHUNK_SIZE - 1 )/POOL_CHUNK_SIZE > MAX_CHUNKS {
            return; // TODO: return error
        }
        let mut chunk_idx = 0;
        let mut cnt = 0;
        for elem in vec.iter()
        {
            self.chunk_list[chunk_idx].data[cnt] = *elem;
            cnt += 1;
            if cnt == POOL_CHUNK_SIZE {
                chunk_idx += 1;
                cnt = 0;
            }
        }
    }

    pub fn copy_to_vec(&self, vec: &mut Vec<u8, MAX_RANDOM_SIZE>)
    {
        if self.size > MAX_RANDOM_SIZE {
            return; // TODO: return error
        }
        let mut chunk_idx = 0;
        let mut cnt = 0;
        let mut chunk_cnt = 0;
        loop
        {
            match vec.push(self.chunk_list[chunk_idx].data[chunk_cnt]) {
                Ok(_) => {
                },
                Err(_) => {
                    return;
                }
            }
            cnt += 1;
            if cnt == self.size {
                break;
            }
            chunk_cnt += 1;
            if chunk_cnt == POOL_CHUNK_SIZE {
                chunk_idx += 1;
                chunk_cnt = 0;
            }
        }
    }

}