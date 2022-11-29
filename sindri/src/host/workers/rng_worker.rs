use crate::common::jobs::Response::GetRandom;
use crate::common::jobs::{Error, Response};
use crate::common::limits::MAX_RANDOM_SIZE;
use crate::common::pool::Pool;
use crate::crypto::rng::{EntropySource, Rng};
use rand_core::RngCore;

pub struct RngWorker<'a, E: EntropySource> {
    pub pool: &'a Pool,
    pub rng: Rng<E>,
}

impl<'a, E: EntropySource> RngWorker<'a, E> {
    pub fn get_random(&mut self, size: usize) -> Response {
        if size >= MAX_RANDOM_SIZE {
            return Response::Error(Error::RequestTooLarge);
        }
        match self.pool.alloc(size) {
            Err(_) => Response::Error(Error::Alloc),
            Ok(mut chunk) => {
                self.rng.fill_bytes(chunk.as_slice_mut());
                GetRandom { data: chunk }
            }
        }
    }
}
