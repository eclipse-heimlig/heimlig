use crate::common::jobs::Response;
use crate::common::jobs::Response::GetRandom;
use crate::common::limits::MAX_RANDOM_SIZE;
use crate::common::pool::Pool;
use crate::crypto::rng::{EntropySource, Rng};
use crate::host::scheduler::Error;
use rand_core::RngCore;

pub struct RngWorker<E: EntropySource> {
    pub pool: &'static Pool,
    pub rng: Rng<E>,
}

impl<E: EntropySource> RngWorker<E> {
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
