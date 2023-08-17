use crate::common::jobs::Response::GetRandom;
use crate::common::jobs::{Error, OutParam, Response};
use crate::common::limits::MAX_RANDOM_SIZE;
use crate::common::pool::Pool;
use crate::crypto::rng::{EntropySource, Rng};
use rand_core::RngCore;

pub struct RngWorker<'a, E: EntropySource> {
    pub pool: &'a Pool,
    pub rng: Rng<E>,
}

impl<'a, E: EntropySource> RngWorker<'a, E> {
    pub fn get_random(&mut self, mut data: OutParam) -> Response {
        let data_slice = data.as_mut_slice();
        if data_slice.len() >= MAX_RANDOM_SIZE {
            return Response::Error(Error::RequestTooLarge);
        }
        self.rng.fill_bytes(data_slice);
        GetRandom { data }
    }
}
