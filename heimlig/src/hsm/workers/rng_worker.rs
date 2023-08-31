use crate::common::jobs::Response::GetRandom;
use crate::common::jobs::{Error, Response};
use crate::common::limits::MAX_RANDOM_SIZE;
use crate::crypto::rng::{EntropySource, Rng};
use rand_core::RngCore;

pub struct RngWorker<E: EntropySource> {
    pub rng: Rng<E>,
}

impl<E: EntropySource> RngWorker<E> {
    pub fn get_random<'a>(&mut self, output: &'a mut [u8]) -> Response<'a> {
        if output.len() >= MAX_RANDOM_SIZE {
            return Response::Error(Error::RequestTooLarge);
        }
        self.rng.fill_bytes(output);
        GetRandom { data: output }
    }
}
