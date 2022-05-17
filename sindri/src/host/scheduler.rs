use crate::common::alloc::alloc_vec;
use crate::crypto::rng::{EntropySource, Rng};
use crate::host::jobs::{Request, Response, MAX_RANDOM_DATA};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub enum Error {
    Alloc,
    RequestedDataExceedsLimit,
}

pub struct Scheduler<E: EntropySource> {
    pub rng: Rng<E>, // TODO: Have the RNG as a singleton available everywhere?
}

// TODO: Replace return value with an SPSC queue back to the caller for async operation
impl<E: EntropySource> Scheduler<E> {
    pub fn schedule(&mut self, job: Request) -> Response {
        match job {
            Request::GetRandom { size } => {
                if size >= MAX_RANDOM_DATA {
                    return Response::Error(Error::RequestedDataExceedsLimit);
                }
                if let Ok(mut data) = alloc_vec(size) {
                    self.rng.fill_bytes(data.as_mut_slice());
                    Response::GetRandom { data }
                } else {
                    Response::Error(Error::Alloc)
                }
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod test {
    use crate::crypto::rng::{EntropySource, Rng};
    use crate::host::jobs::{Request, Response, MAX_RANDOM_DATA};
    use crate::host::scheduler::Error;
    use crate::host::scheduler::Scheduler;

    #[derive(Default)]
    pub struct TestEntropySource {}

    impl EntropySource for TestEntropySource {
        fn random_seed(&mut self) -> [u8; 32] {
            [0u8; 32]
        }
    }

    #[test]
    fn get_random() {
        let entropy = TestEntropySource::default();
        let rng = Rng::new(entropy, None);
        let mut scheduler = Scheduler { rng };
        let request = Request::GetRandom { size: 32 };
        let response = scheduler.schedule(request);
        match response {
            Response::GetRandom { data } => {
                assert_eq!(data.len(), 32)
            }
            _ => {
                panic!("Unexpected response type");
            }
        };
    }

    #[test]
    fn get_random_request_too_large() {
        let entropy = TestEntropySource::default();
        let rng = Rng::new(entropy, None);
        let mut scheduler = Scheduler { rng };
        let request = Request::GetRandom {
            size: MAX_RANDOM_DATA + 1,
        };
        let response = scheduler.schedule(request);
        assert!(matches!(
            response,
            Response::Error(Error::RequestedDataExceedsLimit)
        ))
    }
}
