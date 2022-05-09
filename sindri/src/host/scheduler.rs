use crate::common::alloc::alloc_vec;
use crate::crypto::rng::{EntropySource, Rng};
use crate::host::jobs::Error::{Alloc, RequestedDataExceedsLimit};
use crate::host::jobs::{CryptoRequest, CryptoResponse, MAX_RANDOM_DATA};
use rand_core::RngCore;

pub struct Scheduler<E: EntropySource> {
    pub rng: Rng<E>, // TODO: Have the RNG as a singleton available everywhere?
}

// TODO: Replace return value with an SPSC queue back to the caller for async operation
impl<E: EntropySource> Scheduler<E> {
    pub fn schedule(&mut self, job: CryptoRequest) -> CryptoResponse {
        match job {
            CryptoRequest::GetRandom { size } => {
                if size >= MAX_RANDOM_DATA {
                    return CryptoResponse::Error(RequestedDataExceedsLimit);
                }
                if let Ok(mut data) = alloc_vec(size) {
                    self.rng.fill_bytes(data.as_mut_slice());
                    CryptoResponse::GetRandom { data }
                } else {
                    CryptoResponse::Error(Alloc)
                }
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod test {
    use crate::crypto::rng::{EntropySource, Rng};
    use crate::host::jobs::Error::RequestedDataExceedsLimit;
    use crate::host::jobs::{CryptoRequest, CryptoResponse, MAX_RANDOM_DATA};
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
        let request = CryptoRequest::GetRandom { size: 32 };
        let response = scheduler.schedule(request);
        match response {
            CryptoResponse::GetRandom { data } => {
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
        let request = CryptoRequest::GetRandom {
            size: MAX_RANDOM_DATA + 1,
        };
        let response = scheduler.schedule(request);
        assert!(matches!(
            response,
            CryptoResponse::Error(RequestedDataExceedsLimit)
        ))
    }
}
