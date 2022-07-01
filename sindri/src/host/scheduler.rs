use crate::common::jobs::{Request, Response};
use crate::common::limits::MAX_RANDOM_SIZE;
use crate::crypto::rng::{EntropySource, Rng};
use heapless::Vec;
use rand_core::RngCore;

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Error {
    Alloc,
    RequestedDataExceedsLimit,
}

pub struct Job {
    pub id: u32,
    pub request: Request,
}

pub struct JobResult {
    pub id: u32,
    pub response: Response,
}

pub struct Scheduler<E: EntropySource> {
    pub rng: Rng<E>, // TODO: Have the RNG as a singleton available everywhere?
}

// TODO: Replace return value with an SPSC queue back to the caller for async operation
impl<E: EntropySource> Scheduler<E> {
    pub async fn schedule(&mut self, job: Job) -> JobResult {
        let response = match job.request {
            Request::GetRandom { size } => self.proc_random(size),
        };
        JobResult {
            id: job.id,
            response,
        }
    }

    // TODO: Move to worker task
    fn proc_random(&mut self, size: usize) -> Response {
        if size >= MAX_RANDOM_SIZE {
            return Response::Error(Error::RequestedDataExceedsLimit);
        }
        let mut data: Vec<u8, MAX_RANDOM_SIZE> = Vec::new();
        match data.resize(size, 0) {
            Ok(_) => {
                self.rng.fill_bytes(&mut data);
                Response::GetRandom { data }
            }
            Err(_) => Response::Error(Error::Alloc),
        }
    }
}

#[cfg(test)]
pub(crate) mod test {
    use crate::common::jobs::{Request, Response};
    use crate::common::limits::MAX_RANDOM_SIZE;
    use crate::crypto::rng::{EntropySource, Rng};
    use crate::host::scheduler::Scheduler;
    use crate::host::scheduler::{Error, Job};

    #[derive(Default)]
    pub struct TestEntropySource {}

    impl EntropySource for TestEntropySource {
        fn random_seed(&mut self) -> [u8; 32] {
            [0u8; 32]
        }
    }

    #[futures_test::test]
    async fn get_random() {
        let entropy = TestEntropySource::default();
        let rng = Rng::new(entropy, None);
        let mut scheduler = Scheduler { rng };
        let request = Request::GetRandom { size: 32 };
        let job = Job { id: 0, request };
        let result = scheduler.schedule(job).await;
        match result.response {
            Response::GetRandom { data } => {
                assert_eq!(data.len(), 32)
            }
            _ => {
                panic!("Unexpected response type");
            }
        };
    }

    #[futures_test::test]
    async fn get_random_request_too_large() {
        let entropy = TestEntropySource::default();
        let rng = Rng::new(entropy, None);
        let mut scheduler = Scheduler { rng };
        let request = Request::GetRandom {
            size: MAX_RANDOM_SIZE + 1,
        };
        let job = Job { id: 0, request };
        let result = scheduler.schedule(job).await;
        assert!(matches!(
            result.response,
            Response::Error(Error::RequestedDataExceedsLimit)
        ))
    }
}
