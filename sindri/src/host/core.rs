use crate::crypto::rng::{EntropySource, Rng};
use crate::host::jobs::{Error, Request};
use crate::host::scheduler::Scheduler;
use alloc::vec::Vec;

pub trait Client {
    fn write(&mut self, data: &[u8]);
}

pub struct Core<E: EntropySource> {
    scheduler: Scheduler<E>,
}

impl<E: EntropySource> Core<E> {
    pub fn new(rng: Rng<E>) -> Core<E> {
        Core {
            scheduler: Scheduler { rng },
        }
    }
}

impl<E: EntropySource> Core<E> {
    pub fn process<C: Client>(&mut self, client: &mut C, data: &[u8]) -> Result<(), Error> {
        let request = Request::try_from(data)?;
        let response = self.scheduler.schedule(request);
        let response: Vec<u8> = response.try_into().expect("Failed to serialize result");
        client.write(response.as_slice());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use crate::crypto::rng;
    use crate::host::core::{Client, Core};
    use crate::host::jobs::{Error, Request, Response};
    use alloc::vec;
    use alloc::vec::Vec;
    use std::println;

    struct TestClient {
        output: Vec<u8>,
    }

    impl Client for TestClient {
        fn write(&mut self, data: &[u8]) {
            self.output.extend_from_slice(&data);
            println!("Data received by client: {}", hex::encode(&data));
        }
    }

    #[test]
    fn receive_rng_request() {
        let entropy = rng::test::TestEntropySource::default();
        let rng = rng::Rng::new(entropy, None);
        let request = Request::GetRandom { size: 32 };
        let mut client = TestClient { output: Vec::new() };
        let mut core = Core::new(rng);
        let request = postcard::to_allocvec(&request).unwrap();
        assert!(matches!(
            core.process(&mut client, request.as_slice()),
            Ok(())
        ));
        match postcard::from_bytes(client.output.as_slice()).unwrap() {
            Response::GetRandom { data } => {
                assert_eq!(data.len(), 32)
            }
            _ => {
                panic!("Unexpected response type");
            }
        }
    }

    #[test]
    fn receive_invalid_data() {
        let entropy = rng::test::TestEntropySource::default();
        let rng = rng::Rng::new(entropy, None);
        let mut client = TestClient { output: Vec::new() };
        let mut core = Core::new(rng);
        let invalid_data = vec![1, 2, 3];
        assert!(matches!(
            core.process(&mut client, invalid_data.as_slice()),
            Err(Error::Decode(postcard::Error::SerdeDeCustom))
        ));
    }
}
