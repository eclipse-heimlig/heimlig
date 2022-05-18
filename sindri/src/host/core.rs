use crate::common::channel::Sender;
use crate::common::jobs::{Error, Request};
use crate::crypto::rng::{EntropySource, Rng};
use crate::host::scheduler::Scheduler;
use alloc::vec::Vec;

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
    pub fn process<S: Sender>(&mut self, sender: &mut S, data: &[u8]) -> Result<(), Error> {
        let request = Request::try_from(data)?;
        let response = self.scheduler.schedule(request);
        let response: Vec<u8> = response.try_into().expect("Failed to serialize result");
        sender.send(response.as_slice());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use crate::common::channel::{Receiver, Sender};
    use crate::common::jobs::{Error, Request, Response};
    use crate::crypto::rng;
    use crate::host::core::Core;
    use alloc::vec;
    use alloc::vec::Vec;
    use std::println;

    struct TestClient {
        id: u32,
        output: Vec<u8>,
    }

    impl Receiver for TestClient {
        fn id(&self) -> u32 {
            self.id
        }

        fn recv(&mut self) -> Vec<u8> {
            let ret = self.output.clone();
            self.output.clear();
            ret
        }
    }

    impl Sender for TestClient {
        fn id(&self) -> u32 {
            self.id
        }

        fn send(&mut self, data: &[u8]) {
            self.output.extend_from_slice(&data);
            println!("Data received by client: {}", hex::encode(&data));
        }
    }

    #[test]
    fn receive_rng_request() {
        let entropy = rng::test::TestEntropySource::default();
        let rng = rng::Rng::new(entropy, None);
        let request = Request::GetRandom { size: 32 };
        let mut client = TestClient {
            id: 0,
            output: Vec::new(),
        };
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
        let mut client = TestClient {
            id: 0,
            output: Vec::new(),
        };
        let mut core = Core::new(rng);
        let invalid_data = vec![1, 2, 3];
        assert!(matches!(
            core.process(&mut client, invalid_data.as_slice()),
            Err(Error::Decode)
        ));
    }
}
