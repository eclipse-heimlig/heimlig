use crate::common::jobs::{Request, Response};
use crate::crypto::rng::{EntropySource, Rng};
use crate::host::scheduler::Scheduler;
use heapless::spsc::Producer;

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Error {
    Encode,
    Decode,
    Send,
}

pub struct Core<E: EntropySource, const QUEUE_SIZE: usize> {
    scheduler: Scheduler<E>,
}

impl<E: EntropySource, const QUEUE_SIZE: usize> Core<E, QUEUE_SIZE> {
    pub fn new(rng: Rng<E>) -> Core<E, QUEUE_SIZE> {
        Core {
            scheduler: Scheduler { rng },
        }
    }
}

impl<E: EntropySource, const QUEUE_SIZE: usize> Core<E, QUEUE_SIZE> {
    pub async fn process(
        &mut self,
        producer: &mut Producer<'_, Response, QUEUE_SIZE>,
        request: Request,
    ) -> Result<(), Error> {
        let response = self.scheduler.schedule(request).await;
        producer.enqueue(response).map_err(|_| Error::Send)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use crate::common::jobs::{Request, Response};
    use crate::crypto::rng;
    use crate::host::core::Core;
    use heapless::spsc::Queue;

    const QUEUE_SIZE: usize = 8;
    static mut HOST_TO_CLIENT: Queue<Response, QUEUE_SIZE> = Queue::<Response, QUEUE_SIZE>::new();

    #[futures_test::test]
    async fn receive_rng_request() {
        let entropy = rng::test::TestEntropySource::default();
        let rng = rng::Rng::new(entropy, None);
        let (mut p2, mut c2) = unsafe { HOST_TO_CLIENT.split() };

        let request = Request::GetRandom { size: 32 };
        let mut core = Core::<_, QUEUE_SIZE>::new(rng);
        assert!(matches!(core.process(&mut p2, request).await, Ok(())));
        match c2.dequeue() {
            Some(response) => match response {
                Response::GetRandom { data } => {
                    assert_eq!(data.len(), 32)
                }
                _ => {
                    panic!("Unexpected response type");
                }
            },
            None => {
                panic!("Failed to obtain response");
            }
        }
    }
}
