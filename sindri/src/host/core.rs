use crate::common::jobs::{Request, Response};
use crate::crypto::rng::{EntropySource, Rng};
use crate::host::scheduler::Scheduler;

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

pub trait Sender {
    fn send(&mut self, response: Response);
}

impl<E: EntropySource, const QUEUE_SIZE: usize> Core<E, QUEUE_SIZE> {
    pub async fn process(
        &mut self,
        sender: &mut dyn Sender,
        request: Request,
    ) -> Result<(), Error> {
        let response = self.scheduler.schedule(request).await;
        sender.send(response);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use crate::common::jobs::{Request, Response};
    use crate::crypto::rng;
    use crate::host::core::Core;
    use heapless::spsc::{Consumer, Producer, Queue};

    const QUEUE_SIZE: usize = 8;

    struct ResponseReceiver<'a> {
        receiver: Consumer<'a, Response, QUEUE_SIZE>,
    }

    struct ResponseSender<'a> {
        sender: Producer<'a, Response, QUEUE_SIZE>,
    }

    impl<'ch> crate::host::core::Sender for ResponseSender<'ch> {
        fn send(&mut self, response: Response) {
            let _response = self.sender.enqueue(response);
        }
    }

    impl<'ch> ResponseReceiver<'ch> {
        fn recv(&mut self) -> Option<Response> {
            self.receiver.dequeue()
        }
    }

    #[futures_test::test]
    async fn receive_rng_request() {
        let entropy = rng::test::TestEntropySource::default();
        let rng = rng::Rng::new(entropy, None);
        let mut core = Core::<_, QUEUE_SIZE>::new(rng);
        let mut host_to_client: Queue<Response, QUEUE_SIZE> = Queue::<Response, QUEUE_SIZE>::new();
        let (h2c_p, h2c_c) = host_to_client.split();
        let mut response_receiver = ResponseReceiver { receiver: h2c_c };
        let mut response_sender = ResponseSender { sender: h2c_p };

        let request = Request::GetRandom { size: 32 };
        assert!(matches!(
            core.process(&mut response_sender, request).await,
            Ok(())
        ));
        match response_receiver.recv() {
            Some(response) => match response {
                Response::GetRandom { data } => {
                    assert_eq!(data.len(), 32)
                }
                _ => {
                    panic!("Unexpected response type");
                }
            },
            None => {
                panic!("Failed to receive expected response");
            }
        }
    }
}
