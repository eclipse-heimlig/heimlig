use crate::crypto::rng::{EntropySource, Rng};
use crate::host::core::Error::{Decode, UnknownChannel};
use crate::host::jobs::{CryptoRequest, CryptoResponse};
use crate::host::scheduler::Scheduler;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

pub type ChannelId = u8;

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Error {
    Decode(postcard::Error),
    Encode(postcard::Error),
    UnknownChannel,
}

pub trait Channel {
    fn id(&self) -> ChannelId;
    fn available_data(&self) -> usize;
    fn read(&mut self) -> &[u8];
    fn write(&mut self, data: &[u8]);
}

#[derive(Deserialize, Serialize)]
struct Request {
    channel: ChannelId,
    inner: CryptoRequest,
}

#[derive(Deserialize, Serialize)]
struct Response {
    inner: CryptoResponse,
}

struct Core<C: Channel, E: EntropySource> {
    scheduler: Scheduler<E>,
    channels: Vec<C>,
}

impl<C: Channel, E: EntropySource> Core<C, E> {
    pub fn new(channels: Vec<C>, rng: Rng<E>) -> Core<C, E> {
        Core {
            scheduler: Scheduler { rng },
            channels,
        }
    }
}

impl<C: Channel, E: EntropySource> Core<C, E> {
    pub fn receive(&mut self, data: &[u8]) -> Result<(), Error> {
        let request: Request = postcard::from_bytes(data).map_err(Decode)?;
        let channel = self
            .channels
            .iter_mut()
            .find(|c| c.id() == request.channel)
            .ok_or(UnknownChannel)?;
        let response = self.scheduler.schedule(request.inner);
        let response = postcard::to_allocvec(&Response { inner: response }) // TODO: Avoid allocation by using rkyv or bincode
            .expect("Failed to serialize result");
        channel.write(response.as_slice());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use crate::crypto::rng;
    use crate::host::core::Error::Decode;
    use crate::host::core::{Channel, ChannelId, Core, Request, Response};
    use crate::host::jobs::{CryptoRequest, CryptoResponse};
    use alloc::vec;
    use alloc::vec::Vec;

    struct TestChannel {
        id: ChannelId,
        input: Vec<u8>,
        output: Vec<u8>,
    }

    impl Channel for TestChannel {
        fn id(&self) -> ChannelId {
            self.id
        }

        fn available_data(&self) -> usize {
            self.input.len()
        }

        fn read(&mut self) -> &[u8] {
            self.input.as_ref()
        }

        fn write(&mut self, data: &[u8]) {
            self.output.extend_from_slice(&data);
            std::println!("Channel {}: {}", self.id, hex::encode(&data));
        }
    }

    #[test]
    fn receive_rng_request() {
        let entropy = rng::test::TestEntropySource::default();
        let rng = rng::Rng::new(entropy, None);
        let channel_id = 0;
        let request = Request {
            channel: channel_id,
            inner: CryptoRequest::GetRandom { size: 32 },
        };
        let request = postcard::to_allocvec(&request).unwrap();
        let mut channel = TestChannel {
            id: channel_id,
            input: request.into(),
            output: Vec::new(),
        };
        let data = channel.read().to_vec();
        let mut core = Core::new(vec![channel], rng);
        assert!(matches!(core.receive(data.as_slice()), Ok(())));
        let output = core
            .channels
            .iter()
            .find(|c| c.id() == channel_id)
            .unwrap()
            .output
            .clone();
        let response: Response = postcard::from_bytes(output.as_slice()).unwrap();
        match response.inner {
            CryptoResponse::GetRandom { data } => {
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
        let invalid_data = vec![1, 2, 3];
        let mut channel = TestChannel {
            id: 0,
            input: invalid_data,
            output: Vec::new(),
        };
        let data = channel.read().to_vec();
        let mut core = Core::new(vec![channel], rng);
        assert!(matches!(
            core.receive(data.as_slice()),
            Err(Decode(postcard::Error::SerdeDeCustom))
        ));
    }
}
