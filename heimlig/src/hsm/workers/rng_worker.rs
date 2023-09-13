use crate::common::jobs::Response::GetRandom;
use crate::common::jobs::{Error, Request, Response};
use crate::common::limits::MAX_RANDOM_SIZE;
use crate::common::queues;
use crate::common::queues::ResponseSink;
use crate::crypto::rng::{EntropySource, Rng};
use rand_core::RngCore;

pub struct RngWorker<
    'data,
    E: EntropySource,
    ReqSrc: Iterator<Item = (usize, Request<'data>)>,
    RespSink: ResponseSink<'data>,
> {
    pub rng: Rng<E>,
    pub requests: ReqSrc,
    pub responses: RespSink,
}

impl<
        'data,
        E: EntropySource,
        ReqSrc: Iterator<Item = (usize, Request<'data>)>,
        RespSink: ResponseSink<'data>,
    > RngWorker<'data, E, ReqSrc, RespSink>
{
    pub fn execute(&mut self) -> Result<(), queues::Error> {
        if self.responses.ready() {
            match self.requests.next() {
                None => Ok(()), // Nothing to process
                Some((_id, Request::GetRandom { output })) => {
                    let response = self.get_random(output);
                    self.responses.send(response)
                }
                _ => panic!("Encountered unexpected request"), // TODO: Integration error. Return error here instead?
            }
        } else {
            Err(queues::Error::NotReady)
        }
    }

    fn get_random<'a>(&mut self, output: &'a mut [u8]) -> Response<'a> {
        if output.len() >= MAX_RANDOM_SIZE {
            return Response::Error(Error::RequestTooLarge);
        }
        self.rng.fill_bytes(output);
        GetRandom { data: output }
    }
}
