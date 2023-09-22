use crate::common::jobs::Response::GetRandom;
use crate::common::jobs::{ClientId, Error, Request, RequestId, Response};
use crate::common::limits::MAX_RANDOM_SIZE;
use crate::crypto::rng::{EntropySource, Rng};
use futures::{Sink, SinkExt, Stream, StreamExt};
use rand_core::RngCore;

pub struct RngWorker<
    'data,
    E: EntropySource,
    ReqSrc: Stream<Item = Request<'data>>,
    RespSink: Sink<Response<'data>>,
> {
    pub rng: Rng<E>,
    pub requests: ReqSrc,
    pub responses: RespSink,
}

impl<
        'data,
        E: EntropySource,
        ReqSrc: Stream<Item = Request<'data>> + Unpin,
        RespSink: Sink<Response<'data>> + Unpin,
    > RngWorker<'data, E, ReqSrc, RespSink>
{
    pub async fn execute(&mut self) -> Result<(), Error> {
        match self.requests.next().await {
            None => Ok(()), // Nothing to process
            Some(Request::GetRandom {
                client_id,
                request_id,
                output,
            }) => {
                let response = self.get_random(client_id, request_id, output);
                self.responses
                    .send(response)
                    .await
                    .map_err(|_e| Error::Send)
            }
            _ => panic!("Encountered unexpected request"),
        }
    }

    fn get_random(
        &mut self,
        client_id: ClientId,
        request_id: RequestId,
        output: &'data mut [u8],
    ) -> Response<'data> {
        if output.len() >= MAX_RANDOM_SIZE {
            return Response::Error {
                client_id,
                request_id,
                error: Error::RequestTooLarge,
            };
        }
        self.rng.fill_bytes(output);
        GetRandom {
            client_id,
            request_id,
            data: output,
        }
    }
}
