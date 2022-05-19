use crate::common::channel::{Receiver, Sender};
use crate::common::jobs::{Request, Response};
use alloc::vec::Vec;

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Error {
    Encode,
    Decode,
    Send,
}

/// Sindri API to be instantiated once per core
// TODO: Enable multiple clients
pub struct Api<S: Sender, R: Receiver> {
    pub sender: S,
    pub receiver: R,
}

impl<S: Sender, R: Receiver> Api<S, R> {
    pub fn enqueue(&mut self, request: Request) -> Result<(), Error> {
        let request: Vec<u8> = request.try_into().map_err(|_| Error::Encode)?;
        self.sender
            .send(request.as_slice())
            .map_err(|_| Error::Send)?;
        Ok(())
    }

    pub fn dequeue(&mut self) -> Result<Response, Error> {
        let response = self.receiver.recv();
        Response::try_from(response.as_slice()).map_err(|_| Error::Decode)
    }
}
