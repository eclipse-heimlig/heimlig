use crate::common::channel::{Receiver, Sender};
use crate::common::jobs::{Error, Request, Response};
use alloc::vec::Vec;

/// Sindri API to be instantiated once per core
// TODO: Enable multiple clients
pub struct Api<S: Sender, R: Receiver> {
    pub sender: S,
    pub receiver: R,
}

impl<S: Sender, R: Receiver> Api<S, R> {
    pub fn enqueue(&mut self, request: Request) -> Result<(), Error> {
        let request: Vec<u8> = request.try_into()?;
        self.sender.send(request.as_slice());
        Ok(())
    }

    pub fn dequeue(&mut self) -> Result<Response, Error> {
        let response = self.receiver.recv();
        Response::try_from(response.as_slice())
    }
}
