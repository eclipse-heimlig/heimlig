use crate::common::jobs::{Request, Response};

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Error {
    /// No [Channel] found for given ID.
    UnknownChannelId,
    /// Failed to enqueue into a queue
    Enqueue,
    /// Queue was not ready
    NotReady,
}

/// Sink where the requests to the Core can be pushed to
pub trait RequestSink<'data> {
    /// Send a [Request] to the client through this sink.
    fn send(&mut self, request: Request<'data>) -> Result<(), Error>;
    fn ready(&self) -> bool; // TODO: Remove after async is implemented
}

/// Sink where the responses from the Core can be pushed to
pub trait ResponseSink<'data> {
    /// Send a [Response] to the client through this sink.
    fn send(&mut self, response: Response<'data>) -> Result<(), Error>;
    fn ready(&self) -> bool; // TODO: Remove after async is implemented
}

// TODO: Use trait aliases once they are stable (https://doc.rust-lang.org/beta/unstable-book/language-features/trait-alias.html)
// pub type RequestSource<'data> = dyn Iterator<Item = (usize, Request<'data>)>;
// pub type ResponseSource<'data> = dyn Iterator<Item = (usize, Response<'data>)>;
