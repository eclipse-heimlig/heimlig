use crate::common::jobs::{Request, Response};

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Error {
    /// No [Channel] found for given ID.
    UnknownChannelId,
    /// Attempted to push to a full queue.
    QueueFull,
    /// Failed to enqueue into a queue
    Enqueue,
    /// Sink was not ready
    NotReady,
}

/// Sink where the responses from the Core can be pushed to
pub trait ResponseSink<'data> {
    /// Send a [Response] to the client through this sink.
    fn send(&mut self, response: Response<'data>) -> Result<(), Error>;
    fn ready(&self) -> bool;
}

/// Sink where the requests to the Core can be pushed to
pub trait RequestSink<'data> {
    /// Send a [Request] to the client through this sink.
    fn send(&mut self, request: Request<'data>) -> Result<(), Error>;
    fn ready(&self) -> bool;
}
