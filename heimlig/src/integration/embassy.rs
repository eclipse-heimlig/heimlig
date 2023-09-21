use crate::common::jobs::{Request, Response};
use core::cell::RefCell;
use core::pin::Pin;
use core::task::{Context, Poll};
use embassy_sync::blocking_mutex;
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::waitqueue::WakerRegistration;
use heapless::spsc::{Consumer, Producer};

pub struct RequestQueueSource<'ch, 'data, M: RawMutex + Unpin, const QUEUE_SIZE: usize> {
    consumer: Consumer<'ch, Request<'data>, QUEUE_SIZE>,
    sender_waker: blocking_mutex::Mutex<M, RefCell<WakerRegistration>>,
}

pub struct ResponseQueueSink<'ch, 'data, M: RawMutex + Unpin, const QUEUE_SIZE: usize> {
    producer: Producer<'ch, Response<'data>, QUEUE_SIZE>,
    receiver_waker: blocking_mutex::Mutex<M, RefCell<WakerRegistration>>,
    sender_waker: blocking_mutex::Mutex<M, RefCell<WakerRegistration>>,
}

pub struct ResponseQueueSource<'ch, 'data, M: RawMutex + Unpin, const QUEUE_SIZE: usize> {
    consumer: Consumer<'ch, Response<'data>, QUEUE_SIZE>,
    senders_waker: blocking_mutex::Mutex<M, RefCell<WakerRegistration>>,
}

pub struct RequestQueueSink<'ch, 'data, M: RawMutex + Unpin, const QUEUE_SIZE: usize> {
    producer: Producer<'ch, Request<'data>, QUEUE_SIZE>,
    receiver_waker: blocking_mutex::Mutex<M, RefCell<WakerRegistration>>,
    sender_waker: blocking_mutex::Mutex<M, RefCell<WakerRegistration>>,
}

impl<'data, M: RawMutex + Unpin, const QUEUE_SIZE: usize> futures::Stream
    for RequestQueueSource<'_, 'data, M, QUEUE_SIZE>
{
    type Item = Request<'data>;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.sender_waker.lock(|w| w.borrow_mut().wake());
        // No need to return pending and wake a receiver waker as dequeue() always returns directly
        Poll::Ready(self.get_mut().consumer.dequeue())
    }
}

impl<'ch, 'data, M: RawMutex + Unpin, const QUEUE_SIZE: usize>
    RequestQueueSource<'ch, 'data, M, QUEUE_SIZE>
{
    pub fn new(requests: Consumer<'ch, Request<'data>, QUEUE_SIZE>) -> Self {
        RequestQueueSource {
            consumer: requests,
            sender_waker: blocking_mutex::Mutex::new(RefCell::new(WakerRegistration::new())),
        }
    }
}

impl<'data, M: RawMutex + Unpin, const QUEUE_SIZE: usize> futures::Sink<Response<'data>>
    for ResponseQueueSink<'_, 'data, M, QUEUE_SIZE>
{
    type Error = ();

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.producer.ready() {
            Poll::Ready(Ok(()))
        } else {
            self.sender_waker.lock(|w| w.borrow_mut().wake());
            Poll::Pending
        }
    }

    fn start_send(self: Pin<&mut Self>, response: Response<'data>) -> Result<(), Self::Error> {
        self.receiver_waker.lock(|w| w.borrow_mut().wake());
        self.get_mut()
            .producer
            .enqueue(response)
            // Should never happen as a previous successful call to poll_ready can be assumed by contract
            .expect("Queue was full");
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

impl<'ch, 'data, M: RawMutex + Unpin, const QUEUE_SIZE: usize>
    ResponseQueueSink<'ch, 'data, M, QUEUE_SIZE>
{
    pub fn new(responses: Producer<'ch, Response<'data>, QUEUE_SIZE>) -> Self {
        ResponseQueueSink {
            producer: responses,
            receiver_waker: blocking_mutex::Mutex::new(RefCell::new(WakerRegistration::new())),
            sender_waker: blocking_mutex::Mutex::new(RefCell::new(WakerRegistration::new())),
        }
    }
}

impl<'data, M: RawMutex + Unpin, const QUEUE_SIZE: usize> futures::Stream
    for ResponseQueueSource<'_, 'data, M, QUEUE_SIZE>
{
    type Item = Response<'data>;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.senders_waker.lock(|w| w.borrow_mut().wake());
        // No need to return pending and wake a receiver waker as dequeue() always returns directly
        Poll::Ready(self.get_mut().consumer.dequeue())
    }
}

impl<'ch, 'data, M: RawMutex + Unpin, const QUEUE_SIZE: usize>
    ResponseQueueSource<'ch, 'data, M, QUEUE_SIZE>
{
    pub fn new(responses: Consumer<'ch, Response<'data>, QUEUE_SIZE>) -> Self {
        ResponseQueueSource {
            consumer: responses,
            senders_waker: blocking_mutex::Mutex::new(RefCell::new(WakerRegistration::new())),
        }
    }
}

impl<'data, M: RawMutex + Unpin, const QUEUE_SIZE: usize> futures::Sink<Request<'data>>
    for RequestQueueSink<'_, 'data, M, QUEUE_SIZE>
{
    type Error = ();

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.producer.ready() {
            Poll::Ready(Ok(()))
        } else {
            self.sender_waker.lock(|w| w.borrow_mut().wake());
            Poll::Pending
        }
    }

    fn start_send(self: Pin<&mut Self>, request: Request<'data>) -> Result<(), Self::Error> {
        self.receiver_waker.lock(|w| w.borrow_mut().wake());
        self.get_mut()
            .producer
            .enqueue(request)
            // Should never happen as a previous successful call to poll_ready can be assumed by contract
            .expect("Queue was full");
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

impl<'ch, 'data, M: RawMutex + Unpin, const QUEUE_SIZE: usize>
    RequestQueueSink<'ch, 'data, M, QUEUE_SIZE>
{
    pub fn new(requests: Producer<'ch, Request<'data>, QUEUE_SIZE>) -> Self {
        RequestQueueSink {
            producer: requests,
            receiver_waker: blocking_mutex::Mutex::new(RefCell::new(WakerRegistration::new())),
            sender_waker: blocking_mutex::Mutex::new(RefCell::new(WakerRegistration::new())),
        }
    }
}
