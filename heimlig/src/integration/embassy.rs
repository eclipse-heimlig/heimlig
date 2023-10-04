use crate::common::jobs::{Request, Response};
use core::cell::RefCell;
use core::pin::Pin;
use core::task::{Context, Poll};
use critical_section::Mutex;
use embassy_sync::waitqueue::WakerRegistration;
use heapless::spsc::{Consumer, Producer, Queue};

pub type RequestQueue<'data, const QUEUE_SIZE: usize> = AsyncQueue<Request<'data>, QUEUE_SIZE>;
pub type ResponseQueue<'data, const QUEUE_SIZE: usize> = AsyncQueue<Response<'data>, QUEUE_SIZE>;
pub type RequestQueueSink<'ch, 'data, const QUEUE_SIZE: usize> =
    AsyncQueueSink<'ch, Request<'data>, QUEUE_SIZE>;
pub type RequestQueueSource<'ch, 'data, const QUEUE_SIZE: usize> =
    AsyncQueueSource<'ch, Request<'data>, QUEUE_SIZE>;
pub type ResponseQueueSink<'ch, 'data, const QUEUE_SIZE: usize> =
    AsyncQueueSink<'ch, Response<'data>, QUEUE_SIZE>;
pub type ResponseQueueSource<'ch, 'data, const QUEUE_SIZE: usize> =
    AsyncQueueSource<'ch, Response<'data>, QUEUE_SIZE>;

pub struct AsyncQueue<T, const QUEUE_SIZE: usize> {
    queue: Queue<T, QUEUE_SIZE>,
    receiver_waker: Mutex<RefCell<WakerRegistration>>,
    sender_waker: Mutex<RefCell<WakerRegistration>>,
}

impl<T, const QUEUE_SIZE: usize> Default for AsyncQueue<T, QUEUE_SIZE> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const QUEUE_SIZE: usize> AsyncQueue<T, QUEUE_SIZE> {
    pub const fn new() -> Self {
        Self {
            queue: Queue::<T, QUEUE_SIZE>::new(),
            receiver_waker: Mutex::new(RefCell::new(WakerRegistration::new())),
            sender_waker: Mutex::new(RefCell::new(WakerRegistration::new())),
        }
    }

    pub fn split(
        &mut self,
    ) -> (
        AsyncQueueSink<'_, T, QUEUE_SIZE>,
        AsyncQueueSource<'_, T, QUEUE_SIZE>,
    ) {
        let (producer, consumer) = self.queue.split();
        (
            AsyncQueueSink {
                producer,
                receiver_waker: &self.receiver_waker,
                sender_waker: &self.sender_waker,
            },
            AsyncQueueSource {
                consumer,
                receiver_waker: &self.receiver_waker,
                sender_waker: &self.sender_waker,
            },
        )
    }
}

pub struct AsyncQueueSource<'ch, T, const QUEUE_SIZE: usize> {
    consumer: Consumer<'ch, T, QUEUE_SIZE>,
    receiver_waker: &'ch Mutex<RefCell<WakerRegistration>>,
    sender_waker: &'ch Mutex<RefCell<WakerRegistration>>,
}

pub struct AsyncQueueSink<'ch, T, const QUEUE_SIZE: usize> {
    producer: Producer<'ch, T, QUEUE_SIZE>,
    receiver_waker: &'ch Mutex<RefCell<WakerRegistration>>,
    sender_waker: &'ch Mutex<RefCell<WakerRegistration>>,
}

impl<T, const QUEUE_SIZE: usize> futures::Stream for AsyncQueueSource<'_, T, QUEUE_SIZE> {
    type Item = T;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(item) = self.consumer.dequeue() {
            critical_section::with(|cs| self.sender_waker.borrow_ref_mut(cs).wake());
            Poll::Ready(Some(item))
        } else {
            critical_section::with(|cs| {
                self.receiver_waker.borrow_ref_mut(cs).register(cx.waker())
            });
            Poll::Pending
        }
    }
}

impl<T, const QUEUE_SIZE: usize> futures::Sink<T> for AsyncQueueSink<'_, T, QUEUE_SIZE> {
    type Error = ();

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.producer.ready() {
            Poll::Ready(Ok(()))
        } else {
            critical_section::with(|cs| self.sender_waker.borrow_ref_mut(cs).register(cx.waker()));
            Poll::Pending
        }
    }

    fn start_send(self: Pin<&mut Self>, item: T) -> Result<(), Self::Error> {
        critical_section::with(|cs| self.receiver_waker.borrow_ref_mut(cs).wake());
        let _ = self.get_mut().producer.enqueue(item);
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}
