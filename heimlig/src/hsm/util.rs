use core::{
    fmt,
    mem::{self},
    pin::Pin,
    task::{Context, Poll},
};

use futures::Future;
use heapless::Vec;

#[derive(Debug)]
enum MaybeDone<Fut: Future> {
    /// A not-yet-completed future
    Future(/* #[pin] */ Fut),
    /// The output of the completed future
    Done(Fut::Output),
    /// The empty variant after the result of a [`MaybeDone`] has been
    /// taken using the [`take_output`](MaybeDone::take_output) method.
    Gone,
}

impl<Fut: Future> MaybeDone<Fut> {
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> bool {
        let this = unsafe { self.get_unchecked_mut() };
        match this {
            Self::Future(fut) => match unsafe { Pin::new_unchecked(fut) }.poll(cx) {
                Poll::Ready(res) => {
                    *this = Self::Done(res);
                    true
                }
                Poll::Pending => false,
            },
            _ => true,
        }
    }

    fn take_output(&mut self) -> Fut::Output {
        match &*self {
            Self::Done(_) => {}
            Self::Future(_) | Self::Gone => panic!("take_output when MaybeDone is not done."),
        }
        match mem::replace(self, Self::Gone) {
            MaybeDone::Done(output) => output,
            _ => unreachable!(),
        }
    }
}

impl<Fut: Future + Unpin> Unpin for MaybeDone<Fut> {}

/// Future for the [`join_vec`] function.
#[must_use = "futures do nothing unless you `.await` or poll them"]
pub struct JoinVec<Fut: Future, const N: usize> {
    futures: Vec<MaybeDone<Fut>, N>,
}

impl<Fut: Future, const N: usize> fmt::Debug for JoinVec<Fut, N>
where
    Fut: Future + fmt::Debug,
    Fut::Output: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JoinVec")
            .field("futures", &self.futures)
            .finish()
    }
}

impl<Fut: Future, const N: usize> Future for JoinVec<Fut, N> {
    type Output = Vec<Fut::Output, N>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };
        let mut all_done = true;
        for f in this.futures.iter_mut() {
            all_done &= unsafe { Pin::new_unchecked(f) }.poll(cx);
        }

        if all_done {
            let vec: Vec<Fut::Output, N> =
                Vec::from_iter(this.futures.iter_mut().map(|fut| fut.take_output()));
            Poll::Ready(vec)
        } else {
            Poll::Pending
        }
    }
}

/// Joins the result of an array of futures, waiting for them all to complete.
///
/// This function will return a new future which awaits all futures to
/// complete. The returned future will finish with a tuple of all results.
///
/// Note that this function consumes the passed futures and returns a
/// wrapped version of it.
///
/// # Examples
///
/// ```
/// # embassy_futures::block_on(async {
///
/// async fn foo(n: u32) -> u32 { n }
/// let a = foo(1);
/// let b = foo(2);
/// let c = foo(3);
/// let res = embassy_futures::join::join_vec([a, b, c]).await;
///
/// assert_eq!(res, [1, 2, 3]);
/// # });
/// ```
pub fn join_vec<Fut: Future, const N: usize>(futures: Vec<Fut, N>) -> JoinVec<Fut, N> {
    JoinVec {
        futures: Vec::from_iter(futures.into_iter().map(MaybeDone::Future)),
    }
}
