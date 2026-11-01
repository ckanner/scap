use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_stream::Stream;
use tokio_util::sync::PollSemaphore;
use tonic::transport::server::Connected;

/// Reserve before accepting: the semaphore bounds both TLS handshakes and live
/// sockets. An exhausted budget backpressures the OS listener instead of adding
/// an unbounded userspace accept queue.
pub(crate) struct BoundedIncoming<S> {
    stream: S,
    semaphore: PollSemaphore,
    reserved: Option<OwnedSemaphorePermit>,
}

impl<S> BoundedIncoming<S> {
    pub(crate) fn new(stream: S, semaphore: Arc<Semaphore>) -> Self {
        Self {
            stream,
            semaphore: PollSemaphore::new(semaphore),
            reserved: None,
        }
    }
}

impl<S, T> Stream for BoundedIncoming<S>
where
    S: Stream<Item = io::Result<T>> + Unpin,
{
    type Item = io::Result<BoundedIo<T>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.reserved.is_none() {
            self.reserved = ready!(self.semaphore.poll_acquire(cx));
            if self.reserved.is_none() {
                return Poll::Ready(None);
            }
        }
        let next = ready!(Pin::new(&mut self.stream).poll_next(cx));
        let permit = self
            .reserved
            .take()
            .expect("a connection slot was reserved");
        Poll::Ready(next.map(|result| {
            result.map(|io| BoundedIo {
                io,
                _permit: permit,
            })
        }))
    }
}

pub(crate) struct BoundedIo<T> {
    io: T,
    _permit: OwnedSemaphorePermit,
}

impl<T: Connected> Connected for BoundedIo<T> {
    type ConnectInfo = T::ConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.io.connect_info()
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for BoundedIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for BoundedIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

#[cfg(test)]
#[path = "incoming_tests.rs"]
mod tests;
