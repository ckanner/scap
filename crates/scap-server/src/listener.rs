//! Reserve a finite connection slot before accepting a socket. A finite absolute
//! connection lifetime also bounds idle/partial HTTP requests independently of
//! the application's request deadline and body-size limits.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::serve::Listener;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};
use tokio::time::Sleep;

pub(crate) struct Bounded<L> {
    inner: L,
    slots: Arc<Semaphore>,
    lifetime: Duration,
    stop: Option<watch::Receiver<bool>>,
}

impl<L> Bounded<L> {
    pub(crate) fn new(inner: L) -> Self {
        Self {
            inner,
            slots: Arc::new(Semaphore::new(64)),
            lifetime: Duration::from_secs(30),
            stop: None,
        }
    }

    pub(crate) fn with_stop(inner: L, stop: watch::Receiver<bool>) -> Self {
        let mut listener = Self::new(inner);
        listener.stop = Some(stop);
        listener
    }
}

impl<L: Listener> Listener for Bounded<L> {
    type Io = Connection<L::Io>;
    type Addr = L::Addr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        // This private semaphore is never closed and always has nonzero capacity.
        let permit = self.slots.clone().acquire_owned().await.unwrap();
        let (io, address) = self.inner.accept().await;
        (
            Connection {
                io,
                timeout: Box::pin(tokio::time::sleep(self.lifetime)),
                stop: Box::pin(stopped(self.stop.clone())),
                closed: false,
                _permit: permit,
            },
            address,
        )
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

pub(crate) struct Connection<I> {
    io: I,
    timeout: Pin<Box<Sleep>>,
    stop: Pin<Box<dyn Future<Output = ()> + Send>>,
    closed: bool,
    _permit: OwnedSemaphorePermit,
}

impl<I> Connection<I> {
    fn alive(&mut self, context: &mut Context<'_>) -> io::Result<()> {
        if self.closed || self.stop.as_mut().poll(context).is_ready() {
            self.closed = true;
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "node stopping",
            ));
        }
        if self.timeout.as_mut().poll(context).is_ready() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "HTTP connection lifetime",
            ));
        }
        Ok(())
    }
}

async fn stopped(signal: Option<watch::Receiver<bool>>) {
    match signal {
        Some(mut signal) => {
            while !*signal.borrow_and_update() {
                if signal.changed().await.is_err() {
                    break;
                }
            }
        }
        None => std::future::pending::<()>().await,
    }
}

impl<I: AsyncRead + Unpin> AsyncRead for Connection<I> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.alive(context)?;
        Pin::new(&mut self.io).poll_read(context, buffer)
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for Connection<I> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.alive(context)?;
        Pin::new(&mut self.io).poll_write(context, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.alive(context)?;
        Pin::new(&mut self.io).poll_flush(context)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.alive(context)?;
        Pin::new(&mut self.io).poll_shutdown(context)
    }
}

#[cfg(test)]
mod tests;
