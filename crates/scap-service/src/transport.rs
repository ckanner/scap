//! Bounded HTTP/1 connections before authentication or body admission.
//!
//! A connection slot owns a complete Tokio task until it is joined. Header
//! limits do not account for application bodies, allocator overhead or sockets
//! in the kernel backlog, and are not a process RSS limit.

use std::convert::Infallible;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::{Body, Bytes, HttpBody};
use axum::serve::Listener;
use axum::Router;
use hyper::server::conn::http1;
use hyper::service::{service_fn, Service};
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::Instant;

use crate::{daemon::Shutdown, Failure};

/// The versioned connection policy. Missing deployment configuration uses v1.
/// Every field is required when an explicit profile is supplied.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub version: u8,
    pub max_connections: usize,
    pub max_headers: usize,
    pub max_header_bytes: usize,
    pub max_buffer_bytes: usize,
    pub header_timeout_ms: u64,
    pub response_timeout_ms: u64,
    pub shutdown_timeout_ms: u64,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            version: 1,
            max_connections: 128,
            max_headers: 64,
            max_header_bytes: 16 * 1024,
            max_buffer_bytes: 32 * 1024,
            header_timeout_ms: 5000,
            response_timeout_ms: 30000,
            shutdown_timeout_ms: 30000,
        }
    }
}

/// Only checked policies can reach the builder, whose buffer setter may panic.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits(Profile);

impl Profile {
    pub(crate) fn checked(self) -> Result<Limits, Failure> {
        if self.version != 1
            || !(1..=4096).contains(&self.max_connections)
            || !(1..=256).contains(&self.max_headers)
            || !(1..=65536).contains(&self.max_header_bytes)
            || !(8192..=1048576).contains(&self.max_buffer_bytes)
            || self.max_header_bytes > self.max_buffer_bytes
            || !(1..=60000).contains(&self.header_timeout_ms)
            || !(1..=86400000).contains(&self.response_timeout_ms)
            || !(1..=86400000).contains(&self.shutdown_timeout_ms)
        {
            return Err(Failure::new("CONFIG"));
        }
        Ok(Limits(self))
    }
}

/// Stop accepting at capacity; never spawn tasks that wait for a connection
/// permit. Completed but unjoined tasks count too, so handles cannot accumulate.
/// The Listener keeps Axum's existing accept-error retry policy.
pub(crate) async fn serve<L: Listener>(
    mut listener: L,
    router: Router,
    limits: Limits,
    mut shutdown: Shutdown,
) {
    let mut connections = JoinSet::new();
    let (stop, stopped) = watch::channel(());
    loop {
        let accepting = connections.len() < limits.0.max_connections;
        let joining = !connections.is_empty();
        tokio::select! {
            biased;
            _ = &mut shutdown => break,
            _ = connections.join_next(), if joining => {},
            (io, _) = listener.accept(), if accepting => {
                connections.spawn(connection(io, router.clone(), limits, stopped.clone()));
            }
        }
    }
    drop(listener);
    drop(stop);
    // Give admitted connections a fixed drain window, then drop their real
    // futures and join them. Database jobs retain their own reservations and
    // are still joined by the daemon after its request runtime is dropped.
    let deadline = Instant::now() + Duration::from_millis(limits.0.shutdown_timeout_ms);
    if tokio::time::timeout_at(deadline, async {
        while connections.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        connections.abort_all();
    }
    while connections.join_next().await.is_some() {}
}

#[derive(Default)]
struct DrainState {
    bodies: usize,
    deadline: Option<Instant>,
}

/// A response deadline remains armed while either a body or its last queued
/// frame is alive. A flush only clears it after Hyper has dropped all bodies.
/// Pipelined responses that share an unflushed batch keep its earliest deadline.
struct Drain {
    state: Mutex<DrainState>,
    deadlines: watch::Sender<Option<Instant>>,
}

impl Drain {
    fn new() -> (Arc<Self>, watch::Receiver<Option<Instant>>) {
        let (deadlines, receiver) = watch::channel(None);
        (
            Arc::new(Self {
                state: Mutex::new(DrainState::default()),
                deadlines,
            }),
            receiver,
        )
    }

    fn begin(self: &Arc<Self>, timeout: Duration) -> PendingBody {
        let mut state = self.state.lock().expect("response drain state");
        state.bodies += 1;
        if state.deadline.is_none() {
            state.deadline = Some(Instant::now() + timeout);
            self.deadlines.send_replace(state.deadline);
        }
        PendingBody(self.clone())
    }

    fn flushed(&self) {
        let mut state = self.state.lock().expect("response drain state");
        if state.bodies == 0 && state.deadline.take().is_some() {
            self.deadlines.send_replace(None);
        }
    }
}

struct PendingBody(Arc<Drain>);

impl Drop for PendingBody {
    fn drop(&mut self) {
        self.0.state.lock().expect("response drain state").bodies -= 1;
    }
}

/// Field order destroys the actual body before its transport observation. This
/// observation does not own or refund the application's Bytes/intake credits.
struct DrainBody {
    inner: Body,
    _pending: PendingBody,
}

impl HttpBody for DrainBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, axum::Error>>> {
        Pin::new(&mut self.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

/// Hyper 1.12 calls the underlying flush only after draining its write queue.
/// Keeping writev support preserves the original Bytes owners until then.
struct DrainIo<I> {
    inner: I,
    drain: Arc<Drain>,
}

impl<I: AsyncRead + Unpin> AsyncRead for DrainIo<I> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, bytes)
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for DrainIo<I> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, bytes)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bytes)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let outcome = Pin::new(&mut self.inner).poll_flush(cx);
        if let Poll::Ready(Ok(())) = &outcome {
            self.drain.flushed();
        }
        outcome
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

async fn response_expired(mut deadlines: watch::Receiver<Option<Instant>>) {
    loop {
        let deadline = *deadlines.borrow_and_update();
        let changed = if let Some(deadline) = deadline {
            tokio::select! {
                biased;
                _ = tokio::time::sleep_until(deadline) => return,
                changed = deadlines.changed() => changed,
            }
        } else {
            deadlines.changed().await
        };
        if changed.is_err() {
            return;
        }
    }
}

async fn connection<I: AsyncRead + AsyncWrite + Unpin>(
    io: I,
    router: Router,
    limits: Limits,
    mut stopped: watch::Receiver<()>,
) {
    let profile = limits.0;
    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_millis(profile.header_timeout_ms))
        .max_headers(profile.max_headers)
        .max_header_size(profile.max_header_bytes)
        .max_buf_size(profile.max_buffer_bytes)
        // Queue owned Bytes instead of copying response frames into a flat
        // transport buffer. A large frame still needs its application budget.
        .writev(true)
        .keep_alive(true);
    // Do not use the auto builder: unrelated S3 client dependencies can enable
    // HTTP/2 through Cargo feature unification. Upgrades are not part of v1.
    let (drain, deadlines) = Drain::new();
    let io = DrainIo {
        inner: io,
        drain: drain.clone(),
    };
    let router = TowerToHyperService::new(router);
    let service = service_fn(move |request| {
        let response = router.call(request);
        let drain = drain.clone();
        async move {
            // Router's error is uninhabited; express that without a dead error path.
            let Ok(response) = response.await;
            let pending = drain.begin(Duration::from_millis(profile.response_timeout_ms));
            Ok::<_, Infallible>(response.map(|inner| DrainBody {
                inner,
                _pending: pending,
            }))
        }
    });
    let connection = builder.serve_connection(TokioIo::new(io), service);
    let mut connection = std::pin::pin!(connection);
    let mut expired = std::pin::pin!(response_expired(deadlines));
    tokio::select! {
        _ = &mut expired => {},
        _ = &mut connection => {},
        _ = stopped.changed() => {
            connection.as_mut().graceful_shutdown();
            tokio::select! {
                _ = &mut expired => {},
                _ = &mut connection => {},
            }
        }
    }
}

#[cfg(test)]
mod tests;
