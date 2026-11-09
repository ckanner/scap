//! Bounded HTTP/1 connections before authentication or body admission.
//!
//! A connection slot owns a complete Tokio task until it is joined. Header
//! limits do not account for application bodies, allocator overhead or sockets
//! in the kernel backlog, and are not a process RSS limit.

use std::time::Duration;

use axum::serve::Listener;
use axum::Router;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::watch;
use tokio::task::JoinSet;

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
    // Preserve graceful shutdown: active responses may finish, and no task is
    // detached or aborted. The daemon drops its runtime before joining workers.
    while connections.join_next().await.is_some() {}
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
    let connection = builder.serve_connection(TokioIo::new(io), TowerToHyperService::new(router));
    let mut connection = std::pin::pin!(connection);
    tokio::select! {
        _ = &mut connection => {},
        _ = stopped.changed() => {
            connection.as_mut().graceful_shutdown();
            let _ = connection.await;
        }
    }
}

#[cfg(test)]
mod tests;
