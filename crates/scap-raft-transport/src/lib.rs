//! Bounded, mutually authenticated Raft peer transport.
//!
//! The receiver only acknowledges admission to the caller's bounded inbox.
//! Authentication/authorization is rechecked by that inbox before execution.
//! This crate does not send append acknowledgements, apply entries or retry SQL.

mod client;
mod incoming;
mod server;

use std::fmt::{self, Display};
use std::time::Duration;

use scap_raft_wire::Envelope;
use tonic::Status;

pub use client::{ClientSecurity, PeerAuthorizer, PeerClient, PeerEndpoint};
pub use server::{PeerServer, ServerSecurity};

pub const RPC_PATH: &str = "/scap.raft.peer.v1.Peer/Deliver";
const SERVICE_NAME: &str = "scap.raft.peer.v1.Peer";
const RECEIVED_VERSION: u32 = 1;
const MAX_PEM_BYTES: usize = 1024 * 1024;

/// Called synchronously after TLS and bounded protobuf decoding. Implementations
/// must do bounded work: authenticate the actual DER, authorize the complete
/// envelope and atomically reserve inbox count/bytes. Retain authentication
/// evidence and recheck current authority and certificate validity at dequeue.
pub trait Ingress: Send + Sync + 'static {
    fn admit(&self, peer_leaf_der: &[u8], envelope: Envelope) -> Result<(), AdmissionError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionError {
    Unauthenticated,
    PermissionDenied,
    Invalid,
    Limit,
    Unavailable,
}

#[derive(Debug)]
pub enum Error {
    Invalid(&'static str),
    Wire(String),
    Transport(String),
    Rpc(Status),
    Deadline,
    UnexpectedReceipt,
}

impl Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for Error {}

/// There are no unlimited defaults. Global request admission happens before
/// protobuf decoding; total decoded bytes are bounded by this count times the
/// per-message cap. Inbox storage has a separate count/byte budget.
#[derive(Clone, Debug)]
pub struct TransportLimits {
    pub max_wire_bytes: u32,
    pub max_connections: u32,
    pub max_inflight_requests: u32,
    pub max_streams_per_connection: u32,
    pub max_header_bytes: u32,
    pub handshake_timeout: Duration,
    pub request_timeout: Duration,
    pub connect_timeout: Duration,
    pub max_connection_age: Duration,
    pub connection_grace: Duration,
}

impl TransportLimits {
    pub fn validate(&self) -> Result<(), Error> {
        if !(128..=64 * 1024 * 1024).contains(&self.max_wire_bytes) {
            return Err(Error::Invalid("wire bytes outside supported range"));
        }
        for value in [
            self.max_connections,
            self.max_inflight_requests,
            self.max_streams_per_connection,
        ] {
            if !(1..=65_536).contains(&value) {
                return Err(Error::Invalid("invalid connection or concurrency limit"));
            }
        }
        if !(1024..=64 * 1024).contains(&self.max_header_bytes) {
            return Err(Error::Invalid("invalid HTTP header limit"));
        }
        for duration in [
            self.handshake_timeout,
            self.request_timeout,
            self.connect_timeout,
            self.max_connection_age,
            self.connection_grace,
        ] {
            if duration.is_zero() || duration > Duration::from_secs(3600) {
                return Err(Error::Invalid("invalid bounded transport duration"));
            }
        }
        Ok(())
    }

    fn grpc_bytes(&self) -> usize {
        // One protobuf tag and at most five length-varint bytes. Compression is
        // disabled, and wire decoding independently enforces max_wire_bytes.
        self.max_wire_bytes as usize + 6
    }
}

fn check_pem(parts: &[&[u8]]) -> Result<(), Error> {
    for part in parts {
        if part.is_empty() || part.len() > MAX_PEM_BYTES {
            return Err(Error::Invalid("missing or oversized TLS material"));
        }
    }
    Ok(())
}

fn transport_error(error: impl Display) -> Error {
    Error::Transport(error.to_string())
}

fn admission_status(error: AdmissionError) -> Status {
    match error {
        AdmissionError::Unauthenticated => Status::unauthenticated("peer certificate rejected"),
        AdmissionError::PermissionDenied => Status::permission_denied("peer route rejected"),
        AdmissionError::Invalid => Status::invalid_argument("invalid Raft envelope"),
        AdmissionError::Limit => Status::resource_exhausted("peer inbox capacity exceeded"),
        AdmissionError::Unavailable => Status::unavailable("peer inbox unavailable"),
    }
}

#[derive(Clone, PartialEq, prost::Message)]
struct Packet {
    #[prost(bytes = "vec", tag = "1")]
    data: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct Received {
    #[prost(uint32, tag = "1")]
    version: u32,
}

#[cfg(test)]
mod tests;
