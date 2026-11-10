//! Authenticated, bounded HTTP admission for the S3-authoritative runtime.
//! All SQL, recovery, authorization and publication run on confined workers.

pub mod auth;
pub mod catalogue;
pub mod catalogue_scheduler;
pub mod catalogue_wire;
pub mod config;
pub mod daemon;
pub mod discovery;
pub mod discovery_cursor;
pub mod discovery_wire;
pub mod engine;
pub mod http;
pub mod intake;
pub mod output;
pub mod scheduler;
pub mod transport;
pub mod wire;

use scap_object::{Error, Receipt};
use scap_object_store::StoreError;

#[derive(Debug)]
pub struct Failure {
    pub code: &'static str,
    pub receipt: Option<Box<Receipt>>,
}

impl Failure {
    pub fn new(code: &'static str) -> Self {
        Self {
            code,
            receipt: None,
        }
    }
}

impl From<Error> for Failure {
    fn from(error: Error) -> Self {
        let code = match error {
            Error::Denied => "DENIED",
            Error::Lifecycle => "LIFECYCLE",
            Error::Fenced => "FENCED",
            Error::Conflict | Error::Store(StoreError::Conflict) => "CONFLICT",
            Error::RequestConflict => "REQUEST_CONFLICT",
            Error::WindowFull => "WINDOW_FULL",
            Error::Closed => "CLOSED",
            Error::Retired => "RETIRED",
            Error::Unknown | Error::Store(StoreError::Unknown) => "UNKNOWN",
            Error::Store(StoreError::Missing) => "MISSING",
            Error::Limit
            | Error::Store(StoreError::Budget)
            | Error::Store(StoreError::Limit)
            | Error::Sql(scap_sql::SqlError::ResourceExhausted) => "LIMIT",
            Error::Corrupt | Error::Format(_) | Error::Store(StoreError::Corrupt) => "CORRUPT",
            Error::StaleSnapshot => "STALE_SNAPSHOT",
            Error::SnapshotExpired => "SNAPSHOT_EXPIRED",
            Error::Gc(error) => match error {
                scap_object_store::GcError::Invalid => "INVALID",
                scap_object_store::GcError::Limit => "LIMIT",
                scap_object_store::GcError::Denied => "DENIED",
                scap_object_store::GcError::Unsupported => "GC_UNSUPPORTED",
                scap_object_store::GcError::Corrupt => "CORRUPT",
                scap_object_store::GcError::Unknown => "UNKNOWN",
            },
            Error::CommittedButUnavailable(receipt) => {
                return Self {
                    code: "COMMITTED_BUT_UNAVAILABLE",
                    receipt: Some(receipt),
                };
            }
            Error::Sql(_) | Error::Store(StoreError::Invalid) => "INVALID",
            Error::Engine(error) => match error {
                scap_object_sqlite::Error::ResultLimit
                | scap_object_sqlite::Error::ResourceExhausted => "LIMIT",
                scap_object_sqlite::Error::Interrupted => "DEADLINE",
                scap_object_sqlite::Error::OutcomeUnknown => "UNKNOWN",
                scap_object_sqlite::Error::CommittedButUnavailable => "COMMITTED_BUT_UNAVAILABLE",
                scap_object_sqlite::Error::InvalidImage => "CORRUPT",
                _ => "ENGINE",
            },
        };
        Self::new(code)
    }
}

#[cfg(test)]
mod tests;

// Unit-test the actual binary wrapper under the same source coverage map.
#[cfg(test)]
extern crate self as scap_service;

#[cfg(test)]
#[path = "main.rs"]
mod entrypoint;
