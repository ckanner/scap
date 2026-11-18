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
mod instance;
pub mod intake;
pub mod output;
pub mod owner_wire;
pub mod restore;
pub mod restore_wire;
pub mod scheduler;
pub mod snapshot_wire;
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
        // Payload-bearing outcomes are handled before the scalar codebook so
        // an accepted receipt is never discarded or reconstructed from a code.
        if let Error::CommittedButUnavailable(receipt) = error {
            return Self {
                code: "COMMITTED_BUT_UNAVAILABLE",
                receipt: Some(receipt),
            };
        }
        if let Error::Store(error) = error {
            return Self::new(store_code(error));
        }
        if let Error::Gc(error) = error {
            return Self::new(gc_code(error));
        }
        if let Error::Engine(error) = error {
            return Self::new(engine_code(error));
        }
        if let Error::Sql(error) = error {
            let code = if error == scap_sql::SqlError::ResourceExhausted {
                "LIMIT"
            } else {
                "INVALID"
            };
            return Self::new(code);
        }
        if let Error::Format(_) = error {
            return Self::new("CORRUPT");
        }
        let code = if let Error::Denied = error {
            "DENIED"
        } else if let Error::Lifecycle = error {
            "LIFECYCLE"
        } else if let Error::Fenced = error {
            "FENCED"
        } else if let Error::Conflict = error {
            "CONFLICT"
        } else if let Error::RequestConflict = error {
            "REQUEST_CONFLICT"
        } else if let Error::WindowFull = error {
            "WINDOW_FULL"
        } else if let Error::Closed = error {
            "CLOSED"
        } else if let Error::Retired = error {
            "RETIRED"
        } else if let Error::Unknown = error {
            "UNKNOWN"
        } else if let Error::Limit = error {
            "LIMIT"
        } else if let Error::Corrupt = error {
            "CORRUPT"
        } else if let Error::StaleSnapshot = error {
            "STALE_SNAPSHOT"
        } else {
            "SNAPSHOT_EXPIRED"
        };
        Self::new(code)
    }
}

fn store_code(error: StoreError) -> &'static str {
    if error == StoreError::Conflict {
        "CONFLICT"
    } else if error == StoreError::Unknown {
        "UNKNOWN"
    } else if error == StoreError::Missing {
        "MISSING"
    } else if error == StoreError::Budget || error == StoreError::Limit {
        "LIMIT"
    } else if error == StoreError::Corrupt {
        "CORRUPT"
    } else {
        "INVALID"
    }
}

fn gc_code(error: scap_object_store::GcError) -> &'static str {
    use scap_object_store::GcError;
    if error == GcError::Invalid {
        "INVALID"
    } else if error == GcError::Limit {
        "LIMIT"
    } else if error == GcError::Denied {
        "DENIED"
    } else if error == GcError::Unsupported {
        "GC_UNSUPPORTED"
    } else if error == GcError::Corrupt {
        "CORRUPT"
    } else {
        "UNKNOWN"
    }
}

fn engine_code(error: scap_object_sqlite::Error) -> &'static str {
    use scap_object_sqlite::Error;
    if matches!(error, Error::ResultLimit) || matches!(error, Error::ResourceExhausted) {
        "LIMIT"
    } else if let Error::Interrupted = error {
        "DEADLINE"
    } else if let Error::OutcomeUnknown = error {
        "UNKNOWN"
    } else if let Error::CommittedButUnavailable = error {
        "COMMITTED_BUT_UNAVAILABLE"
    } else if let Error::InvalidImage = error {
        "CORRUPT"
    } else {
        "ENGINE"
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
