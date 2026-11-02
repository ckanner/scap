//! Bounded service admission and leader-owned SQL scheduling.
//!
//! The public HTTP endpoint never supplies a replicated Admission directly.
//! A configured credential maps to one immutable database identity and a
//! principal. Every actual operation is checked again by the cell state.

mod archive;
mod archive_jobs;
mod auth;
mod cache;
mod cli;
mod config;
mod listener;
mod local;
mod mailbox;
mod node;
mod worker;

pub use cli::command;
pub use config::{ArchiveConfig, Config, DatabaseConfig, PeerConfig, TokenConfig};
pub use node::{run, StartMode};

use scap_service::ServiceError;

fn failure(code: &str) -> ServiceError {
    ServiceError::new(code, code)
}

#[cfg(test)]
mod tests;
