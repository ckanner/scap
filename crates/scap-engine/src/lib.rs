//! Authoritative cell binding for shared bounded physical SQLite recovery.
//!
//! Native execution caches are rebuilt from a quorum-bound baseline and tail.
//! Page encoding/replay is shared with cell compaction in scap_core::physical;
//! this adapter additionally requires fresh Safe ReadIndex, current admission,
//! exact applied position and the authoritative cell commit hash.

use scap_cell::{Admission, CellState, Position, Reject};
use scap_core::physical;
use scap_core::{CommitReceipt, CommitTicket, PreparedWrite};

pub use physical::{
    EngineIdentity, Head, Limits, PageBatch, PageChange, HEADER_SIZE, MAX_DATABASE_PAGES, PAGE_SIZE,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryTarget {
    pub position: Position,
    pub revision: u64,
    pub commit_hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Limits,
    Identity,
    Ticket,
    Receipt,
    Exhausted,
    TooLarge,
    Malformed,
    PageOrder,
    MissingPage,
    SqliteHeader,
    Head,
    Integrity,
    Authorization(Reject),
}

impl From<physical::Error> for Error {
    fn from(value: physical::Error) -> Self {
        match value {
            physical::Error::Limits => Self::Limits,
            physical::Error::Identity => Self::Identity,
            physical::Error::Ticket => Self::Ticket,
            physical::Error::Receipt => Self::Receipt,
            physical::Error::Exhausted => Self::Exhausted,
            physical::Error::TooLarge => Self::TooLarge,
            physical::Error::Malformed => Self::Malformed,
            physical::Error::PageOrder => Self::PageOrder,
            physical::Error::MissingPage => Self::MissingPage,
            physical::Error::SqliteHeader => Self::SqliteHeader,
            physical::Error::Head => Self::Head,
            physical::Error::Integrity => Self::Integrity,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Image {
    inner: physical::Image,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prepared {
    inner: physical::Prepared,
}

impl Image {
    pub fn empty(identity: EngineIdentity, limits: Limits) -> Result<Self, Error> {
        physical::Image::empty(identity, limits)
            .map(|inner| Self { inner })
            .map_err(Into::into)
    }

    pub fn head(&self) -> Head {
        self.inner.head()
    }

    pub fn bytes(&self) -> &[u8] {
        self.inner.bytes()
    }

    pub fn limits(&self) -> Limits {
        self.inner.limits()
    }

    pub fn prepare(&self, ticket: CommitTicket, batch: PageBatch) -> Result<Prepared, Error> {
        self.inner
            .prepare(ticket, batch)
            .map(|inner| Prepared { inner })
            .map_err(Into::into)
    }

    /// Requires a fresh Safe ReadIndex and decode_bound of the same durable
    /// view. The resulting image is for a NEW execution file, never permission
    /// to reopen an untrusted prior SQLite/WAL cache. Native fsync and
    /// integrity_check remain separate requirements before activation.
    pub fn recover(
        state: &CellState,
        identity: EngineIdentity,
        admission: Admission,
        expected: RecoveryTarget,
        limits: Limits,
    ) -> Result<Self, Error> {
        let mut image = physical::Image::empty(identity, limits)?;
        if state.identity() != identity.cell || state.position() != expected.position {
            return Err(Error::Head);
        }
        let recovery = state
            .recovery_source(identity.database, admission)
            .map_err(Error::Authorization)?;
        // Successful recovery_source proves the exact database exists, and
        // CellState validates its base anchor and contiguous physical tail
        // against the complete retained commit/result chain.
        let database = state.database(identity.database.database_id).unwrap();
        if database.revision != expected.revision || database.commit_hash != expected.commit_hash {
            return Err(Error::Head);
        }
        if let Some(base) = recovery.base {
            image = physical::Image::from_snapshot(
                physical::Snapshot {
                    head: Head {
                        identity,
                        revision: base.revision,
                        image_digest: base.image_digest,
                    },
                    bytes: base.bytes.clone(),
                },
                limits,
            )?;
        }
        for transaction in recovery.tail {
            image = image.replay(&transaction.commit.receipt, &transaction.physical_changes)?;
        }
        Ok(Self { inner: image })
    }
}

impl Prepared {
    pub fn write(&self) -> &PreparedWrite {
        self.inner.write()
    }

    /// Only a new, exact durable acceptance may publish these staged pages.
    /// Historical deduplication must discard this Prepared and recover authority.
    pub fn accepted(self, receipt: &CommitReceipt) -> Result<Image, Error> {
        self.inner
            .accepted(receipt)
            .map(|inner| Image { inner })
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests;
