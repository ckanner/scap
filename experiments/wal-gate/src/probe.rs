//! Test harness only. This package deliberately has no library target.
//!
//! The callback is a synchronous test decision, not a quorum or durable store.
//! Spills are rejected: collecting only the final xFrames call is not enough to
//! reconstruct a transaction that previously spilled pages.

use std::ffi::c_int;
use std::path::Path;
use std::sync::Arc;

use libsql_sys::ffi;
use libsql_sys::rusqlite::{self, OpenFlags};
use libsql_sys::wal::wrapper::{WrapWal, WrappedWal};
use libsql_sys::wal::{self, PageHeaders, Sqlite3Wal, Sqlite3WalManager, Wal, WalManager};

pub const PAGE_SIZE: usize = 4096;
pub const MAX_PAGES: usize = 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageChange {
    pub number: u32,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitBatch {
    pub size_after: u32,
    pub pages: Vec<PageChange>,
}

type Decision = dyn Fn(&CommitBatch) -> wal::Result<()> + Send + Sync;

#[derive(Clone)]
pub struct GateWal {
    decision: Arc<Decision>,
}

impl GateWal {
    pub fn new(decision: impl Fn(&CommitBatch) -> wal::Result<()> + Send + Sync + 'static) -> Self {
        Self {
            decision: Arc::new(decision),
        }
    }

    fn decide_then_publish<T>(
        &self,
        batch: &CommitBatch,
        publish: impl FnOnce() -> wal::Result<T>,
    ) -> wal::Result<T> {
        (self.decision)(batch)?;
        publish()
    }
}

fn validate_mode(page_size: c_int, is_commit: bool) -> wal::Result<()> {
    // Upstream PageHeaders::iter() is fixed to 4096 at this revision. Check
    // before traversing it, including when the callback is a non-commit spill.
    if page_size != PAGE_SIZE as c_int {
        return Err(wal::Error::new(ffi::SQLITE_MISMATCH));
    }
    if !is_commit {
        return Err(wal::Error::new(ffi::SQLITE_TOOBIG));
    }
    Ok(())
}

fn collect_batch<'a>(
    size_after: u32,
    pages: impl IntoIterator<Item = (u32, &'a [u8])>,
) -> wal::Result<CommitBatch> {
    if size_after == 0 {
        return Err(wal::Error::new(ffi::SQLITE_CORRUPT));
    }
    let mut copied = Vec::new();
    for (number, bytes) in pages {
        if copied.len() == MAX_PAGES {
            return Err(wal::Error::new(ffi::SQLITE_TOOBIG));
        }
        if number == 0 || number > size_after || bytes.len() != PAGE_SIZE {
            return Err(wal::Error::new(ffi::SQLITE_CORRUPT));
        }
        copied.push(PageChange {
            number,
            bytes: bytes.to_vec(),
        });
    }
    if copied.is_empty() {
        return Err(wal::Error::new(ffi::SQLITE_CORRUPT));
    }
    Ok(CommitBatch {
        size_after,
        pages: copied,
    })
}

impl<W: Wal> WrapWal<W> for GateWal {
    fn insert_frames(
        &mut self,
        wrapped: &mut W,
        page_size: c_int,
        page_headers: &mut PageHeaders,
        size_after: u32,
        is_commit: bool,
        sync_flags: c_int,
    ) -> wal::Result<usize> {
        validate_mode(page_size, is_commit)?;
        let batch = collect_batch(size_after, page_headers.iter())?;
        // This ordering is the subject of the engine probes. No ordinary
        // sqlite3_wal_hook is installed. A rejection never reaches native
        // xFrames for the commit and never publishes its shared WAL header.
        self.decide_then_publish(&batch, || {
            wrapped.insert_frames(page_size, page_headers, size_after, is_commit, sync_flags)
        })
    }
}

pub type ProbeConnection = libsql_sys::Connection<WrappedWal<GateWal, Sqlite3Wal>>;

pub fn open(path: &Path, gate: GateWal) -> rusqlite::Result<ProbeConnection> {
    let manager = Sqlite3WalManager::default().wrap(gate);
    let conn = libsql_sys::Connection::open(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_FULL_MUTEX,
        manager,
        libsql_sys::connection::NO_AUTOCHECKPOINT,
        None,
    )?;
    conn.execute_batch(
        "PRAGMA page_size=4096; PRAGMA synchronous=FULL; \
         PRAGMA cache_spill=OFF; PRAGMA wal_autocheckpoint=0;",
    )?;
    let actual: i64 = conn.query_row("PRAGMA page_size", [], |row| row.get(0))?;
    if actual != PAGE_SIZE as i64 {
        return Err(rusqlite::Error::SqliteFailure(
            wal::Error::new(ffi::SQLITE_MISMATCH),
            Some("the probe supports only 4096-byte pages".into()),
        ));
    }
    Ok(conn)
}

#[cfg(test)]
mod contract_tests {
    use super::*;
    use std::cell::Cell;

    fn small_batch() -> CommitBatch {
        collect_batch(1, [(1, &[0_u8; PAGE_SIZE][..])]).unwrap()
    }

    #[test]
    fn unsupported_page_size_and_spill_fail_closed() {
        assert_eq!(validate_mode(4096, true), Ok(()));
        assert_eq!(
            validate_mode(8192, true).unwrap_err().extended_code,
            ffi::SQLITE_MISMATCH
        );
        assert_eq!(
            validate_mode(4096, false).unwrap_err().extended_code,
            ffi::SQLITE_TOOBIG
        );
    }

    #[test]
    fn malformed_or_empty_page_batch_is_rejected() {
        let page = [0_u8; PAGE_SIZE];
        for (size, pages) in [
            (0, vec![(1, &page[..])]),
            (1, vec![(0, &page[..])]),
            (1, vec![(2, &page[..])]),
            (1, vec![(1, &page[..PAGE_SIZE - 1])]),
            (1, vec![]),
        ] {
            assert_eq!(
                collect_batch(size, pages).unwrap_err().extended_code,
                ffi::SQLITE_CORRUPT
            );
        }
    }

    #[test]
    fn page_capture_owns_the_bytes_and_enforces_its_limit() {
        let mut page = [3_u8; PAGE_SIZE];
        let copied = collect_batch(1, [(1, &page[..])]).unwrap();
        page[0] = 9;
        assert_eq!(copied.pages[0].bytes[0], 3);
        assert_eq!(copied.pages[0].number, 1);
        assert_eq!(copied.size_after, 1);
        let result = collect_batch(1, std::iter::repeat((1, &page[..])).take(MAX_PAGES + 1));
        assert_eq!(result.unwrap_err().extended_code, ffi::SQLITE_TOOBIG);
    }

    #[test]
    fn rejection_never_calls_the_publish_operation() {
        let published = Cell::new(false);
        let gate = GateWal::new(|_| Err(wal::Error::new(ffi::SQLITE_ABORT)));
        let result = gate.decide_then_publish(&small_batch(), || {
            published.set(true);
            Ok(1)
        });
        assert_eq!(result.unwrap_err().extended_code, ffi::SQLITE_ABORT);
        assert!(!published.get());
    }

    #[test]
    fn acceptance_does_not_hide_a_publish_error() {
        let gate = GateWal::new(|batch| {
            assert_eq!(batch.pages.len(), 1);
            Ok(())
        });
        assert_eq!(gate.decide_then_publish(&small_batch(), || Ok(3)), Ok(3));
        let result: wal::Result<()> = gate.decide_then_publish(&small_batch(), || {
            Err(wal::Error::new(ffi::SQLITE_IOERR_FSYNC))
        });
        assert_eq!(result.unwrap_err().extended_code, ffi::SQLITE_IOERR_FSYNC);
    }
}
