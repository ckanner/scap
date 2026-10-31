use std::cell::RefCell;
use std::ffi::c_int;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::rc::Rc;

use libsql_sys::ffi;
use libsql_sys::wal::wrapper::WrapWal;
use libsql_sys::wal::{self, PageHeaders, Wal};
use scap_core::{CommitReceipt, CommitTicket};
use scap_engine::{Image, PageBatch, PageChange, PAGE_SIZE};

use crate::{CommitGate, Error, GateDecision, LookupDecision, WriterLimits};

pub(crate) struct Attempt {
    pub base: Image,
    pub ticket: CommitTicket,
    pub fingerprint: [u8; 32],
    pub result: Vec<u8>,
}

pub(crate) enum Resolution {
    Accepted {
        receipt: CommitReceipt,
        image: Image,
    },
    Replay {
        receipt: CommitReceipt,
        result: Vec<u8>,
    },
    Failed(Error),
}

pub(crate) struct GateState<G> {
    gate: G,
    pub limits: WriterLimits,
    pub attempt: Option<Attempt>,
    pub resolution: Option<Resolution>,
}

impl<G: CommitGate> GateState<G> {
    pub fn new(gate: G, limits: WriterLimits) -> Self {
        Self {
            gate,
            limits,
            attempt: None,
            resolution: None,
        }
    }

    pub fn reset(&mut self) {
        self.attempt = None;
        self.resolution = None;
    }

    pub fn lookup_caught(&mut self, ticket: &CommitTicket, fingerprint: [u8; 32]) -> bool {
        self.resolution = Some(Resolution::Failed(Error::OutcomeUnknown));
        let decision = catch_unwind(AssertUnwindSafe(|| self.gate.lookup(ticket, fingerprint)));
        self.resolution = match decision {
            Ok(LookupDecision::NotFound) => None,
            Ok(LookupDecision::AlreadyCommitted { receipt, result }) => {
                Some(self.historical(ticket, receipt, result))
            }
            Ok(LookupDecision::Rejected(reason)) => {
                Some(Resolution::Failed(Error::Rejected(reason)))
            }
            Ok(LookupDecision::Unknown) | Err(_) => Some(Resolution::Failed(Error::OutcomeUnknown)),
        };
        self.resolution.is_none()
    }

    fn historical(
        &self,
        ticket: &CommitTicket,
        receipt: CommitReceipt,
        result: Vec<u8>,
    ) -> Resolution {
        if !valid_historical_receipt(ticket, &receipt) {
            return Resolution::Failed(Error::InvalidReceipt);
        }
        if result.len() > self.limits.sql.max_result_bytes as usize {
            return Resolution::Failed(Error::CommittedButUnavailable {
                receipt: Box::new(receipt),
            });
        }
        Resolution::Replay { receipt, result }
    }

    /// Catch every user adapter panic before it can unwind through SQLite's C
    /// callback. Unknown is installed before proposing, so a panic cannot turn
    /// an accepted-but-unreported transition into a definitive rollback.
    pub fn decide_caught(&mut self, batch: PageBatch) -> bool {
        if self.resolution.is_some() {
            return false;
        }
        self.resolution = Some(Resolution::Failed(Error::OutcomeUnknown));
        match catch_unwind(AssertUnwindSafe(|| self.decide(batch))) {
            Ok(resolution) => self.resolution = Some(resolution),
            Err(_) => return false,
        }
        matches!(self.resolution, Some(Resolution::Accepted { .. }))
    }

    fn decide(&mut self, batch: PageBatch) -> Resolution {
        let Some(attempt) = self.attempt.as_ref() else {
            return Resolution::Failed(Error::InvalidSql);
        };
        let prepared = match attempt.base.prepare(attempt.ticket.clone(), batch) {
            Ok(prepared) => prepared,
            Err(error) => return Resolution::Failed(Error::Image(error)),
        };
        match self
            .gate
            .propose(prepared.write(), attempt.fingerprint, &attempt.result)
        {
            GateDecision::Accepted(receipt) => match prepared.accepted(&receipt) {
                Ok(image) => Resolution::Accepted { receipt, image },
                Err(_) => Resolution::Failed(Error::InvalidReceipt),
            },
            GateDecision::AlreadyCommitted { receipt, result } => {
                self.historical(&attempt.ticket, receipt, result)
            }
            GateDecision::Rejected(reason) => Resolution::Failed(Error::Rejected(reason)),
            GateDecision::Unknown => Resolution::Failed(Error::OutcomeUnknown),
        }
    }

    pub fn take_error(&mut self, fallback: Error) -> Error {
        match self.resolution.take() {
            Some(Resolution::Accepted { receipt, .. }) => Error::CommittedButUnavailable {
                receipt: Box::new(receipt),
            },
            Some(Resolution::Failed(error)) => error,
            Some(Resolution::Replay { receipt, .. }) => Error::CommittedButUnavailable {
                receipt: Box::new(receipt),
            },
            None => fallback,
        }
    }
}

/// Volatile owner/auth epochs and physical digest may legitimately differ for
/// a business deduplication hit. Database generation and request identity may
/// never differ; the trusted gate additionally verifies current authorization,
/// original principal and semantic fingerprint in the replicated state machine.
pub(crate) fn valid_historical_receipt(ticket: &CommitTicket, receipt: &CommitReceipt) -> bool {
    let original = &receipt.ticket;
    original.cell_id == ticket.cell_id
        && original.cell_incarnation == ticket.cell_incarnation
        && original.database_id == ticket.database_id
        && original.incarnation == ticket.incarnation
        && original.placement_generation == ticket.placement_generation
        && original.request_id == ticket.request_id
        && original.owner_epoch != 0
        && original.worker_instance_id != 0
        && original.auth_epoch != 0
        && original.predecessor.checked_add(1) == Some(receipt.sequence)
}

pub(crate) struct GateWal<G> {
    state: Rc<RefCell<GateState<G>>>,
}

impl<G> Clone for GateWal<G> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
        }
    }
}

impl<G> GateWal<G> {
    pub fn new(state: Rc<RefCell<GateState<G>>>) -> Self {
        Self { state }
    }
}

pub(crate) fn validate_mode(page_size: c_int, is_commit: bool) -> wal::Result<()> {
    // PageHeaders::iter() is hard-coded to 4096 in the pinned upstream. No
    // traversal, including spill traversal, is safe before this exact check.
    if page_size != PAGE_SIZE as c_int {
        return Err(wal::Error::new(ffi::SQLITE_MISMATCH));
    }
    if !is_commit {
        return Err(wal::Error::new(ffi::SQLITE_TOOBIG));
    }
    Ok(())
}

pub(crate) fn collect(
    size_after: u32,
    pages: &mut dyn Iterator<Item = (u32, &[u8])>,
    max_pages: u32,
) -> wal::Result<PageBatch> {
    let mut copied = Vec::new();
    for (number, bytes) in pages {
        if copied.len() == max_pages as usize {
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
    Ok(PageBatch {
        size_after,
        pages: copied,
    })
}

pub(crate) fn ffi_guard(call: &mut dyn FnMut() -> wal::Result<usize>) -> wal::Result<usize> {
    match catch_unwind(AssertUnwindSafe(call)) {
        Ok(result) => result,
        Err(_) => Err(wal::Error::new(ffi::SQLITE_ABORT)),
    }
}

impl<W: Wal, G: CommitGate> WrapWal<W> for GateWal<G> {
    fn insert_frames(
        &mut self,
        wrapped: &mut W,
        page_size: c_int,
        page_headers: &mut PageHeaders,
        size_after: u32,
        is_commit: bool,
        sync_flags: c_int,
    ) -> wal::Result<usize> {
        // Neither allocation nor user callbacks may unwind through extern C.
        // The caller permanently stops the writer on every native failure.
        ffi_guard(&mut || {
            validate_mode(page_size, is_commit)?;
            let limit = self.state.borrow().limits.max_changed_pages;
            let batch = collect(size_after, &mut page_headers.iter(), limit)?;
            if !self.state.borrow_mut().decide_caught(batch) {
                return Err(wal::Error::new(ffi::SQLITE_ABORT));
            }
            wrapped.insert_frames(page_size, page_headers, size_after, is_commit, sync_flags)
        })
    }
}
