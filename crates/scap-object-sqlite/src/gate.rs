use std::cell::RefCell;
use std::ffi::c_int;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::rc::Rc;

use libsql_sys::ffi;
use libsql_sys::wal::wrapper::WrapWal;
use libsql_sys::wal::{self, PageHeaders, Wal};

use crate::{
    image, CommitGate, Error, GateDecision, PageBatch, PageChange, WriterLimits, PAGE_SIZE,
};

pub(crate) struct Attempt {
    pub base_pages: u32,
    pub result: Vec<u8>,
}

pub(crate) enum Resolution {
    Accepted(u32),
    Failed(Error),
}

pub(crate) struct GateState<G> {
    gate: G,
    pub limits: WriterLimits,
    pub attempt: Option<Attempt>,
    pub resolution: Option<Resolution>,
    staging: Option<StageCapture>,
}

pub(crate) struct StageCapture {
    pub base_pages: u32,
    max_changed_pages: u32,
    pub pending: Option<PageBatch>,
    pub error: Option<Error>,
}

impl<G: CommitGate> GateState<G> {
    pub fn new(gate: G, limits: WriterLimits) -> Self {
        Self {
            gate,
            limits,
            attempt: None,
            resolution: None,
            staging: None,
        }
    }

    pub fn reset(&mut self) {
        self.attempt = None;
        self.resolution = None;
        self.staging = None;
    }

    pub fn begin_staging(&mut self, base_pages: u32, max_changed_pages: u32) {
        self.reset();
        self.staging = Some(StageCapture {
            base_pages,
            max_changed_pages,
            pending: None,
            error: None,
        });
    }

    pub fn take_staging(&mut self) -> StageCapture {
        self.staging.take().expect("one capture per group member")
    }

    fn capture_limit(&self) -> u32 {
        self.staging
            .as_ref()
            .map_or(self.limits.max_changed_pages, |stage| {
                stage.max_changed_pages
            })
    }

    pub(crate) fn capture_or_publish(&mut self, mut batch: PageBatch) -> bool {
        let Some(stage) = self.staging.as_mut() else {
            return self.decide_caught(batch);
        };
        // Native COMMIT may only contribute one final capture. This never
        // calls the authority gate and never manufactures Accepted.
        if stage.pending.is_some() || stage.error.is_some() {
            stage.error = Some(Error::InvalidSql);
            return false;
        }
        let mut limits = self.limits;
        limits.max_changed_pages = stage.max_changed_pages;
        if let Err(error) = image::normalize_growth(stage.base_pages, &mut batch, limits) {
            stage.error = Some(error);
            return false;
        }
        stage.pending = Some(batch);
        true
    }

    /// Install UNKNOWN before calling the adapter. Panics may occur after an
    /// accepted remote operation, so they cannot be interpreted as rollback.
    pub fn decide_caught(&mut self, batch: PageBatch) -> bool {
        if self.resolution.is_some() {
            return false;
        }
        self.resolution = Some(Resolution::Failed(Error::OutcomeUnknown));
        match catch_unwind(AssertUnwindSafe(|| self.decide(batch))) {
            Ok(resolution) => self.resolution = Some(resolution),
            Err(_) => return false,
        }
        matches!(self.resolution, Some(Resolution::Accepted(_)))
    }

    fn decide(&mut self, mut batch: PageBatch) -> Resolution {
        let Some(attempt) = self.attempt.as_ref() else {
            return Resolution::Failed(Error::InvalidSql);
        };
        if let Err(error) = image::normalize_growth(attempt.base_pages, &mut batch, self.limits) {
            return Resolution::Failed(error);
        }
        match self.gate.publish(&batch, &attempt.result) {
            GateDecision::Accepted => Resolution::Accepted(batch.size_after),
            GateDecision::Rejected => Resolution::Failed(Error::Rejected),
            GateDecision::Unknown => Resolution::Failed(Error::OutcomeUnknown),
        }
    }

    pub fn take_error(&mut self, fallback: Error) -> Error {
        match self.resolution.take() {
            Some(Resolution::Accepted(_)) => Error::CommittedButUnavailable,
            Some(Resolution::Failed(error)) => error,
            None => fallback,
        }
    }
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
    // Pinned upstream PageHeaders::iter() is hard-coded to 4096. Check first,
    // including rejected spills, before traversing any native page pointers.
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
        ffi_guard(&mut || {
            validate_mode(page_size, is_commit)?;
            let limit = self.state.borrow().capture_limit();
            let batch = collect(size_after, &mut page_headers.iter(), limit)?;
            if !self.state.borrow_mut().capture_or_publish(batch) {
                return Err(wal::Error::new(ffi::SQLITE_ABORT));
            }
            wrapped.insert_frames(page_size, page_headers, size_after, is_commit, sync_flags)
        })
    }
}
