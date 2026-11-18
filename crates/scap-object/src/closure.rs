//! Complete raw-byte closure verification for one original Snapshot.
//!
//! The cursor is owned, in-memory only and non-cloneable. Pending retains the
//! same authority/context/deadline; an error consumes its verified prefix.
//! No cursor, frame visit or completion grants publication or reclamation.

use std::time::Instant;

use crate::data_tree;
use crate::format::{
    object_key, Entry, IndexChild, OutcomeRef, Payload, Request, RequestIndex, Scope, Transition,
    CHUNK_PAGES, MAX_OBJECT_BYTES, PAGE_SIZE,
};
use crate::object_context::ObjectContext;
use crate::{check_cancelled, check_retained_result, request_index, Error, Snapshot};

const MAX_PATH: usize = 6;

pub(super) struct StepBudget {
    pub max_frames: u32,
    pub max_read_bytes: u64,
}

impl Default for StepBudget {
    fn default() -> Self {
        Self {
            max_frames: 64,
            max_read_bytes: 2 * MAX_OBJECT_BYTES as u64,
        }
    }
}

#[derive(Default, Debug, PartialEq, Eq)]
struct StepUsage {
    frames: u32,
    read_bytes: u64,
}

#[derive(Default, Debug, PartialEq, Eq)]
struct WindowTotal {
    entries: u64,
    bytes: u64,
    last_id: u64,
    committed: u64,
    cancelled: u64,
}

#[derive(Default, Debug, PartialEq, Eq)]
pub(super) struct ClosureTotals {
    frames: u64,
    frame_bytes: u64,
    pages: u64,
    chunks: u64,
    windows: [WindowTotal; 3],
}

struct Basis<'a> {
    snapshot: &'a Snapshot,
    objects: &'a ObjectContext,
    deadline: Instant,
    stop: &'a dyn Fn() -> bool,
    retained_revision: u64,
}

impl Basis<'_> {
    fn check(&self) -> Result<(), Error> {
        if (self.stop)() || Instant::now() >= self.deadline {
            Err(Error::Unknown)
        } else {
            Ok(())
        }
    }
}

pub(super) enum Role {
    Manifest,
    Node {
        level: u8,
        first: u32,
        pages: u32,
    },
    Chunk {
        first: u32,
        pages: u32,
    },
    Window {
        window: usize,
    },
    Child {
        window: usize,
        level: u8,
        reference: IndexChild,
    },
    Result {
        window: usize,
        request: Request,
        bytes: u64,
    },
}

struct Edge {
    hash: String,
    role: Role,
}

/// Only this frame and its incoming typed edge have been checked when a visitor
/// runs. Descendants and the remainder of the closure may still fail.
pub(super) struct FrameVisit<'a> {
    pub scope: &'a Scope,
    pub storage_generation: u64,
    pub hash: &'a str,
    pub key: &'a str,
    pub role: &'a Role,
    pub bytes: &'a [u8],
}

enum PathFrame {
    Data {
        level: u8,
        first: u32,
        pages: u32,
        position: usize,
        children: std::vec::IntoIter<String>,
    },
    Index {
        window: usize,
        level: u8,
        children: std::vec::IntoIter<IndexChild>,
    },
    Entries {
        window: usize,
        entries: std::vec::IntoIter<Entry>,
    },
}

enum Work {
    Edge(Edge),
    Cancelled {
        window: usize,
        id: u64,
        transition: Transition,
    },
}

impl PathFrame {
    fn next(&mut self) -> Option<Work> {
        match self {
            Self::Data {
                level,
                first,
                pages,
                position,
                children,
            } => {
                let hash = children.next()?;
                let first = data_tree::child_first(*level, *first, *position);
                *position += 1;
                let role = if *level == 0 {
                    Role::Chunk {
                        first,
                        pages: *pages,
                    }
                } else {
                    Role::Node {
                        level: *level - 1,
                        first,
                        pages: *pages,
                    }
                };
                Some(Work::Edge(Edge { hash, role }))
            }
            Self::Index {
                window,
                level,
                children,
            } => {
                let reference = children.next()?;
                Some(Work::Edge(Edge {
                    hash: reference.hash.clone(),
                    role: Role::Child {
                        window: *window,
                        level: *level - 1,
                        reference,
                    },
                }))
            }
            Self::Entries { window, entries } => {
                let entry = entries.next()?;
                Some(match entry.outcome {
                    OutcomeRef::Committed { result } => Work::Edge(Edge {
                        hash: result,
                        role: Role::Result {
                            window: *window,
                            request: entry.request,
                            bytes: entry.result_bytes,
                        },
                    }),
                    OutcomeRef::Cancelled { transition } => Work::Cancelled {
                        window: *window,
                        id: entry.request.id,
                        transition,
                    },
                })
            }
        }
    }
}

enum Action {
    Manifest(crate::format::Manifest),
    Node {
        level: u8,
        first: u32,
        pages: u32,
        children: Vec<String>,
    },
    Chunk {
        pages: u64,
    },
    Index {
        window: usize,
        index: RequestIndex,
    },
    Result {
        window: usize,
        id: u64,
        bytes: u64,
    },
}

pub(super) struct Cursor<'a> {
    basis: Basis<'a>,
    next: Option<Edge>,
    next_window: usize,
    path: [Option<PathFrame>; MAX_PATH],
    depth: usize,
    manifest_pages: u32,
    expected_pages: Option<u32>,
    next_retained: usize,
    root_start_pages: u64,
    root_start_chunks: u64,
    data_complete: bool,
    totals: ClosureTotals,
}

pub(super) enum Step<'a> {
    Pending(Box<Cursor<'a>>),
    Complete(VerifiedClosure<'a>),
}

pub(super) struct VerifiedClosure<'a> {
    basis: Basis<'a>,
    totals: ClosureTotals,
}

impl VerifiedClosure<'_> {
    pub(super) fn finish(self, original: &Snapshot) -> Result<ClosureTotals, Error> {
        self.basis.check()?;
        if self.basis.snapshot.head != original.head || self.basis.snapshot.etag != original.etag {
            return Err(Error::StaleSnapshot);
        }
        Ok(self.totals)
    }
}

fn add(value: &mut u64, amount: u64) -> Result<(), Error> {
    *value = value.checked_add(amount).ok_or(Error::Limit)?;
    Ok(())
}

impl<'a> Cursor<'a> {
    pub(super) fn new(
        objects: &'a ObjectContext,
        snapshot: &'a Snapshot,
        deadline: Instant,
        stop: &'a dyn Fn() -> bool,
    ) -> Result<Box<Self>, Error> {
        if !objects.matches(&snapshot.head) {
            return Err(Error::StaleSnapshot);
        }
        snapshot.head.validate().map_err(Error::Format)?;
        let basis = Basis {
            snapshot,
            objects,
            deadline,
            stop,
            retained_revision: snapshot.head.revision,
        };
        basis.check()?;
        Ok(Box::new(Self {
            basis,
            next: Some(Edge {
                hash: snapshot.head.data_root.clone(),
                role: Role::Manifest,
            }),
            next_window: 0,
            path: std::array::from_fn(|_| None),
            depth: 0,
            manifest_pages: 0,
            expected_pages: None,
            next_retained: 0,
            root_start_pages: 0,
            root_start_chunks: 0,
            data_complete: false,
            totals: ClosureTotals::default(),
        }))
    }

    pub(super) fn for_copy(
        objects: &'a ObjectContext,
        snapshot: &'a Snapshot,
        plan: &crate::format::CopyPlan,
        deadline: Instant,
        stop: &'a dyn Fn() -> bool,
    ) -> Result<Box<Self>, Error> {
        if snapshot.head.storage.plan.as_ref() != Some(plan) || !plan.basis.matches(&snapshot.head)
        {
            return Err(Error::Conflict);
        }
        let mut cursor = Self::new(objects, snapshot, deadline, stop)?;
        cursor.basis.retained_revision = plan.basis.revision;
        Ok(cursor)
    }

    fn push(&mut self, frame: PathFrame) -> Result<(), Error> {
        let slot = self.path.get_mut(self.depth).ok_or(Error::Limit)?;
        *slot = Some(frame);
        self.depth += 1;
        Ok(())
    }

    fn entry(&mut self, window: usize, id: u64, bytes: u64, committed: bool) -> Result<(), Error> {
        let total = self.totals.windows.get_mut(window).ok_or(Error::Corrupt)?;
        if id <= total.last_id {
            return Err(Error::Corrupt);
        }
        add(&mut total.entries, 1)?;
        add(&mut total.bytes, bytes)?;
        if committed {
            add(&mut total.committed, 1)?;
        } else {
            add(&mut total.cancelled, 1)?;
        }
        total.last_id = id;
        Ok(())
    }

    fn prepare(&mut self) -> Result<(), Error> {
        if self.next.is_some() {
            return Ok(());
        }
        while self.depth != 0 {
            self.basis.check()?;
            let frame = self.path[self.depth - 1].as_mut().expect("occupied path");
            match frame.next() {
                Some(Work::Edge(edge)) => {
                    self.next = Some(edge);
                    return Ok(());
                }
                Some(Work::Cancelled {
                    window,
                    id,
                    transition,
                }) => {
                    check_cancelled(&self.basis.snapshot.head, id, &transition)
                        .map_err(|error| self.basis.objects.observe(error))?;
                    if transition.revision > self.basis.retained_revision {
                        return Err(self.basis.objects.observe(Error::Corrupt));
                    }
                    self.entry(window, id, 0, false)
                        .map_err(|error| self.basis.objects.observe(error))?;
                }
                None => {
                    self.depth -= 1;
                    self.path[self.depth] = None;
                }
            }
        }
        if !self.data_complete {
            self.check_data_root()?;
            self.data_complete = true;
        }
        if let Some(entry) = self
            .basis
            .snapshot
            .head
            .snapshots
            .as_deref()
            .unwrap_or(&[])
            .get(self.next_retained)
        {
            self.next = Some(Edge {
                hash: entry.point.data_root.clone(),
                role: Role::Manifest,
            });
            self.next_retained += 1;
            self.expected_pages = Some(entry.point.page_count);
            self.root_start_pages = self.totals.pages;
            self.root_start_chunks = self.totals.chunks;
            self.data_complete = false;
            return Ok(());
        }
        if let Some(window) = self.basis.snapshot.head.windows.get(self.next_window) {
            self.next = Some(Edge {
                hash: window.root.clone(),
                role: Role::Window {
                    window: self.next_window,
                },
            });
            self.next_window += 1;
        }
        Ok(())
    }

    fn action(
        &self,
        visit: &FrameVisit<'_>,
        metadata: Payload,
        raw: &[u8],
    ) -> Result<Action, Error> {
        if visit.key != object_key(visit.scope, visit.storage_generation, visit.hash) {
            return Err(Error::Corrupt);
        }
        let head = &self.basis.snapshot.head;
        match (visit.role, metadata) {
            (Role::Manifest, Payload::Manifest(manifest)) => {
                if let Some(expected) = self.expected_pages {
                    if manifest.page_count != expected {
                        return Err(Error::Corrupt);
                    }
                } else if manifest.page_count > head.quota.max_pages().map_err(Error::Format)? {
                    return Err(Error::Limit);
                }
                Ok(Action::Manifest(manifest))
            }
            (
                Role::Node {
                    level,
                    first,
                    pages,
                },
                Payload::Node {
                    level: actual,
                    first_chunk,
                    children,
                },
            ) => {
                data_tree::check_node(actual, first_chunk, children.len(), *level, *first, *pages)?;
                Ok(Action::Node {
                    level: *level,
                    first: *first,
                    pages: *pages,
                    children,
                })
            }
            (Role::Chunk { first, pages }, Payload::Chunk { first_page, .. }) => {
                data_tree::check_chunk(first_page, raw.len(), *first, *pages)?;
                Ok(Action::Chunk {
                    pages: (raw.len() / PAGE_SIZE) as u64,
                })
            }
            (Role::Window { window }, Payload::Index(index)) => {
                request_index::check_root(
                    &index,
                    head.windows.get(*window).ok_or(Error::Corrupt)?,
                )?;
                Ok(Action::Index {
                    window: *window,
                    index,
                })
            }
            (
                Role::Child {
                    window,
                    level,
                    reference,
                },
                Payload::Index(index),
            ) => {
                let epoch = head.windows.get(*window).ok_or(Error::Corrupt)?.epoch;
                request_index::check_child(&index, reference, epoch, *level)?;
                Ok(Action::Index {
                    window: *window,
                    index,
                })
            }
            (
                Role::Result {
                    window,
                    request,
                    bytes,
                },
                Payload::Result(stored),
            ) => {
                check_retained_result(head, request, &stored, raw)?;
                if stored.transition.revision > self.basis.retained_revision {
                    return Err(Error::Corrupt);
                }
                if raw.len() as u64 != *bytes {
                    return Err(Error::Corrupt);
                }
                Ok(Action::Result {
                    window: *window,
                    id: request.id,
                    bytes: *bytes,
                })
            }
            _ => Err(Error::Corrupt),
        }
    }

    fn apply(&mut self, action: Action, frame_bytes: usize) -> Result<(), Error> {
        add(&mut self.totals.frames, 1)?;
        add(&mut self.totals.frame_bytes, frame_bytes as u64)?;
        match action {
            Action::Manifest(manifest) => {
                self.manifest_pages = manifest.page_count;
                self.next = manifest.root.map(|hash| Edge {
                    hash,
                    role: Role::Node {
                        level: data_tree::level_for(manifest.page_count),
                        first: 0,
                        pages: manifest.page_count,
                    },
                });
            }
            Action::Node {
                level,
                first,
                pages,
                children,
            } => self.push(PathFrame::Data {
                level,
                first,
                pages,
                position: 0,
                children: children.into_iter(),
            })?,
            Action::Chunk { pages } => {
                add(&mut self.totals.pages, pages)?;
                add(&mut self.totals.chunks, 1)?;
            }
            Action::Index { window, index } => self.push(match index {
                RequestIndex::Leaf { entries, .. } => PathFrame::Entries {
                    window,
                    entries: entries.into_iter(),
                },
                RequestIndex::Branch {
                    level, children, ..
                } => PathFrame::Index {
                    window,
                    level,
                    children: children.into_iter(),
                },
            })?,
            Action::Result { window, id, bytes } => self.entry(window, id, bytes, true)?,
        }
        Ok(())
    }

    fn check_data_root(&self) -> Result<(), Error> {
        if self.totals.pages.checked_sub(self.root_start_pages) != Some(self.manifest_pages as u64)
            || self.totals.chunks.checked_sub(self.root_start_chunks)
                != Some(self.manifest_pages.div_ceil(CHUNK_PAGES) as u64)
        {
            return Err(self.basis.objects.observe(Error::Corrupt));
        }
        Ok(())
    }

    fn complete(self: Box<Self>) -> Result<VerifiedClosure<'a>, Error> {
        self.basis.check()?;
        self.check_data_root()?;
        for (window, total) in self
            .basis
            .snapshot
            .head
            .windows
            .iter()
            .zip(&self.totals.windows)
        {
            if total.entries != window.count as u64
                || total.bytes != window.result_bytes
                || total.entries
                    != total
                        .committed
                        .checked_add(total.cancelled)
                        .ok_or(Error::Limit)?
            {
                return Err(self.basis.objects.observe(Error::Corrupt));
            }
        }
        Ok(VerifiedClosure {
            basis: self.basis,
            totals: self.totals,
        })
    }

    /// A bounded step consumes its old cursor. Only Pending returns continuation;
    /// any error drops all local prefix state without authorizing a retry.
    pub(super) fn advance(
        mut self: Box<Self>,
        budget: StepBudget,
        visitor: &mut dyn FnMut(FrameVisit<'_>) -> Result<(), Error>,
    ) -> Result<Step<'a>, Error> {
        let cap = MAX_OBJECT_BYTES as u64;
        if budget.max_frames == 0 || budget.max_read_bytes < cap {
            return Err(Error::Limit);
        }
        let mut usage = StepUsage::default();
        loop {
            self.basis.check()?;
            self.prepare()?;
            if self.next.is_none() {
                return self.complete().map(Step::Complete);
            }
            if usage.frames == budget.max_frames || budget.max_read_bytes - usage.read_bytes < cap {
                return Ok(Step::Pending(self));
            }
            let edge = self.next.take().expect("prepared edge");
            usage.frames += 1;
            usage.read_bytes += cap;
            let objects = self.basis.objects;
            let length = objects.with_raw(&edge.hash, self.basis.deadline, |key, frame| {
                self.basis.check()?;
                let parts = frame.into_parts();
                let visit = FrameVisit {
                    scope: &self.basis.snapshot.head.scope,
                    storage_generation: self.basis.snapshot.head.storage.active_generation,
                    hash: &edge.hash,
                    key,
                    role: &edge.role,
                    bytes: parts.frame,
                };
                let action = self
                    .action(&visit, parts.metadata, parts.raw)
                    .map_err(|error| objects.observe(error))?;
                self.basis.check()?;
                let length = visit.bytes.len();
                visitor(visit)?;
                self.basis.check()?;
                self.apply(action, length)
                    .map_err(|error| objects.observe(error))?;
                Ok(length)
            })?;
            // A successful parsed frame is bounded by cap. Transport/callback
            // errors retain their reservation and consume the entire cursor.
            usage.read_bytes -= cap - length as u64;
        }
    }
}

#[cfg(test)]
#[path = "closure_tests.rs"]
mod tests;
