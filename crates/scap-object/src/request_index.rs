//! Immutable, bounded B+ tree for retained request identities and results.
//! Only the insertion path changes. GC is disabled: unchanged siblings inherit
//! the published root's guarantee; cold recovery still visits every edge.

use std::time::Instant;

use crate::data_tree::DataObjects;
use crate::format::{Entry, IndexChild, Payload, RequestIndex, Window, MAX_REQUESTS};
use crate::Error;

fn load(
    store: &impl DataObjects,
    hash: &str,
    epoch: u64,
    deadline: Instant,
) -> Result<RequestIndex, Error> {
    let index = match store.load(hash, deadline)? {
        Payload::Index(index) => index,
        _ => return Err(Error::Corrupt),
    };
    index.validate().map_err(|_| Error::Corrupt)?;
    if index.epoch() != epoch {
        return Err(Error::Corrupt);
    }
    Ok(index)
}

fn root(
    store: &impl DataObjects,
    window: &Window,
    deadline: Instant,
) -> Result<RequestIndex, Error> {
    let index = load(store, &window.root, window.epoch, deadline)?;
    let summary = index.summary();
    if summary.count != window.count || summary.result_bytes != window.result_bytes {
        return Err(Error::Corrupt);
    }
    Ok(index)
}

fn child(
    store: &impl DataObjects,
    reference: &IndexChild,
    epoch: u64,
    level: u8,
    deadline: Instant,
) -> Result<RequestIndex, Error> {
    let index = load(store, &reference.hash, epoch, deadline)?;
    let (width, capacity) = index.occupancy();
    if index.level() != level || width < capacity / 2 || index.summary() != reference.summary {
        return Err(Error::Corrupt);
    }
    Ok(index)
}

fn save(
    store: &impl DataObjects,
    index: RequestIndex,
    deadline: Instant,
) -> Result<IndexChild, Error> {
    index.validate().map_err(Error::Format)?;
    let summary = index.summary();
    let hash = store.save(Payload::Index(index), deadline)?;
    Ok(IndexChild { hash, summary })
}

pub(crate) fn empty(
    store: &impl DataObjects,
    epoch: u64,
    deadline: Instant,
) -> Result<String, Error> {
    Ok(save(
        store,
        RequestIndex::Leaf {
            epoch,
            entries: Vec::new(),
        },
        deadline,
    )?
    .hash)
}

pub(crate) fn lookup(
    store: &impl DataObjects,
    window: &Window,
    id: u64,
    deadline: Instant,
) -> Result<Option<Entry>, Error> {
    let mut index = root(store, window, deadline)?;
    // Every child is one level lower, and the codec limits the root to level 3.
    // This cannot become an unbounded chain, even for adversarial object bytes.
    loop {
        match index {
            RequestIndex::Leaf { mut entries, .. } => {
                return Ok(entries
                    .binary_search_by_key(&id, |entry| entry.request.id)
                    .ok()
                    .map(|position| entries.remove(position)));
            }
            RequestIndex::Branch {
                epoch,
                level,
                children,
            } => {
                let Some(reference) = children.iter().find(|reference| {
                    reference.summary.first <= id && id <= reference.summary.last
                }) else {
                    return Ok(None);
                };
                index = child(store, reference, epoch, level - 1, deadline)?;
            }
        }
    }
}

fn split(
    store: &impl DataObjects,
    mut index: RequestIndex,
    deadline: Instant,
) -> Result<Vec<IndexChild>, Error> {
    let (width, capacity) = index.occupancy();
    if width <= capacity {
        return Ok(vec![save(store, index, deadline)?]);
    }
    let right = match &mut index {
        RequestIndex::Leaf { epoch, entries } => RequestIndex::Leaf {
            epoch: *epoch,
            entries: entries.split_off(capacity / 2),
        },
        RequestIndex::Branch {
            epoch,
            level,
            children,
        } => RequestIndex::Branch {
            epoch: *epoch,
            level: *level,
            children: children.split_off(capacity / 2),
        },
    };
    Ok(vec![
        save(store, index, deadline)?,
        save(store, right, deadline)?,
    ])
}

fn edit(
    store: &impl DataObjects,
    mut index: RequestIndex,
    entry: Entry,
    deadline: Instant,
) -> Result<Vec<IndexChild>, Error> {
    match &mut index {
        RequestIndex::Leaf { entries, .. } => {
            let position = entries
                .binary_search_by_key(&entry.request.id, |old| old.request.id)
                .map_or_else(Ok, |_| Err(Error::RequestConflict))?;
            entries.insert(position, entry);
        }
        RequestIndex::Branch {
            epoch,
            level,
            children,
        } => {
            // A gap is assigned to its right neighbor; IDs beyond the last
            // range extend the last leaf. No legal ID distribution loses space.
            let position = children
                .partition_point(|reference| reference.summary.last < entry.request.id)
                .min(children.len() - 1);
            let previous = child(store, &children[position], *epoch, *level - 1, deadline)?;
            let replacement = edit(store, previous, entry, deadline)?;
            children.splice(position..=position, replacement);
        }
    }
    split(store, index, deadline)
}

pub(crate) fn insert(
    store: &impl DataObjects,
    window: &Window,
    entry: Entry,
    deadline: Instant,
) -> Result<Window, Error> {
    let index = root(store, window, deadline)?;
    if entry.request.epoch != window.epoch {
        return Err(Error::RequestConflict);
    }
    if window.count == MAX_REQUESTS {
        return Err(Error::WindowFull);
    }
    let level = index.level();
    let mut references = edit(store, index, entry, deadline)?;
    let reference = if references.len() == 1 {
        references.remove(0)
    } else {
        save(
            store,
            RequestIndex::Branch {
                epoch: window.epoch,
                level: level + 1,
                children: references,
            },
            deadline,
        )?
    };
    Ok(Window {
        epoch: window.epoch,
        root: reference.hash,
        count: reference.summary.count,
        result_bytes: reference.summary.result_bytes,
    })
}

fn visit(
    store: &impl DataObjects,
    index: RequestIndex,
    deadline: Instant,
    visitor: &mut impl FnMut(Entry) -> Result<(), Error>,
) -> Result<(), Error> {
    match index {
        RequestIndex::Leaf { entries, .. } => {
            for entry in entries {
                visitor(entry)?;
            }
        }
        RequestIndex::Branch {
            epoch,
            level,
            children,
        } => {
            for reference in children {
                let next = child(store, &reference, epoch, level - 1, deadline)?;
                visit(store, next, deadline, visitor)?;
            }
        }
    }
    Ok(())
}

/// Full verification deliberately loads every child, including branches that a
/// point lookup would never touch. Strict level descent and disjoint ranges
/// reject cycles and duplicate subtrees without an unbounded visited set.
pub(crate) fn walk(
    store: &impl DataObjects,
    window: &Window,
    deadline: Instant,
    mut visitor: impl FnMut(Entry) -> Result<(), Error>,
) -> Result<(), Error> {
    visit(
        store,
        root(store, window, deadline)?,
        deadline,
        &mut visitor,
    )
}

#[cfg(test)]
#[path = "request_index_tests.rs"]
mod tests;
