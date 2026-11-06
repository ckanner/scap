//! Bounded, content-addressed physical page tree. Unchanged subtrees inherit the
//! base HEAD's immutable-object guarantee; cold recovery validates every block.

use std::collections::BTreeMap;
use std::time::Instant;

use scap_object_sqlite::PageBatch;

use crate::format::{Manifest, Payload, CHUNK_PAGES, MAX_PAGES, PAGE_SIZE, TREE_FANOUT};
use crate::Error;

pub(crate) trait DataObjects {
    fn load(&self, hash: &str, deadline: Instant) -> Result<Payload, Error>;
    fn save(&self, payload: Payload, deadline: Instant) -> Result<String, Error>;
}

pub(crate) fn empty(store: &impl DataObjects, deadline: Instant) -> Result<String, Error> {
    store.save(
        Payload::Manifest(Manifest {
            page_count: 0,
            root: None,
        }),
        deadline,
    )
}

pub(crate) fn manifest(
    store: &impl DataObjects,
    root: &str,
    deadline: Instant,
) -> Result<Manifest, Error> {
    match store.load(root, deadline)? {
        Payload::Manifest(manifest) => {
            manifest.validate().map_err(|_| Error::Corrupt)?;
            Ok(manifest)
        }
        _ => Err(Error::Corrupt),
    }
}

fn level_for(pages: u32) -> u8 {
    let chunks = pages.div_ceil(CHUNK_PAGES) as u64;
    let mut level = 0;
    while chunks > span(level) {
        level += 1;
    }
    level
}

/// Number of chunks covered by a complete node at the zero-based level.
fn span(level: u8) -> u64 {
    (TREE_FANOUT as u64).pow(level as u32 + 1)
}

fn child_span(level: u8) -> u64 {
    (TREE_FANOUT as u64).pow(level as u32)
}

fn child_count(level: u8, first_chunk: u32, pages: u32) -> usize {
    (pages.div_ceil(CHUNK_PAGES) as u64)
        .saturating_sub(first_chunk as u64)
        .min(span(level))
        .div_ceil(child_span(level)) as usize
}

fn child_first(level: u8, first_chunk: u32, index: usize) -> u32 {
    // Callers enumerate only child_count entries for a <= MAX_PAGES image.
    (first_chunk as u64 + index as u64 * child_span(level)) as u32
}

fn extent(level: u8, first_chunk: u32, pages: u32) -> u64 {
    (pages as u64)
        .saturating_sub(first_chunk as u64 * CHUNK_PAGES as u64)
        .min(span(level) * CHUNK_PAGES as u64)
}

fn chunk_len(first_chunk: u32, pages: u32) -> usize {
    (pages as u64)
        .saturating_sub(first_chunk as u64 * CHUNK_PAGES as u64)
        .min(CHUNK_PAGES as u64) as usize
        * PAGE_SIZE
}

fn load_node(
    store: &impl DataObjects,
    hash: &str,
    level: u8,
    first_chunk: u32,
    pages: u32,
    deadline: Instant,
) -> Result<Vec<String>, Error> {
    match store.load(hash, deadline)? {
        Payload::Node {
            level: actual_level,
            first_chunk: actual_first,
            children,
        } if actual_level == level
            && actual_first == first_chunk
            && children.len() == child_count(level, first_chunk, pages) =>
        {
            Ok(children)
        }
        _ => Err(Error::Corrupt),
    }
}

fn load_chunk(
    store: &impl DataObjects,
    hash: &str,
    first_chunk: u32,
    pages: u32,
    deadline: Instant,
) -> Result<Vec<u8>, Error> {
    match store.load(hash, deadline)? {
        Payload::Chunk { first_page, bytes }
            if first_page == first_chunk * CHUNK_PAGES + 1
                && bytes.len() == chunk_len(first_chunk, pages) =>
        {
            Ok(bytes)
        }
        _ => Err(Error::Corrupt),
    }
}

pub(crate) fn walk(
    store: &impl DataObjects,
    manifest: &Manifest,
    deadline: Instant,
    mut on_chunk: impl FnMut(u32, &[u8]) -> Result<(), Error>,
) -> Result<(), Error> {
    manifest.validate().map_err(|_| Error::Corrupt)?;
    if let Some(root) = &manifest.root {
        walk_node(
            store,
            root,
            level_for(manifest.page_count),
            0,
            manifest.page_count,
            deadline,
            &mut on_chunk,
        )?;
    }
    Ok(())
}

fn walk_node(
    store: &impl DataObjects,
    hash: &str,
    level: u8,
    first_chunk: u32,
    pages: u32,
    deadline: Instant,
    on_chunk: &mut impl FnMut(u32, &[u8]) -> Result<(), Error>,
) -> Result<(), Error> {
    let children = load_node(store, hash, level, first_chunk, pages, deadline)?;
    for (index, child) in children.iter().enumerate() {
        let first = child_first(level, first_chunk, index);
        if level == 0 {
            let bytes = load_chunk(store, child, first, pages, deadline)?;
            on_chunk(first * CHUNK_PAGES + 1, &bytes)?;
        } else {
            walk_node(store, child, level - 1, first, pages, deadline, on_chunk)?;
        }
    }
    Ok(())
}

#[derive(Clone)]
struct Original {
    level: u8,
    hash: String,
}

struct Edit<'a, S> {
    store: &'a S,
    old_pages: u32,
    new_pages: u32,
    changes: BTreeMap<u32, &'a [u8]>,
    deadline: Instant,
}

impl<S: DataObjects> Edit<'_, S> {
    fn has_changes(&self, first: u64, end: u64) -> bool {
        // Page keys are u32; the exclusive upper edge may be 2^32 or larger.
        self.changes
            .range(first as u32..)
            .next()
            .is_some_and(|(page, _)| (*page as u64) < end)
    }

    fn node(&self, old: Option<&Original>, level: u8, first_chunk: u32) -> Result<String, Error> {
        let first_page = first_chunk as u64 * CHUNK_PAGES as u64 + 1;
        if let Some(original) = old {
            if original.level == level
                && extent(level, first_chunk, self.old_pages)
                    == extent(level, first_chunk, self.new_pages)
                && !self.has_changes(first_page, first_page + span(level) * CHUNK_PAGES as u64)
            {
                return Ok(original.hash.clone());
            }
        }
        let old_children = match old {
            Some(original) if original.level == level => load_node(
                self.store,
                &original.hash,
                level,
                first_chunk,
                self.old_pages,
                self.deadline,
            )?
            .into_iter()
            .map(|hash| Original {
                level: level.saturating_sub(1),
                hash,
            })
            .collect(),
            // Growing the tree creates virtual parents around the old root;
            // they are saved only after all referenced new objects are durable.
            Some(original) => vec![original.clone()],
            None => Vec::new(),
        };
        let mut children = Vec::with_capacity(child_count(level, first_chunk, self.new_pages));
        for index in 0..child_count(level, first_chunk, self.new_pages) {
            let first = child_first(level, first_chunk, index);
            let previous = old_children.get(index);
            let child = if level == 0 {
                self.chunk(previous.map(|value| value.hash.as_str()), first)?
            } else {
                self.node(previous, level - 1, first)?
            };
            children.push(child);
        }
        self.store.save(
            Payload::Node {
                level,
                first_chunk,
                children,
            },
            self.deadline,
        )
    }

    fn chunk(&self, old: Option<&str>, first_chunk: u32) -> Result<String, Error> {
        let first_page = first_chunk * CHUNK_PAGES + 1;
        let length = chunk_len(first_chunk, self.new_pages);
        let end_page = first_page as u64 + (length / PAGE_SIZE) as u64;
        if let Some(hash) = old {
            if chunk_len(first_chunk, self.old_pages) == length
                && !self.has_changes(first_page as u64, end_page)
            {
                return Ok(hash.to_owned());
            }
        }
        let previous = match old {
            Some(hash) => load_chunk(self.store, hash, first_chunk, self.old_pages, self.deadline)?,
            None => Vec::new(),
        };
        let mut bytes = Vec::with_capacity(length);
        for page in first_page as u64..end_page {
            if let Some(changed) = self.changes.get(&(page as u32)) {
                bytes.extend_from_slice(changed);
            } else {
                let offset = (page - first_page as u64) as usize * PAGE_SIZE;
                // A missing growth page is never synthesized as a zero page.
                bytes.extend_from_slice(
                    previous
                        .get(offset..offset + PAGE_SIZE)
                        .ok_or(Error::Corrupt)?,
                );
            }
        }
        self.store
            .save(Payload::Chunk { first_page, bytes }, self.deadline)
    }
}

pub(crate) fn update(
    store: &impl DataObjects,
    base_root: &str,
    batch: &PageBatch,
    max_pages: u32,
    deadline: Instant,
) -> Result<String, Error> {
    if max_pages == 0 || max_pages > MAX_PAGES || batch.size_after > max_pages {
        return Err(Error::Limit);
    }
    let base = manifest(store, base_root, deadline)?;
    let mut changes = BTreeMap::new();
    let mut previous = 0;
    let mut added = 0;
    for page in &batch.pages {
        if page.number <= previous
            || page.number > batch.size_after
            || page.bytes.len() != PAGE_SIZE
        {
            return Err(Error::Corrupt);
        }
        previous = page.number;
        added += u32::from(page.number > base.page_count);
        changes.insert(page.number, page.bytes.as_slice());
    }
    if added != batch.size_after.saturating_sub(base.page_count) {
        return Err(Error::Corrupt);
    }
    if batch.size_after == base.page_count && changes.is_empty() {
        return Ok(base_root.to_owned());
    }
    if batch.size_after == 0 {
        return empty(store, deadline);
    }
    let level = level_for(batch.size_after);
    let mut original = base.root.map(|hash| Original {
        level: level_for(base.page_count),
        hash,
    });
    if let Some(original) = &mut original {
        // A smaller image has a canonical, shallower root. Only its left spine
        // is read; detached trailing subtrees are not downloaded or deleted.
        while original.level > level {
            let children = load_node(
                store,
                &original.hash,
                original.level,
                0,
                base.page_count,
                deadline,
            )?;
            original.hash = children[0].clone();
            original.level -= 1;
        }
    }
    let edit = Edit {
        store,
        old_pages: base.page_count,
        new_pages: batch.size_after,
        changes,
        deadline,
    };
    let root = edit.node(original.as_ref(), level, 0)?;
    store.save(
        Payload::Manifest(Manifest {
            page_count: batch.size_after,
            root: Some(root),
        }),
        deadline,
    )
}

#[cfg(test)]
#[path = "data_tree_tests.rs"]
mod tests;
