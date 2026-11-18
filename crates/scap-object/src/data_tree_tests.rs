//! The tree uses the production v2 encoder. A controllable decoded-object port
//! supplies structural faults; independent S3/process evidence remains separate.

use super::*;
use crate::format::{digest, encode_object, Envelope, Scope, CHUNK_BYTES, MAX_TREE_LEVEL};
use scap_object_sqlite::PageChange;
use scap_object_store::StoreError;
use std::cell::{Cell, RefCell};
use std::time::Duration;

#[derive(Clone, Debug)]
enum Call {
    Load(String),
    Save,
}

#[derive(Clone, Default)]
struct Memory {
    objects: RefCell<BTreeMap<String, Payload>>,
    calls: RefCell<Vec<Call>>,
    deadlines: RefCell<Vec<Instant>>,
    fail_at: Cell<Option<usize>>,
}

impl Memory {
    fn record(&self, call: Call, deadline: Instant) -> Result<(), Error> {
        let mut calls = self.calls.borrow_mut();
        calls.push(call);
        self.deadlines.borrow_mut().push(deadline);
        if self.fail_at.get() == Some(calls.len()) {
            return Err(Error::Store(StoreError::Unknown));
        }
        Ok(())
    }

    fn reset(&self) {
        self.calls.borrow_mut().clear();
        self.deadlines.borrow_mut().clear();
        self.fail_at.set(None);
    }

    fn counts(&self) -> (usize, usize) {
        let calls = self.calls.borrow();
        (
            calls
                .iter()
                .filter(|call| matches!(call, Call::Load(_)))
                .count(),
            calls
                .iter()
                .filter(|call| matches!(call, Call::Save))
                .count(),
        )
    }

    fn value(&self, hash: &str) -> Payload {
        self.objects.borrow()[hash].clone()
    }

    fn corrupt(&self, hash: &str, value: Payload) {
        self.objects.borrow_mut().insert(hash.to_owned(), value);
    }
}

impl DataObjects for Memory {
    fn load(&self, hash: &str, deadline: Instant) -> Result<Payload, Error> {
        self.record(Call::Load(hash.to_owned()), deadline)?;
        self.objects
            .borrow()
            .get(hash)
            .cloned()
            .ok_or(Error::Store(StoreError::Missing))
    }

    fn save(&self, payload: Payload, deadline: Instant) -> Result<String, Error> {
        self.record(Call::Save, deadline)?;
        let wire = encode_object(&Envelope {
            format: 2,
            scope: Scope {
                deployment: 1,
                tenant: 2,
                database: 3,
                incarnation: 4,
                generation: 5,
            },
            payload: payload.clone(),
        })
        .map_err(Error::Format)?;
        let hash = digest(&wire);
        self.objects.borrow_mut().insert(hash.clone(), payload);
        Ok(hash)
    }
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(600)
}

fn page(number: u32) -> PageChange {
    PageChange {
        number,
        bytes: vec![(number % 251) as u8; PAGE_SIZE],
    }
}

fn build(pages: u32) -> (Memory, String) {
    let store = Memory::default();
    let end = deadline();
    let base = empty(&store, end).unwrap();
    let root = update(
        &store,
        &base,
        &PageBatch {
            size_after: pages,
            pages: (1..=pages).map(page).collect(),
        },
        MAX_PAGES,
        end,
    )
    .unwrap();
    store.reset();
    (store, root)
}

fn descriptor(store: &Memory, hash: &str) -> Manifest {
    match store.value(hash) {
        Payload::Manifest(value) => value,
        _ => panic!("manifest expected"),
    }
}

fn children(store: &Memory, hash: &str) -> Vec<String> {
    match store.value(hash) {
        Payload::Node { children, .. } => children,
        _ => panic!("node expected"),
    }
}

fn verify_image(store: &Memory, root: &str, pages: u32, patch: Option<u32>) {
    let value = manifest(store, root, deadline()).unwrap();
    assert_eq!(value.page_count, pages);
    let mut seen = 0;
    walk(store, &value, deadline(), |first, bytes| {
        assert_eq!(first, seen + 1);
        assert!(bytes.len() <= CHUNK_BYTES);
        for bytes in bytes.chunks_exact(PAGE_SIZE) {
            seen += 1;
            let expected = if patch == Some(seen) {
                255
            } else {
                (seen % 251) as u8
            };
            assert!(bytes.iter().all(|byte| *byte == expected));
        }
        Ok(())
    })
    .unwrap();
    assert_eq!(seen, pages);
}

fn consume(
    store: &Memory,
    value: &Manifest,
    deadline: Instant,
    fail_consumer: bool,
) -> Result<usize, Error> {
    let mut chunks = 0;
    walk(store, value, deadline, |_, _| {
        if fail_consumer {
            return Err(Error::Limit);
        }
        chunks += 1;
        Ok(())
    })?;
    Ok(chunks)
}

#[test]
fn empty_and_manifest_validation_never_invent_data() {
    let store = Memory::default();
    let end = deadline();
    let root = empty(&store, end).unwrap();
    let value = manifest(&store, &root, end).unwrap();
    assert_eq!(
        value,
        Manifest {
            page_count: 0,
            root: None
        }
    );
    store.reset();
    assert_eq!(consume(&store, &value, end, false).unwrap(), 0);
    assert_eq!(store.counts(), (0, 0));
    assert_eq!(
        update(
            &store,
            &root,
            &PageBatch {
                size_after: 0,
                pages: vec![]
            },
            MAX_PAGES,
            end
        )
        .unwrap(),
        root
    );
    assert_eq!(store.counts(), (1, 0));
    assert!(store
        .deadlines
        .borrow()
        .iter()
        .all(|observed| *observed == end));
    let wrong = store
        .save(crate::tests::index_payload(1, vec![]), end)
        .unwrap();
    assert!(matches!(manifest(&store, &wrong, end), Err(Error::Corrupt)));
    let invalid = Manifest {
        page_count: 1,
        root: None,
    };
    store.corrupt(&root, Payload::Manifest(invalid.clone()));
    assert!(matches!(manifest(&store, &root, end), Err(Error::Corrupt)));
    assert!(matches!(
        consume(&store, &invalid, end, false),
        Err(Error::Corrupt)
    ));
    assert!(matches!(
        manifest(&store, "missing", end),
        Err(Error::Store(StoreError::Missing))
    ));
}

#[test]
fn one_changed_page_reads_only_one_block_and_its_path_in_a_large_tree() {
    // This real in-memory physical image is larger than the old 256 KiB profile
    // by over two orders of magnitude and spans two level-zero nodes.
    let pages = CHUNK_PAGES * TREE_FANOUT as u32 + 17;
    let (store, root) = build(pages);
    let before = descriptor(&store, &root);
    let before_children = children(&store, before.root.as_ref().unwrap());
    let changed_page = 5 * CHUNK_PAGES + 1;
    let mut changed = page(changed_page);
    changed.bytes.fill(255);
    let end = deadline();
    let next = update(
        &store,
        &root,
        &PageBatch {
            size_after: pages,
            pages: vec![changed],
        },
        MAX_PAGES,
        end,
    )
    .unwrap();
    assert_eq!(store.counts(), (4, 4)); // manifest, root, one node, one chunk
    assert!(store
        .deadlines
        .borrow()
        .iter()
        .all(|observed| *observed == end));
    let after = descriptor(&store, &next);
    let after_children = children(&store, after.root.as_ref().unwrap());
    assert_ne!(before_children[0], after_children[0]);
    assert_eq!(before_children[1], after_children[1]);
    assert!(!store
        .calls
        .borrow()
        .iter()
        .any(|call| matches!(call, Call::Load(hash) if hash == &before_children[1])));
    let old_leaf = children(&store, &before_children[0]);
    let new_leaf = children(&store, &after_children[0]);
    assert_eq!(old_leaf.len(), TREE_FANOUT);
    for index in 0..TREE_FANOUT {
        assert_eq!(old_leaf[index] == new_leaf[index], index != 5);
    }
    verify_image(&store, &root, pages, None);
    verify_image(&store, &next, pages, Some(changed_page));
}

#[test]
fn partial_growth_and_truncation_preserve_exact_page_contents() {
    let (store, root) = build(63);
    let next = update(
        &store,
        &root,
        &PageBatch {
            size_after: 66,
            pages: (64..=66).map(page).collect(),
        },
        MAX_PAGES,
        deadline(),
    )
    .unwrap();
    verify_image(&store, &next, 66, None);
    let shrunk = update(
        &store,
        &next,
        &PageBatch {
            size_after: 35,
            pages: vec![],
        },
        MAX_PAGES,
        deadline(),
    )
    .unwrap();
    verify_image(&store, &shrunk, 35, None);
    let exact = update(
        &store,
        &shrunk,
        &PageBatch {
            size_after: 32,
            pages: vec![],
        },
        MAX_PAGES,
        deadline(),
    )
    .unwrap();
    verify_image(&store, &exact, 32, None);
    let empty_root = update(
        &store,
        &exact,
        &PageBatch {
            size_after: 0,
            pages: vec![],
        },
        MAX_PAGES,
        deadline(),
    )
    .unwrap();
    verify_image(&store, &empty_root, 0, None);
    let fresh = update(
        &store,
        &empty_root,
        &PageBatch {
            size_after: 1,
            pages: vec![page(1)],
        },
        MAX_PAGES,
        deadline(),
    )
    .unwrap();
    verify_image(&store, &fresh, 1, None);
    // The old version stays readable; truncation never physically deletes it.
    verify_image(&store, &root, 63, None);
}

#[test]
fn canonical_roots_grow_and_shrink_without_reading_unmodified_subtrees() {
    let full = CHUNK_PAGES * TREE_FANOUT as u32;
    let (store, root) = build(full);
    let end = deadline();
    let grown = update(
        &store,
        &root,
        &PageBatch {
            size_after: full + 1,
            pages: vec![page(full + 1)],
        },
        MAX_PAGES,
        end,
    )
    .unwrap();
    assert_eq!(store.counts(), (1, 4));
    let old_tree = descriptor(&store, &root).root.unwrap();
    let new_tree = descriptor(&store, &grown).root.unwrap();
    assert_eq!(children(&store, &new_tree)[0], old_tree);
    verify_image(&store, &grown, full + 1, None);
    store.reset();
    let shrunk = update(
        &store,
        &grown,
        &PageBatch {
            size_after: CHUNK_PAGES,
            pages: vec![],
        },
        MAX_PAGES,
        end,
    )
    .unwrap();
    assert_eq!(store.counts(), (3, 2));
    assert!(matches!(
        store.value(descriptor(&store, &shrunk).root.as_ref().unwrap()),
        Payload::Node { level: 0, .. }
    ));
    verify_image(&store, &shrunk, CHUNK_PAGES, None);
}

#[test]
fn invalid_page_batches_and_quota_crossings_have_no_upload_side_effects() {
    let (store, root) = build(2);
    for (batch, maximum, is_limit) in [
        (
            PageBatch {
                size_after: 2,
                pages: vec![],
            },
            0,
            true,
        ),
        (
            PageBatch {
                size_after: 2,
                pages: vec![],
            },
            u32::MAX,
            true,
        ),
        (
            PageBatch {
                size_after: 3,
                pages: vec![page(3)],
            },
            2,
            true,
        ),
        (
            PageBatch {
                size_after: 2,
                pages: vec![page(0)],
            },
            MAX_PAGES,
            false,
        ),
        (
            PageBatch {
                size_after: 2,
                pages: vec![page(1), page(1)],
            },
            MAX_PAGES,
            false,
        ),
        (
            PageBatch {
                size_after: 2,
                pages: vec![page(2), page(1)],
            },
            MAX_PAGES,
            false,
        ),
        (
            PageBatch {
                size_after: 2,
                pages: vec![page(3)],
            },
            MAX_PAGES,
            false,
        ),
        (
            PageBatch {
                size_after: 2,
                pages: vec![PageChange {
                    number: 1,
                    bytes: vec![0; PAGE_SIZE - 1],
                }],
            },
            MAX_PAGES,
            false,
        ),
        (
            PageBatch {
                size_after: 4,
                pages: vec![page(4)],
            },
            MAX_PAGES,
            false,
        ),
        (
            PageBatch {
                size_after: 3,
                pages: vec![],
            },
            MAX_PAGES,
            false,
        ),
        (
            PageBatch {
                size_after: 1,
                pages: vec![page(2)],
            },
            MAX_PAGES,
            false,
        ),
    ] {
        store.reset();
        let result = update(&store, &root, &batch, maximum, deadline());
        if is_limit {
            assert!(matches!(result, Err(Error::Limit)));
        } else {
            assert!(matches!(result, Err(Error::Corrupt)));
        }
        assert_eq!(store.counts().1, 0);
    }
}

#[test]
fn every_accessed_node_and_chunk_is_bound_to_its_exact_range_and_kind() {
    let (original, root) = build(33);
    let value = descriptor(&original, &root);
    let tree = value.root.as_ref().unwrap();
    let child = children(&original, tree);
    for payload in [
        crate::tests::index_payload(1, vec![]),
        Payload::Node {
            level: 1,
            first_chunk: 0,
            children: child.clone(),
        },
        Payload::Node {
            level: 0,
            first_chunk: 1,
            children: child.clone(),
        },
        Payload::Node {
            level: 0,
            first_chunk: 0,
            children: vec![child[0].clone()],
        },
    ] {
        let store = original.clone();
        store.corrupt(tree, payload);
        assert!(matches!(
            walk(&store, &value, deadline(), |_, _| Ok(())),
            Err(Error::Corrupt)
        ));
        assert!(matches!(
            update(
                &store,
                &root,
                &PageBatch {
                    size_after: 33,
                    pages: vec![page(1)]
                },
                MAX_PAGES,
                deadline()
            ),
            Err(Error::Corrupt)
        ));
    }
    for payload in [
        crate::tests::index_payload(1, vec![]),
        Payload::Chunk {
            first_page: 33,
            bytes: vec![0; CHUNK_BYTES],
        },
        Payload::Chunk {
            first_page: 1,
            bytes: vec![0; PAGE_SIZE],
        },
    ] {
        let store = original.clone();
        store.corrupt(&child[0], payload);
        assert!(matches!(
            walk(&store, &value, deadline(), |_, _| Ok(())),
            Err(Error::Corrupt)
        ));
        assert!(matches!(
            update(
                &store,
                &root,
                &PageBatch {
                    size_after: 33,
                    pages: vec![page(1)]
                },
                MAX_PAGES,
                deadline()
            ),
            Err(Error::Corrupt)
        ));
    }
    let store = original.clone();
    store.corrupt(
        tree,
        Payload::Node {
            level: 0,
            first_chunk: 0,
            children: vec![child[0].clone(); 2],
        },
    );
    assert!(matches!(
        walk(&store, &value, deadline(), |_, _| Ok(())),
        Err(Error::Corrupt)
    ));
    let store = original.clone();
    store.objects.borrow_mut().remove(&child[1]);
    let mut seen = 0;
    assert!(matches!(
        walk(&store, &value, deadline(), |_, _| {
            seen += 1;
            Ok(())
        }),
        Err(Error::Store(StoreError::Missing))
    ));
    assert_eq!(seen, 1);
}

#[test]
fn every_object_io_failure_and_stream_consumer_failure_propagates() {
    let (original, root) = build(40);
    let batch = PageBatch {
        size_after: 41,
        pages: vec![page(1), page(41)],
    };
    let success = original.clone();
    update(&success, &root, &batch, MAX_PAGES, deadline()).unwrap();
    for point in 1..=success.calls.borrow().len() {
        let store = original.clone();
        store.fail_at.set(Some(point));
        assert!(matches!(
            update(&store, &root, &batch, MAX_PAGES, deadline()),
            Err(Error::Store(StoreError::Unknown))
        ));
        assert_eq!(store.calls.borrow().len(), point);
        store.reset();
        verify_image(&store, &root, 40, None);
    }
    let value = descriptor(&original, &root);
    let success = original.clone();
    assert_eq!(consume(&success, &value, deadline(), false).unwrap(), 2);
    for point in 1..=success.calls.borrow().len() {
        let store = original.clone();
        store.fail_at.set(Some(point));
        assert!(matches!(
            consume(&store, &value, deadline(), false),
            Err(Error::Store(StoreError::Unknown))
        ));
        assert_eq!(store.calls.borrow().len(), point);
    }
    let store = original.clone();
    assert!(matches!(
        consume(&store, &value, deadline(), true),
        Err(Error::Limit)
    ));
    assert_eq!(store.counts(), (2, 0));
    let store = Memory::default();
    store.fail_at.set(Some(1));
    assert!(matches!(
        empty(&store, deadline()),
        Err(Error::Store(StoreError::Unknown))
    ));
}

#[test]
fn truncating_to_empty_propagates_manifest_save_failure() {
    let (store, root) = build(1);
    let original = store.objects.borrow().clone();
    let end = deadline();
    store.fail_at.set(Some(2));
    assert!(matches!(
        super::update(
            &store,
            &root,
            &PageBatch {
                size_after: 0,
                pages: vec![],
            },
            MAX_PAGES,
            end,
        ),
        Err(Error::Store(StoreError::Unknown))
    ));
    assert!(matches!(
        store.calls.borrow().as_slice(),
        [Call::Load(hash), Call::Save] if hash == &root
    ));
    assert_eq!(store.deadlines.borrow().as_slice(), &[end, end]);
    assert_eq!(*store.objects.borrow(), original);
    store.reset();
    verify_image(&store, &root, 1, None);
}

#[test]
fn recursive_read_edit_and_root_shrink_propagate_object_io_failure() {
    let (original, root) = build(8193);
    for (batch, point) in [
        (
            PageBatch {
                size_after: 8193,
                pages: vec![page(1)],
            },
            3,
        ),
        (
            PageBatch {
                size_after: 32,
                pages: vec![],
            },
            2,
        ),
    ] {
        let store = original.clone();
        store.fail_at.set(Some(point));
        assert!(matches!(
            update(&store, &root, &batch, MAX_PAGES, deadline()),
            Err(Error::Store(StoreError::Unknown))
        ));
        assert_eq!(store.counts(), (point, 0));
        assert_eq!(descriptor(&store, &root).page_count, 8193);
    }
    let value = descriptor(&original, &root);
    assert_eq!(consume(&original, &value, deadline(), false).unwrap(), 257);
    original.reset();
    original.fail_at.set(Some(2));
    assert!(matches!(
        consume(&original, &value, deadline(), false),
        Err(Error::Store(StoreError::Unknown))
    ));
    assert_eq!(original.counts(), (2, 0));
}

#[test]
fn geometry_covers_native_maximum_and_never_fills_growth_holes_with_zeroes() {
    for (pages, level) in [
        (0, 0),
        (1, 0),
        (8192, 0),
        (8193, 1),
        (2_097_152, 1),
        (2_097_153, 2),
        (536_870_912, 2),
        (536_870_913, 3),
        (MAX_PAGES, MAX_TREE_LEVEL),
    ] {
        assert_eq!(level_for(pages), level);
    }
    assert_eq!(span(MAX_TREE_LEVEL), 1_u64 << 32);
    assert_eq!(child_count(3, 0, MAX_PAGES), 8);
    assert_eq!(
        chunk_len(MAX_PAGES.div_ceil(CHUNK_PAGES) - 1, MAX_PAGES),
        30 * PAGE_SIZE
    );
    let store = Memory::default();
    let edit = Edit {
        store: &store,
        old_pages: 0,
        new_pages: 1,
        changes: BTreeMap::new(),
        deadline: deadline(),
    };
    assert!(matches!(edit.chunk(None, 0), Err(Error::Corrupt)));
    assert_eq!(store.counts(), (0, 0));
}
