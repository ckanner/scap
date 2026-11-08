//! Deterministic object-port tests and a separate ordered-map reference model.
//! This is not signed S3 or native publication evidence.

use super::*;
use crate::format::{digest, encode_object, Envelope, OutcomeRef, Request, Scope, Transition};
use scap_object_store::StoreError;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

#[derive(Clone, Default)]
struct Memory {
    objects: RefCell<BTreeMap<String, Payload>>,
    calls: RefCell<Vec<(bool, String, Instant)>>,
    fail_at: Cell<Option<usize>>,
}

impl Memory {
    fn record(&self, write: bool, hash: &str, end: Instant) -> Result<(), Error> {
        let mut calls = self.calls.borrow_mut();
        calls.push((write, hash.into(), end));
        if self.fail_at.get() == Some(calls.len()) {
            return Err(Error::Store(StoreError::Unknown));
        }
        Ok(())
    }

    fn reset(&self) {
        self.calls.borrow_mut().clear();
        self.fail_at.set(None);
    }

    fn counts(&self) -> (usize, usize) {
        let calls = self.calls.borrow();
        (
            calls.iter().filter(|call| !call.0).count(),
            calls.iter().filter(|call| call.0).count(),
        )
    }

    // Test storage can discard unreferenced candidates to keep adversarial
    // capacity models small. This helper is not a production GC algorithm.
    fn retain(&self, window: &Window) {
        let mut keep = BTreeSet::new();
        let mut pending = vec![window.root.clone()];
        while let Some(hash) = pending.pop() {
            if !keep.insert(hash.clone()) {
                continue;
            }
            if let Payload::Index(RequestIndex::Branch { children, .. }) =
                &self.objects.borrow()[&hash]
            {
                pending.extend(children.iter().map(|child| child.hash.clone()));
            }
        }
        self.objects
            .borrow_mut()
            .retain(|key, _| keep.contains(key));
    }
}

impl DataObjects for Memory {
    fn load(&self, hash: &str, deadline: Instant) -> Result<Payload, Error> {
        self.record(false, hash, deadline)?;
        self.objects
            .borrow()
            .get(hash)
            .cloned()
            .ok_or(Error::Store(StoreError::Missing))
    }

    fn save(&self, payload: Payload, deadline: Instant) -> Result<String, Error> {
        self.record(true, "", deadline)?;
        let bytes = encode_object(&Envelope {
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
        let hash = digest(&bytes);
        self.objects.borrow_mut().insert(hash.clone(), payload);
        Ok(hash)
    }
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(600)
}

fn entry(id: u64) -> Entry {
    Entry {
        request: Request {
            epoch: 1,
            id,
            principal: id % 7 + 1,
            fingerprint: digest(&id.to_le_bytes()),
        },
        outcome: if id.is_multiple_of(3) {
            OutcomeRef::Cancelled {
                transition: Transition {
                    revision: 1,
                    nonce: id,
                },
            }
        } else {
            OutcomeRef::Committed {
                result: digest(&[b'r', (id % 251) as u8]),
            }
        },
        result_bytes: if id.is_multiple_of(3) {
            0
        } else {
            id % 113 + 1
        },
    }
}

fn empty_window(store: &Memory, end: Instant) -> Window {
    Window {
        epoch: 1,
        root: empty(store, 1, end).unwrap(),
        count: 0,
        result_bytes: 0,
    }
}

fn collect(store: &Memory, window: &Window, end: Instant) -> Result<Vec<Entry>, Error> {
    let mut entries = Vec::new();
    walk(store, window, end, |entry| {
        entries.push(entry);
        Ok(())
    })?;
    Ok(entries)
}

fn window(reference: IndexChild) -> Window {
    Window {
        epoch: 1,
        root: reference.hash,
        count: reference.summary.count,
        result_bytes: reference.summary.result_bytes,
    }
}

fn leaf(store: &Memory, first: u64, count: usize, end: Instant) -> IndexChild {
    save(
        store,
        RequestIndex::Leaf {
            epoch: 1,
            entries: (first..first + count as u64).map(entry).collect(),
        },
        end,
    )
    .unwrap()
}

fn branch(store: &Memory, level: u8, children: Vec<IndexChild>, end: Instant) -> IndexChild {
    save(
        store,
        RequestIndex::Branch {
            epoch: 1,
            level,
            children,
        },
        end,
    )
    .unwrap()
}

fn two_leaves(store: &Memory, end: Instant) -> Window {
    let a = leaf(store, 1, 64, end);
    let b = leaf(store, 100, 64, end);
    window(branch(store, 1, vec![a, b], end))
}

#[test]
fn arbitrary_ids_and_outcomes_match_an_independent_ordered_map() {
    let orders = [
        (1..=2305).collect::<Vec<u64>>(),
        (1..=2305).rev().collect(),
        (0..2305)
            .map(|id| {
                if id % 2 == 0 {
                    id / 2 + 1
                } else {
                    u64::MAX - id / 2
                }
            })
            .collect(),
        (1..=2305).map(|id| ((id * 1543) % 2309) + 1).collect(),
    ];
    for ids in orders {
        let store = Memory::default();
        let end = deadline();
        let mut current = empty_window(&store, end);
        let mut expected = BTreeMap::new();
        assert!(lookup(&store, &current, 1, end).unwrap().is_none());
        for id in ids {
            let value = entry(id);
            store.reset();
            current = insert(&store, &current, value.clone(), end).unwrap();
            let (reads, writes) = store.counts();
            assert!(reads <= 4 && writes <= 9, "bounded path: {reads}/{writes}");
            expected.insert(id, value.clone());
            assert_eq!(current.count as usize, expected.len());
            assert_eq!(lookup(&store, &current, id, end).unwrap(), Some(value));
            if expected.len() % 257 == 0 {
                assert_eq!(
                    collect(&store, &current, end).unwrap(),
                    expected.values().cloned().collect::<Vec<_>>()
                );
                store.retain(&current);
            }
        }
        assert_eq!(
            collect(&store, &current, end).unwrap(),
            expected.values().cloned().collect::<Vec<_>>()
        );
        assert_eq!(
            current.result_bytes,
            expected
                .values()
                .map(|entry| entry.result_bytes)
                .sum::<u64>()
        );
        assert!(lookup(&store, &current, 0, end).unwrap().is_none());
        let original = current.clone();
        let mut conflict = expected.values().next().unwrap().clone();
        conflict.request.principal += 1;
        assert!(matches!(
            insert(&store, &current, conflict, end),
            Err(Error::RequestConflict)
        ));
        assert_eq!(
            collect(&store, &original, end).unwrap(),
            expected.values().cloned().collect::<Vec<_>>()
        );
    }
}

#[test]
fn gaps_extend_the_right_neighbor_and_last_range_without_losing_capacity() {
    let store = Memory::default();
    let end = deadline();
    let original = two_leaves(&store, end);
    assert!(lookup(&store, &original, 80, end).unwrap().is_none());
    assert!(lookup(&store, &original, 200, end).unwrap().is_none());
    let mut current = original.clone();
    for id in [80, u64::MAX, 200, 65, 99] {
        current = insert(&store, &current, entry(id), end).unwrap();
        assert_eq!(lookup(&store, &current, id, end).unwrap(), Some(entry(id)));
    }
    assert_eq!(collect(&store, &original, end).unwrap().len(), 128);
    assert_eq!(collect(&store, &current, end).unwrap().len(), 133);
    let mut wrong_epoch = entry(66);
    wrong_epoch.request.epoch = 2;
    assert!(matches!(
        insert(&store, &current, wrong_epoch, end),
        Err(Error::RequestConflict)
    ));
}

#[test]
fn cascading_splits_reach_four_layers_and_maximum_window_is_not_bucket_limited() {
    let store = Memory::default();
    let end = deadline();
    let mut id = 1;
    let mut parents = Vec::new();
    for parent in 0..32 {
        let mut children = Vec::new();
        for child in 0..if parent == 31 { 32 } else { 16 } {
            let count = if parent == 31 && child == 31 { 128 } else { 64 };
            children.push(leaf(&store, id, count, end));
            id += count as u64;
        }
        parents.push(branch(&store, 1, children, end));
    }
    let original = window(branch(&store, 2, parents, end));
    store.reset();
    let grown = insert(&store, &original, entry(u64::MAX), end).unwrap();
    assert_eq!(store.counts(), (3, 7));
    assert_eq!(root(&store, &grown, end).unwrap().level(), 3);
    store.reset();
    assert_eq!(
        lookup(&store, &grown, u64::MAX, end).unwrap(),
        Some(entry(u64::MAX))
    );
    assert_eq!(store.counts(), (4, 0));
    let values = collect(&store, &grown, end).unwrap();
    assert_eq!(values.len(), original.count as usize + 1);
    assert_eq!(values.last(), Some(&entry(u64::MAX)));
    assert_eq!(
        collect(&store, &original, end).unwrap().len(),
        original.count as usize
    );

    let store = Memory::default();
    let mut leaves = Vec::new();
    for first in (1..=MAX_REQUESTS as u64).step_by(128) {
        leaves.push(leaf(&store, first, 128, end));
    }
    let parents = leaves
        .chunks(32)
        .map(|children| branch(&store, 1, children.to_vec(), end))
        .collect();
    let full = window(branch(&store, 2, parents, end));
    assert_eq!(full.count, MAX_REQUESTS);
    assert_eq!(
        collect(&store, &full, end).unwrap().len(),
        MAX_REQUESTS as usize
    );
    assert!(matches!(
        insert(&store, &full, entry(u64::MAX), end),
        Err(Error::WindowFull)
    ));
}

#[test]
fn root_type_epoch_aggregate_and_locally_invalid_nodes_fail_closed() {
    let store = Memory::default();
    let end = deadline();
    let good = two_leaves(&store, end);
    let original = store.objects.borrow()[&good.root].clone();
    for payload in [
        Payload::Manifest(crate::format::Manifest {
            page_count: 0,
            root: None,
        }),
        Payload::Index(RequestIndex::Leaf {
            epoch: 0,
            entries: vec![],
        }),
        Payload::Index(RequestIndex::Leaf {
            epoch: 2,
            entries: vec![],
        }),
    ] {
        store
            .objects
            .borrow_mut()
            .insert(good.root.clone(), payload);
        assert!(matches!(lookup(&store, &good, 1, end), Err(Error::Corrupt)));
    }
    store
        .objects
        .borrow_mut()
        .insert(good.root.clone(), original);
    for count in [false, true] {
        let mut invalid = good.clone();
        if count {
            invalid.count += 1;
        } else {
            invalid.result_bytes += 1;
        }
        assert!(matches!(
            walk(&store, &invalid, end, |_| Ok(())),
            Err(Error::Corrupt)
        ));
    }
    assert!(matches!(empty(&store, 0, end), Err(Error::Format(_))));
}

#[test]
fn every_child_range_level_occupancy_and_aggregate_is_verified() {
    let store = Memory::default();
    let end = deadline();
    let good = two_leaves(&store, end);
    let Payload::Index(RequestIndex::Branch { children, .. }) =
        store.objects.borrow()[&good.root].clone()
    else {
        panic!()
    };
    let reference = children[0].clone();
    assert!(matches!(
        child(&store, &reference, 1, 1, end),
        Err(Error::Corrupt)
    ));
    let too_short = RequestIndex::Leaf {
        epoch: 1,
        entries: (1..64).map(entry).collect(),
    };
    store
        .objects
        .borrow_mut()
        .insert(reference.hash.clone(), Payload::Index(too_short));
    assert!(matches!(
        walk(&store, &good, end, |_| Ok(())),
        Err(Error::Corrupt)
    ));
    store.objects.borrow_mut().insert(
        reference.hash.clone(),
        Payload::Index(RequestIndex::Leaf {
            epoch: 1,
            entries: (1..=64).map(entry).collect(),
        }),
    );
    let mut mismatch = reference.clone();
    mismatch.summary.result_bytes += 1;
    assert!(matches!(
        child(&store, &mismatch, 1, 0, end),
        Err(Error::Corrupt)
    ));
    // A point lookup can avoid the other branch; full recovery must not.
    store.objects.borrow_mut().remove(&children[1].hash);
    assert_eq!(lookup(&store, &good, 1, end).unwrap(), Some(entry(1)));
    assert!(matches!(
        walk(&store, &good, end, |_| Ok(())),
        Err(Error::Store(StoreError::Missing))
    ));
    // A fake cycle has a non-decreasing level and is rejected on its first edge.
    let cycle = store.objects.borrow()[&good.root].clone();
    store
        .objects
        .borrow_mut()
        .insert(reference.hash.clone(), cycle);
    assert!(matches!(
        walk(&store, &good, end, |_| Ok(())),
        Err(Error::Corrupt)
    ));
}

#[test]
fn all_object_calls_keep_the_original_deadline_and_propagate_failures() {
    let original = Memory::default();
    let end = deadline();
    let mut current = empty_window(&original, end);
    for id in 1..=128 {
        current = insert(&original, &current, entry(id), end).unwrap();
    }
    original.reset();
    insert(&original, &current, entry(129), end).unwrap();
    let total = original.calls.borrow().len();
    for fail_at in 1..=total {
        let store = original.clone();
        store.reset();
        store.fail_at.set(Some(fail_at));
        assert!(matches!(
            insert(&store, &current, entry(129), end),
            Err(Error::Store(StoreError::Unknown))
        ));
        assert!(store.calls.borrow().iter().all(|call| call.2 == end));
        store.reset();
        assert_eq!(collect(&store, &current, end).unwrap().len(), 128);
    }
    original.reset();
    original.fail_at.set(Some(1));
    assert!(matches!(
        empty(&original, 1, end),
        Err(Error::Store(StoreError::Unknown))
    ));
    original.reset();
    original.fail_at.set(Some(1));
    assert!(matches!(
        split(
            &original,
            RequestIndex::Leaf {
                epoch: 1,
                entries: vec![entry(1)]
            },
            end
        ),
        Err(Error::Store(StoreError::Unknown))
    ));
    original.reset();
    assert!(matches!(
        walk(&original, &current, end, |_| Err(Error::Denied)),
        Err(Error::Denied)
    ));
}

#[test]
fn missing_child_aborts_point_lookup_and_insertion_before_publication() {
    let store = Memory::default();
    let end = deadline();
    let original = two_leaves(&store, end);
    let Payload::Index(RequestIndex::Branch { children, .. }) =
        store.objects.borrow()[&original.root].clone()
    else {
        panic!()
    };
    store.objects.borrow_mut().remove(&children[1].hash);
    assert!(matches!(
        lookup(&store, &original, 100, end),
        Err(Error::Store(StoreError::Missing))
    ));
    store.reset();
    assert!(matches!(
        insert(&store, &original, entry(200), end),
        Err(Error::Store(StoreError::Missing))
    ));
    assert_eq!(store.counts(), (2, 0));
    assert_eq!(lookup(&store, &original, 1, end).unwrap(), Some(entry(1)));
}

#[test]
fn recursive_visitor_failure_and_duplicate_hash_with_forged_range_fail_closed() {
    let store = Memory::default();
    let end = deadline();
    let original = two_leaves(&store, end);
    assert!(matches!(
        walk(&store, &original, end, |_| Err(Error::Denied)),
        Err(Error::Denied)
    ));
    let Payload::Index(mut index) = store.objects.borrow()[&original.root].clone() else {
        panic!()
    };
    let RequestIndex::Branch { children, .. } = &mut index else {
        panic!()
    };
    children[1].hash = children[0].hash.clone();
    // The claims are sorted and non-overlapping; only loading the repeated
    // actual child exposes that its range and aggregate differ from the claim.
    index.validate().unwrap();
    store
        .objects
        .borrow_mut()
        .insert(original.root.clone(), Payload::Index(index));
    assert_eq!(lookup(&store, &original, 1, end).unwrap(), Some(entry(1)));
    assert!(matches!(
        walk(&store, &original, end, |_| Ok(())),
        Err(Error::Corrupt)
    ));
}

#[test]
fn full_walk_propagates_visitor_and_child_failure_without_skipping_entries() {
    let store = Memory::default();
    let end = deadline();
    let original = two_leaves(&store, end);
    let fail = Cell::new(false);
    let seen = Cell::new(0);
    let mut visitor = |_| {
        seen.set(seen.get() + 1);
        if fail.get() {
            Err(Error::Denied)
        } else {
            Ok(())
        }
    };
    walk(&store, &original, end, &mut visitor).unwrap();
    assert_eq!(seen.get(), 128);
    fail.set(true);
    assert!(matches!(
        walk(&store, &original, end, &mut visitor),
        Err(Error::Denied)
    ));
    assert_eq!(seen.get(), 129);
    fail.set(false);
    let Payload::Index(RequestIndex::Branch { children, .. }) =
        store.objects.borrow()[&original.root].clone()
    else {
        panic!()
    };
    store.objects.borrow_mut().remove(&children[1].hash);
    assert!(matches!(
        walk(&store, &original, end, &mut visitor),
        Err(Error::Store(StoreError::Missing))
    ));
    assert_eq!(seen.get(), 193);
}
