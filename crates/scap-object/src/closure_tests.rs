use super::*;
use crate::format::{digest, encode_object, Envelope, Manifest, StoredResult, Window};
use crate::tests::{deadline, scope, Memory};
use crate::{Database, Options};
use scap_object_store::{Condition, Objects, StoreError, Stored};
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

struct Read {
    key: String,
    deadline: Instant,
    maximum: usize,
    pointer: usize,
    bytes: usize,
}

#[derive(Default)]
struct Trace {
    memory: Memory,
    reads: Mutex<Vec<Read>>,
    writes: AtomicUsize,
    failure: Mutex<Option<(usize, StoreError)>>,
    stop_at: AtomicUsize,
    stopped: AtomicBool,
}

impl Objects for Trace {
    fn get(&self, key: &str, maximum: usize, end: Instant) -> Result<Stored, StoreError> {
        let mut reads = self.reads.lock().unwrap();
        reads.push(Read {
            key: key.into(),
            deadline: end,
            maximum,
            pointer: 0,
            bytes: 0,
        });
        if let Some((at, error)) = &*self.failure.lock().unwrap() {
            if reads.len() == *at {
                return Err(error.clone());
            }
        }
        let stored = self.memory.get(key, maximum, end)?;
        let observed = reads.last_mut().unwrap();
        observed.pointer = stored.bytes.as_ptr() as usize;
        observed.bytes = stored.bytes.len();
        if reads.len() == self.stop_at.load(Ordering::Relaxed) {
            self.stopped.store(true, Ordering::Release);
        }
        Ok(stored)
    }

    fn put(&self, _: &str, _: &[u8], _: Condition<'_>, _: Instant) -> Result<String, StoreError> {
        self.writes.fetch_add(1, Ordering::Relaxed);
        Err(StoreError::Invalid)
    }
}

struct Fixture {
    trace: Arc<Trace>,
    database: Database,
    snapshot: Snapshot,
    expected: Vec<String>,
}

fn not_stopped() -> bool {
    false
}

fn raw_result() -> Vec<u8> {
    scap_sql::encode_result(
        &scap_sql::TransactionResult {
            statements: vec![scap_sql::StatementResult {
                columns: vec!["original".into()],
                rows: vec![vec![scap_sql::Value::Real(-0.0)]],
                affected_rows: u64::MAX,
                last_insert_rowid: i64::MIN,
            }],
        },
        crate::options::durable_sql_limits(),
    )
    .unwrap()
}

fn identity(epoch: u64, id: u64) -> Request {
    Request {
        epoch,
        id,
        principal: 99,
        fingerprint: digest(format!("{epoch}:{id}").as_bytes()),
    }
}

fn put(trace: &Trace, payload: Payload) -> String {
    let raw = encode_object(&Envelope {
        format: 2,
        scope: scope(),
        payload,
    })
    .unwrap();
    put_raw(trace, raw)
}

fn put_raw(trace: &Trace, raw: Vec<u8>) -> String {
    let hash = digest(&raw);
    trace.memory.set(object_key(&scope(), 1, &hash), raw);
    hash
}

fn fixture(pages: u32, windows: u64) -> Fixture {
    assert!(pages <= 8193);
    let trace = Arc::new(Trace::default());
    let database = Database::new(trace.clone(), scope(), 10).unwrap();
    let mut chunks = Vec::new();
    for first in (1..=pages).step_by(32) {
        let count = (pages - first + 1).min(32);
        chunks.push(put(
            &trace,
            Payload::Chunk {
                first_page: first,
                bytes: vec![0x5a; count as usize * 4096],
            },
        ));
    }
    let mut expected = Vec::new();
    let root = if pages == 0 {
        None
    } else if pages <= 8192 {
        let node = put(
            &trace,
            Payload::Node {
                level: 0,
                first_chunk: 0,
                children: chunks.clone(),
            },
        );
        expected.push(node.clone());
        expected.extend(chunks);
        Some(node)
    } else {
        let left = put(
            &trace,
            Payload::Node {
                level: 0,
                first_chunk: 0,
                children: chunks[..256].to_vec(),
            },
        );
        let right = put(
            &trace,
            Payload::Node {
                level: 0,
                first_chunk: 256,
                children: chunks[256..].to_vec(),
            },
        );
        let node = put(
            &trace,
            Payload::Node {
                level: 1,
                first_chunk: 0,
                children: vec![left.clone(), right.clone()],
            },
        );
        expected.extend([node.clone(), left]);
        expected.extend(chunks[..256].iter().cloned());
        expected.push(right);
        expected.extend(chunks[256..].iter().cloned());
        Some(node)
    };
    let manifest = put(
        &trace,
        Payload::Manifest(Manifest {
            page_count: pages,
            root,
        }),
    );
    expected.insert(0, manifest.clone());
    let mut retained = Vec::new();
    let result = raw_result();
    for epoch in (1..=windows).rev() {
        let request = identity(epoch, 10);
        let hash = put(
            &trace,
            Payload::Result(StoredResult {
                request: request.clone(),
                sequence: 4,
                transition: Transition {
                    revision: 3,
                    nonce: 10,
                },
                data_root: digest(b"historical receipt identity, deliberately absent"),
                bytes: result.clone(),
            }),
        );
        let index = put(
            &trace,
            Payload::Index(RequestIndex::Leaf {
                epoch,
                entries: vec![
                    Entry {
                        request,
                        outcome: OutcomeRef::Committed {
                            result: hash.clone(),
                        },
                        result_bytes: result.len() as u64,
                    },
                    Entry {
                        request: identity(epoch, 90),
                        outcome: OutcomeRef::Cancelled {
                            transition: Transition {
                                revision: 2,
                                nonce: 90,
                            },
                        },
                        result_bytes: 0,
                    },
                ],
            }),
        );
        expected.extend([index.clone(), hash]);
        retained.push(Window {
            epoch,
            root: index,
            count: 2,
            result_bytes: result.len() as u64,
        });
    }
    let mut options = Options::default();
    options.retention.max_entries = 2;
    let head = crate::format::Head {
        format: 6,
        scope: scope(),
        head_serial: 11,
        storage: crate::format::Storage {
            active_generation: 1,
            allocated_through: 1,
            plan: None,
            sweep: None,
            terminal: None,
        },
        revision: 10,
        transition: Transition {
            revision: 10,
            nonce: 9,
        },
        sequence: 5,
        owner_epoch: 1,
        owner_instance: 10,
        owner_plan: None,
        active: true,
        auth_epoch: 1,
        policy: vec![crate::format::Permission {
            principal: 7,
            read: true,
            write: true,
            admin: true,
        }],
        lifecycle: crate::format::Lifecycle::Ready,
        creation: None,
        deletion: None,
        data_root: manifest,
        quota: options.quota,
        retention: options.retention,
        request_epoch: windows,
        windows: retained,
    };
    head.validate().unwrap();
    Fixture {
        trace,
        database,
        snapshot: Snapshot {
            head,
            etag: "original-head-etag".into(),
        },
        expected,
    }
}

fn drive(fixture: &Fixture, single: bool) -> Result<(ClosureTotals, Vec<String>), Error> {
    let context = ObjectContext::capture(&fixture.database, &fixture.snapshot.head).unwrap();
    let end = deadline();
    let stop = || fixture.trace.stopped.load(Ordering::Acquire);
    let mut cursor = Cursor::new(&context, &fixture.snapshot, end, &stop)?;
    let mut visited = Vec::new();
    loop {
        let reads_before = fixture.trace.reads.lock().unwrap().len();
        let budget = if single {
            StepBudget {
                max_frames: 1,
                max_read_bytes: MAX_OBJECT_BYTES as u64,
            }
        } else {
            StepBudget::default()
        };
        let max_frames = budget.max_frames;
        let max_read_bytes = budget.max_read_bytes;
        match cursor.advance(budget, &mut |frame| {
            let reads = fixture.trace.reads.lock().unwrap();
            let original = reads.last().unwrap();
            assert_eq!(frame.bytes.as_ptr() as usize, original.pointer);
            assert_eq!(frame.key, original.key);
            assert_eq!(digest(frame.bytes), frame.hash);
            assert_eq!(frame.scope, &fixture.snapshot.head.scope);
            assert_eq!(frame.storage_generation, 1);
            visited.push(frame.hash.to_owned());
            Ok(())
        })? {
            Step::Pending(next) => {
                let reads = fixture.trace.reads.lock().unwrap();
                let reads_after = reads.len();
                assert!(reads_after > reads_before);
                let frames = (reads_after - reads_before) as u32;
                let bytes: u64 = reads[reads_before..]
                    .iter()
                    .map(|read| read.bytes as u64)
                    .sum();
                assert!(frames <= max_frames);
                assert!(bytes <= max_read_bytes);
                assert!(frames == max_frames || max_read_bytes - bytes < MAX_OBJECT_BYTES as u64);
                if single {
                    assert_eq!(frames, 1);
                }
                assert!(next.depth <= MAX_PATH);
                cursor = next;
            }
            Step::Complete(proof) => {
                for read in fixture.trace.reads.lock().unwrap().iter() {
                    assert_eq!(read.deadline, end);
                    assert_eq!(read.maximum, MAX_OBJECT_BYTES);
                }
                assert_eq!(fixture.trace.writes.load(Ordering::Relaxed), 0);
                return Ok((proof.finish(&fixture.snapshot)?, visited));
            }
        }
    }
}

#[test]
fn complete_small_closures_resume_without_reencoding_or_revisiting_prefixes() {
    for (pages, windows) in [(0, 1), (1, 2), (32, 3), (33, 3), (8192, 1), (8193, 1)] {
        let fixture = fixture(pages, windows);
        let (totals, visited) = drive(&fixture, true).unwrap();
        assert_eq!(visited, fixture.expected);
        assert_eq!(totals.frames, visited.len() as u64);
        assert_eq!(totals.pages, pages as u64);
        assert_eq!(totals.chunks, pages.div_ceil(32) as u64);
        assert_eq!(fixture.trace.reads.lock().unwrap().len(), visited.len());
        for total in totals.windows.iter().take(windows as usize) {
            assert_eq!((total.entries, total.committed, total.cancelled), (2, 1, 1));
            assert_eq!(total.bytes, raw_result().len() as u64);
        }
        fixture.trace.reads.lock().unwrap().clear();
        let (batched, visited_again) = drive(&fixture, false).unwrap();
        assert_eq!(batched, totals);
        assert_eq!(visited_again, visited);
    }
}

fn payload(trace: &Trace, hash: &str) -> Payload {
    let stored = trace
        .memory
        .get(&object_key(&scope(), 1, hash), MAX_OBJECT_BYTES, deadline())
        .unwrap();
    crate::format::decode_object(&stored.bytes, &scope(), hash)
        .unwrap()
        .payload
}

fn replace_node(fixture: &mut Fixture, node: Payload) {
    let hash = put(&fixture.trace, node);
    fixture.snapshot.head.data_root = put(
        &fixture.trace,
        Payload::Manifest(Manifest {
            page_count: 33,
            root: Some(hash),
        }),
    );
}

fn expect_corrupt(fixture: &Fixture) {
    assert!(matches!(drive(fixture, true), Err(Error::Corrupt)));
    assert!(fixture.database.quarantined.load(Ordering::Acquire));
    assert_eq!(fixture.trace.writes.load(Ordering::Relaxed), 0);
}

#[test]
fn hash_valid_data_frames_still_obey_every_incoming_edge() {
    let first = fixture(33, 1);
    let node_hash = first.expected[1].clone();
    let Payload::Node { children, .. } = payload(&first.trace, &node_hash) else {
        panic!()
    };
    for (level, start, references) in [
        (1, 0, children.clone()),
        (0, 1, children.clone()),
        (0, 0, vec![children[0].clone()]),
        (0, 0, vec![children[0].clone(); 2]),
    ] {
        let mut fixture = fixture(33, 1);
        replace_node(
            &mut fixture,
            Payload::Node {
                level,
                first_chunk: start,
                children: references,
            },
        );
        expect_corrupt(&fixture);
    }
    for (position, first_page, pages) in [(0, 33, 32), (0, 1, 1), (1, 33, 32)] {
        let mut fixture = fixture(33, 1);
        let mut references = children.clone();
        references[position] = put(
            &fixture.trace,
            Payload::Chunk {
                first_page,
                bytes: vec![1; pages * PAGE_SIZE],
            },
        );
        replace_node(
            &mut fixture,
            Payload::Node {
                level: 0,
                first_chunk: 0,
                children: references,
            },
        );
        expect_corrupt(&fixture);
    }
    let mut wrong_kind = fixture(33, 1);
    wrong_kind.snapshot.head.data_root = wrong_kind.snapshot.head.windows[0].root.clone();
    expect_corrupt(&wrong_kind);
    let mut chunk_kind = fixture(33, 1);
    let mut references = children;
    references[0] = chunk_kind.snapshot.head.windows[0].root.clone();
    replace_node(
        &mut chunk_kind,
        Payload::Node {
            level: 0,
            first_chunk: 0,
            children: references,
        },
    );
    expect_corrupt(&chunk_kind);
}

fn leaf(
    trace: &Trace,
    first: u64,
    count: usize,
    epoch: u64,
    sequence: u64,
) -> (IndexChild, Vec<String>) {
    let raw = raw_result();
    let result = put(
        trace,
        Payload::Result(StoredResult {
            request: identity(epoch, first),
            sequence,
            transition: Transition {
                revision: 3,
                nonce: first,
            },
            data_root: digest(b"absent history"),
            bytes: raw.clone(),
        }),
    );
    let entries = (0..count)
        .map(|offset| Entry {
            request: identity(epoch, first + offset as u64),
            outcome: if offset == 0 {
                OutcomeRef::Committed {
                    result: result.clone(),
                }
            } else {
                OutcomeRef::Cancelled {
                    transition: Transition {
                        revision: 2,
                        nonce: first + offset as u64,
                    },
                }
            },
            result_bytes: if offset == 0 { raw.len() as u64 } else { 0 },
        })
        .collect();
    let hash = put(trace, Payload::Index(RequestIndex::Leaf { epoch, entries }));
    (
        IndexChild {
            hash: hash.clone(),
            summary: crate::format::IndexSummary {
                first,
                last: first + count as u64 - 1,
                count: count as u32,
                result_bytes: raw.len() as u64,
            },
        },
        vec![hash, result],
    )
}

fn index_fixture() -> Fixture {
    let mut fixture = fixture(0, 1);
    let (left, mut left_visits) = leaf(&fixture.trace, 1, 64, 1, 4);
    let (right, right_visits) = leaf(&fixture.trace, 1001, 64, 1, 1);
    let bytes = left.summary.result_bytes + right.summary.result_bytes;
    let root = put(
        &fixture.trace,
        Payload::Index(RequestIndex::Branch {
            epoch: 1,
            level: 1,
            children: vec![left, right],
        }),
    );
    fixture.snapshot.head.retention.max_entries = 128;
    fixture.snapshot.head.windows[0] = Window {
        epoch: 1,
        root: root.clone(),
        count: 128,
        result_bytes: bytes,
    };
    fixture.expected = vec![fixture.snapshot.head.data_root.clone(), root];
    fixture.expected.append(&mut left_visits);
    fixture.expected.extend(right_visits);
    fixture
}

fn replace_index_root(fixture: &mut Fixture, index: RequestIndex) {
    let summary = index.summary();
    let root = put(&fixture.trace, Payload::Index(index));
    fixture.snapshot.head.windows[0] = Window {
        epoch: 1,
        root,
        count: summary.count,
        result_bytes: summary.result_bytes,
    };
    fixture.snapshot.head.retention.max_entries = summary.count.max(1);
}

#[test]
fn btree_ranges_occupancy_epochs_and_level_descent_are_checked_in_full() {
    let fixture = index_fixture();
    let (totals, actual) = drive(&fixture, true).unwrap();
    assert_eq!(actual, fixture.expected);
    assert_eq!(
        (totals.windows[0].entries, totals.windows[0].committed),
        (128, 2)
    );
    // The later request ID has the earlier commit sequence, and principal 99
    // is absent from today's ACL. Neither fact invalidates retained bytes.
    for case in 0..7 {
        let mut fixture = index_fixture();
        let Payload::Index(RequestIndex::Branch { mut children, .. }) =
            payload(&fixture.trace, &fixture.snapshot.head.windows[0].root)
        else {
            panic!()
        };
        match case {
            0 => children[0].hash = leaf(&fixture.trace, 1, 63, 1, 4).0.hash,
            1 => children[0].hash = leaf(&fixture.trace, 1, 65, 1, 4).0.hash,
            2 => children[0].hash = leaf(&fixture.trace, 1, 64, 2, 4).0.hash,
            3 => children[0].summary.result_bytes += 1,
            4 => children[1].hash = children[0].hash.clone(),
            5 => children[0].hash = fixture.snapshot.head.windows[0].root.clone(),
            _ => children[0].hash = fixture.snapshot.head.data_root.clone(),
        }
        replace_index_root(
            &mut fixture,
            RequestIndex::Branch {
                epoch: 1,
                level: 1,
                children,
            },
        );
        expect_corrupt(&fixture);
    }
    // An individually valid, root-sized branch is too small as a non-root.
    let mut underfull = index_fixture();
    let original = underfull.snapshot.head.windows[0].root.clone();
    replace_index_root(
        &mut underfull,
        RequestIndex::Branch {
            epoch: 1,
            level: 2,
            children: vec![
                IndexChild {
                    hash: original.clone(),
                    summary: crate::format::IndexSummary {
                        first: 1,
                        last: 2048,
                        count: 1024,
                        result_bytes: 0,
                    },
                },
                IndexChild {
                    hash: original,
                    summary: crate::format::IndexSummary {
                        first: 2049,
                        last: 4096,
                        count: 1024,
                        result_bytes: 0,
                    },
                },
            ],
        },
    );
    expect_corrupt(&underfull);
    for counter in [false, true] {
        let mut fixture = index_fixture();
        if counter {
            fixture.snapshot.head.windows[0].count -= 1;
        } else {
            fixture.snapshot.head.windows[0].result_bytes -= 1;
        }
        expect_corrupt(&fixture);
    }
    let mut foreign_root = self::fixture(0, 1);
    foreign_root.snapshot.head.windows[0].root = leaf(&foreign_root.trace, 1, 2, 2, 1).0.hash;
    expect_corrupt(&foreign_root);
}

#[test]
fn retained_result_binding_length_and_wire_failures_are_not_hidden_by_valid_hashes() {
    for case in 0..7 {
        let mut fixture = fixture(0, 1);
        let Payload::Index(RequestIndex::Leaf { mut entries, .. }) =
            payload(&fixture.trace, &fixture.snapshot.head.windows[0].root)
        else {
            panic!()
        };
        let OutcomeRef::Committed { result } = &entries[0].outcome else {
            panic!()
        };
        let Payload::Result(mut stored) = payload(&fixture.trace, result) else {
            panic!()
        };
        match case {
            0 => stored.request.id += 1,
            1 => stored.sequence = fixture.snapshot.head.sequence + 1,
            2 => stored.transition.revision = fixture.snapshot.head.revision + 1,
            3 => entries[0].result_bytes += 1,
            4 => {
                stored.bytes.push(0);
                entries[0].result_bytes += 1;
            }
            5 => {
                stored.bytes.clear();
                entries[0].result_bytes = 0;
            }
            _ => {
                entries[1].outcome = OutcomeRef::Cancelled {
                    transition: Transition {
                        revision: fixture.snapshot.head.revision + 1,
                        nonce: 1,
                    },
                }
            }
        }
        entries[0].outcome = OutcomeRef::Committed {
            result: put(&fixture.trace, Payload::Result(stored)),
        };
        replace_index_root(&mut fixture, RequestIndex::Leaf { epoch: 1, entries });
        expect_corrupt(&fixture);
    }
}

#[test]
fn callback_errors_do_not_quarantine_source_and_completions_keep_original_identity() {
    for error in [Error::Corrupt, Error::Store(StoreError::Corrupt)] {
        let fixture = fixture(0, 1);
        let context = ObjectContext::capture(&fixture.database, &fixture.snapshot.head).unwrap();
        let cursor = Cursor::new(&context, &fixture.snapshot, deadline(), &not_stopped).unwrap();
        let mut error = Some(error);
        assert!(cursor
            .advance(StepBudget::default(), &mut |_| Err(error.take().unwrap()))
            .is_err());
        assert_eq!(fixture.trace.reads.lock().unwrap().len(), 1);
        assert!(!fixture.database.quarantined.load(Ordering::Acquire));
    }
    for changed_body in [false, true] {
        let fixture = fixture(0, 1);
        let context = ObjectContext::capture(&fixture.database, &fixture.snapshot.head).unwrap();
        let cursor = Cursor::new(&context, &fixture.snapshot, deadline(), &not_stopped).unwrap();
        let Step::Complete(proof) = cursor
            .advance(StepBudget::default(), &mut |_| Ok(()))
            .unwrap()
        else {
            panic!()
        };
        let mut foreign = fixture.snapshot.clone();
        if changed_body {
            foreign.head.sequence += 1;
        } else {
            foreign.etag.push('x');
        }
        assert!(matches!(proof.finish(&foreign), Err(Error::StaleSnapshot)));
    }
    let fixture = fixture(0, 1);
    let context = ObjectContext::capture(&fixture.database, &fixture.snapshot.head).unwrap();
    let stopped = Cell::new(false);
    let stop = || stopped.get();
    let cursor = Cursor::new(&context, &fixture.snapshot, deadline(), &stop).unwrap();
    let Step::Complete(proof) = cursor
        .advance(StepBudget::default(), &mut |_| Ok(()))
        .unwrap()
    else {
        panic!()
    };
    stopped.set(true);
    assert!(matches!(
        proof.finish(&fixture.snapshot),
        Err(Error::Unknown)
    ));
    assert!(!fixture.database.quarantined.load(Ordering::Acquire));
}

#[test]
fn every_unknown_or_missing_read_cut_consumes_the_prefix_without_success() {
    let total = fixture(33, 3).expected.len();
    for error in [StoreError::Unknown, StoreError::Missing] {
        for at in 1..=total {
            let fixture = fixture(33, 3);
            *fixture.trace.failure.lock().unwrap() = Some((at, error.clone()));
            assert!(
                matches!(drive(&fixture, true), Err(Error::Store(ref actual)) if *actual == error)
            );
            assert_eq!(
                fixture.trace.reads.lock().unwrap().len(),
                at + usize::from(error == StoreError::Missing)
            );
            assert!(!fixture.database.quarantined.load(Ordering::Acquire));
            assert_eq!(
                fixture.database.healthy().is_err(),
                error == StoreError::Missing
            );
        }
    }
}

#[test]
fn stop_deadline_and_budget_boundaries_never_quarantine_or_create_a_completion() {
    let fixture = fixture(33, 1);
    let context = ObjectContext::capture(&fixture.database, &fixture.snapshot.head).unwrap();
    let stopped = Cell::new(false);
    let stop = || stopped.get();
    assert!(matches!(
        Cursor::new(&context, &fixture.snapshot, Instant::now(), &stop),
        Err(Error::Unknown)
    ));
    stopped.set(true);
    assert!(matches!(
        Cursor::new(&context, &fixture.snapshot, deadline(), &stop),
        Err(Error::Unknown)
    ));
    stopped.set(false);
    for budget in [
        StepBudget {
            max_frames: 0,
            max_read_bytes: MAX_OBJECT_BYTES as u64,
        },
        StepBudget {
            max_frames: 1,
            max_read_bytes: MAX_OBJECT_BYTES as u64 - 1,
        },
    ] {
        let cursor = Cursor::new(&context, &fixture.snapshot, deadline(), &stop).unwrap();
        assert!(matches!(
            cursor.advance(budget, &mut |_| Ok(())),
            Err(Error::Limit)
        ));
    }
    assert!(fixture.trace.reads.lock().unwrap().is_empty());
    let cursor = Cursor::new(&context, &fixture.snapshot, deadline(), &stop).unwrap();
    assert!(matches!(
        cursor.advance(StepBudget::default(), &mut |_| {
            stopped.set(true);
            Ok(())
        }),
        Err(Error::Unknown)
    ));
    assert_eq!(fixture.trace.reads.lock().unwrap().len(), 1);
    assert!(!fixture.database.quarantined.load(Ordering::Acquire));

    let late = self::fixture(0, 1);
    late.trace.stop_at.store(1, Ordering::Relaxed);
    assert!(matches!(drive(&late, true), Err(Error::Unknown)));
    assert!(!late.database.quarantined.load(Ordering::Acquire));
}

fn pretty(trace: &Trace, payload: Payload) -> String {
    let original = encode_object(&Envelope {
        format: 2,
        scope: scope(),
        payload,
    })
    .unwrap();
    let metadata = u32::from_le_bytes(original[8..12].try_into().unwrap()) as usize;
    let value: serde_json::Value = serde_json::from_slice(&original[20..20 + metadata]).unwrap();
    let json = format!(
        "\n{}\t ",
        serde_json::to_string_pretty(&value)
            .unwrap()
            .replace("result", "res\\u0075lt")
    );
    let raw = &original[20 + metadata..];
    let mut frame = b"SCAPOBJ2".to_vec();
    frame.extend_from_slice(&(json.len() as u32).to_le_bytes());
    frame.extend_from_slice(&(raw.len() as u64).to_le_bytes());
    frame.extend_from_slice(json.as_bytes());
    frame.extend_from_slice(raw);
    assert_ne!(digest(&frame), digest(&original));
    put_raw(trace, frame)
}

#[test]
fn noncanonical_original_bytes_and_valid_maximum_results_are_not_materialized_twice() {
    for maximum in [false, true] {
        let mut fixture = fixture(0, 1);
        let bytes = if maximum {
            let make = |blob| scap_sql::TransactionResult {
                statements: vec![scap_sql::StatementResult {
                    columns: vec!["x".into()],
                    rows: vec![vec![scap_sql::Value::Blob(blob)]],
                    affected_rows: 0,
                    last_insert_rowid: 0,
                }],
            };
            let overhead =
                scap_sql::encode_result(&make(Vec::new()), crate::options::durable_sql_limits())
                    .unwrap()
                    .len();
            let encoded = scap_sql::encode_result(
                &make(vec![0xa7; crate::format::MAX_RESULT_BYTES - overhead]),
                crate::options::durable_sql_limits(),
            )
            .unwrap();
            assert_eq!(encoded.len(), crate::format::MAX_RESULT_BYTES);
            encoded
        } else {
            raw_result()
        };
        fixture.database.options.sql.max_result_bytes = 128;
        fixture.database.options.sql.max_value_bytes = 128;
        fixture.database.options.validate().unwrap();
        let request = identity(1, 1000);
        let result = pretty(
            &fixture.trace,
            Payload::Result(StoredResult {
                request: request.clone(),
                sequence: 1,
                transition: Transition {
                    revision: 2,
                    nonce: request.id,
                },
                data_root: digest(b"receipt identity is not a retained edge"),
                bytes: bytes.clone(),
            }),
        );
        let index = pretty(
            &fixture.trace,
            Payload::Index(RequestIndex::Leaf {
                epoch: 1,
                entries: vec![Entry {
                    request,
                    outcome: OutcomeRef::Committed {
                        result: result.clone(),
                    },
                    result_bytes: bytes.len() as u64,
                }],
            }),
        );
        let manifest = pretty(
            &fixture.trace,
            Payload::Manifest(Manifest {
                page_count: 0,
                root: None,
            }),
        );
        fixture.snapshot.head.data_root = manifest.clone();
        fixture.snapshot.head.windows[0] = Window {
            epoch: 1,
            root: index.clone(),
            count: 1,
            result_bytes: bytes.len() as u64,
        };
        fixture.expected = vec![manifest, index, result];
        let (totals, visited) = drive(&fixture, true).unwrap();
        assert_eq!(visited, fixture.expected);
        assert_eq!(totals.windows[0].bytes, bytes.len() as u64);
        assert_eq!(fixture.trace.reads.lock().unwrap().len(), 3);
    }
}

#[test]
fn highest_data_geometry_is_a_verified_prefix_not_a_full_capacity_claim() {
    let mut fixture = fixture(0, 1);
    let mut child = put(
        &fixture.trace,
        Payload::Chunk {
            first_page: 1,
            bytes: vec![0; 32 * 4096],
        },
    );
    let mut expected = vec![child.clone()];
    for level in 0..=3 {
        let width = if level == 3 { 8 } else { 256 };
        let mut children = vec![child];
        children.extend((1..width).map(|i| digest(format!("unfetched:{level}:{i}").as_bytes())));
        child = put(
            &fixture.trace,
            Payload::Node {
                level,
                first_chunk: 0,
                children,
            },
        );
        expected.push(child.clone());
    }
    let manifest = put(
        &fixture.trace,
        Payload::Manifest(Manifest {
            page_count: crate::format::MAX_PAGES,
            root: Some(child),
        }),
    );
    expected.push(manifest.clone());
    expected.reverse();
    fixture.snapshot.head.data_root = manifest;
    fixture.snapshot.head.quota.max_bytes = None;
    let context = ObjectContext::capture(&fixture.database, &fixture.snapshot.head).unwrap();
    let cursor = Cursor::new(&context, &fixture.snapshot, deadline(), &not_stopped).unwrap();
    let mut visited = Vec::new();
    let Step::Pending(cursor) = cursor
        .advance(
            StepBudget {
                max_frames: 6,
                max_read_bytes: 2 * MAX_OBJECT_BYTES as u64,
            },
            &mut |frame| {
                visited.push(frame.hash.to_owned());
                Ok(())
            },
        )
        .unwrap()
    else {
        panic!("a prefix cannot certify the omitted tree")
    };
    assert_eq!(fixture.trace.reads.lock().unwrap().len(), 6);
    assert_eq!(visited, expected);
    assert_eq!(cursor.depth, 4);
    assert_eq!(cursor.totals.pages, 32);
    assert!(matches!(
        cursor.advance(StepBudget::default(), &mut |_| Ok(())),
        Err(Error::Store(StoreError::Missing))
    ));
    assert_eq!(fixture.trace.reads.lock().unwrap().len(), 8);
    assert_eq!(
        fixture.trace.reads.lock().unwrap().last().unwrap().key,
        crate::format::head_key(&fixture.snapshot.head.scope)
    );
}

fn branch(
    trace: &Trace,
    level: u8,
    children: Vec<(IndexChild, Vec<String>)>,
) -> (IndexChild, Vec<String>) {
    let summary = crate::format::IndexSummary {
        first: children.first().unwrap().0.summary.first,
        last: children.last().unwrap().0.summary.last,
        count: children.iter().map(|item| item.0.summary.count).sum(),
        result_bytes: children
            .iter()
            .map(|item| item.0.summary.result_bytes)
            .sum(),
    };
    let hash = put(
        trace,
        Payload::Index(RequestIndex::Branch {
            epoch: 1,
            level,
            children: children.iter().map(|item| item.0.clone()).collect(),
        }),
    );
    let mut visits = vec![hash.clone()];
    for (_, subtree) in children {
        visits.extend(subtree);
    }
    (IndexChild { hash, summary }, visits)
}

#[test]
fn a_complete_maximum_height_request_index_checks_every_retained_entry() {
    let mut fixture = fixture(0, 1);
    let mut second = Vec::new();
    let mut first = 1;
    for _ in 0..2 {
        let mut first_level = Vec::new();
        for _ in 0..16 {
            let mut leaves = Vec::new();
            for _ in 0..16 {
                leaves.push(leaf(&fixture.trace, first, 64, 1, 1));
                first += 1000;
            }
            first_level.push(branch(&fixture.trace, 1, leaves));
        }
        second.push(branch(&fixture.trace, 2, first_level));
    }
    let (root, visits) = branch(&fixture.trace, 3, second);
    fixture.snapshot.head.retention.max_entries = 32768;
    fixture.snapshot.head.windows[0] = Window {
        epoch: 1,
        root: root.hash,
        count: root.summary.count,
        result_bytes: root.summary.result_bytes,
    };
    fixture.expected = vec![fixture.snapshot.head.data_root.clone()];
    fixture.expected.extend(visits);
    let (totals, visited) = drive(&fixture, false).unwrap();
    assert_eq!(visited, fixture.expected);
    assert_eq!(totals.frames, 1060);
    assert_eq!(
        (
            totals.windows[0].entries,
            totals.windows[0].committed,
            totals.windows[0].cancelled
        ),
        (32768, 512, 32256)
    );
}

#[test]
fn namespace_original_head_and_byte_budget_admission_are_bound_without_new_reads() {
    let fixture = fixture(0, 1);
    for change_scope in [false, true] {
        let mut foreign = fixture.snapshot.head.clone();
        if change_scope {
            foreign.scope.generation += 1;
        } else {
            foreign.storage.active_generation += 1;
        }
        let context = ObjectContext::capture(&fixture.database, &foreign).unwrap();
        assert!(matches!(
            Cursor::new(&context, &fixture.snapshot, deadline(), &not_stopped),
            Err(Error::StaleSnapshot)
        ));
    }
    let context = ObjectContext::capture(&fixture.database, &fixture.snapshot.head).unwrap();
    let mut invalid = fixture.snapshot.clone();
    invalid.head.format = 4;
    assert!(matches!(
        Cursor::new(&context, &invalid, deadline(), &not_stopped),
        Err(Error::Format(_))
    ));
    assert!(fixture.trace.reads.lock().unwrap().is_empty());
    let cursor = Cursor::new(&context, &fixture.snapshot, deadline(), &not_stopped).unwrap();
    let Step::Pending(cursor) = cursor
        .advance(
            StepBudget {
                max_frames: 64,
                max_read_bytes: MAX_OBJECT_BYTES as u64,
            },
            &mut |_| Ok(()),
        )
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(cursor.totals.frames, 1);
    assert_eq!(fixture.trace.reads.lock().unwrap().len(), 1);
    assert!(fixture.trace.reads.lock().unwrap()[0].bytes < MAX_OBJECT_BYTES);
}

#[test]
fn copy_cursor_requires_exact_plan_basis_and_original_source_context() {
    let mut fixture = fixture(0, 1);
    fixture.snapshot.head.active = false;
    fixture.snapshot.head.storage.allocated_through = 2;
    let mut plan = crate::format::CopyPlan {
        serial: 11,
        source: 1,
        target: 2,
        phase: crate::format::CopyPhase::Copying,
        basis: crate::format::CopyBasis::capture(&fixture.snapshot.head),
    };
    fixture.snapshot.head.storage.plan = Some(plan.clone());
    let context = ObjectContext::capture(&fixture.database, &fixture.snapshot.head).unwrap();
    plan.target = 3;
    assert!(matches!(
        Cursor::for_copy(&context, &fixture.snapshot, &plan, deadline(), &not_stopped),
        Err(Error::Conflict)
    ));
    assert!(matches!(
        ObjectContext::target(&fixture.database, &fixture.snapshot, &plan, deadline()),
        Err(Error::Conflict)
    ));
    plan.target = 2;
    plan.basis.sequence += 1;
    fixture.snapshot.head.storage.plan = Some(plan.clone());
    assert!(matches!(
        Cursor::for_copy(&context, &fixture.snapshot, &plan, deadline(), &not_stopped),
        Err(Error::Conflict)
    ));
    assert!(matches!(
        ObjectContext::target(&fixture.database, &fixture.snapshot, &plan, deadline()),
        Err(Error::Conflict)
    ));
    plan.basis.sequence -= 1;
    fixture.snapshot.head.storage.plan = Some(plan.clone());
    let mut foreign = fixture.snapshot.head.clone();
    foreign.scope.generation += 1;
    let foreign = ObjectContext::capture(&fixture.database, &foreign).unwrap();
    assert!(matches!(
        Cursor::for_copy(&foreign, &fixture.snapshot, &plan, deadline(), &not_stopped),
        Err(Error::StaleSnapshot)
    ));
    assert!(fixture.trace.reads.lock().unwrap().is_empty());
}

#[test]
fn a_later_acl_revision_cannot_legitimize_results_or_cancellation_newer_than_copy_basis() {
    for cancelled in [false, true] {
        let mut fixture = fixture(0, 1);
        if cancelled {
            let root = put(
                &fixture.trace,
                Payload::Index(RequestIndex::Leaf {
                    epoch: 1,
                    entries: vec![Entry {
                        request: identity(1, 1),
                        outcome: OutcomeRef::Cancelled {
                            transition: Transition {
                                revision: 2,
                                nonce: 1,
                            },
                        },
                        result_bytes: 0,
                    }],
                }),
            );
            fixture.snapshot.head.windows[0].root = root;
            fixture.snapshot.head.windows[0].count = 1;
            fixture.snapshot.head.windows[0].result_bytes = 0;
        }
        fixture.snapshot.head.active = false;
        fixture.snapshot.head.storage.allocated_through = 2;
        let mut basis = crate::format::CopyBasis::capture(&fixture.snapshot.head);
        basis.revision = 1;
        let plan = crate::format::CopyPlan {
            serial: 11,
            source: 1,
            target: 2,
            phase: crate::format::CopyPhase::Copying,
            basis,
        };
        fixture.snapshot.head.storage.plan = Some(plan.clone());
        fixture.snapshot.head.validate().unwrap();
        let context = ObjectContext::capture(&fixture.database, &fixture.snapshot.head).unwrap();
        let cursor =
            Cursor::for_copy(&context, &fixture.snapshot, &plan, deadline(), &not_stopped).unwrap();
        assert!(matches!(
            cursor.advance(StepBudget::default(), &mut |_| Ok(())),
            Err(Error::Corrupt)
        ));
        assert!(fixture.database.quarantined.load(Ordering::Relaxed));
    }
}

#[test]
fn existing_verifier_drives_multiple_steps_without_restarting_the_prefix() {
    let fixture = fixture(2048, 1);
    assert!(fixture.expected.len() > StepBudget::default().max_frames as usize);
    let context = ObjectContext::capture(&fixture.database, &fixture.snapshot.head).unwrap();
    let end = deadline();
    fixture
        .database
        .verify_closure(&context, &fixture.snapshot, end)
        .unwrap();
    let reads = fixture.trace.reads.lock().unwrap();
    assert_eq!(reads.len(), fixture.expected.len());
    for (read, hash) in reads.iter().zip(&fixture.expected) {
        assert_eq!(read.key, object_key(&fixture.snapshot.head.scope, 1, hash));
        assert_eq!(read.deadline, end);
        assert_eq!(read.maximum, MAX_OBJECT_BYTES);
    }
    assert_eq!(fixture.trace.writes.load(Ordering::Relaxed), 0);
}

#[test]
fn every_observed_stop_checkpoint_withholds_completion_without_quarantine() {
    let fixture = fixture(33, 3);
    let calls = Cell::new(0);
    let stop_at = Cell::new(usize::MAX);
    let visits = Cell::new(0);
    let stop = || {
        calls.set(calls.get() + 1);
        calls.get() == stop_at.get()
    };
    let run = || {
        let context = ObjectContext::capture(&fixture.database, &fixture.snapshot.head).unwrap();
        let cursor = Cursor::new(&context, &fixture.snapshot, deadline(), &stop)?;
        match cursor.advance(StepBudget::default(), &mut |_| {
            visits.set(visits.get() + 1);
            Ok(())
        })? {
            Step::Complete(proof) => proof.finish(&fixture.snapshot),
            Step::Pending(_) => panic!("this small graph fits in one step"),
        }
    };
    assert_eq!(run().unwrap().frames, fixture.expected.len() as u64);
    let checkpoints = calls.get();
    for cut in 1..=checkpoints {
        calls.set(0);
        visits.set(0);
        stop_at.set(cut);
        fixture.trace.reads.lock().unwrap().clear();
        assert!(
            matches!(run(), Err(Error::Unknown)),
            "stop checkpoint {cut}"
        );
        assert_eq!(calls.get(), cut);
        let reads = fixture.trace.reads.lock().unwrap().len();
        assert!(reads <= fixture.expected.len());
        assert!(visits.get() <= reads);
        assert!(!fixture.database.quarantined.load(Ordering::Acquire));
        assert_eq!(fixture.trace.writes.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn private_accounting_and_path_guards_fail_closed_before_any_completion() {
    // The opaque cursor cannot be supplied by a client. Injecting these local
    // counter faults checks its defensive bounds without pretending that a
    // format-valid closure can naturally contain u64::MAX frames or entries.
    for counter in 0..9 {
        let fixture = fixture(1, 1);
        let context = ObjectContext::capture(&fixture.database, &fixture.snapshot.head).unwrap();
        let mut cursor =
            Cursor::new(&context, &fixture.snapshot, deadline(), &not_stopped).unwrap();
        match counter {
            0 => cursor.totals.frames = u64::MAX,
            1 => cursor.totals.frame_bytes = u64::MAX,
            2 => cursor.totals.pages = u64::MAX,
            3 => cursor.totals.chunks = u64::MAX,
            4 => cursor.totals.windows[0].entries = u64::MAX,
            5 => cursor.totals.windows[0].bytes = u64::MAX,
            6 => cursor.totals.windows[0].committed = u64::MAX,
            7 => cursor.totals.windows[0].cancelled = u64::MAX,
            8 => cursor.totals.windows[0].last_id = 10,
            _ => unreachable!(),
        }
        let outcome = cursor.advance(StepBudget::default(), &mut |_| Ok(()));
        if counter == 8 {
            assert!(matches!(outcome, Err(Error::Corrupt)));
            assert!(fixture.database.quarantined.load(Ordering::Acquire));
        } else {
            assert!(matches!(outcome, Err(Error::Limit)), "counter {counter}");
            assert!(!fixture.database.quarantined.load(Ordering::Acquire));
        }
        assert_eq!(fixture.trace.writes.load(Ordering::Relaxed), 0);
    }

    let fixture = fixture(0, 1);
    let context = ObjectContext::capture(&fixture.database, &fixture.snapshot.head).unwrap();
    let mut cursor = Cursor::new(&context, &fixture.snapshot, deadline(), &not_stopped).unwrap();
    assert!(matches!(cursor.entry(3, 1, 0, false), Err(Error::Corrupt)));
    for index_action in [false, true] {
        let mut cursor =
            Cursor::new(&context, &fixture.snapshot, deadline(), &not_stopped).unwrap();
        for _ in 0..MAX_PATH {
            cursor
                .push(PathFrame::Entries {
                    window: 0,
                    entries: Vec::new().into_iter(),
                })
                .unwrap();
        }
        let action = if index_action {
            Action::Index {
                window: 0,
                index: RequestIndex::Leaf {
                    epoch: 1,
                    entries: Vec::new(),
                },
            }
        } else {
            Action::Node {
                level: 0,
                first: 0,
                pages: 1,
                children: vec![digest(b"bounded pending child")],
            }
        };
        assert!(matches!(cursor.apply(action, 1), Err(Error::Limit)));
        assert_eq!(cursor.depth, MAX_PATH);
        assert_eq!(
            cursor.path.iter().filter(|slot| slot.is_some()).count(),
            MAX_PATH
        );
    }
    assert!(fixture.trace.reads.lock().unwrap().is_empty());
}

#[test]
fn raw_edge_checks_reject_wrong_physical_key_and_out_of_range_window() {
    let fixture = fixture(0, 1);
    let context = ObjectContext::capture(&fixture.database, &fixture.snapshot.head).unwrap();
    let cursor = Cursor::new(&context, &fixture.snapshot, deadline(), &not_stopped).unwrap();
    let hash = &fixture.snapshot.head.windows[0].root;
    let key = object_key(&fixture.snapshot.head.scope, 1, hash);
    let stored = fixture
        .trace
        .memory
        .get(&key, MAX_OBJECT_BYTES, deadline())
        .unwrap();
    for case in 0..3 {
        let frame =
            crate::format::ValidatedFrame::parse(&stored.bytes, &fixture.snapshot.head.scope, hash)
                .unwrap();
        let parts = frame.into_parts();
        let Payload::Index(index) = &parts.metadata else {
            panic!()
        };
        let role = match case {
            0 => Role::Window { window: 0 },
            1 => Role::Window { window: 3 },
            _ => Role::Child {
                window: 3,
                level: 0,
                reference: IndexChild {
                    hash: hash.clone(),
                    summary: index.summary(),
                },
            },
        };
        let physical_key = if case == 0 {
            object_key(&fixture.snapshot.head.scope, 2, hash)
        } else {
            key.clone()
        };
        let visit = FrameVisit {
            scope: &fixture.snapshot.head.scope,
            storage_generation: 1,
            hash,
            key: &physical_key,
            role: &role,
            bytes: parts.frame,
        };
        assert!(matches!(
            cursor.action(&visit, parts.metadata, parts.raw),
            Err(Error::Corrupt)
        ));
    }

    // A caller cannot mutate Basis through the API. Keep the pure quota-error
    // boundary covered independently of Cursor::new's HEAD validation.
    let mut invalid = fixture.snapshot.clone();
    invalid.head.quota.max_bytes = Some(1);
    let mut cursor = Cursor::new(&context, &fixture.snapshot, deadline(), &not_stopped).unwrap();
    cursor.basis.snapshot = &invalid;
    let hash = &fixture.snapshot.head.data_root;
    let key = object_key(&fixture.snapshot.head.scope, 1, hash);
    let stored = fixture
        .trace
        .memory
        .get(&key, MAX_OBJECT_BYTES, deadline())
        .unwrap();
    let parts =
        crate::format::ValidatedFrame::parse(&stored.bytes, &fixture.snapshot.head.scope, hash)
            .unwrap()
            .into_parts();
    let visit = FrameVisit {
        scope: &fixture.snapshot.head.scope,
        storage_generation: 1,
        hash,
        key: &key,
        role: &Role::Manifest,
        bytes: parts.frame,
    };
    assert!(matches!(
        cursor.action(&visit, parts.metadata, parts.raw),
        Err(Error::Format(_))
    ));
    assert!(fixture.trace.reads.lock().unwrap().is_empty());
    assert!(!fixture.database.quarantined.load(Ordering::Acquire));
}

#[test]
fn completion_rejects_inconsistent_totals_of_an_actually_verified_graph() {
    for fault in 0..6 {
        let fixture = fixture(1, 1);
        let context = ObjectContext::capture(&fixture.database, &fixture.snapshot.head).unwrap();
        let cursor = Cursor::new(&context, &fixture.snapshot, deadline(), &not_stopped).unwrap();
        let Step::Complete(proof) = cursor
            .advance(StepBudget::default(), &mut |_| Ok(()))
            .unwrap()
        else {
            panic!()
        };
        // Inject one inconsistency into actual collected totals. There is no
        // externally constructible cursor or resume token for this state.
        let mut cursor = Box::new(Cursor {
            basis: proof.basis,
            totals: proof.totals,
            next: None,
            next_window: 1,
            path: std::array::from_fn(|_| None),
            depth: 0,
            manifest_pages: 1,
        });
        match fault {
            0 => cursor.totals.pages = 0,
            1 => cursor.totals.chunks = 0,
            2 => cursor.totals.windows[0].entries = 1,
            3 => cursor.totals.windows[0].bytes -= 1,
            4 => cursor.totals.windows[0].cancelled = 0,
            5 => cursor.totals.windows[0].committed = u64::MAX,
            _ => unreachable!(),
        }
        let result = cursor.complete();
        if fault == 5 {
            assert!(matches!(result, Err(Error::Limit)));
            assert!(!fixture.database.quarantined.load(Ordering::Acquire));
        } else {
            assert!(matches!(result, Err(Error::Corrupt)));
            assert!(fixture.database.quarantined.load(Ordering::Acquire));
        }
        assert_eq!(
            fixture.trace.reads.lock().unwrap().len(),
            fixture.expected.len()
        );
        assert_eq!(fixture.trace.writes.load(Ordering::Relaxed), 0);
    }
}
