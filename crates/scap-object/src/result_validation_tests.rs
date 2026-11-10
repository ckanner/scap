//! Correct hashes and envelope metadata are insufficient for retained results.
//! These fixtures inject a new, correctly hashed Result and Index referenced
//! by HEAD, so failures cannot be attributed to an outer digest mismatch.

use super::tests::{deadline, fixture, identity, scope, sql, test_options, Memory};
use super::*;
use scap_object_store::Stored;
use scap_sql::{StatementResult, Value};

fn valid_result() -> Vec<u8> {
    scap_sql::encode_result(
        &TransactionResult {
            statements: vec![StatementResult {
                columns: vec!["n".into(), "r".into(), "b".into()],
                rows: vec![vec![
                    Value::Integer(i64::MIN),
                    Value::Real(-0.0),
                    Value::Blob(vec![0, 255, 42]),
                ]],
                affected_rows: u64::MAX,
                last_insert_rowid: i64::MAX,
            }],
        },
        durable_sql_limits(),
    )
    .unwrap()
}

fn install(
    bytes: Vec<u8>,
    closed: bool,
    inactive: bool,
) -> (Arc<Memory>, Database, Request, Stored) {
    let (objects, database) = fixture();
    let request = identity(1);
    let mut head = database.read_head(deadline()).unwrap().head;
    head.revision += 1;
    head.head_serial += 1;
    head.transition = Transition {
        revision: head.revision,
        nonce: request.id,
    };
    head.sequence = 1;
    head.active = !inactive;
    let length = bytes.len() as u64;
    let root = ObjectContext::bootstrap(&database)
        .unwrap()
        .save(
            Payload::Result(StoredResult {
                request: request.clone(),
                sequence: 1,
                transition: head.transition.clone(),
                data_root: head.data_root.clone(),
                bytes,
            }),
            deadline(),
        )
        .unwrap();
    let root = ObjectContext::bootstrap(&database)
        .unwrap()
        .save(
            crate::tests::index_payload(
                1,
                vec![Entry {
                    result_bytes: length,
                    request: request.clone(),
                    outcome: OutcomeRef::Committed { result: root },
                }],
            ),
            deadline(),
        )
        .unwrap();
    head.windows[0].root = root;
    head.windows[0].count = 1;
    head.windows[0].result_bytes = length;
    if closed {
        // A closed window must be full under its persisted retention policy.
        // One-entry fixtures exercise retirement without inventing an invalid
        // HEAD or padding the scenario with unrelated result records.
        head.retention.max_entries = 1;
        head.request_epoch = 2;
        let empty = ObjectContext::bootstrap(&database)
            .unwrap()
            .save(crate::tests::index_payload(2, vec![]), deadline())
            .unwrap();
        head.windows.insert(
            0,
            Window {
                epoch: 2,
                root: empty,
                count: 0,
                result_bytes: 0,
            },
        );
    }
    objects.set(head_key(&scope()), encode_head(&head).unwrap());
    let before = objects
        .get(&head_key(&scope()), MAX_HEAD_BYTES, deadline())
        .unwrap();
    (objects, database, request, before)
}

fn assert_unchanged(objects: &Memory, database: &Database, before: &Stored) {
    assert_eq!(
        objects
            .get(&head_key(&scope()), MAX_HEAD_BYTES, deadline())
            .unwrap(),
        *before
    );
    assert!(matches!(database.healthy(), Err(Error::Corrupt)));
    assert!(matches!(database.clone().healthy(), Err(Error::Corrupt)));
}

#[test]
fn original_result_length_is_verified_against_each_leaf_claim() {
    for operation in 0..3 {
        let (objects, database, request, _) = install(valid_result(), false, false);
        let mut head = database.read_head(deadline()).unwrap().head;
        let mut entries =
            crate::tests::index_entries(&database, &head.windows[0], deadline()).unwrap();
        entries[0].result_bytes += 1;
        head.windows[0].result_bytes += 1;
        head.windows[0].root = ObjectContext::bootstrap(&database)
            .unwrap()
            .save(crate::tests::index_payload(1, entries), deadline())
            .unwrap();
        objects.set(head_key(&scope()), encode_head(&head).unwrap());
        let before = objects
            .get(&head_key(&scope()), MAX_HEAD_BYTES, deadline())
            .unwrap();
        let temporary = tempfile::tempdir().unwrap();
        let error = match operation {
            0 => database.lookup(7, &request, deadline()).unwrap_err(),
            1 => database
                .query(
                    7,
                    &sql("SELECT 1"),
                    &temporary.path().join("cold-query"),
                    deadline(),
                )
                .unwrap_err(),
            _ => match database.session(7, &temporary.path().join("cold-open"), deadline()) {
                Err(error) => error,
                Ok(_) => panic!("incorrect length claim survived recovery"),
            },
        };
        assert!(matches!(error, Error::Corrupt));
        assert_unchanged(&objects, &database, &before);
    }
}

#[test]
fn direct_cold_query_and_open_validate_the_branch_a_point_lookup_does_not_visit() {
    for open in [false, true] {
        let (objects, database) = fixture();
        let mut head = database.read_head(deadline()).unwrap().head;
        head.retention.max_entries = 4096;
        let mut children = Vec::new();
        for first in [1, 100] {
            let index = RequestIndex::Leaf {
                epoch: 1,
                entries: (first..first + 64)
                    .map(|id| Entry {
                        request: identity(id),
                        outcome: OutcomeRef::Cancelled {
                            transition: Transition {
                                revision: head.revision,
                                nonce: id,
                            },
                        },
                        result_bytes: 0,
                    })
                    .collect(),
            };
            let summary = index.summary();
            let hash = ObjectContext::bootstrap(&database)
                .unwrap()
                .save(Payload::Index(index), deadline())
                .unwrap();
            children.push(IndexChild { hash, summary });
        }
        let missing = object_key(&scope(), 1, &children[1].hash);
        head.windows[0].count = 128;
        head.windows[0].root = ObjectContext::bootstrap(&database)
            .unwrap()
            .save(
                Payload::Index(RequestIndex::Branch {
                    epoch: 1,
                    level: 1,
                    children,
                }),
                deadline(),
            )
            .unwrap();
        objects.set(head_key(&scope()), encode_head(&head).unwrap());
        let before = objects
            .get(&head_key(&scope()), MAX_HEAD_BYTES, deadline())
            .unwrap();
        objects.fail(false, missing.clone(), StoreError::Missing);
        assert!(matches!(
            database.lookup(7, &identity(1), deadline()),
            Ok(Resolution::Cancelled { .. })
        ));
        let preceding = objects.gets_for(&missing);
        let temporary = tempfile::tempdir().unwrap();
        let error = if open {
            match database.session(7, &temporary.path().join("open"), deadline()) {
                Err(error) => error,
                Ok(_) => panic!("cold Open omitted a retained branch"),
            }
        } else {
            database
                .query(
                    7,
                    &sql("SELECT 1"),
                    &temporary.path().join("query"),
                    deadline(),
                )
                .unwrap_err()
        };
        assert!(matches!(error, Error::Store(StoreError::Missing)));
        assert_eq!(objects.gets_for(&missing), preceding + 1);
        assert_unchanged(&objects, &database, &before);
    }
}

#[test]
fn valid_historical_results_keep_exact_receipt_and_bytes_with_lower_local_limits() {
    for closed in [false, true] {
        let bytes = valid_result();
        let (objects, database, request, before) = install(bytes.clone(), closed, false);
        let original = database.lookup(7, &request, deadline()).unwrap();
        let Resolution::Committed {
            receipt,
            bytes: retained,
        } = &original
        else {
            panic!("a valid bound result must resolve");
        };
        assert_eq!(retained, &bytes);
        assert_eq!(receipt.request, request);
        assert_eq!(receipt.sequence, 1);
        let mut options = test_options();
        options.sql.max_result_bytes = 12;
        options.sql.max_value_bytes = 1;
        let restricted = Database::with_options(objects.clone(), scope(), 10, options).unwrap();
        assert_eq!(
            restricted.lookup(7, &request, deadline()).unwrap(),
            original
        );
        assert_eq!(
            restricted.cancel(7, &request, deadline()).unwrap(),
            original
        );
        assert_eq!(
            objects
                .get(&head_key(&scope()), MAX_HEAD_BYTES, deadline())
                .unwrap(),
            before
        );
        assert!(restricted.healthy().is_ok());
    }
}

#[test]
fn retained_nonce_is_bound_to_request_id_in_lookup_activation_and_compaction() {
    for cancelled in [false, true] {
        for operation in 0..3 {
            let (objects, database, request, _) = install(valid_result(), false, true);
            let mut head = database.read_head(deadline()).unwrap().head;
            let mut entries =
                crate::tests::index_entries(&database, &head.windows[0], deadline()).unwrap();
            if cancelled {
                entries[0].outcome = OutcomeRef::Cancelled {
                    transition: Transition {
                        revision: head.revision,
                        nonce: request.id + 1,
                    },
                };
                entries[0].result_bytes = 0;
                head.windows[0].result_bytes = 0;
            } else {
                let OutcomeRef::Committed { result } = &entries[0].outcome else {
                    panic!()
                };
                let Payload::Result(mut stored) = ObjectContext::bootstrap(&database)
                    .unwrap()
                    .load(result, deadline())
                    .unwrap()
                else {
                    panic!()
                };
                stored.transition.nonce = request.id + 1;
                entries[0].outcome = OutcomeRef::Committed {
                    result: ObjectContext::bootstrap(&database)
                        .unwrap()
                        .save(Payload::Result(stored), deadline())
                        .unwrap(),
                };
            }
            head.windows[0].root = ObjectContext::bootstrap(&database)
                .unwrap()
                .save(crate::tests::index_payload(1, entries), deadline())
                .unwrap();
            objects.set(head_key(&scope()), encode_head(&head).unwrap());
            let (result, expected) = match operation {
                0 => (database.lookup(7, &request, deadline()).map(|_| ()), head),
                1 => (
                    database
                        .activate(7, head.revision, 88, deadline())
                        .map(|_| ()),
                    head,
                ),
                _ => {
                    let begin = database
                        .compact_begin(7, head.head_serial, deadline())
                        .unwrap();
                    let serial = begin.storage.plan.as_ref().unwrap().serial;
                    (
                        database.compact_copy(7, serial, deadline()).map(|_| ()),
                        begin,
                    )
                }
            };
            assert!(
                matches!(result, Err(Error::Corrupt)),
                "cancelled={cancelled}, operation={operation}"
            );
            let actual = database.status(7, deadline()).unwrap();
            assert_eq!(actual, expected);
            if operation == 2 {
                assert_eq!(
                    actual.storage.plan.as_ref().unwrap().phase,
                    CopyPhase::Copying
                );
                assert!(matches!(
                    database.compact_promote(7, actual.storage.plan.unwrap().serial, deadline()),
                    Err(Error::Conflict)
                ));
            }
            assert!(database.quarantined.load(Ordering::Acquire));
        }
    }
}

#[test]
fn lookup_rejects_semantically_invalid_results_despite_correct_object_hashes() {
    let valid = valid_result();
    let mut bad_magic = valid.clone();
    bad_magic[0] ^= 1;
    let mut trailing = valid.clone();
    trailing.push(0);
    let mut too_many_statements = b"SCAPRES1".to_vec();
    too_many_statements.extend_from_slice(&u32::MAX.to_le_bytes());
    for bytes in [
        vec![],
        bad_magic,
        trailing,
        valid[..valid.len() - 1].to_vec(),
        too_many_statements,
    ] {
        for closed in [false, true] {
            let (objects, database, request, before) = install(bytes.clone(), closed, false);
            // Envelope and reference decoding itself succeeds on the baseline.
            let head = database.read_head(deadline()).unwrap().head;
            let window = head
                .windows
                .iter()
                .find(|entry| entry.epoch == request.epoch)
                .unwrap();
            let entries = crate::tests::index_entries(&database, window, deadline()).unwrap();
            let OutcomeRef::Committed { result } = &entries[0].outcome else {
                panic!("fixture is a committed reference");
            };
            assert!(matches!(
                ObjectContext::bootstrap(&database)
                    .unwrap()
                    .load(result, deadline())
                    .unwrap(),
                Payload::Result(_)
            ));
            assert!(matches!(
                database.lookup(7, &request, deadline()),
                Err(Error::Corrupt)
            ));
            assert_unchanged(&objects, &database, &before);
        }
    }
}

#[test]
fn cancel_does_not_return_a_false_committed_or_cancelled_result() {
    let (objects, database, request, before) = install(b"bad-result".to_vec(), false, false);
    assert!(matches!(
        database.cancel(7, &request, deadline()),
        Err(Error::Corrupt)
    ));
    assert_unchanged(&objects, &database, &before);
}

#[test]
fn cold_activation_checks_retained_result_codec_before_publishing_active() {
    for closed in [false, true] {
        for with_session in [false, true] {
            let (objects, database, _, before) = install(b"bad-result".to_vec(), closed, true);
            let revision = database.status(7, deadline()).unwrap().revision;
            let temporary = tempfile::tempdir().unwrap();
            let result = if with_session {
                database
                    .activate_session(7, revision, 200, &temporary.path().join("cold"), deadline())
                    .map(|_| ())
            } else {
                database.activate(7, revision, 200, deadline()).map(|_| ())
            };
            assert!(matches!(result, Err(Error::Corrupt)));
            assert_unchanged(&objects, &database, &before);
            assert!(!database.status(7, deadline()).unwrap().active);
        }
    }
}

#[test]
fn session_and_one_shot_first_write_refuse_corrupt_retained_history() {
    for recover_only in [false, true] {
        let (objects, database, _, before) = install(b"bad-result".to_vec(), true, false);
        let temporary = tempfile::tempdir().unwrap();
        let result = if recover_only {
            database
                .session(7, &temporary.path().join("session"), deadline())
                .map(|_| ())
        } else {
            let next = Request {
                epoch: 2,
                ..identity(2)
            };
            database
                .execute(
                    7,
                    &next,
                    &sql("SELECT 1"),
                    &temporary.path().join("write"),
                    deadline(),
                )
                .map(|_| ())
        };
        assert!(matches!(result, Err(Error::Corrupt)));
        assert_unchanged(&objects, &database, &before);
    }
}

#[test]
fn authorization_and_request_identity_are_checked_before_result_contents() {
    let (objects, database, request, before) = install(b"bad-result".to_vec(), false, false);
    assert!(matches!(
        database.lookup(8, &request, deadline()),
        Err(Error::Denied)
    ));
    let changed = Request {
        principal: 8,
        ..request.clone()
    };
    assert!(matches!(
        database.lookup(7, &changed, deadline()),
        Err(Error::Denied)
    ));
    let changed = Request {
        fingerprint: digest(b"different SQL"),
        ..request
    };
    assert!(matches!(
        database.lookup(7, &changed, deadline()),
        Err(Error::RequestConflict)
    ));
    assert!(database.healthy().is_ok());
    assert_eq!(
        objects
            .get(&head_key(&scope()), MAX_HEAD_BYTES, deadline())
            .unwrap(),
        before
    );
}

#[test]
fn decoded_corruption_blocks_warm_publication_even_after_head_is_restored() {
    let (objects, database) = fixture();
    let temporary = tempfile::tempdir().unwrap();
    let mut session = database
        .session(7, &temporary.path().join("warm"), deadline())
        .unwrap();
    let (receipt, _) = session
        .execute(7, &identity(1), &sql("SELECT 1"), deadline())
        .unwrap();
    let original = database.read_head(deadline()).unwrap();
    let Payload::Result(mut stored) = ObjectContext::bootstrap(&database)
        .unwrap()
        .load(&receipt.result_hash, deadline())
        .unwrap()
    else {
        panic!("accepted request must have a result object");
    };
    stored.bytes[0] ^= 1;
    let corrupt_result = ObjectContext::bootstrap(&database)
        .unwrap()
        .save(Payload::Result(stored), deadline())
        .unwrap();
    let mut entries =
        crate::tests::index_entries(&database, &original.head.windows[0], deadline()).unwrap();
    entries[0].outcome = OutcomeRef::Committed {
        result: corrupt_result,
    };
    let mut damaged = original.head.clone();
    damaged.windows[0].root = ObjectContext::bootstrap(&database)
        .unwrap()
        .save(crate::tests::index_payload(1, entries), deadline())
        .unwrap();
    objects.set(head_key(&scope()), encode_head(&damaged).unwrap());
    assert!(matches!(
        database.clone().lookup(7, &identity(1), deadline()),
        Err(Error::Corrupt)
    ));
    objects.set(head_key(&scope()), encode_head(&original.head).unwrap());
    let before = objects
        .get(&head_key(&scope()), MAX_HEAD_BYTES, deadline())
        .unwrap();
    assert!(matches!(
        session.execute(7, &identity(2), &sql("SELECT 1"), deadline()),
        Err(Error::Corrupt)
    ));
    assert!(matches!(
        database.cancel(7, &identity(2), deadline()),
        Err(Error::Corrupt)
    ));
    assert!(matches!(
        database.set_lifecycle(
            7,
            original.head.revision,
            201,
            Lifecycle::Maintenance,
            deadline()
        ),
        Err(Error::Corrupt)
    ));
    assert_unchanged(&objects, &database, &before);
    // Quarantine is per handle/clone, not a new distributed fencing mechanism.
    let fresh = Database::with_options(objects, scope(), 10, test_options()).unwrap();
    assert!(fresh.healthy().is_ok());
    assert!(matches!(
        fresh.lookup(7, &identity(1), deadline()).unwrap(),
        Resolution::Committed { .. }
    ));
}

#[test]
fn materializing_historical_results_remains_a_defensive_decoder_boundary() {
    let bytes = valid_result();
    let (_, database, request, _) = install(bytes.clone(), false, false);
    let Resolution::Committed { receipt, .. } = database.lookup(7, &request, deadline()).unwrap()
    else {
        panic!("a valid bound result must resolve");
    };
    let Admission::Existing(retained_receipt, result) = database
        .decode_retained_admission(receipt.clone(), &bytes)
        .unwrap()
    else {
        panic!("decoding retained bytes cannot admit a fresh execution");
    };
    assert_eq!(retained_receipt, receipt);
    assert_eq!(
        result,
        scap_sql::decode_result(&bytes, durable_sql_limits()).unwrap()
    );
    assert!(database.healthy().is_ok());
    assert!(matches!(
        database.decode_retained_admission(receipt, b"bad-result"),
        Err(Error::Corrupt)
    ));
    assert!(matches!(database.healthy(), Err(Error::Corrupt)));
}

#[test]
fn historical_result_memory_pressure_preserves_receipt_lookup_and_health() {
    let bytes = valid_result();
    let (objects, database, request, before) = install(bytes.clone(), false, false);
    let original = database.lookup(7, &request, deadline()).unwrap();
    let Resolution::Committed { receipt, .. } = &original else {
        panic!("valid retained outcome must be committed");
    };
    let mut options = test_options();
    options.result_memory_bytes = std::mem::size_of::<TransactionResult>() as u64;
    let restricted = Database::with_options(objects.clone(), scope(), 10, options).unwrap();
    let error = match restricted.decode_retained_admission(receipt.clone(), &bytes) {
        Err(error) => error,
        Ok(_) => panic!("typed graph exceeded its independent budget"),
    };
    assert!(matches!(error, Error::CommittedButUnavailable(kept) if *kept == *receipt));
    assert!(restricted.healthy().is_ok());
    assert_eq!(
        restricted.lookup(7, &request, deadline()).unwrap(),
        original
    );
    assert_eq!(
        restricted.cancel(7, &request, deadline()).unwrap(),
        original
    );
    assert_eq!(
        objects
            .get(&head_key(&scope()), MAX_HEAD_BYTES, deadline())
            .unwrap(),
        before
    );
    // Raising only the local materialization allowance recovers the original
    // result; it neither mutates authority nor authorizes a fresh SQL attempt.
    assert!(matches!(
        database.decode_retained_admission(receipt.clone(), &bytes).unwrap(),
        Admission::Existing(kept, _) if kept == *receipt
    ));
}
