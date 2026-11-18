//! SQL publication retains an independent exact Manifest GET. Immutable
//! creation/readback, native ACK and the original HEAD CAS are separate gates.

use super::*;
use crate::tests::{deadline, fixture, scope, sql, test_options, Memory};
use scap_object_sqlite::PageChange;
use scap_object_store::{Condition, Stored};
use std::sync::Mutex;
use std::time::Duration;

fn batch() -> PageBatch {
    PageBatch {
        size_after: 2,
        pages: (1..=2)
            .map(|number| PageChange {
                number,
                bytes: vec![number as u8; PAGE_SIZE],
            })
            .collect(),
    }
}

fn prepared(context: &ObjectContext, base: &Snapshot, until: Instant) -> Head {
    let root = data_tree::update(context, &base.head.data_root, &batch(), 64, until).unwrap();
    let mut next = Database::next(&base.head, 99).unwrap();
    next.data_root = root;
    next
}

fn stored_head(objects: &Memory) -> Stored {
    objects
        .entries()
        .into_iter()
        .find(|(key, _)| *key == head_key(&scope()))
        .unwrap()
        .1
}

#[test]
fn business_and_dependency_changing_management_each_keep_the_final_manifest_get() {
    let (objects, database) = fixture();
    let until = deadline();
    let base = database.read_head(until).unwrap();
    let context = ObjectContext::from_snapshot(&database, &base, until).unwrap();
    let next = prepared(&context, &base, until);
    let key = object_key(&scope(), 1, &next.data_root);
    assert_eq!(objects.gets_for(&key), 1, "immutable save's exact readback");
    let before = objects.operation_count();
    database
        .clone()
        .publish_in(&context, &base, &next, until)
        .unwrap();
    assert_eq!(
        objects.operation_count(),
        before + 2,
        "final Manifest GET and original HEAD CAS"
    );
    assert_eq!(objects.gets_for(&key), 2);

    let base = database.read_head(until).unwrap();
    let next = Database::next(&base.head, 100).unwrap();
    let before = objects.operation_count();
    database.publish(&base, &next, until).unwrap();
    assert_eq!(
        objects.operation_count(),
        before + 2,
        "management GET and CAS"
    );
    assert_eq!(objects.gets_for(&key), 3);
}

#[test]
fn native_writes_and_noop_results_keep_the_final_get_and_original_results() {
    let (objects, database) = fixture();
    let directory = tempfile::tempdir().unwrap();
    let mut session = database
        .session(7, &directory.path().join("native"), deadline())
        .unwrap();
    let create = sql("CREATE TABLE value_store(value INTEGER)");
    session
        .execute(7, &request(1, 1, 7, &create).unwrap(), &create, deadline())
        .unwrap();
    for (id, statements, changing) in [
        (
            2,
            sql("INSERT INTO value_store VALUES(random()) RETURNING value"),
            true,
        ),
        (3, sql("SELECT random()"), false),
    ] {
        let before = database.read_head(deadline()).unwrap();
        let old_key = object_key(&scope(), 1, &before.head.data_root);
        let old_gets = objects.gets_for(&old_key);
        let identity = request(1, id, 7, &statements).unwrap();
        let (receipt, original) = session
            .execute(7, &identity, &statements, deadline())
            .unwrap();
        let key = object_key(&scope(), 1, &receipt.data_root);
        if changing {
            assert_ne!(receipt.data_root, before.head.data_root);
            assert_eq!(
                objects.gets_for(&key),
                2,
                "new manifest readback and publication GET"
            );
        } else {
            assert_eq!(receipt.data_root, before.head.data_root);
            assert_eq!(
                objects.gets_for(&key) - old_gets,
                2,
                "unchanged manifest validation and publication GET"
            );
        }
        let Resolution::Committed {
            receipt: saved,
            bytes,
        } = database.lookup(7, &identity, deadline()).unwrap()
        else {
            panic!("native ACK must retain the original result");
        };
        assert_eq!(saved, receipt);
        assert_eq!(
            scap_sql::decode_result(&bytes, durable_sql_limits()).unwrap(),
            original
        );
    }
}

#[test]
fn invalid_candidates_quota_and_original_deadline_withhold_publication() {
    for fault in 0..4 {
        let (objects, database) = fixture();
        let until = deadline();
        let base = database.read_head(until).unwrap();
        let context = ObjectContext::from_snapshot(&database, &base, until).unwrap();
        let mut next = prepared(&context, &base, until);
        match fault {
            0 => next.quota.max_bytes = Some(0),
            1 => next.transition.nonce = 0,
            2 => next.quota.max_bytes = Some(PAGE_SIZE as u64),
            _ => {}
        }
        let original = stored_head(&objects);
        let before = objects.operation_count();
        let expired = ObjectContext::from_snapshot(&database, &base, Instant::now()).unwrap();
        let result = database.publish_in(
            if fault == 3 { &expired } else { &context },
            &base,
            &next,
            until + Duration::from_secs(1),
        );
        match fault {
            0 | 1 => assert!(matches!(result, Err(Error::Format(_)))),
            2 => assert!(matches!(result, Err(Error::Limit))),
            _ => assert!(matches!(result, Err(Error::Unknown))),
        }
        assert_eq!(objects.operation_count(), before + usize::from(fault == 2));
        assert_eq!(stored_head(&objects), original);
    }
}

#[test]
fn prior_readback_never_overrides_later_context_or_lineage_failure() {
    for fault in 0..3 {
        let (objects, database) = fixture();
        let until = deadline();
        let base = database.read_head(until).unwrap();
        let context = ObjectContext::from_snapshot(&database, &base, until).unwrap();
        let next = prepared(&context, &base, until);
        match fault {
            0 => {
                objects.fail(
                    false,
                    object_key(&scope(), 1, &base.head.data_root),
                    StoreError::Unknown,
                );
                assert!(matches!(
                    context.load(&base.head.data_root, until),
                    Err(Error::Store(StoreError::Unknown))
                ));
            }
            1 => database.quarantined.store(true, Ordering::Release),
            _ => {
                let observer =
                    ObjectContext::from_snapshot(&database.clone(), &base, until).unwrap();
                objects.remove(&object_key(&scope(), 1, &next.data_root));
                assert!(matches!(
                    observer.load(&next.data_root, until),
                    Err(Error::Store(StoreError::Missing))
                ));
            }
        }
        let before = objects.operation_count();
        let original = stored_head(&objects);
        let result = database.publish_in(&context, &base, &next, until);
        if fault == 0 {
            assert!(matches!(result, Err(Error::Unknown)));
        } else {
            assert!(matches!(result, Err(Error::Corrupt)));
        }
        assert_eq!(objects.operation_count(), before);
        assert_eq!(stored_head(&objects), original);
    }
}

#[test]
fn final_manifest_get_failure_never_publishes_an_earlier_successful_readback() {
    for error in [
        StoreError::Unknown,
        StoreError::Missing,
        StoreError::Corrupt,
    ] {
        let (objects, database) = fixture();
        let until = deadline();
        let base = database.read_head(until).unwrap();
        let context = ObjectContext::from_snapshot(&database, &base, until).unwrap();
        let next = prepared(&context, &base, until);
        let key = object_key(&scope(), 1, &next.data_root);
        assert_eq!(objects.gets_for(&key), 1);
        let original = stored_head(&objects);
        objects.fail(false, key.clone(), error.clone());
        assert!(matches!(database.publish_in(&context, &base, &next, until),
            Err(Error::Store(actual)) if actual == error));
        assert_eq!(
            objects.gets_for(&key),
            2,
            "the independent publication GET was attempted"
        );
        assert_eq!(
            stored_head(&objects),
            original,
            "no HEAD body or ETag change"
        );
    }
}

struct ArmedFailure {
    root_key: String,
    error: Option<StoreError>,
    result_saved: bool,
    index_saved: bool,
    earlier_manifest_reads: usize,
    triggered: bool,
}

#[derive(Default)]
struct NativePublicationCut {
    inner: Memory,
    armed: Mutex<Option<ArmedFailure>>,
}

impl Objects for NativePublicationCut {
    fn get(&self, key: &str, maximum: usize, until: Instant) -> Result<Stored, StoreError> {
        if let Some(armed) = self.armed.lock().unwrap().as_mut() {
            if key == armed.root_key {
                if armed.index_saved {
                    if let Some(error) = armed.error.take() {
                        armed.triggered = true;
                        return Err(error);
                    }
                }
                armed.earlier_manifest_reads += 1;
            }
        }
        self.inner.get(key, maximum, until)
    }

    fn put(
        &self,
        key: &str,
        bytes: &[u8],
        condition: Condition<'_>,
        until: Instant,
    ) -> Result<String, StoreError> {
        let result = self.inner.put(key, bytes, condition, until);
        if matches!(condition, Condition::Absent) {
            if let Some(armed) = self.armed.lock().unwrap().as_mut() {
                let envelope = format::decode_object(bytes, &scope(), &digest(bytes)).unwrap();
                match envelope.payload {
                    Payload::Manifest(_) => {
                        armed.root_key = key.to_owned();
                        armed.earlier_manifest_reads = 0;
                    }
                    Payload::Result(_) => armed.result_saved = true,
                    Payload::Index(_) if armed.result_saved => armed.index_saved = true,
                    _ => {}
                }
            }
        }
        result
    }
}

#[test]
fn native_commit_stops_without_ack_when_the_final_manifest_get_fails() {
    for changing in [false, true] {
        for error in [
            StoreError::Unknown,
            StoreError::Missing,
            StoreError::Corrupt,
        ] {
            let objects = Arc::new(NativePublicationCut::default());
            let database =
                Database::with_options(objects.clone(), scope(), 10, test_options()).unwrap();
            database.create(7, 1, deadline()).unwrap();
            database.activate(7, 1, 2, deadline()).unwrap();
            let directory = tempfile::tempdir().unwrap();
            let mut session = database
                .session(7, &directory.path().join("original"), deadline())
                .unwrap();
            let create = sql("CREATE TABLE value_store(value INTEGER)");
            session
                .execute(7, &request(1, 1, 7, &create).unwrap(), &create, deadline())
                .unwrap();
            let base = database.read_head(deadline()).unwrap();
            let original = stored_head(&objects.inner);
            *objects.armed.lock().unwrap() = Some(ArmedFailure {
                root_key: object_key(&scope(), 1, &base.head.data_root),
                error: Some(error.clone()),
                result_saved: false,
                index_saved: false,
                earlier_manifest_reads: 0,
                triggered: false,
            });
            let statements = sql(if changing {
                "INSERT INTO value_store VALUES(random()) RETURNING value"
            } else {
                "SELECT random()"
            });
            let identity = request(1, 2, 7, &statements).unwrap();
            assert!(
                matches!(session.execute(7, &identity, &statements, deadline()),
                Err(Error::Store(actual)) if actual == error)
            );
            {
                let armed = objects.armed.lock().unwrap();
                let armed = armed.as_ref().unwrap();
                assert!(armed.result_saved && armed.index_saved && armed.triggered);
                assert!(
                    armed.earlier_manifest_reads > 0,
                    "normal validation/readback must precede the final GET fault"
                );
            }
            assert_eq!(stored_head(&objects.inner), original);
            assert!(
                session.writer.is_stopped(),
                "ambiguous publication must stop native SQL"
            );
            assert!(matches!(
                session.query(7, &sql("SELECT 1"), deadline()),
                Err(Error::StaleSnapshot)
            ));
            drop(session);
            let cold =
                Database::with_options(objects.clone(), scope(), 10, test_options()).unwrap();
            assert_eq!(
                cold.lookup(7, &identity, deadline()).unwrap(),
                Resolution::Unknown
            );
            let rows = cold
                .query(
                    7,
                    &sql("SELECT count(*) FROM value_store"),
                    &directory.path().join("cold"),
                    deadline(),
                )
                .unwrap();
            assert_eq!(
                rows.statements[0].rows,
                vec![vec![scap_sql::Value::Integer(0)]]
            );
        }
    }
}

#[test]
fn late_original_publication_keeps_conflict_and_unknown_without_rebinding() {
    for lost_ack in [false, true] {
        let (objects, database) = fixture();
        let until = deadline();
        let base = database.read_head(until).unwrap();
        let context = ObjectContext::from_snapshot(&database, &base, until).unwrap();
        let next = prepared(&context, &base, until);
        if lost_ack {
            objects.lose_next_cas();
        } else {
            let later = Database::next(&base.head, 77).unwrap();
            database.publish(&base, &later, until).unwrap();
        }
        let before = objects.operation_count();
        let result = database.publish_in(&context, &base, &next, until);
        assert_eq!(
            objects.operation_count(),
            before + 2,
            "final Manifest GET and one original CAS, no HEAD refresh"
        );
        if lost_ack {
            assert!(matches!(result, Err(Error::Store(StoreError::Unknown))));
            assert_eq!(database.read_head(until).unwrap().head, next);
        } else {
            assert!(matches!(result, Err(Error::Conflict)));
            assert_ne!(database.read_head(until).unwrap().head, next);
        }
    }
}
