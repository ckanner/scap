//! Observed immutable-closure failures stop publication through this handle and
//! its clones. These tests do not assert cross-worker or persistent fencing.

use super::tests::{deadline, fixture, identity, scope, sql, test_options, Memory};
use super::*;
use scap_object_store::Stored;
use std::sync::{atomic::AtomicUsize, Mutex};

fn warm(database: &Database, directory: &Path) -> (Session, Receipt) {
    let mut session = database.session(7, directory, deadline()).unwrap();
    let (receipt, _) = session
        .execute(7, &identity(1), &sql("SELECT 1"), deadline())
        .unwrap();
    assert!(session.history_verified);
    (session, receipt)
}

fn assert_publication_is_blocked(objects: &Memory, database: &Database, session: &mut Session) {
    let key = head_key(&scope());
    let before = objects.get(&key, MAX_HEAD_BYTES, deadline()).unwrap();
    let head = decode_head(&before.bytes, &scope()).unwrap();
    assert!(matches!(database.healthy(), Err(Error::Corrupt)));
    assert!(matches!(
        session.execute(7, &identity(2), &sql("SELECT 1"), deadline()),
        Err(Error::Corrupt)
    ));
    assert!(matches!(
        database.cancel(7, &identity(2), deadline()),
        Err(Error::Corrupt)
    ));
    assert!(matches!(
        database.set_lifecycle(7, head.revision, 90, Lifecycle::Maintenance, deadline()),
        Err(Error::Corrupt)
    ));
    assert!(matches!(
        database.set_quota(
            7,
            head.revision,
            91,
            DatabaseQuota { max_bytes: None },
            deadline()
        ),
        Err(Error::Corrupt)
    ));
    assert_eq!(
        objects.get(&key, MAX_HEAD_BYTES, deadline()).unwrap(),
        before
    );
    assert_eq!(
        database.lookup(7, &identity(2), deadline()).unwrap(),
        Resolution::Unknown
    );
}

#[test]
fn observed_missing_corrupt_or_oversized_retained_objects_stop_warm_publication() {
    for fault in [StoreError::Missing, StoreError::Corrupt, StoreError::Limit] {
        let (objects, database) = fixture();
        let temporary = tempfile::tempdir().unwrap();
        let (mut session, receipt) = warm(&database, &temporary.path().join("warm"));
        let observer = database.clone();
        assert!(Arc::ptr_eq(&observer.quarantined, &database.quarantined));
        objects.fail(
            false,
            object_key(&scope(), &receipt.result_hash),
            fault.clone(),
        );
        assert!(matches!(
            observer.lookup(7, &receipt.request, deadline()),
            Err(Error::Store(observed)) if observed == fault
        ));
        // The fault is one-shot. Successful later reads cannot silently clear
        // the failure or turn the already-warmed connection into authority.
        assert!(matches!(
            observer.lookup(7, &receipt.request, deadline()).unwrap(),
            Resolution::Committed { .. }
        ));
        assert_publication_is_blocked(&objects, &database, &mut session);
    }
}

#[test]
fn malformed_retained_wire_stops_warm_publication_even_after_bytes_are_restored() {
    let (objects, database) = fixture();
    let temporary = tempfile::tempdir().unwrap();
    let (mut session, receipt) = warm(&database, &temporary.path().join("warm"));
    let key = object_key(&scope(), &receipt.result_hash);
    let original = objects.get(&key, MAX_OBJECT_BYTES, deadline()).unwrap();
    objects.set(key.clone(), b"broken immutable object".to_vec());
    assert!(matches!(
        database.clone().lookup(7, &receipt.request, deadline()),
        Err(Error::Format(FormatError::Corrupt))
    ));
    objects.set(key, original.bytes);
    assert_publication_is_blocked(&objects, &database, &mut session);
}

#[test]
fn decoded_result_kind_identity_ordering_and_codec_failures_stop_warm_publication() {
    for mutation in 0..5 {
        let (objects, database) = fixture();
        let temporary = tempfile::tempdir().unwrap();
        let (mut session, receipt) = warm(&database, &temporary.path().join("warm"));
        let original = database.read_head(deadline()).unwrap();
        let Payload::Result(mut stored) = ObjectContext::bootstrap(&database)
            .load(&receipt.result_hash, deadline())
            .unwrap()
        else {
            panic!("committed receipt must reference its stored result");
        };
        let payload = if mutation == 0 {
            crate::tests::index_payload(1, vec![])
        } else {
            match mutation {
                1 => stored.request.principal += 1,
                2 => stored.sequence += 1,
                3 => stored.transition.revision += 1,
                _ => stored.bytes[0] ^= 1,
            }
            Payload::Result(stored)
        };
        let replacement = ObjectContext::bootstrap(&database)
            .save(payload, deadline())
            .unwrap();
        let mut entries =
            crate::tests::index_entries(&database, &original.head.windows[0], deadline()).unwrap();
        entries[0].outcome = OutcomeRef::Committed {
            result: replacement,
        };
        let mut damaged = original.head.clone();
        damaged.windows[0].root = ObjectContext::bootstrap(&database)
            .save(crate::tests::index_payload(1, entries), deadline())
            .unwrap();
        objects.set(head_key(&scope()), encode_head(&damaged).unwrap());
        if mutation == 4 {
            assert!(matches!(
                database.execute(
                    7,
                    &receipt.request,
                    &sql("SELECT 1"),
                    &temporary.path().join("never-run"),
                    deadline()
                ),
                Err(Error::Corrupt)
            ));
            assert!(!temporary.path().join("never-run").exists());
        } else {
            assert!(matches!(
                database.clone().lookup(7, &receipt.request, deadline()),
                Err(Error::Corrupt)
            ));
        }
        // Restoring the prior authoritative body removes the injected defect,
        // but does not reset the shared failure remembered by the old session.
        objects.set(head_key(&scope()), encode_head(&original.head).unwrap());
        assert_publication_is_blocked(&objects, &database, &mut session);
    }
}

#[test]
fn failed_immutable_readback_and_colliding_corrupt_bytes_stop_existing_sessions() {
    for collision in [false, true] {
        let (objects, database) = fixture();
        let temporary = tempfile::tempdir().unwrap();
        let (mut session, _) = warm(&database, &temporary.path().join("warm"));
        let payload = Payload::Chunk {
            first_page: 1,
            bytes: vec![42; PAGE_SIZE],
        };
        let bytes = encode_object(&Envelope {
            format: 2,
            scope: scope(),
            payload: payload.clone(),
        })
        .unwrap();
        let key = object_key(&scope(), &digest(&bytes));
        if collision {
            objects.set(key, b"not the immutable bytes".to_vec());
            assert!(matches!(
                ObjectContext::bootstrap(&database).save(payload, deadline()),
                Err(Error::Corrupt)
            ));
        } else {
            objects.fail(false, key, StoreError::Missing);
            assert!(matches!(
                ObjectContext::bootstrap(&database).save(payload, deadline()),
                Err(Error::Store(StoreError::Missing))
            ));
        }
        assert_publication_is_blocked(&objects, &database, &mut session);
    }
}

#[test]
fn transient_reads_and_unknown_or_conflicting_cas_do_not_poison_the_handle() {
    for fault in [StoreError::Unknown, StoreError::Conflict] {
        let (objects, database) = fixture();
        let temporary = tempfile::tempdir().unwrap();
        let (mut session, receipt) = warm(&database, &temporary.path().join("warm"));
        let observer = database.clone();
        objects.fail(
            false,
            object_key(&scope(), &receipt.result_hash),
            StoreError::Unknown,
        );
        assert!(matches!(
            observer.lookup(7, &receipt.request, deadline()),
            Err(Error::Store(StoreError::Unknown))
        ));
        let before = database.read_head(deadline()).unwrap();
        objects.fail(true, head_key(&scope()), fault.clone());
        let outcome = observer.set_lifecycle(
            7,
            before.head.revision,
            90,
            Lifecycle::Maintenance,
            deadline(),
        );
        match fault {
            StoreError::Unknown => {
                assert!(matches!(outcome, Err(Error::Store(StoreError::Unknown))))
            }
            StoreError::Conflict => assert!(matches!(outcome, Err(Error::Conflict))),
            _ => unreachable!(),
        }
        assert!(database.healthy().is_ok());
        let after = database.read_head(deadline()).unwrap();
        assert_eq!(after.head, before.head);
        assert_eq!(after.etag, before.etag);
        let (committed, _) = session
            .execute(7, &identity(2), &sql("SELECT 1"), deadline())
            .unwrap();
        assert_eq!(committed.sequence, 2);
    }
}

struct Interleaving {
    inner: Arc<Memory>,
    trip: Mutex<Option<Trip>>,
    observed: AtomicBool,
    head_puts: AtomicUsize,
}

struct Trip {
    trigger_key: String,
    retained_key: String,
    observer: Database,
    request: Request,
}

impl Objects for Interleaving {
    fn get(&self, key: &str, maximum: usize, until: Instant) -> Result<Stored, StoreError> {
        let stored = self.inner.get(key, maximum, until)?;
        let trip = {
            let mut armed = self.trip.lock().unwrap();
            if armed.as_ref().is_some_and(|trip| trip.trigger_key == key) {
                armed.take()
            } else {
                None
            }
        };
        if let Some(trip) = trip {
            // Run another clone's real target lookup at the selected I/O cut.
            // Remove the trigger first, so its nested GETs cannot re-enter it.
            self.inner
                .fail(false, trip.retained_key, StoreError::Missing);
            assert!(matches!(
                trip.observer.lookup(7, &trip.request, until),
                Err(Error::Store(StoreError::Missing))
            ));
            self.observed.store(true, Ordering::Release);
        }
        Ok(stored)
    }

    fn put(
        &self,
        key: &str,
        bytes: &[u8],
        condition: Condition<'_>,
        until: Instant,
    ) -> Result<String, StoreError> {
        if key == head_key(&scope()) {
            self.head_puts.fetch_add(1, Ordering::AcqRel);
        }
        self.inner.put(key, bytes, condition, until)
    }
}

#[test]
fn failure_observed_after_initial_publish_check_prevents_the_final_head_put() {
    let objects = Arc::new(Interleaving {
        inner: Arc::new(Memory::default()),
        trip: Mutex::new(None),
        observed: AtomicBool::new(false),
        head_puts: AtomicUsize::new(0),
    });
    let database = Database::with_options(objects.clone(), scope(), 10, test_options()).unwrap();
    database.create(7, 1, deadline()).unwrap();
    database.activate(7, 1, 2, deadline()).unwrap();
    let temporary = tempfile::tempdir().unwrap();
    let (mut session, receipt) = warm(&database, &temporary.path().join("warm"));
    let before = database.read_head(deadline()).unwrap();
    let puts = objects.head_puts.load(Ordering::Acquire);
    *objects.trip.lock().unwrap() = Some(Trip {
        trigger_key: object_key(&scope(), &before.head.data_root),
        retained_key: object_key(&scope(), &receipt.result_hash),
        observer: database.clone(),
        request: receipt.request,
    });
    assert!(database.healthy().is_ok());
    assert!(matches!(
        database.set_lifecycle(
            7,
            before.head.revision,
            90,
            Lifecycle::Maintenance,
            deadline()
        ),
        Err(Error::Corrupt)
    ));
    assert!(objects.observed.load(Ordering::Acquire));
    assert_eq!(objects.head_puts.load(Ordering::Acquire), puts);
    let after = database.read_head(deadline()).unwrap();
    assert_eq!(after.head, before.head);
    assert_eq!(after.etag, before.etag);
    assert_publication_is_blocked(&objects.inner, &database, &mut session);
    assert_eq!(objects.head_puts.load(Ordering::Acquire), puts);
}
