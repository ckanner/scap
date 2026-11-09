//! Metadata publication with content-derived ETags and independent I/O records.

use super::*;
use crate::format::{decode_head, digest};
use crate::tests::{deadline, fixture, scope, test_options, Memory};
use scap_object_store::Stored;
use std::sync::atomic::Ordering;
use std::sync::Mutex;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Put {
    key: String,
    bytes: Vec<u8>,
    condition: Option<String>,
    deadline: Instant,
}

enum Failure {
    Before(StoreError),
    AfterApplied,
}

struct State {
    bytes: Vec<u8>,
    gets: usize,
    puts: Vec<Put>,
    failure: Option<Failure>,
}

struct HeadStore {
    key: String,
    state: Mutex<State>,
}

impl Objects for HeadStore {
    fn get(&self, key: &str, maximum: usize, until: Instant) -> Result<Stored, StoreError> {
        let mut state = self.state.lock().unwrap();
        state.gets += 1;
        assert_eq!(key, self.key, "metadata primitive must not load an object");
        assert!(Instant::now() < until);
        assert!(state.bytes.len() <= maximum);
        Ok(Stored {
            bytes: state.bytes.clone(),
            etag: digest(&state.bytes),
        })
    }

    fn put(
        &self,
        key: &str,
        bytes: &[u8],
        condition: Condition<'_>,
        until: Instant,
    ) -> Result<String, StoreError> {
        let mut state = self.state.lock().unwrap();
        state.puts.push(Put {
            key: key.into(),
            bytes: bytes.to_vec(),
            condition: match condition {
                Condition::Absent => None,
                Condition::Match(etag) => Some(etag.into()),
            },
            deadline: until,
        });
        assert_eq!(key, self.key);
        if Instant::now() >= until {
            return Err(StoreError::Unknown);
        }
        let failure = state.failure.take();
        if let Some(Failure::Before(error)) = failure {
            return Err(error);
        }
        if !matches!(condition, Condition::Match(etag) if etag == digest(&state.bytes)) {
            return Err(StoreError::Conflict);
        }
        state.bytes = bytes.to_vec();
        if matches!(failure, Some(Failure::AfterApplied)) {
            return Err(StoreError::Unknown);
        }
        Ok(digest(bytes))
    }
}

fn metadata() -> (Arc<HeadStore>, Database, Snapshot) {
    let (_, database) = fixture();
    let head = database.read_head(deadline()).unwrap().head;
    let bytes = encode_head(&head).unwrap();
    let base = Snapshot {
        head,
        etag: digest(&bytes),
    };
    let objects = Arc::new(HeadStore {
        key: head_key(&scope()),
        state: Mutex::new(State {
            bytes,
            gets: 0,
            puts: vec![],
            failure: None,
        }),
    });
    let database = Database::with_options(objects.clone(), scope(), 10, test_options()).unwrap();
    (objects, database, base)
}

#[test]
fn prepared_metadata_owns_original_body_etag_backend_scope_and_deadline() {
    let (objects, mut database, mut base) = metadata();
    let mut next = base.head.clone();
    next.head_serial += 1;
    let until = deadline();
    let expected = Put {
        key: head_key(&scope()),
        bytes: encode_head(&next).unwrap(),
        condition: Some(base.etag.clone()),
        deadline: until,
    };
    // A narrow future cleanup path must not need healthy() or READ authority.
    // This test only exercises the private primitive, not a public grant.
    database.quarantined.store(true, Ordering::Release);
    let publication = PreparedHead::new(&database, &base, &next, until).unwrap();
    let ordinary = Database::next(&base.head, 99).unwrap();
    assert!(matches!(
        database.publish(&base, &ordinary, until),
        Err(Error::Corrupt)
    ));
    next.head_serial += 1;
    next.policy.clear();
    base.etag = "later etag".into();
    base.head.scope.generation += 1;
    database.scope.database += 1;
    database.objects = Arc::new(Memory::default());
    drop(database);
    publication.publish().unwrap();
    let state = objects.state.lock().unwrap();
    assert_eq!(state.gets, 0);
    assert_eq!(state.puts, vec![expected.clone()]);
    assert_eq!(state.bytes, expected.bytes);
}

#[test]
fn invalid_metadata_candidates_and_serial_exhaustion_do_no_io() {
    for cut in 0..10 {
        let (objects, database, mut base) = metadata();
        let mut next = Database::next(&base.head, 99).unwrap();
        match cut {
            0 => base.head.scope.database += 1,
            1 => next.scope.generation += 1,
            2 => next.storage.active_generation = 2,
            3 => base.etag.clear(),
            4 => next.head_serial = base.head.head_serial,
            5 => next.head_serial += 1,
            6 => {
                base.head.head_serial = u64::MAX;
                next.head_serial = u64::MAX;
            }
            7 => next.transition.nonce = 0,
            8 => {
                base.head.storage.allocated_through = 2;
                next.storage = base.head.storage.clone();
            }
            _ => next.format = 4,
        }
        let result = PreparedHead::new(&database, &base, &next, deadline());
        if cut == 6 {
            assert!(matches!(result, Err(Error::Limit)));
        } else {
            assert!(matches!(result, Err(Error::Format(FormatError::Invalid))));
        }
        let state = objects.state.lock().unwrap();
        assert_eq!(state.gets, 0);
        assert!(state.puts.is_empty());
    }
}

#[test]
fn original_cas_is_attempted_once_and_unknown_never_manufactures_a_snapshot() {
    for cut in 0..4 {
        let (objects, database, base) = metadata();
        let next = Database::next(&base.head, 99).unwrap();
        let original = encode_head(&base.head).unwrap();
        let proposed = encode_head(&next).unwrap();
        objects.state.lock().unwrap().failure = Some(match cut {
            0 => Failure::Before(StoreError::Conflict),
            1 => Failure::Before(StoreError::Unknown),
            2 => Failure::AfterApplied,
            _ => Failure::Before(StoreError::Invalid),
        });
        let result = PreparedHead::new(&database, &base, &next, deadline())
            .unwrap()
            .publish();
        match cut {
            0 => assert!(matches!(result, Err(Error::Conflict))),
            1 | 2 => assert!(matches!(result, Err(Error::Store(StoreError::Unknown)))),
            _ => assert!(matches!(result, Err(Error::Store(StoreError::Invalid)))),
        }
        {
            let state = objects.state.lock().unwrap();
            assert_eq!(state.gets, 0);
            assert_eq!(state.puts.len(), 1);
            assert_eq!(state.puts[0].condition.as_ref(), Some(&base.etag));
            assert_eq!(state.puts[0].bytes, proposed);
            assert_eq!(&state.bytes, if cut == 2 { &proposed } else { &original });
        }
        // A subsequent exact GET, separately observed, is the only usable
        // body/ETag pair. A lost reply could have either persisted outcome.
        let observed = database.read_head(deadline()).unwrap();
        assert_eq!(objects.state.lock().unwrap().gets, 1);
        assert_eq!(observed.head, if cut == 2 { next } else { base.head });
        assert_eq!(observed.etag, digest(&encode_head(&observed.head).unwrap()));
    }
}

#[test]
fn expired_original_deadline_is_forwarded_without_renewal() {
    let (objects, database, base) = metadata();
    let next = Database::next(&base.head, 99).unwrap();
    let expired = Instant::now();
    assert!(matches!(
        PreparedHead::new(&database, &base, &next, expired)
            .unwrap()
            .publish(),
        Err(Error::Store(StoreError::Unknown))
    ));
    let state = objects.state.lock().unwrap();
    assert_eq!(state.gets, 0);
    assert_eq!(state.puts.len(), 1);
    assert_eq!(state.puts[0].deadline, expired);
    assert_eq!(state.bytes, encode_head(&base.head).unwrap());
}

#[test]
fn metadata_churn_cannot_recreate_the_original_content_etag_or_rebase_a_writer() {
    let (objects, database, base) = metadata();
    let business = Database::next(&base.head, 99).unwrap();
    let old = PreparedHead::new(&database, &base, &business, deadline()).unwrap();
    let mut observed = base.clone();
    for serial in [3, 4] {
        let mut technical = observed.head.clone();
        technical.head_serial += 1;
        PreparedHead::new(&database, &observed, &technical, deadline())
            .unwrap()
            .publish()
            .unwrap();
        observed = database.read_head(deadline()).unwrap();
        assert_eq!(observed.head.head_serial, serial);
        assert_eq!(observed.head.revision, base.head.revision);
        assert_eq!(observed.head.transition, base.head.transition);
        assert_ne!(observed.etag, base.etag);
        let mut only_serial = observed.head.clone();
        only_serial.head_serial = base.head.head_serial;
        assert_eq!(only_serial, base.head);
    }
    assert!(matches!(old.publish(), Err(Error::Conflict)));
    assert_eq!(database.read_head(deadline()).unwrap().head, observed.head);
    let state = objects.state.lock().unwrap();
    assert_eq!(state.puts.len(), 3);
    assert_eq!(state.puts[2].condition.as_ref(), Some(&base.etag));
    assert_eq!(state.puts[2].bytes, encode_head(&business).unwrap());
    let next = Database::next(&observed.head, 100).unwrap();
    assert_eq!((next.revision, next.head_serial), (3, 5));
    assert_eq!(
        decode_head(&encode_head(&next).unwrap(), &scope()).unwrap(),
        next
    );
}

#[test]
fn initial_authority_requires_original_scope_and_first_business_and_technical_ordinals() {
    let (objects, database, base) = metadata();
    let mut initial = base.head;
    initial.revision = 1;
    initial.transition.revision = 1;
    initial.head_serial = 1;
    initial.active = false;
    for cut in 0..5 {
        let mut invalid = initial.clone();
        match cut {
            0 => invalid.scope.incarnation += 1,
            1 => {
                invalid.revision = 2;
                invalid.transition.revision = 2;
                invalid.head_serial = 2;
            }
            2 => invalid.head_serial = 2,
            3 => invalid.format = 4,
            _ => invalid.storage.allocated_through = 2,
        }
        assert!(matches!(
            database.create_head(&invalid, deadline()),
            Err(Error::Format(FormatError::Invalid))
        ));
    }
    assert!(objects.state.lock().unwrap().puts.is_empty());
    assert!(matches!(
        database.create_head(&initial, deadline()),
        Err(Error::Store(StoreError::Conflict))
    ));
    let state = objects.state.lock().unwrap();
    assert_eq!(state.gets, 0);
    assert_eq!(state.puts.len(), 1);
    assert_eq!(state.puts[0].condition, None);
}
