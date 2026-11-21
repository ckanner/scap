use super::*;
use scap_object_sqlite::PageChange;
use scap_object_store::Stored;
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;

pub(super) const TEST_WINDOW: u32 = 8;

// Small fixtures are explicit and do not change production creation defaults.
pub(super) fn test_options() -> Options {
    let mut options = Options::default();
    options.quota.max_bytes = Some(64 * PAGE_SIZE as u64);
    options.retention.max_entries = TEST_WINDOW;
    options
}

// A small test oracle only; the production recovery path streams into a file.
impl Database {
    fn image(&self, head: &Head, until: Instant) -> Result<Vec<u8>, Error> {
        let objects = ObjectContext::capture(self, head).unwrap();
        let manifest = data_tree::manifest(&objects, &head.data_root, until)?;
        let mut bytes = Vec::new();
        data_tree::walk(&objects, &manifest, until, |_, chunk| {
            bytes.extend_from_slice(chunk);
            Ok(())
        })?;
        Ok(bytes)
    }
}

// Direct candidate fixtures deliberately bypass SQL admission. Their original
// Snapshot, request and deadline still share one captured object context.
pub(super) fn attempt(
    database: &Database,
    base: &Snapshot,
    request: &Request,
    deadline: Instant,
) -> AttemptContext {
    AttemptContext {
        base: base.clone(),
        objects: ObjectContext::from_snapshot(database, base, deadline).unwrap(),
        request: request.clone(),
        deadline,
    }
}

#[derive(Default)]
pub(super) struct Memory {
    inner: Mutex<State>,
}

#[derive(Default)]
struct State {
    values: BTreeMap<String, Stored>,
    serial: u64,
    failures: Vec<(bool, String, StoreError)>,
    lose_cas: bool,
    corrupt_create: bool,
    gets: usize,
    operations: usize,
    fail_at: Option<usize>,
    preserve_replaced_etag: bool,
    replace: Option<(usize, String, Vec<u8>)>,
    get_keys: Vec<String>,
    put_keys: Vec<String>,
    remove_directory_on_get: Option<(String, std::path::PathBuf)>,
}

impl Memory {
    pub(super) fn operation_count(&self) -> usize {
        self.inner.lock().unwrap().operations
    }

    pub(super) fn get_count(&self) -> usize {
        self.inner.lock().unwrap().gets
    }

    pub(super) fn fail_after(&self, offset: usize) {
        let mut state = self.inner.lock().unwrap();
        state.fail_at = Some(state.operations + offset);
    }

    pub(super) fn entries(&self) -> Vec<(String, Stored)> {
        self.inner
            .lock()
            .unwrap()
            .values
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect()
    }

    pub(super) fn remove(&self, key: &str) {
        self.inner.lock().unwrap().values.remove(key);
    }

    pub(super) fn delete_exact(&self, key: &str, etag: &str) -> scap_object_store::DeleteOutcome {
        let mut state = self.inner.lock().unwrap();
        match state.values.get(key) {
            None => scap_object_store::DeleteOutcome::Missing,
            Some(value) if format!("\"{}\"", value.etag) != etag => {
                scap_object_store::DeleteOutcome::Conflict
            }
            Some(_) => {
                state.values.remove(key);
                scap_object_store::DeleteOutcome::Applied
            }
        }
    }

    pub(super) fn set(&self, key: String, bytes: Vec<u8>) {
        let mut state = self.inner.lock().unwrap();
        state.serial += 1;
        let etag = state.serial.to_string();
        state.values.insert(key, Stored { bytes, etag });
    }

    pub(super) fn fail(&self, put: bool, key: String, error: StoreError) {
        self.inner.lock().unwrap().failures.push((put, key, error));
    }

    pub(super) fn lose_next_cas(&self) {
        self.inner.lock().unwrap().lose_cas = true;
    }

    pub(super) fn gets_for(&self, key: &str) -> usize {
        self.inner
            .lock()
            .unwrap()
            .get_keys
            .iter()
            .filter(|value| *value == key)
            .count()
    }

    pub(super) fn puts_for(&self, key: &str) -> usize {
        self.inner
            .lock()
            .unwrap()
            .put_keys
            .iter()
            .filter(|value| *value == key)
            .count()
    }

    pub(super) fn replace_after(
        &self,
        count: usize,
        key: String,
        bytes: Vec<u8>,
        preserve_etag: bool,
    ) {
        let mut state = self.inner.lock().unwrap();
        state.replace = Some((state.gets + count, key, bytes));
        state.preserve_replaced_etag = preserve_etag;
    }

    pub(super) fn remove_directory_when_reading(&self, key: String, path: std::path::PathBuf) {
        self.inner.lock().unwrap().remove_directory_on_get = Some((key, path));
    }
}

impl Objects for Memory {
    fn get(&self, key: &str, max_bytes: usize, deadline: Instant) -> Result<Stored, StoreError> {
        if Instant::now() >= deadline {
            return Err(StoreError::Unknown);
        }
        let mut state = self.inner.lock().unwrap();
        state.operations += 1;
        if state.fail_at == Some(state.operations) {
            return Err(StoreError::Unknown);
        }
        state.gets += 1;
        state.get_keys.push(key.to_owned());
        if state
            .remove_directory_on_get
            .as_ref()
            .is_some_and(|item| item.0 == key)
        {
            let (_, path) = state.remove_directory_on_get.take().unwrap();
            std::fs::remove_dir_all(path).unwrap();
        }
        if state.replace.as_ref().is_some_and(|r| r.0 == state.gets) {
            let (_, target, bytes) = state.replace.take().unwrap();
            state.serial += 1;
            let etag = if state.preserve_replaced_etag {
                state.values.get(&target).unwrap().etag.clone()
            } else {
                state.serial.to_string()
            };
            state.values.insert(target, Stored { bytes, etag });
        }
        if let Some(index) = state
            .failures
            .iter()
            .position(|f| !f.0 && (f.1 == key || f.1 == "*"))
        {
            return Err(state.failures.remove(index).2);
        }
        let value = state.values.get(key).ok_or(StoreError::Missing)?;
        if value.bytes.len() > max_bytes {
            return Err(StoreError::Limit);
        }
        Ok(Stored {
            bytes: value.bytes.clone(),
            etag: value.etag.clone(),
        })
    }

    fn put(
        &self,
        key: &str,
        bytes: &[u8],
        condition: Condition<'_>,
        deadline: Instant,
    ) -> Result<String, StoreError> {
        if Instant::now() >= deadline {
            return Err(StoreError::Unknown);
        }
        let mut state = self.inner.lock().unwrap();
        state.operations += 1;
        state.put_keys.push(key.to_owned());
        if state.fail_at == Some(state.operations) {
            return Err(StoreError::Unknown);
        }
        if let Some(index) = state
            .failures
            .iter()
            .position(|f| f.0 && (f.1 == key || f.1 == "*"))
        {
            return Err(state.failures.remove(index).2);
        }
        let old = state.values.get(key);
        match condition {
            Condition::Absent if old.is_some() => return Err(StoreError::Conflict),
            Condition::Match(etag) if old.is_none_or(|v| v.etag != etag) => {
                return Err(StoreError::Conflict)
            }
            _ => {}
        }
        state.serial += 1;
        let etag = state.serial.to_string();
        let stored = if state.corrupt_create && matches!(condition, Condition::Absent) {
            vec![0]
        } else {
            bytes.to_vec()
        };
        state.values.insert(
            key.to_owned(),
            Stored {
                bytes: stored,
                etag: etag.clone(),
            },
        );
        if state.lose_cas && matches!(condition, Condition::Match(_)) {
            state.lose_cas = false;
            return Err(StoreError::Unknown);
        }
        Ok(etag)
    }
}

pub(super) fn scope() -> Scope {
    Scope {
        deployment: 1,
        tenant: 2,
        database: 3,
        incarnation: 4,
        generation: 5,
    }
}
pub(super) fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(60)
}
pub(super) fn sql(text: &str) -> Vec<Statement> {
    vec![Statement {
        sql: text.to_owned(),
        parameters: vec![],
    }]
}
pub(super) fn fixture() -> (Arc<Memory>, Database) {
    let objects = Arc::new(Memory::default());
    let database = Database::with_options(objects.clone(), scope(), 10, test_options()).unwrap();
    database.create(7, 1, deadline()).unwrap();
    database.activate(7, 1, 2, deadline()).unwrap();
    (objects, database)
}
pub(super) fn identity(id: u64) -> Request {
    request(1, id, 7, &sql("SELECT 1")).unwrap()
}
pub(super) fn replace_head(objects: &Memory, database: &Database, f: impl FnOnce(&mut Head)) {
    let mut head = database.read_head(deadline()).unwrap().head;
    f(&mut head);
    objects.set(head_key(&database.scope), encode_head(&head).unwrap());
}
fn empty_result() -> TransactionResult {
    TransactionResult { statements: vec![] }
}
fn sample_receipt() -> Receipt {
    Receipt {
        scope: scope(),
        request: identity(1),
        sequence: 1,
        transition: Transition {
            revision: 3,
            nonce: 1,
        },
        data_root: digest(b"data"),
        result_hash: digest(b"result"),
    }
}

#[test]
fn explicit_creation_rejects_reuse_and_missing_is_not_auto_initialized() {
    let objects = Arc::new(Memory::default());
    let database = Database::new(objects.clone(), scope(), 10).unwrap();
    assert!(matches!(
        database.status(7, deadline()),
        Err(Error::Store(StoreError::Missing))
    ));
    assert!(matches!(
        Database::new(objects.clone(), scope(), 0),
        Err(Error::Fenced)
    ));
    let mut bad_scope = scope();
    bad_scope.tenant = 0;
    assert!(matches!(
        Database::new(objects.clone(), bad_scope, 1),
        Err(Error::Format(_))
    ));
    assert!(matches!(
        database.create(0, 1, deadline()),
        Err(Error::Format(_))
    ));
    let head = database.create(7, 1, deadline()).unwrap();
    assert!(!head.active);
    assert!(matches!(
        database.create(7, 1, deadline()),
        Err(Error::Store(StoreError::Conflict))
    ));
    assert!(matches!(
        database.status(7, Instant::now()),
        Err(Error::Store(StoreError::Unknown))
    ));
    assert!(matches!(
        request(0, 1, 7, &sql("SELECT 1")),
        Err(Error::Format(_))
    ));
    assert!(matches!(request(1, 1, 7, &[]), Err(Error::Sql(_))));
}

#[test]
fn real_sql_and_random_result_survive_complete_compute_reconstruction() {
    let (objects, database) = fixture();
    let temp = tempfile::tempdir().unwrap();
    let statements = sql("CREATE TABLE items(id INTEGER PRIMARY KEY, value TEXT)");
    let first = request(1, 1, 7, &statements).unwrap();
    database
        .execute(7, &first, &statements, &temp.path().join("ddl"), deadline())
        .unwrap();
    let statements =
        sql("INSERT INTO items(value) VALUES (hex(randomblob(16))) RETURNING id, value");
    let second = request(1, 2, 7, &statements).unwrap();
    let (receipt, result) = database
        .execute(
            7,
            &second,
            &statements,
            &temp.path().join("write"),
            deadline(),
        )
        .unwrap();
    assert_eq!(receipt.sequence, 2);
    let original = result.statements[0].rows[0].clone();
    temp.close().unwrap();
    drop(database);
    let restarted = Database::new(objects, scope(), 11).unwrap();
    let head = restarted.status(7, deadline()).unwrap();
    let recovering = restarted.takeover(7, head.revision, 9, deadline()).unwrap();
    assert!(!recovering.active);
    restarted
        .activate(7, recovering.revision, 10, deadline())
        .unwrap();
    let fresh = tempfile::tempdir().unwrap();
    let query = restarted
        .query(
            7,
            &sql("SELECT id, value FROM items"),
            &fresh.path().join("read"),
            deadline(),
        )
        .unwrap();
    assert_eq!(query.statements[0].rows[0], original);
    let (replayed, recovered) = restarted
        .execute(
            7,
            &second,
            &statements,
            &fresh.path().join("unused"),
            deadline(),
        )
        .unwrap();
    assert_eq!(replayed, receipt);
    assert_eq!(recovered, result);
    assert!(!fresh.path().join("unused").exists());
}

#[test]
fn response_loss_keeps_original_identity_and_random_result() {
    let (objects, database) = fixture();
    let temp = tempfile::tempdir().unwrap();
    let statements = sql("SELECT hex(randomblob(16))");
    let identity = request(1, 10, 7, &statements).unwrap();
    objects.inner.lock().unwrap().lose_cas = true;
    assert!(matches!(
        database.execute(
            7,
            &identity,
            &statements,
            &temp.path().join("attempt"),
            deadline()
        ),
        Err(Error::Store(StoreError::Unknown))
    ));
    let Resolution::Committed { receipt, bytes } =
        database.lookup(7, &identity, deadline()).unwrap()
    else {
        panic!()
    };
    let original = scap_sql::decode_result(&bytes, sql_limits()).unwrap();
    assert_eq!(
        database.cancel(7, &identity, deadline()).unwrap(),
        Resolution::Committed { receipt, bytes }
    );
    let (_, result) = database
        .execute(
            7,
            &identity,
            &statements,
            &temp.path().join("not-executed"),
            deadline(),
        )
        .unwrap();
    assert_eq!(result, original);
    assert!(!temp.path().join("not-executed").exists());
}

#[test]
fn cancellation_fences_late_candidate_and_lookup_absence_is_unknown() {
    let (_, database) = fixture();
    let identity = identity(11);
    let base = database.read_head(deadline()).unwrap();
    assert_eq!(
        database.lookup(7, &identity, deadline()).unwrap(),
        Resolution::Unknown
    );
    let cancelled = database.cancel(7, &identity, deadline()).unwrap();
    assert!(matches!(cancelled, Resolution::Cancelled { .. }));
    assert_eq!(
        database.cancel(7, &identity, deadline()).unwrap(),
        cancelled
    );
    assert!(matches!(
        database.commit(
            &crate::tests::attempt(&database, &base, &identity, deadline()),
            &PageBatch {
                size_after: 0,
                pages: vec![]
            },
            b"result"
        ),
        Err(Error::Conflict)
    ));
    let temp = tempfile::tempdir().unwrap();
    assert!(matches!(
        database.execute(
            7,
            &identity,
            &sql("SELECT 1"),
            &temp.path().join("no"),
            deadline()
        ),
        Err(Error::Closed)
    ));
    let mut changed = identity.clone();
    changed.fingerprint = digest(b"different");
    assert!(matches!(
        database.lookup(7, &changed, deadline()),
        Err(Error::RequestConflict)
    ));
    changed = identity.clone();
    changed.principal = 8;
    assert!(matches!(
        database.lookup(7, &changed, deadline()),
        Err(Error::Denied)
    ));
    assert!(matches!(
        database.cancel(7, &changed, deadline()),
        Err(Error::Denied)
    ));
    changed = identity.clone();
    changed.epoch = 2;
    assert!(matches!(
        database.lookup(7, &changed, deadline()),
        Err(Error::RequestConflict)
    ));
    changed.epoch = 0;
    assert!(matches!(
        database.lookup(7, &changed, deadline()),
        Err(Error::Format(_))
    ));
}

#[test]
fn policy_owner_lifecycle_and_revision_bind_every_operation() {
    let (objects, database) = fixture();
    let temp = tempfile::tempdir().unwrap();
    assert!(matches!(database.status(8, deadline()), Err(Error::Denied)));
    let policy = vec![
        Permission {
            principal: 7,
            read: true,
            write: true,
            admin: true,
        },
        Permission {
            principal: 8,
            read: false,
            write: false,
            admin: false,
        },
    ];
    let changed = database.set_policy(7, 2, 4, policy, deadline()).unwrap();
    assert!(matches!(database.status(8, deadline()), Err(Error::Denied)));
    assert!(matches!(
        database.takeover(8, changed.revision, 5, deadline()),
        Err(Error::Denied)
    ));
    assert!(matches!(
        database.takeover(7, 1, 5, deadline()),
        Err(Error::Conflict)
    ));
    let other = Database::new(objects.clone(), scope(), 20).unwrap();
    assert!(matches!(
        other.execute(
            7,
            &identity(1),
            &sql("SELECT 1"),
            &temp.path().join("fenced"),
            deadline()
        ),
        Err(Error::Fenced)
    ));
    let recovering = other.takeover(7, changed.revision, 6, deadline()).unwrap();
    assert!(matches!(
        database.activate(7, recovering.revision, 7, deadline()),
        Err(Error::Fenced)
    ));
    let active = other
        .activate(7, recovering.revision, 7, deadline())
        .unwrap();
    assert!(matches!(
        other.activate(7, active.revision, 8, deadline()),
        Err(Error::Fenced)
    ));
    let maintenance = other
        .set_lifecycle(7, active.revision, 9, Lifecycle::Maintenance, deadline())
        .unwrap();
    assert!(matches!(
        other.takeover(7, maintenance.revision, 10, deadline()),
        Err(Error::Lifecycle)
    ));
    assert!(matches!(
        other.execute(
            7,
            &identity(2),
            &sql("SELECT 1"),
            &temp.path().join("maintenance"),
            deadline()
        ),
        Err(Error::Lifecycle)
    ));
    assert!(other
        .query(
            7,
            &sql("SELECT 1"),
            &temp.path().join("maintenance-read"),
            deadline()
        )
        .is_ok());
    let deleted = other
        .set_lifecycle(7, maintenance.revision, 11, Lifecycle::Deleted, deadline())
        .unwrap();
    assert_eq!(deleted.lifecycle, Lifecycle::Deleted);
    assert!(matches!(other.status(7, deadline()), Err(Error::Lifecycle)));
    assert!(matches!(
        other.set_lifecycle(7, deleted.revision, 12, Lifecycle::Ready, deadline()),
        Err(Error::Lifecycle)
    ));
}

#[test]
fn bounded_generation_retention_never_fabricates_cancellation() {
    let (_, database) = fixture();
    assert!(matches!(
        database.close_full(7, 2, 1, deadline()),
        Err(Error::WindowFull)
    ));
    for epoch in 1..=3 {
        for id in 1..=TEST_WINDOW as u64 {
            let mut identity = identity(id);
            identity.epoch = epoch;
            database.cancel(7, &identity, deadline()).unwrap();
        }
        let mut full = identity(999);
        full.epoch = epoch;
        assert!(matches!(
            database.cancel(7, &full, deadline()),
            Err(Error::WindowFull)
        ));
        let temp = tempfile::tempdir().unwrap();
        assert!(matches!(
            database.execute(
                7,
                &full,
                &sql("SELECT 1"),
                &temp.path().join("full"),
                deadline()
            ),
            Err(Error::WindowFull)
        ));
        let head = database.status(7, deadline()).unwrap();
        database
            .close_full(7, head.revision, epoch, deadline())
            .unwrap();
        if epoch == 1 {
            assert_eq!(
                database.lookup(7, &full, deadline()).unwrap(),
                Resolution::Closed
            );
            assert!(matches!(
                database.execute(
                    7,
                    &full,
                    &sql("SELECT 1"),
                    &temp.path().join("closed"),
                    deadline()
                ),
                Err(Error::Closed)
            ));
        }
    }
    assert_eq!(
        database.lookup(7, &identity(1), deadline()).unwrap(),
        Resolution::Retired
    );
    let temp = tempfile::tempdir().unwrap();
    assert!(matches!(
        database.execute(
            7,
            &identity(1),
            &sql("SELECT 1"),
            &temp.path().join("retired"),
            deadline()
        ),
        Err(Error::Retired)
    ));
    assert_eq!(database.status(7, deadline()).unwrap().windows.len(), 3);
}

#[test]
fn corrupt_missing_and_wrong_kind_objects_fail_closed() {
    let (objects, database) = fixture();
    let base = database.read_head(deadline()).unwrap();
    let original = objects
        .get(&head_key(&scope()), MAX_HEAD_BYTES, deadline())
        .unwrap();
    objects.set(head_key(&scope()), b"not json".to_vec());
    assert!(matches!(
        database.status(7, deadline()),
        Err(Error::Format(_))
    ));
    objects.set(head_key(&scope()), original.bytes);
    objects
        .inner
        .lock()
        .unwrap()
        .values
        .get_mut(&head_key(&scope()))
        .unwrap()
        .etag
        .clear();
    assert!(matches!(
        database.status(7, deadline()),
        Err(Error::Corrupt)
    ));
    objects.set(head_key(&scope()), encode_head(&base.head).unwrap());
    let key = object_key(&scope(), 1, &base.head.data_root);
    objects.fail(false, key.clone(), StoreError::Missing);
    assert!(matches!(
        database.image(&base.head, deadline()),
        Err(Error::Store(StoreError::Missing))
    ));
    objects.set(key.clone(), b"broken".to_vec());
    assert!(matches!(
        database.image(&base.head, deadline()),
        Err(Error::Format(_))
    ));
    let wrong = ObjectContext::bootstrap(&database)
        .unwrap()
        .save(crate::tests::index_payload(1, vec![]), deadline())
        .unwrap();
    let mut head = base.head.clone();
    head.data_root = wrong.clone();
    assert!(matches!(
        database.image(&head, deadline()),
        Err(Error::Corrupt)
    ));
    let page = ObjectContext::bootstrap(&database)
        .unwrap()
        .save(
            Payload::Chunk {
                first_page: 1,
                bytes: vec![0; PAGE_SIZE],
            },
            deadline(),
        )
        .unwrap();
    head.data_root = ObjectContext::bootstrap(&database)
        .unwrap()
        .save(
            Payload::Manifest(Manifest {
                page_count: 1,
                root: Some(page),
            }),
            deadline(),
        )
        .unwrap();
    assert!(matches!(
        database.image(&head, deadline()),
        Err(Error::Corrupt)
    ));
    head.data_root = ObjectContext::bootstrap(&database)
        .unwrap()
        .save(
            Payload::Manifest(Manifest {
                page_count: 1,
                root: Some(wrong),
            }),
            deadline(),
        )
        .unwrap();
    assert!(matches!(
        database.image(&head, deadline()),
        Err(Error::Corrupt)
    ));
    let mut window = base.head.windows[0].clone();
    window.root = head.data_root;
    assert!(matches!(
        crate::tests::index_entries(&database, &window, deadline()),
        Err(Error::Corrupt)
    ));
    window = base.head.windows[0].clone();
    window.count = 1;
    assert!(matches!(
        crate::tests::index_entries(&database, &window, deadline()),
        Err(Error::Corrupt)
    ));
    let mut foreign = identity(3);
    foreign.epoch = 2;
    window.root = ObjectContext::bootstrap(&database)
        .unwrap()
        .save(
            crate::tests::index_payload(
                2,
                vec![Entry {
                    result_bytes: 0,
                    request: foreign,
                    outcome: OutcomeRef::Cancelled {
                        transition: Transition {
                            revision: 1,
                            nonce: 1,
                        },
                    },
                }],
            ),
            deadline(),
        )
        .unwrap();
    assert!(matches!(
        crate::tests::index_entries(&database, &window, deadline()),
        Err(Error::Corrupt)
    ));
}

#[test]
fn uploads_are_immutable_verified_and_fail_without_head_publication() {
    let (objects, database) = fixture();
    objects.fail(true, "*".into(), StoreError::Unknown);
    assert!(matches!(
        ObjectContext::bootstrap(&database).unwrap().save(
            Payload::Chunk {
                first_page: 1,
                bytes: vec![1; PAGE_SIZE]
            },
            deadline()
        ),
        Err(Error::Store(StoreError::Unknown))
    ));
    objects.inner.lock().unwrap().corrupt_create = true;
    assert!(matches!(
        ObjectContext::bootstrap(&database).unwrap().save(
            Payload::Chunk {
                first_page: 1,
                bytes: vec![2; PAGE_SIZE]
            },
            deadline()
        ),
        Err(Error::Corrupt)
    ));
    objects.inner.lock().unwrap().corrupt_create = false;
    objects.fail(false, "*".into(), StoreError::Missing);
    assert!(matches!(
        ObjectContext::bootstrap(&database).unwrap().save(
            Payload::Chunk {
                first_page: 1,
                bytes: vec![3; PAGE_SIZE]
            },
            deadline()
        ),
        Err(Error::Store(StoreError::Missing))
    ));
    assert!(matches!(
        ObjectContext::bootstrap(&database).unwrap().save(
            Payload::Chunk {
                first_page: 1,
                bytes: vec![0]
            },
            deadline()
        ),
        Err(Error::Format(_))
    ));
    let (objects, database) = fixture();
    let base = database.read_head(deadline()).unwrap();
    let mut next = Database::next(&base.head, 1).unwrap();
    next.transition.nonce = 0;
    assert!(matches!(
        database.publish(&base, &next, deadline()),
        Err(Error::Format(_))
    ));
    let next = Database::next(&base.head, 1).unwrap();
    objects.fail(true, head_key(&scope()), StoreError::Unknown);
    assert!(matches!(
        database.publish(&base, &next, deadline()),
        Err(Error::Store(StoreError::Unknown))
    ));
}

#[test]
fn precise_page_deltas_reuse_unchanged_pages_and_validate_bounds() {
    let (_, database) = fixture();
    let base = database.read_head(deadline()).unwrap();
    let page = PageChange {
        number: 1,
        bytes: vec![1; PAGE_SIZE],
    };
    let batch = PageBatch {
        size_after: 1,
        pages: vec![page.clone()],
    };
    let first = database
        .commit(
            &crate::tests::attempt(&database, &base, &identity(1), deadline()),
            &batch,
            b"one",
        )
        .unwrap();
    let base = database.read_head(deadline()).unwrap();
    let unchanged = PageBatch {
        size_after: 1,
        pages: vec![],
    };
    let second = database
        .commit(
            &crate::tests::attempt(&database, &base, &identity(2), deadline()),
            &unchanged,
            b"two",
        )
        .unwrap();
    assert_eq!(first.data_root, second.data_root);
    let base = database.read_head(deadline()).unwrap();
    for invalid in [
        PageBatch {
            size_after: 65,
            pages: vec![],
        },
        PageBatch {
            size_after: 2,
            pages: vec![],
        },
        PageBatch {
            size_after: 1,
            pages: vec![page.clone(), page],
        },
        PageBatch {
            size_after: 1,
            pages: vec![PageChange {
                number: 0,
                bytes: vec![0; PAGE_SIZE],
            }],
        },
        PageBatch {
            size_after: 1,
            pages: vec![PageChange {
                number: 2,
                bytes: vec![0; PAGE_SIZE],
            }],
        },
        PageBatch {
            size_after: 1,
            pages: vec![PageChange {
                number: 1,
                bytes: vec![0],
            }],
        },
    ] {
        assert!(database
            .commit(
                &crate::tests::attempt(&database, &base, &identity(3), deadline()),
                &invalid,
                b"x"
            )
            .is_err());
    }
    let mut head = base.head.clone();
    let transition = head.transition.clone();
    assert!(matches!(
        database.append(
            &ObjectContext::capture(&database, &head).unwrap(),
            &mut head,
            Entry {
                result_bytes: 0,
                request: identity(1),
                outcome: OutcomeRef::Cancelled { transition }
            },
            deadline()
        ),
        Err(Error::RequestConflict)
    ));
    database
        .commit(
            &crate::tests::attempt(&database, &base, &identity(3), deadline()),
            &PageBatch {
                size_after: 0,
                pages: vec![],
            },
            b"truncate",
        )
        .unwrap();
    assert_eq!(
        database
            .image(&database.read_head(deadline()).unwrap().head, deadline())
            .unwrap(),
        Vec::<u8>::new()
    );
}

#[test]
fn authorization_checks_each_permission_and_recovery_cannot_activate_stale_head() {
    let (objects, database) = fixture();
    let mut head = database.status(7, deadline()).unwrap();
    head.policy[0].read = false;
    assert!(matches!(
        Database::authorize(&head, 7, true, false, false),
        Err(Error::Denied)
    ));
    head.policy[0].read = true;
    head.policy[0].write = false;
    assert!(matches!(
        Database::authorize(&head, 7, false, true, false),
        Err(Error::Denied)
    ));
    head.policy[0].write = true;
    head.policy[0].admin = false;
    assert!(matches!(
        Database::authorize(&head, 7, false, false, true),
        Err(Error::Denied)
    ));
    let recovering = database.takeover(7, 2, 4, deadline()).unwrap();
    let mut changed = Database::next(&recovering, 5).unwrap();
    changed.auth_epoch += 1;
    let mut state = objects.inner.lock().unwrap();
    state.replace = Some((
        state.gets + 2,
        head_key(&scope()),
        encode_head(&changed).unwrap(),
    ));
    drop(state);
    assert!(matches!(
        database.activate(7, recovering.revision, 6, deadline()),
        Err(Error::Conflict)
    ));
}

#[test]
fn arithmetic_exhaustion_is_fail_closed() {
    let (objects, database) = fixture();
    replace_head(&objects, &database, |h| {
        h.revision = u64::MAX;
        h.head_serial = u64::MAX;
        h.transition.revision = u64::MAX;
    });
    assert!(matches!(
        database.takeover(7, u64::MAX, 3, deadline()),
        Err(Error::Limit)
    ));
    replace_head(&objects, &database, |h| {
        h.revision = 2;
        h.head_serial = 2;
        h.transition.revision = 2;
        h.owner_epoch = u64::MAX;
    });
    assert!(matches!(
        database.takeover(7, 2, 3, deadline()),
        Err(Error::Limit)
    ));
    replace_head(&objects, &database, |h| h.auth_epoch = u64::MAX);
    assert!(matches!(
        database.set_policy(7, 2, 3, vec![], deadline()),
        Err(Error::Limit)
    ));
    replace_head(&objects, &database, |h| h.sequence = u64::MAX);
    let base = database.read_head(deadline()).unwrap();
    assert!(matches!(
        database.commit(
            &crate::tests::attempt(&database, &base, &identity(1), deadline()),
            &PageBatch {
                size_after: 0,
                pages: vec![]
            },
            b"x"
        ),
        Err(Error::Limit)
    ));
}

#[test]
fn completion_requires_both_authority_and_native_publication() {
    let receipt = sample_receipt();
    assert!(Database::finish(Some(Ok(receipt.clone())), Ok(empty_result())).is_ok());
    assert!(matches!(
        Database::finish(
            Some(Ok(receipt)),
            Err(scap_object_sqlite::Error::OutcomeUnknown)
        ),
        Err(Error::CommittedButUnavailable(_))
    ));
    assert!(matches!(
        Database::finish(Some(Err(Error::Conflict)), Ok(empty_result())),
        Err(Error::Conflict)
    ));
    assert!(matches!(
        Database::finish(None, Err(scap_object_sqlite::Error::OutcomeUnknown)),
        Err(Error::Engine(_))
    ));
    assert!(matches!(
        Database::finish(None, Ok(empty_result())),
        Err(Error::Unknown)
    ));
    let (_, database) = fixture();
    let mut unarmed = PublishGate {
        database,
        state: Rc::new(RefCell::new(Publication::default())),
    };
    assert!(matches!(
        unarmed.publish(
            &PageBatch {
                size_after: 0,
                pages: vec![]
            },
            b""
        ),
        GateDecision::Unknown
    ));
}

#[test]
fn invalid_sql_identity_and_local_cache_failures_do_not_publish() {
    let (_, database) = fixture();
    let temp = tempfile::tempdir().unwrap();
    assert!(matches!(
        database.execute(
            7,
            &identity(1),
            &sql("SELECT 2"),
            &temp.path().join("different"),
            deadline()
        ),
        Err(Error::RequestConflict)
    ));
    let bad = sql("THIS IS NOT SQL");
    let id = request(1, 2, 7, &bad).unwrap();
    assert!(matches!(
        database.execute(7, &id, &bad, &temp.path().join("invalid"), deadline()),
        Err(Error::Engine(_))
    ));
    assert!(matches!(
        database.execute(7, &identity(3), &sql("SELECT 1"), temp.path(), deadline()),
        Err(Error::Engine(_))
    ));
    assert!(matches!(
        database.query(7, &sql("SELECT 1"), temp.path(), deadline()),
        Err(Error::Engine(_))
    ));
    assert!(matches!(
        database.query(
            7,
            &sql("CREATE TABLE forbidden(x)"),
            &temp.path().join("readonly"),
            deadline()
        ),
        Err(Error::Engine(_))
    ));
    assert_eq!(database.status(7, deadline()).unwrap().sequence, 0);
}

fn prepare_operation(name: &str) -> (Arc<Memory>, Database) {
    let (objects, database) = fixture();
    if name == "create" {
        objects.inner.lock().unwrap().values.clear();
    } else if name == "activate" || name == "activate_session" {
        replace_head(&objects, &database, |h| h.active = false);
        // Recovery must include a retained result, not just empty metadata.
        let mut head = database.read_head(deadline()).unwrap().head;
        let result = ObjectContext::bootstrap(&database)
            .unwrap()
            .save(
                Payload::Result(StoredResult {
                    request: identity(1),
                    sequence: 1,
                    transition: Transition {
                        revision: 2,
                        nonce: 1,
                    },
                    data_root: head.data_root.clone(),
                    bytes: scap_sql::encode_result(&empty_result(), sql_limits()).unwrap(),
                }),
                deadline(),
            )
            .unwrap();
        head.sequence = 1;
        database
            .append(
                &ObjectContext::capture(&database, &head).unwrap(),
                &mut head,
                Entry {
                    result_bytes: scap_sql::encode_result(&empty_result(), sql_limits())
                        .unwrap()
                        .len() as u64,
                    request: identity(1),
                    outcome: OutcomeRef::Committed { result },
                },
                deadline(),
            )
            .unwrap();
        objects.set(head_key(&scope()), encode_head(&head).unwrap());
    } else if name == "close" {
        let mut head = database.read_head(deadline()).unwrap().head;
        let entries = (1..=TEST_WINDOW as u64)
            .map(|id| Entry {
                result_bytes: 0,
                request: identity(id),
                outcome: OutcomeRef::Cancelled {
                    transition: Transition {
                        revision: head.revision,
                        nonce: id,
                    },
                },
            })
            .collect();
        head.windows[0].root = ObjectContext::bootstrap(&database)
            .unwrap()
            .save(crate::tests::index_payload(1, entries), deadline())
            .unwrap();
        head.windows[0].count = TEST_WINDOW;
        objects.set(head_key(&scope()), encode_head(&head).unwrap());
    } else if name == "lookup" {
        let base = database.read_head(deadline()).unwrap();
        database
            .commit(
                &crate::tests::attempt(&database, &base, &identity(1), deadline()),
                &PageBatch {
                    size_after: 0,
                    pages: vec![],
                },
                &scap_sql::encode_result(&empty_result(), sql_limits()).unwrap(),
            )
            .unwrap();
    }
    objects.inner.lock().unwrap().operations = 0;
    (objects, database)
}

fn run_operation(name: &str, database: &Database, path: &Path) -> Result<(), Error> {
    match name {
        "create" => database.create(7, 1, deadline()).map(|_| ()),
        "status" => database.status(7, deadline()).map(|_| ()),
        "activate" => database.activate(7, 2, 5, deadline()).map(|_| ()),
        "activate_session" => database
            .activate_session(7, 2, 5, path, deadline())
            .map(|_| ()),
        "session" => database.session(7, path, deadline()).map(|_| ()),
        "quota" => database
            .set_quota(7, 2, 5, DatabaseQuota { max_bytes: None }, deadline())
            .map(|_| ()),
        "takeover" => database.takeover(7, 2, 5, deadline()).map(|_| ()),
        "policy" => database
            .set_policy(
                7,
                2,
                5,
                vec![Permission {
                    principal: 7,
                    read: true,
                    write: true,
                    admin: true,
                }],
                deadline(),
            )
            .map(|_| ()),
        "lifecycle" => database
            .set_lifecycle(7, 2, 5, Lifecycle::Maintenance, deadline())
            .map(|_| ()),
        "close" => database.close_full(7, 2, 5, deadline()).map(|_| ()),
        "cancel" => database.cancel(7, &identity(1), deadline()).map(|_| ()),
        "execute" => database
            .execute(7, &identity(1), &sql("SELECT 1"), path, deadline())
            .map(|_| ()),
        "query" => database
            .query(7, &sql("SELECT 1"), path, deadline())
            .map(|_| ()),
        "lookup" => database.lookup(7, &identity(1), deadline()).map(|_| ()),
        _ => unreachable!(),
    }
}

#[test]
fn each_object_io_cut_fails_without_returning_a_successful_operation() {
    for name in [
        "create",
        "status",
        "activate",
        "activate_session",
        "session",
        "quota",
        "takeover",
        "policy",
        "lifecycle",
        "close",
        "cancel",
        "execute",
        "query",
        "lookup",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let (objects, database) = prepare_operation(name);
        run_operation(name, &database, &temp.path().join("baseline")).unwrap();
        let calls = objects.inner.lock().unwrap().operations;
        for cut in 1..=calls {
            let (objects, database) = prepare_operation(name);
            objects.inner.lock().unwrap().fail_at = Some(cut);
            let outcome = run_operation(name, &database, &temp.path().join(format!("cut-{cut}")));
            assert!(outcome.is_err(), "{name} at object call {cut}/{calls}");
            assert!(objects.inner.lock().unwrap().operations >= cut);
        }
    }
}

#[test]
fn control_methods_propagate_epoch_revision_and_admission_failure() {
    for name in [
        "activate",
        "activate_session",
        "takeover",
        "policy",
        "lifecycle",
        "quota",
        "close",
    ] {
        let (objects, database) = prepare_operation(name);
        replace_head(&objects, &database, |h| {
            h.revision = u64::MAX;
            h.head_serial = u64::MAX;
            h.transition.revision = u64::MAX;
        });
        let temporary = tempfile::tempdir().unwrap();
        let outcome = match name {
            "activate_session" => database
                .activate_session(
                    7,
                    u64::MAX,
                    1,
                    &temporary.path().join("overflow"),
                    deadline(),
                )
                .map(|value| value.0),
            "quota" => database.set_quota(
                7,
                u64::MAX,
                1,
                DatabaseQuota { max_bytes: None },
                deadline(),
            ),
            "activate" => database.activate(7, u64::MAX, 1, deadline()),
            "takeover" => database.takeover(7, u64::MAX, 1, deadline()),
            "policy" => database.set_policy(7, u64::MAX, 1, vec![], deadline()),
            "lifecycle" => database.set_lifecycle(7, u64::MAX, 1, Lifecycle::Ready, deadline()),
            "close" => database.close_full(7, u64::MAX, 1, deadline()),
            _ => unreachable!(),
        };
        assert!(matches!(outcome, Err(Error::Limit)), "{name}: {outcome:?}");
    }
    let (objects, database) = prepare_operation("close");
    let mut head = database.read_head(deadline()).unwrap().head;
    head.request_epoch = u64::MAX;
    head.windows = (0..3)
        .map(|n| Window {
            epoch: u64::MAX - n,
            root: head.windows[0].root.clone(),
            count: TEST_WINDOW,
            result_bytes: 0,
        })
        .collect();
    objects.set(head_key(&scope()), encode_head(&head).unwrap());
    assert!(matches!(
        database.close_full(7, 2, 1, deadline()),
        Err(Error::Limit)
    ));
    let (objects, database) = fixture();
    replace_head(&objects, &database, |h| {
        h.revision = u64::MAX;
        h.head_serial = u64::MAX;
        h.transition.revision = u64::MAX;
    });
    assert!(matches!(
        database.cancel(7, &identity(1), deadline()),
        Err(Error::Limit)
    ));
    let base = database.read_head(deadline()).unwrap();
    assert!(matches!(
        database.commit(
            &crate::tests::attempt(&database, &base, &identity(1), deadline()),
            &PageBatch {
                size_after: 0,
                pages: vec![]
            },
            b"x"
        ),
        Err(Error::Limit)
    ));
}

#[test]
fn all_business_updates_keep_expected_revision_separate_from_head_serial() {
    for name in [
        "activate",
        "activate_session",
        "takeover",
        "policy",
        "lifecycle",
        "quota",
        "close",
        "cancel",
        "execute",
    ] {
        for exhausted in [false, true] {
            let (objects, database) = prepare_operation(name);
            replace_head(&objects, &database, |head| {
                head.head_serial = if exhausted { u64::MAX } else { 40 };
            });
            let before = database.read_head(deadline()).unwrap();
            let temporary = tempfile::tempdir().unwrap();
            let result = run_operation(name, &database, &temporary.path().join("business"));
            let after = database.read_head(deadline()).unwrap();
            if exhausted {
                assert!(matches!(result, Err(Error::Limit)), "{name}: {result:?}");
                assert_eq!(after.head, before.head, "{name}");
                assert_eq!(after.etag, before.etag, "{name}");
            } else {
                result.unwrap();
                assert_eq!(after.head.revision, 3, "{name}");
                assert_eq!(after.head.transition.revision, 3, "{name}");
                assert_eq!(after.head.head_serial, 41, "{name}");
                assert_eq!(after.head.storage, before.head.storage, "{name}");
            }
        }
    }
}

#[test]
fn retained_result_content_is_bound_to_identity_sequence_and_transition() {
    let (objects, database) = fixture();
    let head = database.read_head(deadline()).unwrap().head;
    let wrong_kind = ObjectContext::bootstrap(&database)
        .unwrap()
        .save(crate::tests::index_payload(1, vec![]), deadline())
        .unwrap();
    assert!(matches!(
        database.resolve_entry(
            &ObjectContext::capture(&database, &head).unwrap(),
            &head,
            &identity(1),
            &OutcomeRef::Committed { result: wrong_kind },
            deadline()
        ),
        Err(Error::Corrupt)
    ));
    let mut stored = StoredResult {
        request: identity(1),
        sequence: 1,
        transition: Transition {
            revision: 2,
            nonce: 1,
        },
        data_root: head.data_root.clone(),
        bytes: b"bad codec".to_vec(),
    };
    let mut accepted = head.clone();
    accepted.sequence = 1;
    for mode in 0..3 {
        let mut bad = stored.clone();
        match mode {
            0 => bad.request.id = 2,
            1 => bad.sequence = 2,
            _ => bad.transition.revision = 3,
        }
        let result = ObjectContext::bootstrap(&database)
            .unwrap()
            .save(Payload::Result(bad), deadline())
            .unwrap();
        assert!(matches!(
            database.resolve_entry(
                &ObjectContext::capture(&database, &accepted).unwrap(),
                &accepted,
                &identity(1),
                &OutcomeRef::Committed { result },
                deadline()
            ),
            Err(Error::Corrupt)
        ));
    }
    assert!(matches!(
        database.resolve_entry(
            &ObjectContext::capture(&database, &accepted).unwrap(),
            &accepted,
            &identity(1),
            &OutcomeRef::Cancelled {
                transition: Transition {
                    revision: 3,
                    nonce: 1
                }
            },
            deadline()
        ),
        Err(Error::Corrupt)
    ));
    stored.sequence = 1;
    let result = ObjectContext::bootstrap(&database)
        .unwrap()
        .save(Payload::Result(stored), deadline())
        .unwrap();
    database
        .append(
            &ObjectContext::capture(&database, &accepted).unwrap(),
            &mut accepted,
            Entry {
                result_bytes: b"bad codec".len() as u64,
                request: identity(1),
                outcome: OutcomeRef::Committed { result },
            },
            deadline(),
        )
        .unwrap();
    objects.set(head_key(&scope()), encode_head(&accepted).unwrap());
    let temp = tempfile::tempdir().unwrap();
    assert!(matches!(
        database.execute(
            7,
            &identity(1),
            &sql("SELECT 1"),
            &temp.path().join("not-run"),
            deadline()
        ),
        Err(Error::Corrupt)
    ));
}

#[test]
fn admission_and_physical_failure_boundaries_are_explicit() {
    let (objects, database) = fixture();
    let temp = tempfile::tempdir().unwrap();
    let foreign = request(1, 1, 8, &sql("SELECT 1")).unwrap();
    assert!(matches!(
        database.cancel(8, &foreign, deadline()),
        Err(Error::Denied)
    ));
    assert!(matches!(
        database.execute(
            8,
            &foreign,
            &sql("SELECT 1"),
            &temp.path().join("denied"),
            deadline()
        ),
        Err(Error::Denied)
    ));
    assert!(matches!(
        database.query(
            8,
            &sql("SELECT 1"),
            &temp.path().join("denied-read"),
            deadline()
        ),
        Err(Error::Denied)
    ));
    assert!(matches!(
        database.execute(7, &identity(1), &[], &temp.path().join("empty"), deadline()),
        Err(Error::Sql(_))
    ));
    let mut base = database.read_head(deadline()).unwrap();
    base.head.active = false;
    assert!(matches!(
        database.commit(
            &crate::tests::attempt(&database, &base, &identity(1), deadline()),
            &PageBatch {
                size_after: 0,
                pages: vec![]
            },
            b""
        ),
        Err(Error::Fenced)
    ));
    replace_head(&objects, &database, |h| {
        h.lifecycle = Lifecycle::Maintenance
    });
    assert!(matches!(
        database.activate(7, 2, 3, deadline()),
        Err(Error::Lifecycle)
    ));
    replace_head(&objects, &database, |h| h.lifecycle = Lifecycle::Ready);
    let page = vec![42; PAGE_SIZE];
    let page_root = ObjectContext::bootstrap(&database)
        .unwrap()
        .save(
            Payload::Chunk {
                first_page: 1,
                bytes: page.clone(),
            },
            deadline(),
        )
        .unwrap();
    let root = ObjectContext::bootstrap(&database)
        .unwrap()
        .save(
            Payload::Manifest(Manifest {
                page_count: 1,
                root: Some(
                    ObjectContext::bootstrap(&database)
                        .unwrap()
                        .save(
                            Payload::Node {
                                level: 0,
                                first_chunk: 0,
                                children: vec![page_root.clone()],
                            },
                            deadline(),
                        )
                        .unwrap(),
                ),
            }),
            deadline(),
        )
        .unwrap();
    let mut head = database.status(7, deadline()).unwrap();
    head.data_root = root;
    objects.fail(
        false,
        object_key(&scope(), 1, &page_root),
        StoreError::Missing,
    );
    assert!(matches!(
        database.image(&head, deadline()),
        Err(Error::Store(StoreError::Missing))
    ));
    let database = Database::with_options(objects.clone(), scope(), 10, test_options()).unwrap();
    let base = database.read_head(deadline()).unwrap();
    objects.fail(true, "*".into(), StoreError::Unknown);
    assert!(matches!(
        database.commit(
            &crate::tests::attempt(&database, &base, &identity(1), deadline()),
            &PageBatch {
                size_after: 1,
                pages: vec![PageChange {
                    number: 1,
                    bytes: page
                }]
            },
            b""
        ),
        Err(Error::Store(StoreError::Unknown))
    ));
}

#[test]
fn activation_rejects_changed_body_even_if_broken_transport_reuses_etag() {
    let (objects, database) = fixture();
    let head = database.takeover(7, 2, 3, deadline()).unwrap();
    let mut changed = Database::next(&head, 4).unwrap();
    changed.auth_epoch += 1;
    let mut state = objects.inner.lock().unwrap();
    state.preserve_replaced_etag = true;
    state.replace = Some((
        state.gets + 2,
        head_key(&scope()),
        encode_head(&changed).unwrap(),
    ));
    drop(state);
    assert!(matches!(
        database.activate(7, head.revision, 5, deadline()),
        Err(Error::Conflict)
    ));
}

pub(crate) fn index_payload(epoch: u64, entries: Vec<Entry>) -> Payload {
    Payload::Index(RequestIndex::Leaf { epoch, entries })
}

pub(crate) fn index_entries(
    database: &Database,
    window: &Window,
    end: Instant,
) -> Result<Vec<Entry>, Error> {
    let mut entries = Vec::new();
    let objects = ObjectContext::bootstrap(database).unwrap();
    request_index::walk(&objects, window, end, |entry| {
        entries.push(entry);
        Ok(())
    })?;
    Ok(entries)
}
