use super::*;
use crate::catalogue::tests::discovery_tests::Listing;
use crate::catalogue::tests::{
    abort, catalogue, deadline, delete, input, stage, Fault, Memory, CREATOR,
};
use crate::format::{object_key, PAGE_SIZE};
use crate::tests::{sql, test_options};
use scap_sql::Value;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

struct Readers(Mutex<BTreeMap<u64, u64>>);

impl TenantReaders for Readers {
    fn principal(&self, deployment: u64, tenant: u64) -> Option<u64> {
        assert_eq!(deployment, 1);
        self.0.lock().unwrap().get(&tenant).copied()
    }
}

fn readers() -> Arc<Readers> {
    Arc::new(Readers(Mutex::new([(2, 7), (10, 7), (99, 7)].into())))
}

fn job(objects: Arc<Memory>, readers: Arc<Readers>, budget: RecoveryBudget) -> RecoveryJob {
    RecoveryJob::new(
        objects.clone(),
        Listing::new(objects),
        RecoveryCapability::trusted_deployment(1, 100).unwrap(),
        readers,
        test_options(),
        budget,
        deadline(),
    )
    .unwrap()
}

fn direct(objects: Arc<Memory>, tenant: u64, database: u64) -> Database {
    let scope = Scope {
        deployment: 1,
        tenant,
        database,
        incarnation: 3,
        generation: 1,
    };
    let database = Database::with_options(objects, scope, 10, test_options()).unwrap();
    database.create(7, 1, deadline()).unwrap();
    database.activate(7, 1, 2, deadline()).unwrap();
    database
}

fn seed(database: &Database, directory: &Path) {
    let statements = vec![
        Statement {
            sql: "CREATE TABLE data(id INTEGER PRIMARY KEY, value BLOB)".into(),
            parameters: vec![],
        },
        Statement {
            sql: "INSERT INTO data VALUES(1, ?) RETURNING id, randomblob(7)".into(),
            parameters: vec![Value::Blob(vec![7, 0, 255])],
        },
    ];
    let request = crate::request(1, 1, 7, &statements).unwrap();
    database
        .execute(7, &request, &statements, directory, deadline())
        .unwrap();
}

fn until_image(job: &mut RecoveryJob, directory: &Path) -> RecoveryStep {
    for _ in 0..200 {
        let step = job.step(directory, deadline()).unwrap();
        assert!(step.stopped.is_none(), "{:?}", step.stopped);
        if step.recovered.is_some() {
            return step;
        }
        assert!(!step.completion.recovery_complete);
    }
    panic!("required slot was not discovered")
}

fn until_stopped(job: &mut RecoveryJob, directory: &Path) -> RecoveryStep {
    for _ in 0..200 {
        let step = job.step(directory, deadline()).unwrap();
        if step.stopped.is_some() {
            return step;
        }
        assert!(!step.completion.recovery_complete);
    }
    panic!("failure was hidden")
}

#[test]
fn root_discovery_recovers_each_physical_slot_once_with_full_native_results_and_no_writes() {
    let objects = Arc::new(Memory::default());
    let temp = tempfile::tempdir().unwrap();
    let mut required = BTreeSet::new();
    for tenant in [2, 10, 99] {
        let cat = Catalogue::new(objects.clone(), 1, tenant, 10, test_options()).unwrap();
        let creation = cat
            .prepare(
                CREATOR,
                &input(&format!("unknown-{tenant}"), 1, None),
                deadline(),
            )
            .unwrap()
            .creation;
        cat.resume_create(CREATOR, &creation, deadline()).unwrap();
        let named =
            Database::with_options(objects.clone(), creation.scope.clone(), 10, test_options())
                .unwrap();
        named.activate(7, 2, 3, deadline()).unwrap();
        seed(&named, &temp.path().join("seed"));
        let direct = direct(objects.clone(), tenant, 42);
        seed(&direct, &temp.path().join("seed"));
        if tenant == 10 {
            let head = direct.read_head(deadline()).unwrap().head;
            direct
                .set_lifecycle(7, head.revision, 100, Lifecycle::Maintenance, deadline())
                .unwrap();
        }
        required.insert(format::head_key(&creation.scope));
        required.insert(format::head_key(&direct.scope));
        cat.prepare(
            CREATOR,
            &input(&format!("unreserved-{tenant}"), 2, None),
            deadline(),
        )
        .unwrap();
    }
    let cat = catalogue(objects.clone());
    let old = cat
        .prepare(CREATOR, &input("reused", 3, None), deadline())
        .unwrap()
        .creation;
    cat.resume_create(CREATOR, &old, deadline()).unwrap();
    cat.delete(CREATOR, &delete(&old), deadline()).unwrap();
    let new = cat
        .prepare(CREATOR, &input("reused", 4, Some(3)), deadline())
        .unwrap()
        .creation;
    cat.resume_create(CREATOR, &new, deadline()).unwrap();
    let new_db =
        Database::with_options(objects.clone(), new.scope.clone(), 10, test_options()).unwrap();
    new_db.activate(7, 2, 3, deadline()).unwrap();
    seed(&new_db, &temp.path().join("seed"));
    required.insert(format::head_key(&new.scope));
    let raw_heads: BTreeMap<_, _> = required
        .iter()
        .chain(std::iter::once(&format::head_key(&old.scope)))
        .map(|key| (key.clone(), objects.get_value(key).unwrap()))
        .collect();
    objects.clear_calls();
    let mut job = job(objects.clone(), readers(), RecoveryBudget::default());
    let directory = temp.path().join("restored");
    let mut recovered_keys = BTreeSet::new();
    let mut saw_intent = false;
    let completion = loop {
        let mut step = job.step(&directory, deadline()).unwrap();
        assert!(step.stopped.is_none(), "{:?}", step.stopped);
        if let Some(record) = &step.metadata {
            saw_intent |= record.state == MetadataState::DescriptorOnly;
        }
        if let Some(mut restored) = step.recovered.take() {
            assert!(recovered_keys.insert(format::head_key(&restored.head().scope)));
            let result = restored
                .query(&sql("SELECT id,value FROM data ORDER BY id"), deadline())
                .unwrap();
            assert_eq!(
                result.statements[0].rows,
                vec![vec![Value::Integer(1), Value::Blob(vec![7, 0, 255])]]
            );
            assert!(matches!(
                job.step(&directory, deadline()),
                Err(RecoveryStop::Busy)
            ));
            assert!(directory.join("database.sqlite").is_file());
            drop(restored);
            assert!(!directory.exists());
        }
        if step.completion.recovery_complete {
            break step.completion;
        }
    };
    assert_eq!(recovered_keys, required);
    assert!(saw_intent);
    assert_eq!(completion.data_verified, 7);
    assert_eq!(completion.data_not_required, 1);
    assert_eq!(completion.heads_classified, 8);
    assert!(completion.pending_scope.is_none());
    assert!(completion.preexisting_slots_covered);
    let before = objects.calls().len();
    assert!(
        job.step(&directory, Instant::now())
            .unwrap()
            .completion
            .recovery_complete
    );
    assert_eq!(before, objects.calls().len());
    for (key, value) in raw_heads {
        assert_eq!(objects.get_value(&key).unwrap(), value);
    }
    assert!(objects.calls().iter().all(|call| !call.put));
}

#[test]
fn permission_denial_never_substitutes_the_creator_or_skips_the_pending_scope() {
    let objects = Arc::new(Memory::default());
    let database = direct(objects.clone(), 2, 42);
    let temp = tempfile::tempdir().unwrap();
    seed(&database, &temp.path().join("seed"));
    let readers = readers();
    readers.0.lock().unwrap().insert(2, 90);
    let mut job = job(objects.clone(), readers.clone(), RecoveryBudget::default());
    let directory = temp.path().join("restored");
    objects.clear_calls();
    let stopped = until_stopped(&mut job, &directory);
    assert_eq!(stopped.stopped, Some(RecoveryStop::PermissionBlocked));
    assert_eq!(
        stopped.completion.pending_scope,
        Some(database.scope.clone())
    );
    assert!(stopped.completion.permission_blocked);
    assert!(!stopped.completion.recovery_complete);
    assert_eq!(stopped.usage.data_bytes, 0);
    assert!(!directory.exists());
    let cursor = job.inventory.checkpoint(&job.cursor).unwrap();
    readers.0.lock().unwrap().remove(&2);
    let absent = job.step(&directory, deadline()).unwrap();
    assert_eq!(absent.stopped, Some(RecoveryStop::PermissionBlocked));
    assert_eq!(job.inventory.checkpoint(&job.cursor).unwrap(), cursor);
    readers.0.lock().unwrap().insert(2, 0);
    assert_eq!(
        job.step(&directory, deadline()).unwrap().stopped,
        Some(RecoveryStop::Invalid)
    );
    readers.0.lock().unwrap().insert(2, 7);
    let mut recovered = job.step(&directory, deadline()).unwrap();
    let mut image = recovered.recovered.take().unwrap();
    assert!(image.query(&sql("DELETE FROM data"), deadline()).is_err());
    assert!(objects.calls().iter().all(|call| !call.put));
    drop(image);
    assert!(!directory.exists());
    while !job
        .step(&directory, deadline())
        .unwrap()
        .completion
        .recovery_complete
    {}
}

#[test]
fn pending_metadata_is_classified_without_activating_or_reading_unrequired_data() {
    for phase in [
        CreationPhase::Reserved,
        CreationPhase::Provisioning,
        CreationPhase::Bound,
    ] {
        let (objects, _, _) = stage(phase);
        objects.clear_calls();
        let mut job = job(objects.clone(), readers(), RecoveryBudget::default());
        let temp = tempfile::tempdir().unwrap();
        loop {
            let step = job.step(&temp.path().join("none"), deadline()).unwrap();
            assert!(step.stopped.is_none());
            assert!(step.recovered.is_none());
            assert_eq!(step.usage.data_bytes, 0);
            if step.completion.recovery_complete {
                break;
            }
        }
        assert!(objects.calls().iter().all(|call| !call.put));
    }
    let (objects, cat, creation) = stage(CreationPhase::Reserved);
    cat.abort_create(CREATOR, &abort(&creation), deadline())
        .unwrap();
    let mut job = job(objects, readers(), RecoveryBudget::default());
    let temp = tempfile::tempdir().unwrap();
    loop {
        let step = job.step(&temp.path().join("none"), deadline()).unwrap();
        assert!(step.recovered.is_none());
        assert!(step.stopped.is_none());
        if step.completion.recovery_complete {
            assert_eq!(step.completion.data_not_required, 1);
            break;
        }
    }
}

#[test]
fn corrupt_missing_data_and_native_images_keep_the_exact_slot_pending() {
    let base = Arc::new(Memory::default());
    let database = direct(base.clone(), 2, 42);
    let original = database.read_head(deadline()).unwrap();
    let key = object_key(&database.scope, 1, &original.head.data_root);
    let temp = tempfile::tempdir().unwrap();
    for missing in [false, true] {
        let objects = base.fork();
        if missing {
            objects.remove(&key);
        } else {
            objects.set(&key, vec![1, 2, 3]);
        }
        let mut job = job(objects.clone(), readers(), RecoveryBudget::default());
        let failed = until_stopped(&mut job, &temp.path().join("bad"));
        assert_eq!(failed.stopped, Some(RecoveryStop::Corrupt));
        assert_eq!(
            failed.completion.pending_scope,
            Some(database.scope.clone())
        );
        assert!(!failed.completion.recovery_complete);
        assert!(!temp.path().join("bad").exists());
        assert!(objects.calls().iter().all(|call| !call.put));
    }
    for header in [false, true] {
        let mut page = vec![0; PAGE_SIZE];
        if header {
            page[..16].copy_from_slice(b"SQLite format 3\0");
            page[16..18].copy_from_slice(&[0x10, 0]);
        }
        let root = crate::data_tree::update(
            &ObjectContext::capture(&database, &original.head).unwrap(),
            &original.head.data_root,
            &scap_object_sqlite::PageBatch {
                size_after: 1,
                pages: vec![scap_object_sqlite::PageChange {
                    number: 1,
                    bytes: page,
                }],
            },
            64,
            deadline(),
        )
        .unwrap();
        let mut head = original.head.clone();
        head.data_root = root;
        base.set(
            &format::head_key(&database.scope),
            format::encode_head(&head).unwrap(),
        );
        let mut job = job(base.clone(), readers(), RecoveryBudget::default());
        let failed = until_stopped(&mut job, &temp.path().join("bad-native"));
        assert_eq!(failed.stopped, Some(RecoveryStop::Corrupt));
        assert_eq!(
            failed.completion.pending_scope,
            Some(database.scope.clone())
        );
        assert!(!temp.path().join("bad-native").exists());
    }
}

#[test]
fn complete_recovery_includes_held_roots_beyond_the_current_native_image() {
    use crate::format::{SnapshotEntry, SnapshotLimits, SnapshotPoint, SnapshotRef};
    for missing in [false, true] {
        let objects = Arc::new(Memory::default());
        let database = direct(objects.clone(), 2, 42);
        let old = database.status(7, deadline()).unwrap();
        let temp = tempfile::tempdir().unwrap();
        seed(&database, &temp.path().join("seed"));
        let mut head = database.status(7, deadline()).unwrap();
        assert_ne!(head.data_root, old.data_root);
        head.format = 9;
        head.head_serial += 1;
        head.restore_origin = Some(());
        head.snapshot_limits = Some(SnapshotLimits::default());
        head.snapshots = Some(vec![SnapshotEntry {
            reference: SnapshotRef {
                creator: 7,
                operation: 901,
                capture_serial: old.head_serial + 1,
                descriptor_hash: format::digest(b"retained original point"),
            },
            label: "before-write".into(),
            point: SnapshotPoint {
                data_root: old.data_root.clone(),
                page_count: u32::from(!missing),
                sequence: old.sequence,
                source_revision: old.revision,
            },
        }]);
        objects.set(
            &format::head_key(&database.scope),
            format::encode_head(&head).unwrap(),
        );
        if missing {
            objects.remove(&object_key(&database.scope, 1, &old.data_root));
        }
        objects.clear_calls();
        let mut job = job(objects.clone(), readers(), RecoveryBudget::default());
        let failed = until_stopped(&mut job, &temp.path().join("restored"));
        assert_eq!(failed.stopped, Some(RecoveryStop::Corrupt));
        assert_eq!(
            failed.completion.pending_scope,
            Some(database.scope.clone())
        );
        assert!(!failed.completion.recovery_complete);
        assert!(failed.recovered.is_none());
        assert!(!temp.path().join("restored").exists());
        assert!(objects.calls().iter().all(|call| !call.put));
    }
}

#[test]
fn local_cache_failure_does_not_delete_an_existing_directory_or_advance_data() {
    let objects = Arc::new(Memory::default());
    direct(objects.clone(), 2, 42);
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join("exists");
    std::fs::create_dir(&directory).unwrap();
    std::fs::write(directory.join("keep"), b"untouched").unwrap();
    let mut job = job(objects, readers(), RecoveryBudget::default());
    let failed = until_stopped(&mut job, &directory);
    assert_eq!(failed.stopped, Some(RecoveryStop::Local));
    assert_eq!(std::fs::read(directory.join("keep")).unwrap(), b"untouched");
    assert_eq!(failed.completion.data_verified, 0);
    assert!(failed.completion.pending_scope.is_some());
    assert!(job
        .step(&temp.path().join("fresh"), deadline())
        .unwrap()
        .recovered
        .is_some());
}

#[test]
fn full_retained_history_is_checked_even_when_no_query_targets_the_old_epoch() {
    let objects = Arc::new(Memory::default());
    let scope = Scope {
        deployment: 1,
        tenant: 2,
        database: 42,
        incarnation: 3,
        generation: 1,
    };
    let mut options = test_options();
    options.retention.max_entries = 1;
    let database = Database::with_options(objects.clone(), scope.clone(), 10, options).unwrap();
    database.create(7, 1, deadline()).unwrap();
    database.activate(7, 1, 2, deadline()).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let statements = sql("SELECT randomblob(13)");
    let request = crate::request(1, 1, 7, &statements).unwrap();
    let (receipt, _) = database
        .execute(
            7,
            &request,
            &statements,
            &temp.path().join("seed"),
            deadline(),
        )
        .unwrap();
    let head = database.read_head(deadline()).unwrap().head;
    database
        .close_full(7, head.revision, 9, deadline())
        .unwrap();
    objects.remove(&object_key(&scope, 1, &receipt.result_hash));
    objects.clear_calls();
    let mut job = job(objects.clone(), readers(), RecoveryBudget::default());
    let failed = until_stopped(&mut job, &temp.path().join("recover"));
    assert_eq!(failed.stopped, Some(RecoveryStop::Corrupt));
    assert!(objects
        .calls()
        .iter()
        .any(|call| call.key == object_key(&scope, 1, &receipt.result_hash)));
    assert!(!failed.completion.recovery_complete);
    assert_eq!(failed.completion.data_verified, 0);
    assert!(!temp.path().join("recover").exists());
}

#[test]
fn unknown_reads_and_head_changes_during_native_recovery_never_complete_the_slot() {
    let objects = Arc::new(Memory::default());
    let database = direct(objects.clone(), 2, 42);
    let temp = tempfile::tempdir().unwrap();
    let key = format::head_key(&database.scope);
    let original = database.read_head(deadline()).unwrap();
    for preserve_etag in [false, true] {
        let fork = objects.fork();
        let mut changed = original.head.clone();
        changed.owner_instance += 1;
        let mut job = job(fork.clone(), readers(), RecoveryBudget::default());
        // The per-slot method has selected the actual exact HEAD before this
        // immutable dependency GET. The final HEAD must detect either change.
        fork.cut(
            false,
            &object_key(&database.scope, 1, &original.head.data_root),
            None,
            0,
            Fault::Replace {
                key: key.clone(),
                bytes: format::encode_head(&changed).unwrap(),
                preserve_etag,
            },
        );
        let failed = until_stopped(&mut job, &temp.path().join("race"));
        assert_eq!(failed.stopped, Some(RecoveryStop::Conflict));
        assert_eq!(
            failed.completion.pending_scope,
            Some(database.scope.clone())
        );
        assert!(!temp.path().join("race").exists());
    }
    let mut job = job(objects.clone(), readers(), RecoveryBudget::default());
    objects.cut(
        false,
        &object_key(&database.scope, 1, &original.head.data_root),
        None,
        0,
        Fault::Before(StoreError::Unknown),
    );
    let failed = until_stopped(&mut job, &temp.path().join("unknown"));
    assert_eq!(failed.stopped, Some(RecoveryStop::Unknown));
    let cursor = job.inventory.checkpoint(&job.cursor).unwrap();
    assert!(job
        .step(&temp.path().join("unknown"), deadline())
        .unwrap()
        .recovered
        .is_some());
    assert_eq!(job.inventory.checkpoint(&job.cursor).unwrap(), cursor);
}

#[test]
fn returned_image_requires_fresh_read_and_admin_does_not_grant_it() {
    let objects = Arc::new(Memory::default());
    let database = direct(objects.clone(), 2, 42);
    let temp = tempfile::tempdir().unwrap();
    let mut scan = job(objects.clone(), readers(), RecoveryBudget::default());
    let mut step = until_image(&mut scan, &temp.path().join("image"));
    let mut image = step.recovered.take().unwrap();
    let head = database.read_head(deadline()).unwrap().head;
    database
        .set_policy(
            7,
            head.revision,
            12,
            vec![Permission {
                principal: 7,
                read: false,
                write: true,
                admin: true,
            }],
            deadline(),
        )
        .unwrap();
    assert!(matches!(
        image.query(&sql("SELECT 1"), deadline()),
        Err(Error::Denied)
    ));
    drop(image);
    assert!(!temp.path().join("image").exists());
    let mut fresh = job(objects, readers(), RecoveryBudget::default());
    assert_eq!(
        until_stopped(&mut fresh, &temp.path().join("denied")).stopped,
        Some(RecoveryStop::PermissionBlocked)
    );
}

struct DeniedListings;
impl Listings for DeniedListings {
    fn list_page(
        &self,
        _: &scap_object_store::ListRequest<'_>,
        _: Instant,
    ) -> Result<scap_object_store::ListPage, scap_object_store::ListError> {
        Err(scap_object_store::ListError::Denied)
    }
}

#[test]
fn typed_storage_denial_transport_unknown_and_object_limits_are_not_acl_filtering() {
    assert_eq!(
        RecoveryStop::from(DiscoveryError::SnapshotExpired),
        RecoveryStop::SnapshotExpired
    );
    assert_eq!(
        recovery_error(Error::SnapshotExpired),
        RecoveryStop::SnapshotExpired
    );
    let objects = Arc::new(Memory::default());
    let database = direct(objects.clone(), 2, 42);
    let temp = tempfile::tempdir().unwrap();
    let head = database.read_head(deadline()).unwrap().head;
    for (error, expected) in [
        (StoreError::Unknown, RecoveryStop::Unknown),
        (StoreError::Limit, RecoveryStop::Limit),
        (StoreError::Conflict, RecoveryStop::Conflict),
    ] {
        let fork = objects.fork();
        fork.cut(
            false,
            &object_key(&database.scope, 1, &head.data_root),
            None,
            0,
            Fault::Before(error),
        );
        let mut job = job(fork, readers(), RecoveryBudget::default());
        let step = until_stopped(&mut job, &temp.path().join("failure"));
        assert_eq!(step.stopped, Some(expected));
        assert_eq!(step.completion.pending_scope, Some(database.scope.clone()));
        assert!(!step.completion.permission_blocked);
        assert!(!step.completion.recovery_complete);
    }
    let mut job = RecoveryJob::new(
        objects,
        Arc::new(DeniedListings),
        RecoveryCapability::trusted_deployment(1, 100).unwrap(),
        readers(),
        test_options(),
        RecoveryBudget::default(),
        deadline(),
    )
    .unwrap();
    let step = job.step(&temp.path().join("no-image"), deadline()).unwrap();
    assert_eq!(step.stopped, Some(RecoveryStop::StorageDenied));
    assert!(!step.completion.permission_blocked);
    assert!(!step.completion.traversal_exhausted);
    assert_eq!(step.usage.metadata_bytes, 0);
}

#[test]
fn total_job_budgets_cannot_be_reset_by_steps_or_pending_retries() {
    let objects = Arc::new(Memory::default());
    let database = direct(objects.clone(), 2, 42);
    let temp = tempfile::tempdir().unwrap();
    for budget in [
        RecoveryBudget {
            list_pages: 0,
            ..RecoveryBudget::default()
        },
        RecoveryBudget {
            candidates: 0,
            ..RecoveryBudget::default()
        },
        RecoveryBudget {
            exact_gets: 0,
            ..RecoveryBudget::default()
        },
        RecoveryBudget {
            metadata_bytes: 1,
            ..RecoveryBudget::default()
        },
        RecoveryBudget {
            data_bytes: 0,
            ..RecoveryBudget::default()
        },
    ] {
        let mut job = job(objects.clone(), readers(), budget);
        let first = until_stopped(&mut job, &temp.path().join("bounded"));
        assert_eq!(first.stopped, Some(RecoveryStop::Limit));
        assert!(!first.completion.recovery_complete);
        let again = job.step(&temp.path().join("bounded"), deadline()).unwrap();
        assert_eq!(again.stopped, Some(RecoveryStop::Limit));
        assert!(!again.completion.recovery_complete);
        assert!(again.usage.candidates >= first.usage.candidates);
        assert!(again.usage.metadata_bytes >= first.usage.metadata_bytes);
        assert!(!temp.path().join("bounded").exists());
    }
    let readers = readers();
    readers.0.lock().unwrap().remove(&2);
    let mut job = job(
        objects,
        readers,
        RecoveryBudget {
            candidates: 2,
            ..RecoveryBudget::default()
        },
    );
    let denied = until_stopped(&mut job, &temp.path().join("denied"));
    assert_eq!(denied.stopped, Some(RecoveryStop::PermissionBlocked));
    assert_eq!(denied.usage.candidates, 2);
    let exhausted = job.step(&temp.path().join("denied"), deadline()).unwrap();
    assert_eq!(exhausted.stopped, Some(RecoveryStop::Limit));
    assert_eq!(exhausted.usage.candidates, 2);
    assert_eq!(exhausted.completion.pending_scope, Some(database.scope));
}

thread_local! {
    static CLOCK: RefCell<(Instant, Option<usize>, usize)> = RefCell::new((Instant::now(), None, 0));
}

fn clock_start(cut: Option<usize>) -> Instant {
    let now = Instant::now();
    CLOCK.with(|value| *value.borrow_mut() = (now, cut, 0));
    now + Duration::from_secs(30)
}

fn clock_now() -> Instant {
    CLOCK.with(|value| {
        let mut value = value.borrow_mut();
        value.2 += 1;
        if value.1.is_some_and(|cut| value.2 >= cut) {
            value.0 + Duration::from_secs(30)
        } else {
            value.0
        }
    })
}

#[test]
fn expiry_at_every_metadata_and_native_boundary_never_returns_a_healthy_image() {
    let objects = Arc::new(Memory::default());
    direct(objects.clone(), 2, 42);
    let temp = tempfile::tempdir().unwrap();
    let until = clock_start(None);
    let mut complete = RecoveryJob::with_clock(
        objects.clone(),
        Listing::new(objects.clone()),
        RecoveryCapability::trusted_deployment(1, 100).unwrap(),
        readers(),
        test_options(),
        RecoveryBudget::default(),
        (until, clock_now),
    )
    .unwrap();
    loop {
        let step = complete.step(&temp.path().join("image"), until).unwrap();
        assert!(step.stopped.is_none());
        if step.completion.recovery_complete {
            break;
        }
    }
    let calls = CLOCK.with(|value| value.borrow().2);
    for cut in 1..=calls {
        let until = clock_start(Some(cut));
        let candidate = RecoveryJob::with_clock(
            objects.clone(),
            Listing::new(objects.clone()),
            RecoveryCapability::trusted_deployment(1, 100).unwrap(),
            readers(),
            test_options(),
            RecoveryBudget::default(),
            (until, clock_now),
        );
        let mut job = match candidate {
            Ok(job) => job,
            Err(error) => {
                assert_eq!(error, RecoveryStop::Unknown);
                continue;
            }
        };
        loop {
            let step = job.step(&temp.path().join("expired"), until).unwrap();
            assert!(!step.completion.recovery_complete, "cut {cut}");
            if let Some(error) = step.stopped {
                assert!(step.recovered.is_none(), "cut {cut}");
                assert_eq!(error, RecoveryStop::Unknown, "cut {cut}");
                break;
            }
        }
        assert!(!temp.path().join("expired").exists());
        let after = job.step(&temp.path().join("expired"), deadline()).unwrap();
        assert_eq!(after.stopped, Some(RecoveryStop::Unknown));
        assert!(!after.completion.recovery_complete);
    }
}

#[test]
fn invalid_job_inputs_and_a_foreign_inventory_checkpoint_fail_before_data_recovery() {
    let objects = Arc::new(Memory::default());
    let mut options = test_options();
    options.max_input_bytes = 0;
    assert!(matches!(
        RecoveryJob::new(
            objects.clone(),
            Listing::new(objects.clone()),
            RecoveryCapability::trusted_deployment(1, 100).unwrap(),
            readers(),
            options,
            RecoveryBudget::default(),
            deadline()
        ),
        Err(RecoveryStop::Invalid)
    ));
    assert!(matches!(
        RecoveryJob::new(
            objects.clone(),
            Listing::new(objects.clone()),
            RecoveryCapability::trusted_deployment(1, 100).unwrap(),
            readers(),
            test_options(),
            RecoveryBudget {
                list_pages: 4097,
                ..RecoveryBudget::default()
            },
            deadline()
        ),
        Err(RecoveryStop::Invalid)
    ));
    let mut scan = job(objects.clone(), readers(), RecoveryBudget::default());
    let foreign = job(objects.clone(), readers(), RecoveryBudget::default());
    scan.cursor = foreign.inventory.begin();
    let temp = tempfile::tempdir().unwrap();
    let step = scan.step(&temp.path().join("none"), deadline()).unwrap();
    assert_eq!(step.stopped, Some(RecoveryStop::Invalid));
    assert!(!step.completion.recovery_complete);
    assert!(objects.calls().is_empty());
    let mut scan = job(objects.clone(), readers(), RecoveryBudget::default());
    let malformed = DiscoveredRecord {
        key: "not-a-complete-head".into(),
        kind: RecordKind::Head,
        state: MetadataState::Ready,
        creation: None,
        scope: None,
        binding_revision: None,
        head_revision: Some(1),
        control: None,
    };
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        scan.accept_metadata(&malformed)
    }))
    .is_err());
    assert_eq!(scan.heads, 0);
    assert!(scan.pending.is_none());
    scan.heads = 1;
    let inconsistent = scan.step(&temp.path().join("none"), deadline()).unwrap();
    assert!(inconsistent.completion.traversal_exhausted);
    assert!(!inconsistent.completion.recovery_complete);
}

#[test]
fn empty_inventory_exhausted_at_the_deadline_is_not_complete() {
    let objects = Arc::new(Memory::default());
    let temp = tempfile::tempdir().unwrap();
    let construct = |until| {
        RecoveryJob::with_clock(
            objects.clone(),
            Listing::new(objects.clone()),
            RecoveryCapability::trusted_deployment(1, 100).unwrap(),
            readers(),
            test_options(),
            RecoveryBudget::default(),
            (until, clock_now),
        )
    };
    let until = clock_start(None);
    let mut baseline = construct(until).unwrap();
    assert!(
        baseline
            .step(&temp.path().join("unused"), until)
            .unwrap()
            .completion
            .recovery_complete
    );
    let calls = CLOCK.with(|value| value.borrow().2);
    let mut exhausted_before_failure = false;
    for cut in 1..=calls {
        let until = clock_start(Some(cut));
        let Ok(mut scan) = construct(until) else {
            continue;
        };
        let step = scan.step(&temp.path().join("unused"), until).unwrap();
        assert_eq!(step.stopped, Some(RecoveryStop::Unknown));
        assert!(!step.completion.recovery_complete);
        exhausted_before_failure |= step.completion.traversal_exhausted;
        let again = scan.step(&temp.path().join("unused"), deadline()).unwrap();
        assert_eq!(again.stopped, Some(RecoveryStop::Unknown));
        assert!(!again.completion.recovery_complete);
    }
    assert!(exhausted_before_failure);
    assert!(!temp.path().join("unused").exists());
}

#[test]
fn every_named_snapshot_read_is_required_and_original_scope_is_not_replaced() {
    for phase in [CreationPhase::Provisioning, CreationPhase::Ready] {
        let (objects, _, creation) = stage(phase);
        let scan = job(objects.clone(), readers(), RecoveryBudget::default());
        objects.clear_calls();
        scan.snapshot(&creation.scope, deadline()).unwrap();
        let calls = objects.calls().len();
        for at in 1..=calls {
            let fork = objects.fork();
            let scan = job(fork.clone(), readers(), RecoveryBudget::default());
            fork.fail_at(at, Fault::Before(StoreError::Unknown));
            assert!(
                matches!(
                    scan.snapshot(&creation.scope, deadline()),
                    Err(RecoveryStop::Unknown)
                ),
                "read {at}"
            );
            assert!(fork.calls().iter().all(|call| !call.put));
        }
    }
    let (objects, cat, creation) = stage(CreationPhase::Ready);
    objects.remove(&cat.binding_key(&creation.name));
    let scan = job(objects, readers(), RecoveryBudget::default());
    assert!(matches!(
        scan.snapshot(&creation.scope, deadline()),
        Err(RecoveryStop::Corrupt)
    ));

    let (base, _, creation) = stage(CreationPhase::Provisioning);
    let key = format::head_key(&creation.scope);
    let foreign = Arc::new(Memory::default());
    let mut scope = creation.scope.clone();
    scope.incarnation += 1;
    Database::with_options(foreign.clone(), scope, 10, test_options())
        .unwrap()
        .create(7, 1, deadline())
        .unwrap();
    for replace in [false, true] {
        let objects = base.fork();
        let changed = objects.clone();
        let target = key.clone();
        let bytes = foreign.get_value(&key).unwrap().bytes;
        objects.cut(
            false,
            &key,
            None,
            1,
            Fault::Run(Arc::new(move || {
                if replace {
                    changed.set(&target, bytes.clone());
                } else {
                    changed.remove(&target);
                }
            })),
        );
        let scan = job(objects, readers(), RecoveryBudget::default());
        assert!(matches!(
            scan.snapshot(&creation.scope, deadline()),
            Err(RecoveryStop::Corrupt)
        ));
    }
    base.remove(&key);
    let scan = job(base, readers(), RecoveryBudget::default());
    assert!(matches!(
        scan.snapshot(&creation.scope, deadline()),
        Err(RecoveryStop::Corrupt)
    ));
    let objects = Arc::new(Memory::default());
    let database = direct(objects.clone(), 2, 42);
    let mut head = database.read_head(deadline()).unwrap().head;
    head.scope.incarnation += 1;
    objects.set(
        &format::head_key(&database.scope),
        format::encode_head(&head).unwrap(),
    );
    let scan = job(objects, readers(), RecoveryBudget::default());
    assert!(matches!(
        scan.snapshot(&database.scope, deadline()),
        Err(RecoveryStop::Corrupt)
    ));
}

#[test]
fn metadata_conflicts_preserve_the_unclassified_frontier() {
    let (objects, _, creation) = stage(CreationPhase::Ready);
    let mut scan = job(objects.clone(), readers(), RecoveryBudget::default());
    objects.cut(
        false,
        &format::head_key(&creation.scope),
        None,
        0,
        Fault::Before(StoreError::Conflict),
    );
    let temp = tempfile::tempdir().unwrap();
    let failed = until_stopped(&mut scan, &temp.path().join("none"));
    assert_eq!(failed.stopped, Some(RecoveryStop::Conflict));
    assert!(!failed.completion.traversal_exhausted);
    assert!(!failed.completion.recovery_complete);
    assert_eq!(failed.completion.data_verified, 0);
}
