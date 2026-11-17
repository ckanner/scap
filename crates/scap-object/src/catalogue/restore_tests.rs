use super::*;
use crate::catalogue::tests::{deadline, Fault, Memory, CREATOR};
use crate::format::{encode_head, head_key, object_key, RestoreCopyPhase};
use crate::snapshot::{PrepareSnapshotInput, PreparedSnapshot};
use crate::tests::{scope, sql, test_options};
use crate::{request, Resolution};
use scap_object_store::Stored;
use scap_sql::{Statement, Value};

#[path = "restore_fault_tests.rs"]
mod faults;
#[path = "restore_record_tests.rs"]
mod records;

struct Quoted(Arc<Memory>);

impl Objects for Quoted {
    fn get(&self, key: &str, maximum: usize, deadline: Instant) -> Result<Stored, StoreError> {
        let mut value = self.0.get(key, maximum, deadline)?;
        if !value.etag.is_empty() {
            value.etag = format!("\"{}\"", value.etag);
        }
        Ok(value)
    }
    fn put(
        &self,
        key: &str,
        bytes: &[u8],
        condition: Condition<'_>,
        deadline: Instant,
    ) -> Result<String, StoreError> {
        let condition = match condition {
            Condition::Absent => Condition::Absent,
            Condition::Match(etag) => {
                Condition::Match(etag.strip_prefix('"').unwrap().strip_suffix('"').unwrap())
            }
        };
        self.0
            .put(key, bytes, condition, deadline)
            .map(|etag| format!("\"{etag}\""))
    }
}

struct Fixture {
    memory: Arc<Memory>,
    objects: Arc<Quoted>,
    catalogue: Catalogue,
    source: Database,
    snapshot: PreparedSnapshot,
    directory: tempfile::TempDir,
}

impl Fixture {
    fn new(data: bool) -> Self {
        let memory = Arc::new(Memory::default());
        let objects = Arc::new(Quoted(memory.clone()));
        let source = Database::with_options(objects.clone(), scope(), 10, test_options()).unwrap();
        source.create(7, 1, deadline()).unwrap();
        source.activate(7, 1, 2, deadline()).unwrap();
        let directory = tempfile::tempdir().unwrap();
        if data {
            let statements = vec![
                Statement {
                    sql: "CREATE TABLE restored(n INTEGER PRIMARY KEY,v BLOB)".into(),
                    parameters: vec![],
                },
                Statement {
                    sql: "INSERT INTO restored VALUES(1,?)".into(),
                    parameters: vec![Value::Blob(
                        (0..150_000).map(|value| (value % 251) as u8).collect(),
                    )],
                },
            ];
            let identity = request(1, 1, 7, &statements).unwrap();
            source
                .execute(
                    7,
                    &identity,
                    &statements,
                    &directory.path().join("source"),
                    deadline(),
                )
                .unwrap();
        }
        let head = source.status(7, deadline()).unwrap();
        let snapshot = source
            .snapshot_prepare(
                7,
                &PrepareSnapshotInput {
                    creator: 7,
                    operation: 901,
                    expected_revision: head.revision,
                    expected_head_serial: head.head_serial,
                    label: "retained point".into(),
                },
                deadline(),
            )
            .unwrap();
        source
            .snapshot_capture(7, &snapshot.reference, deadline())
            .unwrap();
        let catalogue = Catalogue::new(objects.clone(), 1, 2, 11, test_options()).unwrap();
        Self {
            memory,
            objects,
            catalogue,
            source,
            snapshot,
            directory,
        }
    }

    fn input(&self) -> PrepareRestore {
        PrepareRestore {
            name: "restored name".into(),
            operation: 700,
            expected_name_revision: None,
            options: CreateOptions::default(),
            source_scope: scope(),
            snapshot: self.snapshot.reference.clone(),
        }
    }

    fn prepare(&self) -> PreparedRestore {
        self.catalogue
            .prepare_restore(CREATOR, &self.input(), deadline())
            .unwrap()
    }

    fn resume(&self, prepared: &PreparedRestore, number: usize) -> RestoreProgress {
        let path = self.directory.path().join(format!("restore-{number}"));
        let progress = self
            .catalogue
            .resume_restore(
                CREATOR,
                &prepared.reference,
                &path,
                RestoreBudget::default(),
                deadline(),
            )
            .unwrap();
        assert!(
            !path.exists(),
            "native validation image must be dropped before returning"
        );
        progress
    }

    fn copying(&self, prepared: &PreparedRestore) {
        assert_eq!(self.resume(prepared, 0).phase, RestorePhase::Reserved);
        assert_eq!(self.resume(prepared, 1).phase, RestorePhase::Copying);
    }

    fn remove_source_payload(&self) {
        let prefix = object_key(&scope(), 1, "");
        for call in self.memory.calls() {
            if call.key.starts_with(&prefix) {
                self.memory.remove(&call.key);
            }
        }
    }

    fn completion_key(&self, prepared: &PreparedRestore) -> String {
        let source = self
            .catalogue
            .restore_descriptor(&prepared.reference, deadline())
            .unwrap();
        self.catalogue.completion_key(&source)
    }
}

#[test]
fn new_scope_restore_uses_retained_bytes_one_cas_and_independent_requests() {
    let fixture = Fixture::new(true);
    let statements = sql("INSERT INTO restored VALUES(2,randomblob(64))");
    let identity = request(1, 2, 7, &statements).unwrap();
    fixture
        .source
        .execute(
            7,
            &identity,
            &statements,
            &fixture.directory.path().join("later"),
            deadline(),
        )
        .unwrap();
    let prepared = fixture.prepare();
    assert_eq!(
        prepared.image_bytes(),
        u64::from(fixture.snapshot.point.page_count) * 4096
    );
    assert!(
        prepared.point.page_count > 32,
        "exercise multiple 128KiB chunks"
    );
    for (number, phase) in [
        RestorePhase::Reserved,
        RestorePhase::Copying,
        RestorePhase::Copied,
        RestorePhase::Bound,
        RestorePhase::Ready,
    ]
    .into_iter()
    .enumerate()
    {
        let before = fixture.memory.calls().len();
        let progress = fixture.resume(&prepared, number);
        assert_eq!(progress.phase, phase);
        let calls = fixture.memory.calls();
        assert_eq!(
            calls[before..]
                .iter()
                .filter(|call| call.put
                    && (call.key.ends_with("/head") || call.key.contains("/catalogue/v1/name/")))
                .count(),
            1
        );
    }
    let named = fixture
        .catalogue
        .resolve(CREATOR, &prepared.reference.creation.name, deadline())
        .unwrap();
    assert_eq!(named.head.revision, 2);
    assert_eq!(named.head.sequence, 0);
    assert_eq!(named.head.request_epoch, 1);
    assert!(!named.head.active);
    assert!(named.head.snapshots.as_ref().unwrap().is_empty());
    assert_ne!(named.head.data_root, fixture.snapshot.point.data_root);
    assert!(matches!(
        named.head.restore_origin,
        Some(Some(format::RestoreOrigin {
            phase: RestoreCopyPhase::Copied { .. },
            ..
        }))
    ));
    fixture.remove_source_payload();
    let target = Database::with_options(
        fixture.objects.clone(),
        named.creation.scope,
        12,
        test_options(),
    )
    .unwrap();
    let result = target
        .query(
            7,
            &sql("SELECT n,length(v),hex(substr(v,1,8)) FROM restored"),
            &fixture.directory.path().join("cold-target"),
            deadline(),
        )
        .unwrap();
    assert_eq!(
        result.statements[0].rows,
        vec![vec![
            Value::Integer(1),
            Value::Integer(150_000),
            Value::Text("0001020304050607".into())
        ]]
    );
    assert!(matches!(
        target.lookup(7, &identity, deadline()).unwrap(),
        Resolution::Unknown
    ));
}

#[test]
fn unknown_completion_resumes_without_source_and_never_reexecutes_sql() {
    let fixture = Fixture::new(true);
    let prepared = fixture.prepare();
    fixture.copying(&prepared);
    let completion = fixture.completion_key(&prepared);
    fixture
        .memory
        .cut(true, &completion, None, 0, Fault::AfterPut);
    assert_eq!(
        fixture.catalogue.resume_restore(
            CREATOR,
            &prepared.reference,
            &fixture.directory.path().join("lost-completion"),
            RestoreBudget::default(),
            deadline()
        ),
        Err(CatalogueError::Unknown)
    );
    assert!(fixture.memory.get_value(&completion).is_some());
    assert_eq!(
        fixture
            .catalogue
            .inspect_restore(CREATOR, 7, 700, deadline())
            .unwrap()
            .phase,
        RestorePhase::Copying
    );
    fixture
        .source
        .snapshot_release(7, &fixture.snapshot.reference, deadline())
        .unwrap();
    fixture.remove_source_payload();
    let mut revoked = fixture.source.read_head(deadline()).unwrap().head;
    revoked.policy[0].read = false;
    fixture
        .memory
        .set(&head_key(&scope()), encode_head(&revoked).unwrap());
    fixture.memory.clear_calls();
    assert_eq!(fixture.resume(&prepared, 2).phase, RestorePhase::Copied);
    assert!(!fixture
        .memory
        .calls()
        .iter()
        .any(|call| call.key == head_key(&scope())
            || call.key.starts_with(&object_key(&scope(), 1, ""))));
    assert_eq!(fixture.resume(&prepared, 3).phase, RestorePhase::Bound);
    assert_eq!(fixture.resume(&prepared, 4).phase, RestorePhase::Ready);
}

#[test]
fn generic_empty_create_and_missing_completion_cannot_complete_restore() {
    let fixture = Fixture::new(false);
    let prepared = fixture.prepare();
    fixture.copying(&prepared);
    assert_eq!(
        fixture
            .catalogue
            .resume_create(CREATOR, &prepared.reference.creation, deadline()),
        Err(CatalogueError::Conflict)
    );
    assert_eq!(
        fixture
            .catalogue
            .inspect_create_operation(CREATOR, 700, deadline()),
        Err(CatalogueError::Conflict)
    );
    assert_eq!(fixture.resume(&prepared, 2).phase, RestorePhase::Copied);
    assert_eq!(fixture.resume(&prepared, 3).phase, RestorePhase::Bound);
    assert_eq!(fixture.resume(&prepared, 4).phase, RestorePhase::Ready);
    fixture.memory.remove(&fixture.completion_key(&prepared));
    assert_eq!(
        fixture
            .catalogue
            .inspect_restore(CREATOR, 7, 700, deadline()),
        Err(CatalogueError::Corrupt)
    );
    assert_eq!(
        fixture
            .catalogue
            .resolve(CREATOR, &prepared.reference.creation.name, deadline()),
        Err(CatalogueError::Corrupt)
    );
    let target = Database::with_options(
        fixture.objects.clone(),
        prepared.reference.creation.scope,
        12,
        test_options(),
    )
    .unwrap();
    assert!(matches!(
        target.session(
            7,
            &fixture.directory.path().join("must-not-open"),
            deadline()
        ),
        Err(Error::Corrupt)
    ));
    assert!(!fixture.directory.path().join("must-not-open").exists());
}
