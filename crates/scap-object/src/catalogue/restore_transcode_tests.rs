use super::*;
use crate::catalogue::QuotaChoice;
use crate::data_tree::DataObjects;
use crate::format::{Manifest, Payload, PAGE_SIZE};
use crate::object_context::ObjectContext;

fn capture_current(fixture: &mut Fixture) {
    let head = fixture.source.status(7, deadline()).unwrap();
    let prepared = fixture
        .source
        .snapshot_prepare(
            7,
            &PrepareSnapshotInput {
                creator: 7,
                operation: 902,
                expected_revision: head.revision,
                expected_head_serial: head.head_serial,
                label: "current test point".into(),
            },
            deadline(),
        )
        .unwrap();
    fixture
        .source
        .snapshot_capture(7, &prepared.reference, deadline())
        .unwrap();
    fixture.snapshot = prepared;
}

#[test]
fn hash_valid_source_edges_and_native_bytes_are_verified_before_completion() {
    for damage in 0..9 {
        let mut fixture = Fixture::new(false);
        let objects = ObjectContext::bootstrap_at(&fixture.source, deadline()).unwrap();
        let empty = objects
            .save(
                Payload::Manifest(Manifest {
                    page_count: 0,
                    root: None,
                }),
                deadline(),
            )
            .unwrap();
        let mut bytes = vec![
            0;
            if damage == 6 {
                2 * PAGE_SIZE
            } else {
                PAGE_SIZE
            }
        ];
        if damage != 7 {
            bytes[..16].copy_from_slice(b"SQLite format 3\0");
            bytes[16..18].copy_from_slice(&[0x10, 0]);
        }
        let chunk = if damage == 4 {
            empty.clone()
        } else {
            objects
                .save(
                    Payload::Chunk {
                        first_page: if damage == 5 { 33 } else { 1 },
                        bytes,
                    },
                    deadline(),
                )
                .unwrap()
        };
        let node = if damage == 0 {
            empty
        } else {
            objects
                .save(
                    Payload::Node {
                        level: u8::from(damage == 1),
                        first_chunk: u32::from(damage == 2),
                        children: if damage == 3 {
                            vec![chunk.clone(), chunk]
                        } else {
                            vec![chunk]
                        },
                    },
                    deadline(),
                )
                .unwrap()
        };
        let root = objects
            .save(
                Payload::Manifest(Manifest {
                    page_count: 1,
                    root: Some(node),
                }),
                deadline(),
            )
            .unwrap();
        drop(objects);
        // Deliberately inject hash-valid external damage. The native SQL path
        // cannot emit these edges/images; S2 must still reject them on restore.
        let mut head = fixture.source.status(7, deadline()).unwrap();
        head.data_root = root;
        fixture
            .memory
            .set(&head_key(&scope()), encode_head(&head).unwrap());
        capture_current(&mut fixture);
        let prepared = fixture.prepare();
        fixture.copying(&prepared);
        let path = fixture.directory.path().join("invalid-source");
        assert_eq!(
            fixture.catalogue.resume_restore(
                CREATOR,
                &prepared.reference,
                &path,
                RestoreBudget::default(),
                deadline()
            ),
            Err(if damage == 8 {
                // A native SQLite open/configuration error has no structured
                // InvalidImage guarantee; it conservatively remains Unknown.
                CatalogueError::Unknown
            } else {
                CatalogueError::Corrupt
            }),
            "damage {damage}"
        );
        assert!(!path.exists());
        assert!(fixture
            .memory
            .get_value(&fixture.completion_key(&prepared))
            .is_none());
        assert_eq!(
            fixture
                .catalogue
                .inspect_restore(CREATOR, 7, 700, deadline())
                .unwrap()
                .phase,
            RestorePhase::Copying
        );
    }
}

#[test]
fn actual_multilevel_sqlite_tree_is_rewrapped_and_restored_without_source_payload() {
    const MIB: u64 = 1024 * 1024;
    let mut fixture = Fixture::new(false);
    let mut options = test_options();
    options.quota.max_bytes = Some(40 * MIB);
    options.sql.max_value_bytes = (40 * MIB) as u32;
    fixture.source = Database::with_options(fixture.objects.clone(), scope(), 10, options).unwrap();
    let head = fixture.source.status(7, deadline()).unwrap();
    fixture
        .source
        .set_quota(
            7,
            head.revision,
            903,
            crate::format::DatabaseQuota {
                max_bytes: Some(40 * MIB),
            },
            deadline(),
        )
        .unwrap();
    let mut statements = sql("CREATE TABLE multilevel(v BLOB)");
    statements.extend(sql("INSERT INTO multilevel VALUES(zeroblob(35651584))"));
    fixture
        .source
        .execute(
            7,
            &request(1, 1, 7, &statements).unwrap(),
            &statements,
            &fixture.directory.path().join("large-source"),
            deadline(),
        )
        .unwrap();
    capture_current(&mut fixture);
    assert!(fixture.snapshot.point.page_count > 32 * 256);
    let prepared = fixture
        .catalogue
        .prepare_restore(
            CREATOR,
            &PrepareRestore {
                options: CreateOptions {
                    quota: QuotaChoice::Limited {
                        max_bytes: 40 * MIB,
                    },
                },
                ..fixture.input()
            },
            deadline(),
        )
        .unwrap();
    for step in 0..5 {
        fixture.resume(&prepared, step);
    }
    fixture.remove_source_payload();
    let target = Database::with_options(
        fixture.objects.clone(),
        prepared.reference.creation.scope.clone(),
        12,
        test_options(),
    )
    .unwrap();
    assert_eq!(
        target
            .query(
                7,
                &sql("SELECT length(v) FROM multilevel"),
                &fixture.directory.path().join("large-cold-target"),
                deadline()
            )
            .unwrap()
            .statements[0]
            .rows,
        vec![vec![Value::Integer(35_651_584)]]
    );
    assert!(prepared.image_bytes() > 32 * MIB);
}
