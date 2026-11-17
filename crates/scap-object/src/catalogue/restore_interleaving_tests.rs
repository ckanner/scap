use super::*;
use crate::catalogue::{AbortPhase, DeletionPhase};
use crate::format::{decode_object, digest, encode_object, Envelope, Payload};

fn first_chunk(fixture: &Fixture) -> (String, Payload) {
    let point = &fixture.snapshot.point;
    let manifest = fixture
        .memory
        .get_value(&object_key(&scope(), 1, &point.data_root))
        .unwrap();
    let Payload::Manifest(manifest) = decode_object(&manifest.bytes, &scope(), &point.data_root)
        .unwrap()
        .payload
    else {
        panic!()
    };
    let hash = manifest.root.unwrap();
    let node = fixture
        .memory
        .get_value(&object_key(&scope(), 1, &hash))
        .unwrap();
    let Payload::Node { children, .. } =
        decode_object(&node.bytes, &scope(), &hash).unwrap().payload
    else {
        panic!()
    };
    let hash = children[0].clone();
    let chunk = fixture
        .memory
        .get_value(&object_key(&scope(), 1, &hash))
        .unwrap();
    (
        hash.clone(),
        decode_object(&chunk.bytes, &scope(), &hash)
            .unwrap()
            .payload,
    )
}

#[test]
fn retired_source_attempt_is_discarded_and_explicit_resume_restarts_same_point_in_new_generation() {
    let fixture = Fixture::new(true);
    let prepared = fixture.prepare();
    fixture.copying(&prepared);
    let (hash, _) = first_chunk(&fixture);
    let key = object_key(&scope(), 1, &hash);
    let source = fixture.source.clone();
    let memory = fixture.memory.clone();
    let removed = key.clone();
    fixture.memory.cut(
        false,
        &key,
        None,
        0,
        Fault::Run(Arc::new(move || {
            let head = source.status(7, deadline()).unwrap();
            let plan = source
                .compact_begin(7, head.head_serial, deadline())
                .unwrap();
            source
                .compact_copy(7, plan.head_serial, deadline())
                .unwrap();
            source
                .compact_promote(7, plan.head_serial, deadline())
                .unwrap();
            memory.remove(&removed);
        })),
    );
    let path = fixture.directory.path().join("retired-prefix");
    assert_eq!(
        fixture.catalogue.resume_restore(
            CREATOR,
            &prepared.reference,
            &path,
            RestoreBudget::default(),
            deadline()
        ),
        Err(CatalogueError::SnapshotExpired)
    );
    assert!(!path.exists());
    assert!(fixture
        .memory
        .get_value(&fixture.completion_key(&prepared))
        .is_none());
    assert_eq!(
        fixture
            .source
            .status(7, deadline())
            .unwrap()
            .storage
            .active_generation,
        2
    );
    fixture.memory.clear_calls();
    assert_eq!(fixture.resume(&prepared, 3).phase, RestorePhase::Copied);
    let calls = fixture.memory.calls();
    assert!(calls
        .iter()
        .any(|call| !call.put
            && call.key == object_key(&scope(), 2, &fixture.snapshot.point.data_root)));
    assert!(calls
        .iter()
        .all(|call| !call.key.starts_with(&object_key(&scope(), 1, ""))));
}

#[test]
fn retired_target_failure_is_conflict_and_never_an_expired_source() {
    let fixture = Fixture::new(true);
    let prepared = fixture.prepare();
    fixture.copying(&prepared);
    let (_, payload) = first_chunk(&fixture);
    let bytes = encode_object(&Envelope {
        format: 2,
        scope: prepared.reference.creation.scope.clone(),
        payload,
    })
    .unwrap();
    let key = object_key(&prepared.reference.creation.scope, 1, &digest(&bytes));
    let memory = fixture.memory.clone();
    let catalogue = fixture.catalogue.clone();
    let reference = prepared.reference.clone();
    let cancellation = AbortCreate {
        creation: reference.creation.clone(),
        operation: 710,
        expected_name_revision: 1,
        nonce: 711,
    };
    let removed = key.clone();
    fixture.memory.cut(
        false,
        &key,
        None,
        0,
        Fault::Run(Arc::new(move || {
            for _ in 0..4 {
                catalogue
                    .abort_restore(CREATOR, &reference, &cancellation, deadline())
                    .unwrap();
            }
            let head = catalogue
                .storage_status(CREATOR, &reference.creation, deadline())
                .unwrap();
            catalogue
                .retire_storage(
                    CREATOR,
                    &RetireNamedStorage {
                        creation: reference.creation.clone(),
                        expected_head_serial: head.head_serial,
                    },
                    deadline(),
                )
                .unwrap();
            memory.remove(&removed);
        })),
    );
    assert_eq!(
        fixture.catalogue.resume_restore(
            CREATOR,
            &prepared.reference,
            &fixture.directory.path().join("target-retired"),
            RestoreBudget::default(),
            deadline()
        ),
        Err(CatalogueError::Conflict)
    );
    assert!(fixture
        .memory
        .get_value(&fixture.completion_key(&prepared))
        .is_none());
    assert_eq!(fixture.resume(&prepared, 3).phase, RestorePhase::Aborted);
    assert!(fixture
        .source
        .query(
            7,
            &sql("SELECT n FROM restored"),
            &fixture.directory.path().join("healthy-source"),
            deadline()
        )
        .is_ok());
}

#[test]
fn concurrent_copy_resumers_share_immutable_completion_but_do_not_rebase_the_head() {
    let fixture = Fixture::new(true);
    let prepared = fixture.prepare();
    fixture.copying(&prepared);
    let catalogue = fixture.catalogue.clone();
    let reference = prepared.reference.clone();
    let directory = fixture.directory.path().join("winning-copy");
    let completion = fixture.completion_key(&prepared);
    fixture.memory.cut(
        true,
        &completion,
        None,
        0,
        Fault::Run(Arc::new(move || {
            assert_eq!(
                catalogue
                    .resume_restore(
                        CREATOR,
                        &reference,
                        &directory,
                        RestoreBudget::default(),
                        deadline()
                    )
                    .unwrap()
                    .phase,
                RestorePhase::Copied
            );
            assert!(!directory.exists());
        })),
    );
    let path = fixture.directory.path().join("losing-copy");
    assert_eq!(
        fixture.catalogue.resume_restore(
            CREATOR,
            &prepared.reference,
            &path,
            RestoreBudget::default(),
            deadline()
        ),
        Err(CatalogueError::Conflict)
    );
    assert!(!path.exists());
    let head = fixture
        .catalogue
        .read_slot(&prepared.reference.creation.scope, deadline())
        .unwrap()
        .unwrap()
        .head;
    assert_eq!((head.revision, head.head_serial, head.sequence), (1, 2, 0));
    assert_eq!(fixture.resume(&prepared, 3).phase, RestorePhase::Bound);
    assert_eq!(fixture.resume(&prepared, 4).phase, RestorePhase::Ready);
}

#[test]
fn unknown_at_every_resume_io_and_lost_write_response_never_returns_success_or_replaces_intent() {
    for stage in 0..5 {
        let fixture = Fixture::new(true);
        let prepared = fixture.prepare();
        for step in 0..stage {
            fixture.resume(&prepared, step);
        }
        let baseline = fixture.fork();
        baseline.resume(&prepared, stage);
        let calls = baseline.memory.calls();
        for (index, call) in calls.iter().enumerate() {
            for after in [false, true].into_iter().filter(|after| !after || call.put) {
                let candidate = fixture.fork();
                candidate.memory.fail_at(
                    index + 1,
                    if after {
                        Fault::AfterPut
                    } else {
                        Fault::Before(StoreError::Unknown)
                    },
                );
                let result = candidate.catalogue.resume_restore(
                    CREATOR,
                    &prepared.reference,
                    &candidate.directory.path().join("cut"),
                    RestoreBudget::default(),
                    deadline(),
                );
                assert_eq!(
                    result,
                    Err(CatalogueError::Unknown),
                    "stage {stage}, IO {index}, after={after}, key={}",
                    call.key
                );
                assert!(!candidate.directory.path().join("cut").exists());
                let observed = candidate
                    .catalogue
                    .inspect_restore(CREATOR, 7, 700, deadline())
                    .unwrap();
                assert_eq!(observed.prepared, prepared);
                for step in 0..6 {
                    if candidate.resume(&prepared, 10 + step).phase == RestorePhase::Ready {
                        break;
                    }
                    assert!(step < 5);
                }
                assert_eq!(
                    candidate
                        .catalogue
                        .inspect_restore(CREATOR, 7, 700, deadline())
                        .unwrap()
                        .phase,
                    RestorePhase::Ready
                );
            }
        }
    }
}

#[test]
fn absent_and_foreign_slots_abort_without_copying_and_allow_a_new_name_generation() {
    for foreign in [false, true] {
        let fixture = Fixture::new(true);
        let prepared = fixture.prepare();
        assert_eq!(fixture.resume(&prepared, 0).phase, RestorePhase::Reserved);
        let occupied = if foreign {
            let mut other = prepared.reference.creation.scope.clone();
            other.incarnation += 1;
            let database =
                Database::with_options(fixture.objects.clone(), other, 22, test_options()).unwrap();
            let original = database.create(90, 100, deadline()).unwrap();
            assert_eq!(
                fixture.resume(&prepared, 1).phase,
                RestorePhase::IdentityConflict
            );
            Some((database, original))
        } else {
            None
        };
        let cancellation = AbortCreate {
            creation: prepared.reference.creation.clone(),
            operation: 710,
            expected_name_revision: 1,
            nonce: 711,
        };
        for expected in [
            AbortPhase::Aborting,
            AbortPhase::Aborting,
            AbortPhase::Aborting,
            AbortPhase::Aborted,
        ] {
            // A ForeignOccupied proof needs no HEAD write, so its path has one
            // fewer explicit step than the absent-HEAD fence path.
            let observed = fixture
                .catalogue
                .abort_restore(CREATOR, &prepared.reference, &cancellation, deadline())
                .unwrap();
            if foreign && observed.phase == AbortPhase::Aborted {
                break;
            }
            assert_eq!(observed.phase, expected);
        }
        assert_eq!(fixture.resume(&prepared, 5).phase, RestorePhase::Aborted);
        assert!(fixture
            .memory
            .get_value(&fixture.completion_key(&prepared))
            .is_none());
        if let Some((database, original)) = occupied {
            assert_eq!(database.status(90, deadline()).unwrap(), original);
        }
        let next = fixture
            .catalogue
            .prepare_restore(
                CREATOR,
                &PrepareRestore {
                    operation: 701,
                    expected_name_revision: Some(3),
                    ..fixture.input()
                },
                deadline(),
            )
            .unwrap();
        for step in 0..5 {
            fixture.resume(&next, 20 + step);
        }
        assert_eq!(fixture.resume(&next, 30).phase, RestorePhase::Ready);
        assert_eq!(fixture.resume(&prepared, 31).phase, RestorePhase::Aborted);
    }
}

#[test]
fn competing_names_and_bound_restore_deletion_keep_distinct_phases() {
    let fixture = Fixture::new(false);
    let first = fixture.prepare();
    let second = fixture
        .catalogue
        .prepare_restore(
            CREATOR,
            &PrepareRestore {
                operation: 701,
                ..fixture.input()
            },
            deadline(),
        )
        .unwrap();
    for step in 0..4 {
        fixture.resume(&first, step);
    }
    assert_eq!(fixture.resume(&second, 4).phase, RestorePhase::NameConflict);
    let cancellation = AbortCreate {
        creation: first.reference.creation.clone(),
        operation: 710,
        expected_name_revision: 1,
        nonce: 711,
    };
    assert_eq!(
        fixture
            .catalogue
            .abort_restore(CREATOR, &first.reference, &cancellation, deadline())
            .unwrap()
            .phase,
        AbortPhase::CannotAbortBound
    );
    assert_eq!(fixture.resume(&first, 5).phase, RestorePhase::Ready);
    let deletion = DeleteNamed {
        creation: first.reference.creation.clone(),
        operation: 720,
        expected_name_revision: 2,
        expected_head_revision: 2,
        nonce: 721,
    };
    fixture.memory.cut(
        true,
        &fixture.catalogue.binding_key(&first.input.name),
        None,
        0,
        Fault::Before(StoreError::Unknown),
    );
    assert_eq!(
        fixture.catalogue.delete(CREATOR, &deletion, deadline()),
        Err(CatalogueError::Unknown)
    );
    assert_eq!(fixture.resume(&first, 6).phase, RestorePhase::Deleting);
    assert_eq!(
        fixture
            .catalogue
            .delete(CREATOR, &deletion, deadline())
            .unwrap()
            .phase,
        DeletionPhase::Deleted
    );
    assert_eq!(fixture.resume(&first, 7).phase, RestorePhase::Deleted);
}

#[test]
fn prepare_race_keeps_the_first_recipe_and_never_replaces_a_different_restore_input() {
    for empty_wins in [false, true] {
        let fixture = Fixture::new(false);
        let catalogue = fixture.catalogue.clone();
        let input = fixture.input();
        let winner = PrepareRestore {
            name: "winning input".into(),
            ..input.clone()
        };
        fixture.memory.cut(
            true,
            &fixture.catalogue.descriptor_key(7, 700),
            None,
            0,
            Fault::Run(Arc::new(move || {
                if empty_wins {
                    catalogue
                        .prepare(
                            CREATOR,
                            &PrepareCreate {
                                name: winner.name.clone(),
                                operation: 700,
                                expected_name_revision: None,
                                options: CreateOptions::default(),
                            },
                            deadline(),
                        )
                        .unwrap();
                } else {
                    catalogue
                        .prepare_restore(CREATOR, &winner, deadline())
                        .unwrap();
                }
            })),
        );
        assert_eq!(
            fixture
                .catalogue
                .prepare_restore(CREATOR, &input, deadline()),
            Err(CatalogueError::Conflict)
        );
        let winner = fixture
            .catalogue
            .read_descriptor(7, 700, deadline())
            .unwrap();
        assert_eq!(winner.creation.name, "winning input");
        assert_eq!(winner.recipe.is_none(), empty_wins);
    }
}

#[test]
fn permanent_completion_prevents_recreating_a_physically_missing_target_head() {
    let fixture = Fixture::new(true);
    let prepared = fixture.prepare();
    fixture.copying(&prepared);
    assert_eq!(fixture.resume(&prepared, 2).phase, RestorePhase::Copied);
    assert!(fixture
        .memory
        .get_value(&fixture.completion_key(&prepared))
        .is_some());
    fixture
        .memory
        .remove(&head_key(&prepared.reference.creation.scope));
    fixture.memory.clear_calls();
    assert_eq!(
        fixture
            .catalogue
            .inspect_restore(CREATOR, 7, 700, deadline()),
        Err(CatalogueError::Corrupt)
    );
    assert_eq!(
        fixture.catalogue.resume_restore(
            CREATOR,
            &prepared.reference,
            &fixture.directory.path().join("must-not-recreate"),
            RestoreBudget::default(),
            deadline()
        ),
        Err(CatalogueError::Corrupt)
    );
    assert!(fixture
        .memory
        .get_value(&head_key(&prepared.reference.creation.scope))
        .is_none());
    assert!(fixture.memory.calls().iter().all(|call| !call.put));
}

#[test]
fn a_completion_arriving_after_missing_head_observation_is_conflict_if_head_now_exists() {
    let fixture = Fixture::new(true);
    let prepared = fixture.prepare();
    assert_eq!(fixture.resume(&prepared, 0).phase, RestorePhase::Reserved);
    let catalogue = fixture.catalogue.clone();
    let reference = prepared.reference.clone();
    let directory = fixture.directory.path().join("concurrent-provision-copy");
    fixture.memory.cut(
        false,
        &fixture.completion_key(&prepared),
        None,
        0,
        Fault::Run(Arc::new(move || {
            assert_eq!(
                catalogue
                    .resume_restore(
                        CREATOR,
                        &reference,
                        &directory,
                        RestoreBudget::default(),
                        deadline()
                    )
                    .unwrap()
                    .phase,
                RestorePhase::Copying
            );
            assert_eq!(
                catalogue
                    .resume_restore(
                        CREATOR,
                        &reference,
                        &directory,
                        RestoreBudget::default(),
                        deadline()
                    )
                    .unwrap()
                    .phase,
                RestorePhase::Copied
            );
        })),
    );
    assert_eq!(
        fixture
            .catalogue
            .inspect_restore(CREATOR, 7, 700, deadline()),
        Err(CatalogueError::Conflict)
    );
    assert_eq!(
        fixture
            .catalogue
            .inspect_restore(CREATOR, 7, 700, deadline())
            .unwrap()
            .phase,
        RestorePhase::Copied
    );
}
