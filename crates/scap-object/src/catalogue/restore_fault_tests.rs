use super::*;
use crate::catalogue::{AbortPhase, QuotaChoice};
use crate::format::{Permission, SnapshotIdentity};

fn abort(prepared: &PreparedRestore) -> AbortCreate {
    AbortCreate {
        creation: prepared.reference.creation.clone(),
        operation: 710,
        expected_name_revision: 1,
        nonce: 711,
    }
}

fn revoke(database: &Database) {
    let head = database.status(7, deadline()).unwrap();
    database
        .set_policy(
            7,
            head.revision,
            9001,
            vec![Permission {
                principal: 7,
                read: false,
                write: true,
                admin: true,
            }],
            deadline(),
        )
        .unwrap();
}

#[test]
fn restore_identity_is_first_winner_across_recipes_and_effective_defaults() {
    let fixture = Fixture::new(true);
    let prepared = fixture.prepare();
    let mut options = test_options();
    options.quota.max_bytes = Some(4096);
    options.retention.max_entries = 1;
    options.snapshot_limits.max_points = 0;
    let other = Catalogue::new(fixture.objects.clone(), 1, 2, 12, options).unwrap();
    assert_eq!(
        other
            .prepare_restore(CREATOR, &fixture.input(), deadline())
            .unwrap(),
        prepared
    );
    for changed in 0..5 {
        let mut input = fixture.input();
        match changed {
            0 => input.name = "another".into(),
            1 => input.expected_name_revision = Some(4),
            2 => input.options.quota = QuotaChoice::Unlimited,
            3 => input.snapshot.capture_serial += 1,
            _ => input.source_scope.incarnation += 1,
        }
        assert_eq!(
            fixture
                .catalogue
                .prepare_restore(CREATOR, &input, deadline()),
            Err(CatalogueError::Conflict)
        );
    }
    let empty = PrepareCreate {
        name: prepared.input.name.clone(),
        operation: 700,
        expected_name_revision: None,
        options: CreateOptions::default(),
    };
    assert_eq!(
        fixture.catalogue.prepare(CREATOR, &empty, deadline()),
        Err(CatalogueError::Conflict)
    );
    let empty = PrepareCreate {
        operation: 701,
        ..empty
    };
    fixture
        .catalogue
        .prepare(CREATOR, &empty, deadline())
        .unwrap();
    let input = PrepareRestore {
        operation: 701,
        ..fixture.input()
    };
    assert_eq!(
        fixture
            .catalogue
            .prepare_restore(CREATOR, &input, deadline()),
        Err(CatalogueError::Conflict)
    );
    let mut denied = CREATOR;
    denied.provision = false;
    fixture.memory.clear_calls();
    assert_eq!(
        fixture
            .catalogue
            .prepare_restore(denied, &fixture.input(), deadline()),
        Err(CatalogueError::Denied)
    );
    assert_eq!(
        fixture
            .catalogue
            .inspect_restore(denied, 7, 700, deadline()),
        Err(CatalogueError::Denied)
    );
    assert!(fixture.memory.calls().is_empty());
}

#[test]
fn restore_prepare_unknown_preserves_the_original_operation() {
    let fixture = Fixture::new(false);
    let key = fixture.catalogue.descriptor_key(7, 700);
    fixture.memory.cut(true, &key, None, 0, Fault::AfterPut);
    assert_eq!(
        fixture
            .catalogue
            .prepare_restore(CREATOR, &fixture.input(), deadline()),
        Err(CatalogueError::Unknown)
    );
    let observed = fixture
        .catalogue
        .inspect_restore(CREATOR, 7, 700, deadline())
        .unwrap();
    assert_eq!(observed.phase, RestorePhase::NotReserved);
    assert_eq!(fixture.prepare(), observed.prepared);
    let mut too_small = fixture.input();
    too_small.operation = 702;
    too_small.options.quota = QuotaChoice::Limited { max_bytes: 4096 };
    let data = Fixture::new(true);
    assert_eq!(
        data.catalogue
            .prepare_restore(CREATOR, &too_small, deadline()),
        Err(CatalogueError::Conflict)
    );
    too_small.snapshot = data.snapshot.reference.clone();
    assert_eq!(
        data.catalogue
            .prepare_restore(CREATOR, &too_small, deadline()),
        Err(CatalogueError::Limit)
    );
    assert!(data
        .memory
        .get_value(&data.catalogue.descriptor_key(7, 702))
        .is_none());
}

#[test]
fn each_copy_budget_and_private_directory_failure_prevents_completion() {
    for field in 0..8 {
        let fixture = Fixture::new(true);
        let prepared = fixture.prepare();
        fixture.copying(&prepared);
        let mut budget = RestoreBudget::default();
        match field {
            0 => budget.source_gets = 0,
            1 => budget.source_bytes = 1,
            2 => budget.target_puts = 0,
            3 => budget.target_put_bytes = 1,
            4 => budget.target_gets = 0,
            5 => budget.target_get_bytes = 1,
            6 => budget.max_image_bytes = 0,
            _ => {}
        }
        let path = fixture.directory.path().join("blocked");
        if field == 7 {
            std::fs::create_dir(&path).unwrap();
        }
        let error = fixture
            .catalogue
            .resume_restore(CREATOR, &prepared.reference, &path, budget, deadline())
            .unwrap_err();
        assert_eq!(
            error,
            if field == 7 {
                CatalogueError::Unknown
            } else {
                CatalogueError::Limit
            },
            "field {field}"
        );
        assert!(fixture
            .memory
            .get_value(&fixture.completion_key(&prepared))
            .is_none());
        assert_eq!(
            path.exists(),
            field == 7,
            "never delete a pre-existing directory"
        );
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
fn metadata_only_resumes_ignore_copy_budgets_but_empty_copy_is_disabled() {
    let fixture = Fixture::new(false);
    let prepared = fixture.prepare();
    let disabled = RestoreBudget {
        source_gets: 0,
        target_gets: 0,
        target_puts: 0,
        ..RestoreBudget::default()
    };
    let path = fixture.directory.path().join("not-allocated");
    for expected in [RestorePhase::Reserved, RestorePhase::Copying] {
        assert_eq!(
            fixture
                .catalogue
                .resume_restore(CREATOR, &prepared.reference, &path, disabled, deadline())
                .unwrap()
                .phase,
            expected
        );
    }
    assert_eq!(
        fixture
            .catalogue
            .resume_restore(CREATOR, &prepared.reference, &path, disabled, deadline()),
        Err(CatalogueError::Limit)
    );
    assert!(!path.exists());
    assert_eq!(fixture.resume(&prepared, 2).phase, RestorePhase::Copied);
    for expected in [RestorePhase::Bound, RestorePhase::Ready] {
        assert_eq!(
            fixture
                .catalogue
                .resume_restore(CREATOR, &prepared.reference, &path, disabled, deadline())
                .unwrap()
                .phase,
            expected
        );
        assert!(!path.exists());
    }
}

#[test]
fn new_copy_requires_a_retained_point_but_target_cancellation_does_not_need_source_access() {
    for revoked in [false, true] {
        let fixture = Fixture::new(true);
        let prepared = fixture.prepare();
        fixture.copying(&prepared);
        if revoked {
            revoke(&fixture.source);
        } else {
            fixture
                .source
                .snapshot_release(7, &fixture.snapshot.reference, deadline())
                .unwrap();
        }
        assert_eq!(
            fixture.catalogue.resume_restore(
                CREATOR,
                &prepared.reference,
                &fixture.directory.path().join("denied"),
                RestoreBudget::default(),
                deadline()
            ),
            Err(if revoked {
                CatalogueError::Denied
            } else {
                CatalogueError::Conflict
            })
        );
        let cancellation = abort(&prepared);
        for expected in [
            AbortPhase::Aborting,
            AbortPhase::Aborting,
            AbortPhase::Aborting,
            AbortPhase::Aborted,
        ] {
            let before = fixture.memory.calls().len();
            assert_eq!(
                fixture
                    .catalogue
                    .abort_restore(CREATOR, &prepared.reference, &cancellation, deadline())
                    .unwrap()
                    .phase,
                expected
            );
            let calls = fixture.memory.calls();
            assert!(
                calls[before..]
                    .iter()
                    .filter(|call| call.put
                        && (call.key.ends_with("/head")
                            || call.key.contains("/catalogue/v1/name/")))
                    .count()
                    <= 1
            );
            assert!(!calls[before..]
                .iter()
                .any(|call| call.key == head_key(&scope())));
        }
        assert_eq!(fixture.resume(&prepared, 10).phase, RestorePhase::Aborted);
        let head = fixture
            .catalogue
            .read_slot(&prepared.reference.creation.scope, deadline())
            .unwrap()
            .unwrap()
            .head;
        let retired = fixture
            .catalogue
            .retire_storage(
                CREATOR,
                &RetireNamedStorage {
                    creation: prepared.reference.creation.clone(),
                    expected_head_serial: head.head_serial,
                },
                deadline(),
            )
            .unwrap();
        assert!(retired.storage.terminal.is_some());
    }
}

#[test]
fn source_revocation_at_either_final_observation_wins_before_metadata_errors() {
    for head_skip in [2, 3] {
        let fixture = Fixture::new(true);
        let prepared = fixture.prepare();
        fixture.copying(&prepared);
        let source = fixture.source.clone();
        fixture.memory.cut(
            false,
            &head_key(&scope()),
            None,
            head_skip,
            Fault::Run(Arc::new(move || revoke(&source))),
        );
        assert_eq!(
            fixture.catalogue.resume_restore(
                CREATOR,
                &prepared.reference,
                &fixture.directory.path().join("revoked-final"),
                RestoreBudget::default(),
                deadline()
            ),
            Err(CatalogueError::Denied)
        );
        assert!(fixture
            .memory
            .get_value(&fixture.completion_key(&prepared))
            .is_none());
        assert!(!fixture.directory.path().join("revoked-final").exists());
    }
    let fixture = Fixture::new(true);
    let prepared = fixture.prepare();
    fixture.copying(&prepared);
    let key = crate::snapshot_records::key(
        &scope(),
        &SnapshotIdentity {
            creator: 7,
            operation: 901,
        },
        false,
    );
    let source = fixture.source.clone();
    let memory = fixture.memory.clone();
    let corrupt = key.clone();
    fixture.memory.cut(
        false,
        &key,
        None,
        1,
        Fault::Run(Arc::new(move || {
            memory.set(&corrupt, b"malformed".to_vec());
            revoke(&source);
        })),
    );
    assert_eq!(
        fixture.catalogue.resume_restore(
            CREATOR,
            &prepared.reference,
            &fixture.directory.path().join("metadata-and-revoked"),
            RestoreBudget::default(),
            deadline()
        ),
        Err(CatalogueError::Denied)
    );
    assert!(fixture
        .memory
        .get_value(&fixture.completion_key(&prepared))
        .is_none());
}

#[test]
fn stable_permission_barrier_rejects_changed_head_without_reusing_the_failed_prefix() {
    let fixture = Fixture::new(true);
    let prepared = fixture.prepare();
    fixture.copying(&prepared);
    let source = fixture.source.clone();
    fixture.memory.cut(
        false,
        &head_key(&scope()),
        None,
        3,
        Fault::Run(Arc::new(move || {
            let head = source.status(7, deadline()).unwrap();
            source
                .set_policy(7, head.revision, 9011, head.policy, deadline())
                .unwrap();
        })),
    );
    assert_eq!(
        fixture.catalogue.resume_restore(
            CREATOR,
            &prepared.reference,
            &fixture.directory.path().join("changed-final"),
            RestoreBudget::default(),
            deadline()
        ),
        Err(CatalogueError::Conflict)
    );
    assert!(fixture
        .memory
        .get_value(&fixture.completion_key(&prepared))
        .is_none());
    fixture.memory.clear_calls();
    assert_eq!(fixture.resume(&prepared, 3).phase, RestorePhase::Copied);
    assert!(fixture
        .memory
        .calls()
        .iter()
        .any(|call| !call.put
            && call.key == object_key(&scope(), 1, &fixture.snapshot.point.data_root)));
}

#[test]
fn admitted_copy_can_finish_after_release_but_late_target_abort_fences_publication() {
    for abort_target in [false, true] {
        let fixture = Fixture::new(true);
        let prepared = fixture.prepare();
        fixture.copying(&prepared);
        let completion = fixture.completion_key(&prepared);
        let source = fixture.source.clone();
        let snapshot = fixture.snapshot.reference.clone();
        let catalogue = fixture.catalogue.clone();
        let reference = prepared.reference.clone();
        let cancel = abort(&prepared);
        fixture.memory.cut(
            true,
            &completion,
            None,
            0,
            Fault::Run(Arc::new(move || {
                if abort_target {
                    assert_eq!(
                        catalogue
                            .abort_restore(CREATOR, &reference, &cancel, deadline())
                            .unwrap()
                            .phase,
                        AbortPhase::Aborting
                    );
                } else {
                    source.snapshot_release(7, &snapshot, deadline()).unwrap();
                    revoke(&source);
                }
            })),
        );
        let result = fixture.catalogue.resume_restore(
            CREATOR,
            &prepared.reference,
            &fixture.directory.path().join("late-effect"),
            RestoreBudget::default(),
            deadline(),
        );
        assert!(fixture.memory.get_value(&completion).is_some());
        if abort_target {
            assert_eq!(result, Err(CatalogueError::Conflict));
            for _ in 0..3 {
                fixture
                    .catalogue
                    .abort_restore(CREATOR, &prepared.reference, &abort(&prepared), deadline())
                    .unwrap();
            }
            assert_eq!(fixture.resume(&prepared, 10).phase, RestorePhase::Aborted);
        } else {
            assert_eq!(result.unwrap().phase, RestorePhase::Copied);
            assert_eq!(fixture.resume(&prepared, 3).phase, RestorePhase::Bound);
            assert_eq!(fixture.resume(&prepared, 4).phase, RestorePhase::Ready);
        }
    }
}

#[test]
fn release_during_an_admitted_copy_uses_accepted_proof_at_the_final_barrier() {
    let fixture = Fixture::new(true);
    let prepared = fixture.prepare();
    fixture.copying(&prepared);
    let source = fixture.source.clone();
    let reference = fixture.snapshot.reference.clone();
    fixture.memory.cut(
        false,
        &head_key(&scope()),
        None,
        2,
        Fault::Run(Arc::new(move || {
            source.snapshot_release(7, &reference, deadline()).unwrap();
        })),
    );
    assert_eq!(fixture.resume(&prepared, 2).phase, RestorePhase::Copied);
}

#[test]
fn released_prepare_and_in_progress_abort_do_not_create_new_authority() {
    let fixture = Fixture::new(false);
    fixture
        .source
        .snapshot_release(7, &fixture.snapshot.reference, deadline())
        .unwrap();
    assert_eq!(
        fixture
            .catalogue
            .prepare_restore(CREATOR, &fixture.input(), deadline()),
        Err(CatalogueError::Conflict)
    );
    let fixture = Fixture::new(false);
    let prepared = fixture.prepare();
    fixture.copying(&prepared);
    assert_eq!(
        fixture
            .catalogue
            .abort_restore(CREATOR, &prepared.reference, &abort(&prepared), deadline())
            .unwrap()
            .phase,
        AbortPhase::Aborting
    );
    fixture.memory.clear_calls();
    assert_eq!(fixture.resume(&prepared, 4).phase, RestorePhase::Aborting);
    assert!(fixture.memory.calls().iter().all(|call| !call.put));
}

#[test]
fn real_image_directory_loss_during_sync_never_publishes_fresh_or_existing_completion() {
    use crate::format::{decode_object, digest, Payload};
    for existing_completion in [false, true] {
        let fixture = Fixture::new(true);
        let prepared = fixture.prepare();
        fixture.copying(&prepared);
        let completion_key = fixture.completion_key(&prepared);
        if existing_completion {
            fixture
                .memory
                .cut(true, &completion_key, None, 0, Fault::AfterPut);
            assert_eq!(
                fixture.catalogue.resume_restore(
                    CREATOR,
                    &prepared.reference,
                    &fixture.directory.path().join("accepted-completion"),
                    RestoreBudget::default(),
                    deadline()
                ),
                Err(CatalogueError::Unknown)
            );
        }
        let baseline = fixture.fork();
        assert_eq!(baseline.resume(&prepared, 3).phase, RestorePhase::Copied);
        let calls = baseline.memory.calls();
        let target_scope = &prepared.reference.creation.scope;
        let target_prefix = object_key(target_scope, 1, "");
        let fault_index = if existing_completion {
            let (index, call) = calls
                .iter()
                .enumerate()
                .rfind(|(_, call)| !call.put && call.key.starts_with(&target_prefix))
                .unwrap();
            let body = baseline.memory.get_value(&call.key).unwrap();
            assert!(matches!(
                decode_object(&body.bytes, target_scope, &digest(&body.bytes))
                    .unwrap()
                    .payload,
                Payload::Chunk { .. }
            ));
            index
        } else {
            let (saved, call) = calls
                .iter()
                .enumerate()
                .find(|(_, call)| {
                    call.put
                        && call.key.starts_with(&target_prefix)
                        && matches!(
                            decode_object(&call.bytes, target_scope, &digest(&call.bytes))
                                .unwrap()
                                .payload,
                            Payload::Manifest(_)
                        )
                })
                .unwrap();
            calls
                .iter()
                .enumerate()
                .skip(saved + 1)
                .find(|(_, read)| !read.put && read.key == call.key)
                .unwrap()
                .0
        };
        let candidate = fixture.fork();
        let before_head = candidate.memory.get_value(&head_key(target_scope)).unwrap();
        let before_completion = candidate.memory.get_value(&completion_key);
        let path = candidate.directory.path().join("kernel-sync-failure");
        let removed = path.clone();
        candidate.memory.fail_at(
            fault_index + 1,
            Fault::Run(Arc::new(move || {
                assert!(removed.join("database.sqlite").is_file());
                // Keep the open file descriptor real; unlink its owned directory.
                // Subsequent directory fsync reaches the kernel and fails ENOENT.
                std::fs::remove_dir_all(&removed).unwrap();
            })),
        );
        assert_eq!(
            candidate.catalogue.resume_restore(
                CREATOR,
                &prepared.reference,
                &path,
                RestoreBudget::default(),
                deadline()
            ),
            Err(CatalogueError::Unknown)
        );
        assert!(!path.exists());
        assert_eq!(
            candidate.memory.get_value(&head_key(target_scope)),
            Some(before_head)
        );
        assert_eq!(
            candidate.memory.get_value(&completion_key),
            before_completion
        );
        assert!(candidate
            .memory
            .calls()
            .iter()
            .all(|call| !call.put || call.key != head_key(target_scope)));
        assert_eq!(
            candidate
                .catalogue
                .inspect_restore(CREATOR, 7, 700, deadline())
                .unwrap()
                .phase,
            RestorePhase::Copying
        );
        assert_eq!(candidate.resume(&prepared, 4).phase, RestorePhase::Copied);
    }
}

#[test]
fn existing_completion_cannot_replace_a_callers_occupied_staging_directory() {
    let fixture = Fixture::new(true);
    let prepared = fixture.prepare();
    fixture.copying(&prepared);
    fixture.memory.cut(
        true,
        &fixture.completion_key(&prepared),
        None,
        0,
        Fault::AfterPut,
    );
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
    fixture.remove_source_payload();
    let path = fixture.directory.path().join("occupied-staging");
    std::fs::create_dir(&path).unwrap();
    let sentinel = path.join("caller-owned");
    std::fs::write(&sentinel, b"preserve this directory").unwrap();
    let head = head_key(&prepared.reference.creation.scope);
    let original_head = fixture.memory.get_value(&head).unwrap();
    let original_completion = fixture
        .memory
        .get_value(&fixture.completion_key(&prepared))
        .unwrap();
    fixture.memory.clear_calls();
    assert_eq!(
        fixture.catalogue.resume_restore(
            CREATOR,
            &prepared.reference,
            &path,
            RestoreBudget::default(),
            deadline()
        ),
        Err(CatalogueError::Unknown)
    );
    assert_eq!(
        std::fs::read(&sentinel).unwrap(),
        b"preserve this directory"
    );
    assert_eq!(fixture.memory.get_value(&head).unwrap(), original_head);
    assert_eq!(
        fixture
            .memory
            .get_value(&fixture.completion_key(&prepared))
            .unwrap(),
        original_completion
    );
    assert!(fixture
        .memory
        .calls()
        .iter()
        .all(|call| !call.put && !call.key.starts_with(&object_key(&scope(), 1, ""))));
    assert_eq!(fixture.resume(&prepared, 3).phase, RestorePhase::Copied);
}
