use super::*;
use records::BindingState;

#[test]
fn concurrent_same_intent_resumers_finish_or_conflict_without_fabricating_a_new_candidate() {
    for operation in [0, 1, 2] {
        let (base, _, creation) = match operation {
            0 => prepared(),
            1 => stage(CreationPhase::Reserved),
            _ => stage(CreationPhase::Ready),
        };
        let invoke = move |catalog: &Catalogue, target: &Creation| -> Result<(), CatalogueError> {
            match operation {
                0 => {
                    assert_eq!(
                        catalog.resume_create(CREATOR, target, deadline())?.phase,
                        CreationPhase::Ready
                    );
                }
                1 => {
                    assert_eq!(
                        catalog
                            .abort_create(CREATOR, &abort(target), deadline())?
                            .phase,
                        AbortPhase::Aborted
                    );
                }
                _ => {
                    assert_eq!(
                        catalog.delete(CREATOR, &delete(target), deadline())?.phase,
                        DeletionPhase::Deleted
                    );
                }
            }
            Ok(())
        };
        let success = base.fork();
        invoke(&catalogue(success.clone()), &creation).unwrap();
        for (index, call) in success.calls().into_iter().enumerate() {
            let objects = base.fork();
            let peer =
                Catalogue::new(objects.clone(), 1, 2, 20, crate::tests::test_options()).unwrap();
            let target = creation.clone();
            let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let flag = ran.clone();
            objects.fail_at(
                index + 1,
                Fault::Run(Arc::new(move || {
                    flag.store(true, std::sync::atomic::Ordering::Release);
                    invoke(&peer, &target).unwrap();
                })),
            );
            let catalog = catalogue(objects.clone());
            let result = invoke(&catalog, &creation);
            assert!(
                matches!(result, Ok(()) | Err(CatalogueError::Conflict)),
                "operation {operation} at {index}, put {}, error {result:?}",
                call.put
            );
            assert!(ran.load(std::sync::atomic::Ordering::Acquire));
            invoke(&catalog, &creation).unwrap();
        }
    }
}

#[test]
fn different_fixed_controls_never_claim_each_others_terminal_transition() {
    for aborting in [true, false] {
        let (objects, catalogue, creation) = stage(if aborting {
            CreationPhase::Reserved
        } else {
            CreationPhase::Ready
        });
        let peer = super::catalogue(objects.clone());
        let target = creation.clone();
        let name_key = catalogue.binding_key(&creation.name);
        objects.cut(
            false,
            &name_key,
            None,
            0,
            Fault::Run(Arc::new(move || {
                if aborting {
                    let mut control = abort(&target);
                    control.operation += 1;
                    control.nonce += 1;
                    peer.abort_create(CREATOR, &control, deadline()).unwrap();
                } else {
                    let mut control = delete(&target);
                    control.operation += 1;
                    control.nonce += 1;
                    peer.delete(CREATOR, &control, deadline()).unwrap();
                }
            })),
        );
        let result = if aborting {
            catalogue
                .abort_create(CREATOR, &abort(&creation), deadline())
                .map(|_| ())
        } else {
            catalogue
                .delete(CREATOR, &delete(&creation), deadline())
                .map(|_| ())
        };
        assert_eq!(result, Err(CatalogueError::Conflict));
    }
}

#[test]
fn every_creation_io_unknown_requires_explicit_fixed_identity_recovery() {
    let (base, _, creation) = prepared();
    let successful = base.fork();
    catalogue(successful.clone())
        .resume_create(CREATOR, &creation, deadline())
        .unwrap();
    let calls = successful.calls();
    for (offset, call) in calls.iter().enumerate() {
        for after in [false, true] {
            if after && !call.put {
                continue;
            }
            let objects = base.fork();
            let catalogue = catalogue(objects.clone());
            objects.fail_at(
                offset + 1,
                if after {
                    Fault::AfterPut
                } else {
                    Fault::Before(StoreError::Unknown)
                },
            );
            assert_eq!(
                catalogue.resume_create(CREATOR, &creation, deadline()),
                Err(CatalogueError::Unknown),
                "offset {offset} after {after}"
            );
            assert_eq!(objects.calls().len(), offset + 1, "must stop after unknown");
            let done = catalogue
                .resume_create(CREATOR, &creation, deadline())
                .unwrap();
            assert_eq!(done.phase, CreationPhase::Ready);
            assert_eq!(done.creation, creation);
            assert_eq!(done.binding_revision, Some(2));
            assert_eq!(done.head_revision, Some(2));
        }
    }
}

#[test]
fn every_abort_and_delete_io_unknown_retains_original_control_and_barrier() {
    for aborting in [true, false] {
        let (base, _, creation) = stage(if aborting {
            CreationPhase::Reserved
        } else {
            CreationPhase::Ready
        });
        let successful = base.fork();
        let catalog = catalogue(successful.clone());
        if aborting {
            catalog
                .abort_create(CREATOR, &abort(&creation), deadline())
                .unwrap();
        } else {
            catalog
                .delete(CREATOR, &delete(&creation), deadline())
                .unwrap();
        }
        let calls = successful.calls();
        for (offset, call) in calls.iter().enumerate() {
            for after in [false, true] {
                if after && !call.put {
                    continue;
                }
                let objects = base.fork();
                let catalogue = catalogue(objects.clone());
                objects.fail_at(
                    offset + 1,
                    if after {
                        Fault::AfterPut
                    } else {
                        Fault::Before(StoreError::Unknown)
                    },
                );
                let result = if aborting {
                    catalogue
                        .abort_create(CREATOR, &abort(&creation), deadline())
                        .map(|_| ())
                } else {
                    catalogue
                        .delete(CREATOR, &delete(&creation), deadline())
                        .map(|_| ())
                };
                assert_eq!(
                    result,
                    Err(CatalogueError::Unknown),
                    "abort {aborting} offset {offset} after {after}"
                );
                assert_eq!(objects.calls().len(), offset + 1);
                if aborting {
                    assert_eq!(
                        catalogue
                            .abort_create(CREATOR, &abort(&creation), deadline())
                            .unwrap()
                            .phase,
                        AbortPhase::Aborted
                    );
                } else {
                    assert_eq!(
                        catalogue
                            .delete(CREATOR, &delete(&creation), deadline())
                            .unwrap()
                            .phase,
                        DeletionPhase::Deleted
                    );
                }
            }
        }
    }
}

#[test]
fn control_success_is_not_inferred_before_name_release_or_exact_proof() {
    let (objects, catalogue, creation) = stage(CreationPhase::Reserved);
    let key = catalogue.binding_key(&creation.name);
    objects.cut(
        true,
        &key,
        Some(("state", "tombstone")),
        0,
        Fault::Before(StoreError::Unknown),
    );
    let control = abort(&creation);
    assert_eq!(
        catalogue.abort_create(CREATOR, &control, deadline()),
        Err(CatalogueError::Unknown)
    );
    let progress = catalogue
        .inspect_create_operation(CREATOR, 1, deadline())
        .unwrap();
    assert_eq!(progress.phase, CreationPhase::Aborting);
    assert_eq!(progress.binding_revision, Some(2));
    assert!(objects.get_value(&catalogue.proof_key(&creation)).is_some());
    assert_eq!(
        catalogue.resolve(CREATOR, &creation.name, deadline()),
        Err(CatalogueError::NotFound)
    );
    let new = catalogue
        .prepare(CREATOR, &input(&creation.name, 2, Some(2)), deadline())
        .unwrap();
    assert_eq!(
        catalogue
            .resume_create(CREATOR, &new.creation, deadline())
            .unwrap()
            .phase,
        CreationPhase::NameConflict
    );
    catalogue
        .abort_create(CREATOR, &control, deadline())
        .unwrap();
    objects.remove(&catalogue.proof_key(&creation));
    assert_eq!(
        catalogue.inspect_create_operation(CREATOR, 1, deadline()),
        Err(CatalogueError::Corrupt)
    );

    let (objects, catalogue, creation) = stage(CreationPhase::Ready);
    objects.cut(
        true,
        &catalogue.binding_key(&creation.name),
        Some(("state", "tombstone")),
        0,
        Fault::Before(StoreError::Unknown),
    );
    let control = delete(&creation);
    assert_eq!(
        catalogue.delete(CREATOR, &control, deadline()),
        Err(CatalogueError::Unknown)
    );
    assert_eq!(
        catalogue
            .inspect_create_operation(CREATOR, 1, deadline())
            .unwrap()
            .phase,
        CreationPhase::Deleting
    );
    assert_eq!(
        catalogue
            .abort_create(CREATOR, &abort(&creation), deadline())
            .unwrap()
            .phase,
        AbortPhase::CannotAbortBound
    );
    assert_eq!(
        catalogue.resolve(CREATOR, &creation.name, deadline()),
        Err(CatalogueError::NotFound)
    );
    assert_eq!(
        catalogue
            .delete(CREATOR, &control, deadline())
            .unwrap()
            .phase,
        DeletionPhase::Deleted
    );
}

#[test]
fn changed_binding_during_cross_key_reads_is_a_conflict_even_with_reused_etag() {
    for preserve_etag in [false, true] {
        let (objects, catalogue, creation) = stage(CreationPhase::Provisioning);
        let original = catalogue
            .read_binding(&creation.name, deadline())
            .unwrap()
            .unwrap();
        let mut changed = original.body.raw().clone();
        changed.state = BindingState::Bound;
        changed.revision = 2;
        let key = catalogue.binding_key(&creation.name);
        objects.cut(
            false,
            &key,
            None,
            1,
            Fault::Replace {
                key: key.clone(),
                bytes: records::encode(&changed).unwrap(),
                preserve_etag,
            },
        );
        assert_eq!(
            catalogue.inspect_create_operation(CREATOR, 1, deadline()),
            Err(CatalogueError::Conflict)
        );
        assert_eq!(
            catalogue
                .inspect_create_operation(CREATOR, 1, deadline())
                .unwrap()
                .phase,
            CreationPhase::Bound
        );
        catalogue
            .resume_create(CREATOR, &creation, deadline())
            .unwrap();
    }
}

#[test]
fn bound_head_missing_wrong_source_and_revoked_read_fail_abort_closed() {
    for corruption in [0, 1, 2] {
        let (objects, catalogue, creation) = stage(CreationPhase::Ready);
        let key = format::head_key(&creation.scope);
        if corruption == 0 {
            objects.remove(&key);
        } else {
            let mut head = catalogue
                .read_slot(&creation.scope, deadline())
                .unwrap()
                .unwrap()
                .head;
            if corruption == 1 {
                head.scope.incarnation += 1;
            } else {
                head.creation.as_mut().unwrap().descriptor_hash = format::digest(b"wrong");
            }
            objects.set(&key, format::encode_head(&head).unwrap());
        }
        assert_eq!(
            catalogue.abort_create(CREATOR, &abort(&creation), deadline()),
            Err(CatalogueError::Corrupt)
        );
    }
    let (_, catalogue, creation) = stage(CreationPhase::Ready);
    let database = catalogue.database(&descriptor(&catalogue, &creation));
    let mut head = database.status(CREATOR.principal, deadline()).unwrap();
    head.policy[0].read = false;
    database
        .set_policy(CREATOR.principal, 2, 9, head.policy, deadline())
        .unwrap();
    assert_eq!(
        catalogue.abort_create(CREATOR, &abort(&creation), deadline()),
        Err(CatalogueError::Denied)
    );
    let mut control = delete(&creation);
    control.expected_head_revision = 3;
    catalogue.delete(CREATOR, &control, deadline()).unwrap();
    assert_eq!(
        catalogue.abort_create(CREATOR, &abort(&creation), deadline()),
        Err(CatalogueError::Denied)
    );
}

#[test]
fn delete_classifies_missing_and_foreign_heads_by_durable_name_phase() {
    for phase in [CreationPhase::Bound, CreationPhase::Ready] {
        let (objects, catalogue, creation) = stage(phase);
        objects.remove(&format::head_key(&creation.scope));
        assert_eq!(
            catalogue.delete(CREATOR, &delete(&creation), deadline()),
            Err(CatalogueError::Corrupt)
        );
        let mut foreign = creation.scope.clone();
        foreign.incarnation += 1;
        Database::with_options(objects.clone(), foreign, 90, crate::tests::test_options())
            .unwrap()
            .create(90, 1, deadline())
            .unwrap();
        assert_eq!(
            catalogue.delete(CREATOR, &delete(&creation), deadline()),
            Err(CatalogueError::Corrupt)
        );
    }
    let (objects, catalogue, creation) = prepared();
    assert_eq!(
        catalogue.delete(CREATOR, &delete(&creation), deadline()),
        Err(CatalogueError::NotFound)
    );
    let mut foreign = creation.scope.clone();
    foreign.incarnation += 1;
    Database::with_options(objects.clone(), foreign, 90, crate::tests::test_options())
        .unwrap()
        .create(90, 1, deadline())
        .unwrap();
    assert_eq!(
        catalogue.delete(CREATOR, &delete(&creation), deadline()),
        Err(CatalogueError::IdentityConflict)
    );
    let progress = catalogue
        .resume_create(CREATOR, &creation, deadline())
        .unwrap();
    assert_eq!(progress.phase, CreationPhase::IdentityConflict);
    catalogue
        .abort_create(CREATOR, &abort(&creation), deadline())
        .unwrap();
    assert_eq!(
        catalogue.delete(CREATOR, &delete(&creation), deadline()),
        Err(CatalogueError::IdentityConflict)
    );
    objects.remove(&format::head_key(&creation.scope));
    assert_eq!(
        catalogue.delete(CREATOR, &delete(&creation), deadline()),
        Err(CatalogueError::Corrupt)
    );
}

#[test]
fn foreign_named_source_requires_exact_descriptor_but_not_business_closure_or_current_name() {
    for change in [0, 1, 2, 3] {
        let (objects, catalogue, creation) = stage(CreationPhase::Reserved);
        let descriptor = descriptor(&catalogue, &creation);
        let database = catalogue.database(&descriptor);
        let mut foreign = database.initial_head(90, 1, deadline()).unwrap();
        foreign.creation = Some(descriptor.origin());
        match change {
            0 => foreign.scope.incarnation += 1,
            1 => foreign.creation.as_mut().unwrap().creator += 1,
            2 => {
                foreign.creation.as_mut().unwrap().descriptor_hash =
                    format::digest(b"unknown descriptor")
            }
            _ => foreign.creation.as_mut().unwrap().name_hash = format::digest(b"wrong name"),
        }
        objects.set(
            &format::head_key(&creation.scope),
            format::encode_head(&foreign).unwrap(),
        );
        assert_eq!(
            catalogue.abort_create(CREATOR, &abort(&creation), deadline()),
            Err(CatalogueError::Corrupt)
        );
        assert_eq!(
            catalogue.resume_create(CREATOR, &creation, deadline()),
            Err(CatalogueError::Corrupt)
        );
    }
    let (objects, catalogue, creation) = stage(CreationPhase::Reserved);
    let mut foreign_scope = creation.scope.clone();
    foreign_scope.incarnation += 1;
    let database = Database::with_options(
        objects.clone(),
        foreign_scope.clone(),
        90,
        crate::tests::test_options(),
    )
    .unwrap();
    let head = database.create(90, 1, deadline()).unwrap();
    objects.remove(&format::object_key(&foreign_scope, &head.data_root));
    objects.clear_calls();
    assert_eq!(
        catalogue
            .abort_create(CREATOR, &abort(&creation), deadline())
            .unwrap()
            .phase,
        AbortPhase::Aborted
    );
    assert!(objects
        .calls()
        .iter()
        .all(|call| !call.key.contains("/objects/")));
    assert_eq!(database.status(90, deadline()).unwrap(), head);
}

#[test]
fn admission_source_and_authority_read_boundaries_reject_without_reinterpretation() {
    let (objects, catalogue, creation) = prepared();
    let before = objects.calls().len();
    let denied = Caller {
        principal: 7,
        provision: false,
    };
    let other = Caller {
        principal: 8,
        provision: true,
    };
    assert_eq!(
        catalogue.prepare(denied, &input("x", 2, None), deadline()),
        Err(CatalogueError::Denied)
    );
    assert_eq!(
        catalogue.resume_create(other, &creation, deadline()),
        Err(CatalogueError::Denied)
    );
    assert_eq!(
        catalogue.abort_create(other, &abort(&creation), deadline()),
        Err(CatalogueError::Denied)
    );
    assert_eq!(
        catalogue.inspect_create_operation(denied, 1, deadline()),
        Err(CatalogueError::Denied)
    );
    assert_eq!(objects.calls().len(), before);
    assert_eq!(
        catalogue.inspect_create_operation(CREATOR, 0, deadline()),
        Err(CatalogueError::Invalid)
    );
    assert_eq!(
        catalogue.inspect_create_operation(CREATOR, 2, deadline()),
        Err(CatalogueError::NotFound)
    );
    let mut changed = creation.clone();
    changed.name = "another".into();
    assert_eq!(
        catalogue.resume_create(CREATOR, &changed, deadline()),
        Err(CatalogueError::Conflict)
    );
    changed = creation.clone();
    changed.scope.database += 1;
    assert_eq!(
        catalogue.resume_create(CREATOR, &changed, deadline()),
        Err(CatalogueError::Invalid)
    );
    for error in [
        StoreError::Invalid,
        StoreError::Corrupt,
        StoreError::Limit,
        StoreError::Unknown,
    ] {
        let expected = store_error(error.clone());
        objects.cut(
            false,
            &catalogue.descriptor_key(7, 1),
            None,
            0,
            Fault::Before(error),
        );
        assert_eq!(
            catalogue.inspect_create_operation(CREATOR, 1, deadline()),
            Err(expected)
        );
    }
    objects.cut(
        false,
        &catalogue.descriptor_key(7, 1),
        None,
        0,
        Fault::EmptyEtag,
    );
    assert_eq!(
        catalogue.inspect_create_operation(CREATOR, 1, deadline()),
        Err(CatalogueError::Corrupt)
    );
    let missing_previous = catalogue
        .prepare(CREATOR, &input("unused", 2, Some(3)), deadline())
        .unwrap();
    assert_eq!(
        catalogue
            .resume_create(CREATOR, &missing_previous.creation, deadline())
            .unwrap()
            .phase,
        CreationPhase::NameConflict
    );
    let expired = Instant::now();
    assert_eq!(
        catalogue.prepare(CREATOR, &input("late", 3, None), expired),
        Err(CatalogueError::Unknown)
    );
}
