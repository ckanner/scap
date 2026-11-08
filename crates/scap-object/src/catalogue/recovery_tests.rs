use super::*;
use records::BindingState;

#[test]
fn unchanged_aborting_name_allows_a_concurrent_head_barrier_and_permanent_proof() {
    // The second worker advances only HEAD and Proof, then loses the response
    // before the name release. Both name observations remain exactly equal.
    // A HEAD-before-Proof reader would pair an old absent/Provisioning HEAD
    // with the new proof and falsely classify this legal history as Corrupt.
    for phase in [CreationPhase::Reserved, CreationPhase::Provisioning] {
        for operation in 0..3 {
            let (objects, catalog, creation) = stage(phase.clone());
            let control = abort(&creation);
            objects.cut(
                true,
                &format::head_key(&creation.scope),
                Some(("lifecycle", "deleted")),
                0,
                Fault::Before(StoreError::Unknown),
            );
            assert_eq!(
                catalog.abort_create(CREATOR, &control, deadline()),
                Err(CatalogueError::Unknown)
            );
            let name_key = catalog.binding_key(&creation.name);
            let before = objects.get_value(&name_key).unwrap();
            let source = descriptor(&catalog, &creation);
            let proof_key = catalog.proof_key(&creation);
            assert!(objects.get_value(&proof_key).is_none());
            let peer_objects = objects.clone();
            let peer =
                Catalogue::new(objects.clone(), 1, 2, 20, crate::tests::test_options()).unwrap();
            let peer_control = control.clone();
            let peer_name = name_key.clone();
            let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let flag = ran.clone();
            objects.cut(
                false,
                &proof_key,
                None,
                0,
                Fault::Run(Arc::new(move || {
                    flag.store(true, std::sync::atomic::Ordering::Release);
                    peer_objects.cut(
                        true,
                        &peer_name,
                        Some(("state", "tombstone")),
                        0,
                        Fault::Before(StoreError::Unknown),
                    );
                    assert_eq!(
                        peer.abort_create(CREATOR, &peer_control, deadline()),
                        Err(CatalogueError::Unknown)
                    );
                })),
            );
            match operation {
                0 => assert_eq!(
                    catalog
                        .inspect_create_operation(CREATOR, creation.operation, deadline())
                        .unwrap()
                        .phase,
                    CreationPhase::Aborting
                ),
                1 => assert_eq!(
                    catalog
                        .resume_create(CREATOR, &creation, deadline())
                        .unwrap()
                        .phase,
                    CreationPhase::Aborting
                ),
                _ => assert_eq!(
                    catalog.resolve(CREATOR, &creation.name, deadline()),
                    Err(CatalogueError::NotFound)
                ),
            }
            assert!(ran.load(std::sync::atomic::Ordering::Acquire));
            let after = objects.get_value(&name_key).unwrap();
            assert_eq!(after.bytes, before.bytes);
            assert_eq!(after.etag, before.etag);
            assert_eq!(
                catalog
                    .database(&source)
                    .read_head(deadline())
                    .unwrap()
                    .head
                    .lifecycle,
                Lifecycle::Deleted
            );
            assert!(objects.get_value(&proof_key).is_some());
            assert_eq!(
                catalog
                    .abort_create(CREATOR, &control, deadline())
                    .unwrap()
                    .phase,
                AbortPhase::Aborted
            );
        }
    }
}

fn nonexistent_target(original: &Creation) -> Creation {
    Creation {
        creator: original.creator,
        operation: original.operation + 100,
        name: "never prepared".into(),
        scope: records::derive_scope(
            original.scope.deployment,
            original.scope.tenant,
            original.creator,
            original.operation + 100,
        )
        .unwrap(),
        expected_name_revision: None,
    }
}

#[test]
fn admitted_controls_check_original_target_before_reading_a_replacement_target() {
    for aborting in [true, false] {
        let (objects, catalog, creation) = stage(if aborting {
            CreationPhase::Reserved
        } else {
            CreationPhase::Ready
        });
        if aborting {
            let mut request = abort(&creation);
            request.expected_name_revision = 99;
            assert_eq!(
                catalog.abort_create(CREATOR, &request, deadline()),
                Err(CatalogueError::Conflict)
            );
            request.creation = nonexistent_target(&creation);
            objects.clear_calls();
            assert_eq!(
                catalog.abort_create(CREATOR, &request, deadline()),
                Err(CatalogueError::Conflict)
            );
        } else {
            let mut request = delete(&creation);
            request.expected_head_revision = 1;
            assert_eq!(
                catalog.delete(CREATOR, &request, deadline()),
                Err(CatalogueError::Conflict)
            );
            request.creation = nonexistent_target(&creation);
            objects.clear_calls();
            assert_eq!(
                catalog.delete(CREATOR, &request, deadline()),
                Err(CatalogueError::Conflict)
            );
        }
        let calls = objects.calls();
        assert_eq!(calls.len(), 1);
        assert!(!calls[0].put);
        assert!(calls[0].key.contains("/control/"));
    }
}

#[test]
fn concurrent_first_admissions_preserve_the_winning_fixed_control_intent() {
    for aborting in [true, false] {
        for during_put in [false, true] {
            let (objects, catalog, creation) = stage(if aborting {
                CreationPhase::Reserved
            } else {
                CreationPhase::Ready
            });
            let kind = if aborting {
                NamedDeletionKind::Abort
            } else {
                NamedDeletionKind::Delete
            };
            let operation = if aborting { 20 } else { 30 };
            let key = catalog.control_address(7, &kind, operation);
            let peer = catalogue(objects.clone());
            let target = creation.clone();
            objects.clear_calls();
            objects.cut(
                during_put,
                &key,
                None,
                usize::from(!during_put),
                Fault::Run(Arc::new(move || {
                    // Both workers passed an absent-control precheck. The
                    // peer now admits its different nonce but cannot advance
                    // the target because its original condition is stale.
                    if aborting {
                        let mut input = abort(&target);
                        input.expected_name_revision = 99;
                        input.nonce += 1;
                        assert_eq!(
                            peer.abort_create(CREATOR, &input, deadline()),
                            Err(CatalogueError::Conflict)
                        );
                    } else {
                        let mut input = delete(&target);
                        input.expected_head_revision = 1;
                        input.nonce += 1;
                        assert_eq!(
                            peer.delete(CREATOR, &input, deadline()),
                            Err(CatalogueError::Conflict)
                        );
                    }
                })),
            );
            if aborting {
                let mut input = abort(&creation);
                input.expected_name_revision = 99;
                assert_eq!(
                    catalog.abort_create(CREATOR, &input, deadline()),
                    Err(CatalogueError::Conflict)
                );
            } else {
                let mut input = delete(&creation);
                input.expected_head_revision = 1;
                assert_eq!(
                    catalog.delete(CREATOR, &input, deadline()),
                    Err(CatalogueError::Conflict)
                );
            }
            let stored = catalog.read::<Control>(&key, deadline()).unwrap().unwrap();
            assert_eq!(stored.body.nonce, if aborting { 22 } else { 32 });
            assert!(objects
                .calls()
                .iter()
                .filter(|call| call.put)
                .all(|call| call.key == key));
        }
    }
}

#[test]
fn unauthorized_delete_never_admits_a_new_control_and_reentry_checks_current_admin() {
    let (objects, catalog, creation) = stage(CreationPhase::Ready);
    let other = Caller {
        principal: 12,
        provision: true,
    };
    objects.clear_calls();
    assert_eq!(
        catalog.delete(other, &delete(&creation), deadline()),
        Err(CatalogueError::Denied)
    );
    assert!(objects.calls().iter().all(|call| !call.put));
    assert!(objects
        .get_value(&catalog.control_address(12, &NamedDeletionKind::Delete, 30))
        .is_none());

    let mut request = delete(&creation);
    request.expected_head_revision = 1;
    assert_eq!(
        catalog.delete(CREATOR, &request, deadline()),
        Err(CatalogueError::Conflict)
    );
    catalog
        .database(&descriptor(&catalog, &creation))
        .set_policy(
            CREATOR.principal,
            2,
            90,
            vec![
                Permission {
                    principal: CREATOR.principal,
                    read: true,
                    write: true,
                    admin: false,
                },
                Permission {
                    principal: other.principal,
                    read: true,
                    write: true,
                    admin: true,
                },
            ],
            deadline(),
        )
        .unwrap();
    objects.clear_calls();
    assert_eq!(
        catalog.delete(CREATOR, &request, deadline()),
        Err(CatalogueError::Denied)
    );
    assert!(objects.calls().iter().all(|call| !call.put));
}

#[test]
fn referenced_abort_proof_missing_is_corrupt_for_every_public_entry() {
    let (objects, catalog, creation) = stage(CreationPhase::Reserved);
    catalog
        .abort_create(CREATOR, &abort(&creation), deadline())
        .unwrap();
    objects.remove(&catalog.proof_key(&creation));
    objects.clear_calls();
    assert_eq!(
        catalog.resolve(CREATOR, &creation.name, deadline()),
        Err(CatalogueError::Corrupt)
    );
    assert_eq!(
        catalog.inspect_create_operation(CREATOR, creation.operation, deadline()),
        Err(CatalogueError::Corrupt)
    );
    assert_eq!(
        catalog.resume_create(CREATOR, &creation, deadline()),
        Err(CatalogueError::Corrupt)
    );
    assert_eq!(
        catalog.abort_create(CREATOR, &abort(&creation), deadline()),
        Err(CatalogueError::Corrupt)
    );
    assert_eq!(
        catalog.delete(CREATOR, &delete(&creation), deadline()),
        Err(CatalogueError::Corrupt)
    );
    assert!(objects.calls().iter().all(|call| !call.put));
}

#[test]
fn referenced_delete_control_is_not_recreated_from_a_retry_after_authority_loss() {
    for released in [false, true] {
        let (objects, catalog, creation) = stage(CreationPhase::Ready);
        let request = delete(&creation);
        if !released {
            objects.cut(
                true,
                &catalog.binding_key(&creation.name),
                Some(("state", "tombstone")),
                0,
                Fault::Before(StoreError::Unknown),
            );
            assert_eq!(
                catalog.delete(CREATOR, &request, deadline()),
                Err(CatalogueError::Unknown)
            );
        } else {
            catalog.delete(CREATOR, &request, deadline()).unwrap();
        }
        let key = catalog.control_address(
            CREATOR.principal,
            &NamedDeletionKind::Delete,
            request.operation,
        );
        objects.remove(&key);
        objects.clear_calls();
        assert_eq!(
            catalog.resolve(CREATOR, &creation.name, deadline()),
            Err(CatalogueError::Corrupt)
        );
        assert_eq!(
            catalog.inspect_create_operation(CREATOR, creation.operation, deadline()),
            Err(CatalogueError::Corrupt)
        );
        assert_eq!(
            catalog.resume_create(CREATOR, &creation, deadline()),
            Err(CatalogueError::Corrupt)
        );
        assert_eq!(
            catalog.delete(CREATOR, &request, deadline()),
            Err(CatalogueError::Corrupt)
        );
        assert!(objects.calls().iter().all(|call| !call.put));
        assert!(objects.get_value(&key).is_none());
    }
}

#[test]
fn resolving_deleting_name_checks_source_independently_of_original_creator_read() {
    let (objects, catalog, creation) = stage(CreationPhase::Ready);
    let reader = Caller {
        principal: 12,
        provision: false,
    };
    catalog
        .database(&descriptor(&catalog, &creation))
        .set_policy(
            CREATOR.principal,
            2,
            90,
            vec![
                Permission {
                    principal: CREATOR.principal,
                    read: false,
                    write: false,
                    admin: true,
                },
                Permission {
                    principal: reader.principal,
                    read: true,
                    write: false,
                    admin: false,
                },
            ],
            deadline(),
        )
        .unwrap();
    assert_eq!(
        catalog
            .resolve(reader, &creation.name, deadline())
            .unwrap()
            .creation,
        creation
    );
    let mut request = delete(&creation);
    request.expected_head_revision = 3;
    objects.cut(
        true,
        &catalog.binding_key(&creation.name),
        Some(("state", "tombstone")),
        0,
        Fault::Before(StoreError::Unknown),
    );
    assert_eq!(
        catalog.delete(CREATOR, &request, deadline()),
        Err(CatalogueError::Unknown)
    );
    assert_eq!(
        catalog.resolve(reader, &creation.name, deadline()),
        Err(CatalogueError::NotFound)
    );
    objects.remove(&catalog.control_address(
        CREATOR.principal,
        &NamedDeletionKind::Delete,
        request.operation,
    ));
    assert_eq!(
        catalog.resolve(reader, &creation.name, deadline()),
        Err(CatalogueError::Corrupt)
    );
}

#[test]
fn old_deleted_operation_rejects_a_different_name_binding_with_a_rolled_back_revision() {
    let (objects, catalog, creation) = stage(CreationPhase::Ready);
    let rival = catalog
        .prepare(CREATOR, &input(&creation.name, 2, None), deadline())
        .unwrap();
    catalog
        .delete(CREATOR, &delete(&creation), deadline())
        .unwrap();
    let source = descriptor(&catalog, &rival.creation);
    let rollback = Binding {
        format: 1,
        creation: rival.creation,
        origin: source.origin(),
        revision: 1,
        state: BindingState::Reserved,
        control: None,
        proof: None,
    };
    // Simulate lost/rolled-back authoritative name state with syntactically
    // valid records, so rejection must come from the cross-key relationship.
    objects.set(
        &catalog.binding_key(&creation.name),
        records::encode(&rollback).unwrap(),
    );
    assert_eq!(
        catalog.inspect_create_operation(CREATOR, creation.operation, deadline()),
        Err(CatalogueError::Corrupt)
    );
    assert_eq!(
        catalog.resume_create(CREATOR, &creation, deadline()),
        Err(CatalogueError::Corrupt)
    );
    assert_eq!(
        catalog.abort_create(CREATOR, &abort(&creation), deadline()),
        Err(CatalogueError::Corrupt)
    );
    assert_eq!(
        catalog.delete(CREATOR, &delete(&creation), deadline()),
        Err(CatalogueError::Corrupt)
    );
}

#[test]
fn canonical_source_keeps_validated_bytes_hash_and_shape_when_raw_clone_changes() {
    let (_, catalog, creation) = prepared();
    let source = descriptor(&catalog, &creation);
    let before = source.bytes().to_vec();
    let origin = source.origin();
    let mut changed = source.raw().clone();
    changed.creation.name = "different".into();
    let next = Canonical::new(changed).unwrap();
    assert_ne!(next.origin(), origin);
    assert_ne!(next.hash(), source.hash());
    assert_eq!(source.bytes(), before);
    assert_eq!(source.origin(), origin);
    assert_eq!(source.hash(), format::digest(&before));
    assert_eq!(source.shape(), &());
    assert_eq!(records::decode::<Descriptor>(&before).unwrap(), source);
}
