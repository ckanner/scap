use super::*;
use crate::catalogue::tests::{
    abort, catalogue, deadline, delete, descriptor, input, stage, Fault, Memory, CREATOR,
};

fn pending_delete(phase: CreationPhase, has_proof: bool) -> (Arc<Memory>, Catalogue, Creation) {
    let (objects, cat, creation) = stage(phase.clone());
    let (key, field) = if phase != CreationPhase::Ready && !has_proof {
        (cat.proof_key(&creation), None)
    } else {
        (
            cat.binding_key(&creation.name),
            Some(("state", "tombstone")),
        )
    };
    objects.cut(true, &key, field, 0, Fault::Before(StoreError::Unknown));
    let result = if phase == CreationPhase::Ready {
        cat.delete(CREATOR, &delete(&creation), deadline())
            .map(|_| ())
    } else {
        cat.abort_create(CREATOR, &abort(&creation), deadline())
            .map(|_| ())
    };
    assert_eq!(result, Err(CatalogueError::Unknown));
    let head = cat.storage_status(CREATOR, &creation, deadline()).unwrap();
    assert_eq!(head.lifecycle, Lifecycle::Deleted);
    assert!(head.storage.terminal.is_none());
    (objects, cat, creation)
}

fn request(creation: &Creation, head: &Head) -> RetireNamedStorage {
    RetireNamedStorage {
        creation: creation.clone(),
        expected_head_serial: head.head_serial,
    }
}

fn remove_payload_and_install_checkpoint(objects: &Memory, sealed: &Head) -> Head {
    let mut head = sealed.clone();
    let generation = head.storage.active_generation;
    head.head_serial += 1;
    let key = format::object_key(&head.scope, generation, &head.data_root);
    objects.remove(&key);
    for window in &head.windows {
        objects.remove(&format::object_key(&head.scope, generation, &window.root));
    }
    head.storage.sweep = Some(format::SweepCheckpoint {
        serial: head.head_serial,
        generation,
        next_after: None,
        exhausted: true,
        entries: vec![format::SweepEntry {
            key,
            hash: head.data_root.clone(),
            etag: "\"original-payload\"".into(),
            disposition: format::SweepDisposition::Pending,
        }],
    });
    objects.set(
        &format::head_key(&head.scope),
        format::encode_head(&head).unwrap(),
    );
    head
}

#[test]
fn terminal_named_seal_preserves_every_original_delete_or_abort_barrier() {
    for phase in [
        CreationPhase::Ready,
        CreationPhase::Reserved,
        CreationPhase::Provisioning,
    ] {
        for has_proof in [false, true] {
            let (objects, cat, creation) = pending_delete(phase.clone(), has_proof);
            let deleted = cat.storage_status(CREATOR, &creation, deadline()).unwrap();
            let source = descriptor(&cat, &creation);
            let db = cat.database(&source);
            assert!(matches!(
                db.storage_status(7, deadline()),
                Err(Error::Lifecycle)
            ));
            assert!(matches!(
                db.retire_storage(7, deleted.head_serial, deadline()),
                Err(Error::Lifecycle)
            ));
            let proof_before = objects.get_value(&cat.proof_key(&creation));
            objects.clear_calls();
            let sealed = cat
                .retire_storage(CREATOR, &request(&creation, &deleted), deadline())
                .unwrap();
            let calls = objects.calls();
            assert!(calls.iter().all(|call| !call.key.contains("/objects/")));
            assert_eq!(calls.iter().filter(|call| call.put).count(), 1);
            assert_eq!(sealed.revision, deleted.revision);
            assert_eq!(sealed.transition, deleted.transition);
            assert_eq!(sealed.deletion, deleted.deletion);
            assert_eq!(sealed.creation, deleted.creation);
            assert_eq!(objects.get_value(&cat.proof_key(&creation)), proof_before);
            let checkpoint = remove_payload_and_install_checkpoint(&objects, &sealed);
            objects.clear_calls();
            if phase == CreationPhase::Ready {
                assert_eq!(
                    cat.delete(CREATOR, &delete(&creation), deadline())
                        .unwrap()
                        .phase,
                    DeletionPhase::Deleted
                );
            } else {
                assert_eq!(
                    cat.abort_create(CREATOR, &abort(&creation), deadline())
                        .unwrap()
                        .phase,
                    AbortPhase::Aborted
                );
                let proof = cat.read_proof(&source, deadline()).unwrap().unwrap();
                assert_eq!(
                    proof.body.barrier,
                    Barrier::OwnDeleted {
                        transition: deleted.transition.clone()
                    }
                );
            }
            assert_eq!(
                cat.storage_status(CREATOR, &creation, deadline()).unwrap(),
                checkpoint
            );
            assert!(objects
                .calls()
                .iter()
                .all(|call| !call.key.contains("/objects/")));
            assert!(objects
                .calls()
                .iter()
                .filter(|call| call.put)
                .all(|call| call.key != format::head_key(&creation.scope)));
        }
    }
}

#[test]
fn terminal_named_admission_uses_current_admin_without_creator_read_or_provision() {
    let (objects, cat, creation) = stage(CreationPhase::Ready);
    let source = descriptor(&cat, &creation);
    let db = cat.database(&source);
    let policy = vec![7, 9]
        .into_iter()
        .map(|principal| Permission {
            principal,
            read: false,
            write: false,
            admin: true,
        })
        .collect();
    let updated = db.set_policy(7, 2, 40, policy, deadline()).unwrap();
    let mut original = delete(&creation);
    original.expected_head_revision = updated.revision;
    cat.delete(CREATOR, &original, deadline()).unwrap();
    let caller = Caller {
        principal: 9,
        provision: false,
    };
    let deleted = cat.storage_status(caller, &creation, deadline()).unwrap();
    let sealed = cat
        .retire_storage(caller, &request(&creation, &deleted), deadline())
        .unwrap();
    assert_eq!(sealed.policy, deleted.policy);
    assert_eq!(
        sealed.deletion.as_ref().unwrap().principal,
        CREATOR.principal
    );
    assert_eq!(
        cat.delete(
            Caller {
                principal: 7,
                provision: false
            },
            &original,
            deadline()
        )
        .unwrap()
        .phase,
        DeletionPhase::Deleted
    );
    assert_eq!(
        cat.storage_status(caller, &creation, deadline()).unwrap(),
        sealed
    );
    let denied = Caller {
        principal: 8,
        provision: true,
    };
    assert_eq!(
        cat.storage_status(denied, &creation, deadline()),
        Err(CatalogueError::Denied)
    );
    assert_eq!(
        cat.retire_storage(denied, &request(&creation, &sealed), deadline()),
        Err(CatalogueError::Denied)
    );
    let mut changed = original;
    changed.nonce += 1;
    assert_eq!(
        cat.delete(CREATOR, &changed, deadline()),
        Err(CatalogueError::Conflict)
    );
    assert!(objects
        .get_value(&format::head_key(&creation.scope))
        .is_some());
}

#[test]
fn terminal_named_reused_name_keeps_old_control_and_new_scope_independent() {
    for aborting in [false, true] {
        let (objects, cat, creation) = pending_delete(
            if aborting {
                CreationPhase::Reserved
            } else {
                CreationPhase::Ready
            },
            true,
        );
        if aborting {
            cat.abort_create(CREATOR, &abort(&creation), deadline())
                .unwrap();
        } else {
            cat.delete(CREATOR, &delete(&creation), deadline()).unwrap();
        }
        let successor = cat
            .prepare(CREATOR, &input(&creation.name, 2, Some(3)), deadline())
            .unwrap()
            .creation;
        cat.resume_create(CREATOR, &successor, deadline()).unwrap();
        let next_key = format::head_key(&successor.scope);
        let next_before = objects.get_value(&next_key).unwrap();
        let name_before = objects.get_value(&cat.binding_key(&creation.name)).unwrap();
        let old = cat.storage_status(CREATOR, &creation, deadline()).unwrap();
        let sealed = cat
            .retire_storage(CREATOR, &request(&creation, &old), deadline())
            .unwrap();
        let checkpoint = remove_payload_and_install_checkpoint(&objects, &sealed);
        if aborting {
            assert_eq!(
                cat.abort_create(CREATOR, &abort(&creation), deadline())
                    .unwrap()
                    .phase,
                AbortPhase::Aborted
            );
        } else {
            assert_eq!(
                cat.delete(CREATOR, &delete(&creation), deadline())
                    .unwrap()
                    .phase,
                DeletionPhase::Deleted
            );
        }
        assert_eq!(
            cat.storage_status(CREATOR, &creation, deadline()).unwrap(),
            checkpoint
        );
        assert_eq!(objects.get_value(&next_key).unwrap(), next_before);
        assert_eq!(
            objects.get_value(&cat.binding_key(&creation.name)).unwrap(),
            name_before
        );
        assert_eq!(
            cat.resolve(CREATOR, &creation.name, deadline())
                .unwrap()
                .creation,
            successor
        );
    }
}

#[test]
fn terminal_named_missing_real_sources_are_never_recreated_from_head_marks() {
    for missing in 0..5 {
        let (objects, cat, creation) = pending_delete(CreationPhase::Reserved, true);
        cat.abort_create(CREATOR, &abort(&creation), deadline())
            .unwrap();
        let deleted = cat.storage_status(CREATOR, &creation, deadline()).unwrap();
        let key = match missing {
            0 => cat.descriptor_key(creation.creator, creation.operation),
            1 => cat.control_address(CREATOR.principal, &NamedDeletionKind::Abort, 20),
            2 => cat.proof_key(&creation),
            3 => format::head_key(&creation.scope),
            _ => cat.binding_key(&creation.name),
        };
        objects.remove(&key);
        objects.clear_calls();
        assert_eq!(
            cat.storage_status(CREATOR, &creation, deadline()),
            Err(CatalogueError::Corrupt),
            "missing {missing}"
        );
        assert_eq!(
            cat.retire_storage(CREATOR, &request(&creation, &deleted), deadline()),
            Err(CatalogueError::Corrupt),
            "missing {missing}"
        );
        assert!(objects.calls().iter().all(|call| !call.put));
        assert!(objects.get_value(&key).is_none());
    }
    // A normal Delete has no AbortProof; its immutable Control is still required.
    let (objects, cat, creation) = pending_delete(CreationPhase::Ready, false);
    let deleted = cat.storage_status(CREATOR, &creation, deadline()).unwrap();
    objects.remove(&cat.control_address(CREATOR.principal, &NamedDeletionKind::Delete, 30));
    objects.clear_calls();
    assert_eq!(
        cat.retire_storage(CREATOR, &request(&creation, &deleted), deadline()),
        Err(CatalogueError::Corrupt)
    );
    assert!(objects.calls().iter().all(|call| !call.put));
}

#[test]
fn terminal_named_foreign_occupancy_never_retires_another_origin_but_abort_completes() {
    let (objects, cat, creation) = stage(CreationPhase::Reserved);
    let foreign = Database::with_options(
        objects.clone(),
        creation.scope.clone(),
        20,
        crate::tests::test_options(),
    )
    .unwrap();
    let head = foreign.create(90, 1, deadline()).unwrap();
    let key = format::head_key(&creation.scope);
    let original = objects.get_value(&key).unwrap();
    objects.cut(
        true,
        &cat.binding_key(&creation.name),
        Some(("state", "tombstone")),
        0,
        Fault::Before(StoreError::Unknown),
    );
    assert_eq!(
        cat.abort_create(CREATOR, &abort(&creation), deadline()),
        Err(CatalogueError::Unknown)
    );
    assert_eq!(
        cat.storage_status(CREATOR, &creation, deadline()),
        Err(CatalogueError::IdentityConflict)
    );
    assert_eq!(
        cat.retire_storage(CREATOR, &request(&creation, &head), deadline()),
        Err(CatalogueError::IdentityConflict)
    );
    assert_eq!(
        cat.abort_create(CREATOR, &abort(&creation), deadline())
            .unwrap()
            .phase,
        AbortPhase::Aborted
    );
    assert_eq!(
        cat.storage_status(CREATOR, &creation, deadline()),
        Err(CatalogueError::IdentityConflict)
    );
    assert_eq!(objects.get_value(&key).unwrap(), original);
    assert_eq!(foreign.status(90, deadline()).unwrap(), head);
}

#[test]
fn terminal_named_exact_name_double_read_rejects_a_concurrent_release() {
    let (objects, cat, creation) = pending_delete(CreationPhase::Ready, false);
    let deleted = cat.storage_status(CREATOR, &creation, deadline()).unwrap();
    let peer = catalogue(objects.clone());
    let target = creation.clone();
    objects.cut(
        false,
        &cat.binding_key(&creation.name),
        None,
        1,
        Fault::Run(Arc::new(move || {
            peer.delete(CREATOR, &delete(&target), deadline()).unwrap();
        })),
    );
    objects.clear_calls();
    assert_eq!(
        cat.retire_storage(CREATOR, &request(&creation, &deleted), deadline()),
        Err(CatalogueError::Conflict)
    );
    assert!(objects
        .calls()
        .iter()
        .all(|call| !call.put || call.key != format::head_key(&creation.scope)));
    assert!(cat
        .storage_status(CREATOR, &creation, deadline())
        .unwrap()
        .storage
        .terminal
        .is_none());
    cat.retire_storage(CREATOR, &request(&creation, &deleted), deadline())
        .unwrap();
}

#[test]
fn terminal_named_every_unknown_stops_at_its_original_io_and_does_not_resolve_the_call() {
    let (base, cat, creation) = pending_delete(CreationPhase::Ready, false);
    let deleted = cat.storage_status(CREATOR, &creation, deadline()).unwrap();
    let input = request(&creation, &deleted);
    let successful = base.fork();
    catalogue(successful.clone())
        .retire_storage(CREATOR, &input, deadline())
        .unwrap();
    for (offset, call) in successful.calls().iter().enumerate() {
        for after in [false, true] {
            if after && !call.put {
                continue;
            }
            let objects = base.fork();
            let cat = catalogue(objects.clone());
            objects.fail_at(
                offset + 1,
                if after {
                    Fault::AfterPut
                } else {
                    Fault::Before(StoreError::Unknown)
                },
            );
            assert_eq!(
                cat.retire_storage(CREATOR, &input, deadline()),
                Err(CatalogueError::Unknown),
                "offset {offset}, after {after}"
            );
            assert_eq!(objects.calls().len(), offset + 1);
            let observed = cat.storage_status(CREATOR, &creation, deadline()).unwrap();
            assert_eq!(observed.storage.terminal.is_some(), after);
            if after {
                assert_eq!(
                    cat.retire_storage(CREATOR, &input, deadline()),
                    Err(CatalogueError::Conflict)
                );
                assert_eq!(
                    cat.retire_storage(CREATOR, &request(&creation, &observed), deadline()),
                    Err(CatalogueError::Conflict)
                );
            }
        }
    }
    let observed = base.fork();
    catalogue(observed.clone())
        .storage_status(CREATOR, &creation, deadline())
        .unwrap();
    for offset in 1..=observed.calls().len() {
        let objects = base.fork();
        objects.fail_at(offset, Fault::Before(StoreError::Unknown));
        assert_eq!(
            catalogue(objects.clone()).storage_status(CREATOR, &creation, deadline()),
            Err(CatalogueError::Unknown)
        );
        assert_eq!(objects.calls().len(), offset);
    }
}

#[test]
fn terminal_named_inputs_and_lifecycle_fail_before_seal() {
    let (objects, cat, creation) = stage(CreationPhase::Ready);
    let head = cat
        .read_slot(&creation.scope, deadline())
        .unwrap()
        .unwrap()
        .head;
    let input = request(&creation, &head);
    assert_eq!(
        cat.storage_status(CREATOR, &creation, deadline()),
        Err(CatalogueError::Conflict)
    );
    assert_eq!(
        cat.retire_storage(CREATOR, &input, deadline()),
        Err(CatalogueError::Conflict)
    );
    objects.clear_calls();
    let caller = Caller {
        principal: 0,
        provision: true,
    };
    assert_eq!(
        cat.storage_status(caller, &creation, deadline()),
        Err(CatalogueError::Invalid)
    );
    assert_eq!(
        cat.retire_storage(caller, &input, deadline()),
        Err(CatalogueError::Invalid)
    );
    let mut wrong = input.clone();
    wrong.expected_head_serial = 0;
    assert_eq!(
        cat.retire_storage(CREATOR, &wrong, deadline()),
        Err(CatalogueError::Invalid)
    );
    wrong = input;
    wrong.creation.scope.tenant += 1;
    assert_eq!(
        cat.storage_status(CREATOR, &wrong.creation, deadline()),
        Err(CatalogueError::Invalid)
    );
    assert_eq!(
        cat.retire_storage(CREATOR, &wrong, deadline()),
        Err(CatalogueError::Invalid)
    );
    assert!(objects.calls().is_empty());
}
