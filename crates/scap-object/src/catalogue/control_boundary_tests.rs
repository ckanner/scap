use super::*;
use crate::catalogue::tests::{
    abort, catalogue, deadline, delete, descriptor, input, stage, Fault, CREATOR,
};

fn admitted(catalog: &Catalogue, source: &Source, kind: NamedDeletionKind) -> Admitted {
    let aborting = kind == NamedDeletionKind::Abort;
    let record = Control {
        format: 1,
        creation: source.creation.clone(),
        origin: source.origin(),
        principal: CREATOR.principal,
        operation: if aborting { 20 } else { 30 },
        expected_name_revision: source.creation.expected_name_revision.unwrap_or(0)
            + if aborting { 1 } else { 2 },
        expected_head_revision: if aborting { None } else { Some(2) },
        kind,
        nonce: if aborting { 21 } else { 31 },
    };
    catalog
        .immutable(&catalog.control_key(&record), &record, deadline())
        .unwrap()
}

#[test]
fn observed_abort_steps_report_only_durably_accepted_cancellation() {
    for cut in 0..6 {
        let (objects, catalog, creation) = stage(if cut == 2 {
            CreationPhase::Provisioning
        } else {
            CreationPhase::Reserved
        });
        let source = descriptor(&catalog, &creation);
        let control = admitted(&catalog, &source, NamedDeletionKind::Abort);
        if cut > 0 {
            let (key, field) = match cut {
                1 | 2 => (
                    format::head_key(&creation.scope),
                    Some(("lifecycle", "deleted")),
                ),
                3 => (catalog.proof_key(&creation), None),
                _ => (
                    catalog.binding_key(&creation.name),
                    Some(("state", "tombstone")),
                ),
            };
            if cut != 5 {
                objects.cut(true, &key, field, 0, Fault::Before(StoreError::Unknown));
            }
            let result = catalog.abort_create(CREATOR, &abort(&creation), deadline());
            if cut == 5 {
                assert_eq!(result.unwrap().phase, AbortPhase::Aborted);
            } else {
                assert_eq!(result, Err(CatalogueError::Unknown));
            }
        }
        let view = catalog.view(&source, deadline()).unwrap();
        let step = catalog
            .abort_plan(&source, &control, &view, deadline())
            .unwrap();
        let result = Catalogue::abort_progress(&source, &control, &view, step);
        match cut {
            0 => assert_eq!(result, Err(CatalogueError::Conflict)),
            5 => assert_eq!(result.unwrap().phase, AbortPhase::Aborted),
            _ => assert_eq!(result.unwrap().phase, AbortPhase::Aborting),
        }
    }
}

#[test]
fn observed_delete_steps_do_not_report_success_before_name_release() {
    for stage_index in 0..4 {
        let (objects, catalog, creation) = stage(if stage_index == 0 {
            CreationPhase::Bound
        } else {
            CreationPhase::Ready
        });
        let source = descriptor(&catalog, &creation);
        let control = admitted(&catalog, &source, NamedDeletionKind::Delete);
        if stage_index > 1 {
            if stage_index == 2 {
                objects.cut(
                    true,
                    &catalog.binding_key(&creation.name),
                    Some(("state", "tombstone")),
                    0,
                    Fault::Before(StoreError::Unknown),
                );
                assert_eq!(
                    catalog.delete(CREATOR, &delete(&creation), deadline()),
                    Err(CatalogueError::Unknown)
                );
            } else {
                catalog
                    .delete(CREATOR, &delete(&creation), deadline())
                    .unwrap();
            }
        }
        let view = catalog.view(&source, deadline()).unwrap();
        let step = catalog.delete_plan(&source, &control, &view).unwrap();
        assert_eq!(
            step.phase(),
            match stage_index {
                0 | 1 => DeletionPhase::NotDeleted,
                2 => DeletionPhase::Deleting,
                _ => DeletionPhase::Deleted,
            }
        );
    }
}

#[test]
fn aborting_or_reused_names_never_accept_a_different_durable_control() {
    for reused in [false, true] {
        let (objects, catalog, creation) = stage(CreationPhase::Reserved);
        if !reused {
            objects.cut(
                true,
                &format::head_key(&creation.scope),
                Some(("lifecycle", "deleted")),
                0,
                Fault::Before(StoreError::Unknown),
            );
        }
        let original = catalog.abort_create(CREATOR, &abort(&creation), deadline());
        if reused {
            original.unwrap();
            let next = catalog
                .prepare(CREATOR, &input(&creation.name, 2, Some(3)), deadline())
                .unwrap();
            catalog
                .resume_create(CREATOR, &next.creation, deadline())
                .unwrap();
        } else {
            assert_eq!(original, Err(CatalogueError::Unknown));
        }
        let mut rival = abort(&creation);
        rival.operation += 1;
        rival.nonce += 1;
        assert_eq!(
            catalog.abort_create(CREATOR, &rival, deadline()),
            Err(CatalogueError::Conflict)
        );
    }
}

#[test]
fn a_losing_creation_cannot_abort_a_name_it_never_reserved() {
    let (_, catalog, creation) = stage(CreationPhase::Ready);
    let rival = catalog
        .prepare(CREATOR, &input(&creation.name, 2, None), deadline())
        .unwrap();
    assert_eq!(
        catalog
            .abort_create(CREATOR, &abort(&rival.creation), deadline())
            .unwrap()
            .phase,
        AbortPhase::NotReserved
    );
}

#[test]
fn delete_arithmetic_and_original_name_condition_fail_without_publication() {
    for overflow in 0..3 {
        let (objects, catalog, creation) = stage(CreationPhase::Ready);
        let mut request = delete(&creation);
        let mut head = catalog
            .read_slot(&creation.scope, deadline())
            .unwrap()
            .unwrap()
            .head;
        match overflow {
            0 => {
                head.revision = u64::MAX;
                head.head_serial = u64::MAX;
                head.transition.revision = u64::MAX;
                request.expected_head_revision = u64::MAX;
            }
            1 => head.owner_epoch = u64::MAX,
            _ => request.expected_name_revision = 99,
        }
        let bytes = format::encode_head(&head).unwrap();
        let key = format::head_key(&creation.scope);
        objects.set(&key, bytes.clone());
        assert_eq!(
            catalog.delete(CREATOR, &request, deadline()),
            Err(if overflow == 2 {
                CatalogueError::Conflict
            } else {
                CatalogueError::Limit
            })
        );
        assert_eq!(objects.get_value(&key).unwrap().bytes, bytes);
    }
}

#[test]
fn abort_fence_and_named_delete_advance_serial_without_rewriting_business_barriers() {
    for aborting in [false, true] {
        for serial in [40, u64::MAX] {
            let (objects, catalog, creation) = stage(if aborting {
                CreationPhase::Provisioning
            } else {
                CreationPhase::Ready
            });
            let key = format::head_key(&creation.scope);
            let mut head = catalog
                .read_slot(&creation.scope, deadline())
                .unwrap()
                .unwrap()
                .head;
            let original_revision = head.revision;
            head.head_serial = serial;
            let bytes = format::encode_head(&head).unwrap();
            objects.set(&key, bytes.clone());
            objects.clear_calls();
            let result = if aborting {
                catalog
                    .abort_create(CREATOR, &abort(&creation), deadline())
                    .map(|_| ())
            } else {
                catalog
                    .delete(CREATOR, &delete(&creation), deadline())
                    .map(|_| ())
            };
            if serial == u64::MAX {
                assert_eq!(result, Err(CatalogueError::Limit));
                assert_eq!(objects.get_value(&key).unwrap().bytes, bytes);
                assert!(objects
                    .calls()
                    .iter()
                    .all(|call| !call.put || call.key != key));
            } else {
                result.unwrap();
                let next = catalog
                    .read_slot(&creation.scope, deadline())
                    .unwrap()
                    .unwrap()
                    .head;
                assert_eq!(next.lifecycle, Lifecycle::Deleted);
                assert_eq!(
                    (next.revision, next.head_serial),
                    (original_revision + 1, 41)
                );
                assert_eq!(next.transition.revision, next.revision);
                if aborting {
                    assert_eq!(next.deletion.as_ref().unwrap().expected_head_revision, None);
                    assert_eq!(
                        catalog
                            .abort_create(CREATOR, &abort(&creation), deadline())
                            .unwrap()
                            .phase,
                        AbortPhase::Aborted
                    );
                } else {
                    assert_eq!(
                        next.deletion.as_ref().unwrap().expected_head_revision,
                        Some(original_revision)
                    );
                    assert_eq!(
                        catalog
                            .delete(CREATOR, &delete(&creation), deadline())
                            .unwrap()
                            .phase,
                        DeletionPhase::Deleted
                    );
                }
            }
        }
    }
    let (_, catalog, creation) = stage(CreationPhase::Reserved);
    catalog
        .abort_create(CREATOR, &abort(&creation), deadline())
        .unwrap();
    let fence = catalog
        .read_slot(&creation.scope, deadline())
        .unwrap()
        .unwrap()
        .head;
    assert_eq!((fence.revision, fence.head_serial), (1, 1));
}

#[test]
fn delete_planning_rejects_a_corrupt_cross_key_state_even_with_valid_current_admin() {
    for corruption in 0..4 {
        let (objects, catalog, creation) = stage(CreationPhase::Ready);
        let source = descriptor(&catalog, &creation);
        let mut control = admitted(&catalog, &source, NamedDeletionKind::Delete);
        if corruption >= 2 {
            objects.cut(
                true,
                &catalog.binding_key(&creation.name),
                Some(("state", "tombstone")),
                0,
                Fault::Before(StoreError::Unknown),
            );
            assert_eq!(
                catalog.delete(CREATOR, &delete(&creation), deadline()),
                Err(CatalogueError::Unknown)
            );
        }
        if corruption == 0 {
            let other = catalog
                .prepare(CREATOR, &input(&creation.name, 2, None), deadline())
                .unwrap();
            let other_source = descriptor(&catalog, &other.creation);
            let binding = Binding {
                format: 1,
                creation: other.creation,
                origin: other_source.origin(),
                revision: 1,
                state: BindingState::Reserved,
                control: None,
                proof: None,
            };
            objects.set(
                &catalog.binding_key(&creation.name),
                records::encode(&binding).unwrap(),
            );
        } else if corruption <= 2 {
            let mut binding = catalog
                .read_binding(&creation.name, deadline())
                .unwrap()
                .unwrap()
                .body
                .raw()
                .clone();
            binding.state = BindingState::Reserved;
            binding.revision = 1;
            objects.set(
                &catalog.binding_key(&creation.name),
                records::encode(&binding).unwrap(),
            );
        } else {
            let mut wrong = control.raw().clone();
            wrong.operation += 1;
            wrong.expected_name_revision = 99;
            control = catalog
                .immutable(&catalog.control_key(&wrong), &wrong, deadline())
                .unwrap();
            let mut head = catalog
                .read_slot(&creation.scope, deadline())
                .unwrap()
                .unwrap()
                .head;
            head.deletion = Some(control.mark());
            objects.set(
                &format::head_key(&creation.scope),
                format::encode_head(&head).unwrap(),
            );
        }
        let view = catalog.view(&source, deadline()).unwrap();
        assert!(matches!(
            catalog.delete_plan(&source, &control, &view),
            Err(CatalogueError::Corrupt)
        ));
    }
}

#[test]
fn final_progress_read_rejects_corruption_after_the_last_successful_cas() {
    for aborting in [false, true] {
        let (base, _, creation) = stage(if aborting {
            CreationPhase::Reserved
        } else {
            CreationPhase::Ready
        });
        let success = base.fork();
        let catalog = catalogue(success.clone());
        if aborting {
            catalog
                .abort_create(CREATOR, &abort(&creation), deadline())
                .unwrap();
        } else {
            catalog
                .delete(CREATOR, &delete(&creation), deadline())
                .unwrap();
        }
        let key = format::head_key(&creation.scope);
        let index = success
            .calls()
            .iter()
            .rposition(|call| !call.put && call.key == key)
            .unwrap()
            + 1;
        let mut corrupted = catalog
            .read_slot(&creation.scope, deadline())
            .unwrap()
            .unwrap()
            .head;
        corrupted.lifecycle = Lifecycle::Ready;
        corrupted.deletion = None;
        let bytes = format::encode_head(&corrupted).unwrap();
        let objects = base.fork();
        objects.fail_at(
            index,
            Fault::Replace {
                key,
                bytes,
                preserve_etag: false,
            },
        );
        let catalog = catalogue(objects);
        let result = if aborting {
            catalog
                .abort_create(CREATOR, &abort(&creation), deadline())
                .map(|_| ())
        } else {
            catalog
                .delete(CREATOR, &delete(&creation), deadline())
                .map(|_| ())
        };
        assert_eq!(result, Err(CatalogueError::Corrupt));
    }
}

#[test]
fn normal_deletion_does_not_restore_revoked_creator_read_on_bound_or_successor_names() {
    for released in [false, true] {
        let (objects, catalog, creation) = stage(CreationPhase::Ready);
        let source = descriptor(&catalog, &creation);
        let mut policy = catalog
            .database(&source)
            .status(7, deadline())
            .unwrap()
            .policy;
        policy[0].read = false;
        catalog
            .database(&source)
            .set_policy(7, 2, 90, policy, deadline())
            .unwrap();
        let mut request = delete(&creation);
        request.expected_head_revision = 3;
        if !released {
            objects.cut(
                true,
                &catalog.binding_key(&creation.name),
                Some(("state", "tombstone")),
                0,
                Fault::Before(StoreError::Unknown),
            );
        }
        let result = catalog.delete(CREATOR, &request, deadline());
        if released {
            result.unwrap();
            let next = catalog
                .prepare(CREATOR, &input(&creation.name, 2, Some(3)), deadline())
                .unwrap();
            catalog
                .resume_create(CREATOR, &next.creation, deadline())
                .unwrap();
        } else {
            assert_eq!(result, Err(CatalogueError::Unknown));
        }
        assert_eq!(
            catalog.abort_create(CREATOR, &abort(&creation), deadline()),
            Err(CatalogueError::Denied)
        );
        assert_eq!(
            catalog.inspect_create_operation(CREATOR, creation.operation, deadline()),
            Err(CatalogueError::Denied)
        );
    }
}
