use super::*;
use crate::catalogue::tests::{
    abort, catalogue, deadline, delete, descriptor, input, prepared, stage, Fault, Memory, CREATOR,
};

fn fixture(case: usize) -> (Arc<Memory>, Catalogue, Vec<Creation>) {
    let (objects, cat, creation) = match case {
        0 | 13 => prepared(),
        1 | 6 | 8 | 11 => stage(CreationPhase::Reserved),
        2 => stage(CreationPhase::Provisioning),
        3 => stage(CreationPhase::Bound),
        _ => stage(CreationPhase::Ready),
    };
    let mut creations = vec![creation.clone()];
    match case {
        5 => {
            let key = format::head_key(&creation.scope);
            let mut head =
                format::decode_head(&objects.get_value(&key).unwrap().bytes, &creation.scope)
                    .unwrap();
            head.lifecycle = Lifecycle::Maintenance;
            head.policy[0].read = false;
            objects.set(&key, format::encode_head(&head).unwrap());
        }
        6 | 8 | 11 => {
            if case == 11 {
                objects.cut(
                    true,
                    &cat.proof_key(&creation),
                    None,
                    0,
                    Fault::Before(StoreError::Unknown),
                );
            }
            let result = cat.abort_create(CREATOR, &abort(&creation), deadline());
            if case == 11 {
                assert_eq!(result, Err(CatalogueError::Unknown));
                let mut losing = abort(&creation);
                losing.operation += 1;
                assert_eq!(
                    cat.abort_create(CREATOR, &losing, deadline()),
                    Err(CatalogueError::Conflict)
                );
            } else {
                result.unwrap();
                let mut losing = abort(&creation);
                losing.operation += 1;
                assert_eq!(
                    cat.abort_create(CREATOR, &losing, deadline()),
                    Err(CatalogueError::Conflict)
                );
            }
        }
        7 | 9 | 10 | 12 => {
            if case == 10 {
                objects.cut(
                    true,
                    &cat.binding_key(&creation.name),
                    Some(("state", "tombstone")),
                    0,
                    Fault::Before(StoreError::Unknown),
                );
            }
            let result = cat.delete(CREATOR, &delete(&creation), deadline());
            if case == 10 {
                assert_eq!(result, Err(CatalogueError::Unknown));
            } else {
                result.unwrap();
            }
        }
        13 => {
            assert_eq!(
                cat.abort_create(CREATOR, &abort(&creation), deadline())
                    .unwrap()
                    .phase,
                AbortPhase::NotReserved
            );
        }
        14 => {
            let mut losing = delete(&creation);
            losing.expected_head_revision += 1;
            assert_eq!(
                cat.delete(CREATOR, &losing, deadline()),
                Err(CatalogueError::Conflict)
            );
        }
        _ => {}
    }
    if matches!(case, 8 | 9 | 12) {
        let next = cat
            .prepare(CREATOR, &input(&creation.name, 2, Some(3)), deadline())
            .unwrap()
            .creation;
        if case != 12 {
            cat.resume_create(CREATOR, &next, deadline()).unwrap();
        }
        creations.push(next);
    }
    (objects, cat, creations)
}

fn candidates(
    cat: &Catalogue,
    objects: &Memory,
    creations: &[Creation],
) -> Vec<(Phase, ListEntry)> {
    let mut values = std::collections::BTreeMap::new();
    for creation in creations {
        for (phase, key) in [
            (Phase::Names, cat.binding_key(&creation.name)),
            (
                Phase::Creates,
                cat.descriptor_key(creation.creator, creation.operation),
            ),
            (Phase::Proofs, cat.proof_key(creation)),
        ] {
            if objects.get_value(&key).is_some() {
                values.insert(key, phase);
            }
        }
        if objects
            .get_value(&format::head_key(&creation.scope))
            .is_some()
        {
            values.insert(
                format!("scap-object/v1/1/2/{}/", creation.scope.database),
                Phase::Slots,
            );
        }
    }
    for (kind, operation) in [
        (NamedDeletionKind::Abort, 20),
        (NamedDeletionKind::Abort, 21),
        (NamedDeletionKind::Delete, 30),
    ] {
        let key = cat.control_address(CREATOR.principal, &kind, operation);
        if objects.get_value(&key).is_some() {
            values.insert(key, Phase::Controls);
        }
    }
    values
        .into_iter()
        .map(|(key, phase)| {
            let kind = if phase == Phase::Slots {
                ListKind::Prefix
            } else {
                ListKind::Object
            };
            (phase, ListEntry { key, kind })
        })
        .collect()
}

#[test]
fn every_metadata_read_is_required_and_control_conditions_are_the_original_bytes() {
    for case in 0..=14 {
        let (base, cat, creations) = fixture(case);
        for (phase, entry) in candidates(&cat, &base, &creations) {
            let objects = base.fork();
            let cat = catalogue(objects.clone());
            let record = cat
                .discover_record(phase, &entry, deadline())
                .unwrap()
                .unwrap();
            let calls = objects.calls();
            assert!(calls.iter().all(|call| !call.put));
            if phase == Phase::Controls {
                let control: Control =
                    serde_json::from_slice(&base.get_value(&entry.key).unwrap().bytes).unwrap();
                assert_eq!(record.creation, Some(control.creation));
                assert_eq!(
                    record.control,
                    Some(ObservedControl {
                        kind: control.kind,
                        principal: control.principal,
                        operation: control.operation,
                        expected_name_revision: control.expected_name_revision,
                        expected_head_revision: control.expected_head_revision,
                        nonce: control.nonce,
                    })
                );
            } else {
                assert!(record.control.is_none());
            }
            for at in 1..=calls.len() {
                let objects = base.fork();
                let cat = catalogue(objects.clone());
                objects.fail_at(at, Fault::Before(StoreError::Unknown));
                assert_eq!(
                    cat.discover_record(phase, &entry, deadline()),
                    Err(DiscoveryError::Unknown),
                    "case {case}, phase {phase:?}, read {at}"
                );
                assert!(objects.calls().iter().all(|call| !call.put));
            }
            if phase == Phase::Names {
                let objects = base.fork();
                let cat = catalogue(objects.clone());
                cat.visible_candidate(CREATOR, &entry, deadline()).ok();
                for at in 1..=objects.calls().len() {
                    let objects = base.fork();
                    let cat = catalogue(objects.clone());
                    objects.fail_at(at, Fault::Before(StoreError::Unknown));
                    assert_eq!(
                        cat.visible_candidate(CREATOR, &entry, deadline()),
                        Err(DiscoveryError::Unknown),
                        "visible case {case}, read {at}"
                    );
                }
            }
        }
    }
}

#[test]
fn immutable_candidate_changes_and_missing_proof_are_not_accepted() {
    let (base, cat, creations) = fixture(6);
    let creation = &creations[0];
    let key = cat.proof_key(creation);
    let entry = ListEntry {
        key: key.clone(),
        kind: ListKind::Object,
    };
    for fault in [
        Fault::Before(StoreError::Missing),
        Fault::Replace {
            key: key.clone(),
            bytes: base.get_value(&key).unwrap().bytes,
            preserve_etag: false,
        },
    ] {
        let objects = base.fork();
        let cat = catalogue(objects.clone());
        let skip = usize::from(matches!(fault, Fault::Replace { .. }));
        objects.cut(false, &key, None, skip, fault);
        assert_eq!(
            cat.discover_record(Phase::Proofs, &entry, deadline()),
            Err(DiscoveryError::Corrupt)
        );
    }
    let key = cat.control_address(7, &NamedDeletionKind::Abort, 20);
    let objects = base.fork();
    objects.remove(&key);
    assert_eq!(
        catalogue(objects).discover_record(
            Phase::Controls,
            &ListEntry {
                key,
                kind: ListKind::Object
            },
            deadline()
        ),
        Err(DiscoveryError::Corrupt)
    );
}

#[test]
fn metadata_reuse_checks_terminal_barriers_without_using_creator_read() {
    let (objects, cat, creations) = fixture(12);
    let original = &creations[0];
    let source = descriptor(&cat, &creations[1]);
    let view = cat.view(&source, deadline()).unwrap();
    assert_eq!(
        cat.metadata_state(&source, &view, deadline()).unwrap(),
        MetadataState::DescriptorOnly
    );
    assert_eq!(
        reuse_state(original.scope.database, view.binding.as_ref().unwrap()),
        MetadataState::IdentityConflict
    );
    let mut wrong_revision = source.raw().clone();
    wrong_revision.creation.expected_name_revision = Some(6);
    let wrong_revision = Canonical::new(wrong_revision).unwrap();
    assert_eq!(
        cat.metadata_state(&wrong_revision, &view, deadline())
            .unwrap(),
        MetadataState::NameConflict
    );
    let key = format::head_key(&original.scope);
    let mut head =
        format::decode_head(&objects.get_value(&key).unwrap().bytes, &original.scope).unwrap();
    head.policy[0].read = false;
    objects.set(&key, format::encode_head(&head).unwrap());
    let old = descriptor(&cat, original);
    assert_eq!(
        cat.metadata_state(&old, &cat.view(&old, deadline()).unwrap(), deadline())
            .unwrap(),
        MetadataState::Deleted
    );
}

fn proof() -> Proof {
    let (_, cat, creations) = fixture(6);
    let source = descriptor(&cat, &creations[0]);
    cat.view(&source, deadline()).unwrap().proof.unwrap()
}

#[test]
fn typed_classification_rejects_missing_barriers_and_incompatible_stable_facts() {
    for phase in [CreationPhase::Provisioning, CreationPhase::Bound] {
        let (_, cat, creation) = stage(phase);
        let source = descriptor(&cat, &creation);
        let mut view = cat.view(&source, deadline()).unwrap();
        view.binding = None;
        assert_eq!(
            cat.metadata_state(&source, &view, deadline()),
            Err(CatalogueError::Corrupt)
        );
        view.head = None;
        view.proof = Some(proof());
        assert_eq!(
            cat.metadata_state(&source, &view, deadline()),
            Err(CatalogueError::Corrupt)
        );
        let mut view = cat.view(&source, deadline()).unwrap();
        view.proof = Some(proof());
        assert_eq!(
            cat.metadata_state(&source, &view, deadline()),
            Err(CatalogueError::Corrupt)
        );
        let mut view = cat.view(&source, deadline()).unwrap();
        view.head.as_mut().unwrap().head.policy[0].write = false;
        assert_eq!(
            cat.metadata_state(&source, &view, deadline()),
            Err(CatalogueError::Corrupt)
        );
    }
    let (_, cat, creation) = stage(CreationPhase::Bound);
    let source = descriptor(&cat, &creation);
    let mut view = cat.view(&source, deadline()).unwrap();
    view.head = None;
    assert_eq!(
        cat.metadata_state(&source, &view, deadline()),
        Err(CatalogueError::Corrupt)
    );

    for case in [6, 7, 11] {
        let (_, cat, creations) = fixture(case);
        let source = descriptor(&cat, &creations[0]);
        let mut view = cat.view(&source, deadline()).unwrap();
        if case == 11 {
            let (_, ready, creation) = stage(CreationPhase::Ready);
            view.head = ready.read_slot(&creation.scope, deadline()).unwrap();
        } else {
            view.head = None;
        }
        assert_eq!(
            cat.metadata_state(&source, &view, deadline()),
            Err(CatalogueError::Corrupt)
        );
    }
    for case in [8, 9] {
        let (_, cat, creations) = fixture(case);
        let source = descriptor(&cat, &creations[0]);
        let mut view = cat.view(&source, deadline()).unwrap();
        let (_, old, old_creations) = fixture(if case == 8 { 6 } else { 7 });
        let older = old
            .read_binding(&old_creations[0].name, deadline())
            .unwrap()
            .unwrap();
        assert_eq!(
            cat.metadata_other(&source, &view, &older, view.head.as_ref(), deadline()),
            Err(CatalogueError::Corrupt)
        );
        if case == 8 {
            let head = view.head.take();
            assert_eq!(
                cat.metadata_state(&source, &view, deadline()),
                Err(CatalogueError::Corrupt)
            );
            view.head = head;
            view.head.as_mut().unwrap().head.lifecycle = Lifecycle::Ready;
            assert_eq!(
                cat.metadata_state(&source, &view, deadline()),
                Err(CatalogueError::Corrupt)
            );
        }
    }
    let (_, cat, creation) = stage(CreationPhase::Ready);
    let competing = cat
        .prepare(CREATOR, &input(&creation.name, 2, None), deadline())
        .unwrap()
        .creation;
    let source = descriptor(&cat, &competing);
    let view = cat.view(&source, deadline()).unwrap();
    assert_eq!(
        cat.metadata_state(&source, &view, deadline()).unwrap(),
        MetadataState::NameConflict
    );
}

#[test]
fn exact_candidate_source_and_physical_slot_are_checked_before_classification() {
    let (base, cat, creation) = stage(CreationPhase::Ready);
    let name = cat.binding_key(&creation.name);
    let control_input = abort(&creation);
    cat.abort_create(CREATOR, &control_input, deadline())
        .unwrap();
    let control = cat.control_address(7, &NamedDeletionKind::Abort, 20);
    for (phase, key) in [(Phase::Names, name.clone()), (Phase::Controls, control)] {
        let objects = base.fork();
        let mut value: serde_json::Value =
            serde_json::from_slice(&objects.get_value(&key).unwrap().bytes).unwrap();
        value["origin"]["descriptor_hash"] = format::digest(b"different-source").into();
        let bytes = if phase == Phase::Names {
            records::encode(&serde_json::from_value::<Binding>(value).unwrap()).unwrap()
        } else {
            records::encode(&serde_json::from_value::<Control>(value).unwrap()).unwrap()
        };
        objects.set(&key, bytes);
        assert_eq!(
            catalogue(objects).discover_record(
                phase,
                &ListEntry {
                    key,
                    kind: ListKind::Object
                },
                deadline()
            ),
            Err(DiscoveryError::Corrupt)
        );
    }
    for (phase, key) in [
        (Phase::Creates, format!("{}/create/7/00", cat.prefix())),
        (Phase::Proofs, format!("{}/abort-proof/7/0", cat.prefix())),
        (Phase::Slots, "scap-object/v1/1/2/00/".into()),
    ] {
        assert_eq!(
            cat.discover_record(
                phase,
                &ListEntry {
                    key,
                    kind: if phase == Phase::Slots {
                        ListKind::Prefix
                    } else {
                        ListKind::Object
                    }
                },
                deadline()
            ),
            Err(DiscoveryError::Corrupt)
        );
    }
    let key = format::head_key(&creation.scope);
    let slot = ListEntry {
        key: key.trim_end_matches("head").into(),
        kind: ListKind::Prefix,
    };
    for change_scope in [false, true] {
        let objects = base.fork();
        let mut head =
            format::decode_head(&objects.get_value(&key).unwrap().bytes, &creation.scope).unwrap();
        if change_scope {
            head.scope.incarnation += 1;
        } else {
            head.creation.as_mut().unwrap().descriptor_hash = format::digest(b"different-source");
        }
        objects.set(&key, format::encode_head(&head).unwrap());
        assert_eq!(
            catalogue(objects).discover_record(Phase::Slots, &slot, deadline()),
            Err(DiscoveryError::Corrupt)
        );
    }
    let objects = base.fork();
    let removed = objects.clone();
    let target = name.clone();
    objects.cut(
        false,
        &name,
        None,
        1,
        Fault::Run(Arc::new(move || removed.remove(&target))),
    );
    assert_eq!(
        catalogue(objects).discover_record(
            Phase::Names,
            &ListEntry {
                key: name,
                kind: ListKind::Object
            },
            deadline()
        ),
        Err(DiscoveryError::Corrupt)
    );
}

#[test]
fn slot_candidate_never_substitutes_a_disappeared_or_foreign_head() {
    let (base, cat, creation) = stage(CreationPhase::Provisioning);
    let key = format::head_key(&creation.scope);
    let slot = ListEntry {
        key: key.trim_end_matches("head").into(),
        kind: ListKind::Prefix,
    };
    let foreign_objects = Arc::new(Memory::default());
    let mut foreign_scope = creation.scope.clone();
    foreign_scope.incarnation += 1;
    Database::new(foreign_objects.clone(), foreign_scope, 10)
        .unwrap()
        .create(7, 8, deadline())
        .unwrap();
    let foreign_bytes = foreign_objects.get_value(&key).unwrap().bytes;
    for foreign in [false, true] {
        let objects = base.fork();
        let changed = objects.clone();
        let target = key.clone();
        let bytes = foreign_bytes.clone();
        objects.cut(
            false,
            &key,
            None,
            1,
            Fault::Run(Arc::new(move || {
                if foreign {
                    changed.set(&target, bytes.clone());
                } else {
                    changed.remove(&target);
                }
            })),
        );
        assert_eq!(
            catalogue(objects).discover_record(Phase::Slots, &slot, deadline()),
            Err(DiscoveryError::Corrupt)
        );
    }
    // A valid immutable control descriptor is only an admission. It cannot
    // claim an accepted deletion of a different permanent physical identity.
    let source = descriptor(&cat, &creation);
    let control = Control {
        format: 1,
        creation,
        origin: source.origin(),
        kind: NamedDeletionKind::Delete,
        principal: 7,
        operation: 30,
        expected_name_revision: 2,
        expected_head_revision: Some(1),
        nonce: 31,
    };
    let control_key = cat.control_key(&control);
    base.set(&control_key, records::encode(&control).unwrap());
    base.set(&key, foreign_bytes);
    let record = cat
        .discover_record(
            Phase::Controls,
            &ListEntry {
                key: control_key,
                kind: ListKind::Object,
            },
            deadline(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(record.state, MetadataState::ControlAdmitted);
}
