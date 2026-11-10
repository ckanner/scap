use super::*;
use records::BindingState;

type Mutation<T> = Box<dyn Fn(&mut T)>;

fn terminal(aborted: bool) -> (Arc<Memory>, Catalogue, Creation) {
    let (objects, catalog, creation) = stage(if aborted {
        CreationPhase::Reserved
    } else {
        CreationPhase::Ready
    });
    if aborted {
        catalog
            .abort_create(CREATOR, &abort(&creation), deadline())
            .unwrap();
    } else {
        catalog
            .delete(CREATOR, &delete(&creation), deadline())
            .unwrap();
    }
    (objects, catalog, creation)
}

fn corrupt_lookup_entries(catalog: &Catalogue, creation: &Creation) {
    assert_eq!(
        catalog.inspect_create_operation(CREATOR, creation.operation, deadline()),
        Err(CatalogueError::Corrupt)
    );
    assert_eq!(
        catalog.resume_create(CREATOR, creation, deadline()),
        Err(CatalogueError::Corrupt)
    );
    assert_eq!(
        catalog.resolve(CREATOR, &creation.name, deadline()),
        Err(CatalogueError::Corrupt)
    );
}

#[test]
fn construction_and_public_input_validation_have_no_authority_side_effects() {
    let objects = Arc::new(Memory::default());
    for (deployment, tenant, worker) in [(0, 2, 10), (1, 0, 10), (1, 2, 0)] {
        assert!(matches!(
            Catalogue::new(
                objects.clone(),
                deployment,
                tenant,
                worker,
                crate::tests::test_options()
            ),
            Err(CatalogueError::Invalid)
        ));
    }
    let mut options = crate::tests::test_options();
    options.retention.max_entries = 0;
    assert!(matches!(
        Catalogue::new(objects.clone(), 1, 2, 10, options),
        Err(CatalogueError::Invalid)
    ));
    let catalog = catalogue(objects.clone());
    let zero = Caller {
        principal: 0,
        provision: true,
    };
    assert_eq!(
        catalog.prepare(zero, &input("x", 1, None), deadline()),
        Err(CatalogueError::Invalid)
    );
    assert_eq!(
        catalog.resolve(zero, "x", deadline()),
        Err(CatalogueError::Invalid)
    );
    assert_eq!(
        catalog.resolve(CREATOR, "", deadline()),
        Err(CatalogueError::Invalid)
    );
    assert_eq!(
        catalog.prepare(CREATOR, &input("x", 0, None), deadline()),
        Err(CatalogueError::Invalid)
    );
    assert_eq!(
        catalog.prepare(CREATOR, &input("x", 1, Some(0)), deadline()),
        Err(CatalogueError::Invalid)
    );
    assert!(objects.calls().is_empty());

    let (_, local, creation) = prepared();
    for (deployment, tenant) in [(2, 2), (1, 3)] {
        let other = Catalogue::new(
            objects.clone(),
            deployment,
            tenant,
            10,
            crate::tests::test_options(),
        )
        .unwrap();
        assert_eq!(
            other.resume_create(CREATOR, &creation, deadline()),
            Err(CatalogueError::Invalid)
        );
    }
    for field in 0..4 {
        let mut request = abort(&creation);
        match field {
            0 => request.operation = 0,
            1 => request.expected_name_revision = 0,
            2 => request.nonce = 0,
            _ => request.creation.scope.database += 1,
        }
        assert_eq!(
            local.abort_create(CREATOR, &request, deadline()),
            Err(CatalogueError::Invalid)
        );
    }
    let mut request = delete(&creation);
    request.expected_head_revision = 0;
    assert_eq!(
        local.delete(CREATOR, &request, deadline()),
        Err(CatalogueError::Invalid)
    );
    assert_eq!(
        local.delete(zero, &delete(&creation), deadline()),
        Err(CatalogueError::Invalid)
    );
}

#[test]
fn prepare_requires_exact_durable_readback_after_admission() {
    for fault in [
        Fault::Before(StoreError::Missing),
        Fault::Before(StoreError::Unknown),
        Fault::EmptyEtag,
    ] {
        let objects = Arc::new(Memory::default());
        let catalog = catalogue(objects.clone());
        let expected = if matches!(fault, Fault::Before(StoreError::Unknown)) {
            CatalogueError::Unknown
        } else {
            CatalogueError::Corrupt
        };
        objects.cut(false, &catalog.descriptor_key(7, 1), None, 0, fault);
        assert_eq!(
            catalog.prepare(CREATOR, &input("x", 1, None), deadline()),
            Err(expected)
        );
    }
}

#[test]
fn resolve_reports_every_incomplete_phase_and_detects_a_changed_outer_binding() {
    for phase in [
        CreationPhase::Reserved,
        CreationPhase::Provisioning,
        CreationPhase::Bound,
    ] {
        let (objects, catalog, creation) = stage(phase.clone());
        assert_eq!(
            catalog.resolve(CREATOR, &creation.name, deadline()),
            Err(CatalogueError::NotFound)
        );
        if phase == CreationPhase::Reserved {
            let mut foreign = creation.scope.clone();
            foreign.incarnation += 1;
            Database::with_options(objects, foreign, 20, crate::tests::test_options())
                .unwrap()
                .create(90, 1, deadline())
                .unwrap();
            assert_eq!(
                catalog.resolve(CREATOR, &creation.name, deadline()),
                Err(CatalogueError::NotFound)
            );
        }
    }
    let (objects, catalog, creation) = stage(CreationPhase::Ready);
    let peer = catalogue(objects.clone());
    let target = creation.clone();
    objects.cut(
        false,
        &catalog.binding_key(&creation.name),
        None,
        1,
        Fault::Run(Arc::new(move || {
            peer.delete(CREATOR, &delete(&target), deadline()).unwrap();
        })),
    );
    assert_eq!(
        catalog.resolve(CREATOR, &creation.name, deadline()),
        Err(CatalogueError::Conflict)
    );
}

#[test]
fn every_resolve_and_tombstone_reuse_io_error_stops_without_returning_success() {
    let (base, _, creation) = stage(CreationPhase::Ready);
    let successful = base.fork();
    catalogue(successful.clone())
        .resolve(CREATOR, &creation.name, deadline())
        .unwrap();
    for offset in 1..=successful.calls().len() {
        let objects = base.fork();
        objects.fail_at(offset, Fault::Before(StoreError::Unknown));
        assert_eq!(
            catalogue(objects).resolve(CREATOR, &creation.name, deadline()),
            Err(CatalogueError::Unknown)
        );
    }
    for aborted in [false, true] {
        let (base, catalog, creation) = terminal(aborted);
        let next = catalog
            .prepare(CREATOR, &input(&creation.name, 2, Some(3)), deadline())
            .unwrap()
            .creation;
        let success = base.fork();
        catalogue(success.clone())
            .resume_create(CREATOR, &next, deadline())
            .unwrap();
        for offset in 1..=success.calls().len() {
            let objects = base.fork();
            objects.fail_at(offset, Fault::Before(StoreError::Unknown));
            assert_eq!(
                catalogue(objects).resume_create(CREATOR, &next, deadline()),
                Err(CatalogueError::Unknown)
            );
        }
    }
}

#[test]
fn descriptor_key_and_scope_are_validated_independently_of_record_encoding() {
    let (base, catalog, creation) = prepared();
    let original = descriptor(&catalog, &creation).raw().clone();
    for field in 0..4 {
        let objects = base.fork();
        let catalog = catalogue(objects.clone());
        let mut changed = original.clone();
        match field {
            0 => changed.creation.creator += 1,
            1 => changed.creation.operation += 1,
            2 => changed.creation.scope.deployment += 1,
            _ => changed.creation.scope.tenant += 1,
        }
        changed.creation.scope = records::derive_scope(
            changed.creation.scope.deployment,
            changed.creation.scope.tenant,
            changed.creation.creator,
            changed.creation.operation,
        )
        .unwrap();
        objects.set(
            &catalog.descriptor_key(creation.creator, creation.operation),
            records::encode(&changed).unwrap(),
        );
        assert_eq!(
            catalog.inspect_create_operation(CREATOR, creation.operation, deadline()),
            Err(CatalogueError::Corrupt)
        );
    }
}

#[test]
fn control_key_and_scope_are_checked_before_comparing_original_intent() {
    let (base, catalog, creation) = stage(CreationPhase::Ready);
    let mut request = delete(&creation);
    request.expected_head_revision = 1;
    assert_eq!(
        catalog.delete(CREATOR, &request, deadline()),
        Err(CatalogueError::Conflict)
    );
    let key = catalog.control_address(7, &NamedDeletionKind::Delete, request.operation);
    let original = catalog
        .read::<Control>(&key, deadline())
        .unwrap()
        .unwrap()
        .body
        .raw()
        .clone();
    for field in 0..5 {
        let objects = base.fork();
        let catalog = catalogue(objects.clone());
        let mut changed = original.clone();
        match field {
            0 => changed.principal += 1,
            1 => {
                changed.kind = NamedDeletionKind::Abort;
                changed.expected_head_revision = None;
            }
            2 => changed.operation += 1,
            3 => changed.creation.scope.deployment += 1,
            _ => changed.creation.scope.tenant += 1,
        }
        changed.creation.scope = records::derive_scope(
            changed.creation.scope.deployment,
            changed.creation.scope.tenant,
            changed.creation.creator,
            changed.creation.operation,
        )
        .unwrap();
        objects.set(&key, records::encode(&changed).unwrap());
        assert_eq!(
            catalog.delete(CREATOR, &request, deadline()),
            Err(CatalogueError::Corrupt)
        );
    }
}

#[test]
fn stable_binding_requires_its_exact_name_descriptor_and_origin() {
    let (base, catalog, creation) = stage(CreationPhase::Reserved);
    let original = catalog
        .read_binding(&creation.name, deadline())
        .unwrap()
        .unwrap()
        .body
        .raw()
        .clone();
    for field in 0..3 {
        let objects = base.fork();
        let catalog = catalogue(objects.clone());
        let mut changed = original.clone();
        match field {
            0 => {
                changed.creation.name = "wrong name".into();
                changed.origin.name_hash = format::digest(b"wrong name");
            }
            1 => changed.creation.expected_name_revision = Some(3),
            _ => changed.origin.descriptor_hash = format::digest(b"wrong descriptor"),
        }
        if field == 1 {
            changed.revision = 4;
        }
        objects.set(
            &catalog.binding_key(&creation.name),
            records::encode(&changed).unwrap(),
        );
        corrupt_lookup_entries(&catalog, &creation);
    }
}

#[test]
fn provisioning_head_contract_rejects_validly_encoded_but_wrong_initial_state() {
    let mutations: Vec<Mutation<Head>> = vec![
        Box::new(|head| {
            head.revision = 2;
            head.head_serial = 2;
            head.transition.revision = 2;
        }),
        Box::new(|head| head.owner_epoch = 2),
        Box::new(|head| head.auth_epoch = 2),
        Box::new(|head| head.quota.max_bytes = None),
        Box::new(|head| head.retention.max_entries += 1),
        Box::new(|head| head.policy[0].read = false),
    ];
    for phase in [CreationPhase::Provisioning, CreationPhase::Bound] {
        let (base, catalog, creation) = stage(phase);
        let original = catalog
            .read_slot(&creation.scope, deadline())
            .unwrap()
            .unwrap()
            .head;
        for mutate in &mutations {
            let objects = base.fork();
            let catalog = catalogue(objects.clone());
            let mut head = original.clone();
            mutate(&mut head);
            objects.set(
                &format::head_key(&creation.scope),
                format::encode_head(&head).unwrap(),
            );
            corrupt_lookup_entries(&catalog, &creation);
            assert_eq!(
                catalog.abort_create(CREATOR, &abort(&creation), deadline()),
                Err(CatalogueError::Corrupt)
            );
            assert_eq!(
                catalog.delete(CREATOR, &delete(&creation), deadline()),
                Err(CatalogueError::Corrupt)
            );
        }
    }
}

#[test]
fn bound_and_reserved_names_reject_impossible_successful_or_missing_heads() {
    for phase in [
        CreationPhase::Provisioning,
        CreationPhase::Bound,
        CreationPhase::Ready,
    ] {
        let (objects, catalog, creation) = stage(phase.clone());
        if phase == CreationPhase::Provisioning {
            let mut head = catalog
                .read_slot(&creation.scope, deadline())
                .unwrap()
                .unwrap()
                .head;
            head.lifecycle = Lifecycle::Ready;
            objects.set(
                &format::head_key(&creation.scope),
                format::encode_head(&head).unwrap(),
            );
        } else {
            objects.remove(&format::head_key(&creation.scope));
        }
        corrupt_lookup_entries(&catalog, &creation);
        assert_eq!(
            catalog.abort_create(CREATOR, &abort(&creation), deadline()),
            Err(CatalogueError::Corrupt)
        );
    }
    let (objects, catalog, creation) = stage(CreationPhase::Ready);
    objects.remove(&catalog.binding_key(&creation.name));
    assert_eq!(
        catalog.inspect_create_operation(CREATOR, creation.operation, deadline()),
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
fn tombstone_barrier_and_control_relationships_are_not_inferred_from_valid_json() {
    let (base, catalog, creation) = terminal(true);
    let proof_key = catalog.proof_key(&creation);
    let proof = catalog
        .read::<AbortProof>(&proof_key, deadline())
        .unwrap()
        .unwrap()
        .body
        .raw()
        .clone();
    let binding_key = catalog.binding_key(&creation.name);
    let binding = catalog
        .read::<Binding>(&binding_key, deadline())
        .unwrap()
        .unwrap()
        .body
        .raw()
        .clone();
    for field in 0..5 {
        let objects = base.fork();
        let catalog = catalogue(objects.clone());
        let mut changed = proof.clone();
        match field {
            0 => {
                changed.control.creation.expected_name_revision = Some(3);
            }
            1 => changed.control.origin.descriptor_hash = format::digest(b"other source"),
            2 => {
                if let Barrier::OwnDeleted { transition } = &mut changed.barrier {
                    transition.revision = 2;
                }
            }
            3 => changed.control.operation += 1,
            _ => changed.control.nonce += 1,
        }
        if field == 4 {
            if let Barrier::OwnDeleted { transition } = &mut changed.barrier {
                transition.nonce = changed.control.nonce;
            }
        }
        if field >= 3 {
            objects.set(
                &catalog.control_key(&changed.control),
                records::encode(&changed.control).unwrap(),
            );
        }
        let bytes = records::encode(&changed).unwrap();
        let mut name = binding.clone();
        if field == 2 {
            name.proof = Some(format::digest(&bytes));
        }
        objects.set(&proof_key, bytes);
        objects.set(&binding_key, records::encode(&name).unwrap());
        corrupt_lookup_entries(&catalog, &creation);
    }
}

#[test]
fn missing_name_after_a_foreign_occupancy_proof_is_authority_loss() {
    let (objects, catalog, creation) = stage(CreationPhase::Reserved);
    let mut foreign = creation.scope.clone();
    foreign.incarnation += 1;
    Database::with_options(objects.clone(), foreign, 20, crate::tests::test_options())
        .unwrap()
        .create(90, 1, deadline())
        .unwrap();
    catalog
        .abort_create(CREATOR, &abort(&creation), deadline())
        .unwrap();
    objects.remove(&catalog.binding_key(&creation.name));
    assert_eq!(
        catalog.inspect_create_operation(CREATOR, creation.operation, deadline()),
        Err(CatalogueError::Corrupt)
    );
    assert_eq!(
        catalog.abort_create(CREATOR, &abort(&creation), deadline()),
        Err(CatalogueError::Corrupt)
    );
}

#[test]
fn immutable_record_creation_never_reinterprets_an_existing_different_intent() {
    let (objects, catalog, creation) = stage(CreationPhase::Reserved);
    let original = descriptor(&catalog, &creation);
    let mut changed = original.raw().clone();
    changed.creation.name = "other".into();
    assert_eq!(
        catalog.immutable(&catalog.descriptor_key(7, 1), &changed, deadline()),
        Err(CatalogueError::Conflict)
    );
    let key = "test-catalogue-boundary";
    let mut invalid = original.raw().clone();
    invalid.format = 0;
    assert_eq!(
        catalog.immutable(key, &invalid, deadline()),
        Err(CatalogueError::Invalid)
    );
    objects.cut(false, key, None, 1, Fault::Before(StoreError::Missing));
    assert_eq!(
        catalog.immutable(key, original.raw(), deadline()),
        Err(CatalogueError::Corrupt)
    );
    // A complete immutable contract uses the same record type for admission,
    // exact reentry and each store failure. Generic codecs must not behave
    // differently just because another authority-record type exercised a path.
    let accepted = catalog.immutable(key, original.raw(), deadline()).unwrap();
    assert_eq!(accepted, original);
    let fresh = "test-catalogue-fresh-immutable";
    for (put, skip) in [(false, 0), (true, 0), (false, 1)] {
        objects.cut(put, fresh, None, skip, Fault::Before(StoreError::Unknown));
        assert_eq!(
            catalog.immutable(fresh, original.raw(), deadline()),
            Err(CatalogueError::Unknown)
        );
        objects.remove(fresh);
    }
    assert_eq!(
        catalog
            .immutable(fresh, original.raw(), deadline())
            .unwrap(),
        original
    );
    let binding = Binding {
        format: 0,
        creation,
        origin: original.origin(),
        revision: 1,
        state: BindingState::Reserved,
        control: None,
        proof: None,
    };
    assert_eq!(
        catalog.write_binding(&binding, None, deadline()),
        Err(CatalogueError::Invalid)
    );
}

#[test]
fn malformed_authority_bytes_and_empty_head_etags_are_rejected() {
    for target in 0..3 {
        let (objects, catalog, creation) = stage(CreationPhase::Ready);
        let key = match target {
            0 => catalog.descriptor_key(7, 1),
            1 => catalog.binding_key(&creation.name),
            _ => format::head_key(&creation.scope),
        };
        objects.set(&key, b"{}".to_vec());
        assert_eq!(
            catalog.resolve(CREATOR, &creation.name, deadline()),
            Err(CatalogueError::Corrupt)
        );
    }
    let (objects, catalog, creation) = stage(CreationPhase::Ready);
    objects.cut(
        false,
        &format::head_key(&creation.scope),
        None,
        0,
        Fault::EmptyEtag,
    );
    assert!(matches!(
        catalog.read_slot(&creation.scope, deadline()),
        Err(CatalogueError::Corrupt)
    ));
}

#[test]
fn proof_cannot_coexist_with_a_rolled_back_reserved_or_bound_name() {
    for state in [BindingState::Reserved, BindingState::Bound] {
        let (objects, catalog, creation) = terminal(true);
        let mut binding = catalog
            .read_binding(&creation.name, deadline())
            .unwrap()
            .unwrap()
            .body
            .raw()
            .clone();
        binding.revision = if state == BindingState::Reserved {
            1
        } else {
            2
        };
        binding.state = state;
        binding.control = None;
        binding.proof = None;
        objects.set(
            &catalog.binding_key(&creation.name),
            records::encode(&binding).unwrap(),
        );
        corrupt_lookup_entries(&catalog, &creation);
        assert_eq!(
            catalog.abort_create(CREATOR, &abort(&creation), deadline()),
            Err(CatalogueError::Corrupt)
        );
    }
}

#[test]
fn aborting_cross_key_validation_rejects_corrupt_head_and_proof_combinations() {
    for corruption in 0..7 {
        let (objects, catalog, creation) = terminal(true);
        let name_key = catalog.binding_key(&creation.name);
        let proof_key = catalog.proof_key(&creation);
        let head_key = format::head_key(&creation.scope);
        let mut binding = catalog
            .read_binding(&creation.name, deadline())
            .unwrap()
            .unwrap()
            .body
            .raw()
            .clone();
        binding.state = BindingState::Aborting;
        binding.revision = 2;
        binding.proof = None;
        objects.set(&name_key, records::encode(&binding).unwrap());
        let mut head = catalog
            .read_slot(&creation.scope, deadline())
            .unwrap()
            .unwrap()
            .head;
        let mut proof = catalog
            .read::<AbortProof>(&proof_key, deadline())
            .unwrap()
            .unwrap()
            .body
            .raw()
            .clone();
        match corruption {
            0 => {
                head.lifecycle = Lifecycle::Provisioning;
                head.deletion = None;
                head.owner_epoch = 2;
                objects.remove(&proof_key);
            }
            1 => {
                head.lifecycle = Lifecycle::Ready;
                head.deletion = None;
                objects.remove(&proof_key);
            }
            2 => {
                head.lifecycle = Lifecycle::Maintenance;
                head.deletion = None;
                objects.remove(&proof_key);
            }
            3 => {
                head.deletion.as_mut().unwrap().operation += 1;
                objects.remove(&proof_key);
            }
            4 => {
                proof.control.operation += 1;
                objects.set(
                    &catalog.control_key(&proof.control),
                    records::encode(&proof.control).unwrap(),
                );
                objects.set(&proof_key, records::encode(&proof).unwrap());
            }
            5 => objects.remove(&head_key),
            _ => {
                if let Barrier::OwnDeleted { transition } = &mut proof.barrier {
                    transition.revision = 2;
                }
                objects.set(&proof_key, records::encode(&proof).unwrap());
            }
        }
        if corruption != 5 {
            objects.set(&head_key, format::encode_head(&head).unwrap());
        }
        corrupt_lookup_entries(&catalog, &creation);
        assert_eq!(
            catalog.abort_create(CREATOR, &abort(&creation), deadline()),
            Err(CatalogueError::Corrupt)
        );
        if corruption == 4 || corruption == 6 {
            assert_eq!(
                catalog.delete(CREATOR, &delete(&creation), deadline()),
                Err(CatalogueError::Corrupt)
            );
        }
    }
}

#[test]
fn terminal_names_require_heads_and_normal_delete_has_no_abort_proof() {
    for aborted in [false, true] {
        let (objects, catalog, creation) = terminal(aborted);
        objects.remove(&format::head_key(&creation.scope));
        corrupt_lookup_entries(&catalog, &creation);
        assert_eq!(
            catalog.abort_create(CREATOR, &abort(&creation), deadline()),
            Err(CatalogueError::Corrupt)
        );
    }
    let (objects, catalog, creation) = terminal(false);
    catalog
        .abort_create(CREATOR, &abort(&creation), deadline())
        .unwrap();
    let control = catalog
        .read::<Control>(
            &catalog.control_address(7, &NamedDeletionKind::Abort, 20),
            deadline(),
        )
        .unwrap()
        .unwrap()
        .body
        .raw()
        .clone();
    let proof = AbortProof {
        format: 1,
        control,
        barrier: Barrier::OwnDeleted {
            transition: format::Transition {
                revision: 1,
                nonce: 21,
            },
        },
    };
    objects.set(
        &catalog.proof_key(&creation),
        records::encode(&proof).unwrap(),
    );
    corrupt_lookup_entries(&catalog, &creation);
    assert_eq!(
        catalog.abort_create(CREATOR, &abort(&creation), deadline()),
        Err(CatalogueError::Corrupt)
    );
}

#[test]
fn own_deleted_and_foreign_occupied_barriers_bind_exact_permanent_origins() {
    for corruption in 0..2 {
        let (objects, catalog, creation) = terminal(true);
        let mut head = catalog
            .read_slot(&creation.scope, deadline())
            .unwrap()
            .unwrap()
            .head;
        head.lifecycle = Lifecycle::Ready;
        head.creation = None;
        head.deletion = None;
        if corruption == 0 {
            head.scope.incarnation += 1;
        }
        objects.set(
            &format::head_key(&creation.scope),
            format::encode_head(&head).unwrap(),
        );
        corrupt_lookup_entries(&catalog, &creation);
    }
    for corruption in 0..2 {
        let (objects, catalog, creation) = stage(CreationPhase::Reserved);
        // A direct database in the same full Scope is a foreign origin relative
        // to this named creation; no probabilistic hash collision is fabricated.
        Database::with_options(
            objects.clone(),
            creation.scope.clone(),
            20,
            crate::tests::test_options(),
        )
        .unwrap()
        .create(90, 1, deadline())
        .unwrap();
        catalog
            .abort_create(CREATOR, &abort(&creation), deadline())
            .unwrap();
        let source = descriptor(&catalog, &creation);
        let mut head = catalog
            .read_slot(&creation.scope, deadline())
            .unwrap()
            .unwrap()
            .head;
        if corruption == 0 {
            head.scope.incarnation += 1;
        } else {
            head.creation = Some(source.origin());
        }
        objects.set(
            &format::head_key(&creation.scope),
            format::encode_head(&head).unwrap(),
        );
        corrupt_lookup_entries(&catalog, &creation);
    }
}

#[test]
fn phase_specific_helpers_refuse_other_valid_durable_phases() {
    let (objects, catalog, creation) = prepared();
    let source = descriptor(&catalog, &creation);
    let foreign = Database::with_options(objects, creation.scope, 20, crate::tests::test_options())
        .unwrap()
        .create(90, 1, deadline())
        .unwrap();
    assert_eq!(
        Catalogue::provisioning(&source, &foreign),
        Err(CatalogueError::Corrupt)
    );
    let (_, catalog, creation) = stage(CreationPhase::Ready);
    let source = descriptor(&catalog, &creation);
    let view = catalog.view(&source, deadline()).unwrap();
    assert_eq!(
        Catalogue::tombstone_view(view.binding.as_ref().unwrap(), &view),
        Err(CatalogueError::Corrupt)
    );
    assert_eq!(
        catalog.delete_source(&source, &view.head.as_ref().unwrap().head, deadline()),
        Err(CatalogueError::Corrupt)
    );
}

#[test]
fn bound_name_cannot_resolve_a_valid_head_from_another_origin() {
    let (objects, catalog, creation) = stage(CreationPhase::Ready);
    let mut head = catalog
        .read_slot(&creation.scope, deadline())
        .unwrap()
        .unwrap()
        .head;
    // The exact same physical and logical Scope can also be represented by a
    // direct HEAD. A valid HEAD alone is not this name's creation authority.
    head.creation = None;
    objects.set(
        &format::head_key(&creation.scope),
        format::encode_head(&head).unwrap(),
    );
    corrupt_lookup_entries(&catalog, &creation);
    assert_eq!(
        catalog.abort_create(CREATOR, &abort(&creation), deadline()),
        Err(CatalogueError::Corrupt)
    );
}

#[test]
fn old_aborted_identity_rejects_rollback_missing_head_and_changed_barrier_after_name_reuse() {
    for corruption in 0..3 {
        let (objects, catalog, creation) = terminal(true);
        let early = catalog
            .prepare(CREATOR, &input(&creation.name, 3, None), deadline())
            .unwrap();
        let next = catalog
            .prepare(CREATOR, &input(&creation.name, 2, Some(3)), deadline())
            .unwrap();
        catalog
            .resume_create(CREATOR, &next.creation, deadline())
            .unwrap();
        match corruption {
            0 => {
                let source = descriptor(&catalog, &early.creation);
                let rollback = Binding {
                    format: 1,
                    creation: early.creation,
                    origin: source.origin(),
                    revision: 1,
                    state: BindingState::Reserved,
                    control: None,
                    proof: None,
                };
                objects.set(
                    &catalog.binding_key(&creation.name),
                    records::encode(&rollback).unwrap(),
                );
            }
            1 => objects.remove(&format::head_key(&creation.scope)),
            _ => {
                let mut head = catalog
                    .read_slot(&creation.scope, deadline())
                    .unwrap()
                    .unwrap()
                    .head;
                head.lifecycle = Lifecycle::Ready;
                head.deletion = None;
                objects.set(
                    &format::head_key(&creation.scope),
                    format::encode_head(&head).unwrap(),
                );
            }
        }
        assert_eq!(
            catalog.inspect_create_operation(CREATOR, 1, deadline()),
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
    }
}

#[test]
fn old_deleted_identity_requires_its_original_control_after_name_reuse() {
    let (objects, catalog, creation) = terminal(false);
    let next = catalog
        .prepare(CREATOR, &input(&creation.name, 2, Some(3)), deadline())
        .unwrap();
    catalog
        .resume_create(CREATOR, &next.creation, deadline())
        .unwrap();
    objects.remove(&catalog.control_address(7, &NamedDeletionKind::Delete, 30));
    assert_eq!(
        catalog.inspect_create_operation(CREATOR, 1, deadline()),
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
}

#[test]
fn bound_deleted_source_checks_original_name_revision_before_reporting_deleting() {
    let (objects, catalog, creation) = stage(CreationPhase::Ready);
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
    let key = catalog.control_address(7, &NamedDeletionKind::Delete, 30);
    let mut control = catalog
        .read::<Control>(&key, deadline())
        .unwrap()
        .unwrap()
        .body
        .raw()
        .clone();
    control.expected_name_revision = 99;
    let admitted = Canonical::new(control).unwrap();
    objects.set(&key, admitted.bytes().to_vec());
    let mut head = catalog
        .read_slot(&creation.scope, deadline())
        .unwrap()
        .unwrap()
        .head;
    head.deletion = Some(admitted.mark());
    objects.set(
        &format::head_key(&creation.scope),
        format::encode_head(&head).unwrap(),
    );
    corrupt_lookup_entries(&catalog, &creation);
    assert_eq!(
        catalog.abort_create(CREATOR, &abort(&creation), deadline()),
        Err(CatalogueError::Corrupt)
    );
}

#[test]
fn a_tombstone_with_a_different_expected_revision_is_not_an_admission_ticket() {
    let (_, catalog, creation) = terminal(false);
    let next = catalog
        .prepare(CREATOR, &input(&creation.name, 2, Some(6)), deadline())
        .unwrap();
    assert_eq!(
        catalog
            .resume_create(CREATOR, &next.creation, deadline())
            .unwrap()
            .phase,
        CreationPhase::NameConflict
    );
}
