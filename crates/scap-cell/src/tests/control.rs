use super::*;

fn apply_control_activation(state: &mut CellState, data: Vec<u8>) -> ControlActivationOutcome {
    let position = Position {
        term: state.position.term,
        index: state.position.index + 1,
    };
    let batch = CellApplication::new(state.identity, state.limits)
        .unwrap()
        .apply_with_results(
            &state.encode(),
            &[Entry {
                term: position.term,
                index: position.index,
                data: data.into(),
                ..Entry::default()
            }],
            &[position.index],
        )
        .unwrap();
    *state = CellState::decode_bound(&batch.state, state.identity, position, state.limits).unwrap();
    assert_eq!(batch.results.len(), 1);
    decode_control_activation_outcome(&batch.results[0], state.identity, position).unwrap()
}

fn activate_control(state: &mut CellState) -> ControlActivationOutcome {
    apply_control_activation(
        state,
        encode_control_activation(state.identity, state.bootstrap_admin),
    )
}

fn enable_retention(state: &mut CellState) {
    let position = Position {
        term: state.position.term,
        index: state.position.index + 1,
    };
    let data = encode_retention_activation(state.identity, state.bootstrap_admin);
    let batch = CellApplication::new(state.identity, state.limits)
        .unwrap()
        .apply_with_results(
            &state.encode(),
            &[Entry {
                term: position.term,
                index: position.index,
                data: data.into(),
                ..Entry::default()
            }],
            &[position.index],
        )
        .unwrap();
    assert_eq!(
        decode_retention_activation_outcome(&batch.results[0], state.identity, position)
            .unwrap()
            .result,
        Ok(())
    );
    *state = CellState::decode_bound(&batch.state, state.identity, position, state.limits).unwrap();
}

fn bounded(mut command: Command, revision: u64) -> Command {
    command.control_revision = Some(revision);
    command
}

fn boot_control() -> CellState {
    let mut state = boot();
    enable_retention(&mut state);
    assert_eq!(activate_control(&mut state).result, Ok(()));
    state
}

fn confirmed(state: &mut CellState, command: &Command, expected: AdminResult) -> ControlResult {
    let original = Position {
        term: state.position.term,
        index: state.position.index + 1,
    };
    let expected = ControlResult {
        revision: command.control_revision.unwrap() + 1,
        position: original,
        result: expected,
    };
    assert_eq!(
        apply(state, command),
        Outcome::ControlApplied(expected.clone())
    );
    assert_eq!(
        state
            .database(command.database.database_id)
            .unwrap()
            .control_revision,
        Some(expected.revision)
    );
    expected
}

fn exact_replay(state: &mut CellState, original: &Command, result: &ControlResult) {
    let before = state.databases.clone();
    let mut refreshed = original.clone();
    refreshed.admission.credential_id += 1;
    refreshed.admission.admission_id += 1;
    refreshed.admission.auth_epoch = state
        .database(original.database.database_id)
        .unwrap()
        .auth_epoch;
    assert_eq!(
        apply(state, &refreshed),
        Outcome::ControlAlreadyApplied(result.clone())
    );
    assert_eq!(state.databases, before);
}

fn active_control() -> CellState {
    let mut state = boot_control();
    confirmed(&mut state, &bounded(create(), 0), AdminResult::Created);
    confirmed(
        &mut state,
        &bounded(claim(0, WORKER, 2), 1),
        AdminResult::OwnerClaimed(OwnerToken {
            epoch: 1,
            worker_instance_id: WORKER,
        }),
    );
    confirmed(
        &mut state,
        &bounded(activate(1, WORKER, 3, 0, [0; 32]), 2),
        AdminResult::OwnerActivated,
    );
    state
}

#[test]
fn all_eight_actions_keep_only_the_latest_exact_original_receipt() {
    let mut state = boot_control();
    let created = bounded(create(), 0);
    let result = confirmed(&mut state, &created, AdminResult::Created);
    exact_replay(&mut state, &created, &result);
    let claimed = bounded(claim(0, WORKER, 2), 1);
    let result = confirmed(
        &mut state,
        &claimed,
        AdminResult::OwnerClaimed(OwnerToken {
            epoch: 1,
            worker_instance_id: WORKER,
        }),
    );
    exact_replay(&mut state, &claimed, &result);
    let activated = bounded(activate(1, WORKER, 3, 0, [0; 32]), 2);
    let result = confirmed(&mut state, &activated, AdminResult::OwnerActivated);
    exact_replay(&mut state, &activated, &result);
    let fenced = bounded(
        command(CommandKind::AuthFence {
            operation_id: operation(4),
            expected_epoch: 1,
            policy: policy(),
        }),
        3,
    );
    let result = confirmed(&mut state, &fenced, AdminResult::AuthChanged(2));
    rejected_without_mutation(&state, &fenced, Reject::Unauthorized);
    exact_replay(&mut state, &fenced, &result);
    let mut sql = write(1, 0);
    sql.admission.auth_epoch = 2;
    commit_parts(&mut sql).0.ticket.auth_epoch = 2;
    assert!(matches!(apply(&mut state, &sql), Outcome::Accepted(_)));
    let physical_before = state
        .recovery_source(database(), current_admission(2))
        .unwrap()
        .tail
        .to_vec();
    assert!(!physical_before[0].physical_changes.is_empty());
    let mut suspended = bounded(suspend(&state, operation(5)), 4);
    suspended.admission.auth_epoch = 2;
    let result = confirmed(&mut state, &suspended, AdminResult::Suspended(2));
    exact_replay(&mut state, &suspended, &result);
    let (archive, bytes) = state
        .archive_snapshot(database(), current_admission(2))
        .unwrap();
    assert_eq!(bytes[8], 4);
    let mut published = bounded(
        command(CommandKind::PublishArchive {
            operation_id: operation(6),
            expected_owner: state.database(database().database_id).unwrap().owner,
            expected_previous: None,
            archive,
        }),
        5,
    );
    published.admission.auth_epoch = 2;
    let result = confirmed(
        &mut state,
        &published,
        AdminResult::ArchivePublished(archive.object_digest),
    );
    exact_replay(&mut state, &published, &result);
    let mut pruned = bounded(
        command(CommandKind::PruneArchive {
            operation_id: operation(7),
            expected_owner: state.database(database().database_id).unwrap().owner,
            archive_digest: archive.object_digest,
        }),
        6,
    );
    pruned.admission.auth_epoch = 2;
    let result = confirmed(
        &mut state,
        &pruned,
        AdminResult::ArchivePruned(archive.object_digest),
    );
    exact_replay(&mut state, &pruned, &result);
    let mut hydrated = bounded(
        command(CommandKind::HydrateArchive {
            operation_id: operation(8),
            archive: bytes,
        }),
        7,
    );
    hydrated.admission.auth_epoch = 2;
    let result = confirmed(
        &mut state,
        &hydrated,
        AdminResult::ArchiveHydrated(archive.object_digest),
    );
    exact_replay(&mut state, &hydrated, &result);
    assert!(!state.database(database().database_id).unwrap().cold);
    // The owner token intentionally still matches: only the durable control
    // revision prevents the delayed original prune from deleting hydrated data.
    rejected_without_mutation(&state, &pruned, Reject::ControlRetired);
    assert_eq!(
        state
            .recovery_source(database(), current_admission(2))
            .unwrap()
            .tail,
        physical_before.as_slice()
    );
    for mut old in [created, claimed, activated, fenced, suspended, published] {
        old.admission.auth_epoch = 2;
        rejected_without_mutation(&state, &old, Reject::ControlRetired);
    }
    assert!(state.administration.is_empty());
    assert_eq!(
        state
            .database(database().database_id)
            .unwrap()
            .control_revision,
        Some(8)
    );
    assert_eq!(decode_snapshot(&state).unwrap(), state);
}

#[test]
fn latest_identity_conflicts_future_revisions_and_retired_commands_are_atomic() {
    let state = active_control();
    let original = bounded(activate(1, WORKER, 3, 0, [0; 32]), 2);
    let mut changed = original.clone();
    if let CommandKind::ActivateOwner { operation_id, .. } = &mut changed.kind {
        *operation_id = operation(99);
    }
    rejected_without_mutation(&state, &changed, Reject::Conflict);
    let mut changed = original.clone();
    if let CommandKind::ActivateOwner { restored_hash, .. } = &mut changed.kind {
        *restored_hash = [1; 32];
    }
    rejected_without_mutation(&state, &changed, Reject::Conflict);
    let mut changed = original.clone();
    changed.admission.principal_id = 44;
    rejected_without_mutation(&state, &changed, Reject::Conflict);
    changed.admission.principal_id = 22;
    rejected_without_mutation(&state, &changed, Reject::Unauthorized);
    let mut changed = original.clone();
    changed.database.incarnation += 1;
    rejected_without_mutation(&state, &changed, Reject::Fenced);
    changed = original.clone();
    changed.database.placement_generation += 1;
    rejected_without_mutation(&state, &changed, Reject::Fenced);
    rejected_without_mutation(&state, &bounded(claim(1, WORKER, 99), 4), Reject::Conflict);
    rejected_without_mutation(
        &state,
        &bounded(claim(0, WORKER, 2), 1),
        Reject::ControlRetired,
    );
    let mut changed = original;
    if let CommandKind::ActivateOwner { operation_id, .. } = &mut changed.kind {
        *operation_id = 0;
    }
    rejected_without_mutation(&state, &changed, Reject::Invalid);
    let mut absent = bounded(create(), 1);
    absent.database.database_id += 100;
    rejected_without_mutation(&state, &absent, Reject::Conflict);
    // Namespaces are per database; a different database may create with its
    // own revision zero and even the same operation ID.
    absent.control_revision = Some(0);
    let mut next = state.clone();
    confirmed(&mut next, &absent, AdminResult::Created);
    assert_eq!(
        next.database(database().database_id).unwrap(),
        state.database(database().database_id).unwrap()
    );
}

#[test]
fn control_envelopes_cannot_turn_sql_or_request_retirement_into_admin_actions() {
    let state = active_control();
    for command in [
        write(1, 0),
        cancel(2),
        command(CommandKind::AcknowledgeRequest {
            request_id: request(2),
            request_fingerprint: [2; 32],
            expected: RequestTerminal::Cancelled {
                position: state.position,
            },
        }),
        command(CommandKind::RotateRequests { expected_epoch: 1 }),
    ] {
        rejected_without_mutation(&state, &bounded(command, 3), Reject::Invalid);
    }
    let legacy = boot();
    rejected_without_mutation(&legacy, &bounded(create(), 0), Reject::Conflict);
    let legacy = active();
    rejected_without_mutation(&legacy, &bounded(claim(1, WORKER, 9), 0), Reject::Conflict);
}

#[test]
fn sql_acknowledgement_and_rotation_do_not_consume_control_revision() {
    let mut state = active_control();
    let control = state.databases[&database().database_id]
        .control_receipt
        .clone();
    assert!(matches!(
        apply(&mut state, &write(1, 0)),
        Outcome::Accepted(_)
    ));
    assert_eq!(apply(&mut state, &cancel(2)), Outcome::Cancelled);
    let cancel_position = match state
        .lookup(database(), admission(), request(2), [2; 32])
        .unwrap()
    {
        Lookup::Cancelled { position, .. } => position,
        other => panic!("{other:?}"),
    };
    for (id, expected) in [
        (1, RequestTerminal::Committed { sequence: 1 }),
        (
            2,
            RequestTerminal::Cancelled {
                position: cancel_position,
            },
        ),
    ] {
        assert_eq!(
            apply(
                &mut state,
                &command(CommandKind::AcknowledgeRequest {
                    request_id: request(id),
                    request_fingerprint: [id as u8; 32],
                    expected,
                })
            ),
            Outcome::RequestAcknowledged
        );
    }
    assert_eq!(
        apply(
            &mut state,
            &command(CommandKind::RotateRequests { expected_epoch: 1 })
        ),
        Outcome::RequestsRotated { epoch: 2 }
    );
    assert_eq!(
        state
            .database(database().database_id)
            .unwrap()
            .control_revision,
        Some(3)
    );
    assert_eq!(
        state.databases[&database().database_id].control_receipt,
        control
    );
    let mut replay = bounded(activate(1, WORKER, 3, 0, [0; 32]), 2);
    // Even the no-longer-current restored SQL revision is part of the original
    // intent: exact replay reports its old success without reactivating anything.
    replay.admission.request_epoch = 2;
    exact_replay(&mut state, &replay, &control.unwrap().result);
}

#[test]
fn legacy_receipts_are_pinned_and_new_legacy_ids_retire_after_activation() {
    let mut state = active();
    let pinned = state.administration.clone();
    assert_eq!(
        state
            .database(database().database_id)
            .unwrap()
            .control_revision,
        None
    );
    enable_retention(&mut state);
    assert_eq!(activate_control(&mut state).result, Ok(()));
    assert!(state.control_enabled());
    assert_eq!(state.physical_history_version(), 5);
    assert_eq!(
        state
            .database(database().database_id)
            .unwrap()
            .control_revision,
        Some(0)
    );
    assert_eq!(state.administration, pinned);
    for (cmd, result) in [
        (create(), AdminResult::Created),
        (
            claim(0, WORKER, 2),
            AdminResult::OwnerClaimed(OwnerToken {
                epoch: 1,
                worker_instance_id: WORKER,
            }),
        ),
        (
            activate(1, WORKER, 3, 0, [0; 32]),
            AdminResult::OwnerActivated,
        ),
    ] {
        assert_eq!(apply(&mut state, &cmd), Outcome::AlreadyApplied(result));
    }
    rejected_without_mutation(&state, &claim(1, WORKER, 90), Reject::ControlRetired);
    let mut other = create();
    if let CommandKind::Create { operation_id, .. } = &mut other.kind {
        *operation_id = operation(90);
    }
    other.database.database_id += 1;
    rejected_without_mutation(&state, &other, Reject::ControlRetired);
    let fenced = bounded(
        command(CommandKind::AuthFence {
            operation_id: operation(90),
            expected_epoch: 1,
            policy: policy(),
        }),
        0,
    );
    confirmed(&mut state, &fenced, AdminResult::AuthChanged(2));
    for mut old in [create(), claim(0, WORKER, 2)] {
        rejected_without_mutation(&state, &old, Reject::Unauthorized);
        old.admission.auth_epoch = 2;
        assert!(matches!(
            apply(&mut state, &old),
            Outcome::AlreadyApplied(_)
        ));
    }
    let mut conflict = claim(1, WORKER, 2);
    conflict.admission.auth_epoch = 2;
    rejected_without_mutation(&state, &conflict, Reject::Conflict);
    let mut unauthorized_create = create();
    unauthorized_create.admission.principal_id = 44;
    unauthorized_create.admission.auth_epoch = 2;
    rejected_without_mutation(&state, &unauthorized_create, Reject::Unauthorized);
    assert_eq!(state.administration, pinned);
    let mut new = bounded(claim(1, WORKER, 90), 1);
    new.admission.auth_epoch = 2;
    confirmed(
        &mut state,
        &new,
        AdminResult::OwnerClaimed(OwnerToken {
            epoch: 2,
            worker_instance_id: WORKER,
        }),
    );
    assert_eq!(state.administration, pinned);
}

#[test]
fn legacy_create_replay_obeys_current_policy_and_database_binding() {
    let mut state = active();
    enable_retention(&mut state);
    assert_eq!(activate_control(&mut state).result, Ok(()));
    let mut old = create();
    old.database.incarnation += 1;
    rejected_without_mutation(&state, &old, Reject::Fenced);
    let fenced = bounded(
        command(CommandKind::AuthFence {
            operation_id: operation(10),
            expected_epoch: 1,
            policy: vec![Grant {
                principal_id: 44,
                permissions: ADMIN,
            }],
        }),
        0,
    );
    confirmed(&mut state, &fenced, AdminResult::AuthChanged(2));
    old = create();
    old.admission.auth_epoch = 2;
    rejected_without_mutation(&state, &old, Reject::Unauthorized);
    let mut new = bounded(create(), 0);
    new.database.database_id += 100;
    new.admission.auth_epoch = 2;
    rejected_without_mutation(&state, &new, Reject::Unauthorized);
}

#[test]
fn more_than_4096_real_new_control_actions_have_constant_record_storage() {
    let mut state = active_control();
    state.limits.max_admin_operations = 1;
    state = decode_snapshot(&state).unwrap();
    let start_size = codec::encode_state(&state, false).len();
    let mut last = bounded(activate(1, WORKER, 3, 0, [0; 32]), 2);
    for cycle in 0..2050u64 {
        let revision = 3 + cycle * 2;
        let owner_epoch = cycle + 1;
        let claimed = bounded(
            claim(owner_epoch, WORKER, 100 + u128::from(cycle) * 2),
            revision,
        );
        confirmed(
            &mut state,
            &claimed,
            AdminResult::OwnerClaimed(OwnerToken {
                epoch: owner_epoch + 1,
                worker_instance_id: WORKER,
            }),
        );
        assert!(codec::encode_state(&state, false).len() <= start_size + 24);
        last = bounded(
            activate(
                owner_epoch + 1,
                WORKER,
                101 + u128::from(cycle) * 2,
                0,
                [0; 32],
            ),
            revision + 1,
        );
        confirmed(&mut state, &last, AdminResult::OwnerActivated);
        assert_eq!(codec::encode_state(&state, false).len(), start_size);
    }
    assert!(state.administration.is_empty());
    assert_eq!(
        state
            .database(database().database_id)
            .unwrap()
            .control_revision,
        Some(4103)
    );
    let result = state.databases[&database().database_id]
        .control_receipt
        .as_ref()
        .unwrap()
        .result
        .clone();
    exact_replay(&mut state, &last, &result);
    rejected_without_mutation(&state, &bounded(create(), 0), Reject::ControlRetired);
}

#[test]
fn a_full_4096_entry_legacy_map_can_upgrade_and_accept_bounded_operations() {
    let mut state = active_with(Limits {
        max_admin_operations: 4096,
        max_state_bytes: 2 * 1024 * 1024,
        ..limits()
    });
    // Apply real legacy transitions directly, checking the whole canonical
    // snapshot once. All records grow monotonically and the final budget fits;
    // repeated full-map cloning is unrelated to the retirement invariant.
    for id in 4..=4096 {
        let cmd = activate(1, WORKER, id, 0, [0; 32]);
        let position = Position {
            index: state.position.index + 1,
            ..state.position
        };
        let outcome = state.execute(&cmd, position).unwrap();
        assert_eq!(
            outcome,
            Outcome::Administrative(AdminResult::OwnerActivated)
        );
        state.position = position;
        state.last_outcome = Some(AppliedOutcome { position, outcome });
    }
    assert!(state.fits());
    state = decode_snapshot(&state).unwrap();
    assert_eq!(state.administration.len(), 4096);
    rejected_without_mutation(&state, &claim(1, WORKER, 5000), Reject::Capacity);
    enable_retention(&mut state);
    let pinned = state.administration.clone();
    assert_eq!(activate_control(&mut state).result, Ok(()));
    confirmed(
        &mut state,
        &bounded(claim(1, WORKER, 5000), 0),
        AdminResult::OwnerClaimed(OwnerToken {
            epoch: 2,
            worker_instance_id: WORKER,
        }),
    );
    assert_eq!(state.administration, pinned);
    assert_eq!(
        apply(&mut state, &activate(1, WORKER, 4096, 0, [0; 32])),
        Outcome::AlreadyApplied(AdminResult::OwnerActivated)
    );
    rejected_without_mutation(&state, &claim(2, WORKER, 5001), Reject::ControlRetired);
    assert_eq!(state.administration, pinned);
}

#[test]
fn control_revision_overflow_rejects_atomically_but_exact_last_retry_survives() {
    let mut state = active_control();
    let db = state.databases.get_mut(&database().database_id).unwrap();
    db.control_revision = Some(u64::MAX);
    let receipt = db.control_receipt.as_mut().unwrap();
    receipt.result.revision = u64::MAX;
    state.last_outcome.as_mut().unwrap().outcome = Outcome::ControlApplied(receipt.result.clone());
    state = decode_snapshot(&state).unwrap();
    rejected_without_mutation(
        &state,
        &bounded(claim(1, WORKER, 4), u64::MAX),
        Reject::Exhausted,
    );
    rejected_without_mutation(
        &state,
        &bounded(claim(0, WORKER, 2), u64::MAX - 2),
        Reject::ControlRetired,
    );
    let result = state.databases[&database().database_id]
        .control_receipt
        .as_ref()
        .unwrap()
        .result
        .clone();
    exact_replay(
        &mut state,
        &bounded(activate(1, WORKER, 3, 0, [0; 32]), u64::MAX - 1),
        &result,
    );
}

fn minimum_budget(state: &CellState) -> u32 {
    (codec::encode_state(state, false).len()
        + state
            .databases
            .values()
            .map(|db| {
                (db.requests.len() - db.acknowledged.len()) * 32
                    + codec::control_receipt_reserve(db.control_receipt.as_ref())
            })
            .sum::<usize>()
        + RESERVED_BYTES) as u32
}

#[test]
fn maximum_receipt_reservation_allows_owner_fencing_at_exact_capacity() {
    let mut state = active_control();
    // Fill the business state while the latest result has its shortest shape.
    assert!(matches!(
        apply(&mut state, &write(1, 0)),
        Outcome::Accepted(_)
    ));
    state.limits.max_state_bytes = minimum_budget(&state);
    state = decode_snapshot(&state).unwrap();
    assert!(state.fits());
    let revision = state
        .database(database().database_id)
        .unwrap()
        .control_revision
        .unwrap();
    confirmed(
        &mut state,
        &bounded(claim(1, WORKER, 5), revision),
        AdminResult::OwnerClaimed(OwnerToken {
            epoch: 2,
            worker_instance_id: WORKER,
        }),
    );
    assert_eq!(minimum_budget(&state), state.limits.max_state_bytes);
    let mut expanding_policy = policy();
    expanding_policy.push(Grant {
        principal_id: 55,
        permissions: READ,
    });
    state.limits.max_policy_grants = 5;
    state = decode_snapshot(&state).unwrap();
    rejected_without_mutation(
        &state,
        &bounded(
            command(CommandKind::AuthFence {
                operation_id: operation(6),
                expected_epoch: 1,
                policy: expanding_policy,
            }),
            revision + 1,
        ),
        Reject::Capacity,
    );
    let mut create_other = bounded(create(), 0);
    create_other.database.database_id += 1;
    rejected_without_mutation(&state, &create_other, Reject::Capacity);
    let mut undersized = state.clone();
    undersized.limits.max_state_bytes -= 1;
    assert_eq!(decode_snapshot(&undersized), Err(Error::Limit));
}

#[test]
fn activation_reserves_an_empty_slots_worst_case_and_does_not_downgrade() {
    let mut state = active();
    enable_retention(&mut state);
    let mut activated = state.clone();
    assert_eq!(activate_control(&mut activated).result, Ok(()));
    let required = minimum_budget(&activated);
    state.limits.max_state_bytes = required - 1;
    assert!(state.fits());
    let before = state.databases.clone();
    assert_eq!(activate_control(&mut state).result, Err(Reject::Capacity));
    assert_eq!(state.physical_history_version(), 4);
    assert_eq!(state.databases, before);
    state.limits.max_state_bytes = required;
    assert_eq!(activate_control(&mut state).result, Ok(()));
    confirmed(
        &mut state,
        &bounded(claim(1, WORKER, 4), 0),
        AdminResult::OwnerClaimed(OwnerToken {
            epoch: 2,
            worker_instance_id: WORKER,
        }),
    );
    let before = state.databases.clone();
    assert_eq!(activate_control(&mut state).result, Ok(()));
    enable_retention(&mut state);
    assert_eq!(activate_history(&mut state).result, Ok(()));
    assert_eq!(state.physical_history_version(), 5);
    assert_eq!(state.databases, before);
}

#[test]
fn control_activation_is_independent_scoped_ordered_and_failure_atomic() {
    for mut state in [
        boot(),
        CellState::bootstrap_legacy(identity(), PRINCIPAL, GENESIS, limits()).unwrap(),
    ] {
        let before = state.clone();
        assert_eq!(activate_control(&mut state).result, Err(Reject::Conflict));
        assert_eq!(state.databases, before.databases);
        assert_eq!(
            state.physical_history_version,
            before.physical_history_version
        );
    }
    let mut state = active();
    enable_retention(&mut state);
    for (cell, admin, expected) in [
        (
            CellIdentity {
                cell_id: identity().cell_id + 1,
                ..identity()
            },
            PRINCIPAL,
            Reject::Fenced,
        ),
        (identity(), PRINCIPAL + 1, Reject::Unauthorized),
    ] {
        let mut changed = state.clone();
        assert_eq!(
            apply_control_activation(&mut changed, encode_control_activation(cell, admin)).result,
            Err(expected)
        );
        assert_eq!(changed.databases, state.databases);
        assert_eq!(changed.physical_history_version(), 4);
    }
    let encoded = encode_control_activation(identity(), PRINCIPAL);
    let mut malformed = encoded.clone();
    malformed[8] = 99;
    assert_eq!(
        apply_control_activation(&mut state.clone(), malformed).result,
        Err(Reject::Invalid)
    );
    let mut small = state.clone();
    small.limits.max_command_bytes = 1;
    assert_eq!(
        apply_control_activation(&mut small, encoded).result,
        Err(Reject::TooLarge)
    );
    assert_eq!(small.physical_history_version(), 4);
    let original_last = state.last_outcome.clone();
    assert_eq!(activate_control(&mut state).result, Ok(()));
    assert_eq!(state.last_outcome, original_last);
    assert!(state.control_enabled());
    assert_eq!(
        state.databases[&database().database_id].control_receipt,
        None
    );
    assert_eq!(decode_snapshot(&state).unwrap(), state);
}

#[test]
fn control_activation_codec_checks_every_scope_position_and_truncation_boundary() {
    let encoded = encode_control_activation(identity(), PRINCIPAL);
    assert_eq!(
        codec::decode_control_activation(&encoded),
        Ok((identity(), PRINCIPAL))
    );
    for end in 0..encoded.len() {
        assert!(codec::decode_control_activation(&encoded[..end]).is_err());
    }
    for end in 0..body(&encoded).len() {
        assert!(
            codec::decode_control_activation(&envelope(&encoded, &body(&encoded)[..end])).is_err()
        );
    }
    assert!(codec::decode_control_activation(&mutate_body(&encoded, |body| body.push(0))).is_err());
    for result in [Ok(()), Err(Reject::ControlRetired)] {
        let expected = ControlActivationOutcome {
            cell: identity(),
            position: GENESIS,
            result,
        };
        let encoded = codec::encode_control_activation_outcome(&expected);
        assert_eq!(
            decode_control_activation_outcome(&encoded, identity(), GENESIS),
            Ok(expected.clone())
        );
        for end in 0..encoded.len() {
            assert!(
                decode_control_activation_outcome(&encoded[..end], identity(), GENESIS).is_err()
            );
        }
        for end in 0..body(&encoded).len() {
            assert!(decode_control_activation_outcome(
                &envelope(&encoded, &body(&encoded)[..end]),
                identity(),
                GENESIS
            )
            .is_err());
        }
        for position in [
            Position { term: 0, ..GENESIS },
            Position {
                index: 0,
                ..GENESIS
            },
            Position {
                index: GENESIS.index + 1,
                ..GENESIS
            },
        ] {
            assert_eq!(
                decode_control_activation_outcome(&encoded, identity(), position),
                Err(Error::Position)
            );
        }
        assert_eq!(
            decode_control_activation_outcome(
                &encoded,
                CellIdentity {
                    cell_id: 999,
                    ..identity()
                },
                GENESIS
            ),
            Err(Error::Binding)
        );
        for cell in [
            CellIdentity {
                cell_id: 0,
                ..identity()
            },
            CellIdentity {
                cell_incarnation: 0,
                ..identity()
            },
        ] {
            let bad = codec::encode_control_activation_outcome(&ControlActivationOutcome {
                cell,
                ..expected.clone()
            });
            assert_eq!(
                decode_control_activation_outcome(&bad, cell, GENESIS),
                Err(Error::Binding)
            );
        }
        assert!(decode_control_activation_outcome(
            &mutate_body(&encoded, |body| body[40] = 2),
            identity(),
            GENESIS
        )
        .is_err());
        assert!(decode_control_activation_outcome(
            &mutate_body(&encoded, |body| body.push(0)),
            identity(),
            GENESIS
        )
        .is_err());
        if expected.result.is_err() {
            assert!(decode_control_activation_outcome(
                &mutate_body(&encoded, |body| body[41] = 255),
                identity(),
                GENESIS
            )
            .is_err());
        }
    }
}

#[test]
fn control_wire_v4_is_used_only_for_control_commands_and_results() {
    let control = bounded(create(), 0);
    let bytes = encode_command(&control, limits()).unwrap();
    assert_eq!(bytes[8], 4);
    assert_eq!(codec::decode_command(&bytes, limits()), Ok(control));
    for end in 0..body(&bytes).len() {
        assert!(codec::decode_command(&envelope(&bytes, &body(&bytes)[..end]), limits()).is_err());
    }
    assert_eq!(encode_command(&create(), limits()).unwrap()[8], 2);
    let mut scoped = cancel(1);
    scoped.admission.request_epoch = 2;
    assert_eq!(encode_command(&scoped, limits()).unwrap()[8], 3);
    assert_eq!(
        encode_applied_outcome(&AppliedOutcome {
            position: GENESIS,
            outcome: Outcome::RequestAcknowledged
        })[8],
        3
    );
    assert_eq!(
        encode_applied_outcome(&AppliedOutcome {
            position: GENESIS,
            outcome: Outcome::Administrative(AdminResult::Created)
        })[8],
        2
    );
    let result = ControlResult {
        revision: 7,
        position: GENESIS,
        result: AdminResult::ArchiveHydrated([2; 32]),
    };
    for outcome in [
        Outcome::ControlApplied(result.clone()),
        Outcome::ControlAlreadyApplied(result),
        Outcome::Rejected(Reject::ControlRetired),
    ] {
        let expected = AppliedOutcome {
            position: GENESIS,
            outcome,
        };
        let bytes = encode_applied_outcome(&expected);
        assert_eq!(bytes[8], 4);
        assert_eq!(decode_applied_outcome(&bytes, GENESIS), Ok(expected));
        for end in 0..body(&bytes).len() {
            assert!(
                decode_applied_outcome(&envelope(&bytes, &body(&bytes)[..end]), GENESIS).is_err()
            );
        }
        for version in [1, 2, 3] {
            let mut old = bytes.clone();
            old[8] = version;
            old = envelope(&old, body(&bytes));
            assert_eq!(
                decode_applied_outcome(&old, GENESIS),
                Err(Error::Malformed("control outcome in legacy envelope"))
            );
        }
    }
    let mut legacy = active();
    legacy.last_outcome.as_mut().unwrap().outcome = Outcome::Rejected(Reject::ControlRetired);
    assert_eq!(
        decode_snapshot(&legacy),
        Err(Error::Malformed("control outcome in legacy state"))
    );
}

#[test]
fn bounded_snapshot_validation_rejects_bad_sequence_receipt_identity_and_positions() {
    let state = active_control();
    let id = database().database_id;
    for case in 0..11 {
        let mut corrupt = state.clone();
        let db = corrupt.databases.get_mut(&id).unwrap();
        match case {
            0 => db.control_revision = Some(0),
            1 => db.control_receipt.as_mut().unwrap().operation_id = 0,
            2 => db.control_receipt.as_mut().unwrap().admission.principal_id = 0,
            3 => db.control_receipt.as_mut().unwrap().admission.credential_id = 0,
            4 => db.control_receipt.as_mut().unwrap().admission.admission_id = 0,
            5 => db.control_receipt.as_mut().unwrap().admission.auth_epoch = 2,
            6 => db.control_receipt.as_mut().unwrap().result.revision = 0,
            7 => db.control_receipt.as_mut().unwrap().result.position.index = 0,
            8 => db.control_receipt.as_mut().unwrap().result.position.index += 100,
            9 => db.control_receipt.as_mut().unwrap().result.position.term = 0,
            10 => {
                db.control_receipt.as_mut().unwrap().result.result =
                    AdminResult::OwnerClaimed(OwnerToken {
                        epoch: 0,
                        worker_instance_id: WORKER,
                    })
            }
            _ => unreachable!(),
        }
        assert!(decode_snapshot(&corrupt).is_err(), "case {case}");
    }
    let mut corrupt = state.clone();
    corrupt.databases.get_mut(&id).unwrap().control_receipt = None;
    assert_eq!(
        decode_snapshot(&corrupt),
        Err(Error::Malformed("control revision lost its receipt"))
    );
    let mut corrupt = state.clone();
    corrupt.databases.get_mut(&id).unwrap().control_revision = None;
    assert_eq!(
        validate_state(&corrupt),
        Err(Error::Malformed("invalid control activation state"))
    );
    let mut corrupt = active();
    corrupt.databases.get_mut(&id).unwrap().control_revision = Some(0);
    assert_eq!(
        validate_state(&corrupt),
        Err(Error::Malformed("invalid control activation state"))
    );
    for applied in [true, false] {
        let mut corrupt = state.clone();
        let mut result = corrupt.databases[&id]
            .control_receipt
            .as_ref()
            .unwrap()
            .result
            .clone();
        result.revision += 1;
        corrupt.last_outcome.as_mut().unwrap().outcome = if applied {
            Outcome::ControlApplied(result)
        } else {
            Outcome::ControlAlreadyApplied(result)
        };
        assert_eq!(
            decode_snapshot(&corrupt),
            Err(Error::Malformed("outcome has no matching durable record"))
        );
    }
    let mut corrupt = state.clone();
    corrupt.last_outcome.as_mut().unwrap().position.index += 1;
    corrupt.position.index += 1;
    assert_eq!(
        decode_snapshot(&corrupt),
        Err(Error::Malformed("outcome has no matching durable record"))
    );
    let bytes = state.encode();
    for end in 0..body(&bytes).len() {
        assert!(CellState::decode_bound(
            &envelope(&bytes, &body(&bytes)[..end]),
            identity(),
            state.position,
            state.limits
        )
        .is_err());
    }
}

#[test]
fn archives_stay_v4_and_old_physical_objects_never_replace_control_metadata() {
    // v2, v3 and v4 were all production object formats. Upgrade after prune,
    // then hydrate their exact published bytes under the new control namespace.
    for version in [2, 3, 4] {
        let mut state = active();
        state.physical_history_version = version;
        apply(&mut state, &write(1, 0));
        if version == 4 {
            state = decode_snapshot(&state).unwrap();
        }
        let (mut state, archive, bytes) = published(state);
        assert_eq!(bytes[8], version);
        let pruned = command(CommandKind::PruneArchive {
            operation_id: operation(12),
            expected_owner: state.database(database().database_id).unwrap().owner,
            archive_digest: archive.object_digest,
        });
        assert!(matches!(
            apply(&mut state, &pruned),
            Outcome::Administrative(AdminResult::ArchivePruned(_))
        ));
        if version == 2 {
            assert_eq!(activate_history(&mut state).result, Ok(()));
        }
        enable_retention(&mut state);
        assert_eq!(activate_control(&mut state).result, Ok(()));
        let before = state.database(database().database_id).unwrap();
        let hydrated = bounded(
            command(CommandKind::HydrateArchive {
                operation_id: operation(13),
                archive: bytes,
            }),
            0,
        );
        let result = confirmed(
            &mut state,
            &hydrated,
            AdminResult::ArchiveHydrated(archive.object_digest),
        );
        let after = state.database(database().database_id).unwrap();
        assert_eq!(after.owner, before.owner);
        assert_eq!(after.auth_epoch, before.auth_epoch);
        assert_eq!(after.request_epoch, before.request_epoch);
        assert_eq!(after.control_revision, Some(1));
        assert!(!after.cold);
        exact_replay(&mut state, &hydrated, &result);
        // A pinned legacy prune can still report its old success but cannot
        // remove the newly restored bytes or roll back the v5 sequence.
        assert!(matches!(
            apply(&mut state, &pruned),
            Outcome::AlreadyApplied(AdminResult::ArchivePruned(_))
        ));
        assert!(!state.database(database().database_id).unwrap().cold);
        assert_eq!(
            state
                .database(database().database_id)
                .unwrap()
                .control_revision,
            Some(1)
        );
        let (_, current_bytes) = state.archive_snapshot(database(), admission()).unwrap();
        assert_eq!(current_bytes[8], 4);
        let mut fake_v5 = current_bytes.clone();
        fake_v5[8] = 5;
        fake_v5 = envelope(&fake_v5, body(&current_bytes));
        assert!(codec::decode_archive(
            &fake_v5,
            identity(),
            &state.databases[&database().database_id],
            archive,
            limits(),
            5
        )
        .is_err());
    }
}

#[test]
fn failed_action_conditions_do_not_consume_a_control_sequence_or_replace_receipt() {
    let state = active_control();
    let archive = ArchiveRef {
        source: state.position,
        revision: 0,
        commit_hash: [0; 32],
        object_digest: [1; 32],
        object_bytes: 1,
        metadata_digest: [2; 32],
    };
    let owner = state.database(database().database_id).unwrap().owner;
    for (command, reason) in [
        (create(), Reject::Exists),
        (claim(0, WORKER, 10), Reject::Fenced),
        (activate(1, WORKER, 11, 1, [1; 32]), Reject::Conflict),
        (
            command(CommandKind::AuthFence {
                operation_id: operation(12),
                expected_epoch: 2,
                policy: policy(),
            }),
            Reject::Conflict,
        ),
        (
            command(CommandKind::SuspendDb {
                operation_id: operation(13),
                token: owner,
                expected_revision: 1,
            }),
            Reject::Conflict,
        ),
        (
            command(CommandKind::PublishArchive {
                operation_id: operation(14),
                expected_owner: owner,
                expected_previous: None,
                archive,
            }),
            Reject::Fenced,
        ),
        (
            command(CommandKind::PruneArchive {
                operation_id: operation(15),
                expected_owner: owner,
                archive_digest: archive.object_digest,
            }),
            Reject::NotFound,
        ),
        (
            command(CommandKind::HydrateArchive {
                operation_id: operation(16),
                archive: Vec::new(),
            }),
            Reject::NotFound,
        ),
    ] {
        rejected_without_mutation(&state, &bounded(command, 3), reason);
    }
    let mut earlier_outcome = state.clone();
    earlier_outcome
        .last_outcome
        .as_mut()
        .unwrap()
        .position
        .index -= 1;
    assert_eq!(
        decode_snapshot(&earlier_outcome),
        Err(Error::Malformed("outcome has no matching durable record"))
    );
    let mut no_receipt = active();
    enable_retention(&mut no_receipt);
    assert_eq!(activate_control(&mut no_receipt).result, Ok(()));
    no_receipt.last_outcome = Some(AppliedOutcome {
        position: no_receipt.position,
        outcome: Outcome::ControlAlreadyApplied(ControlResult {
            revision: 1,
            position: no_receipt.position,
            result: AdminResult::Created,
        }),
    });
    assert_eq!(
        decode_snapshot(&no_receipt),
        Err(Error::Malformed("outcome has no matching durable record"))
    );
}

#[test]
fn returned_control_receipts_bind_nonzero_revision_and_original_durable_position() {
    let enclosing = Position { term: 4, index: 12 };
    for applied in [true, false] {
        for (revision, original, valid) in [
            (1, enclosing, true),
            (0, enclosing, false),
            (
                1,
                Position {
                    term: 0,
                    ..enclosing
                },
                false,
            ),
            (
                1,
                Position {
                    index: 0,
                    ..enclosing
                },
                false,
            ),
            (
                1,
                Position {
                    index: 13,
                    ..enclosing
                },
                false,
            ),
            (1, Position { term: 5, index: 11 }, false),
            (
                1,
                Position {
                    term: 3,
                    ..enclosing
                },
                false,
            ),
            (1, Position { term: 3, index: 10 }, !applied),
        ] {
            let result = ControlResult {
                revision,
                position: original,
                result: AdminResult::Created,
            };
            let expected = AppliedOutcome {
                position: enclosing,
                outcome: if applied {
                    Outcome::ControlApplied(result)
                } else {
                    Outcome::ControlAlreadyApplied(result)
                },
            };
            let encoded = encode_applied_outcome(&expected);
            let decoded = decode_applied_outcome(&encoded, enclosing);
            if valid {
                assert_eq!(decoded, Ok(expected));
            } else {
                assert_eq!(
                    decoded,
                    Err(Error::Malformed("invalid control result proof"))
                );
            }
        }
    }
}

#[test]
fn archive_publication_and_upgrade_reserve_the_full_control_hydration_envelope() {
    let mut legacy = active();
    enable_retention(&mut legacy);
    apply(&mut legacy, &write(1, 0));
    let (published, archive, bytes) = published(legacy);
    let transactions = published.databases[&database().database_id]
        .transactions
        .clone();
    let prune = command(CommandKind::PruneArchive {
        operation_id: operation(12),
        expected_owner: published.database(database().database_id).unwrap().owner,
        archive_digest: archive.object_digest,
    });
    let hydrate = command(CommandKind::HydrateArchive {
        operation_id: operation(13),
        archive: bytes.clone(),
    });
    // Both an already cold object and a hot reference that could later be pruned
    // must pass the future command envelope check before the phase can advance.
    for cold in [false, true] {
        let mut legacy = published.clone();
        if cold {
            assert_eq!(
                apply(&mut legacy, &prune),
                Outcome::Administrative(AdminResult::ArchivePruned(archive.object_digest))
            );
        }
        for reserve in [192, 201] {
            let mut refused = legacy.clone();
            refused.limits.max_command_bytes = bytes.len() as u32 + reserve;
            refused = decode_snapshot(&refused).unwrap();
            let before = refused.databases.clone();
            assert_eq!(activate_control(&mut refused).result, Err(Reject::Capacity));
            assert_eq!(refused.physical_history_version(), 4);
            assert_eq!(refused.databases, before);
            assert_eq!(
                encode_command(&bounded(hydrate.clone(), 0), refused.limits),
                Err(Error::Limit)
            );
            // Refusing activation preserves the complete old lifecycle path.
            if !cold {
                assert_eq!(
                    apply(&mut refused, &prune),
                    Outcome::Administrative(AdminResult::ArchivePruned(archive.object_digest))
                );
            }
            assert_eq!(
                apply(&mut refused, &hydrate),
                Outcome::Administrative(AdminResult::ArchiveHydrated(archive.object_digest))
            );
            assert_eq!(
                refused.databases[&database().database_id].transactions,
                transactions
            );
        }
        // At exactly the new envelope size, either old residency can upgrade
        // and complete the bounded control lifecycle without enlarging limits.
        legacy.limits.max_command_bytes = bytes.len() as u32 + 202;
        legacy = decode_snapshot(&legacy).unwrap();
        assert_eq!(activate_control(&mut legacy).result, Ok(()));
        assert_eq!(
            legacy
                .database(database().database_id)
                .unwrap()
                .control_revision,
            Some(0)
        );
        if !cold {
            confirmed(
                &mut legacy,
                &bounded(prune.clone(), 0),
                AdminResult::ArchivePruned(archive.object_digest),
            );
        }
        let hydrate = bounded(hydrate.clone(), u64::from(!cold));
        assert_eq!(
            encode_command(&hydrate, legacy.limits).unwrap().len(),
            legacy.limits.max_command_bytes as usize
        );
        confirmed(
            &mut legacy,
            &hydrate,
            AdminResult::ArchiveHydrated(archive.object_digest),
        );
        assert_eq!(
            legacy.databases[&database().database_id].transactions,
            transactions
        );
    }

    let mut state = active_control();
    apply(&mut state, &write(1, 0));
    let suspended = bounded(suspend(&state, operation(4)), 3);
    confirmed(&mut state, &suspended, AdminResult::Suspended(2));
    let (archive, bytes) = state.archive_snapshot(database(), admission()).unwrap();
    state.limits.max_command_bytes = bytes.len() as u32 + 201;
    state = decode_snapshot(&state).unwrap();
    assert_eq!(
        state.archive_snapshot(database(), admission()),
        Err(Reject::TooLarge)
    );
    let publish = bounded(
        command(CommandKind::PublishArchive {
            operation_id: operation(5),
            expected_owner: state.database(database().database_id).unwrap().owner,
            expected_previous: None,
            archive,
        }),
        4,
    );
    rejected_without_mutation(&state, &publish, Reject::Invalid);
    state.limits.max_command_bytes += 1;
    let (archive, bytes) = state.archive_snapshot(database(), admission()).unwrap();
    let publish = bounded(
        command(CommandKind::PublishArchive {
            operation_id: operation(5),
            expected_owner: state.database(database().database_id).unwrap().owner,
            expected_previous: None,
            archive,
        }),
        4,
    );
    confirmed(
        &mut state,
        &publish,
        AdminResult::ArchivePublished(archive.object_digest),
    );
    let prune = bounded(
        command(CommandKind::PruneArchive {
            operation_id: operation(6),
            expected_owner: state.database(database().database_id).unwrap().owner,
            archive_digest: archive.object_digest,
        }),
        5,
    );
    confirmed(
        &mut state,
        &prune,
        AdminResult::ArchivePruned(archive.object_digest),
    );
    let hydrate = bounded(
        command(CommandKind::HydrateArchive {
            operation_id: operation(7),
            archive: bytes,
        }),
        6,
    );
    assert_eq!(
        encode_command(&hydrate, state.limits).unwrap().len(),
        state.limits.max_command_bytes as usize
    );
    confirmed(
        &mut state,
        &hydrate,
        AdminResult::ArchiveHydrated(archive.object_digest),
    );
    let mut bad_snapshot = state.clone();
    bad_snapshot.limits.max_command_bytes -= 1;
    assert_eq!(
        decode_snapshot(&bad_snapshot),
        Err(Error::Malformed("invalid archive reference"))
    );
}
