use super::history::{
    from_hex, legacy_admission, legacy_apply, legacy_cell, legacy_database, legacy_limits,
    legacy_recovered_image,
};
use super::*;

fn canonical_limits() -> Limits {
    Limits {
        max_command_bytes: 65_536,
        max_requests_per_database: 64,
        ..legacy_limits()
    }
}

fn legacy_state(bytes: &[u8], index: u64, limits: Limits) -> CellState {
    CellState::decode_bound(bytes, legacy_cell(), Position { term: 1, index }, limits).unwrap()
}

fn canonical_splits(
    prefixes: &str,
    commands: &str,
    archive: &str,
    cold: &str,
    base_revision: u64,
    image: &[u8],
) {
    let prefixes: Vec<_> = prefixes.lines().map(from_hex).collect();
    let commands: Vec<_> = commands.lines().map(from_hex).collect();
    assert_eq!(commands.len(), (prefixes.len() - 1) * 2);
    let index = 5 + commands.len() as u64;
    let full = prefixes.last().unwrap();
    let mut canonical = legacy_state(full, index, canonical_limits());
    assert_eq!(canonical.physical_history_version(), 2);
    assert_eq!(canonical.encode(), *full);
    assert_eq!(canonical.database(9).unwrap().base_revision, 0);
    let prior = canonical.clone();
    assert_eq!(activate_history(&mut canonical).result, Ok(()));
    let view = canonical.database(9).unwrap();
    assert_eq!(view.base_revision, base_revision);
    assert_eq!(view.tail_entries, 1);
    assert_eq!(canonical.last_outcome, prior.last_outcome);
    assert_eq!(canonical.administration, prior.administration);
    assert_eq!(
        canonical.databases[&9].requests,
        prior.databases[&9].requests
    );
    assert_eq!(legacy_recovered_image(&canonical, 1).bytes(), image);
    for (split, prefix) in prefixes.iter().enumerate() {
        let decoded = legacy_state(prefix, 5 + 2 * split as u64, canonical_limits());
        assert_eq!(decoded.encode(), *prefix, "legacy prefix {split}");
        let suffix: Vec<_> = commands
            .iter()
            .enumerate()
            .skip(split * 2)
            .map(|(offset, data)| Entry {
                term: 1,
                index: 6 + offset as u64,
                data: data.clone().into(),
                ..Entry::default()
            })
            .collect();
        let caught_up = CellApplication::new(legacy_cell(), canonical_limits())
            .unwrap()
            .apply(prefix, &suffix)
            .unwrap();
        // Before activation even the complete legacy bytes must agree, not
        // merely the head or successful requests.
        assert_eq!(&caught_up, full, "legacy suffix after prefix {split}");
        let mut upgraded = legacy_state(&caught_up, index, canonical_limits());
        assert_eq!(activate_history(&mut upgraded).result, Ok(()));
        assert_eq!(
            upgraded.encode(),
            canonical.encode(),
            "activation at {split}"
        );
        assert_eq!(
            upgraded.archive_snapshot(legacy_database(), legacy_admission(1)),
            canonical.archive_snapshot(legacy_database(), legacy_admission(1)),
            "canonical archive after prefix {split}"
        );
    }
    for (index, transaction) in prior.databases[&9].transactions.iter().enumerate() {
        assert_eq!(
            canonical.lookup(
                legacy_database(),
                legacy_admission(1),
                101 + index as u128,
                [(index + 1) as u8; 32]
            ),
            Ok(Lookup::Committed {
                commit: transaction.commit.clone(),
                result: transaction.result.clone()
            })
        );
    }
    for cancelled in 0..prefixes.len() {
        assert!(matches!(
            canonical.lookup(
                legacy_database(),
                legacy_admission(1),
                1000 + cancelled as u128,
                [cancelled as u8; 32]
            ),
            Ok(Lookup::Cancelled { .. })
        ));
    }
    let mut restored = legacy_state(&from_hex(cold), index + 3, canonical_limits());
    let old_archive = restored.database(9).unwrap().archive.unwrap();
    let archive = from_hex(archive);
    assert_eq!(old_archive.object_digest, payload_digest(&archive));
    assert_eq!(activate_history(&mut restored).result, Ok(()));
    assert_eq!(restored.database(9).unwrap().base_revision, 0);
    assert!(matches!(
        legacy_apply(
            &mut restored,
            1,
            CommandKind::HydrateArchive {
                operation_id: 40,
                archive,
            }
        ),
        Outcome::Administrative(AdminResult::ArchiveHydrated(_))
    ));
    assert_eq!(restored.databases[&9].base, canonical.databases[&9].base);
    assert_eq!(
        restored.databases[&9].transactions,
        canonical.databases[&9].transactions
    );
    assert_eq!(restored.database(9).unwrap().archive, Some(old_archive));
    assert_eq!(legacy_recovered_image(&restored, 1).bytes(), image);
}

#[test]
fn every_real_v2_entry_prefix_replays_before_one_canonical_activation() {
    canonical_splits(
        include_str!("../../test-fixtures/canonical-entry-prefixes-v2.hex"),
        include_str!("../../test-fixtures/canonical-entry-commands-v2.hex"),
        include_str!("../../test-fixtures/canonical-entry-archive-v2.hex"),
        include_str!("../../test-fixtures/canonical-entry-cold-v2.hex"),
        16,
        &[],
    );
}

#[test]
fn every_real_v2_byte_prefix_replays_before_one_canonical_activation() {
    canonical_splits(
        include_str!("../../test-fixtures/canonical-bytes-prefixes-v2.hex"),
        include_str!("../../test-fixtures/canonical-bytes-commands-v2.hex"),
        include_str!("../../test-fixtures/canonical-bytes-archive-v2.hex"),
        include_str!("../../test-fixtures/canonical-bytes-cold-v2.hex"),
        8,
        &from_hex(include_str!(
            "../../test-fixtures/canonical-bytes-image.hex"
        )),
    );
}

fn recorded_legacy_log(
    genesis: &str,
    commands: &str,
    outcomes: &str,
    digests: &str,
    final_state: &str,
    limits: Limits,
) -> (CellState, Vec<Vec<u8>>) {
    let mut state = legacy_state(&from_hex(genesis), 1, limits);
    let commands: Vec<_> = commands.lines().map(from_hex).collect();
    let outcomes: Vec<_> = outcomes.lines().map(from_hex).collect();
    let digests: Vec<_> = digests.lines().map(from_hex).collect();
    assert_eq!(commands.len(), outcomes.len());
    assert_eq!(commands.len(), digests.len());
    for (index, data) in commands.iter().enumerate() {
        let position = Position {
            term: 1,
            index: 2 + index as u64,
        };
        let entry = Entry {
            term: 1,
            index: position.index,
            data: data.clone().into(),
            ..Entry::default()
        };
        let applied = CellApplication::new(legacy_cell(), limits)
            .unwrap()
            .apply_with_results(&state.encode(), &[entry], &[position.index])
            .unwrap();
        assert_eq!(
            applied.results,
            vec![outcomes[index].clone()],
            "old outcome at {position:?}"
        );
        assert_eq!(
            payload_digest(&applied.state).as_slice(),
            digests[index],
            "old bytes at {position:?}"
        );
        state = legacy_state(&applied.state, position.index, limits);
        assert_eq!(state.physical_history_version(), 2);
        assert_eq!(state.database(9).unwrap().base_revision, 0);
    }
    assert_eq!(state.encode(), from_hex(final_state));
    (state, commands)
}

#[test]
fn old_capacity_rejections_remain_rejections_until_the_durable_activation() {
    let (mut state, commands) = recorded_legacy_log(
        include_str!("../../test-fixtures/legacy-capacity-genesis-v2.hex"),
        include_str!("../../test-fixtures/legacy-capacity-commands-v2.hex"),
        include_str!("../../test-fixtures/legacy-capacity-outcomes-v2.hex"),
        include_str!("../../test-fixtures/legacy-capacity-state-sha256-v2.hex"),
        include_str!("../../test-fixtures/legacy-capacity-final-v2.hex"),
        Limits {
            max_state_bytes: 16_384,
            ..canonical_limits()
        },
    );
    assert_eq!(state.database(9).unwrap().revision, 3);
    assert_eq!(
        state.last_outcome.as_ref().unwrap().outcome,
        Outcome::Rejected(Reject::Capacity)
    );
    for request in 104..=109 {
        assert_eq!(
            state.lookup(
                legacy_database(),
                legacy_admission(1),
                request,
                [(request - 100) as u8; 32]
            ),
            Ok(Lookup::Unknown)
        );
    }
    let records = state.databases[&9].requests.clone();
    assert_eq!(activate_history(&mut state).result, Ok(()));
    assert_eq!(state.database(9).unwrap().base_revision, 3);
    assert_eq!(state.databases[&9].requests, records);
    assert_eq!(legacy_recovered_image(&state, 1).bytes()[100], 3);
    // This explicit new attempt is after activation. It proves the old
    // capacity decisions above were preserved despite the newly freed bytes.
    let rejected = codec::decode_command(&commands[7], state.limits).unwrap();
    assert!(matches!(
        legacy_apply(&mut state, 1, rejected.kind),
        Outcome::Accepted(_)
    ));
    assert_eq!(state.database(9).unwrap().revision, 4);
}

#[test]
fn old_publish_prune_auth_cancel_and_hydrate_suffixes_keep_exact_v2_outcomes() {
    let (mut state, commands) = recorded_legacy_log(
        include_str!("../../test-fixtures/legacy-lifecycle-genesis-v2.hex"),
        include_str!("../../test-fixtures/legacy-lifecycle-commands-v2.hex"),
        include_str!("../../test-fixtures/legacy-lifecycle-outcomes-v2.hex"),
        include_str!("../../test-fixtures/legacy-lifecycle-state-sha256-v2.hex"),
        include_str!("../../test-fixtures/legacy-lifecycle-final-v2.hex"),
        canonical_limits(),
    );
    let old_archive = state.database(9).unwrap().archive.unwrap();
    let records = state.databases[&9].requests.clone();
    let admission = legacy_admission(2);
    let first = state
        .lookup(legacy_database(), admission, 101, [1; 32])
        .unwrap();
    let CommandKind::HydrateArchive { archive, .. } =
        codec::decode_command(commands.last().unwrap(), state.limits)
            .unwrap()
            .kind
    else {
        panic!("old hydrate fixture")
    };
    assert_eq!(archive[8], 2);
    assert_eq!(activate_history(&mut state).result, Ok(()));
    assert_eq!(state.database(9).unwrap().base_revision, 8);
    assert_eq!(state.database(9).unwrap().tail_entries, 1);
    assert_eq!(state.databases[&9].requests, records);
    assert_eq!(
        state
            .lookup(legacy_database(), admission, 101, [1; 32])
            .unwrap(),
        first
    );
    assert!(matches!(
        state.lookup(legacy_database(), admission, 1001, [1; 32]),
        Ok(Lookup::Cancelled { .. })
    ));
    let owner = state.database(9).unwrap().owner;
    assert!(matches!(
        legacy_apply(
            &mut state,
            2,
            CommandKind::PruneArchive {
                operation_id: 50,
                expected_owner: owner,
                archive_digest: old_archive.object_digest,
            }
        ),
        Outcome::Administrative(_)
    ));
    assert!(matches!(
        legacy_apply(
            &mut state,
            2,
            CommandKind::HydrateArchive {
                operation_id: 51,
                archive,
            }
        ),
        Outcome::Administrative(_)
    ));
    assert_eq!(state.databases[&9].requests, records);
    assert_eq!(state.database(9).unwrap().archive, Some(old_archive));
    assert_eq!(state.database(9).unwrap().base_revision, 8);
    assert_eq!(legacy_recovered_image(&state, 2).bytes()[100], 9);
}

fn rejected_activation(state: &mut CellState, data: Vec<u8>, reason: Reject) {
    let mut expected = state.clone();
    expected.position.index += 1;
    let result = apply_activation(state, data);
    assert_eq!(result.result, Err(reason));
    assert_eq!(result.position, expected.position);
    assert_eq!(*state, expected);
}

#[test]
fn activation_checks_scope_administrator_size_and_codec_before_changing_phase() {
    let mut state = CellState::bootstrap_legacy(identity(), PRINCIPAL, GENESIS, limits()).unwrap();
    rejected_activation(
        &mut state,
        encode_history_activation(
            CellIdentity {
                cell_id: 88,
                ..identity()
            },
            PRINCIPAL,
        ),
        Reject::Fenced,
    );
    rejected_activation(
        &mut state,
        encode_history_activation(identity(), PRINCIPAL + 1),
        Reject::Unauthorized,
    );
    let valid = encode_history_activation(identity(), PRINCIPAL);
    let mut checksum = valid.clone();
    checksum[20] ^= 1;
    rejected_activation(&mut state, checksum, Reject::Invalid);
    for version in [0, 2] {
        let mut bytes = valid.clone();
        bytes[8] = version;
        rejected_activation(&mut state, envelope(&bytes, body(&bytes)), Reject::Invalid);
    }
    rejected_activation(
        &mut state,
        mutate_body(&valid, |bytes| bytes.push(0)),
        Reject::Invalid,
    );
    state.limits.max_command_bytes = valid.len() as u32 - 1;
    rejected_activation(&mut state, valid, Reject::TooLarge);
    assert_eq!(state.physical_history_version(), 2);
}

#[test]
fn activation_keeps_all_databases_legacy_if_one_recovery_is_invalid() {
    let mut state = CellState::bootstrap_legacy(identity(), PRINCIPAL, GENESIS, limits()).unwrap();
    apply(&mut state, &create());
    apply(&mut state, &claim(0, WORKER, 2));
    apply(&mut state, &activate(1, WORKER, 3, 0, [0; 32]));
    for request in 1..=8 {
        apply(&mut state, &write(request, request as u64 - 1));
    }
    let other = DatabaseIdentity {
        database_id: database().database_id + 1,
        ..database()
    };
    for mut command in [
        command(CommandKind::Create {
            operation_id: operation(100),
            policy: policy(),
        }),
        claim(0, WORKER, 101),
        activate(1, WORKER, 102, 0, [0; 32]),
    ] {
        command.database = other;
        assert!(matches!(
            apply(&mut state, &command),
            Outcome::Administrative(_)
        ));
    }
    let mut opaque = write(1, 0);
    opaque.database = other;
    commit_parts(&mut opaque).0.ticket.database_id = other.database_id;
    // Legacy acceptance checks the opaque digest but does not replay SCAPIMG.
    assert!(matches!(apply(&mut state, &opaque), Outcome::Accepted(_)));
    rejected_activation(
        &mut state,
        encode_history_activation(identity(), PRINCIPAL),
        Reject::Invalid,
    );
    assert_eq!(
        state
            .database(database().database_id)
            .unwrap()
            .base_revision,
        0
    );
    assert_eq!(
        state.database(database().database_id).unwrap().tail_entries,
        8
    );
    assert_eq!(apply(&mut state, &cancel(12)), Outcome::Cancelled);
}

#[test]
fn activation_does_not_expand_the_old_exact_state_budget() {
    let mut state = CellState::bootstrap_legacy(identity(), PRINCIPAL, GENESIS, limits()).unwrap();
    apply(&mut state, &create());
    apply(&mut state, &claim(0, WORKER, 2));
    apply(&mut state, &activate(1, WORKER, 3, 0, [0; 32]));
    state.limits.max_state_bytes =
        (codec::encode_state(&state, false).len() + RESERVED_BYTES) as u32;
    assert!(state.limits.max_state_bytes >= 1024);
    assert!(state.fits());
    rejected_activation(
        &mut state,
        encode_history_activation(identity(), PRINCIPAL),
        Reject::Capacity,
    );
    assert_eq!(state.encode()[8], 2);
}

#[test]
fn activation_rejects_a_legacy_budget_that_cannot_hold_one_physical_page() {
    let mut state = CellState::bootstrap_legacy(
        identity(),
        PRINCIPAL,
        GENESIS,
        Limits {
            max_state_bytes: 3072,
            ..limits()
        },
    )
    .unwrap();
    apply(&mut state, &create());
    apply(&mut state, &claim(0, WORKER, 2));
    apply(&mut state, &activate(1, WORKER, 3, 0, [0; 32]));
    assert!(matches!(
        apply(&mut state, &write(1, 0)),
        Outcome::Accepted(_)
    ));
    rejected_activation(
        &mut state,
        encode_history_activation(identity(), PRINCIPAL),
        Reject::Capacity,
    );
    assert_eq!(state.physical_history_version(), 2);
    assert_eq!(state.database(database().database_id).unwrap().revision, 1);
}

#[test]
fn internal_result_is_exact_and_cannot_be_confused_with_a_business_outcome() {
    let mut state = active();
    let before = state.clone();
    assert_eq!(state.physical_history_version(), 3);
    let activated = activate_history(&mut state);
    assert_eq!(activated.result, Ok(()));
    assert_eq!(state.databases, before.databases);
    assert_eq!(state.last_outcome, before.last_outcome);
    let bytes = codec::encode_history_activation_outcome(&activated);
    assert_eq!(
        decode_history_activation_outcome(&bytes, identity(), activated.position).unwrap(),
        activated
    );
    assert!(decode_applied_outcome(&bytes, activated.position).is_err());
    assert!(decode_history_activation_outcome(
        &encode_applied_outcome(before.last_outcome.as_ref().unwrap()),
        identity(),
        activated.position
    )
    .is_err());
    for expected in [
        Position {
            term: 0,
            ..activated.position
        },
        Position {
            index: 0,
            ..activated.position
        },
        Position {
            index: activated.position.index + 1,
            ..activated.position
        },
    ] {
        assert_eq!(
            decode_history_activation_outcome(&bytes, identity(), expected),
            Err(Error::Position)
        );
    }
    assert_eq!(
        decode_history_activation_outcome(
            &bytes,
            CellIdentity {
                cell_id: 999,
                ..identity()
            },
            activated.position
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
        let invalid = codec::encode_history_activation_outcome(&HistoryActivationOutcome {
            cell,
            ..activated.clone()
        });
        assert_eq!(
            decode_history_activation_outcome(&invalid, cell, activated.position),
            Err(Error::Binding)
        );
    }
    for end in 0..bytes.len() {
        assert!(
            decode_history_activation_outcome(&bytes[..end], identity(), activated.position)
                .is_err()
        );
    }
    // A valid outer checksum/length must not make truncated inner scope or
    // position fields acceptable.
    for end in 0..40 {
        assert!(decode_history_activation_outcome(
            &envelope(&bytes, &body(&bytes)[..end]),
            identity(),
            activated.position,
        )
        .is_err());
    }
    assert!(decode_history_activation_outcome(
        &mutate_body(&bytes, |body| body[40] = 2),
        identity(),
        activated.position
    )
    .is_err());
    assert!(decode_history_activation_outcome(
        &mutate_body(&bytes, |body| body.push(0)),
        identity(),
        activated.position
    )
    .is_err());
    let rejected = codec::encode_history_activation_outcome(&HistoryActivationOutcome {
        result: Err(Reject::Invalid),
        ..activated.clone()
    });
    assert!(decode_history_activation_outcome(
        &mutate_body(&rejected, |body| body[41] = 255),
        identity(),
        activated.position
    )
    .is_err());
    let command = encode_history_activation(identity(), PRINCIPAL);
    for end in 0..command.len() {
        assert!(codec::decode_history_activation(&command[..end]).is_err());
    }
    for end in 0..body(&command).len() {
        assert!(
            codec::decode_history_activation(&envelope(&command, &body(&command)[..end]),).is_err()
        );
    }
    assert!(
        codec::decode_history_activation(&encode_command(&create(), limits()).unwrap()).is_err()
    );
}

#[test]
fn tracked_activation_and_business_results_stay_bound_to_their_own_indices() {
    let state = CellState::bootstrap_legacy(identity(), PRINCIPAL, GENESIS, limits()).unwrap();
    let activation = Entry {
        term: GENESIS.term,
        index: GENESIS.index + 1,
        data: encode_history_activation(identity(), PRINCIPAL).into(),
        ..Entry::default()
    };
    let create = Entry {
        term: GENESIS.term,
        index: GENESIS.index + 2,
        data: encode_command(&create(), limits()).unwrap().into(),
        ..Entry::default()
    };
    let mut app = CellApplication::new(identity(), limits()).unwrap();
    let batch = app
        .apply_with_results(
            &state.encode(),
            &[activation.clone(), create.clone()],
            &[activation.index, create.index],
        )
        .unwrap();
    assert_eq!(batch.results.len(), 2);
    assert_eq!(
        decode_history_activation_outcome(
            &batch.results[0],
            identity(),
            Position {
                term: activation.term,
                index: activation.index
            }
        )
        .unwrap()
        .result,
        Ok(())
    );
    assert!(matches!(
        decode_applied_outcome(
            &batch.results[1],
            Position {
                term: create.term,
                index: create.index
            }
        )
        .unwrap()
        .outcome,
        Outcome::Administrative(AdminResult::Created)
    ));
    let only_business = app
        .apply_with_results(
            &state.encode(),
            &[activation, create.clone()],
            &[create.index],
        )
        .unwrap();
    assert_eq!(only_business.state, batch.state);
    assert_eq!(only_business.results, vec![batch.results[1].clone()]);
}

#[test]
fn legacy_genesis_is_byte_identical_to_the_real_old_service_and_new_bootstrap_is_explicit() {
    let limits = Limits {
        max_state_bytes: 8_388_608,
        max_command_bytes: 4_194_304,
        max_databases: 32,
        max_policy_grants: 33,
        max_admin_operations: 4096,
        max_requests_per_database: 128,
        max_transaction_bytes: 307_200,
        max_result_bytes: 65_536,
    };
    let position = Position { term: 1, index: 1 };
    let legacy = CellState::bootstrap_legacy(legacy_cell(), 12, position, limits).unwrap();
    assert_eq!(
        legacy.encode(),
        from_hex(include_str!("../../test-fixtures/server-genesis-v2.hex"))
    );
    assert_eq!(legacy.physical_history_version(), 2);
    assert_eq!(
        CellState::bootstrap(legacy_cell(), 12, position, limits)
            .unwrap()
            .physical_history_version(),
        3
    );
    assert!(CellState::bootstrap_legacy(legacy_cell(), 0, position, limits).is_err());
}
