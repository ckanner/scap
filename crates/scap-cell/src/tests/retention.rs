use super::history::{
    from_hex, legacy_admission, legacy_apply, legacy_cell, legacy_database, legacy_limits,
    legacy_recovered_image,
};
use super::*;

fn apply_retention(state: &mut CellState, data: Vec<u8>) -> RetentionActivationOutcome {
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
    decode_retention_activation_outcome(&batch.results[0], state.identity, position).unwrap()
}

fn activate_retention(state: &mut CellState) -> RetentionActivationOutcome {
    apply_retention(
        state,
        encode_retention_activation(state.identity, state.bootstrap_admin),
    )
}

fn scoped(mut command: Command, epoch: u64) -> Command {
    command.admission.request_epoch = epoch;
    command
}

fn epoch_admission(epoch: u64) -> Admission {
    Admission {
        request_epoch: epoch,
        ..admission()
    }
}

fn active_retention() -> CellState {
    let mut state = active();
    assert_eq!(activate_retention(&mut state).result, Ok(()));
    state
}

fn acknowledge(state: &CellState, id: u128, epoch: u64) -> Command {
    let expected = match state
        .lookup(
            database(),
            epoch_admission(epoch),
            request(id),
            [id as u8; 32],
        )
        .unwrap()
    {
        Lookup::Committed { commit, .. } => RequestTerminal::Committed {
            sequence: commit.receipt.sequence,
        },
        Lookup::Cancelled { position, .. } => RequestTerminal::Cancelled { position },
        other => panic!("request must be terminal before acknowledgement: {other:?}"),
    };
    scoped(
        command(CommandKind::AcknowledgeRequest {
            request_id: request(id),
            request_fingerprint: [id as u8; 32],
            expected,
        }),
        epoch,
    )
}

fn confirm(state: &mut CellState, id: u128, epoch: u64) {
    let acknowledgement = acknowledge(state, id, epoch);
    assert_eq!(apply(state, &acknowledgement), Outcome::RequestAcknowledged);
}

fn rotate(epoch: u64) -> Command {
    scoped(
        command(CommandKind::RotateRequests {
            expected_epoch: epoch,
        }),
        epoch,
    )
}

#[test]
fn retention_activation_is_separate_ordered_and_preserves_legacy_results() {
    let mut state = active();
    apply(&mut state, &write(1, 0));
    apply(&mut state, &cancel(2));
    let ack = acknowledge(&state, 1, 1);
    rejected_without_mutation(&state, &ack, Reject::Conflict);
    rejected_without_mutation(&state, &rotate(1), Reject::Conflict);
    rejected_without_mutation(&state, &scoped(create(), 2), Reject::Conflict);
    let original = state.clone();
    let expected = state
        .lookup(database(), admission(), request(1), [1; 32])
        .unwrap();
    assert_eq!(activate_retention(&mut state).result, Ok(()));
    assert_eq!(state.physical_history_version(), 4);
    assert_eq!(state.last_outcome, original.last_outcome);
    assert_eq!(state.databases, original.databases);
    assert_eq!(state.administration, original.administration);
    assert_eq!(
        state
            .lookup(database(), admission(), request(1), [1; 32])
            .unwrap(),
        expected
    );
    assert_eq!(state.encode()[8], 4);
    assert_eq!(decode_snapshot(&state).unwrap(), state);
    let before = state.clone();
    assert_eq!(activate_history(&mut state).result, Ok(()));
    assert_eq!(activate_retention(&mut state).result, Ok(()));
    assert_eq!(state.databases, before.databases);
    assert_eq!(state.physical_history_version(), 4);
    assert_eq!(state.last_outcome, before.last_outcome);

    let mut legacy = CellState::bootstrap_legacy(identity(), PRINCIPAL, GENESIS, limits()).unwrap();
    assert_eq!(
        activate_retention(&mut legacy).result,
        Err(Reject::Conflict)
    );
    assert_eq!(legacy.physical_history_version(), 2);
    assert_eq!(activate_history(&mut legacy).result, Ok(()));
    assert_eq!(activate_retention(&mut legacy).result, Ok(()));
    assert_eq!(legacy.physical_history_version(), 4);
}

#[test]
fn acknowledged_epochs_keep_revision_and_physical_head_while_bounding_history() {
    let mut state = active_retention();
    let administration = state.administration.clone();
    let mut previous_hash = [0; 32];
    for epoch in 1..=20 {
        for id in 1..=8 {
            let revision = (epoch - 1) * 8 + id - 1;
            let cmd = scoped(write(id as u128, revision), epoch);
            let Outcome::Accepted(commit) = apply(&mut state, &cmd) else {
                panic!("new epoch write rejected")
            };
            assert_eq!(commit.receipt.sequence, revision + 1);
            assert_eq!(apply(&mut state, &cmd), Outcome::AlreadyCommitted(commit));
            confirm(&mut state, id as u128, epoch);
        }
        assert_eq!(
            apply(&mut state, &scoped(cancel(9), epoch)),
            Outcome::Cancelled
        );
        confirm(&mut state, 9, epoch);
        let view = state.database(database().database_id).unwrap();
        assert_eq!(view.revision, epoch * 8);
        assert_eq!(view.retained_requests, 9);
        assert_eq!(view.unacknowledged_requests, 0);
        assert_ne!(view.commit_hash, previous_hash);
        previous_hash = view.commit_hash;
        assert_eq!(
            apply(&mut state, &rotate(epoch)),
            Outcome::RequestsRotated { epoch: epoch + 1 }
        );
        let after = state.database(database().database_id).unwrap();
        assert_eq!(after.revision, view.revision);
        assert_eq!(after.commit_hash, view.commit_hash);
        assert_eq!(after.retired_revision, view.revision);
        assert_eq!(after.base_revision, view.revision);
        assert_eq!(after.retained_requests, 0);
        assert_eq!(after.unacknowledged_requests, 0);
        assert_eq!(after.tail_entries, 0);
        assert_eq!(after.tail_bytes, 0);
        assert_eq!(after.request_epoch, epoch + 1);
        assert_eq!(state.administration, administration);
        assert!(state.databases[&database().database_id]
            .transactions
            .is_empty());
        assert_eq!(
            state.lookup(database(), epoch_admission(epoch), request(1), [1; 32]),
            Ok(Lookup::Retired {
                current_epoch: epoch + 1
            })
        );
        assert_eq!(
            state.lookup(database(), epoch_admission(epoch + 1), request(1), [1; 32]),
            Ok(Lookup::Unknown)
        );
        assert_eq!(state.metadata(database(), admission()).unwrap(), after);
        assert_eq!(decode_snapshot(&state).unwrap(), state);
        let source = state.recovery_source(database(), admission()).unwrap();
        let base = source.base.unwrap();
        assert_eq!(base.revision, view.revision);
        assert_eq!(base.commit_hash, view.commit_hash);
        assert!(source.tail.is_empty());
        physical::Image::from_snapshot(
            physical::Snapshot {
                head: physical::Head {
                    identity: physical::EngineIdentity {
                        cell: identity(),
                        database: database(),
                    },
                    revision: base.revision,
                    image_digest: base.image_digest,
                },
                bytes: base.bytes.clone(),
            },
            physical_limits(state.limits),
        )
        .unwrap();
    }
    assert_eq!(
        state.database(database().database_id).unwrap().revision,
        160
    );
}

#[test]
fn acknowledgements_require_the_original_principal_fingerprint_and_terminal_result() {
    let mut state = active_retention();
    apply(&mut state, &write(1, 0));
    apply(&mut state, &cancel(2));
    let ack = acknowledge(&state, 1, 1);
    let cancel_ack = acknowledge(&state, 2, 1);
    let mut variants = Vec::new();
    let mut changed = ack.clone();
    changed.admission.principal_id = 22;
    variants.push((changed, Reject::Unauthorized));
    let mut changed = ack.clone();
    changed.admission.principal_id = 33;
    variants.push((changed, Reject::Unauthorized));
    let mut changed = ack.clone();
    changed.admission.auth_epoch = 2;
    variants.push((changed, Reject::Unauthorized));
    let mut changed = ack.clone();
    changed.admission.request_epoch = 0;
    variants.push((changed, Reject::Unauthorized));
    let mut changed = ack.clone();
    changed.admission.request_epoch = 2;
    variants.push((changed, Reject::Conflict));
    for (id, fingerprint, expected, rejection) in [
        (
            0,
            [1; 32],
            RequestTerminal::Committed { sequence: 1 },
            Reject::Invalid,
        ),
        (
            request(3),
            [3; 32],
            RequestTerminal::Committed { sequence: 1 },
            Reject::NotFound,
        ),
        (
            request(1),
            [9; 32],
            RequestTerminal::Committed { sequence: 1 },
            Reject::Conflict,
        ),
        (
            request(1),
            [1; 32],
            RequestTerminal::Committed { sequence: 2 },
            Reject::Conflict,
        ),
        (
            request(1),
            [1; 32],
            RequestTerminal::Cancelled { position: GENESIS },
            Reject::Conflict,
        ),
        (
            request(2),
            [2; 32],
            RequestTerminal::Cancelled { position: GENESIS },
            Reject::Conflict,
        ),
    ] {
        variants.push((
            command(CommandKind::AcknowledgeRequest {
                request_id: id,
                request_fingerprint: fingerprint,
                expected,
            }),
            rejection,
        ));
    }
    for (cmd, rejection) in variants {
        rejected_without_mutation(&state, &cmd, rejection);
    }
    assert_eq!(
        state.lookup(database(), admission(), request(3), [3; 32]),
        Ok(Lookup::Unknown)
    );
    rejected_without_mutation(&state, &rotate(1), Reject::Conflict);
    assert_eq!(apply(&mut state, &ack), Outcome::RequestAcknowledged);
    let original_ack = state.databases[&database().database_id].acknowledged[&request(1)];
    assert_eq!(apply(&mut state, &ack), Outcome::RequestAcknowledged);
    assert_eq!(
        state.databases[&database().database_id].acknowledged[&request(1)],
        original_ack
    );
    rejected_without_mutation(&state, &rotate(1), Reject::Conflict);
    assert_eq!(apply(&mut state, &cancel_ack), Outcome::RequestAcknowledged);
    assert!(matches!(
        state.lookup(database(), admission(), request(1), [1; 32]),
        Ok(Lookup::Committed {
            acknowledged: true,
            ..
        })
    ));
    assert!(matches!(
        state.lookup(database(), admission(), request(2), [2; 32]),
        Ok(Lookup::Cancelled {
            acknowledged: true,
            ..
        })
    ));
    assert_eq!(
        state
            .database(database().database_id)
            .unwrap()
            .retained_requests,
        2
    );
    assert_eq!(state.administration.len(), 3);
    assert_eq!(decode_snapshot(&state).unwrap(), state);
}

#[test]
fn rotation_requires_admin_current_epoch_nonempty_acknowledged_window_and_fences_every_old_path() {
    let mut state = active_retention();
    rejected_without_mutation(&state, &rotate(1), Reject::Conflict);
    apply(&mut state, &write(1, 0));
    confirm(&mut state, 1, 1);
    let old_ack = acknowledge(&state, 1, 1);
    let mut denied = rotate(1);
    denied.admission.principal_id = 22;
    rejected_without_mutation(&state, &denied, Reject::Unauthorized);
    rejected_without_mutation(&state, &rotate(2), Reject::Conflict);
    let mut future_expected = rotate(1);
    future_expected.kind = CommandKind::RotateRequests { expected_epoch: 2 };
    rejected_without_mutation(&state, &future_expected, Reject::Conflict);
    let mut zero_expected = rotate(1);
    zero_expected.kind = CommandKind::RotateRequests { expected_epoch: 0 };
    rejected_without_mutation(&state, &zero_expected, Reject::Retired);
    let mut administrator = rotate(1);
    administrator.admission.principal_id = 44;
    assert_eq!(
        apply(&mut state, &administrator),
        Outcome::RequestsRotated { epoch: 2 }
    );
    for old in [
        write(1, 1),
        write(7, 1),
        cancel(1),
        cancel(7),
        old_ack,
        rotate(1),
    ] {
        rejected_without_mutation(&state, &old, Reject::Retired);
    }
    let mut old_expected = rotate(2);
    old_expected.kind = CommandKind::RotateRequests { expected_epoch: 1 };
    rejected_without_mutation(&state, &old_expected, Reject::Retired);
    assert_eq!(
        state.lookup(database(), epoch_admission(3), request(1), [1; 32]),
        Err(Reject::Conflict)
    );
    for future in [scoped(write(1, 1), 3), scoped(cancel(1), 3)] {
        rejected_without_mutation(&state, &future, Reject::Conflict);
    }
    // A current READ principal may inspect the public namespace; old outcome
    // payloads remain inaccessible and are never misreported as cancellation.
    assert_eq!(
        state.lookup(
            database(),
            Admission {
                principal_id: 22,
                ..admission()
            },
            request(1),
            [1; 32]
        ),
        Ok(Lookup::Retired { current_epoch: 2 })
    );
    assert_eq!(
        state.lookup(
            database(),
            Admission {
                principal_id: 44,
                ..admission()
            },
            request(1),
            [1; 32]
        ),
        Err(Reject::Unauthorized)
    );
    assert_eq!(
        state
            .metadata(database(), admission())
            .unwrap()
            .request_epoch,
        2
    );
    assert_eq!(decode_snapshot(&state).unwrap(), state);
}

#[test]
fn a_cancel_only_window_has_a_permanent_epoch_fence_without_a_fake_sql_revision() {
    let mut state = active_retention();
    assert_eq!(apply(&mut state, &cancel(1)), Outcome::Cancelled);
    confirm(&mut state, 1, 1);
    assert_eq!(
        apply(&mut state, &rotate(1)),
        Outcome::RequestsRotated { epoch: 2 }
    );
    let view = state.database(database().database_id).unwrap();
    assert_eq!(
        (view.revision, view.retired_revision, view.base_revision),
        (0, 0, 0)
    );
    assert_eq!(view.commit_hash, [0; 32]);
    assert!(state
        .recovery_source(database(), admission())
        .unwrap()
        .base
        .is_none());
    rejected_without_mutation(&state, &write(1, 0), Reject::Retired);
    assert!(matches!(
        apply(&mut state, &scoped(write(1, 0), 2)),
        Outcome::Accepted(_)
    ));
    confirm(&mut state, 1, 2);
    assert_eq!(
        apply(&mut state, &rotate(2)),
        Outcome::RequestsRotated { epoch: 3 }
    );
    assert_eq!(state.database(database().database_id).unwrap().revision, 1);
    // Retire another cancellation without new physical tail. The existing
    // quorum base and its original commit position remain exactly unchanged.
    let base = state.databases[&database().database_id].base.clone();
    apply(&mut state, &scoped(cancel(2), 3));
    confirm(&mut state, 2, 3);
    assert_eq!(
        apply(&mut state, &rotate(3)),
        Outcome::RequestsRotated { epoch: 4 }
    );
    assert_eq!(state.databases[&database().database_id].base, base);
    assert_eq!(decode_snapshot(&state).unwrap(), state);
}

#[test]
fn a_failed_forced_baseline_is_atomic_and_keeps_receipts_and_acknowledgements() {
    let mut state = active_retention();
    let mut opaque = write(1, 0);
    let payload = commit_parts(&mut opaque).0;
    payload.physical_changes[0] ^= 1;
    payload.ticket.payload_digest = payload_digest(&payload.physical_changes);
    assert!(matches!(apply(&mut state, &opaque), Outcome::Accepted(_)));
    confirm(&mut state, 1, 1);
    let before = state.clone();
    rejected_without_mutation(&state, &rotate(1), Reject::Invalid);
    assert_eq!(
        apply(&mut state, &rotate(1)),
        Outcome::Rejected(Reject::Invalid)
    );
    assert_eq!(state.databases, before.databases);
    assert_eq!(
        state
            .database(database().database_id)
            .unwrap()
            .request_epoch,
        1
    );
    assert!(matches!(
        state.lookup(database(), admission(), request(1), [1; 32]),
        Ok(Lookup::Committed {
            acknowledged: true,
            ..
        })
    ));
}

#[test]
fn accepted_v4_records_reserve_acknowledgement_capacity_before_they_fill_the_state() {
    let mut state = active_retention();
    for id in 1..=3 {
        let mut first = write(id, id as u64 - 1);
        commit_parts(&mut first).2.resize(900, 19);
        assert!(matches!(apply(&mut state, &first), Outcome::Accepted(_)));
    }
    // Freeze the replicated budget at the exact current requirement, including
    // the 32 bytes each unacknowledged record has already reserved.
    let required = codec::encode_state(&state, false).len() + RESERVED_BYTES + 3 * 32;
    assert!(required >= physical::PAGE_SIZE);
    state.limits.max_state_bytes = required as u32;
    assert!(state.fits());
    assert_eq!(decode_snapshot(&state).unwrap(), state);
    rejected_without_mutation(&state, &write(4, 3), Reject::Capacity);
    let before = codec::encode_state(&state, false).len();
    for id in 1..=3 {
        confirm(&mut state, id, 1);
    }
    assert_eq!(codec::encode_state(&state, false).len(), before + 3 * 32);
    assert!(state.fits());
    assert_eq!(
        apply(&mut state, &rotate(1)),
        Outcome::RequestsRotated { epoch: 2 }
    );
    assert!(state.fits());
    assert!(matches!(
        apply(&mut state, &scoped(write(4, 3), 2)),
        Outcome::Accepted(_)
    ));
    confirm(&mut state, 4, 2);
    assert_eq!(
        apply(&mut state, &rotate(2)),
        Outcome::RequestsRotated { epoch: 3 }
    );
}

#[test]
fn v4_activation_fails_closed_if_legacy_state_cannot_fund_future_acknowledgements() {
    let mut state = active();
    apply(&mut state, &write(1, 0));
    apply(&mut state, &cancel(2));
    state.limits.max_state_bytes =
        (codec::encode_state(&state, false).len() + RESERVED_BYTES) as u32;
    assert!(state.fits());
    let previous = state.clone();
    assert_eq!(activate_retention(&mut state).result, Err(Reject::Capacity));
    assert_eq!(state.physical_history_version(), 3);
    assert_eq!(state.databases, previous.databases);
    assert_eq!(state.last_outcome, previous.last_outcome);
    assert_eq!(decode_snapshot(&state).unwrap(), state);
}

#[test]
fn cold_acknowledgement_survives_legacy_hydration_and_rotation_cannot_orphan_the_only_image() {
    let mut old = active();
    apply(&mut old, &write(1, 0));
    apply(&mut old, &cancel(2));
    let (mut state, archive, bytes) = published(old);
    assert_eq!(bytes[8], 3);
    let prune = command(CommandKind::PruneArchive {
        operation_id: operation(12),
        expected_owner: state.database(database().database_id).unwrap().owner,
        archive_digest: archive.object_digest,
    });
    assert_eq!(
        apply(&mut state, &prune),
        Outcome::Administrative(AdminResult::ArchivePruned(archive.object_digest))
    );
    assert_eq!(activate_retention(&mut state).result, Ok(()));
    confirm(&mut state, 1, 1);
    confirm(&mut state, 2, 1);
    rejected_without_mutation(&state, &rotate(1), Reject::Cold);
    let confirmed = state.databases[&database().database_id]
        .acknowledged
        .clone();
    assert_eq!(
        state.database(database().database_id).unwrap().archive,
        Some(archive)
    );
    assert_eq!(
        codec::archive_metadata(&state.databases[&database().database_id]),
        archive.metadata_digest
    );
    let hydrate = command(CommandKind::HydrateArchive {
        operation_id: operation(13),
        archive: bytes.clone(),
    });
    assert_eq!(
        apply(&mut state, &hydrate),
        Outcome::Administrative(AdminResult::ArchiveHydrated(archive.object_digest))
    );
    assert_eq!(
        state.databases[&database().database_id].acknowledged,
        confirmed
    );
    assert_eq!(
        apply(&mut state, &rotate(1)),
        Outcome::RequestsRotated { epoch: 2 }
    );
    let after = state.database(database().database_id).unwrap();
    assert_eq!(after.revision, 1);
    assert_eq!(after.base_revision, 1);
    assert!(after.archive.is_none());
    // Existing operation receipts remain immutable no-ops; a different attempt
    // cannot republish, prune or hydrate the now-retired archive namespace.
    assert_eq!(
        apply(&mut state, &hydrate),
        Outcome::AlreadyApplied(AdminResult::ArchiveHydrated(archive.object_digest))
    );
    let new_hydrate = command(CommandKind::HydrateArchive {
        operation_id: operation(14),
        archive: bytes,
    });
    rejected_without_mutation(&state, &new_hydrate, Reject::NotFound);
    let mut old_prune = prune;
    if let CommandKind::PruneArchive { operation_id, .. } = &mut old_prune.kind {
        *operation_id = operation(15);
    }
    rejected_without_mutation(&state, &old_prune, Reject::NotFound);
    let old_publish = command(CommandKind::PublishArchive {
        operation_id: operation(16),
        expected_owner: after.owner,
        expected_previous: None,
        archive,
    });
    rejected_without_mutation(&state, &old_publish, Reject::Conflict);
    assert_eq!(decode_snapshot(&state).unwrap(), state);
}

#[test]
fn v4_archive_binds_retired_prefix_and_epoch_but_not_later_acknowledgements() {
    let mut state = active_retention();
    apply(&mut state, &write(1, 0));
    confirm(&mut state, 1, 1);
    apply(&mut state, &rotate(1));
    for id in 1..=3 {
        assert!(matches!(
            apply(&mut state, &scoped(write(id, id as u64), 2)),
            Outcome::Accepted(_)
        ));
    }
    let (mut state, archive, bytes) = published(state);
    assert_eq!(bytes[8], 4);
    assert_eq!(archive.revision, 4);
    assert_eq!(
        state
            .database(database().database_id)
            .unwrap()
            .retired_revision,
        1
    );
    // Confirmation can race publication and also happen after pruning. It is
    // never imported from an archive and never invalidates physical coverage.
    confirm(&mut state, 1, 2);
    let prune = command(CommandKind::PruneArchive {
        operation_id: operation(12),
        expected_owner: state.database(database().database_id).unwrap().owner,
        archive_digest: archive.object_digest,
    });
    assert!(matches!(
        apply(&mut state, &prune),
        Outcome::Administrative(_)
    ));
    confirm(&mut state, 2, 2);
    confirm(&mut state, 3, 2);
    let acknowledgements = state.databases[&database().database_id]
        .acknowledged
        .clone();
    let hydrate = command(CommandKind::HydrateArchive {
        operation_id: operation(13),
        archive: bytes.clone(),
    });
    assert!(matches!(
        apply(&mut state, &hydrate),
        Outcome::Administrative(_)
    ));
    assert_eq!(
        state.databases[&database().database_id].acknowledged,
        acknowledgements
    );
    assert_eq!(
        state
            .database(database().database_id)
            .unwrap()
            .unacknowledged_requests,
        0
    );
    let head = state.database(database().database_id).unwrap();
    assert_eq!(
        apply(&mut state, &rotate(2)),
        Outcome::RequestsRotated { epoch: 3 }
    );
    let retired = state.database(database().database_id).unwrap();
    assert_eq!(retired.revision, head.revision);
    assert_eq!(retired.commit_hash, head.commit_hash);
    assert_eq!(retired.retired_revision, head.revision);
    assert_eq!(retired.base_revision, head.revision);
    assert!(retired.archive.is_none());
    let (latest, _) = state.archive_snapshot(database(), admission()).unwrap();
    assert_eq!(latest.revision, 4);
    assert_ne!(latest.metadata_digest, archive.metadata_digest);
    assert_eq!(decode_snapshot(&state).unwrap(), state);

    // Matching namespace and retired-prefix metadata cannot authorize a base
    // that ends before that prefix; archive payloads supply their own base and
    // must independently prove this lower bound before indexing the tail.
    let current = &state.databases[&database().database_id];
    let mut stale_base = current.clone();
    stale_base.base.as_mut().unwrap().revision = 3;
    let malformed = codec::encode_archive(identity(), &stale_base, latest.source, 4);
    assert!(matches!(
        codec::decode_archive(&malformed, identity(), current, latest, state.limits, 4),
        Err(Error::Malformed("invalid recovery base position"))
    ));

    // Rebinding the content digest cannot make an old, otherwise valid payload
    // hydrate a new namespace or a different retained-prefix anchor.
    let mut target = state.databases[&database().database_id].clone();
    assert!(codec::decode_archive(&bytes, identity(), &target, archive, state.limits, 4).is_err());
    target.request_epoch = 2;
    assert!(codec::decode_archive(&bytes, identity(), &target, archive, state.limits, 4).is_err());
}

#[test]
fn a_v4_archive_cannot_omit_the_base_of_a_retired_sql_prefix() {
    let mut retired = active_retention();
    apply(&mut retired, &write(1, 0));
    confirm(&mut retired, 1, 1);
    apply(&mut retired, &rotate(1));
    for retained_tail in [false, true] {
        let mut state = retired.clone();
        if retained_tail {
            apply(&mut state, &scoped(write(2, 1), 2));
        }
        let (published, archive, _) = published(state);
        let mut missing_base = published.databases[&database().database_id].clone();
        missing_base.base = None;
        let malformed = codec::encode_archive(identity(), &missing_base, archive.source, 4);
        // Recompute all outer checksums so this exercises the structural
        // recovery proof, rather than stopping at object/envelope integrity.
        let corrupt_reference = ArchiveRef {
            object_digest: payload_digest(&malformed),
            object_bytes: malformed.len() as u32,
            ..archive
        };
        for cold in [false, true] {
            let mut target = published.clone();
            if cold {
                let prune = command(CommandKind::PruneArchive {
                    operation_id: operation(12),
                    expected_owner: target.database(database().database_id).unwrap().owner,
                    archive_digest: archive.object_digest,
                });
                assert!(matches!(
                    apply(&mut target, &prune),
                    Outcome::Administrative(AdminResult::ArchivePruned(_))
                ));
            }
            assert!(matches!(
                codec::decode_archive(
                    &malformed,
                    identity(),
                    &target.databases[&database().database_id],
                    corrupt_reference,
                    target.limits,
                    4,
                ),
                Err(Error::Malformed("retired prefix has no recoverable base"))
            ));
            // A decoded snapshot can only authenticate the opaque reference;
            // even a matching reference must not make Hydrate install a missing
            // base, panic, or change current metadata and recovery material.
            target
                .databases
                .get_mut(&database().database_id)
                .unwrap()
                .archive = Some(corrupt_reference);
            assert_eq!(decode_snapshot(&target).unwrap(), target);
            rejected_without_mutation(
                &target,
                &command(CommandKind::HydrateArchive {
                    operation_id: operation(13),
                    archive: malformed.clone(),
                }),
                Reject::Invalid,
            );
        }
    }
}

#[test]
fn retirement_activation_checks_scope_permissions_size_and_exact_result_binding() {
    let state = active();
    for (cell, admin, expected) in [
        (
            CellIdentity {
                cell_id: 9,
                ..identity()
            },
            PRINCIPAL,
            Reject::Fenced,
        ),
        (identity(), 9, Reject::Unauthorized),
    ] {
        let mut changed = state.clone();
        assert_eq!(
            apply_retention(&mut changed, encode_retention_activation(cell, admin)).result,
            Err(expected)
        );
        assert_eq!(changed.databases, state.databases);
        assert_eq!(changed.physical_history_version(), 3);
    }
    let encoded = encode_retention_activation(identity(), PRINCIPAL);
    let mut changed = state.clone();
    let mut malformed = encoded.clone();
    malformed[8] = 9;
    assert_eq!(
        apply_retention(&mut changed, malformed).result,
        Err(Reject::Invalid)
    );
    let mut tiny = state.clone();
    tiny.limits.max_command_bytes = 1;
    assert_eq!(
        apply_retention(&mut tiny, encoded.clone()).result,
        Err(Reject::TooLarge)
    );
    for end in 0..body(&encoded).len() {
        assert!(
            codec::decode_retention_activation(&envelope(&encoded, &body(&encoded)[..end]))
                .is_err()
        );
    }
    assert!(
        codec::decode_retention_activation(&mutate_body(&encoded, |body| body.push(0))).is_err()
    );

    for result in [Ok(()), Err(Reject::Capacity)] {
        let expected = RetentionActivationOutcome {
            cell: identity(),
            position: GENESIS,
            result,
        };
        let bytes = codec::encode_retention_activation_outcome(&expected);
        assert_eq!(
            decode_retention_activation_outcome(&bytes, identity(), GENESIS),
            Ok(expected)
        );
        let mut corrupt = bytes.clone();
        corrupt[0] ^= 1;
        assert!(decode_retention_activation_outcome(&corrupt, identity(), GENESIS).is_err());
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
            let own = RetentionActivationOutcome {
                cell,
                position: GENESIS,
                result,
            };
            assert!(decode_retention_activation_outcome(
                &codec::encode_retention_activation_outcome(&own),
                cell,
                GENESIS
            )
            .is_err());
        }
        assert_eq!(
            decode_retention_activation_outcome(
                &bytes,
                CellIdentity {
                    cell_id: 9,
                    ..identity()
                },
                GENESIS
            ),
            Err(Error::Binding)
        );
        for pos in [
            Position { term: 0, index: 1 },
            Position { term: 1, index: 0 },
            Position { term: 1, index: 2 },
        ] {
            assert_eq!(
                decode_retention_activation_outcome(&bytes, identity(), pos),
                Err(Error::Position)
            );
        }
        for end in 0..body(&bytes).len() {
            assert!(decode_retention_activation_outcome(
                &envelope(&bytes, &body(&bytes)[..end]),
                identity(),
                GENESIS
            )
            .is_err());
        }
        assert!(decode_retention_activation_outcome(
            &mutate_body(&bytes, |body| body.push(0)),
            identity(),
            GENESIS
        )
        .is_err());
    }
}

fn retained_after_rotation() -> CellState {
    let mut state = active_retention();
    apply(&mut state, &write(1, 0));
    confirm(&mut state, 1, 1);
    apply(&mut state, &rotate(1));
    apply(&mut state, &scoped(write(2, 1), 2));
    apply(&mut state, &scoped(cancel(3), 2));
    confirm(&mut state, 2, 2);
    state
}

#[test]
fn snapshots_reject_broken_prefix_epoch_acknowledgement_and_retirement_bindings() {
    let state = retained_after_rotation();
    let mutate = |change: fn(&mut Database)| {
        let mut invalid = state.clone();
        change(invalid.databases.get_mut(&database().database_id).unwrap());
        assert!(
            decode_snapshot(&invalid).is_err(),
            "invalid snapshot accepted: {invalid:?}"
        );
    };
    for change in [
        (|db: &mut Database| db.request_epoch = 0) as fn(&mut Database),
        |db| db.retired.revision = u64::MAX,
        |db| {
            db.acknowledged.insert(request(8), GENESIS);
            db.acknowledged.insert(request(9), GENESIS);
        },
        |db| db.retired.revision = 0,
        |db| db.retired.source = GENESIS,
        |db| db.retired.source.term = 0,
        |db| db.base = None,
        |db| db.base.as_mut().unwrap().revision = 0,
        |db| db.retirement_position = None,
        |db| {
            db.request_epoch = 1;
            db.retirement_position = None;
        },
        |db| db.request_epoch = 1,
        |db| db.retirement_position = Some(GENESIS),
        |db| db.retirement_position = Some(db.retired.source),
        |db| db.retirement_position.as_mut().unwrap().index = u64::MAX,
        |db| db.transactions[0].admission.request_epoch = 1,
        |db| db.transactions[0].commit.position = db.retirement_position.unwrap(),
        |db| {
            if let RequestRecord::Cancelled { admission, .. } =
                db.requests.get_mut(&request(3)).unwrap()
            {
                admission.request_epoch = 1;
            }
        },
        |db| {
            if let RequestRecord::Cancelled { position, .. } =
                db.requests.get_mut(&request(3)).unwrap()
            {
                *position = db.retirement_position.unwrap();
            }
        },
        |db| {
            db.acknowledged.insert(request(8), GENESIS);
        },
        |db| {
            db.acknowledged.insert(request(2), GENESIS);
        },
        |db| {
            db.acknowledged
                .insert(request(2), db.transactions[0].commit.position);
        },
        |db| {
            db.acknowledged.insert(
                request(2),
                Position {
                    term: 1,
                    index: u64::MAX,
                },
            );
        },
        |db| {
            db.requests.insert(request(2), RequestRecord::Accepted(1));
        },
        |db| db.base.as_mut().unwrap().revision = 3,
        |db| db.base.as_mut().unwrap().commit_hash = [99; 32],
    ] {
        mutate(change);
    }
    let mut absent = active_retention();
    absent
        .databases
        .get_mut(&database().database_id)
        .unwrap()
        .request_epoch = 2;
    assert!(decode_snapshot(&absent).is_err());
    let mut zero_base = active_retention();
    let mut base = state.databases[&database().database_id]
        .base
        .clone()
        .unwrap();
    base.revision = 0;
    zero_base
        .databases
        .get_mut(&database().database_id)
        .unwrap()
        .base = Some(base);
    assert!(decode_snapshot(&zero_base).is_err());
    let mut orphan = state.clone();
    orphan.last_outcome.as_mut().unwrap().outcome = Outcome::RequestsRotated { epoch: 9 };
    assert!(decode_snapshot(&orphan).is_err());
    let mut no_ack = state.clone();
    no_ack
        .databases
        .get_mut(&database().database_id)
        .unwrap()
        .acknowledged
        .clear();
    assert!(decode_snapshot(&no_ack).is_err());

    let (archived, _, _) = published(state);
    let mut invalid = archived.clone();
    let db = invalid.databases.get_mut(&database().database_id).unwrap();
    // A valid retired SQL prefix precedes its namespace retirement. Requiring
    // archive.source >= retirement is therefore stronger than checking only
    // archive.source >= retired.source, including an archive of exactly the
    // retired revision.
    db.archive.as_mut().unwrap().source = db.retired.source;
    assert!(decode_snapshot(&invalid).is_err());
    let mut invalid = archived;
    invalid
        .databases
        .get_mut(&database().database_id)
        .unwrap()
        .archive
        .as_mut()
        .unwrap()
        .revision = 0;
    assert!(decode_snapshot(&invalid).is_err());
}

#[test]
fn v4_snapshots_and_archives_reject_truncated_fields_and_duplicate_acknowledgements() {
    let mut state = retained_after_rotation();
    confirm(&mut state, 3, 2);
    let encoded = state.encode();
    for end in 0..body(&encoded).len() {
        let truncated = envelope(&encoded, &body(&encoded)[..end]);
        assert!(
            CellState::decode_bound(&truncated, identity(), state.position, state.limits).is_err()
        );
    }
    let acknowledgements = &state.databases[&database().database_id].acknowledged;
    let mut table = Vec::new();
    for (&request_id, &position) in acknowledgements {
        table.extend_from_slice(&request_id.to_be_bytes());
        table.extend_from_slice(&position.term.to_be_bytes());
        table.extend_from_slice(&position.index.to_be_bytes());
    }
    let duplicate = mutate_body(&encoded, |body| {
        let offset = unique_offset(body, &table);
        body[offset + 32..offset + 48].copy_from_slice(&request(2).to_be_bytes());
    });
    assert_eq!(
        CellState::decode_bound(&duplicate, identity(), state.position, state.limits),
        Err(Error::Malformed("duplicate request acknowledgement"))
    );
    let (archive, bytes) = state.archive_snapshot(database(), admission()).unwrap();
    let database = &state.databases[&database().database_id];
    for end in 0..body(&bytes).len() {
        let truncated = envelope(&bytes, &body(&bytes)[..end]);
        assert!(
            codec::decode_archive(&truncated, identity(), database, archive, state.limits, 4)
                .is_err()
        );
    }
}

#[test]
fn a_legacy_archive_cannot_supply_a_new_epoch_or_retired_prefix() {
    let mut legacy = active();
    apply(&mut legacy, &write(1, 0));
    let (archive, bytes) = legacy.archive_snapshot(database(), admission()).unwrap();
    assert_eq!(bytes[8], 3);
    let original = &legacy.databases[&database().database_id];
    let mut new_epoch = original.clone();
    new_epoch.request_epoch = 2;
    assert!(matches!(
        codec::decode_archive(&bytes, identity(), &new_epoch, archive, legacy.limits, 4),
        Err(Error::Binding)
    ));
    let mut new_prefix = original.clone();
    new_prefix.retired.revision = 1;
    assert!(matches!(
        codec::decode_archive(&bytes, identity(), &new_prefix, archive, legacy.limits, 4),
        Err(Error::Binding)
    ));
}

#[test]
fn a_retired_epoch_cannot_be_followed_by_a_larger_index_from_an_earlier_term() {
    let mut state = active_retention();
    apply(&mut state, &write(1, 0));
    confirm(&mut state, 1, 1);
    apply_at(&mut state, &rotate(1), 5);
    apply_at(&mut state, &scoped(write(2, 1), 2), 5);
    apply_at(&mut state, &scoped(cancel(3), 2), 5);
    apply_at(&mut state, &scoped(cancel(4), 2), 5);
    let mut accepted = state.clone();
    accepted
        .databases
        .get_mut(&database().database_id)
        .unwrap()
        .transactions[0]
        .commit
        .position
        .term = 4;
    assert!(decode_snapshot(&accepted).is_err());
    let mut cancelled = state;
    if let RequestRecord::Cancelled { position, .. } = cancelled
        .databases
        .get_mut(&database().database_id)
        .unwrap()
        .requests
        .get_mut(&request(3))
        .unwrap()
    {
        position.term = 4;
    }
    assert!(decode_snapshot(&cancelled).is_err());
}

#[test]
fn request_epoch_and_lifetime_revision_never_wrap() {
    let mut state = active_retention();
    apply(&mut state, &write(1, 0));
    confirm(&mut state, 1, 1);
    apply(&mut state, &rotate(1));
    let mut exhausted_epoch = state.clone();
    exhausted_epoch
        .databases
        .get_mut(&database().database_id)
        .unwrap()
        .request_epoch = u64::MAX;
    exhausted_epoch.last_outcome.as_mut().unwrap().outcome =
        Outcome::RequestsRotated { epoch: u64::MAX };
    assert_eq!(decode_snapshot(&exhausted_epoch).unwrap(), exhausted_epoch);
    apply(&mut exhausted_epoch, &scoped(cancel(2), u64::MAX));
    confirm(&mut exhausted_epoch, 2, u64::MAX);
    rejected_without_mutation(&exhausted_epoch, &rotate(u64::MAX), Reject::Exhausted);

    let db = state.databases.get_mut(&database().database_id).unwrap();
    db.retired.revision = u64::MAX;
    db.base.as_mut().unwrap().revision = u64::MAX;
    assert_eq!(decode_snapshot(&state).unwrap(), state);
    let mut write = scoped(write(2, 0), 2);
    commit_parts(&mut write).0.ticket.predecessor = u64::MAX;
    rejected_without_mutation(&state, &write, Reject::Exhausted);
}

#[test]
fn new_command_and_result_envelopes_reject_downgrade_unknown_tags_and_truncation() {
    let mut state = active_retention();
    apply(&mut state, &write(1, 0));
    apply(&mut state, &cancel(2));
    for command in [
        acknowledge(&state, 1, 1),
        acknowledge(&state, 2, 1),
        rotate(1),
        scoped(write(3, 1), 2),
    ] {
        let encoded = encode_command(&command, limits()).unwrap();
        assert_eq!(encoded[8], 3);
        assert_eq!(codec::decode_command(&encoded, limits()).unwrap(), command);
        for end in 0..body(&encoded).len() {
            assert!(
                codec::decode_command(&envelope(&encoded, &body(&encoded)[..end]), limits())
                    .is_err()
            );
        }
        if matches!(
            command.kind,
            CommandKind::AcknowledgeRequest { .. } | CommandKind::RotateRequests { .. }
        ) {
            let mut old = encoded.clone();
            old[8] = 2;
            let mut payload = body(&encoded).to_vec();
            payload.drain(112..120);
            assert!(codec::decode_command(&envelope(&old, &payload), limits()).is_err());
        }
    }
    let ack = encode_command(&acknowledge(&state, 1, 1), limits()).unwrap();
    assert!(codec::decode_command(&mutate_body(&ack, |body| body[169] = 255), limits()).is_err());
    for outcome in [
        Outcome::RequestAcknowledged,
        Outcome::RequestsRotated { epoch: 2 },
        Outcome::Rejected(Reject::Retired),
    ] {
        let value = AppliedOutcome {
            position: GENESIS,
            outcome,
        };
        let bytes = encode_applied_outcome(&value);
        assert_eq!(bytes[8], 3);
        assert_eq!(decode_applied_outcome(&bytes, GENESIS), Ok(value));
        for end in 0..body(&bytes).len() {
            assert!(
                decode_applied_outcome(&envelope(&bytes, &body(&bytes)[..end]), GENESIS).is_err()
            );
        }
        let mut old = bytes.clone();
        old[8] = 2;
        assert!(decode_applied_outcome(&envelope(&old, body(&bytes)), GENESIS).is_err());
    }
    let mut legacy = active();
    legacy.last_outcome.as_mut().unwrap().outcome = Outcome::RequestAcknowledged;
    assert!(decode_snapshot(&legacy).is_err());
}

fn canonical_v3_trace(
    prefixes: &str,
    commands: &str,
    outcomes: &str,
    digests: &str,
    limits: Limits,
    activation: Result<(), Reject>,
) -> CellState {
    let prefixes: Vec<_> = prefixes.lines().map(from_hex).collect();
    let commands: Vec<_> = commands.lines().map(from_hex).collect();
    let outcomes: Vec<_> = outcomes.lines().map(from_hex).collect();
    let digests: Vec<_> = digests.lines().map(from_hex).collect();
    assert_eq!(prefixes.len(), commands.len() + 1);
    assert_eq!(commands.len(), outcomes.len());
    assert_eq!(commands.len(), digests.len());
    assert_eq!(
        CellState::bootstrap(legacy_cell(), 12, GENESIS, limits)
            .unwrap()
            .encode(),
        prefixes[0]
    );
    let position = Position {
        term: 1,
        index: prefixes.len() as u64,
    };
    let mut canonical =
        CellState::decode_bound(prefixes.last().unwrap(), legacy_cell(), position, limits).unwrap();
    let original = canonical.clone();
    assert_eq!(original.physical_history_version(), 3);
    let activated = activate_retention(&mut canonical);
    assert_eq!(activated.result, activation);
    assert_eq!(
        canonical.physical_history_version(),
        if activation.is_ok() { 4 } else { 3 }
    );
    assert_eq!(canonical.databases, original.databases);
    assert_eq!(canonical.administration, original.administration);
    assert_eq!(canonical.last_outcome, original.last_outcome);
    let current_admission = legacy_admission(canonical.database(9).unwrap().auth_epoch);
    let archive = canonical
        .archive_snapshot(legacy_database(), current_admission)
        .unwrap();

    // These inputs are byte-for-byte outputs of the separately compiled
    // b9f5128 v3 implementation, including Capacity decisions and cold
    // publish/prune/hydrate transitions. Every possible restart prefix must
    // reproduce every old suffix outcome and byte before the new ordered entry.
    for (split, prefix) in prefixes.iter().enumerate() {
        let mut state = CellState::decode_bound(
            prefix,
            legacy_cell(),
            Position {
                term: 1,
                index: split as u64 + 1,
            },
            limits,
        )
        .unwrap();
        assert_eq!(state.encode(), *prefix, "old v3 prefix {split}");
        assert_eq!(state.physical_history_version(), 3);
        for (offset, command) in commands.iter().enumerate().skip(split) {
            assert_eq!(command[8], 2);
            let position = Position {
                term: 1,
                index: offset as u64 + 2,
            };
            let batch = CellApplication::new(legacy_cell(), limits)
                .unwrap()
                .apply_with_results(
                    &state.encode(),
                    &[Entry {
                        term: 1,
                        index: position.index,
                        data: command.clone().into(),
                        ..Entry::default()
                    }],
                    &[position.index],
                )
                .unwrap();
            assert_eq!(
                batch.results,
                vec![outcomes[offset].clone()],
                "old v3 outcome {split}/{offset}"
            );
            assert_eq!(
                batch.state,
                prefixes[offset + 1],
                "old v3 state {split}/{offset}"
            );
            assert_eq!(
                payload_digest(&batch.state).as_slice(),
                digests[offset],
                "old v3 digest {split}/{offset}"
            );
            state = CellState::decode_bound(&batch.state, legacy_cell(), position, limits).unwrap();
            assert_eq!(
                state.encode(),
                batch.state,
                "decoded old v3 state {split}/{offset}"
            );
            assert_eq!(state.physical_history_version(), 3);
        }
        assert_eq!(state, original, "old v3 final state from {split}");
        assert_eq!(activate_retention(&mut state), activated);
        assert_eq!(
            state.encode(),
            canonical.encode(),
            "canonical v4 activation from {split}"
        );
        assert_eq!(
            state
                .archive_snapshot(legacy_database(), current_admission)
                .unwrap(),
            archive,
            "canonical archive after activation from {split}"
        );
    }
    canonical
}

#[test]
fn every_real_v3_lifecycle_prefix_replays_exactly_then_retires_with_the_same_physical_image() {
    let mut state = canonical_v3_trace(
        include_str!("../../test-fixtures/retention-v3-lifecycle.prefixes.hex"),
        include_str!("../../test-fixtures/retention-v3-lifecycle.commands.hex"),
        include_str!("../../test-fixtures/retention-v3-lifecycle.outcomes.hex"),
        include_str!("../../test-fixtures/retention-v3-lifecycle.state-sha256.hex"),
        Limits {
            max_command_bytes: 65_536,
            max_requests_per_database: 12,
            max_result_bytes: 1536,
            ..legacy_limits()
        },
        Ok(()),
    );
    let expected_image = from_hex(include_str!(
        "../../test-fixtures/retention-v3-lifecycle.image.hex"
    ));
    assert_eq!(legacy_recovered_image(&state, 2).bytes(), expected_image);
    let original = state.database(9).unwrap();
    assert_eq!(
        (
            original.revision,
            original.base_revision,
            original.retained_requests
        ),
        (10, 8, 12)
    );
    let db = &state.databases[&9];
    let confirmations: Vec<_> = db
        .requests
        .iter()
        .map(|(&request_id, record)| {
            let (request_fingerprint, expected) = match record {
                RequestRecord::Accepted(sequence) => (
                    db.transaction(*sequence).request_fingerprint,
                    RequestTerminal::Committed {
                        sequence: *sequence,
                    },
                ),
                RequestRecord::Cancelled {
                    fingerprint,
                    position,
                    ..
                } => (
                    *fingerprint,
                    RequestTerminal::Cancelled {
                        position: *position,
                    },
                ),
            };
            CommandKind::AcknowledgeRequest {
                request_id,
                request_fingerprint,
                expected,
            }
        })
        .collect();
    for command in confirmations {
        assert_eq!(
            legacy_apply(&mut state, 2, command),
            Outcome::RequestAcknowledged
        );
    }
    assert_eq!(
        legacy_apply(
            &mut state,
            2,
            CommandKind::RotateRequests { expected_epoch: 1 }
        ),
        Outcome::RequestsRotated { epoch: 2 }
    );
    let retired = state.database(9).unwrap();
    assert_eq!(retired.revision, original.revision);
    assert_eq!(retired.commit_hash, original.commit_hash);
    assert_eq!(retired.base_revision, 10);
    assert_eq!(retired.retired_revision, 10);
    assert_eq!(retired.retained_requests, 0);
    assert!(retired.archive.is_none());
    assert_eq!(legacy_recovered_image(&state, 2).bytes(), expected_image);
    assert_eq!(
        state.lookup(legacy_database(), legacy_admission(2), 101, [1; 32]),
        Ok(Lookup::Retired { current_epoch: 2 })
    );
    assert_eq!(
        CellState::decode_bound(&state.encode(), legacy_cell(), state.position, state.limits)
            .unwrap(),
        state
    );
}

#[test]
fn every_real_v3_full_state_prefix_preserves_capacity_then_rejects_unfunded_activation() {
    let state = canonical_v3_trace(
        include_str!("../../test-fixtures/retention-v3-capacity.prefixes.hex"),
        include_str!("../../test-fixtures/retention-v3-capacity.commands.hex"),
        include_str!("../../test-fixtures/retention-v3-capacity.outcomes.hex"),
        include_str!("../../test-fixtures/retention-v3-capacity.state-sha256.hex"),
        Limits {
            max_state_bytes: 8192,
            max_command_bytes: 65_536,
            max_requests_per_database: 64,
            max_result_bytes: 1536,
            ..legacy_limits()
        },
        Err(Reject::Capacity),
    );
    assert_eq!(state.physical_history_version(), 3);
    assert_eq!(state.database(9).unwrap().revision, 3);
    assert_eq!(
        state.last_outcome.unwrap().outcome,
        Outcome::Rejected(Reject::Capacity)
    );
}
