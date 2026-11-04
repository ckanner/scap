use super::*;

fn suspend(state: &CellState, id: u128) -> Command {
    let view = state.database(database().database_id).unwrap();
    command(CommandKind::SuspendDb {
        operation_id: id,
        token: view.owner,
        expected_revision: view.revision,
    })
}

fn published(mut state: CellState) -> (CellState, ArchiveRef, Vec<u8>) {
    let cmd = suspend(&state, operation(10));
    assert!(matches!(
        apply(&mut state, &cmd),
        Outcome::Administrative(AdminResult::Suspended(_))
    ));
    let (archive, bytes) = state.archive_snapshot(database(), admission()).unwrap();
    let cmd = command(CommandKind::PublishArchive {
        expected_owner: state.database(database().database_id).unwrap().owner,
        operation_id: operation(11),
        expected_previous: None,
        archive,
    });
    assert_eq!(
        apply(&mut state, &cmd),
        Outcome::Administrative(AdminResult::ArchivePublished(archive.object_digest))
    );
    (state, archive, bytes)
}

#[test]
fn cold_archive_roundtrip_preserves_receipts_results_cancel_and_revokes_writer() {
    let mut state = active();
    apply(&mut state, &write(1, 0));
    apply(&mut state, &write(2, 1));
    apply(&mut state, &cancel(3));
    let before = state
        .lookup(database(), admission(), request(1), [1; 32])
        .unwrap();
    let history = state
        .recovery_transactions(database(), admission())
        .unwrap()
        .to_vec();
    let (mut state, archive, bytes) = published(state);
    assert_eq!(
        state.database(database().database_id).unwrap().owner.epoch,
        2
    );
    rejected_without_mutation(
        &state,
        &activate(1, WORKER, 20, 2, archive.commit_hash),
        Reject::Fenced,
    );
    rejected_without_mutation(
        &state,
        &activate(2, WORKER, 20, 2, archive.commit_hash),
        Reject::Fenced,
    );
    let prune = command(CommandKind::PruneArchive {
        expected_owner: OwnerToken {
            epoch: 2,
            worker_instance_id: WORKER,
        },
        operation_id: operation(12),
        archive_digest: archive.object_digest,
    });
    assert_eq!(
        apply(&mut state, &prune),
        Outcome::Administrative(AdminResult::ArchivePruned(archive.object_digest))
    );
    assert_eq!(
        apply(&mut state, &prune),
        Outcome::AlreadyApplied(AdminResult::ArchivePruned(archive.object_digest))
    );
    let view = state.database(database().database_id).unwrap();
    assert!(view.suspended && view.cold && !view.active);
    assert_eq!(view.archive, Some(archive));
    assert_eq!(
        state
            .lookup(database(), admission(), request(1), [1; 32])
            .unwrap(),
        before
    );
    assert!(matches!(
        state.lookup(database(), admission(), request(3), [3; 32]),
        Ok(Lookup::Cancelled { .. })
    ));
    assert_eq!(
        state.recovery_transactions(database(), admission()),
        Err(Reject::Cold)
    );
    assert_eq!(
        state.archive_snapshot(database(), admission()),
        Err(Reject::Cold)
    );
    rejected_without_mutation(&state, &claim(2, 77, 20), Reject::Cold);
    rejected_without_mutation(
        &state,
        &activate(2, WORKER, 20, 2, archive.commit_hash),
        Reject::Cold,
    );
    rejected_without_mutation(&state, &write(4, 2), Reject::Fenced);
    state = decode_snapshot(&state).unwrap();
    assert_eq!(
        state.databases[&database().database_id]
            .transactions
            .iter()
            .map(|tx| tx.physical_changes.len())
            .sum::<usize>(),
        0
    );
    let hydrate = command(CommandKind::HydrateArchive {
        operation_id: operation(13),
        archive: bytes,
    });
    assert_eq!(
        apply(&mut state, &hydrate),
        Outcome::Administrative(AdminResult::ArchiveHydrated(archive.object_digest))
    );
    assert_eq!(
        state
            .recovery_transactions(database(), admission())
            .unwrap(),
        history
    );
    assert_eq!(
        apply(&mut state, &hydrate),
        Outcome::AlreadyApplied(AdminResult::ArchiveHydrated(archive.object_digest))
    );
    assert_eq!(decode_snapshot(&state).unwrap(), state);
    apply(&mut state, &claim(2, 77, 14));
    apply(&mut state, &activate(3, 77, 15, 2, archive.commit_hash));
    assert!(state.database(database().database_id).unwrap().active);
}

#[test]
fn archive_publication_requires_current_scope_head_previous_digest_and_exact_bytes() {
    let state = active();
    let (archive, bytes) = state.archive_snapshot(database(), admission()).unwrap();
    let publish = |reference, previous, id| {
        command(CommandKind::PublishArchive {
            expected_owner: OwnerToken {
                epoch: 2,
                worker_instance_id: WORKER,
            },
            operation_id: operation(id),
            expected_previous: previous,
            archive: reference,
        })
    };
    rejected_without_mutation(&state, &publish(archive, None, 20), Reject::Fenced);
    assert_eq!(
        state.archive_snapshot(
            database(),
            Admission {
                principal_id: 22,
                ..admission()
            }
        ),
        Err(Reject::Unauthorized)
    );
    let (mut state, archive, _) = published(state);
    for i in 0..7 {
        let mut invalid = archive;
        let expected = match i {
            0 => {
                invalid.revision += 1;
                Reject::Conflict
            }
            1 => {
                invalid.commit_hash[0] ^= 1;
                Reject::Conflict
            }
            2 => {
                invalid.source.index = u64::MAX;
                Reject::Conflict
            }
            3 => {
                invalid.object_bytes += 1;
                Reject::Invalid
            }
            4 => {
                invalid.object_digest[0] ^= 1;
                Reject::Invalid
            }
            5 => {
                invalid.metadata_digest[0] ^= 1;
                Reject::Invalid
            }
            _ => {
                invalid.source.term = 0;
                Reject::Conflict
            }
        };
        rejected_without_mutation(
            &state,
            &publish(invalid, Some(archive.object_digest), 20),
            expected,
        );
    }
    rejected_without_mutation(&state, &publish(archive, None, 20), Reject::Conflict);
    assert_eq!(
        apply(
            &mut state,
            &publish(archive, Some(archive.object_digest), 20)
        ),
        Outcome::Administrative(AdminResult::ArchivePublished(archive.object_digest))
    );
    let mut constrained = state.clone();
    constrained.limits.max_command_bytes = bytes.len() as u32;
    assert_eq!(
        constrained.archive_snapshot(database(), admission()),
        Err(Reject::TooLarge)
    );
    assert_eq!(
        constrained.execute(
            &publish(archive, Some(archive.object_digest), 21),
            Position {
                term: 10,
                index: 100
            }
        ),
        Err(Reject::Invalid)
    );
}

#[test]
fn archive_suspend_and_prune_are_ordered_fenced_and_idempotent() {
    let state = active();
    let mut wrong = suspend(&state, operation(20));
    if let CommandKind::SuspendDb { token, .. } = &mut wrong.kind {
        token.epoch += 1;
    }
    rejected_without_mutation(&state, &wrong, Reject::Fenced);
    let mut wrong = suspend(&state, operation(20));
    if let CommandKind::SuspendDb {
        expected_revision, ..
    } = &mut wrong.kind
    {
        *expected_revision += 1;
    }
    rejected_without_mutation(&state, &wrong, Reject::Conflict);
    let mut exhausted = state.clone();
    exhausted
        .databases
        .get_mut(&database().database_id)
        .unwrap()
        .owner
        .epoch = u64::MAX;
    let cmd = suspend(&exhausted, operation(20));
    rejected_without_mutation(&exhausted, &cmd, Reject::Exhausted);
    let prune = |digest| {
        command(CommandKind::PruneArchive {
            expected_owner: OwnerToken {
                epoch: 2,
                worker_instance_id: WORKER,
            },
            operation_id: operation(20),
            archive_digest: digest,
        })
    };
    rejected_without_mutation(&state, &prune([0; 32]), Reject::NotFound);
    let (mut state, archive, bytes) = published(state);
    let stale_owner = OwnerToken {
        epoch: 1,
        worker_instance_id: WORKER,
    };
    rejected_without_mutation(
        &state,
        &command(CommandKind::PublishArchive {
            operation_id: operation(30),
            expected_owner: stale_owner,
            expected_previous: Some(archive.object_digest),
            archive,
        }),
        Reject::Fenced,
    );
    rejected_without_mutation(
        &state,
        &command(CommandKind::PruneArchive {
            operation_id: operation(30),
            expected_owner: stale_owner,
            archive_digest: archive.object_digest,
        }),
        Reject::Fenced,
    );
    let again = suspend(&state, operation(21));
    assert_eq!(
        apply(&mut state, &again),
        Outcome::Administrative(AdminResult::Suspended(2))
    );
    rejected_without_mutation(&state, &prune([0; 32]), Reject::Conflict);
    for i in 0..2 {
        let mut mismatch = state.clone();
        let value = mismatch
            .databases
            .get_mut(&database().database_id)
            .unwrap()
            .archive
            .as_mut()
            .unwrap();
        if i == 0 {
            value.revision += 1;
        } else {
            value.commit_hash[0] ^= 1;
        }
        assert_eq!(
            mismatch.execute(
                &prune(archive.object_digest),
                Position {
                    term: 10,
                    index: 100
                }
            ),
            Err(Reject::Conflict)
        );
    }
    apply(&mut state, &claim(2, 77, 22));
    rejected_without_mutation(&state, &prune(archive.object_digest), Reject::Fenced);
    let hydrate = command(CommandKind::HydrateArchive {
        operation_id: operation(23),
        archive: bytes,
    });
    rejected_without_mutation(&state, &hydrate, Reject::Fenced);
    let mut created = boot();
    apply(&mut created, &create());
    let command = suspend(&created, operation(24));
    assert_eq!(
        apply(&mut created, &command),
        Outcome::Administrative(AdminResult::Suspended(0))
    );
    assert_eq!(decode_snapshot(&created).unwrap(), created);
}

#[test]
fn hydrate_rejects_unpublished_damaged_or_cross_scope_archive_without_overwriting_metadata() {
    let state = active();
    let hydrate = |bytes| {
        command(CommandKind::HydrateArchive {
            operation_id: operation(20),
            archive: bytes,
        })
    };
    rejected_without_mutation(&state, &hydrate(Vec::new()), Reject::NotFound);
    let mut state = state;
    apply(&mut state, &write(1, 0));
    let (mut state, archive, bytes) = published(state);
    rejected_without_mutation(&state, &hydrate(Vec::new()), Reject::Invalid);
    let mut corrupt = bytes.clone();
    corrupt[0] ^= 1;
    rejected_without_mutation(&state, &hydrate(corrupt), Reject::Invalid);
    apply(
        &mut state,
        &command(CommandKind::PruneArchive {
            expected_owner: OwnerToken {
                epoch: 2,
                worker_instance_id: WORKER,
            },
            operation_id: operation(12),
            archive_digest: archive.object_digest,
        }),
    );
    let publish = command(CommandKind::PublishArchive {
        expected_owner: OwnerToken {
            epoch: 2,
            worker_instance_id: WORKER,
        },
        operation_id: operation(30),
        expected_previous: Some(archive.object_digest),
        archive,
    });
    rejected_without_mutation(&state, &publish, Reject::Fenced);
    // A hostile/mismatched archived record cannot replace any retained field.
    // This direct codec exercise also checks malformed internals independently
    // of the outer immutable object's digest gate.
    for index in 0..8 {
        let mut target = state.databases[&database().database_id].clone();
        let tx = &mut target.transactions[0];
        match index {
            0 => tx.admission.admission_id += 1,
            1 => tx.request_fingerprint[0] ^= 1,
            2 => tx.commit.receipt.sequence += 1,
            3 => tx.result.push(0),
            4 => tx.commit_hash[0] ^= 1,
            5 => target.transactions.clear(),
            6 => target.identity.incarnation += 1,
            _ => target.identity.placement_generation += 1,
        }
        assert!(codec::decode_archive(&bytes, identity(), &target, archive, limits()).is_err());
    }
    assert!(codec::decode_archive(
        &bytes,
        CellIdentity {
            cell_id: 999,
            ..identity()
        },
        &state.databases[&database().database_id],
        archive,
        limits()
    )
    .is_err());
    let mut wrong_ref = archive;
    wrong_ref.source.index += 1;
    assert!(codec::decode_archive(
        &bytes,
        identity(),
        &state.databases[&database().database_id],
        wrong_ref,
        limits()
    )
    .is_err());
    let mut changed = state.clone();
    changed
        .databases
        .get_mut(&database().database_id)
        .unwrap()
        .transactions[0]
        .result
        .push(0);
    assert_eq!(
        changed.execute(
            &hydrate(bytes.clone()),
            Position {
                term: 10,
                index: 100
            }
        ),
        Err(Reject::Invalid)
    );
    for end in 0..body(&bytes).len() {
        assert!(codec::decode_archive(
            &envelope(&bytes, &body(&bytes)[..end]),
            identity(),
            &state.databases[&database().database_id],
            archive,
            limits()
        )
        .is_err());
    }
    let trailing = mutate_body(&bytes, |body| body.push(0));
    assert!(codec::decode_archive(
        &trailing,
        identity(),
        &state.databases[&database().database_id],
        archive,
        limits()
    )
    .is_err());
}

#[test]
fn v1_hot_state_and_old_commands_upgrade_explicitly_without_cold_defaults() {
    fn legacy_state(state: &CellState) -> Vec<u8> {
        let mut template = state.encode();
        template[8] = 1;
        let mut bytes = body(&template).to_vec();
        // v2 adds three flags for this unarchived database immediately before
        // the administrative count. All original hashes stay unchanged.
        let extension = unique_offset(&bytes, &operation(1).to_be_bytes()) - 8 - 3;
        assert_eq!(&bytes[extension..extension + 3], &[0, 0, 0]);
        bytes.drain(extension..extension + 3);
        envelope(&template, &bytes)
    }
    let original = rich();
    let legacy = legacy_state(&original);
    let decoded =
        CellState::decode_bound(&legacy, identity(), original.position, limits()).unwrap();
    assert_eq!(decoded, original);
    assert_eq!(decoded.encode()[8], 2);
    // v2 envelope headers do not change the existing administrative intent
    // bytes: old durable IDs must still resolve after an upgrade.
    let mut replayed = decoded.clone();
    assert_eq!(
        apply(&mut replayed, &create()),
        Outcome::AlreadyApplied(AdminResult::Created)
    );
    for mut old_command in [
        claim(0, WORKER, 2),
        activate(1, WORKER, 3, 0, [0; 32]),
        command(CommandKind::AuthFence {
            operation_id: operation(4),
            expected_epoch: 1,
            policy: policy(),
        }),
    ] {
        old_command.admission.auth_epoch = 2;
        assert!(matches!(
            apply(&mut replayed, &old_command),
            Outcome::AlreadyApplied(_)
        ));
    }
    let mut never_claimed = boot();
    apply(&mut never_claimed, &create());
    // v1 had no suspended flag, including databases never assigned an owner.
    never_claimed
        .databases
        .get_mut(&database().database_id)
        .unwrap()
        .suspended = false;
    let mut upgraded = CellState::decode_bound(
        &legacy_state(&never_claimed),
        identity(),
        never_claimed.position,
        limits(),
    )
    .unwrap();
    let pause = suspend(&upgraded, operation(2));
    assert_eq!(
        apply(&mut upgraded, &pause),
        Outcome::Administrative(AdminResult::Suspended(0))
    );
    assert_eq!(
        upgraded.database(database().database_id).unwrap().owner,
        OwnerToken {
            epoch: 0,
            worker_instance_id: 0
        }
    );
    assert_eq!(decode_snapshot(&upgraded).unwrap(), upgraded);
    for command in [
        create(),
        claim(0, WORKER, 2),
        activate(1, WORKER, 3, 0, [0; 32]),
        write(1, 0),
        cancel(2),
        command(CommandKind::AuthFence {
            operation_id: operation(4),
            expected_epoch: 1,
            policy: policy(),
        }),
    ] {
        let mut bytes = encode_command(&command, limits()).unwrap();
        bytes[8] = 1;
        assert_eq!(
            codec::decode_command(&envelope(&bytes, body(&bytes)), limits()).unwrap(),
            command
        );
    }
    let old = AppliedOutcome {
        position: Position { term: 1, index: 1 },
        outcome: Outcome::Rejected(Reject::Fenced),
    };
    let mut bytes = encode_applied_outcome(&old);
    bytes[8] = 1;
    assert_eq!(
        decode_applied_outcome(&envelope(&bytes, body(&bytes)), old.position).unwrap(),
        old
    );
    let (state, archive, data) = published(active());
    let commands = [
        suspend(&state, operation(20)),
        command(CommandKind::PublishArchive {
            expected_owner: OwnerToken {
                epoch: 2,
                worker_instance_id: WORKER,
            },
            operation_id: operation(20),
            expected_previous: Some(archive.object_digest),
            archive,
        }),
        command(CommandKind::PruneArchive {
            expected_owner: OwnerToken {
                epoch: 2,
                worker_instance_id: WORKER,
            },
            operation_id: operation(20),
            archive_digest: archive.object_digest,
        }),
        command(CommandKind::HydrateArchive {
            operation_id: operation(20),
            archive: data.clone(),
        }),
    ];
    for command in commands {
        let mut bytes = encode_command(&command, limits()).unwrap();
        bytes[8] = 1;
        assert!(codec::decode_command(&envelope(&bytes, body(&bytes)), limits()).is_err());
        let bytes = encode_command(&command, limits()).unwrap();
        for end in 0..body(&bytes).len() {
            assert!(
                codec::decode_command(&envelope(&bytes, &body(&bytes)[..end]), limits()).is_err()
            );
        }
    }
    for result in [
        AdminResult::Suspended(1),
        AdminResult::ArchivePublished([1; 32]),
        AdminResult::ArchivePruned([1; 32]),
        AdminResult::ArchiveHydrated([1; 32]),
    ] {
        let mut invalid = original.clone();
        invalid
            .administration
            .get_mut(&operation(1))
            .unwrap()
            .result = result.clone();
        assert_eq!(
            CellState::decode_bound(
                &legacy_state(&invalid),
                identity(),
                invalid.position,
                limits()
            ),
            Err(Error::Malformed(
                "new administrative result in legacy state"
            ))
        );
        for outcome in [
            Outcome::Administrative(result.clone()),
            Outcome::AlreadyApplied(result),
        ] {
            let mut invalid = original.clone();
            invalid.last_outcome.as_mut().unwrap().outcome = outcome.clone();
            assert_eq!(
                CellState::decode_bound(
                    &legacy_state(&invalid),
                    identity(),
                    invalid.position,
                    limits()
                ),
                Err(Error::Malformed("new outcome in legacy state"))
            );
            let value = AppliedOutcome {
                position: old.position,
                outcome,
            };
            let mut bytes = encode_applied_outcome(&value);
            bytes[8] = 1;
            assert!(decode_applied_outcome(&envelope(&bytes, body(&bytes)), old.position).is_err());
        }
    }
    let value = AppliedOutcome {
        position: old.position,
        outcome: Outcome::Rejected(Reject::Cold),
    };
    let mut bytes = encode_applied_outcome(&value);
    bytes[8] = 1;
    assert!(decode_applied_outcome(&envelope(&bytes, body(&bytes)), old.position).is_err());
    let mut legacy = data;
    legacy[8] = 1;
    assert!(codec::decode_archive(
        &envelope(&legacy, body(&legacy)),
        identity(),
        &state.databases[&database().database_id],
        archive,
        limits()
    )
    .is_err());
}

#[test]
fn cold_snapshot_rejects_partial_payload_and_broken_reference_or_metadata() {
    let mut hot = active();
    apply(&mut hot, &write(1, 0));
    apply(&mut hot, &write(2, 1));
    let (mut state, archive, _) = published(hot.clone());
    apply(
        &mut state,
        &command(CommandKind::PruneArchive {
            expected_owner: OwnerToken {
                epoch: 2,
                worker_instance_id: WORKER,
            },
            operation_id: operation(12),
            archive_digest: archive.object_digest,
        }),
    );
    for index in 0..15 {
        let mut damaged = state.clone();
        let db = damaged.databases.get_mut(&database().database_id).unwrap();
        match index {
            0 => db.active = true,
            1 => db.suspended = false,
            2 => db.archive = None,
            3 => db.archive.as_mut().unwrap().source.index = 999,
            4 => db.archive.as_mut().unwrap().revision = 99,
            5 => db.archive.as_mut().unwrap().object_bytes = 0,
            6 => db.archive.as_mut().unwrap().object_bytes = 8192,
            7 => db.archive.as_mut().unwrap().object_digest = [0; 32],
            8 => db.archive.as_mut().unwrap().commit_hash = [1; 32],
            9 => db.archive.as_mut().unwrap().metadata_digest = [1; 32],
            10 => {
                let hash = db.transactions[0].commit_hash;
                let value = db.archive.as_mut().unwrap();
                value.revision = 1;
                value.commit_hash = hash;
            }
            11 => db.transactions[0].physical_changes = vec![1],
            12 => db.archive.as_mut().unwrap().source = Position { term: 1, index: 1 },
            13 => {
                let value = db.archive.as_mut().unwrap();
                value.revision = 1;
                value.commit_hash = [1; 32];
            }
            _ => db.transactions[0].result.push(1),
        }
        assert!(decode_snapshot(&damaged).is_err(), "cold fault {index}");
    }
    let target = &hot.databases[&database().database_id];
    for index in 0..3 {
        let mut source = target.clone();
        match index {
            0 => source.transactions[0].physical_changes.clear(),
            1 => source.transactions[0].physical_changes[0] ^= 1,
            _ => source.transactions[0].commit_hash = [42; 32],
        }
        let bytes = codec::encode_archive(identity(), &source, archive.source);
        let retained = if index == 2 { &source } else { target };
        assert!(codec::decode_archive(&bytes, identity(), retained, archive, limits()).is_err());
    }
    let mut damaged = state.clone();
    damaged
        .administration
        .get_mut(&operation(10))
        .unwrap()
        .result = AdminResult::Suspended(999);
    assert!(decode_snapshot(&damaged).is_err());
    for operation_id in [operation(11), operation(12)] {
        let mut damaged = state.clone();
        damaged
            .administration
            .get_mut(&operation_id)
            .unwrap()
            .result = AdminResult::ArchivePublished([0; 32]);
        assert!(decode_snapshot(&damaged).is_err());
    }
    let mut old_source = archive;
    old_source.source = Position { term: 1, index: 1 };
    assert_eq!(
        hot.execute(
            &command(CommandKind::PublishArchive {
                expected_owner: OwnerToken {
                    epoch: 2,
                    worker_instance_id: WORKER
                },
                operation_id: operation(30),
                expected_previous: None,
                archive: old_source
            }),
            Position {
                term: 10,
                index: 100
            }
        ),
        Err(Reject::Fenced)
    );
}

#[test]
fn lifecycle_codec_truncation_and_ordering_guards_cover_full_archive_and_outcomes() {
    let mut state = active();
    apply(&mut state, &write(1, 0));
    let (state, archive, bytes) = published(state);
    let db = &state.databases[&database().database_id];
    assert!(codec::decode_archive(&[], identity(), db, archive, limits()).is_err());
    for end in 0..body(&state.encode()).len() {
        let image = state.encode();
        assert!(CellState::decode_bound(
            &envelope(&image, &body(&image)[..end]),
            identity(),
            state.position,
            limits()
        )
        .is_err());
    }
    for result in [
        AdminResult::Suspended(2),
        AdminResult::ArchivePublished([1; 32]),
        AdminResult::ArchivePruned([1; 32]),
        AdminResult::ArchiveHydrated([1; 32]),
    ] {
        let value = AppliedOutcome {
            position: state.position,
            outcome: Outcome::Administrative(result),
        };
        let image = encode_applied_outcome(&value);
        for end in 0..body(&image).len() {
            assert!(decode_applied_outcome(
                &envelope(&image, &body(&image)[..end]),
                state.position
            )
            .is_err());
        }
    }
    let mut old_source = archive;
    old_source.source = Position { term: 1, index: 1 };
    rejected_without_mutation(
        &state,
        &command(CommandKind::PublishArchive {
            expected_owner: OwnerToken {
                epoch: 2,
                worker_instance_id: WORKER,
            },
            operation_id: operation(30),
            expected_previous: Some(archive.object_digest),
            archive: old_source,
        }),
        Reject::Conflict,
    );
    let mut waking = state.clone();
    apply(&mut waking, &claim(2, 77, 20));
    rejected_without_mutation(
        &waking,
        &command(CommandKind::PublishArchive {
            expected_owner: OwnerToken {
                epoch: 2,
                worker_instance_id: WORKER,
            },
            operation_id: operation(30),
            expected_previous: Some(archive.object_digest),
            archive,
        }),
        Reject::Fenced,
    );
    apply(&mut waking, &activate(3, 77, 21, 1, archive.commit_hash));
    rejected_without_mutation(
        &waking,
        &command(CommandKind::PruneArchive {
            expected_owner: OwnerToken {
                epoch: 2,
                worker_instance_id: WORKER,
            },
            operation_id: operation(30),
            archive_digest: archive.object_digest,
        }),
        Reject::Fenced,
    );
    rejected_without_mutation(
        &waking,
        &command(CommandKind::HydrateArchive {
            operation_id: operation(30),
            archive: bytes,
        }),
        Reject::Fenced,
    );
}

#[test]
fn read_metadata_is_fresh_authorized_and_available_without_waking_cold_data() {
    let mut state = active();
    apply(&mut state, &write(1, 0));
    let (mut state, archive, _) = published(state);
    let reader = Admission {
        principal_id: 33,
        ..admission()
    };
    assert_eq!(state.metadata(database(), reader).unwrap().revision, 1);
    apply(
        &mut state,
        &command(CommandKind::PruneArchive {
            expected_owner: OwnerToken {
                epoch: 2,
                worker_instance_id: WORKER,
            },
            operation_id: operation(12),
            archive_digest: archive.object_digest,
        }),
    );
    assert!(state.metadata(database(), reader).unwrap().cold);
    assert_eq!(
        state.metadata(
            database(),
            Admission {
                auth_epoch: 2,
                ..reader
            }
        ),
        Err(Reject::Unauthorized)
    );
    assert_eq!(
        state.metadata(
            database(),
            Admission {
                principal_id: 44,
                ..reader
            }
        ),
        Err(Reject::Unauthorized)
    );
    assert_eq!(
        state.metadata(
            DatabaseIdentity {
                incarnation: 999,
                ..database()
            },
            reader
        ),
        Err(Reject::Fenced)
    );
    assert_eq!(
        state.metadata(
            DatabaseIdentity {
                database_id: 999,
                ..database()
            },
            reader
        ),
        Err(Reject::NotFound)
    );
    assert_eq!(
        state.archive_status(database(), reader),
        Err(Reject::Unauthorized)
    );
    assert!(state.archive_status(database(), admission()).unwrap().cold);
}

#[test]
fn transaction_preflight_needs_both_permissions_current_owner_and_exact_head() {
    let mut state = active();
    let owner = state.database(database().database_id).unwrap().owner;
    let view = state
        .authorize_write(database(), admission(), owner, 0)
        .unwrap();
    assert_eq!(view.position, state.position());
    assert_eq!(view.admission, admission());
    assert_eq!(
        state.authorize_write(database(), admission(), owner, 1),
        Err(Reject::Conflict)
    );
    assert_eq!(
        state.authorize_write(
            database(),
            Admission {
                principal_id: 33,
                ..admission()
            },
            owner,
            0,
        ),
        Err(Reject::Unauthorized)
    );
    state
        .databases
        .get_mut(&database().database_id)
        .unwrap()
        .policy[1]
        .permissions = WRITE;
    assert_eq!(
        state.authorize_write(
            database(),
            Admission {
                principal_id: 22,
                ..admission()
            },
            owner,
            0,
        ),
        Err(Reject::Unauthorized)
    );
    assert_eq!(
        state.authorize_write(database(), admission(), OwnerToken { epoch: 2, ..owner }, 0,),
        Err(Reject::Fenced)
    );
}

#[test]
fn tracked_results_belong_to_each_requested_entry_not_the_last_batch_outcome() {
    let state = active();
    let commands = [write(1, 0), write(1, 0), claim(1, 88, 4), write(2, 1)];
    let entries: Vec<_> = commands
        .iter()
        .enumerate()
        .map(|(offset, command)| Entry {
            term: 2,
            index: state.position().index + offset as u64 + 1,
            data: encode_command(command, limits()).unwrap().into(),
            ..Entry::default()
        })
        .collect();
    let requested = [entries[0].index, entries[1].index, entries[3].index];
    let mut app = CellApplication::new(identity(), limits()).unwrap();
    let batch = app
        .apply_with_results(&state.encode(), &entries, &requested)
        .unwrap();
    assert_eq!(batch.state, app.apply(&state.encode(), &entries).unwrap());
    let outcomes: Vec<_> = batch
        .results
        .iter()
        .zip(requested)
        .map(|(bytes, index)| {
            decode_applied_outcome(bytes, Position { term: 2, index })
                .unwrap()
                .outcome
        })
        .collect();
    assert!(matches!(outcomes[0], Outcome::Accepted(_)));
    assert!(matches!(outcomes[1], Outcome::AlreadyCommitted(_)));
    assert_eq!(outcomes[2], Outcome::Rejected(Reject::Fenced));
    assert!(app
        .apply_with_results(&state.encode(), &entries, &[])
        .unwrap()
        .results
        .is_empty());
    for invalid in [
        vec![999],
        vec![entries[1].index, entries[0].index],
        vec![entries[0].index; 2],
    ] {
        assert!(matches!(
            app.apply_with_results(&state.encode(), &entries, &invalid),
            Err(Error::Position)
        ));
    }
    assert!(app.apply_with_results(&[], &[], &[]).is_err());
    let invalid = Entry {
        term: 1,
        index: 999,
        ..Entry::default()
    };
    assert!(matches!(
        app.apply_with_results(&state.encode(), &[invalid], &[]),
        Err(Error::Position)
    ));
    for initial in [boot(), active()] {
        let entry = Entry {
            term: 2,
            index: initial.position().index + 1,
            ..Entry::default()
        };
        assert!(matches!(
            app.apply_with_results(
                &initial.encode(),
                std::slice::from_ref(&entry),
                &[entry.index]
            ),
            Err(Error::Position)
        ));
    }
    assert_eq!(
        app.apply_with_results(&state.encode(), &[], &[])
            .unwrap()
            .state,
        state.encode()
    );
}

#[test]
fn tracked_outcome_codec_is_versioned_bounded_and_position_bound() {
    let mut state = active();
    apply(&mut state, &write(1, 0));
    let value = state.last_outcome().unwrap().clone();
    let bytes = encode_applied_outcome(&value);
    assert!(bytes.len() <= MAX_APPLIED_OUTCOME_BYTES as usize);
    assert_eq!(
        decode_applied_outcome(&bytes, value.position).unwrap(),
        value
    );
    for position in [
        Position {
            term: 0,
            ..value.position
        },
        Position {
            index: 0,
            ..value.position
        },
        Position {
            index: 99,
            ..value.position
        },
    ] {
        assert_eq!(
            decode_applied_outcome(&bytes, position),
            Err(Error::Position)
        );
    }
    assert_eq!(
        decode_applied_outcome(
            &vec![0; MAX_APPLIED_OUTCOME_BYTES as usize + 1],
            value.position
        ),
        Err(Error::Limit)
    );
    for end in 0..body(&bytes).len() {
        assert!(
            decode_applied_outcome(&envelope(&bytes, &body(&bytes)[..end]), value.position)
                .is_err()
        );
    }
    for invalid in [
        mutate_body(&bytes, |body| body.push(0)),
        mutate_body(&bytes, |body| body[16] = 255),
        vec![0; 2],
    ] {
        assert!(decode_applied_outcome(&invalid, value.position).is_err());
    }
}

const PRINCIPAL: u128 = 11;
const WORKER: u128 = 77;
const GENESIS: Position = Position { term: 1, index: 1 };

fn identity() -> CellIdentity {
    CellIdentity {
        cell_id: 41,
        cell_incarnation: 9,
    }
}
fn database() -> DatabaseIdentity {
    DatabaseIdentity {
        database_id: 101,
        incarnation: 3,
        placement_generation: 2,
    }
}
fn limits() -> Limits {
    Limits {
        max_state_bytes: 65_536,
        max_command_bytes: 8192,
        max_databases: 3,
        max_policy_grants: 4,
        max_admin_operations: 32,
        max_requests_per_database: 16,
        max_transaction_bytes: 1024,
        max_result_bytes: 1024,
    }
}
fn operation(number: u128) -> u128 {
    0xaaaa_bbbb_cccc_dddd_0000_0000_0000_0000 | number
}
fn request(number: u128) -> u128 {
    0xdddd_cccc_bbbb_aaaa_0000_0000_0000_0000 | number
}
fn admission() -> Admission {
    Admission {
        principal_id: PRINCIPAL,
        credential_id: 12,
        admission_id: 13,
        auth_epoch: 1,
    }
}
fn policy() -> Vec<Grant> {
    vec![
        Grant {
            principal_id: PRINCIPAL,
            permissions: READ | WRITE | ADMIN,
        },
        Grant {
            principal_id: 22,
            permissions: READ | WRITE,
        },
        Grant {
            principal_id: 33,
            permissions: READ,
        },
        Grant {
            principal_id: 44,
            permissions: ADMIN,
        },
    ]
}
fn command(kind: CommandKind) -> Command {
    Command {
        cell: identity(),
        database: database(),
        admission: admission(),
        kind,
    }
}
fn create() -> Command {
    command(CommandKind::Create {
        operation_id: operation(1),
        policy: policy(),
    })
}
fn claim(epoch: u64, worker: u128, op: u128) -> Command {
    command(CommandKind::ClaimOwner {
        operation_id: operation(op),
        expected_epoch: epoch,
        worker_instance_id: worker,
    })
}
fn activate(epoch: u64, worker: u128, op: u128, revision: u64, hash: [u8; 32]) -> Command {
    command(CommandKind::ActivateOwner {
        operation_id: operation(op),
        token: OwnerToken {
            epoch,
            worker_instance_id: worker,
        },
        restored_revision: revision,
        restored_hash: hash,
    })
}
fn cancel(id: u128) -> Command {
    command(CommandKind::ResolveOrCancel {
        request_id: request(id),
        request_fingerprint: [id as u8; 32],
    })
}
fn write(id: u128, predecessor: u64) -> Command {
    let physical_changes = vec![0, 255, id as u8, 42];
    command(CommandKind::Commit {
        write: PreparedWrite {
            ticket: CommitTicket {
                cell_id: identity().cell_id,
                cell_incarnation: identity().cell_incarnation,
                database_id: database().database_id,
                incarnation: database().incarnation,
                placement_generation: database().placement_generation,
                owner_epoch: 1,
                worker_instance_id: WORKER,
                auth_epoch: 1,
                request_id: request(id),
                predecessor,
                payload_digest: payload_digest(&physical_changes),
            },
            physical_changes,
        },
        request_fingerprint: [id as u8; 32],
        result: vec![id as u8, 0, 255],
    })
}
fn boot_with(limits: Limits) -> CellState {
    CellState::bootstrap(identity(), PRINCIPAL, GENESIS, limits).unwrap()
}
fn boot() -> CellState {
    let state = boot_with(limits());
    assert_eq!(state.identity(), identity());
    state
}
fn apply_at(state: &mut CellState, cmd: &Command, term: u64) -> Outcome {
    let position = Position {
        term,
        index: state.position.index + 1,
    };
    let entry = Entry {
        term,
        index: position.index,
        data: encode_command(cmd, state.limits).unwrap().into(),
        ..Entry::default()
    };
    let mut app = CellApplication::new(identity(), state.limits).unwrap();
    let next = app.apply(&state.encode(), &[entry]).unwrap();
    *state = CellState::decode_bound(&next, identity(), position, state.limits).unwrap();
    state.last_outcome().unwrap().outcome.clone()
}
fn apply(state: &mut CellState, cmd: &Command) -> Outcome {
    apply_at(state, cmd, state.position.term)
}
fn active_with(limits: Limits) -> CellState {
    let mut state = boot_with(limits);
    assert_eq!(
        apply(&mut state, &create()),
        Outcome::Administrative(AdminResult::Created)
    );
    assert_eq!(
        apply(&mut state, &claim(0, WORKER, 2)),
        Outcome::Administrative(AdminResult::OwnerClaimed(OwnerToken {
            epoch: 1,
            worker_instance_id: WORKER
        }))
    );
    assert_eq!(
        apply(&mut state, &activate(1, WORKER, 3, 0, [0; 32])),
        Outcome::Administrative(AdminResult::OwnerActivated)
    );
    state
}
fn active() -> CellState {
    active_with(limits())
}
fn rich() -> CellState {
    let mut state = active();
    assert!(matches!(
        apply_at(&mut state, &write(1, 0), 2),
        Outcome::Accepted(_)
    ));
    assert!(matches!(
        apply_at(&mut state, &write(2, 1), 3),
        Outcome::Accepted(_)
    ));
    assert_eq!(apply(&mut state, &cancel(3)), Outcome::Cancelled);
    let mut fence = command(CommandKind::AuthFence {
        operation_id: operation(4),
        expected_epoch: 1,
        policy: policy(),
    });
    assert_eq!(
        apply(&mut state, &fence),
        Outcome::Administrative(AdminResult::AuthChanged(2))
    );
    fence.admission.auth_epoch = 2;
    assert_eq!(
        apply(&mut state, &fence),
        Outcome::AlreadyApplied(AdminResult::AuthChanged(2))
    );
    state
}
fn current_admission(epoch: u64) -> Admission {
    Admission {
        auth_epoch: epoch,
        ..admission()
    }
}
fn rejected_without_mutation(state: &CellState, cmd: &Command, reason: Reject) {
    let mut next = state.clone();
    let before = state.position;
    assert_eq!(apply(&mut next, cmd), Outcome::Rejected(reason));
    assert_eq!(next.databases, state.databases);
    assert_eq!(next.administration, state.administration);
    assert_eq!(next.position.index, before.index + 1);
}
fn commit_parts(cmd: &mut Command) -> (&mut PreparedWrite, &mut [u8; 32], &mut Vec<u8>) {
    if let CommandKind::Commit {
        write,
        request_fingerprint,
        result,
    } = &mut cmd.kind
    {
        (write, request_fingerprint, result)
    } else {
        panic!("commit fixture")
    }
}
fn envelope(original: &[u8], body: &[u8]) -> Vec<u8> {
    let mut bytes = original[..9].to_vec();
    bytes.extend_from_slice(&(body.len() as u64).to_be_bytes());
    bytes.extend_from_slice(body);
    bytes.extend_from_slice(&payload_digest(&bytes));
    bytes
}
fn body(bytes: &[u8]) -> &[u8] {
    &bytes[17..bytes.len() - 32]
}
fn mutate_body(bytes: &[u8], change: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut payload = body(bytes).to_vec();
    change(&mut payload);
    envelope(bytes, &payload)
}
fn decode_snapshot(state: &CellState) -> Result<CellState, Error> {
    CellState::decode_bound(&state.encode(), identity(), state.position, state.limits)
}

#[test]
fn explicit_bootstrap_configuration_and_snapshot_binding() {
    let state = boot();
    assert_eq!(state.position(), GENESIS);
    assert_eq!(
        decode_snapshot(&state).unwrap().bootstrap_administrator(),
        PRINCIPAL
    );
    assert!(state.last_outcome().is_none());
    assert!(state.database(999).is_none());
    assert_eq!(decode_snapshot(&state).unwrap(), state);
    assert_eq!(
        CellState::decode_bound(
            &state.encode(),
            identity(),
            Position { term: 2, index: 1 },
            limits()
        ),
        Err(Error::Position)
    );
    for bad in [
        CellIdentity {
            cell_id: 0,
            ..identity()
        },
        CellIdentity {
            cell_incarnation: 0,
            ..identity()
        },
    ] {
        assert!(CellState::bootstrap(bad, PRINCIPAL, GENESIS, limits()).is_err());
        assert!(CellApplication::new(bad, limits()).is_err());
    }
    for (admin, position) in [
        (0, GENESIS),
        (PRINCIPAL, Position { term: 0, index: 1 }),
        (PRINCIPAL, Position { term: 1, index: 0 }),
    ] {
        assert!(CellState::bootstrap(identity(), admin, position, limits()).is_err());
    }
    for i in 0..8 {
        let mut bound = limits();
        match i {
            0 => bound.max_state_bytes = 1023,
            1 => bound.max_command_bytes = 0,
            2 => bound.max_databases = 0,
            3 => bound.max_policy_grants = 0,
            4 => bound.max_admin_operations = 0,
            5 => bound.max_requests_per_database = 0,
            6 => bound.max_transaction_bytes = 0,
            _ => bound.max_result_bytes = 0,
        }
        assert!(CellApplication::new(identity(), bound).is_err());
    }
    assert_eq!(format!("{}", Error::Binding), "Binding");
    let mut app = CellApplication::new(identity(), limits()).unwrap();
    assert_eq!(app.apply(&state.encode(), &[]).unwrap(), state.encode());
}

#[test]
fn every_command_roundtrips_and_control_results_are_idempotent() {
    let commands = [
        create(),
        claim(0, WORKER, 2),
        activate(1, WORKER, 3, 0, [0; 32]),
        command(CommandKind::AuthFence {
            operation_id: operation(4),
            expected_epoch: 1,
            policy: policy(),
        }),
        write(1, 0),
        cancel(2),
    ];
    for cmd in commands {
        assert_eq!(
            codec::decode_command(&encode_command(&cmd, limits()).unwrap(), limits()).unwrap(),
            cmd
        );
    }
    let mut state = boot();
    assert_eq!(
        apply(&mut state, &create()),
        Outcome::Administrative(AdminResult::Created)
    );
    assert_eq!(
        apply(&mut state, &create()),
        Outcome::AlreadyApplied(AdminResult::Created)
    );
    let claim = claim(0, WORKER, 2);
    assert!(matches!(
        apply(&mut state, &claim),
        Outcome::Administrative(AdminResult::OwnerClaimed(_))
    ));
    let mut replay = claim.clone();
    replay.admission.credential_id += 10;
    replay.admission.admission_id += 10;
    assert!(matches!(
        apply(&mut state, &replay),
        Outcome::AlreadyApplied(AdminResult::OwnerClaimed(_))
    ));
    let activation = activate(1, WORKER, 3, 0, [0; 32]);
    assert_eq!(
        apply(&mut state, &activation),
        Outcome::Administrative(AdminResult::OwnerActivated)
    );
    assert_eq!(
        apply(&mut state, &activation),
        Outcome::AlreadyApplied(AdminResult::OwnerActivated)
    );
    assert_eq!(decode_snapshot(&state).unwrap(), state);
}

#[test]
fn creation_and_every_administrative_rejection_preserve_existing_state() {
    let empty = boot();
    let mut cmd = create();
    cmd.admission.principal_id = 22;
    rejected_without_mutation(&empty, &cmd, Reject::Unauthorized);
    cmd = create();
    cmd.admission.auth_epoch = 2;
    rejected_without_mutation(&empty, &cmd, Reject::Unauthorized);
    cmd = create();
    if let CommandKind::Create { operation_id, .. } = &mut cmd.kind {
        *operation_id = 0;
    }
    rejected_without_mutation(&empty, &cmd, Reject::Invalid);
    for invalid in [
        vec![],
        vec![Grant {
            principal_id: 0,
            permissions: 7,
        }],
        vec![Grant {
            principal_id: 11,
            permissions: 0,
        }],
        vec![Grant {
            principal_id: 11,
            permissions: 8,
        }],
        vec![Grant {
            principal_id: 11,
            permissions: READ,
        }],
        vec![
            Grant {
                principal_id: 11,
                permissions: 7,
            },
            Grant {
                principal_id: 11,
                permissions: 7,
            },
        ],
        vec![
            Grant {
                principal_id: 22,
                permissions: 7,
            },
            Grant {
                principal_id: 11,
                permissions: 7,
            },
        ],
        vec![
            Grant {
                principal_id: 11,
                permissions: 7
            };
            5
        ],
    ] {
        let cmd = command(CommandKind::Create {
            operation_id: operation(1),
            policy: invalid,
        });
        rejected_without_mutation(&empty, &cmd, Reject::Invalid);
    }
    let state = active();
    let mut exists = create();
    if let CommandKind::Create { operation_id, .. } = &mut exists.kind {
        *operation_id = operation(10);
    }
    rejected_without_mutation(&state, &exists, Reject::Exists);
    rejected_without_mutation(&state, &claim(0, WORKER, 10), Reject::Fenced);
    rejected_without_mutation(&state, &claim(1, 0, 10), Reject::Fenced);
    rejected_without_mutation(&state, &activate(0, 0, 10, 0, [0; 32]), Reject::Fenced);
    rejected_without_mutation(
        &state,
        &activate(1, WORKER + 1, 10, 0, [0; 32]),
        Reject::Fenced,
    );
    rejected_without_mutation(
        &state,
        &activate(1, WORKER, 10, 1, [0; 32]),
        Reject::Conflict,
    );
    rejected_without_mutation(
        &state,
        &activate(1, WORKER, 10, 0, [1; 32]),
        Reject::Conflict,
    );
    let fence = command(CommandKind::AuthFence {
        operation_id: operation(10),
        expected_epoch: 2,
        policy: policy(),
    });
    rejected_without_mutation(&state, &fence, Reject::Conflict);
    let bad_policy = command(CommandKind::AuthFence {
        operation_id: operation(10),
        expected_epoch: 1,
        policy: vec![],
    });
    rejected_without_mutation(&state, &bad_policy, Reject::Invalid);
    let mut unauthorized = claim(1, 88, 10);
    unauthorized.admission.principal_id = 22;
    rejected_without_mutation(&state, &unauthorized, Reject::Unauthorized);
}

#[test]
fn request_scope_and_admission_fields_are_independently_checked() {
    let state = active();
    for i in 0..6 {
        let mut cmd = write(1, 0);
        match i {
            0 => cmd.cell.cell_id += 1,
            1 => cmd.cell.cell_incarnation += 1,
            2 => cmd.database.database_id = 0,
            3 => cmd.database.incarnation = 0,
            4 => cmd.database.placement_generation = 0,
            _ => cmd.database.incarnation += 1,
        }
        rejected_without_mutation(&state, &cmd, Reject::Fenced);
    }
    for i in 0..4 {
        let mut cmd = write(1, 0);
        match i {
            0 => cmd.admission.principal_id = 0,
            1 => cmd.admission.credential_id = 0,
            2 => cmd.admission.admission_id = 0,
            _ => cmd.admission.auth_epoch = 0,
        }
        rejected_without_mutation(&state, &cmd, Reject::Unauthorized);
    }
    let mut cmd = write(1, 0);
    cmd.database.database_id += 1;
    rejected_without_mutation(&state, &cmd, Reject::NotFound);
    cmd = write(1, 0);
    cmd.admission.auth_epoch += 1;
    rejected_without_mutation(&state, &cmd, Reject::Unauthorized);
    cmd = write(1, 0);
    cmd.admission.principal_id = 33;
    rejected_without_mutation(&state, &cmd, Reject::Unauthorized);
    for i in 0..6 {
        let mut cmd = write(1, 0);
        let ticket = &mut commit_parts(&mut cmd).0.ticket;
        match i {
            0 => ticket.cell_id += 1,
            1 => ticket.cell_incarnation += 1,
            2 => ticket.database_id += 1,
            3 => ticket.incarnation += 1,
            4 => ticket.placement_generation += 1,
            _ => ticket.auth_epoch += 1,
        }
        rejected_without_mutation(&state, &cmd, Reject::Fenced);
    }
}

#[test]
fn physical_acceptance_rejection_and_original_result_identity() {
    let mut state = active();
    let cmd = write(1, 0);
    let accepted = match apply(&mut state, &cmd) {
        Outcome::Accepted(commit) => commit,
        other => panic!("{other:?}"),
    };
    assert_eq!(accepted.receipt.sequence, 1);
    assert_eq!(accepted.position, state.position);
    assert_eq!(
        apply(&mut state, &cmd),
        Outcome::AlreadyCommitted(accepted.clone())
    );
    let mut replay = cmd.clone();
    let (new_write, _, result) = commit_parts(&mut replay);
    new_write.ticket.owner_epoch = 999;
    new_write.ticket.predecessor = 999;
    new_write.physical_changes = vec![99];
    *result = vec![88];
    assert_eq!(
        apply(&mut state, &replay),
        Outcome::AlreadyCommitted(accepted.clone())
    );
    assert_eq!(
        state
            .recovery_transactions(database(), admission())
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        state
            .recovery_transactions(database(), admission())
            .unwrap()[0]
            .physical_changes,
        vec![0, 255, 1, 42]
    );
    assert_eq!(
        state
            .lookup(database(), admission(), request(1), [1; 32])
            .unwrap(),
        Lookup::Committed {
            commit: accepted.clone(),
            result: vec![1, 0, 255]
        }
    );
    let mut conflicting = cmd.clone();
    *commit_parts(&mut conflicting).1 = [99; 32];
    rejected_without_mutation(&state, &conflicting, Reject::Conflict);
    let mut other_principal = cmd.clone();
    other_principal.admission.principal_id = 22;
    rejected_without_mutation(&state, &other_principal, Reject::Unauthorized);
    let mut zero_id = write(2, 1);
    commit_parts(&mut zero_id).0.ticket.request_id = 0;
    rejected_without_mutation(&state, &zero_id, Reject::Invalid);
    for i in 0..2 {
        let mut stale = write(2, 1);
        let ticket = &mut commit_parts(&mut stale).0.ticket;
        if i == 0 {
            ticket.owner_epoch += 1;
        } else {
            ticket.worker_instance_id += 1;
        }
        rejected_without_mutation(&state, &stale, Reject::Fenced);
    }
    rejected_without_mutation(&state, &write(2, 0), Reject::Conflict);
    let mut empty = write(2, 1);
    commit_parts(&mut empty).0.physical_changes.clear();
    rejected_without_mutation(&state, &empty, Reject::Invalid);
    let mut corrupt = write(2, 1);
    commit_parts(&mut corrupt).0.ticket.payload_digest[0] ^= 1;
    rejected_without_mutation(&state, &corrupt, Reject::Invalid);
    let mut big = write(2, 1);
    let prepared = commit_parts(&mut big).0;
    prepared.physical_changes = vec![1; limits().max_transaction_bytes as usize + 1];
    prepared.ticket.payload_digest = payload_digest(&prepared.physical_changes);
    rejected_without_mutation(&state, &big, Reject::TooLarge);
    big = write(2, 1);
    *commit_parts(&mut big).2 = vec![1; limits().max_result_bytes as usize + 1];
    rejected_without_mutation(&state, &big, Reject::TooLarge);
}

#[test]
fn owner_handoff_requires_exact_restore_before_new_writes_and_reads() {
    let mut state = active();
    apply(&mut state, &write(1, 0));
    let previous = state.database(database().database_id).unwrap();
    assert!(state
        .authorize_read(database(), admission(), previous.owner)
        .is_ok());
    assert_eq!(
        state.authorize_read(
            database(),
            admission(),
            OwnerToken {
                epoch: 1,
                worker_instance_id: 88
            }
        ),
        Err(Reject::Fenced)
    );
    assert!(matches!(
        apply(&mut state, &claim(1, 88, 4)),
        Outcome::Administrative(AdminResult::OwnerClaimed(_))
    ));
    rejected_without_mutation(&state, &write(2, 1), Reject::Fenced);
    assert_eq!(
        state.authorize_read(
            database(),
            admission(),
            state.database(database().database_id).unwrap().owner
        ),
        Err(Reject::Fenced)
    );
    assert_eq!(
        apply(
            &mut state,
            &activate(2, 88, 5, previous.revision, previous.commit_hash)
        ),
        Outcome::Administrative(AdminResult::OwnerActivated)
    );
    let mut next = write(2, 1);
    let ticket = &mut commit_parts(&mut next).0.ticket;
    ticket.owner_epoch = 2;
    ticket.worker_instance_id = 88;
    assert!(matches!(apply(&mut state, &next), Outcome::Accepted(_)));
    let view = state
        .authorize_read(
            database(),
            admission(),
            OwnerToken {
                epoch: 2,
                worker_instance_id: 88,
            },
        )
        .unwrap();
    assert_eq!(view.database.revision, 2);
    assert_eq!(view.position, state.position);
    assert_eq!(view.admission, admission());
    assert_eq!(view.cell, identity());
}

#[test]
fn auth_fence_rechecks_current_permission_before_historical_results() {
    let mut state = active();
    apply(&mut state, &write(1, 0));
    let fence = command(CommandKind::AuthFence {
        operation_id: operation(4),
        expected_epoch: 1,
        policy: policy(),
    });
    assert_eq!(
        apply(&mut state, &fence),
        Outcome::Administrative(AdminResult::AuthChanged(2))
    );
    rejected_without_mutation(&state, &write(1, 0), Reject::Unauthorized);
    assert_eq!(
        state.lookup(database(), admission(), request(1), [1; 32]),
        Err(Reject::Unauthorized)
    );
    assert!(state
        .recovery_transactions(database(), admission())
        .is_err());
    assert!(state
        .authorize_read(
            database(),
            admission(),
            OwnerToken {
                epoch: 1,
                worker_instance_id: WORKER
            }
        )
        .is_err());
    let mut fresh = fence.clone();
    fresh.admission.auth_epoch = 2;
    assert_eq!(
        apply(&mut state, &fresh),
        Outcome::AlreadyApplied(AdminResult::AuthChanged(2))
    );
    let mut replay = write(1, 0);
    replay.admission.auth_epoch = 2;
    commit_parts(&mut replay).0.ticket.auth_epoch = 2;
    assert!(matches!(
        apply(&mut state, &replay),
        Outcome::AlreadyCommitted(_)
    ));
    let revoke = Command {
        admission: current_admission(2),
        kind: CommandKind::AuthFence {
            operation_id: operation(5),
            expected_epoch: 2,
            policy: vec![Grant {
                principal_id: 22,
                permissions: 7,
            }],
        },
        ..command(CommandKind::ResolveOrCancel {
            request_id: 1,
            request_fingerprint: [0; 32],
        })
    };
    assert_eq!(
        apply(&mut state, &revoke),
        Outcome::Administrative(AdminResult::AuthChanged(3))
    );
    let mut retry = revoke;
    retry.admission.auth_epoch = 3;
    rejected_without_mutation(&state, &retry, Reject::Unauthorized);
    assert_eq!(
        state.lookup(database(), current_admission(3), request(1), [1; 32]),
        Err(Reject::Unauthorized)
    );
    let other = Admission {
        principal_id: 22,
        auth_epoch: 3,
        ..admission()
    };
    assert_eq!(
        state.lookup(database(), other, request(1), [1; 32]),
        Err(Reject::Unauthorized)
    );
}

#[test]
fn lookup_absence_is_unknown_and_cancel_fences_survive_snapshot() {
    let mut state = active();
    assert_eq!(
        state
            .lookup(database(), admission(), request(1), [1; 32])
            .unwrap(),
        Lookup::Unknown
    );
    assert_eq!(apply(&mut state, &cancel(1)), Outcome::Cancelled);
    let cancellation = state.position;
    assert_eq!(apply(&mut state, &cancel(1)), Outcome::AlreadyCancelled);
    state = decode_snapshot(&state).unwrap();
    assert_eq!(
        state
            .lookup(database(), admission(), request(1), [1; 32])
            .unwrap(),
        Lookup::Cancelled {
            position: cancellation
        }
    );
    rejected_without_mutation(&state, &write(1, 0), Reject::Cancelled);
    assert!(matches!(
        apply(&mut state, &write(2, 0)),
        Outcome::Accepted(_)
    ));
    let outcome = apply(&mut state, &cancel(2));
    assert!(matches!(outcome, Outcome::AlreadyCommitted(_)));
    assert_eq!(state.database(database().database_id).unwrap().revision, 1);
    assert_eq!(
        state.lookup(database(), admission(), request(1), [7; 32]),
        Err(Reject::Conflict)
    );
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
        Err(Reject::Unauthorized)
    );
    let zero = command(CommandKind::ResolveOrCancel {
        request_id: 0,
        request_fingerprint: [0; 32],
    });
    rejected_without_mutation(&state, &zero, Reject::Invalid);
    let unauthorized = Command {
        admission: Admission {
            principal_id: 33,
            ..admission()
        },
        ..cancel(3)
    };
    rejected_without_mutation(&state, &unauthorized, Reject::Unauthorized);
}

#[test]
fn administrative_operation_ids_bind_stable_intent_and_current_subject() {
    let state = active();
    let conflicting = claim(1, 99, 2);
    rejected_without_mutation(&state, &conflicting, Reject::Conflict);
    let mut principal = claim(0, WORKER, 2);
    principal.admission.principal_id = 44;
    rejected_without_mutation(&state, &principal, Reject::Conflict);
    let mut different_database = create();
    different_database.database.database_id += 1;
    rejected_without_mutation(&state, &different_database, Reject::Conflict);
}

#[test]
fn explicit_capacity_limits_never_evict_transactions_or_cancellation_fences() {
    let mut bound = limits();
    bound.max_databases = 1;
    let mut state = boot_with(bound);
    apply(&mut state, &create());
    let mut another = create();
    another.database.database_id += 1;
    if let CommandKind::Create { operation_id, .. } = &mut another.kind {
        *operation_id = operation(9);
    }
    rejected_without_mutation(&state, &another, Reject::Capacity);
    bound = limits();
    bound.max_admin_operations = 3;
    let state = active_with(bound);
    rejected_without_mutation(&state, &claim(1, 88, 4), Reject::Capacity);
    bound = limits();
    bound.max_requests_per_database = 1;
    let mut state = active_with(bound);
    apply(&mut state, &write(1, 0));
    rejected_without_mutation(&state, &write(2, 1), Reject::Capacity);
    rejected_without_mutation(&state, &cancel(2), Reject::Capacity);
    assert!(matches!(
        apply(&mut state, &write(1, 0)),
        Outcome::AlreadyCommitted(_)
    ));
    let mut cancelled = active_with(bound);
    apply(&mut cancelled, &cancel(1));
    rejected_without_mutation(&cancelled, &write(2, 0), Reject::Capacity);
    assert_eq!(apply(&mut cancelled, &cancel(1)), Outcome::AlreadyCancelled);
}

#[test]
fn aggregate_capacity_reserves_a_durable_rejection_and_position() {
    let mut bound = limits();
    bound.max_state_bytes = 2048;
    let mut state = active_with(bound);
    let mut large = write(1, 0);
    let prepared = commit_parts(&mut large).0;
    prepared.physical_changes = vec![7; 1024];
    prepared.ticket.payload_digest = payload_digest(&prepared.physical_changes);
    let original = state.clone();
    assert_eq!(
        apply(&mut state, &large),
        Outcome::Rejected(Reject::Capacity)
    );
    assert_eq!(state.databases, original.databases);
    assert!(state.encode().len() <= bound.max_state_bytes as usize);
    assert!(matches!(
        apply(&mut state, &write(1, 0)),
        Outcome::Accepted(_)
    ));
    assert!(decode_snapshot(&state).is_ok());
}

#[test]
fn exhausted_generations_are_preserved_and_never_wrap() {
    let mut state = active();
    state
        .databases
        .get_mut(&database().database_id)
        .unwrap()
        .owner
        .epoch = u64::MAX;
    state = decode_snapshot(&state).unwrap();
    rejected_without_mutation(&state, &claim(u64::MAX, 88, 4), Reject::Exhausted);
    state = active();
    state
        .databases
        .get_mut(&database().database_id)
        .unwrap()
        .auth_epoch = u64::MAX;
    state = decode_snapshot(&state).unwrap();
    let cmd = Command {
        admission: current_admission(u64::MAX),
        kind: CommandKind::AuthFence {
            operation_id: operation(4),
            expected_epoch: u64::MAX,
            policy: policy(),
        },
        ..create()
    };
    rejected_without_mutation(&state, &cmd, Reject::Exhausted);
}

#[test]
fn noops_configuration_and_rejections_advance_exact_position_without_revision() {
    let mut state = active();
    let previous = state.last_outcome.clone();
    let mut app = CellApplication::new(identity(), limits()).unwrap();
    let mut normal = Entry {
        term: 2,
        index: 5,
        ..Entry::default()
    };
    let mut configuration = Entry {
        term: 2,
        index: 6,
        ..Entry::default()
    };
    configuration.set_entry_type(EntryType::EntryConfChangeV2);
    configuration.data = vec![1, 2].into();
    let bytes = app
        .apply(&state.encode(), &[normal.clone(), configuration])
        .unwrap();
    state = CellState::decode_bound(&bytes, identity(), Position { term: 2, index: 6 }, limits())
        .unwrap();
    assert_eq!(state.last_outcome, previous);
    assert_eq!(state.database(database().database_id).unwrap().revision, 0);
    assert_eq!(
        app.apply(&state.encode(), &[normal.clone()]),
        Err(Error::Position)
    );
    normal.index = 7;
    normal.term = 1;
    assert_eq!(
        app.apply(&state.encode(), &[normal.clone()]),
        Err(Error::Position)
    );
    normal.term = 2;
    normal.data = vec![1; limits().max_command_bytes as usize + 1].into();
    let next = app.apply(&state.encode(), &[normal]).unwrap();
    let next = CellState::decode_bound(&next, identity(), Position { term: 2, index: 7 }, limits())
        .unwrap();
    assert_eq!(
        next.last_outcome.unwrap().outcome,
        Outcome::Rejected(Reject::TooLarge)
    );
    let exhausted = CellState::bootstrap(
        identity(),
        PRINCIPAL,
        Position {
            term: 1,
            index: u64::MAX,
        },
        limits(),
    )
    .unwrap();
    let entry = Entry {
        term: 1,
        index: 0,
        ..Entry::default()
    };
    assert_eq!(
        app.apply(&exhausted.encode(), &[entry]),
        Err(Error::Position)
    );
}

#[test]
fn snapshot_contains_all_physical_bytes_results_fences_and_read_authority() {
    let state = rich();
    let reopened = decode_snapshot(&state).unwrap();
    assert_eq!(reopened, state);
    let view = reopened
        .authorize_read(
            database(),
            current_admission(2),
            OwnerToken {
                epoch: 1,
                worker_instance_id: WORKER,
            },
        )
        .unwrap();
    assert_eq!(view.database.revision, 2);
    assert_ne!(view.database.commit_hash, [0; 32]);
    let transactions = reopened
        .recovery_transactions(database(), current_admission(2))
        .unwrap();
    assert_eq!(transactions.len(), 2);
    assert_eq!(transactions[1].result, vec![2, 0, 255]);
    assert!(matches!(
        reopened
            .lookup(database(), current_admission(2), request(3), [3; 32])
            .unwrap(),
        Lookup::Cancelled { .. }
    ));
    assert!(CellState::decode_bound(
        &state.encode(),
        CellIdentity {
            cell_id: 42,
            ..identity()
        },
        state.position,
        limits()
    )
    .is_err());
    let mut changed_limits = limits();
    changed_limits.max_result_bytes += 1;
    assert_eq!(
        CellState::decode_bound(&state.encode(), identity(), state.position, changed_limits),
        Err(Error::Binding)
    );
}

#[test]
fn command_and_snapshot_envelopes_reject_damage_unknown_formats_and_truncation() {
    let state = rich();
    let image = state.encode();
    for end in 0..image.len() {
        assert!(
            CellState::decode_bound(&image[..end], identity(), state.position, limits()).is_err(),
            "outer prefix {end}"
        );
    }
    for index in [0, 8, 17, image.len() - 1] {
        let mut corrupt = image.clone();
        corrupt[index] ^= 1;
        assert!(CellState::decode_bound(&corrupt, identity(), state.position, limits()).is_err());
    }
    let mut oversized = image.clone();
    oversized.resize(limits().max_state_bytes as usize + 1, 0);
    assert_eq!(
        CellState::decode_bound(&oversized, identity(), state.position, limits()),
        Err(Error::Limit)
    );
    let mut bad_length = image.clone();
    bad_length[9..17].copy_from_slice(&u64::MAX.to_be_bytes());
    assert_eq!(
        CellState::decode_bound(&bad_length, identity(), state.position, limits()),
        Err(Error::Limit)
    );
    let trailing = mutate_body(&image, |body| body.push(0));
    assert!(CellState::decode_bound(&trailing, identity(), state.position, limits()).is_err());
    for end in 0..body(&image).len() {
        let truncated = envelope(&image, &body(&image)[..end]);
        assert!(
            CellState::decode_bound(&truncated, identity(), state.position, limits()).is_err(),
            "inner prefix {end}"
        );
    }
    for cmd in [
        create(),
        claim(0, WORKER, 2),
        activate(1, WORKER, 3, 0, [0; 32]),
        command(CommandKind::AuthFence {
            operation_id: operation(4),
            expected_epoch: 1,
            policy: policy(),
        }),
        write(1, 0),
        cancel(2),
    ] {
        let encoded = encode_command(&cmd, limits()).unwrap();
        for end in 0..body(&encoded).len() {
            assert!(
                codec::decode_command(&envelope(&encoded, &body(&encoded)[..end]), limits())
                    .is_err()
            );
        }
        let unknown = mutate_body(&encoded, |body| body[112] = 255);
        assert!(codec::decode_command(&unknown, limits()).is_err());
        let trailing = mutate_body(&encoded, |body| body.push(0));
        assert!(codec::decode_command(&trailing, limits()).is_err());
    }
    let mut app = CellApplication::new(identity(), limits()).unwrap();
    let entry = Entry {
        term: state.position.term,
        index: state.position.index + 1,
        data: vec![1, 2, 3].into(),
        ..Entry::default()
    };
    assert!(app.apply(&state.encode(), &[entry]).is_err());
}

#[test]
fn encoding_rejects_owned_and_encoded_command_limits() {
    let mut bound = limits();
    bound.max_command_bytes = 16;
    assert_eq!(encode_command(&create(), bound), Err(Error::Limit));
    let mut large = write(1, 0);
    *commit_parts(&mut large).2 = vec![0; 8193];
    assert_eq!(encode_command(&large, limits()), Err(Error::Limit));
    assert_eq!(
        encode_command(&claim(0, WORKER, 2), bound),
        Err(Error::Limit)
    );
}

#[test]
fn position_bounds_reject_zero_future_and_wrong_term_at_same_index() {
    let bound = Position { term: 4, index: 8 };
    for position in [
        Position { term: 0, index: 1 },
        Position { term: 1, index: 0 },
        Position { term: 1, index: 9 },
        Position { term: 5, index: 1 },
        Position { term: 3, index: 8 },
    ] {
        assert!(!position_within(position, bound));
    }
    assert!(position_within(Position { term: 1, index: 1 }, bound));
    assert!(position_within(bound, bound));
}

fn reject_snapshot(change: impl FnOnce(&mut CellState)) {
    let mut state = rich();
    change(&mut state);
    assert!(
        decode_snapshot(&state).is_err(),
        "damaged durable image was accepted"
    );
}

#[test]
fn damaged_snapshot_metadata_and_bounded_collections_are_rejected() {
    for index in 0..13 {
        reject_snapshot(|state| {
            let db = state.databases.get_mut(&database().database_id).unwrap();
            match index {
                0 => state.bootstrap_admin = 0,
                1 => state.position.term = 0,
                2 => state.position.index = 0,
                3 => db.identity.database_id = 0,
                4 => db.identity.incarnation = 0,
                5 => db.identity.placement_generation = 0,
                6 => db.auth_epoch = 0,
                7 => db.owner.epoch = 0,
                8 => db.owner.worker_instance_id = 0,
                9 => {
                    db.owner = OwnerToken {
                        epoch: 0,
                        worker_instance_id: 0,
                    };
                    db.active = true;
                }
                10 => db.policy.clear(),
                11 => db.policy[0].permissions = 128,
                _ => state.last_outcome = None,
            }
        });
    }
    reject_snapshot(|state| {
        let db = state.databases[&database().database_id].clone();
        for i in 0..4 {
            let mut extra = db.clone();
            extra.identity.database_id = 1000 + i;
            state.databases.insert(1000 + i, extra);
        }
    });
    reject_snapshot(|state| {
        let db = state.databases.get_mut(&database().database_id).unwrap();
        db.policy = vec![
            Grant {
                principal_id: 11,
                permissions: 7
            };
            5
        ];
    });
    reject_snapshot(|state| {
        let db = state.databases.get_mut(&database().database_id).unwrap();
        db.transactions = vec![db.transactions[0].clone(); 17];
    });
    reject_snapshot(|state| {
        let db = state.databases.get_mut(&database().database_id).unwrap();
        for i in 10..30 {
            db.requests.insert(request(i), RequestRecord::Accepted(1));
        }
    });
    reject_snapshot(|state| {
        let record = state.administration[&operation(1)].clone();
        for i in 10..45 {
            state.administration.insert(operation(i), record.clone());
        }
    });
    reject_snapshot(|state| {
        state
            .databases
            .get_mut(&database().database_id)
            .unwrap()
            .transactions[0]
            .physical_changes = vec![0; 1025];
    });
    reject_snapshot(|state| {
        state
            .databases
            .get_mut(&database().database_id)
            .unwrap()
            .transactions[0]
            .result = vec![0; 1025];
    });
    let mut reserve = rich();
    reserve.limits.max_state_bytes =
        (codec::encode_state(&reserve, false).len() + RESERVED_BYTES - 1) as u32;
    assert!(reserve.encode().len() <= reserve.limits.max_state_bytes as usize);
    assert_eq!(decode_snapshot(&reserve), Err(Error::Limit));
}

#[test]
fn snapshot_rejects_transaction_identity_audit_chain_and_request_mismatch() {
    for index in 0..24 {
        reject_snapshot(|state| {
            let db = state.databases.get_mut(&database().database_id).unwrap();
            let tx = &mut db.transactions[0];
            let ticket = &mut tx.commit.receipt.ticket;
            match index {
                0 => ticket.cell_id += 1,
                1 => ticket.cell_incarnation += 1,
                2 => ticket.database_id += 1,
                3 => ticket.incarnation += 1,
                4 => ticket.placement_generation += 1,
                5 => ticket.auth_epoch = 0,
                6 => ticket.auth_epoch = 3,
                7 => ticket.owner_epoch = 0,
                8 => ticket.owner_epoch = 2,
                9 => ticket.worker_instance_id = 0,
                10 => ticket.request_id = 0,
                11 => ticket.predecessor = 3,
                12 => tx.commit.receipt.sequence = 2,
                13 => tx.admission.principal_id = 0,
                14 => tx.admission.credential_id = 0,
                15 => tx.admission.admission_id = 0,
                16 => tx.admission.auth_epoch = 0,
                17 => tx.admission.auth_epoch = 2,
                18 => tx.commit.position.index = 99,
                19 => tx.physical_changes.clear(),
                20 => tx.physical_changes[0] ^= 1,
                21 => tx.commit_hash[0] ^= 1,
                22 => {
                    db.requests.remove(&request(1));
                }
                _ => {
                    db.requests.insert(request(1), RequestRecord::Accepted(2));
                }
            }
        });
    }
    reject_snapshot(|state| {
        let db = state.databases.get_mut(&database().database_id).unwrap();
        db.transactions[1].commit.position.index = db.transactions[0].commit.position.index;
    });
    reject_snapshot(|state| {
        state
            .databases
            .get_mut(&database().database_id)
            .unwrap()
            .transactions[1]
            .commit
            .position
            .term = 1;
    });
}

#[test]
fn snapshot_rejects_invalid_request_and_administrative_records() {
    for sequence in [0, 3, 1] {
        reject_snapshot(|state| {
            state
                .databases
                .get_mut(&database().database_id)
                .unwrap()
                .requests
                .insert(request(99), RequestRecord::Accepted(sequence));
        });
    }
    reject_snapshot(|state| {
        let db = state.databases.get_mut(&database().database_id).unwrap();
        let record = db.requests[&request(3)].clone();
        db.requests.insert(0, record);
    });
    for index in 0..6 {
        reject_snapshot(|state| {
            let db = state.databases.get_mut(&database().database_id).unwrap();
            if let RequestRecord::Cancelled {
                admission,
                position,
                ..
            } = db.requests.get_mut(&request(3)).unwrap()
            {
                match index {
                    0 => admission.principal_id = 0,
                    1 => admission.credential_id = 0,
                    2 => admission.admission_id = 0,
                    3 => admission.auth_epoch = 0,
                    4 => admission.auth_epoch = 3,
                    _ => position.index = 99,
                }
            }
        });
    }
    reject_snapshot(|state| {
        let record = state.administration[&operation(1)].clone();
        state.administration.insert(0, record);
    });
    for index in 0..8 {
        reject_snapshot(|state| {
            let record = state.administration.get_mut(&operation(1)).unwrap();
            match index {
                0 => record.admission.principal_id = 0,
                1 => record.admission.credential_id = 0,
                2 => record.admission.admission_id = 0,
                3 => record.admission.auth_epoch = 0,
                4 => record.position.index = 99,
                5 => record.database.database_id = 999,
                6 => record.database.incarnation += 1,
                _ => record.admission.auth_epoch = 3,
            }
        });
    }
    for index in 0..3 {
        reject_snapshot(|state| {
            let record = state.administration.get_mut(&operation(2)).unwrap();
            if let AdminResult::OwnerClaimed(token) = &mut record.result {
                match index {
                    0 => token.epoch = 0,
                    1 => token.epoch = 2,
                    _ => token.worker_instance_id = 0,
                }
            }
        });
    }
    reject_snapshot(|state| {
        state.administration.remove(&operation(2));
        let db = state.databases.get_mut(&database().database_id).unwrap();
        db.owner = OwnerToken {
            epoch: 0,
            worker_instance_id: 0,
        };
        db.active = false;
        db.transactions.clear();
        db.requests.clear();
    });
    for epoch in [1, 3] {
        reject_snapshot(|state| {
            state.administration.get_mut(&operation(4)).unwrap().result =
                AdminResult::AuthChanged(epoch);
        });
    }
}

#[test]
fn last_outcome_must_reference_a_real_durable_effect_at_a_compatible_position() {
    reject_snapshot(|state| {
        state.last_outcome.as_mut().unwrap().position.index = 99;
    });
    for index in 0..5 {
        reject_snapshot(|state| {
            let mut commit = state.databases[&database().database_id].transactions[0]
                .commit
                .clone();
            let last = state.last_outcome.as_mut().unwrap();
            match index {
                0 => commit.receipt.ticket.database_id = 999,
                1 => commit.receipt.sequence = 999,
                2 => last.position = Position { term: 1, index: 4 },
                3 => {
                    last.outcome = Outcome::Accepted(commit);
                    return;
                }
                _ => {
                    last.outcome = Outcome::Administrative(AdminResult::AuthChanged(99));
                    return;
                }
            }
            last.outcome = Outcome::AlreadyCommitted(commit);
        });
    }
    reject_snapshot(|state| {
        state.last_outcome = Some(AppliedOutcome {
            position: Position { term: 3, index: 7 },
            outcome: Outcome::AlreadyApplied(AdminResult::AuthChanged(2)),
        });
    });
    reject_snapshot(|state| {
        state.last_outcome.as_mut().unwrap().outcome =
            Outcome::Administrative(AdminResult::AuthChanged(2));
    });
    reject_snapshot(|state| {
        state.last_outcome.as_mut().unwrap().outcome = Outcome::Cancelled;
    });
    reject_snapshot(|state| {
        state.last_outcome = Some(AppliedOutcome {
            position: Position { term: 3, index: 6 },
            outcome: Outcome::AlreadyCancelled,
        });
    });
    reject_snapshot(|state| {
        state
            .databases
            .get_mut(&database().database_id)
            .unwrap()
            .requests
            .remove(&request(3));
        state.last_outcome.as_mut().unwrap().outcome = Outcome::AlreadyCancelled;
    });
}

fn unique_offset(bytes: &[u8], marker: &[u8]) -> usize {
    let matches: Vec<_> = bytes
        .windows(marker.len())
        .enumerate()
        .filter_map(|(i, window)| (window == marker).then_some(i))
        .collect();
    assert_eq!(matches.len(), 1, "unique serialized fixture marker");
    matches[0]
}

#[test]
fn strict_codec_rejects_duplicate_keys_and_unknown_tags() {
    let state = rich();
    let image = state.encode();
    let mut duplicate_db = state.clone();
    duplicate_db
        .databases
        .insert(999, duplicate_db.databases[&database().database_id].clone());
    assert!(decode_snapshot(&duplicate_db).is_err());
    let duplicate_request = mutate_body(&image, |body| {
        let offset = unique_offset(body, &request(3).to_be_bytes());
        body[offset..offset + 16].copy_from_slice(&request(1).to_be_bytes());
    });
    assert!(
        CellState::decode_bound(&duplicate_request, identity(), state.position, limits()).is_err()
    );
    let duplicate_operation = mutate_body(&image, |body| {
        let offset = unique_offset(body, &operation(2).to_be_bytes());
        body[offset..offset + 16].copy_from_slice(&operation(1).to_be_bytes());
    });
    assert!(
        CellState::decode_bound(&duplicate_operation, identity(), state.position, limits())
            .is_err()
    );
    for index in 0..5 {
        let malformed = mutate_body(&image, |body| {
            let offset = match index {
                0 => 160,
                1 => unique_offset(body, &request(3).to_be_bytes()) + 16,
                2 => unique_offset(body, &operation(1).to_be_bytes()) + 16 + 56 + 32 + 32,
                3 => body.len() - 10,
                _ => body.len() - 9,
            };
            body[offset] = 255;
        });
        assert!(CellState::decode_bound(&malformed, identity(), state.position, limits()).is_err());
    }
    let mut rejected = active();
    apply(&mut rejected, &write(1, 3));
    let invalid_reason = mutate_body(&rejected.encode(), |body| {
        let last = body.len() - 1;
        body[last] = 255;
    });
    assert!(
        CellState::decode_bound(&invalid_reason, identity(), rejected.position, limits()).is_err()
    );
}

#[test]
fn historical_receipts_retain_original_admission_across_fences_and_replays() {
    let mut state = active();
    let original = write(1, 0);
    apply(&mut state, &original);
    apply(&mut state, &cancel(2));
    let fence = command(CommandKind::AuthFence {
        operation_id: operation(4),
        expected_epoch: 1,
        policy: policy(),
    });
    apply(&mut state, &fence);
    let mut replay = original;
    replay.admission = Admission {
        credential_id: 999,
        admission_id: 888,
        auth_epoch: 2,
        ..admission()
    };
    commit_parts(&mut replay).0.ticket.auth_epoch = 2;
    assert!(matches!(
        apply(&mut state, &replay),
        Outcome::AlreadyCommitted(_)
    ));
    let mut admin_replay = fence;
    admin_replay.admission = replay.admission;
    assert_eq!(
        apply(&mut state, &admin_replay),
        Outcome::AlreadyApplied(AdminResult::AuthChanged(2))
    );
    let mut cancel_replay = cancel(2);
    cancel_replay.admission = replay.admission;
    assert_eq!(apply(&mut state, &cancel_replay), Outcome::AlreadyCancelled);
    let recovered = decode_snapshot(&state).unwrap();
    assert_eq!(
        recovered.databases[&database().database_id].transactions[0].admission,
        admission()
    );
    assert!(
        matches!(recovered.databases[&database().database_id].requests[&request(2)], RequestRecord::Cancelled { admission: original, .. } if original == admission())
    );
    assert_eq!(
        recovered.administration[&operation(4)].admission,
        admission()
    );
}

#[test]
fn public_read_and_application_recovery_reject_invalid_dependencies() {
    let state = active();
    assert_eq!(
        state.lookup(
            database(),
            Admission {
                credential_id: 0,
                ..admission()
            },
            request(1),
            [1; 32]
        ),
        Err(Reject::Unauthorized)
    );
    assert!(CellState::decode_bound(
        &state.encode(),
        CellIdentity {
            cell_id: 0,
            ..identity()
        },
        state.position,
        limits()
    )
    .is_err());
    let mut app = CellApplication::new(identity(), limits()).unwrap();
    assert!(app.apply(&[1, 2, 3], &[]).is_err());
}

#[test]
fn each_result_payload_rejects_truncation_before_it_can_authorize_completion() {
    let mut accepted = active();
    apply(&mut accepted, &write(1, 0));
    let mut replay = accepted.clone();
    apply(&mut replay, &write(1, 0));
    let mut rejected = accepted.clone();
    apply(&mut rejected, &write(2, 0));
    for state in [active(), accepted, replay, rejected] {
        let image = state.encode();
        let without = codec::encode_state(&state, false);
        let start = body(&without).len() - 1;
        for end in start..body(&image).len() {
            let truncated = envelope(&image, &body(&image)[..end]);
            assert!(
                CellState::decode_bound(&truncated, identity(), state.position, state.limits)
                    .is_err()
            );
        }
    }
}
