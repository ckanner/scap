use super::*;

fn page_limits() -> Limits {
    Limits {
        max_command_bytes: 32_768,
        max_requests_per_database: 32,
        max_transaction_bytes: 8192,
        ..limits()
    }
}

fn page_write(image: &physical::Image, id: u128, value: u8) -> physical::Prepared {
    let mut bytes = vec![value; physical::PAGE_SIZE];
    bytes[..16].copy_from_slice(b"SQLite format 3\0");
    bytes[16..18].copy_from_slice(&[0x10, 0]);
    image
        .prepare(
            CommitTicket {
                cell_id: identity().cell_id,
                cell_incarnation: identity().cell_incarnation,
                database_id: database().database_id,
                incarnation: database().incarnation,
                placement_generation: database().placement_generation,
                owner_epoch: 1,
                worker_instance_id: WORKER,
                auth_epoch: 1,
                request_id: request(id),
                predecessor: image.head().revision,
                payload_digest: [0; 32],
            },
            physical::PageBatch {
                size_after: 1,
                pages: vec![physical::PageChange { number: 1, bytes }],
            },
        )
        .unwrap()
}

fn page_history(count: u128) -> (CellState, physical::Image) {
    let mut state = active_with(page_limits());
    let mut image = physical::Image::empty(
        physical::EngineIdentity {
            cell: identity(),
            database: database(),
        },
        physical_limits(state.limits),
    )
    .unwrap();
    for id in 1..=count {
        let prepared = page_write(&image, id, id as u8);
        let command = command(CommandKind::Commit {
            write: prepared.write().clone(),
            request_fingerprint: [id as u8; 32],
            result: vec![id as u8, 0, 255],
        });
        let Outcome::Accepted(commit) = apply(&mut state, &command) else {
            panic!("valid physical history was rejected");
        };
        image = prepared.accepted(&commit.receipt).unwrap();
        let source = state.recovery_source(database(), admission()).unwrap();
        if source.tail.is_empty() {
            let base = source.base.unwrap();
            assert_eq!(base.bytes, image.bytes());
            assert_eq!(base.image_digest, image.head().image_digest);
            assert_eq!(base.revision, id as u64);
            assert_eq!(base.source, commit.position);
        }
    }
    (state, image)
}

#[test]
fn repeated_entry_folds_keep_every_result_cancellation_and_original_receipt() {
    let mut state = active_with(Limits {
        max_requests_per_database: 32,
        ..limits()
    });
    let mut first = None;
    for id in 1..=17 {
        let outcome = apply(&mut state, &write(id, id as u64 - 1));
        let Outcome::Accepted(commit) = outcome else {
            panic!("{outcome:?}")
        };
        if id == 1 {
            first = Some(commit);
        }
        let view = state.database(database().database_id).unwrap();
        assert_eq!(view.revision, id as u64);
        assert_eq!(view.base_revision, id as u64 / 8 * 8);
        assert_eq!(view.tail_entries, id as u64 % 8);
        assert_eq!(
            view.tail_bytes,
            (id as u64 % 8) * physical::HEADER_SIZE as u64
        );
    }
    let first = first.unwrap();
    assert_eq!(
        state.lookup(database(), admission(), request(1), [1; 32]),
        Ok(Lookup::Committed {
            commit: first.clone(),
            result: vec![1, 0, 255],
            acknowledged: false,
        })
    );
    assert_eq!(
        apply(&mut state, &write(1, 999)),
        Outcome::AlreadyCommitted(first)
    );
    assert_eq!(apply(&mut state, &cancel(31)), Outcome::Cancelled);
    rejected_without_mutation(&state, &write(31, 17), Reject::Cancelled);
    let source = state.recovery_source(database(), admission()).unwrap();
    assert_eq!(source.base.unwrap().revision, 16);
    assert_eq!(source.tail[0].commit.receipt.sequence, 17);
    assert!(state.databases[&database().database_id].transactions[..16]
        .iter()
        .all(|tx| tx.physical_changes.is_empty()));
    assert_eq!(
        state.databases[&database().database_id].transactions.len(),
        17
    );
    assert_eq!(decode_snapshot(&state).unwrap(), state);
}

#[test]
fn byte_threshold_folds_nonempty_sqlite_pages_before_the_entry_threshold() {
    let (state, image) = page_history(13);
    let view = state.database(database().database_id).unwrap();
    assert_eq!(view.revision, 13);
    assert_eq!(view.base_revision, 12);
    assert_eq!(view.tail_entries, 1);
    assert_eq!(
        view.tail_bytes,
        (physical::HEADER_SIZE + physical::PAGE_SIZE + 4) as u64
    );
    let source = state.recovery_source(database(), admission()).unwrap();
    let base = source.base.unwrap();
    assert_eq!(base.bytes[100], 12);
    assert_eq!(base.bytes.len(), physical::PAGE_SIZE);
    let restored = physical::Image::from_snapshot(
        physical::Snapshot {
            head: physical::Head {
                identity: image.head().identity,
                revision: base.revision,
                image_digest: base.image_digest,
            },
            bytes: base.bytes.clone(),
        },
        image.limits(),
    )
    .unwrap();
    let restored = restored
        .replay(
            &source.tail[0].commit.receipt,
            &source.tail[0].physical_changes,
        )
        .unwrap();
    assert_eq!(restored, image);
    assert_eq!(state.encode()[8], 3);
    assert_eq!(encode_command(&write(20, 13), state.limits).unwrap()[8], 2);
    assert_eq!(encode_applied_outcome(state.last_outcome().unwrap())[8], 2);
}

#[test]
fn a_failed_fold_does_not_retire_old_bytes_or_create_a_request_record() {
    let mut state = active();
    for id in 1..=7 {
        apply(&mut state, &write(id, id as u64 - 1));
    }
    let original = state.databases[&database().database_id].clone();
    let mut invalid = write(8, 7);
    let payload = commit_parts(&mut invalid).0;
    payload.physical_changes[0] ^= 1;
    payload.ticket.payload_digest = payload_digest(&payload.physical_changes);
    rejected_without_mutation(&state, &invalid, Reject::Invalid);
    assert_eq!(
        apply(&mut state, &invalid),
        Outcome::Rejected(Reject::Invalid)
    );
    assert_eq!(state.databases[&database().database_id], original);
    assert_eq!(
        state.lookup(database(), admission(), request(8), [8; 32]),
        Ok(Lookup::Unknown)
    );
    assert!(matches!(
        apply(&mut state, &write(8, 7)),
        Outcome::Accepted(_)
    ));
    assert_eq!(
        state
            .database(database().database_id)
            .unwrap()
            .base_revision,
        8
    );
}

#[test]
fn physical_retirement_never_releases_request_identity_capacity() {
    let mut state = active_with(Limits {
        max_requests_per_database: 8,
        ..limits()
    });
    for id in 1..=8 {
        apply(&mut state, &write(id, id as u64 - 1));
    }
    assert!(state
        .recovery_source(database(), admission())
        .unwrap()
        .tail
        .is_empty());
    rejected_without_mutation(&state, &write(9, 8), Reject::Capacity);
    rejected_without_mutation(&state, &cancel(9), Reject::Capacity);
    assert!(matches!(
        apply(&mut state, &write(1, 0)),
        Outcome::AlreadyCommitted(_)
    ));
    assert_eq!(state.database(database().database_id).unwrap().revision, 8);
}

#[test]
fn a_base_snapshot_is_not_authority_without_exact_position_head_and_image_binding() {
    let (state, _) = page_history(5);
    for case in 0..11 {
        let mut invalid = state.clone();
        let db = invalid.databases.get_mut(&database().database_id).unwrap();
        let base = db.base.as_mut().unwrap();
        match case {
            0 => base.revision = 0,
            1 => base.revision = 99,
            2 => base.source.index = 0,
            3 => base.source.index = state.position.index + 1,
            4 => base.source.index -= 1,
            5 => base.commit_hash[0] ^= 1,
            6 => base.image_digest[0] ^= 1,
            7 => {
                base.bytes.pop();
            }
            8 => {
                base.bytes[0] ^= 1;
                base.image_digest = payload_digest(&base.bytes);
            }
            9 => db.transactions[0].physical_changes = vec![1],
            _ => db.transactions[4].physical_changes.clear(),
        }
        assert!(decode_snapshot(&invalid).is_err(), "case {case}");
    }
}

#[test]
fn base_and_tail_archive_roundtrip_retains_metadata_and_cold_has_no_resident_payload() {
    let (state, _) = page_history(5);
    let original = state.databases[&database().database_id].clone();
    let (mut state, archive, bytes) = published(state);
    assert_eq!(bytes[8], 3);
    let owner = state.database(database().database_id).unwrap().owner;
    let prune = command(CommandKind::PruneArchive {
        operation_id: operation(12),
        expected_owner: owner,
        archive_digest: archive.object_digest,
    });
    assert!(matches!(
        apply(&mut state, &prune),
        Outcome::Administrative(AdminResult::ArchivePruned(_))
    ));
    let view = state.database(database().database_id).unwrap();
    assert_eq!(
        (view.base_revision, view.tail_entries, view.tail_bytes),
        (4, 0, 0)
    );
    assert!(state.databases[&database().database_id]
        .base
        .as_ref()
        .unwrap()
        .bytes
        .is_empty());
    assert_eq!(
        state.recovery_source(database(), admission()),
        Err(Reject::Cold)
    );
    let mut invalid = state.clone();
    invalid
        .databases
        .get_mut(&database().database_id)
        .unwrap()
        .base
        .as_mut()
        .unwrap()
        .bytes
        .push(1);
    assert!(decode_snapshot(&invalid).is_err());
    apply(&mut state, &cancel(30));
    apply(
        &mut state,
        &command(CommandKind::HydrateArchive {
            operation_id: operation(13),
            archive: bytes,
        }),
    );
    let current = &state.databases[&database().database_id];
    assert_eq!(current.transactions, original.transactions);
    assert_eq!(current.base, original.base);
    assert!(matches!(
        state.lookup(database(), admission(), request(30), [30; 32]),
        Ok(Lookup::Cancelled { .. })
    ));
    assert_eq!(decode_snapshot(&state).unwrap(), state);
}

pub(super) fn from_hex(text: &str) -> Vec<u8> {
    let text: String = text.split_whitespace().collect();
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

pub(super) fn legacy_limits() -> Limits {
    Limits {
        max_state_bytes: 65_536,
        max_command_bytes: 16_384,
        max_databases: 4,
        max_policy_grants: 4,
        max_admin_operations: 64,
        max_requests_per_database: 16,
        max_transaction_bytes: 8192,
        max_result_bytes: 1024,
    }
}

pub(super) fn legacy_cell() -> CellIdentity {
    CellIdentity {
        cell_id: 7,
        cell_incarnation: 8,
    }
}
pub(super) fn legacy_database() -> DatabaseIdentity {
    DatabaseIdentity {
        database_id: 9,
        incarnation: 10,
        placement_generation: 11,
    }
}
pub(super) fn legacy_admission(epoch: u64) -> Admission {
    Admission {
        principal_id: 12,
        credential_id: 13,
        admission_id: 14,
        auth_epoch: epoch,
        request_epoch: 1,
    }
}

pub(super) fn legacy_apply(state: &mut CellState, epoch: u64, kind: CommandKind) -> Outcome {
    let position = Position {
        term: 1,
        index: state.position.index + 1,
    };
    let command = Command {
        cell: legacy_cell(),
        database: legacy_database(),
        admission: legacy_admission(epoch),
        control_revision: None,
        kind,
    };
    let entry = Entry {
        term: 1,
        index: position.index,
        data: encode_command(&command, state.limits).unwrap().into(),
        ..Entry::default()
    };
    let bytes = CellApplication::new(legacy_cell(), state.limits)
        .unwrap()
        .apply(&state.encode(), &[entry])
        .unwrap();
    *state = CellState::decode_bound(&bytes, legacy_cell(), position, state.limits).unwrap();
    state.last_outcome.as_ref().unwrap().outcome.clone()
}

pub(super) fn legacy_recovered_image(state: &CellState, epoch: u64) -> physical::Image {
    let source = state
        .recovery_source(legacy_database(), legacy_admission(epoch))
        .unwrap();
    let identity = physical::EngineIdentity {
        cell: legacy_cell(),
        database: legacy_database(),
    };
    let mut image = if let Some(base) = source.base {
        physical::Image::from_snapshot(
            physical::Snapshot {
                head: physical::Head {
                    identity,
                    revision: base.revision,
                    image_digest: base.image_digest,
                },
                bytes: base.bytes.clone(),
            },
            physical_limits(state.limits),
        )
    } else {
        physical::Image::empty(identity, physical_limits(state.limits))
    }
    .unwrap();
    for transaction in source.tail {
        image = image
            .replay(&transaction.commit.receipt, &transaction.physical_changes)
            .unwrap();
    }
    image
}

#[test]
fn immutable_real_v2_hot_and_cold_fixtures_migrate_without_losing_the_old_archive() {
    let archive_bytes = from_hex(include_str!("../../test-fixtures/archive-v2.hex"));
    let image = from_hex(include_str!("../../test-fixtures/image.hex"));
    assert_eq!(
        payload_digest(&archive_bytes),
        [
            0x2d, 0x6e, 0x68, 0x6e, 0xe4, 0x9d, 0x78, 0x38, 0x6f, 0xe6, 0xdf, 0x7e, 0x45, 0xdd,
            0x0f, 0xf4, 0x60, 0x42, 0x23, 0x99, 0xe1, 0x84, 0x56, 0x72, 0xb8, 0x7e, 0xda, 0xd5,
            0x7d, 0x3d, 0xc4, 0xe6
        ]
    );
    for (fixture, position, cold) in [
        (include_str!("../../test-fixtures/hot-v2.hex"), 9, false),
        (include_str!("../../test-fixtures/cold-v2.hex"), 10, true),
    ] {
        let bytes = from_hex(fixture);
        assert_eq!(bytes[8], 2);
        let mut state = CellState::decode_bound(
            &bytes,
            legacy_cell(),
            Position {
                term: 1,
                index: position,
            },
            legacy_limits(),
        )
        .unwrap();
        assert_eq!(state.physical_history_version(), 2);
        assert_eq!(state.encode(), bytes);
        assert_eq!(activate_history(&mut state).result, Ok(()));
        assert_eq!(state.encode()[8], 3);
        let view = state.database(9).unwrap();
        let archive = view.archive.unwrap();
        assert_eq!(view.cold, cold);
        assert_eq!(view.revision, 2);
        assert_eq!(view.base_revision, 0);
        assert_eq!(archive.object_digest, payload_digest(&archive_bytes));
        let old_result = state
            .lookup(legacy_database(), legacy_admission(1), 101, [1; 32])
            .unwrap();
        if !cold {
            assert_eq!(legacy_recovered_image(&state, 1).bytes(), image);
            legacy_apply(
                &mut state,
                1,
                CommandKind::PruneArchive {
                    operation_id: 40,
                    expected_owner: view.owner,
                    archive_digest: archive.object_digest,
                },
            );
        }
        legacy_apply(
            &mut state,
            1,
            CommandKind::AuthFence {
                operation_id: 41,
                expected_epoch: 1,
                policy: vec![Grant {
                    principal_id: 12,
                    permissions: READ | WRITE | ADMIN,
                }],
            },
        );
        legacy_apply(
            &mut state,
            2,
            CommandKind::ResolveOrCancel {
                request_id: 104,
                request_fingerprint: [4; 32],
            },
        );
        assert!(matches!(
            legacy_apply(
                &mut state,
                2,
                CommandKind::HydrateArchive {
                    operation_id: 42,
                    archive: archive_bytes.clone()
                }
            ),
            Outcome::Administrative(AdminResult::ArchiveHydrated(_))
        ));
        let source = state
            .recovery_source(legacy_database(), legacy_admission(2))
            .unwrap();
        assert!(source.base.is_none());
        assert_eq!(source.tail.len(), 2);
        assert_eq!(legacy_recovered_image(&state, 2).bytes(), image);
        assert_eq!(
            state
                .lookup(legacy_database(), legacy_admission(2), 101, [1; 32])
                .unwrap(),
            old_result
        );
        for request in [103, 104] {
            assert!(matches!(
                state.lookup(
                    legacy_database(),
                    legacy_admission(2),
                    request,
                    [(request - 100) as u8; 32]
                ),
                Ok(Lookup::Cancelled { .. })
            ));
        }
        // Existing v2 coverage is still valid after hydration normalized the
        // physical representation to a canonical v3 tail. No new publication is required.
        legacy_apply(
            &mut state,
            2,
            CommandKind::PruneArchive {
                operation_id: 43,
                expected_owner: view.owner,
                archive_digest: archive.object_digest,
            },
        );
        legacy_apply(
            &mut state,
            2,
            CommandKind::HydrateArchive {
                operation_id: 44,
                archive: archive_bytes.clone(),
            },
        );
        let (new_archive, new_bytes) = state
            .archive_snapshot(legacy_database(), legacy_admission(2))
            .unwrap();
        assert_eq!(new_bytes[8], 3);
        assert_eq!(new_archive.metadata_digest, archive.metadata_digest);
        legacy_apply(
            &mut state,
            2,
            CommandKind::PublishArchive {
                operation_id: 45,
                expected_owner: view.owner,
                expected_previous: Some(archive.object_digest),
                archive: new_archive,
            },
        );
        legacy_apply(
            &mut state,
            2,
            CommandKind::PruneArchive {
                operation_id: 46,
                expected_owner: view.owner,
                archive_digest: new_archive.object_digest,
            },
        );
        legacy_apply(
            &mut state,
            2,
            CommandKind::HydrateArchive {
                operation_id: 47,
                archive: new_bytes,
            },
        );
        assert_eq!(legacy_recovered_image(&state, 2).bytes(), image);
    }
}

#[test]
fn v3_decoders_reject_an_unfolded_tail_and_truncated_or_oversized_base() {
    let mut state = active();
    let mut originals = Vec::new();
    for id in 1..=8 {
        let mut command = write(id, id as u64 - 1);
        originals.push(commit_parts(&mut command).0.physical_changes.clone());
        apply(&mut state, &command);
    }
    let db = state.databases.get_mut(&database().database_id).unwrap();
    db.base = None;
    for (transaction, payload) in db.transactions.iter_mut().zip(originals) {
        transaction.physical_changes = payload;
    }
    assert_eq!(
        decode_snapshot(&state),
        Err(Error::Malformed("physical tail exceeds v3 bound"))
    );
    let (archive, bytes) = state.archive_snapshot(database(), admission()).unwrap();
    assert!(matches!(
        codec::decode_archive(
            &bytes,
            identity(),
            &state.databases[&database().database_id],
            archive,
            state.limits,
            3
        ),
        Err(Error::Malformed("archive physical tail exceeds v3 bound"))
    ));

    let (state, _) = page_history(4);
    let (archive, bytes) = state.archive_snapshot(database(), admission()).unwrap();
    let db = &state.databases[&database().database_id];
    let body_len = body(&bytes).len();
    let base_start = body_len - 97 - physical::PAGE_SIZE;
    for offset in [0, 1, 9, 17, 25, 57, 89, 97, 100] {
        let truncated = envelope(&bytes, &body(&bytes)[..base_start + offset]);
        assert!(
            codec::decode_archive(&truncated, identity(), db, archive, state.limits, 3).is_err()
        );
    }
    let oversized = mutate_body(&bytes, |body| {
        body[base_start + 89..base_start + 97].copy_from_slice(&u64::MAX.to_be_bytes())
    });
    assert!(matches!(
        codec::decode_archive(&oversized, identity(), db, archive, state.limits, 3),
        Err(Error::Limit)
    ));
    let prefix = mutate_body(&bytes, |body| body[base_start] = 2);
    assert!(codec::decode_archive(&prefix, identity(), db, archive, state.limits, 3).is_err());
    let mut zero_version = state.encode();
    zero_version[8] = 0;
    let zero_version = envelope(&zero_version, body(&zero_version));
    assert!(
        CellState::decode_bound(&zero_version, identity(), state.position, state.limits).is_err()
    );
}

#[test]
fn compaction_limits_are_replicated_and_invalid_or_oversized_bases_never_replace_history() {
    let (fully_covered, _) = page_history(4);
    let mut no_tail = fully_covered.databases[&database().database_id].clone();
    let before = no_tail.clone();
    assert_eq!(no_tail.compact(identity(), fully_covered.limits), Ok(()));
    assert_eq!(no_tail, before);
    let (state, _) = page_history(5);
    let original = state.databases[&database().database_id].clone();
    let mut damaged = original.clone();
    damaged.base.as_mut().unwrap().image_digest[0] ^= 1;
    let before = damaged.clone();
    assert_eq!(
        damaged.compact(
            identity(),
            Limits {
                max_state_bytes: 8192,
                ..state.limits
            }
        ),
        Err(Reject::Invalid)
    );
    assert_eq!(damaged, before);
    let mut oversized = original.clone();
    oversized
        .base
        .as_mut()
        .unwrap()
        .bytes
        .resize(physical::PAGE_SIZE * 2, 0);
    let before = oversized.clone();
    assert_eq!(
        oversized.compact(
            identity(),
            Limits {
                max_state_bytes: physical::PAGE_SIZE as u32,
                ..state.limits
            }
        ),
        Err(Reject::TooLarge)
    );
    assert_eq!(oversized, before);
    let mut limited = original.clone();
    assert_eq!(
        limited.compact(
            identity(),
            Limits {
                max_state_bytes: 1024,
                ..state.limits
            }
        ),
        Err(Reject::Capacity)
    );
    assert_eq!(limited, original);
    assert_eq!(
        physical_limits(Limits {
            max_state_bytes: u32::MAX,
            ..limits()
        })
        .max_database_pages,
        physical::MAX_DATABASE_PAGES
    );
}

#[test]
fn archive_inner_validation_rejects_invalid_base_and_unretired_prefix_bytes() {
    let (state, _) = page_history(5);
    let (archive, _) = state.archive_snapshot(database(), admission()).unwrap();
    let retained = &state.databases[&database().database_id];
    let mut damaged = retained.clone();
    damaged.base.as_mut().unwrap().image_digest[0] ^= 1;
    let bytes = codec::encode_archive(identity(), &damaged, archive.source, 3);
    assert!(matches!(
        codec::decode_archive(&bytes, identity(), retained, archive, state.limits, 3),
        Err(Error::Malformed("invalid recovery base image"))
    ));
    let mut unretired = retained.clone();
    unretired.transactions[0].physical_changes.push(1);
    let bytes = codec::encode_archive(identity(), &unretired, archive.source, 3);
    assert!(matches!(
        codec::decode_archive(&bytes, identity(), retained, archive, state.limits, 3),
        Err(Error::Binding)
    ));
}

#[test]
fn an_activated_legacy_cold_archive_must_still_be_physically_recoverable() {
    let mut state = CellState::bootstrap_legacy(identity(), PRINCIPAL, GENESIS, limits()).unwrap();
    apply(&mut state, &create());
    apply(&mut state, &claim(0, WORKER, 2));
    apply(&mut state, &activate(1, WORKER, 3, 0, [0; 32]));
    let mut opaque = write(1, 0);
    let write = commit_parts(&mut opaque).0;
    write.physical_changes[0] ^= 1;
    write.ticket.payload_digest = payload_digest(&write.physical_changes);
    assert!(matches!(apply(&mut state, &opaque), Outcome::Accepted(_)));
    let (mut state, archive, bytes) = published(state);
    assert_eq!(bytes[8], 2);
    let expected_owner = state.database(database().database_id).unwrap().owner;
    assert!(matches!(
        apply(
            &mut state,
            &command(CommandKind::PruneArchive {
                operation_id: operation(12),
                expected_owner,
                archive_digest: archive.object_digest,
            })
        ),
        Outcome::Administrative(_)
    ));
    assert_eq!(activate_history(&mut state).result, Ok(()));
    let before = state.databases[&database().database_id].clone();
    assert_eq!(
        apply(
            &mut state,
            &command(CommandKind::HydrateArchive {
                operation_id: operation(13),
                archive: bytes,
            })
        ),
        Outcome::Rejected(Reject::Invalid)
    );
    assert_eq!(state.databases[&database().database_id], before);
    assert!(state.database(database().database_id).unwrap().cold);
    assert_eq!(
        state.database(database().database_id).unwrap().archive,
        Some(archive)
    );
    assert!(matches!(
        state.lookup(database(), admission(), request(1), [1; 32]),
        Ok(Lookup::Committed { .. })
    ));
}
