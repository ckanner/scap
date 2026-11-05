use super::*;
use scap_cell::ControlResult;

fn controlled() -> (Controller<Port, Store>, Port, Store, RequestContext) {
    let mut state = initial();
    apply_raw(
        &mut state,
        scap_cell::encode_retention_activation(cell(), 11),
        limits(),
    );
    apply_raw(
        &mut state,
        scap_cell::encode_control_activation(cell(), 11),
        limits(),
    );
    assert!(state.control_enabled());
    build_with(state, identity(), limits(), context())
}

fn status(port: &Port) -> DatabaseView {
    port.0
        .borrow()
        .state
        .database(database().database_id)
        .unwrap()
}

#[test]
fn bound_cold_lifecycle_advances_only_confirmed_control_receipts() {
    let (mut controller, port, store, context) = controlled();
    let active = status(&port);
    controller
        .hydrate_bound(&context, active.clone(), 4)
        .unwrap();
    assert_eq!(status(&port), active);
    controller
        .suspend_bound(&context, active.clone(), 4)
        .unwrap();
    let suspended = status(&port);
    assert_eq!(suspended.control_revision, Some(1));
    let published = controller
        .publish_bound(&context, suspended.clone(), 5)
        .unwrap();
    assert_eq!(published.control_revision(), Some(2));
    let archive = published.archive();
    assert_eq!(status(&port).archive, Some(archive));
    assert_eq!(store.0.borrow().objects.len(), 1);
    controller
        .prune_bound(&context, suspended, published, 6)
        .unwrap();
    let cold = status(&port);
    assert!(cold.cold);
    assert_eq!(cold.control_revision, Some(3));
    controller.hydrate_bound(&context, cold.clone(), 7).unwrap();
    let restored = status(&port);
    assert!(!restored.cold);
    assert_eq!(restored.control_revision, Some(4));
    assert_eq!(restored.owner, cold.owner);
    assert_eq!(restored.auth_epoch, cold.auth_epoch);
    assert_eq!(restored.request_epoch, cold.request_epoch);
    assert_eq!(restored.revision, active.revision);
    assert_eq!(restored.commit_hash, active.commit_hash);
    assert!(matches!(
        port.0
            .borrow()
            .state
            .lookup(database(), admission(), 88, [7; 32]),
        Ok(scap_cell::Lookup::Committed { .. })
    ));
}

#[test]
fn enabled_control_protocol_rejects_convenience_methods_without_new_bindings() {
    let (mut controller, port, store, context) = controlled();
    let before = status(&port);
    for operation in 4..6 {
        assert_eq!(
            controller.suspend(&context, database(), operation),
            Err(Error::Invalid)
        );
        assert_eq!(
            controller.publish(&context, database(), operation),
            Err(Error::Invalid)
        );
        assert_eq!(
            controller.prune(&context, database(), operation),
            Err(Error::Invalid)
        );
        assert_eq!(
            controller.hydrate(&context, database(), operation),
            Err(Error::Invalid)
        );
    }
    assert_eq!(status(&port), before);
    assert_eq!(port.0.borrow().proposals, 0);
    assert!(store.0.borrow().objects.is_empty());
}

#[test]
fn bound_lifecycle_retries_do_not_refresh_after_unknown() {
    for stage in 0..4 {
        for applied in [false, true] {
            let (mut controller, port, _, context) = controlled();
            let mut expected = status(&port);
            if stage > 0 {
                controller.suspend_bound(&context, expected, 4).unwrap();
                expected = status(&port);
            }
            let mut publication = None;
            if stage >= 2 {
                publication = Some(
                    controller
                        .publish_bound(&context, expected.clone(), 5)
                        .unwrap(),
                );
            }
            if stage == 3 {
                controller
                    .prune_bound(&context, expected, publication.clone().unwrap(), 6)
                    .unwrap();
                expected = status(&port);
            }
            let before = status(&port);
            port.0.borrow_mut().propose_fail = !applied;
            port.0.borrow_mut().unknown_after_apply = applied;
            let attempt = |controller: &mut Controller<Port, Store>| match stage {
                0 => controller.suspend_bound(&context, expected.clone(), 4),
                1 => controller
                    .publish_bound(&context, expected.clone(), 5)
                    .map(|_| ()),
                2 => controller.prune_bound(
                    &context,
                    expected.clone(),
                    publication.clone().unwrap(),
                    6,
                ),
                _ => controller.hydrate_bound(&context, expected.clone(), 7),
            };
            assert_eq!(attempt(&mut controller), Err(Error::Unknown));
            let uncertain = status(&port);
            let sent = port.0.borrow().proposals;
            port.0.borrow_mut().propose_fail = false;
            port.0.borrow_mut().unknown_after_apply = false;
            let repeated = attempt(&mut controller);
            if applied {
                assert_eq!(
                    repeated,
                    Err(Error::Rejected(Reject::Fenced)),
                    "stage {stage}"
                );
                assert_eq!(status(&port), uncertain);
                assert_eq!(port.0.borrow().proposals, sent);
            } else {
                repeated.unwrap();
                assert_eq!(port.0.borrow().proposals, sent + 1);
            }
            assert_eq!(
                status(&port).control_revision,
                before.control_revision.map(|revision| revision + 1)
            );
        }
    }
}

#[test]
fn prune_requires_the_same_publication_source_and_no_intervening_control() {
    let (mut controller, port, _, context) = controlled();
    controller
        .suspend_bound(&context, status(&port), 4)
        .unwrap();
    let original = status(&port);
    let published = controller
        .publish_bound(&context, original.clone(), 5)
        .unwrap();
    let mut unrelated = original.clone();
    unrelated.owner.epoch += 1;
    assert_eq!(
        controller.prune_bound(&context, unrelated, published.clone(), 6),
        Err(Error::Invalid)
    );
    // A second publication changes only the administrative sequence. It cannot
    // make the first publication's queued cleanup current again.
    let after_publish = status(&port);
    apply_kind(
        &mut port.0.borrow_mut().state,
        CommandKind::PublishArchive {
            operation_id: 55,
            expected_owner: after_publish.owner,
            expected_previous: after_publish.archive.map(|archive| archive.object_digest),
            archive: published.archive(),
        },
    );
    let interleaved = status(&port);
    assert_eq!(interleaved.owner, after_publish.owner);
    assert_eq!(interleaved.commit_hash, after_publish.commit_hash);
    assert_eq!(interleaved.archive, after_publish.archive);
    assert_eq!(interleaved.control_revision, Some(3));
    assert_eq!(
        controller.prune_bound(&context, original, published, 6),
        Err(Error::Rejected(Reject::Fenced))
    );
    assert_eq!(status(&port), interleaved);
    assert!(!interleaved.cold);
}

#[test]
fn malformed_publication_confirmation_produces_no_receipt_and_no_refresh() {
    for outcome in [
        Outcome::Administrative(AdminResult::ArchivePublished([0; 32])),
        Outcome::ControlApplied(ControlResult {
            revision: 9,
            position: Position { term: 1, index: 9 },
            result: AdminResult::ArchivePublished([0; 32]),
        }),
    ] {
        let (mut controller, port, _, context) = controlled();
        controller
            .suspend_bound(&context, status(&port), 4)
            .unwrap();
        let expected = status(&port);
        port.0.borrow_mut().outcome = Some(outcome);
        assert_eq!(
            controller.publish_bound(&context, expected.clone(), 5),
            Err(Error::Unknown)
        );
        let current = status(&port);
        assert_eq!(current.control_revision, Some(2));
        assert!(!current.cold);
        assert_eq!(
            controller.publish_bound(&context, expected, 5),
            Err(Error::Rejected(Reject::Fenced))
        );
        assert_eq!(status(&port), current);
    }
}

#[test]
fn bound_suspend_and_hydrate_recheck_the_captured_view_and_authorization() {
    for hydrate in [false, true] {
        for failure in 0..3 {
            let (mut controller, port, _, mut context) = controlled();
            let expected = status(&port);
            match failure {
                0 => port.0.borrow_mut().read_fail = true,
                1 => context.admission.auth_epoch += 1,
                _ => {
                    controller
                        .suspend_bound(&context, expected.clone(), 4)
                        .unwrap();
                }
            }
            let result = if hydrate {
                controller.hydrate_bound(&context, expected, 5)
            } else {
                controller.suspend_bound(&context, expected, 5)
            };
            assert!(result.is_err());
            assert_eq!(port.0.borrow().proposals, usize::from(failure == 2));
        }
    }
}

#[test]
fn accepted_control_results_require_original_revision_and_business_effect() {
    for repeated in [false, true] {
        let result = ControlResult {
            revision: 8,
            position: Position { term: 1, index: 5 },
            result: AdminResult::ArchiveHydrated([1; 32]),
        };
        let outcome = if repeated {
            Outcome::ControlAlreadyApplied(result)
        } else {
            Outcome::ControlApplied(result)
        };
        assert_eq!(
            accepted(
                outcome.clone(),
                AdminResult::ArchiveHydrated([1; 32]),
                Some(7)
            ),
            Ok(Some(8))
        );
        for expected in [None, Some(6), Some(u64::MAX)] {
            assert_eq!(
                accepted(
                    outcome.clone(),
                    AdminResult::ArchiveHydrated([1; 32]),
                    expected
                ),
                Err(Error::Unknown)
            );
        }
        assert_eq!(
            accepted(outcome, AdminResult::ArchiveHydrated([2; 32]), Some(7)),
            Err(Error::Unknown)
        );
    }
    for legacy in [
        Outcome::Administrative(AdminResult::Created),
        Outcome::AlreadyApplied(AdminResult::Created),
    ] {
        assert_eq!(
            accepted(legacy, AdminResult::Created, Some(7)),
            Err(Error::Unknown)
        );
    }
}

fn empty_control_state(bounded: Limits) -> CellState {
    let mut state =
        CellState::bootstrap(cell(), 11, Position { term: 1, index: 1 }, bounded).unwrap();
    let create = Command {
        cell: cell(),
        database: database(),
        admission: admission(),
        control_revision: None,
        kind: CommandKind::Create {
            operation_id: 1,
            policy: vec![Grant {
                principal_id: 11,
                permissions: READ | WRITE | ADMIN,
            }],
        },
    };
    apply_raw(
        &mut state,
        scap_cell::encode_command(&create, bounded).unwrap(),
        bounded,
    );
    apply_raw(
        &mut state,
        scap_cell::encode_retention_activation(cell(), 11),
        bounded,
    );
    apply_raw(
        &mut state,
        scap_cell::encode_control_activation(cell(), 11),
        bounded,
    );
    state
}

#[test]
fn every_publishable_control_archive_fits_the_bound_hydration_envelope() {
    let original = empty_control_state(limits());
    let (_, bytes) = original.archive_snapshot(database(), admission()).unwrap();
    let hydrate = Command {
        cell: cell(),
        database: database(),
        admission: admission(),
        control_revision: original
            .database(database().database_id)
            .unwrap()
            .control_revision,
        kind: CommandKind::HydrateArchive {
            operation_id: 2,
            archive: bytes.clone(),
        },
    };
    let required = scap_cell::encode_command(&hydrate, limits()).unwrap().len() - bytes.len();
    assert_eq!(required, 202);
    for margin in [192, required - 1, required] {
        let bounded = Limits {
            max_command_bytes: (bytes.len() + margin) as u32,
            ..limits()
        };
        let state = empty_control_state(bounded);
        let result = state.archive_snapshot(database(), admission());
        if margin < required {
            assert_eq!(
                result,
                Err(Reject::TooLarge),
                "must retain hot recovery bytes at margin {margin}"
            );
        } else {
            let (_, bytes) = result.unwrap();
            let mut hydrate = hydrate.clone();
            hydrate.kind = CommandKind::HydrateArchive {
                operation_id: 2,
                archive: bytes,
            };
            assert!(scap_cell::encode_command(&hydrate, bounded).is_ok());
        }
    }
}
