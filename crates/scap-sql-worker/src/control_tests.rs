use super::*;
use scap_cell::ControlResult;

fn kit() -> Kit {
    let mut kit = Kit::new();
    {
        let state = &mut kit.port.0.borrow_mut().state;
        apply_data(
            state,
            scap_cell::encode_retention_activation(identity().cell, 11),
        );
        apply_data(
            state,
            scap_cell::encode_control_activation(identity().cell, 11),
        );
        assert!(state.control_enabled());
        kit.request.expected_control_revision = state
            .database(identity().database.database_id)
            .unwrap()
            .control_revision;
    }
    kit
}

fn confirm(state: &CellState) -> scap_cell::DatabaseView {
    state.database(identity().database.database_id).unwrap()
}

#[test]
fn recovery_binds_activate_to_exact_claim_completion() {
    let kit = kit();
    let original = kit.request;
    let writer = kit.recover(kit.factory(), limits()).unwrap();
    let final_view = confirm(&kit.port.0.borrow().state);
    assert!(final_view.active);
    assert_eq!(
        final_view.control_revision,
        original
            .expected_control_revision
            .map(|revision| revision + 2)
    );
    let mut claim = command(CommandKind::ClaimOwner {
        operation_id: original.claim_operation_id,
        expected_epoch: original.expected_owner_epoch,
        worker_instance_id: original.worker_instance_id,
    });
    claim.control_revision = original.expected_control_revision;
    let mut activate = command(CommandKind::ActivateOwner {
        operation_id: original.activate_operation_id,
        token: writer.owner(),
        restored_revision: 0,
        restored_hash: [0; 32],
    });
    activate.control_revision = original
        .expected_control_revision
        .map(|revision| revision + 1);
    assert_eq!(
        kit.port.0.borrow().sent,
        vec![
            scap_cell::encode_command(&claim, cell_limits()).unwrap(),
            scap_cell::encode_command(&activate, cell_limits()).unwrap(),
        ]
    );
    assert_eq!(kit.request, original);
}

#[test]
fn lost_claim_ack_can_only_retry_the_same_bound_claim_with_refreshed_credentials() {
    let mut kit = kit();
    let original = kit.request;
    kit.port.0.borrow_mut().unknown_after_apply.insert(1);
    assert!(matches!(
        kit.recover(kit.factory(), limits()),
        Err(Error::Client(scap_cell_client::Error::Unknown))
    ));
    let claimed = confirm(&kit.port.0.borrow().state);
    assert!(!claimed.active);
    assert_eq!(claimed.control_revision, Some(1));
    kit.context.admission.credential_id += 1;
    kit.context.admission.admission_id += 1;
    let writer = kit.recover(kit.factory(), limits()).unwrap();
    assert_eq!(writer.owner(), claimed.owner);
    assert_eq!(kit.request, original);
    assert_eq!(
        confirm(&kit.port.0.borrow().state).control_revision,
        Some(2)
    );
    let mut old = command(CommandKind::ClaimOwner {
        operation_id: original.claim_operation_id,
        expected_epoch: original.expected_owner_epoch,
        worker_instance_id: original.worker_instance_id,
    });
    old.control_revision = original.expected_control_revision;
    let first = scap_cell::encode_command(&old, cell_limits()).unwrap();
    old.admission = kit.context.admission;
    let second = scap_cell::encode_command(&old, cell_limits()).unwrap();
    assert_eq!(kit.port.0.borrow().sent[..2], [first, second]);
}

#[test]
fn lost_activation_or_intervening_control_never_rebinds_a_recovery_intent() {
    for activation_was_applied in [false, true] {
        let kit = kit();
        kit.port
            .0
            .borrow_mut()
            .unknown_after_apply
            .insert(if activation_was_applied { 2 } else { 1 });
        assert!(matches!(
            kit.recover(kit.factory(), limits()),
            Err(Error::Client(_))
        ));
        if !activation_was_applied {
            let view = confirm(&kit.port.0.borrow().state);
            apply(
                &mut kit.port.0.borrow_mut().state,
                CommandKind::SuspendDb {
                    operation_id: 30,
                    token: view.owner,
                    expected_revision: view.revision,
                },
            );
        }
        let before = confirm(&kit.port.0.borrow().state);
        let factory = kit.factory();
        let effects = factory.effect.clone();
        assert!(matches!(
            kit.recover(factory, limits()),
            Err(Error::Rejected(Reject::ControlRetired))
        ));
        assert_eq!(confirm(&kit.port.0.borrow().state), before);
        assert_eq!(effects.borrow().dropped, 0);
        assert_eq!(kit.request.expected_control_revision, Some(0));
    }
}

#[test]
fn same_head_control_interleavings_fail_before_writer_publication() {
    for stage in 0..3 {
        let kit = kit();
        let mutation = CommandKind::AuthFence {
            operation_id: 50,
            expected_epoch: 1,
            policy: vec![Grant {
                principal_id: 11,
                permissions: READ | WRITE | ADMIN,
            }],
        };
        match stage {
            0 => {
                kit.port.0.borrow_mut().mutate_reads.insert(2, mutation);
            }
            1 => {
                kit.port.0.borrow_mut().mutate_proposals.insert(2, mutation);
            }
            _ => {
                kit.port.0.borrow_mut().mutate_reads.insert(3, mutation);
            }
        }
        let factory = kit.factory();
        let effects = factory.effect.clone();
        assert!(matches!(
            kit.recover(factory, limits()),
            Err(Error::Rejected(_))
        ));
        assert_eq!(effects.borrow().dropped, usize::from(stage != 0));
        let view = confirm(&kit.port.0.borrow().state);
        assert_eq!(view.revision, 0);
        assert_eq!(view.commit_hash, [0; 32]);
        assert_eq!(
            view.owner.worker_instance_id,
            kit.request.worker_instance_id
        );
    }
}

#[test]
fn unbound_or_future_recovery_intents_and_missing_final_view_do_not_open_writers() {
    for expected in [None, Some(9)] {
        let mut kit = kit();
        kit.request.expected_control_revision = expected;
        let before = confirm(&kit.port.0.borrow().state);
        assert!(matches!(
            kit.recover(kit.factory(), limits()),
            Err(Error::Rejected(_))
        ));
        assert_eq!(confirm(&kit.port.0.borrow().state), before);
        assert_eq!(kit.port.0.borrow().proposals, 1);
    }
    let kit = kit();
    kit.port.0.borrow_mut().override_reads.insert(3, genesis());
    let factory = kit.factory();
    let effects = factory.effect.clone();
    assert!(matches!(
        kit.recover(factory, limits()),
        Err(Error::Rejected(Reject::NotFound))
    ));
    assert_eq!(effects.borrow().dropped, 1);
}

#[test]
fn administrative_control_completion_checks_revision_and_effect_without_refresh() {
    for repeated in [false, true] {
        let receipt = ControlResult {
            revision: 8,
            position: Position { term: 1, index: 5 },
            result: AdminResult::OwnerActivated,
        };
        let outcome = if repeated {
            Outcome::ControlAlreadyApplied(receipt)
        } else {
            Outcome::ControlApplied(receipt)
        };
        assert_eq!(
            administrative(outcome.clone(), AdminResult::OwnerActivated, Some(7)).unwrap(),
            Some(8)
        );
        for revision in [None, Some(6), Some(u64::MAX)] {
            assert!(matches!(
                administrative(outcome.clone(), AdminResult::OwnerActivated, revision),
                Err(Error::Unknown)
            ));
        }
        assert!(matches!(
            administrative(outcome, AdminResult::Created, Some(7)),
            Err(Error::Unknown)
        ));
    }
    for legacy in [
        Outcome::Administrative(AdminResult::OwnerActivated),
        Outcome::AlreadyApplied(AdminResult::OwnerActivated),
    ] {
        assert!(matches!(
            administrative(legacy, AdminResult::OwnerActivated, Some(7)),
            Err(Error::Unknown)
        ));
    }
    assert!(matches!(
        administrative(
            Outcome::Rejected(Reject::ControlRetired),
            AdminResult::OwnerActivated,
            Some(7)
        ),
        Err(Error::Rejected(Reject::ControlRetired))
    ));
}

#[test]
fn administrative_recovery_still_requires_current_write_authority_before_serving() {
    let mut kit = kit();
    apply(
        &mut kit.port.0.borrow_mut().state,
        CommandKind::AuthFence {
            operation_id: 60,
            expected_epoch: 1,
            policy: vec![Grant {
                principal_id: 11,
                permissions: READ | ADMIN,
            }],
        },
    );
    kit.context.admission.auth_epoch = 2;
    kit.request.expected_control_revision = confirm(&kit.port.0.borrow().state).control_revision;
    let factory = kit.factory();
    let effects = factory.effect.clone();
    assert!(matches!(
        kit.recover(factory, limits()),
        Err(Error::Rejected(Reject::Unauthorized))
    ));
    assert_eq!(effects.borrow().dropped, 1);
    assert_eq!(kit.port.0.borrow().proposals, 2);
}
