use super::*;
use scap_cell::ControlResult;

fn controlled(position: Position) -> CellState {
    let mut state = retained_state(Position {
        term: position.term,
        index: position.index - 1,
    });
    apply_raw(&mut state, scap_cell::encode_control_activation(cell(), 11));
    assert!(state.control_enabled());
    assert_eq!(state.position(), position);
    state
}

fn control_client() -> (Client<Port>, Port, Arc<TestClock>, RequestContext) {
    let (mut client, port, clock, context) = build();
    client.activate_retention(&context).unwrap();
    client.activate_control(&context).unwrap();
    port.0.borrow_mut().sent.clear();
    port.0.borrow_mut().read_calls = 0;
    (client, port, clock, context)
}

fn claim() -> CommandKind {
    CommandKind::ClaimOwner {
        operation_id: 70,
        expected_epoch: 1,
        worker_instance_id: 78,
    }
}

#[test]
fn independent_control_activation_confirms_phase_five_and_preserves_older_capabilities() {
    let (mut client, port, _, context) = build();
    client.activate_retention(&context).unwrap();
    let before = port.0.borrow().state.database(db().database_id).unwrap();
    let state = client.activate_control(&context).unwrap();
    let after = state.database(db().database_id).unwrap();
    assert!(state.control_enabled());
    assert_eq!(state.physical_history_version(), 5);
    assert_eq!(after.owner, before.owner);
    assert_eq!(after.revision, before.revision);
    assert_eq!(after.commit_hash, before.commit_hash);
    assert_eq!(after.request_epoch, before.request_epoch);
    assert!(after.control_revision.is_some());
    assert_eq!(
        port.0.borrow().sent[1],
        scap_cell::encode_control_activation(cell(), 11)
    );
    assert_ne!(
        port.0.borrow().sent[1],
        scap_cell::encode_retention_activation(cell(), 11)
    );
    let repeated = client.activate_control(&context).unwrap();
    assert_eq!(repeated.database(db().database_id).unwrap(), after);
    assert!(client
        .activate_retention(&context)
        .unwrap()
        .control_enabled());
    assert!(client.activate_history(&context).unwrap().control_enabled());
    let held = port.0.borrow();
    assert!(held
        .deadlines
        .iter()
        .all(|deadline| *deadline == context.deadline));
    assert!(held
        .cancel_pointers
        .iter()
        .all(|pointer| *pointer == Arc::as_ptr(&context.cancelled) as usize));
}

#[test]
fn control_activation_rejects_bad_completion_wrong_namespace_and_unauthorized_upgrade() {
    let (mut client, port, _, mut context) = build();
    client.activate_retention(&context).unwrap();
    port.0.borrow_mut().read_calls = 0;
    for field in 0..7 {
        let mut state = retained_state(Position { term: 1, index: 4 });
        let mut result = apply_raw(&mut state, scap_cell::encode_control_activation(cell(), 11));
        match field {
            0 => result.ticket.boot_id = 0,
            1 => result.ticket.sequence = 0,
            2 => result.data.clear(),
            3 => result.index += 1,
            4 => result.term += 1,
            5 => result.index = 0,
            _ => result.term = 0,
        }
        port.0.borrow_mut().proposals.push_back(Ok(result));
        assert!(matches!(
            client.activate_control(&context),
            Err(Error::Unknown)
        ));
    }
    for error in [RuntimeError::Unknown, RuntimeError::NotLeader] {
        port.0.borrow_mut().proposals.push_back(Err(error));
        assert!(matches!(
            client.activate_control(&context),
            Err(Error::Unknown)
        ));
    }
    let other = CellIdentity {
        cell_incarnation: 31,
        ..cell()
    };
    let mut other_state =
        CellState::bootstrap(other, 11, Position { term: 1, index: 1 }, limits()).unwrap();
    apply_raw(
        &mut other_state,
        scap_cell::encode_retention_activation(other, 11),
    );
    let result = apply_raw(
        &mut other_state,
        scap_cell::encode_control_activation(other, 11),
    );
    port.0.borrow_mut().proposals.push_back(Ok(result));
    assert!(matches!(
        client.activate_control(&context),
        Err(Error::Unknown)
    ));
    let wrong_phase = apply_raw(
        &mut bootstrap(),
        scap_cell::encode_retention_activation(cell(), 11),
    );
    port.0.borrow_mut().proposals.push_back(Ok(wrong_phase));
    assert!(matches!(
        client.activate_control(&context),
        Err(Error::Unknown)
    ));
    context.admission.principal_id = 22;
    assert!(matches!(
        client.activate_control(&context),
        Err(Error::Unknown)
    ));
    context.admission.principal_id = 11;
    port.0.borrow_mut().state = bootstrap();
    assert!(matches!(
        client.activate_control(&context),
        Err(Error::Unknown)
    ));
    port.0.borrow_mut().state =
        CellState::bootstrap_legacy(cell(), 11, Position { term: 1, index: 1 }, limits()).unwrap();
    assert!(matches!(
        client.activate_control(&context),
        Err(Error::Unknown)
    ));
    assert_eq!(port.0.borrow().read_calls, 0);
}

#[test]
fn control_activation_rechecks_fresh_phase_position_and_original_budget() {
    let stale_states = [
        retained_state(Position { term: 2, index: 7 }),
        controlled(Position { term: 2, index: 6 }),
        controlled(Position { term: 1, index: 7 }),
    ];
    for stale in stale_states {
        let (mut client, port, _, context) = build();
        port.0.borrow_mut().state = retained_state(Position { term: 2, index: 6 });
        port.0.borrow_mut().reads.push_back(Ok(view(&stale)));
        assert!(matches!(
            client.activate_control(&context),
            Err(Error::Unknown)
        ));
        assert!(port.0.borrow().state.control_enabled());
        assert_eq!(port.0.borrow().sent.len(), 1);
    }
    let (mut client, port, _, context) = build();
    port.0.borrow_mut().state = retained_state(Position { term: 1, index: 6 });
    port.0
        .borrow_mut()
        .reads
        .push_back(Err(RuntimeError::Unknown));
    assert!(matches!(
        client.activate_control(&context),
        Err(Error::Unknown)
    ));
    assert_eq!(port.0.borrow().sent.len(), 1);
    for expires in 1..=2 {
        let (mut client, port, clock, context) = build();
        clock.expire_on_call.store(
            clock.calls.load(Ordering::Acquire) + expires,
            Ordering::Release,
        );
        assert!(matches!(
            client.activate_control(&context),
            Err(Error::Unknown)
        ));
        assert!(port.0.borrow().sent.is_empty());
    }
    for after_read in [false, true] {
        let (mut client, port, _, context) = build();
        port.0.borrow_mut().state = retained_state(Position { term: 1, index: 6 });
        let cancelled = context.cancelled.clone();
        let hook: Box<dyn FnOnce()> = Box::new(move || cancelled.store(true, Ordering::Release));
        if after_read {
            port.0.borrow_mut().after_read = Some(hook);
        } else {
            port.0.borrow_mut().after_proposal = Some(hook);
        }
        assert!(matches!(
            client.activate_control(&context),
            Err(Error::Unknown)
        ));
        assert!(port.0.borrow().state.control_enabled());
        assert_eq!(port.0.borrow().read_calls, usize::from(after_read));
        assert_eq!(port.0.borrow().sent.len(), 1);
    }
}

#[test]
fn control_submission_keeps_the_original_intent_after_lost_ack_and_credential_refresh() {
    let (mut client, port, _, mut context) = control_client();
    let expected = port
        .0
        .borrow()
        .state
        .database(db().database_id)
        .unwrap()
        .control_revision;
    let mut original = command(claim());
    original.control_revision = expected;
    let bytes = scap_cell::encode_command(&original, limits()).unwrap();
    let applied = apply_bytes(&mut port.0.borrow_mut().state, bytes.clone());
    port.0
        .borrow_mut()
        .proposals
        .push_back(Err(RuntimeError::Unknown));
    assert!(matches!(
        client.submit_control(&context, db(), expected, claim()),
        Err(Error::Unknown)
    ));
    assert_eq!(port.0.borrow().sent, vec![bytes]);
    context.admission.credential_id += 1;
    context.admission.admission_id += 1;
    let repeated = client
        .submit_control(&context, db(), expected, claim())
        .unwrap();
    let Outcome::ControlApplied(original_receipt) = applied.outcome else {
        panic!("claim rejected")
    };
    assert_eq!(
        repeated.outcome,
        Outcome::ControlAlreadyApplied(original_receipt.clone())
    );
    assert_eq!(port.0.borrow().read_calls, 0);
    let view = port.0.borrow().state.database(db().database_id).unwrap();
    client
        .submit_control(
            &context,
            db(),
            view.control_revision,
            CommandKind::SuspendDb {
                operation_id: 71,
                token: view.owner,
                expected_revision: view.revision,
            },
        )
        .unwrap();
    let retired = client
        .submit_control(&context, db(), expected, claim())
        .unwrap();
    assert_eq!(retired.outcome, Outcome::Rejected(Reject::ControlRetired));
    assert_eq!(port.0.borrow().read_calls, 0);
    assert_eq!(port.0.borrow().sent.len(), 4);
    assert_eq!(original_receipt.revision, expected.unwrap() + 1);
}

#[test]
fn control_retry_rejects_a_newer_duplicate_receipt_without_refreshing_intent() {
    let (mut client, port, _, context) = control_client();
    let state = port.0.borrow().state.clone();
    let expected = state.database(db().database_id).unwrap().control_revision;
    let mut original = command(claim());
    original.control_revision = expected;
    let bytes = scap_cell::encode_command(&original, limits()).unwrap();
    port.0
        .borrow_mut()
        .proposals
        .push_back(Err(RuntimeError::Unknown));
    assert!(matches!(
        client.submit_control(&context, db(), expected, claim()),
        Err(Error::Unknown)
    ));

    // A valid duplicate-result envelope can still describe a newer control
    // identity. Its business effect and original position cannot authorize
    // replacing the revision captured before the first attempt.
    let original_position = Position {
        term: state.position().term,
        index: state.position().index + 2,
    };
    let returned = AppliedOutcome {
        position: Position {
            index: original_position.index + 1,
            ..original_position
        },
        outcome: Outcome::ControlAlreadyApplied(ControlResult {
            revision: expected.unwrap() + 2,
            position: original_position,
            result: AdminResult::OwnerClaimed(OwnerToken {
                epoch: 2,
                worker_instance_id: 78,
            }),
        }),
    };
    let response = reply(returned.clone());
    assert_eq!(
        scap_cell::decode_applied_outcome(&response.data, returned.position),
        Ok(returned)
    );
    port.0.borrow_mut().proposals.push_back(Ok(response));
    assert!(matches!(
        client.submit_control(&context, db(), expected, claim()),
        Err(Error::Unknown)
    ));
    assert_eq!(port.0.borrow().sent, vec![bytes.clone(), bytes]);
    assert_eq!(port.0.borrow().read_calls, 0);
}

#[test]
fn control_submission_requires_the_exact_receipt_namespace_revision_and_position() {
    for case in 0..14 {
        let (mut client, port, _, context) = control_client();
        let receipt = ControlResult {
            revision: if case == 1 { 8 } else { 1 },
            position: Position { term: 1, index: 5 },
            result: AdminResult::Created,
        };
        let business = match case {
            0 => Outcome::Administrative(AdminResult::Created),
            2 | 13 => Outcome::ControlAlreadyApplied(receipt),
            5 => Outcome::Rejected(Reject::ControlRetired),
            6 => Outcome::ControlApplied(ControlResult {
                position: Position { term: 1, index: 4 },
                ..receipt
            }),
            7 => Outcome::ControlAlreadyApplied(ControlResult {
                position: Position { term: 1, index: 6 },
                ..receipt
            }),
            8 => Outcome::ControlAlreadyApplied(ControlResult {
                position: Position { term: 2, index: 4 },
                ..receipt
            }),
            9 => Outcome::ControlAlreadyApplied(ControlResult {
                position: Position { term: 1, index: 4 },
                ..receipt
            }),
            10 => Outcome::ControlAlreadyApplied(ControlResult {
                position: Position { term: 0, index: 4 },
                ..receipt
            }),
            11 => Outcome::ControlAlreadyApplied(ControlResult {
                position: Position { term: 1, index: 0 },
                ..receipt
            }),
            _ => Outcome::ControlApplied(receipt),
        };
        let result = if case == 13 {
            reply(AppliedOutcome {
                position: Position { term: 2, index: 5 },
                outcome: business,
            })
        } else {
            outcome(business)
        };
        port.0.borrow_mut().proposals.push_back(Ok(result));
        let expected = match case {
            2 | 12 => None,
            3 => Some(u64::MAX),
            _ => Some(0),
        };
        let result = client.submit_control(&context, db(), expected, claim());
        if [4, 5, 9].contains(&case) {
            assert!(result.is_ok(), "case {case}");
        } else {
            assert!(
                matches!(result, Err(Error::Unknown)),
                "case {case}: {result:?}"
            );
        }
        assert_eq!(port.0.borrow().sent.len(), 1);
        assert_eq!(port.0.borrow().read_calls, 0);
    }
}
