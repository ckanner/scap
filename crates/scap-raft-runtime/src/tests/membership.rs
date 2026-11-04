use super::*;

fn dynamic() -> (Node, Handle, Arc<TestClock>) {
    let clock = Arc::new(TestClock::new());
    let mut cfg = config();
    cfg.requests.max_bytes = 32_768;
    cfg.max_pending_deliveries = 64;
    let limits = policy(&[1, 2, 3], &certificate()).limits();
    let p = Policy::with_trusted_peers(scope(), vec![1, 2, 3, 4, 5], vec![], limits).unwrap();
    let (node, handle) = Runtime::new(
        driver(&[1, 2, 3], Backend::default()),
        p,
        cfg,
        clock.clone(),
    )
    .unwrap();
    (node, handle, clock)
}

fn pump(node: &mut Node, network: &mut Capture) -> Vec<Message> {
    node.poll(network).unwrap();
    std::mem::take(&mut network.sent)
        .into_iter()
        .map(|delivery| {
            node.handle.complete(delivery.id, DeliveryResult::Received);
            Message::parse_from_bytes(&delivery.envelope.payload).unwrap()
        })
        .collect()
}

fn reply(
    node: &mut Node,
    network: &mut Capture,
    kind: MessageType,
    peer: u64,
    term: u64,
    index: u64,
    context: Vec<u8>,
) -> Vec<Message> {
    let mut message = Message {
        from: peer,
        to: 1,
        term,
        index,
        context: context.into(),
        ..Default::default()
    };
    message.set_msg_type(kind);
    node.driver.step(message).unwrap();
    pump(node, network)
}

fn elect_three(node: &mut Node, network: &mut Capture) {
    node.driver.campaign().unwrap();
    let pre_vote = pump(node, network).into_iter().find(|m| m.to == 2).unwrap();
    let vote = reply(
        node,
        network,
        MessageType::MsgRequestPreVoteResponse,
        2,
        pre_vote.term,
        0,
        vec![],
    )
    .into_iter()
    .find(|m| m.to == 2)
    .unwrap();
    reply(
        node,
        network,
        MessageType::MsgRequestVoteResponse,
        2,
        vote.term,
        0,
        vec![],
    );
    acknowledge(node, network, 2);
    assert_eq!(node.driver.status().unwrap().role, raft::StateRole::Leader);
}

fn acknowledge(node: &mut Node, network: &mut Capture, peer: u64) {
    let status = node.driver.status().unwrap();
    reply(
        node,
        network,
        MessageType::MsgAppendResponse,
        peer,
        status.term,
        status.last_index,
        vec![],
    );
}

fn change_input(node: &Node, change: MembershipChange) -> Input {
    Input::ChangeMembership {
        expected: node.driver.view().unwrap().conf_state.clone(),
        change,
    }
}

#[test]
fn fresh_membership_read_waits_for_its_safe_read_index() {
    let (mut node, handle, clock) = dynamic();
    let mut network = Capture::default();
    elect_three(&mut node, &mut network);
    let pending = handle.submit(Input::Membership, deadline(&clock)).unwrap();
    let messages = pump(&mut node, &mut network);
    assert!(matches!(
        pending.receiver.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    let heartbeat = messages
        .into_iter()
        .find(|m| {
            m.to == 2 && m.get_msg_type() == MessageType::MsgHeartbeat && !m.context.is_empty()
        })
        .unwrap();
    reply(
        &mut node,
        &mut network,
        MessageType::MsgHeartbeatResponse,
        2,
        heartbeat.term,
        0,
        heartbeat.context.to_vec(),
    );
    let Answer::Membership(status) = pending.wait().unwrap() else {
        panic!("membership read");
    };
    assert_eq!(status.conf_state.voters, vec![1, 2, 3]);
    assert_eq!(status.leader_id, 1);
    assert_eq!(status.applied, node.driver.view().unwrap().applied);
    assert!(status.commit >= status.applied);
    assert_eq!(status.progress.len(), 3);
    assert_eq!(handle.mailbox.requests.lock().count, 0);
}

#[test]
fn membership_changes_are_trusted_bounded_and_acknowledged_only_after_apply() {
    let (mut node, handle, clock) = dynamic();
    let mut network = Capture::default();
    elect_three(&mut node, &mut network);
    let unknown = handle
        .submit(
            change_input(&node, MembershipChange::AddLearner { node_id: 9 }),
            deadline(&clock),
        )
        .unwrap();
    pump(&mut node, &mut network);
    assert!(matches!(unknown.wait(), Err(Error::Wire(_))));
    let first = handle
        .submit(
            change_input(&node, MembershipChange::AddLearner { node_id: 4 }),
            deadline(&clock),
        )
        .unwrap();
    pump(&mut node, &mut network);
    assert!(matches!(
        first.receiver.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    assert!(node.driver.view().unwrap().conf_state.learners.is_empty());
    assert_eq!(handle.mailbox.requests.lock().count, 1);
    let concurrent = handle
        .submit(
            change_input(&node, MembershipChange::AddLearner { node_id: 5 }),
            deadline(&clock),
        )
        .unwrap();
    pump(&mut node, &mut network);
    assert_eq!(concurrent.wait().unwrap_err(), Error::MembershipPending);
    acknowledge(&mut node, &mut network, 2);
    let Answer::MembershipChanged(status) = first.wait().unwrap() else {
        panic!("durable configuration result");
    };
    assert_eq!(status.conf_state.learners, vec![4]);
    let replacement = MembershipChange::ReplaceVoter {
        remove_id: 3,
        learner_id: 4,
    };
    let lagging = handle
        .submit(change_input(&node, replacement), deadline(&clock))
        .unwrap();
    pump(&mut node, &mut network);
    assert_eq!(lagging.wait().unwrap_err(), Error::LearnerNotCaughtUp);
    acknowledge(&mut node, &mut network, 4);
    let replacement = handle
        .submit(change_input(&node, replacement), deadline(&clock))
        .unwrap();
    pump(&mut node, &mut network);
    acknowledge(&mut node, &mut network, 2);
    let Answer::MembershipChanged(joint) = replacement.wait().unwrap() else {
        panic!("joint result");
    };
    assert_eq!(joint.conf_state.voters, vec![1, 2, 4]);
    assert_eq!(joint.conf_state.voters_outgoing, vec![1, 2, 3]);
    let leave = handle
        .submit(
            change_input(&node, MembershipChange::LeaveJoint),
            deadline(&clock),
        )
        .unwrap();
    pump(&mut node, &mut network);
    acknowledge(&mut node, &mut network, 2);
    let Answer::MembershipChanged(stable) = leave.wait().unwrap() else {
        panic!("stable result");
    };
    assert!(stable.conf_state.voters_outgoing.is_empty());
    assert_eq!(handle.mailbox.requests.lock().count, 0);
}

#[test]
fn cancellation_and_expiry_retire_only_waiters_and_stale_cas_cannot_repeat() {
    for cancel in [false, true] {
        let (mut node, handle, clock) = dynamic();
        let mut network = Capture::default();
        elect_three(&mut node, &mut network);
        let input = change_input(&node, MembershipChange::AddLearner { node_id: 4 });
        let pending = handle.submit(input, deadline(&clock)).unwrap();
        pump(&mut node, &mut network);
        if cancel {
            pending.cancelled.store(true, Ordering::Release);
        } else {
            clock.advance(Duration::from_secs(2));
        }
        pump(&mut node, &mut network);
        assert_eq!(pending.wait().unwrap_err(), Error::Unknown);
        assert!(node.membership.is_none());
        assert_eq!(handle.mailbox.requests.lock().count, 0);
        acknowledge(&mut node, &mut network, 2);
        assert_eq!(
            node.driver.membership_status().unwrap().conf_state.learners,
            vec![4]
        );
        let stale = Input::ChangeMembership {
            expected: ConfState {
                voters: vec![1, 2, 3],
                ..Default::default()
            },
            change: MembershipChange::AddLearner { node_id: 5 },
        };
        let pending = handle.submit(stale, deadline(&clock)).unwrap();
        pump(&mut node, &mut network);
        assert_eq!(pending.wait().unwrap_err(), Error::MembershipConflict);
    }
}

#[test]
fn fixed_policy_rejects_configuration_management_without_changing_state() {
    let (mut node, handle, clock, _, _) = build(&[1]);
    let mut network = Capture::default();
    elect(&mut node, &mut network);
    assert!(matches!(
        call(&mut node, &handle, &clock, &mut network, Input::Membership).unwrap(),
        Answer::Membership(_)
    ));
    let input = change_input(&node, MembershipChange::AddLearner { node_id: 4 });
    let before = node.driver.view().unwrap().clone();
    assert!(matches!(
        call(&mut node, &handle, &clock, &mut network, input),
        Err(Error::Wire(_))
    ));
    assert_eq!(node.driver.view().unwrap(), &before);
}

#[test]
fn membership_request_budget_counts_all_cas_sets_and_rejects_oversized_input() {
    let (_, handle, clock) = dynamic();
    let mut conf = ConfState {
        voters: vec![1, 2, 3],
        learners: vec![4],
        voters_outgoing: vec![1, 2, 5],
        learners_next: vec![5],
        auto_leave: false,
        ..Default::default()
    };
    assert_eq!(
        membership_request_bytes(&conf).unwrap(),
        MEMBERSHIP_BYTES + 256 + 8 * 16
    );
    let mut unknown = conf.clone();
    unknown
        .mut_unknown_fields()
        .add_length_delimited(99, vec![7; 32]);
    assert_eq!(
        membership_request_bytes(&unknown).unwrap_err(),
        Error::Invalid("unknown membership fields")
    );
    for field in 0..4 {
        let mut invalid = conf.clone();
        *match field {
            0 => &mut invalid.voters,
            1 => &mut invalid.learners,
            2 => &mut invalid.voters_outgoing,
            _ => &mut invalid.learners_next,
        } = vec![1; MAX_MEMBERS + 1];
        assert!(matches!(
            handle.submit(
                Input::ChangeMembership {
                    expected: invalid,
                    change: MembershipChange::LeaveJoint
                },
                deadline(&clock)
            ),
            Err(Error::InputLimit)
        ));
    }
    conf.voters.clear();
    assert!(membership_request_bytes(&conf).is_ok());
    for (input, expected) in [
        (
            scap_raft_driver::Error::MembershipConflict,
            Error::MembershipConflict,
        ),
        (
            scap_raft_driver::Error::MembershipPending,
            Error::MembershipPending,
        ),
        (
            scap_raft_driver::Error::LearnerNotCaughtUp,
            Error::LearnerNotCaughtUp,
        ),
        (
            scap_raft_driver::Error::MembershipInvalid("invalid action"),
            Error::Invalid("invalid action"),
        ),
    ] {
        assert_eq!(driver_error(input), expected);
    }
}

#[test]
fn dynamic_runtime_accepts_genesis_that_excludes_a_registered_local_node() {
    let clock = Arc::new(TestClock::new());
    let p = Policy::with_trusted_peers(
        scope(),
        vec![1, 2, 3, 4],
        vec![],
        policy(&[1], &certificate()).limits(),
    )
    .unwrap();
    let (mut node, handle) = Runtime::new(
        driver(&[2, 3, 4], Backend::default()),
        p,
        config(),
        clock.clone(),
    )
    .unwrap();
    assert!(!node.driver.status().unwrap().is_voter);
    assert_eq!(
        call(
            &mut node,
            &handle,
            &clock,
            &mut Capture::default(),
            Input::Membership
        )
        .unwrap_err(),
        Error::NotLeader
    );
}

#[test]
fn fatal_membership_operations_close_ingress_without_fabricating_completion() {
    for operation in [
        "change_membership",
        "membership_status",
        "cancel_membership",
    ] {
        let (mut node, handle, clock) = dynamic();
        let mut network = Capture::default();
        elect_three(&mut node, &mut network);
        let pending = handle
            .submit(
                change_input(&node, MembershipChange::AddLearner { node_id: 4 }),
                deadline(&clock),
            )
            .unwrap();
        if operation == "change_membership" {
            node.driver.fail(operation, 0, true);
            assert!(matches!(node.poll(&mut network), Err(Error::Driver(_))));
            assert!(matches!(pending.wait(), Err(Error::Driver(_))));
        } else {
            pump(&mut node, &mut network);
            node.driver.fail(operation, 0, true);
            if operation == "cancel_membership" {
                pending.cancelled.store(true, Ordering::Release);
            } else {
                let status = node.driver.status().unwrap();
                let mut ack = Message {
                    from: 2,
                    to: 1,
                    term: status.term,
                    index: status.last_index,
                    ..Default::default()
                };
                ack.set_msg_type(MessageType::MsgAppendResponse);
                node.driver.step(ack).unwrap();
            }
            assert!(matches!(node.poll(&mut network), Err(Error::Driver(_))));
            assert!(matches!(
                pending.wait(),
                Err(Error::Driver(_)) | Err(Error::Unknown)
            ));
        }
        assert!(handle.is_stopped());
        assert!(node.membership.is_none());
    }
}

#[test]
fn stop_releases_pending_membership_as_unknown() {
    let (mut node, handle, clock) = dynamic();
    let mut network = Capture::default();
    elect_three(&mut node, &mut network);
    let pending = handle
        .submit(
            change_input(&node, MembershipChange::AddLearner { node_id: 4 }),
            deadline(&clock),
        )
        .unwrap();
    pump(&mut node, &mut network);
    handle.stop();
    assert_eq!(node.poll(&mut network).unwrap_err(), Error::Closed);
    assert_eq!(pending.wait().unwrap_err(), Error::Unknown);
    assert_eq!(handle.mailbox.requests.lock().count, 0);
}

#[test]
fn membership_handoff_rechecks_original_deadline_and_cancellation_after_commit() {
    for cancel in [false, true] {
        let (mut node, handle, clock) = dynamic();
        let mut network = Capture::default();
        elect_three(&mut node, &mut network);
        let pending = handle
            .submit(
                change_input(&node, MembershipChange::AddLearner { node_id: 4 }),
                deadline(&clock),
            )
            .unwrap();
        pump(&mut node, &mut network);
        if cancel {
            pending.cancelled.store(true, Ordering::Release);
        } else {
            clock.advance(Duration::from_secs(2));
        }
        acknowledge(&mut node, &mut network, 2);
        assert_eq!(pending.wait().unwrap_err(), Error::Unknown);
        assert_eq!(
            node.driver.membership_status().unwrap().conf_state.learners,
            vec![4]
        );
        assert!(node.membership.is_none());
        assert_eq!(handle.mailbox.requests.lock().count, 0);
    }
}

#[test]
fn stale_or_inconsistent_membership_results_cannot_complete_a_new_waiter() {
    for fault in 0..4 {
        let (mut node, handle, clock) = dynamic();
        let mut network = Capture::default();
        elect_three(&mut node, &mut network);
        let pending = handle
            .submit(
                change_input(&node, MembershipChange::AddLearner { node_id: 4 }),
                deadline(&clock),
            )
            .unwrap();
        pump(&mut node, &mut network);
        let status = node.driver.membership_status().unwrap();
        let mut result = MembershipResult {
            ticket: node.membership.as_ref().unwrap().ticket,
            index: status.applied,
            term: status.term,
            conf_state: status.conf_state,
        };
        match fault {
            0 => result.ticket.boot_id += 1,
            1 => result.index += 1,
            2 => result.conf_state.learners = vec![5],
            _ => node.driver.fail("membership_status", 0, false),
        }
        node.driver.extra_memberships.push(result);
        pump(&mut node, &mut network);
        if fault == 0 {
            assert!(matches!(
                pending.receiver.try_recv(),
                Err(mpsc::TryRecvError::Empty)
            ));
            assert!(node.membership.is_some());
            acknowledge(&mut node, &mut network, 2);
            assert!(matches!(
                pending.wait().unwrap(),
                Answer::MembershipChanged(_)
            ));
        } else {
            assert!(matches!(
                pending.wait(),
                Err(Error::Unknown) | Err(Error::Driver(_))
            ));
            assert!(node.membership.is_none());
            // The underlying exact proposal can still commit after this
            // inconsistent adapter completion; no retired waiter is revived.
            acknowledge(&mut node, &mut network, 2);
            assert!(!handle.is_stopped());
        }
        assert_eq!(handle.mailbox.requests.lock().count, 0);
    }
}

#[test]
fn fresh_membership_read_propagates_status_failure_and_stops_on_fatal_failure() {
    for fatal in [false, true] {
        let (mut node, handle, clock, _, _) = build(&[1]);
        let mut network = Capture::default();
        elect(&mut node, &mut network);
        let pending = handle.submit(Input::Membership, deadline(&clock)).unwrap();
        node.driver.fail("membership_status", 0, fatal);
        let result = node.poll(&mut network);
        assert_eq!(result.is_err(), fatal);
        assert!(matches!(pending.wait(), Err(Error::Driver(_))));
        assert_eq!(handle.is_stopped(), fatal);
    }
}
