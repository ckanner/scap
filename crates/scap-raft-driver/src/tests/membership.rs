use super::*;

fn leader_three() -> (Node, Backend) {
    let (mut node, backend, _) = build(&[1, 2, 3], config());
    elect_with_peer(&mut node);
    (node, backend)
}

fn acknowledge(node: &mut Node, peer: u64) -> Output {
    let status = node.status().unwrap();
    let mut response = Message {
        from: peer,
        to: 1,
        term: status.term,
        index: status.last_index,
        ..Default::default()
    };
    response.set_msg_type(MessageType::MsgAppendResponse);
    node.step(response).unwrap();
    drain(node)
}

fn add_learner(node: &mut Node, node_id: u64) -> MembershipResult {
    let expected = node.view().unwrap().conf_state.clone();
    let ticket = node
        .change_membership(&expected, MembershipChange::AddLearner { node_id })
        .unwrap();
    let before = drain(node);
    assert!(
        before.memberships.is_empty(),
        "admission is not application"
    );
    assert!(node.view().unwrap().conf_state.learners.is_empty());
    let output = acknowledge(node, 2);
    assert_eq!(output.memberships.len(), 1);
    let result = output.memberships.into_iter().next().unwrap();
    assert_eq!(result.ticket, ticket);
    assert_eq!(result.conf_state.learners, vec![node_id]);
    result
}

#[test]
fn management_waits_for_durable_application_catchup_and_explicit_joint_exit() {
    let (mut node, backend) = leader_three();
    let original = node.membership_status().unwrap();
    let added = add_learner(&mut node, 4);
    assert!(added.index > original.applied);
    let status = node.membership_status().unwrap();
    assert_eq!(status.conf_state.voters, vec![1, 2, 3]);
    assert_eq!(status.conf_state.learners, vec![4]);
    assert!(
        status
            .progress
            .iter()
            .find(|p| p.node_id == 4)
            .unwrap()
            .is_learner
    );
    let replace = MembershipChange::ReplaceVoter {
        remove_id: 3,
        learner_id: 4,
    };
    assert!(matches!(
        node.change_membership(&status.conf_state, replace),
        Err(Error::LearnerNotCaughtUp)
    ));
    acknowledge(&mut node, 4);
    let status = node.membership_status().unwrap();
    assert!(
        status
            .progress
            .iter()
            .find(|p| p.node_id == 4)
            .unwrap()
            .matched
            >= status.commit
    );
    let ticket = node.change_membership(&status.conf_state, replace).unwrap();
    assert!(drain(&mut node).memberships.is_empty());
    let output = acknowledge(&mut node, 2);
    assert_eq!(output.memberships[0].ticket, ticket);
    let joint = node.membership_status().unwrap();
    assert_eq!(joint.conf_state.voters, vec![1, 2, 4]);
    assert_eq!(joint.conf_state.voters_outgoing, vec![1, 2, 3]);
    assert!(!joint.conf_state.auto_leave);
    for _ in 0..3 {
        node.tick().unwrap();
        drain(&mut node);
    }
    assert!(!node.view().unwrap().conf_state.voters_outgoing.is_empty());
    let ticket = node
        .change_membership(&joint.conf_state, MembershipChange::LeaveJoint)
        .unwrap();
    drain(&mut node);
    let result = acknowledge(&mut node, 2).memberships.remove(0);
    assert_eq!(result.ticket, ticket);
    assert!(result.conf_state.voters_outgoing.is_empty());
    node.checkpoint().unwrap();
    drop(node);
    let mut reopened_config = config();
    reopened_config.boot_id += 1;
    let mut node = Driver::new(
        Store::open_existing(backend, identity(), limits()).unwrap(),
        Counter::default(),
        reopened_config,
        &logger(),
    )
    .unwrap();
    elect_with_peer(&mut node);
    let status = node.membership_status().unwrap();
    assert!(status.snapshot_index >= result.index);
    assert_eq!(status.conf_state, result.conf_state);
    for retired in [1, 2, 3, 4] {
        assert!(matches!(
            node.change_membership(
                &status.conf_state,
                MembershipChange::AddLearner { node_id: retired }
            ),
            Err(Error::MembershipInvalid(_))
        ));
    }
    add_learner(&mut node, u64::MAX);
}

#[test]
fn pending_configuration_cancellation_and_stale_cas_do_not_replay_changes() {
    let (mut node, _) = leader_three();
    let expected = node.view().unwrap().conf_state.clone();
    let ticket = node
        .change_membership(&expected, MembershipChange::AddLearner { node_id: 4 })
        .unwrap();
    drain(&mut node);
    assert!(matches!(
        node.change_membership(&expected, MembershipChange::AddLearner { node_id: 5 }),
        Err(Error::MembershipPending)
    ));
    assert!(!node
        .cancel_membership(MembershipTicket {
            boot_id: ticket.boot_id + 1,
            ..ticket
        })
        .unwrap());
    assert!(node.cancel_membership(ticket).unwrap());
    assert!(!node.cancel_membership(ticket).unwrap());
    assert!(matches!(
        node.change_membership(&expected, MembershipChange::AddLearner { node_id: 5 }),
        Err(Error::MembershipPending)
    ));
    assert!(acknowledge(&mut node, 2).memberships.is_empty());
    assert_eq!(
        node.membership_status().unwrap().conf_state.learners,
        vec![4]
    );
    assert!(matches!(
        node.change_membership(&expected, MembershipChange::AddLearner { node_id: 5 }),
        Err(Error::MembershipConflict)
    ));
    assert_eq!(node.next_membership, ticket.sequence + 1);
}

#[test]
fn joining_and_removed_nodes_never_campaign_propose_or_read() {
    let backend = Backend::default();
    let mut id = identity();
    id.node_id = 4;
    let store = Store::create_new(
        backend.clone(),
        id.clone(),
        ConfState {
            voters: vec![1, 2, 3],
            ..Default::default()
        },
        limits(),
    )
    .unwrap();
    let mut node = Driver::new(store, Counter::default(), config(), &logger()).unwrap();
    assert!(!node.status().unwrap().is_voter);
    assert!(matches!(node.campaign(), Err(Error::NotLeader)));
    for _ in 0..30 {
        node.tick().unwrap();
        drain(&mut node);
    }
    assert_eq!(node.status().unwrap().role, StateRole::Follower);
    assert!(matches!(
        node.propose(vec![], vec![1]),
        Err(Error::NotLeader)
    ));
    assert!(matches!(
        node.propose_tracked(vec![1], 8),
        Err(Error::NotLeader)
    ));
    assert!(matches!(node.read_index(), Err(Error::NotLeader)));
    let mut snapshot = raft::eraftpb::Snapshot::default();
    snapshot.mut_metadata().index = 20;
    snapshot.mut_metadata().term = 2;
    snapshot.mut_metadata().set_conf_state(ConfState {
        voters: vec![1, 2, 3],
        learners: vec![4],
        ..Default::default()
    });
    snapshot.data = 7u64.to_be_bytes().to_vec().into();
    let mut message = Message {
        from: 2,
        to: 4,
        term: 3,
        ..Default::default()
    };
    message.set_msg_type(MessageType::MsgSnapshot);
    message.set_snapshot(snapshot);
    node.step(message).unwrap();
    drain(&mut node);
    assert!(!node.status().unwrap().is_voter);
    assert_eq!(node.view().unwrap().applied, 20);
    assert_eq!(value(&node.view().unwrap().application), 7);
    drop(node);
    let mut node = Driver::new(
        Store::open_existing(backend, id, limits()).unwrap(),
        Counter::default(),
        config(),
        &logger(),
    )
    .unwrap();
    assert!(!node.status().unwrap().is_voter);
    assert!(matches!(node.campaign(), Err(Error::NotLeader)));
}

#[test]
fn exact_configuration_result_does_not_match_old_forged_or_superseded_entries() {
    let (mut node, _) = leader_three();
    let conf = node.view().unwrap().conf_state.clone();
    node.change_membership(&conf, MembershipChange::AddLearner { node_id: 4 })
        .unwrap();
    let pending = node.pending_membership.as_ref().unwrap();
    let entry = Entry {
        index: 3,
        term: pending.term,
        context: pending.context.clone().into(),
        data: pending.data.clone().into(),
        ..Default::default()
    };
    let target = pending.target.clone();
    let result = node.match_membership(&entry, &target).unwrap();
    for mutate in [
        |e: &mut Entry| e.term += 1,
        |e: &mut Entry| e.context = vec![0].into(),
        |e: &mut Entry| e.data = vec![0].into(),
    ] {
        let mut candidate = entry.clone();
        mutate(&mut candidate);
        assert!(node.match_membership(&candidate, &target).is_none());
    }
    assert!(node.match_membership(&entry, &conf).is_none());
    let mut invalid = target.clone();
    invalid.voters.resize(MAX_MEMBERS + 1, 1);
    assert!(node.match_membership(&entry, &invalid).is_none());
    node.pending_membership.as_mut().unwrap().result = Some(result);
    assert!(node.match_membership(&entry, &target).is_none());
    node.pending_membership = None;
    assert!(node.match_membership(&entry, &target).is_none());
}

#[test]
fn membership_admission_and_result_queues_obey_explicit_bounds() {
    let (mut node, _) = leader_three();
    let expected = node.view().unwrap().conf_state.clone();
    let action = MembershipChange::AddLearner { node_id: 4 };
    node.next_membership = u64::MAX;
    assert!(matches!(
        node.change_membership(&expected, action),
        Err(Error::ProposalIdExhausted)
    ));
    node.next_membership = 1;
    node.config.max_input_bytes = 1;
    assert!(matches!(
        node.change_membership(&expected, action),
        Err(Error::InputLimit)
    ));
    node.config.max_input_bytes = 65536;
    node.config.max_output_bytes = MEMBERSHIP_BYTES - 1;
    assert!(matches!(
        node.change_membership(&expected, action),
        Err(Error::InputLimit)
    ));
    node.config.max_output_bytes = MEMBERSHIP_BYTES;
    node.change_membership(&expected, action).unwrap();
    drain(&mut node);
    let status = node.status().unwrap();
    let mut ack = Message {
        from: 2,
        to: 1,
        term: status.term,
        index: status.last_index,
        ..Default::default()
    };
    ack.set_msg_type(MessageType::MsgAppendResponse);
    node.step(ack).unwrap();
    let output = node.drain().unwrap();
    assert!(output.memberships.is_empty());
    assert!(output.more_ready);
    assert!(node.has_completed_membership());
    assert!(matches!(node.tick(), Err(Error::NeedsDrain)));
    // Drain any remaining protocol work while holding the completed result at
    // the output-budget boundary. Admission must remain closed even when only
    // the completed membership waiter, rather than a RawNode Ready, remains.
    node.config.max_output_bytes = MEMBERSHIP_BYTES - 1;
    assert!(node.drain().unwrap().memberships.is_empty());
    assert!(!node.node.has_ready());
    assert!(matches!(node.tick(), Err(Error::NeedsDrain)));
    node.config.max_output_bytes = MEMBERSHIP_BYTES;
    assert_eq!(drain(&mut node).memberships.len(), 1);
    assert!(!node.has_completed_membership());
    let backend = Backend::default();
    let conf = ConfState {
        voters: (1..=16).collect(),
        learners: vec![17],
        ..Default::default()
    };
    let large = Store::create_new(backend, identity(), conf, limits()).unwrap();
    let node = Driver::new(large, Counter::default(), config(), &logger()).unwrap();
    assert!(matches!(node.membership_status(), Err(Error::InputLimit)));
    let (node, _, _) = build(&(1..=17).collect::<Vec<_>>(), config());
    assert!(matches!(node.membership_status(), Err(Error::InputLimit)));
}

#[test]
fn storage_uncertainty_never_releases_an_applied_membership_result() {
    for after in [false, true] {
        let (mut node, backend) = leader_three();
        let expected = node.view().unwrap().conf_state.clone();
        node.change_membership(&expected, MembershipChange::AddLearner { node_id: 4 })
            .unwrap();
        drain(&mut node);
        let status = node.status().unwrap();
        let mut ack = Message {
            from: 2,
            to: 1,
            term: status.term,
            index: status.last_index,
            ..Default::default()
        };
        ack.set_msg_type(MessageType::MsgAppendResponse);
        node.step(ack).unwrap();
        let at = backend.writes.get() + 2;
        backend.fault.set(if after {
            Fault::After(at)
        } else {
            Fault::Before(at)
        });
        assert!(matches!(node.drain(), Err(Error::Store(_))));
        assert!(node.is_stopped());
        assert!(matches!(node.membership_status(), Err(Error::Stopped)));
        assert!(matches!(
            node.cancel_membership(MembershipTicket {
                boot_id: 40,
                sequence: 1
            }),
            Err(Error::Stopped)
        ));
        backend.fault.set(Fault::None);
        let disk = Store::open_existing(backend, identity(), limits()).unwrap();
        if after {
            assert_eq!(disk.view().unwrap().conf_state.learners, vec![4]);
        } else {
            assert!(disk.view().unwrap().conf_state.learners.is_empty());
        }
        let mut reopened = Driver::new(disk, Counter::default(), config(), &logger()).unwrap();
        assert!(drain(&mut reopened).memberships.is_empty());
        assert_eq!(reopened.view().unwrap().conf_state.learners, vec![4]);
    }
}

fn elect_outgoing_leader(node: &mut Node) {
    node.campaign().unwrap();
    let messages = drain(node).messages;
    let term = messages
        .iter()
        .find(|m| m.get_msg_type() == MessageType::MsgRequestPreVote)
        .unwrap()
        .term;
    for peer in [2, 3] {
        let mut message = Message {
            from: peer,
            to: 1,
            term,
            ..Default::default()
        };
        message.set_msg_type(MessageType::MsgRequestPreVoteResponse);
        node.step(message).unwrap();
        drain(node);
    }
    let term = node.status().unwrap().term;
    for peer in [2, 3] {
        let mut message = Message {
            from: peer,
            to: 1,
            term,
            ..Default::default()
        };
        message.set_msg_type(MessageType::MsgRequestVoteResponse);
        node.step(message).unwrap();
        drain(node);
    }
    acknowledge(node, 2);
    acknowledge(node, 3);
    assert_eq!(node.status().unwrap().role, StateRole::Leader);
    assert!(node.status().unwrap().is_voter);
}

#[test]
fn leaving_joint_can_remove_the_new_leader_and_releases_no_stale_heartbeats() {
    let backend = Backend::default();
    let conf = ConfState {
        voters: vec![2, 3, 4],
        voters_outgoing: vec![1, 2, 3],
        ..Default::default()
    };
    let store = Store::create_new(backend.clone(), identity(), conf, limits()).unwrap();
    let mut node = Driver::new(store, Counter::default(), config(), &logger()).unwrap();
    elect_outgoing_leader(&mut node);
    let expected = node.membership_status().unwrap().conf_state;
    let ticket = node
        .change_membership(&expected, MembershipChange::LeaveJoint)
        .unwrap();
    drain(&mut node);
    assert!(acknowledge(&mut node, 2).memberships.is_empty());
    let status = node.status().unwrap();
    let mut ack = Message {
        from: 3,
        to: 1,
        term: status.term,
        index: status.last_index,
        ..Default::default()
    };
    ack.set_msg_type(MessageType::MsgAppendResponse);
    node.step(ack).unwrap();
    // Control the narrow RawNode output boundary: all already-produced leader
    // message classes must be suppressed in the retirement Ready, while a
    // replica response remains eligible for release after durable application.
    for kind in [
        MessageType::MsgAppend,
        MessageType::MsgHeartbeat,
        MessageType::MsgSnapshot,
        MessageType::MsgAppendResponse,
    ] {
        node.node.raft.msgs.push(Message {
            msg_type: kind,
            from: 1,
            to: 2,
            term: status.term,
            ..Default::default()
        });
    }
    let output = drain(&mut node);
    assert_eq!(output.memberships[0].ticket, ticket);
    assert!(output.messages.iter().all(|message| !matches!(
        message.get_msg_type(),
        MessageType::MsgAppend | MessageType::MsgHeartbeat | MessageType::MsgSnapshot
    )));
    assert!(output
        .messages
        .iter()
        .any(|message| message.get_msg_type() == MessageType::MsgAppendResponse));
    assert_eq!(node.status().unwrap().role, StateRole::Follower);
    assert_eq!(node.status().unwrap().leader_id, 0);
    assert!(!node.status().unwrap().is_voter);
    for _ in 0..30 {
        node.tick().unwrap();
        assert!(drain(&mut node).messages.is_empty());
    }
    assert!(matches!(node.campaign(), Err(Error::NotLeader)));
    assert!(matches!(node.read_index(), Err(Error::NotLeader)));
    assert!(matches!(
        node.propose(vec![], vec![1]),
        Err(Error::NotLeader)
    ));
    assert!(matches!(
        node.change_membership(&expected, MembershipChange::LeaveJoint),
        Err(Error::NotLeader)
    ));
    drop(node);
    let mut reopened = Driver::new(
        Store::open_existing(backend, identity(), limits()).unwrap(),
        Counter::default(),
        config(),
        &logger(),
    )
    .unwrap();
    assert!(!reopened.status().unwrap().is_voter);
    assert!(matches!(reopened.campaign(), Err(Error::NotLeader)));
}

#[test]
fn leader_transfer_drops_membership_admission_without_stopping_or_losing_a_waiter() {
    let (mut node, _) = leader_three();
    node.node.transfer_leader(2);
    drain(&mut node);
    let expected = node.view().unwrap().conf_state.clone();
    assert!(matches!(
        node.change_membership(&expected, MembershipChange::AddLearner { node_id: 4 }),
        Err(Error::Raft(raft::Error::ProposalDropped))
    ));
    assert!(!node.is_stopped());
    assert!(node.pending_membership.is_none());
}

#[test]
fn leader_role_alone_never_authorizes_a_nonvoter() {
    let (mut node, _) = leader_three();
    // Reproduce the pinned upstream post_conf_change TODO directly: it removes
    // voting eligibility but keeps StateRole::Leader until our durable drain
    // performs the explicit step-down. Every public leader input also fences
    // that intermediate protocol state independently of the role field.
    let change = ConfChange {
        node_id: 1,
        change_type: ConfChangeType::RemoveNode,
        ..Default::default()
    };
    node.node.apply_conf_change(&change).unwrap();
    assert_eq!(node.node.raft.state, StateRole::Leader);
    assert!(!node.status().unwrap().is_voter);
    assert!(matches!(
        node.propose(vec![], vec![1]),
        Err(Error::NotLeader)
    ));
    assert!(matches!(node.read_index(), Err(Error::NotLeader)));
}

#[test]
fn term_change_can_complete_the_exact_configuration_but_snapshot_cannot_invent_its_receipt() {
    for snapshot in [false, true] {
        let (mut node, _) = leader_three();
        let before = node.view().unwrap().conf_state.clone();
        let ticket = node
            .change_membership(&before, MembershipChange::AddLearner { node_id: 4 })
            .unwrap();
        drain(&mut node);
        let tail = node.view().unwrap().entries.last().unwrap().clone();
        let mut message = Message {
            from: 2,
            to: 1,
            term: tail.term + 1,
            index: tail.index - 1,
            log_term: tail.term,
            commit: tail.index,
            ..Default::default()
        };
        if snapshot {
            let mut image = raft::eraftpb::Snapshot::default();
            image.mut_metadata().index = 20;
            image.mut_metadata().term = tail.term;
            image.mut_metadata().set_conf_state(ConfState {
                voters: vec![1, 2, 3],
                learners: vec![4],
                ..Default::default()
            });
            image.data = 0u64.to_be_bytes().to_vec().into();
            message.set_msg_type(MessageType::MsgSnapshot);
            message.set_snapshot(image);
        } else {
            message.set_msg_type(MessageType::MsgAppend);
            message.set_entries(vec![tail].into());
        }
        node.step(message).unwrap();
        let output = drain(&mut node);
        if snapshot {
            assert!(output.memberships.is_empty());
            elect_with_peer(&mut node);
            let conf = node.view().unwrap().conf_state.clone();
            assert!(matches!(
                node.change_membership(
                    &conf,
                    MembershipChange::ReplaceVoter {
                        remove_id: 3,
                        learner_id: 4
                    }
                ),
                Err(Error::MembershipPending)
            ));
            assert!(node.cancel_membership(ticket).unwrap());
        } else {
            assert_eq!(output.memberships[0].ticket, ticket);
            assert_eq!(output.memberships[0].conf_state.learners, vec![4]);
            assert_eq!(node.status().unwrap().role, StateRole::Follower);
        }
    }
}
