use super::*;

fn stable_conf() -> ConfState {
    ConfState {
        voters: vec![1, 2, 3],
        ..Default::default()
    }
}

fn learner_conf() -> ConfState {
    let mut conf = stable_conf();
    conf.learners.push(4);
    conf
}

fn joint_conf() -> ConfState {
    ConfState {
        voters: vec![1, 2, 4],
        voters_outgoing: vec![1, 2, 3],
        ..Default::default()
    }
}

#[test]
fn configuration_cas_compares_sets_and_bounds_every_field() {
    let mut conf = joint_conf();
    conf.voters.reverse();
    conf.voters_outgoing.reverse();
    assert_eq!(canonical(&conf).unwrap(), joint_conf());
    let mut unknown = conf.clone();
    unknown.mut_unknown_fields().add_varint(99, 7);
    assert!(matches!(
        canonical(&unknown),
        Err(Error::MembershipInvalid(_))
    ));
    for field in 0..4 {
        for ids in [vec![0], vec![7, 7], vec![1; MAX_MEMBERS + 1]] {
            let mut conf = stable_conf();
            *match field {
                0 => &mut conf.voters,
                1 => &mut conf.learners,
                2 => &mut conf.voters_outgoing,
                _ => &mut conf.learners_next,
            } = ids;
            assert!(canonical(&conf).is_err());
        }
    }
    let current = stable_conf();
    let mut invalid = current.clone();
    invalid.voters[0] = 0;
    for (actual, expected) in [(&invalid, &current), (&current, &invalid)] {
        assert!(matches!(
            target(
                actual,
                expected,
                MembershipChange::AddLearner { node_id: 4 },
                1
            ),
            Err(Error::MembershipInvalid(_))
        ));
    }
    assert!(matches!(
        target(
            &current,
            &learner_conf(),
            MembershipChange::AddLearner { node_id: 4 },
            1
        ),
        Err(Error::MembershipConflict)
    ));
    let mut unsorted = current.clone();
    unsorted.voters.reverse();
    assert_eq!(
        target(
            &current,
            &unsorted,
            MembershipChange::AddLearner { node_id: 4 },
            1
        )
        .unwrap(),
        learner_conf()
    );
}

#[test]
fn explicit_replacement_preserves_three_voters_and_both_joint_majorities() {
    let original = stable_conf();
    let learner = target(
        &original,
        &original,
        MembershipChange::AddLearner { node_id: 4 },
        1,
    )
    .unwrap();
    assert_eq!(learner, learner_conf());
    let action = MembershipChange::ReplaceVoter {
        remove_id: 3,
        learner_id: 4,
    };
    let joint = target(&learner, &learner, action, 1).unwrap();
    assert_eq!(joint, joint_conf());
    let encoded = action.to_conf_change();
    assert_eq!(encoded.get_transition(), ConfChangeTransition::Explicit);
    assert_eq!(
        encoded.changes[0].get_change_type(),
        ConfChangeType::AddNode
    );
    assert_eq!(encoded.changes[0].node_id, 4);
    assert_eq!(
        encoded.changes[1].get_change_type(),
        ConfChangeType::RemoveNode
    );
    assert_eq!(encoded.changes[1].node_id, 3);
    let completed = target(&joint, &joint, MembershipChange::LeaveJoint, 3).unwrap();
    assert_eq!(completed.voters, vec![1, 2, 4]);
    assert!(completed.voters_outgoing.is_empty());
    assert!(MembershipChange::LeaveJoint
        .to_conf_change()
        .changes
        .is_empty());
    assert_eq!(
        MembershipChange::LeaveJoint
            .to_conf_change()
            .get_transition(),
        ConfChangeTransition::Auto
    );
    assert_eq!(
        MembershipChange::AddLearner { node_id: 9 }
            .to_conf_change()
            .changes[0]
            .get_change_type(),
        ConfChangeType::AddLearnerNode
    );
}

#[test]
fn profile_rejects_shortcuts_extra_learners_self_removal_and_joint_reentry() {
    let replace = MembershipChange::ReplaceVoter {
        remove_id: 3,
        learner_id: 4,
    };
    let add = MembershipChange::AddLearner { node_id: 4 };
    for change in [add, replace, MembershipChange::LeaveJoint] {
        for mutate in [
            |c: &mut ConfState| c.voters.pop().map(|_| ()).unwrap(),
            |c: &mut ConfState| c.learners = vec![4, 5],
            |c: &mut ConfState| c.learners_next = vec![3],
            |c: &mut ConfState| c.auto_leave = true,
        ] {
            let mut conf = learner_conf();
            mutate(&mut conf);
            assert!(matches!(
                target(&conf, &conf, change, 1),
                Err(Error::MembershipInvalid(_))
            ));
        }
    }
    for action in [
        MembershipChange::ReplaceVoter {
            remove_id: 1,
            learner_id: 4,
        },
        MembershipChange::ReplaceVoter {
            remove_id: 9,
            learner_id: 4,
        },
        MembershipChange::ReplaceVoter {
            remove_id: 3,
            learner_id: 5,
        },
        MembershipChange::AddLearner { node_id: 5 },
    ] {
        let current = learner_conf();
        assert!(matches!(
            target(&current, &current, action, 1),
            Err(Error::MembershipInvalid(_))
        ));
    }
    let current = stable_conf();
    assert!(matches!(
        target(&current, &current, replace, 1),
        Err(Error::MembershipInvalid(_))
    ));
    let legacy = ConfState {
        voters: vec![1, 3, 4],
        learners: vec![2],
        ..Default::default()
    };
    assert!(matches!(
        target(
            &legacy,
            &legacy,
            MembershipChange::ReplaceVoter {
                remove_id: 3,
                learner_id: 2
            },
            1
        ),
        Err(Error::MembershipInvalid(_))
    ));
    let current = joint_conf();
    for action in [add, replace] {
        assert!(matches!(
            target(&current, &current, action, 1),
            Err(Error::MembershipPending)
        ));
    }
}

#[test]
fn leave_accepts_only_the_explicit_replacement_joint_shape() {
    let changes: &[fn(&mut ConfState)] = &[
        |c| c.voters_outgoing.clear(),
        |c| c.learners = vec![5],
        |c| c.voters = vec![4, 5, 6],
        |c| c.voters = vec![1, 2, 3],
        |c| c.voters = vec![1, 2, 9],
    ];
    for change in changes {
        let mut conf = joint_conf();
        change(&mut conf);
        let result = target(&conf, &conf, MembershipChange::LeaveJoint, 1);
        if conf.voters == [1, 2, 9] {
            assert!(result.is_ok());
        } else {
            assert!(matches!(result, Err(Error::MembershipInvalid(_))));
        }
    }
    let conf = ConfState {
        voters: vec![1, 2, 3],
        voters_outgoing: vec![1, 2, 4],
        ..Default::default()
    };
    assert!(target(&conf, &conf, MembershipChange::LeaveJoint, 1).is_err());
}

#[test]
fn monotonic_identity_prevents_retired_id_reuse_and_never_overflows() {
    let mut conf = stable_conf();
    for new_id in [4, 9, u64::MAX] {
        for stale in [0, 1, 2, 3, conf.voters[2]] {
            assert!(matches!(
                target(
                    &conf,
                    &conf,
                    MembershipChange::AddLearner { node_id: stale },
                    1
                ),
                Err(Error::MembershipInvalid(_))
            ));
        }
        conf = target(
            &conf,
            &conf,
            MembershipChange::AddLearner { node_id: new_id },
            1,
        )
        .unwrap();
        let remove_id = conf.voters[2];
        conf = target(
            &conf,
            &conf,
            MembershipChange::ReplaceVoter {
                remove_id,
                learner_id: new_id,
            },
            1,
        )
        .unwrap();
        conf = target(&conf, &conf, MembershipChange::LeaveJoint, 1).unwrap();
    }
    assert!(target(
        &conf,
        &conf,
        MembershipChange::AddLearner { node_id: u64::MAX },
        1
    )
    .is_err());
}
