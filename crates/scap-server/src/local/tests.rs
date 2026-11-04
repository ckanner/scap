use super::*;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use raft::eraftpb::ConfState;
use scap_cell::{Admission, CellApplication, CellState, Command, CommandKind, Grant, Position};
use scap_raft_driver::{Driver, DriverConfig};
use scap_raft_runtime::{Delivery, Network, QueueLimits, Runtime, RuntimeConfig, SystemClock};
use scap_raft_store::{AtomicBackend, Identity, Limits, LoadState, Store};
use scap_raft_wire::{Policy, Scope};

use crate::config::cell_limits;
use crate::tests::config;

#[derive(Default)]
pub(crate) struct Memory(Mutex<Option<Vec<u8>>>);
impl AtomicBackend for Memory {
    type Error = &'static str;
    fn load(&mut self, _: usize) -> Result<LoadState, Self::Error> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .clone()
            .map_or(LoadState::Empty, LoadState::Image))
    }
    fn replace_sync(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        *self.0.lock().unwrap() = Some(bytes.to_vec());
        Ok(())
    }
}

struct NoNetwork;
impl Network for NoNetwork {
    fn try_send(&mut self, _: Delivery) -> Result<(), Error> {
        panic!("single voter must not need a peer")
    }
}

pub(crate) fn runtime(elect: bool) -> (Runtime<Driver<Memory, CellApplication>>, LocalPort) {
    let config = config();
    let identity = Identity {
        cluster_id: config.cluster_id,
        cell_id: config.cell.cell_id,
        cell_incarnation: config.cell.cell_incarnation,
        node_id: config.node_id,
    };
    let genesis = CellState::bootstrap(
        config.cell,
        config.administrator_id,
        Position { term: 1, index: 1 },
        cell_limits(),
    )
    .unwrap()
    .encode();
    let store = Store::create_new_with_application(
        Memory::default(),
        identity.clone(),
        ConfState {
            voters: vec![1],
            ..ConfState::default()
        },
        Limits {
            max_image_bytes: 1 << 20,
            max_entry_bytes: 4096,
            max_entries: 256,
            max_application_bytes: 128 * 1024,
        },
        genesis,
    )
    .unwrap();
    let mut driver = Driver::new(
        store,
        CellApplication::new(config.cell, cell_limits()).unwrap(),
        DriverConfig {
            raft: raft::Config {
                election_tick: 10,
                heartbeat_tick: 1,
                max_size_per_msg: 1024,
                max_inflight_msgs: 8,
                max_uncommitted_size: 4096,
                max_committed_size_per_ready: 4096,
                ..raft::Config::default()
            },
            boot_id: 321,
            max_input_bytes: 4096,
            max_output_messages: 16,
            max_output_bytes: 8192,
            max_pending_reads: 4,
            max_pending_proposals: 4,
            max_pending_proposal_bytes: 65536,
            max_ready_rounds: 16,
        },
        &slog::Logger::root(slog::Discard, slog::o!()),
    )
    .unwrap();
    if elect {
        driver.campaign().unwrap();
        driver.drain().unwrap();
    }
    let policy = Policy::new(
        Scope {
            cluster_id: identity.cluster_id,
            cell_id: identity.cell_id,
            cell_incarnation: identity.cell_incarnation,
            node_id: 1,
        },
        vec![1],
        vec![],
        scap_raft_wire::Limits {
            max_payload_bytes: 4096,
            max_entries: 32,
            max_fields: 1024,
            max_certificate_bytes: 8192,
            max_bindings: 4,
        },
    )
    .unwrap();
    let (runtime, handle) = Runtime::new(
        driver,
        policy,
        RuntimeConfig {
            inbox: QueueLimits {
                max_messages: 4,
                max_bytes: 32768,
            },
            requests: QueueLimits {
                max_messages: 4,
                max_bytes: 512 * 1024,
            },
            max_pending_deliveries: 16,
            max_pending_delivery_bytes: 8192,
            max_pending_reads: 4,
            max_pending_proposals: 4,
            max_result_bytes: 1024,
            max_view_bytes: 128 * 1024,
            max_poll_rounds: 16,
            tick_interval: Duration::from_millis(10),
            delivery_timeout: Duration::from_millis(50),
            max_inbound_age: Duration::from_secs(1),
        },
        Arc::new(SystemClock),
    )
    .unwrap();
    (runtime, LocalPort { handle })
}

fn status_at(applied: u64, snapshot_index: u64) -> Status {
    Status {
        role: raft::StateRole::Leader,
        leader_id: 1,
        term: 2,
        commit: applied,
        applied,
        last_index: applied,
        snapshot_index,
        is_voter: true,
    }
}

#[test]
fn removed_or_learner_nodes_never_report_sql_leadership() {
    let mut state = status_at(5, 1);
    assert_eq!(leadership(state.clone()), (true, 2));
    state.is_voter = false;
    assert_eq!(leadership(state.clone()), (false, 2));
    state.role = raft::StateRole::Follower;
    state.is_voter = true;
    assert_eq!(leadership(state), (false, 2));
}

fn control_replies(
    force: bool,
    replies: Vec<Result<Answer, Error>>,
) -> (Result<(), ServiceError>, Vec<bool>) {
    let mut replies: std::collections::VecDeque<_> = replies.into();
    let mut requested = Vec::new();
    let result = maintain(force, |input| {
        requested.push(matches!(input, Input::Checkpoint));
        replies.pop_front().expect("exact control request sequence")
    });
    assert!(replies.is_empty());
    (result, requested)
}

#[test]
fn checkpoint_policy_handles_forced_periodic_empty_and_invalid_runtime_replies() {
    for (applied, snapshot, force, checkpoint) in [
        (1, 1, true, false),
        (2, 1, false, false),
        (2, 1, true, true),
        (129, 1, false, true),
        (1, 2, false, false),
    ] {
        let mut replies = vec![Ok(Answer::Status(status_at(applied, snapshot)))];
        if checkpoint {
            replies.push(Ok(Answer::Checkpointed));
        }
        let (result, requested) = control_replies(force, replies);
        result.unwrap();
        assert_eq!(
            requested,
            if checkpoint {
                vec![false, true]
            } else {
                vec![false]
            }
        );
    }
    for answer in [Ok(Answer::Admitted), Err(Error::Closed)] {
        assert_eq!(
            control_replies(false, vec![answer]).0.unwrap_err().code,
            "UNAVAILABLE"
        );
    }
    for answer in [Ok(Answer::Admitted), Err(Error::Unknown)] {
        assert_eq!(
            control_replies(true, vec![Ok(Answer::Status(status_at(2, 1))), answer])
                .0
                .unwrap_err()
                .code,
            "CHECKPOINT_UNAVAILABLE"
        );
    }
}

#[test]
fn native_runtime_delegates_tracked_commit_safe_read_status_and_checkpoint() {
    let (mut runtime, mut port) = runtime(true);
    let owner = std::thread::spawn(move || runtime.run(&mut NoNetwork));
    let deadline = Instant::now() + Duration::from_secs(5);
    let cancelled = AtomicBool::new(false);
    let config = config();
    assert_eq!(port.identity(), port.handle.identity());
    assert_eq!(port.leadership(deadline).unwrap(), (true, 2));
    port.maintain(deadline, false).unwrap();
    let command = Command {
        cell: config.cell,
        database: config.databases[0].identity,
        admission: Admission {
            principal_id: config.administrator_id,
            credential_id: config.service_credential_id,
            admission_id: 1000,
            auth_epoch: 1,
        },
        kind: CommandKind::Create {
            operation_id: 1000,
            policy: vec![Grant {
                principal_id: config.administrator_id,
                permissions: 7,
            }],
        },
    };
    let result = port
        .propose(
            scap_cell::encode_command(&command, cell_limits()).unwrap(),
            deadline,
            &cancelled,
        )
        .unwrap();
    let view = port.read(deadline, &cancelled).unwrap();
    assert_eq!((view.term, view.index), (result.term, result.index));
    assert!(view.barrier.index <= view.index);
    let state = CellState::decode_bound(
        &view.application,
        config.cell,
        Position {
            term: view.term,
            index: view.index,
        },
        cell_limits(),
    )
    .unwrap();
    assert!(state.database(3).is_some());
    port.maintain(deadline, true).unwrap();
    let checkpointed = status(port.request(Input::Status, deadline)).unwrap();
    assert_eq!(checkpointed.applied, checkpointed.snapshot_index);
    port.handle.stop();
    owner.join().unwrap().unwrap();
    assert_eq!(port.leadership(deadline).unwrap_err().code, "UNAVAILABLE");
    assert_eq!(
        port.maintain(deadline, true).unwrap_err().code,
        "UNAVAILABLE"
    );
    assert_eq!(port.read(deadline, &cancelled).unwrap_err(), Error::Closed);
    assert_eq!(
        port.propose(vec![1], deadline, &cancelled).unwrap_err(),
        Error::Closed
    );
}

#[test]
fn missing_owner_and_original_budget_never_run_the_runtime_on_sql_thread() {
    let (_runtime, mut port) = runtime(false);
    let deadline = Instant::now() + Duration::from_millis(10);
    assert_eq!(port.leadership(deadline).unwrap_err().code, "UNAVAILABLE");
    let cancelled = AtomicBool::new(true);
    let later = Instant::now() + Duration::from_secs(1);
    assert_eq!(port.read(later, &cancelled).unwrap_err(), Error::Unknown);
    assert_eq!(
        port.propose(vec![1], later, &cancelled).unwrap_err(),
        Error::Unknown
    );
    assert_eq!(
        port.maintain(Instant::now() - Duration::from_secs(1), false)
            .unwrap_err()
            .code,
        "UNAVAILABLE"
    );
    port.handle.stop();
}
