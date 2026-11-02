use super::*;
use raft::eraftpb::{ConfState, Entry, EntryType};
use scap_raft_driver::{Application, AppliedBatch, Driver, DriverConfig};
use scap_raft_runtime::{Delivery, Network, QueueLimits, Runtime, RuntimeConfig, SystemClock};
use scap_raft_store::{AtomicBackend, Limits as StoreLimits, LoadState, Store};
use scap_raft_wire::{Limits as WireLimits, Policy, Scope};
use std::sync::Mutex;
use std::time::Duration;

#[derive(Default)]
struct Backend(Mutex<Option<Vec<u8>>>);

impl AtomicBackend for Backend {
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

struct ApplicationResult;

impl Application for ApplicationResult {
    type Error = &'static str;
    fn apply(&mut self, previous: &[u8], entries: &[Entry]) -> Result<Vec<u8>, Self::Error> {
        let mut state = previous.to_vec();
        for entry in entries {
            if entry.get_entry_type() == EntryType::EntryNormal && !entry.data.is_empty() {
                state = entry.data.to_vec();
            }
        }
        Ok(state)
    }
    fn apply_with_results(
        &mut self,
        previous: &[u8],
        entries: &[Entry],
        requested: &[u64],
    ) -> Result<AppliedBatch, Self::Error> {
        let mut state = previous.to_vec();
        let mut results = Vec::new();
        for entry in entries {
            state = self.apply(&state, std::slice::from_ref(entry))?;
            if requested.contains(&entry.index) {
                results.push(state.clone());
            }
        }
        Ok(AppliedBatch { state, results })
    }
}

struct NoNetwork;

impl Network for NoNetwork {
    fn try_send(&mut self, _: Delivery) -> Result<(), scap_raft_runtime::Error> {
        panic!("single-voter unit runtime must not need a peer");
    }
}

fn build(elect: bool) -> (Runtime<Driver<Backend, ApplicationResult>>, Handle) {
    let identity = super::super::tests::identity();
    let store = Store::create_new(
        Backend::default(),
        identity.clone(),
        ConfState {
            voters: vec![1],
            ..ConfState::default()
        },
        StoreLimits {
            max_image_bytes: 1 << 20,
            max_entry_bytes: 4096,
            max_entries: 128,
            max_application_bytes: 4096,
        },
    )
    .unwrap();
    let mut driver = Driver::new(
        store,
        ApplicationResult,
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
            boot_id: 123,
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
            node_id: identity.node_id,
        },
        vec![1],
        vec![],
        WireLimits {
            max_payload_bytes: 4096,
            max_entries: 32,
            max_fields: 1024,
            max_certificate_bytes: 8192,
            max_bindings: 4,
        },
    )
    .unwrap();
    Runtime::new(
        driver,
        policy,
        RuntimeConfig {
            inbox: QueueLimits {
                max_messages: 4,
                max_bytes: 32768,
            },
            requests: QueueLimits {
                max_messages: 4,
                max_bytes: 8192,
            },
            max_pending_deliveries: 16,
            max_pending_delivery_bytes: 8192,
            max_pending_reads: 4,
            max_pending_proposals: 4,
            max_result_bytes: 512,
            max_view_bytes: 1024,
            max_poll_rounds: 16,
            tick_interval: Duration::from_millis(5),
            delivery_timeout: Duration::from_millis(50),
            max_inbound_age: Duration::from_secs(1),
        },
        Arc::new(SystemClock),
    )
    .unwrap()
}

#[test]
fn real_handle_delegates_reads_and_tracked_results_without_driving_raft_on_sql_thread() {
    let (mut runtime, handle) = build(true);
    let mut port = RuntimePort::new(handle.clone());
    let mut clone = port.clone();
    assert_eq!(clone.identity(), handle.identity());
    let thread = std::thread::spawn(move || runtime.run(&mut NoNetwork));
    let deadline = Instant::now() + Duration::from_secs(5);
    let cancelled = AtomicBool::new(false);
    let result = port
        .propose(b"exact command bytes".to_vec(), deadline, &cancelled)
        .unwrap();
    assert_eq!(result.ticket.boot_id, 123);
    assert_eq!(result.data, b"exact command bytes");
    let view = clone.read(deadline, &cancelled).unwrap();
    assert_eq!(view.identity, port.identity());
    assert_eq!(view.application, result.data);
    assert_eq!(view.index, result.index);
    assert_eq!(view.term, result.term);
    assert!(view.barrier.index <= view.index);
    handle.stop();
    thread.join().unwrap().unwrap();
}

#[test]
fn real_handle_propagates_pre_admission_and_wait_errors_with_original_budget() {
    let (_runtime, handle) = build(false);
    let mut port = RuntimePort::new(handle.clone());
    let past = Instant::now() - Duration::from_secs(1);
    let deadline = Instant::now() + Duration::from_secs(5);
    let not_cancelled = AtomicBool::new(false);
    assert_eq!(
        port.read(past, &not_cancelled).unwrap_err(),
        scap_raft_runtime::Error::Expired
    );
    assert_eq!(
        port.propose(vec![1], past, &not_cancelled).unwrap_err(),
        scap_raft_runtime::Error::Expired
    );
    // With no owner polling, cancellation must terminate both waits; the
    // synchronous adapter cannot secretly advance the runtime by itself.
    let cancelled = AtomicBool::new(true);
    assert_eq!(
        port.read(deadline, &cancelled).unwrap_err(),
        scap_raft_runtime::Error::Unknown
    );
    assert_eq!(
        port.propose(vec![1], deadline, &cancelled).unwrap_err(),
        scap_raft_runtime::Error::Unknown
    );
    handle.stop();
    assert_eq!(
        port.read(deadline, &not_cancelled).unwrap_err(),
        scap_raft_runtime::Error::Closed
    );
    assert_eq!(
        port.propose(vec![1], deadline, &not_cancelled).unwrap_err(),
        scap_raft_runtime::Error::Closed
    );
}

#[test]
fn runtime_admission_and_other_answers_are_never_mistaken_for_commit_or_read() {
    assert_eq!(
        read_answer(Answer::Admitted).unwrap_err(),
        scap_raft_runtime::Error::Unknown
    );
    assert_eq!(
        proposal_answer(Answer::Admitted).unwrap_err(),
        scap_raft_runtime::Error::Unknown
    );
    assert_eq!(
        proposal_answer(Answer::Checkpointed).unwrap_err(),
        scap_raft_runtime::Error::Unknown
    );
}
