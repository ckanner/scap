use super::*;
use raft::eraftpb::{ConfState, Entry, EntryType, Message, MessageType};
use scap_raft_driver::{Application, AppliedBatch, Driver, DriverConfig};
use scap_raft_store::{AtomicBackend, Limits, LoadState, Store};
use scap_raft_wire::{certificate_identity, Binding, Limits as WireLimits};
use std::sync::atomic::{AtomicU8, AtomicUsize};

mod membership;

#[derive(Clone, Default)]
struct Backend {
    image: Arc<Mutex<Option<Vec<u8>>>>,
    fault: Arc<AtomicU8>,
}

impl AtomicBackend for Backend {
    type Error = &'static str;
    fn load(&mut self, _: usize) -> Result<LoadState, Self::Error> {
        Ok(self
            .image
            .lock()
            .clone()
            .map_or(LoadState::Empty, LoadState::Image))
    }
    fn replace_sync(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        match self.fault.swap(0, Ordering::SeqCst) {
            1 => Err("injected storage failure"),
            2 => panic!("injected storage panic"),
            _ => {
                *self.image.lock() = Some(bytes.to_vec());
                Ok(())
            }
        }
    }
}

#[derive(Clone, Default)]
struct Counter;

impl Application for Counter {
    type Error = &'static str;
    fn apply(&mut self, previous: &[u8], entries: &[Entry]) -> Result<Vec<u8>, Self::Error> {
        let mut value = if previous.is_empty() {
            0
        } else {
            u64::from_be_bytes(previous.try_into().unwrap())
        };
        for entry in entries {
            if entry.get_entry_type() == EntryType::EntryNormal && !entry.data.is_empty() {
                value += u64::from_be_bytes(entry.data[..].try_into().unwrap());
            }
        }
        Ok(value.to_be_bytes().to_vec())
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

struct TestClock {
    reading: Mutex<ClockReading>,
    fail: AtomicBool,
    calls: AtomicUsize,
}

impl TestClock {
    fn new() -> Self {
        Self {
            reading: Mutex::new(SystemClock.now().unwrap()),
            fail: AtomicBool::new(false),
            calls: AtomicUsize::new(0),
        }
    }
    fn advance(&self, by: Duration) {
        self.reading.lock().instant += by;
    }
}

impl Clock for TestClock {
    fn now(&self) -> Result<ClockReading, Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(Ordering::SeqCst) {
            return Err(Error::Clock);
        }
        Ok(*self.reading.lock())
    }
}

#[derive(Default)]
struct Capture {
    sent: Vec<Delivery>,
    reject: bool,
    stop: Option<Handle>,
}

impl Network for Capture {
    fn try_send(&mut self, delivery: Delivery) -> Result<(), Error> {
        if let Some(handle) = self.stop.take() {
            handle.stop();
            return Err(Error::Closed);
        }
        if self.reject {
            Err(Error::Full)
        } else {
            self.sent.push(delivery);
            Ok(())
        }
    }
}

type Node = Runtime<FaultDriver>;

fn config() -> RuntimeConfig {
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
        max_result_bytes: 8,
        max_view_bytes: 1024,
        max_poll_rounds: 32,
        tick_interval: Duration::from_millis(5),
        delivery_timeout: Duration::from_millis(50),
        max_inbound_age: Duration::from_secs(1),
    }
}

fn scope() -> Scope {
    Scope {
        cluster_id: 10,
        cell_id: 20,
        cell_incarnation: 30,
        node_id: 1,
    }
}

fn certificate() -> Vec<u8> {
    rcgen::generate_simple_self_signed(vec!["unit.scap.invalid".into()])
        .unwrap()
        .cert
        .der()
        .to_vec()
}

fn policy(voters: &[u64], der: &[u8]) -> Policy {
    let binding = Binding {
        node_id: *voters.last().unwrap(),
        fingerprint: certificate_identity(der, 8192).unwrap().fingerprint,
    };
    Policy::new(
        scope(),
        voters.to_vec(),
        vec![binding],
        WireLimits {
            max_payload_bytes: 4096,
            max_entries: 32,
            max_fields: 1024,
            max_certificate_bytes: 8192,
            max_bindings: 8,
        },
    )
    .unwrap()
}

fn driver(voters: &[u64], backend: Backend) -> FaultDriver {
    FaultDriver::new(raw_driver(voters, backend))
}

fn raw_driver(voters: &[u64], backend: Backend) -> Driver<Backend, Counter> {
    let s = scope();
    let store = Store::create_new(
        backend,
        Identity {
            cluster_id: s.cluster_id,
            cell_id: s.cell_id,
            cell_incarnation: s.cell_incarnation,
            node_id: s.node_id,
        },
        ConfState {
            voters: voters.to_vec(),
            ..Default::default()
        },
        Limits {
            max_image_bytes: 1 << 20,
            max_entry_bytes: 4096,
            max_entries: 128,
            max_application_bytes: 4096,
        },
    )
    .unwrap();
    Driver::new(
        store,
        Counter,
        DriverConfig {
            raft: raft::Config {
                election_tick: 2,
                heartbeat_tick: 1,
                min_election_tick: 2,
                max_election_tick: 3,
                max_size_per_msg: 1024,
                max_inflight_msgs: 8,
                max_uncommitted_size: 4096,
                max_committed_size_per_ready: 4096,
                ..Default::default()
            },
            boot_id: 40,
            max_input_bytes: 4096,
            max_output_messages: 32,
            max_output_bytes: 8192,
            max_pending_reads: 4,
            max_pending_proposals: 16,
            max_pending_proposal_bytes: 65536,
            max_ready_rounds: 16,
        },
        &slog::Logger::root(slog::Discard, slog::o!()),
    )
    .unwrap()
}

fn build(voters: &[u64]) -> (Node, Handle, Arc<TestClock>, Backend, Vec<u8>) {
    let clock = Arc::new(TestClock::new());
    let backend = Backend::default();
    let der = certificate();
    let (node, handle) = Runtime::new(
        driver(voters, backend.clone()),
        policy(voters, &der),
        config(),
        clock.clone(),
    )
    .unwrap();
    (node, handle, clock, backend, der)
}

fn deadline(clock: &TestClock) -> Instant {
    clock.now().unwrap().instant + Duration::from_secs(2)
}

fn elect(node: &mut Node, network: &mut Capture) {
    node.driver.campaign().unwrap();
    node.poll(network).unwrap();
}

fn call(
    node: &mut Node,
    handle: &Handle,
    clock: &TestClock,
    network: &mut Capture,
    input: Input,
) -> Result<Answer, Error> {
    let pending = handle.submit(input, deadline(clock))?;
    node.poll(network)?;
    pending.wait()
}

fn envelope(kind: MessageType, from: u64, term: u64) -> Envelope {
    let s = scope();
    let message = Message {
        msg_type: kind,
        from,
        to: s.node_id,
        term,
        ..Default::default()
    };
    Envelope {
        version: VERSION,
        codec: CODEC,
        cluster_id: s.cluster_id,
        cell_id: s.cell_id,
        cell_incarnation: s.cell_incarnation,
        from_node: from,
        to_node: s.node_id,
        payload: message.write_to_bytes().unwrap(),
    }
}

#[test]
fn single_owner_serializes_proposal_read_checkpoint_and_tick() {
    let (mut node, handle, clock, _, _) = build(&[1]);
    let mut network = Capture::default();
    assert!(matches!(
        call(&mut node, &handle, &clock, &mut network, Input::Status).unwrap(),
        Answer::Status(_)
    ));
    assert_eq!(
        call(&mut node, &handle, &clock, &mut network, Input::Read).unwrap_err(),
        Error::NotLeader
    );
    elect(&mut node, &mut network);
    assert!(matches!(
        call(
            &mut node,
            &handle,
            &clock,
            &mut network,
            Input::Propose {
                context: vec![],
                data: 7_u64.to_be_bytes().to_vec()
            }
        )
        .unwrap(),
        Answer::Admitted
    ));
    let Answer::Read(view) = call(&mut node, &handle, &clock, &mut network, Input::Read).unwrap()
    else {
        panic!("read view")
    };
    assert_eq!(view.application, 7_u64.to_be_bytes());
    assert_eq!(view.identity.node_id, 1);
    assert!(view.index >= view.barrier.index);
    assert_eq!(view.term, node.driver.view().unwrap().hard_state.term);
    assert!(matches!(
        call(&mut node, &handle, &clock, &mut network, Input::Checkpoint).unwrap(),
        Answer::Checkpointed
    ));
    let Answer::Read(view) = call(&mut node, &handle, &clock, &mut network, Input::Read).unwrap()
    else {
        panic!("read view")
    };
    assert_eq!(
        view.term,
        node.driver.view().unwrap().snapshot.get_metadata().term
    );
    clock.advance(config().tick_interval);
    assert!(node.poll(&mut network).unwrap() > 0);
    assert_eq!(node.poll(&mut network).unwrap(), 0);
}

#[test]
fn closed_expired_full_and_cancelled_requests_are_bounded() {
    let (mut node, handle, clock, _, _) = build(&[1]);
    assert!(matches!(
        handle.submit(Input::Status, clock.now().unwrap().instant),
        Err(Error::Expired)
    ));
    assert!(matches!(
        handle.submit(
            Input::Propose {
                context: vec![0; 8192],
                data: vec![0; 8192]
            },
            deadline(&clock)
        ),
        Err(Error::Full)
    ));
    let calls: Vec<_> = (0..4)
        .map(|_| handle.submit(Input::Status, deadline(&clock)).unwrap())
        .collect();
    assert!(matches!(
        handle.submit(Input::Status, deadline(&clock)),
        Err(Error::Full)
    ));
    drop(calls);
    node.poll(&mut Capture::default()).unwrap();
    let expired = handle.submit(Input::Status, deadline(&clock)).unwrap();
    clock.advance(Duration::from_secs(3));
    node.poll(&mut Capture::default()).unwrap();
    assert_eq!(expired.wait().unwrap_err(), Error::Unknown);
    let pending = handle.submit(Input::Status, deadline(&clock)).unwrap();
    handle.stop();
    assert_eq!(pending.wait().unwrap_err(), Error::Closed);
    assert!(handle.is_stopped());
    assert!(matches!(
        handle.submit(Input::Status, deadline(&clock)),
        Err(Error::Closed)
    ));
    assert_eq!(handle.replace_bindings(vec![]), Err(Error::Closed));
    assert_eq!(node.poll(&mut Capture::default()), Err(Error::Closed));
    assert!(!handle.complete(1, DeliveryResult::Failed));
}

#[test]
fn authenticated_inbox_rechecks_revoke_and_expiry_at_handoff() {
    let (mut node, handle, clock, _, der) = build(&[1, 2]);
    let heartbeat = envelope(MessageType::MsgHeartbeat, 2, 2);
    handle.admit(&der, heartbeat.clone()).unwrap();
    handle.replace_bindings(vec![]).unwrap();
    node.poll(&mut Capture::default()).unwrap();
    assert_eq!(node.driver.status().unwrap().term, 1);
    assert_eq!(
        handle.admit(&der, heartbeat.clone()),
        Err(AdmissionError::PermissionDenied)
    );
    let binding = Binding {
        node_id: 2,
        fingerprint: certificate_identity(&der, 8192).unwrap().fingerprint,
    };
    handle.replace_bindings(vec![binding]).unwrap();
    handle.admit(&der, heartbeat.clone()).unwrap();
    clock.advance(config().max_inbound_age);
    node.poll(&mut Capture::default()).unwrap();
    assert_eq!(node.driver.status().unwrap().term, 1);
    handle.admit(&der, heartbeat.clone()).unwrap();
    node.poll(&mut Capture::default()).unwrap();
    assert_eq!(node.driver.status().unwrap().term, 2);
    assert_eq!(
        handle.admit(b"invalid", heartbeat.clone()),
        Err(AdmissionError::Invalid)
    );
    for _ in 0..4 {
        handle.admit(&der, heartbeat.clone()).unwrap();
    }
    assert_eq!(
        handle.admit(&der, heartbeat.clone()),
        Err(AdmissionError::Limit)
    );
    clock.fail.store(true, Ordering::SeqCst);
    assert_eq!(
        handle.admit(&der, heartbeat.clone()),
        Err(AdmissionError::Unavailable)
    );
    clock.fail.store(false, Ordering::SeqCst);
    handle.stop();
    assert_eq!(
        handle.admit(&der, heartbeat),
        Err(AdmissionError::Unavailable)
    );
}

#[test]
fn runtime_closes_ingress_on_storage_error_or_panic() {
    for fault in [1, 2] {
        let (mut node, handle, clock, backend, _) = build(&[1]);
        let mut network = Capture::default();
        elect(&mut node, &mut network);
        let pending = handle
            .submit(
                Input::Propose {
                    context: vec![],
                    data: 1_u64.to_be_bytes().to_vec(),
                },
                deadline(&clock),
            )
            .unwrap();
        backend.fault.store(fault, Ordering::SeqCst);
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| node.poll(&mut network)));
        if fault == 1 {
            assert!(matches!(result.unwrap(), Err(Error::Driver(_))));
        } else {
            assert!(result.is_err());
        }
        assert!(handle.is_stopped());
        // Admission may have completed before persistence failed. It must
        // never be interpreted as a durable accepted business result.
        let _ = pending.wait();
        assert_eq!(node.poll(&mut network), Err(Error::Closed));
    }
}

#[test]
fn configuration_identity_membership_and_time_fail_closed() {
    let changes: &[fn(&mut RuntimeConfig)] = &[
        |c| c.inbox.max_messages = 0,
        |c| c.inbox.max_messages = 65_537,
        |c| c.requests.max_bytes = 1,
        |c| c.requests.max_bytes = usize::MAX,
        |c| c.max_pending_deliveries = 0,
        |c| c.max_pending_delivery_bytes = 1,
        |c| c.max_pending_reads = 0,
        |c| c.max_pending_proposals = 0,
        |c| c.max_result_bytes = 0,
        |c| c.max_view_bytes = 0,
        |c| c.max_poll_rounds = 0,
        |c| c.tick_interval = Duration::ZERO,
        |c| c.delivery_timeout = Duration::ZERO,
        |c| c.max_inbound_age = Duration::ZERO,
        |c| c.tick_interval = Duration::from_secs(61),
        |c| c.delivery_timeout = Duration::from_secs(61),
        |c| c.max_inbound_age = Duration::from_secs(61),
        |c| c.max_view_bytes = c.requests.max_bytes,
        |c| c.max_result_bytes = c.requests.max_bytes,
    ];
    let der = certificate();
    for change in changes {
        let mut cfg = config();
        change(&mut cfg);
        assert!(Runtime::new(
            driver(&[1], Backend::default()),
            policy(&[1], &der),
            cfg,
            Arc::new(TestClock::new())
        )
        .is_err());
    }
    let mut other = scope();
    other.cell_id += 1;
    let p = Policy::new(other, vec![1], vec![], policy(&[1], &der).limits()).unwrap();
    assert!(matches!(
        Runtime::new(
            driver(&[1], Backend::default()),
            p,
            config(),
            Arc::new(TestClock::new())
        ),
        Err(Error::Invalid(_))
    ));
    let p = policy(&[1], &der);
    let conf = ConfState {
        voters: vec![1],
        ..Default::default()
    };
    let changes: &[fn(&mut ConfState)] = &[
        |c| c.voters = vec![2],
        |c| c.learners = vec![2],
        |c| c.voters_outgoing = vec![1],
        |c| c.learners_next = vec![2],
        |c| c.auto_leave = true,
    ];
    for change in changes {
        let mut c = conf.clone();
        change(&mut c);
        assert!(validate_members(&c, &p).is_err());
    }
    assert!(Runtime::new(
        driver(&[1, 2], Backend::default()),
        p,
        config(),
        Arc::new(TestClock::new())
    )
    .is_err());
    let clock = Arc::new(TestClock::new());
    clock.fail.store(true, Ordering::SeqCst);
    assert!(matches!(
        Runtime::new(
            driver(&[1], Backend::default()),
            policy(&[1], &der),
            config(),
            clock
        ),
        Err(Error::Clock)
    ));
    assert_eq!(unix_seconds(Duration::MAX), Err(Error::Clock));
    assert_eq!(
        clock_reading(
            Instant::now(),
            (UNIX_EPOCH - Duration::from_secs(1)).duration_since(UNIX_EPOCH)
        )
        .unwrap_err(),
        Error::Clock
    );
    assert_eq!(
        clock_reading(Instant::now(), Ok(Duration::MAX)).unwrap_err(),
        Error::Clock
    );
    assert!(SystemClock.now().unwrap().unix_seconds > 0);
}

#[test]
fn quotas_follow_queued_work_and_completed_responses() {
    let (mut node, handle, clock, _, _) = build(&[1]);
    let mut network = Capture::default();
    let pending: Vec<_> = (0..4)
        .map(|_| handle.submit(Input::Status, deadline(&clock)).unwrap())
        .collect();
    node.poll(&mut network).unwrap();
    assert_eq!(handle.mailbox.requests.lock().count, 4);
    assert!(matches!(
        handle.submit(Input::Status, deadline(&clock)),
        Err(Error::Full)
    ));
    drop(pending);
    assert_eq!(handle.mailbox.requests.lock().count, 0);
    let pending = handle
        .submit(
            Input::Propose {
                context: vec![0; 3000],
                data: vec![],
            },
            deadline(&clock),
        )
        .unwrap();
    assert!(matches!(
        handle.submit(
            Input::Propose {
                context: vec![0; 3000],
                data: vec![]
            },
            deadline(&clock)
        ),
        Err(Error::Full)
    ));
    drop(pending);
    assert_eq!(
        handle.mailbox.requests.lock().count,
        1,
        "queue still owns bytes after cancellation"
    );
    node.poll(&mut network).unwrap();
    assert_eq!(handle.mailbox.requests.lock().bytes, 0);
    let pending = handle.submit(Input::Status, deadline(&clock)).unwrap();
    assert_eq!(
        pending.wait_at(pending.deadline).unwrap_err(),
        Error::Unknown
    );
    drop(pending);
    node.poll(&mut network).unwrap();
    let short = handle
        .submit(Input::Status, Instant::now() + Duration::from_millis(1))
        .unwrap();
    assert_eq!(short.wait().unwrap_err(), Error::Unknown);
    let pending = handle.submit(Input::Status, deadline(&clock)).unwrap();
    handle.mailbox.state.lock().requests.clear();
    assert_eq!(pending.wait().unwrap_err(), Error::Unknown);
}

#[test]
fn error_conversion_and_allocation_accounting_preserve_classification() {
    use scap_raft_driver::Error as D;
    for (input, expected) in [
        (D::NotLeader, Error::NotLeader),
        (D::ReadNotReady, Error::ReadNotReady),
        (D::ReadLimit, Error::InputLimit),
        (D::InputLimit, Error::InputLimit),
        (D::ProposalLimit, Error::Full),
    ] {
        assert_eq!(driver_error(input), expected);
    }
    assert!(matches!(driver_error(D::Stopped), Error::Driver(_)));
    assert!(matches!(
        codec_error(std::io::Error::other("codec").into()),
        Error::Driver(_)
    ));
    assert!(Error::Clock.to_string().contains("Clock"));
    use scap_raft_wire::Error as W;
    for (input, expected) in [
        (W::Unauthorized, AdmissionError::PermissionDenied),
        (W::PolicyChanged, AdmissionError::PermissionDenied),
        (W::CertificateTime, AdmissionError::Unauthenticated),
        (W::Limit("test"), AdmissionError::Limit),
        (W::Malformed("test"), AdmissionError::Invalid),
    ] {
        assert_eq!(admission_error(input), expected);
    }
    let der = certificate();
    let mut limit = policy(&[1], &der).limits();
    assert!(inbound_cost(100, limit).unwrap() > 200);
    limit.max_fields = usize::MAX;
    limit.max_entries = usize::MAX;
    assert_eq!(inbound_cost(usize::MAX, limit), None);
    limit.max_fields = 1;
    assert_eq!(inbound_cost(usize::MAX, limit), None);
    limit.max_entries = 1;
    assert_eq!(inbound_cost(usize::MAX, limit), None);
    assert_eq!(inbound_cost(usize::MAX / 2 - 1, limit), None);
    assert_eq!(inbound_cost(usize::MAX / 2 - 100, limit), None);
    limit.max_entries = 0;
    assert_eq!(inbound_cost(usize::MAX / 2 - 200, limit), None);
    assert!(!fits(
        QueueLimits {
            max_messages: 1,
            max_bytes: 10
        },
        0,
        20,
        1
    ));
}

fn elect_pair(node: &mut Node, network: &mut Capture) {
    elect(node, network);
    for (kind, index) in [
        (MessageType::MsgRequestPreVoteResponse, 0),
        (MessageType::MsgRequestVoteResponse, 0),
        (MessageType::MsgAppendResponse, 2),
    ] {
        node.driver
            .step(Message {
                msg_type: kind,
                from: 2,
                to: 1,
                term: 2,
                index,
                ..Default::default()
            })
            .unwrap();
        node.poll(network).unwrap();
    }
    assert_eq!(node.driver.status().unwrap().role, raft::StateRole::Leader);
}

#[test]
fn pending_reads_are_cancelled_expired_limited_and_closed() {
    let (mut node, handle, clock, _, _) = build(&[1, 2]);
    let mut network = Capture::default();
    elect_pair(&mut node, &mut network);
    node.config.max_pending_reads = 1;
    let first = handle.submit(Input::Read, deadline(&clock)).unwrap();
    node.poll(&mut network).unwrap();
    assert_eq!(node.reads.len(), 1);
    assert_eq!(
        call(&mut node, &handle, &clock, &mut network, Input::Read).unwrap_err(),
        Error::Full
    );
    drop(first);
    node.poll(&mut network).unwrap();
    assert!(node.reads.is_empty());
    let second = handle.submit(Input::Read, deadline(&clock)).unwrap();
    node.poll(&mut network).unwrap();
    clock.advance(Duration::from_secs(3));
    node.poll(&mut network).unwrap();
    assert_eq!(second.wait().unwrap_err(), Error::Unknown);
    let third = handle.submit(Input::Read, deadline(&clock)).unwrap();
    node.poll(&mut network).unwrap();
    assert!(!node.reads.is_empty());
    handle.stop();
    assert_eq!(node.poll(&mut network), Err(Error::Closed));
    assert_eq!(third.wait().unwrap_err(), Error::Closed);
}

#[test]
fn request_and_read_errors_do_not_claim_commitment() {
    let (mut node, handle, clock, backend, _) = build(&[1]);
    let mut network = Capture::default();
    elect(&mut node, &mut network);
    // The read view has its own limit, independent of successful persistence.
    node.config.max_view_bytes = 1;
    assert_eq!(
        call(&mut node, &handle, &clock, &mut network, Input::Read).unwrap_err(),
        Error::InputLimit
    );
    node.config.max_view_bytes = 1024;
    backend.fault.store(1, Ordering::SeqCst);
    let pending = handle.submit(Input::Checkpoint, deadline(&clock)).unwrap();
    assert!(matches!(node.poll(&mut network), Err(Error::Driver(_))));
    assert!(matches!(pending.wait(), Err(Error::Driver(_))));
    let (mut node, handle, clock, _, _) = build(&[1]);
    clock.fail.store(true, Ordering::SeqCst);
    assert!(matches!(
        handle.submit(Input::Status, Instant::now() + Duration::from_secs(1)),
        Err(Error::Clock)
    ));
    assert_eq!(node.poll(&mut network), Err(Error::Clock));
    assert!(handle.is_stopped());
}

#[test]
fn delivery_feedback_is_bounded_correlated_and_deadline_checked() {
    let (mut node, handle, clock, _, _) = build(&[1, 2]);
    let mut network = Capture::default();
    elect_pair(&mut node, &mut network);
    for delivery in network.sent.drain(..) {
        handle.complete(delivery.id, DeliveryResult::Received);
    }
    node.poll(&mut network).unwrap();
    let now = clock.now().unwrap().instant;
    let message = Message {
        msg_type: MessageType::MsgAppend,
        from: 1,
        to: 2,
        term: 2,
        ..Default::default()
    };
    node.emit(message.clone(), now, &mut network).unwrap();
    let id = network.sent.pop().unwrap().id;
    assert!(handle.complete(id, DeliveryResult::Failed));
    assert!(!handle.complete(id, DeliveryResult::Received));
    assert!(node.feedback(now).unwrap());
    assert!(!handle.complete(id, DeliveryResult::Received));
    assert!(!handle.complete(u64::MAX, DeliveryResult::Received));
    node.emit(message.clone(), now, &mut network).unwrap();
    assert!(node.feedback(now + config().delivery_timeout).unwrap());
    let mut snapshot = message.clone();
    snapshot.msg_type = MessageType::MsgSnapshot;
    node.emit(snapshot.clone(), now, &mut network).unwrap();
    let old = network.sent.last().unwrap().id;
    node.emit(snapshot.clone(), now, &mut network).unwrap();
    let current = network.sent.last().unwrap().id;
    handle.complete(old, DeliveryResult::Received);
    assert!(node.feedback(now).unwrap());
    assert_eq!(node.latest_snapshot.get(&2).unwrap().0, current);
    handle.complete(current, DeliveryResult::Received);
    assert!(node.feedback(now).unwrap());
    node.emit(snapshot.clone(), now, &mut network).unwrap();
    let late = network.sent.last().unwrap().id;
    handle.complete(late, DeliveryResult::Received);
    assert!(node.feedback(now + config().delivery_timeout).unwrap());
    assert!(node.latest_snapshot.is_empty());
    node.emit(snapshot.clone(), now, &mut network).unwrap();
    let old_term = network.sent.last().unwrap().id;
    node.driver
        .step(Message {
            msg_type: MessageType::MsgHeartbeat,
            from: 2,
            to: 1,
            term: 3,
            ..Default::default()
        })
        .unwrap();
    node.driver.drain().unwrap();
    handle.complete(old_term, DeliveryResult::Received);
    assert!(node.feedback(now).unwrap());
    assert!(node.latest_snapshot.is_empty());
    node.next_delivery = u64::MAX;
    assert!(matches!(
        node.emit(message, now, &mut network),
        Err(Error::Invalid(_))
    ));
}

#[test]
fn saturated_or_rejected_delivery_reports_snapshot_failure_without_growing() {
    let (mut node, handle, clock, _, _) = build(&[1]);
    let mut network = Capture::default();
    elect(&mut node, &mut network);
    let now = clock.now().unwrap().instant;
    let message = Message {
        msg_type: MessageType::MsgAppend,
        from: 1,
        to: 2,
        term: 2,
        ..Default::default()
    };
    let mut snapshot = message.clone();
    snapshot.msg_type = MessageType::MsgSnapshot;
    node.config.max_pending_deliveries = 1;
    node.emit(message.clone(), now, &mut network).unwrap();
    node.emit(message.clone(), now, &mut network).unwrap();
    node.emit(snapshot.clone(), now, &mut network).unwrap();
    assert_eq!(node.deliveries.len(), 1);
    assert!(node.feedback(now).unwrap());
    let id = network.sent[0].id;
    handle.complete(id, DeliveryResult::Received);
    node.feedback(now).unwrap();
    node.config.max_pending_delivery_bytes = 1;
    node.emit(snapshot.clone(), now, &mut network).unwrap();
    assert!(node.feedback(now).unwrap());
    node.latest_snapshot.insert(2, (0, 0));
    assert!(node.feedback(now).unwrap());
    node.config.max_pending_delivery_bytes = 8192;
    network.reject = true;
    node.emit(message.clone(), now, &mut network).unwrap();
    assert!(node.feedback(now).unwrap());
    handle
        .mailbox
        .state
        .lock()
        .feedback
        .insert(123, DeliveryResult::Failed);
    assert!(node.feedback(now).unwrap());
    assert!(!node.feedback(now).unwrap());
    handle.stop();
    node.emit(message, now, &mut network).unwrap();
    assert!(node.deliveries.is_empty());
}

// Fail exactly one scheduler-to-driver operation. Every non-failing call still
// executes the formal durable driver, rather than a second Raft implementation.
struct FaultDriver {
    inner: Driver<Backend, Counter>,
    fault: Mutex<Option<(&'static str, usize, bool)>>,
    stopped: AtomicBool,
    more_ready_once: bool,
    extra_proposals: Vec<ProposalResult>,
    extra_memberships: Vec<MembershipResult>,
}

impl FaultDriver {
    fn new(inner: Driver<Backend, Counter>) -> Self {
        Self {
            inner,
            fault: Mutex::new(None),
            stopped: AtomicBool::new(false),
            more_ready_once: false,
            extra_proposals: Vec::new(),
            extra_memberships: Vec::new(),
        }
    }
    fn fail(&self, operation: &'static str, skip: usize, fatal: bool) {
        *self.fault.lock() = Some((operation, skip, fatal));
    }
    fn campaign(&mut self) -> Result<(), scap_raft_driver::Error> {
        self.inner.campaign()
    }
    fn guard(&self, operation: &str) -> Result<(), scap_raft_driver::Error> {
        let mut fault = self.fault.lock();
        if let Some((name, skip, fatal)) = fault.as_mut() {
            if *name == operation {
                if *skip == 0 {
                    self.stopped.store(*fatal, Ordering::SeqCst);
                    *fault = None;
                    return Err(scap_raft_driver::Error::Invalid(
                        "injected operation failure",
                    ));
                }
                *skip -= 1;
            }
        }
        Ok(())
    }
}

impl RaftDriver for FaultDriver {
    fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst) || RaftDriver::is_stopped(&self.inner)
    }
    fn view(&self) -> Result<&scap_raft_store::State, scap_raft_driver::Error> {
        self.guard("view")?;
        RaftDriver::view(&self.inner)
    }
    fn status(&self) -> Result<Status, scap_raft_driver::Error> {
        self.guard("status")?;
        RaftDriver::status(&self.inner)
    }
    fn membership_status(&self) -> Result<MembershipStatus, scap_raft_driver::Error> {
        self.guard("membership_status")?;
        RaftDriver::membership_status(&self.inner)
    }
    fn change_membership(
        &mut self,
        expected: &ConfState,
        change: MembershipChange,
    ) -> Result<MembershipTicket, scap_raft_driver::Error> {
        self.guard("change_membership")?;
        RaftDriver::change_membership(&mut self.inner, expected, change)
    }
    fn cancel_membership(
        &mut self,
        ticket: MembershipTicket,
    ) -> Result<bool, scap_raft_driver::Error> {
        self.guard("cancel_membership")?;
        RaftDriver::cancel_membership(&mut self.inner, ticket)
    }
    fn drain(&mut self) -> Result<scap_raft_driver::Output, scap_raft_driver::Error> {
        self.guard("drain")?;
        let mut output = RaftDriver::drain(&mut self.inner)?;
        output.more_ready |= std::mem::take(&mut self.more_ready_once);
        output
            .proposals
            .extend(std::mem::take(&mut self.extra_proposals));
        output
            .memberships
            .extend(std::mem::take(&mut self.extra_memberships));
        Ok(output)
    }
    fn tick(&mut self) -> Result<(), scap_raft_driver::Error> {
        self.guard("tick")?;
        RaftDriver::tick(&mut self.inner)
    }
    fn step(&mut self, message: Message) -> Result<(), scap_raft_driver::Error> {
        self.guard("step")?;
        RaftDriver::step(&mut self.inner, message)
    }
    fn propose(&mut self, context: Vec<u8>, data: Vec<u8>) -> Result<(), scap_raft_driver::Error> {
        self.guard("propose")?;
        RaftDriver::propose(&mut self.inner, context, data)
    }
    fn propose_tracked(
        &mut self,
        data: Vec<u8>,
        max_result_bytes: usize,
    ) -> Result<ProposalTicket, scap_raft_driver::Error> {
        self.guard("propose_tracked")?;
        RaftDriver::propose_tracked(&mut self.inner, data, max_result_bytes)
    }
    fn cancel_proposal(&mut self, ticket: ProposalTicket) -> Result<bool, scap_raft_driver::Error> {
        self.guard("cancel_proposal")?;
        RaftDriver::cancel_proposal(&mut self.inner, ticket)
    }
    fn read_index(&mut self) -> Result<ReadTicket, scap_raft_driver::Error> {
        self.guard("read_index")?;
        RaftDriver::read_index(&mut self.inner)
    }
    fn cancel_read(&mut self, ticket: ReadTicket) -> Result<bool, scap_raft_driver::Error> {
        self.guard("cancel_read")?;
        RaftDriver::cancel_read(&mut self.inner, ticket)
    }
    fn checkpoint(&mut self) -> Result<(), scap_raft_driver::Error> {
        self.guard("checkpoint")?;
        RaftDriver::checkpoint(&mut self.inner)
    }
    fn report_unreachable(&mut self, peer: u64) -> Result<(), scap_raft_driver::Error> {
        self.guard("report_unreachable")?;
        RaftDriver::report_unreachable(&mut self.inner, peer)
    }
    fn report_snapshot(
        &mut self,
        peer: u64,
        status: SnapshotStatus,
    ) -> Result<(), scap_raft_driver::Error> {
        self.guard("report_snapshot")?;
        RaftDriver::report_snapshot(&mut self.inner, peer, status)
    }
}

fn fault_node() -> (Runtime<FaultDriver>, Handle, Arc<TestClock>, Vec<u8>) {
    let clock = Arc::new(TestClock::new());
    let der = certificate();
    let (node, handle) = Runtime::new(
        driver(&[1, 2], Backend::default()),
        policy(&[1, 2], &der),
        config(),
        clock.clone(),
    )
    .unwrap();
    (node, handle, clock, der)
}

fn maximum_instant() -> Instant {
    let origin = Instant::now();
    let (mut low, mut high) = (0_u128, Duration::MAX.as_nanos());
    while low < high {
        let mid = low + (high - low).div_ceil(2);
        let duration = Duration::new((mid / 1_000_000_000) as u64, (mid % 1_000_000_000) as u32);
        if origin.checked_add(duration).is_some() {
            low = mid;
        } else {
            high = mid - 1;
        }
    }
    origin + Duration::new((low / 1_000_000_000) as u64, (low % 1_000_000_000) as u32)
}

#[test]
fn clock_range_and_codec_failure_leave_no_partial_admission() {
    let max = maximum_instant();
    assert!(max.checked_add(Duration::from_nanos(1)).is_none());
    let der = certificate();
    let clock = Arc::new(TestClock::new());
    clock.reading.lock().instant = max;
    assert!(matches!(
        Runtime::new(
            driver(&[1], Backend::default()),
            policy(&[1], &der),
            config(),
            clock
        ),
        Err(Error::Invalid("tick interval overflow"))
    ));
    let (mut node, handle, clock, _, der) = build(&[1, 2]);
    clock.reading.lock().instant = max;
    assert_eq!(
        handle.admit(&der, envelope(MessageType::MsgHeartbeat, 2, 2)),
        Err(AdmissionError::Limit)
    );
    assert!(handle.mailbox.state.lock().inbound.is_empty());
    assert_eq!(node.poll(&mut Capture::default()), Err(Error::Clock));
    assert!(handle.is_stopped());

    let (mut node, _, clock, _, _) = build(&[1]);
    let message = Message {
        from: 1,
        to: 2,
        ..Default::default()
    };
    assert_eq!(
        node.emit(message.clone(), max, &mut Capture::default()),
        Err(Error::Clock)
    );
    assert!(matches!(
        node.emit_encoded(
            message,
            Err(Error::Driver("codec".into())),
            clock.now().unwrap().instant,
            &mut Capture::default()
        ),
        Err(Error::Driver(_))
    ));
    assert!(node.deliveries.is_empty());
}

#[test]
fn each_scheduler_driver_failure_closes_admission_without_claiming_commit() {
    let driver = driver(&[1], Backend::default());
    driver.fail("view", 0, true);
    assert!(matches!(
        Runtime::new(
            driver,
            policy(&[1], &certificate()),
            config(),
            Arc::new(TestClock::new())
        ),
        Err(Error::Driver(_))
    ));

    for operation in ["drain", "tick", "status"] {
        let (mut node, handle, clock, _) = fault_node();
        if operation == "tick" {
            clock.advance(config().tick_interval);
        }
        if operation == "status" {
            node.driver.inner.campaign().unwrap();
        }
        node.driver.fail(operation, 0, true);
        assert!(
            matches!(node.poll(&mut Capture::default()), Err(Error::Driver(_))),
            "{operation}"
        );
        assert!(handle.is_stopped());
        assert!(node.driver.fault.lock().is_none());
    }
    // Both alternating scheduling orders propagate a fatal step/request error.
    for request_first in [false, true] {
        let (mut node, handle, clock, der) = fault_node();
        node.prefer_request = request_first;
        handle
            .admit(&der, envelope(MessageType::MsgHeartbeat, 2, 2))
            .unwrap();
        node.driver.fail("step", 0, true);
        assert!(matches!(
            node.poll(&mut Capture::default()),
            Err(Error::Driver(_))
        ));
        assert!(handle.is_stopped());
        let (mut node, handle, _, _) = fault_node();
        node.prefer_request = request_first;
        let pending = handle.submit(Input::Status, deadline(&clock)).unwrap();
        node.driver.fail("status", 0, true);
        assert!(matches!(
            node.poll(&mut Capture::default()),
            Err(Error::Driver(_))
        ));
        assert!(matches!(pending.wait(), Err(Error::Driver(_))));
        assert!(handle.is_stopped());
    }
    let (mut node, handle, _, der) = fault_node();
    handle
        .admit(&der, envelope(MessageType::MsgHeartbeat, 2, 2))
        .unwrap();
    node.driver.fail("step", 0, false);
    node.poll(&mut Capture::default()).unwrap();
    assert!(
        !handle.is_stopped(),
        "ordinary input rejection is not fatal"
    );
}

#[test]
fn read_handoff_rechecks_cancellation_deadline_and_driver_failure() {
    let (mut node, handle, clock, _) = fault_node();
    // Elect the real single-voter driver before wrapping it in the same port.
    let mut inner = raw_driver(&[1], Backend::default());
    inner.campaign().unwrap();
    inner.drain().unwrap();
    node.driver.inner = inner;
    for reason in ["cancelled", "expired", "view"] {
        let pending = handle.submit(Input::Read, deadline(&clock)).unwrap();
        node.request(clock.now().unwrap().instant).unwrap();
        let (_, read) = node.reads.pop_first().unwrap();
        let barrier = node.driver.drain().unwrap().reads.remove(0);
        let now = clock.now().unwrap().instant;
        match reason {
            "cancelled" => pending.cancelled.store(true, Ordering::Release),
            "expired" => {}
            "view" => node.driver.fail("view", 0, true),
            _ => unreachable!(),
        }
        let result = node.read_answer(
            &read,
            barrier,
            if reason == "expired" {
                read.request.deadline
            } else {
                now
            },
        );
        if reason == "view" {
            assert!(matches!(result, Err(Error::Driver(_))));
        } else {
            assert!(matches!(result, Err(Error::Unknown)));
        }
    }
    let (mut node, handle, clock, _) = fault_node();
    let pending = handle.submit(Input::Read, deadline(&clock)).unwrap();
    let request = handle.mailbox.state.lock().requests.pop_front().unwrap();
    node.reads.insert(
        1,
        ReadRequest {
            ticket: ReadTicket {
                boot_id: 40,
                sequence: 1,
            },
            request,
        },
    );
    node.driver.fail("cancel_read", 0, true);
    drop(pending);
    assert!(matches!(
        node.poll(&mut Capture::default()),
        Err(Error::Driver(_))
    ));
    assert!(handle.is_stopped());
}

#[test]
fn feedback_revokes_callback_before_driver_work_and_errors_close_ingress() {
    for operation in [
        "status",
        "report_unreachable",
        "report_snapshot",
        "dropped_status",
        "dropped_report",
    ] {
        let (mut node, handle, clock, _) = fault_node();
        let mut inner = raw_driver(&[1], Backend::default());
        inner.campaign().unwrap();
        inner.drain().unwrap();
        node.driver.inner = inner;
        let now = clock.now().unwrap().instant;
        let snapshot = operation.contains("snapshot") || operation.starts_with("dropped");
        let message = Message {
            msg_type: if snapshot {
                MessageType::MsgSnapshot
            } else {
                MessageType::MsgAppend
            },
            from: 1,
            to: 2,
            term: 2,
            ..Default::default()
        };
        if operation.starts_with("dropped") {
            node.config.max_pending_deliveries = 0;
        }
        let mut network = Capture::default();
        node.emit(message, now, &mut network).unwrap();
        if let Some(delivery) = network.sent.first() {
            assert!(handle.complete(delivery.id, DeliveryResult::Failed));
        }
        node.driver.fail(
            match operation {
                "dropped_status" => "status",
                "dropped_report" => "report_snapshot",
                other => other,
            },
            0,
            true,
        );
        assert!(
            matches!(node.poll(&mut network), Err(Error::Driver(_))),
            "{operation}"
        );
        assert!(handle.is_stopped());
        assert!(handle.mailbox.state.lock().live_deliveries.is_empty());
        for delivery in network.sent {
            assert!(!handle.complete(delivery.id, DeliveryResult::Received));
        }
    }
    // Same-term role change also makes old feedback inapplicable.
    let (mut node, handle, clock, _, _) = build(&[1, 2]);
    let now = clock.now().unwrap().instant;
    let message = Message {
        from: 1,
        to: 2,
        term: 1,
        ..Default::default()
    };
    let mut network = Capture::default();
    node.emit(message, now, &mut network).unwrap();
    handle.complete(network.sent[0].id, DeliveryResult::Failed);
    node.feedback(now).unwrap();
    assert!(node.deliveries.is_empty());
}

#[test]
fn scheduler_drains_continuations_and_ignores_unowned_read_completions() {
    let (mut node, _, _, _) = fault_node();
    node.driver.more_ready_once = true;
    assert_eq!(node.poll(&mut Capture::default()).unwrap(), 1);
    assert!(!node.driver.more_ready_once);
    let (mut node, _, _, _, _) = build(&[1]);
    let mut network = Capture::default();
    elect(&mut node, &mut network);
    node.driver.read_index().unwrap();
    node.poll(&mut network).unwrap();
    assert!(node.reads.is_empty());
}

#[test]
fn blocking_owner_wakes_stops_and_reports_failure() {
    let (mut node, handle, clock, _, _) = build(&[1]);
    let pending = handle.submit(Input::Status, deadline(&clock)).unwrap();
    let calls = clock.calls.load(Ordering::SeqCst);
    let thread = std::thread::spawn(move || node.run(&mut Capture::default()));
    assert!(matches!(pending.wait(), Ok(Answer::Status(_))));
    let bound = Instant::now() + Duration::from_secs(2);
    while clock.calls.load(Ordering::SeqCst) < calls + 4 {
        assert!(Instant::now() < bound, "owner did not reach idle poll");
        std::thread::yield_now();
    }
    handle.stop();
    assert_eq!(thread.join().unwrap(), Ok(()));

    let (mut node, handle, clock, _, _) = build(&[1, 2]);
    node.driver.campaign().unwrap();
    clock.advance(config().tick_interval);
    assert_eq!(
        node.run(&mut Capture {
            stop: Some(handle.clone()),
            ..Default::default()
        }),
        Ok(())
    );
    assert!(handle.is_stopped());
    let (mut node, handle, clock, _, _) = build(&[1]);
    clock.fail.store(true, Ordering::SeqCst);
    assert_eq!(node.run(&mut Capture::default()), Err(Error::Clock));
    assert!(handle.is_stopped());
    assert_eq!(node.run(&mut Capture::default()), Ok(()));
}

#[test]
fn idle_wait_never_loses_already_queued_work_or_stop() {
    let (_, handle, clock, _, der) = build(&[1, 2]);
    // Keep the actual owner alive: dropping it would close the mailbox.
    let (_node, handle2, _, _, _) = build(&[1, 2]);
    handle.mailbox.wait_for_work(); // closed
    handle2.mailbox.wait_for_work(); // idle, bounded timeout
    let (_node, handle, _, _, _) = build(&[1, 2]);
    handle
        .mailbox
        .state
        .lock()
        .feedback
        .insert(123, DeliveryResult::Failed);
    handle.mailbox.wait_for_work();
    handle.mailbox.state.lock().feedback.clear();
    let pending = handle.submit(Input::Status, deadline(&clock)).unwrap();
    handle.mailbox.wait_for_work();
    drop(pending);
    handle.mailbox.state.lock().requests.clear();
    // Use this mailbox's configured certificate binding.
    let binding = Binding {
        node_id: 2,
        fingerprint: certificate_identity(&der, 8192).unwrap().fingerprint,
    };
    handle.replace_bindings(vec![binding]).unwrap();
    handle
        .admit(&der, envelope(MessageType::MsgHeartbeat, 2, 2))
        .unwrap();
    handle.mailbox.wait_for_work();
}

#[test]
fn taking_a_receipt_or_timeout_revokes_completion_before_owner_cleanup() {
    for completed in [false, true] {
        let (mut node, handle, clock, _, _) = build(&[1]);
        let now = clock.now().unwrap().instant;
        let mut network = Capture::default();
        node.emit(
            Message {
                from: 1,
                to: 2,
                ..Default::default()
            },
            now,
            &mut network,
        )
        .unwrap();
        let id = network.sent[0].id;
        if completed {
            assert!(handle.complete(id, DeliveryResult::Received));
        }
        let at = if completed {
            now
        } else {
            now + config().delivery_timeout
        };
        assert_eq!(
            node.take_feedback(at),
            Some((
                id,
                if completed {
                    DeliveryResult::Received
                } else {
                    DeliveryResult::Failed
                }
            ))
        );
        assert!(
            node.deliveries.contains_key(&id),
            "owner cleanup deliberately has not run"
        );
        assert!(
            !handle.complete(id, DeliveryResult::Received),
            "callback admission already revoked"
        );
        assert!(handle.mailbox.state.lock().feedback.is_empty());
    }
}

#[test]
fn fatal_read_view_closes_ingress_in_the_same_poll() {
    let (mut node, handle, clock, _, _) = build(&[1]);
    let mut network = Capture::default();
    elect(&mut node, &mut network);
    let pending = handle.submit(Input::Read, deadline(&clock)).unwrap();
    node.driver.fail("view", 0, true);
    assert!(matches!(node.poll(&mut network), Err(Error::Driver(_))));
    assert!(matches!(pending.wait(), Err(Error::Driver(_))));
    assert!(handle.is_stopped());
    assert!(node.reads.is_empty());
    assert!(matches!(
        handle.submit(Input::Status, deadline(&clock)),
        Err(Error::Closed)
    ));
}

fn tracked(amount: u64) -> Input {
    Input::ProposeTracked {
        data: amount.to_be_bytes().to_vec(),
    }
}

#[test]
fn tracked_results_are_bound_to_each_request_and_runtime_scope() {
    let (mut node, handle, clock, _, der) = build(&[1]);
    let mut network = Capture::default();
    elect(&mut node, &mut network);
    assert_eq!(handle.identity(), node.driver.view().unwrap().identity);
    let identity = handle.identity();
    handle
        .replace_bindings(vec![Binding {
            node_id: 1,
            fingerprint: certificate_identity(&der, 8192).unwrap().fingerprint,
        }])
        .unwrap();
    assert_eq!(handle.identity(), identity);
    let calls: Vec<_> = [5, 7, 11]
        .into_iter()
        .map(|amount| handle.submit(tracked(amount), deadline(&clock)).unwrap())
        .collect();
    node.poll(&mut network).unwrap();
    assert!(node.proposals.is_empty());
    assert_eq!(handle.mailbox.requests.lock().count, 3);
    assert_eq!(handle.mailbox.requests.lock().bytes, 3 * (16 + 8 + 256));
    let mut last = 0;
    for (pending, expected) in calls.into_iter().zip([5u64, 12, 23]) {
        let Answer::Applied(result) = pending.wait().unwrap() else {
            panic!("missing applied result")
        };
        assert_eq!(result.data, expected.to_be_bytes());
        assert!(result.index > last);
        assert_eq!(result.term, node.driver.status().unwrap().term);
        assert!(result.index <= node.driver.view().unwrap().applied);
        last = result.index;
    }
    assert_eq!(handle.mailbox.requests.lock().bytes, 0);
    // A driver-owned attempt without a runtime waiter is never delivered to a
    // subsequent request, even though its command still changes durable state.
    node.driver
        .propose_tracked(1u64.to_be_bytes().to_vec(), 8)
        .unwrap();
    node.poll(&mut network).unwrap();
    assert!(node.proposals.is_empty());
}

#[test]
fn tracked_waiters_are_count_limited_cancelled_expired_and_closed_as_unknown() {
    let (mut node, handle, clock, _, _) = build(&[1, 2]);
    let mut network = Capture::default();
    elect_pair(&mut node, &mut network);
    node.config.max_pending_proposals = 1;
    let first = handle.submit(tracked(5), deadline(&clock)).unwrap();
    node.poll(&mut network).unwrap();
    assert_eq!(node.proposals.len(), 1);
    assert_eq!(
        call(&mut node, &handle, &clock, &mut network, tracked(7)).unwrap_err(),
        Error::Full
    );
    drop(first);
    node.poll(&mut network).unwrap();
    assert!(node.proposals.is_empty());
    let second = handle.submit(tracked(7), deadline(&clock)).unwrap();
    node.poll(&mut network).unwrap();
    clock.advance(Duration::from_secs(3));
    node.poll(&mut network).unwrap();
    assert_eq!(second.wait().unwrap_err(), Error::Unknown);
    let third = handle.submit(tracked(11), deadline(&clock)).unwrap();
    node.poll(&mut network).unwrap();
    assert_eq!(node.proposals.len(), 1);
    handle.stop();
    assert_eq!(node.poll(&mut network), Err(Error::Closed));
    assert_eq!(third.wait().unwrap_err(), Error::Unknown);
}

#[test]
fn tracked_errors_preserve_admission_and_post_admission_distinctions() {
    let (mut node, handle, clock, _, _) = build(&[1]);
    let mut network = Capture::default();
    assert_eq!(
        call(&mut node, &handle, &clock, &mut network, tracked(7)).unwrap_err(),
        Error::NotLeader
    );
    elect(&mut node, &mut network);
    node.driver.fail("propose_tracked", 0, false);
    assert!(matches!(
        call(&mut node, &handle, &clock, &mut network, tracked(7)),
        Err(Error::Driver(_))
    ));
    assert!(!handle.is_stopped());
    node.driver.fail("propose_tracked", 0, true);
    let pending = handle.submit(tracked(7), deadline(&clock)).unwrap();
    assert!(matches!(node.poll(&mut network), Err(Error::Driver(_))));
    assert!(matches!(pending.wait(), Err(Error::Driver(_))));
    assert!(handle.is_stopped());

    let (mut node, handle, clock, backend, _) = build(&[1]);
    elect(&mut node, &mut network);
    node.config.max_poll_rounds = 1;
    let pending = handle.submit(tracked(7), deadline(&clock)).unwrap();
    node.poll(&mut network).unwrap();
    assert_eq!(node.proposals.len(), 1);
    backend.fault.store(1, Ordering::SeqCst);
    assert!(matches!(node.poll(&mut network), Err(Error::Driver(_))));
    assert_eq!(pending.wait().unwrap_err(), Error::Unknown);

    let (mut node, handle, clock, _, _) = build(&[1, 2]);
    elect_pair(&mut node, &mut network);
    let pending = handle.submit(tracked(7), deadline(&clock)).unwrap();
    node.poll(&mut network).unwrap();
    drop(pending);
    node.driver.fail("cancel_proposal", 0, true);
    assert!(matches!(node.poll(&mut network), Err(Error::Driver(_))));
    assert!(handle.is_stopped());
}

#[test]
fn tracked_handoff_rechecks_cancellation_deadline_and_result_budget() {
    for mode in 0..4 {
        let (mut node, handle, clock, _, _) = build(&[1]);
        let mut network = Capture::default();
        elect(&mut node, &mut network);
        node.config.max_poll_rounds = 1;
        let pending = handle.submit(tracked(7), deadline(&clock)).unwrap();
        node.poll(&mut network).unwrap();
        assert_eq!(node.proposals.len(), 1);
        match mode {
            0 => pending.cancelled.store(true, Ordering::Release),
            1 => clock.advance(Duration::from_secs(3)),
            2 => node.config.max_result_bytes = 1,
            _ => {}
        }
        node.poll(&mut network).unwrap();
        if mode == 3 {
            assert!(matches!(pending.wait(), Ok(Answer::Applied(_))));
        } else {
            assert_eq!(pending.wait().unwrap_err(), Error::Unknown);
        }
        assert!(node.proposals.is_empty());
    }
}

#[test]
fn old_boot_proposal_output_cannot_consume_a_current_waiter() {
    let (mut node, handle, clock, _, _) = build(&[1, 2]);
    let mut network = Capture::default();
    elect_pair(&mut node, &mut network);
    let pending = handle.submit(tracked(7), deadline(&clock)).unwrap();
    node.poll(&mut network).unwrap();
    let ticket = node.proposals.values().next().unwrap().ticket;
    node.driver.extra_proposals.push(ProposalResult {
        ticket: ProposalTicket {
            boot_id: ticket.boot_id + 1,
            ..ticket
        },
        index: 3,
        term: 2,
        data: 99u64.to_be_bytes().to_vec(),
    });
    node.poll(&mut network).unwrap();
    assert_eq!(node.proposals.len(), 1);
    let status = node.driver.status().unwrap();
    node.driver
        .step(Message {
            msg_type: MessageType::MsgAppendResponse,
            from: 2,
            to: 1,
            term: status.term,
            index: status.last_index,
            ..Default::default()
        })
        .unwrap();
    node.poll(&mut network).unwrap();
    let Answer::Applied(result) = pending.wait().unwrap() else {
        panic!("missing result")
    };
    assert_eq!(result.ticket, ticket);
    assert_eq!(result.data, 7u64.to_be_bytes());
}

#[test]
fn cancellable_wait_uses_one_deadline_and_rechecks_the_returned_answer() {
    let (mut node, handle, clock, _, _) = build(&[1]);
    let mut network = Capture::default();
    let active = AtomicBool::new(false);
    let cancelled = AtomicBool::new(true);
    let pending = handle.submit(Input::Status, deadline(&clock)).unwrap();
    node.poll(&mut network).unwrap();
    assert!(matches!(
        pending.wait_cancelled(&active),
        Ok(Answer::Status(_))
    ));

    let pending = handle.submit(Input::Status, deadline(&clock)).unwrap();
    let cancellation = Arc::clone(&pending.cancelled);
    assert_eq!(
        pending.wait_cancelled(&cancelled).unwrap_err(),
        Error::Unknown
    );
    assert!(cancellation.load(Ordering::Acquire));
    node.poll(&mut network).unwrap();

    let pending = handle
        .submit(Input::Status, Instant::now() + Duration::from_millis(1))
        .unwrap();
    assert_eq!(pending.wait_cancelled(&active).unwrap_err(), Error::Unknown);
    node.poll(&mut network).unwrap();

    let pending = handle.submit(Input::Status, deadline(&clock)).unwrap();
    handle.mailbox.state.lock().requests.clear();
    assert_eq!(pending.wait_cancelled(&active).unwrap_err(), Error::Unknown);

    let pending = handle.submit(Input::Status, deadline(&clock)).unwrap();
    assert_eq!(
        pending
            .finish_wait(Ok(Answer::Checkpointed), &cancelled, Instant::now())
            .unwrap_err(),
        Error::Unknown
    );
    assert_eq!(
        pending
            .finish_wait(Ok(Answer::Checkpointed), &active, pending.deadline)
            .unwrap_err(),
        Error::Unknown
    );
    drop(pending);
    node.poll(&mut network).unwrap();

    let pending = handle.submit(Input::Status, deadline(&clock)).unwrap();
    let flag = Arc::new(AtomicBool::new(false));
    let flag_writer = Arc::clone(&flag);
    let writer = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(20));
        flag_writer.store(true, Ordering::Release);
    });
    assert_eq!(pending.wait_cancelled(&flag).unwrap_err(), Error::Unknown);
    writer.join().unwrap();
    node.poll(&mut network).unwrap();
    assert_eq!(handle.mailbox.requests.lock().count, 0);
}
