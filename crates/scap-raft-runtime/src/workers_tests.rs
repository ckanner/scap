use super::*;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use parking_lot::Condvar;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
};
use scap_raft_transport::{AdmissionError, Ingress, PeerServer, ServerSecurity};
use scap_raft_wire::{Envelope, Limits, Policy, Scope, CODEC, VERSION};
use tokio::sync::oneshot;

use crate::{Mailbox, QueueLimits, RequestBudget, RuntimeConfig, Shared, SystemClock};

fn config() -> RuntimeConfig {
    RuntimeConfig {
        inbox: QueueLimits {
            max_messages: 8,
            max_bytes: 32_768,
        },
        requests: QueueLimits {
            max_messages: 8,
            max_bytes: 8192,
        },
        max_pending_deliveries: 16,
        max_pending_delivery_bytes: 8192,
        max_pending_reads: 8,
        max_pending_proposals: 8,
        max_result_bytes: 4096,
        max_view_bytes: 4096,
        max_poll_rounds: 32,
        tick_interval: Duration::from_millis(10),
        delivery_timeout: Duration::from_secs(1),
        max_inbound_age: Duration::from_secs(1),
    }
}

// The worker boundary owns a real Handle, not a simulated Raft cluster. These
// tests inspect the exact feedback mailbox that the serial owner consumes.
fn handle(voters: &[u64], config: RuntimeConfig) -> Handle {
    let policy = Policy::new(
        Scope {
            cluster_id: 17,
            cell_id: 29,
            cell_incarnation: 3,
            node_id: 1,
        },
        voters.to_vec(),
        Vec::new(),
        Limits {
            max_payload_bytes: 4096,
            max_entries: 32,
            max_fields: 1024,
            max_certificate_bytes: 8192,
            max_bindings: 8,
        },
    )
    .unwrap();
    Handle {
        mailbox: Arc::new(Mailbox {
            identity: scap_raft_store::Identity {
                cluster_id: 17,
                cell_id: 29,
                cell_incarnation: 3,
                node_id: 1,
            },
            state: Mutex::new(Shared {
                policy,
                inbound: VecDeque::new(),
                inbound_bytes: 0,
                requests: VecDeque::new(),
                feedback: BTreeMap::new(),
                live_deliveries: BTreeMap::new(),
                closed: false,
            }),
            wake: Condvar::new(),
            config,
            clock: Arc::new(SystemClock),
            requests: Arc::new(Mutex::new(RequestBudget {
                limits: config.requests,
                count: 0,
                bytes: 0,
            })),
        }),
    }
}

fn transport_limits() -> TransportLimits {
    TransportLimits {
        max_wire_bytes: 4096,
        max_connections: 8,
        max_inflight_requests: 8,
        max_streams_per_connection: 4,
        max_header_bytes: 4096,
        handshake_timeout: Duration::from_secs(2),
        request_timeout: Duration::from_secs(2),
        connect_timeout: Duration::from_secs(2),
        max_connection_age: Duration::from_secs(10),
        connection_grace: Duration::from_secs(1),
    }
}

fn endpoint(node_id: u64) -> PeerEndpoint {
    PeerEndpoint {
        uri: "https://127.0.0.1:9".into(),
        cluster_id: 17,
        node_id,
    }
}

fn bounded_security() -> ClientSecurity {
    ClientSecurity {
        certificate_pem: b"bounded: native validation occurs on connect".to_vec(),
        private_key_pem: b"bounded: native validation occurs on connect".to_vec(),
        server_ca_pem: b"bounded: native validation occurs on connect".to_vec(),
    }
}

fn delivery(id: u64, peer: u64, snapshot: bool) -> Delivery {
    Delivery {
        id,
        peer,
        snapshot,
        envelope: Envelope {
            version: VERSION,
            codec: CODEC,
            cluster_id: 17,
            cell_id: 29,
            cell_incarnation: 3,
            from_node: 1,
            to_node: peer,
            payload: vec![8, 8, 16, peer as u8, 24, 1],
        },
        deadline: Instant::now() + Duration::from_secs(5),
    }
}

fn budget(messages: usize, bytes: usize) -> Arc<Budget> {
    Arc::new(Budget {
        held: Mutex::new(Held::default()),
        max_messages: messages,
        max_bytes: bytes,
    })
}

fn retained(budget: &Budget) -> (usize, usize) {
    let held = budget.held.lock();
    (held.messages, held.bytes)
}

fn queued(budget: &Arc<Budget>, delivery: Delivery) -> Queued {
    let bytes = HEADER_BYTES + delivery.envelope.payload.len();
    Queued {
        delivery,
        _reservation: budget.reserve(bytes).unwrap(),
    }
}

fn register(handle: &Handle, ids: &[u64]) {
    handle
        .mailbox
        .state
        .lock()
        .live_deliveries
        .extend(ids.iter().map(|id| (*id, ())));
}

fn feedback(handle: &Handle) -> BTreeMap<u64, DeliveryResult> {
    handle.mailbox.state.lock().feedback.clone()
}

fn start_error(
    handle: Handle,
    endpoints: Vec<PeerEndpoint>,
    security: ClientSecurity,
    limits: TransportLimits,
    capacity: usize,
) -> Error {
    match NetworkWorkers::start(handle, endpoints, security, limits, capacity) {
        Err(error) => error,
        Ok(_) => panic!("invalid workers configuration unexpectedly started"),
    }
}

#[test]
fn startup_rejects_invalid_limits_identities_and_missing_executor_before_spawning() {
    let make = || handle(&[1, 2, 3], config());
    let peers = || vec![endpoint(2), endpoint(3)];
    assert!(matches!(
        start_error(
            make(),
            vec![
                PeerEndpoint {
                    uri: "http://127.0.0.1:9".into(),
                    ..endpoint(2)
                },
                endpoint(3)
            ],
            bounded_security(),
            transport_limits(),
            1,
        ),
        Error::Network(_)
    ));
    let mut limits = transport_limits();
    limits.max_wire_bytes = 0;
    assert!(matches!(
        start_error(make(), peers(), bounded_security(), limits, 1),
        Error::Network(_)
    ));
    let mut limits = transport_limits();
    limits.max_connections = 3;
    assert_eq!(
        start_error(make(), peers(), bounded_security(), limits, 1),
        Error::Invalid("connection budget does not cover peer lanes")
    );
    let mut security = bounded_security();
    security.certificate_pem.clear();
    assert!(matches!(
        start_error(make(), peers(), security, transport_limits(), 1),
        Error::Network(_)
    ));
    for capacity in [0, config().max_pending_deliveries + 1] {
        assert_eq!(
            start_error(
                make(),
                peers(),
                bounded_security(),
                transport_limits(),
                capacity
            ),
            Error::Invalid("sender queue limit")
        );
    }
    let huge = RuntimeConfig {
        max_pending_deliveries: usize::MAX,
        ..config()
    };
    assert_eq!(
        start_error(
            handle(&[1, 2, 3], huge),
            peers(),
            bounded_security(),
            transport_limits(),
            tokio::sync::Semaphore::MAX_PERMITS + 1
        ),
        Error::Invalid("sender queue limit")
    );
    let closed = make();
    closed.stop();
    assert_eq!(
        start_error(closed, peers(), bounded_security(), transport_limits(), 1),
        Error::Closed
    );
    assert_eq!(
        start_error(
            make(),
            vec![endpoint(2)],
            bounded_security(),
            transport_limits(),
            1
        ),
        Error::Invalid("peer endpoint set")
    );
    for invalid in [
        vec![
            PeerEndpoint {
                cluster_id: 18,
                ..endpoint(2)
            },
            endpoint(3),
        ],
        vec![endpoint(2), endpoint(2)],
        vec![endpoint(1), endpoint(3)],
        vec![endpoint(2), endpoint(4)],
    ] {
        assert_eq!(
            start_error(make(), invalid, bounded_security(), transport_limits(), 1),
            Error::Invalid("peer endpoint identity")
        );
    }
    let error = start_error(make(), peers(), bounded_security(), transport_limits(), 1);
    assert!(matches!(error, Error::Network(_)));
    assert_eq!(
        network_error("executor unavailable"),
        Error::Network("executor unavailable".into())
    );
}

#[tokio::test]
async fn fixed_peers_have_independent_ordinary_and_snapshot_routes_and_finite_shutdown() {
    let node = handle(&[1, 2, 3], config());
    let (workers, sender) = NetworkWorkers::start(
        node,
        vec![endpoint(3), endpoint(2)],
        bounded_security(),
        transport_limits(),
        2,
    )
    .unwrap();
    assert_eq!(workers.tasks.len(), 4);
    assert_eq!(
        sender.routes.keys().copied().collect::<Vec<_>>(),
        vec![(2, false), (2, true), (3, false), (3, true)]
    );
    assert_eq!(sender.budget.max_messages, config().max_pending_deliveries);
    assert_eq!(sender.budget.max_bytes, config().max_pending_delivery_bytes);
    workers
        .shutdown(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    assert!(sender.routes.values().all(mpsc::Sender::is_closed));
    assert_eq!(retained(&sender.budget), (0, 0));

    let (workers, sender) = NetworkWorkers::start(
        handle(&[1], config()),
        Vec::new(),
        bounded_security(),
        transport_limits(),
        1,
    )
    .unwrap();
    assert!(workers.tasks.is_empty());
    assert!(sender.routes.is_empty());
    workers.shutdown(Instant::now()).await.unwrap();
}

#[test]
fn physical_budget_is_shared_across_clones_lanes_and_inflight_payloads() {
    let bytes = HEADER_BYTES + delivery(1, 2, false).envelope.payload.len();
    let held = budget(2, bytes * 2);
    let (ordinary, mut receive_ordinary) = mpsc::channel(1);
    let (snapshot, mut receive_snapshot) = mpsc::channel(1);
    let mut sender = NetworkSender {
        routes: BTreeMap::from([((2, false), ordinary), ((2, true), snapshot)]),
        budget: Arc::clone(&held),
    };
    let mut clone = sender.clone();
    assert_eq!(
        sender.try_send(delivery(0, 3, false)),
        Err(Error::Invalid("peer route"))
    );
    assert_eq!(retained(&held), (0, 0));
    sender.try_send(delivery(1, 2, false)).unwrap();
    assert_eq!(retained(&held), (1, bytes));
    // A failed mpsc reservation releases its physical quota immediately.
    assert_eq!(clone.try_send(delivery(2, 2, false)), Err(Error::Full));
    assert_eq!(retained(&held), (1, bytes));
    let inflight = receive_ordinary.try_recv().unwrap();
    assert_eq!(inflight.delivery.id, 1);
    clone.try_send(delivery(3, 2, true)).unwrap();
    assert_eq!(retained(&held), (2, bytes * 2));
    assert_eq!(sender.try_send(delivery(4, 2, false)), Err(Error::Full));
    // Dequeueing, and a logical receipt elsewhere, cannot refund held bytes.
    let handle = handle(&[1, 2], config());
    register(&handle, &[1]);
    assert!(handle.complete(1, DeliveryResult::Received));
    assert_eq!(retained(&held), (2, bytes * 2));
    drop(inflight);
    assert_eq!(retained(&held), (1, bytes));
    let mut too_large = delivery(5, 2, false);
    too_large.envelope.payload.push(0);
    assert_eq!(clone.try_send(too_large), Err(Error::Full));
    assert_eq!(retained(&held), (1, bytes));
    sender.try_send(delivery(6, 2, false)).unwrap();
    drop(receive_ordinary);
    assert_eq!(retained(&held), (1, bytes));
    assert_eq!(clone.try_send(delivery(7, 2, false)), Err(Error::Closed));
    assert_eq!(retained(&held), (1, bytes));
    assert_eq!(receive_snapshot.try_recv().unwrap().delivery.id, 3);
    assert_eq!(retained(&held), (0, 0));
}

#[tokio::test]
async fn one_absolute_deadline_bounds_an_attempt_and_preserves_failure() {
    let now = Instant::now();
    let polled = AtomicBool::new(false);
    assert!(
        !attempt_before(
            now,
            async {
                polled.store(true, Ordering::SeqCst);
                Ok(())
            },
            || now
        )
        .await
    );
    assert!(!polled.load(Ordering::SeqCst));
    let deadline = now + Duration::from_secs(1);
    assert!(attempt_before(deadline, async { Ok(()) }, || now).await);
    let clock_calls = AtomicUsize::new(0);
    assert!(
        !attempt_before(
            deadline,
            async { Err(scap_raft_transport::Error::Deadline) },
            || {
                clock_calls.fetch_add(1, Ordering::SeqCst);
                now
            }
        )
        .await
    );
    assert_eq!(clock_calls.load(Ordering::SeqCst), 1);
    let mut times = [now, deadline].into_iter();
    assert!(!attempt_before(deadline, async { Ok(()) }, || times.next().unwrap()).await);
    assert!(times.next().is_none());
    assert!(
        !attempt_before(
            Instant::now() + Duration::from_millis(5),
            std::future::pending(),
            Instant::now
        )
        .await
    );
}

struct ReadyLink {
    results: VecDeque<bool>,
    seen: Arc<Mutex<Vec<(u64, u64, bool)>>>,
}

impl Deliver for ReadyLink {
    async fn deliver(&mut self, delivery: Delivery) -> bool {
        self.seen
            .lock()
            .push((delivery.id, delivery.peer, delivery.snapshot));
        self.results.pop_front().unwrap()
    }
}

struct Dropped(Option<oneshot::Sender<()>>);

impl Drop for Dropped {
    fn drop(&mut self) {
        let _ = self.0.take().unwrap().send(());
    }
}

struct BlockedLink {
    entered: Option<oneshot::Sender<u64>>,
    dropped: Option<oneshot::Sender<()>>,
}

impl Deliver for BlockedLink {
    async fn deliver(&mut self, delivery: Delivery) -> bool {
        let _guard = Dropped(self.dropped.take());
        self.entered.take().unwrap().send(delivery.id).unwrap();
        std::future::pending().await
    }
}

#[tokio::test]
async fn worker_reports_each_attempt_once_and_releases_payload_after_completion() {
    let handle = handle(&[1, 2], config());
    register(&handle, &[1, 2]);
    let held = budget(2, 4096);
    let (sender, receiver) = mpsc::channel(2);
    sender
        .try_send(queued(&held, delivery(1, 2, false)))
        .ok()
        .unwrap();
    sender
        .try_send(queued(&held, delivery(2, 2, true)))
        .ok()
        .unwrap();
    drop(sender);
    let seen = Arc::new(Mutex::new(Vec::new()));
    send_loop(
        handle.clone(),
        receiver,
        CancellationToken::new(),
        ReadyLink {
            results: VecDeque::from([true, false]),
            seen: Arc::clone(&seen),
        },
    )
    .await;
    assert_eq!(*seen.lock(), vec![(1, 2, false), (2, 2, true)]);
    assert_eq!(
        feedback(&handle),
        BTreeMap::from([(1, DeliveryResult::Received), (2, DeliveryResult::Failed)])
    );
    assert_eq!(retained(&held), (0, 0));
}

#[tokio::test]
async fn cancellation_before_dequeue_drops_queued_payload_without_starting_attempt() {
    let handle = handle(&[1, 2], config());
    register(&handle, &[1]);
    let held = budget(1, 4096);
    let (sender, receiver) = mpsc::channel(1);
    sender
        .try_send(queued(&held, delivery(1, 2, false)))
        .ok()
        .unwrap();
    let stop = CancellationToken::new();
    stop.cancel();
    let seen = Arc::new(Mutex::new(Vec::new()));
    send_loop(
        handle.clone(),
        receiver,
        stop,
        ReadyLink {
            results: VecDeque::new(),
            seen: Arc::clone(&seen),
        },
    )
    .await;
    assert!(seen.lock().is_empty());
    assert!(feedback(&handle).is_empty());
    assert!(sender.is_closed());
    assert_eq!(retained(&held), (0, 0));
}

#[tokio::test]
async fn blocked_peer_and_snapshot_lanes_do_not_block_other_attempts_and_cancel_releases_all() {
    let handle = handle(&[1, 2, 3], config());
    register(&handle, &[1, 2, 3, 4]);
    let held = budget(4, 4096);
    let (ordinary, receive_ordinary) = mpsc::channel(2);
    let (snapshot, receive_snapshot) = mpsc::channel(1);
    let (other_peer, receive_other) = mpsc::channel(1);
    let mut sender = NetworkSender {
        routes: BTreeMap::from([
            ((2, false), ordinary),
            ((2, true), snapshot),
            ((3, false), other_peer),
        ]),
        budget: Arc::clone(&held),
    };
    for message in [
        delivery(1, 2, false),
        delivery(2, 2, false),
        delivery(3, 2, true),
        delivery(4, 3, false),
    ] {
        sender.try_send(message).unwrap();
    }
    drop(sender);
    let (entered, has_entered) = oneshot::channel();
    let (dropped, has_dropped) = oneshot::channel();
    let stop = CancellationToken::new();
    let blocked = tokio::spawn(send_loop(
        handle.clone(),
        receive_ordinary,
        stop.clone(),
        BlockedLink {
            entered: Some(entered),
            dropped: Some(dropped),
        },
    ));
    assert_eq!(has_entered.await.unwrap(), 1);
    let seen = Arc::new(Mutex::new(Vec::new()));
    let successful = || ReadyLink {
        results: VecDeque::from([true]),
        seen: Arc::clone(&seen),
    };
    let snapshots = tokio::spawn(send_loop(
        handle.clone(),
        receive_snapshot,
        stop.clone(),
        successful(),
    ));
    let peers = tokio::spawn(send_loop(
        handle.clone(),
        receive_other,
        stop.clone(),
        successful(),
    ));
    snapshots.await.unwrap();
    peers.await.unwrap();
    assert_eq!(
        feedback(&handle),
        BTreeMap::from([(3, DeliveryResult::Received), (4, DeliveryResult::Received)])
    );
    assert_eq!(retained(&held).0, 2);
    assert!(!blocked.is_finished());
    stop.cancel();
    blocked.await.unwrap();
    has_dropped.await.unwrap();
    assert_eq!(
        feedback(&handle),
        BTreeMap::from([
            (1, DeliveryResult::Failed),
            (3, DeliveryResult::Received),
            (4, DeliveryResult::Received)
        ])
    );
    assert_eq!(retained(&held), (0, 0));
}

async fn pending_task() -> (JoinHandle<()>, oneshot::Receiver<()>) {
    let (entered, has_entered) = oneshot::channel();
    let (dropped, has_dropped) = oneshot::channel();
    let task = tokio::spawn(async move {
        let _guard = Dropped(Some(dropped));
        entered.send(()).unwrap();
        std::future::pending().await
    });
    has_entered.await.unwrap();
    (task, has_dropped)
}

async fn assert_dropped(receiver: oneshot::Receiver<()>) {
    tokio::time::timeout(Duration::from_secs(1), receiver)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn bounded_shutdown_aborts_current_and_remaining_tasks_on_deadline() {
    let (first, first_dropped) = pending_task().await;
    let (second, second_dropped) = pending_task().await;
    let stop = CancellationToken::new();
    let workers = NetworkWorkers {
        stop: stop.clone(),
        tasks: vec![first, second],
    };
    assert_eq!(workers.shutdown(Instant::now()).await, Err(Error::Expired));
    assert!(stop.is_cancelled());
    assert_dropped(first_dropped).await;
    assert_dropped(second_dropped).await;
}

#[tokio::test]
async fn failed_join_aborts_other_tasks_and_drop_without_shutdown_also_cancels() {
    let (pending, dropped) = pending_task().await;
    let panic = tokio::spawn(async { panic!("controlled worker panic") });
    let workers = NetworkWorkers {
        stop: CancellationToken::new(),
        tasks: vec![pending, panic],
    };
    assert!(matches!(
        workers
            .shutdown(Instant::now() + Duration::from_secs(1))
            .await,
        Err(Error::Network(_))
    ));
    assert_dropped(dropped).await;
    let (pending, dropped) = pending_task().await;
    let stop = CancellationToken::new();
    drop(NetworkWorkers {
        stop: stop.clone(),
        tasks: vec![pending],
    });
    assert!(stop.is_cancelled());
    assert_dropped(dropped).await;
}

struct Authority {
    certificate: Certificate,
    key: KeyPair,
}

struct FixedClock(Result<crate::ClockReading, Error>);

impl crate::Clock for FixedClock {
    fn now(&self) -> Result<crate::ClockReading, Error> {
        self.0.clone()
    }
}

#[test]
fn outgoing_authorization_uses_current_scope_pin_time_and_stopped_state() {
    let authority = Authority::new();
    let (_, _, der) = authority.credentials(2);
    let mut node = handle(&[1, 2, 3], config());
    let identity = scap_raft_wire::certificate_identity(&der, 8192).unwrap();
    assert_eq!(
        PeerAuthorizer::authorize(&node, &endpoint(2), &der),
        Err(AdmissionError::PermissionDenied)
    );
    node.replace_bindings(vec![scap_raft_wire::Binding {
        node_id: 2,
        fingerprint: identity.fingerprint,
    }])
    .unwrap();
    assert_eq!(PeerAuthorizer::authorize(&node, &endpoint(2), &der), Ok(()));
    assert_eq!(
        PeerAuthorizer::authorize(&node, &endpoint(3), &der),
        Err(AdmissionError::PermissionDenied)
    );
    assert_eq!(
        PeerAuthorizer::authorize(
            &node,
            &PeerEndpoint {
                cluster_id: 18,
                ..endpoint(2)
            },
            &der
        ),
        Err(AdmissionError::PermissionDenied)
    );
    assert_eq!(
        PeerAuthorizer::authorize(&node, &endpoint(2), &[1]),
        Err(AdmissionError::Invalid)
    );
    assert_eq!(
        PeerAuthorizer::authorize(&node, &endpoint(2), &vec![0; 8193]),
        Err(AdmissionError::Limit)
    );
    for unix_seconds in [identity.not_before - 1, identity.not_after + 1] {
        Arc::get_mut(&mut node.mailbox).unwrap().clock =
            Arc::new(FixedClock(Ok(crate::ClockReading {
                instant: Instant::now(),
                unix_seconds,
            })));
        assert_eq!(
            PeerAuthorizer::authorize(&node, &endpoint(2), &der),
            Err(AdmissionError::Unauthenticated)
        );
    }
    Arc::get_mut(&mut node.mailbox).unwrap().clock = Arc::new(FixedClock(Err(Error::Clock)));
    assert_eq!(
        PeerAuthorizer::authorize(&node, &endpoint(2), &der),
        Err(AdmissionError::Unavailable)
    );
    Arc::get_mut(&mut node.mailbox).unwrap().clock = Arc::new(SystemClock);
    node.stop();
    assert_eq!(
        PeerAuthorizer::authorize(&node, &endpoint(2), &der),
        Err(AdmissionError::Unavailable)
    );
}

impl Authority {
    fn new() -> Self {
        let mut parameters = CertificateParams::new(Vec::new()).unwrap();
        parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let key = KeyPair::generate().unwrap();
        Self {
            certificate: parameters.self_signed(&key).unwrap(),
            key,
        }
    }

    fn credentials(&self, node: u64) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut parameters = CertificateParams::new(vec![endpoint(node).server_name()]).unwrap();
        parameters.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let key = KeyPair::generate().unwrap();
        let certificate = parameters
            .signed_by(&key, &self.certificate, &self.key)
            .unwrap();
        (
            certificate.pem().into_bytes(),
            key.serialize_pem().into_bytes(),
            certificate.der().to_vec(),
        )
    }
}

#[derive(Default)]
struct Sink {
    seen: Mutex<Vec<(Vec<u8>, Envelope)>>,
    reject: AtomicBool,
}

impl Ingress for Sink {
    fn admit(&self, der: &[u8], envelope: Envelope) -> Result<(), AdmissionError> {
        if self.reject.load(Ordering::SeqCst) {
            return Err(AdmissionError::PermissionDenied);
        }
        self.seen.lock().push((der.to_vec(), envelope));
        Ok(())
    }
}

// This is one native adapter boundary, with no Raft simulation or quorum.
// Counting TCP accepts proves reuse without substituting a fake transport;
// current outbound pins and inbound policy still apply on the same socket.
#[tokio::test]
async fn native_delivery_reuses_a_bounded_channel_and_revalidates_current_authority() {
    let authority = Authority::new();
    let (certificate_pem, private_key_pem, server_der) = authority.credentials(2);
    let sink = Arc::new(Sink::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = PeerServer::new(
        Arc::clone(&sink),
        ServerSecurity {
            certificate_pem,
            private_key_pem,
            client_ca_pem: authority.certificate.pem().into_bytes(),
        },
        transport_limits(),
    )
    .unwrap();
    let server_stop = CancellationToken::new();
    let server_task = tokio::spawn(server.serve(listener, server_stop.clone().cancelled_owned()));

    let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_address = proxy.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let proxy_accepted = Arc::clone(&accepted);
    let proxy_stop = CancellationToken::new();
    let proxy_cancel = proxy_stop.clone();
    let proxy_task = tokio::spawn(async move {
        let mut tunnels = tokio::task::JoinSet::new();
        while let Some(Ok((mut incoming, _))) =
            proxy_cancel.run_until_cancelled(proxy.accept()).await
        {
            proxy_accepted.fetch_add(1, Ordering::SeqCst);
            tunnels.spawn(async move {
                let mut outgoing = tokio::net::TcpStream::connect(address).await.unwrap();
                let _ = tokio::io::copy_bidirectional(&mut incoming, &mut outgoing).await;
            });
        }
        tunnels.abort_all();
    });
    let (certificate_pem, private_key_pem, expected_der) = authority.credentials(1);
    let node = handle(&[1, 2], config());
    let binding = scap_raft_wire::Binding {
        node_id: 2,
        fingerprint: scap_raft_wire::certificate_identity(&server_der, 8192)
            .unwrap()
            .fingerprint,
    };
    node.replace_bindings(vec![binding]).unwrap();
    let mut link = TonicDelivery {
        endpoint: PeerEndpoint {
            uri: format!("https://{proxy_address}"),
            ..endpoint(2)
        },
        security: Arc::new(ClientSecurity {
            certificate_pem,
            private_key_pem,
            server_ca_pem: authority.certificate.pem().into_bytes(),
        }),
        limits: transport_limits(),
        authorizer: Arc::new(node.clone()),
        cached: None,
    };
    register(&node, &[1, 2]);
    let held = budget(2, 4096);
    let (sender, receiver) = mpsc::channel(2);
    let mut expected = Vec::new();
    for id in [1, 2] {
        let message = delivery(id, 2, id == 2);
        expected.push((expected_der.clone(), message.envelope.clone()));
        sender.try_send(queued(&held, message)).ok().unwrap();
    }
    drop(sender);
    send_loop(
        node.clone(),
        receiver,
        CancellationToken::new(),
        TonicDelivery {
            endpoint: link.endpoint.clone(),
            security: Arc::clone(&link.security),
            limits: link.limits.clone(),
            authorizer: Arc::clone(&link.authorizer),
            cached: None,
        },
    )
    .await;
    assert_eq!(*sink.seen.lock(), expected);
    assert_eq!(
        feedback(&node),
        BTreeMap::from([(1, DeliveryResult::Received), (2, DeliveryResult::Received)])
    );
    assert_eq!(retained(&held), (0, 0));
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
    sink.reject.store(true, Ordering::SeqCst);
    assert!(!link.deliver(delivery(3, 2, false)).await);
    assert_eq!(accepted.load(Ordering::SeqCst), 2);
    assert!(link.cached.is_none());
    assert_eq!(sink.seen.lock().len(), 2);
    sink.reject.store(false, Ordering::SeqCst);
    assert!(link.deliver(delivery(4, 2, false)).await);
    assert!(link.deliver(delivery(5, 2, false)).await);
    assert_eq!(accepted.load(Ordering::SeqCst), 3);
    assert!(link.cached.is_some());
    assert_eq!(sink.seen.lock().len(), 4);
    node.replace_bindings(vec![]).unwrap();
    assert!(!link.deliver(delivery(6, 2, false)).await);
    assert_eq!(accepted.load(Ordering::SeqCst), 3);
    assert!(link.cached.is_none());
    assert_eq!(sink.seen.lock().len(), 4);
    // New handshakes also consult the current pins. Restoring a pin permits a
    // new delivery, never silently retries the one whose outcome failed.
    assert!(!link.deliver(delivery(7, 2, false)).await);
    assert_eq!(accepted.load(Ordering::SeqCst), 4);
    node.replace_bindings(vec![binding]).unwrap();
    assert!(link.deliver(delivery(8, 2, false)).await);
    assert_eq!(accepted.load(Ordering::SeqCst), 5);
    link.cached.as_mut().unwrap().connected = Instant::now() - link.limits.max_connection_age;
    assert!(link.deliver(delivery(9, 2, false)).await);
    assert_eq!(accepted.load(Ordering::SeqCst), 6);
    let mut expired = delivery(10, 2, false);
    expired.deadline = Instant::now();
    assert!(!link.deliver(expired).await);
    assert_eq!(accepted.load(Ordering::SeqCst), 6);
    assert!(link.cached.is_none());
    link.endpoint.uri = "http://127.0.0.1:9".into();
    assert!(!link.deliver(delivery(11, 2, false)).await);
    proxy_stop.cancel();
    proxy_task.await.unwrap();
    server_stop.cancel();
    tokio::time::timeout(Duration::from_secs(3), server_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn deadline_and_shutdown_cancel_a_native_tls_connect_that_never_finishes() {
    let authority = Authority::new();
    let (certificate_pem, private_key_pem, _) = authority.credentials(1);
    let security = Arc::new(ClientSecurity {
        certificate_pem,
        private_key_pem,
        server_ca_pem: authority.certificate.pem().into_bytes(),
    });
    for cancel in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (entered, has_entered) = oneshot::channel();
        let peer_stop = CancellationToken::new();
        let peer_cancel = peer_stop.clone();
        let peer = tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.unwrap();
            entered.send(()).unwrap();
            peer_cancel.cancelled().await;
        });
        let node = handle(&[1, 2], config());
        let link = TonicDelivery {
            endpoint: PeerEndpoint {
                uri: format!("https://{address}"),
                ..endpoint(2)
            },
            security: Arc::clone(&security),
            limits: transport_limits(),
            authorizer: Arc::new(node.clone()),
            cached: None,
        };
        register(&node, &[1]);
        let held = budget(1, 4096);
        let (sender, receiver) = mpsc::channel(1);
        let mut message = delivery(1, 2, false);
        if !cancel {
            message.deadline = Instant::now() + Duration::from_millis(100);
        }
        sender.try_send(queued(&held, message)).ok().unwrap();
        drop(sender);
        let stop = CancellationToken::new();
        let outcome = tokio::spawn(send_loop(node.clone(), receiver, stop.clone(), link));
        tokio::time::timeout(Duration::from_secs(1), has_entered)
            .await
            .unwrap()
            .unwrap();
        if cancel {
            stop.cancel();
        }
        tokio::time::timeout(Duration::from_secs(1), outcome)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            feedback(&node),
            BTreeMap::from([(1, DeliveryResult::Failed)])
        );
        assert_eq!(retained(&held), (0, 0));
        peer_stop.cancel();
        peer.await.unwrap();
    }
}
