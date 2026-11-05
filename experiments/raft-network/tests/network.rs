//! Real network and process contracts, deliberately separate from unit profiles.
#[path = "../src/certs.rs"]
mod certs;
#[path = "../src/child.rs"]
mod child;
#[path = "../src/common.rs"]
mod common;
#[path = "../src/harness.rs"]
mod harness;
#[path = "../src/protocol.rs"]
mod protocol;
#[path = "../src/proxy.rs"]
mod proxy;

use std::collections::BTreeMap;
use std::thread;
use std::time::{Duration, Instant};

use protobuf::Message as ProtobufMessage;
use raft::eraftpb::{Message, MessageType};
use scap_cell::{CellState, CommandKind, Lookup, Outcome};
use scap_raft_rocks::RocksBackend;
use scap_raft_store::Store;
use scap_raft_transport::{Error as TransportError, PeerClient, PeerEndpoint};
use scap_raft_wire::{Envelope, CODEC, VERSION};
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint};
use tonic::Code;

use certs::Material;
use harness::Cluster;
use proxy::Mode;

fn fingerprint(request: u128) -> [u8; 32] {
    scap_cell::payload_digest(&request.to_be_bytes())
}

fn lookup(state: &CellState, request: u128) -> Lookup {
    state
        .lookup(
            common::DATABASE,
            common::admission(),
            request,
            fingerprint(request),
        )
        .unwrap()
}

fn assert_request(state: &CellState, request: u128, sequence: u64) {
    let Lookup::Committed { commit, result, .. } = lookup(state, request) else {
        panic!("acknowledged request disappeared: {request}");
    };
    assert_eq!(commit.receipt.sequence, sequence);
    assert_eq!(commit.receipt.ticket.request_id, request);
    assert_eq!(result, format!("original-result-{request}").into_bytes());
}

fn caught_up(cluster: &mut Cluster, id: u64, index: u64) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if cluster.status(id).applied >= index {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "node {id} did not catch up to {index}"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

fn heartbeat(from: u64, to: u64, term: u64) -> Envelope {
    let mut message = Message::default();
    message.set_msg_type(MessageType::MsgHeartbeat);
    message.set_from(from);
    message.set_to(to);
    message.set_term(term);
    Envelope {
        version: VERSION,
        codec: CODEC,
        cluster_id: common::CLUSTER,
        cell_id: common::CELL,
        cell_incarnation: common::CELL_GENERATION,
        from_node: from,
        to_node: to,
        payload: message.write_to_bytes().unwrap(),
    }
}

fn rpc_code(result: Result<(), TransportError>, expected: Code) {
    match result {
        Err(TransportError::Rpc(status)) => assert_eq!(status.code(), expected, "{status}"),
        other => panic!("expected gRPC {expected:?}, got {other:?}"),
    }
}

#[test]
fn automatic_runtime_commits_and_reads_across_real_mtls_reconnects() {
    if child::maybe_run() {
        return;
    }
    let mut cluster = Cluster::new(
        "automatic_runtime_commits_and_reads_across_real_mtls_reconnects",
        BTreeMap::new(),
    );
    cluster.start_all();
    let leader = cluster.leader(&[1, 2, 3]);
    cluster.initialize(leader);
    for request in 1..=3 {
        cluster.accepted(leader, request, request as u64 - 1);
    }
    let before_duplicate = cluster.status(leader).applied;
    // Retrying the exact accepted business command cannot append a new revision.
    assert_eq!(
        cluster.propose(leader, &common::commit(3, 2)).kind,
        "admitted"
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    let state = loop {
        let state = cluster.try_read(leader, 2000).unwrap();
        if state.last_outcome().is_some_and(|applied| {
            applied.position.index > before_duplicate
                && matches!(&applied.outcome, Outcome::AlreadyCommitted(commit)
                    if commit.receipt.ticket.request_id == 3)
        }) {
            break state;
        }
        assert!(Instant::now() < deadline, "duplicate did not apply");
        thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(
        state
            .database(common::DATABASE.database_id)
            .unwrap()
            .revision,
        3
    );
    assert_request(&state, 3, 3);
    let follower = (1..=3).find(|node| *node != leader).unwrap();
    cluster.partition(follower, Mode::Refuse);
    let state = cluster.accepted(leader, 4, 3);
    cluster.partition(follower, Mode::Open);
    caught_up(&mut cluster, follower, state.position().index);
    let state = cluster.try_read(leader, 2000).unwrap();
    for request in 1..=4 {
        assert_request(&state, request, request as u64);
    }
    cluster.record("actual socket refusal and reconnection retained accepted history; duplicate request retained original result/revision");
    cluster.finish();
}

#[test]
fn tcp_blackhole_minority_cannot_commit_or_finish_a_new_read() {
    if child::maybe_run() {
        return;
    }
    let mut cluster = Cluster::new(
        "tcp_blackhole_minority_cannot_commit_or_finish_a_new_read",
        BTreeMap::new(),
    );
    cluster.start_all();
    let old = cluster.leader(&[1, 2, 3]);
    cluster.initialize(old);
    cluster.accepted(old, 201, 0);
    let before = cluster.status(old);
    cluster.partition(old, Mode::Blackhole);
    let proposal = cluster.propose(old, &common::commit(202, 1));
    assert_eq!(
        proposal.kind, "admitted",
        "fixture must stage before quorum-loss demotion"
    );
    assert!(cluster.try_read(old, 150).is_err());
    let isolated = cluster.status(old);
    assert_eq!(isolated.commit, before.commit);
    assert!(
        isolated.last > isolated.commit,
        "minority fixture must observe a real uncommitted suffix"
    );
    let others: Vec<_> = (1..=3).filter(|id| *id != old).collect();
    let leader = cluster.leader(&others);
    let state = cluster.accepted(leader, 203, 1);
    assert_request(&state, 201, 1);
    assert!(matches!(lookup(&state, 202), Lookup::Unknown));
    let cancel = common::command(CommandKind::ResolveOrCancel {
        request_id: 202,
        request_fingerprint: fingerprint(202),
    });
    assert_eq!(cluster.propose(leader, &cancel).kind, "admitted");
    let deadline = Instant::now() + Duration::from_secs(10);
    let final_state = loop {
        let state = cluster.try_read(leader, 2000).unwrap();
        if matches!(lookup(&state, 202), Lookup::Cancelled { .. }) {
            break state;
        }
        assert!(Instant::now() < deadline);
    };
    cluster.partition(old, Mode::Open);
    caught_up(&mut cluster, old, final_state.position().index);
    assert_request(&cluster.try_read(leader, 2000).unwrap(), 203, 2);
    cluster.record("UNKNOWN attempt was resolved by a later ordered cancellation; timeout itself was not treated as rollback");
    cluster.finish();
}

#[test]
fn killed_leader_and_full_cluster_restart_retain_cell_history() {
    if child::maybe_run() {
        return;
    }
    let mut cluster = Cluster::new(
        "killed_leader_and_full_cluster_restart_retain_cell_history",
        BTreeMap::new(),
    );
    cluster.start_all();
    let old = cluster.leader(&[1, 2, 3]);
    cluster.initialize(old);
    cluster.accepted(old, 301, 0);
    cluster.accepted(old, 302, 1);
    cluster.kill(old);
    let others: Vec<_> = (1..=3).filter(|id| *id != old).collect();
    let leader = cluster.leader(&others);
    let state = cluster.try_read(leader, 2000).unwrap();
    assert_request(&state, 301, 1);
    assert_request(&state, 302, 2);
    let state = cluster.accepted(leader, 303, 2);
    cluster.restart(old);
    for id in 1..=3 {
        caught_up(&mut cluster, id, state.position().index);
    }
    for id in 1..=3 {
        cluster.kill(id);
    }
    for id in 1..=3 {
        cluster.restart(id);
    }
    let leader = cluster.leader(&[1, 2, 3]);
    let state = cluster.try_read(leader, 2000).unwrap();
    for (request, sequence) in [(301, 1), (302, 2), (303, 3)] {
        assert_request(&state, request, sequence);
    }
    let state = cluster.accepted(leader, 304, 3);
    assert_request(&state, 304, 4);
    cluster.record("all replicas reopened their original RocksDB paths after SIGKILL; accepted outcomes and fresh-boot SafeReadIndex retained");
    cluster.finish();
}

#[test]
fn lagging_replica_installs_a_snapshot_over_real_mtls() {
    if child::maybe_run() {
        return;
    }
    let mut cluster = Cluster::new(
        "lagging_replica_installs_a_snapshot_over_real_mtls",
        BTreeMap::new(),
    );
    cluster.start_all();
    let leader = cluster.leader(&[1, 2, 3]);
    cluster.initialize(leader);
    cluster.accepted(leader, 401, 0);
    let lagging = (1..=3).find(|id| *id != leader).unwrap();
    let old = cluster.status(lagging);
    cluster.kill(lagging);
    for request in 402..=408 {
        cluster.accepted(leader, request, request as u64 - 401);
    }
    let reply = cluster
        .nodes
        .get_mut(&leader)
        .unwrap()
        .command("checkpoint", "2000");
    assert_eq!(reply.kind, "checkpoint", "{reply:?}");
    let checkpoint = cluster.status(leader);
    assert!(checkpoint.snapshot > old.last);
    cluster.record(format!(
        "leader checkpoint={}; lagging previous last={}; all peer traffic is mTLS",
        checkpoint.snapshot, old.last
    ));
    cluster.restart(lagging);
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let installed = cluster.status(lagging);
        if installed.snapshot >= checkpoint.snapshot && installed.applied >= checkpoint.applied {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "actual snapshot installation deadline"
        );
        thread::sleep(Duration::from_millis(20));
    }
    cluster.kill(lagging);
    // Inspect the actual receiver's durable snapshot after the second crash,
    // independently of the healthy leader's application history.
    let store = Store::open_existing(
        RocksBackend::open_existing(&cluster.directory.path().join(format!("node{lagging}")))
            .unwrap(),
        common::identity(lagging),
        common::store_limits(),
    )
    .unwrap();
    let snapshot = &store.view().unwrap().snapshot;
    assert!(snapshot.get_metadata().index >= checkpoint.snapshot);
    let installed_state = CellState::decode_bound(
        snapshot.get_data(),
        common::cell(),
        scap_cell::Position {
            term: snapshot.get_metadata().term,
            index: snapshot.get_metadata().index,
        },
        common::cell_limits(),
    )
    .unwrap();
    for request in 401..=408 {
        assert_request(&installed_state, request, request as u64 - 400);
    }
    drop(store);
    cluster.restart(lagging);
    caught_up(&mut cluster, lagging, checkpoint.applied);
    assert!(cluster.status(lagging).snapshot >= checkpoint.snapshot);
    let state = cluster.try_read(leader, 2000).unwrap();
    for request in 401..=408 {
        assert_request(&state, request, request as u64 - 400);
    }
    cluster.record("actual MsgSnapshot advanced a previously lagging durable snapshot and survived another SIGKILL/reopen");
    cluster.finish();
}

#[derive(Clone, PartialEq, prost::Message)]
struct Packet {
    #[prost(bytes = "vec", tag = "1")]
    data: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct Received {
    #[prost(uint32, tag = "1")]
    version: u32,
}

async fn anonymous_rejected(endpoint: PeerEndpoint, ca: &[u8], envelope: Envelope) {
    let tls = ClientTlsConfig::new()
        .domain_name(endpoint.server_name())
        .ca_certificate(Certificate::from_pem(ca));
    let channel = Endpoint::from_shared(endpoint.uri)
        .unwrap()
        .tls_config(tls)
        .unwrap()
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(2))
        .connect()
        .await;
    if let Ok(channel) = channel {
        let mut client = tonic::client::Grpc::new(channel);
        if client.ready().await.is_ok() {
            let packet = Packet {
                data: scap_raft_wire::encode_envelope(&envelope, 700 * 1024).unwrap(),
            };
            let response: Result<tonic::Response<Received>, _> = client
                .unary(
                    tonic::Request::new(packet),
                    tonic::codegen::http::uri::PathAndQuery::from_static(
                        scap_raft_transport::RPC_PATH,
                    ),
                    tonic_prost::ProstCodec::default(),
                )
                .await;
            assert!(response.is_err(), "server accepted an anonymous client");
        }
    }
}

#[test]
fn mtls_and_node_authorization_reject_untrusted_inputs_before_raft() {
    if child::maybe_run() {
        return;
    }
    let mut cluster = Cluster::new(
        "mtls_and_node_authorization_reject_untrusted_inputs_before_raft",
        BTreeMap::new(),
    );
    let endpoint = cluster.endpoint(2, 1);
    let attack = heartbeat(2, 1, 900);
    cluster.runtime.block_on(async {
        let mut ready = PeerClient::connect(
            endpoint.clone(),
            cluster.materials[&2].client(&cluster.ca),
            common::transport_limits(),
        )
        .await
        .unwrap();
        ready
            .send(heartbeat(2, 1, 1), Instant::now() + Duration::from_secs(2))
            .await
            .unwrap();
    });
    cluster.runtime.block_on(anonymous_rejected(
        endpoint.clone(),
        &cluster.ca,
        attack.clone(),
    ));
    for name in ["foreign2", "expired2"] {
        let material = Material::load(&cluster.certificates(), name);
        cluster.runtime.block_on(async {
            if let Ok(mut client) = PeerClient::connect(
                endpoint.clone(),
                material.client(&cluster.ca),
                common::transport_limits(),
            )
            .await
            {
                assert!(client
                    .send(attack.clone(), Instant::now() + Duration::from_secs(2))
                    .await
                    .is_err());
            }
        });
        cluster.record(format!("real TLS handshake/request rejected {name}"));
    }
    let unbound = Material::load(&cluster.certificates(), "unbound2");
    cluster.runtime.block_on(async {
        let mut client = PeerClient::connect(
            endpoint.clone(),
            unbound.client(&cluster.ca),
            common::transport_limits(),
        )
        .await
        .unwrap();
        rpc_code(
            client
                .send(attack.clone(), Instant::now() + Duration::from_secs(2))
                .await,
            Code::PermissionDenied,
        );
        let mut valid = PeerClient::connect(
            endpoint.clone(),
            cluster.materials[&2].client(&cluster.ca),
            common::transport_limits(),
        )
        .await
        .unwrap();
        rpc_code(
            valid
                .send(
                    heartbeat(3, 1, 900),
                    Instant::now() + Duration::from_secs(2),
                )
                .await,
            Code::PermissionDenied,
        );
        let mut stale = attack.clone();
        stale.cell_incarnation += 1;
        rpc_code(
            valid
                .send(stale, Instant::now() + Duration::from_secs(2))
                .await,
            Code::PermissionDenied,
        );
        let mut local = Message::parse_from_bytes(&attack.payload).unwrap();
        local.set_msg_type(MessageType::MsgHup);
        let mut envelope = attack.clone();
        envelope.payload = local.write_to_bytes().unwrap();
        rpc_code(
            valid
                .send(envelope, Instant::now() + Duration::from_secs(2))
                .await,
            Code::InvalidArgument,
        );
    });
    cluster.start_all();
    let leader = cluster.leader(&[1, 2, 3]);
    for id in 1..=3 {
        assert!(cluster.status(id).term < 900);
    }
    cluster.initialize(leader);
    cluster.accepted(leader, 501, 0);
    cluster.record("anonymous, foreign CA, expired cert, unbound valid-CA leaf, forged node, stale cell and local Raft message caused no injected term transition");
    cluster.finish();
}

#[test]
fn pin_rotation_revokes_existing_connection_and_queued_messages() {
    if child::maybe_run() {
        return;
    }
    let mut cluster = Cluster::new(
        "pin_rotation_revokes_existing_connection_and_queued_messages",
        BTreeMap::from([(1, (2, 64 * 1024))]),
    );
    let endpoint = cluster.endpoint(2, 1);
    let mut original = cluster
        .runtime
        .block_on(PeerClient::connect(
            endpoint.clone(),
            cluster.materials[&2].client(&cluster.ca),
            common::transport_limits(),
        ))
        .unwrap();
    let queued_at = Instant::now();
    for _ in 0..2 {
        cluster
            .runtime
            .block_on(original.send(
                heartbeat(2, 1, 900),
                Instant::now() + Duration::from_secs(2),
            ))
            .unwrap();
    }
    rpc_code(
        cluster.runtime.block_on(original.send(
            heartbeat(2, 1, 900),
            Instant::now() + Duration::from_secs(2),
        )),
        Code::ResourceExhausted,
    );
    let connections = cluster.accepted_connections(2, 1);
    assert_eq!(connections, 1, "same real TCP connection before rotation");
    let rotated = Material::load(&cluster.certificates(), "rotated2");
    let mut bindings = cluster.bindings();
    bindings.retain(|binding| binding.node_id != 2);
    bindings.push(rotated.binding(2));
    cluster.set_bindings(1, bindings);
    let mut replacement = cluster
        .runtime
        .block_on(PeerClient::connect(
            endpoint,
            rotated.client(&cluster.ca),
            common::transport_limits(),
        ))
        .unwrap();
    rpc_code(
        cluster.runtime.block_on(
            replacement.send(heartbeat(2, 1, 1), Instant::now() + Duration::from_secs(2)),
        ),
        Code::ResourceExhausted,
    );
    cluster.start(1);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match cluster
            .runtime
            .block_on(replacement.send(heartbeat(2, 1, 1), Instant::now() + Duration::from_secs(2)))
        {
            Ok(()) => break,
            Err(TransportError::Rpc(status)) if status.code() == Code::ResourceExhausted => {
                assert!(Instant::now() < deadline);
                thread::sleep(Duration::from_millis(10));
            }
            result => panic!("replacement pin failed after queue processing: {result:?}"),
        }
    }
    assert!(
        queued_at.elapsed() < Duration::from_secs(30),
        "revocation, not inbound age expiry, must reject queued traffic"
    );
    assert!(
        cluster.status(1).term < 900,
        "queued pre-rotation message was executed after revocation"
    );
    rpc_code(
        cluster.runtime.block_on(original.send(
            heartbeat(2, 1, 900),
            Instant::now() + Duration::from_secs(2),
        )),
        Code::PermissionDenied,
    );
    assert_eq!(
        cluster.accepted_connections(2, 1),
        connections + 1,
        "revocation applied on the original connection; only replacement client added a second TCP connection"
    );
    cluster.set_bindings(1, cluster.bindings());
    cluster
        .runtime
        .block_on(original.send(heartbeat(2, 1, 1), Instant::now() + Duration::from_secs(2)))
        .unwrap();
    cluster.record("pin revision invalidated two accepted-but-unprocessed inputs; existing channel was denied; replacement pin and restored pin admitted independently");
    drop(original);
    drop(replacement);
    cluster.start(2);
    cluster.start(3);
    cluster.leader(&[1, 2, 3]);
    cluster.finish();
}

#[test]
fn inbox_bytes_deadlines_and_receipts_do_not_claim_durability() {
    if child::maybe_run() {
        return;
    }
    let mut cluster = Cluster::new(
        "inbox_bytes_deadlines_and_receipts_do_not_claim_durability",
        BTreeMap::from([(1, (1, 64 * 1024)), (3, (64, 4500))]),
    );
    let mut client1 = cluster
        .runtime
        .block_on(PeerClient::connect(
            cluster.endpoint(2, 1),
            cluster.materials[&2].client(&cluster.ca),
            common::transport_limits(),
        ))
        .unwrap();
    let expired = cluster.runtime.block_on(client1.send(
        heartbeat(2, 1, 900),
        Instant::now() - Duration::from_millis(1),
    ));
    assert!(matches!(expired, Err(TransportError::Deadline)));
    cluster
        .runtime
        .block_on(client1.send(
            heartbeat(2, 1, 900),
            Instant::now() + Duration::from_secs(2),
        ))
        .unwrap();
    rpc_code(
        cluster.runtime.block_on(client1.send(
            heartbeat(2, 1, 900),
            Instant::now() + Duration::from_secs(2),
        )),
        Code::ResourceExhausted,
    );
    let mut client3 = cluster
        .runtime
        .block_on(PeerClient::connect(
            cluster.endpoint(2, 3),
            cluster.materials[&2].client(&cluster.ca),
            common::transport_limits(),
        ))
        .unwrap();
    cluster
        .runtime
        .block_on(client3.send(
            heartbeat(2, 3, 900),
            Instant::now() + Duration::from_secs(2),
        ))
        .unwrap();
    rpc_code(
        cluster.runtime.block_on(client3.send(
            heartbeat(2, 3, 900),
            Instant::now() + Duration::from_secs(2),
        )),
        Code::ResourceExhausted,
    );
    drop(client1);
    drop(client3);
    cluster.stop_node(1);
    let store = Store::open_existing(
        RocksBackend::open_existing(&cluster.directory.path().join("node1")).unwrap(),
        common::identity(1),
        common::store_limits(),
    )
    .unwrap();
    let view = store.view().unwrap();
    assert_eq!(view.applied, 1);
    assert_eq!(view.hard_state.term, 1);
    assert_eq!(view.hard_state.commit, 1);
    let genesis_application = CellState::bootstrap(
        common::cell(),
        common::ADMINISTRATOR,
        common::genesis(),
        common::cell_limits(),
    )
    .unwrap()
    .encode();
    assert_eq!(view.application, genesis_application);
    drop(store);
    cluster.record("count and cumulative-byte inbox limits refused extra traffic; expired send reserved no slot; Received alone did not alter durable term/commit/application");
    cluster.finish();
}

#[test]
fn one_way_partition_cannot_turn_rpc_receipts_into_safe_reads() {
    if child::maybe_run() {
        return;
    }
    let mut cluster = Cluster::new(
        "one_way_partition_cannot_turn_rpc_receipts_into_safe_reads",
        BTreeMap::new(),
    );
    cluster.start_all();
    let old = cluster.leader(&[1, 2, 3]);
    cluster.initialize(old);
    cluster.accepted(old, 801, 0);
    let others: Vec<_> = (1..=3).filter(|id| *id != old).collect();
    for peer in &others {
        cluster.route(*peer, old, Mode::Blackhole);
    }
    // Opposite-direction routes remain Open, including their gRPC receipt
    // path. Raft replies use the blocked follower -> leader channels instead.
    // This does not instrument or count each successful receipt after the cut.
    assert!(cluster.try_read(old, 150).is_err());
    let leader = cluster.leader(&others);
    let state = cluster.accepted(leader, 802, 1);
    assert_request(&state, 801, 1);
    for peer in &others {
        cluster.route(*peer, old, Mode::Open);
    }
    caught_up(&mut cluster, old, state.position().index);
    assert_request(&cluster.try_read(leader, 2000).unwrap(), 802, 2);
    cluster.record("a new read request returned no success with only follower-to-old-leader routes blackholed; opposite routes remained Open; majority accepted and recovery converged");
    cluster.finish();
}
