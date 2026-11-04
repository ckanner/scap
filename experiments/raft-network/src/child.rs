//! Each node is a real process with one formal runtime, independent RocksDB,
//! a real mTLS server, and the formal bounded outgoing network workers.
use std::fs;
use std::io::{self, BufReader, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use raft::eraftpb::ConfState;
use scap_cell::{CellApplication, CellState};
use scap_raft_driver::Driver;
use scap_raft_rocks::RocksBackend;
use scap_raft_runtime::{
    Answer, Input, NetworkWorkers, QueueLimits, Runtime, RuntimeConfig, SystemClock,
};
use scap_raft_store::Store;
use scap_raft_transport::{PeerEndpoint, PeerServer};
use scap_raft_wire::Binding;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use crate::certs::Material;
use crate::common;
use crate::protocol::{hex, line, unhex, PREFIX, REQUEST_BYTES, RESPONSE_BYTES};

pub const CHILD_ID: &str = "SCAP_NETWORK_CHILD_ID";
pub const CHILD_DIRECTORY: &str = "SCAP_NETWORK_CHILD_DIRECTORY";
pub const CHILD_CERTIFICATES: &str = "SCAP_NETWORK_CHILD_CERTIFICATES";
pub const CHILD_CREATE: &str = "SCAP_NETWORK_CHILD_CREATE";
pub const CHILD_BOOT: &str = "SCAP_NETWORK_CHILD_BOOT";
pub const CHILD_INBOX_MESSAGES: &str = "SCAP_NETWORK_CHILD_INBOX_MESSAGES";
pub const CHILD_INBOX_BYTES: &str = "SCAP_NETWORK_CHILD_INBOX_BYTES";

fn emit(sequence: u64, kind: &str, fields: &str) {
    let text = format!("{PREFIX} {sequence} {kind} {fields} END\n");
    assert!(text.len() <= RESPONSE_BYTES);
    let mut stdout = io::stdout().lock();
    stdout.write_all(text.as_bytes()).unwrap();
    stdout.flush().unwrap();
}

pub fn maybe_run() -> bool {
    let Ok(id) = std::env::var(CHILD_ID) else {
        return false;
    };
    let node: u64 = id.parse().unwrap();
    let directory = PathBuf::from(std::env::var_os(CHILD_DIRECTORY).unwrap());
    let certificates = PathBuf::from(std::env::var_os(CHILD_CERTIFICATES).unwrap());
    let boot = std::env::var(CHILD_BOOT).unwrap().parse().unwrap();
    let create = std::env::var(CHILD_CREATE).unwrap() == "1";
    let material = Material::load(&certificates, &format!("node{node}"));
    let ca = fs::read(certificates.join("ca.pem")).unwrap();
    let bindings = (1..=3)
        .map(|id| Material::load(&certificates, &format!("node{id}")).binding(id))
        .collect();
    let store = if create {
        let mut members = ConfState::default();
        members.set_voters(vec![1, 2, 3]);
        let application = CellState::bootstrap(
            common::cell(),
            common::ADMINISTRATOR,
            common::genesis(),
            common::cell_limits(),
        )
        .unwrap()
        .encode();
        Store::create_new_with_application(
            RocksBackend::create_new(&directory).unwrap(),
            common::identity(node),
            members,
            common::store_limits(),
            application,
        )
        .unwrap()
    } else {
        Store::open_existing(
            RocksBackend::open_existing(&directory).unwrap(),
            common::identity(node),
            common::store_limits(),
        )
        .unwrap()
    };
    let application = CellApplication::new(common::cell(), common::cell_limits()).unwrap();
    let logger = slog::Logger::root(slog::Discard, slog::o!());
    let driver = Driver::new(
        store,
        application,
        common::driver_config(node, boot),
        &logger,
    )
    .unwrap();
    let config = RuntimeConfig {
        inbox: QueueLimits {
            max_messages: std::env::var(CHILD_INBOX_MESSAGES)
                .unwrap()
                .parse()
                .unwrap(),
            max_bytes: std::env::var(CHILD_INBOX_BYTES).unwrap().parse().unwrap(),
        },
        requests: QueueLimits {
            max_messages: 32,
            max_bytes: 1024 * 1024,
        },
        max_pending_deliveries: 128,
        max_pending_delivery_bytes: 4 * 1024 * 1024,
        max_pending_reads: 16,
        max_pending_proposals: 16,
        max_result_bytes: 512,
        max_view_bytes: 512 * 1024,
        max_poll_rounds: 64,
        tick_interval: Duration::from_millis(20),
        delivery_timeout: Duration::from_millis(750),
        max_inbound_age: Duration::from_secs(30),
    };
    let (runtime, handle) = Runtime::new(
        driver,
        common::policy(node, bindings),
        config,
        Arc::new(SystemClock),
    )
    .unwrap();
    let mut runtime = Some(runtime);
    let async_runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let listener = async_runtime
        .block_on(TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let address = listener.local_addr().unwrap();
    let server = PeerServer::new(
        Arc::new(handle.clone()),
        material.server(&ca),
        common::transport_limits(),
    )
    .unwrap();
    let (stop_server, stopped_server) = oneshot::channel();
    let serving = async_runtime.spawn(server.serve(listener, async {
        let _ = stopped_server.await;
    }));
    emit(0, "ready", &address.to_string());
    let mut running = None;
    let mut workers = None;
    let mut reader = BufReader::new(io::stdin().lock());
    while let Some(frame) = line(&mut reader, REQUEST_BYTES).unwrap() {
        let frame = std::str::from_utf8(&frame).unwrap();
        let parts: Vec<_> = frame.split_whitespace().collect();
        let sequence = parts[1].parse().unwrap();
        match parts[0] {
            "start" => {
                let endpoints = parts[2]
                    .split(',')
                    .map(|route| {
                        let (peer, address) = route.split_once('@').unwrap();
                        PeerEndpoint {
                            uri: format!("https://{address}/"),
                            cluster_id: common::CLUSTER,
                            node_id: peer.parse().unwrap(),
                        }
                    })
                    .collect();
                let (network_workers, mut sender) = {
                    let _entered = async_runtime.enter();
                    NetworkWorkers::start(
                        handle.clone(),
                        endpoints,
                        material.client(&ca),
                        common::transport_limits(),
                        32,
                    )
                    .unwrap()
                };
                let mut runtime = runtime.take().expect("runtime starts once");
                running = Some(thread::spawn(move || runtime.run(&mut sender)));
                workers = Some(network_workers);
                emit(sequence, "started", "-");
            }
            "pins" => {
                let bindings = if parts[2] == "-" {
                    Vec::new()
                } else {
                    parts[2]
                        .split(',')
                        .map(|value| {
                            let (node, fingerprint) = value.split_once(':').unwrap();
                            Binding {
                                node_id: node.parse().unwrap(),
                                fingerprint: unhex(fingerprint).try_into().unwrap(),
                            }
                        })
                        .collect()
                };
                match handle.replace_bindings(bindings) {
                    Ok(revision) => emit(sequence, "pins", &revision.to_string()),
                    Err(error) => emit(sequence, "error", &hex(error.to_string().as_bytes())),
                }
            }
            "stop" => {
                handle.stop();
                emit(sequence, "stopped", "-");
                break;
            }
            command => {
                let input = match command {
                    "status" => Input::Status,
                    "read" => Input::Read,
                    "checkpoint" => Input::Checkpoint,
                    "propose" => Input::Propose {
                        context: Vec::new(),
                        data: unhex(parts[3]),
                    },
                    _ => panic!("unknown fixture command"),
                };
                let deadline = Instant::now() + Duration::from_millis(parts[2].parse().unwrap());
                let answer = handle
                    .submit(input, deadline)
                    .and_then(|pending| pending.wait());
                match answer {
                    Ok(Answer::Admitted) => emit(sequence, "admitted", "-"),
                    Ok(Answer::Applied(_)) => {
                        panic!("ordinary-proposal fixture received a tracked application result")
                    }
                    Ok(Answer::Membership(_) | Answer::MembershipChanged(_)) => {
                        panic!("fixed-membership fixture received a membership result")
                    }
                    Ok(Answer::Checkpointed) => emit(sequence, "checkpoint", "-"),
                    Ok(Answer::Status(status)) => {
                        emit(
                            sequence,
                            "status",
                            &format!(
                                "{} {} {} {} {} {} {}",
                                status.role as u8,
                                status.leader_id,
                                status.term,
                                status.commit,
                                status.applied,
                                status.last_index,
                                status.snapshot_index,
                            ),
                        );
                    }
                    Ok(Answer::Read(view)) => {
                        assert_eq!(view.identity, common::identity(node));
                        assert!(view.index >= view.barrier.index);
                        emit(
                            sequence,
                            "read",
                            &format!(
                                "{} {} {} {} {} {}",
                                view.term,
                                view.index,
                                hex(&view.application),
                                view.barrier.ticket.boot_id,
                                view.barrier.ticket.sequence,
                                view.barrier.index,
                            ),
                        );
                    }
                    Err(error) => emit(sequence, "error", &hex(error.to_string().as_bytes())),
                }
            }
        }
    }
    handle.stop();
    if let Some(workers) = workers {
        async_runtime
            .block_on(workers.shutdown(Instant::now() + Duration::from_secs(5)))
            .unwrap();
    }
    if let Some(running) = running {
        running.join().unwrap().unwrap();
    }
    let _ = stop_server.send(());
    async_runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(5), serving)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    });
    true
}
