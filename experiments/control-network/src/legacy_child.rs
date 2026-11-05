//! Each node is a real process with one formal runtime, independent RocksDB,
//! a real mTLS server, and the formal bounded outgoing network workers.
use std::fs;
use std::io::{self, BufReader, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use raft::eraftpb::ConfState;
use scap_cell::{
    ArchiveRef, CellApplication, CellState, CommandKind, Grant, OwnerToken, Position, ADMIN, READ,
    WRITE,
};
use scap_cell_client::{Client, RuntimePort};
use scap_raft_driver::Driver;
use scap_raft_rocks::RocksBackend;
use scap_raft_runtime::{
    Answer, Input, NetworkWorkers, QueueLimits, Runtime, RuntimeConfig, SystemClock,
};
use scap_raft_store::Store;
use scap_raft_transport::{PeerEndpoint, PeerServer};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use crate::certs::Material;
use crate::common;
use crate::protocol::{hex, line, unhex, PREFIX, REQUEST_BYTES, RESPONSE_BYTES};
use crate::sql_thread::{self, SqlThread};

pub const CHILD_ID: &str = "SCAP_SQL_NETWORK_CHILD_ID";
pub const CHILD_DIRECTORY: &str = "SCAP_SQL_NETWORK_CHILD_DIRECTORY";
pub const CHILD_CERTIFICATES: &str = "SCAP_SQL_NETWORK_CHILD_CERTIFICATES";
pub const CHILD_CREATE: &str = "SCAP_SQL_NETWORK_CHILD_CREATE";
pub const CHILD_BOOT: &str = "SCAP_SQL_NETWORK_CHILD_BOOT";
pub const CHILD_INBOX_MESSAGES: &str = "SCAP_SQL_NETWORK_CHILD_INBOX_MESSAGES";
pub const CHILD_INBOX_BYTES: &str = "SCAP_SQL_NETWORK_CHILD_INBOX_BYTES";

pub(crate) fn emit(sequence: u64, kind: &str, fields: &str) {
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
    let bindings = (1..=4)
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
            max_bytes: 16 * 1024 * 1024,
        },
        max_pending_deliveries: 128,
        max_pending_delivery_bytes: 16 * 1024 * 1024,
        max_pending_reads: 16,
        max_pending_proposals: 16,
        max_result_bytes: 16 * 1024,
        max_view_bytes: 8 * 1024 * 1024,
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
    let mut client = Client::new(
        common::CLUSTER,
        common::cell(),
        common::cell_limits(),
        RuntimePort::new(handle.clone()),
        Arc::new(SystemClock),
    )
    .unwrap();
    let sql_worker = SqlThread::start(
        handle.clone(),
        directory.parent().unwrap().to_path_buf(),
        node,
    );
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
            "recover" | "sql" | "query" => {
                let deadline = Instant::now() + Duration::from_millis(parts[2].parse().unwrap());
                sql_worker.enqueue(&parts, deadline, sequence);
            }
            "create" | "claim" | "auth" | "reader" | "resolve" | "archive_suspend"
            | "archive_publish" | "archive_prune" | "archive_hydrate" => {
                let deadline = Instant::now() + Duration::from_millis(parts[2].parse().unwrap());
                let auth = parts[3].parse().unwrap();
                let kind = match parts[0] {
                    "create" => CommandKind::Create {
                        operation_id: 1,
                        policy: vec![Grant {
                            principal_id: common::ADMINISTRATOR,
                            permissions: READ | WRITE | ADMIN,
                        }],
                    },
                    "claim" => CommandKind::ClaimOwner {
                        operation_id: parts[4].parse().unwrap(),
                        expected_epoch: parts[5].parse().unwrap(),
                        worker_instance_id: parts[6].parse().unwrap(),
                    },
                    "auth" => CommandKind::AuthFence {
                        operation_id: parts[4].parse().unwrap(),
                        expected_epoch: auth,
                        policy: vec![Grant {
                            principal_id: common::ADMINISTRATOR,
                            permissions: READ | WRITE | ADMIN,
                        }],
                    },
                    "reader" => CommandKind::AuthFence {
                        operation_id: parts[4].parse().unwrap(),
                        expected_epoch: auth,
                        policy: vec![
                            Grant {
                                principal_id: common::ADMINISTRATOR,
                                permissions: READ | WRITE | ADMIN,
                            },
                            Grant {
                                principal_id: common::READER,
                                permissions: READ,
                            },
                        ],
                    },
                    "resolve" => CommandKind::ResolveOrCancel {
                        request_id: parts[4].parse().unwrap(),
                        request_fingerprint: unhex(parts[5]).try_into().unwrap(),
                    },
                    "archive_suspend" => CommandKind::SuspendDb {
                        operation_id: parts[4].parse().unwrap(),
                        token: OwnerToken {
                            epoch: parts[5].parse().unwrap(),
                            worker_instance_id: parts[6].parse().unwrap(),
                        },
                        expected_revision: parts[7].parse().unwrap(),
                    },
                    "archive_publish" => CommandKind::PublishArchive {
                        operation_id: parts[4].parse().unwrap(),
                        expected_owner: OwnerToken {
                            epoch: parts[5].parse().unwrap(),
                            worker_instance_id: parts[6].parse().unwrap(),
                        },
                        expected_previous: if parts[7] == "-" {
                            None
                        } else {
                            Some(unhex(parts[7]).try_into().unwrap())
                        },
                        archive: ArchiveRef {
                            source: Position {
                                term: parts[8].parse().unwrap(),
                                index: parts[9].parse().unwrap(),
                            },
                            revision: parts[10].parse().unwrap(),
                            commit_hash: unhex(parts[11]).try_into().unwrap(),
                            object_digest: unhex(parts[12]).try_into().unwrap(),
                            object_bytes: parts[13].parse().unwrap(),
                            metadata_digest: unhex(parts[14]).try_into().unwrap(),
                        },
                    },
                    "archive_prune" => CommandKind::PruneArchive {
                        operation_id: parts[4].parse().unwrap(),
                        expected_owner: OwnerToken {
                            epoch: parts[5].parse().unwrap(),
                            worker_instance_id: parts[6].parse().unwrap(),
                        },
                        archive_digest: unhex(parts[7]).try_into().unwrap(),
                    },
                    "archive_hydrate" => CommandKind::HydrateArchive {
                        operation_id: parts[4].parse().unwrap(),
                        archive: unhex(parts[5]),
                    },
                    _ => unreachable!(),
                };
                match client.submit(&sql_thread::context(auth, deadline), common::DATABASE, kind) {
                    Ok(outcome) => {
                        emit(sequence, "applied", &hex(format!("{outcome:?}").as_bytes()))
                    }
                    Err(error) => emit(sequence, "error", &hex(format!("{error:?}").as_bytes())),
                }
            }
            "activate_retention" => {
                let context = sql_thread::context(1, Instant::now() + Duration::from_secs(5));
                let state = client.activate_retention(&context).unwrap();
                assert_eq!(state.physical_history_version(), 4);
                emit(sequence, "activated_retention", "4");
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
                    Ok(Answer::Applied(outcome)) => emit(sequence, "applied", &hex(&outcome.data)),
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
    sql_worker.stop();
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
