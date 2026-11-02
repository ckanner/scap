//! Test-only scheduling around the formal ports. All authorization, owner
//! recovery, outcome matching, and native publication stay in production code.
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use scap_cell::{Outcome, Position};
use scap_cell_client::{CellPort, Client, RequestContext, RuntimePort};
use scap_raft_driver::ProposalResult;
use scap_raft_runtime::{Clock, Error as RuntimeError, Handle, ReadView, SystemClock};
use scap_raft_store::Identity;
use scap_sql_worker::{OwnerRequest, WorkerLimits, Writer};

use crate::common;
use crate::protocol::{hex, unhex};

struct Hook {
    phase: String,
    path: PathBuf,
}

#[derive(Clone, Default)]
struct Scheduling(Arc<Mutex<Option<Hook>>>);

impl Scheduling {
    fn arm(&self, phase: &str, path: PathBuf) {
        let mut current = self.0.lock().unwrap();
        assert!(
            current.is_none(),
            "the preceding scheduling hook was not consumed"
        );
        if phase != "none" {
            *current = Some(Hook {
                phase: phase.into(),
                path,
            });
        }
    }

    fn pause(&self, phase: &str, observation: &str) {
        let hook = {
            let mut current = self.0.lock().unwrap();
            if current.as_ref().is_some_and(|hook| hook.phase == phase) {
                current.take()
            } else {
                None
            }
        };
        let Some(hook) = hook else { return };
        // Publish the complete observation atomically so the parent cannot
        // mistake a partially written file for a reached scheduling boundary.
        let temporary = hook.path.with_extension("temporary");
        fs::write(&temporary, format!("{phase}: {observation}")).unwrap();
        fs::rename(temporary, hook.path.with_extension("ready")).unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        while !hook.path.with_extension("continue").exists() {
            assert!(
                Instant::now() < deadline,
                "bounded gate scheduling deadline"
            );
            thread::sleep(Duration::from_millis(2));
        }
    }
}

#[derive(Clone)]
struct PausingPort {
    inner: RuntimePort,
    scheduling: Scheduling,
}

impl CellPort for PausingPort {
    fn identity(&self) -> Identity {
        self.inner.identity()
    }

    fn read(
        &mut self,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<ReadView, RuntimeError> {
        let view = self.inner.read(deadline, cancelled)?;
        self.scheduling.pause(
            "read",
            &format!("SafeReadIndex term={} index={}", view.term, view.index),
        );
        Ok(view)
    }

    fn propose(
        &mut self,
        data: Vec<u8>,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<ProposalResult, RuntimeError> {
        self.scheduling
            .pause("proposal", "before formal tracked proposal");
        let result = self.inner.propose(data, deadline, cancelled)?;
        let applied = scap_cell::decode_applied_outcome(
            &result.data,
            Position {
                term: result.term,
                index: result.index,
            },
        )
        .unwrap();
        if matches!(applied.outcome, Outcome::Accepted(_)) {
            self.scheduling.pause("accepted", &format!("{applied:?}"));
        }
        Ok(result)
    }
}

pub struct Response {
    pub kind: &'static str,
    pub fields: String,
}

enum Task {
    Run {
        parts: Vec<String>,
        deadline: Instant,
        sequence: u64,
    },
    Stop,
}

/// One dedicated OS thread owns and constructs the !Send native writer. The
/// cell runtime and its Tokio network executor remain separate threads.
pub struct SqlThread {
    commands: mpsc::SyncSender<Task>,
    running: JoinHandle<()>,
}

pub fn context(auth_epoch: u64, deadline: Instant) -> RequestContext {
    let mut admission = common::admission();
    admission.auth_epoch = auth_epoch;
    RequestContext {
        admission,
        deadline,
        cancelled: Arc::new(AtomicBool::new(false)),
    }
}

impl SqlThread {
    pub fn start(handle: Handle, root: PathBuf, node: u64) -> Self {
        let (commands, receiver) = mpsc::sync_channel(1);
        let running = thread::spawn(move || {
            let clock: Arc<dyn Clock> = Arc::new(SystemClock);
            let scheduling = Scheduling::default();
            let port = PausingPort {
                inner: RuntimePort::new(handle),
                scheduling: scheduling.clone(),
            };
            let client = Client::new(
                common::CLUSTER,
                common::cell(),
                common::cell_limits(),
                port,
                clock.clone(),
            )
            .unwrap();
            let mut session = SqlSession {
                writer: None,
                client,
                scheduling,
                root,
                node,
                clock,
            };
            while let Ok(task) = receiver.recv() {
                match task {
                    Task::Stop => break,
                    Task::Run {
                        parts,
                        deadline,
                        sequence,
                    } => {
                        let result = session.dispatch(&parts, deadline);
                        crate::child::emit(sequence, result.kind, &result.fields);
                    }
                }
            }
        });
        Self { commands, running }
    }

    pub fn enqueue(&self, parts: &[&str], deadline: Instant, sequence: u64) {
        self.commands
            .try_send(Task::Run {
                parts: parts.iter().map(|part| (*part).into()).collect(),
                deadline,
                sequence,
            })
            .unwrap();
    }

    pub fn stop(self) {
        self.commands.send(Task::Stop).unwrap();
        self.running.join().unwrap();
    }
}

struct SqlSession {
    writer: Option<Writer<PausingPort>>,
    client: Client<PausingPort>,
    scheduling: Scheduling,
    root: PathBuf,
    node: u64,
    clock: Arc<dyn Clock>,
}

impl SqlSession {
    fn dispatch(&mut self, parts: &[String], deadline: Instant) -> Response {
        let node = self.node;
        match parts[0].as_str() {
            "recover" => {
                let worker: u128 = parts[3].parse().unwrap();
                let expected: u64 = parts[4].parse().unwrap();
                let auth: u64 = parts[5].parse().unwrap();
                let operation: u128 = parts[6].parse().unwrap();
                let directory = self.root.join(format!("writer-{node}-{worker}"));
                // Dropping a stopped cache is an effect; the production owner API
                // chooses and verifies every step of reconstruction and activation.
                self.writer = None;
                match Writer::recover(
                    self.client.clone(),
                    &context(auth, deadline),
                    OwnerRequest {
                        identity: common::engine_identity(),
                        expected_owner_epoch: expected,
                        worker_instance_id: worker,
                        claim_operation_id: operation,
                        activate_operation_id: operation + 1,
                    },
                    &directory,
                    WorkerLimits {
                        engine: common::engine_limits(),
                        sqlite: common::writer_limits(),
                    },
                    self.clock.clone(),
                ) {
                    Ok(recovered) => {
                        let fields =
                            format!("{} {}", recovered.owner().epoch, recovered.head().revision);
                        self.writer = Some(recovered);
                        Response {
                            kind: "recovered",
                            fields,
                        }
                    }
                    Err(error) => Response {
                        kind: "error",
                        fields: hex(format!("{error:?}").as_bytes()),
                    },
                }
            }
            "sql" => {
                let request: u128 = parts[3].parse().unwrap();
                let auth: u64 = parts[4].parse().unwrap();
                self.scheduling
                    .arm(&parts[5], self.root.join(format!("hook-{node}-{request}")));
                let statements = parts[6]
                    .split(',')
                    .map(|text| common::sql(&String::from_utf8(unhex(text)).unwrap()))
                    .collect::<Vec<_>>();
                let result = self.writer.as_mut().unwrap().execute(
                    context(auth, deadline),
                    request,
                    &statements,
                );
                match result {
                    Ok(completed) => {
                        let result =
                            scap_sql::encode_result(&completed.result, common::writer_limits().sql)
                                .unwrap();
                        Response {
                            kind: "sql",
                            fields: format!(
                                "{} {} {} {} {} {}",
                                completed.receipt.sequence,
                                completed.replayed,
                                hex(&result),
                                completed.receipt.ticket.owner_epoch,
                                completed.receipt.ticket.worker_instance_id,
                                hex(&completed.receipt.ticket.payload_digest)
                            ),
                        }
                    }
                    Err(error) => Response {
                        kind: "error",
                        fields: hex(format!("{error:?}").as_bytes()),
                    },
                }
            }
            "query" => {
                // The request number only names the test scheduling hook; the
                // formal query has no write request ID or retained result.
                let request: u128 = parts[3].parse().unwrap();
                let auth: u64 = parts[4].parse().unwrap();
                self.scheduling
                    .arm(&parts[5], self.root.join(format!("hook-{node}-{request}")));
                let statements = parts[6]
                    .split(',')
                    .map(|text| common::sql(&String::from_utf8(unhex(text)).unwrap()))
                    .collect::<Vec<_>>();
                let mut request_context = context(auth, deadline);
                request_context.admission.principal_id = common::READER;
                match self
                    .writer
                    .as_mut()
                    .unwrap()
                    .query(request_context, &statements)
                {
                    Ok(completed) => Response {
                        kind: "query",
                        fields: format!(
                            "{} {} {} {} {}",
                            completed.revision,
                            completed.position.term,
                            completed.position.index,
                            hex(&completed.commit_hash),
                            hex(&scap_sql::encode_result(
                                &completed.result,
                                common::writer_limits().sql
                            )
                            .unwrap()),
                        ),
                    },
                    Err(error) => Response {
                        kind: "error",
                        fields: hex(format!("{error:?}").as_bytes()),
                    },
                }
            }
            _ => panic!("unknown SQL fixture action"),
        }
    }
}
