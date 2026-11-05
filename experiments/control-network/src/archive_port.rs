//! Trusted test scheduling around formal ports; no archive acceptance logic.
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use scap_archive::{Controller, PublishedArchive, S3Config, S3};
use scap_cell::DatabaseView;
use scap_cell_client::{CellPort, Client, RuntimePort};
use scap_raft_driver::ProposalResult;
use scap_raft_runtime::{Error, Handle, ReadView, SystemClock};
use scap_raft_store::Identity;
use serde_json::json;

use crate::{common, protocol::hex, sql_thread};

#[derive(Clone)]
struct DroppingPort {
    inner: RuntimePort,
    discard: Arc<AtomicBool>,
}
impl CellPort for DroppingPort {
    fn identity(&self) -> Identity {
        self.inner.identity()
    }
    fn read(&mut self, deadline: Instant, cancelled: &AtomicBool) -> Result<ReadView, Error> {
        self.inner.read(deadline, cancelled)
    }
    fn propose(
        &mut self,
        data: Vec<u8>,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<ProposalResult, Error> {
        let observed = self.inner.propose(data.clone(), deadline, cancelled)?;
        if self.discard.swap(false, Ordering::SeqCst) {
            let directory =
                std::env::var_os("SCAP_CONTROL_EVIDENCE_DIR").expect("private evidence directory");
            let path = std::path::PathBuf::from(directory).join(format!(
                "lost-response-node-{}.jsonl",
                self.identity().node_id
            ));
            let mut file = OpenOptions::new()
                .append(true)
                .create(true)
                .open(path)
                .unwrap();
            writeln!(
                file,
                "{}",
                json!({
                    "event":"durable_result_discarded", "node_id":self.identity().node_id,
                    "command":hex(&data), "term":observed.term,"index":observed.index,
                    "result":hex(&observed.data), "ticket_boot":observed.ticket.boot_id.to_string(),
                    "ticket_sequence":observed.ticket.sequence,
                })
            )
            .unwrap();
            file.sync_all().unwrap();
            // The real tracked result is deliberately hidden only after its
            // durable quorum. No fabricated outcome reaches the Controller.
            return Err(Error::Unknown);
        }
        Ok(observed)
    }
}

pub struct ArchivePort {
    reader: Client<RuntimePort>,
    controller: Option<Controller<DroppingPort, S3>>,
    discard: Arc<AtomicBool>,
    saved: Option<(DatabaseView, PublishedArchive)>,
}
impl ArchivePort {
    pub fn new(handle: Handle, runtime: tokio::runtime::Handle) -> Self {
        let discard = Arc::new(AtomicBool::new(false));
        let reader = Client::new(
            common::CLUSTER,
            common::cell(),
            common::cell_limits(),
            RuntimePort::new(handle.clone()),
            Arc::new(SystemClock),
        )
        .unwrap();
        let controller = std::env::var("SCAP_CONTROL_S3_ENDPOINT")
            .ok()
            .map(|endpoint| {
                let objects = S3::new(
                    S3Config {
                        endpoint,
                        region: "us-east-1".into(),
                        bucket: "scap-history".into(),
                        access_key: std::env::var("SCAP_HISTORY_S3_ACCESS").unwrap(),
                        secret_key: std::env::var("SCAP_HISTORY_S3_SECRET").unwrap(),
                        session_token: None,
                        allow_http: true,
                        max_object_bytes: 8 * 1024 * 1024,
                        request_timeout: Duration::from_secs(4),
                    },
                    runtime,
                )
                .unwrap();
                let port = DroppingPort {
                    inner: RuntimePort::new(handle),
                    discard: discard.clone(),
                };
                let client = Client::new(
                    common::CLUSTER,
                    common::cell(),
                    common::cell_limits(),
                    port,
                    Arc::new(SystemClock),
                )
                .unwrap();
                Controller::new(client, objects)
            });
        Self {
            reader,
            controller,
            discard,
            saved: None,
        }
    }
    pub fn command(&mut self, parts: &[&str], deadline: Instant) -> (&'static str, String) {
        let auth = parts[3].parse().unwrap();
        let operation = parts[4].parse().unwrap();
        let context = sql_thread::context(auth, deadline);
        let state = self.reader.read(&context).unwrap();
        let view = state
            .archive_status(common::DATABASE, context.admission)
            .unwrap();
        let controller = self
            .controller
            .as_mut()
            .expect("real SeaweedFS configuration required");
        self.discard
            .store(parts.get(5) == Some(&"lose"), Ordering::SeqCst);
        let result = match parts[0] {
            "s3_suspend" => controller.suspend_bound(&context, view, operation),
            "s3_publish" => {
                self.saved = None;
                controller
                    .publish_bound(&context, view.clone(), operation)
                    .map(|published| {
                        self.saved = Some((view, published));
                    })
            }
            "s3_prune" | "s3_saved_prune" => {
                let Some((source, published)) = self.saved.clone() else {
                    self.discard.store(false, Ordering::SeqCst);
                    return ("error", hex(b"NoConfirmedPublication"));
                };
                controller.prune_bound(&context, source, published, operation)
            }
            "s3_hydrate" => controller.hydrate_bound(&context, view, operation),
            _ => unreachable!(),
        };
        self.discard.store(false, Ordering::SeqCst);
        match result {
            Ok(()) => ("archive_ok", hex(parts[0].as_bytes())),
            Err(error) => ("error", hex(format!("{error:?}").as_bytes())),
        }
    }
}
