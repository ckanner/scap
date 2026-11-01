//! Finite orchestration and observations, not a second Raft runtime.
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, BufReader, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use raft::StateRole;
use scap_cell::{CellState, Command as CellCommand, Lookup, Position};
use scap_raft_wire::Binding;
use tempfile::TempDir;

use crate::certs::{Authority, Material};
use crate::child;
use crate::common;
use crate::protocol::{hex, line, unhex, Reply, REQUEST_BYTES, RESPONSE_BYTES};
use crate::proxy::{Mode, Proxy};

const REQUEST_DEADLINE: Duration = Duration::from_secs(10);
const EXIT_DEADLINE: Duration = Duration::from_secs(15);
const SCENARIO_DEADLINE: Duration = Duration::from_secs(120);

pub struct Node {
    process: Child,
    commands: Option<SyncSender<Vec<u8>>>,
    writes: Receiver<Result<(), String>>,
    replies: Option<Receiver<Result<Reply, String>>>,
    threads: Vec<JoinHandle<()>>,
    sequence: u64,
    pub address: SocketAddr,
    pub boot: u128,
}

fn remaining(deadline: Instant) -> Duration {
    deadline
        .checked_duration_since(Instant::now())
        .expect("fixture deadline expired")
}

fn wait_exit(process: &mut Child) -> io::Result<ExitStatus> {
    let deadline = Instant::now() + EXIT_DEADLINE;
    loop {
        if let Some(status) = process.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "child exit deadline",
            ));
        }
        thread::sleep(Duration::from_millis(5));
    }
}

impl Node {
    fn new(
        test: &str,
        id: u64,
        directory: &Path,
        certificates: &Path,
        boot: u128,
        create: bool,
        inbox: (usize, usize),
    ) -> Self {
        let mut process = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--nocapture", "--test-threads=1"])
            .env(child::CHILD_ID, id.to_string())
            .env(child::CHILD_DIRECTORY, directory)
            .env(child::CHILD_CERTIFICATES, certificates)
            .env(child::CHILD_BOOT, boot.to_string())
            .env(child::CHILD_CREATE, if create { "1" } else { "0" })
            .env(child::CHILD_INBOX_MESSAGES, inbox.0.to_string())
            .env(child::CHILD_INBOX_BYTES, inbox.1.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let mut stdin = process.stdin.take().unwrap();
        let stdout = process.stdout.take().unwrap();
        let (commands, incoming) = mpsc::sync_channel::<Vec<u8>>(1);
        let (written, writes) = mpsc::sync_channel(1);
        let writer = thread::spawn(move || {
            while let Ok(bytes) = incoming.recv() {
                let result = stdin
                    .write_all(&bytes)
                    .and_then(|()| stdin.flush())
                    .map_err(|error| error.to_string());
                if written.send(result).is_err() {
                    break;
                }
            }
        });
        let (observations, replies) = mpsc::sync_channel(1);
        let reader = thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let response = match line(&mut reader, RESPONSE_BYTES) {
                    Ok(Some(bytes)) => {
                        let text = String::from_utf8(bytes).unwrap();
                        match Reply::parse(&text) {
                            Some(reply) => Ok(reply),
                            None => continue,
                        }
                    }
                    Ok(None) => break,
                    Err(error) => Err(error.to_string()),
                };
                if observations.send(response).is_err() {
                    break;
                }
            }
        });
        // Install the failure cleanup guard before waiting for startup. A
        // stalled or malformed child must not escape when this wait panics.
        let mut node = Self {
            process,
            commands: Some(commands),
            writes,
            replies: Some(replies),
            threads: vec![writer, reader],
            sequence: 0,
            address: SocketAddr::from(([127, 0, 0, 1], 0)),
            boot,
        };
        let ready = node
            .replies
            .as_ref()
            .unwrap()
            .recv_timeout(REQUEST_DEADLINE)
            .expect("real child startup response")
            .unwrap();
        assert_eq!(ready.sequence, 0);
        assert_eq!(ready.kind, "ready");
        node.address = ready.fields[0].parse().unwrap();
        node
    }

    pub fn command(&mut self, command: &str, arguments: &str) -> Reply {
        let deadline = Instant::now() + REQUEST_DEADLINE;
        self.sequence += 1;
        let bytes = format!("{command} {} {arguments}\n", self.sequence).into_bytes();
        assert!(bytes.len() <= REQUEST_BYTES);
        self.commands.as_ref().unwrap().try_send(bytes).unwrap();
        self.writes
            .recv_timeout(remaining(deadline))
            .expect("control write deadline")
            .unwrap();
        let reply = self
            .replies
            .as_ref()
            .unwrap()
            .recv_timeout(remaining(deadline))
            .expect("control response deadline")
            .unwrap();
        assert_eq!(reply.sequence, self.sequence);
        reply
    }

    fn kill(&mut self) {
        if self.process.try_wait().unwrap().is_some() {
            panic!("child exited before injected SIGKILL");
        }
        self.process.kill().unwrap();
        let status = wait_exit(&mut self.process).unwrap();
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(9));
        self.release_threads();
    }

    fn graceful(&mut self) {
        assert_eq!(self.command("stop", "-").kind, "stopped");
        self.commands.take();
        assert!(wait_exit(&mut self.process).unwrap().success());
        self.release_threads();
    }

    fn release_threads(&mut self) {
        self.commands.take();
        self.replies.take();
        for thread in self.threads.drain(..) {
            thread.join().unwrap();
        }
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        if self.process.try_wait().ok().flatten().is_none() {
            let _ = self.process.kill();
            let _ = wait_exit(&mut self.process);
        }
        self.commands.take();
        self.replies.take();
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Status {
    pub role: u8,
    pub leader: u64,
    pub term: u64,
    pub commit: u64,
    pub applied: u64,
    pub last: u64,
    pub snapshot: u64,
}

impl Status {
    fn from_reply(reply: Reply) -> Self {
        assert_eq!(reply.kind, "status", "{reply:?}");
        assert_eq!(reply.fields.len(), 7);
        let value = |index: usize| reply.fields[index].parse::<u64>().unwrap();
        let status = Self {
            role: u8::try_from(value(0)).unwrap(),
            leader: value(1),
            term: value(2),
            commit: value(3),
            applied: value(4),
            last: value(5),
            snapshot: value(6),
        };
        assert!(status.snapshot <= status.applied);
        assert!(status.applied <= status.commit);
        assert!(status.commit <= status.last);
        status
    }
}

pub struct Cluster {
    pub runtime: tokio::runtime::Runtime,
    pub directory: TempDir,
    pub ca: Vec<u8>,
    pub materials: BTreeMap<u64, Material>,
    pub nodes: BTreeMap<u64, Node>,
    proxies: BTreeMap<(u64, u64), Proxy>,
    test: &'static str,
    next_boot: u128,
    began: Instant,
    history: Vec<String>,
}

impl Cluster {
    pub fn new(test: &'static str, inbox: BTreeMap<u64, (usize, usize)>) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let certificates = directory.path().join("certificates");
        fs::create_dir(&certificates).unwrap();
        let authority = Authority::new();
        let ca = authority.pem();
        fs::write(certificates.join("ca.pem"), &ca).unwrap();
        let mut materials = BTreeMap::new();
        for id in 1..=3 {
            let material = authority.issue(id, false);
            material.write(&certificates, &format!("node{id}"));
            materials.insert(id, material);
        }
        authority.issue(2, false).write(&certificates, "rotated2");
        authority.issue(2, false).write(&certificates, "unbound2");
        authority.issue(2, true).write(&certificates, "expired2");
        Authority::new()
            .issue(2, false)
            .write(&certificates, "foreign2");
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let mut nodes = BTreeMap::new();
        for id in 1..=3 {
            nodes.insert(
                id,
                Node::new(
                    test,
                    id,
                    &directory.path().join(format!("node{id}")),
                    &certificates,
                    u128::from(id),
                    true,
                    inbox.get(&id).copied().unwrap_or((64, 64 * 1024 * 1024)),
                ),
            );
        }
        let mut proxies = BTreeMap::new();
        for from in 1..=3 {
            for to in 1..=3 {
                if from != to {
                    proxies.insert(
                        (from, to),
                        runtime.block_on(Proxy::start(nodes[&to].address)),
                    );
                }
            }
        }
        let mut cluster = Self {
            runtime,
            directory,
            ca,
            materials,
            nodes,
            proxies,
            test,
            next_boot: 4,
            began: Instant::now(),
            history: Vec::new(),
        };
        cluster.record("three independent processes and RocksDB directories ready; ephemeral mTLS certificates generated");
        cluster
    }

    pub fn certificates(&self) -> PathBuf {
        self.directory.path().join("certificates")
    }

    pub fn record(&mut self, event: impl AsRef<str>) {
        assert!(
            self.began.elapsed() < SCENARIO_DEADLINE,
            "scenario work deadline"
        );
        assert!(self.history.len() < 20_000, "bounded evidence item count");
        self.history.push(format!(
            "{}ms {}",
            self.began.elapsed().as_millis(),
            event.as_ref()
        ));
        assert!(self.history.iter().map(String::len).sum::<usize>() <= 8 * 1024 * 1024);
    }

    pub fn start(&mut self, id: u64) {
        let routes = self
            .proxies
            .iter()
            .filter(|((from, _), _)| *from == id)
            .map(|((_, to), proxy)| format!("{to}@{}", proxy.address))
            .collect::<Vec<_>>()
            .join(",");
        let reply = self.nodes.get_mut(&id).unwrap().command("start", &routes);
        assert_eq!(reply.kind, "started", "{reply:?}");
        self.record(format!(
            "node={id} formal runtime automatic tick and fixed mTLS network workers started"
        ));
    }

    pub fn start_all(&mut self) {
        for id in 1..=3 {
            self.start(id);
        }
    }

    pub fn status(&mut self, id: u64) -> Status {
        let reply = self.nodes.get_mut(&id).unwrap().command("status", "2000");
        let status = Status::from_reply(reply);
        if status.role == StateRole::Leader as u8 {
            assert_eq!(status.leader, id);
        }
        self.record(format!("node={id} status={status:?}"));
        status
    }

    pub fn try_read(&mut self, id: u64, millis: u64) -> Result<CellState, String> {
        let reply = self
            .nodes
            .get_mut(&id)
            .unwrap()
            .command("read", &millis.to_string());
        if let Some(error) = reply.error() {
            self.record(format!("node={id} read error={error}"));
            return Err(error);
        }
        assert_eq!(reply.kind, "read");
        assert_eq!(reply.fields.len(), 6);
        let position = Position {
            term: reply.fields[0].parse().unwrap(),
            index: reply.fields[1].parse().unwrap(),
        };
        let boot: u128 = reply.fields[3].parse().unwrap();
        assert_eq!(boot, self.nodes[&id].boot);
        let barrier: u64 = reply.fields[5].parse().unwrap();
        assert!(position.index >= barrier);
        let state = CellState::decode_bound(
            &unhex(&reply.fields[2]),
            common::cell(),
            position,
            common::cell_limits(),
        )
        .unwrap();
        self.record(format!("node={id} SafeReadIndex boot={boot} ticket={} barrier={barrier} application={position:?}", reply.fields[4]));
        Ok(state)
    }

    pub fn leader(&mut self, candidates: &[u64]) -> u64 {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            for id in candidates {
                if self.status(*id).role == StateRole::Leader as u8
                    && self.try_read(*id, 500).is_ok()
                {
                    return *id;
                }
            }
            assert!(Instant::now() < deadline, "no ready leader before deadline");
            thread::sleep(Duration::from_millis(20));
        }
    }

    pub fn propose(&mut self, leader: u64, command: &CellCommand) -> Reply {
        let data = scap_cell::encode_command(command, common::cell_limits()).unwrap();
        let reply = self
            .nodes
            .get_mut(&leader)
            .unwrap()
            .command("propose", &format!("2000 {}", hex(&data)));
        self.record(format!(
            "node={leader} proposal {:?} reply={}",
            command.kind, reply.kind
        ));
        reply
    }

    pub fn initialize(&mut self, leader: u64) {
        for command in common::initialization() {
            assert_eq!(self.propose(leader, &command).kind, "admitted");
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let state = self.try_read(leader, 1000).unwrap();
                let done = match &command.kind {
                    scap_cell::CommandKind::Create { .. } => {
                        state.database(common::DATABASE.database_id).is_some()
                    }
                    scap_cell::CommandKind::ClaimOwner { .. } => state
                        .database(common::DATABASE.database_id)
                        .is_some_and(|db| db.owner == common::OWNER),
                    scap_cell::CommandKind::ActivateOwner { .. } => state
                        .database(common::DATABASE.database_id)
                        .is_some_and(|db| db.active),
                    _ => unreachable!(),
                };
                if done {
                    break;
                }
                assert!(Instant::now() < deadline);
                thread::sleep(Duration::from_millis(10));
            }
        }
    }

    pub fn accepted(&mut self, leader: u64, request: u128, predecessor: u64) -> CellState {
        let command = common::commit(request, predecessor);
        assert_eq!(self.propose(leader, &command).kind, "admitted");
        self.wait_accepted(leader, request, predecessor + 1)
    }

    pub fn wait_accepted(&mut self, leader: u64, request: u128, sequence: u64) -> CellState {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let state = self.try_read(leader, 1000).unwrap();
            if let Lookup::Committed { commit, result } = state
                .lookup(
                    common::DATABASE,
                    common::admission(),
                    request,
                    scap_cell::payload_digest(&request.to_be_bytes()),
                )
                .unwrap()
            {
                assert_eq!(commit.receipt.sequence, sequence);
                assert_eq!(result, format!("original-result-{request}").into_bytes());
                self.record(format!(
                    "request={request} durably accepted sequence={sequence} with original result"
                ));
                return state;
            }
            assert!(Instant::now() < deadline, "request not accepted");
            thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn partition(&mut self, id: u64, mode: Mode) {
        for ((from, to), proxy) in &self.proxies {
            if *from == id || *to == id {
                proxy.set(mode);
            }
        }
        self.record(format!("node={id} bidirectional real TCP mode={mode:?}"));
    }

    pub fn route(&mut self, from: u64, to: u64, mode: Mode) {
        self.proxies[&(from, to)].set(mode);
        self.record(format!("route={from}->{to} real TCP mode={mode:?}"));
    }

    pub fn endpoint(&self, from: u64, to: u64) -> scap_raft_transport::PeerEndpoint {
        scap_raft_transport::PeerEndpoint {
            uri: format!("https://{}/", self.proxies[&(from, to)].address),
            cluster_id: common::CLUSTER,
            node_id: to,
        }
    }

    pub fn accepted_connections(&self, from: u64, to: u64) -> u64 {
        self.proxies[&(from, to)].counters().0
    }

    pub fn stop_node(&mut self, id: u64) {
        self.nodes.get_mut(&id).unwrap().graceful();
        self.nodes.remove(&id);
        self.record(format!(
            "node={id} acknowledged stop, server/network drained, process exited successfully"
        ));
    }

    pub fn kill(&mut self, id: u64) {
        self.nodes.get_mut(&id).unwrap().kill();
        self.nodes.remove(&id);
        self.record(format!(
            "node={id} actual SIGKILL signal=9; native destructors bypassed"
        ));
    }

    pub fn restart(&mut self, id: u64) {
        assert!(!self.nodes.contains_key(&id));
        let node = Node::new(
            self.test,
            id,
            &self.directory.path().join(format!("node{id}")),
            &self.certificates(),
            self.next_boot,
            false,
            (64, 64 * 1024 * 1024),
        );
        self.next_boot += 1;
        for ((_, to), proxy) in &self.proxies {
            if *to == id {
                proxy.retarget(node.address);
            }
        }
        self.nodes.insert(id, node);
        self.record(format!(
            "node={id} strict same-directory reopen with fresh boot"
        ));
        self.start(id);
    }

    pub fn bindings(&self) -> Vec<Binding> {
        self.materials
            .iter()
            .map(|(id, material)| material.binding(*id))
            .collect()
    }

    pub fn set_bindings(&mut self, node: u64, bindings: Vec<Binding>) {
        let payload = if bindings.is_empty() {
            "-".into()
        } else {
            bindings
                .iter()
                .map(|binding| format!("{}:{}", binding.node_id, hex(&binding.fingerprint)))
                .collect::<Vec<_>>()
                .join(",")
        };
        let reply = self.nodes.get_mut(&node).unwrap().command("pins", &payload);
        assert_eq!(reply.kind, "pins", "{reply:?}");
        self.record(format!(
            "node={node} trusted pin replacement revision={}",
            reply.fields[0]
        ));
    }

    pub fn finish(mut self) {
        for node in self.nodes.values_mut() {
            node.graceful();
        }
        self.nodes.clear();
        let proxies = std::mem::take(&mut self.proxies);
        for ((from, to), proxy) in proxies {
            let (accepted, completed_bytes) = proxy.counters();
            self.record(format!(
                "route={from}->{to} accepted_tcp={accepted} completed_copy_bytes={completed_bytes}"
            ));
            self.runtime.block_on(proxy.stop());
        }
        self.record("verification passed");
        self.write_evidence();
    }

    fn write_evidence(&self) {
        let directory = std::env::var_os("SCAP_NETWORK_EVIDENCE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/evidence/raft-network")
            });
        fs::create_dir_all(&directory).unwrap();
        let text = format!(
            "SCAP real mTLS runtime contracts v1\nraft=ad13f3d90780f53aea2488c6a4b76c0d334bf136 tonic=0.14.6 runtime=first-party\nthree independent OS processes; bounded transparent TCP faults; ephemeral CA/leaf material\nwall-clock event times are fixture traces, not a production latency or RTO measurement\n{}\n",
            self.history.join("\n"),
        );
        fs::write(directory.join(format!("{}.log", self.test)), text).unwrap();
    }
}

impl Drop for Cluster {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!(
                "network contract failed; bounded history:\n{}",
                self.history.join("\n")
            );
        }
        self.nodes.clear();
    }
}
