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
use scap_cell::{CellState, Position};
use tempfile::TempDir;

use crate::certs::Authority;
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
    pending: Option<u64>,
    held: BTreeMap<u64, Reply>,
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
            pending: None,
            held: BTreeMap::new(),
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

    fn send(&mut self, command: &str, arguments: &str) -> u64 {
        let deadline = Instant::now() + REQUEST_DEADLINE;
        self.sequence += 1;
        let bytes = format!("{command} {} {arguments}\n", self.sequence).into_bytes();
        assert!(bytes.len() <= REQUEST_BYTES);
        self.commands.as_ref().unwrap().try_send(bytes).unwrap();
        self.writes
            .recv_timeout(remaining(deadline))
            .expect("control write deadline")
            .unwrap();
        self.sequence
    }

    pub fn begin(&mut self, command: &str, arguments: &str) {
        assert!(self.pending.is_none(), "only one outstanding SQL request");
        let sequence = self.send(command, arguments);
        self.pending = Some(sequence);
    }

    fn receive_sequence(&mut self, sequence: u64) -> Reply {
        let deadline = Instant::now() + REQUEST_DEADLINE;
        loop {
            if let Some(reply) = self.held.remove(&sequence) {
                return reply;
            }
            let reply = self
                .replies
                .as_ref()
                .unwrap()
                .recv_timeout(remaining(deadline))
                .expect("control response deadline")
                .unwrap();
            if reply.sequence == sequence {
                return reply;
            }
            assert!(self.held.len() < 4, "bounded out-of-order observations");
            assert!(self.held.insert(reply.sequence, reply).is_none());
        }
    }

    pub fn receive(&mut self) -> Reply {
        let sequence = self.pending.take().expect("no outstanding SQL request");
        self.receive_sequence(sequence)
    }

    pub fn command(&mut self, command: &str, arguments: &str) -> Reply {
        let sequence = self.send(command, arguments);
        self.receive_sequence(sequence)
    }

    pub fn assert_no_reply(&self) {
        assert!(!self.held.contains_key(&self.pending.unwrap()));
        assert!(
            matches!(
                self.replies.as_ref().unwrap().try_recv(),
                Err(mpsc::TryRecvError::Empty)
            ),
            "SQL acknowledged before the paused gate returned"
        );
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
        for id in 1..=3 {
            let material = authority.issue(id, false);
            material.write(&certificates, &format!("node{id}"));
        }
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

    pub fn initialize(&mut self, leader: u64) {
        let reply = self
            .nodes
            .get_mut(&leader)
            .unwrap()
            .command("create", "5000 1");
        assert_eq!(reply.kind, "applied", "{reply:?}");
        assert!(String::from_utf8(unhex(&reply.fields[0]))
            .unwrap()
            .contains("Created"));
        let state = self.try_read(leader, 2000).unwrap();
        assert_eq!(
            state
                .database(common::DATABASE.database_id)
                .unwrap()
                .revision,
            0
        );
        self.record("database created through the formal correlated CellClient");
    }

    pub fn writer_directory(&self, node: u64, incarnation: u128) -> PathBuf {
        self.directory
            .path()
            .join(format!("writer-{node}-{incarnation}"))
    }

    pub fn recover(
        &mut self,
        node: u64,
        worker: u128,
        expected_epoch: u64,
        auth_epoch: u64,
    ) -> PathBuf {
        let directory = self.writer_directory(node, worker);
        assert!(
            !directory.exists(),
            "recovery must use an entirely new cache directory"
        );
        let reply = self.nodes.get_mut(&node).unwrap().command(
            "recover",
            &format!("5000 {worker} {expected_epoch} {auth_epoch} {}", worker * 2),
        );
        assert_eq!(reply.kind, "recovered", "{reply:?}");
        assert_eq!(reply.fields[0].parse::<u64>().unwrap(), expected_epoch + 1);
        self.record(format!(
            "node={node} worker={worker} formal claim/recover/activate completed in new directory"
        ));
        directory.join("database.sqlite")
    }

    pub fn begin_sql(
        &mut self,
        node: u64,
        request: u128,
        auth_epoch: u64,
        hook: &str,
        statements: &[scap_sql::Statement],
    ) {
        // The bounded fixture control protocol deliberately supports only
        // parameterless batches; public SQL request encoding belongs to the
        // production SQL/SDK layer, not to this test harness.
        assert!(!statements.is_empty());
        assert!(statements
            .iter()
            .all(|statement| statement.parameters.is_empty()));
        let statements = statements
            .iter()
            .map(|statement| hex(statement.sql.as_bytes()))
            .collect::<Vec<_>>()
            .join(",");
        self.nodes.get_mut(&node).unwrap().begin(
            "sql",
            &format!("2500 {request} {auth_epoch} {hook} {statements}"),
        );
        self.record(format!(
            "node={node} SQL request={request} hook={hook} issued"
        ));
    }

    pub fn sql(
        &mut self,
        node: u64,
        request: u128,
        auth_epoch: u64,
        statements: &[scap_sql::Statement],
    ) -> Reply {
        self.begin_sql(node, request, auth_epoch, "none", statements);
        self.nodes.get_mut(&node).unwrap().receive()
    }

    fn hook_path(&self, node: u64, request: u128, extension: &str) -> PathBuf {
        self.directory
            .path()
            .join(format!("hook-{node}-{request}.{extension}"))
    }

    pub fn wait_hook(&mut self, node: u64, request: u128) -> String {
        let path = self.hook_path(node, request, "ready");
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(text) = fs::read_to_string(&path) {
                self.nodes[&node].assert_no_reply();
                self.record(format!(
                    "node={node} request={request} formal port paused: {text}"
                ));
                return text;
            }
            assert!(
                Instant::now() < deadline,
                "gate never reached the required pause"
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    pub fn resume(&mut self, node: u64, request: u128) {
        fs::write(self.hook_path(node, request, "continue"), b"continue").unwrap();
        self.record(format!("node={node} request={request} gate resumed"));
    }

    pub fn apply(&mut self, node: u64, command: &str, arguments: &str) -> String {
        let reply = self
            .nodes
            .get_mut(&node)
            .unwrap()
            .command(command, arguments);
        assert_eq!(reply.kind, "applied", "{reply:?}");
        let outcome = String::from_utf8(unhex(&reply.fields[0])).unwrap();
        self.record(format!("node={node} ordered {command}: {outcome}"));
        outcome
    }

    pub fn partition(&mut self, id: u64, mode: Mode) {
        for ((from, to), proxy) in &self.proxies {
            if *from == id || *to == id {
                proxy.set(mode);
            }
        }
        self.record(format!("node={id} bidirectional real TCP mode={mode:?}"));
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
        let directory = std::env::var_os("SCAP_SQL_NETWORK_EVIDENCE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/evidence/sqlite-network")
            });
        fs::create_dir_all(&directory).unwrap();
        let text = format!(
            "SCAP real SQL and mTLS durable cell contracts v1\nraft=ad13f3d90780f53aea2488c6a4b76c0d334bf136 tonic=0.14.6 runtime=first-party\nthree independent voter OS processes; dedicated SQL threads; bounded transparent TCP faults; ephemeral CA/leaf material\nwall-clock event times are fixture traces, not a production latency or RTO measurement\n{}\n",
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
