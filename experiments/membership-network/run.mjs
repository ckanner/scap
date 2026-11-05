import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { createReadStream } from "node:fs";
import { appendFile, chmod, mkdir, mkdtemp, open, stat, writeFile } from "node:fs/promises";
import net from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createClient, ScapError } from "../../sdk/node/dist/client.js";
import { readFreshMembership } from "./read-membership.mjs";

// Production daemons own every membership, persistence, authorization and SQL
// decision. This file supplies only process/network faults and independent
// assertions. It is deliberately outside the unit coverage profile.
const root = fileURLToPath(new URL("../../", import.meta.url));
const binary = process.env.SCAP_SERVER_BIN;
assert.ok(binary && path.isAbsolute(binary), "SCAP_SERVER_BIN must be an absolute production binary path");
assert.equal(process.env.LLVM_PROFILE_FILE, undefined, "Do not mix real faults with unit profiles");
assert.equal(process.env.NODE_V8_COVERAGE, undefined, "Do not mix real faults with unit profiles");
const evidence = process.env.SCAP_MEMBERSHIP_EVIDENCE_DIR ?? await mkdtemp(path.join(tmpdir(), "scap-membership-evidence-"));
await mkdir(evidence, { recursive: true, mode: 0o700 });
await chmod(evidence, 0o700);
const scratch = await mkdtemp(path.join(tmpdir(), "scap-membership-fixture-"));
const hash = createHash("sha256");
for await (const bytes of createReadStream(binary)) hash.update(bytes);
await writeFile(path.join(evidence, "binary.json"), JSON.stringify({ binary, sha256: hash.digest("hex"), description: process.env.SCAP_SERVICE_BUILD_DESCRIPTION ?? "current local working tree" }, null, 2), { flag: "wx", mode: 0o600 });
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const identity = (number) => BigInt(number).toString(16).padStart(32, "0");
const digest = (text) => createHash("sha256").update(text).digest("hex");
const resources = [];
const completed = [];
let history;

async function event(name, values = {}) {
  const line = JSON.stringify({ elapsed_ms: Math.round(performance.now()), event: name, ...values });
  if (history) await appendFile(history, line + "\n");
  process.stdout.write(line + "\n");
}

async function contract(name, run) {
  history = path.join(evidence, name + ".history.jsonl");
  await writeFile(history, "", { flag: "wx", mode: 0o600 });
  await event("contract_started", { name });
  try {
    await run();
    for (const resource of resources) resource.assertNoUnexpectedExit();
    await event("contract_completed", { name });
    await appendFile(history, "verification passed\n");
    completed.push(name);
  } catch (error) {
    await event("contract_failed", { name, message: error.message });
    throw error;
  } finally { history = undefined; }
}

async function command(program, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(program, args, { cwd: root, env: process.env, stdio: ["ignore", "pipe", "pipe"], ...options });
    let output = "";
    child.stdout.on("data", (data) => { output = (output + data.toString()).slice(-256_000); });
    child.stderr.on("data", (data) => { output = (output + data.toString()).slice(-256_000); });
    child.once("error", () => reject(new Error(path.basename(program) + " failed to start")));
    child.once("exit", (code) => {
      if (code === 0) resolve(output);
      else reject(new Error(path.basename(program) + " exited " + code + (options.private ? " (private fixture output retained locally)" : ": " + output)));
    });
  });
}

async function processAt(args, filename, extraEnv = {}) {
  const file = await open(filename, "a", 0o600);
  const child = spawn(binary, args, { cwd: root, env: { ...process.env, ...extraEnv }, stdio: ["ignore", file.fd, file.fd] });
  const state = { child, exit: null, plannedStop: false, unexpectedExit: false };
  state.done = new Promise((resolve, reject) => {
    child.once("error", () => reject(new Error("production daemon failed to start")));
    child.once("exit", (code, signal) => {
      state.exit = { code, signal };
      state.unexpectedExit = !state.plannedStop;
      resolve(state.exit);
    });
  });
  await file.close();
  state.stop = async (signal = "SIGKILL") => {
    if (state.exit) return;
    state.plannedStop = true;
    child.kill(signal);
    if (!await Promise.race([state.done.then(() => true), delay(5000).then(() => false)])) {
      child.kill("SIGKILL"); await state.done;
    }
  };
  return state;
}

async function freePort() {
  const listener = net.createServer();
  await new Promise((resolve, reject) => { listener.once("error", reject); listener.listen(0, "127.0.0.1", resolve); });
  const port = listener.address().port;
  await new Promise((resolve) => listener.close(resolve));
  return port;
}

class Proxy {
  blocked = false;
  sockets = new Set();
  constructor(source, destination, port) {
    this.source = source; this.destination = destination;
    this.listener = net.createServer((client) => {
      client.setNoDelay(true); this.track(client);
      if (this.blocked) { client.pause(); return; }
      const upstream = net.connect({ host: "127.0.0.1", port });
      upstream.setNoDelay(true); this.track(upstream);
      client.on("error", () => upstream.destroy());
      upstream.on("error", () => client.destroy());
      client.on("close", () => upstream.destroy());
      upstream.on("close", () => client.destroy());
      client.pipe(upstream); upstream.pipe(client);
    });
  }
  track(socket) { this.sockets.add(socket); socket.on("error", () => {}); socket.on("close", () => this.sockets.delete(socket)); }
  async start() {
    await new Promise((resolve, reject) => { this.listener.once("error", reject); this.listener.listen(0, "127.0.0.1", resolve); });
    this.port = this.listener.address().port;
  }
  block(value) { this.blocked = value; for (const socket of this.sockets) socket.destroy(); }
  async stop() { this.block(true); await new Promise((resolve) => this.listener.close(resolve)); }
}

async function certificates(directory, clusterId) {
  await mkdir(directory, { mode: 0o700 });
  const ca = path.join(directory, "ca.pem");
  const key = path.join(directory, "ca.key");
  await command("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "2", "-subj", "/CN=SCAP ephemeral membership CA", "-keyout", key, "-out", ca], { private: true });
  await chmod(key, 0o600);
  const leaves = [];
  for (const node of [1, 2, 3, 4, 5]) {
    const base = path.join(directory, "node-" + node);
    const dns = `node-${node}.cluster-${clusterId}.scap.internal`;
    await command("openssl", ["req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256", "-subj", "/CN=" + dns, "-keyout", base + ".key", "-out", base + ".csr"], { private: true });
    await writeFile(base + ".ext", `basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:${dns}\n`, { mode: 0o600 });
    await command("openssl", ["x509", "-req", "-in", base + ".csr", "-CA", ca, "-CAkey", key, "-set_serial", String(node + 1), "-days", "2", "-sha256", "-extfile", base + ".ext", "-out", base + ".pem"], { private: true });
    await command("openssl", ["x509", "-in", base + ".pem", "-outform", "DER", "-out", base + ".der"], { private: true });
    await chmod(base + ".key", 0o600);
    leaves.push({ pem: base + ".pem", key: base + ".key", der: base + ".der" });
  }
  return { ca, leaves };
}

function conf(value) {
  return {
    voters: [...value.voters].sort((a, b) => a - b),
    learners: [...value.learners].sort((a, b) => a - b),
    voters_outgoing: [...value.voters_outgoing].sort((a, b) => a - b),
    learners_next: [...value.learners_next].sort((a, b) => a - b),
    auto_leave: value.auto_leave,
  };
}

class Cluster {
  processes = [];
  allProcesses = [];
  proxies = [];
  membershipReads = 0;
  expected = { alpha: [], beta: [] };
  async start() {
    this.directory = path.join(scratch, "replicas");
    await mkdir(this.directory, { mode: 0o700 });
    const clusterId = identity(41);
    const certs = await certificates(path.join(this.directory, "certs"), clusterId);
    const used = new Set();
    const port = async () => { for (;;) { const number = await freePort(); if (!used.has(number)) { used.add(number); return number; } } };
    this.http = []; this.peer = []; this.management = [];
    for (let node = 0; node < 5; node++) { this.http.push(await port()); this.peer.push(await port()); this.management.push(await port()); }
    // Node 5 is only a pretrusted future candidate, used to prove that a valid
    // configuration proposal cannot complete without quorum. Four daemons run.
    this.endpoints = this.http.slice(0, 4).map((port) => "http://127.0.0.1:" + port);
    this.tokens = { alpha: randomBytes(32).toString("hex"), beta: randomBytes(32).toString("hex"), administrator: randomBytes(32).toString("hex") };
    this.configs = []; this.configuration = [];
    for (let source = 0; source < 5; source++) {
      const peers = [];
      for (let destination = 0; destination < 5; destination++) {
        const proxy = new Proxy(source, destination, this.peer[destination]);
        await proxy.start(); this.proxies.push(proxy);
        peers.push({ node_id: destination + 1, uri: "https://127.0.0.1:" + proxy.port, certificate_der: certs.leaves[destination].der });
      }
      const config = {
        version: 1, cluster_id: clusterId, cell_id: identity(42), cell_incarnation: 1, node_id: source + 1,
        administrator_id: identity(100), service_credential_id: identity(101),
        bootstrap_voters: [1, 2, 3], peers, idle_seconds: 3600,
        data_dir: path.join(this.directory, "data-" + (source + 1)),
        http_listen: "127.0.0.1:" + this.http[source], peer_listen: "127.0.0.1:" + this.peer[source],
        certificate_pem: certs.leaves[source].pem, private_key_pem: certs.leaves[source].key, ca_pem: certs.ca,
        management: { listen: "127.0.0.1:" + this.management[source], token_sha256: digest(this.tokens.administrator) },
        databases: ["alpha", "beta"].map((name, index) => ({
          name, database_id: identity(43 + index), incarnation: 1, placement_generation: 1,
          tokens: [{ sha256: digest(this.tokens[name]), principal_id: identity(200 + 10 * index), credential_id: identity(201 + 10 * index), auth_epoch: 1, permissions: 3 }],
        })),
      };
      const filename = path.join(this.directory, "node-" + (source + 1) + ".json");
      await writeFile(filename, JSON.stringify(config), { mode: 0o600 });
      this.configs.push(filename); this.configuration.push(config);
    }
    resources.push(this);
    for (let node = 0; node < 3; node++) await this.launch(node, "--initialize");
    await this.waitLeader();
  }
  async launch(node, mode) {
    const extra = mode === "--join" ? {
      SCAP_JOIN_MANAGEMENT_URL: "http://127.0.0.1:" + this.management[await this.waitLeader()],
      SCAP_MANAGEMENT_TOKEN: this.tokens.administrator,
    } : {};
    this.processes[node] = await processAt([...(mode ? [mode] : []), this.configs[node]], path.join(this.directory, "node-" + (node + 1) + ".private.log"), extra);
    this.allProcesses.push({ node, state: this.processes[node] });
  }
  assertNoUnexpectedExit() {
    for (const { node, state } of this.allProcesses) {
      assert.equal(state.unexpectedExit, false, "Unexpected production daemon exit for node " + (node + 1) + ": " + JSON.stringify(state.exit));
    }
  }
  client(database = "alpha", excluded = [], timeoutMs = 5000) {
    return createClient({ endpoints: this.endpoints.filter((_, node) => !excluded.includes(node)), database, authToken: this.tokens[database], timeoutMs });
  }
  isolate(node, blocked) { for (const proxy of this.proxies) if (proxy.source === node || proxy.destination === node) proxy.block(blocked); }
  async ready(node) {
    try {
      const reply = await fetch(this.endpoints[node] + "/readyz", { redirect: "manual", signal: AbortSignal.timeout(600) });
      await reply.body?.cancel(); return reply.status === 200;
    } catch { return false; }
  }
  async waitLeader(excluded = [], budget = 30_000) {
    const end = performance.now() + budget;
    while (performance.now() < end) {
      this.assertNoUnexpectedExit();
      for (let node = 0; node < 4; node++) if (!excluded.includes(node) && await this.ready(node)) return node;
      await delay(100);
    }
    throw new Error("No ready leader before the original recovery budget");
  }
  async admin(node, method = "GET", body, token = this.tokens.administrator, resource = "membership") {
    const response = await fetch("http://127.0.0.1:" + this.management[node] + "/v1/admin/" + resource, {
      method, redirect: "manual", signal: AbortSignal.timeout((body?.deadline_ms ?? 5000) + 1500),
      headers: { authorization: "Bearer " + token, ...(body ? { "content-type": "application/json" } : {}) },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    const data = await response.json();
    return { status: response.status, data };
  }
  async localStatus(node) {
    const end = performance.now() + 5000;
    let last;
    do {
      try {
        last = await this.admin(node, "GET", undefined, this.tokens.administrator, "status");
        if (last.status === 200) {
          assert.equal(last.data.authoritative, false, "local observation must not be presented as a linearizable configuration read");
          assert.equal(last.data.node_id, node + 1);
          return last.data.status;
        }
      } catch (error) { if (error instanceof assert.AssertionError) throw error; }
      await delay(50);
    } while (performance.now() < end);
    throw new Error("Local diagnostic endpoint did not become available for node " + (node + 1));
  }
  async membership(excluded = []) {
    const read = ++this.membershipReads;
    return readFreshMembership({
      nodes: [0, 1, 2, 3].filter((node) => !excluded.includes(node)),
      readinessUrl: (node) => this.endpoints[node] + "/readyz",
      membershipUrl: (node) => "http://127.0.0.1:" + this.management[node] + "/v1/admin/membership",
      token: this.tokens.administrator,
      record: (attempt) => event("membership_read_attempt", { read, ...attempt }),
      assertLive: () => this.assertNoUnexpectedExit(),
    });
  }
  async change(action, fields = {}, expected) {
    const { leader, view } = await this.membership();
    const result = await this.admin(leader, "POST", { action, ...fields, expected_conf_state: expected ?? conf(view.conf_state), deadline_ms: 5000 });
    await event("membership_change_result", { action, ...fields, http_status: result.status, code: result.data.code ?? null, outcome: result.data.outcome ?? null });
    assert.equal(result.status, 200, "one membership proposal must complete under a healthy quorum");
    assert.equal(result.data.outcome, "applied", "proposal admission alone is not completion");
    return result.data.membership;
  }
  async write(database, number) {
    const client = this.client(database);
    const marker = randomBytes(16).toString("hex");
    try {
      await client.execute({ sql: "INSERT INTO witness(id,marker) VALUES (?,?)", args: [BigInt(number), marker] });
      this.expected[database].push([BigInt(number), marker]);
    } finally { client.close(); }
  }
  async verify(excluded = []) {
    const recovery = {};
    for (const database of ["alpha", "beta"]) {
      const client = this.client(database, excluded);
      try {
        const actual = (await client.query("SELECT id,marker FROM witness ORDER BY id")).rows.map((row) => Array.from(row));
        assert.deepEqual(actual, this.expected[database], "every acknowledged row must remain exact after membership changes");
        const status = await client.status();
        assert.ok(status.baseRevision > 0n, "the SQL witness must recover from a nonzero physical base");
        assert.ok(status.baseRevision <= status.revision && status.tailEntries < 8n);
        assert.ok(status.tailBytes < 1_228_800n);
        assert.equal(status.cold, false, "this experiment never prunes its quorum-resident physical base to S3");
        recovery[database] = { revision: status.revision.toString(), base_revision: status.baseRevision.toString(), tail_entries: status.tailEntries.toString(), tail_bytes: status.tailBytes.toString() };
      } finally { client.close(); }
    }
    await event("all_acknowledged_rows_verified", { alpha: this.expected.alpha.length, beta: this.expected.beta.length, lost_acknowledgements: 0, recovery });
  }
  async stop() {
    for (const state of this.processes) await state?.stop();
    for (const proxy of this.proxies) await proxy.stop();
    this.proxies = [];
  }
}

const cluster = new Cluster();
let removed;
let initialConf;
let learnerGenesis;
let baseObservedBy;

try {
  await contract("01-original-quorum-and-unjoined-node", async () => {
    await cluster.start();
    for (const database of ["alpha", "beta"]) {
      const client = cluster.client(database);
      try { await client.execute("CREATE TABLE witness(id INTEGER PRIMARY KEY,marker TEXT NOT NULL)"); }
      finally { client.close(); }
    }
    initialConf = conf((await cluster.membership()).view.conf_state);
    assert.deepEqual(initialConf, { voters: [1, 2, 3], learners: [], voters_outgoing: [], learners_next: [], auto_leave: false });
    await cluster.launch(3, "--join");
    const joined = await cluster.localStatus(3);
    assert.equal(joined.is_voter, false);
    assert.equal(joined.snapshot_index, 1, "Join must use the same nonempty durable genesis as original voters");
    assert.equal(joined.applied, 1);
    learnerGenesis = joined;
    assert.equal(await cluster.ready(3), false, "pretrusted but unjoined node cannot serve");
    await event("unjoined_node_remains_nonvoting", { node_id: 4, conf_state: initialConf });
  });

  await contract("02-management-authorization-and-cas", async () => {
    const { leader } = await cluster.membership();
    for (const token of [cluster.tokens.alpha, randomBytes(32).toString("hex")]) {
      const denied = await cluster.admin(leader, "GET", undefined, token);
      assert.ok([401, 403].includes(denied.status), "tenant or invalid token cannot read cluster management state");
      const writeDenied = await cluster.admin(leader, "POST", { action: "add_learner", node_id: 4, expected_conf_state: initialConf, deadline_ms: 1000 }, token);
      assert.ok([401, 403].includes(writeDenied.status), "tenant or invalid token cannot change membership");
    }
    const invalidPeer = await cluster.admin(leader, "POST", { action: "add_learner", node_id: 99, expected_conf_state: initialConf, deadline_ms: 1000 });
    assert.notEqual(invalidPeer.status, 200, "an unregistered identity must not enter Raft configuration");
    const wrong = { ...initialConf, voters: [1, 2, 4] };
    const stale = await cluster.admin(leader, "POST", { action: "add_learner", node_id: 4, expected_conf_state: wrong, deadline_ms: 1000 });
    assert.equal(stale.status, 409, "configuration CAS must reject a mismatched starting configuration");
    assert.equal(stale.data.code, "MEMBERSHIP_CONFLICT");
    assert.deepEqual(conf((await cluster.membership()).view.conf_state), initialConf);
    await event("management_boundaries_verified", { tenant_token_denied: true, unregistered_peer_denied: true, stale_configuration_denied: true });
  });

  await contract("03-lagging-learner-cannot-be-promoted", async () => {
    cluster.isolate(3, true);
    const learner = await cluster.change("add_learner", { node_id: 4 });
    assert.deepEqual(conf(learner.conf_state), { ...initialConf, learners: [4] });
    await cluster.write("alpha", 1);
    const { leader, view } = await cluster.membership();
    removed = [0, 1, 2].find((node) => node !== leader);
    const early = await cluster.admin(leader, "POST", { action: "replace_voter", node_id: 4, remove_id: removed + 1, expected_conf_state: conf(view.conf_state), deadline_ms: 1000 });
    assert.equal(early.status, 409, "a learner behind the durable commit cannot be promoted");
    assert.equal(early.data.code, "LEARNER_NOT_CAUGHT_UP");
    assert.deepEqual(conf((await cluster.membership()).view.conf_state), { ...initialConf, learners: [4] });
    await event("promotion_rejected_before_catchup", { learner: 4, replace_candidate: removed + 1, code: early.data.code ?? null });
  });

  await contract("04-compacted-history-catches-up-new-replica", async () => {
    // More than the production checkpoint distance, while each database stays
    // below its existing 128-request budget. No test-only checkpoint shortcut.
    for (let number = 2; number <= 67; number++) {
      await cluster.write("alpha", number);
      await cluster.write("beta", number);
      if (number === 10) {
        const bases = {};
        for (const database of ["alpha", "beta"]) {
          const client = cluster.client(database);
          try {
            const status = await client.status();
            assert.ok(status.baseRevision > 0n, "physical history must fold before the Raft snapshots being tested");
            assert.equal(status.cold, false);
            bases[database] = { revision: status.revision.toString(), base_revision: status.baseRevision.toString(), tail_entries: status.tailEntries.toString(), tail_bytes: status.tailBytes.toString() };
          } finally { client.close(); }
        }
        // This is an authoritative applied upper bound AFTER both fresh
        // database reads. Every subsequent snapshot above B must therefore
        // contain a nonzero base for both databases. We do not present a
        // leader's tenant status as a direct read of the learner's contents.
        baseObservedBy = (await cluster.membership()).view.applied;
        assert.ok(Number.isSafeInteger(baseObservedBy) && baseObservedBy > learnerGenesis.applied);
        await event("physical_bases_exist_before_snapshot_boundary", { authoritative_applied_upper_bound: baseObservedBy, databases: bases, learner_directly_inspected: false });
      }
    }
    const end = performance.now() + 15_000;
    let source;
    let compacted;
    do {
      source = (await cluster.membership()).view;
      compacted = await Promise.all([0, 1, 2].map((node) => cluster.localStatus(node)));
      if (compacted.every((status) => status.snapshot_index > baseObservedBy)) break;
      await delay(100);
    } while (performance.now() < end);
    assert.ok(compacted.every((status) => status.snapshot_index > baseObservedBy), "every original voter must compact beyond the authoritative bound after both physical bases were observed, so every possible source snapshot contains them");
    const compactedThrough = Math.min(...compacted.map((status) => status.snapshot_index));
    const isolated = await cluster.localStatus(3);
    assert.equal(isolated.applied, learnerGenesis.applied, "isolated learner must still be behind the compacted prefix");
    assert.equal(isolated.snapshot_index, learnerGenesis.snapshot_index);
    cluster.isolate(3, false);
    const caughtUpBy = performance.now() + 30_000;
    let caught;
    let installed;
    do {
      const view = (await cluster.membership()).view;
      const progress = view.progress.find((peer) => peer.node_id === 4);
      installed = await cluster.localStatus(3);
      if (progress && progress.matched >= view.commit && installed.snapshot_index >= compactedThrough && installed.applied >= source.commit) { caught = view; break; }
      await delay(100);
    } while (performance.now() < caughtUpBy);
    assert.ok(caught, "learner must durably catch up and apply the source head through the real Raft transport");
    assert.ok(installed.snapshot_index >= compactedThrough, "new replica must hold a real durable snapshot after all original voters compact their logs");
    assert.ok(installed.applied >= source.commit, "new replica must durably apply the source head");
    assert.equal(await cluster.ready(3), false, "caught-up learner still cannot serve as leader");
    await event("learner_caught_up_after_compaction", { isolated_learner_applied: isolated.applied, base_observed_by_applied: baseObservedBy, original_voter_snapshots: compacted.map((status, node) => ({ node_id: node + 1, snapshot_index: status.snapshot_index, applied: status.applied })), compacted_through: compactedThrough, source_snapshot_index: source.snapshot_index, learner_snapshot_index: installed.snapshot_index, learner_applied: installed.applied, commit: caught.commit, progress: caught.progress, base_transfer_proof: "fresh source base observations, all sources compact beyond that bound, real learner snapshot install, then exact SQL and unique-node4-disk ACK recovery" });
    await cluster.verify();
  });

  await contract("05-joint-configuration-survives-process-restart", async () => {
    const { leader } = await cluster.membership();
    removed = [0, 1, 2].find((node) => node !== leader);
    await cluster.processes[removed].stop("SIGKILL");
    const joint = await cluster.change("replace_voter", { node_id: 4, remove_id: removed + 1 });
    const expected = { voters: [1, 2, 3].filter((node) => node !== removed + 1).concat(4).sort(), learners: [], voters_outgoing: [1, 2, 3], learners_next: [], auto_leave: false };
    assert.deepEqual(conf(joint.conf_state), expected, "replacement must enter explicit joint consensus");
    for (const state of cluster.processes) await state?.stop("SIGKILL");
    for (let node = 0; node < 4; node++) if (node !== removed) await cluster.launch(node);
    await cluster.waitLeader([removed]);
    const reopened = await cluster.membership([removed]);
    assert.deepEqual(conf(reopened.view.conf_state), expected, "restart must retain both joint majorities");
    await cluster.verify([removed]);
    await event("joint_configuration_reopened", { removed_node: removed + 1, conf_state: expected });
  });

  await contract("06-final-membership-and-old-node-return", async () => {
    const stable = await cluster.change("leave_joint");
    const voters = [1, 2, 3].filter((node) => node !== removed + 1).concat(4).sort();
    assert.deepEqual(conf(stable.conf_state), { voters, learners: [], voters_outgoing: [], learners_next: [], auto_leave: false });
    await cluster.write("beta", 68);
    await cluster.launch(removed);
    await delay(1000);
    assert.equal(await cluster.ready(removed), false, "removed node must never restore public readiness");
    const managementLeader = await cluster.waitLeader([removed]);
    const reused = await cluster.admin(managementLeader, "POST", { action: "add_learner", node_id: removed + 1, expected_conf_state: conf(stable.conf_state), deadline_ms: 1000 });
    assert.notEqual(reused.status, 200, "a removed old identity must never be enrolled again");
    const duplicate = { ...cluster.configuration[3], data_dir: path.join(cluster.directory, "duplicate-voter-4") };
    const duplicateConfig = path.join(cluster.directory, "duplicate-voter-4.json");
    await writeFile(duplicateConfig, JSON.stringify(duplicate), { mode: 0o600 });
    await assert.rejects(command(binary, ["--join", duplicateConfig], { private: true, env: {
      ...process.env, SCAP_MANAGEMENT_TOKEN: cluster.tokens.administrator,
      SCAP_JOIN_MANAGEMENT_URL: "http://127.0.0.1:" + cluster.management[managementLeader],
    } }), "an already enrolled voter cannot use an empty directory to join under its old ID");
    await assert.rejects(stat(duplicate.data_dir), { code: "ENOENT" }, "rejected Join must not initialize a new data directory");
    await cluster.verify([removed]);
    const result = await command(binary, ["--membership", cluster.configs[await cluster.waitLeader([removed])]], { env: { ...process.env, SCAP_MANAGEMENT_TOKEN: cluster.tokens.administrator } });
    const cli = JSON.parse(result);
    assert.deepEqual(conf((cli.membership ?? cli).conf_state), conf(stable.conf_state), "management CLI must use the real authenticated strong-read endpoint");
    await event("old_node_cannot_rejoin_by_reopen", { removed_node: removed + 1, active_voters: voters, management_cli_verified: true, duplicate_voter_join_rejected_before_directory_creation: true });
  });

  await contract("07-new-voter-quorum-preserves-acknowledged-sql", async () => {
    // Force an election that needs the replacement voter: stop one surviving
    // original voter, leaving precisely one original voter plus node 4.
    const original = [0, 1, 2].find((node) => node !== removed);
    await cluster.processes[original].stop("SIGKILL");
    const survivors = [0, 1, 2, 3].filter((node) => ![removed, original].includes(node));
    cluster.isolate(removed, true);
    await cluster.waitLeader([removed, original]);
    const client = cluster.client("alpha", [removed, original]);
    const marker = randomBytes(16).toString("hex");
    try {
      await client.execute({ sql: "INSERT INTO witness(id,marker) VALUES (?,?)", args: [68n, marker] });
      cluster.expected.alpha.push([68n, marker]);
    } finally { client.close(); }
    await cluster.verify([removed, original]);
    // The new ACK existed only on node 4 and the other surviving original
    // voter. Kill both. Restart node 4 with the original voter stopped BEFORE
    // that write; the only possible source of the new ACK is node 4's disk.
    for (const node of survivors) await cluster.processes[node].stop("SIGKILL");
    const heldOriginal = survivors.find((node) => node !== 3);
    await cluster.launch(original);
    await cluster.launch(3);
    await cluster.waitLeader([removed, heldOriginal]);
    await cluster.verify([removed, heldOriginal]);
    await event("replacement_voter_is_part_of_durable_quorum", { write_survivors: survivors.map((node) => node + 1), restart_survivors: [original + 1, 4], new_ack_source: 4, original_ack_holder_kept_stopped: heldOriginal + 1 });
    await cluster.launch(heldOriginal);
    cluster.isolate(removed, false);
  });

  await contract("08-no-quorum-never-forces-membership", async () => {
    const { leader, view } = await cluster.membership([removed]);
    cluster.isolate(leader, true);
    const isolated = cluster.client("alpha", [0, 1, 2, 3].filter((node) => node !== leader), 1000);
    try { await assert.rejects(isolated.query("SELECT COUNT(*) FROM witness"), ScapError); }
    finally { isolated.close(); }
    const attempted = await cluster.admin(leader, "POST", { action: "add_learner", node_id: 5, expected_conf_state: conf(view.conf_state), deadline_ms: 1000 });
    assert.notEqual(attempted.status, 200, "minority cannot acknowledge a membership transition");
    cluster.isolate(leader, false);
    await cluster.waitLeader([removed]);
    const resolved = (await cluster.membership([removed])).view;
    await cluster.verify([removed]);
    await event("minority_management_and_strong_read_rejected", { isolated_node: leader + 1, http_status: attempted.status, code: attempted.data.code ?? null, final_conf_state: conf(resolved.conf_state), late_commit_after_quorum_return_is_possible: true });
  });

  assert.equal(cluster.expected.alpha.length + cluster.expected.beta.length, 135);
  await writeFile(path.join(evidence, "summary.json"), JSON.stringify({ completed, all_contracts_passed: completed.length === 8, acknowledged_rows: { alpha: cluster.expected.alpha.length, beta: cluster.expected.beta.length }, lost_acknowledgements: 0, base_observed_by_applied: baseObservedBy, base_snapshot_transfer_proof: "combined authoritative source/snapshot/SQL/disk evidence; no direct learner database metadata endpoint", production_slo_passed: false, private_fixture_data_exported: false }, null, 2), { flag: "wx", mode: 0o600 });
  await event("all_membership_contracts_completed", { count: completed.length, production_slo_passed: false });
} finally {
  for (const resource of resources.reverse()) await resource.stop();
}
