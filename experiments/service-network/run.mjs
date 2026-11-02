import assert from "node:assert/strict";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import { createReadStream } from "node:fs";
import { mkdir, mkdtemp, writeFile, appendFile, open, chmod } from "node:fs/promises";
import net from "node:net";
import { tmpdir, cpus, totalmem, platform, release, arch } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { createClient, ScapError } from "../../sdk/node/dist/client.js";

// Only fault controls and assertions live here. SQL, authentication, ownership,
// Raft, archive and recovery always execute the production binary and SDK.
const root = fileURLToPath(new URL("../../", import.meta.url));
const require = createRequire(new URL("../../sdk/node/package.json", import.meta.url));
const { createClient: libsqlClient } = require("@libsql/client/http");
const binary = process.env.SCAP_SERVER_BIN;
assert.ok(binary && path.isAbsolute(binary), "SCAP_SERVER_BIN must name the built production binary");
assert.equal(process.env.NODE_V8_COVERAGE, undefined, "Real contracts must not contribute to unit coverage");
assert.equal(process.env.LLVM_PROFILE_FILE, undefined, "Run the stable production binary outside the unit coverage profile");
const evidence = process.env.SCAP_SERVICE_NETWORK_EVIDENCE_DIR ?? await mkdtemp(path.join(tmpdir(), "scap-service-network-"));
await mkdir(evidence, { recursive: true, mode: 0o700 });
await chmod(evidence, 0o700);
const digest = createHash("sha256");
for await (const chunk of createReadStream(binary)) digest.update(chunk);
const build = { path: binary, sha256: digest.digest("hex"), profile: path.basename(path.dirname(binary)), description: process.env.SCAP_SERVICE_BUILD_DESCRIPTION ?? "current local working tree" };
await writeFile(path.join(evidence, "binary.json"), JSON.stringify(build, null, 2), { flag: "wx", mode: 0o600 });
const scratch = await mkdtemp(path.join(tmpdir(), "scap-service-fixture-"));
const identity = (n) => BigInt(n).toString(16).padStart(32, "0");
const id = () => randomUUID().replaceAll("-", "");
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const resources = [];
const completed = [];
let currentHistory;

async function event(name, data = {}) {
  const record = JSON.stringify({ elapsed_ms: Math.round(performance.now()), event: name, ...data });
  if (currentHistory) await appendFile(currentHistory, `${record}\n`);
  process.stdout.write(`${record}\n`);
}

async function contract(name, action) {
  currentHistory = path.join(evidence, `${name}.history.jsonl`);
  await writeFile(currentHistory, "", { mode: 0o600, flag: "wx" });
  await event("contract_started", { name });
  try {
    await action();
    await event("contract_completed", { name });
    await appendFile(currentHistory, "verification passed\n");
    completed.push(name);
  } catch (error) {
    await event("contract_failed", { name, message: error.message });
    throw error;
  } finally { currentHistory = undefined; }
}

async function command(program, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(program, args, { cwd: root, stdio: ["ignore", "pipe", "pipe"], ...options });
    let output = "";
    child.stdout.on("data", (data) => { output = (output + data.toString()).slice(-256_000); });
    child.stderr.on("data", (data) => { output = (output + data.toString()).slice(-256_000); });
    child.on("error", () => reject(new Error(`${path.basename(program)} could not start`)));
    child.on("exit", (code) => code === 0 ? resolve(output) : reject(new Error(`${path.basename(program)} exited ${code}: ${options.private ? "private fixture command failed" : output}`)));
  });
}

async function loggedProcess(program, args, file, env = process.env) {
  const log = await open(file, "a", 0o600);
  const child = spawn(program, args, { cwd: root, env, stdio: ["ignore", log.fd, log.fd] });
  const state = { child, exit: null };
  state.done = new Promise((resolve, reject) => {
    child.once("error", () => reject(new Error(`${path.basename(program)} failed to start`)));
    child.once("exit", (code, signal) => { state.exit = { code, signal }; resolve(state.exit); });
  });
  await log.close();
  state.stop = async (signal = "SIGKILL") => {
    if (state.exit !== null) return;
    child.kill(signal);
    const stopped = await Promise.race([state.done.then(() => true), delay(5000).then(() => false)]);
    if (!stopped) { child.kill("SIGKILL"); await state.done; }
  };
  return state;
}

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  const port = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}

class Proxy {
  blocked = false;
  sockets = new Set();
  constructor(source, destination, port) {
    this.source = source; this.destination = destination;
    this.server = net.createServer((client) => {
      client.setNoDelay(true);
      this.track(client);
      if (this.blocked) { client.pause(); return; }
      const upstream = net.connect({ host: "127.0.0.1", port });
      upstream.setNoDelay(true);
      this.track(upstream);
      client.on("error", () => upstream.destroy());
      upstream.on("error", () => client.destroy());
      client.on("close", () => upstream.destroy());
      upstream.on("close", () => client.destroy());
      client.pipe(upstream); upstream.pipe(client);
    });
  }
  track(socket) { this.sockets.add(socket); socket.on("error", () => {}); socket.on("close", () => this.sockets.delete(socket)); }
  async listen() {
    await new Promise((resolve, reject) => { this.server.once("error", reject); this.server.listen(0, "127.0.0.1", resolve); });
    this.port = this.server.address().port;
  }
  block(blocked) { this.blocked = blocked; for (const socket of this.sockets) socket.destroy(); }
  async close() { this.block(true); await new Promise((resolve) => this.server.close(resolve)); }
}

async function certificates(directory, cluster) {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const caKey = path.join(directory, "ca.key");
  const ca = path.join(directory, "ca.pem");
  await command("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "2", "-subj", "/CN=SCAP ephemeral contract CA", "-keyout", caKey, "-out", ca], { private: true });
  const leaves = [];
  for (const node of [1, 2, 3]) {
    const base = path.join(directory, `node-${node}`);
    const dns = `node-${node}.cluster-${cluster}.scap.internal`;
    await command("openssl", ["req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256", "-subj", `/CN=${dns}`, "-keyout", `${base}.key`, "-out", `${base}.csr`], { private: true });
    await writeFile(`${base}.ext`, `basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:${dns}\n`, { mode: 0o600 });
    await command("openssl", ["x509", "-req", "-in", `${base}.csr`, "-CA", ca, "-CAkey", caKey, "-set_serial", String(node + 1), "-days", "2", "-sha256", "-extfile", `${base}.ext`, "-out", `${base}.pem`], { private: true });
    await command("openssl", ["x509", "-in", `${base}.pem`, "-outform", "DER", "-out", `${base}.der`], { private: true });
    await chmod(`${base}.key`, 0o600);
    leaves.push({ pem: `${base}.pem`, key: `${base}.key`, der: `${base}.der` });
  }
  await chmod(caKey, 0o600);
  return { ca, leaves };
}

class Cluster {
  processes = [];
  proxies = [];
  constructor(name, archive) { this.name = name; this.archive = archive; this.directory = path.join(scratch, name); }
  async start() {
    await mkdir(this.directory, { mode: 0o700 });
    const clusterId = identity(this.name === "ha" ? 1 : 11);
    const certs = await certificates(path.join(this.directory, "certs"), clusterId);
    const ports = new Set();
    const port = async () => { for (;;) { const p = await freePort(); if (!ports.has(p)) { ports.add(p); return p; } } };
    this.http = [await port(), await port(), await port()];
    this.peer = [await port(), await port(), await port()];
    this.endpoints = this.http.map((p) => `http://127.0.0.1:${p}`);
    this.tokens = { alpha: randomBytes(32).toString("hex"), beta: randomBytes(32).toString("hex"), reader: randomBytes(32).toString("hex") };
    this.configs = [];
    for (let source = 0; source < 3; source++) {
      const peers = [];
      for (let destination = 0; destination < 3; destination++) {
        const proxy = new Proxy(source, destination, this.peer[destination]);
        await proxy.listen(); this.proxies.push(proxy);
        peers.push({ node_id: destination + 1, uri: `https://127.0.0.1:${proxy.port}`, certificate_der: certs.leaves[destination].der });
      }
      const token = (value, principal, credential, permissions) => ({ sha256: createHash("sha256").update(value).digest("hex"), principal_id: identity(principal), credential_id: identity(credential), auth_epoch: 1, permissions });
      const configuration = {
        version: 1, cluster_id: clusterId, cell_id: identity(2), cell_incarnation: 1, node_id: source + 1,
        administrator_id: identity(100), service_credential_id: identity(101), data_dir: path.join(this.directory, `data-${source + 1}`),
        http_listen: `127.0.0.1:${this.http[source]}`, peer_listen: `127.0.0.1:${this.peer[source]}`,
        certificate_pem: certs.leaves[source].pem, private_key_pem: certs.leaves[source].key, ca_pem: certs.ca,
        peers, idle_seconds: this.archive ? 5 : 3600,
        databases: [
          { name: "alpha", database_id: identity(3), incarnation: 1, placement_generation: 1, tokens: [token(this.tokens.alpha, 200, 201, 3), token(this.tokens.reader, 202, 203, 1)] },
          { name: "beta", database_id: identity(4), incarnation: 1, placement_generation: 1, tokens: [token(this.tokens.beta, 300, 301, 3)] },
        ],
        ...(this.archive ? { archive: this.archive.config } : {}),
      };
      const config = path.join(this.directory, `node-${source + 1}.json`);
      await writeFile(config, JSON.stringify(configuration), { mode: 0o600 }); this.configs.push(config);
    }
    resources.push(this);
    for (let node = 0; node < 3; node++) await this.launch(node, true);
    await this.waitLeader();
  }
  async launch(node, initialize = false) {
    this.processes[node] = await loggedProcess(binary, [...(initialize ? ["--initialize"] : []), this.configs[node]], path.join(this.directory, `node-${node + 1}.private.log`), this.archive ? { ...process.env, ...this.archive.env } : process.env);
  }
  client(database = "alpha", changes = {}, runtime) { return createClient({ endpoints: this.endpoints, database, authToken: this.tokens[database], timeoutMs: 8000, ...changes }, runtime); }
  async leaders() {
    return (await Promise.all(this.endpoints.map(async (endpoint, index) => {
      try {
        const response = await fetch(`${endpoint}/readyz`, { redirect: "manual", signal: AbortSignal.timeout(600) });
        await response.body?.cancel(); return response.status === 200 ? index : null;
      } catch { return null; }
    }))).filter((node) => node !== null);
  }
  async waitLeader(excluded = [], budget = 30_000) {
    const end = performance.now() + budget;
    while (performance.now() < end) {
      const ready = (await this.leaders()).filter((node) => !excluded.includes(node));
      if (ready.length > 0) return ready[0];
      for (let node = 0; node < 3; node++) if (!excluded.includes(node) && this.processes[node]?.exit) throw new Error(`Replica ${node + 1} exited: ${JSON.stringify(this.processes[node].exit)}; private logs under ${this.directory}`);
      await delay(100);
    }
    throw new Error(`No ready leader within ${budget} ms; private logs under ${this.directory}`);
  }
  isolate(node, blocked) { for (const proxy of this.proxies) if (proxy.source === node || proxy.destination === node) proxy.block(blocked); }
  async stop() {
    for (const proc of this.processes) await proc?.stop();
    for (const proxy of this.proxies) await proxy.close();
    this.proxies = [];
  }
}

async function stableRead(cluster, database, statement, expected, excluded = []) {
  const db = cluster.client(database, { endpoints: cluster.endpoints.filter((_, index) => !excluded.includes(index)), timeoutMs: 3000 });
  const end = performance.now() + 30_000;
  let successful = 0, stableStart;
  try {
    while (performance.now() < end) {
      try {
        assert.deepEqual((await db.query(statement)).rows.map((row) => Array.from(row)), expected);
        if (successful++ === 0) stableStart = performance.now();
        if (successful === 5) return stableStart;
      } catch (error) {
        if (!(error instanceof ScapError)) throw error;
        successful = 0;
      }
      await delay(250);
    }
    throw new Error("No stable one-second strong-read window before recovery budget");
  } finally { db.close(); }
}

async function direct(cluster, node, statement, mode, requestId, budget = 1000) {
  const deadline = Date.now() + budget;
  const db = libsqlClient({ url: `${cluster.endpoints[node]}/db/alpha/`, authToken: cluster.tokens.alpha, intMode: "bigint",
    fetch: async (input, init) => {
      const request = new Request(input, init);
      request.headers.set("x-scap-request-id", requestId); request.headers.set("x-scap-mode", mode);
      request.headers.set("x-scap-deadline-unix-ms", String(deadline));
      return fetch(request, { signal: AbortSignal.timeout(Math.max(1, deadline - Date.now())), redirect: "manual" });
    },
  });
  try { return await db.execute(statement); } finally { db.close(); }
}

async function highAvailability() {
  const cluster = new Cluster("ha");
  await contract("01-three-real-daemons", async () => {
    await cluster.start();
    await event("three_voters_ready", { replicas: 3, links: cluster.proxies.length, leader: (await cluster.waitLeader()) + 1 });
  });
  await contract("02-real-node-sdk", async () => {
    const output = await command(process.execPath, ["--test", "--test-isolation=none", "sdk/node/integration/client.test.mjs"], {
      env: { ...process.env, SCAP_ENDPOINTS: JSON.stringify(cluster.endpoints), SCAP_DATABASE: "alpha", SCAP_TOKEN: cluster.tokens.alpha },
    });
    await writeFile(path.join(evidence, "sdk-integration.log"), output, { mode: 0o600 });
    assert.match(output, /tests 5/); assert.match(output, /pass 5/); assert.match(output, /fail 0/);
    await event("real_sdk_contracts", { tests: 5, passed: 5, fake_backend: false });
  });
  let ack;
  const alpha = cluster.client(), beta = cluster.client("beta");
  try {
    await contract("03-tenant-and-read-permissions", async () => {
      await alpha.execute("CREATE TABLE ha_probe(id INTEGER PRIMARY KEY, nonce TEXT)");
      await beta.execute("CREATE TABLE private_beta(id INTEGER PRIMARY KEY, value TEXT)");
      await beta.execute("INSERT INTO private_beta VALUES(1, 'beta-only')");
      const crossed = cluster.client("beta", { authToken: cluster.tokens.alpha });
      try {
        await assert.rejects(crossed.query("SELECT value FROM private_beta"), (error) => error.code === "UNAUTHORIZED");
        await assert.rejects(crossed.status(), (error) => error.code === "UNAUTHORIZED");
      } finally { crossed.close(); }
      const reader = cluster.client("alpha", { authToken: cluster.tokens.reader });
      try {
        assert.equal((await reader.query("SELECT count(*) AS n FROM ha_probe")).rows[0].n, 0n);
        await reader.status();
        await assert.rejects(reader.execute("INSERT INTO ha_probe VALUES(99, 'denied')"), (error) => error.code === "UNAUTHORIZED");
      } finally { reader.close(); }
      await event("scope_checks", { cross_database_query: "denied", cross_database_status: "denied", read_only_select: "allowed", read_only_write: "denied" });
    });
    await contract("04-acknowledged-write-leader-kill", async () => {
      const statement = "INSERT INTO ha_probe VALUES(1, hex(randomblob(12))) RETURNING nonce";
      const requestId = id(); const result = await alpha.execute(statement, { requestId });
      ack = { requestId, statements: [statement], nonce: result.rows[0].nonce };
      const leader = await cluster.waitLeader();
      await event("acknowledged", { request_id: requestId, leader: leader + 1 });
      const failed = performance.now(); await cluster.processes[leader].stop("SIGKILL");
      const stable = await stableRead(cluster, "alpha", "SELECT nonce FROM ha_probe WHERE id=1", [[ack.nonce]], [leader]);
      const resultAfter = await alpha.lookup(ack);
      assert.equal(resultAfter.state, "committed"); assert.equal(resultAfter.results[0].rows[0][0], ack.nonce);
      await alpha.execute("INSERT INTO ha_probe VALUES(2, 'new-majority')");
      await event("leader_recovered", { killed: leader + 1, replacement: (await cluster.waitLeader([leader])) + 1, first_short_read_window_ms: Math.round(stable - failed), short_read_window_ms: 1000, formal_rto: false, acknowledged_rows_lost: 0, retained_result_equal: true });
      await cluster.launch(leader);
      await delay(500);
    });
    let fenced;
    await contract("05-real-minority-tcp-blackhole", async () => {
      const oldLeader = await cluster.waitLeader();
      // Direct address bypasses the SDK readiness hint: the database must itself
      // reject fresh reads/writes without a quorum, including a formerly valid owner.
      await direct(cluster, oldLeader, "SELECT count(*) FROM ha_probe", "read", id());
      cluster.isolate(oldLeader, true);
      const fault = performance.now();
      await assert.rejects(direct(cluster, oldLeader, "SELECT count(*) FROM ha_probe", "read", id(), 1200));
      fenced = { requestId: id(), statements: ["INSERT INTO ha_probe VALUES(3, 'isolated-writer')"] };
      await assert.rejects(direct(cluster, oldLeader, fenced.statements[0], "write", fenced.requestId, 1200));
      await cluster.waitLeader([oldLeader]);
      const majority = cluster.client("alpha", { endpoints: cluster.endpoints.filter((_, node) => node !== oldLeader) });
      try {
        assert.deepEqual(await majority.resolveOrCancel(fenced), { state: "cancelled" });
        await majority.execute("INSERT INTO ha_probe VALUES(4, 'partition-majority')");
        assert.equal((await majority.query("SELECT count(*) AS n FROM ha_probe WHERE id=3")).rows[0].n, 0n);
      } finally { majority.close(); }
      cluster.isolate(oldLeader, false);
      await stableRead(cluster, "alpha", "SELECT id FROM ha_probe ORDER BY id", [[1n], [2n], [4n]]);
      assert.deepEqual(await alpha.lookup(fenced), { state: "cancelled" });
      await event("partition_fenced", { isolated: oldLeader + 1, fresh_read: "rejected", fresh_write: "rejected", majority_ack: true, old_request: "cancelled", fault_elapsed_ms: Math.round(performance.now() - fault) });
    });
    await contract("06-all-processes-reopen", async () => {
      for (const process of cluster.processes) await process.stop("SIGKILL");
      for (let node = 0; node < 3; node++) await cluster.launch(node);
      await cluster.waitLeader();
      await stableRead(cluster, "alpha", "SELECT id FROM ha_probe ORDER BY id", [[1n], [2n], [4n]]);
      assert.equal((await alpha.lookup(ack)).results[0].rows[0][0], ack.nonce);
      assert.deepEqual(await alpha.lookup(fenced), { state: "cancelled" });
      assert.equal((await beta.query("SELECT value FROM private_beta WHERE id=1")).rows[0].value, "beta-only");
      await event("full_group_reopened", { replicas: 3, retained_original_result: true, cancel_fence_retained: true, both_databases_intact: true });
    });
  } finally { alpha.close(); beta.close(); await cluster.stop(); }
}

class Seaweed {
  async start() {
    const executable = process.env.SCAP_SEAWEEDFS_BIN;
    assert.ok(executable && path.isAbsolute(executable), "SCAP_SEAWEEDFS_BIN is required for the actual S3 lifecycle contract");
    const version = await command(executable, ["version"]);
    assert.match(version, /4\.51 153ab668c99731a6d29492bf6c61d0b4fa701101/);
    this.executable = executable; this.directory = path.join(scratch, "s3");
    await mkdir(this.directory, { mode: 0o700 });
    this.access = randomBytes(16).toString("hex"); this.secret = randomBytes(32).toString("hex");
    const identityFile = path.join(this.directory, "identity.json");
    await writeFile(identityFile, JSON.stringify({ identities: [{ name: "scap-contract", credentials: [{ accessKey: this.access, secretKey: this.secret }], actions: ["Admin", "Read", "Write", "List", "Tagging"] }] }), { mode: 0o600 });
    const used = new Set();
    const port = async () => { for (;;) { const number = await freePort(); if (!used.has(number)) { used.add(number); return number; } } };
    const ports = {};
    for (const flag of ["master.port", "master.port.grpc", "volume.port", "volume.port.grpc", "filer.port", "filer.port.grpc", "s3.port", "s3.port.grpc"]) ports[flag] = await port();
    this.endpoint = `http://127.0.0.1:${ports["s3.port"]}`;
    this.proxy = new Proxy(-1, -1, ports["s3.port"]);
    await this.proxy.listen();
    this.args = ["mini", `-dir=${this.directory}`, "-ip=127.0.0.1", "-ip.bind=127.0.0.1", "-admin.ui=false", "-webdav=false", "-s3.port.iceberg=0", "-s3.port.lance=0", "-volume.max=2", "-master.volumeSizeLimitMB=64", "-bucket=scap-test", `-s3.config=${identityFile}`, ...Object.entries(ports).map(([flag, value]) => `-${flag}=${value}`)];
    this.config = { endpoint: `http://127.0.0.1:${this.proxy.port}`, region: "us-east-1", bucket: "scap-test", access_key_env: "SCAP_CONTRACT_S3_ACCESS", secret_key_env: "SCAP_CONTRACT_S3_SECRET", allow_http: true };
    this.env = { SCAP_CONTRACT_S3_ACCESS: this.access, SCAP_CONTRACT_S3_SECRET: this.secret };
    resources.push({ stop: () => this.close() }); await this.launch();
  }
  async launch() {
    this.process = await loggedProcess(this.executable, this.args, path.join(this.directory, "backend.private.log"));
    const deadline = performance.now() + 30_000;
    while (performance.now() < deadline) {
      if (this.process.exit) throw new Error("S3 backend exited during startup");
      try {
        await command("curl", ["--silent", "--show-error", "--fail", "--max-time", "1", "--noproxy", "*", "--aws-sigv4", "aws:amz:us-east-1:s3", "--user", `${this.access}:${this.secret}`, "-X", "PUT", "--data-binary", "ready", `${this.endpoint}/scap-test/contract-ready`], { private: true });
        return;
      } catch { await delay(150); }
    }
    throw new Error("S3 did not accept an authenticated object within startup budget");
  }
  async stop() { await this.process?.stop("SIGKILL"); }
  blackhole(blocked) { this.proxy.block(blocked); }
  async close() {
    await this.stop();
    if (this.proxy) { const proxy = this.proxy; this.proxy = undefined; await proxy.close(); }
  }
}

async function lifecycle() {
  const s3 = new Seaweed(); await s3.start();
  const cluster = new Cluster("archive", s3);
  await cluster.start();
  const hot = cluster.client("alpha"), cold = cluster.client("beta");
  let keepAlive = true, keepAliveError;
  const keepHot = (async () => {
    while (keepAlive) {
      try { await hot.query("SELECT 1"); } catch (error) { keepAliveError = error; }
      await delay(400);
    }
  })();
  try {
    await contract("07-s3-cold-publication-and-wake", async () => {
      await hot.execute("CREATE TABLE hot_probe(id INTEGER PRIMARY KEY)");
      await cold.execute("CREATE TABLE cold_probe(id INTEGER PRIMARY KEY, nonce TEXT)");
      const request = { requestId: id(), statements: ["INSERT INTO cold_probe VALUES(1, hex(randomblob(12))) RETURNING nonce"] };
      const original = await cold.execute(request.statements[0], { requestId: request.requestId });
      const end = performance.now() + 40_000;
      let status;
      while (performance.now() < end) {
        status = await cold.status();
        if (status.cold) break;
        await delay(300);
      }
      assert.equal(status.cold, true, "Cold must be proven by fresh metadata after Raft archive publication/prune");
      assert.equal(status.suspended, true); assert.equal(status.ownerActive, false);
      assert.equal(status.archivedRevision, status.revision);
      assert.equal((await hot.status()).cold, false);
      await event("cold_proven", { revision: status.revision.toString(), archived_revision: status.archivedRevision.toString(), suspended: status.suspended, owner_active: status.ownerActive });
      await s3.stop();
      await hot.execute("INSERT INTO hot_probe VALUES(1)");
      assert.equal((await hot.query("SELECT count(*) AS n FROM hot_probe")).rows[0].n, 1n);
      await assert.rejects(cold.query("SELECT nonce FROM cold_probe"));
      assert.equal((await cold.status()).cold, true);
      await hot.execute("INSERT INTO hot_probe VALUES(2)");
      await event("s3_outage", { hot_write: "acknowledged", hot_fresh_read: "served", cold_wake: "rejected", metadata_retained: true });
      await s3.launch();
      assert.equal((await cold.query("SELECT nonce FROM cold_probe WHERE id=1")).rows[0].nonce, original.rows[0].nonce);
      assert.equal((await cold.lookup(request)).results[0].rows[0][0], original.rows[0].nonce);
      const awake = await cold.status();
      assert.equal(awake.cold, false); assert.equal(awake.suspended, false); assert.equal(awake.ownerActive, true);
      assert.equal((await hot.query("SELECT count(*) AS n FROM hot_probe")).rows[0].n, 2n);
      assert.equal(keepAliveError, undefined);
      await event("exact_archive_rehydrated", { original_random_result_retained: true, cold: awake.cold, active_owner: awake.ownerActive, hot_acknowledged_rows: 2 });
      // A new revision needs a new durable archive. Hold actual object-storage
      // TCP connections open without forwarding: the background archive must
      // consume its own budget without monopolizing the active SQL worker.
      await cold.execute("UPDATE cold_probe SET nonce='new-unarchived-revision' WHERE id=1");
      s3.blackhole(true);
      const pendingEnd = performance.now() + 25_000;
      let pending;
      while (performance.now() < pendingEnd) {
        pending = await cold.status();
        if (pending.suspended && !pending.cold) break;
        await delay(300);
      }
      assert.equal(pending.suspended, true); assert.equal(pending.cold, false);
      assert.ok(pending.archivedRevision === null || pending.archivedRevision < pending.revision);
      const hotLatencies = [];
      for (let value = 3; value <= 7; value++) {
        const began = performance.now();
        await hot.execute({ sql: "INSERT INTO hot_probe VALUES(?)", args: [BigInt(value)] }, { timeoutMs: 1500 });
        assert.equal((await hot.query("SELECT count(*) AS n FROM hot_probe", { timeoutMs: 1500 })).rows[0].n, BigInt(value));
        hotLatencies.push(Math.round(performance.now() - began));
        await delay(200);
      }
      await event("pending_archive_blackhole", { revision: pending.revision.toString(), archived_revision: pending.archivedRevision?.toString() ?? null, cold: pending.cold, hot_pairs: 5, per_request_deadline_ms: 1500, read_write_pair_latencies_ms: hotLatencies });
      s3.blackhole(false);
      const publishedEnd = performance.now() + 30_000;
      let published;
      while (performance.now() < publishedEnd) {
        published = await cold.status();
        if (published.cold) break;
        await delay(300);
      }
      assert.equal(published.cold, true); assert.equal(published.archivedRevision, pending.revision);
      assert.equal((await cold.query("SELECT nonce FROM cold_probe WHERE id=1")).rows[0].nonce, "new-unarchived-revision");
      assert.equal((await cold.lookup(request)).results[0].rows[0][0], original.rows[0].nonce);
      assert.equal(keepAliveError, undefined);
      await event("background_archive_recovered", { exact_new_revision: published.revision.toString(), original_request_result_preserved: true, hot_acknowledged_rows: 7 });
    });
  } finally { keepAlive = false; await keepHot; hot.close(); cold.close(); await cluster.stop(); await s3.close(); }
}

async function recoveryMeasurement() {
  await contract("08-local-recovery-measurement", async () => {
    const cluster = new Cluster("measurement"); await cluster.start();
    const names = ["alpha", "beta"];
    const clients = names.map((database) => cluster.client(database, { timeoutMs: 8000 }));
    const samples = [];
    const sampleFile = path.join(evidence, "latency.samples.jsonl");
    await writeFile(sampleFile, "", { flag: "wx", mode: 0o600 });
    const origin = performance.now();
    const relative = (value) => Math.round((value - origin) * 1000) / 1000;
    try {
      for (const client of clients) {
        await client.execute("CREATE TABLE performance_probe(id INTEGER PRIMARY KEY, value TEXT)");
        await client.execute("INSERT INTO performance_probe VALUES(-1, 'ack-before-failure')");
      }
      const sample = async (phase, round, database, kind, scheduled) => {
        const requestId = id();
        const invoked = performance.now();
        const client = clients[names.indexOf(database)];
        const statement = kind === "read" ? "SELECT value FROM performance_probe WHERE id=-1" : {
          sql: "INSERT INTO performance_probe VALUES(?, ?) RETURNING value",
          args: [BigInt((phase === "hot" ? 0 : 100) + round), requestId],
        };
        const record = { phase, round, database, kind, request_id: requestId, scheduled_ms: relative(scheduled), invoked_ms: relative(invoked), deadline_ms: relative(invoked + 8000) };
        try {
          const result = kind === "read" ? await client.query(statement, { requestId }) : await client.execute(statement, { requestId });
          assert.equal(result.rows[0].value, kind === "read" ? "ack-before-failure" : requestId);
          record.outcome = "success";
        } catch (error) {
          record.code = error.code ?? "ASSERTION";
          record.outcome = error instanceof ScapError ? ({ COMMIT_UNKNOWN: "unknown", EXPIRED: "expired", OVERLOADED: "admission_rejected" }[error.code] ?? "platform_error") : "correctness_error";
          if (!(error instanceof ScapError)) record.failure = error.message;
        }
        record.result_ms = relative(performance.now());
        record.latency_ms = Math.round((record.result_ms - record.scheduled_ms) * 1000) / 1000;
        samples.push(record);
        await appendFile(sampleFile, `${JSON.stringify(record)}\n`);
        return record;
      };
      const phase = async (name, rounds) => {
        const start = performance.now();
        const pending = [];
        for (let round = 0; round < rounds; round++) {
          const scheduled = start + round * 1000;
          await delay(Math.max(0, scheduled - performance.now()));
          for (const database of names) for (const kind of ["read", "write"]) pending.push(sample(name, round, database, kind, scheduled));
        }
        await delay(Math.max(0, start + rounds * 1000 - performance.now()));
        await Promise.all(pending);
        return start;
      };
      await event("measurement_workload", { databases: names, scheduled_per_database_per_second: { strong_reads: 1, stable_id_writes: 1 }, hot_seconds: 30, recovery_seconds: 60, request_deadline_ms: 8000, production_slo_load: false });
      await phase("hot", 30);
      const leader = await cluster.waitLeader();
      const fault = performance.now();
      // This independent controller timestamps immediately before SIGKILL.
      await cluster.processes[leader].stop("SIGKILL");
      await event("measurement_leader_killed", { replica: leader + 1, fault_ms: relative(fault) });
      const recoveryStart = await phase("recovery", 60);
      const summaries = [];
      for (const phase of ["hot", "recovery"]) for (const database of names) for (const kind of ["read", "write"]) {
        const entries = samples.filter((entry) => entry.phase === phase && entry.database === database && entry.kind === kind);
        const outcomes = {};
        for (const entry of entries) outcomes[entry.outcome] = (outcomes[entry.outcome] ?? 0) + 1;
        const latencies = entries.filter((entry) => entry.outcome === "success").map((entry) => entry.latency_ms).sort((a, b) => a - b);
        const percentile = (fraction) => latencies.length ? latencies[Math.max(0, Math.ceil(fraction * latencies.length) - 1)] : null;
        summaries.push({ phase, database, kind, total: entries.length, outcomes, successful_latency_ms: { min: latencies[0] ?? null, p50: percentile(.5), p95: percentile(.95), p99: percentile(.99), max: latencies.at(-1) ?? null }, failed_requests_not_removed: true });
      }
      const recovery = samples.filter((entry) => entry.phase === "recovery");
      const firstSuccess = recovery.filter((entry) => entry.outcome === "success").sort((a, b) => a.result_ms - b.result_ms)[0];
      let windowRound = null;
      for (let start = 0; start <= 30; start++) {
        const window = recovery.filter((entry) => entry.round >= start && entry.round < start + 30);
        if (window.length === 120 && window.every((entry) => entry.outcome === "success" && entry.result_ms < entry.deadline_ms && entry.invoked_ms - entry.scheduled_ms < 100)) { windowRound = start; break; }
      }
      const report = {
        version: 1, build, environment: { platform: platform(), release: release(), arch: arch(), node: process.version, cpus: cpus().length, cpu_model: cpus()[0]?.model, memory_bytes: totalmem(), topology: "one host, loopback HTTP and mTLS TCP, three real daemons, ephemeral local disk", proxy_nodelay: true, request_deadline_ms: 8000, probe_period_ms: 1000, affected_databases: names },
        sample_count: samples.length, summaries,
        recovery: { fault_ms: relative(fault), first_success_ms: firstSuccess ? firstSuccess.result_ms - relative(fault) : null,
          stable_window_start_round: windowRound, stable_window_seconds: 30, samples_per_database_per_kind: 30,
          local_recovery_window_start_ms: windowRound === null ? null : relative(recoveryStart + windowRound * 1000) - relative(fault),
          stable_window_confirmation_ms: windowRound === null ? null : Math.max(relative(recoveryStart + (windowRound + 30) * 1000), ...recovery.filter((entry) => entry.round >= windowRound && entry.round < windowRound + 30).map((entry) => entry.result_ms)) - relative(fault),
          first_success_per_database_ms: Object.fromEntries(names.map((database) => {
            const values = recovery.filter((entry) => entry.database === database && entry.outcome === "success").map((entry) => entry.result_ms);
            return [database, values.length ? Math.min(...values) - relative(fault) : null];
          })),
          observation_end_ms: relative(performance.now()), production_slo_passed: false,
          limitations: "One small-data loopback event; four probes/s, not the 500 requests/s reference load. No AZ failures, no latency-SLO or percentile-RTO claim. Build profile and exact binary hash are recorded; failures and UNKNOWN remain in the sample denominator." },
      };
      await writeFile(path.join(evidence, "measurement.json"), JSON.stringify(report, null, 2), { mode: 0o600 });
      assert.equal(samples.some((entry) => entry.outcome === "correctness_error"), false);
      // ACK retention is independently checked, including all baseline/fault probes.
      for (let index = 0; index < names.length; index++) {
        const rows = (await clients[index].query("SELECT value FROM performance_probe WHERE id>=0")).rows;
        const present = new Set(rows.map((row) => row.value));
        for (const entry of samples.filter((entry) => entry.database === names[index] && entry.kind === "write" && entry.outcome === "success")) assert.ok(present.has(entry.request_id), "An acknowledged measured write was lost");
      }
      await event("measurement_completed", { samples: samples.length, affected_databases: names, thirty_second_window_found: windowRound !== null, local_window_start_after_fault_ms: report.recovery.local_recovery_window_start_ms, production_slo_passed: false, acknowledged_rows_lost: 0 });
      assert.notEqual(windowRound, null, "No qualifying 30-second two-database window; raw failed/UNKNOWN samples retained");
    } finally { for (const client of clients) client.close(); await cluster.stop(); }
  });
}

try {
  const only = process.env.SCAP_SERVICE_NETWORK_ONLY;
  assert.ok(only === undefined || only === "measurement" || only === "lifecycle", "Unknown contract selection");
  assert.ok(only !== "lifecycle" || process.env.SCAP_SEAWEEDFS_BIN, "The selected lifecycle contract requires SCAP_SEAWEEDFS_BIN");
  if (!only) await highAvailability();
  if (only !== "measurement" && process.env.SCAP_SEAWEEDFS_BIN) await lifecycle();
  else if (only !== "measurement") await event("s3_contract_not_run", { reason: "SCAP_SEAWEEDFS_BIN not set" });
  if (only !== "lifecycle") await recoveryMeasurement();
  await writeFile(path.join(evidence, "completed.json"), JSON.stringify({ completed_contracts: completed, selected_contract: only ?? "all", s3_requested: Boolean(process.env.SCAP_SEAWEEDFS_BIN) }, null, 2), { mode: 0o600 });
  await writeFile(path.join(evidence, "complete.txt"), "verification passed\n", { mode: 0o600 });
  process.stdout.write(`Evidence: ${evidence}\n`);
} finally {
  for (const resource of resources.reverse()) await resource.stop();
}
