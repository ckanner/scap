import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { createReadStream } from "node:fs";
import { chmod, mkdir, open, readdir, stat, writeFile } from "node:fs/promises";
import net from "node:net";
import path from "node:path";

// Deployment and fault controls only. Accepted images, archives, authorizations
// and owner transitions always come from the production service.
export const delay = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));
export const identity = (number) => BigInt(number).toString(16).padStart(32, "0");
export const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");

export async function fileIdentity(filename) {
  const hash = createHash("sha256");
  for await (const bytes of createReadStream(filename)) hash.update(bytes);
  return { path: filename, bytes: (await stat(filename)).size, sha256: hash.digest("hex") };
}

export async function command(program, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(program, args, { cwd: options.cwd, env: options.env ?? process.env, stdio: ["ignore", "pipe", "pipe"] });
    const chunks = [];
    let bytes = 0, stderr = "", failure;
    const timer = setTimeout(() => { failure = new Error(path.basename(program) + " exceeded its command deadline"); child.kill("SIGKILL"); }, options.timeoutMs ?? 30_000);
    child.stdout.on("data", (data) => {
      bytes += data.length;
      if (bytes > 16 * 1024 * 1024) { failure = new Error("bounded fixture output exceeded"); child.kill("SIGKILL"); }
      else chunks.push(data);
    });
    child.stderr.on("data", (data) => { stderr = (stderr + data.toString()).slice(-4096); });
    child.once("error", () => { clearTimeout(timer); reject(new Error(path.basename(program) + " could not start")); });
    child.once("exit", (code, signal) => {
      clearTimeout(timer);
      if (failure) reject(failure);
      else if (code !== 0) reject(new Error(path.basename(program) + " exited " + code + "/" + signal + (options.private ? " (private output retained outside public evidence)" : ": " + stderr)));
      else resolve(Buffer.concat(chunks));
    });
  });
}

export async function processAt(program, args, filename, env = process.env, expectedFailure = false) {
  const file = await open(filename, "a", 0o600);
  const child = spawn(program, args, { env, stdio: ["ignore", file.fd, file.fd] });
  const state = { child, exit: null, plannedStop: expectedFailure, unexpectedExit: false, file: filename };
  state.done = new Promise((resolve, reject) => {
    child.once("error", () => reject(new Error(path.basename(program) + " could not start")));
    child.once("exit", (code, signal) => {
      state.exit = { code, signal };
      state.unexpectedExit = !state.plannedStop;
      resolve(state.exit);
    });
  });
  await file.close();
  state.stop = async (signal = "SIGKILL") => {
    if (state.exit !== null) return;
    state.plannedStop = true;
    child.kill(signal);
    if (!await Promise.race([state.done.then(() => true), delay(5000).then(() => false)])) {
      child.kill("SIGKILL"); await state.done;
      if (signal !== "SIGKILL") throw new Error("graceful daemon shutdown exceeded its original deadline");
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

async function ports(count) {
  const result = new Set();
  while (result.size < count) result.add(await freePort());
  return [...result];
}

class Proxy {
  blocked = false;
  blockedConnections = 0;
  sockets = new Set();
  constructor(source, destination, port) {
    this.source = source; this.destination = destination;
    this.listener = net.createServer((client) => {
      client.setNoDelay(true); this.track(client);
      if (this.blocked) { this.blockedConnections++; client.pause(); return; }
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
  async listen() {
    await new Promise((resolve, reject) => { this.listener.once("error", reject); this.listener.listen(0, "127.0.0.1", resolve); });
    this.port = this.listener.address().port;
  }
  block(value) { this.blocked = value; for (const socket of this.sockets) socket.destroy(); }
  async close() { this.block(true); await new Promise((resolve) => this.listener.close(resolve)); }
}

async function certificates(directory, cluster) {
  await mkdir(directory, { mode: 0o700 });
  const ca = path.join(directory, "ca.pem"), key = path.join(directory, "ca.key");
  await command("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "2", "-subj", "/CN=SCAP ephemeral history contract CA", "-keyout", key, "-out", ca], { private: true });
  await chmod(key, 0o600);
  const leaves = [];
  for (const node of [1, 2, 3]) {
    const base = path.join(directory, "node-" + node), dns = `node-${node}.cluster-${cluster}.scap.internal`;
    await command("openssl", ["req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256", "-subj", "/CN=" + dns, "-keyout", base + ".key", "-out", base + ".csr"], { private: true });
    await writeFile(base + ".ext", `basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:${dns}\n`, { mode: 0o600 });
    await command("openssl", ["x509", "-req", "-in", base + ".csr", "-CA", ca, "-CAkey", key, "-set_serial", String(node + 1), "-days", "2", "-sha256", "-extfile", base + ".ext", "-out", base + ".pem"], { private: true });
    await command("openssl", ["x509", "-in", base + ".pem", "-outform", "DER", "-out", base + ".der"], { private: true });
    await chmod(base + ".key", 0o600);
    leaves.push({ pem: base + ".pem", key: base + ".key", der: base + ".der" });
  }
  return { ca, leaves };
}

export class Cluster {
  processes = [];
  allProcesses = [];
  proxies = [];
  configs = [];
  configuration = [];
  constructor(directory, archive, observedFetch, createClient) {
    this.directory = directory; this.archive = archive; this.observedFetch = observedFetch; this.createClient = createClient;
  }
  async prepare() {
    await mkdir(this.directory, { mode: 0o700 });
    this.clusterId = identity(61); this.cellId = identity(62);
    const certs = await certificates(path.join(this.directory, "certificates"), this.clusterId);
    const assigned = await ports(9); this.http = assigned.slice(0, 3); this.peer = assigned.slice(3, 6); this.management = assigned.slice(6);
    this.endpoints = this.http.map((port) => "http://127.0.0.1:" + port);
    this.managementEndpoints = this.management.map((port) => "http://127.0.0.1:" + port);
    this.tokens = { alpha: randomBytes(32).toString("hex"), beta: randomBytes(32).toString("hex"), reader: randomBytes(32).toString("hex"), administrator: randomBytes(32).toString("hex") };
    for (let source = 0; source < 3; source++) {
      const peers = [];
      for (let destination = 0; destination < 3; destination++) {
        const proxy = new Proxy(source, destination, this.peer[destination]);
        await proxy.listen(); this.proxies.push(proxy);
        peers.push({ node_id: destination + 1, uri: "https://127.0.0.1:" + proxy.port, certificate_der: certs.leaves[destination].der });
      }
      const token = (value, principal, credential, permissions) => ({ sha256: digest(value), principal_id: identity(principal), credential_id: identity(credential), auth_epoch: 1, permissions });
      const config = {
        version: 1, cluster_id: this.clusterId, cell_id: this.cellId, cell_incarnation: 1, node_id: source + 1,
        administrator_id: identity(100), service_credential_id: identity(101),
        data_dir: path.join(this.directory, "data-" + (source + 1)),
        http_listen: "127.0.0.1:" + this.http[source], peer_listen: "127.0.0.1:" + this.peer[source],
        management: { listen: "127.0.0.1:" + this.management[source], token_sha256: digest(this.tokens.administrator) },
        certificate_pem: certs.leaves[source].pem, private_key_pem: certs.leaves[source].key, ca_pem: certs.ca,
        peers, idle_seconds: 6, archive: this.archive.config,
        databases: [
          { name: "alpha", database_id: identity(63), incarnation: 1, placement_generation: 1, tokens: [token(this.tokens.alpha, 200, 201, 3), token(this.tokens.reader, 202, 203, 1)] },
          { name: "beta", database_id: identity(64), incarnation: 1, placement_generation: 1, tokens: [token(this.tokens.beta, 300, 301, 3)] },
        ],
      };
      const filename = path.join(this.directory, "node-" + (source + 1) + ".json");
      await writeFile(filename, JSON.stringify(config), { mode: 0o600 });
      this.configs.push(filename); this.configuration.push(config);
    }
  }
  async launchAll(binary, initialize = false) {
    assert.ok(this.processes.every((state) => state.exit !== null), "all old processes must stop before switching binaries");
    this.binary = binary;
    for (let node = 0; node < 3; node++) await this.launch(node, binary, initialize);
    await this.waitLeader();
  }
  async launch(node, binary, initialize = false) {
    assert.ok(Number.isInteger(node) && node >= 0 && node < 3);
    assert.ok(!this.processes[node] || this.processes[node].exit !== null, "a replica identity must never run twice");
    const state = await processAt(binary, [...(initialize ? ["--initialize"] : []), this.configs[node]], path.join(this.directory, "node-" + (node + 1) + ".private.log"), { ...process.env, ...this.archive.env });
    this.processes[node] = state; this.allProcesses.push({ node, state });
  }
  assertNoUnexpectedExit() {
    for (const { node, state } of this.allProcesses) assert.equal(state.unexpectedExit, false, "unexpected exit of replica " + (node + 1) + ": " + JSON.stringify(state.exit));
    this.archive.assertNoUnexpectedExit();
  }
  async waitLeader(budget = 30_000) {
    const deadline = performance.now() + budget;
    do {
      this.assertNoUnexpectedExit();
      for (let node = 0; node < 3; node++) {
        try {
          const response = await this.observedFetch(this.endpoints[node] + "/readyz", { redirect: "manual", signal: AbortSignal.timeout(600) });
          await response.body?.cancel();
          if (response.status === 200) return node;
        } catch { /* readiness observation only; no SQL submitted */ }
      }
      await delay(100);
    } while (performance.now() < deadline);
    throw new Error("no ready leader before the original recovery deadline");
  }
  async waitLive(node, budget = 30_000) {
    const deadline = performance.now() + budget;
    do {
      this.assertNoUnexpectedExit();
      try {
        const response = await this.observedFetch(this.endpoints[node] + "/livez", { redirect: "manual", signal: AbortSignal.timeout(600) });
        await response.body?.cancel();
        if (response.status === 200) return;
      } catch { /* process liveness only; no SQL submitted */ }
      await delay(100);
    } while (performance.now() < deadline);
    throw new Error("replica HTTP listener did not start before its original deadline");
  }
  client(database, overrides = {}) { return this.createClient({ endpoints: this.endpoints, database, authToken: this.tokens[database], timeoutMs: 10_000, ...overrides }); }
  async localStatus(node) {
    const response = await this.observedFetch(this.managementEndpoints[node] + "/v1/admin/status", {
      redirect: "manual", signal: AbortSignal.timeout(6500), headers: { authorization: "Bearer " + this.tokens.administrator },
    });
    assert.equal(response.status, 200);
    const data = await response.json();
    assert.equal(data.authoritative, false, "local applied/commit observations are not strong reads or commit confirmation");
    assert.equal(data.node_id, node + 1);
    for (const field of ["applied", "commit", "snapshot_index"]) assert.ok(Number.isSafeInteger(data.status[field]) && data.status[field] >= 0);
    assert.ok(data.status.snapshot_index <= data.status.applied && data.status.applied <= data.status.commit);
    assert.equal(data.status.is_voter, true);
    return data;
  }
  async waitApplied(node, minimum, budget = 30_000) {
    const deadline = performance.now() + budget;
    do {
      this.assertNoUnexpectedExit();
      const observed = await this.localStatus(node);
      if (observed.status.applied >= minimum) return observed;
      await delay(100);
    } while (performance.now() < deadline);
    throw new Error("replica did not apply the witnessed committed prefix before its original deadline");
  }
  async membership() {
    const leader = await this.waitLeader();
    const response = await this.observedFetch(this.managementEndpoints[leader] + "/v1/admin/membership", {
      redirect: "manual", signal: AbortSignal.timeout(6500), headers: { authorization: "Bearer " + this.tokens.administrator },
    });
    assert.equal(response.status, 200);
    return this.decodeMembership(leader, await response.json());
  }
  decodeMembership(leader, data) {
    const membership = data.membership;
    assert.equal(data.scope.cluster_id, this.clusterId); assert.equal(data.scope.cell_id, this.cellId);
    assert.deepEqual(membership.conf_state, { voters: [1, 2, 3], learners: [], voters_outgoing: [], learners_next: [], auto_leave: false }, "this upgrade experiment never changes the original three-voter configuration");
    assert.ok(Number.isSafeInteger(membership.applied) && membership.applied > 0);
    return { leader: leader + 1, ...membership };
  }
  async stop(node, signal = "SIGKILL") {
    this.assertNoUnexpectedExit();
    const state = this.processes[node];
    await state.stop(signal);
    if (signal === "SIGKILL") assert.equal(state.exit.signal, "SIGKILL");
    else assert.equal(state.exit.code, 0);
    return state.exit;
  }
  async stopAll(signal = "SIGKILL") {
    for (let node = 0; node < 3; node++) await this.stop(node, signal);
  }
  async writerFiles() {
    const result = [];
    for (let node = 0; node < 3; node++) {
      const directory = path.join(this.configuration[node].data_dir, "writers");
      const entries = await readdir(directory, { withFileTypes: true });
      for (const entry of entries) {
        assert.ok(entry.isDirectory() && /^[0-9a-f]{32}$/.test(entry.name));
        const filename = path.join(directory, entry.name, "database.sqlite");
        const details = await stat(filename);
        assert.ok(details.isFile() && details.size <= 256 * 1024, "private SQLite image must retain the original 256KiB bound");
        result.push({ node_id: node + 1, worker_instance: entry.name, relative_path: path.relative(this.directory, filename), main_file_bytes: details.size });
      }
    }
    return result.sort((left, right) => left.relative_path.localeCompare(right.relative_path));
  }
  async close() {
    const processes = await Promise.allSettled(this.processes.map((state) => state?.stop()));
    const proxies = await Promise.allSettled(this.proxies.map((proxy) => proxy.close()));
    this.proxies = [];
    const failed = [...processes, ...proxies].filter((result) => result.status === "rejected");
    if (failed.length) throw new AggregateError(failed.map((result) => result.reason), "private fixture cleanup failed");
  }
}

export class Seaweed {
  processes = [];
  allProcesses = [];
  constructor(directory, record) { this.directory = directory; this.record = record; }
  async start() {
    this.executable = process.env.SCAP_SEAWEEDFS_BIN;
    assert.ok(this.executable && path.isAbsolute(this.executable), "SCAP_SEAWEEDFS_BIN is required; no fake object backend is supported");
    const version = (await command(this.executable, ["version"])).toString();
    assert.match(version, /4\.51 153ab668c99731a6d29492bf6c61d0b4fa701101/);
    this.mode = process.env.SCAP_SEAWEEDFS_MODE ?? "mini";
    assert.ok(["mini", "separate"].includes(this.mode));
    await mkdir(this.directory, { mode: 0o700 });
    this.access = randomBytes(16).toString("hex"); this.secret = randomBytes(32).toString("hex");
    const identityFile = path.join(this.directory, "identity.json");
    await writeFile(identityFile, JSON.stringify({ identities: [{ name: "scap-history", credentials: [{ accessKey: this.access, secretKey: this.secret }], actions: ["Admin", "Read", "Write", "List", "Tagging"] }] }), { mode: 0o600 });
    const numbers = await ports(8), flags = ["master.port", "master.port.grpc", "volume.port", "volume.port.grpc", "filer.port", "filer.port.grpc", "s3.port", "s3.port.grpc"];
    const assigned = Object.fromEntries(flags.map((flag, index) => [flag, numbers[index]]));
    this.endpoint = "http://127.0.0.1:" + assigned["s3.port"];
    this.proxy = new Proxy(-1, -1, assigned["s3.port"]); await this.proxy.listen();
    this.commands = [{ name: "backend", args: ["mini", "-dir=" + this.directory, "-ip=127.0.0.1", "-ip.bind=127.0.0.1", "-admin.ui=false", "-webdav=false", "-s3.port.iceberg=0", "-s3.port.lance=0", "-volume.max=2", "-master.volumeSizeLimitMB=64", "-bucket=scap-history", "-s3.config=" + identityFile, ...Object.entries(assigned).map(([flag, value]) => "-" + flag + "=" + value)] }];
    if (this.mode === "separate") {
      const master = `127.0.0.1:${assigned["master.port"]}.${assigned["master.port.grpc"]}`, filer = `127.0.0.1:${assigned["filer.port"]}.${assigned["filer.port.grpc"]}`;
      for (const name of ["master", "volume", "filer"]) await mkdir(path.join(this.directory, name), { mode: 0o700 });
      const listen = (name) => ["-ip=127.0.0.1", "-ip.bind=127.0.0.1", "-port=" + assigned[name + ".port"], "-port.grpc=" + assigned[name + ".port.grpc"]];
      this.commands = [
        { name: "master", args: ["master", ...listen("master"), "-mdir=" + path.join(this.directory, "master"), "-peers=none", "-telemetry=false", "-volumeSizeLimitMB=64"] },
        { name: "volume", args: ["volume", ...listen("volume"), "-dir=" + path.join(this.directory, "volume"), "-master=" + master, "-max=2"] },
        { name: "filer", args: ["filer", ...listen("filer"), "-defaultStoreDir=" + path.join(this.directory, "filer"), "-master=" + master] },
        { name: "s3", args: ["s3", ...listen("s3"), "-filer=" + filer, "-config=" + identityFile, "-port.iceberg=0", "-port.lance=0"] },
      ];
    }
    this.config = { endpoint: "http://127.0.0.1:" + this.proxy.port, region: "us-east-1", bucket: "scap-history", access_key_env: "SCAP_HISTORY_S3_ACCESS", secret_key_env: "SCAP_HISTORY_S3_SECRET", allow_http: true };
    this.env = { SCAP_HISTORY_S3_ACCESS: this.access, SCAP_HISTORY_S3_SECRET: this.secret };
    for (const entry of this.commands) {
      const state = await processAt(this.executable, entry.args, path.join(this.directory, entry.name + ".private.log"));
      this.processes.push(state); this.allProcesses.push(state);
    }
    const deadline = performance.now() + 30_000;
    let attempt = 0;
    do {
      this.assertNoUnexpectedExit();
      try {
        if (this.mode === "separate") {
          try { await this.signed(["--head", this.endpoint + "/scap-history"]); }
          catch { await this.signed(["-X", "PUT", "--data-binary", "", this.endpoint + "/scap-history"]); }
        }
        await this.signed(["-X", "PUT", "--data-binary", "ready", this.endpoint + "/scap-history/contract-ready"]);
        await this.record("s3_bootstrap_attempt", { attempt: attempt++, outcome: "success", idempotent_backend_setup_only: true });
        this.identity = { ...(await fileIdentity(this.executable)), version: "4.51", commit: "153ab668c99731a6d29492bf6c61d0b4fa701101", mode: this.mode, processes: this.commands.map((entry) => entry.name) };
        return;
      } catch {
        await this.record("s3_bootstrap_attempt", { attempt: attempt++, outcome: "unavailable", idempotent_backend_setup_only: true });
        await delay(150);
      }
    } while (performance.now() < deadline);
    throw new Error("actual signed S3 backend did not become usable before its startup deadline");
  }
  signed(args) { return command("curl", ["--silent", "--show-error", "--fail", "--max-time", "2", "--noproxy", "*", "--aws-sigv4", "aws:amz:us-east-1:s3", "--user", this.access + ":" + this.secret, ...args], { private: true }); }
  assertNoUnexpectedExit() { for (const state of this.allProcesses) assert.equal(state.unexpectedExit, false, "unexpected S3 component exit"); }
  blackhole(blocked) { this.proxy.block(blocked); }
  async archiveInventory(clusterId, cellId, databaseId) {
    // These authenticated S3 reads independently identify the actual immutable
    // object format. The production cell still chooses which object to hydrate.
    const prefix = `scap/v1/${clusterId}/${cellId}/1/${databaseId}/1/1/`;
    const listing = (await this.signed([this.endpoint + "/scap-history?list-type=2&prefix=" + encodeURIComponent(prefix)])).toString();
    assert.ok(!/<IsTruncated>true<\/IsTruncated>/.test(listing), "bounded fixture object inventory must be complete");
    const keys = [...listing.matchAll(/<Key>([^<]+)<\/Key>/g)].map((match) => match[1]).sort();
    const result = [];
    for (const key of keys) {
      assert.ok(key.startsWith(prefix) && /^[a-z0-9/]+$/.test(key) && key.length === prefix.length + 64);
      const bytes = await this.signed([this.endpoint + "/scap-history/" + key]);
      assert.equal(bytes.subarray(0, 8).toString(), "SCAPARC!");
      assert.equal(digest(bytes), key.slice(-64), "object bytes must match their immutable content-addressed key");
      result.push({ key, sha256: digest(bytes), bytes: bytes.length, format_version: bytes[8] });
    }
    return result;
  }
  async close() {
    const results = await Promise.allSettled([...this.processes].reverse().map((state) => state.stop()));
    if (this.proxy) { const proxy = this.proxy; this.proxy = undefined; results.push(...await Promise.allSettled([proxy.close()])); }
    const failed = results.filter((result) => result.status === "rejected");
    if (failed.length) throw new AggregateError(failed.map((result) => result.reason), "private S3 fixture cleanup failed");
  }
}
