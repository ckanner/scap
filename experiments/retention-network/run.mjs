import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { appendFile, chmod, mkdir, mkdtemp, readFile, readdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { createClient, ScapError } from "../../sdk/node/dist/client.js";
import { Cluster, Seaweed, delay, digest, fileIdentity, identity, processAt } from "../history-network/deployment.mjs";

// Only deployment, fault injection and assertions live here. The separately
// frozen old daemon creates every legacy disk/archive; production code performs
// all request fencing, acknowledgement, retirement and physical recovery.
const oldCommit = "b9f512819358494f178b01d7f1d960dff8222c1c";
const frozenOldSha = "87080fbf3ef7a5ea1615f8f70559ceb94114b9d1e0d42a85ccaecb31ed503bc2";
const selectedOldSha = process.env.SCAP_RETENTION_OLD_SERVER_SHA256 ?? frozenOldSha;
assert.match(selectedOldSha, /^[0-9a-f]{64}$/, "legacy build receipt must be a lowercase SHA-256 digest");
const binary = process.env.SCAP_SERVER_BIN;
const oldBinary = process.env.SCAP_RETENTION_OLD_SERVER_BIN;
assert.ok(binary && path.isAbsolute(binary) && oldBinary && path.isAbsolute(oldBinary), "SCAP_SERVER_BIN and SCAP_RETENTION_OLD_SERVER_BIN must identify separate absolute production binaries");
assert.equal(process.env.SCAP_RETENTION_OLD_SOURCE_COMMIT ?? oldCommit, oldCommit, "the legacy producer must be the exact V3 main commit");
assert.equal(process.env.LLVM_PROFILE_FILE, undefined, "real faults cannot enter unit profiles");
assert.equal(process.env.NODE_V8_COVERAGE, undefined, "real faults cannot enter unit profiles");

const evidence = process.env.SCAP_RETENTION_EVIDENCE_DIR ?? await mkdtemp(path.join(tmpdir(), "scap-retention-evidence-"));
await mkdir(evidence, { recursive: true, mode: 0o700 }); await chmod(evidence, 0o700);
const scratch = await mkdtemp(path.join(tmpdir(), "scap-retention-fixture-"));
const started = performance.now();
const ms = () => Math.round((performance.now() - started) * 1000) / 1000;
const id = () => randomUUID().replaceAll("-", "");
const json = (value) => JSON.stringify(value, (_, entry) => typeof entry === "bigint" ? entry.toString() : entry);
const oldIdentity = await fileIdentity(oldBinary), currentIdentity = await fileIdentity(binary);
assert.equal(oldIdentity.sha256, selectedOldSha, "legacy binary does not match the selected V3 build receipt");
assert.notEqual(oldIdentity.sha256, currentIdentity.sha256);
const harnessIdentity = await Promise.all([
  fileURLToPath(import.meta.url),
  fileURLToPath(new URL("../history-network/deployment.mjs", import.meta.url)),
  fileURLToPath(new URL("check_evidence.py", import.meta.url)),
].map(fileIdentity));
await writeFile(path.join(evidence, "binary.json"), JSON.stringify({ old: { ...oldIdentity, source_commit: oldCommit, selected_build_receipt_sha256: selectedOldSha }, current: { ...currentIdentity, build_description: process.env.SCAP_SERVICE_BUILD_DESCRIPTION ?? "current local source" }, harness: harnessIdentity }, null, 2), { flag: "wx", mode: 0o600 });
for (const name of ["requests.jsonl", "http-attempts.jsonl", "write-results.jsonl", "application-acks.jsonl", "windows.jsonl"]) await writeFile(path.join(evidence, name), "", { flag: "wx", mode: 0o600 });

const require = createRequire(new URL("../../sdk/node/package.json", import.meta.url));
const { createClient: nativeClient } = require("@libsql/client/http");
const completed = [], requests = [], http = [], retained = [], applicationAcks = [], windows = [], clients = [];
const expectedRows = { alpha: new Map(), beta: new Map() };
const epoch = { alpha: 1n, beta: 1n };
const profile = { databases: 32, database_bytes: 256 * 1024, requests_per_database: 128, state_bytes: 8 * 1024 * 1024 };
let history, requestOrdinal = 0, httpOrdinal = 0, nextRow = 10;
let alpha, beta, alphaAdmin, betaAdmin, sameReader, otherWriter;
let newActive = false, responseLoss, mixed, lagger, oldArchives, newArchives, lostWrite, capacityRejected;
let oldConfigurations = [], lostRotation, recoveredFiles;

async function event(name, data = {}) {
  const line = json({ elapsed_ms: ms(), event: name, ...data });
  if (history) await appendFile(history, line + "\n");
  process.stdout.write(line + "\n");
}

async function observedFetch(input, init) {
  const request = new Request(input, init), target = new URL(request.url);
  const node = cluster.endpoints?.indexOf(target.origin) ?? -1;
  const managementNode = cluster.managementEndpoints?.indexOf(target.origin) ?? -1;
  const record = { ordinal: httpOrdinal++, invoked_ms: ms(), node_id: Math.max(node, managementNode) + 1, method: request.method, route: target.pathname, request_id: request.headers.get("x-scap-request-id"), request_epoch: request.headers.get("x-scap-request-epoch"), mode: request.headers.get("x-scap-mode"), deadline_unix_ms: request.headers.get("x-scap-deadline-unix-ms") };
  try {
    const response = await fetch(request);
    record.status = response.status; record.outcome = "response";
    let body;
    if (request.method === "POST" || target.pathname === "/v1/admin/membership"
        || (request.method === "GET" && node >= 0 && target.pathname.endsWith("/v1/status"))) {
      try { body = await response.clone().json(); record.code = body.code ?? body.results?.find((entry) => entry.type === "error")?.error?.code ?? null; }
      catch { record.code = "UNPARSEABLE_RESPONSE"; }
    }
    if (responseLoss && !responseLoss.observed && request.method === "POST" && record.request_id === responseLoss.requestId && record.request_epoch === responseLoss.requestEpoch.toString()) {
      assert.equal(record.code, null, "only a complete successful server response may be deliberately lost");
      assert.equal(response.status, 200);
      if (responseLoss.kind === "rotate") assert.equal(body.state, "rotated");
      else assert.ok(body.results.some((entry) => entry.type === "ok" && entry.response?.type === "execute"));
      await response.arrayBuffer();
      responseLoss.httpOrdinal = record.ordinal;
      responseLoss.observed = true;
      record.injected_response_loss = true;
      record.outcome = "response_lost";
      throw new Error("injected loss after a complete successful " + responseLoss.kind + " response");
    }
    return response;
  } catch (error) {
    if (!record.injected_response_loss) { record.outcome = "transport_error"; record.code = error.name; }
    throw error;
  } finally {
    record.result_ms = ms(); http.push(record);
    await appendFile(path.join(evidence, "http-attempts.jsonl"), json(record) + "\n");
  }
}

const s3 = new Seaweed(path.join(scratch, "s3"), event);
const cluster = new Cluster(path.join(scratch, "replicas"), s3, observedFetch, (config) => {
  const client = createClient(config, { fetch: observedFetch, now: Date.now, monotonic: () => performance.now(), requestId: id, createClient: nativeClient });
  clients.push(client); return client;
});
const user = (database) => database === "alpha" ? alpha : beta;
const administrator = (database) => database === "alpha" ? alphaAdmin : betaAdmin;

async function contract(name, action) {
  history = path.join(evidence, name + ".history.jsonl");
  await writeFile(history, "", { flag: "wx", mode: 0o600 });
  await event("contract_started", { name });
  try {
    await action(); cluster.assertNoUnexpectedExit();
    await event("contract_completed", { name });
    await appendFile(history, "verification passed\n"); completed.push(name);
  } catch (error) { await event("contract_failed", { name, message: error.message }); throw error; }
  finally { history = undefined; }
}

async function operation(database, kind, label, request, run) {
  const record = { ordinal: requestOrdinal++, database, kind, label, request_id: request.requestId, request_epoch: request.requestEpoch.toString(), invoked_ms: ms() };
  if (request.statements?.length) record.statements_sha256 = digest(json(request.statements));
  try {
    const result = await run(); record.outcome = "success";
    if (kind === "lookup" || kind === "cancel") {
      record.observed_state = result.state;
      if (result.state === "committed") { record.sequence = result.sequence; record.results_sha256 = digest(json(result.results)); record.acknowledged = result.acknowledged; }
      if (result.state === "cancelled") { record.position = result.position; record.acknowledged = result.acknowledged; }
      if (result.state === "retired") record.current_epoch = result.currentEpoch;
    }
    if (kind === "status") record.metadata = result;
    if (kind === "rotate") record.rotated_epoch = result;
    return result;
  } catch (error) {
    record.outcome = error instanceof ScapError ? "service_error" : "failure";
    record.code = error.code ?? error.name; throw error;
  } finally {
    record.result_ms = ms(); requests.push(record);
    await appendFile(path.join(evidence, "requests.jsonl"), json(record) + "\n");
  }
}

function newRequest(database, statements = [], requestId = id(), requestEpoch = epoch[database]) {
  return { requestId, requestEpoch, statements };
}
function normalized(result) {
  return { columns: [...result.columns], rows: result.rows.map((row) => Array.from(row)), rowsAffected: result.rowsAffected, lastInsertRowid: result.lastInsertRowid ?? null };
}
function observeRows(database, result) {
  const idColumn = result.columns.indexOf("id"), valueColumn = result.columns.indexOf("value");
  if (idColumn >= 0 && valueColumn >= 0) for (const row of result.rows) expectedRows[database].set(row[idColumn].toString(), row[valueColumn]);
}

async function retainWrite(database, request, result, label, observedVia) {
  const record = { database, request, result, label, state: "committed", applicationAcknowledged: false, retired: false, observedVia };
  retained.push(record); observeRows(database, result);
  await appendFile(path.join(evidence, "write-results.jsonl"), json({ database, request_id: request.requestId, request_epoch: request.requestEpoch, statements_sha256: digest(json(request.statements)), label, result, observed_via: observedVia }) + "\n");
  return record;
}

async function write(database, label, statement, requestId = id()) {
  const request = newRequest(database, [statement], requestId);
  const tracked = await operation(database, "write", label, request, () => user(database).executeTracked(statement, { requestId: request.requestId, requestEpoch: request.requestEpoch }));
  assert.equal(tracked.request.requestId, request.requestId); assert.equal(tracked.request.requestEpoch, request.requestEpoch);
  return retainWrite(database, request, normalized(tracked.result), label, "successful_sql_response");
}

async function query(database, label, statement, client = user(database), timeoutMs) {
  const request = newRequest(database, [statement]);
  return operation(database, "read", label, request, () => client.query(statement, { requestId: request.requestId, requestEpoch: request.requestEpoch, ...(timeoutMs === undefined ? {} : { timeoutMs }) }));
}

async function status(database, label = "metadata") {
  const request = newRequest(database);
  return operation(database, "status", label, request, async () => {
    const result = await user(database).status({ requestId: request.requestId, requestEpoch: request.requestEpoch });
    for (const name of ["revision", "baseRevision", "tailEntries", "tailBytes"]) assert.equal(typeof result[name], "bigint");
    assert.ok(result.baseRevision <= result.revision);
    if (newActive) {
      for (const name of ["requestEpoch", "retainedRequests", "unacknowledgedRequests", "retiredRevision"]) assert.equal(typeof result[name], "bigint");
      assert.ok(result.retainedRequests <= 128n && result.unacknowledgedRequests <= result.retainedRequests);
      assert.ok(result.retiredRevision <= result.revision);
    } else assert.equal(result.requestEpoch, null, "the real old V3 producer cannot invent new retention metadata");
    return result;
  });
}

async function lookup(record, label, client = user(record.database)) {
  return operation(record.database, "lookup", label, record.request, () => client.lookup(record.request));
}
async function verifyTerminal(record, label) {
  const terminal = await lookup(record, label);
  assert.equal(terminal.state, record.state);
  if (record.state === "committed") assert.deepEqual(terminal.results, [record.result]);
  if (record.state === "cancelled" && newActive) {
    assert.ok(terminal.position && terminal.position.term > 0n && terminal.position.index > 0n);
    if (record.position) assert.deepEqual(terminal.position, record.position);
    record.position = terminal.position;
  }
  if (newActive) assert.equal(terminal.acknowledged, record.applicationAcknowledged);
  return terminal;
}

async function cancel(database, label, row, request = newRequest(database, [`INSERT INTO witness VALUES(${row},'cancelled-must-never-appear')`])) {
  const terminal = await operation(database, "cancel", label, request, () => user(database).resolveOrCancel(request));
  assert.equal(terminal.state, "cancelled", "a committed unknown request must remain committed and fail this cancellation fixture");
  const record = { database, request, label, state: "cancelled", position: terminal.position, applicationAcknowledged: false, retired: false };
  retained.push(record); return record;
}

async function acknowledge(record, label) {
  const terminal = await verifyTerminal(record, label + "_terminal");
  await operation(record.database, "acknowledge", label, record.request, () => user(record.database).acknowledge(record.request, terminal));
  record.applicationAcknowledged = true;
  const receipt = { database: record.database, request_id: record.request.requestId, request_epoch: record.request.requestEpoch, state: terminal.state, ...(terminal.state === "committed" ? { sequence: terminal.sequence, result_sha256: digest(json(terminal.results)) } : { position: terminal.position }), label };
  applicationAcks.push(receipt); await appendFile(path.join(evidence, "application-acks.jsonl"), json(receipt) + "\n");
}

async function expectError(database, kind, label, request, run, allowed) {
  let rejected;
  try { await operation(database, kind, label, request, run); }
  catch (error) { rejected = error; }
  assert.ok(rejected instanceof ScapError, label + " must have a real SDK/service rejection");
  if (allowed) assert.ok(allowed.includes(rejected.code), label + " unexpected rejection: " + rejected.code);
  return rejected;
}

async function sqlImage(database, label) {
  const rows = [];
  for (let offset = 0; ; offset += 128) {
    const result = await query(database, label, `SELECT id,value FROM witness ORDER BY id LIMIT 128 OFFSET ${offset}`);
    for (const row of result.rows) rows.push([row.id.toString(), row.value]);
    if (result.rows.length < 128) break;
  }
  const expected = [...expectedRows[database]].sort((left, right) => BigInt(left[0]) < BigInt(right[0]) ? -1 : 1);
  assert.deepEqual(rows, expected, "all confirmed current SQL values must survive; cancellation/overflow rows must be absent");
  return { rows: rows.length, sha256: digest(json(rows)) };
}

async function waitCold(database = "beta") {
  const deadline = performance.now() + 45_000;
  let current;
  do {
    current = await status(database, "wait_cold_metadata");
    if (current.cold) break;
    if (database !== "alpha") await query("alpha", "keep_alpha_hot_while_beta_archives", "SELECT 1");
    await delay(150);
  } while (performance.now() < deadline);
  assert.equal(current.cold, true); assert.equal(current.suspended, true); assert.equal(current.ownerActive, false); assert.equal(current.archivedRevision, current.revision);
  return current;
}

async function rotate(database, label, loseResponse = false) {
  await query(database, label + "_hot_barrier", "SELECT 1");
  const before = await status(database, label + "_before"), sqlBefore = await sqlImage(database, label + "_sql_before");
  assert.equal(before.requestEpoch, epoch[database]); assert.ok(before.retainedRequests > 0n); assert.equal(before.unacknowledgedRequests, 0n);
  const request = newRequest(database);
  if (loseResponse) responseLoss = { kind: "rotate", requestId: request.requestId, requestEpoch: request.requestEpoch, observed: false };
  try {
    if (loseResponse) {
      await expectError(database, "rotate", label, request, () => administrator(database).rotateRequests(request.requestEpoch, { requestId: request.requestId }), ["COMMIT_UNKNOWN"]);
      assert.equal(responseLoss.observed, true);
      const posts = http.filter((entry) => entry.request_id === request.requestId && entry.method === "POST");
      assert.equal(posts.length, 1); assert.equal(posts[0].outcome, "response_lost");
      lostRotation = { request_id: request.requestId, request_epoch: request.requestEpoch, http_ordinal: posts[0].ordinal, mutation_posts: 1, original_error: "COMMIT_UNKNOWN" };
    } else {
      const next = await operation(database, "rotate", label, request, () => administrator(database).rotateRequests(request.requestEpoch, { requestId: request.requestId }));
      assert.equal(next, request.requestEpoch + 1n);
    }
  } finally { responseLoss = undefined; }
  const after = await status(database, label + "_after"), sqlAfter = await sqlImage(database, label + "_sql_after");
  assert.equal(after.requestEpoch, request.requestEpoch + 1n);
  assert.equal(after.revision, before.revision); assert.equal(after.retiredRevision, before.revision);
  assert.equal(after.retainedRequests, 0n); assert.equal(after.unacknowledgedRequests, 0n); assert.equal(after.archivedRevision, null);
  assert.deepEqual(sqlAfter, sqlBefore);
  const retiredHere = retained.filter((entry) => entry.database === database && entry.request.requestEpoch === request.requestEpoch);
  assert.equal(BigInt(retiredHere.length), before.retainedRequests);
  assert.ok(retiredHere.every((entry) => entry.applicationAcknowledged));
  for (const entry of retiredHere) entry.retired = true;
  epoch[database] = after.requestEpoch;
  const window = { database, request_id: request.requestId, from_epoch: request.requestEpoch, to_epoch: after.requestEpoch, retained_before: before.retainedRequests, unacknowledged_before: before.unacknowledgedRequests, revision_before: before.revision, revision_after: after.revision, retired_revision: after.retiredRevision, retained_after: after.retainedRequests, archive_cleared: after.archivedRevision === null, sql_before: sqlBefore, sql_after: sqlAfter, lost_response: loseResponse };
  windows.push(window); await appendFile(path.join(evidence, "windows.jsonl"), json(window) + "\n");
  return window;
}

async function directSql(node, statement, mode, request, budget = 2500) {
  const deadline = Date.now() + budget;
  let posts = 0;
  const driver = nativeClient({ url: cluster.endpoints[node] + "/db/alpha/", authToken: cluster.tokens.alpha, intMode: "bigint", fetch: async (input, init) => {
    const inputRequest = new Request(input, init);
    assert.equal(new URL(inputRequest.url).origin, cluster.endpoints[node]);
    if (inputRequest.method === "POST") assert.equal(++posts, 1);
    inputRequest.headers.set("x-scap-request-id", request.requestId);
    inputRequest.headers.set("x-scap-request-epoch", request.requestEpoch.toString());
    inputRequest.headers.set("x-scap-mode", mode);
    inputRequest.headers.set("x-scap-deadline-unix-ms", deadline.toString());
    return observedFetch(inputRequest, { redirect: "manual", signal: AbortSignal.timeout(Math.max(1, deadline - Date.now() + 1500)) });
  } });
  try { return await driver.execute(statement); }
  catch (error) { if (error instanceof assert.AssertionError) throw error; throw new ScapError(error.message, error.code ?? "COMMIT_UNKNOWN", request); }
  finally { driver.close(); }
}

async function rejectedDirect(node, label, statement, mode, request = newRequest("alpha", [statement])) {
  await expectError("alpha", mode === "read" ? "read" : "write", label, request, () => directSql(node, statement, mode, request), ["NOT_LEADER", "COMMIT_UNKNOWN", "EXPIRED"]);
  const posts = http.filter((entry) => entry.request_id === request.requestId && entry.method === "POST");
  assert.equal(posts.length, 1); assert.equal(posts[0].node_id, node + 1); assert.equal(posts[0].outcome, "response");
  return { node_id: node + 1, request_id: request.requestId, request_epoch: request.requestEpoch, http_ordinal: posts[0].ordinal, code: posts[0].code, actual_service_response: true, posts: 1, original_server_deadline_ms: 2500, response_drain_allowance_ms: 1500 };
}

async function configureOrdinaryTokens() {
  cluster.tokens.same_reader = randomBytes(32).toString("hex");
  cluster.tokens.other_writer = randomBytes(32).toString("hex");
  for (let node = 0; node < 3; node++) {
    const config = cluster.configuration[node];
    config.databases[0].tokens.push(
      { sha256: digest(cluster.tokens.same_reader), principal_id: identity(200), credential_id: identity(204), auth_epoch: 1, permissions: 1 },
      { sha256: digest(cluster.tokens.other_writer), principal_id: identity(205), credential_id: identity(206), auth_epoch: 1, permissions: 3 },
    );
    await writeFile(cluster.configs[node], JSON.stringify(config), { mode: 0o600 });
    const legacy = path.join(cluster.directory, "legacy-node-" + (node + 1) + ".json");
    await writeFile(legacy, JSON.stringify(config), { flag: "wx", mode: 0o600 }); oldConfigurations.push(legacy);
  }
}

async function configureRetentionAdministrators() {
  // The original user keeps its original principal and replicated permissions.
  // Explicit new credentials bind the existing bootstrap admin already present
  // in every old database policy; activation never promotes a user principal.
  cluster.tokens.alpha_admin = randomBytes(32).toString("hex");
  cluster.tokens.beta_admin = randomBytes(32).toString("hex");
  for (let node = 0; node < 3; node++) {
    const config = cluster.configuration[node];
    for (const [index, database] of ["alpha", "beta"].entries()) config.databases[index].tokens.push({
      sha256: digest(cluster.tokens[database + "_admin"]), principal_id: identity(100), credential_id: identity(401 + index), auth_epoch: 1, permissions: 5, retention_admin: true,
    });
    await writeFile(cluster.configs[node], JSON.stringify(config), { mode: 0o600 });
  }
  alphaAdmin = cluster.client("alpha", { authToken: cluster.tokens.alpha_admin });
  betaAdmin = cluster.client("beta", { authToken: cluster.tokens.beta_admin });
  sameReader = cluster.client("alpha", { authToken: cluster.tokens.same_reader });
  otherWriter = cluster.client("alpha", { authToken: cluster.tokens.other_writer });
}

async function verifyRetired(record, label) {
  const result = await lookup(record, label);
  assert.deepEqual(result, { state: "retired", currentEpoch: epoch[record.database] });
}
async function verifyDurableState(label, databases = ["alpha", "beta"]) {
  const sql = {};
  for (const database of databases) {
    sql[database] = await sqlImage(database, label + "_" + database);
    const view = await status(database, label + "_status"); assert.equal(view.requestEpoch, epoch[database]);
    const current = retained.filter((entry) => entry.database === database && !entry.retired);
    assert.equal(view.retainedRequests, BigInt(current.length));
    assert.equal(view.unacknowledgedRequests, BigInt(current.filter((entry) => !entry.applicationAcknowledged).length));
    for (const record of current) await verifyTerminal(record, label + "_retained_terminal");
    for (const requestEpoch of new Set(retained.filter((entry) => entry.database === database && entry.retired).map((entry) => entry.request.requestEpoch))) {
      await verifyRetired(retained.find((entry) => entry.database === database && entry.request.requestEpoch === requestEpoch), label + "_retired_fence");
    }
  }
  return sql;
}

try {
  await contract("01-real-v3-hot-and-cold-producer", async () => {
    await s3.start();
    await writeFile(path.join(evidence, "s3-backend.json"), JSON.stringify(s3.identity, null, 2), { flag: "wx", mode: 0o600 });
    await cluster.prepare(); await configureOrdinaryTokens(); await cluster.launchAll(oldBinary, true);
    alpha = cluster.client("alpha"); beta = cluster.client("beta");
    for (const database of ["alpha", "beta"]) {
      await write(database, "legacy_" + database + "_schema", "CREATE TABLE witness(id INTEGER PRIMARY KEY,value TEXT NOT NULL)");
      await write(database, "legacy_" + database + "_random_result", "INSERT INTO witness VALUES(1,hex(randomblob(12))) RETURNING id,value");
      await cancel(database, "legacy_" + database + "_cancel", database === "alpha" ? -1 : -2);
    }
    const cold = await waitCold();
    oldArchives = await s3.archiveInventory(cluster.clusterId, cluster.cellId, identity(64));
    assert.ok(oldArchives.length > 0 && oldArchives.every((archive) => archive.format_version === 3));
    await event("real_v3_fixture_created", { source_commit: oldCommit, producer_sha256: oldIdentity.sha256, beta: cold, archives: oldArchives, profile_limits: profile, synthetic_old_state: false });
  });

  await contract("02-wire-generations-cannot-form-quorum", async () => {
    const membership = await cluster.membership();
    await query("alpha", "keep_alpha_hot_before_mixed_version", "SELECT 1");
    const upgraded = [0, 1, 2].find((node) => node !== membership.leader - 1);
    const oldApplied = await cluster.waitApplied(upgraded, membership.applied);
    await cluster.stop(upgraded, "SIGTERM"); await cluster.launch(upgraded, binary); await cluster.waitLive(upgraded);
    const ready = await observedFetch(cluster.endpoints[upgraded] + "/readyz", { redirect: "manual", signal: AbortSignal.timeout(1000) });
    await ready.body?.cancel(); assert.equal(ready.status, 503, "a lone new state machine cannot become ready using two old peers");
    const read = await rejectedDirect(upgraded, "mixed_new_read_rejected", "SELECT value FROM witness WHERE id=1", "read");
    const request = newRequest("alpha", ["INSERT INTO witness VALUES(-3,'mixed-version-must-not-commit')"]);
    const writeProbe = await rejectedDirect(upgraded, "mixed_new_write_once_rejected", request.statements[0], "write", request);
    await write("alpha", "old_quorum_still_commits", "INSERT INTO witness VALUES(2,hex(randomblob(12))) RETURNING id,value");
    await cancel("alpha", "mixed_write_ordered_resolution", -3, request);
    const witnessed = await cluster.membership(), after = await cluster.localStatus(upgraded);
    assert.ok(witnessed.applied > after.status.applied, "new wire4 node must not apply the old wire2 quorum's witnessed write");
    assert.notEqual(witnessed.leader, upgraded + 1);
    mixed = { upgraded_node_id: upgraded + 1, old_applied: oldApplied, isolated_new: after, old_quorum_witness: witnessed, rejected_read: read, rejected_write: writeProbe, old_peer_envelope_version: 2, new_peer_envelope_version: 4, peer_proxies_blocked: false };
    await event("wire_generations_fenced", mixed);
  });

  await contract("03-stop-upgrade-and-original-window-capacity", async () => {
    await cluster.stopAll("SIGTERM");
    await configureRetentionAdministrators();
    await event("all_old_and_new_processes_stopped", { replicas: cluster.processes.map((state, node) => ({ node_id: node + 1, exit: state.exit })), same_data_directories: true, initialize_used_after_first_boot: false, new_admin_binds_existing_bootstrap_policy: true });
    await cluster.launchAll(binary); newActive = true;
    const caughtUp = await cluster.waitApplied(mixed.upgraded_node_id - 1, mixed.old_quorum_witness.applied);
    for (const record of retained) await verifyTerminal(record, "original_terminal_after_v4_activation");
    assert.equal((await status("beta")).cold, true);
    let current = await status("alpha", "upgraded_window_start");
    assert.equal(current.requestEpoch, 1n); assert.equal(current.retainedRequests, BigInt(retained.filter((entry) => entry.database === "alpha").length));
    await event("same_legacy_directories_activated_v4", { lagging_replica_caught_up: caughtUp, witnessed_old_prefix: mixed.old_quorum_witness.applied, original_alpha: current, original_beta: await status("beta", "legacy_cold_after_activation"), old_terminal_count: retained.length });
    while (current.retainedRequests < 127n) {
      await write("alpha", "fill_original_window_" + current.retainedRequests, `INSERT INTO witness VALUES(${nextRow++},hex(randomblob(12))) RETURNING id,value`);
      current = await status("alpha", "window_fill_metadata");
    }
    const request = newRequest("alpha", [`INSERT INTO witness VALUES(${nextRow++},hex(randomblob(12))) RETURNING id,value`]);
    responseLoss = { kind: "write", requestId: request.requestId, requestEpoch: request.requestEpoch, observed: false };
    try {
      await expectError("alpha", "write", "committed_response_deliberately_lost", request, () => alpha.execute(request.statements[0], { requestId: request.requestId, requestEpoch: request.requestEpoch }), ["COMMIT_UNKNOWN"]);
      assert.equal(responseLoss.observed, true);
      const posts = http.filter((entry) => entry.request_id === request.requestId && entry.method === "POST");
      assert.equal(posts.length, 1); assert.equal(posts[0].outcome, "response_lost");
      const outcome = await operation("alpha", "lookup", "lost_write_actual_terminal", request, () => alpha.lookup(request));
      assert.equal(outcome.state, "committed"); assert.equal(outcome.acknowledged, false);
      lostWrite = await retainWrite("alpha", request, outcome.results[0], "committed_response_deliberately_lost", "lookup_after_response_loss");
    } finally { responseLoss = undefined; }
    const full = await status("alpha", "original_128_record_window_full");
    assert.equal(full.retainedRequests, 128n); assert.equal(full.unacknowledgedRequests, 128n);
    capacityRejected = newRequest("alpha", ["INSERT INTO witness VALUES(-4,'capacity-must-not-commit')"]);
    await expectError("alpha", "write", "129th_record_rejected_without_retry", capacityRejected, () => alpha.execute(capacityRejected.statements[0], { requestId: capacityRejected.requestId, requestEpoch: 1n }), ["COMMIT_UNKNOWN"]);
    const posts = http.filter((entry) => entry.request_id === capacityRejected.requestId && entry.method === "POST");
    assert.equal(posts.length, 1); assert.equal(posts[0].outcome, "response");
    assert.equal((await status("alpha")).retainedRequests, 128n);
    await sqlImage("alpha", "capacity_rejection_has_no_sql_effect");
    await event("original_request_capacity_preserved", { limit: 128, observed_records: full.retainedRequests, unknown_committed_request_id: lostWrite.request.requestId, overflow_request_id: capacityRejected.requestId, overflow_posts: posts.length, counters_unchanged: true });
  });

  await contract("04-explicit-receipts-and-ordered-retirement", async () => {
    const first = retained.find((entry) => entry.database === "alpha" && entry.state === "committed");
    const terminal = await verifyTerminal(first, "known_terminal_for_authorization_checks");
    await expectError("alpha", "acknowledge", "wrong_terminal_receipt_rejected", first.request, () => alpha.acknowledge(first.request, { ...terminal, sequence: terminal.sequence + 1n }), ["RESOLVE_REJECTED"]);
    await expectError("alpha", "acknowledge", "different_principal_cannot_ack", first.request, () => otherWriter.acknowledge(first.request, terminal), ["RESOLVE_REJECTED"]);
    await expectError("alpha", "acknowledge", "same_principal_read_only_cannot_borrow_write", first.request, () => sameReader.acknowledge(first.request, terminal), ["UNAUTHORIZED"]);
    const rotateRequest = newRequest("alpha");
    await expectError("alpha", "rotate", "ordinary_writer_cannot_rotate", rotateRequest, () => alpha.rotateRequests(1n, { requestId: rotateRequest.requestId }), ["UNAUTHORIZED"]);
    const pendingRequest = newRequest("alpha");
    await expectError("alpha", "rotate", "unacknowledged_window_cannot_rotate", pendingRequest, () => alphaAdmin.rotateRequests(1n, { requestId: pendingRequest.requestId }), ["RETIREMENT_REJECTED"]);
    const firstWindow = retained.filter((entry) => entry.database === "alpha");
    for (const [index, record] of firstWindow.entries()) {
      if (record !== lostWrite) await acknowledge(record, "explicit_ack_initial_window");
      if (index % 16 === 0) await query("alpha", "keep_initial_ack_window_hot", "SELECT 1");
    }
    const onePending = await status("alpha", "unknown_result_remains_unacknowledged");
    assert.equal(onePending.unacknowledgedRequests, 1n);
    const unknownBlocks = newRequest("alpha");
    await expectError("alpha", "rotate", "unprocessed_unknown_commit_blocks_rotation", unknownBlocks, () => alphaAdmin.rotateRequests(1n, { requestId: unknownBlocks.requestId }), ["RETIREMENT_REJECTED"]);
    await acknowledge(lostWrite, "application_explicitly_processes_lost_result");
    const firstRotation = await rotate("alpha", "retire_original_epoch");
    assert.equal(firstRotation.to_epoch, 2n);
    for (const record of firstWindow) await verifyRetired(record, "every_original_identity_is_retired");
    await expectError("alpha", "write", "retired_execute_rejected", first.request, () => alpha.execute(first.request.statements[0], { requestId: first.request.requestId, requestEpoch: 1n }), ["REQUEST_RETIRED"]);
    await expectError("alpha", "cancel", "retired_cancellation_rejected", first.request, () => alpha.resolveOrCancel(first.request), ["REQUEST_RETIRED"]);
    await expectError("alpha", "acknowledge", "retired_acknowledgement_rejected", first.request, () => alpha.acknowledge(first.request, terminal), ["REQUEST_RETIRED"]);
    const oldOverflow = { database: "alpha", request: capacityRejected };
    await verifyRetired(oldOverflow, "unknown_overflow_identity_fenced_by_retirement");
    await sqlImage("alpha", "retired_actions_have_no_sql_effects");
    await event("explicit_application_ack_and_retirement_verified", { initial_window: firstRotation, unknown_was_last_unacknowledged: lostWrite.request.requestId, wrong_receipt_and_authority_rejected: true, old_requests_permanently_fenced: true });
  });

  await contract("05-repeated-full-windows-with-offline-replica", async () => {
    const membership = await cluster.membership();
    const node = [0, 1, 2].find((candidate) => candidate !== membership.leader - 1);
    const before = await cluster.waitApplied(node, membership.applied);
    await cluster.stop(node, "SIGKILL"); lagger = { node, before };
    await event("replica_stopped_before_repeated_retirement", { node_id: node + 1, local: before });
    const reused = retained.find((entry) => entry.database === "alpha" && entry.state === "committed");
    for (const expectedEpoch of [2n, 3n]) {
      assert.equal(epoch.alpha, expectedEpoch);
      for (let entry = 0; entry < 128; entry++) {
        const record = await write("alpha", `epoch_${expectedEpoch}_write_${entry}`, `INSERT INTO witness VALUES(${nextRow++},hex(randomblob(12))) RETURNING id,value`, entry === 0 && expectedEpoch === 2n ? reused.request.requestId : id());
        await acknowledge(record, `epoch_${expectedEpoch}_explicit_ack_${entry}`);
      }
      const full = await status("alpha", "repeated_full_window");
      assert.equal(full.retainedRequests, 128n); assert.equal(full.unacknowledgedRequests, 0n);
      await verifyRetired(reused, "same_id_old_generation_stays_retired");
      const window = await rotate("alpha", "rotate_completed_window_" + expectedEpoch);
      assert.equal(window.retained_before, 128n);
      await event("full_request_window_reclaimed", { window });
    }
    assert.equal(epoch.alpha, 4n);
    assert.equal(windows.filter((entry) => entry.database === "alpha" && entry.retained_before === 128n).length, 3);
    await event("three_original_size_windows_completed", { windows: 3, retained_record_budget_per_window: 128, total_retired_records: 384, final_epoch: epoch.alpha, lagging_replica_id: node + 1, increased_limits: false });
  });

  await contract("06-snapshot-installs-retirement-fences", async () => {
    const live = [0, 1, 2].filter((node) => node !== lagger.node), deadline = performance.now() + 30_000;
    let sources;
    do {
      sources = await Promise.all(live.map((node) => cluster.localStatus(node)));
      if (sources.every((source) => source.status.snapshot_index > lagger.before.status.applied)) break;
      await query("alpha", "keep_alpha_hot_while_snapshot_advances", "SELECT 1"); await delay(100);
    } while (performance.now() < deadline);
    assert.ok(sources.every((source) => source.status.snapshot_index > lagger.before.status.applied), "every available source must have purged beyond the stopped replica's applied prefix");
    const witness = await cluster.membership();
    await cluster.launch(lagger.node, binary); await cluster.waitLive(lagger.node);
    const installed = await cluster.waitApplied(lagger.node, witness.applied);
    assert.ok(installed.status.snapshot_index >= Math.min(...sources.map((source) => source.status.snapshot_index)));
    // Beta must remain cold on the original V3 object until contract 07. A SQL
    // inspection here would hydrate it and invalidate the cold-ACK experiment.
    const sql = await verifyDurableState("after_lagging_snapshot_install", ["alpha"]);
    const betaCold = await status("beta", "legacy_beta_still_cold_after_snapshot_install");
    assert.equal(betaCold.cold, true); assert.equal(betaCold.requestEpoch, 1n);
    const local = await cluster.localStatus(lagger.node);
    await event("retirement_snapshot_install_verified", { lagging_node_id: lagger.node + 1, before: lagger.before, available_sources: sources, after: local, witnessed_prefix: witness.applied, sql, beta_cold: betaCold, new_directory_created: false, local_status_is_commit_proof: false });
  });

  await contract("07-cold-ack-survives-legacy-hydration", async () => {
    assert.equal((await status("beta")).cold, true);
    const betaRecords = retained.filter((entry) => entry.database === "beta" && !entry.retired);
    for (const record of betaRecords) await acknowledge(record, "ack_while_legacy_archive_is_cold");
    const cold = await status("beta", "cold_acknowledgements_are_metadata_only");
    assert.equal(cold.cold, true); assert.equal(cold.unacknowledgedRequests, 0n);
    const coldRotate = newRequest("beta");
    await expectError("beta", "rotate", "cold_rotation_requires_physical_materialization", coldRotate, () => betaAdmin.rotateRequests(1n, { requestId: coldRotate.requestId }), ["RETIREMENT_REJECTED"]);
    const blocked = s3.proxy.blockedConnections;
    s3.blackhole(true);
    const wake = query("beta", "legacy_archive_blackhole", "SELECT id,value FROM witness ORDER BY id", beta, 3000);
    const rejected = assert.rejects(wake, ScapError);
    const observedBy = performance.now() + 2000;
    while (s3.proxy.blockedConnections === blocked && performance.now() < observedBy) await delay(20);
    assert.ok(s3.proxy.blockedConnections > blocked, "the cold request must actually enter the S3 TCP blackhole");
    await query("alpha", "hot_database_survives_legacy_archive_blackhole", "SELECT 1");
    await rejected;
    const afterBlackhole = await status("beta", "failed_wake_keeps_cold_ack_metadata");
    assert.equal(afterBlackhole.cold, true); assert.equal(afterBlackhole.unacknowledgedRequests, 0n);
    await event("legacy_archive_tcp_blackhole_observed", { blocked_connections_before: blocked, blocked_connections_after: s3.proxy.blockedConnections, beta: afterBlackhole, hot_alpha_read_succeeded: true, failed_wake_not_replayed: true });
    s3.blackhole(false);
    await sqlImage("beta", "legacy_v3_archive_hydrated_by_v4");
    for (const record of betaRecords) await verifyTerminal(record, "cold_ack_survives_older_archive_hydration");
    const retiredBeta = await rotate("beta", "retire_beta_after_verified_hydration");
    assert.equal(retiredBeta.to_epoch, 2n);
    for (const record of betaRecords) await verifyRetired(record, "legacy_beta_result_retired");
    await write("beta", "new_v4_beta_write", "INSERT INTO witness VALUES(2,hex(randomblob(12))) RETURNING id,value");
    const newCold = await waitCold();
    newArchives = await s3.archiveInventory(cluster.clusterId, cluster.cellId, identity(64));
    assert.ok(newArchives.some((entry) => entry.format_version === 4));
    for (const old of oldArchives) assert.ok(newArchives.some((entry) => entry.sha256 === old.sha256), "old immutable objects must remain untouched by logical result retirement");
    await sqlImage("beta", "new_v4_archive_round_trip");
    await event("cold_metadata_and_archive_generations_preserved", { cold_ack: cold, retired_beta: retiredBeta, new_cold: newCold, old_archives: oldArchives, new_archives: newArchives, new_result_unacknowledged: true, obsolete_archive_reference_cleared: true });
  });

  await contract("08-unknown-rotation-and-crash-recovery", async () => {
    const beforeLostRotation = await write("alpha", "epoch4_result_before_lost_rotation", `INSERT INTO witness VALUES(${nextRow++},hex(randomblob(12))) RETURNING id,value`);
    await acknowledge(beforeLostRotation, "explicit_ack_before_lost_rotation");
    await rotate("alpha", "rotation_response_deliberately_lost", true);
    assert.equal(epoch.alpha, 5n);
    const pending = await write("alpha", "new_epoch_unacknowledged_result", `INSERT INTO witness VALUES(${nextRow++},hex(randomblob(12))) RETURNING id,value`);
    assert.equal((await verifyTerminal(pending, "pending_before_crash")).acknowledged, false);
    const before = await verifyDurableState("before_leader_sigkill");
    const membership = await cluster.membership(), leader = membership.leader - 1;
    const killed = await cluster.stop(leader, "SIGKILL"); await cluster.waitLeader();
    assert.deepEqual(await verifyDurableState("after_leader_sigkill"), before);
    await cluster.launch(leader, binary); await cluster.waitLive(leader);
    const committed = await cluster.membership();
    await Promise.all([0, 1, 2].map((node) => cluster.waitApplied(node, committed.applied)));
    const previousFiles = await cluster.writerFiles();
    await cluster.stopAll("SIGKILL");
    await event("three_replicas_sigkilled", { replicas: cluster.processes.map((state, node) => ({ node_id: node + 1, exit: state.exit })), prior_writer_files: previousFiles, lost_rotation: lostRotation });
    await cluster.launchAll(binary);
    assert.deepEqual(await verifyDurableState("after_full_group_sigkill"), before);
    recoveredFiles = await cluster.writerFiles();
    const oldWorkers = new Set(previousFiles.map((entry) => entry.worker_instance));
    assert.ok(recoveredFiles.length >= 2 && recoveredFiles.every((entry) => !oldWorkers.has(entry.worker_instance)));
    await event("unknown_rotation_and_crashes_preserve_fences", { leader_id: leader + 1, leader_exit: killed, lost_rotation: lostRotation, current_unacknowledged_request_id: pending.request.requestId, current_unacknowledged_epoch: pending.request.requestEpoch, sql: before, recovered_files: recoveredFiles, acknowledged_sql_lost: 0, original_unknown_sql_replayed: false });
  });

  await contract("09-old-binary-rejects-v4-and-new-reopens", async () => {
    const witness = await cluster.membership();
    const applied = await Promise.all([0, 1, 2].map((node) => cluster.waitApplied(node, witness.applied)));
    await cluster.stopAll("SIGTERM");
    const rejections = [];
    for (let node = 0; node < 3; node++) {
      const filename = path.join(scratch, "old-v3-open-" + (node + 1) + ".private.log");
      const child = await processAt(oldBinary, [oldConfigurations[node]], filename, { ...process.env, ...s3.env }, true);
      const exited = await Promise.race([child.done, delay(10_000).then(() => null)]);
      if (exited === null) { await child.stop(); throw new Error("old V3 daemon did not reject V4 disk state"); }
      assert.ok(exited.code !== null && exited.code !== 0 && exited.signal === null);
      assert.match(await readFile(filename, "utf8"), /STORE_APPLICATION/, "config, lock or port failures do not prove storage-version rejection");
      rejections.push({ node_id: node + 1, exit: exited, reason: "STORE_APPLICATION", old_compatible_configuration: true, initialize_flag_used: false });
    }
    await cluster.launchAll(binary);
    const sql = await verifyDurableState("after_rejected_v3_downgrade");
    assert.deepEqual(await fileIdentity(oldBinary), oldIdentity); assert.deepEqual(await fileIdentity(binary), currentIdentity);
    assert.deepEqual(await Promise.all(harnessIdentity.map((entry) => fileIdentity(entry.path))), harnessIdentity);
    await event("v3_downgrade_rejected_and_v4_state_reopened", { rejections, local_applied_before_stop: applied, committed_before_stop: witness.applied, sql, all_new_daemons_stopped_before_old_opens: true, no_database_reinitialization: true, source_inputs_unchanged: true });
  });

  const failed = requests.filter((entry) => entry.outcome !== "success");
  const summary = {
    completed, all_contracts_passed: completed.length === 9,
    request_attempts: requests.length, unsuccessful_attempts: failed, http_attempts: http.length,
    original_profile: profile, full_alpha_windows: windows.filter((window) => window.database === "alpha" && window.retained_before === 128n).length,
    total_retired_records: windows.reduce((sum, window) => sum + window.retained_before, 0n), application_acknowledgements: applicationAcks.length,
    successful_sql_responses: retained.filter((record) => record.observedVia === "successful_sql_response").length,
    committed_unknown_results_resolved_without_sql_replay: retained.filter((record) => record.observedVia === "lookup_after_response_loss").length,
    final_request_epochs: epoch, current_retained_results: retained.filter((record) => !record.retired).map((record) => ({ database: record.database, request_id: record.request.requestId, request_epoch: record.request.requestEpoch, acknowledged: record.applicationAcknowledged })),
    old_peer_envelope_version: 2, new_peer_envelope_version: 4, old_archive_format: 3, new_archive_format: 4,
    mixed_versions_rejected: true, source_snapshot_precedes_lagger_resume: true, same_id_new_epoch_tested: true,
    lost_rotation: lostRotation, leader_sigkill: true, full_group_sigkill: true, downgrade_rejected_nodes: 3,
    effective_voters: [1, 2, 3], membership_changes_submitted: 0, limits_increased: false,
    current_sql_state_equal: true, acknowledged_sql_lost: 0, production_slo_passed: false, private_fixture_data_exported: false,
  };
  await writeFile(path.join(evidence, "summary.json"), json(summary) + "\n", { flag: "wx", mode: 0o600 });
  const artifacts = [];
  for (const name of (await readdir(evidence)).sort()) artifacts.push({ name, ...(await fileIdentity(path.join(evidence, name))) });
  await writeFile(path.join(evidence, "artifacts.json"), json(artifacts) + "\n", { flag: "wx", mode: 0o600 });
  await event("all_retention_contracts_completed", { count: completed.length, all_samples_preserved: true, production_slo_passed: false });
} catch (error) {
  await writeFile(path.join(evidence, "failure.json"), json({ completed, request_attempts: requests.length, http_attempts: http.length, message: error.message, name: error.name, all_contracts_passed: false, production_slo_passed: false }) + "\n", { flag: "wx", mode: 0o600 });
  throw error;
} finally {
  for (const client of clients) client.close();
  const cleanup = await Promise.allSettled([cluster.close(), s3.close()]);
  const failures = cleanup.filter((result) => result.status === "rejected");
  if (failures.length) throw new AggregateError(failures.map((result) => result.reason), "private fixture cleanup failed");
}
