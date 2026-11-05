import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { appendFile, chmod, mkdir, mkdtemp, readFile, readdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { createClient, ScapError } from "../../sdk/node/dist/client.js";
import { Cluster, Seaweed, delay, digest, fileIdentity, identity, processAt } from "../history-network/deployment.mjs";

// This runner orchestrates only processes, faults and independent observations.
// The old executable and the archived old Rust source produce all legacy state.
const ALLOWED_OLD_COMMITS = new Set(["fa34c955ab8bcb1895e1348184bd0687d07833f8", "99e1e31cab1fd23fa25a64211671f9ceb56d8058", "f14b03d03d9216ea56b78aef9d71c5d78fd83645"]);
const OLD_COMMIT = process.env.SCAP_CONTROL_OLD_SERVER_SOURCE_COMMIT ?? "fa34c955ab8bcb1895e1348184bd0687d07833f8";
const LEGACY_PROBE_COMMIT = process.env.SCAP_CONTROL_LEGACY_SOURCE_COMMIT ?? "f14b03d03d9216ea56b78aef9d71c5d78fd83645";
const OLD_SHA = process.env.SCAP_CONTROL_OLD_SERVER_SHA256 ?? "52e81c031af6202ef4a41b2b8fab59d3cf202f56af51161951e7eb85f115b68b";
assert.ok(ALLOWED_OLD_COMMITS.has(OLD_COMMIT)); assert.ok(ALLOWED_OLD_COMMITS.has(LEGACY_PROBE_COMMIT));
assert.match(OLD_SHA, /^[0-9a-f]{64}$/);
const required = (name) => {
  const value = process.env[name]; assert.ok(value && path.isAbsolute(value), `${name} must be an absolute path`); return value;
};
const binary = required("SCAP_SERVER_BIN"), oldBinary = required("SCAP_OLD_SERVER_BIN");
const testBinary = required("SCAP_CONTROL_TEST_BIN"), legacyTestBinary = required("SCAP_CONTROL_LEGACY_TEST_BIN");
const probeBuildReceipt = required("SCAP_CONTROL_PROBE_BUILD_RECEIPT");
const legacySourceReceipt = required("SCAP_CONTROL_LEGACY_SOURCE_RECEIPT");
assert.equal(process.env.LLVM_PROFILE_FILE, undefined, "fault experiments cannot contribute unit profiles");
assert.equal(process.env.NODE_V8_COVERAGE, undefined, "fault experiments cannot contribute unit profiles");
const evidence = process.env.SCAP_CONTROL_EVIDENCE_DIR ?? await mkdtemp(path.join(tmpdir(), "scap-control-evidence-"));
assert.ok(path.isAbsolute(evidence) && path.relative(tmpdir(), evidence) && !path.relative(tmpdir(), evidence).startsWith(".."), "live evidence must use a unique /tmp subdirectory, then be closed and checked before copying");
await mkdir(evidence, { recursive: true, mode: 0o700 }); await chmod(evidence, 0o700);
assert.deepEqual(await readdir(evidence), [], "never append a second run to previous evidence");
const scratch = await mkdtemp(path.join(tmpdir(), "scap-control-fixture-"));
const legacyFixture = path.join(scratch, "closed-v4-full-table");
const started = performance.now(), ms = () => Math.round((performance.now() - started) * 1000) / 1000;
const id = () => randomUUID().replaceAll("-", "");
const json = (value) => JSON.stringify(value, (_, entry) => typeof entry === "bigint" ? entry.toString() : entry);
const oldIdentity = await fileIdentity(oldBinary), currentIdentity = await fileIdentity(binary);
assert.equal(oldIdentity.sha256, OLD_SHA, "the real v4 producer must match its frozen release build receipt");
assert.notEqual(currentIdentity.sha256, oldIdentity.sha256);
const legacySource = JSON.parse(await readFile(legacySourceReceipt, "utf8"));
const probeBuild = JSON.parse(await readFile(probeBuildReceipt, "utf8"));
assert.equal(legacySource.source_commit, LEGACY_PROBE_COMMIT); assert.equal(legacySource.synthetic_old_state, false);
const binaries = { old: { ...oldIdentity, source_commit: OLD_COMMIT, selected_build_receipt_sha256: OLD_SHA }, current: currentIdentity, probe: await fileIdentity(testBinary), legacy_probe: await fileIdentity(legacyTestBinary) };
assert.equal(legacySource.executable.sha256, binaries.legacy_probe.sha256, "legacy probe binary must match the completed source-bound build receipt");
assert.equal(legacySource.executable.bytes, binaries.legacy_probe.bytes);
for (const [build, executable, target] of [[probeBuild, binaries.probe, "contracts"], [legacySource.probe_build, binaries.legacy_probe, "legacy"]]) {
  assert.equal(build.complete, true); assert.equal(build.build_profile, "release"); assert.equal(build.target, target);
  assert.equal(build.executable.sha256, executable.sha256); assert.equal(build.executable.bytes, executable.bytes);
  assert.equal(build.cargo_artifact.profile.opt_level, "3"); assert.equal(build.cargo_artifact.profile.debug_assertions, false);
  assert.equal(build.cargo_artifact.profile.test, true); assert.equal(build.fault_tests_executed, false);
}
for (const input of legacySource.harness_inputs) {
  const actual = await fileIdentity(fileURLToPath(new URL(input.relative_path, import.meta.url)));
  assert.equal(actual.sha256,input.sha256,"legacy harness input differs from its source-bound build receipt");
}
const harness = [];
async function inventory(directory) {
  for (const entry of (await readdir(directory, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
    if (entry.name === "target" || entry.name === "__pycache__") continue;
    const filename = path.join(directory, entry.name);
    if (entry.isDirectory()) await inventory(filename);
    else { assert.ok(entry.isFile()); harness.push(await fileIdentity(filename)); }
  }
}
await inventory(fileURLToPath(new URL(".", import.meta.url)));
harness.push(await fileIdentity(fileURLToPath(new URL("../history-network/deployment.mjs", import.meta.url))));
harness.push(await fileIdentity(fileURLToPath(new URL("../../sdk/node/dist/client.js", import.meta.url))));
await writeFile(path.join(evidence, "binary.json"), json({ ...binaries, harness, candidate_description: process.env.SCAP_SERVICE_BUILD_DESCRIPTION ?? "current local candidate" }) + "\n", { flag: "wx", mode: 0o600 });
await writeFile(path.join(evidence, "legacy-source.json"), json(legacySource) + "\n", { flag: "wx", mode: 0o600 });
await writeFile(path.join(evidence, "probe-build.json"), json(probeBuild) + "\n", { flag: "wx", mode: 0o600 });
for (const [prefix, build] of [["probe", probeBuild], ["legacy", legacySource.probe_build]]) {
  for (const [suffix, recorded] of [["-cargo.jsonl", build.build_stdout], ["-cargo.stderr.log", build.build_stderr]]) {
    const raw = await readFile(recorded.path);
    assert.equal(raw.length, recorded.bytes); assert.equal(digest(raw), recorded.sha256, "closed probe build log changed");
    await writeFile(path.join(evidence, prefix + suffix), raw, { flag: "wx", mode: 0o600 });
  }
}
for (const name of ["requests.jsonl", "http-attempts.jsonl", "write-results.jsonl"]) await writeFile(path.join(evidence, name), "", { flag: "wx", mode: 0o600 });
let history, requestOrdinal = 0, httpOrdinal = 0;
const completed = [], requests = [], http = [], retained = [], clients = [], probes = [];
const expected = { alpha: new Map(), beta: new Map() };
const require = createRequire(new URL("../../sdk/node/package.json", import.meta.url));
const { createClient: nativeClient } = require("@libsql/client/http");
async function event(event, fields = {}) {
  const line = json({ elapsed_ms: ms(), event, ...fields });
  if (history) await appendFile(history, line + "\n");
  process.stdout.write(line + "\n");
}
async function observedFetch(input, init) {
  const request = new Request(input, init), url = new URL(request.url);
  const node = cluster.endpoints?.indexOf(url.origin) ?? -1, management = cluster.managementEndpoints?.indexOf(url.origin) ?? -1;
  const record = { ordinal: httpOrdinal++, invoked_ms: ms(), node_id: Math.max(node, management) + 1, method: request.method, route: url.pathname, request_id: request.headers.get("x-scap-request-id"), request_epoch: request.headers.get("x-scap-request-epoch"), mode: request.headers.get("x-scap-mode"), deadline_unix_ms: request.headers.get("x-scap-deadline-unix-ms") };
  try {
    const response = await fetch(request); record.status = response.status; record.outcome = "response";
    if (request.method === "POST" || url.pathname.includes("/v1/admin/")) {
      try { const body = await response.clone().json(); record.code = body.code ?? body.results?.find((entry) => entry.type === "error")?.error?.code ?? null; }
      catch { record.code = "UNPARSEABLE_RESPONSE"; }
    }
    return response;
  } catch (error) { record.outcome = "transport_error"; record.code = error.name; throw error; }
  finally { record.result_ms = ms(); http.push(record); await appendFile(path.join(evidence, "http-attempts.jsonl"), json(record) + "\n"); }
}
const s3 = new Seaweed(path.join(scratch, "s3"), event);
const cluster = new Cluster(path.join(scratch, "replicas"), s3, observedFetch, (config) => {
  const client = createClient(config, { fetch: observedFetch, now: Date.now, monotonic: () => performance.now(), requestId: id, createClient: nativeClient }); clients.push(client); return client;
});
let users, mixed, oldArchives;
async function contract(name, run) {
  history = path.join(evidence, name + ".history.jsonl"); await writeFile(history, "", { flag: "wx", mode: 0o600 });
  await event("contract_started", { name });
  await run();
  cluster.assertNoUnexpectedExit(); await event("contract_completed", { name }); completed.push(name);
}
async function operation(database, kind, label, request, run) {
  const record = { ordinal: requestOrdinal++, invoked_ms: ms(), database, kind, label, request_id: request?.requestId ?? null, request_epoch: request?.requestEpoch ?? 1n };
  try { const result = await run(); record.outcome = "success"; return result; }
  catch (error) { record.outcome = error instanceof ScapError ? "service_error" : "failure"; record.code = error.code ?? error.name; throw error; }
  finally { record.result_ms = ms(); requests.push(record); await appendFile(path.join(evidence, "requests.jsonl"), json(record) + "\n"); }
}
const normalized = (result) => ({ columns: [...result.columns], rows: result.rows.map((row) => Array.from(row)), rowsAffected: result.rowsAffected, lastInsertRowid: result.lastInsertRowid ?? null });
async function write(database, label, statement) {
  const request = { requestId: id(), requestEpoch: 1n, statements: [statement] };
  const tracked = await operation(database, "write", label, request, () => users[database].executeTracked(statement, { requestId: request.requestId, requestEpoch: 1n }));
  assert.equal(tracked.request.requestId, request.requestId); assert.equal(tracked.request.requestEpoch, 1n);
  const result = normalized(tracked.result), record = { database, request, result, state: "committed" }; retained.push(record);
  const a = result.columns.indexOf("id"), b = result.columns.indexOf("value");
  if (a >= 0 && b >= 0) for (const row of result.rows) expected[database].set(row[a].toString(), row[b]);
  await appendFile(path.join(evidence, "write-results.jsonl"), json({ database, request_id: request.requestId, request_epoch: 1n, label, result, statement_sha256: digest(statement) }) + "\n");
  return record;
}
async function query(database, label, statement) {
  const request = { requestId: id(), requestEpoch: 1n, statements: [statement] };
  return operation(database, "read", label, request, () => users[database].query(statement, { requestId: request.requestId, requestEpoch: 1n }));
}
async function warmRead(database, label, statement) {
  // Each failed read remains in evidence. Reads alone may be attempted again
  // while asynchronous recovery finishes; uncertain mutations are never replayed.
  const deadline = performance.now() + 30_000;
  do {
    try { return await query(database, label, statement); }
    catch (error) { if (!(error instanceof ScapError) || !["NOT_LEADER", "COMMIT_UNKNOWN", "OVERLOADED", "ARCHIVE_UNAVAILABLE", "RECOVERY_UNAVAILABLE", "EXPIRED"].includes(error.code)) throw error; }
    await delay(150);
  } while (performance.now() < deadline);
  throw new Error("read-only recovery fixture deadline expired");
}
async function status(database) {
  const request = { requestId: id(), requestEpoch: 1n };
  return operation(database, "status", "metadata", request, () => users[database].status({ requestId: request.requestId, requestEpoch: 1n }));
}
async function verify(label, includeSql = true) {
  for (const record of retained) {
    const outcome = await operation(record.database, "lookup", label, record.request, () => users[record.database].lookup(record.request));
    assert.equal(outcome.state, record.state);
    if (record.state === "committed") assert.deepEqual(outcome.results, [record.result]);
    else assert.deepEqual(outcome.position, record.position);
  }
  const images = {};
  if (includeSql) for (const database of ["alpha", "beta"]) {
    const rows = await warmRead(database, label, "SELECT id,value FROM witness ORDER BY id");
    const actual = rows.rows.map((row) => [row.id.toString(), row.value]);
    const wanted = [...expected[database]].sort((a, b) => Number(BigInt(a[0]) - BigInt(b[0])));
    assert.deepEqual(actual, wanted); images[database] = { rows: actual.length, sha256: digest(json(actual)) };
  }
  return images;
}
async function cold(database = "beta") {
  const deadline = performance.now() + 45_000; let value;
  do {
    value = await status(database); if (value.cold) break;
    if (database !== "alpha") await warmRead("alpha", "keep_alpha_hot", "SELECT 1");
    await delay(150);
  } while (performance.now() < deadline);
  assert.equal(value.cold, true); assert.equal(value.suspended, true); assert.equal(value.ownerActive, false); assert.equal(value.archivedRevision, value.revision); return value;
}
async function waitWithTimeout(promise, milliseconds) {
  let timer;
  try {
    return await Promise.race([promise, new Promise((resolve) => { timer = setTimeout(() => resolve(null), milliseconds); })]);
  } finally {
    clearTimeout(timer);
  }
}
async function runProbe(executable, name, filename, timeoutMs = 600_000) {
  const state = await processAt(executable, ["--exact", name, "--nocapture", "--test-threads=1"], path.join(evidence, filename), {
    ...process.env, ...s3.env, SCAP_CONTROL_EVIDENCE_DIR: evidence, SCAP_CONTROL_S3_ENDPOINT: s3.config.endpoint, SCAP_CONTROL_LEGACY_FIXTURE_DIR: legacyFixture,
  }, true); probes.push(state);
  const exit = await waitWithTimeout(state.done, timeoutMs);
  if (exit === null) { await state.stop(); throw new Error(name + " exceeded its finite fault-contract deadline"); }
  assert.deepEqual(exit, { code: 0, signal: null }, "real Rust contract failed; original output is retained");
  const output = await readFile(state.file, "utf8"); assert.match(output, /test result: ok\. 1 passed; 0 failed/);
  return exit;
}
async function rejectedDirect(node, mode, statement) {
  const request = { requestId: id(), requestEpoch: 1n, statements: [statement] }, deadline = Date.now() + 2500;
  let posts = 0, rejection;
  const driver = nativeClient({ url: cluster.endpoints[node] + "/db/alpha/", authToken: cluster.tokens.alpha, intMode: "bigint", fetch: async (input, init) => {
    const wire = new Request(input, init); assert.equal(new URL(wire.url).origin, cluster.endpoints[node]);
    if (wire.method === "POST") assert.equal(++posts, 1);
    wire.headers.set("x-scap-request-id", request.requestId); wire.headers.set("x-scap-request-epoch", "1"); wire.headers.set("x-scap-mode", mode); wire.headers.set("x-scap-deadline-unix-ms", String(deadline));
    return observedFetch(wire, { redirect: "manual", signal: AbortSignal.timeout(Math.max(1, deadline - Date.now() + 1500)) });
  } });
  try {
    await operation("alpha", "mixed_" + mode, "single_new_generation_probe", request, async () => {
      try { return await driver.execute(statement); }
      catch (error) { if (error instanceof assert.AssertionError) throw error; throw new ScapError(error.message, error.code ?? "COMMIT_UNKNOWN", request); }
    });
  } catch (error) { rejection = error; }
  finally { driver.close(); }
  assert.ok(rejection instanceof ScapError); assert.ok(["NOT_LEADER", "COMMIT_UNKNOWN", "EXPIRED"].includes(rejection.code)); assert.equal(posts, 1);
  const attempts = http.filter((entry) => entry.request_id === request.requestId && entry.method === "POST"); assert.equal(attempts.length, 1);
  assert.equal(attempts[0].node_id, node + 1); assert.equal(attempts[0].outcome, "response");
  return { request, evidence: { node_id: node + 1, request_id: request.requestId, http_ordinal: attempts[0].ordinal, code: attempts[0].code, posts: 1 } };
}

try {
  await contract("01-full-v4-control-table-and-new-bounded-faults", async () => {
    await s3.start(); await writeFile(path.join(evidence, "s3-backend.json"), json(s3.identity) + "\n", { flag: "wx", mode: 0o600 });
    await runProbe(legacyTestBinary, "real_v4_full_legacy_table", "legacy-test.log");
    const produced = JSON.parse(await readFile(path.join(evidence,"legacy-producer.json"),"utf8"));
    assert.equal(produced.source_commit, legacySource.source_commit); assert.equal(produced.source_tree, legacySource.source_tree);
    await runProbe(testBinary, "full_v4_fixture_activates_bounded_control", "legacy-upgrade-test.log");
    await runProbe(testBinary, "bounded_control_faults", "control-test.log");
    await event("rust_contracts_completed", { legacy_controls: 4096, new_controls: 4097, old_producer_source_commit: LEGACY_PROBE_COMMIT, old_daemon_source_commit: OLD_COMMIT, real_s3: true, synthetic_old_state: false });
  });
  await contract("02-real-v4-production-hot-and-cold-data", async () => {
    await cluster.prepare(); await cluster.launchAll(oldBinary, true); users = { alpha: cluster.client("alpha"), beta: cluster.client("beta") };
    for (const database of ["alpha", "beta"]) {
      await warmRead(database, "initial_native_owner", "SELECT 1");
      await write(database, "legacy_schema", "CREATE TABLE witness(id INTEGER PRIMARY KEY,value TEXT NOT NULL)");
      await write(database, "legacy_random_result", "INSERT INTO witness VALUES(1,hex(randomblob(12))) RETURNING id,value");
    }
    await verify("legacy_original_results", false);
    const beta = await cold(); oldArchives = await s3.archiveInventory(cluster.clusterId, cluster.cellId, identity(64));
    assert.ok(oldArchives.length > 0 && oldArchives.every((entry) => entry.format_version === 4));
    await event("real_v4_production_fixture", { producer_sha256: OLD_SHA, source_commit: OLD_COMMIT, beta, archives: oldArchives, synthetic_old_state: false });
  });
  await contract("03-mixed-peer-generations-fail-closed", async () => {
    const before = await cluster.membership(), upgraded = [0, 1, 2].find((node) => node !== before.leader - 1);
    const oldApplied = await cluster.waitApplied(upgraded, before.applied);
    await cluster.stop(upgraded, "SIGTERM"); await cluster.launch(upgraded, binary); await cluster.waitLive(upgraded);
    const ready = await observedFetch(cluster.endpoints[upgraded] + "/readyz", { signal: AbortSignal.timeout(1000) }); await ready.body?.cancel(); assert.equal(ready.status, 503);
    const read = await rejectedDirect(upgraded, "read", "SELECT value FROM witness WHERE id=1");
    const deniedWrite = await rejectedDirect(upgraded, "write", "INSERT INTO witness VALUES(-3,'must-not-commit')");
    await write("alpha", "old_quorum_witness", "INSERT INTO witness VALUES(2,hex(randomblob(12))) RETURNING id,value");
    const terminal = await operation("alpha", "cancel", "ordered_resolution_of_mixed_probe", deniedWrite.request, () => users.alpha.resolveOrCancel(deniedWrite.request)); assert.equal(terminal.state, "cancelled");
    retained.push({ database: "alpha", request: deniedWrite.request, state: "cancelled", position: terminal.position });
    const witnessed = await cluster.membership(), isolated = await cluster.localStatus(upgraded);
    assert.ok(witnessed.applied > isolated.status.applied); assert.notEqual(witnessed.leader, upgraded + 1); assert.ok(cluster.proxies.every((proxy) => !proxy.blocked));
    mixed = { upgraded_node: upgraded + 1, before: oldApplied, isolated_new: isolated, old_quorum_witness: witnessed, read: read.evidence, write: deniedWrite.evidence, old_peer_version: 3, new_peer_version: 4, proxies_blocked: false };
    await event("mixed_generations_rejected", mixed);
  });
  await contract("04-v4-to-v5-upgrade-cold-and-crash-recovery", async () => {
    await cluster.stopAll("SIGTERM"); await cluster.launchAll(binary);
    await cluster.waitApplied(mixed.upgraded_node - 1, mixed.old_quorum_witness.applied);
    const oldCold = await status("beta"); assert.equal(oldCold.cold, true);
    await verify("same_directories_after_v5_activation", false);
    const originalSql = await verify("legacy_archive_hydrated");
    for (let cycle = 0; cycle < 2; cycle++) {
      const before = await cold(); const images = await verify("current_real_cold_cycle_" + cycle); assert.deepEqual(images, originalSql);
      await event("production_cold_cycle", { cycle, cold: before, sql: images, retained_results_identical: true });
    }
    const leader = await cluster.waitLeader(), killed = await cluster.stop(leader, "SIGKILL"); assert.equal(killed.signal, "SIGKILL");
    await cluster.waitLeader(); const afterKill = await verify("owner_process_sigkill"); assert.deepEqual(afterKill, originalSql);
    await cluster.launch(leader, binary); await cluster.waitLive(leader);
    const witness = await cluster.membership(); await Promise.all([0, 1, 2].map((node) => cluster.waitApplied(node, witness.applied)));
    await cluster.stopAll("SIGKILL"); await cluster.launchAll(binary); assert.deepEqual(await verify("all_processes_reopened"), originalSql);
    const archives = await s3.archiveInventory(cluster.clusterId, cluster.cellId, identity(64)); assert.ok(archives.every((entry) => entry.format_version === 4));
    await event("v5_recovery_preserves_originals", { original_sql: originalSql, old_archive_format: 4, current_archive_format: 4, archives, leader_sigkill: killed, group_sigkill: true, original_results_verified: retained.length, acknowledged_sql_lost: 0, unknown_mutations_replayed: false });
  });
  await contract("05-v4-binary-rejects-v5-state", async () => {
    const witness = await cluster.membership(); await Promise.all([0, 1, 2].map((node) => cluster.waitApplied(node, witness.applied))); await cluster.stopAll("SIGTERM");
    const rejections = [];
    for (let node = 0; node < 3; node++) {
      const filename = path.join(scratch, "old-v4-reopen-" + (node + 1) + ".private.log");
      const child = await processAt(oldBinary, [cluster.configs[node]], filename, { ...process.env, ...s3.env }, true); probes.push(child);
      const exit = await waitWithTimeout(child.done, 10_000);
      if (exit === null) { await child.stop(); throw new Error("old v4 binary failed to reject v5 state"); }
      assert.ok(exit.code !== null && exit.code !== 0 && exit.signal === null); assert.match(await readFile(filename, "utf8"), /STORE_APPLICATION/);
      rejections.push({ node_id: node + 1, exit, reason: "STORE_APPLICATION", old_compatible_configuration: true, initialize_used: false });
    }
    await cluster.launchAll(binary); const sql = await verify("after_rejected_downgrade");
    await event("old_binary_rejected_and_new_reopened", { rejections, sql, committed_before_stop: witness.applied, same_directories: true, old_processes_all_rejected: true });
  });
  for (const [key, filename] of [["old", oldBinary], ["current", binary], ["probe", testBinary], ["legacy_probe", legacyTestBinary]]) assert.deepEqual(await fileIdentity(filename), binaries[key].path ? { path: binaries[key].path, bytes: binaries[key].bytes, sha256: binaries[key].sha256 } : binaries[key]);
  for (const expected of harness) assert.deepEqual(await fileIdentity(expected.path), expected, "harness inputs changed during the evidence interval");
  // Close all writers and process-owned files before hashing the evidence set.
  for (const client of clients) client.close();
  await cluster.close(); await s3.close();
  await writeFile(path.join(evidence, "summary.json"), json({ schema: 1, completed, all_contracts_passed: completed.length === 5, legacy_full_controls: 4096, successful_bounded_controls: 4097, real_production_cold_cycles: 2, original_terminal_results: retained.length, unsuccessful_attempts: requests.filter((record) => record.outcome !== "success"), request_attempts: requests.length, http_attempts: http.length, old_peer_version: 3, new_peer_version: 4, old_state_version: 4, new_state_version: 5, mixed_peer_generations_rejected: true, downgraded_nodes_rejected: 3, unknown_mutations_replayed: false, acknowledged_sql_lost: 0, production_slo_passed: false, processes_closed: true }) + "\n", { flag: "wx", mode: 0o600 });
  const artifacts = [];
  for (const name of (await readdir(evidence)).sort()) { const details = await fileIdentity(path.join(evidence, name)); artifacts.push({ name, bytes: details.bytes, sha256: details.sha256 }); }
  await writeFile(path.join(evidence, "closed-manifest.json"), json({ schema: 1, closed: true, artifacts }) + "\n", { flag: "wx", mode: 0o600 });
  history = undefined; await event("all_control_contracts_completed", { count: completed.length, all_samples_preserved: true, evidence, production_slo_passed: false });
} catch (error) {
  await writeFile(path.join(evidence, "failure.json"), json({ completed, request_attempts: requests.length, http_attempts: http.length, name: error.name, message: error.message, all_contracts_passed: false }) + "\n", { flag: "wx", mode: 0o600 }); throw error;
} finally {
  for (const client of clients) client.close();
  const cleanup = await Promise.allSettled([cluster.close(), s3.close(), ...probes.map((state) => state.stop())]);
  const failures = cleanup.filter((entry) => entry.status === "rejected");
  if (failures.length) throw new AggregateError(failures.map((entry) => entry.reason), "control fixture cleanup failed");
}
