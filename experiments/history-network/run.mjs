import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { appendFile, chmod, mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { createClient, ScapError } from "../../sdk/node/dist/client.js";
import { Cluster, Seaweed, delay, digest, fileIdentity, identity, processAt } from "./deployment.mjs";

// The old application format is produced by a separately built, pinned V2
// daemon. This harness never synthesizes an old cell image or replays SQL to
// manufacture an upgrade fixture.
const oldCommit = "662f04133f6a869d0dae5b05467656e6deca5c12";
const frozenOldSha = "9a9df3656d99e5275ca4cee74ceb7e8c85ba37156d5e24e605011728c7064dbb";
const binary = process.env.SCAP_SERVER_BIN, oldBinary = process.env.SCAP_OLD_SERVER_BIN;
assert.ok(binary && path.isAbsolute(binary) && oldBinary && path.isAbsolute(oldBinary), "SCAP_SERVER_BIN and SCAP_OLD_SERVER_BIN must be absolute production binary paths");
assert.equal(process.env.SCAP_OLD_SERVER_SOURCE_COMMIT ?? oldCommit, oldCommit, "the old producer must be the pinned V2 source commit");
assert.equal(process.env.LLVM_PROFILE_FILE, undefined, "real upgrade/fault contracts cannot enter unit coverage");
assert.equal(process.env.NODE_V8_COVERAGE, undefined, "real upgrade/fault contracts cannot enter unit coverage");
const evidence = process.env.SCAP_HISTORY_EVIDENCE_DIR ?? await mkdtemp(path.join(tmpdir(), "scap-history-evidence-"));
await mkdir(evidence, { recursive: true, mode: 0o700 }); await chmod(evidence, 0o700);
const scratch = await mkdtemp(path.join(tmpdir(), "scap-history-fixture-"));
const origin = performance.now();
const milliseconds = () => Math.round((performance.now() - origin) * 1000) / 1000;
const id = () => randomUUID().replaceAll("-", "");
const json = (value) => JSON.stringify(value, (_, field) => typeof field === "bigint" ? field.toString() : field);
const oldIdentity = await fileIdentity(oldBinary), newIdentity = await fileIdentity(binary);
assert.equal(oldIdentity.sha256, process.env.SCAP_OLD_SERVER_SHA256 ?? frozenOldSha, "old executable does not match the explicitly selected V2 build receipt");
assert.notEqual(oldIdentity.sha256, newIdentity.sha256, "upgrade requires distinct old and new production executables");
const harnessIdentity = await Promise.all([fileURLToPath(import.meta.url), fileURLToPath(new URL("deployment.mjs", import.meta.url)), fileURLToPath(new URL("check_evidence.py", import.meta.url))].map(fileIdentity));
await writeFile(path.join(evidence, "binary.json"), JSON.stringify({ old: { ...oldIdentity, source_commit: oldCommit }, current: { ...newIdentity, build_description: process.env.SCAP_SERVICE_BUILD_DESCRIPTION ?? "current local working tree" }, harness: harnessIdentity }, null, 2), { flag: "wx", mode: 0o600 });
for (const filename of ["requests.jsonl", "http-attempts.jsonl", "overwrites.jsonl", "acknowledgements.jsonl"]) await writeFile(path.join(evidence, filename), "", { flag: "wx", mode: 0o600 });

const require = createRequire(new URL("../../sdk/node/package.json", import.meta.url));
const { createClient: nativeClient } = require("@libsql/client/http");
const completed = [], attempts = [], httpAttempts = [], acknowledgements = [], cancellations = [];
const clients = [];
let history, requestOrdinal = 0, httpOrdinal = 0;
let cumulativeObservedPhysical = 0n, baseAdvances = 0, maxTailEntries = 0n, maxTailBytes = 0n;
let alphaNonce, betaNonce, alphaPayload, legacyArchives, currentArchives, recoveryFiles, mixedVersion, overwriteStart;
const profile = { databases: 32, database_bytes: 256 * 1024, requests_per_database: 128, state_bytes: 8 * 1024 * 1024, transaction_bytes: 300 * 1024, tail_entries_trigger: 8, tail_bytes_trigger: 1_228_800 };

async function event(event, fields = {}) {
  const line = json({ elapsed_ms: milliseconds(), event, ...fields });
  if (history) await appendFile(history, line + "\n");
  process.stdout.write(line + "\n");
}

async function observedFetch(input, init) {
  const request = new Request(input, init), target = new URL(request.url);
  const node = cluster.endpoints?.indexOf(target.origin) ?? -1, managementNode = cluster.managementEndpoints?.indexOf(target.origin) ?? -1;
  const observation = { ordinal: httpOrdinal++, invoked_ms: milliseconds(), node_id: Math.max(node, managementNode) + 1, method: request.method, route: target.pathname, request_id: request.headers.get("x-scap-request-id"), mode: request.headers.get("x-scap-mode"), deadline_unix_ms: request.headers.get("x-scap-deadline-unix-ms") };
  try {
    const response = await fetch(request);
    observation.status = response.status; observation.outcome = "response";
    if (request.method === "POST" || target.pathname === "/v1/admin/membership") {
      // Store only a public error code, never tokens, SQL bodies or response
      // data. This lets the audit distinguish a before-proposal NOT_LEADER
      // route from an impermissible retry after an uncertain submission.
      try {
        const body = await response.clone().json();
        observation.code = body.code ?? body.results?.find((entry) => entry.type === "error")?.error?.code ?? null;
      } catch { observation.code = "UNPARSEABLE_RESPONSE"; }
    }
    return response;
  } catch (error) {
    observation.outcome = "transport_error"; observation.code = error.name;
    throw error;
  } finally {
    observation.result_ms = milliseconds();
    httpAttempts.push(observation);
    await appendFile(path.join(evidence, "http-attempts.jsonl"), json(observation) + "\n");
  }
}

const s3 = new Seaweed(path.join(scratch, "s3"), event);
const cluster = new Cluster(path.join(scratch, "replicas"), s3, observedFetch, (config) => {
  const client = createClient(config, { fetch: observedFetch, now: Date.now, monotonic: () => performance.now(), requestId: id, createClient: nativeClient });
  clients.push(client); return client;
});
let alpha, beta;

async function contract(name, action) {
  history = path.join(evidence, name + ".history.jsonl");
  await writeFile(history, "", { flag: "wx", mode: 0o600 });
  await event("contract_started", { name });
  try {
    await action(); cluster.assertNoUnexpectedExit();
    await event("contract_completed", { name });
    await appendFile(history, "verification passed\n"); completed.push(name);
  } catch (error) {
    await event("contract_failed", { name, message: error.message }); throw error;
  } finally { history = undefined; }
}

async function operation(database, kind, label, requestId, run, statement) {
  const record = { ordinal: requestOrdinal++, database, kind, label, request_id: requestId, invoked_ms: milliseconds() };
  if (statement !== undefined) record.statement_sha256 = digest(typeof statement === "string" ? statement : json(statement));
  try {
    const result = await run(); record.outcome = "success";
    if (kind === "lookup" || kind === "cancel") {
      record.observed_state = result.state;
      if (result.state === "committed") {
        record.sequence = result.sequence.toString();
        record.results_sha256 = digest(json(result.results));
      }
    }
    if (kind === "status") record.metadata = result;
    return result;
  } catch (error) {
    record.outcome = error instanceof ScapError ? "service_error" : "failure";
    record.code = error.code ?? error.name; throw error;
  } finally {
    record.result_ms = milliseconds(); attempts.push(record);
    await appendFile(path.join(evidence, "requests.jsonl"), json(record) + "\n");
  }
}

function normalized(result) {
  return { columns: [...result.columns], rows: result.rows.map((row) => Array.from(row)), rowsAffected: result.rowsAffected, lastInsertRowid: result.lastInsertRowid ?? null };
}

async function execute(database, label, statement) {
  const client = database === "alpha" ? alpha : beta, requestId = id();
  const result = await operation(database, "write", label, requestId, () => client.execute(statement, { requestId }), statement);
  const retained = normalized(result);
  const ack = { database, requestId, statements: [statement], result: retained, label };
  acknowledgements.push(ack);
  await appendFile(path.join(evidence, "acknowledgements.jsonl"), json({ database, request_id: requestId, label, statement_sha256: digest(typeof statement === "string" ? statement : json(statement)), result: retained }) + "\n");
  return result;
}

async function query(database, label, statement, client = database === "alpha" ? alpha : beta, timeoutMs) {
  const requestId = id();
  return operation(database, "read", label, requestId, () => client.query(statement, { requestId, ...(timeoutMs ? { timeoutMs } : {}) }), statement);
}

async function direct(node, statement, mode, requestId, budget = 2500) {
  const deadline = Date.now() + budget, endpoint = cluster.endpoints[node] + "/db/alpha/";
  let posts = 0;
  const driver = nativeClient({ url: endpoint, authToken: cluster.tokens.alpha, intMode: "bigint", fetch: async (input, init) => {
    const request = new Request(input, init), target = new URL(request.url);
    assert.equal(target.origin, cluster.endpoints[node]); assert.ok(target.pathname.startsWith("/db/alpha/"));
    if (request.method === "POST") assert.equal(++posts, 1, "a direct mixed-version probe must send its SQL exactly once");
    request.headers.set("x-scap-request-id", requestId); request.headers.set("x-scap-mode", mode);
    request.headers.set("x-scap-deadline-unix-ms", String(deadline));
    // The server's original deadline remains fixed. A bounded response-drain
    // allowance lets the ledger retain its real deadline rejection instead of
    // replacing that response with a client-side network timeout.
    return observedFetch(request, { redirect: "manual", signal: AbortSignal.timeout(Math.max(1, deadline - Date.now() + 1500)) });
  } });
  try { return await driver.execute(statement); }
  catch (error) {
    if (error instanceof assert.AssertionError) throw error;
    throw new ScapError(error.message, error.code ?? "COMMIT_UNKNOWN", { requestId, statements: [statement] });
  }
  finally { driver.close(); }
}

async function rejectDirect(node, label, statement, mode, requestId = id(), allowQueryFailure = false) {
  await assert.rejects(operation("alpha", mode, label, requestId, () => direct(node, statement, mode, requestId), statement), ScapError);
  const posts = httpAttempts.filter((entry) => entry.request_id === requestId && entry.method === "POST");
  assert.equal(posts.length, 1); assert.equal(posts[0].node_id, node + 1);
  assert.equal(posts[0].outcome, "response", "a lost HTTP transport is not proof of a service-level quorum rejection");
  const allowed = ["NOT_LEADER", "COMMIT_UNKNOWN", "EXPIRED"];
  // An existing old-version writer maps a query-time ReadIndex loss to this
  // read-only code. New-version pre-activation probes never accept it.
  if (allowQueryFailure && mode === "read") allowed.push("QUERY_FAILED");
  assert.ok(allowed.includes(posts[0].code), "unexpected rejection does not prove version isolation: " + posts[0].code);
  return { node_id: node + 1, request_id: requestId, http_ordinal: posts[0].ordinal, code: posts[0].code, status: posts[0].status, original_server_deadline_ms: 2500, response_drain_allowance_ms: 1500, sql_posts: 1, readiness_bypassed: true };
}

async function prepareRecoveredOldQuorum(nodes, budget = 30_000) {
  const started = milliseconds(), deadline = started + budget;
  const remaining = () => {
    const value = Math.floor(deadline - milliseconds());
    assert.ok(value > 0, "old quorum did not recover before its original preparation deadline");
    return value;
  };
  await event("old_quorum_recovery_preparation_started", { nodes: nodes.map((node) => node + 1), started_ms: started, deadline_ms: deadline, original_budget_ms: budget, sql_submitted: false });
  async function observe(node, membership) {
    const ordinal = httpOrdinal, route = membership ? "/v1/admin/membership" : "/readyz";
    let response;
    try {
      response = await observedFetch((membership ? cluster.managementEndpoints[node] : cluster.endpoints[node]) + route, {
        redirect: "manual", signal: AbortSignal.timeout(Math.min(membership ? 6500 : 600, remaining())),
        ...(membership ? { headers: { authorization: "Bearer " + cluster.tokens.administrator } } : {}),
      });
    } catch (error) {
      if (error instanceof TypeError || ["AbortError", "TimeoutError"].includes(error.name)) return null;
      throw error;
    }
    remaining();
    if (!membership) {
      await response.body?.cancel();
      assert.ok([200, 503].includes(response.status), "unexpected readiness response during quorum preparation");
      return response.status === 200 ? { node_id: node + 1, http_ordinal: ordinal } : null;
    }
    const data = await response.json();
    if (response.status !== 200) {
      assert.ok((response.status === 409 && data.code === "NOT_LEADER") || (response.status === 503 && data.code === "MEMBERSHIP_UNKNOWN"), "unexpected fresh membership rejection during quorum preparation");
      return null;
    }
    const view = cluster.decodeMembership(node, data);
    assert.equal(view.leader_id, node + 1);
    return { node_id: node + 1, http_ordinal: ordinal, membership: view };
  }
  for (;;) {
    cluster.assertNoUnexpectedExit();
    for (const node of nodes) {
      const first = await observe(node, true);
      if (first === null) continue;
      await delay(Math.min(100, remaining()));
      const ready = await observe(node, false);
      if (ready === null) continue;
      const second = await observe(node, true);
      if (second === null || first.membership.term !== second.membership.term) continue;
      assert.ok(second.membership.applied >= first.membership.applied);
      remaining();
      await event("old_quorum_recovery_prepared", { started_ms: started, deadline_ms: deadline, completed_ms: milliseconds(), original_budget_ms: budget, confirmations: [first, second], readiness: ready, sql_submitted: false });
      return;
    }
    await delay(Math.min(100, remaining()));
  }
}

async function status(database, legacy = false) {
  const client = database === "alpha" ? alpha : beta, requestId = id();
  return operation(database, "status", legacy ? "legacy_metadata" : "metadata", requestId, async () => {
    if (!legacy) {
      const result = await client.status({ requestId });
      for (const field of ["revision", "baseRevision", "tailEntries", "tailBytes"]) assert.equal(typeof result[field], "bigint", "new server must provide real bounded-history metadata: " + field);
      assert.ok(result.baseRevision <= result.revision && result.tailEntries < BigInt(profile.tail_entries_trigger));
      assert.ok(result.tailBytes < BigInt(profile.tail_bytes_trigger));
      maxTailEntries = result.tailEntries > maxTailEntries ? result.tailEntries : maxTailEntries;
      maxTailBytes = result.tailBytes > maxTailBytes ? result.tailBytes : maxTailBytes;
      return result;
    }
    // Do not fabricate zero base/tail fields that the old binary never exposed.
    const leader = await cluster.waitLeader();
    const response = await observedFetch(cluster.endpoints[leader] + "/db/" + database + "/v1/status", {
      redirect: "manual", signal: AbortSignal.timeout(5000), headers: { authorization: "Bearer " + cluster.tokens[database], "x-scap-request-id": requestId, "x-scap-deadline-unix-ms": String(Date.now() + 5000) },
    });
    assert.equal(response.status, 200);
    const data = await response.json();
    assert.equal(data.base_revision, undefined, "old producer must use its original V2 status contract");
    return { revision: BigInt(data.revision), suspended: data.suspended, cold: data.cold, ownerActive: data.owner_active, archivedRevision: data.archived_revision === null ? null : BigInt(data.archived_revision) };
  });
}

async function cancel(database, label, number) {
  const client = database === "alpha" ? alpha : beta;
  const request = { requestId: id(), statements: [`INSERT INTO witness VALUES(${number}, 'must-remain-cancelled')`] };
  const outcome = await operation(database, "cancel", label, request.requestId, () => client.resolveOrCancel(request));
  assert.equal(outcome.state, "cancelled"); cancellations.push({ database, ...request });
  return request;
}

async function verifyCancelled(request, label, submitLate = false) {
  const client = request.database === "alpha" ? alpha : beta;
  if (submitLate) {
    await assert.rejects(operation(request.database, "write", label + "_late_attempt", request.requestId, () => client.execute(request.statements[0], { requestId: request.requestId })), ScapError);
  }
  const outcome = await operation(request.database, "lookup", label, request.requestId, () => client.lookup(request));
  assert.equal(outcome.state, "cancelled");
}

async function waitCold(legacy = false) {
  const deadline = performance.now() + 45_000;
  let current;
  do {
    current = await status("beta", legacy);
    if (current.cold) break;
    await query("alpha", "keep_alpha_hot_while_beta_archives", "SELECT 1");
    await delay(200);
  } while (performance.now() < deadline);
  assert.equal(current.cold, true, "fresh metadata must prove publication and pruning, not merely an object PUT");
  assert.equal(current.suspended, true); assert.equal(current.ownerActive, false); assert.equal(current.archivedRevision, current.revision);
  assert.equal((await status("alpha", legacy)).cold, false);
  return current;
}

async function payloadImage(label) {
  const rows = [];
  // Each public result remains below 32KiB; no server SQL/result limit changes.
  for (let number = 1; number <= 8; number++) {
    const row = (await query("alpha", label, `SELECT generation,value FROM payloads WHERE id=${number}`)).rows[0];
    const bytes = Buffer.from(row.value);
    assert.equal(bytes.length, 24 * 1024);
    rows.push({ id: number, generation: row.generation.toString(), bytes: bytes.length, sha256: digest(bytes) });
  }
  return rows;
}

async function verifyAll(label) {
  for (let index = 0; index < acknowledgements.length; index++) {
    const ack = acknowledgements[index], client = ack.database === "alpha" ? alpha : beta;
    const outcome = await operation(ack.database, "lookup", label, ack.requestId, () => client.lookup(ack));
    assert.equal(outcome.state, "committed");
    assert.deepEqual(outcome.results, [ack.result], "every ACK must retain the exact original result after physical folding");
    if (index % 8 === 0) await query("alpha", "keep_alpha_hot_while_checking_outcomes", "SELECT 1");
  }
  for (const request of cancellations) await verifyCancelled(request, label);
  assert.equal((await query("alpha", label, "SELECT value FROM witness WHERE id=1")).rows[0].value, alphaNonce);
  assert.equal((await query("beta", label, "SELECT value FROM witness WHERE id=1")).rows[0].value, betaNonce);
  for (const database of ["alpha", "beta"]) assert.equal((await query(database, label, "SELECT count(*) AS n FROM witness WHERE id<>1")).rows[0].n, 0n);
  if (alphaPayload) assert.deepEqual(await payloadImage(label), alphaPayload, "the complete surviving BLOB bytes must match, beyond sampled prefixes");
  await event("all_acknowledgements_verified", { label, acknowledgements: acknowledgements.length, cancellations: cancellations.length, original_results_lost: 0, current_sql_state_equal: true, overwritten_values_checked_via_original_results: true });
}

try {
  await contract("01-old-v2-hot-and-cold", async () => {
    await s3.start();
    await writeFile(path.join(evidence, "s3-backend.json"), JSON.stringify(s3.identity, null, 2), { flag: "wx", mode: 0o600 });
    await cluster.prepare(); await cluster.launchAll(oldBinary, true);
    alpha = cluster.client("alpha"); beta = cluster.client("beta");
    await execute("alpha", "old_alpha_schema", "CREATE TABLE witness(id INTEGER PRIMARY KEY,value TEXT NOT NULL)");
    alphaNonce = (await execute("alpha", "old_alpha_random_result", "INSERT INTO witness VALUES(1,hex(randomblob(12))) RETURNING value")).rows[0].value;
    await execute("alpha", "old_alpha_payload_schema", "CREATE TABLE payloads(id INTEGER PRIMARY KEY,value BLOB NOT NULL,generation INTEGER NOT NULL)");
    await execute("alpha", "old_alpha_payload_seed", "INSERT INTO payloads VALUES " + Array.from({ length: 8 }, (_, index) => `(${index + 1},randomblob(24576),0)`).join(","));
    await execute("beta", "old_beta_schema", "CREATE TABLE witness(id INTEGER PRIMARY KEY,value TEXT NOT NULL)");
    betaNonce = (await execute("beta", "old_beta_random_result", "INSERT INTO witness VALUES(1,hex(randomblob(12))) RETURNING value")).rows[0].value;
    await cancel("alpha", "old_alpha_cancel_fence", 90);
    await cancel("beta", "old_beta_cancel_fence", 91);
    const cold = await waitCold(true);
    legacyArchives = await s3.archiveInventory(cluster.clusterId, cluster.cellId, identity(64));
    assert.ok(legacyArchives.length > 0 && legacyArchives.every((archive) => archive.format_version === 2));
    await event("old_v2_fixture_created", { binary_sha256: oldIdentity.sha256, source_commit: oldCommit, alpha_hot: true, beta: cold, archives: legacyArchives, acknowledged_writes: acknowledgements.length, cancellation_fences: cancellations.length, profile_limits: profile });
  });

  await contract("02-mixed-versions-cannot-form-quorum", async () => {
    const membership = await cluster.membership();
    const original = await Promise.all([0, 1, 2].map((node) => cluster.waitApplied(node, membership.applied)));
    assert.equal((await status("alpha", true)).revision, 4n);
    await query("alpha", "keep_old_alpha_hot_before_mixed_upgrade", "SELECT 1");
    const upgraded = [0, 1, 2].find((node) => node !== membership.leader - 1);
    const oldExit = await cluster.stop(upgraded, "SIGTERM"), oldStopped = milliseconds();
    await cluster.launch(upgraded, binary);
    await cluster.waitLive(upgraded);
    const prefix = await cluster.localStatus(upgraded);
    await event("mixed_version_started", { upgraded_node_id: upgraded + 1, original_membership: membership, original_local_status: original, replaced_old_exit: oldExit, old_stopped_ms: oldStopped, new_live_ms: milliseconds(), new_prefix: prefix, prefix_database_revision: "4", old_peer_envelope_version: 1, new_peer_envelope_version: 3, peer_proxies_blocked: false, initialize_flag_used: false });
    const rejectedRead = await rejectDirect(upgraded, "new_version_cannot_read_from_old_quorum", "SELECT value FROM witness WHERE id=1", "read");
    const rejectedRequest = { database: "alpha", requestId: id(), statements: ["INSERT INTO witness VALUES(94,'mixed-version-must-not-commit')"] };
    const rejectedWrite = await rejectDirect(upgraded, "new_version_write_sent_once", rejectedRequest.statements[0], "write", rejectedRequest.requestId);
    alphaNonce = (await execute("alpha", "old_quorum_accepts_while_new_version_isolated", "UPDATE witness SET value=hex(randomblob(12)) WHERE id=1 RETURNING value")).rows[0].value;
    const oldAck = acknowledgements.at(-1);
    const resolution = await operation("alpha", "cancel", "mixed_write_ordered_resolution", rejectedRequest.requestId, () => alpha.resolveOrCancel(rejectedRequest));
    await event("mixed_rejected_write_resolved", { request_id: rejectedRequest.requestId, original_response: rejectedWrite, actual_ordered_outcome: resolution });
    assert.equal(resolution.state, "cancelled", "an unexpected committed mixed-version write must remain a failed contract, never be rewritten as cancellation");
    cancellations.push(rejectedRequest);
    const oldQuorum = await cluster.membership();
    assert.notEqual(oldQuorum.leader, upgraded + 1);
    const stillBehind = await cluster.localStatus(upgraded);
    assert.equal(stillBehind.status.applied, prefix.status.applied, "new wire3 replica must not apply old wire1 quorum entries");
    assert.ok(oldQuorum.applied > stillBehind.status.applied);
    const remainingOld = oldQuorum.leader - 1;
    const stoppedOld = [0, 1, 2].find((node) => node !== upgraded && node !== remainingOld);
    const stoppedOldExit = await cluster.stop(stoppedOld, "SIGTERM"), oldMinorityStarted = milliseconds();
    await cluster.waitLive(remainingOld); await cluster.waitLive(upgraded);
    const minorityStatus = await Promise.all([remainingOld, upgraded].map((node) => cluster.localStatus(node)));
    const rejectedMinorityRead = await rejectDirect(remainingOld, "one_old_and_one_new_cannot_serve_strong_read", "SELECT value FROM witness WHERE id=1", "read", id(), true);
    const frozen = await cluster.localStatus(upgraded);
    assert.equal(frozen.status.applied, prefix.status.applied);
    const newExit = await cluster.stop(upgraded, "SIGTERM"), newStopped = milliseconds();
    // Retain this lagging upgraded directory. It is neither rebuilt nor
    // initialized; the later all-new group must apply the witnessed suffix.
    await cluster.launch(stoppedOld, oldBinary);
    await prepareRecoveredOldQuorum([remainingOld, stoppedOld]);
    assert.equal((await query("alpha", "restored_old_quorum_value", "SELECT value FROM witness WHERE id=1")).rows[0].value, alphaNonce);
    const retained = await operation("alpha", "lookup", "restored_old_quorum_ack", oldAck.requestId, () => alpha.lookup(oldAck));
    assert.equal(retained.state, "committed"); assert.deepEqual(retained.results, [oldAck.result]);
    await verifyCancelled(rejectedRequest, "restored_old_quorum_mixed_fence");
    const source = await cluster.membership();
    mixedVersion = { upgraded_node_id: upgraded + 1, prefix, frozen, old_quorum: oldQuorum, source_before_full_upgrade: source, old_ack_request_id: oldAck.requestId, cancelled_request_id: rejectedRequest.requestId, rejected_new_read: rejectedRead, rejected_new_write: rejectedWrite, rejected_mixed_minority_read: rejectedMinorityRead, mixed_minority_live_nodes: [remainingOld + 1, upgraded + 1], mixed_minority_local_status: minorityStatus, stopped_old_node_id: stoppedOld + 1, stopped_old_exit: stoppedOldExit, old_minority_started_ms: oldMinorityStarted, new_stopped_ms: newStopped, new_exit: newExit, old_quorum_restored_ms: milliseconds(), lagging_directory_retained: true, peer_proxies_blocked: false, membership_changes_submitted: 0 };
    await event("mixed_version_fence_verified", mixedVersion);
  });

  await contract("03-stop-upgrade-preserves-history", async () => {
    await cluster.stopAll("SIGTERM");
    await event("old_group_stopped", { replicas: cluster.processes.map((state, node) => ({ node_id: node + 1, exit: state.exit })), all_versions_stopped_before_full_upgrade: true, lagging_upgraded_node_id: mixedVersion.upgraded_node_id });
    await cluster.launchAll(binary);
    const caughtUp = await cluster.waitApplied(mixedVersion.upgraded_node_id - 1, mixedVersion.source_before_full_upgrade.applied);
    assert.ok(caughtUp.status.applied > mixedVersion.frozen.status.applied);
    assert.equal((await query("alpha", "upgraded_original_value", "SELECT value FROM witness WHERE id=1")).rows[0].value, alphaNonce);
    const hot = await status("alpha"), cold = await status("beta");
    assert.equal(hot.revision, 5n); assert.equal(hot.cold, false);
    assert.equal(hot.tailEntries, hot.revision - hot.baseRevision, "legacy recovery must retain the exact un-folded suffix");
    assert.equal(cold.revision, 2n); assert.equal(cold.cold, true);
    assert.equal(cold.archivedRevision, 2n);
    for (const ack of acknowledgements.filter((entry) => entry.label.endsWith("random_result"))) {
      const client = ack.database === "alpha" ? alpha : beta;
      const outcome = await operation(ack.database, "lookup", "old_original_result_after_upgrade", ack.requestId, () => client.lookup(ack));
      assert.deepEqual(outcome.results, [ack.result]);
    }
    for (const request of cancellations) await verifyCancelled(request, "old_cancel_after_upgrade");
    assert.equal((await status("beta")).cold, true, "Lookup and metadata must not silently hydrate old archive payloads");
    await event("same_directories_upgraded", { alpha: hot, beta: cold, lagging_replica_caught_up: caughtUp, witnessed_old_prefix: mixedVersion.source_before_full_upgrade.applied, old_results_equal: true, cancellation_fences_preserved: true, initialized_again: false });
  });

  await contract("04-overwrite-exceeds-original-history-budget", async () => {
    let previous = await status("alpha");
    overwriteStart = previous;
    await event("bounded_history_overwrites_started", { metadata: overwriteStart });
    for (let generation = 1; generation <= 64; generation++) {
      const result = await execute("alpha", "overwrite_" + generation, { sql: "UPDATE payloads SET value=randomblob(24576),generation=? RETURNING id,generation,hex(substr(value,1,16)) AS prefix", args: [BigInt(generation)] });
      assert.equal(result.rows.length, 8);
      assert.ok(result.rows.every((row) => row.generation === BigInt(generation) && /^[0-9A-F]{32}$/.test(row.prefix)));
      const current = await status("alpha");
      assert.equal(current.revision, previous.revision + 1n);
      assert.ok(current.baseRevision >= previous.baseRevision && !current.cold);
      let observed = 0n;
      if (current.baseRevision === previous.baseRevision) {
        observed = current.tailBytes - previous.tailBytes;
        assert.ok(observed > 0n, "a non-folding real BLOB rewrite must append measured physical bytes");
        cumulativeObservedPhysical += observed;
      } else {
        baseAdvances++; assert.equal(current.tailEntries, 0n); assert.equal(current.tailBytes, 0n);
      }
      await appendFile(path.join(evidence, "overwrites.jsonl"), json({ generation, request_id: acknowledgements.at(-1).requestId, previous_revision: previous.revision, previous_base_revision: previous.baseRevision, previous_tail_entries: previous.tailEntries, previous_tail_bytes: previous.tailBytes, revision: current.revision, base_revision: current.baseRevision, tail_entries: current.tailEntries, tail_bytes: current.tailBytes, observed_new_physical_bytes: observed, cumulative_observed_physical_bytes: cumulativeObservedPhysical, folded_transaction_bytes_excluded: current.baseRevision !== previous.baseRevision }) + "\n");
      previous = current;
    }
    assert.ok(cumulativeObservedPhysical > BigInt(profile.state_bytes), "measured non-folding tail deltas alone must exceed the original 8MiB state budget");
    assert.ok(baseAdvances >= 2, "a single eager conversion is insufficient to demonstrate bounded ongoing history");
    assert.ok(acknowledgements.filter((ack) => ack.database === "alpha").length + cancellations.filter((request) => request.database === "alpha").length < profile.requests_per_database);
    alphaPayload = await payloadImage("complete_final_blob_witness");
    await verifyCancelled(cancellations.find((request) => request.database === "alpha"), "original_fence_after_many_bases", true);
    assert.equal((await query("alpha", "cancelled_sql_did_not_execute", "SELECT count(*) AS n FROM witness WHERE id<>1")).rows[0].n, 0n);
    await event("bounded_physical_history_demonstrated", { overwrites: 64, blob_rows: 8, blob_bytes_per_row: 24576, base_advances: baseAdvances, cumulative_observed_physical_bytes: cumulativeObservedPhysical, original_state_budget_bytes: profile.state_bytes, lower_bound_excludes_fold_trigger_transactions: true, latest: previous, surviving_payloads: alphaPayload, limits_increased: false });
  });

  await contract("05-old-s3-archive-hydrates-with-new-fence", async () => {
    assert.equal((await status("beta")).cold, true);
    const createdAfterArchive = await cancel("beta", "new_cancellation_after_old_archive", 92);
    const crossed = cluster.client("beta", { authToken: cluster.tokens.alpha });
    await assert.rejects(query("beta", "wrong_tenant_cannot_wake_old_archive", "SELECT value FROM witness", crossed), (error) => error.code === "UNAUTHORIZED");
    assert.equal((await status("beta")).cold, true);
    const blockedBefore = s3.proxy.blockedConnections;
    s3.blackhole(true);
    const wake = query("beta", "real_old_archive_blackhole", "SELECT value FROM witness", beta, 3000);
    const rejected = assert.rejects(wake, ScapError);
    const observedBy = performance.now() + 2000;
    while (s3.proxy.blockedConnections === blockedBefore && performance.now() < observedBy) await delay(20);
    assert.ok(s3.proxy.blockedConnections > blockedBefore, "the old archive wake must actually reach the S3 network fault");
    assert.equal((await query("alpha", "alpha_remains_readable_during_old_archive_fault", "SELECT value FROM witness WHERE id=1")).rows[0].value, alphaNonce);
    await rejected;
    assert.equal((await status("beta")).cold, true);
    s3.blackhole(false);
    assert.equal((await query("beta", "hydrate_exact_old_v2_archive", "SELECT value FROM witness WHERE id=1")).rows[0].value, betaNonce);
    const awake = await status("beta");
    assert.equal(awake.cold, false); assert.equal(awake.revision, 2n);
    assert.equal(awake.tailEntries, awake.revision - awake.baseRevision, "legacy archive migration must retain its exact physical recovery suffix");
    await verifyCancelled({ database: "beta", ...createdAfterArchive }, "new_fence_survives_old_archive_hydrate", true);
    await verifyAll("after_old_archive_hydrate");
    await event("old_archive_hydrated_without_metadata_rollback", { legacy_archives: legacyArchives, new_cancellation_after_archive: createdAfterArchive.requestId, beta: awake, tenant_authorization_preserved: true, dynamic_auth_fence_in_separate_rust_contract: true, old_random_result_equal: true });
  });

  await contract("06-new-v4-archive-roundtrip", async () => {
    for (let revision = 1; revision <= 9; revision++) betaNonce = (await execute("beta", "new_beta_update_" + revision, "UPDATE witness SET value=hex(randomblob(12)) WHERE id=1 RETURNING value")).rows[0].value;
    const hot = await status("beta"); assert.ok(hot.baseRevision > 2n);
    const cold = await waitCold();
    currentArchives = await s3.archiveInventory(cluster.clusterId, cluster.cellId, identity(64));
    assert.ok(currentArchives.some((archive) => archive.format_version === 4));
    for (const legacy of legacyArchives) assert.ok(currentArchives.some((archive) => archive.sha256 === legacy.sha256), "an upgrade must not overwrite or delete the old immutable object");
    await cancel("beta", "new_cancellation_after_v4_archive", 93);
    assert.equal((await query("beta", "hydrate_exact_new_v4_archive", "SELECT value FROM witness WHERE id=1")).rows[0].value, betaNonce);
    await verifyAll("after_v4_archive_hydrate");
    await event("new_archive_roundtrip_verified", { before_cold: hot, cold, archives: currentArchives, original_v2_object_preserved: true, current_result_equal: true, all_old_results_and_new_fences_preserved: true });
  });

  await contract("07-sigkill-recovers-from-base-and-tail", async () => {
    await query("beta", "warm_beta_before_owner_snapshot", "SELECT 1");
    await query("alpha", "warm_alpha_before_owner_snapshot", "SELECT 1");
    const previous = await cluster.writerFiles();
    assert.ok(previous.length >= 2);
    const before = { alpha: await status("alpha"), beta: await status("beta") };
    await cluster.stopAll("SIGKILL");
    await event("full_group_sigkill", { replicas: cluster.processes.map((state, node) => ({ node_id: node + 1, exit: state.exit })), before, prior_writer_files: previous });
    await cluster.launchAll(binary);
    await verifyAll("after_full_group_sigkill");
    await query("beta", "warm_beta_after_owner_recovery", "SELECT 1");
    await query("alpha", "warm_alpha_after_owner_recovery", "SELECT 1");
    recoveryFiles = await cluster.writerFiles();
    assert.ok(recoveryFiles.length >= 2);
    const oldWorkers = new Set(previous.map((entry) => entry.worker_instance));
    assert.ok(recoveryFiles.every((entry) => !oldWorkers.has(entry.worker_instance)), "all recovered writers must use fresh instances and directories");
    assert.ok(recoveryFiles.some((entry) => entry.main_file_bytes >= 8 * 24 * 1024), "a newly reconstructed native SQLite file must actually contain the large payload image");
    for (const database of ["alpha", "beta"]) {
      const recovered = await status(database);
      assert.equal(recovered.revision, before[database].revision); assert.ok(recovered.baseRevision >= before[database].baseRevision);
    }
    await event("new_owner_directories_recovered", { new_writer_files: recoveryFiles, original_results_lost: 0, current_sql_state_equal: true, production_slo_passed: false });
  });

  await contract("08-old-binary-rejects-v4-storage", async () => {
    const committed = await cluster.membership();
    const applied = await Promise.all([0, 1, 2].map((node) => cluster.waitApplied(node, committed.applied)));
    await cluster.stopAll("SIGTERM");
    const rejected = [];
    for (let node = 0; node < 3; node++) {
      // All new processes are stopped. Never pass --initialize, delete the
      // directory, or turn this expected application-version rejection into a
      // storage re-creation. RocksDB's own open bookkeeping may change files.
      const filename = path.join(scratch, "old-downgrade-" + (node + 1) + ".private.log");
      const process = await processAt(oldBinary, [cluster.configs[node]], filename, { ...globalThis.process.env, ...s3.env }, true);
      const exited = await Promise.race([process.done, delay(10_000).then(() => null)]);
      if (exited === null) { await process.stop(); throw new Error("old daemon did not fail closed on V4 storage"); }
      assert.ok(exited.code !== null && exited.code !== 0 && exited.signal === null);
      const output = await readFile(filename, "utf8");
      assert.match(output, /STORE_APPLICATION/, "a busy lock or bind failure is not evidence of V4 downgrade rejection");
      rejected.push({ node_id: node + 1, exit: exited, reason: "STORE_APPLICATION", initialize_flag_used: false });
    }
    await event("old_binary_failed_closed", { attempts: rejected, committed_before_stop: committed.applied, local_applied_before_stop: applied, all_new_daemons_stopped: true, no_database_reinitialization: true, physical_rocks_files_not_claimed_immutable: true });
  });

  await contract("09-new-binary-reopens-after-rejected-downgrade", async () => {
    await cluster.launchAll(binary);
    await verifyAll("after_rejected_downgrade");
    for (const database of ["alpha", "beta"]) assert.ok((await status(database)).baseRevision > 0n);
    assert.deepEqual(await fileIdentity(oldBinary), oldIdentity);
    assert.deepEqual(await fileIdentity(binary), newIdentity);
    assert.deepEqual(await Promise.all(harnessIdentity.map((entry) => fileIdentity(entry.path))), harnessIdentity);
    await event("new_binary_reopened_without_ack_loss", { original_results_lost: 0, all_fences_retained: true, same_raft_directories: true, binary_and_harness_inputs_unchanged: true, final_membership: await cluster.membership() });
  });

  const identities = Object.fromEntries(["alpha", "beta"].map((database) => [database, new Set([...acknowledgements, ...cancellations].filter((entry) => entry.database === database).map((entry) => entry.requestId)).size]));
  assert.ok(Object.values(identities).every((count) => count < profile.requests_per_database));
  assert.equal(acknowledgements.length, 80); assert.equal(cancellations.length, 5);
  await writeFile(path.join(evidence, "summary.json"), JSON.stringify({
    completed, all_contracts_passed: completed.length === 9,
    acknowledged_writes: acknowledgements.length,
    acknowledgements_by_database: Object.fromEntries(["alpha", "beta"].map((database) => [database, acknowledgements.filter((entry) => entry.database === database).length])),
    retained_request_identities: identities, cancellation_fences: cancellations.length,
    request_attempts: attempts.length, unsuccessful_attempts: attempts.filter((entry) => entry.outcome !== "success"), http_attempts: httpOrdinal,
    overwrites: 64, base_advances: baseAdvances, cumulative_observed_physical_bytes: cumulativeObservedPhysical.toString(), fold_trigger_physical_bytes_excluded: true,
    maximum_tail_entries: maxTailEntries.toString(), maximum_tail_bytes: maxTailBytes.toString(), profile_limits: profile,
    old_archive_format: 2, new_archive_format: 4, original_results_lost: 0, current_sql_state_equal: true,
    mixed_versions_rejected: true, old_peer_envelope_version: 1, new_peer_envelope_version: 3,
    effective_voters: [1, 2, 3], membership_changes_submitted: 0, dynamic_peer_policy_for_existing_read_only_management: true,
    local_status_is_commit_confirmation: false, downgrade_rejected_nodes: 3, full_group_sigkill: true, fresh_writer_directories: recoveryFiles,
    production_slo_passed: false, private_fixture_data_exported: false,
  }, null, 2), { flag: "wx", mode: 0o600 });
  await event("all_history_contracts_completed", { count: completed.length, original_results_lost: 0, production_slo_passed: false });
} finally {
  for (const client of clients) client.close();
  const cleaned = await Promise.allSettled([cluster.close(), s3.close()]);
  const failed = cleaned.filter((result) => result.status === "rejected");
  if (failed.length) throw new AggregateError(failed.map((result) => result.reason), "private fixture cleanup failed");
}
