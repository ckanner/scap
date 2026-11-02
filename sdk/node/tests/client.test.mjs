import test from "node:test";
import assert from "node:assert/strict";
import { createClient as libsqlClient } from "@libsql/client/http";
import { createClient, ScapClient, ScapError } from "../dist/client.js";

const ID = "0123456789abcdef0123456789abcdef";
const config = { endpoints: ["http://one.local", "http://two.local"], database: "db", authToken: "token", timeoutMs: 500 };
const empty = { cols: [], rows: [], affected_row_count: 0, last_insert_rowid: null };
const result = { cols: [{ name: "value", decltype: "INTEGER" }], rows: [[{ type: "integer", value: "7" }]], affected_row_count: 1, last_insert_rowid: "9" };

function runtime(fetch, rest = {}) {
  return { fetch: async (input, init) => fetch(new Request(input, init)), now: () => 1000,
    monotonic: () => 0, requestId: () => ID, createClient: libsqlClient, ...rest };
}

function response(value, request, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json", "x-scap-request-id": request.headers.get("x-scap-request-id") } });
}

async function hrana(request, error) {
  const body = await request.json();
  const results = body.requests.map((entry) => {
    if (entry.type === "execute") return error ? { type: "error", error } : { type: "ok", response: { type: "execute", result } };
    if (entry.type === "batch") {
      if (error) return { type: "error", error };
      const steps = entry.batch.steps.map((_, index, steps) => index === steps.length - 1 ? null : index === 0 || index === steps.length - 2 ? empty : result);
      return { type: "ok", response: { type: "batch", result: { step_results: steps, step_errors: steps.map(() => null) } } };
    }
    return { type: "ok", response: { type: entry.type } };
  });
  return response({ baton: null, base_url: null, results }, request);
}

function healthy(handler = hrana) { return async (request) => new URL(request.url).pathname === "/readyz" ? new Response(null, { status: 200 }) : handler(request); }

test("default runtime uses the real pinned libSQL driver and an entrance-generated ID", async () => {
  const previous = globalThis.fetch;
  const seen = [];
  globalThis.fetch = async (input, init) => {
    const request = new Request(input, init); seen.push(request);
    return healthy()(request);
  };
  try {
    const db = createClient({ endpoints: ["http://one.local"], database: "db", authToken: "token" });
    const output = await db.execute("SELECT 7");
    assert.equal(output.rows[0].value, 7n);
    assert.equal(seen[0].headers.has("authorization"), false);
    assert.equal(seen[0].redirect, "manual");
    assert.match(seen[1].headers.get("x-scap-request-id"), /^[0-9a-f]{32}$/);
    assert.equal(seen[1].headers.get("authorization"), "Bearer token");
    assert.ok(Number(seen[1].headers.get("x-scap-deadline-unix-ms")) > Date.now());
    db.close();
  } finally { globalThis.fetch = previous; }
});

test("configuration and per-call budgets reject every invalid boundary", async () => {
  for (const change of [{ database: "" }, { database: "a/b" }, { database: "x".repeat(65) }, { authToken: "" }, { authToken: "x".repeat(8193) },
    { endpoints: [] }, { endpoints: Array(17).fill("http://one.local") }, { endpoints: ["file:///tmp/db"] }, { endpoints: ["http://u@one.local"] },
    { endpoints: ["http://u:p@one.local"] }, { endpoints: ["http://one.local?q=1"] }, { endpoints: ["http://one.local#x"] }, { endpoints: ["http://one.local/path"] },
    { timeoutMs: 0 }, { timeoutMs: -1 }, { timeoutMs: 1.5 }, { timeoutMs: 3_600_001 }, { maxResponseBytes: 0 }, { maxResponseBytes: 128 * 1024 * 1024 + 1 }]) {
    assert.throws(() => new ScapClient({ ...config, ...change }));
  }
  const db = createClient(config, runtime(healthy()));
  for (const options of [{ timeoutMs: 501 }, { timeoutMs: 0 }, { requestId: "bad" }, { requestId: "0".repeat(32) }]) await assert.rejects(db.execute("SELECT 1", options));
  for (const stmt of ["", { sql: 1 }, { sql: "SELECT :x", args: { x: 1 } }]) await assert.rejects(db.execute(stmt));
  assert.throws(() => createClient({ ...config, endpoints: ["not a url"] }));
  assert.ok(createClient({ ...config, endpoints: ["https://one.local"], database: "a-b_1" }));
});

test("read, execute and atomic batches retain driver APIs, modes and immutable parameter copies", async () => {
  const captured = [];
  const db = createClient(config, runtime(healthy(async (request) => { captured.push({ headers: request.headers, body: await request.clone().json() }); return hrana(request); })));
  assert.equal((await db.query("SELECT 7")).rows[0].value, 7n);
  const bytes = new Uint8Array([1, 2]);
  const buffer = Uint8Array.of(3, 4).buffer;
  const date = new Date(1234);
  const input = { sql: "SELECT ?, ?, ?, ?, ?, ?, ?, ?", args: [bytes, buffer, date, true, false, null, "text", 1.25] };
  const promise = db.execute(input, { requestId: ID.toUpperCase() });
  bytes[0] = 99; new Uint8Array(buffer)[0] = 99; date.setTime(9000); input.sql = "bad";
  await promise;
  assert.equal(captured[0].headers.get("x-scap-mode"), "read");
  assert.equal(captured[1].headers.get("x-scap-mode"), "write");
  const stmt = captured[1].body.requests[0].stmt;
  assert.equal(stmt.sql, "SELECT ?, ?, ?, ?, ?, ?, ?, ?");
  assert.deepEqual(stmt.args, [{ type: "blob", base64: "AQI=" }, { type: "blob", base64: "AwQ=" }, { type: "float", value: 1234 },
    { type: "integer", value: "1" }, { type: "integer", value: "0" }, { type: "null" }, { type: "text", value: "text" }, { type: "float", value: 1.25 }]);
  for (const mode of [undefined, "write", "read"]) {
    const output = await db.batch(["SELECT 1", "SELECT 1"], mode);
    assert.equal(output.length, 2); assert.equal(output[1].rows[0].value, 7n);
  }
  assert.equal(captured.at(-1).headers.get("x-scap-mode"), "read");
  assert.ok(captured[2].body.requests.some((request) => request.type === "store_sql"));
});

test("ready probes are bounded hints and only NOT_LEADER permits another SQL attempt", async () => {
  const seen = [];
  const db = createClient(config, runtime(async (request) => {
    seen.push(request);
    const url = new URL(request.url);
    if (url.pathname === "/readyz") return new Response("ready", { status: 200 });
    return hrana(request, url.hostname === "one.local" ? { code: "NOT_LEADER", message: "not leader" } : undefined);
  }));
  assert.equal((await db.execute("INSERT INTO t VALUES (1)")).rows[0].value, 7n);
  const writes = seen.filter((request) => request.method === "POST");
  assert.equal(writes.length, 2); assert.equal(writes[0].headers.get("x-scap-request-id"), writes[1].headers.get("x-scap-request-id"));
  assert.equal(writes[0].headers.get("x-scap-deadline-unix-ms"), writes[1].headers.get("x-scap-deadline-unix-ms"));
  for (const first of ["error", "unready", "redirect"]) {
    const routes = [];
    const db = createClient(config, runtime(async (request) => {
      routes.push(request.url);
      if (request.url === "http://one.local/readyz") {
        if (first === "error") throw new Error("connect");
        return new Response(null, { status: first === "unready" ? 503 : 302, headers: { location: "http://evil.local/" } });
      }
      return healthy()(request);
    }));
    await db.execute("SELECT 1");
    assert.equal(routes.length, 3); assert.equal(routes.at(-1), "http://two.local/db/db/v2/pipeline");
  }
  for (const only of ["unready", "not_leader"]) {
    const db = createClient(config, runtime(async (request) => {
      if (new URL(request.url).pathname === "/readyz") return new Response(null, { status: only === "unready" ? 503 : 200 });
      return hrana(request, { code: "NOT_LEADER", message: "not leader" });
    }));
    await assert.rejects(db.execute("SELECT 1"), (error) => error.code === "NO_LEADER");
  }
});

test("unknown, SQL errors, redirects and transport failures never replay writes", async () => {
  for (const mode of ["network", "unknown", "sql", "redirect", "mismatch", "oversized", "empty"]) {
    let attempts = 0;
    const db = createClient({ ...config, maxResponseBytes: 1024 }, runtime(healthy(async (request) => {
      attempts++;
      if (mode === "network") throw new Error("connection lost");
      if (mode === "redirect") return new Response(null, { status: 307, headers: { location: "http://evil.local/" } });
      if (mode === "empty") return new Response(null, { status: 200 });
      if (mode === "oversized") return new Response("x".repeat(1025));
      if (mode === "mismatch") return new Response("{}", { headers: { "x-scap-request-id": "0".repeat(32) } });
      return hrana(request, { code: mode === "unknown" ? "COMMIT_UNKNOWN" : "SQLITE_CONSTRAINT", message: "failure" });
    })));
    await assert.rejects(db.execute("INSERT INTO t VALUES (1)"), (error) => error instanceof ScapError && error.request.requestId === ID);
    assert.equal(attempts, 1);
  }
});

test("concurrent requests keep independent entrance identities and absolute deadlines", async () => {
  let next = 1;
  const requests = [];
  const db = createClient(config, runtime(healthy(async (request) => {
    requests.push({ id: request.headers.get("x-scap-request-id"), deadline: request.headers.get("x-scap-deadline-unix-ms"), sql: (await request.clone().json()).requests[0].stmt.sql });
    await new Promise((resolve) => setTimeout(resolve, requests.length === 1 ? 3 : 1));
    return hrana(request);
  }), { requestId: () => String(next++).padStart(32, "0") }));
  await Promise.all([db.execute("SELECT 1", { timeoutMs: 50 }), db.query("SELECT 2", { timeoutMs: 100 })]);
  assert.deepEqual(requests, [{ id: "1".padStart(32, "0"), deadline: "1050", sql: "SELECT 1" }, { id: "2".padStart(32, "0"), deadline: "1100", sql: "SELECT 2" }]);
});

test("cancellation and the original monotonic deadline cover every async boundary", async () => {
  const already = new AbortController(); already.abort();
  const db = createClient(config, runtime(healthy()));
  await assert.rejects(db.execute("SELECT 1", { signal: already.signal }), (error) => error.code === "EXPIRED");
  db.close();
  await assert.rejects(db.execute("SELECT 1"), (error) => error.code === "CLIENT_CLOSED");
  let calls = 0;
  const elapsed = createClient(config, runtime(healthy(), { monotonic: () => calls++ === 0 ? 0 : 1000 }));
  await assert.rejects(elapsed.execute("SELECT 1"), (error) => error.code === "EXPIRED");
  for (const stage of ["probe", "sql"]) {
    const controller = new AbortController();
    const db = createClient(config, runtime(async (request) => {
      if (new URL(request.url).pathname === "/readyz" && stage === "sql") return new Response(null);
      return new Promise((_, reject) => request.signal.addEventListener("abort", () => reject(new Error("aborted")), { once: true }));
    }));
    const promise = db.execute("SELECT 1", { signal: controller.signal });
    setTimeout(() => controller.abort(), 2);
    await assert.rejects(promise, (error) => error.code === (stage === "probe" ? "EXPIRED" : "COMMIT_UNKNOWN"));
  }
  const timer = createClient({ ...config, timeoutMs: 2 }, runtime(async (request) => new Promise((_, reject) => request.signal.addEventListener("abort", () => reject(new Error("timeout"))))));
  await assert.rejects(timer.execute("SELECT 1"), (error) => error.code === "EXPIRED");
  let mono = 0;
  const after = createClient(config, runtime(healthy(async (request) => { const result = await hrana(request); mono = 1000; return result; }), { monotonic: () => mono }));
  await assert.rejects(after.execute("SELECT 1"), (error) => error.code === "COMMIT_UNKNOWN");
});

test("outcome methods send exact original parameters and preserve unknown separately from cancellation", async () => {
  const captured = [];
  let state = "unknown";
  const retained = { state: "committed", sequence: "7", results: [{ cols: ["n", "i", "f", "s", "b"].map((name) => ({ name })),
    rows: [[{ type: "null" }, { type: "integer", value: "-9223372036854775808" }, { type: "float", value: 1.5 }, { type: "text", value: "hi" }, { type: "blob", base64: "AP8=" }]], affected_row_count: 1, last_insert_rowid: "9223372036854775807" }, empty] };
  const db = createClient(config, runtime(healthy(async (request) => { captured.push(await request.json()); return response(state === "committed" ? retained : { state }, request); })));
  const original = { requestId: ID, statements: [{ sql: "SELECT ?,?,?,?,?,?", args: [null, 3n, 1.25, "x", new Uint8Array([1]), new Uint8Array([2]).buffer] }] };
  assert.deepEqual(await db.lookup(original), { state: "unknown" });
  state = "cancelled"; assert.deepEqual(await db.resolveOrCancel(original), { state: "cancelled" });
  state = "committed"; const output = await db.lookup(original);
  assert.equal(output.sequence, 7n); assert.equal(output.results[0].rows[0][1], -(1n << 63n));
  assert.deepEqual(new Uint8Array(output.results[0].rows[0][4]), new Uint8Array([0, 255]));
  assert.equal(output.results[1].lastInsertRowid, null);
  assert.equal(captured[0].action, "lookup"); assert.equal(captured[1].action, "resolve_or_cancel");
  assert.deepEqual(captured[0].statements[0].args, [{ type: "null" }, { type: "integer", value: "3" }, { type: "float", value: 1.25 }, { type: "text", value: "x" }, { type: "blob", base64: "AQ==" }, { type: "blob", base64: "Ag==" }]);
  await assert.rejects(db.lookup({ requestId: ID, statements: [{ sql: "SELECT ?", args: [Infinity] }] }), (error) => error.code === "COMMIT_UNKNOWN");
});

test("outcome error, identity and decoder checks reject malformed retained successes", async () => {
  const base = { state: "committed", sequence: "1", results: [{ cols: [{ name: "v" }], rows: [[{ type: "integer", value: "1" }]], affected_row_count: 0, last_insert_rowid: "0" }] };
  const malformed = [null, 1, { state: "bad" }, { state: "committed", sequence: "1", results: null }];
  for (const sequence of [1, "x", "0", "18446744073709551616"]) malformed.push({ ...base, sequence });
  for (const changed of [{ cols: null }, { rows: null }, { affected_row_count: 1.5 }, { affected_row_count: -1 }, { cols: [{ name: 1 }] }, { rows: [null] }, { rows: [[]] }, { last_insert_rowid: "9223372036854775808" }]) malformed.push({ ...base, results: [{ ...base.results[0], ...changed }] });
  for (const value of [null, 1, { type: "integer", value: "-9223372036854775809" }, { type: "float", value: "1" }, { type: "text", value: 1 }, { type: "blob", base64: 1 }, { type: "blob", base64: "!!!" }, { type: "bad" }]) malformed.push({ ...base, results: [{ ...base.results[0], rows: [[value]] }] });
  for (const value of malformed) {
    const db = createClient(config, runtime(healthy(async (request) => response(value, request))));
    await assert.rejects(db.lookup({ requestId: ID, statements: ["SELECT 1"] }), (error) => error instanceof ScapError && error.code === "COMMIT_UNKNOWN");
  }
  const nonfinite = createClient(config, runtime(healthy(async () => new Response('{"state":"committed","sequence":"1","results":[{"cols":[{"name":"v"}],"rows":[[{"type":"float","value":1e400}]],"affected_row_count":0,"last_insert_rowid":null}'))));
  await assert.rejects(nonfinite.lookup({ requestId: ID, statements: ["SELECT 1"] }));
  const denied = createClient(config, runtime(healthy(async (request) => response({ code: "UNAUTHORIZED", message: "denied" }, request, 401))));
  await assert.rejects(denied.lookup({ requestId: ID, statements: ["SELECT 1"] }), (error) => error.code === "UNAUTHORIZED");
  let attempts = 0;
  const routed = createClient(config, runtime(healthy(async (request) => ++attempts === 1 ? response({ code: "NOT_LEADER", message: "leader changed" }, request, 503) : response({ state: "unknown" }, request))));
  assert.deepEqual(await routed.lookup({ requestId: ID, statements: ["SELECT 1"] }), { state: "unknown" });
});

test("unconfigured driver targets and non-Error failures retain request identity", async () => {
  for (const target of ["http://evil.local/db/db/v2/pipeline", "http://one.local/db/other/v2/pipeline"]) {
    let sent = 0;
    const db = createClient(config, runtime(async () => { sent++; return new Response(null); }, {
      createClient: (config) => ({ execute: async () => config.fetch(new Request(target)), close() {} }),
    }));
    await assert.rejects(db.execute("SELECT 1"), (error) => error.code === "COMMIT_UNKNOWN");
    assert.equal(sent, 1);
  }
  for (const thrown of [null, "broken", { code: "CUSTOM" }]) {
    const db = createClient(config, runtime(healthy(), { createClient: () => ({ execute: async () => { throw thrown; }, close() {} }) }));
    await assert.rejects(db.execute("SELECT 1"), (error) => error instanceof ScapError && error.request.requestId === ID);
  }
});


test("authorized status preserves unsigned revisions without a SQL write or wake", async () => {
  const captured = [];
  let value = { revision: "0", suspended: false, cold: false, owner_active: true, archived_revision: null };
  const db = createClient(config, runtime(healthy(async (request) => {
    captured.push(request);
    return response(value, request);
  })));
  assert.deepEqual(await db.status(), { revision: 0n, suspended: false, cold: false, ownerActive: true, archivedRevision: null });
  value = { revision: "18446744073709551615", suspended: true, cold: true, owner_active: false, archived_revision: "18446744073709551615" };
  assert.deepEqual(await db.status({ requestId: ID }), { revision: (1n << 64n) - 1n, suspended: true, cold: true, ownerActive: false, archivedRevision: (1n << 64n) - 1n });
  assert.equal(captured[0].method, "GET"); assert.equal(captured[0].url, "http://one.local/db/db/v1/status");
  assert.equal(captured[0].headers.get("authorization"), "Bearer token");
  assert.equal(await captured[0].text(), "");
  for (const malformed of [null, 1, {}, { ...value, cold: 1 }, { ...value, owner_active: 1 }, { ...value, revision: "-1" }, { ...value, archived_revision: "18446744073709551616" }]) {
    value = malformed;
    await assert.rejects(db.status(), (error) => error.code === "COMMIT_UNKNOWN" && error.request.statements.length === 0);
  }
});
