import test from "node:test";
import assert from "node:assert/strict";
import { createClient as libsqlClient } from "@libsql/client/http";
import { createClient, ScapError } from "../dist/client.js";

// No mock backend, fake SQL response or coverage-profile reuse in this suite.
// The caller owns and starts the real three-voter SCAP service processes.
for (const name of ["SCAP_ENDPOINTS", "SCAP_DATABASE", "SCAP_TOKEN"]) {
  if (!process.env[name]) throw new Error(`${name} is required for real-service contracts`);
}
const endpoints = JSON.parse(process.env.SCAP_ENDPOINTS);
const database = process.env.SCAP_DATABASE;
const authToken = process.env.SCAP_TOKEN;
const config = { endpoints, database, authToken, timeoutMs: 10_000 };
const prefix = `sdk_${crypto.randomUUID().replaceAll("-", "")}`;
const requestId = () => crypto.randomUUID().replaceAll("-", "");

async function leader() {
  for (const endpoint of endpoints) {
    const response = await fetch(new URL("/readyz", endpoint), { redirect: "manual", signal: AbortSignal.timeout(2000) });
    await response.body?.cancel();
    if (response.status === 200) return endpoint;
  }
  throw new Error("No ready replica supplied to real SDK contracts");
}

test("unmodified pinned @libsql/client executes SQL, cached atomic batches and SQLite values", async () => {
  const endpoint = await leader();
  const db = libsqlClient({ url: new URL(`/db/${database}/`, endpoint).href, authToken, intMode: "bigint" });
  try {
    await db.execute(`CREATE TABLE ${prefix}_raw(id INTEGER PRIMARY KEY, value BLOB)`);
    const insert = `INSERT INTO ${prefix}_raw(id, value) VALUES (?, ?) RETURNING id, value`;
    const results = await db.batch([
      { sql: insert, args: [9223372036854775807n, new Uint8Array([0, 1, 255])] },
      { sql: insert, args: [-9223372036854775808n, new Uint8Array([3, 4])] },
    ], "write");
    assert.equal(results[0].rows[0].id, 9223372036854775807n);
    assert.equal(results[1].rows[0].id, -9223372036854775808n);
    assert.deepEqual(new Uint8Array(results[0].rows[0].value), new Uint8Array([0, 1, 255]));
    const values = await db.execute({ sql: "SELECT ? AS n, ? AS f, ? AS s", args: [null, 1.5, "你好"] });
    assert.equal(values.rows[0].n, null); assert.equal(values.rows[0].f, 1.5); assert.equal(values.rows[0].s, "你好");
    await assert.rejects(db.batch([
      { sql: insert, args: [1n, new Uint8Array([5])] },
      { sql: insert, args: [1n, new Uint8Array([6])] },
    ]));
  } finally { db.close(); }
  const reader = createClient(config);
  try { assert.equal((await reader.query(`SELECT count(*) AS n FROM ${prefix}_raw`)).rows[0].n, 2n); }
  finally { reader.close(); }
});

test("stable request IDs retain original random RETURNING results without duplicate SQL execution", async () => {
  const db = createClient(config);
  try {
    await db.execute(`CREATE TABLE ${prefix}_dedup(id INTEGER PRIMARY KEY, nonce TEXT)`);
    const id = requestId();
    const statement = { sql: `INSERT INTO ${prefix}_dedup VALUES (?, hex(randomblob(12))) RETURNING nonce`, args: [1n] };
    const original = await db.execute(statement, { requestId: id });
    const repeated = await db.execute(statement, { requestId: id });
    assert.equal(repeated.rows[0].nonce, original.rows[0].nonce);
    assert.equal((await db.query(`SELECT count(*) AS n FROM ${prefix}_dedup`)).rows[0].n, 1n);
    const outcome = await db.lookup({ requestId: id, statements: [statement] });
    assert.equal(outcome.state, "committed");
    assert.equal(outcome.results[0].rows[0][0], original.rows[0].nonce);
    await assert.rejects(db.execute({ ...statement, args: [2n] }, { requestId: id }));
  } finally { db.close(); }
});

test("explicit strong queries create no accepted-write result and reject SQL mutations", async () => {
  const db = createClient(config);
  try {
    await db.execute(`CREATE TABLE ${prefix}_read(id INTEGER PRIMARY KEY)`);
    const id = requestId();
    const statement = `SELECT count(*) AS n FROM ${prefix}_read`;
    assert.equal((await db.query(statement, { requestId: id })).rows[0].n, 0n);
    assert.deepEqual(await db.lookup({ requestId: id, statements: [statement] }), { state: "unknown" });
    await assert.rejects(db.query(`INSERT INTO ${prefix}_read VALUES (1)`));
    assert.equal((await db.query(statement)).rows[0].n, 0n);
  } finally { db.close(); }
});

test("a lost successful HTTP response is UNKNOWN and resolves to one original committed transaction", async () => {
  const setup = createClient(config);
  await setup.execute(`CREATE TABLE ${prefix}_lost(id INTEGER PRIMARY KEY, nonce TEXT)`);
  setup.close();
  let attempts = 0;
  const runtime = {
    now: () => Date.now(), monotonic: () => performance.now(), requestId,
    createClient: libsqlClient,
    fetch: async (input, init) => {
      const request = new Request(input, init);
      const response = await fetch(request);
      if (request.method === "POST" && new URL(request.url).pathname.endsWith("/v2/pipeline")) {
        attempts++;
        assert.equal(response.status, 200);
        const body = await response.json();
        assert.equal(body.results.find((result) => result.response?.type === "execute")?.type, "ok");
        throw new Error("injected loss after complete successful response");
      }
      return response;
    },
  };
  const db = createClient(config, runtime);
  let identity;
  try {
    await assert.rejects(db.execute(`INSERT INTO ${prefix}_lost VALUES (1, hex(randomblob(12))) RETURNING nonce`), (error) => {
      assert.ok(error instanceof ScapError); assert.equal(error.code, "COMMIT_UNKNOWN"); identity = error.request; return true;
    });
  } finally { db.close(); }
  assert.equal(attempts, 1);
  const resolver = createClient(config);
  try {
    const outcome = await resolver.lookup(identity);
    assert.equal(outcome.state, "committed");
    const state = await resolver.query(`SELECT nonce FROM ${prefix}_lost WHERE id = 1`);
    assert.equal(outcome.results[0].rows[0][0], state.rows[0].nonce);
    assert.equal((await resolver.query(`SELECT count(*) AS n FROM ${prefix}_lost`)).rows[0].n, 1n);
  } finally { resolver.close(); }
});

test("ordered cancellation fences a future same-ID write and credentials cannot select another scope", async () => {
  const db = createClient(config);
  try {
    await db.execute(`CREATE TABLE ${prefix}_cancel(id INTEGER PRIMARY KEY)`);
    const identity = { requestId: requestId(), statements: [`INSERT INTO ${prefix}_cancel VALUES (1)`] };
    assert.deepEqual(await db.lookup(identity), { state: "unknown" });
    const cancelled = await db.resolveOrCancel(identity);
    assert.equal(cancelled.state, "cancelled");
    assert.equal(cancelled.acknowledged, false);
    assert.ok(cancelled.position.term > 0n && cancelled.position.index > 0n);
    await assert.rejects(db.execute(identity.statements[0], { requestId: identity.requestId }));
    assert.equal((await db.query(`SELECT count(*) AS n FROM ${prefix}_cancel`)).rows[0].n, 0n);
  } finally { db.close(); }
  const denied = createClient({ ...config, authToken: "invalid-credential" });
  try { await assert.rejects(denied.query("SELECT 1"), (error) => error.code === "UNAUTHORIZED"); }
  finally { denied.close(); }
  const other = createClient({ ...config, database: "unconfigured_database" });
  try { await assert.rejects(other.query("SELECT 1")); }
  finally { other.close(); }
});
