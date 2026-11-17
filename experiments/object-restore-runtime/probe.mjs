/** Actual restore scenarios. No production logic or retries are implemented here. */
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createServer, request, Agent } from 'node:http';
import { createServer as netServer } from 'node:net';
import { mkdir, writeFile, appendFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { setTimeout as pause } from 'node:timers/promises';
import { Client, CatalogueClient, UnknownError } from '../../sdk/node/src/client.js';

const [binary, backend, privateDirectory, evidence] = process.argv.slice(2);
assert.ok(binary && backend && privateDirectory && evidence);
const TOKEN = 'synthetic-s2-restore-credential-principal-three';
const ADMIN = 'synthetic-s2-restore-credential-principal-nine';
const SCOPE = { deployment: '1', tenant: '2', database: '3', incarnation: '4', generation: '5' };
const BUCKET = 'scap-test';
const sourcePrefix = `scap-object/v1/1/2/3/inc/4/gen/5/storage/`;
const sha = (data) => createHash('sha256').update(data).digest('hex');
const keyed = (key, data) => createHmac('sha256', key).update(data).digest();
const json = (value) => JSON.stringify(value, (_, item) => typeof item === 'bigint' ? `${item}n` : item);
const history = [];
const cases = [];
const services = [];
let service;
let gate;
let proxy;
const agent = new Agent({ keepAlive: true, maxSockets: 16 });

function arm(prefix) {
  assert.equal(gate, undefined);
  let arrived, release;
  const reached = new Promise((resolve) => { arrived = resolve; });
  const wait = new Promise((resolve) => { release = resolve; });
  const value = { prefix, reached, arrived, wait, release, consumed: false };
  gate = value;
  return value;
}

async function proxyStart() {
  proxy = createServer(async (incoming, outgoing) => {
    const path = incoming.url;
    const current = gate;
    if (current && !current.consumed && incoming.method === 'GET' && path.startsWith(`/${BUCKET}/${current.prefix}`)) {
      current.consumed = true;
      current.arrived();
      await current.wait;
      gate = undefined;
    }
    const upstream = request(new URL(path, backend), { method: incoming.method, headers: incoming.headers, agent }, (response) => {
      history.push({ method: incoming.method, path, status: response.statusCode,
        if_match: incoming.headers['if-match'] ?? null, if_none_match: incoming.headers['if-none-match'] ?? null });
      outgoing.writeHead(response.statusCode, response.headers);
      response.pipe(outgoing);
    });
    upstream.on('error', (error) => { outgoing.destroy(error); });
    incoming.pipe(upstream);
  });
  proxy.listen(0, '127.0.0.1');
  await once(proxy, 'listening');
  return `http://127.0.0.1:${proxy.address().port}`;
}

async function port() {
  const socket = netServer(); socket.listen(0, '127.0.0.1'); await once(socket, 'listening');
  const value = socket.address().port; socket.close(); await once(socket, 'close'); return value;
}

function configuration(endpoint, cache, listen, worker) {
  const admission = { workers: 1, queued_total: 8, queued_per_tenant: 6, queued_per_name: 4,
    intake: 4, max_body_bytes: 65536, timeout_ms: 10000 };
  return { version: 1, listen, worker_instance: String(worker), cache_directory: cache,
    s3: { endpoint, region: 'us-east-1', bucket: BUCKET, access_key_env: 'SCAP_RESTORE_ACCESS',
      secret_key_env: 'SCAP_RESTORE_SECRET', session_token_env: null, allow_http: true, timeout_ms: 30000 },
    admission: { active_database_actors: 8, active_database_actors_per_tenant: 8, actor_idle_timeout_ms: 10000,
      control_workers: 2, queued_total: 32, queued_per_tenant: 24, queued_per_database: 8, reserved_controls: 4,
      data_intake: 8, control_intake: 8, recovery_intake: 4, max_body_bytes: 2 * 1024 * 1024,
      timeout_ms: 10000, recovery_timeout_ms: 60000 },
    catalogue: admission, restore: { admission, recovery_timeout_ms: 60000,
      max_staging_bytes: 64 * 1024 * 1024, max_staging_bytes_per_tenant: 32 * 1024 * 1024,
      budget: { source_gets: 4096, source_bytes: 64 * 1024 * 1024, target_puts: 4096,
        target_put_bytes: 64 * 1024 * 1024, target_gets: 4096, target_get_bytes: 64 * 1024 * 1024,
        max_image_bytes: 16 * 1024 * 1024 } },
    cache: { pages_per_actor: 4096, parallel_recoveries: 2 },
    credentials: [[TOKEN, '3'], [ADMIN, '9']].map(([token, principal]) => ({ sha256: sha(token),
      deployment: '1', tenant: '2', principal, provision: true })) };
}

async function start(endpoint, worker) {
  const cache = join(privateDirectory, `cache-${worker}`);
  await mkdir(cache);
  const address = `127.0.0.1:${await port()}`;
  const path = join(privateDirectory, `config-${worker}.json`);
  await writeFile(path, JSON.stringify(configuration(endpoint, cache, address, worker)));
  const child = spawn(binary, [path], { stdio: ['ignore', 'pipe', 'pipe'] });
  const owned = { child, cache, endpoint: `http://${address}`, worker, output: '', error: '' };
  owned.exited = once(child, 'exit');
  child.stdout.on('data', (bytes) => { owned.output += bytes; });
  child.stderr.on('data', (bytes) => { owned.error += bytes; });
  services.push(owned);
  for (let count = 0; count < 150; count++) {
    assert.equal(child.exitCode, null, owned.error);
    try {
      const response = await fetch(`${owned.endpoint}/healthz`, { signal: AbortSignal.timeout(200) });
      if (response.status === 200) { service = owned; return owned; }
    } catch {}
    await pause(50);
  }
  throw new Error(`daemon readiness exceeded: ${owned.error}`);
}

async function stop(owned) {
  if (owned.child.exitCode === null && owned.child.signalCode === null) owned.child.kill('SIGKILL');
  const [code, signal] = await owned.exited;
  assert.equal(signal, 'SIGKILL'); assert.equal(code, null);
  await writeFile(join(evidence, `daemon-${owned.worker}.stderr.log`), owned.error);
  await rm(owned.cache, { recursive: true });
}

const names = (fetcher = fetch) => new CatalogueClient({ endpoint: `${service.endpoint}/v1/catalogue`,
  token: TOKEN, deployment: '1', tenant: '2', principal: '3', fetch: fetcher, timeoutMs: 10000, recoveryTimeoutMs: 60000 });
const database = (scope = SCOPE, principal = '3') => new Client({ endpoint: `${service.endpoint}/v1`,
  token: principal === '3' ? TOKEN : ADMIN, scope, principal, timeoutMs: 10000, recoveryTimeoutMs: 60000 });
const check = async (name, action) => { await action(); cases.push(name); await writeFile(join(evidence, 'cases.json'), json(cases)); };
const reject = (promise, code) => assert.rejects(promise, (error) => error.code === code);
const sourceSelect = [{ sql: 'SELECT id,n,payload FROM saved ORDER BY id', parameters: [] }];
const originalStatements = [{ sql: 'CREATE TABLE saved(id INTEGER PRIMARY KEY,n INTEGER,payload BLOB)', parameters: [] },
  { sql: 'INSERT INTO saved VALUES(1,random(),randomblob(180000))', parameters: [] },
  { sql: 'INSERT INTO saved VALUES(2,?,?)', parameters: [9007199254740993n, Buffer.alloc(8192, 73)] }, ...sourceSelect];
let snapshot, expected, original, originalCommitted, prepared;

async function prepare(operation, name) {
  const client = names();
  const intent = client.prepareIntent({ operation: 'prepare_restore', name, restore_operation: String(operation),
    expected_name_revision: null, options: { quota: { mode: 'default' } }, source_scope: SCOPE, snapshot: snapshot.reference });
  const saved = client.saveIntent(intent);
  await appendFile(join(evidence, 'intents.jsonl'), `${saved}\n`);
  return client.submit(client.restoreIntent(saved));
}

async function toCopying(value) {
  for (const phase of ['reserved', 'copying']) assert.equal((await names().resumeRestore(value.reference)).phase, phase);
}

async function finish(value, phases) {
  for (const phase of phases) assert.equal((await names().resumeRestore(value.reference)).phase, phase);
}

async function s3(method, key) {
  const url = new URL(`/${BUCKET}/${key}`, backend);
  const date = new Date().toISOString().replace(/[:-]|\.\d{3}/g, '');
  const day = date.slice(0, 8), digest = sha('');
  const headers = { host: url.host, 'x-amz-content-sha256': digest, 'x-amz-date': date };
  const signed = Object.keys(headers).join(';');
  const canonical = `${method}\n${url.pathname}\n\n${Object.entries(headers).map(([k, v]) => `${k}:${v}\n`).join('')}\n${signed}\n${digest}`;
  const scope = `${day}/us-east-1/s3/aws4_request`;
  const keyDate = keyed(`AWS4${process.env.SCAP_RESTORE_SECRET}`, day);
  const signing = keyed(keyed(keyed(keyDate, 'us-east-1'), 's3'), 'aws4_request');
  const signature = keyed(signing, `AWS4-HMAC-SHA256\n${date}\n${scope}\n${sha(canonical)}`).toString('hex');
  headers.authorization = `AWS4-HMAC-SHA256 Credential=${process.env.SCAP_RESTORE_ACCESS}/${scope}, SignedHeaders=${signed}, Signature=${signature}`;
  return fetch(url, { method, headers, signal: AbortSignal.timeout(10000) });
}

try {
  const endpoint = await proxyStart();
  await start(endpoint, 2001);
  await check('native_source_snapshot_keeps_exact_random_and_blob_values', async () => {
    const db = database();
    const created = await db.create({ nonce: '1' });
    await db.activate({ expectedRevision: created.revision, nonce: '2' });
    original = db.prepare(originalStatements, { epoch: '1', id: '1' });
    originalCommitted = await db.execute(original);
    expected = await db.query(sourceSelect);
    assert.deepEqual(originalCommitted.result.statements[3].rows, expected.statements[0].rows);
    const head = await db.status();
    const saved = db.prepareSnapshotInput({ creator: '3', operation: '900', expected_revision: head.revision,
      expected_head_serial: head.head_serial, label: 'retained original' });
    snapshot = await db.snapshotPrepare(saved);
    await db.snapshotCapture(snapshot);
    await db.execute(db.prepare([{ sql: 'UPDATE saved SET n=0,payload=zeroblob(16)', parameters: [] }], { epoch: '1', id: '2' }));
    assert.notDeepEqual(await db.query(sourceSelect), expected);
  });
  await check('empty_create_and_restore_share_the_first_winner_slot', async () => {
    prepared = await prepare(1001, 'restored');
    await reject(names().prepareCreate({ name: 'restored', create_operation: '1001', expected_name_revision: null,
      options: { quota: { mode: 'default' } } }), 'CONFLICT');
    await reject(names().prepareRestore({ ...prepared.input, name: 'changed' }), 'CONFLICT');
  });
  await check('cancel_while_payload_get_is_held_permanently_fences_late_copy', async () => {
    const value = await prepare(1002, 'cancelled'); await toCopying(value);
    const held = arm(sourcePrefix);
    const running = names().resumeRestore(value.reference).then((result) => ({ result }), (error) => ({ error }));
    await Promise.race([held.reached, pause(15000).then(() => { throw new Error('copy never reached payload'); })]);
    assert.equal((await names().inspectRestore('1002')).phase, 'copying');
    const input = { reference: value.reference, control_operation: '1102', expected_name_revision: '1', nonce: '1102' };
    for (let count = 0; count < 4; count++) {
      const aborted = await names().abortRestore(input);
      if (aborted.phase === 'aborted') break;
      assert.equal(aborted.phase, 'aborting');
    }
    assert.equal((await names().inspectRestore('1002')).phase, 'aborted');
    held.release();
    const outcome = await running;
    assert.equal(outcome.error?.code, 'CONFLICT');
    assert.equal((await names().resumeRestore(value.reference)).phase, 'aborted');
    await reject(names().resolveName('cancelled'), 'NOT_FOUND');
  });
  await check('fresh_source_revocation_wins_over_a_completed_payload_prefix', async () => {
    const value = await prepare(1003, 'revoked'); await toCopying(value);
    const held = arm(sourcePrefix);
    const running = names().resumeRestore(value.reference).then((result) => ({ result }), (error) => ({ error }));
    await Promise.race([held.reached, pause(15000).then(() => { throw new Error('copy never reached payload'); })]);
    const db = database(), head = await db.status();
    await db.setPolicy({ expectedRevision: head.revision, nonce: '1203', permissions: [
      { principal: '9', read: true, write: true, admin: true }] });
    held.release();
    const outcome = await running;
    assert.equal(outcome.error?.code, 'DENIED');
    assert.equal((await names().inspectRestore('1003')).phase, 'copying');
    const admin = database(SCOPE, '9'), deniedHead = await admin.status();
    await admin.setPolicy({ expectedRevision: deniedHead.revision, nonce: '1204', permissions: [
      { principal: '3', read: true, write: true, admin: true }, { principal: '9', read: true, write: true, admin: true }] });
    await finish(value, ['copied', 'bound', 'ready']);
    assert.deepEqual(await database(value.reference.creation.scope).query(sourceSelect), expected);
  });
  await check('lost_http_response_and_sigkill_resume_original_operation_without_recopy', async () => {
    await toCopying(prepared);
    const lost = names(async (...args) => { const response = await fetch(...args); await response.arrayBuffer(); throw new Error('injected lost HTTP reply after execution'); });
    await assert.rejects(lost.resumeRestore(prepared.reference), UnknownError);
    await stop(service);
    await start(endpoint, 2002);
    const before = history.length;
    assert.equal((await names().inspectRestore('1001')).phase, 'copied');
    await finish(prepared, ['bound', 'ready']);
    assert.equal(history.slice(before).filter((row) => row.method === 'GET' && row.path.startsWith(`/${BUCKET}/${sourcePrefix}`)).length, 0);
    const target = database(prepared.reference.creation.scope), head = await target.status();
    assert.equal(head.sequence, '0'); assert.equal(head.active, false);
    assert.deepEqual(await target.query(sourceSelect), expected);
    const targetOld = target.prepare(originalStatements, { epoch: '1', id: '1' });
    assert.equal((await target.lookup(targetOld)).state, 'unknown');
    const recovered = await database().lookup(original);
    assert.equal(recovered.state, 'committed');
    assert.deepEqual(recovered.receipt, originalCommitted.receipt);
    assert.deepEqual(recovered.result, originalCommitted.result);
  });
  await check('source_payload_deleted_then_all_cache_lost_target_still_recovers', async () => {
    const db = database(); await db.snapshotRelease(snapshot);
    const head = await db.status();
    const deleted = await db.setLifecycle({ expectedRevision: head.revision, nonce: '1301', lifecycle: 'deleted' });
    await db.retireStorage({ expectedHeadSerial: deleted.head_serial });
    const keys = [...new Set(history.filter((row) => row.method === 'PUT' && row.status < 300 &&
      row.path.startsWith(`/${BUCKET}/${sourcePrefix}`)).map((row) => row.path.slice(BUCKET.length + 2)))];
    assert.ok(keys.length >= 6, 'multi-chunk source objects were not observed');
    for (const key of keys) { assert.ok((await s3('DELETE', key)).ok); assert.equal((await s3('GET', key)).status, 404); }
    await stop(service);
    await start(endpoint, 2003);
    assert.deepEqual(await database(prepared.reference.creation.scope).query(sourceSelect), expected);
    const resolved = await names().resolveName('restored');
    assert.deepEqual(resolved.creation, prepared.reference.creation);
    await writeFile(join(evidence, 'source-deletion.json'), json({ verified_absent_payloads: keys.length,
      retained_target_rows: expected.statements[0].rows.length, expected_result_sha256: sha(json(expected)) }));
  });
  await writeFile(join(evidence, 'result.json'), json({ status: 'PASS', cases, services: services.map(({ child, worker }) => ({ pid: child.pid, worker })),
    object_requests: history.length, expected_result_sha256: sha(json(expected)), original_restore: prepared.reference }));
} finally {
  gate?.release();
  for (const owned of services) if (owned.child.exitCode === null && owned.child.signalCode === null) await stop(owned);
  agent.destroy();
  if (proxy) { const closed = once(proxy, 'close'); proxy.closeAllConnections(); proxy.close(); await closed; }
  await writeFile(join(evidence, 's3-history.jsonl'), `${history.map(json).join('\n')}\n`);
}
