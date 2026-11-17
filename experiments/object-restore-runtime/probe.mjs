/** Actual restore scenarios. No production logic or retries are implemented here. */
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createServer, request, Agent } from 'node:http';
import { createServer as netServer } from 'node:net';
import { mkdir, writeFile, appendFile, rm, lstat, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { setTimeout as pause } from 'node:timers/promises';
import { Client, CatalogueClient, UnknownError } from '../../sdk/node/src/client.js';
import { Recorder, bytes, processIdentity, typedResult } from './capture.mjs';

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
const records = new Recorder(evidence);
let service;
let gate;
let proxy;
const agent = new Agent({ keepAlive: true, maxSockets: 16 });

function arm(prefix) {
  assert.equal(gate, undefined);
  let arrived, release;
  const reached = new Promise((resolve) => { arrived = resolve; });
  const wait = new Promise((resolve) => { release = resolve; });
  const id = records.emit('gate_armed', { prefix });
  const value = { id, prefix, reached, arrived, wait, consumed: false,
    release() { if (!this.released) { this.released = true; records.emit('gate_released', { gate: id }); release(); } } };
  gate = value;
  return value;
}

async function proxyStart() {
  proxy = createServer(async (incoming, outgoing) => {
    const path = incoming.url;
    const id = ++records.s3, stage = records.stage;
    records.emit('s3_request', { id, method: incoming.method, path,
      if_match: incoming.headers['if-match'] ?? null, if_none_match: incoming.headers['if-none-match'] ?? null }, stage);
    const current = gate;
    if (current && !current.consumed && incoming.method === 'GET' && path.startsWith(`/${BUCKET}/${current.prefix}`)) {
      current.consumed = true;
      records.emit('gate_held', { gate: current.id, request: id }, stage);
      current.arrived();
      await current.wait;
      gate = undefined;
    }
    const requestHash = createHash('sha256'), requestChunks = [];
    let requestBytes = 0;
    incoming.on('data', (chunk) => { requestHash.update(chunk); requestBytes += chunk.length;
      if (path.endsWith('/head')) requestChunks.push(chunk); });
    incoming.on('end', () => records.emit('s3_request_end', { id, length: requestBytes, sha256: requestHash.digest('hex'),
      ...(path.endsWith('/head') ? { body: bytes(Buffer.concat(requestChunks)) } : {}) }, stage));
    const upstream = request(new URL(path, backend), { method: incoming.method, headers: incoming.headers, agent }, (response) => {
      const responseHash = createHash('sha256'), responseChunks = [];
      let responseBytes = 0;
      response.on('data', (chunk) => { responseHash.update(chunk); responseBytes += chunk.length;
        if (path.endsWith('/head')) responseChunks.push(chunk); });
      response.on('end', () => {
        records.emit('s3_response', { id, status: response.statusCode, etag: response.headers.etag ?? null,
          length: responseBytes, sha256: responseHash.digest('hex'),
          ...(path.endsWith('/head') ? { body: bytes(Buffer.concat(responseChunks)) } : {}) }, stage);
        history.push({ id, method: incoming.method, path, status: response.statusCode,
          if_match: incoming.headers['if-match'] ?? null, if_none_match: incoming.headers['if-none-match'] ?? null });
      });
      outgoing.writeHead(response.statusCode, response.headers);
      response.pipe(outgoing);
    });
    upstream.on('error', (error) => { records.emit('s3_transport_failure', { id }, stage); outgoing.destroy(error); });
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
  assert.deepEqual(await readdir(cache), []);
  const address = `127.0.0.1:${await port()}`;
  const path = join(privateDirectory, `config-${worker}.json`);
  const configBytes = JSON.stringify(configuration(endpoint, cache, address, worker));
  await writeFile(path, configBytes, { mode: 0o600 });
  const child = spawn(binary, [path], { stdio: ['ignore', 'pipe', 'pipe'] });
  const owned = { id: services.length + 1, child, cache, endpoint: `http://${address}`, worker, output: '', error: '' };
  owned.exited = once(child, 'exit');
  owned.closed = once(child, 'close');
  child.stdout.on('data', (bytes) => { owned.output += bytes; });
  child.stderr.on('data', (bytes) => { owned.error += bytes; });
  services.push(owned);
  records.emit('service_spawned', { process: owned.id, ...processIdentity(child.pid), worker: String(worker),
    cache_id: `cache-${worker}`, cache_fresh: true, cache_empty: true, config_sha256: sha(configBytes) });
  for (let count = 0; count < 150; count++) {
    assert.equal(child.exitCode, null, owned.error);
    try {
      const response = await fetch(`${owned.endpoint}/healthz`, { signal: AbortSignal.timeout(200) });
      if (response.status === 200) {
        records.emit('service_ready', { process: owned.id, status: response.status, body: bytes(await response.arrayBuffer()) });
        service = owned; return owned;
      }
    } catch {}
    await pause(50);
  }
  throw new Error(`daemon readiness exceeded: ${owned.error}`);
}

async function stop(owned) {
  assert.equal(owned.stopped, undefined);
  assert.equal(owned.child.exitCode, null); assert.equal(owned.child.signalCode, null);
  assert.equal(owned.child.kill('SIGKILL'), true);
  records.emit('signal_sent', { process: owned.id, signal: 'SIGKILL', accepted: true });
  const [code, signal] = await owned.exited;
  assert.equal(signal, 'SIGKILL'); assert.equal(code, null);
  const [closeCode, closeSignal] = await owned.closed;
  assert.equal(closeSignal, 'SIGKILL'); assert.equal(closeCode, null);
  records.emit('service_reaped', { process: owned.id, code, signal, close_code: closeCode, close_signal: closeSignal });
  await writeFile(join(evidence, `daemon-${owned.worker}.stderr.log`), owned.error);
  await rm(owned.cache, { recursive: true });
  await assert.rejects(lstat(owned.cache), { code: 'ENOENT' });
  records.emit('cache_deleted', { process: owned.id, cache_id: `cache-${owned.worker}`, absent: true });
  owned.stopped = true;
}

const names = (fetcher = records.fetch(service)) => new CatalogueClient({ endpoint: `${service.endpoint}/v1/catalogue`,
  token: TOKEN, deployment: '1', tenant: '2', principal: '3', fetch: fetcher, timeoutMs: 10000, recoveryTimeoutMs: 60000 });
const database = (scope = SCOPE, principal = '3') => new Client({ endpoint: `${service.endpoint}/v1`,
  token: principal === '3' ? TOKEN : ADMIN, scope, principal, fetch: records.fetch(service, principal),
  timeoutMs: 10000, recoveryTimeoutMs: 60000 });
const check = async (name, action) => { records.stage = name; records.emit('case_begin', { name });
  await action(); records.emit('case_end', { name }); cases.push(name); await writeFile(join(evidence, 'cases.json'), json(cases)); };
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
  records.emit('intent_saved', { operation: String(operation), body: bytes(Buffer.from(saved)) });
  return client.submit(client.restoreIntent(saved));
}

async function toCopying(value) {
  for (const phase of ['reserved', 'copying']) assert.equal((await names().resumeRestore(value.reference)).phase, phase);
}

async function finish(value, phases) {
  for (const phase of phases) assert.equal((await names().resumeRestore(value.reference)).phase, phase);
}

async function s3(method, key) {
  const id = ++records.admin, stage = records.stage;
  records.emit('admin_request', { id, method, path: `/${BUCKET}/${key}` }, stage);
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
  const response = await fetch(url, { method, headers, signal: AbortSignal.timeout(10000) });
  const body = Buffer.from(await response.arrayBuffer());
  records.emit('admin_response', { id, status: response.status, length: body.length, sha256: sha(body) }, stage);
  return response;
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
    const originalHttp = records.http;
    expected = await db.query(sourceSelect);
    records.emit('expectation', { name: 'original', original_http: originalHttp, query_http: records.http,
      result: typedResult(originalCommitted.result), rows: typedResult(expected), receipt: originalCommitted.receipt,
      raw_result: bytes(originalCommitted.rawResult) });
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
    const lost = names(records.fetch(service, '3', true));
    await assert.rejects(lost.resumeRestore(prepared.reference), (error) => {
      assert.ok(error instanceof UnknownError);
      records.emit('unknown_observed', { id: records.lostHttp, code: error.code, reference: error.reference });
      return true;
    });
    await stop(service);
    await start(endpoint, 2002);
    const before = history.length;
    records.emit('checkpoint', { name: 'completed_resume_begin' });
    assert.equal((await names().inspectRestore('1001')).phase, 'copied');
    await finish(prepared, ['bound', 'ready']);
    records.emit('checkpoint', { name: 'completed_resume_end' });
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
  await check('completed_restore_missing_target_head_fails_closed_without_recreation', async () => {
    const value = await prepare(1004, 'authority-loss'); await toCopying(value);
    await finish(value, ['copied']);
    const scope = value.reference.creation.scope;
    const path = `/${BUCKET}/scap-object/v1/${scope.deployment}/${scope.tenant}/${scope.database}/head`;
    assert.ok(history.some((row) => row.method === 'PUT' && row.path === path && row.status >= 200 && row.status < 300));
    records.emit('checkpoint', { name: 'authority_loss_before_delete', scope, path });
    assert.ok((await s3('DELETE', path.slice(BUCKET.length + 2))).ok);
    assert.equal((await s3('GET', path.slice(BUCKET.length + 2))).status, 404);
    const before = history.length;
    records.emit('checkpoint', { name: 'authority_loss_missing_verified', path });
    await reject(names().inspectRestore('1004'), 'CORRUPT');
    await reject(names().resumeRestore(value.reference), 'CORRUPT');
    assert.equal(history.slice(before).filter((row) => row.method === 'PUT' && row.path === path).length, 0);
    records.emit('checkpoint', { name: 'authority_loss_checks_end', path });
  });
  await check('source_payload_deleted_then_all_cache_lost_target_still_recovers', async () => {
    const db = database(); await db.snapshotRelease(snapshot);
    const head = await db.status();
    const deleted = await db.setLifecycle({ expectedRevision: head.revision, nonce: '1301', lifecycle: 'deleted' });
    await db.retireStorage({ expectedHeadSerial: deleted.head_serial });
    const keys = [...new Set(history.filter((row) => ['GET', 'PUT'].includes(row.method) && row.status >= 200 && row.status < 300 &&
      row.path.startsWith(`/${BUCKET}/${sourcePrefix}`)).map((row) => row.path.slice(BUCKET.length + 2)))];
    assert.ok(keys.length >= 6, 'multi-chunk source objects were not observed');
    for (const key of keys) { assert.ok((await s3('DELETE', key)).ok); assert.equal((await s3('GET', key)).status, 404); }
    records.emit('checkpoint', { name: 'source_payloads_deleted', keys: keys.map((key) => `/${BUCKET}/${key}`) });
    await stop(service);
    await start(endpoint, 2003);
    assert.deepEqual(await database(prepared.reference.creation.scope).query(sourceSelect), expected);
    const resolved = await names().resolveName('restored');
    assert.deepEqual(resolved.creation, prepared.reference.creation);
    await writeFile(join(evidence, 'source-deletion.json'), json({ verified_absent_payloads: keys.length,
      retained_target_rows: expected.statements[0].rows.length, expected_result_sha256: sha(json(expected)) }));
  });
} finally {
  records.stage = 'teardown';
  gate?.release();
  for (const owned of services) if (!owned.stopped) await stop(owned);
  agent.destroy();
  if (proxy) { const closed = once(proxy, 'close'); proxy.closeAllConnections(); proxy.close(); await closed; }
  await writeFile(join(evidence, 's3-history.jsonl'), `${history.map(json).join('\n')}\n`);
}
records.emit('probe_complete', { cases, processes: services.length, object_requests: history.length });
await writeFile(join(evidence, 'result.json'), json({ status: 'PROBE_COMPLETED_AUDIT_REQUIRED', cases,
  services: services.map(({ child, worker }) => ({ pid: child.pid, worker })), object_requests: history.length,
  expected_result_sha256: sha(json(expected)), original_restore: prepared.reference }));
