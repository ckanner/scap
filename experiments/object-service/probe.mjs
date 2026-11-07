/** Real SDK -> HTTP daemon -> signed S3 -> native SQLite acceptance client.
 * This script is test assembly; all protocol/client logic is imported from SDK.
 */
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync, openSync, writeSync, fsyncSync, closeSync } from 'node:fs';
import { Client } from '../../sdk/node/src/client.js';

const [mode, privatePath, evidence] = process.argv.slice(2);
const config = JSON.parse(readFileSync(privatePath, 'utf8'));
let httpAttempts = 0;
const scope = (database = '101', tenant = '7') => ({ deployment: '1', tenant, database, incarnation: '1', generation: '1' });
function client(options = {}) {
  return new Client({ endpoint: config.endpoint + '/v1', token: config.tokens.admin,
    scope: scope(), principal: '11', timeoutMs: 10000,
    fetch: (...arguments_) => { httpAttempts++; return globalThis.fetch(...arguments_); }, ...options });
}
const a = client();
const statement = (sql, parameters = []) => ({ sql, parameters });
const sha = (data) => createHash('sha256').update(data).digest('hex');
function append(file, value) {
  const fd = openSync(evidence + '/' + file, 'a', 0o600);
  try { writeSync(fd, JSON.stringify(value) + '\n'); fsyncSync(fd); } finally { closeSync(fd); }
}
function prepared(client, statements, id) {
  const request = client.prepare(statements, { epoch: '1', id });
  append('inputs.jsonl', { request: client.save(request) });
  return request;
}
async function acknowledged(client, request) {
  const value = await client.execute(request);
  assert.equal(value.state, 'committed');
  append('acks.jsonl', { request: client.save(request), receipt: value.receipt,
    raw: value.rawResult.toString('base64'), raw_sha256: sha(value.rawResult) });
  return value;
}
function saved() { return JSON.parse(readFileSync(evidence + '/state.json', 'utf8')); }
function remember(value) { writeFileSync(evidence + '/state.json', JSON.stringify(value, null, 2) + '\n', { mode: 0o600 }); }
async function rejected(fn, codes) {
  await assert.rejects(fn, (error) => codes.includes(error.code));
}
async function control(client, method, fields = {}) {
  const status = await client.status();
  return client[method]({ expectedRevision: status.revision, nonce: String(BigInt(status.revision) + 8000n), ...fields });
}
async function verifyData(client, state) {
  const result = await client.query([statement('SELECT id, payload, label, large_integer FROM records ORDER BY id')]);
  assert.equal(result.statements[0].rows.length, state.rows.length);
  for (let i = 0; i < state.rows.length; i++) {
    const [id, bytes, label, integer] = result.statements[0].rows[i];
    assert.equal(id, BigInt(state.rows[i].id));
    assert.equal(sha(bytes), state.rows[i].sha256);
    assert.equal(label, state.rows[i].label);
    assert.equal(integer, 9223372036854775807n);
  }
  const count = await client.query([statement('SELECT count(*) FROM cancelled_effect')]);
  assert.equal(count.statements[0].rows[0][0], 0n);
  return result.statements[0].rows.length;
}

let report;
if (mode === 'initialize') {
  const wrong = client({ token: 'z'.repeat(64) });
  await rejected(() => wrong.status(), ['UNAUTHENTICATED']);
  const crossTenant = client({ token: config.tokens.other, principal: '22' });
  await rejected(() => crossTenant.status(), ['DENIED']);
  const created = await a.create({ nonce: '501' });
  assert.equal(created.active, false);
  assert.equal(created.max_bytes, '10737418240');
  await a.activate({ expectedRevision: created.revision, nonce: '502' });
  await a.open();
  const setup = prepared(a, [statement('CREATE TABLE records(id INTEGER PRIMARY KEY, payload BLOB, label TEXT, large_integer INTEGER)'),
    statement('CREATE TABLE cancelled_effect(id INTEGER)')], '1');
  await acknowledged(a, setup);
  const rows = [];
  for (let i = 0; i < 8; i++) {
    const bytes = randomBytes(65536), label = '\ufeff原始结果\0😀-' + i;
    const row = { id: i + 1, sha256: sha(bytes), label };
    append('data-inputs.jsonl', row); rows.push(row);
    const request = prepared(a, [statement('INSERT INTO records VALUES(?1,?2,?3,?4) RETURNING id, random(), payload, label, large_integer',
      [BigInt(row.id), bytes, label, 9223372036854775807n])], String(i + 2));
    const first = await acknowledged(a, request);
    const duplicate = await a.execute(a.restore(a.save(request)));
    append('duplicate-acks.jsonl', { request: a.save(request), receipt: duplicate.receipt,
      raw: duplicate.rawResult.toString('base64'), raw_sha256: sha(duplicate.rawResult) });
    assert.deepEqual(duplicate.receipt, first.receipt);
    assert.deepEqual(duplicate.rawResult, first.rawResult);
    const lookup = await a.lookup(request), cancel = await a.cancel(request);
    assert.deepEqual(lookup.receipt, first.receipt);
    assert.deepEqual(cancel.rawResult, first.rawResult);
    assert.equal(first.result.statements[0].rows[0][0], BigInt(row.id));
    assert.equal(sha(first.result.statements[0].rows[0][2]), row.sha256);
  }
  const collision = a.prepare([statement('SELECT 123')], { epoch: '1', id: '2' });
  await rejected(() => a.execute(collision), ['REQUEST_CONFLICT']);
  const cancelled = prepared(a, [statement('INSERT INTO cancelled_effect VALUES(1)')], '50');
  assert.equal((await a.cancel(cancelled)).state, 'cancelled');
  await rejected(() => a.execute(cancelled), ['CLOSED']);
  const readOnly = client({ token: config.tokens.reader, principal: '12' });
  await control(a, 'setPolicy', { permissions: [
    { principal: '11', read: true, write: true, admin: true },
    { principal: '12', read: true, write: false, admin: false },
  ] });
  await readOnly.open();
  assert.equal((await readOnly.query([statement('SELECT count(*) FROM records')])).statements[0].rows[0][0], 8n);
  const readerWrite = readOnly.prepare([statement('INSERT INTO cancelled_effect VALUES(2)')], { epoch: '1', id: '51' });
  await rejected(() => readOnly.execute(readerWrite), ['DENIED']);
  await control(a, 'setPolicy', { permissions: [{ principal: '11', read: true, write: true, admin: true }] });
  await rejected(() => readOnly.query([statement('SELECT count(*) FROM records')]), ['DENIED']);
  const b = client({ token: config.tokens.other, scope: scope('202', '8'), principal: '22' });
  const bCreated = await b.create({ nonce: '601' });
  await b.activate({ expectedRevision: bCreated.revision, nonce: '602' });
  await acknowledged(b, prepared(b, [statement('CREATE TABLE isolated(x INTEGER)'), statement('INSERT INTO isolated VALUES(77) RETURNING x')], '1'));
  await control(a, 'setLifecycle', { lifecycle: 'maintenance' });
  await rejected(() => a.execute(a.prepare([statement('INSERT INTO cancelled_effect VALUES(3)')], { epoch: '1', id: '52' })), ['LIFECYCLE']);
  assert.equal((await b.query([statement('SELECT x FROM isolated')])).statements[0].rows[0][0], 77n);
  await control(a, 'setLifecycle', { lifecycle: 'ready' });
  const state = { rows, cancelled: a.save(cancelled) }; remember(state);
  report = { phase: mode, rows_verified: await verifyData(a, state),
    contracts: ['authenticated_tenant_boundary', 'lossless_typed_sql', 'duplicate_original_results',
      'committed_lookup_cancel', 'request_collision', 'cancelled_request_fence',
      'warm_read_revocation', 'independent_database_and_maintenance'] };
} else if (mode === 'concurrent_create') {
  const first = client({ scope: scope('303') }), second = client({ scope: scope('303'), endpoint: config.secondary + '/v1' });
  const attempts = await Promise.allSettled([first.create({ nonce: '701' }), second.create({ nonce: '702' })]);
  assert.equal(attempts.filter((value) => value.status === 'fulfilled').length, 1);
  assert.equal(attempts.filter((value) => value.status === 'rejected' && value.reason.code === 'CONFLICT').length, 1);
  const left = await first.status(), right = await second.status();
  assert.deepEqual(left, right);
  report = { phase: mode, winners: 1, revision: left.revision, owner: left.owner_instance };
} else if (mode === 'unknown_write') {
  const request = prepared(a, [statement('INSERT INTO records VALUES(99, ?1, ?2, ?3) RETURNING id, random()',
    [Buffer.from('uncertain-original-payload'), 'unknown', 9223372036854775807n])], '99');
  const state = saved(); state.uncertain = a.save(request);
  state.rows.push({ id: 99, sha256: sha(Buffer.from('uncertain-original-payload')), label: 'unknown' }); remember(state);
  await rejected(() => a.execute(request), ['UNKNOWN']);
  assert.equal(httpAttempts, 1, 'SDK sent more than one HTTP attempt for the uncertain execute');
  append('outcomes.jsonl', { request: a.save(request), execute: 'UNKNOWN' });
  report = { phase: mode, original_outcome: 'UNKNOWN', sdk_http_attempts: httpAttempts };
} else if (mode === 'resolve_unknown') {
  const state = saved(), request = a.restore(state.uncertain);
  const value = await a.lookup(request); assert.equal(value.state, 'committed');
  state.uncertainReceipt = value.receipt; state.uncertainRaw = value.rawResult.toString('base64'); remember(state);
  append('outcomes.jsonl', { request: state.uncertain, resolved: 'committed', receipt: value.receipt, raw: state.uncertainRaw });
  report = { phase: mode, resolved: 'committed', rows_verified: await verifyData(a, state) };
} else if (mode === 'blackhole') {
  await rejected(() => a.query([statement('SELECT count(*) FROM records')]), ['UNKNOWN']);
  report = { phase: mode, cached_read_succeeded: false };
} else if (mode === 'takeover') {
  const newOwner = client({ endpoint: config.secondary + '/v1' });
  const prior = await newOwner.status();
  const taken = await newOwner.takeover({ expectedRevision: prior.revision, nonce: '9001' });
  await newOwner.activate({ expectedRevision: taken.revision, nonce: '9002' });
  const oldWrite = a.prepare([statement('INSERT INTO cancelled_effect VALUES(4)')], { epoch: '1', id: '100' });
  await rejected(() => a.execute(oldWrite), ['FENCED']);
  const state = saved();
  report = { phase: mode, old_writer_fenced: true, rows_verified: await verifyData(newOwner, state) };
} else if (mode === 'recover') {
  const prior = await a.status();
  const taken = await a.takeover({ expectedRevision: prior.revision, nonce: '9501' });
  await a.activate({ expectedRevision: taken.revision, nonce: '9502' });
  const state = saved(); let audited = 0;
  const ledger = readFileSync(evidence + '/acks.jsonl', 'utf8') + readFileSync(evidence + '/duplicate-acks.jsonl', 'utf8');
  for (const line of ledger.trim().split('\n')) {
    const ack = JSON.parse(line), target = JSON.parse(ack.request).scope;
    const targetClient = target.tenant === '8' ? client({ token: config.tokens.other, scope: target, principal: '22' }) : a;
    const value = await targetClient.lookup(targetClient.restore(ack.request));
    assert.equal(value.state, 'committed'); assert.deepEqual(value.receipt, ack.receipt);
    assert.equal(value.rawResult.toString('base64'), ack.raw); assert.equal(sha(value.rawResult), ack.raw_sha256); audited++;
  }
  const uncertain = await a.lookup(a.restore(state.uncertain));
  assert.deepEqual(uncertain.receipt, state.uncertainReceipt);
  assert.equal(uncertain.rawResult.toString('base64'), state.uncertainRaw);
  assert.equal((await a.cancel(a.restore(state.cancelled))).state, 'cancelled');
  const b = client({ token: config.tokens.other, scope: scope('202', '8'), principal: '22' });
  const bPrior = await b.status();
  const bTaken = await b.takeover({ expectedRevision: bPrior.revision, nonce: '9601' });
  await b.activate({ expectedRevision: bTaken.revision, nonce: '9602' });
  await b.open();
  const isolated = await b.query([statement('SELECT x FROM isolated')]);
  assert.deepEqual(isolated.statements[0].rows, [[77n]]);
  report = { phase: mode, acknowledgements_audited: audited, rows_verified: await verifyData(a, state),
    other_tenant_rows_verified: isolated.statements[0].rows.length, recovered_data_databases: 2,
    mismatch_count: 0, uncertain_original_result_preserved: true };
} else {
  throw new Error('Unknown acceptance phase');
}
append('client-phases.jsonl', report);
console.log(JSON.stringify(report));
