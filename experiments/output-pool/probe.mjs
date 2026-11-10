/** Only SDK assembly and raw HTTP observations; no database implementation. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { closeSync, fsyncSync, openSync, readFileSync, writeFileSync, writeSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const [phase, configPath, evidence] = process.argv.slice(2);
const config = JSON.parse(readFileSync(configPath, 'utf8'));
const { Client } = await import(pathToFileURL(config.source_root + '/sdk/node/src/client.js'));
const sha = (value) => createHash('sha256').update(value).digest('hex');
function emit(event, fields = {}) {
  const fd = openSync(evidence + '/sdk.jsonl', 'a', 0o600);
  try {
    writeSync(fd, JSON.stringify({ event, phase, monotonic_ns: process.hrtime.bigint().toString(), ...fields }) + '\n');
    fsyncSync(fd);
  } finally { closeSync(fd); }
}
function save(name, raw) {
  const fd = openSync(evidence + '/' + name, 'wx', 0o600);
  try { writeFileSync(fd, raw); fsyncSync(fd); } finally { closeSync(fd); }
  return { file: name, bytes: raw.length, sha256: sha(raw) };
}
let attempts = 0;
function transport(role) {
  return async (url, options) => {
    const id = phase + '-' + (++attempts);
    const raw = Buffer.from(options.body);
    const request = save(id + '.request.json', raw);
    emit('http_request', { id, role, token_sha256: sha(config.tokens[role]), request, method: options.method, url: String(url) });
    try {
      const response = await globalThis.fetch(url, options);
      const body = Buffer.from(await response.arrayBuffer());
      const record = save(id + '.response.json', body);
      emit('http_response', { id, role, status: response.status, response: record, complete: true });
      return new Response(body, { status: response.status, headers: response.headers });
    } catch (error) {
      emit('http_error', { id, name: error.name });
      throw error;
    }
  };
}
const scope = (role) => ({ deployment: '1', tenant: role === 'b' ? '8' : '7',
  database: role === 'b' ? '202' : '101', incarnation: '1', generation: '1' });
function client(role) {
  return new Client({ endpoint: config.endpoint + '/v1', token: config.tokens[role],
    scope: scope(role), principal: { a: '11', a_reader: '12', b: '22' }[role],
    timeoutMs: 60000, recoveryTimeoutMs: 60000, allowInsecureHttp: true,
    fetch: transport(role) });
}
const a = client('a'), b = client('b'), reader = client('a_reader');
const columns = Array.from({ length: 16 }, (_, i) => `zeroblob(2097152) AS b${i}`).join(', ');
const large = [{ sql: 'SELECT ' + columns, parameters: [] }];
const tracked = () => a.restore(JSON.parse(readFileSync(evidence + '/intent.json', 'utf8')).serialized);
function checkLarge(result) {
  const statement = result.statements[0];
  assert.equal(result.statements.length, 1);
  assert.deepEqual(statement.columns, Array.from({ length: 16 }, (_, i) => 'b' + i));
  assert.equal(statement.rows.length, 1);
  for (const value of statement.rows[0]) {
    assert.equal(value.length, 2097152);
    assert.equal(value.every((byte) => byte === 0), true);
  }
}
emit('sdk_started', { pid: process.pid });
if (phase === 'setup') {
  const ca = await a.create({ nonce: '501' });
  await a.activate({ expectedRevision: ca.revision, nonce: '502' });
  const schema = a.prepare([{ sql: 'CREATE TABLE proof(id INTEGER PRIMARY KEY)', parameters: [] }], { epoch: '1', id: '1' });
  await a.execute(schema);
  const sa = await a.status();
  await a.setPolicy({ expectedRevision: sa.revision, nonce: '503', permissions: [
    { principal: '11', read: true, write: true, admin: true },
    { principal: '12', read: true, write: false, admin: false },
  ] });
  const cb = await b.create({ nonce: '601' });
  await b.activate({ expectedRevision: cb.revision, nonce: '602' });
  const intent = a.prepare([{ sql: 'INSERT INTO proof VALUES(1) RETURNING ' + columns, parameters: [] }], { epoch: '1', id: '2' });
  const record = { serialized: a.save(intent), prepared_monotonic_ns: process.hrtime.bigint().toString() };
  save('intent.json', Buffer.from(JSON.stringify(record) + '\n'));
} else if (phase === 'tenant-limit' || phase === 'global-limit') {
  await assert.rejects(() => (phase === 'tenant-limit' ? reader : b).query(large), (error) => error.code === 'LIMIT');
} else if (phase === 'control') {
  const value = await a.status();
  assert.equal(value.active, true);
  emit('control_result', { value });
} else if (phase === 'insert') {
  let caught;
  try { await a.execute(tracked()); } catch (error) { caught = error; }
  assert.equal(caught?.code, 'COMMITTED_BUT_UNAVAILABLE');
  assert.equal(caught.outcome, 'committed');
  assert.ok(caught.receipt);
  save('cbu-receipt.json', Buffer.from(JSON.stringify(caught.receipt) + '\n'));
  emit('committed_unavailable', { receipt: caught.receipt, attempts });
} else if (phase === 'after-disconnect') {
  checkLarge(await a.query(large));
} else if (phase === 'lookup') {
  const value = await a.lookup(tracked());
  assert.equal(value.state, 'committed');
  assert.deepEqual(value.receipt, JSON.parse(readFileSync(evidence + '/cbu-receipt.json', 'utf8')));
  checkLarge(value.result);
  emit('resolved', { receipt: value.receipt, result_bytes: value.rawResult.length, result_sha256: sha(value.rawResult) });
} else if (phase === 'count') {
  const value = await a.query([{ sql: 'SELECT count(*) FROM proof', parameters: [] }]);
  assert.deepEqual(value.statements[0].rows, [[1n]]);
  emit('count_result', { count: '1' });
} else {
  throw new Error('unknown output pool phase');
}
emit('sdk_finished', { attempts });
console.log(JSON.stringify({ phase, attempts }));
