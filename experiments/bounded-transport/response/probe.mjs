/** Assemble the real SDK and preserve raw HTTP; no database implementation. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { closeSync, fsyncSync, openSync, readFileSync, writeFileSync, writeSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const [phase, configPath, evidence] = process.argv.slice(2);
const config = JSON.parse(readFileSync(configPath, 'utf8'));
const { Client } = await import(pathToFileURL(config.source_root + '/sdk/node/src/client.js'));
const sha = (raw) => createHash('sha256').update(raw).digest('hex');
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
const client = new Client({ endpoint: config.endpoint + '/v1', token: config.token,
  scope: { deployment: '1', tenant: '7', database: '101', incarnation: '1', generation: '1' },
  principal: '11', allowInsecureHttp: true, timeoutMs: 60000, recoveryTimeoutMs: 60000,
  fetch: async (url, options) => {
    const id = phase + '-' + (++attempts);
    emit('http_request', { id, token_sha256: sha(config.token), method: options.method,
      url: String(url), request: save(id + '.request.json', Buffer.from(options.body)) });
    try {
      const response = await globalThis.fetch(url, options);
      const raw = Buffer.from(await response.arrayBuffer());
      emit('http_response', { id, status: response.status, complete: true,
        response: save(id + '.response.json', raw) });
      return new Response(raw, { status: response.status, headers: response.headers });
    } catch (error) {
      emit('http_error', { id, name: error.name });
      throw error;
    }
  },
});
const columns = Array.from({ length: 8 }, (_, i) => `zeroblob(2097152) AS b${i}`).join(', ');
emit('sdk_started', { pid: process.pid });
if (phase === 'setup') {
  const created = await client.create({ nonce: '501' });
  await client.activate({ expectedRevision: created.revision, nonce: '502' });
  await client.execute(client.prepare([{ sql: 'CREATE TABLE proof(id INTEGER PRIMARY KEY)', parameters: [] }],
    { epoch: '1', id: '1' }));
  const intent = client.prepare([{ sql: 'INSERT INTO proof VALUES(1) RETURNING ' + columns, parameters: [] }],
    { epoch: '1', id: '2' });
  save('intent.json', Buffer.from(JSON.stringify({ serialized: client.save(intent),
    prepared_monotonic_ns: process.hrtime.bigint().toString() }) + '\n'));
} else if (phase === 'after-stalled' || phase === 'after-drip') {
  const value = await client.query([{ sql: 'SELECT 17', parameters: [] }]);
  assert.deepEqual(value.statements[0].rows, [[17n]]);
} else if (phase === 'lookup') {
  const intent = client.restore(JSON.parse(readFileSync(evidence + '/intent.json', 'utf8')).serialized);
  const value = await client.lookup(intent);
  assert.equal(value.state, 'committed');
  assert.deepEqual(value.receipt.request, intent.request);
  const result = value.result;
  assert.equal(result.statements.length, 1);
  assert.deepEqual(result.statements[0].columns, Array.from({ length: 8 }, (_, i) => 'b' + i));
  assert.equal(result.statements[0].rows.length, 1);
  for (const blob of result.statements[0].rows[0]) {
    assert.equal(blob.length, 2097152);
    assert.equal(blob.every((byte) => byte === 0), true);
  }
  emit('resolved', { receipt: value.receipt, result_bytes: value.rawResult.length,
    result_sha256: sha(value.rawResult) });
  const count = await client.query([{ sql: 'SELECT count(*) FROM proof', parameters: [] }]);
  assert.deepEqual(count.statements[0].rows, [[1n]]);
} else {
  throw new Error('unknown response phase');
}
emit('sdk_finished', { attempts });
console.log(JSON.stringify({ phase, attempts }));
