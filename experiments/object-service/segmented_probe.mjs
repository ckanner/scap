/** Actual daemon/SDK calls; fixed denominators are saved before the run. */
import assert from 'node:assert/strict';
import { randomBytes, createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { Client, decodeResult } from '../../sdk/node/src/client.js';
import { createLedger } from './client_ledger.mjs';

const [phase, privatePath, evidence] = process.argv.slice(2);
const config = JSON.parse(readFileSync(privatePath, 'utf8'));
const plan = JSON.parse(readFileSync(evidence + '/segmented-plan.json', 'utf8'));
const ledger = createLedger(evidence, phase);
const client = new Client({ endpoint: config.endpoint + '/v1', token: config.token, scope: plan.scope,
  principal: '11', timeoutMs: plan.deadlines.client_request_ms, recoveryTimeoutMs: plan.deadlines.client_request_ms,
  fetch: ledger.transport('index') });
const statePath = evidence + '/segmented-state.json';
const state = phase === 'seed' ? {} : JSON.parse(readFileSync(statePath, 'utf8'));
const sha = (raw) => createHash('sha256').update(raw).digest('hex');
const statement = (sql, parameters = []) => ({ sql, parameters });
const save = () => writeFileSync(statePath, JSON.stringify(state) + '\n', { mode: 0o600 });
let ordinal = 0;
async function invoke(label, operation, fn, expectedError) {
  assert.deepEqual(plan.calls[phase][ordinal++], [label, operation]);
  ledger.append('segmented-calls.jsonl', { event: 'call_started', label, operation });
  try {
    const value = await fn();
    ledger.append('segmented-calls.jsonl', { event: 'call_finished', label, call_id: ledger.last('index'), outcome: 'ok' });
    assert.equal(expectedError, undefined, 'planned rejection became success');
    return value;
  } catch (error) {
    ledger.append('segmented-calls.jsonl', { event: 'call_finished', label, call_id: ledger.last('index'), outcome: error.code ?? error.name });
    if (expectedError === undefined) throw error;
    assert.equal(error.code, expectedError);
    return error;
  }
}
function prepared(label, id, statements) {
  const value = client.prepare(statements, { epoch: '1', id: String(id) });
  ledger.append('segmented-inputs.jsonl', { label, request: client.save(value) });
  return value;
}
async function original(label, name) {
  const expected = state[name];
  const value = await invoke(label, 'lookup', () => client.lookup(client.restore(expected.request)));
  assert.deepEqual(value.receipt, expected.receipt);
  assert.equal(value.rawResult.toString('base64'), expected.raw);
  ledger.append('segmented-lookups.jsonl', { label, original_call_id: expected.call_id, call_id: ledger.last('index'),
    receipt: value.receipt, raw: value.rawResult.toString('base64') });
}
async function query(label, expectedError) {
  const value = await invoke(label, 'query', () => client.query([statement('SELECT id,payload,nonce FROM witness ORDER BY id')]), expectedError);
  if (expectedError === undefined) {
    const first = decodeResult(Buffer.from(state.first.raw, 'base64')).statements.at(-1);
    const last = decodeResult(Buffer.from(state.last.raw, 'base64')).statements.at(-1);
    assert.deepEqual(value.statements[0].columns, first.columns);
    assert.deepEqual(value.statements[0].rows, [...first.rows, ...last.rows]);
  }
}
async function cancelled(label) {
  const value = await invoke(label, 'lookup', () => client.lookup(client.restore(state.cancelled.request)));
  assert.deepEqual(value, state.cancelled.resolution);
}

if (phase === 'seed') {
  const created = await invoke('create', 'create', () => client.create({ nonce: '701' }));
  await invoke('activate', 'activate', () => client.activate({ expectedRevision: created.revision, nonce: '702' }));
  for (let id = 1; id <= plan.last_id; id++) {
    if (id !== 1 && id !== plan.last_id) {
      const label = 'cancel_' + id;
      const request = prepared(label, id, [statement("INSERT INTO witness VALUES(?1,x'00',-1)", [BigInt(id)])]);
      const value = await invoke(label, 'cancel', () => client.cancel(request));
      assert.equal(value.state, 'cancelled');
      if (id === 2) { state.cancelled = { request: client.save(request), resolution: value }; save(); }
      continue;
    }
    const name = id === 1 ? 'first' : 'last';
    const payload = randomBytes(plan.original_blob_bytes);
    const statements = [
      ...(id === 1 ? [statement('CREATE TABLE witness(id INTEGER PRIMARY KEY,payload BLOB,nonce INTEGER)')] : []),
      statement('INSERT INTO witness VALUES(?1,?2,random()) RETURNING id,payload,nonce', [BigInt(id === 1 ? 1 : 2), payload]),
    ];
    const request = prepared('execute_' + name, id, statements);
    const value = await invoke('execute_' + name, 'execute', () => client.execute(request));
    assert.deepEqual(value.result.statements.at(-1).rows[0].slice(0, 2), [BigInt(id === 1 ? 1 : 2), payload]);
    const ack = { name, request: client.save(request), call_id: ledger.last('index'), receipt: value.receipt,
      raw: value.rawResult.toString('base64'), raw_sha256: sha(value.rawResult) };
    ledger.append('segmented-acks.jsonl', ack); state[name] = ack; save();
  }
} else if (phase === 'warm') {
  await invoke('warm_status', 'status', () => client.status());
  await query('warm_query'); await original('warm_first', 'first'); await original('warm_last', 'last');
  await cancelled('warm_cancelled');
  const unknown = prepared('unknown', 9000, [statement('SELECT 9000')]);
  assert.equal((await invoke('unknown', 'lookup', () => client.lookup(unknown))).state, 'unknown');
  const conflict = prepared('conflict', 1, [statement('SELECT 999')]);
  await invoke('conflict', 'lookup', () => client.lookup(conflict), 'REQUEST_CONFLICT');
} else if (phase === 'cold' || phase === 'repaired') {
  await invoke(phase + '_open', 'open', () => client.open());
  await query(phase + '_query'); await original(phase + '_first', 'first'); await original(phase + '_last', 'last');
  await cancelled(phase + '_cancelled');
} else if (['corrupt', 'missing', 'summary'].includes(phase)) {
  const code = phase === 'missing' ? 'MISSING' : 'CORRUPT';
  await original(phase + '_first', 'first');
  await invoke(phase + '_open', 'open', () => client.open(), code);
  await query(phase + '_query', code);
  await invoke(phase + '_status', 'status', () => client.status());
} else { throw new Error('unplanned phase'); }
assert.equal(ordinal, plan.calls[phase].length);
assert.equal(ledger.attempts(), ordinal, 'an SDK call was repeated');
ledger.append('segmented-phases.jsonl', { calls: ordinal, sdk_http_attempts: ledger.attempts() });
console.log(JSON.stringify({ phase, calls: ordinal }));
