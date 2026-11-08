/** Actual SDK/HTTP workload. The controller holds one real signed S3 GET. */
import assert from 'node:assert/strict';
import { randomBytes, createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { Client, decodeResult } from '../../sdk/node/src/client.js';
import { createLedger } from './client_ledger.mjs';

const [phase, privatePath, evidence] = process.argv.slice(2);
const config = JSON.parse(readFileSync(privatePath, 'utf8'));
const plan = JSON.parse(readFileSync(evidence + '/isolation-plan.json', 'utf8'));
const ledger = createLedger(evidence, phase);
const clients = new Map();
for (const name of ['a', 'b', 'c']) {
  clients.set(name, new Client({ endpoint: config.endpoint + '/v1', token: config.token,
    scope: plan.scopes[name], principal: '11', timeoutMs: plan.deadlines.client_request_ms,
    recoveryTimeoutMs: plan.deadlines.client_request_ms,
    fetch: ledger.transport(name) }));
}
const sha = (raw) => createHash('sha256').update(raw).digest('hex');
const statement = (sql, parameters = []) => ({ sql, parameters });
const statePath = evidence + '/isolation-state.json';
const state = phase === 'seed' ? {} : JSON.parse(readFileSync(statePath, 'utf8'));
const save = () => writeFileSync(statePath, JSON.stringify(state) + '\n', { mode: 0o600 });
let ordinal = 0;
async function invoke(label, name, operation, fn, expectedError) {
  assert.deepEqual(plan.calls[phase][ordinal++], [label, name, operation]);
  ledger.append('isolation-calls.jsonl', { event: 'call_started', label, name, operation });
  try {
    const value = await fn(clients.get(name));
    ledger.append('isolation-calls.jsonl', { event: 'call_finished', label, call_id: ledger.last(name), outcome: 'ok' });
    assert.equal(expectedError, undefined, 'expected a rejected call');
    return value;
  } catch (error) {
    ledger.append('isolation-calls.jsonl', { event: 'call_finished', label, call_id: ledger.last(name), outcome: error.code ?? error.name });
    if (expectedError === undefined) throw error;
    assert.equal(error.code, expectedError);
    return error;
  }
}
async function query(label, name) {
  const value = await invoke(label, name, 'query', (client) => client.query([
    statement('SELECT id,payload,label,nonce FROM witness ORDER BY id')]));
  const original = decodeResult(Buffer.from(state[name].raw, 'base64')).statements[1];
  assert.deepEqual(value.statements[0].columns, original.columns);
  assert.deepEqual(value.statements[0].rows, original.rows);
}

if (phase === 'seed') {
  for (const [index, name] of ['a', 'b'].entries()) {
    const client = clients.get(name);
    const created = await invoke(name + '_create', name, 'create', (value) => value.create({ nonce: String(501 + index * 10) }));
    await invoke(name + '_activate', name, 'activate', (value) => value.activate({
      expectedRevision: created.revision, nonce: String(502 + index * 10) }));
    const payload = randomBytes(plan.blob_bytes[name]);
    const label = '\ufeff隔离\0😀-' + name;
    const prepared = client.prepare([
      statement('CREATE TABLE witness(id INTEGER PRIMARY KEY,payload BLOB,label TEXT,nonce INTEGER)'),
      statement('INSERT INTO witness VALUES(1,?1,?2,random()) RETURNING id,payload,label,nonce', [payload, label]),
    ], { epoch: '1', id: '1' });
    const request = client.save(prepared);
    ledger.append('isolation-inputs.jsonl', { name, request, payload_sha256: sha(payload), payload_bytes: payload.length, label });
    const value = await invoke(name + '_execute', name, 'execute', (target) => target.execute(prepared));
    assert.equal(value.state, 'committed');
    assert.deepEqual(value.result.statements[1].rows[0].slice(0, 3), [1n, payload, label]);
    const ack = { name, request, call_id: ledger.last(name), receipt: value.receipt,
      raw: value.rawResult.toString('base64'), raw_sha256: sha(value.rawResult) };
    ledger.append('isolation-acks.jsonl', ack);
    state[name] = ack;
    save();
  }
} else if (phase === 'keep_b_hot') {
  for (let index = 0; index < 6; index++) {
    await new Promise((resolve) => setTimeout(resolve, plan.deadlines.keep_b_period_ms));
    await query('b_keep_' + index, 'b');
  }
} else if (phase === 'cold_a') {
  await invoke('a_cold_open', 'a', 'open', (client) => client.open());
} else if (phase === 'during_cold') {
  await query('b_while_a_blocked', 'b');
  await invoke('c_at_capacity', 'c', 'query', (client) => client.query([statement('SELECT 999')]), 'BACKPRESSURE');
  const status = await invoke('a_control_while_blocked', 'a', 'status', (client) => client.status());
  assert.equal(status.sequence, state.a.receipt.sequence);
  assert.equal(status.revision, state.a.receipt.transition.revision);
  await query('b_after_backpressure', 'b');
} else if (phase === 'after_release') {
  await query('a_resident_query', 'a');
  await query('b_still_resident', 'b');
  for (const name of ['a', 'b']) {
    const value = await invoke(name + '_original_lookup', name, 'lookup', (client) => client.lookup(client.restore(state[name].request)));
    assert.deepEqual(value.receipt, state[name].receipt);
    assert.equal(value.rawResult.toString('base64'), state[name].raw);
    ledger.append('isolation-lookups.jsonl', { name, call_id: ledger.last(name), original_call_id: state[name].call_id,
      receipt: value.receipt, raw: value.rawResult.toString('base64'), raw_sha256: sha(value.rawResult) });
  }
} else {
  throw new Error('unplanned isolation phase');
}
assert.equal(ordinal, plan.calls[phase].length);
assert.equal(ledger.attempts(), ordinal, 'SDK retried an invocation');
ledger.append('isolation-phases.jsonl', { calls: ordinal, sdk_http_attempts: ledger.attempts() });
console.log(JSON.stringify({ phase, calls: ordinal }));
