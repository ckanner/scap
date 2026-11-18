/** Actual unmodified SDK calls; the parent controls only transport gates. */
import assert from 'node:assert/strict';
import { readFileSync, appendFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { Client } from '../../sdk/node/src/client.js';
import { createLedger } from '../object-service/client_ledger.mjs';

const config = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const inputs = new Map(), acknowledgements = new Map(), used = new Set(), pending = new Set();
const statement = (sql) => ({ sql, parameters: [] });
const emit = (event, fields) => {
  const row = { event, monotonic_ns: process.hrtime.bigint().toString(), ...fields };
  const raw = JSON.stringify(row) + '\n';
  appendFileSync(config.evidence + '/probe.jsonl', raw, { mode: 0o600 });
  process.stdout.write(raw);
};
const permissions = (read) => [
  { principal: '11', read: true, write: true, admin: true },
  { principal: '12', read, write: false, admin: false },
];

async function invoke(command) {
  const spec = config.commands.find((entry) => entry.id === command);
  assert(spec && !used.has(command));
  used.add(command);
  const ledger = createLedger(config.evidence, command);
  const caller = spec.caller ?? (spec.scope === 'b' ? 'other' : 'admin');
  const client = new Client({ endpoint: config.endpoint, token: config.tokens[caller],
    scope: config.scopes[spec.scope], principal: { admin: '11', reader: '12', other: '22' }[caller],
    allowInsecureHttp: true, timeoutMs: 20000, recoveryTimeoutMs: 30000,
    fetch: async (url, options) => {
      const headers = new Headers(options.headers);
      headers.set('X-SCAP-Fixture-Command', command);
      return ledger.transport(command)(url, { ...options, headers });
    } });
  emit('command_started', { command });
  let outcome = 'ok';
  try {
    if (spec.operation === 'seed') {
      const created = await client.create({ nonce: '1' });
      await client.activate({ expectedRevision: created.revision, nonce: '2' });
      const prepared = client.prepare([
        statement('CREATE TABLE witness(n INTEGER PRIMARY KEY,nonce INTEGER)'),
        statement('INSERT INTO witness VALUES(1,random()) RETURNING n,nonce'),
      ], { epoch: '1', id: '1' });
      inputs.set(command, client.save(prepared));
      const ack = await client.execute(prepared);
      acknowledgements.set(command, ack);
      ledger.append('original-results.jsonl', { command, input: inputs.get(command), receipt: ack.receipt,
        raw: ack.rawResult.toString('base64') });
      if (spec.scope === 'a') await client.setPolicy({ expectedRevision: ack.receipt.transition.revision,
        nonce: '4', permissions: permissions(true) });
    } else if (spec.operation === 'write') {
      const prepared = client.prepare([statement(`INSERT INTO witness VALUES(${spec.n},random()) RETURNING n,nonce`)],
        { epoch: '1', id: String(spec.n) });
      inputs.set(command, client.save(prepared));
      const ack = await client.execute(prepared);
      acknowledgements.set(command, ack);
      ledger.append('original-results.jsonl', { command, input: inputs.get(command), receipt: ack.receipt,
        raw: ack.rawResult.toString('base64') });
    } else if (spec.operation === 'query') {
      const value = await client.query([statement('SELECT n FROM witness ORDER BY n')]);
      assert.deepEqual(value.statements[0].rows.map((row) => row[0].toString()), spec.rows);
    } else if (spec.operation === 'query_write') {
      await client.query([statement('INSERT INTO witness VALUES(99,random())')]);
    } else if (spec.operation === 'status') {
      const value = await client.status();
      assert.equal(value.active, true);
    } else if (spec.operation === 'revoke') {
      const status = await client.status();
      await client.setPolicy({ expectedRevision: status.revision, nonce: '9', permissions: permissions(false) });
    } else if (spec.operation === 'lookup') {
      const original = acknowledgements.get(spec.original);
      const value = await client.lookup(client.restore(inputs.get(spec.original)));
      assert.deepEqual(value.receipt, original.receipt);
      assert.equal(value.rawResult.toString('base64'), original.rawResult.toString('base64'));
      ledger.append('original-lookups.jsonl', { command, original: spec.original,
        receipt: value.receipt, raw: value.rawResult.toString('base64') });
    } else throw new Error('unplanned operation');
    assert.equal(spec.error, undefined, 'expected rejection did not occur');
  } catch (error) {
    outcome = error.code ?? error.name;
    if (spec.error !== outcome) {
      emit('command_failed', { command, outcome, message: error.message });
      throw error;
    }
  } finally {
    ledger.close();
  }
  assert.equal(ledger.attempts(), spec.http, 'SDK performed an unexpected extra POST');
  emit('command_finished', { command, outcome, attempts: ledger.attempts() });
}

for await (const line of createInterface({ input: process.stdin })) {
  const { command } = JSON.parse(line);
  const promise = invoke(command);
  pending.add(promise);
  promise.then(() => pending.delete(promise), () => { process.exitCode = 1; pending.delete(promise); });
}
await Promise.allSettled(pending);
assert.equal(used.size, config.commands.length);
