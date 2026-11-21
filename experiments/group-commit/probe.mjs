/** Actual SDK requests; the parent only gates original transports. */
import assert from 'node:assert/strict';
import { readFileSync, appendFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { Client } from '../../sdk/node/src/client.js';
import { createLedger } from '../object-service/client_ledger.mjs';

const config = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const inputs = new Map(), acknowledgements = new Map(), used = new Set(), pending = new Set();
const statement = (sql) => ({ sql, parameters: [] });
function emit(event, fields) {
  const row = { event, monotonic_ns: process.hrtime.bigint().toString(), ...fields };
  const raw = JSON.stringify(row) + '\n';
  appendFileSync(config.evidence + '/probe.jsonl', raw, { mode: 0o600 });
  process.stdout.write(raw);
}

async function invoke(command) {
  const spec = config.commands.find((entry) => entry.id === command);
  assert(spec && !used.has(command)); used.add(command);
  const ledger = createLedger(config.evidence, command);
  const client = new Client({ endpoint: config.endpoints[spec.worker ?? 'primary'], token: config.token,
    scope: config.scope, principal: '11', allowInsecureHttp: true,
    timeoutMs: 20000, recoveryTimeoutMs: 30000,
    fetch: (url, options) => {
      const headers = new Headers(options.headers); headers.set('X-SCAP-Fixture-Command', command);
      return ledger.transport(command)(url, { ...options, headers });
    } });
  emit('command_started', { command });
  let outcome = 'ok';
  function save(prepared) {
    inputs.set(command, client.save(prepared));
    ledger.append('original-inputs.jsonl', { command, input: inputs.get(command) });
    return prepared;
  }
  function accepted(ack) {
    acknowledgements.set(command, ack);
    ledger.append('original-results.jsonl', { command, input: inputs.get(command), receipt: ack.receipt,
      raw: ack.rawResult.toString('base64') });
  }
  try {
    if (spec.operation === 'seed') {
      const created = await client.create({ nonce: '1' });
      await client.activate({ expectedRevision: created.revision, nonce: '2' });
      accepted(await client.execute(save(client.prepare(config.seedSql.map(statement), { epoch: '1', id: '1' }))));
    } else if (spec.operation === 'execute') {
      accepted(await client.execute(save(client.prepare(spec.sql.map(statement), { epoch: '1', id: spec.request_id }))));
    } else if (spec.operation === 'duplicate') {
      const ack = await client.execute(client.restore(inputs.get(spec.original)));
      assert.deepEqual(ack.receipt, acknowledgements.get(spec.original).receipt);
      assert.deepEqual(ack.rawResult, acknowledgements.get(spec.original).rawResult);
    } else if (spec.operation === 'cancel') {
      const value = await client.cancel(client.restore(inputs.get(spec.original)));
      assert.equal(value.state, 'cancelled');
    } else if (spec.operation === 'resume') {
      const current = await client.status();
      const claimed = await client.takeover({ expectedRevision: current.revision, nonce: '2001' });
      await client.activate({ expectedRevision: claimed.revision, nonce: '2002' });
    } else if (spec.operation === 'lookup') {
      const value = await client.lookup(client.restore(inputs.get(spec.original)));
      assert.equal(value.state, spec.state);
      if (value.state === 'committed') {
        const original = acknowledgements.get(spec.original);
        if (original) {
          assert.deepEqual(value.receipt, original.receipt);
          assert.deepEqual(value.rawResult, original.rawResult);
        }
        ledger.append('original-lookups.jsonl', { command, original: spec.original,
          receipt: value.receipt, raw: value.rawResult.toString('base64') });
      }
    } else if (spec.operation === 'query') {
      const value = await client.query([
        statement('SELECT n,nonce FROM witness ORDER BY n'),
        statement('SELECT n FROM child ORDER BY n'),
        statement('SELECT n FROM parent ORDER BY n'),
        statement('SELECT n FROM grouped_ddl ORDER BY n'),
      ]);
      assert.deepEqual(value.statements[0].rows.map((row) => Number(row[0])), config.finalRows);
      assert.deepEqual(value.statements[1].rows, []);
      assert.deepEqual(value.statements[2].rows, [[99n], [199n]]);
      assert.deepEqual(value.statements[3].rows, [[12n]]);
    } else throw new Error('unplanned operation');
    assert.equal(spec.error, undefined, 'expected failure did not occur');
  } catch (error) {
    outcome = error.code ?? error.name;
    if (spec.error !== outcome) {
      emit('command_failed', { command, outcome, message: error.message });
      throw error;
    }
  } finally { ledger.close(); }
  assert.equal(ledger.attempts(), spec.http, 'SDK repeated or omitted an original POST');
  emit('command_finished', { command, outcome, attempts: ledger.attempts() });
}

for await (const line of createInterface({ input: process.stdin })) {
  const { command } = JSON.parse(line);
  const promise = invoke(command); pending.add(promise);
  promise.then(() => pending.delete(promise), () => { process.exitCode = 1; pending.delete(promise); });
}
await Promise.allSettled(pending);
assert.equal(used.size, config.commands.length);
