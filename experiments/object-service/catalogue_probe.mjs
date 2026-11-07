/** Real CatalogueClient / Client calls only; the controller injects S3 faults. */
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { Client, CatalogueClient } from '../../sdk/node/src/client.js';
import { createLedger } from './client_ledger.mjs';

const [phase, privatePath, evidence] = process.argv.slice(2);
const config = JSON.parse(readFileSync(privatePath, 'utf8'));
const ledger = createLedger(evidence, phase), contexts = new WeakMap();
let clientOrdinal = 0, inputOrdinal = 0;
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
const statePath = evidence + '/catalogue-state.json';
const state = (() => { try { return JSON.parse(readFileSync(statePath, 'utf8')); } catch (error) { if (error.code === 'ENOENT') return {}; throw error; } })();
const remember = () => writeFileSync(statePath, JSON.stringify(state, null, 2) + '\n', { mode: 0o600 });
const options = (role = 'admin', secondary = false) => {
  const id = String(++clientOrdinal);
  return [id, { endpoint: (secondary ? config.secondary : config.endpoint), token: config.tokens[role],
    principal: role === 'reader' ? '12' : role === 'rival' ? '13' : '11', timeoutMs: 10000,
    fetch: ledger.transport(id) }];
};
function catalogue(role, secondary) {
  const [id, input] = options(role, secondary);
  const client = new CatalogueClient({ ...input, endpoint: input.endpoint + '/v1/catalogue', deployment: '1', tenant: '7' });
  contexts.set(client, id); return client;
}
function database(creation, role = 'admin') {
  const [id, input] = options(role);
  const client = new Client({ ...input, endpoint: input.endpoint + '/v1', scope: creation.scope });
  contexts.set(client, id); return client;
}
const last = (client) => ledger.last(contexts.get(client));
const a = catalogue(), adminOnly = catalogue('reader'), rival = catalogue('rival');
function fixed(client, action, label) {
  const intent = client.prepareIntent(action);
  const serialized = client.saveIntent(intent);
  ledger.append('catalogue-inputs.jsonl', { input_id: `${phase}:${++inputOrdinal}`, label, intent: serialized });
  return intent;
}
async function send(client, intent, label, expectedError) {
  const original = client.saveIntent(intent);
  try {
    const value = await client.submit(intent);
    ledger.append('catalogue-outcomes.jsonl', { label, call_id: last(client), intent: original, value });
    assert.equal(expectedError, undefined, `expected ${expectedError}`);
    return value;
  } catch (error) {
    ledger.append('catalogue-outcomes.jsonl', { label, call_id: last(client), intent: original,
      error: { code: error.code, reference: error.reference ?? null } });
    if (error.code === 'UNKNOWN') {
      assert.deepEqual(error.reference.intent, intent, 'UNKNOWN discarded the original complete intent');
    }
    if (expectedError === undefined) throw error;
    assert.equal(error.code, expectedError);
    return error;
  }
}
async function action(client, body, label, expectedError) {
  return send(client, fixed(client, body, label), label, expectedError);
}
const prepare = (name, operation, expected_name_revision = null) => ({ operation: 'prepare_create', name,
  create_operation: operation, expected_name_revision, options: { quota: { mode: 'default' } } });
const resume = (creation) => ({ operation: 'resume_create', creation });
const inspect = (operation) => ({ operation: 'inspect_create_operation', create_operation: operation });
const resolve = (name) => ({ operation: 'resolve_name', name });
const abort = (creation, operation, revision, nonce) => ({ operation: 'abort_create', creation,
  control_operation: operation, expected_name_revision: revision, nonce });
const statement = (sql, parameters = []) => ({ sql, parameters });

async function seed(creation, label) {
  const client = database(creation), status = await client.status();
  await client.activate({ expectedRevision: status.revision, nonce: '7001' });
  const tracked = client.prepare([statement('CREATE TABLE witness(id INTEGER PRIMARY KEY, payload BLOB, label TEXT)'),
    statement('INSERT INTO witness VALUES(1,?1,?2) RETURNING id,payload,label,random()', [Buffer.from('payload-' + label), label])], { epoch: '1', id: '1' });
  const request = client.save(tracked);
  ledger.append('catalogue-sql-inputs.jsonl', { label, request });
  const first = await client.execute(tracked);
  assert.equal(first.state, 'committed');
  const saved = { label, request, receipt: first.receipt, raw: first.rawResult.toString('base64'), raw_sha256: sha(first.rawResult) };
  ledger.append('catalogue-sql-acks.jsonl', { kind: 'original', call_id: last(client), ...saved });
  const duplicate = await client.execute(client.restore(request));
  assert.deepEqual(duplicate.receipt, first.receipt); assert.deepEqual(duplicate.rawResult, first.rawResult);
  ledger.append('catalogue-sql-acks.jsonl', { kind: 'duplicate', call_id: last(client), ...saved });
  state.sql ??= []; state.sql.push(saved); remember();
  return client;
}

if (phase === 'initial') {
  await action(adminOnly, prepare('denied', '9001'), 'provision_denied', 'DENIED');
  const prepared = await action(a, prepare('目录 Main', '1001'), 'main_prepare');
  state.main = prepared.creation; remember();
  assert.equal((await action(a, inspect('1001'), 'main_descriptor_only')).phase, 'not_reserved');
  await action(a, prepare('different-name', '1001'), 'same_id_changed_name', 'CONFLICT');
  await action(a, { ...prepare('目录 Main', '1001'), options: { quota: { mode: 'unlimited' } } }, 'same_id_changed_quota', 'CONFLICT');
  const early = await action(a, abort(state.main, '1002', '1', '1003'), 'descriptor_only_abort');
  assert.equal(early.phase, 'not_reserved');
  const ready = await action(a, resume(state.main), 'main_ready'); assert.equal(ready.phase, 'ready');
  state.mainBinding = ready.binding_revision;
  const bound = await action(a, abort(state.main, '1004', ready.binding_revision, '1005'), 'bound_cannot_abort');
  assert.equal(bound.phase, 'cannot_abort_bound');
  await action(rival, prepare('目录 Main', '1101'), 'rival_prepare');
  const rivalProgress = await action(rival, inspect('1101'), 'rival_inspect');
  const competing = await action(rival, resume(rivalProgress.creation), 'rival_resume');
  assert.equal(competing.phase, 'name_conflict');
  await action(a, resolve('目录 main'), 'case_sensitive_name', 'NOT_FOUND');
  const sql = await seed(state.main, 'deleted-main');
  const status = await sql.status();
  const changed = await sql.setPolicy({ expectedRevision: status.revision, nonce: '7010', permissions: [
    { principal: '11', read: true, write: true, admin: true }, { principal: '12', read: false, write: false, admin: true }] });
  state.mainHead = changed.revision; remember();
  await action(adminOnly, resolve(state.main.name), 'admin_is_not_read', 'DENIED');
} else if (phase === 'saturation_held') {
  const value = await action(a, resolve(state.main.name), 'held_directory_read');
  assert.deepEqual(value.creation, state.main);
} else if (phase === 'saturation_probe') {
  await action(a, resolve(state.main.name), 'directory_backpressure', 'BACKPRESSURE');
  const client = database(state.main), original = state.sql.find((row) => row.label === 'deleted-main');
  const lookup = await client.lookup(client.restore(original.request));
  assert.deepEqual(lookup.receipt, original.receipt); assert.equal(lookup.rawResult.toString('base64'), original.raw);
  ledger.append('catalogue-capacity.jsonl', { operation: 'lookup', call_id: last(client), original: original.request });
  const cancelled = client.prepare([statement('INSERT INTO witness VALUES(99,x\'00\',\'cancelled\')')], { epoch: '1', id: '99' });
  const observed = await client.cancel(cancelled); assert.equal(observed.state, 'cancelled');
  ledger.append('catalogue-capacity.jsonl', { operation: 'cancel', call_id: last(client), original: client.save(cancelled), transition: observed.transition });
  const status = await client.status(); state.mainHead = status.revision; remember();
} else if (phase === 'abort_prepare') {
  state.aborting = (await action(a, prepare('cancelled-name', '2001'), 'abort_prepare')).creation; remember();
} else if (phase === 'abort_resume_held') {
  await action(a, resume(state.aborting), 'late_provision_candidate', 'CONFLICT');
} else if (phase === 'abort_win') {
  const second = catalogue('admin', true);
  const before = await action(second, inspect('2001'), 'held_reserved_inspect');
  assert.equal(before.phase, 'reserved');
  const intent = fixed(second, abort(state.aborting, '2002', before.binding_revision, '2003'), 'abort_winner');
  state.abortIntent = second.saveIntent(intent); remember();
  const value = await send(second, intent, 'abort_winner'); assert.equal(value.phase, 'aborted');
  state.abortResult = value; remember();
} else if (phase === 'abort_finish') {
  const inspected = await action(a, inspect('2001'), 'aborted_inspect'); assert.equal(inspected.phase, 'aborted');
  const late = await action(a, resume(state.aborting), 'late_resume_after_abort'); assert.equal(late.phase, 'aborted');
  const intent = a.restoreIntent(state.abortIntent);
  ledger.append('catalogue-inputs.jsonl', { input_id: `${phase}:${++inputOrdinal}`, label: 'abort_original_reentry', intent: state.abortIntent });
  assert.deepEqual(await send(a, intent, 'abort_original_reentry'), state.abortResult);
} else if (phase === 'descriptor_unknown') {
  const intent = fixed(a, prepare('surviving-name', '3001'), 'descriptor_unknown');
  state.prepareIntent = a.saveIntent(intent); remember();
  await send(a, intent, 'descriptor_unknown', 'UNKNOWN');
  assert.equal(ledger.attempts(), 1);
} else if (phase === 'descriptor_recover') {
  const inspected = await action(a, inspect('3001'), 'descriptor_resolved'); assert.equal(inspected.phase, 'not_reserved');
  const intent = a.restoreIntent(state.prepareIntent);
  ledger.append('catalogue-inputs.jsonl', { input_id: `${phase}:${++inputOrdinal}`, label: 'descriptor_original_reentry', intent: state.prepareIntent });
  const prepared = await send(a, intent, 'descriptor_original_reentry');
  assert.deepEqual(prepared.creation, inspected.creation); state.surviving = prepared.creation; remember();
} else if (phase === 'ready_unknown') {
  const intent = fixed(a, resume(state.surviving), 'ready_unknown');
  state.resumeIntent = a.saveIntent(intent); remember();
  await send(a, intent, 'ready_unknown', 'UNKNOWN'); assert.equal(ledger.attempts(), 1);
} else if (phase === 'ready_recover') {
  const inspected = await action(a, inspect('3001'), 'ready_resolved'); assert.equal(inspected.phase, 'ready');
  const intent = a.restoreIntent(state.resumeIntent);
  ledger.append('catalogue-inputs.jsonl', { input_id: `${phase}:${++inputOrdinal}`, label: 'ready_original_reentry', intent: state.resumeIntent });
  const ready = await send(a, intent, 'ready_original_reentry');
  assert.deepEqual(ready, inspected);
  await seed(state.surviving, 'surviving'); remember();
} else if (phase === 'delete_unknown') {
  const intent = fixed(adminOnly, { operation: 'delete_name', creation: state.main, control_operation: '4001',
    expected_name_revision: state.mainBinding, expected_head_revision: state.mainHead, nonce: '4002' }, 'delete_unknown');
  state.deleteIntent = adminOnly.saveIntent(intent); remember();
  await send(adminOnly, intent, 'delete_unknown', 'UNKNOWN'); assert.equal(ledger.attempts(), 1);
} else if (phase === 'delete_recover') {
  const intent = adminOnly.restoreIntent(state.deleteIntent);
  const changed = JSON.parse(state.deleteIntent).action; changed.nonce = '4999';
  await action(adminOnly, changed, 'same_delete_id_changed_nonce', 'CONFLICT');
  ledger.append('catalogue-inputs.jsonl', { input_id: `${phase}:${++inputOrdinal}`, label: 'delete_original_reentry', intent: state.deleteIntent });
  const deleted = await send(adminOnly, intent, 'delete_original_reentry'); assert.equal(deleted.phase, 'deleted');
  state.deletion = deleted; remember();
  await action(a, resolve(state.main.name), 'deleted_name_unresolvable', 'NOT_FOUND');
} else if (phase === 'reuse') {
  const replacement = await action(a, prepare(state.main.name, '5001', state.deletion.binding_revision), 'replacement_prepare');
  assert.notDeepEqual(replacement.creation.scope, state.main.scope); state.replacement = replacement.creation; remember();
  const ready = await action(a, resume(state.replacement), 'replacement_ready'); assert.equal(ready.phase, 'ready');
  const old = await action(a, inspect('1001'), 'old_creation_after_reuse');
  assert.equal(old.phase, 'deleted'); assert.equal(old.binding_revision, null);
  await seed(state.replacement, 'replacement'); remember();
} else if (phase === 'recover') {
  for (const creation of [state.surviving, state.replacement]) {
    const resolved = await action(a, resolve(creation.name), 'cold_resolve_' + creation.operation);
    assert.deepEqual(resolved.creation, creation);
    const client = database(creation), prior = await client.status();
    const taken = await client.takeover({ expectedRevision: prior.revision, nonce: '8001' });
    await client.activate({ expectedRevision: taken.revision, nonce: '8002' });
    const result = await client.query([statement('SELECT id,payload,label FROM witness ORDER BY id')]);
    const label = creation.operation === '3001' ? 'surviving' : 'replacement';
    assert.deepEqual(result.statements[0].rows, [[1n, Buffer.from('payload-' + label), label]]);
  }
  const acks = readFileSync(evidence + '/catalogue-sql-acks.jsonl', 'utf8').trim().split('\n').map(JSON.parse);
  for (const ack of acks) {
    const saved = JSON.parse(ack.request), client = database({ scope: saved.scope });
    if (ack.label === 'deleted-main') {
      await assert.rejects(() => client.lookup(client.restore(ack.request)), (error) => error.code === 'LIFECYCLE');
      ledger.append('catalogue-sql-recoveries.jsonl', { classification: 'deleted', call_id: last(client), original_call_id: ack.call_id, request: ack.request });
    } else {
      const value = await client.lookup(client.restore(ack.request));
      assert.deepEqual(value.receipt, ack.receipt); assert.equal(value.rawResult.toString('base64'), ack.raw);
      ledger.append('catalogue-sql-recoveries.jsonl', { classification: 'committed', call_id: last(client), original_call_id: ack.call_id,
        request: ack.request, receipt: value.receipt, raw: value.rawResult.toString('base64'), raw_sha256: sha(value.rawResult) });
    }
  }
  const cancelled = await action(a, inspect('2001'), 'cold_aborted_inspect'); assert.equal(cancelled.phase, 'aborted');
  const old = await action(a, inspect('1001'), 'cold_deleted_inspect'); assert.equal(old.phase, 'deleted'); assert.equal(old.binding_revision, null);
} else { throw new Error('Unknown catalogue acceptance phase'); }

ledger.append('catalogue-phases.jsonl', { phase, status: 'completed', http_attempts: ledger.attempts() });
console.log(JSON.stringify({ phase, status: 'completed', http_attempts: ledger.attempts() }));
