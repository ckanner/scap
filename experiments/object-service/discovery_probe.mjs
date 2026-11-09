/** Fixture assembly: the actual public Node SDK performs every HTTP operation. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { Client, CatalogueClient, DiscoveryClient } from '../../sdk/node/src/client.js';
import { createLedger } from './client_ledger.mjs';

const [phase, privatePath, evidence] = process.argv.slice(2);
const config = JSON.parse(readFileSync(privatePath, 'utf8'));
const ledger = createLedger(evidence, phase), contexts = new WeakMap();
const sha = (raw) => createHash('sha256').update(raw).digest('hex');
const safe = (value) => JSON.parse(JSON.stringify(value, (_key, item) => typeof item === 'bigint' ? { $integer: item.toString() } : item));
const statePath = evidence + '/discovery-state.json';
let state = {};
try { state = JSON.parse(readFileSync(statePath, 'utf8')); } catch (error) { if (error.code !== 'ENOENT') throw error; }
const remember = () => writeFileSync(statePath, JSON.stringify(state, null, 2) + '\n', { mode: 0o600 });
let ordinal = 0;
function options(role, secondary = false) {
  const id = `${role}:${++ordinal}`, identity = config.roles[role], original = ledger.transport(id);
  const input = { endpoint: secondary ? config.secondary : config.endpoint,
    token: config.tokens[role], principal: identity.principal, timeoutMs: 10000,
    fetch: async (url, init) => {
      const authorization = new Headers(init.headers).get('authorization');
      assert.match(authorization, /^Bearer /);
      const pending = original(url, init);
      ledger.append('discovery-auth.jsonl', { call_id: ledger.last(id), role,
        credential_sha256: sha(authorization.slice(7)), endpoint: String(url) });
      return pending;
    } };
  return { id, identity, input, role };
}
function discovery(role = 'reader', secondary = false) {
  const context = options(role, secondary);
  const client = new DiscoveryClient({ ...context.input, endpoint: context.input.endpoint + '/v1/discovery',
    deployment: context.identity.deployment, tenant: context.identity.tenant });
  contexts.set(client, context); return client;
}
function catalogue(role = 'admin') {
  const context = options(role);
  const client = new CatalogueClient({ ...context.input, endpoint: context.input.endpoint + '/v1/catalogue',
    deployment: context.identity.deployment, tenant: context.identity.tenant });
  contexts.set(client, context); return client;
}
function database(creation = state.first, role = 'admin') {
  const context = options(role);
  const client = new Client({ ...context.input, endpoint: context.input.endpoint + '/v1', scope: creation.scope });
  contexts.set(client, context); return client;
}
const statement = (sql, parameters = []) => ({ sql, parameters });
const last = (client) => ledger.last(contexts.get(client).id);
async function call(client, label, operation, invoke, expectedError = null) {
  const before = ledger.attempts(), context = contexts.get(client);
  ledger.append('discovery-calls.jsonl', { event: 'call_started', label, operation, role: context.role,
    client: context.id, credential_sha256: sha(config.tokens[context.role]) });
  let value, error;
  try { value = await invoke(); } catch (caught) { error = caught; }
  ledger.append('discovery-calls.jsonl', { event: 'call_finished', label, call_id: last(client),
    attempts: ledger.attempts() - before, ...(error ? { error: { code: error.code ?? null, name: error.name } } : { value: safe(value) }) });
  assert.equal(ledger.attempts() - before, 1, `${label}: public SDK invocation must send exactly one POST`);
  if (expectedError !== null) {
    assert.ok(error, `${label}: expected ${expectedError}`);
    assert.ok([].concat(expectedError).includes(error.code), `${label}: got ${error.code}`);
    return error;
  }
  if (error) throw error;
  return value;
}
async function page(client, label, cursor = null, inventory = false, expectedError = null, overrides) {
  return call(client, label, inventory ? 'deployment_inventory' : 'list_names',
    () => inventory ? client.deploymentInventory(cursor, overrides) : client.listNames(cursor, overrides), expectedError);
}
const MAX_SCAN_PAGES = 128;
async function complete(client, label, cursor = null, inventory = false, remaining = MAX_SCAN_PAGES) {
  const collected = [];
  for (let index = 0; index < remaining; index++) {
    const value = await page(client, `${label}_${index}`, cursor, inventory);
    normal(value);
    collected.push(...(inventory ? value.records : value.names));
    if (value.cursor === null) return collected;
    assert.notEqual(value.cursor, cursor);
    cursor = value.cursor;
  }
  throw new Error('explicit fixture scan exceeded its finite page bound');
}
function normal(value) {
  // A fixed read deadline can stop an unfaulted scan. The independent oracle
  // proves progress from the following physical LIST, never from token text.
  assert.ok(value.stopped === null || value.stopped === 'LIMIT' || value.stopped === 'UNKNOWN');
  const exhausted = value.completion?.traversal_exhausted ?? value.traversal_exhausted;
  assert.equal(exhausted, value.cursor === null);
  if (exhausted) assert.equal(value.stopped, null);
  else assert.equal(typeof value.cursor, 'string');
}
async function remainder(client, label, value, inventory = false) {
  return value.cursor === null ? [] : complete(client, label, value.cursor, inventory, MAX_SCAN_PAGES - 1);
}
async function policy(creation, label, read) {
  const client = database(creation);
  const current = await call(client, label + '_status', 'status', () => client.status());
  return call(client, label, 'policy', () => client.setPolicy({ expectedRevision: current.revision,
    nonce: String(BigInt(current.revision) + 8000n), permissions: [
      { principal: '11', read: true, write: true, admin: true },
      { principal: '12', read, write: false, admin: true },
    ] }));
}
function names(values) { return values.map((item) => item.creation.name); }
async function hot(label, recover = false) {
  const client = database();
  if (recover) {
    const current = await call(client, label + '_status', 'status', () => client.status());
    const taken = await call(client, label + '_takeover', 'takeover', () => client.takeover({ expectedRevision: current.revision, nonce: '99001' }));
    await call(client, label + '_activate', 'activate', () => client.activate({ expectedRevision: taken.revision, nonce: '99002' }));
  }
  const result = await call(client, label + '_query', 'query', () => client.query([statement('SELECT id, label FROM witness ORDER BY id')]));
  assert.deepEqual(result.statements[0].rows, [[1n, 'discovery-native-witness']]);
  const request = client.restore(state.sql.request);
  for (const method of ['lookup', 'cancel']) {
    const value = await call(client, label + '_' + method, method, () => client[method](request));
    assert.equal(value.state, 'committed');
    assert.deepEqual(value.receipt, state.sql.receipt);
    assert.equal(value.rawResult.toString('base64'), state.sql.raw);
    ledger.append('discovery-sql-results.jsonl', { kind: method, label: label + '_' + method,
      call_id: last(client), request: state.sql.request, receipt: value.receipt,
      raw: value.rawResult.toString('base64'), raw_sha256: sha(value.rawResult) });
  }
}

if (phase === 'setup') {
  state.creations = [];
  const admin = catalogue();
  for (let index = 0; index < 129; index++) {
    const prepared = await call(admin, `prepare_${index}`, 'prepare_create', () => admin.prepareCreate({
      name: `discovery-${String(index).padStart(3, '0')}`, create_operation: String(10000 + index),
      expected_name_revision: null, options: { quota: { mode: 'default' } } }));
    const ready = await call(admin, `ready_${index}`, 'resume_create', () => admin.resumeCreate(prepared.creation));
    assert.equal(ready.phase, 'ready');
    state.creations.push(prepared.creation);
  }
  state.creations.sort((a, b) => Buffer.compare(Buffer.from(sha(a.name)), Buffer.from(sha(b.name))));
  state.first = state.creations[0]; state.last = state.creations.at(-1); state.second = state.creations[1];
  for (const role of ['other', 'foreign']) {
    const target = catalogue(role);
    const prepared = await call(target, `prepare_${role}`, 'prepare_create', () => target.prepareCreate({
      name: 'discovery-' + role, create_operation: '20001', expected_name_revision: null,
      options: { quota: { mode: 'default' } } }));
    const ready = await call(target, `ready_${role}`, 'resume_create', () => target.resumeCreate(prepared.creation));
    assert.equal(ready.phase, 'ready'); state[role] = prepared.creation;
  }
  const dormant = await call(admin, 'prepare_dormant', 'prepare_create', () => admin.prepareCreate({
    name: 'discovery-descriptor-only', create_operation: '30001', expected_name_revision: null,
    options: { quota: { mode: 'default' } } }));
  state.dormant = dormant.creation;
  const aborted = await call(admin, 'control_dormant', 'abort_create', () => admin.abortCreate({ creation: dormant.creation,
    control_operation: '30002', expected_name_revision: '1', nonce: '30003' }));
  assert.equal(aborted.phase, 'not_reserved');
  await policy(state.first, 'grant_first', true);
  await policy(state.last, 'grant_last', true);
  const client = database();
  const current = await call(client, 'seed_status', 'status', () => client.status());
  await call(client, 'seed_activate', 'activate', () => client.activate({ expectedRevision: current.revision, nonce: '50001' }));
  const request = client.prepare([statement('CREATE TABLE witness(id INTEGER PRIMARY KEY, label TEXT)'),
    statement("INSERT INTO witness VALUES(1,'discovery-native-witness') RETURNING id,label,random()")], { epoch: '1', id: '1' });
  const serialized = client.save(request);
  ledger.append('discovery-sql-inputs.jsonl', { request: serialized });
  const committed = await call(client, 'seed_execute', 'execute', () => client.execute(request));
  assert.equal(committed.state, 'committed');
  state.sql = { request: serialized, receipt: committed.receipt, raw: committed.rawResult.toString('base64'), raw_sha256: sha(committed.rawResult) };
  ledger.append('discovery-sql-results.jsonl', { kind: 'execute', label: 'seed_execute', call_id: last(client), ...state.sql });
  remember();
} else if (phase === 'reader_first') {
  const value = await page(discovery(), 'reader_first');
  normal(value); assert.equal(typeof value.cursor, 'string');
  assert.deepEqual(names(value.names), [state.first.name]);
  state.readerCursor = value.cursor; remember();
} else if (phase === 'revoke_continue') {
  state.revocation = await policy(state.last, 'revoke_last', false);
  const reader = catalogue('reader');
  await call(reader, 'revoked_resolve', 'resolve_name', () => reader.resolveName(state.last.name), 'DENIED');
  const seen = await complete(discovery(), 'reader_resume', state.readerCursor, false, MAX_SCAN_PAGES - 1);
  assert.ok(!names(seen).includes(state.last.name)); assert.deepEqual(names(seen), []);
  remember();
} else if (phase === 'capabilities') {
  await page(discovery('admin'), 'provision_is_not_inventory', null, true, 'DENIED');
  const sql = database(state.first, 'operator');
  await call(sql, 'inventory_is_not_sql', 'query', () => sql.query([statement('SELECT 1')]), 'DENIED');
  const cross = database(state.other, 'operator');
  await call(cross, 'operator_cannot_cross_tenant_sql', 'query', () => cross.query([statement('SELECT 1')]), 'DENIED');
  const operator = discovery('operator');
  const first = await page(operator, 'operator_names_first');
  normal(first); assert.deepEqual(first.names, []); assert.equal(typeof first.cursor, 'string');
  state.operatorNamesCursor = first.cursor;
  assert.deepEqual(await remainder(operator, 'operator_names_resume', first), []);
  const inventory = await page(operator, 'operator_inventory_first', null, true);
  normal(inventory); assert.equal(typeof inventory.cursor, 'string');
  state.inventoryCursor = inventory.cursor;
  const records = [...inventory.records, ...await remainder(operator, 'operator_inventory_resume', inventory, true)];
  assert.ok(records.some((row) => row.scope?.tenant === '8'));
  assert.ok(records.some((row) => row.kind === 'control' && row.control !== null));
  assert.ok(records.every((row) => row.scope === null || row.scope.deployment === '1'));
  state.inventoryKeys = records.map((row) => row.key); remember();
} else if (phase === 'cursor_bindings') {
  const original = state.readerCursor;
  const index = Math.floor(original.length / 2);
  const changed = original.slice(0, index) + (original[index] === 'A' ? 'B' : 'A') + original.slice(index + 1);
  await page(discovery(), 'tampered_cursor', changed, false, 'CURSOR_INVALID');
  await page(discovery('admin'), 'principal_cursor', original, false, 'CURSOR_INVALID');
  await page(discovery('other'), 'tenant_cursor', original, false, 'CURSOR_INVALID');
  await page(discovery('foreign'), 'deployment_cursor', original, false, 'CURSOR_INVALID');
  await page(discovery('operator'), 'names_as_inventory', state.operatorNamesCursor, true, 'CURSOR_INVALID');
  await page(discovery('operator'), 'inventory_as_names', state.inventoryCursor, false, 'CURSOR_INVALID');
  await page(discovery('reader', true), 'other_daemon_cursor', original, false, 'CURSOR_INVALID');
  const client = discovery();
  const positive = await page(client, 'original_cursor_positive', original);
  normal(positive);
  assert.deepEqual(names([...positive.names, ...await remainder(client, 'original_cursor_resume', positive)]), []);
} else if (phase.startsWith('fault_')) {
  const result = await page(discovery(), phase);
  assert.equal(result.stopped, config.expectedStop); assert.equal(result.traversal_exhausted, false);
  assert.equal(typeof result.cursor, 'string');
  state.faultCursor = result.cursor; state.faultNames = names(result.names); remember();
} else if (phase.startsWith('after_fault_')) {
  const rows = await complete(discovery(), phase, state.faultCursor, false, MAX_SCAN_PAGES - 1);
  const observed = [...state.faultNames, ...names(rows)];
  assert.deepEqual(observed, [state.first.name]);
} else if (phase === 'slow_progress') {
  const client = discovery(), collected = [];
  let cursor = null, incomplete = 0, finished = false;
  for (let index = 0; index < 16; index++) {
    const value = await page(client, `slow_progress_${index}`, cursor);
    collected.push(...value.names);
    if (value.cursor === null) {
      assert.equal(value.traversal_exhausted, true);
      assert.equal(value.stopped, null);
      finished = true; break;
    }
    assert.equal(value.stopped, 'UNKNOWN');
    assert.equal(value.traversal_exhausted, false);
    assert.equal(typeof value.cursor, 'string');
    assert.notEqual(value.cursor, cursor);
    cursor = value.cursor; incomplete++;
  }
  assert.ok(finished && incomplete >= 2, 'steady-latency pages must retain progress and complete');
  assert.deepEqual(names(collected), [state.first.name]);
} else if (phase === 'prime_hot') {
  const client = database();
  const value = await call(client, 'prime_hot_query', 'query', () => client.query([statement('SELECT id, label FROM witness ORDER BY id')]));
  assert.deepEqual(value.statements[0].rows, [[1n, 'discovery-native-witness']]);
} else if (phase === 'hold_timeout') {
  await page(discovery(), 'held_client_timeout', null, false, 'DEADLINE', { timeoutMs: 180 });
} else if (phase === 'hold_abort') {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 180);
  try { await page(discovery('other'), 'held_client_abort', null, false, 'ABORTED', { signal: controller.signal }); }
  finally { clearTimeout(timeout); }
} else if (phase === 'one_held_probe') {
  await page(discovery(), 'tenant_one_still_busy', null, false, 'BACKPRESSURE');
  const empty = await page(discovery('third'), 'spare_global_slot_empty_success');
  assert.deepEqual(empty, { names: [], cursor: null, traversal_exhausted: true, stopped: null });
} else if (phase === 'held_probes') {
  await page(discovery(), 'same_tenant_still_busy', null, false, 'BACKPRESSURE');
  await page(discovery('other'), 'aborted_tenant_still_busy', null, false, 'BACKPRESSURE');
  await page(discovery('third'), 'global_two_still_busy', null, false, 'BACKPRESSURE');
  await hot('while_held');
} else if (phase === 'release_recovered') {
  const client = discovery();
  let succeeded = false;
  for (let index = 0; index < 150; index++) {
    try {
      const value = await page(client, `after_release_${index}`);
      normal(value);
      assert.deepEqual(names([...value.names, ...await remainder(client, 'after_release_resume', value)]), [state.first.name]);
      succeeded = true; break;
    } catch (error) {
      if (error.code !== 'BACKPRESSURE') throw error;
      await new Promise((resolve) => setTimeout(resolve, 40));
    }
  }
  assert.equal(succeeded, true);
} else if (phase === 'cursor_before_loss') {
  const client = discovery();
  const fresh = await page(client, 'fresh_cursor_before_loss');
  normal(fresh); assert.equal(typeof fresh.cursor, 'string');
  assert.deepEqual(names([...fresh.names, ...await remainder(client, 'fresh_cursor_resume', fresh)]), [state.first.name]);
  state.restartCursor = fresh.cursor; remember();
} else if (phase === 'restart') {
  await page(discovery(), 'restart_cursor', state.restartCursor, false, 'CURSOR_INVALID');
  assert.deepEqual(names(await complete(discovery(), 'restart_names')), [state.first.name]);
  const records = await complete(discovery('operator'), 'restart_inventory', null, true);
  assert.deepEqual(records.map((row) => row.key).sort(), state.inventoryKeys.slice().sort());
  await hot('after_restart', true);
} else {
  throw new Error('unknown discovery phase: ' + phase);
}
ledger.append('discovery-phases.jsonl', { event: 'phase_finished', attempts: ledger.attempts() });
