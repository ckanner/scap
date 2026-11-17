import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CatalogueClient, ClientError, UnknownError } from '../src/client.js';

const SCOPE = { deployment: '1', tenant: '2', database: '3', incarnation: '4', generation: '5' };
const INPUT = { name: 'restored É', restore_operation: '9007199254740999', expected_name_revision: null,
  options: { quota: { mode: 'default' } }, source_scope: SCOPE,
  snapshot: { creator: '7', operation: '8', capture_serial: '10', descriptor_hash: 'a'.repeat(64) } };
const CREATION = { creator: '7', operation: INPUT.restore_operation, name: INPUT.name,
  scope: { ...SCOPE, database: '101', incarnation: '102', generation: '103' }, expected_name_revision: null };
const REFERENCE = { creation: CREATION, descriptor_hash: 'b'.repeat(64) };
const PREPARED = { reference: REFERENCE, input: INPUT, initial_quota: { max_bytes: '10737418240' },
  retention: { max_entries: 4096, max_result_bytes: '1048576' },
  point: { data_root: 'c'.repeat(64), page_count: 2, sequence: '9007199254740997', source_revision: '9' } };
const PROGRESS = { prepared: PREPARED, phase: 'copying', binding_revision: '1', head_revision: '1' };
const ABORT = { reference: REFERENCE, control_operation: '12', expected_name_revision: '1', nonce: '13' };
const ABORTED = { creation: CREATION, operation: '12', nonce: '13', phase: 'aborted',
  binding_revision: '2', head_revision: '2' };
const OPTIONS = { endpoint: 'http://127.0.0.1:8123/v1/catalogue', token: 'synthetic-restore-test-credential',
  deployment: '1', tenant: '2', principal: '7' };
const clone = (value) => JSON.parse(JSON.stringify(value));
const ok = (value) => new Response(JSON.stringify({ ok: true, value }), { headers: { 'content-type': 'application/json' } });
const client = (fetch, extra = {}) => new CatalogueClient({ ...OPTIONS, fetch, ...extra });
const invalid = (fn) => assert.throws(fn, (error) => error instanceof ClientError && error.code === 'INVALID');
const ACTIONS = [{ operation: 'prepare_restore', ...INPUT }, { operation: 'resume_restore', reference: REFERENCE },
  { operation: 'inspect_restore', creator: '7', restore_operation: INPUT.restore_operation },
  { operation: 'abort_restore', ...ABORT }];

test('restore keeps the exact source and original intent across persistence and independent POSTs', async () => {
  const observed = [];
  const outputs = [PREPARED, PROGRESS, PROGRESS, ABORTED];
  const c = client(async (url, request) => {
    assert.equal(url, OPTIONS.endpoint);
    const { version, ...action } = JSON.parse(request.body);
    assert.equal(version, 1);
    assert.equal(request.headers['x-scap-admission'], action.operation === 'resume_restore' ? 'recovery' : 'catalogue');
    assert.equal(request.redirect, 'error');
    observed.push(action);
    return ok(outputs[observed.length - 1]);
  });
  for (const action of ACTIONS) {
    const mutable = clone(action), intent = c.prepareIntent(mutable), saved = c.saveIntent(intent);
    if (mutable.source_scope) mutable.source_scope.database = '99';
    if (mutable.reference) mutable.reference.descriptor_hash = 'd'.repeat(64);
    assert.deepEqual(c.restoreIntent(saved), intent);
    assert.deepEqual(intent.action, action);
    const frozen = (value) => {
      assert.equal(Object.isFrozen(value), true);
      for (const child of Object.values(value)) if (child !== null && typeof child === 'object') frozen(child);
    };
    frozen(intent);
  }
  const actual = [await c.prepareRestore(INPUT), await c.resumeRestore(REFERENCE),
    await c.inspectRestore(INPUT.restore_operation), await c.abortRestore(ABORT)];
  assert.deepEqual(observed, ACTIONS);
  assert.deepEqual(actual, outputs);
  assert.ok(actual.every(Object.isFrozen));
  assert.ok(Object.isFrozen(actual[0].input.snapshot));
});

test('restore validates all caller supplied identities and rejects incomplete or mixed authority inputs', () => {
  const c = client(() => assert.fail('invalid restore must not send HTTP'));
  for (const action of ACTIONS) {
    for (const key of Object.keys(action)) {
      const bad = clone(action); delete bad[key]; invalid(() => c.prepareIntent(bad));
    }
    invalid(() => c.prepareIntent({ ...action, completion: {} }));
  }
  for (const key of ['deployment', 'tenant']) {
    invalid(() => c.prepareRestore({ ...INPUT, source_scope: { ...SCOPE, [key]: '99' } }));
  }
  for (const hash of [1, '', 'A'.repeat(64), 'a'.repeat(63), 'z'.repeat(64)]) {
    invalid(() => c.resumeRestore({ ...REFERENCE, descriptor_hash: hash }));
  }
  invalid(() => c.resumeRestore({ ...REFERENCE, creation: { ...CREATION, creator: '8' } }));
  invalid(() => c.prepareIntent({ ...ACTIONS[2], creator: '8' }));
  invalid(() => c.prepareRestore({ ...INPUT, copy_proof: 'untrusted' }));
  invalid(() => c.abortRestore({ ...ABORT, completion: 'untrusted' }));
  invalid(() => c.prepareRestore({ ...INPUT, snapshot: { ...INPUT.snapshot, capture_serial: '0' } }));
  invalid(() => c.prepareRestore({ ...INPUT, snapshot: { ...INPUT.snapshot, etag: 'untrusted' } }));
  for (const value of ['0', '01', 1, '18446744073709551616']) {
    invalid(() => c.inspectRestore(value));
    invalid(() => c.prepareRestore({ ...INPUT, restore_operation: value }));
  }
});

test('restore binds every prepared response to the source snapshot, descriptor, name and quota', async () => {
  for (const quota of [{ mode: 'default' }, { mode: 'unlimited' }, { mode: 'limited', max_bytes: '8192' }]) {
    const input = { ...INPUT, expected_name_revision: '4', options: { quota } };
    const result = clone(PREPARED);
    result.input = input;
    result.reference.creation.expected_name_revision = '4';
    result.initial_quota.max_bytes = quota.mode === 'default' ? '10737418240' : quota.mode === 'unlimited' ? null : '8192';
    const c = client(() => ok(result));
    assert.deepEqual(await c.prepareRestore(input), result);
    if (quota.mode !== 'default') {
      result.initial_quota.max_bytes = '4096';
      await assert.rejects(c.prepareRestore(input), UnknownError);
    }
  }
  const mutations = [
    (v) => { v.extra = true; },
    (v) => { v.input.name = 'changed'; },
    (v) => { v.input.restore_operation = '1'; },
    (v) => { v.input.expected_name_revision = '1'; },
    (v) => { v.reference.creation.creator = '8'; },
    (v) => { v.reference.creation.scope = SCOPE; },
    (v) => { v.point.source_revision = INPUT.snapshot.capture_serial; },
    (v) => { v.point.page_count = 1.5; },
    (v) => { v.reference.descriptor_hash = 'invalid'; },
    (v) => { v.input.source_scope.database = '99'; },
    (v) => { v.input.snapshot.creator = '9'; },
    (v) => { v.input.snapshot.operation = '9'; },
    (v) => { v.input.snapshot.capture_serial = '11'; },
    (v) => { v.input.snapshot.descriptor_hash = 'd'.repeat(64); },
    (v) => { v.input.options.quota = { mode: 'unlimited' }; v.initial_quota.max_bytes = null; },
    (v) => { v.input.name = 'changed'; v.reference.creation.name = 'changed'; },
    (v) => { v.input.restore_operation = '99'; v.reference.creation.operation = '99'; },
    (v) => { v.input.expected_name_revision = '4'; v.reference.creation.expected_name_revision = '4'; },
  ];
  for (const mutate of mutations) {
    const value = clone(PREPARED); mutate(value);
    let calls = 0;
    const c = client(() => { calls++; return ok(value); });
    await assert.rejects(c.prepareRestore(INPUT), (error) => {
      assert.equal(error instanceof UnknownError, true);
      assert.deepEqual(error.reference.intent.action, ACTIONS[0]);
      return true;
    });
    assert.equal(calls, 1);
  }
  const input = { ...INPUT, options: { quota: { mode: 'limited', max_bytes: '8192' } } };
  const value = clone(PREPARED);
  value.input.options.quota = { mode: 'limited', max_bytes: '12288' };
  value.initial_quota.max_bytes = '12288';
  await assert.rejects(client(() => ok(value)).prepareRestore(input), UnknownError);
});

test('restore observations preserve the exact operation and never turn ambiguity into a retry', async () => {
  for (const phase of ['not_reserved', 'reserved', 'copying', 'copied', 'bound', 'ready',
    'aborting', 'aborted', 'deleting', 'deleted', 'name_conflict', 'identity_conflict']) {
    const value = { ...PROGRESS, phase, binding_revision: null, head_revision: null };
    assert.deepEqual(await client(() => ok(value)).resumeRestore(REFERENCE), value);
  }
  for (const mutate of [
    (v) => { v.phase = 'provisioning'; },
    (v) => { v.prepared.reference.descriptor_hash = 'd'.repeat(64); },
    (v) => { v.prepared.reference.creation.name = 'other'; v.prepared.input.name = 'other'; },
    (v) => { v.prepared.reference.creation.operation = '99'; v.prepared.input.restore_operation = '99'; },
  ]) {
    const value = clone(PROGRESS); mutate(value);
    await assert.rejects(client(() => ok(value)).resumeRestore(REFERENCE), UnknownError);
  }
  const other = clone(PROGRESS);
  other.prepared.reference.creation.operation = other.prepared.input.restore_operation = '99';
  await assert.rejects(client(() => ok(other)).inspectRestore(INPUT.restore_operation), ClientError);
  const aborted = clone(ABORTED); aborted.nonce = '99';
  await assert.rejects(client(() => ok(aborted)).abortRestore(ABORT), UnknownError);
  let calls = 0;
  const lost = client(() => { calls++; throw new Error('response lost'); });
  await assert.rejects(lost.resumeRestore(REFERENCE), (error) => error instanceof UnknownError &&
    error.reference.intent.action.reference.descriptor_hash === REFERENCE.descriptor_hash);
  await assert.rejects(lost.inspectRestore(INPUT.restore_operation), (error) => error instanceof ClientError &&
    !(error instanceof UnknownError));
  assert.equal(calls, 2);
});
