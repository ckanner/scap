import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CatalogueClient, ClientError, RemoteError, UnknownError } from '../src/client.js';
import * as catalogue from '../src/catalogue_wire.js';

const U64 = '18446744073709551615';
const CONTEXT = { deployment: '9007199254740993', tenant: '9007199254740995', principal: '17' };
const OPTIONS = { endpoint: 'http://127.0.0.1:8123/v1/catalogue',
  token: 'synthetic-catalogue-unit-only-credential', ...CONTEXT };
const SCOPE = { deployment: CONTEXT.deployment, tenant: CONTEXT.tenant,
  database: U64, incarnation: '9007199254740997', generation: '1' };
const CREATION = { creator: '17', operation: U64, name: '账簿😀', scope: SCOPE, expected_name_revision: null };
const POLICY = { initial_quota: { max_bytes: '10737418240' }, retention: { max_entries: 4096, max_result_bytes: U64 } };
const PREPARE = { operation: 'prepare_create', name: CREATION.name, create_operation: U64,
  expected_name_revision: null, options: { quota: { mode: 'default' } } };
const ABORT = { operation: 'abort_create', creation: CREATION, control_operation: U64,
  expected_name_revision: '9007199254740999', nonce: U64 };
const DELETE = { ...ABORT, operation: 'delete_name', expected_head_revision: '9007199254741001' };
const ACTIONS = [PREPARE, { operation: 'resume_create', creation: CREATION }, ABORT,
  { operation: 'inspect_create_operation', create_operation: U64 },
  { operation: 'resolve_name', name: CREATION.name }, DELETE];
const CREATE_PHASES = ['not_reserved', 'reserved', 'provisioning', 'bound', 'ready', 'aborting',
  'aborted', 'deleting', 'deleted', 'name_conflict', 'identity_conflict'];
const clone = (value) => JSON.parse(JSON.stringify(value));
const invalid = (fn) => assert.throws(fn, (error) => error instanceof ClientError && error.code === 'INVALID');
const response = (value) => new Response(JSON.stringify({ ok: true, value }),
  { status: 200, headers: { 'content-type': 'application/json' } });
const client = (fetcher, extra = {}) => new CatalogueClient({ ...OPTIONS, fetch: fetcher, ...extra });
const withoutOperation = ({ operation, ...value }) => value;
function head() {
  return { scope: clone(SCOPE), revision: U64, head_serial: U64,
    storage: { active_generation: '1', allocated_through: '1', plan: null, sweep: null },
    sequence: '0', owner_epoch: '2', owner_instance: '3', active: false,
    auth_epoch: '4', lifecycle: 'ready', request_epoch: '5', max_bytes: null,
    transition: { revision: U64, nonce: '6' },
    retention: { max_entries: 4096, max_result_bytes: U64, oldest_epoch: '1' } };
}
function prepared() { return { creation: clone(CREATION), ...clone(POLICY) }; }
function progress(phase = 'ready') {
  return { ...prepared(), phase, binding_revision: U64, head_revision: U64 };
}
function control(action = ABORT, phase = 'aborted') {
  return { creation: clone(action.creation), operation: action.control_operation, nonce: action.nonce,
    phase, binding_revision: null, head_revision: U64 };
}
function fixture(action) {
  switch (action.operation) {
    case 'prepare_create': return prepared();
    case 'resume_create': case 'inspect_create_operation': return progress();
    case 'abort_create': return control();
    case 'delete_name': return control(DELETE, 'deleted');
    case 'resolve_name': return { creation: clone(CREATION), binding_revision: U64, head: head() };
  }
  assert.fail('Unexpected fixture action');
}

test('catalogue context and saved intents preserve authority, caller and every original condition', () => {
  const c = new CatalogueClient(OPTIONS);
  assert.deepEqual([c.deployment, c.tenant, c.principal], Object.values(CONTEXT));
  for (const original of ACTIONS) {
    const input = clone(original), intent = c.prepareIntent(input), saved = c.saveIntent(intent);
    input.operation = 'query';
    if (input.creation) input.creation.scope.database = '1';
    assert.equal(c.saveIntent(intent), saved);
    assert.deepEqual(c.restoreIntent(saved), intent);
    assert.deepEqual(JSON.parse(saved), { version: 1, ...CONTEXT, action: original });
    const frozen = (value) => {
      assert.equal(Object.isFrozen(value), true);
      for (const child of Object.values(value)) if (child !== null && typeof child === 'object') frozen(child);
    };
    frozen(intent);
    assert.throws(() => { intent.action.operation = 'delete_name'; }, TypeError);
    invalid(() => c.saveIntent(clone(intent)));
    invalid(() => c.submit(clone(intent)));
    for (const key of Object.keys(CONTEXT)) {
      const other = new CatalogueClient({ ...OPTIONS, [key]: '23' });
      invalid(() => other.saveIntent(intent));
      invalid(() => other.restoreIntent(saved));
    }
  }
  const input = { ...PREPARE, expected_name_revision: U64 };
  assert.equal(c.restoreIntent(c.saveIntent(c.prepareIntent(input))).action.expected_name_revision, U64);
  for (const input of [undefined, null, 1, '', 'x'.repeat(65537), '{}', '{',
    '{"version":1,"version":1}', JSON.stringify({ ...JSON.parse(c.saveIntent(c.prepareIntent(PREPARE))), version: 2 })]) {
    invalid(() => c.restoreIntent(input));
  }
  for (const key of Object.keys(CONTEXT)) {
    invalid(() => new CatalogueClient({ ...OPTIONS, [key]: 1 }));
    const saved = JSON.parse(c.saveIntent(c.prepareIntent(PREPARE))); saved[key] = '01';
    invalid(() => c.restoreIntent(JSON.stringify(saved)));
  }
  invalid(() => new CatalogueClient({ ...OPTIONS, scope: SCOPE }));
  invalid(() => new CatalogueClient({ ...OPTIONS, get principal() { assert.fail('getter evaluated'); } }));
});

test('catalogue actions reject partial, noncanonical, unauthorized and surplus conditions before transport', () => {
  const c = client(() => assert.fail('No invalid intent may send HTTP'));
  for (const input of [null, {}, [], { operation: 1 }, { operation: 'query' },
    { ...PREPARE, version: 1 }, { ...PREPARE, tenant: '1' },
    { ...PREPARE, get name() { assert.fail('getter evaluated'); } }]) invalid(() => c.prepareIntent(input));
  for (const action of ACTIONS) {
    for (const key of Object.keys(action)) {
      const bad = clone(action); delete bad[key]; invalid(() => c.prepareIntent(bad));
    }
    invalid(() => c.prepareIntent({ ...action, extra: true }));
  }
  for (const name of [1, '', '\ud800', 'a'.repeat(129), '界'.repeat(43), '\0', '\u007f', '\u0085']) {
    invalid(() => c.prepareIntent({ ...PREPARE, name }));
  }
  for (const name of ['a'.repeat(128), '界'.repeat(42), 'e\u0301', 'é', '\u200b']) {
    assert.equal(c.prepareIntent({ operation: 'resolve_name', name }).action.name, name);
  }
  for (const value of [0, 1n, '0', '01', '-1', '18446744073709551616']) {
    invalid(() => c.prepareIntent({ ...PREPARE, create_operation: value }));
    invalid(() => c.prepareIntent({ ...PREPARE, expected_name_revision: value }));
    for (const key of ['control_operation', 'expected_name_revision', 'expected_head_revision', 'nonce']) {
      invalid(() => c.prepareIntent({ ...DELETE, [key]: value }));
    }
  }
  for (const quota of [{}, { mode: 'other' }, { mode: 'default', max_bytes: null },
    { mode: 'unlimited', max_bytes: '4096' }, { mode: 'limited' }, { mode: 'limited', max_bytes: null },
    { mode: 'limited', max_bytes: '4097' }, { mode: 'limited', max_bytes: U64 }]) {
    invalid(() => c.prepareIntent({ ...PREPARE, options: { quota } }));
  }
  for (const quota of [{ mode: 'unlimited' }, { mode: 'limited', max_bytes: '4096' }]) {
    assert.deepEqual(c.prepareIntent({ ...PREPARE, options: { quota } }).action.options.quota, quota);
  }
  invalid(() => c.prepareIntent({ ...PREPARE, options: { quota: { mode: 'default' }, extra: true } }));
  for (const key of ['deployment', 'tenant']) {
    invalid(() => c.prepareIntent({ ...DELETE, creation: { ...CREATION, scope: { ...SCOPE, [key]: '1' } } }));
  }
  for (const action of [ACTIONS[1], ABORT]) {
    invalid(() => c.prepareIntent({ ...action, creation: { ...CREATION, creator: '18' } }));
  }
  const otherCreator = { ...DELETE, creation: { ...CREATION, creator: '18' } };
  assert.equal(c.prepareIntent(otherCreator).action.creation.creator, '18');
  for (const fn of [() => c.prepareCreate({ ...withoutOperation(PREPARE), extra: 1 }),
    () => c.abortCreate({ ...withoutOperation(ABORT), extra: 1 }),
    () => c.deleteName({ ...withoutOperation(DELETE), extra: 1 })]) invalid(fn);
});

test('six catalogue methods make one bounded POST with only the strict flat envelope and catalogue admission', async () => {
  const calls = [];
  const c = client(async (url, request) => {
    const body = JSON.parse(request.body), { version, ...action } = body;
    assert.equal(url, OPTIONS.endpoint); assert.equal(version, 1);
    assert.equal(request.method, 'POST'); assert.equal(request.redirect, 'error');
    assert.equal(request.headers['x-scap-admission'], 'catalogue');
    assert.equal(request.headers.authorization, `Bearer ${OPTIONS.token}`);
    for (const key of ['scope', 'principal', 'tenant', 'deployment', 'intent']) assert.equal(Object.hasOwn(body, key), false);
    calls.push(action); return response(fixture(action));
  });
  const outputs = [await c.prepareCreate(withoutOperation(PREPARE)), await c.resumeCreate(CREATION),
    await c.abortCreate(withoutOperation(ABORT)), await c.inspectCreateOperation(U64),
    await c.resolveName(CREATION.name), await c.deleteName(withoutOperation(DELETE))];
  assert.deepEqual(calls, ACTIONS);
  outputs.forEach((value, i) => assert.deepEqual(value, fixture(ACTIONS[i])));
  for (const output of outputs) {
    assert.equal(Object.isFrozen(output), true); assert.equal(Object.isFrozen(output.creation), true);
  }
  assert.equal(outputs[0].creation.scope.database, U64);
  assert.equal(outputs[1].head_revision, U64); assert.equal(outputs[2].operation, U64);
  assert.equal(outputs[4].head.revision, U64);
});

test('all public phases, nullable revisions and explicit quota choices survive response validation', () => {
  const c = new CatalogueClient(OPTIONS), read = c.prepareIntent(ACTIONS[3]), resume = c.prepareIntent(ACTIONS[1]);
  for (const phase of CREATE_PHASES) {
    for (const intent of [read, resume]) {
      const value = { ...progress(phase), binding_revision: null, head_revision: null };
      assert.deepEqual(catalogue.decode(value, intent), value);
    }
  }
  for (const [input, phases] of [[ABORT, ['not_reserved', 'cannot_abort_bound', 'aborting', 'aborted']],
    [DELETE, ['not_deleted', 'deleting', 'deleted']]]) {
    for (const phase of phases) {
      const value = { ...control(input, phase), binding_revision: U64, head_revision: null };
      assert.deepEqual(catalogue.decode(value, c.prepareIntent(input)), value);
    }
  }
  for (const [quota, max_bytes] of [[{ mode: 'default' }, null], [{ mode: 'unlimited' }, null],
    [{ mode: 'limited', max_bytes: '4096' }, '4096']]) {
    const input = { ...PREPARE, options: { quota } }, value = { ...prepared(), initial_quota: { max_bytes } };
    assert.deepEqual(catalogue.decode(value, c.prepareIntent(input)), value);
  }
  const value = { ...prepared(), creation: { ...CREATION, expected_name_revision: U64 } };
  assert.deepEqual(catalogue.decode(value, c.prepareIntent({ ...PREPARE, expected_name_revision: U64 })), value);
  const named = fixture(ACTIONS[4]); named.head.lifecycle = 'maintenance';
  assert.deepEqual(catalogue.decode(named, c.prepareIntent(ACTIONS[4])), named);
});

test('catalogue decoders bind original creation, control identity and strict response schema', () => {
  const c = new CatalogueClient(OPTIONS);
  const checkBad = (action, mutate) => {
    const value = fixture(action); mutate(value);
    invalid(() => catalogue.decode(value, c.prepareIntent(action)));
  };
  for (const action of ACTIONS) {
    checkBad(action, (v) => { v.proof = 'untrusted'; });
    checkBad(action, (v) => { delete v.creation.expected_name_revision; });
    for (const key of ['deployment', 'tenant']) checkBad(action, (v) => { v.creation.scope[key] = '1'; });
    checkBad(action, (v) => { v.creation.operation = 1; });
  }
  for (const action of [ACTIONS[1], ABORT, DELETE]) {
    for (const key of ['creator', 'operation', 'name', 'expected_name_revision']) {
      checkBad(action, (v) => { v.creation[key] = '1'; });
    }
    checkBad(action, (v) => { v.creation.scope.database = '1'; });
  }
  for (const action of [PREPARE, ACTIONS[3]]) {
    for (const key of ['creator', 'operation']) checkBad(action, (v) => { v.creation[key] = '1'; });
  }
  checkBad(PREPARE, (v) => { v.creation.name = 'other'; });
  checkBad(PREPARE, (v) => { v.creation.expected_name_revision = '1'; });
  for (const action of [ACTIONS[1], ACTIONS[3], ABORT, DELETE]) {
    checkBad(action, (v) => { v.phase = 'unknown_future_phase'; });
    checkBad(action, (v) => { delete v.head_revision; });
    checkBad(action, (v) => { v.binding_revision = '0'; });
    checkBad(action, (v) => { v.head_revision = 1; });
  }
  for (const action of [ABORT, DELETE]) {
    checkBad(action, (v) => { v.operation = '1'; });
    checkBad(action, (v) => { v.nonce = '1'; });
  }
  for (const max_entries of [0, -1, 65537, 1.5, '1']) checkBad(PREPARE, (v) => { v.retention.max_entries = max_entries; });
  checkBad(PREPARE, (v) => { v.retention.max_result_bytes = '0'; });
  checkBad(PREPARE, (v) => { v.retention.oldest_epoch = '1'; });
  checkBad(PREPARE, (v) => { v.initial_quota.max_bytes = '4097'; });
  for (const quota of [{ mode: 'unlimited' }, { mode: 'limited', max_bytes: '4096' }]) {
    invalid(() => catalogue.decode(prepared(), c.prepareIntent({ ...PREPARE, options: { quota } })));
  }
  checkBad(ACTIONS[4], (v) => { v.creation.name = 'other'; });
  checkBad(ACTIONS[4], (v) => { v.binding_revision = null; });
  checkBad(ACTIONS[4], (v) => { v.head.scope.database = '1'; });
  checkBad(ACTIONS[4], (v) => { v.head.lifecycle = 'deleted'; });
  checkBad(ACTIONS[4], (v) => { v.head.lifecycle = 'provisioning'; });
  const foreignCreator = { ...DELETE, creation: { ...CREATION, creator: '18' } };
  assert.deepEqual(catalogue.decode(control(foreignCreator, 'deleted'), c.prepareIntent(foreignCreator)), control(foreignCreator, 'deleted'));
});

test('transport UNKNOWN keeps the whole original intent and only explicit resubmission sends again', async () => {
  for (const action of [PREPARE, ACTIONS[1], ABORT, DELETE]) {
    let calls = 0;
    const c = client(async () => { ++calls; throw new Error('untrusted fetch failure'); });
    const intent = c.prepareIntent(action), saved = c.saveIntent(intent);
    await assert.rejects(c.submit(intent), (error) => {
      assert.equal(error instanceof UnknownError, true); assert.equal(error.reference.intent, intent);
      assert.deepEqual([error.reference.deployment, error.reference.tenant, error.reference.principal], Object.values(CONTEXT));
      assert.equal(c.saveIntent(error.reference.intent), saved); assert.equal(error.cause.code, 'TRANSPORT');
      return true;
    });
    assert.equal(calls, 1);
    const restored = c.restoreIntent(saved);
    await assert.rejects(c.submit(restored), UnknownError); assert.equal(calls, 2);
  }
  for (const action of [ACTIONS[3], ACTIONS[4]]) {
    let calls = 0;
    const c = client(async () => { ++calls; throw new Error('lost read'); });
    await assert.rejects(c.submit(c.prepareIntent(action)), (error) =>
      error instanceof ClientError && !(error instanceof UnknownError) && error.code === 'TRANSPORT');
    assert.equal(calls, 1);
  }
});

test('catalogue remote error codes are exact and malformed mutation responses remain UNKNOWN', async () => {
  for (const [code, status] of [['INVALID', 400], ['DENIED', 403], ['NOT_FOUND', 404], ['CONFLICT', 409],
    ['IDENTITY_CONFLICT', 409], ['CORRUPT', 409], ['LIMIT', 413], ['UNKNOWN', 503]]) {
    let calls = 0;
    const c = client(async () => {
      ++calls;
      return new Response(JSON.stringify({ ok: false, error: { code, message: 'untrusted remote details' } }),
        { status, headers: { 'content-type': 'application/json' } });
    });
    const intent = c.prepareIntent(DELETE);
    await assert.rejects(c.submit(intent), (error) => {
      assert.equal(error.code, code); assert.equal(error.reference.intent, intent);
      assert.equal(error.message.includes('untrusted'), false);
      assert.equal(error instanceof (code === 'UNKNOWN' ? UnknownError : RemoteError), true);
      return true;
    });
    assert.equal(calls, 1);
  }
  const malformed = client(async () => response({ ...control(DELETE, 'deleted'), nonce: '1' }));
  await assert.rejects(malformed.deleteName(withoutOperation(DELETE)), (error) =>
    error instanceof UnknownError && error.cause.code === 'INVALID' && error.reference.intent.action.nonce === U64);
  const missing = client(async () => response({ ...progress(), phase: 'not_a_phase' }));
  await assert.rejects(missing.inspectCreateOperation(U64), (error) =>
    error instanceof ClientError && !(error instanceof UnknownError) && error.code === 'INVALID');
});
