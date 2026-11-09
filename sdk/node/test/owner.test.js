import { test } from 'node:test';
import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { OwnerClient, OwnerReconcileError, ClientError } from '../src/client.js';
import { inspectIntent, matchesBase, matchesTransition } from '../src/owner_intent.js';
import { OPTIONS, SCOPE, A, B, clone, head, claim, activated, takeover, success, failure, script } from './owner_fixture.js';

const owner = (io, extra = {}) => new OwnerClient({ ...OPTIONS, fetch: io.fetch, ...extra });
const invalid = (fn) => assert.throws(fn, (e) => e instanceof ClientError && e.code === 'INVALID');
const stop = (code, phase, outcome) => (e) => e instanceof OwnerReconcileError && e.code === code && e.phase === phase && e.outcome === outcome;

test('owner probes use one guarded read on the copied trusted route without requiring that worker to own the database', async () => {
  const routes = clone(OPTIONS.routes), io = script([head(), head()]), db = owner(io, { routes });
  routes[1].endpoint = 'https://untrusted.invalid/v1';
  const observed = await db.probe('200');
  assert.equal(observed.owner_instance, '100');
  assert.deepEqual(io.calls[0].body, { version: 1, scope: SCOPE,
    operation: 'status', expected_worker_instance: '200' });
  assert.equal(io.calls[0].url, B);
  assert.equal(io.calls[0].init.headers['x-scap-admission'], 'control');
  assert.equal(io.calls[0].init.redirect, 'error');
  assert.equal(io.calls[0].init.signal.aborted, true);
  await db.observe();
  assert.equal(io.calls[1].url, A);
  assert.deepEqual(io.calls[1].body, { version: 1, scope: SCOPE, operation: 'status' });
  await assert.rejects(db.probe('300'), { code: 'UNROUTABLE' });
  for (const worker of [undefined, null, '0', 200, '0200']) {
    await assert.rejects(db.probe(worker), { code: 'INVALID' });
  }
  const aborted = new AbortController(); aborted.abort();
  await assert.rejects(db.probe('200', { signal: aborted.signal }), { code: 'ABORTED' });
  assert.equal(io.calls.length, 2);
});

test('probe rejection or lost response never falls back, recovers, mutates ownership or dispatches SQL', async () => {
  for (const [response, code] of [
    [() => failure('TARGET_MISMATCH', 409), 'TARGET_MISMATCH'],
    [() => failure('DENIED', 403), 'DENIED'],
    [() => failure('UNKNOWN', 503), 'UNKNOWN'],
    [() => { throw new Error('lost status response'); }, 'TRANSPORT'],
    [head({ scope: { ...SCOPE, incarnation: '9' } }), 'INVALID'],
  ]) {
    const io = script([response]), db = owner(io);
    await assert.rejects(db.probe('200'), (error) => error instanceof ClientError &&
      !(error instanceof OwnerReconcileError) && error.code === code);
    assert.equal(io.calls.length, 1);
    assert.equal(io.calls[0].url, B);
    assert.equal(io.calls[0].body.operation, 'status');
    assert.equal(io.calls[0].body.expected_worker_instance, '200');
  }
});

test('probe absolute deadline stops dispatch after synchronous request encoding', async (t) => {
  let now = 0;
  t.mock.method(performance, 'now', () => now);
  const original = JSON.stringify;
  t.mock.method(JSON, 'stringify', (value, ...rest) => {
    const result = original(value, ...rest);
    if (value?.operation === 'status') now = 11;
    return result;
  });
  const io = script([]), db = owner(io);
  await assert.rejects(db.probe('200', { timeoutMs: 10 }), { code: 'DEADLINE' });
  assert.equal(io.calls.length, 0);
});

test('probe uses the ordinary total budget and withholds an over-budget verified response', async (t) => {
  let now = 0;
  t.mock.method(performance, 'now', () => now);
  const original = JSON.stringify;
  t.mock.method(JSON, 'stringify', (value, ...rest) => {
    const result = original(value, ...rest);
    if (value?.operation === 'status') now = 9.5;
    return result;
  });
  const io = script([() => { now = 10.1; return success(head()); }]);
  const db = owner(io, { timeoutMs: 10, recoveryTimeoutMs: 1000 });
  await assert.rejects(db.probe('200'), { code: 'DEADLINE' });
  assert.equal(io.calls.length, 1);
  assert.equal(io.calls[0].body.operation, 'status');
  assert.equal(io.calls[0].init.signal.aborted, true);
});

test('owner intents bind context, persist without effects, and dispatch each original phase only once', async () => {
  const io = script([head(), head(), claim(), activated(), activated()]), db = owner(io);
  assert.deepEqual(db.scope, SCOPE); assert.equal(db.principal, '7');
  const observed = await db.observe(), input = clone(takeover);
  const intent = db.prepareTakeover(observed, input), saved = db.saveIntent(intent);
  input.targetWorker = '100';
  assert.equal(intent.targetWorker, '200'); assert.equal(Object.isFrozen(intent), true);
  assert.equal(Object.isFrozen(intent.scope), true);
  assert.throws(() => { intent.scope.database = '99'; }, TypeError);
  const result = await db.reconcile(intent);
  assert.equal(result.state, 'active'); assert.deepEqual(result.status, activated());
  assert.deepEqual(io.calls.map((c) => [c.url, c.body.operation]),
    [[A, 'status'], [A, 'status'], [B, 'takeover'], [B, 'activate']]);
  for (const [index, revision, nonce] of [[2, '10', '21'], [3, '11', '22']]) {
    assert.equal(io.calls[index].body.expected_revision, revision);
    assert.equal(io.calls[index].body.nonce, nonce);
    assert.equal(io.calls[index].body.expected_worker_instance, '200');
  }
  assert.equal(db.saveIntent(intent), saved);
  await assert.rejects(db.reconcile(intent), stop('INTENT_USED', 'observe', 'not_sent'));
  assert.equal(io.calls.length, 4);
  const restored = db.restoreIntent(saved);
  assert.deepEqual(restored, intent);
  assert.equal((await db.inspect(restored)).state, 'activation_accepted');
  await assert.rejects(db.reconcile(restored), stop('INTENT_USED', 'observe', 'not_sent'));
  assert.equal(io.calls.length, 5);
});

test('activation-only intent retains owner epoch and never sends takeover', async () => {
  const base = claim(), io = script([base, activated()]), db = owner(io);
  const intent = db.prepareActivation(base, { activateNonce: '22' });
  const saved = db.saveIntent(intent);
  assert.equal(intent.takeoverNonce, null); assert.equal(intent.mode, 'activate');
  const result = await db.reconcile(intent);
  assert.equal(result.status.owner_epoch, base.owner_epoch);
  assert.deepEqual(io.calls.map((c) => c.body.operation), ['status', 'activate']);
  assert.deepEqual(db.restoreIntent(saved), intent);
});

test('a surviving explicitly configured bootstrap can inspect an old intent without changing its routes or dispatch rights', async () => {
  const old = owner(script([])), intent = old.prepareTakeover(head(), takeover), saved = old.saveIntent(intent);
  const io = script([claim()]), surviving = owner(io, { bootstrapEndpoint: B });
  const restored = surviving.restoreIntent(saved);
  assert.equal(restored.registryDigest, intent.registryDigest);
  assert.equal((await surviving.inspect(restored)).state, 'takeover_accepted');
  assert.equal(io.calls[0].url, B);
  await assert.rejects(surviving.reconcile(restored), stop('INTENT_USED', 'observe', 'not_sent'));
  assert.equal(io.calls.length, 1);
  const rebound = owner(script([]), { bootstrapEndpoint: B,
    routes: [OPTIONS.routes[0], { workerInstance: '200', endpoint: 'https://different-worker.invalid/v1' }] });
  invalid(() => rebound.restoreIntent(saved));
});

test('owner preparation and restore reject forged identity, mutable context, ambiguous JSON and arithmetic overflow', () => {
  const io = script([]), db = owner(io), intent = db.prepareTakeover(head(), takeover), saved = db.saveIntent(intent);
  invalid(() => db.saveIntent(clone(intent)));
  invalid(() => db.prepareTakeover(head({ lifecycle: 'maintenance' }), takeover));
  invalid(() => db.prepareTakeover(head({ scope: { ...SCOPE, tenant: '9' } }), takeover));
  invalid(() => db.prepareTakeover(head(), { ...takeover, targetWorker: '100' }));
  invalid(() => db.prepareTakeover(head(), { ...takeover, takeoverNonce: '22' }));
  invalid(() => db.prepareTakeover(head(), { ...takeover, activateNonce: '0' }));
  invalid(() => db.prepareTakeover(head(), { ...takeover, extra: true }));
  invalid(() => db.prepareTakeover(head({ revision: '18446744073709551614', transition: { revision: '18446744073709551614', nonce: '9' } }), takeover));
  invalid(() => db.prepareTakeover(head({ owner_epoch: '18446744073709551615' }), takeover));
  invalid(() => db.prepareActivation(head(), { activateNonce: '22' }));
  invalid(() => db.prepareActivation(head({ active: false, revision: '18446744073709551615',
    transition: { revision: '18446744073709551615', nonce: '9' } }), { activateNonce: '22' }));
  for (const serialized of [null, 'x'.repeat(16385), '{', saved.replace('"version":1', '"version":1,"version":1')]) {
    invalid(() => db.restoreIntent(serialized));
  }
  for (const change of [
    (i) => { i.version = 2; }, (i) => { i.mode = 'automatic'; }, (i) => { i.principal = '8'; },
    (i) => { i.registryDigest = 'f'.repeat(64); }, (i) => { i.scope.generation = '6'; },
    (i) => { i.baseActive = 1; }, (i) => { i.baseRevision = '01'; }, (i) => { i.takeoverNonce = null; },
    (i) => { i.extra = true; }, (i) => { i.mode = 'activate'; },
    (i) => { i.mode = 'activate'; i.takeoverNonce = null; i.baseActive = false; },
  ]) {
    const changed = JSON.parse(saved); change(changed); invalid(() => db.restoreIntent(JSON.stringify(changed)));
  }
  const another = owner(script([]), { principal: '8' });
  invalid(() => another.saveIntent(intent));
  const differentRegistry = owner(script([]), { routes: [{ workerInstance: '100', endpoint: A }] });
  invalid(() => differentRegistry.restoreIntent(saved));
  assert.throws(() => db.prepareTakeover(head(), { ...takeover, targetWorker: '300' }), { code: 'UNROUTABLE' });
  assert.equal(io.calls.length, 0);
});

test('inspect distinguishes exact transition proof from current state and never mutates HEAD', async () => {
  const cases = [
    [head(), 'base_observed'], [claim(), 'takeover_accepted'], [activated(), 'activation_accepted'],
    [head({ revision: '13', owner_epoch: '3', owner_instance: '200' }), 'target_active'],
    [head({ revision: '13', owner_epoch: '3', owner_instance: '200', active: false }), 'target_inactive'],
    [head({ revision: '13', owner_epoch: '4', owner_instance: '200' }), 'superseded'],
    [head({ revision: '13', owner_epoch: '3', owner_instance: '300' }), 'superseded'],
    [head({ lifecycle: 'maintenance' }), 'blocked'],
    [head({ revision: '9' }), 'unresolved'], [head({ owner_instance: '200' }), 'unresolved'],
  ];
  const io = script(cases.map(([status]) => status)), db = owner(io);
  const intent = db.prepareTakeover(head(), takeover);
  for (const [, state] of cases) assert.equal((await db.inspect(intent)).state, state);
  assert(io.calls.every((c) => c.body.operation === 'status' && c.url === A));
  // Every matching component matters, including values whose revision is equal.
  for (const key of ['owner_epoch', 'owner_instance', 'active', 'lifecycle']) {
    const changed = head({ [key]: key === 'active' ? false : key === 'lifecycle' ? 'maintenance' : '99' });
    assert.equal(matchesBase(intent, changed), false);
  }
  for (const [key, value] of [['revision', '13'], ['owner_instance', '100'], ['owner_epoch', '4'], ['active', false], ['lifecycle', 'maintenance']]) {
    const changed = activated(); changed[key] = value;
    assert.equal(matchesTransition(intent, 'activate', changed), false);
  }
  const changedNonce = activated(); changedNonce.transition.nonce = '23';
  assert.equal(matchesTransition(intent, 'activate', changedNonce), false);
  const activation = db.prepareActivation(claim(), { activateNonce: '22' });
  assert.equal(inspectIntent(activation, head({ revision: '10' })).state, 'unresolved');
});

test('changed authority, read denial and invalid intentions stop before any owner mutation', async () => {
  for (const [response, code] of [[head({ revision: '11' }), 'SUPERSEDED'],
    [() => failure('DENIED', 403), 'DENIED'], [() => failure('UNKNOWN', 503), 'UNKNOWN']]) {
    const io = script([response]), db = owner(io), intent = db.prepareTakeover(head(), takeover);
    await assert.rejects(db.reconcile(intent), stop(code, 'observe', 'not_sent'));
    await assert.rejects(db.reconcile(intent), stop('INTENT_USED', 'observe', 'not_sent'));
    assert.deepEqual(io.calls.map((c) => c.body.operation), ['status']);
  }
  const io = script([]), db = owner(io);
  await assert.rejects(db.reconcile({ token: 'do-not-retain-unvalidated-secret' }),
    (e) => e instanceof ClientError && !(e instanceof OwnerReconcileError) && e.code === 'INVALID' &&
      !JSON.stringify(e).includes('do-not-retain-unvalidated-secret'));
  await assert.rejects(db.inspect({}), { code: 'INVALID' });
  assert.equal(io.calls.length, 0);
});

test('takeover conflicts or destination mismatch do not refresh conditions or send activation', async () => {
  for (const [code, http] of [['CONFLICT', 409], ['TARGET_MISMATCH', 409], ['DENIED', 403], ['RECOVERY_BUSY', 429]]) {
    const io = script([head(), () => failure(code, http)]), db = owner(io), intent = db.prepareTakeover(head(), takeover);
    await assert.rejects(db.reconcile(intent), (e) => stop(code, 'takeover', 'unresolved')(e) && e.intent === intent && e.lastConfirmed === null);
    assert.deepEqual(io.calls.map((c) => c.body.operation), ['status', 'takeover']);
  }
});

test('takeover response loss and malformed transition preserve uncertainty without another mutation', async () => {
  const wrong = [
    () => { throw new Error('secret token'); }, () => failure('UNKNOWN', 503),
    () => { const h = claim(); h.transition.nonce = '99'; return success(h); },
    () => { const h = claim(); h.revision = h.transition.revision = '12'; return success(h); },
    () => success({ ...claim(), owner_instance: '100' }), () => success({ ...claim(), owner_epoch: '4' }),
    () => success({ ...claim(), active: true }), () => success({ ...claim(), lifecycle: 'maintenance' }),
  ];
  for (const response of wrong) {
    const io = script([head(), response, claim()]), db = owner(io), intent = db.prepareTakeover(head(), takeover);
    await assert.rejects(db.reconcile(intent), (e) => stop('UNKNOWN', 'takeover', 'unknown')(e) && e.intent === intent);
    assert.equal(io.calls.length, 2);
    const restored = db.restoreIntent(db.saveIntent(intent));
    assert.equal((await db.inspect(restored)).state, 'takeover_accepted');
    await assert.rejects(db.reconcile(restored), stop('INTENT_USED', 'observe', 'not_sent'));
    assert.equal(io.calls.length, 3);
  }
});

test('activation failures retain the confirmed claim and can only continue via a fresh activation intent', async () => {
  const io = script([head(), claim(), () => { throw new Error('lost activation response'); },
    claim(), claim(), activated()]);
  const db = owner(io), original = db.prepareTakeover(head(), takeover);
  await assert.rejects(db.reconcile(original), (e) => stop('UNKNOWN', 'activate', 'unknown')(e) && e.lastConfirmed.owner_epoch === '3');
  const restored = db.restoreIntent(db.saveIntent(original)), inspected = await db.inspect(restored);
  assert.equal(inspected.state, 'takeover_accepted');
  const activation = db.prepareActivation(inspected.status, { activateNonce: '22' });
  assert.equal((await db.reconcile(activation)).state, 'active');
  assert.deepEqual(io.calls.map((c) => c.body.operation), ['status', 'takeover', 'activate', 'status', 'status', 'activate']);
  const blocked = script([head(), claim(), () => failure('DENIED', 403)]), denied = owner(blocked);
  await assert.rejects(denied.reconcile(denied.prepareTakeover(head(), takeover)),
    (e) => stop('DENIED', 'activate', 'partial')(e) && e.lastConfirmed.active === false);
});

test('owner deadline preserves a confirmed phase without issuing the next transition', async (t) => {
  let now = 0;
  t.mock.method(performance, 'now', () => now);
  const original = JSON.stringify;
  t.mock.method(JSON, 'stringify', (value, ...rest) => {
    const result = original(value, ...rest);
    if (value?.operation === 'takeover') now = 9.5;
    return result;
  });
  const io = script([() => { now = 9; return success(head()); }, () => { now = 10.1; return success(claim()); }]);
  const db = owner(io), intent = db.prepareTakeover(head(), takeover);
  await assert.rejects(db.reconcile(intent, { timeoutMs: 10 }),
    (e) => stop('DEADLINE', 'takeover', 'partial')(e) && e.lastConfirmed.transition.nonce === '21');
  assert.deepEqual(io.calls.map((c) => c.body.operation), ['status', 'takeover']);
});

test('owner deadline can retain verified activation while still refusing an over-budget success', async (t) => {
  let now = 0;
  t.mock.method(performance, 'now', () => now);
  const original = JSON.stringify;
  t.mock.method(JSON, 'stringify', (value, ...rest) => {
    const result = original(value, ...rest);
    if (value?.operation === 'activate') now = 9.5;
    return result;
  });
  const io = script([() => { now = 9; return success(claim()); }, () => { now = 10.1; return success(activated()); }]);
  const db = owner(io), intent = db.prepareActivation(claim(), { activateNonce: '22' });
  await assert.rejects(db.reconcile(intent, { timeoutMs: 10 }), stop('DEADLINE', 'activate', 'active'));
  assert.equal(io.calls.length, 2);
});
