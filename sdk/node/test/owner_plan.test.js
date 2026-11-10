import { test } from 'node:test';
import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { Client, OwnerClient, OwnerPlanClient, ClientError, RemoteError, UnknownError } from '../src/client.js';
import * as wire from '../src/wire.js';
import * as planWire from '../src/owner_plan_wire.js';
import * as legacy from '../src/owner_intent.js';
import { A, B, OPTIONS, head, success, failure, script, takeover } from './owner_fixture.js';
import { SCOPE, INPUT, clone, prepared, marker, observed } from './owner_plan_fixture.js';

const invalid = (fn) => assert.throws(fn, (e) => e instanceof ClientError && e.code === 'INVALID');
const code = (expected) => (e) => e instanceof ClientError && e.code === expected;
const identity = { creator: INPUT.creator, operation: INPUT.operation };
const owner = (io, extra = {}) => new OwnerPlanClient({ ...OPTIONS, fetch: io.fetch, ...extra });
const direct = (io, extra = {}) => new Client({ endpoint: A, token: OPTIONS.token, scope: SCOPE,
  principal: '7', fetch: io.fetch, ...extra });
const decode = (value, input = INPUT) => planWire.observation(value, SCOPE, input, planWire.input(input));
const verified = (input = INPUT) => planWire.preparation({ state: 'prepared', prepared: prepared(input) },
  SCOPE, planWire.input(input)).prepared;
const mutate = (value, change, check) => { const bad = clone(value); change(bad); invalid(() => check(bad)); };

test('saved owner inputs are complete immutable decimal records before any RPC and survive another current ADMIN', async () => {
  const io = script([]), db = owner(io), mutable = clone(INPUT), saved = db.prepareInput(mutable);
  assert.deepEqual(db.scope, SCOPE); assert.equal(db.principal, '7');
  mutable.nonces.claim = '900'; mutable.target_worker = '100';
  assert.deepEqual(saved.input, INPUT); assert.equal(io.calls.length, 0);
  for (const value of [saved, saved.scope, saved.input, saved.input.nonces]) assert.equal(Object.isFrozen(value), true);
  assert.throws(() => { saved.input.nonces.claim = '999'; }, TypeError);
  const serialized = db.saveInput(saved);
  assert.equal(serialized.includes('http'), false); assert.equal(serialized.includes(OPTIONS.token), false);
  const next = owner(script([{ state: 'prepared', prepared: prepared() }]), { principal: '8' });
  const restored = next.restoreInput(serialized);
  assert.deepEqual(restored, saved);
  assert.equal((await next.prepare(restored)).state, 'prepared');
  invalid(() => db.saveInput(clone(saved)));
  const foreign = owner(io, { scope: { ...SCOPE, database: '99' } });
  invalid(() => foreign.saveInput(saved)); invalid(() => foreign.restoreInput(serialized));
  for (const value of [null, 7, ' '.repeat(16385), '{', serialized.replace('"version":1', '"version":1,"version":1')]) {
    invalid(() => db.restoreInput(value));
  }
  for (const change of [(x) => x.version = 2, (x) => x.extra = true, (x) => delete x.input,
    (x) => x.scope.database = '0', (x) => x.input.expected_revision = '00']) {
    const bad = JSON.parse(serialized); change(bad); invalid(() => db.restoreInput(JSON.stringify(bad)));
  }
  for (const key of ['creator', 'operation', 'expected_revision', 'expected_head_serial', 'target_worker']) {
    for (const value of ['0', '01', 1, '18446744073709551616']) mutate(INPUT, (x) => x[key] = value, planWire.input);
  }
  for (const change of [(x) => x.expected_revision = '16', (x) => x.mode = 'unknown', (x) => x.extra = 'secret',
    (x) => delete x.creator, (x) => x.nonces.abort = x.nonces.claim, (x) => x.nonces.cancel = '0',
    (x) => x.nonces.extra = '1', (x) => delete x.nonces.activate]) mutate(INPUT, change, planWire.input);
  invalid(() => db.prepareInput({ ...INPUT, get nonces() { throw new Error('accessor must not run'); } }));
  const maximum = { ...INPUT, expected_revision: '18446744073709551615', expected_head_serial: '18446744073709551615' };
  assert.equal(db.prepareInput(maximum).input.expected_revision, maximum.expected_revision);
  invalid(() => planWire.preparation({ state: 'prepared', prepared: prepared(maximum) }, SCOPE, planWire.input(maximum)));
  const largePhysical = { ...INPUT, expected_head_serial: '18446744073709551615' };
  invalid(() => planWire.preparation({ state: 'prepared', prepared: prepared(largePhysical) }, SCOPE, planWire.input(largePhysical)));
});

test('preparation treats Pending separately and requires actual identity, input and Scope before minting a Prepared value', () => {
  const fixed = planWire.input(INPUT), value = { state: 'prepared', prepared: prepared() };
  const result = planWire.preparation(value, SCOPE, fixed);
  assert.equal(planWire.checkPrepared(result.prepared, SCOPE), result.prepared);
  invalid(() => planWire.checkPrepared(clone(result.prepared), SCOPE));
  invalid(() => planWire.checkPrepared(result.prepared, { ...SCOPE, generation: '6' }));
  const blocker = { creator: '8', operation: '99', descriptor_hash: 'b'.repeat(64) };
  const pending = planWire.preparation({ state: 'pending', reference: blocker }, SCOPE, fixed);
  assert.deepEqual(pending, { state: 'pending', reference: blocker });
  invalid(() => planWire.checkPrepared(pending.reference, SCOPE));
  for (const change of [(x) => x.state = 'ready', (x) => x.reference = prepared().reference,
    (x) => x.prepared.scope.tenant = '8', (x) => x.prepared.reference.creator = '8',
    (x) => x.prepared.reference.operation = '8', (x) => x.prepared.reference.descriptor_hash = 'A'.repeat(64),
    (x) => x.prepared.input.target_worker = '100', (x) => x.prepared.input.nonces.abort = '901',
    (x) => x.prepared.input.expected_head_serial = '16']) {
    mutate(value, change, (x) => planWire.preparation(x, SCOPE, fixed));
  }
  for (const change of [(x) => x.reference.creator = '0', (x) => x.reference.operation = '0',
    (x) => x.reference.descriptor_hash = 'INVALID', (x) => x.prepared = prepared()]) {
    mutate(pending, change, (x) => planWire.preparation(x, SCOPE, fixed));
  }
  const shuffled = clone(value);
  shuffled.prepared.input = Object.fromEntries(Object.entries(shuffled.prepared.input).reverse());
  shuffled.prepared.input.nonces = Object.fromEntries(Object.entries(shuffled.prepared.input.nonces).reverse());
  assert.deepEqual(planWire.preparation(shuffled, SCOPE, fixed), result);
});

test('strict current owner markers reject contradictions, exhausted counters and permanently absent compatibility fields', () => {
  for (const phase of ['claimed', 'cancelling', 'active', 'aborted']) {
    const value = observed(phase);
    assert.deepEqual(wire.status(value.status, SCOPE), value.status);
    assert.equal(Object.isFrozen(wire.status(value.status, SCOPE).owner_plan.phase), true);
  }
  const value = observed('claimed').status;
  for (const change of [(x) => delete x.owner_plan, (x) => x.owner_plan = {},
    (x) => x.owner_plan.reference.creator = '0', (x) => x.owner_plan.reference.operation = '0',
    (x) => x.owner_plan.reference.descriptor_hash = 'x', (x) => x.owner_plan.admission.kind = 'no',
    (x) => x.owner_plan.phase.kind = 'no', (x) => x.owner_plan.admission.revision = '1',
    (x) => x.owner_plan.admission.revision = '17', (x) => x.owner_plan.phase.revision = '17',
    (x) => x.owner_plan.admission.kind = 'cancel', (x) => x.owner_plan.phase.revision = '12',
    (x) => x.owner_plan.phase.head_serial = '17', (x) => { x.revision = '10'; x.transition.revision = '10'; },
    (x) => x.head_serial = '15', (x) => x.active = true, (x) => x.lifecycle = 'maintenance',
    (x) => x.owner_epoch = '4', (x) => x.owner_instance = '100', (x) => x.head_serial = '17',
    (x) => { x.revision = '18446744073709551615'; x.transition.revision = x.revision; x.head_serial = x.revision; },
    (x) => x.head_serial = '18446744073709551615',
    (x) => { x.storage.allocated_through = '2'; x.storage.plan = { serial: '12', source: '1', target: '2', phase: 'copying' }; },
    (x) => { x.storage.allocated_through = '2'; x.storage.sweep = { serial: '12', generation: '2', next_after: null,
      exhausted: true, pending: 1, applied: 0, observed_absent: 0, condition_mismatch: 0 }; }]) {
    mutate(value, change, (x) => wire.status(x, SCOPE));
  }
  const active = observed('active').status;
  for (const change of [(x) => x.owner_plan.admission.kind = 'cancel',
    (x) => x.owner_plan.phase.revision = '11', (x) => x.owner_plan.phase.head_serial = '16',
    (x) => { x.owner_plan.phase.head_serial = '18'; x.head_serial = '18'; }]) {
    mutate(active, change, (x) => wire.status(x, SCOPE));
  }
  const cancelled = observed('cancelling').status;
  mutate(cancelled, (x) => x.owner_plan.admission.kind = 'claim', (x) => wire.status(x, SCOPE));
  const metadata = clone(value);
  metadata.revision = '12'; metadata.head_serial = '17'; metadata.transition = { revision: '12', nonce: '900' };
  assert.equal(wire.status(metadata, SCOPE).owner_plan.phase.revision, '11');
});

test('owner observations keep historical success separate from current ownership, lifecycle and SQL result knowledge', () => {
  for (const phase of ['prepared', 'fenced', 'claimed', 'cancelling', 'active', 'aborted']) {
    const value = observed(phase), result = decode(value);
    assert.deepEqual(result, value); assert.equal(planWire.checkPrepared(result.prepared, SCOPE), result.prepared);
    for (const object of [result, result.prepared, result.prepared.input, result.prepared.reference]) assert.ok(Object.isFrozen(object));
  }
  const cancel = observed('aborted', INPUT, 'cancel'); assert.deepEqual(decode(cancel), cancel);
  const activation = { ...INPUT, mode: 'activate' };
  for (const phase of ['prepared', 'claimed', 'cancelling', 'active', 'aborted']) {
    const value = observed(phase, activation); assert.deepEqual(decode(value, activation), value);
  }
  const late = observed('active');
  late.status.revision = '14'; late.status.head_serial = '20';
  late.status.transition = { revision: '14', nonce: '999' };
  late.status.owner_epoch = '4'; late.status.active = false; late.status.lifecycle = 'deleted';
  late.status.storage.terminal = { serial: '20' };
  assert.equal(decode(late).accepted.phase.owner_epoch, '3');
  const nextInput = { ...INPUT, operation: '90', expected_revision: '20', expected_head_serial: '30', target_worker: '300' };
  const historical = observed('active'); historical.status = observed('claimed', nextInput, 'claim', 'b'.repeat(64)).status;
  const result = decode(historical);
  assert.equal(result.state, 'active'); assert.equal(result.status.active, false);
  assert.equal(result.status.owner_instance, '300'); assert.equal(result.accepted.phase.owner_instance, '200');
  const reversed = clone(historical); reversed.accepted.admission = Object.fromEntries(Object.entries(reversed.accepted.admission).reverse());
  reversed.accepted.phase = Object.fromEntries(Object.entries(reversed.accepted.phase).reverse());
  assert.deepEqual(decode(reversed), result);
  const noHistory = observed('fenced'); noHistory.status = historical.status;
  assert.equal(decode(noHistory).accepted, null);
  const previousInput = { ...INPUT, operation: '89', expected_revision: '7', expected_head_serial: '12', target_worker: '100' };
  const nextPrepared = observed('prepared'); nextPrepared.status.owner_plan = marker('active', previousInput, 'claim', 'c'.repeat(64));
  nextPrepared.status.owner_epoch = '3';
  assert.equal(decode(nextPrepared).state, 'prepared');
  const pendingBase = clone(nextPrepared); pendingBase.status.owner_plan = marker('claimed', previousInput, 'claim', 'c'.repeat(64));
  pendingBase.status.active = false;
  invalid(() => decode(pendingBase));
  const reordered = observed('active');
  reordered.accepted.admission = Object.fromEntries(Object.entries(reordered.accepted.admission).reverse());
  reordered.accepted.phase = Object.fromEntries(Object.entries(reordered.accepted.phase).reverse());
  assert.equal(decode(reordered).state, 'active');
  // Same-worker takeover is a valid explicit epoch fence; unlike old OwnerClient it need not change routes.
  const sameWorker = { ...INPUT, target_worker: '100' };
  assert.equal(decode(observed('claimed', sameWorker), sameWorker).accepted.phase.owner_instance, '100');
});

test('observation decoder rejects cross-operation, cross-base, phase, proof ordering and omitted-history mutations', () => {
  const value = observed('active');
  for (const change of [(x) => x.prepared.input.operation = '8', (x) => x.prepared.scope.database = '8',
    (x) => x.prepared.input.mode = 'activate', (x) => x.state = 'claimed', (x) => x.accepted = null,
    (x) => x.accepted.reference.creator = '8', (x) => x.accepted.reference.operation = '8',
    (x) => x.accepted.reference.descriptor_hash = 'b'.repeat(64),
    (x) => { x.accepted.admission.revision = '12'; x.accepted.phase.revision = '13'; },
    (x) => { x.accepted.admission.head_serial = '17'; x.accepted.phase.head_serial = '18'; },
    (x) => x.accepted.phase.nonce = '999', (x) => x.accepted.phase.owner_instance = '100',
    (x) => x.accepted.phase.owner_epoch = '1', (x) => x.status.owner_plan = null,
    (x) => x.status.owner_plan.phase.nonce = '900',
    (x) => x.status.owner_plan.reference.descriptor_hash = 'b'.repeat(64)]) {
    mutate(value, change, decode);
  }
  const currentPending = observed('claimed');
  mutate(currentPending, (x) => { x.state = 'prepared'; x.accepted = null; }, decode);
  const otherInput = { ...INPUT, operation: '91', expected_revision: '20', expected_head_serial: '30' };
  const historical = observed('active'); historical.status = observed('claimed', otherInput, 'claim', 'b'.repeat(64)).status;
  for (const change of [(x) => { x.accepted = marker('claimed'); x.state = 'claimed'; },
    (x) => { x.status.owner_plan.admission.revision = '12'; x.status.owner_plan.phase.revision = '12'; },
    (x) => { x.status.owner_plan.admission.head_serial = '17'; x.status.owner_plan.phase.head_serial = '17';
      x.status.owner_plan.admission.revision = '11'; x.status.owner_plan.phase.revision = '11';
      x.status.revision = '11'; x.status.head_serial = '17'; x.status.transition.revision = '11'; }]) {
    mutate(historical, change, decode);
  }
  const base = observed('prepared');
  for (const change of [(x) => x.state = 'not_applied', (x) => { x.status.revision = '11'; x.status.transition.revision = '11'; },
    (x) => x.status.head_serial = '16', (x) => x.status.lifecycle = 'maintenance',
    (x) => { x.status.active = false; x.status.storage.allocated_through = '2';
      x.status.storage.plan = { serial: '12', source: '1', target: '2', phase: 'copying' }; },
    (x) => { x.status.storage.allocated_through = '2'; x.status.storage.sweep = { serial: '12', generation: '2',
      next_after: null, exhausted: true, pending: 1, applied: 0, observed_absent: 0, condition_mismatch: 0 }; }]) mutate(base, change, decode);
  const activateInput = { ...INPUT, mode: 'activate' }, activate = observed('prepared', activateInput);
  for (const change of [(x) => x.status.active = true, (x) => x.status.owner_instance = '100']) {
    mutate(activate, change, (x) => decode(x, activateInput));
  }
  invalid(() => planWire.observation(value, SCOPE, { creator: '8', operation: INPUT.operation }, planWire.input(INPUT)));
  invalid(() => planWire.observation(value, SCOPE, { creator: '7', operation: '8' }, planWire.input(INPUT)));
});

test('low-level owner calls send exactly the original wire action, fixed guards and admission class', async () => {
  const io = script([{ state: 'prepared', prepared: prepared() }, observed('prepared'), observed('active'),
    observed('claimed'), observed('active'), observed('aborted')]);
  const db = direct(io);
  const value = await db.ownerPrepare(INPUT);
  const inspected = await db.ownerInspect(INPUT);
  const history = await db.ownerObserve(identity);
  invalid(() => db.ownerClaim(history.prepared));
  await db.ownerClaim(value.prepared); await db.ownerResume(inspected.prepared); await db.ownerAbort(value.prepared);
  const plan = prepared().reference;
  assert.deepEqual(io.calls.map((x) => x.body), [
    { version: 1, scope: SCOPE, operation: 'owner_prepare', input: INPUT },
    { version: 1, scope: SCOPE, operation: 'owner_inspect', identity },
    { version: 1, scope: SCOPE, operation: 'owner_inspect', identity },
    { version: 1, scope: SCOPE, operation: 'owner_claim', plan, expected_worker_instance: '200' },
    { version: 1, scope: SCOPE, operation: 'owner_resume', plan, expected_worker_instance: '200' },
    { version: 1, scope: SCOPE, operation: 'owner_abort', plan },
  ]);
  assert.deepEqual(io.calls.map((x) => x.init.headers['x-scap-admission']), ['control', 'control', 'control', 'control', 'recovery', 'control']);
  for (const call of io.calls) assert.equal(call.url, A);
  invalid(() => db.ownerObserve({ ...identity, descriptor_hash: 'a'.repeat(64) }));
});

test('routed durable administration only uses configured target routes and keeps history reads independent of target availability', async () => {
  const io = script([{ state: 'prepared', prepared: prepared() }, observed('prepared'), observed('active'),
    observed('claimed'), observed('active'), observed('aborted')]);
  const db = owner(io), saved = db.prepareInput(INPUT);
  const ready = await db.prepare(saved);
  await db.inspect(saved); const history = await db.observe(identity);
  await assert.rejects(db.claim(history.prepared), code('INVALID'));
  await db.claim(ready.prepared); await db.resume(ready.prepared); await db.abort(ready.prepared);
  assert.deepEqual(io.calls.map((x) => x.url), [A, A, A, B, B, A]);
  assert.deepEqual(io.calls.map((x) => x.body.operation), ['owner_prepare', 'owner_inspect', 'owner_inspect', 'owner_claim', 'owner_resume', 'owner_abort']);
  const missingIo = script([observed('fenced'), observed('aborted')]);
  const missing = owner(missingIo, { routes: [{ workerInstance: '100', endpoint: A }], principal: '8' });
  const found = await missing.inspect(missing.restoreInput(db.saveInput(saved)));
  await assert.rejects(missing.claim(found.prepared), code('UNROUTABLE'));
  await missing.abort(found.prepared);
  assert.equal(missingIo.calls.length, 2);
  await assert.rejects(db.prepare(clone(saved)), code('INVALID'));
});

test('lost prepare ACK retains original input and explicit inspection restores the actual first-wins descriptor', async () => {
  const io = script([() => { throw new Error(OPTIONS.token); }, observed('claimed')]);
  const db = owner(io), saved = db.prepareInput(INPUT), durable = db.saveInput(saved);
  await assert.rejects(db.prepare(saved), (e) => e instanceof UnknownError && e.reference.operation === 'owner_prepare' &&
    assert.deepEqual(e.reference.ownerInput, INPUT) === undefined && !JSON.stringify(e).includes(OPTIONS.token));
  assert.equal(io.calls.length, 1);
  const recovered = await db.inspect(db.restoreInput(durable));
  assert.equal(recovered.state, 'claimed'); assert.equal(recovered.prepared.reference.descriptor_hash, 'a'.repeat(64));
  assert.equal(io.calls.length, 2);
  const wrongIo = script([observed('claimed')]), wrong = owner(wrongIo);
  const changed = wrong.prepareInput({ ...INPUT, target_worker: '100' });
  await assert.rejects(wrong.inspect(changed), code('INVALID'));
  assert.equal(wrongIo.calls.length, 1);
  const pendingIo = script([{ state: 'pending', reference: { creator: '8', operation: '99', descriptor_hash: 'b'.repeat(64) } }]);
  const pendingOwner = owner(pendingIo);
  const pending = await pendingOwner.prepare(pendingOwner.prepareInput(INPUT));
  assert.equal(pending.state, 'pending'); await assert.rejects(pendingOwner.claim(pending.reference), code('INVALID'));
  assert.equal(pendingIo.calls.length, 1);
});

test('uncertain mutations and explicit rejections keep immutable operation references without phase loops', async () => {
  for (const method of ['claim', 'resume', 'abort']) {
    for (const response of [() => { throw new Error('secret'); }, () => success({ bad: true })]) {
      const io = script([response]), db = owner(io);
      await assert.rejects(db[method](verified()), (e) => e instanceof UnknownError && e.reference.operation === `owner_${method}` &&
        assert.deepEqual(e.reference.ownerPlan, prepared().reference) === undefined &&
        e.reference.expectedWorkerInstance === (method === 'abort' ? undefined : '200'));
      assert.equal(io.calls.length, 1);
    }
  }
  for (const rejection of ['DENIED', 'CONFLICT', 'LIMIT', 'CORRUPT', 'SNAPSHOT_EXPIRED', 'RECOVERY_BUSY']) {
    const status = { DENIED: 403, LIMIT: 413, RECOVERY_BUSY: 429 }[rejection] ?? 409;
    const io = script([() => failure(rejection, status)]), db = owner(io);
    await assert.rejects(db.resume(verified()), (e) => e instanceof RemoteError && e.code === rejection &&
      e.outcome === 'unresolved' && e.reference.ownerPlan.operation === INPUT.operation);
    assert.equal(io.calls.length, 1);
  }
  for (const method of ['inspect', 'observe']) {
    const io = script([() => { throw new Error('secret'); }]), db = owner(io);
    await assert.rejects(db[method](method === 'inspect' ? db.prepareInput(INPUT) : identity), (e) =>
      e instanceof ClientError && !(e instanceof UnknownError) && e.code === 'TRANSPORT');
    assert.equal(io.calls.length, 1);
  }
});

test('durable owner calls preserve one original deadline, abort and recovery timeout without dispatching an expired request', async (t) => {
  let now = 0, calls = 0;
  t.mock.method(performance, 'now', () => now);
  const original = JSON.stringify;
  t.mock.method(JSON, 'stringify', (value, ...rest) => {
    const result = original(value, ...rest);
    if (value?.operation === 'owner_prepare') now = 11;
    return result;
  });
  const db = owner({ fetch: () => { calls++; return success(observed('prepared')); } });
  await assert.rejects(db.prepare(db.prepareInput(INPUT), { timeoutMs: 10 }), (e) => e instanceof UnknownError && e.cause.code === 'DEADLINE');
  // Inner transport cannot observe whether its injected Fetch wrapper dispatched.
  // This remains conservative UNKNOWN, while the actual destination saw zero POSTs.
  assert.equal(calls, 0);
  now = 0;
  const controller = new AbortController(); controller.abort();
  await assert.rejects(db.inspect(db.prepareInput(INPUT), { signal: controller.signal }), code('ABORTED'));
  const io = script([() => { now = 11; return success(observed('active')); }]);
  const recovery = owner(io, { timeoutMs: 10, recoveryTimeoutMs: 20 });
  assert.equal((await recovery.resume(verified())).state, 'active');
  assert.equal(io.calls.length, 1);
});

test('original operation deadline and abort are checked again after a verified owner response', async (t) => {
  let now = 0;
  t.mock.method(performance, 'now', () => now);
  // Delay precisely between the low-level method's verified result and the
  // composition's exit. This does not replace its production transport.
  const claim = Client.prototype.ownerClaim;
  t.mock.method(Client.prototype, 'ownerClaim', async function (...args) {
    const result = await claim.apply(this, args); now = 11; return result;
  });
  const io = script([observed('claimed')]), db = owner(io);
  await assert.rejects(db.claim(verified(), { timeoutMs: 10 }), (e) => e instanceof UnknownError && e.cause.code === 'DEADLINE' &&
    e.reference.expectedWorkerInstance === '200' && e.reference.ownerPlan.descriptor_hash === 'a'.repeat(64));
  now = 0;
  const inspect = Client.prototype.ownerInspect;
  t.mock.method(Client.prototype, 'ownerInspect', async function (...args) {
    const result = await inspect.apply(this, args); now = 11; return result;
  });
  const readIo = script([observed('prepared')]), read = owner(readIo);
  await assert.rejects(read.inspect(read.prepareInput(INPUT), { timeoutMs: 10 }), code('DEADLINE'));
  now = 0;
  const controller = new AbortController(), observe = Client.prototype.ownerObserve;
  t.mock.method(Client.prototype, 'ownerObserve', async function (...args) {
    const result = await observe.apply(this, args); controller.abort(); return result;
  });
  const aborted = owner(script([observed('active')]));
  await assert.rejects(aborted.observe(identity, { signal: controller.signal }), code('ABORTED'));
});

test('legacy owner intent restore remains inspect-only and HEAD8 permanently blocks old nonce inference', async () => {
  const legacyIo = script([observed('claimed').status]), old = new OwnerClient({ ...OPTIONS, fetch: legacyIo.fetch });
  const intent = old.prepareTakeover(head(), takeover), restored = old.restoreIntent(old.saveIntent(intent));
  assert.equal((await old.inspect(restored)).state, 'blocked');
  await assert.rejects(old.reconcile(restored), (e) => e.code === 'INTENT_USED' && e.outcome === 'not_sent');
  invalid(() => old.prepareTakeover(observed('claimed').status, takeover));
  assert.equal(legacy.matchesBase(intent, observed('claimed').status), false);
  assert.equal(legacy.matchesTransition(intent, 'activate', observed('active').status), false);
  assert.equal(legacyIo.calls.length, 1);
});
