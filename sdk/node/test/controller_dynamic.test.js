import { test } from 'node:test';
import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { Buffer } from 'node:buffer';
import { OwnerController } from '../src/controller.js';
import { OwnerControllerFleet } from '../src/controller_fleet.js';
import { createControllerPolicy } from '../src/controller_policy.js';
import { controllerLineage, controllerRoutes, extendsLineage, retiredWorker } from '../src/controller_lineage.js';
import { config, policy, input } from './controller_policy.test.js';
import { A, B, OPTIONS, head, script, failure } from './owner_fixture.js';
import { observed, prepared } from './owner_plan_fixture.js';

const C = 'http://127.0.0.1:8125/v1';
const additional = { workerInstance: '300', endpoint: C, rank: 2 };
const expanded = (extra = {}) => policy({ workers: [...config().workers, additional], ...extra });
const entry = (p, previousPolicies = []) => ({ policy: p, previousPolicies, token: OPTIONS.token });
const turn = () => new Promise(setImmediate);
const owned = () => ({ async fetch() { throw new Error('unexpected network'); }, async close() {}, async quiesce() {} });
const clock = (t) => { let now = 0; t.mock.method(performance, 'now', () => now); return (value) => { now = value; }; };
const missing = () => failure('MISSING', 409);
const control = (p, history, io) => new OwnerController({ policy: p, previousPolicies: history, token: OPTIONS.token, fetch: io.fetch });

test('membership commitments preserve legacy bytes and permanently bind canonical explicit retirement', () => {
  const original = policy();
  assert.equal(policy({ retiredWorkers: [] }).canonical, original.canonical);
  assert.equal(retiredWorker(original, '100'), false);
  const next = expanded({ retiredWorkers: ['200', '100'] });
  assert.deepEqual(next.retiredWorkers, ['100', '200']);
  assert.equal(Object.isFrozen(next.retiredWorkers), true);
  assert.notEqual(next.digest, expanded().digest);
  assert.equal(retiredWorker(next, '100'), true); assert.equal(retiredWorker(next, '300'), false);
  for (const retiredWorkers of [null, ['100', '100'], ['999'], ['0'], ['100', '200', '300', '400'], [7]]) {
    assert.throws(() => expanded({ retiredWorkers }));
  }
  const replacement = expanded({ workers: [...config().workers, { ...additional, endpoint: A }], retiredWorkers: ['100'] });
  assert.deepEqual(controllerRoutes(replacement), [
    { workerInstance: '300', endpoint: A }, { workerInstance: '200', endpoint: B },
  ]);
  const retiredLast = policy({ workers: [{ workerInstance: '100', endpoint: A, rank: 0 },
    { workerInstance: '200', endpoint: A, rank: 1 }], retiredWorkers: ['200'] });
  assert.deepEqual(controllerRoutes(retiredLast), [{ workerInstance: '100', endpoint: A }]);
  assert.throws(() => expanded({ workers: [...config().workers, { ...additional, endpoint: A }] }));
});

test('complete history permits monotonic membership and rejects authority expansion, rebinding, rollback and omission', () => {
  const first = policy(), second = expanded(), third = expanded({ retiredWorkers: ['100'] });
  assert.deepEqual(controllerLineage(third, [first, second]), [first, second, third]);
  assert.equal(Object.isFrozen(controllerLineage(first)), true);
  extendsLineage([first, second], [first, second, third]);
  extendsLineage([first], [first]);
  assert.throws(() => extendsLineage([first, second], [first]));
  assert.throws(() => extendsLineage([first], [second]));
  assert.throws(() => controllerLineage(first, [first]));
  assert.throws(() => controllerLineage(first, null));
  assert.throws(() => controllerLineage(first, Array(17).fill(first)));
  for (const changes of [
    { principal: '8' }, { authorityId: 'other' }, { scope: { ...first.scope, tenant: '9' } },
    { modes: { takeover: false, activate: true, cancel: true } }, { recoveryTimeoutMs: 400 },
    { allowInsecureHttp: true }, { workers: [config().workers[1]] },
    { workers: [{ ...config().workers[0], endpoint: C }, config().workers[1]] },
    { workers: [{ ...config().workers[0], rank: 4 }, config().workers[1]] },
    { workers: [config().workers[0], { ...config().workers[1], rank: 3 }, additional] },
  ]) assert.throws(() => controllerLineage(policy(changes), [first]));
  assert.throws(() => controllerLineage(second, [first, third]));
  const ranked = policy({ workers: [{ workerInstance: '100', endpoint: A, rank: 1 },
    { workerInstance: '200', endpoint: B, rank: 3 }] });
  const inserted = policy({ workers: [...ranked.workers, additional] });
  assert.throws(() => controllerLineage(inserted, [ranked]));
  const workers = Array.from({ length: 200 }, (_, n) => ({ workerInstance: String(n + 1), rank: n,
    endpoint: `https://worker-${n}.example.test/v1` }));
  const large = Array.from({ length: 8 }, (_, n) => policy({ workers, metadataEndpoints: [`https://meta-${n}.example.test/v1`] }));
  assert.throws(() => controllerLineage(large.at(-1), large.slice(0, -1)));
});

test('explicit retirement starts a new guarded takeover without calling a replaced old endpoint', async (t) => {
  clock(t); const prior = policy(), next = expanded({ retiredWorkers: ['100'] }), h = head();
  const i = input(next, { mode: 'takeover', target_worker: '200' });
  const io = script([h, missing, h, { state: 'prepared', prepared: prepared(i) }]);
  const c = control(next, [prior], io), report = await c.tick();
  assert.equal(report.state, 'prepared');
  assert.deepEqual(io.calls.map(({ body }) => body.operation), ['status', 'owner_inspect', 'status', 'owner_prepare']);
  assert.equal(io.calls[2].body.expected_worker_instance, '200');
  assert.equal(io.calls.some(({ body }) => body.expected_worker_instance === '100'), false);
  assert.deepEqual(io.calls[3].body.input.nonces, next.nonces); await c.close();
});

test('historical claimed target retirement permits only original inspect and abort with no guarded claim or resume', async () => {
  for (const cancel of [true, false]) {
    const modes = { takeover: true, activate: true, cancel }, prior = policy({ modes });
    const next = expanded({ modes, retiredWorkers: ['200'] });
    const i = input(prior, { mode: 'takeover', target_worker: '200' }), old = observed('claimed', i);
    const replies = [old.status, old, old];
    if (cancel) replies.push(observed('aborted', i));
    const io = script(replies), c = control(next, [prior], io), report = await c.tick();
    assert.equal(report.reason, cancel ? 'VERIFIED_OWNER_OBSERVATION' : 'AUTOMATIC_CANCEL_DISABLED');
    assert.equal(io.calls.some(({ body }) => body.expected_worker_instance !== undefined), false);
    assert.equal(io.calls.some(({ body }) => ['execute', 'owner_claim', 'owner_resume', 'owner_prepare'].includes(body.operation)), false);
    if (cancel) assert.deepEqual(io.calls.at(-1).body.plan, old.prepared.reference);
    await c.close();
  }
});

test('retired unaccepted first winner is reverified and cancelled under its original recipe', async (t) => {
  const now = clock(t), prior = policy(), next = expanded({ retiredWorkers: ['100', '200'] });
  const i = input(prior, { mode: 'takeover', target_worker: '200' }), old = observed('prepared', i);
  const io = script([old.status, old, { state: 'prepared', prepared: prepared(i) },
    old.status, old, old, observed('cancelling', i)]), c = control(next, [prior], io);
  assert.equal((await c.tick()).state, 'prepared'); now(5000);
  assert.equal((await c.tick()).state, 'cancelling');
  const mutations = io.calls.filter(({ body }) => ['owner_prepare', 'owner_abort'].includes(body.operation));
  assert.deepEqual(mutations[0].body.input, i);
  assert.deepEqual(mutations[1].body.plan, old.prepared.reference);
  assert.equal(io.calls.some(({ body }) => body.expected_worker_instance !== undefined), false);
  await c.close();
});

test('old terminal policy is recognized read-only and an unretired old pending target retains its original guard', async (t) => {
  const now = clock(t), prior = policy(), next = expanded(), i = input(prior, { mode: 'takeover', target_worker: '200' });
  const terminal = observed('active', i), terminalIo = script([terminal.status, terminal, terminal.status]);
  const a = control(next, [prior], terminalIo); assert.equal((await a.tick()).state, 'healthy'); await a.close();
  const old = observed('claimed', i), io = script([old.status, old, old, old.status,
    old.status, old, old, old.status, terminal]), b = control(next, [prior], io);
  assert.equal((await b.tick()).reason, 'RECOVERY_REQUIRES_NEXT_TICK_BUDGET'); now(5000);
  assert.equal((await b.tick()).state, 'active_observed');
  assert.deepEqual(io.calls.at(-1).body.plan, old.prepared.reference);
  assert.equal(io.calls.at(-1).body.expected_worker_instance, '200'); await b.close();
  const foreign = script([old.status, old]), rejected = control(next, [], foreign);
  assert.equal((await rejected.tick()).reason, 'POLICY'); await rejected.close();
});

test('new target mismatch and revoked authority stay blocking and never refresh a guard', async () => {
  const prior = policy(), next = expanded({ retiredWorkers: ['100', '200'],
    workers: [...config().workers, { ...additional, endpoint: A }] });
  for (const code of ['TARGET_MISMATCH', 'DENIED']) {
    const io = script([head(), missing, () => failure(code, code === 'DENIED' ? 403 : 409)]);
    const c = control(next, [prior], io), report = await c.tick();
    assert.equal(report.state, 'blocked'); assert.equal(report.reason, code); assert.equal(report.mutations, 0);
    assert.equal(io.calls.at(-1).body.expected_worker_instance, '300'); await c.close();
  }
  const allRetired = policy({ retiredWorkers: ['100', '200'] }), io = script([head(), missing]);
  const c = control(allRetired, [prior], io);
  assert.equal((await c.tick()).reason, 'REGISTRY_RANK_EXHAUSTED'); await c.close();
});

test('fleet reload joins the original tick, pauses admission and atomically preserves every configured bound', async (t) => {
  const prior = policy(), next = expanded(), calls = []; let release;
  t.mock.method(OwnerController.prototype, 'tick', function () {
    calls.push(this.policy.digest); return new Promise((resolve) => { release = () => resolve({ state: 'healthy' }); });
  });
  const f = new OwnerControllerFleet({ entries: [entry(prior)], revision: '7', transport: owned() });
  assert.equal(f.revision, '7'); assert.equal(f.updating, false); assert.equal(f.poll().started, 1);
  const replacing = f.replace({ revision: '8', entries: [entry(next, [prior])] });
  assert.equal(f.updating, true); assert.equal(f.revision, '7'); assert.equal(f.poll().started, 0);
  await assert.rejects(f.replace({ revision: '9', entries: [entry(next, [prior])] }), { code: 'BACKPRESSURE' });
  await turn(); assert.equal(f.revision, '7'); release();
  assert.deepEqual(await replacing, { revision: '8', scopes: 1 });
  assert.equal(f.updating, false); assert.equal(f.snapshot().active, 0); assert.equal(f.poll().started, 1);
  assert.deepEqual(calls, [prior.digest, next.digest]); release(); await turn(); await f.close();
  await assert.rejects(f.replace({ revision: '9', entries: [entry(next, [prior])] }), { code: 'ABORTED' });
});

test('invalid or rolled-back reload keeps the live snapshot and known removed Scope history cannot be erased', async () => {
  const prior = policy(), next = expanded(), other = policy({ scope: { ...prior.scope, database: '99' } });
  const f = new OwnerControllerFleet({ entries: [entry(prior)], revision: '1', transport: owned() });
  for (const proposed of [
    { revision: '1', entries: [entry(prior)] }, { revision: '0', entries: [entry(prior)] },
    { revision: '2', entries: [entry(next)] }, { revision: '2', entries: [] },
    { revision: '2', entries: [entry(next, [prior])], extra: true },
    { revision: '2', entries: [{ ...entry(next, [prior]), token: 'bad' }] },
  ]) await assert.rejects(f.replace(proposed));
  assert.equal(f.revision, '1'); assert.equal(f.updating, false);
  await f.replace({ revision: '2', entries: [entry(next, [prior])] });
  await f.replace({ revision: '3', entries: [entry(other)] });
  await assert.rejects(f.replace({ revision: '4', entries: [entry(prior)] }));
  await f.replace({ revision: '4', entries: [entry(next, [prior])] });
  await f.close();
  const fixed = new OwnerControllerFleet({ entries: [entry(prior)] });
  assert.equal(fixed.revision, null);
  await assert.rejects(fixed.replace({ revision: '1', entries: [entry(prior)] })); await fixed.close();
});

test('retirement is coherent across Scopes and an endpoint can be reused only after the old incarnation retires', async () => {
  const prior = policy(), next = expanded({ retiredWorkers: ['100'], workers: [...config().workers, { ...additional, endpoint: A }] });
  const other = policy({ scope: { ...prior.scope, database: '99' } });
  assert.throws(() => new OwnerControllerFleet({ entries: [entry(next, [prior]), entry(other)], revision: '1' }));
  const otherRetired = policy({ scope: other.scope, retiredWorkers: ['100'] });
  const f = new OwnerControllerFleet({ entries: [entry(next, [prior]), entry(otherRetired, [other])], revision: '1' });
  await f.replace({ revision: '2', entries: [entry(next, [prior])] });
  await assert.rejects(f.replace({ revision: '3', entries: [entry(next, [prior]), entry(other)] }));
  await f.close();
});

test('shutdown racing a reload joins work and transport without installing the next revision', async (t) => {
  let release, closes = 0;
  t.mock.method(OwnerController.prototype, 'tick', () => new Promise((resolve) => { release = resolve; }));
  const prior = policy(), next = expanded(), transport = owned(); transport.close = async () => { closes++; };
  const f = new OwnerControllerFleet({ entries: [entry(prior)], revision: '1', transport });
  f.poll(); const updating = f.replace({ revision: '2', entries: [entry(next, [prior])] });
  const rejected = assert.rejects(updating, { code: 'ABORTED' }), closing = f.close();
  assert.equal(f.close(), closing); await turn(); assert.equal(closes, 0);
  release({ state: 'healthy' }); await rejected; await closing;
  assert.equal(closes, 1); assert.equal(f.revision, '1'); assert.equal(f.snapshot().active, 0);
});

test('joined uncertainty survives policy reloads and temporary Scope withdrawal without SQL replay', async (t) => {
  const now = clock(t), prior = policy(), next = expanded(), i = input(prior), old = observed('prepared', i);
  const io = script([old.status, old.status, missing, () => { throw new Error('lost reply'); },
    old.status, old.status, old, { state: 'prepared', prepared: prepared(i) }]);
  const transport = { fetch: io.fetch, async close() {}, async quiesce() {} }, f = new OwnerControllerFleet({ entries: [entry(prior)], revision: '1', transport });
  f.poll(); await turn(); const report = f.takeReports()[0]; assert.equal(report.pastUnknown, true);
  const other = policy({ scope: { ...prior.scope, database: '99' } });
  await f.replace({ revision: '2', entries: [entry(other)] });
  await f.replace({ revision: '3', entries: [entry(next, [prior])] }); now(5000);
  f.poll(); await turn(); const resumed = f.takeReports()[0];
  assert.equal(resumed.pastUnknown, true); assert.deepEqual(resumed.lastUncertainCall, report.lastUncertainCall);
  assert.equal(resumed.state, 'prepared'); assert.equal(io.calls.some(({ body }) => body.operation === 'execute'), false);
  await f.close();
  const closed = control(prior, [], script([])), fresh = control(prior, [], script([]));
  assert.throws(() => fresh.inheritUncertainty({})); assert.throws(() => fresh.inheritUncertainty(closed));
  await closed.close(); fresh.inheritUncertainty(closed); await fresh.close();
});

test('lifetime scope history is bounded even when active configurations are small', async (t) => {
  // Isolate the cardinality gate from the independently tested byte gate.
  t.mock.method(Buffer, 'byteLength', () => 1);
  const entries = (start, count) => Array.from({ length: count }, (_, n) => entry(policy({
    scope: { ...config().scope, database: String(start + n) } })));
  const f = new OwnerControllerFleet({ entries: entries(1, 128), revision: '1', transport: owned() });
  await assert.rejects(f.replace({ revision: '2', entries: entries(129, 1) }));
  assert.equal(f.revision, '1'); await f.close();
});

test('reload keeps admission closed until old network resources join, and a broken join stops the fleet', async () => {
  const prior = policy(); let finish; const network = owned();
  network.quiesce = () => new Promise((resolve) => { finish = resolve; });
  const f = new OwnerControllerFleet({ entries: [entry(prior)], revision: '1', transport: network });
  const updating = f.replace({ revision: '2', entries: [entry(prior)] }); await turn();
  assert.equal(f.revision, '1'); assert.equal(f.updating, true); assert.equal(f.poll().started, 0);
  finish(); await updating; assert.equal(f.revision, '2'); await f.close();
  const broken = owned(); broken.quiesce = async () => { throw new Error('broken ownership contract'); };
  const failed = new OwnerControllerFleet({ entries: [entry(prior)], revision: '1', transport: broken });
  await assert.rejects(failed.replace({ revision: '2', entries: [entry(prior)] }), /broken ownership/);
  assert.equal(failed.snapshot().closed, true); assert.throws(() => failed.poll(), { code: 'ABORTED' }); await failed.close();
  assert.throws(() => new OwnerControllerFleet({ entries: [entry(prior)], revision: '1',
    transport: { fetch: async () => {}, close: async () => {} } }));
});
