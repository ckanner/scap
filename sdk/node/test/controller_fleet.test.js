import { test } from 'node:test';
import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { OwnerControllerFleet } from '../src/controller_fleet.js';
import { OwnerController } from '../src/controller.js';
import { policy, config } from './controller_policy.test.js';
import { createControllerPolicy } from '../src/controller_policy.js';
import { SCOPE, OPTIONS, A, B } from './owner_fixture.js';

const entry = (id, tenant = '2', extra = {}) => ({ policy: policy({ ...extra,
  scope: { ...SCOPE, database: String(id), tenant } }), token: OPTIONS.token });
const turn = () => new Promise(setImmediate);
const transport = () => ({ closed: false, async fetch() { throw new Error('unexpected I/O'); },
  async close() { this.closed = true; } });
function deferredTicks(t) {
  const calls = [], due = new Map();
  t.mock.getter(OwnerController.prototype, 'nextTickAt', function () { return due.get(this.policy.scope.database) ?? 0; });
  t.mock.method(OwnerController.prototype, 'tick', function () {
    return new Promise((resolve, reject) => calls.push({ policy: this.policy,
      resolve: () => { due.set(this.policy.scope.database, performance.now() + 5000); resolve(Object.freeze({ scope: this.policy.scope, state: 'healthy' })); }, reject }));
  });
  return calls;
}

test('fleet retains at most eight ticks, four per tenant, with fair slots and no queued rounds', async (t) => {
  const calls = deferredTicks(t), owned = transport();
  const fleet = new OwnerControllerFleet({ entries: Array.from({ length: 12 }, (_, n) => entry(1000 + n, n < 6 ? '2' : '3')), transport: owned });
  assert.deepEqual(fleet.snapshot(), { closed: false, scopes: 12, active: 0, recoveries: 0, pendingReports: 0 });
  assert.equal(fleet.poll().started, 8); assert.equal(fleet.poll().started, 0); assert.equal(calls.length, 8);
  assert.equal(calls.filter((x) => x.policy.scope.tenant === '2').length, 4);
  assert.equal(calls.filter((x) => x.policy.scope.tenant === '3').length, 4);
  calls[0].resolve(); calls[1].resolve(); await turn();
  assert.equal(fleet.snapshot().active, 6); assert.equal(fleet.poll().started, 2);
  assert.equal(calls[8].policy.scope.tenant, '2'); assert.equal(calls[9].policy.scope.tenant, '2');
  for (const call of calls.slice(2)) call.resolve(); await turn();
  assert.equal(fleet.snapshot().active, 0); assert.equal(fleet.snapshot().pendingReports, 10);
  assert.equal(fleet.poll().started, 2);
  assert.deepEqual(calls.slice(10, 12).map((x) => x.policy.scope.database), ['1010', '1011']);
  for (const call of calls.slice(10)) call.resolve(); await turn();
  assert.equal(fleet.snapshot().pendingReports, 12);
  const reports = fleet.takeReports(); assert.equal(reports.length, 12); assert.equal(Object.isFrozen(reports), true);
  assert.equal(fleet.takeReports().length, 0); assert.equal(fleet.snapshot().pendingReports, 0);
  await fleet.close(); assert.equal(owned.closed, true); await assert.rejects(async () => fleet.poll(), { code: 'ABORTED' });
});

test('one fleet recovery slot is held to tick completion, and close joins every owned operation before transport', async (t) => {
  const calls = deferredTicks(t), original = Object.getOwnPropertyDescriptor(OwnerController.prototype, 'needsRecovery');
  Object.defineProperty(OwnerController.prototype, 'needsRecovery', { configurable: true, get() { return true; } });
  t.after(() => Object.defineProperty(OwnerController.prototype, 'needsRecovery', original));
  const owned = transport(), fleet = new OwnerControllerFleet({ entries: [entry(1), entry(2), entry(3)], transport: owned });
  assert.equal(fleet.poll().started, 1); assert.equal(fleet.snapshot().recoveries, 1); assert.equal(fleet.poll().started, 0);
  calls[0].resolve(); await turn(); assert.equal(fleet.snapshot().recoveries, 0);
  assert.equal(fleet.poll().started, 1); assert.equal(calls[1].policy.scope.database, '2');
  const closing = fleet.close(); assert.equal(fleet.close(), closing);
  await turn(); assert.equal(owned.closed, false); assert.equal(fleet.snapshot().closed, true);
  calls[1].resolve(); await closing;
  assert.equal(owned.closed, true); assert.equal(fleet.snapshot().active, 0); assert.equal(fleet.snapshot().recoveries, 0);
});

test('unexpected controller rejection is bounded and sanitized without leaking credentials or adding work', async (t) => {
  const calls = deferredTicks(t), owned = transport(), fleet = new OwnerControllerFleet({ entries: [entry(1)], transport: owned });
  fleet.poll(); calls[0].reject(new Error(OPTIONS.token)); await turn();
  const [report] = fleet.takeReports(); assert.equal(report.reason, 'CONTROLLER_FAILURE');
  assert.equal(JSON.stringify(report).includes(OPTIONS.token), false); assert.equal(fleet.snapshot().active, 0);
  await fleet.close();
});

test('fleet uses each Scope cadence and the default owned transport can close without creating sockets', async (t) => {
  t.mock.getter(OwnerController.prototype, 'nextTickAt', () => Number.MAX_SAFE_INTEGER);
  const fleet = new OwnerControllerFleet({ entries: [entry(1)] });
  assert.equal(fleet.poll().started, 0); assert.equal(fleet.snapshot().active, 0); await fleet.close();
});

test('fleet configuration bounds Scope count, total canonical bytes, routes and exact incarnation mapping', () => {
  const owned = transport();
  for (const entries of [[], Array(129).fill(entry(1)), [entry(1), entry(1)]]) {
    assert.throws(() => new OwnerControllerFleet({ entries, transport: owned }));
  }
  assert.throws(() => new OwnerControllerFleet({ entries: [entry(1)], transport: null }));
  assert.throws(() => new OwnerControllerFleet({ entries: [entry(1)], transport: {} }));
  assert.throws(() => new OwnerControllerFleet({ entries: [{ policy: policy(), token: OPTIONS.token, extra: true }], transport: owned }));
  const large = Array.from({ length: 100 }, (_, i) => ({ workerInstance: String(i + 1), rank: i,
    endpoint: `https://worker-${i}.example.test/v1` }));
  assert.throws(() => new OwnerControllerFleet({ entries: Array.from({ length: 8 }, (_, i) => entry(i + 1, '2', { workers: large })), transport: owned }));
  const many = (start) => Array.from({ length: 200 }, (_, i) => ({ workerInstance: String(start + i), rank: i,
    endpoint: `https://w${start + i}.test/v1` }));
  assert.throws(() => new OwnerControllerFleet({ entries: [entry(1, '2', { workers: many(1) }), entry(2, '2', { workers: many(1000) })], transport: owned }));
  for (const workers of [
    [{ workerInstance: '100', rank: 0, endpoint: 'https://changed.example/v1' }, { workerInstance: '200', rank: 1, endpoint: B }],
    [{ workerInstance: '300', rank: 0, endpoint: A }, { workerInstance: '200', rank: 1, endpoint: B }],
    [{ workerInstance: '100', rank: 2, endpoint: A }, { workerInstance: '200', rank: 1, endpoint: B }],
  ]) assert.throws(() => new OwnerControllerFleet({ entries: [entry(1), entry(2, '2', { workers })], transport: owned }));
  assert.throws(() => new OwnerControllerFleet({ entries: [{ policy: createControllerPolicy(config()), token: '' }], transport: owned }));
});

test('fleet dispatches only real SDK control requests through its owned transport and honors completed tick cadence', async () => {
  const configured = entry(1), calls = [], owned = transport();
  owned.fetch = async (url, init) => {
    const body = JSON.parse(init.body); calls.push({ url, body });
    assert.equal(body.operation, 'status');
    const value = { scope: configured.policy.scope, revision: '10', head_serial: '10', owner_plan: null,
      storage: { active_generation: '1', allocated_through: '1', plan: null, sweep: null, terminal: null },
      sequence: '0', owner_epoch: '2', owner_instance: '100', active: true, auth_epoch: '1', lifecycle: 'ready',
      request_epoch: '3', max_bytes: null, retention: { max_entries: 4096, max_result_bytes: '268435456', oldest_epoch: '1' },
      transition: { revision: '10', nonce: '9' } };
    return new Response(JSON.stringify({ ok: true, value }), { status: 200, headers: { 'content-type': 'application/json' } });
  };
  const fleet = new OwnerControllerFleet({ entries: [configured], transport: owned });
  assert.equal(fleet.poll().started, 1); await turn();
  assert.equal(fleet.snapshot().active, 0); assert.equal(fleet.takeReports()[0].state, 'healthy');
  assert.equal(calls.length, 2); assert.equal(calls[1].body.expected_worker_instance, '100');
  assert.equal(fleet.poll().started, 0); await fleet.close(); assert.equal(owned.closed, true);
});
