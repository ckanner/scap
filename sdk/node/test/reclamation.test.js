import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Client, ClientError, RemoteError, UnknownError } from '../src/client.js';
import * as wire from '../src/wire.js';
import { head, SCOPE, clone, success, failure } from './owner_fixture.js';

const OPTIONS = { endpoint: 'http://127.0.0.1:8123/v1', token: 'synthetic-maintenance-only-credential', scope: SCOPE, principal: '7' };
const HASH = 'a'.repeat(64);
const physical = (active = '1', allocated = '2') => ({ active_generation: active, allocated_through: allocated, plan: null, sweep: null });
function planned(phase = 'copying') {
  return head({ head_serial: phase === 'copying' ? '11' : '12', active: false,
    storage: { ...physical(), plan: { serial: '11', source: '1', target: '2', phase } } });
}
const promoted = () => head({ head_serial: '13', active: false, storage: physical('2', '2') });
const aborted = () => head({ head_serial: '12', active: false, storage: physical() });
function checkpoint() {
  return head({ head_serial: '20', storage: { ...physical('2', '2'), sweep: {
    serial: '20', generation: '1', next_after: null, exhausted: true,
    pending: 1, applied: 0, observed_absent: 0, condition_mismatch: 0,
  } } });
}
const report = (status = checkpoint(), changes = {}) => ({ status, generation: '1', scanned: 1, next_after: null, exhausted: true, ...changes });
const cases = [
  ['compactBegin', { expectedHeadSerial: '10' }, 'compact_begin', 'control', () => planned()],
  ['compactCopy', { planSerial: '11' }, 'compact_copy', 'recovery', () => planned('sealed')],
  ['compactPromote', { planSerial: '11' }, 'compact_promote', 'control', promoted],
  ['compactAbort', { planSerial: '11' }, 'compact_abort', 'control', aborted],
  ['gcPrepare', { expectedHeadSerial: '19', generation: '1', after: null }, 'gc_prepare', 'recovery', () => report()],
  ['gcResume', { batchSerial: '20' }, 'gc_resume', 'recovery', () => report(head({ head_serial: '22', storage: physical('2', '2') }))],
];
const invalid = (fn) => assert.throws(fn, (error) => error instanceof ClientError && error.code === 'INVALID');

function mutation(value, change, decode = (raw) => wire.status(raw, SCOPE)) {
  const bad = clone(value); change(bad); invalid(() => decode(bad));
}

test('physical status validates bounded plans without exposing keys, ETags or captured roots', () => {
  const plain = promoted();
  assert.deepEqual(wire.status(plain, SCOPE), plain);
  mutation(plain, (s) => s.head_serial = '0');
  mutation(plain, (s) => s.head_serial = '9');
  mutation(plain, (s) => s.storage.active_generation = '0');
  mutation(plain, (s) => s.storage.allocated_through = '1');
  mutation(plain, (s) => s.storage.allocated_through = '14');
  for (const phase of ['copying', 'sealed']) {
    const value = planned(phase), decoded = wire.status(value, SCOPE);
    assert.deepEqual(decoded, value);
    assert.equal(Object.isFrozen(decoded.storage), true);
    assert.equal(Object.isFrozen(decoded.storage.plan), true);
  }
  for (const change of [
    (s) => s.active = true, (s) => s.lifecycle = 'maintenance',
    (s) => s.storage.sweep = checkpoint().storage.sweep,
    (s) => s.storage.plan.serial = '12', (s) => s.storage.plan.source = '2',
    (s) => s.storage.plan.target = '3', (s) => { s.storage.allocated_through = '1'; s.storage.plan.target = '1'; },
    (s) => s.storage.plan.phase = 'done', (s) => s.storage.plan.etag = 'forbidden',
  ]) mutation(planned(), change);
  assert.equal(wire.afterHash(null), null); assert.equal(wire.afterHash(HASH), HASH);
  for (const after of ['', 'A'.repeat(64), 'storage/1/objects/' + HASH, {}, 1]) invalid(() => wire.afterHash(after));
});

test('sweep status validates generation retirement, full-width serials and bounded disposition counts', () => {
  const value = checkpoint();
  assert.equal(Object.isFrozen(wire.status(value, SCOPE).storage.sweep), true);
  for (const change of [
    (s) => s.lifecycle = 'deleted',
    (s) => s.storage.sweep.serial = '21', (s) => s.storage.sweep.generation = '2',
    (s) => s.storage.sweep.generation = '3', (s) => s.storage.sweep.next_after = 'bad',
    (s) => s.storage.sweep.exhausted = 1, (s) => s.storage.sweep.pending = 0,
    (s) => s.storage.sweep.exhausted = false, (s) => s.storage.sweep.next_after = HASH,
    (s) => { s.storage.sweep.pending = 32; s.storage.sweep.applied = 1; },
  ]) mutation(value, change);
  for (const count of ['1', .5, -1, 33]) mutation(value, (s) => s.storage.sweep.applied = count);
  const bounded = checkpoint();
  bounded.storage.sweep = { ...bounded.storage.sweep, pending: 8, applied: 8, observed_absent: 8,
    condition_mismatch: 8, next_after: HASH, exhausted: false };
  assert.deepEqual(wire.status(bounded, SCOPE), bounded);
});

test('sweep reports validate their page and persisted checkpoint while allowing all-missing pages', () => {
  const decode = (value) => wire.sweepReport(value, SCOPE);
  assert.deepEqual(decode(report()), report());
  const empty = report(promoted(), { scanned: 0 });
  assert.deepEqual(decode(empty), empty);
  mutation(empty, (r) => r.status.lifecycle = 'deleted', decode);
  const missing = report(promoted(), { scanned: 32, next_after: HASH, exhausted: false });
  assert.deepEqual(decode(missing), missing);
  const laterPlan = planned();
  laterPlan.storage.active_generation = '2'; laterPlan.storage.allocated_through = '3';
  laterPlan.storage.plan.source = '2'; laterPlan.storage.plan.target = '3';
  assert.deepEqual(decode(report(laterPlan)), report(laterPlan));
  mutation(report(laterPlan), (r) => r.generation = '3', decode);
  const continued = checkpoint();
  continued.storage.sweep.next_after = HASH; continued.storage.sweep.exhausted = false;
  const continuedReport = report(continued, { next_after: HASH, exhausted: false });
  assert.deepEqual(decode(continuedReport), continuedReport);
  mutation(continuedReport, (r) => r.next_after = 'b'.repeat(64), decode);
  for (const change of [
    (r) => r.generation = '2', (r) => r.generation = '3',
    (r) => r.next_after = '?', (r) => r.exhausted = 'yes',
    (r) => r.next_after = HASH, (r) => r.exhausted = false,
    (r) => { r.status.storage.active_generation = '3'; r.status.storage.allocated_through = '3'; r.generation = '2'; },
  ]) mutation(report(), change, decode);
  for (const scanned of [-1, 33, .5, '1']) mutation(report(), (r) => r.scanned = scanned, decode);
});

test('every explicit maintenance method sends one bounded request with the correct admission and result binding', async () => {
  for (const [method, input, operation, admission, response] of cases) {
    const seen = [];
    const client = new Client({ ...OPTIONS, fetch: async (_url, init) => {
      seen.push(init); return success(response());
    } });
    assert.deepEqual(await client[method](input), response());
    assert.equal(seen.length, 1);
    assert.equal(seen[0].headers['x-scap-admission'], admission);
    const body = JSON.parse(seen[0].body);
    assert.equal(body.operation, operation); assert.deepEqual(body.scope, SCOPE);
    assert.equal(body.version, 1);
    if (input.expectedHeadSerial !== undefined) assert.equal(body.expected_head_serial, input.expectedHeadSerial);
    if (input.planSerial !== undefined) assert.equal(body.plan_serial, input.planSerial);
    if (input.batchSerial !== undefined) assert.equal(body.batch_serial, input.batchSerial);
    if (method === 'gcPrepare') { assert.equal(body.generation, '1'); assert.equal(body.after, null); }
  }
  for (const [method, input, , admission, response] of cases.filter((row) => row[3] === 'recovery')) {
    const client = new Client({ ...OPTIONS, timeoutMs: 1, recoveryTimeoutMs: 500,
      fetch: async () => { await new Promise((resolve) => setTimeout(resolve, 5)); return success(response()); } });
    assert.equal(admission, 'recovery'); await client[method](input);
  }
  for (const [scanned, exhausted, after] of [[0, true, null], [32, false, HASH]]) {
    const response = report(head({ head_serial: '19', storage: physical('2', '2') }), { scanned, exhausted, next_after: after });
    const client = new Client({ ...OPTIONS, fetch: async () => success(response) });
    assert.deepEqual(await client.gcPrepare({ expectedHeadSerial: '19', generation: '1', after }), response);
  }
});

test('maintenance validation rejects arbitrary delete targets and malformed serials before any transport', () => {
  const client = new Client({ ...OPTIONS, fetch: () => assert.fail('unexpected network') });
  for (const [method, input] of cases) {
    invalid(() => client[method]({}));
    invalid(() => client[method]({ ...input, keys: [HASH] }));
    const key = Object.keys(input)[0];
    invalid(() => client[method]({ ...input, [key]: '0' }));
    invalid(() => client[method]({ ...input, [key]: 1 }));
  }
  invalid(() => client.gcPrepare({ expectedHeadSerial: '1', generation: '0', after: null }));
  invalid(() => client.gcPrepare({ expectedHeadSerial: '1', generation: '2', after: 'prefix/' }));
  invalid(() => client.gcPrepare({ expectedHeadSerial: '1', generation: '2' }));
});

test('uncertain maintenance never retries and retains the original serial, generation and page frontier', async () => {
  for (const [method, input, operation] of cases) {
    let calls = 0;
    const client = new Client({ ...OPTIONS, fetch: () => { ++calls; throw new Error('private transport text'); } });
    await assert.rejects(client[method](input), (error) => {
      assert.ok(error instanceof UnknownError); assert.equal(error.reference.operation, operation);
      assert.deepEqual(error.reference.scope, SCOPE);
      if (input.expectedHeadSerial) assert.equal(error.reference.expectedHeadSerial, input.expectedHeadSerial);
      if (input.planSerial) assert.equal(error.reference.planSerial, input.planSerial);
      if (input.batchSerial) assert.equal(error.reference.batchSerial, input.batchSerial);
      if (method === 'gcPrepare') { assert.equal(error.reference.storageGeneration, '1'); assert.equal(error.reference.after, null); }
      return true;
    });
    assert.equal(calls, 1);
  }
  for (const code of ['SNAPSHOT_EXPIRED', 'GC_DISABLED', 'GC_UNSUPPORTED']) {
    let calls = 0;
    const client = new Client({ ...OPTIONS, fetch: () => { ++calls; return failure(code); } });
    await assert.rejects(client.gcResume({ batchSerial: '20' }), (error) => error instanceof RemoteError && error.code === code && error.outcome === 'unresolved');
    assert.equal(calls, 1);
  }
});

test('a valid-looking response for another maintenance transition remains UNKNOWN', async () => {
  const wrong = [
    ['compactBegin', { expectedHeadSerial: '10' }, promoted()],
    ['compactBegin', { expectedHeadSerial: '10' }, head({ head_serial: '11', storage: physical() })],
    ['compactBegin', { expectedHeadSerial: '10' }, { ...planned(), storage: { ...planned().storage, plan: { ...planned().storage.plan, serial: '10' } } }],
    ['compactBegin', { expectedHeadSerial: '10' }, { ...planned('sealed'), head_serial: '11' }],
    ['compactCopy', { planSerial: '11' }, promoted()],
    ['compactCopy', { planSerial: '10' }, planned('sealed')],
    ['compactCopy', { planSerial: '11' }, planned()],
    ['compactPromote', { planSerial: '20' }, promoted()],
    ['compactPromote', { planSerial: '10' }, planned()],
    ['compactPromote', { planSerial: '11' }, checkpoint()],
    ['compactPromote', { planSerial: '11' }, aborted()],
    ['compactPromote', { planSerial: '11' }, { ...promoted(), active: true }],
    ['compactPromote', { planSerial: '11' }, { ...promoted(), lifecycle: 'maintenance' }],
    ['compactAbort', { planSerial: '20' }, aborted()],
    ['compactAbort', { planSerial: '10' }, planned()],
    ['compactAbort', { planSerial: '11' }, checkpoint()],
    ['compactAbort', { planSerial: '11' }, promoted()],
    ['compactAbort', { planSerial: '11' }, { ...aborted(), active: true }],
    ['compactAbort', { planSerial: '11' }, { ...aborted(), lifecycle: 'deleted' }],
    ['gcPrepare', { expectedHeadSerial: '18', generation: '1', after: null }, report()],
    ['gcPrepare', { expectedHeadSerial: '19', generation: '1', after: null }, report(promoted(), { scanned: 0 })],
    ['gcPrepare', { expectedHeadSerial: '19', generation: '1', after: null }, report({ ...checkpoint(), storage: { ...checkpoint().storage, sweep: { ...checkpoint().storage.sweep, serial: '19' } } })],
    ['gcPrepare', { expectedHeadSerial: '19', generation: '1', after: null }, report(head({ head_serial: '19', storage: physical('3', '3') }), { generation: '2', scanned: 0 })],
    ['gcResume', { batchSerial: '21' }, report(checkpoint())],
    ['gcResume', { batchSerial: '19' }, report(checkpoint())],
  ];
  for (const [method, input, response] of wrong) {
    let calls = 0;
    const client = new Client({ ...OPTIONS, fetch: () => { ++calls; return success(response); } });
    await assert.rejects(client[method](input), (error) => error instanceof UnknownError);
    assert.equal(calls, 1);
  }
});
