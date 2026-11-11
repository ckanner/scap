import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Client, ClientError, UnknownError } from '../src/client.js';
import * as wire from '../src/snapshot_wire.js';
import { A, OPTIONS, script, success, failure } from './owner_fixture.js';
import { marker, INPUT as OWNER_INPUT } from './owner_plan_fixture.js';
import { SCOPE, INPUT, LIMITS, clone, prepared, entry, observed, listed } from './snapshot_fixture.js';

const client = (io, extra = {}) => new Client({ endpoint: A, token: OPTIONS.token, scope: SCOPE, principal: '7', fetch: io.fetch, ...extra });
const invalid = (fn) => assert.throws(fn, (error) => error instanceof ClientError && error.code === 'INVALID');
const identity = { creator: INPUT.creator, operation: INPUT.operation };
const decode = (value) => wire.observation(value, SCOPE, identity, wire.input(INPUT));
const mutate = (value, change, check) => { const bad = clone(value); change(bad); invalid(() => check(bad)); };

test('snapshot intentions persist exact counters and scope before one-shot preparation', async () => {
  const io = script([prepared()]), db = client(io), mutable = clone(INPUT), saved = db.prepareSnapshotInput(mutable);
  mutable.label = 'different';
  assert.deepEqual(saved.input, INPUT); assert.equal(io.calls.length, 0);
  for (const value of [saved, saved.scope, saved.input]) assert.ok(Object.isFrozen(value));
  const text = db.saveSnapshotInput(saved);
  assert.equal(text.includes(OPTIONS.token), false);
  const restored = db.restoreSnapshotInput(text);
  const result = await db.snapshotPrepare(restored);
  assert.deepEqual(result, prepared());
  assert.equal(wire.checkPrepared(result, SCOPE), result);
  assert.deepEqual(io.calls[0].body, { version: 1, scope: SCOPE, operation: 'snapshot_prepare', input: INPUT });
  assert.equal(io.calls[0].init.headers['x-scap-admission'], 'control');
  invalid(() => db.saveSnapshotInput(clone(saved)));
  invalid(() => db.snapshotPrepare(clone(saved)));
  invalid(() => db.snapshotCapture(clone(result)));
  const foreign = client(script([]), { scope: { ...SCOPE, database: '99' } });
  invalid(() => foreign.saveSnapshotInput(saved)); invalid(() => foreign.snapshotRelease(result));
  invalid(() => foreign.restoreSnapshotInput(text));
  for (const value of [null, 'x'.repeat(16385), '{', text.replace('"version":1', '"version":1,"version":1')]) invalid(() => db.restoreSnapshotInput(value));
  for (const change of [(x) => x.version = 2, (x) => x.extra = true, (x) => x.input.operation = '00']) {
    const bad = JSON.parse(text); change(bad); invalid(() => db.restoreSnapshotInput(JSON.stringify(bad)));
  }
});

test('snapshot inputs reject malformed labels, rounded counters and impossible descriptor geometry', () => {
  for (const label of [null, '', '\n', 'é'.repeat(65), '\ud800']) mutate(INPUT, (x) => x.label = label, wire.input);
  assert.equal(wire.input({ ...INPUT, label: 'é'.repeat(64) }).label.length, 64);
  for (const key of ['creator', 'operation', 'expected_revision', 'expected_head_serial']) {
    for (const value of [0, '0', '01', '18446744073709551616']) mutate(INPUT, (x) => x[key] = value, wire.input);
  }
  mutate(INPUT, (x) => x.expected_revision = '16', wire.input);
  const check = (x) => wire.preparation(x, SCOPE, wire.input(INPUT));
  for (const change of [(x) => x.scope.tenant = '9', (x) => x.reference.creator = '8',
    (x) => x.reference.operation = '82', (x) => x.reference.descriptor_hash = 'A'.repeat(64),
    (x) => x.reference.descriptor_hash = 1, (x) => x.reference.capture_serial = '17',
    (x) => x.point.source_revision = '9', (x) => x.input.label = 'changed',
    (x) => x.point.data_root = '', (x) => x.point.page_count = 1.5,
    (x) => x.point.page_count = -1, (x) => x.point.page_count = 4294967295]) mutate(prepared(), change, check);
  const empty = prepared(); empty.point.page_count = 0; empty.point.sequence = '0';
  assert.equal(check(empty).point.page_count, 0);
  assert.deepEqual(wire.identity(identity), identity);
  for (const value of [{ max_points: -1, max_logical_bytes: '0' }, { max_points: 1.1, max_logical_bytes: '0' },
    { max_points: 65, max_logical_bytes: '0' }, { max_points: 64, max_logical_bytes: '1125899906318337' }]) invalid(() => wire.limits(value));
  assert.deepEqual(wire.limits({ max_points: 0, max_logical_bytes: '0' }), { max_points: 0, max_logical_bytes: '0' });
});

test('snapshot observations distinguish present retention, release evidence and unresolved historical outcome', () => {
  for (const state of ['prepared', 'retained', 'released_observed', 'fenced']) {
    const value = observed(state), result = decode(value);
    assert.deepEqual(result, value); assert.equal(wire.checkPrepared(result.prepared, SCOPE), result.prepared);
    for (const object of [result, result.prepared, result.prepared.reference, result.prepared.point]) assert.ok(Object.isFrozen(object));
  }
  const historical = observed('released_observed'); historical.status.lifecycle = 'deleted'; historical.status.active = false;
  historical.status.storage.terminal = { serial: '17' };
  assert.equal(decode(historical).state, 'released_observed');
  const unbranded = wire.observation(observed(), SCOPE, identity);
  invalid(() => wire.checkPrepared(unbranded.prepared, SCOPE));
  mutate(observed(), (x) => x.prepared.reference.operation = '82', decode);
  for (const change of [(x) => x.state = 'committed', (x) => x.accepted = null,
    (x) => x.accepted.reference.descriptor_hash = 'c'.repeat(64),
    (x) => x.accepted.point.data_root = 'c'.repeat(64), (x) => x.accepted.label = 'changed',
    (x) => x.accepted.point.source_revision = '16', (x) => x.status.head_serial = '15',
    (x) => { x.status.revision = '9'; x.status.transition.revision = '9'; }, (x) => x.status.sequence = '1',
    (x) => { x.status.lifecycle = 'deleted'; x.status.active = false; x.status.storage.terminal = { serial: '16' }; }]) mutate(observed(), change, decode);
  mutate(observed('released_observed'), (x) => x.status.head_serial = '16', decode);
  mutate(observed('fenced'), (x) => x.status.head_serial = '15', decode);
  const stale = observed('prepared');
  for (const change of [(x) => { x.status.revision = '11'; x.status.transition.revision = '11'; },
    (x) => x.status.head_serial = '16', (x) => { x.status.lifecycle = 'maintenance'; x.status.active = false; },
    (x) => { x.status.storage.allocated_through = '2'; x.status.storage.plan = { serial: '15', source: '1', target: '2', phase: 'copying' }; },
    (x) => { x.status.storage.allocated_through = '2'; x.status.storage.sweep = { serial: '15', generation: '2', next_after: null,
      exhausted: true, pending: 1, applied: 0, observed_absent: 0, condition_mismatch: 0 }; }]) mutate(stale, change, decode);
  const previous = { ...OWNER_INPUT, expected_revision: '7', expected_head_serial: '12', target_worker: '100' };
  const settled = observed('prepared'); settled.status.owner_plan = marker('active', previous);
  assert.equal(decode(settled).state, 'prepared');
  const pending = observed('prepared'); pending.status.owner_plan = marker('claimed', { ...previous, expected_revision: '9', expected_head_serial: '14' });
  pending.status.owner_epoch = pending.status.owner_plan.phase.owner_epoch; pending.status.active = false;
  invalid(() => decode(pending));
});

test('snapshot listing enforces complete sorted identities and historical gross bounds independently of current quota', () => {
  assert.deepEqual(wire.listing(listed(), SCOPE), listed());
  const legacy = listed([], null); assert.deepEqual(wire.listing(legacy, SCOPE), legacy);
  const quota = listed(); quota.status.max_bytes = '4096';
  assert.equal(wire.listing(quota, SCOPE).snapshots[0].point.page_count, 3);
  for (const change of [(x) => x.snapshots = {}, (x) => x.snapshots = Array.from({ length: 65 }, entry),
    (x) => x.limits = null, (x) => x.limits.max_points = 0, (x) => x.limits.max_logical_bytes = '4096',
    (x) => { x.status.lifecycle = 'deleted'; x.status.active = false; x.status.storage.terminal = { serial: '20' }; }]) mutate(listed(), change, (x) => wire.listing(x, SCOPE));
  const second = entry(); second.reference.capture_serial = '17'; second.reference.operation = '82'; second.label = 'next';
  const two = listed([entry(), second]); assert.equal(wire.listing(two, SCOPE).snapshots.length, 2);
  for (const change of [(x) => x.snapshots.reverse(), (x) => x.snapshots[1].reference.operation = '81',
    (x) => x.snapshots[1].label = 'before migration']) mutate(two, change, (x) => wire.listing(x, SCOPE));
  const terminal = listed([], LIMITS); terminal.status.lifecycle = 'deleted'; terminal.status.active = false;
  terminal.status.storage.terminal = { serial: '20' }; assert.equal(wire.listing(terminal, SCOPE).snapshots.length, 0);
});

test('snapshot client uses fixed references and never turns identity-only observation into mutation authority', async () => {
  const io = script([prepared(), observed('prepared'), observed(), observed('released_observed'), observed(), listed()]), db = client(io);
  const saved = db.prepareSnapshotInput(INPUT), point = await db.snapshotPrepare(saved);
  assert.equal((await db.snapshotInspect(saved)).state, 'prepared');
  assert.equal((await db.snapshotCapture(point)).state, 'retained');
  assert.equal((await db.snapshotRelease(point)).state, 'released_observed');
  const observation = await db.snapshotObserve(identity);
  invalid(() => db.snapshotRelease(observation.prepared));
  assert.deepEqual(await db.snapshotList(), listed());
  assert.deepEqual(io.calls.map((x) => x.body.operation), ['snapshot_prepare', 'snapshot_inspect', 'snapshot_capture', 'snapshot_release', 'snapshot_inspect', 'snapshot_list']);
  for (const call of io.calls.slice(2, 4)) assert.deepEqual(call.body.reference, prepared().reference);
  const swapped = observed(); swapped.prepared.reference.descriptor_hash = swapped.accepted.reference.descriptor_hash = 'c'.repeat(64);
  const broken = client(script([prepared(), swapped]));
  const fixed = await broken.snapshotPrepare(broken.prepareSnapshotInput(INPUT));
  await assert.rejects(broken.snapshotCapture(fixed), (e) => e instanceof UnknownError && e.reference.snapshotReference.descriptor_hash === 'a'.repeat(64));
});

test('snapshot mutation loss is UNKNOWN with original intent and read loss does not dispatch another request', async () => {
  for (const operation of ['snapshotPrepare', 'snapshotCapture', 'snapshotRelease', 'setSnapshotLimits']) {
    const io = script([prepared(), () => { throw new Error('lost response'); }]), db = client(io);
    const saved = db.prepareSnapshotInput(INPUT), point = await db.snapshotPrepare(saved);
    const arg = operation === 'snapshotPrepare' ? saved : operation === 'setSnapshotLimits' ?
      { expectedRevision: '10', nonce: '99', limits: LIMITS } : point;
    await assert.rejects(db[operation](arg), (e) => e instanceof UnknownError && e.outcome === 'unknown' &&
      (operation === 'snapshotPrepare' ? e.reference.snapshotInput.operation === '81' : operation === 'setSnapshotLimits' ? e.reference.snapshotLimits.max_points === 64 : e.reference.snapshotReference.capture_serial === '16'));
    assert.equal(io.calls.length, 2);
  }
  for (const operation of ['snapshotInspect', 'snapshotObserve', 'snapshotList']) {
    const io = script([() => { throw new Error('read response lost'); }]), db = client(io), saved = db.prepareSnapshotInput(INPUT);
    await assert.rejects(db[operation](operation === 'snapshotInspect' ? saved : operation === 'snapshotObserve' ? identity : undefined),
      (e) => e instanceof ClientError && !(e instanceof UnknownError) && e.code === 'TRANSPORT');
    assert.equal(io.calls.length, 1);
  }
  const io = script([() => failure('DENIED', 403)]), db = client(io);
  await assert.rejects(db.snapshotPrepare(db.prepareSnapshotInput(INPUT)), { code: 'DENIED' });
  assert.equal(io.calls.length, 1);
});

test('snapshot limits require original revision, nonce and exact persisted policy in the response', async () => {
  const changed = listed([]); changed.status.revision = '11'; changed.status.head_serial = '21';
  changed.status.transition = { revision: '11', nonce: '99' };
  const input = { expectedRevision: '10', nonce: '99', limits: LIMITS };
  const io = script([changed]), db = client(io);
  assert.deepEqual(await db.setSnapshotLimits(input), changed);
  assert.deepEqual(io.calls[0].body, { version: 1, scope: SCOPE, operation: 'snapshot_limits', expected_revision: '10', nonce: '99', limits: LIMITS });
  for (const change of [(x) => x.status.transition.nonce = '98', (x) => x.limits.max_points = 63,
    (x) => { x.status.revision = '12'; x.status.transition.revision = '12'; }]) {
    const bad = clone(changed); change(bad);
    await assert.rejects(client(script([bad])).setSnapshotLimits(input), { code: 'UNKNOWN' });
  }
});
