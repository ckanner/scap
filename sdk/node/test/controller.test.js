import { test } from 'node:test';
import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { OwnerController } from '../src/controller.js';
import { ClientError } from '../src/errors.js';
import { policy, input } from './controller_policy.test.js';
import { A, B, OPTIONS, head, script, success, failure } from './owner_fixture.js';
import { observed, prepared } from './owner_plan_fixture.js';

const controller = (p, io) => new OwnerController({ policy: p, token: OPTIONS.token, fetch: io.fetch });
const lost = () => { throw new Error('synthetic secret that must never enter a report'); };
const missing = () => failure('MISSING', 409);
const original = (p, changes = {}) => observed('prepared', input(p, changes));
const clock = (t) => { let now = 0; t.mock.method(performance, 'now', () => now); return (value) => { now = value; }; };

test('healthy idle owner is read-only, cadence is bounded, and configuration never admits caller SQL', async (t) => {
  clock(t); const p = policy(), h = head(), io = script([h, h]), c = controller(p, io);
  const result = await c.tick();
  assert.equal(result.state, 'healthy'); assert.equal(result.mutations, 0); assert.equal(result.httpCalls, 2);
  assert.equal(result.nativeSession, 'NOT_CERTIFIED'); assert.equal(result.lastUncertainCall, null);
  assert.equal((await c.tick()).reason, 'INTERVAL'); assert.equal(io.calls.length, 2);
  assert.equal(c.policy, p); assert.equal(c.needsRecovery, false); assert.equal(c.nextTickAt, 5000);
  assert.equal(c.lastReport.reason, 'INTERVAL');
  await assert.rejects(c.tick({ timeoutMs: 30001 }), { code: 'INVALID' });
  await assert.rejects(c.tick({ sql: 'SELECT 1' }), { code: 'INVALID' });
  assert.throws(() => new OwnerController({ policy: p, token: OPTIONS.token, fetch: null }));
  await c.close(); await assert.rejects(c.tick(), { code: 'ABORTED' });
});

test('inactive activation prepares, claims and resumes as three separate original ticks', async (t) => {
  const now = clock(t), p = policy(), i = input(p), o = original(p), claimed = observed('claimed', i), active = observed('active', i);
  const io = script([o.status, o.status, missing, { state: 'prepared', prepared: prepared(i) },
    o.status, o.status, o, o, claimed,
    claimed.status, claimed, claimed, claimed.status, active]);
  const c = controller(p, io);
  assert.equal((await c.tick()).state, 'prepared'); now(5000);
  assert.equal((await c.tick()).state, 'claimed'); assert.equal(c.needsRecovery, true); now(10000);
  const report = await c.tick(); assert.equal(report.state, 'active_observed'); assert.equal(report.acceptedPhase, 'active');
  assert.equal(report.recoveryBudget, true); assert.equal(report.nativeSession, 'NOT_CERTIFIED');
  const mutations = io.calls.filter(({ body }) => body.operation !== 'status' && body.operation !== 'owner_inspect');
  assert.deepEqual(mutations.map(({ body }) => body.operation), ['owner_prepare', 'owner_claim', 'owner_resume']);
  assert.equal(mutations[0].body.input.operation, '10');
  assert.equal(mutations[1].body.expected_worker_instance, '100'); assert.equal(mutations[2].body.expected_worker_instance, '100');
  assert.equal(io.calls.some(({ body }) => body.operation === 'execute'), false);
  await c.close();
});

test('restart discovers a claimed plan from actual history but never renews into recovery in the same tick', async (t) => {
  const now = clock(t), p = policy(), i = input(p, { mode: 'takeover', target_worker: '200' }), o = observed('claimed', i);
  const io = script([o.status, o, o, o.status, o.status, o, o, o.status, observed('active', i)]), c = controller(p, io);
  let report = await c.tick(); assert.equal(report.reason, 'RECOVERY_REQUIRES_NEXT_TICK_BUDGET'); assert.equal(report.mutations, 0);
  assert.equal(c.needsRecovery, true); now(5000); report = await c.tick();
  assert.equal(report.state, 'active_observed'); assert.equal(report.mutations, 1); assert.equal(report.recoveryBudget, true);
  assert.equal(io.calls.filter(({ body }) => body.operation === 'owner_resume').length, 1);
  await c.close();
});

test('lost local prepare input requires a fresh failure window and the same durable first winner before claim', async (t) => {
  const now = clock(t), p = policy(), i = input(p, { mode: 'takeover', target_worker: '200' }), o = observed('prepared', i);
  const failedProbe = [o.status, lost, o.status];
  const io = script([...failedProbe, ...failedProbe, ...failedProbe, o, o.status,
    { state: 'prepared', prepared: prepared(i) }, ...failedProbe, o, o.status, o, observed('claimed', i)]);
  const c = controller(p, io);
  assert.equal((await c.tick()).reason, 'OWNER_SUSPICION_INCOMPLETE'); now(5000);
  assert.equal((await c.tick()).reason, 'OWNER_SUSPICION_INCOMPLETE'); now(10000);
  assert.equal((await c.tick()).state, 'prepared'); now(15000);
  assert.equal((await c.tick()).state, 'claimed');
  const mutations = io.calls.filter(({ body }) => body.operation.startsWith('owner_') && body.operation !== 'owner_inspect');
  assert.deepEqual(mutations.map(({ body }) => body.operation), ['owner_prepare', 'owner_claim']);
  assert.deepEqual(mutations[0].body.input, i);
  assert.equal(mutations[1].body.plan.descriptor_hash, 'a'.repeat(64));
  await c.close();
});

test('an unknown prepare retains original input, later history cannot manufacture the old ACK, and no SQL is sent', async (t) => {
  const now = clock(t), p = policy(), o = original(p), i = input(p);
  const io = script([o.status, o.status, missing, lost, o.status, o.status, o, { state: 'prepared', prepared: prepared(i) }]);
  const c = controller(p, io); let report = await c.tick();
  assert.equal(report.state, 'unknown'); assert.equal(report.pastUnknown, true);
  assert.equal(JSON.parse(report.lastUncertainCall.request).input.operation, '10');
  assert.equal(JSON.stringify(report).includes('synthetic secret'), false);
  assert.equal(JSON.stringify(report).includes(OPTIONS.token), false);
  now(5000); report = await c.tick(); assert.equal(report.state, 'prepared'); assert.equal(report.pastUnknown, true);
  assert.equal(io.calls.filter(({ body }) => body.operation === 'owner_prepare').length, 2);
  await c.close();
});

test('foreign creator, different full policy, unknown worker and maintenance all block mutations', async () => {
  const p = policy(), own = input(p, { mode: 'takeover', target_worker: '200' });
  const cases = [
    { replies: [head({ owner_instance: '300' })], reason: 'UNKNOWN_OWNER' },
    { replies: [head({ lifecycle: 'maintenance', active: false })], reason: 'LIFECYCLE_OR_STORAGE_MAINTENANCE' },
    { replies: [observed('claimed', { ...own, creator: '8' }).status], reason: 'FOREIGN_CREATOR' },
    { replies: [observed('claimed', { ...own, nonces: { claim: '1', cancel: '2', activate: '3', abort: '4' } }).status,
      observed('claimed', { ...own, nonces: { claim: '1', cancel: '2', activate: '3', abort: '4' } })], reason: 'POLICY' },
  ];
  for (const { replies, reason } of cases) {
    const io = script(replies), c = controller(p, io), report = await c.tick();
    assert.equal(report.state, 'blocked'); assert.equal(report.reason, reason); assert.equal(report.mutations, 0); await c.close();
  }
});

test('authorization, corruption, route mismatch and remote unavailable are never counted as death', async () => {
  for (const [code, status] of [['DENIED', 403], ['CORRUPT', 409], ['TARGET_MISMATCH', 409], ['UNAVAILABLE', 503]]) {
    const io = script([head(), () => failure(code, status)]), c = controller(policy(), io), report = await c.tick();
    assert.equal(report.state, 'blocked'); assert.equal(report.reason, code); assert.equal(report.httpCalls, 2); assert.equal(report.mutations, 0);
    await c.close();
  }
});

test('busy recovery and payload limits back off without burning a worker rank or rewriting the plan', async (t) => {
  const now = clock(t), p = policy(), i = input(p), o = observed('claimed', i), replies = [];
  for (let n = 0; n < 7; n++) replies.push(o.status, o, o, o.status, () => failure(n === 0 ? 'LIMIT' : 'RECOVERY_BUSY', n === 0 ? 413 : 429));
  const io = script([o.status, o, o, o.status, ...replies]), c = controller(p, io);
  await c.tick();
  let last = c.nextTickAt;
  for (const delay of [5000, 10000, 20000, 40000, 60000, 60000, 60000]) {
    now(last); const report = await c.tick(); assert.equal(report.state, 'waiting');
    assert.equal(c.nextTickAt - last, delay); last = c.nextTickAt; assert.equal(report.pastUnknown, false);
  }
  assert.equal(io.calls.some(({ body }) => ['owner_prepare', 'owner_abort', 'owner_claim'].includes(body.operation)), false);
  await c.close();
});

test('one owned in-flight tick rejects overlap and close aborts and joins it without claiming remote cancellation', async () => {
  let started; const admitted = new Promise((resolve) => { started = resolve; });
  const c = new OwnerController({ policy: policy(), token: OPTIONS.token,
    fetch: (_url, init) => new Promise((_resolve, reject) => { started(); init.signal.addEventListener('abort', () => reject(new Error('aborted'))); }) });
  const pending = c.tick(); await admitted;
  await assert.rejects(c.tick(), { code: 'BACKPRESSURE' });
  await c.close(); const report = await pending; assert.equal(report.state, 'blocked'); assert.equal(report.mutations, 0);
  await assert.rejects(c.tick(), { code: 'ABORTED' });
});

test('fresh authority changes reset decision knowledge and an original deadline never admits a late next request', async (t) => {
  const now = clock(t), io = script([head(), head({ revision: '11', head_serial: '11', transition: { revision: '11', nonce: '7' } })]);
  const c = controller(policy(), io); assert.equal((await c.tick()).reason, 'STALE'); await c.close();
  const next = script([() => { now(11); return success(head()); }]), d = controller(policy(), next);
  now(0); const report = await d.tick({ timeoutMs: 10 }); assert.equal(report.reason, 'DEADLINE'); assert.equal(next.calls.length, 1);
  await d.close();
});

test('a new takeover advances only to a higher rank after three fresh independent failures', async (t) => {
  const now = clock(t), p = policy(), i = input(p, { mode: 'takeover', target_worker: '200' }), h = head();
  const fail = [h, lost, h], io = script([...fail, ...fail, ...fail, missing, h,
    { state: 'prepared', prepared: prepared(i) }]), c = controller(p, io);
  await c.tick(); now(5000); await c.tick(); now(10000);
  const report = await c.tick(); assert.equal(report.state, 'prepared'); assert.equal(report.httpCalls, 6);
  assert.equal(io.calls.at(-1).body.input.target_worker, '200');
  assert.equal(io.calls.at(-1).body.input.operation, h.head_serial); await c.close();
});

test('without a surviving independent authority no failed probe authorizes any mutation', async () => {
  for (const [p, replies] of [[policy(), [lost, lost]], [policy({ metadataEndpoints: [A] }), [head(), lost]],
    [policy(), [() => failure('DENIED', 403)]]]) {
    const io = script(replies), c = controller(p, io), report = await c.tick();
    assert.equal(report.state, 'blocked'); assert.equal(report.mutations, 0); await c.close();
  }
  const io = script([lost, head(), head()]), c = controller(policy(), io);
  assert.equal((await c.tick()).state, 'healthy'); assert.equal(io.calls[1].url, B); await c.close();
});

test('accepted cancelling is resumed as abort, while an unavailable claimed target needs its own fresh window', async (t) => {
  const now = clock(t), p = policy(), i = input(p, { mode: 'takeover', target_worker: '200' });
  const cancelled = observed('cancelling', i), aborted = observed('aborted', i, 'cancel');
  const first = script([cancelled.status, cancelled, cancelled, aborted]), c = controller(p, first);
  assert.equal((await c.tick()).state, 'aborted'); assert.equal(first.calls.at(-1).body.operation, 'owner_abort'); await c.close();
  const claimed = observed('claimed', i), fail = [claimed.status, claimed, claimed, lost, claimed.status];
  const io = script([...fail, ...fail, ...fail, observed('aborted', i)]), d = controller(p, io);
  assert.equal((await d.tick()).reason, 'TARGET_SUSPICION_INCOMPLETE'); now(5000);
  assert.equal((await d.tick()).reason, 'TARGET_SUSPICION_INCOMPLETE'); now(10000);
  assert.equal((await d.tick()).state, 'aborted'); assert.equal(io.calls.at(-1).body.operation, 'owner_abort'); await d.close();
});

test('explicitly disabled modes and exhausted serial/revision/epoch or rank fail closed', async (t) => {
  const now = clock(t);
  for (const p of [policy({ modes: { takeover: true, activate: false, cancel: true } })]) {
    const h = head({ active: false }), c = controller(p, script([h, h]));
    assert.equal((await c.tick()).reason, 'AUTOMATIC_ACTIVATION_DISABLED'); await c.close();
  }
  for (const p of [policy({ modes: { takeover: true, activate: true, cancel: false } })]) {
    const o = observed('cancelling', input(p)), c = controller(p, script([o.status, o, o]));
    assert.equal((await c.tick()).reason, 'AUTOMATIC_CANCEL_DISABLED'); await c.close();
    const claimed = observed('claimed', input(p)), fail = [claimed.status, claimed, claimed, lost, claimed.status];
    const d = controller(p, script([...fail, ...fail, ...fail]));
    now(0); await d.tick(); now(5000); await d.tick(); now(10000);
    assert.equal((await d.tick()).reason, 'AUTOMATIC_CANCEL_DISABLED'); await d.close();
  }
  for (const [p, h, reason] of [
    [policy({ modes: { takeover: false, activate: true, cancel: true } }), head(), 'AUTOMATIC_TAKEOVER_DISABLED'],
    [policy(), head({ owner_epoch: '18446744073709551615' }), 'COUNTER_RESERVE_EXHAUSTED'],
    [policy(), head({ owner_instance: '200' }), 'REGISTRY_RANK_EXHAUSTED'],
  ]) {
    const fail = [h, lost, h], replies = [...fail, ...fail, ...fail];
    if (reason === 'REGISTRY_RANK_EXHAUSTED') replies.push(missing);
    const c = controller(p, script(replies)); now(0); await c.tick(); now(5000); await c.tick(); now(10000);
    assert.equal((await c.tick()).reason, reason); await c.close();
  }
  for (const counters of [{ revision: '18446744073709551614', head_serial: '18446744073709551614' },
    { revision: '10', head_serial: '18446744073709551614' }]) {
    const h = head({ ...counters, active: false, transition: { revision: counters.revision, nonce: '9' } });
    const c = controller(policy(), script([h, h])); now(0);
    assert.equal((await c.tick()).reason, 'COUNTER_RESERVE_EXHAUSTED'); await c.close();
  }
});

test('first-winner corruption is never repaired by changing the locally verified input or hash', async (t) => {
  const now = clock(t), p = policy(), i = input(p), o = observed('prepared', i);
  const bad = observed('prepared', i, undefined, 'b'.repeat(64));
  const io = script([o.status, o.status, missing, { state: 'prepared', prepared: prepared(i) },
    o.status, o.status, bad]), c = controller(p, io);
  assert.equal((await c.tick()).state, 'prepared'); now(5000);
  assert.equal((await c.tick()).reason, 'CORRUPT');
  assert.equal(io.calls.filter(({ body }) => body.operation === 'owner_prepare').length, 1);
  assert.equal(io.calls.filter(({ body }) => body.operation === 'owner_claim').length, 0); await c.close();
});

test('a fresh changed HEAD discards suspicion and historical Active is only an observation', async (t) => {
  const now = clock(t), p = policy(), h = head(), changed = head({ head_serial: '11' });
  const io = script([h, lost, h, changed, lost, changed]), c = controller(p, io);
  await c.tick(); now(5000); assert.equal((await c.tick()).reason, 'OWNER_SUSPICION_INCOMPLETE'); await c.close();
  const o = observed('active', input(p)), active = script([o.status, o, o.status]), d = controller(p, active);
  const report = await d.tick(); assert.equal(report.state, 'healthy'); assert.equal(report.acceptedPhase, 'active');
  assert.equal(report.nativeSession, 'NOT_CERTIFIED'); assert.equal(report.mutations, 0); await d.close();
});

test('healthy inactive original owner cancels a fixed unaccepted takeover before preparing activation at a new serial', async (t) => {
  const now = clock(t), p = policy(), i = input(p, { mode: 'takeover', target_worker: '200' });
  const o = observed('prepared', i); o.status.active = false;
  const cancelling = observed('cancelling', i), aborted = observed('aborted', i, 'cancel');
  const nextInput = input(p, { operation: '12', expected_revision: '12', expected_head_serial: '12' });
  const io = script([o.status, o.status, o, { state: 'prepared', prepared: prepared(i) },
    o.status, o.status, o, o, cancelling,
    cancelling.status, cancelling, cancelling, aborted,
    aborted.status, aborted, aborted.status, missing, { state: 'prepared', prepared: prepared(nextInput) }]);
  const c = controller(p, io);
  assert.equal((await c.tick()).state, 'prepared'); now(5000);
  assert.equal((await c.tick()).state, 'cancelling'); now(10000);
  assert.equal((await c.tick()).state, 'aborted'); now(15000);
  assert.equal((await c.tick()).state, 'prepared');
  const mutations = io.calls.filter(({ body }) => body.operation !== 'status' && body.operation !== 'owner_inspect');
  assert.deepEqual(mutations.map(({ body }) => body.operation), ['owner_prepare', 'owner_abort', 'owner_abort', 'owner_prepare']);
  assert.deepEqual(mutations[0].body.input, i); assert.deepEqual(mutations.at(-1).body.input, nextInput);
  assert.equal(mutations.some(({ body }) => body.operation === 'owner_claim'), false);
  await c.close();
});

test('healthy active original owner never inspects or cancels an old unaccepted takeover just to clean it up', async () => {
  const p = policy(), h = head(), io = script([h, h]), c = controller(p, io);
  assert.equal((await c.tick()).state, 'healthy');
  assert.deepEqual(io.calls.map(({ body }) => body.operation), ['status', 'status']); await c.close();
});
