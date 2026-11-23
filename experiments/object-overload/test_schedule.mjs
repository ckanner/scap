import assert from 'node:assert/strict';
import test from 'node:test';
import { runArrivals } from './schedule.mjs';
import { setImmediate as nextTurn, setTimeout as delay } from 'node:timers/promises';
import { until } from './arrival_clock.mjs';

const calls = Array.from({ length: 6 }, (_, id) => ({ id, offset_ns: id * 100 }));
const plan = { client_inflight_limit: 2, duration_ms: 1 };

test('blocked calls never delay later offers and a full generator rejects without queueing', async () => {
  const offered = [], issued = [], rejected = [], releases = [];
  let now = 1000n;
  await runArrivals(calls, now, plan, {
    async until(target) { now = now > target ? now : target; },
    offered(call, scheduled, active) { offered.push([call.id, scheduled, now, active]); },
    rejected(call) { rejected.push(call.id); },
    invoke(call) { issued.push(call.id); return new Promise((resolve) => releases.push(resolve)); },
    arrivalsFinished(active) {
      assert.equal(now, 1_001_000n); assert.equal(active, 2);
      assert.equal(offered.length, 6);
      releases.forEach((resolve) => resolve());
    },
  });
  assert.deepEqual(issued, [0, 1]);
  assert.deepEqual(rejected, [2, 3, 4, 5]);
  assert.deepEqual(offered.map((row) => row[1]), calls.map((call) => 1000n + BigInt(call.offset_ns)));
});

test('completed work returns only its own generator slot before the next independent offer', async () => {
  const active = [], issued = [];
  await runArrivals(calls, 1000n, plan, {
    async until() {},
    offered(_call, _scheduled, count) { active.push(count); },
    rejected() { assert.fail('unexpected generator rejection'); },
    async invoke(call) { issued.push(call.id); },
    arrivalsFinished(count) { assert.equal(count, 0); },
  });
  assert.deepEqual(issued, calls.map((call) => call.id));
  assert.deepEqual(active, [0, 0, 0, 0, 0, 0]);
});

test('late handling preserves original scheduled times instead of moving the schedule', async () => {
  let now = 1000n;
  const scheduled = [], actual = [];
  await runArrivals(calls, now, plan, {
    async until(target) { now = now > target ? now : target; },
    offered(_call, target) { scheduled.push(target); actual.push(now); now += 250n; },
    rejected() { assert.fail('unexpected rejection'); },
    async invoke() {},
    arrivalsFinished() {},
  });
  assert.deepEqual(scheduled, [1000n, 1100n, 1200n, 1300n, 1400n, 1500n]);
  assert.deepEqual(actual, [1000n, 1250n, 1500n, 1750n, 2000n, 2250n]);
});

test('an observation failure is retained and cannot become a successful drained phase', async () => {
  const failure = new Error('raw evidence write failed');
  let closed = false;
  await assert.rejects(runArrivals(calls, 1000n, plan, {
    async until() {},
    offered() {}, rejected() {},
    invoke() { return Promise.reject(failure); },
    arrivalsFinished() { closed = true; },
  }), (error) => error === failure);
  assert.equal(closed, true);
});

// A deterministic witness for the old overdue-only microtask catch-up. These
// ready event-loop callbacks stand for runnable completions; the witness does
// not assert that the historical HTTP responses were already OS-ready.
async function legacyUntil(target) {
  const now = () => process.hrtime.bigint();
  while (now() < target) await delay(Math.max(1, Number(target - now()) / 1e6));
}

async function completionWitness(waitUntil) {
  const origin = process.hrtime.bigint() - 20_000_000n;
  const offered = [], issued = [], rejected = [], settled = [];
  let activeAtEnd;
  await runArrivals(calls, origin, plan, {
    until: waitUntil,
    offered(call, scheduled, active) { offered.push({ id: call.id, scheduled, active }); },
    rejected(call) { rejected.push(call.id); },
    invoke(call) {
      issued.push(call.id);
      return nextTurn().then(() => { settled.push(call.id); });
    },
    arrivalsFinished(active) { activeAtEnd = active; },
  });
  assert.deepEqual(offered.map((row) => row.scheduled),
    calls.map((call) => origin + BigInt(call.offset_ns)));
  return { offered, issued, rejected, settled, activeAtEnd };
}

test('overdue catch-up yields to runnable completions without moving planned arrivals', { timeout: 5000 }, async () => {
  const legacy = await completionWitness(legacyUntil);
  assert.deepEqual(legacy.issued, [0, 1]);
  assert.deepEqual(legacy.rejected, [2, 3, 4, 5]);
  assert.deepEqual(legacy.offered.map((row) => row.active), [0, 1, 2, 2, 2, 2]);
  assert.equal(legacy.activeAtEnd, 2);
  const current = await completionWitness(until);
  assert.deepEqual(current.issued, calls.map((call) => call.id));
  assert.deepEqual(current.rejected, []);
  assert.deepEqual(current.offered.map((row) => row.active), [0, 0, 0, 0, 0, 0]);
  assert.equal(current.activeAtEnd, 0);
});

test('the arrival clock keeps its absolute target and takes exactly one independent turn', async () => {
  let now = 1000n, turns = 0;
  const delays = [];
  const clock = {
    now: () => now,
    async delay(milliseconds) {
      delays.push(milliseconds);
      now += BigInt(Math.min(milliseconds, 2)) * 1_000_000n;
    },
    async turn() { turns++; },
  };
  await until(3_001_000n, clock);
  assert.deepEqual(delays, [3, 1]);
  assert.equal(now, 3_001_000n);
  assert.equal(turns, 1);
  await until(1000n, clock);
  assert.deepEqual(delays, [3, 1]);
  assert.equal(now, 3_001_000n);
  assert.equal(turns, 2);
});

test('a real 64-call backlog still offers every arrival and rejects seven without waiting', { timeout: 5000 }, async () => {
  const blocked = Array.from({ length: 71 }, (_, id) => ({ id, offset_ns: id * 100 }));
  const origin = process.hrtime.bigint() - 20_000_000n;
  const offered = [], issued = [], rejected = [], releases = [], waits = [];
  let ended = false;
  await runArrivals(blocked, origin, { client_inflight_limit: 64, duration_ms: 1 }, {
    async until(target) { waits.push(target); await until(target); },
    offered(call, scheduled, active) {
      offered.push([call.id, scheduled, active]);
      assert.ok(active <= 64);
    },
    rejected(call) { rejected.push(call.id); },
    invoke(call) {
      issued.push(call.id);
      return new Promise((resolve) => releases.push(resolve));
    },
    arrivalsFinished(active) {
      ended = true;
      assert.equal(active, 64);
      assert.equal(offered.length, 71);
      assert.equal(issued.length, 64);
      assert.deepEqual(rejected, [64, 65, 66, 67, 68, 69, 70]);
      // No SDK operation can resolve until every original offer has happened.
      releases.forEach((resolve) => resolve());
    },
  });
  assert.equal(ended, true);
  assert.deepEqual(issued, blocked.slice(0, 64).map((call) => call.id));
  assert.deepEqual(offered.map((row) => row[1]),
    blocked.map((call) => origin + BigInt(call.offset_ns)));
  assert.deepEqual(waits, [...offered.map((row) => row[1]), origin + 1_000_000n]);
});

test('the yielding clock still propagates observation failure after all independent offers', async () => {
  const failure = new Error('raw evidence write failed');
  let offered = 0, ended = false;
  const origin = process.hrtime.bigint() - 20_000_000n;
  await assert.rejects(runArrivals(calls, origin, plan, {
    until,
    offered() { offered++; },
    rejected() { assert.fail('completed failed observations must return their own slots'); },
    invoke() { return Promise.reject(failure); },
    arrivalsFinished() { ended = true; },
  }), (error) => error === failure);
  assert.equal(offered, calls.length);
  assert.equal(ended, true);
});
