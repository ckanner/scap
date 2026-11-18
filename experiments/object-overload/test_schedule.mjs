import assert from 'node:assert/strict';
import test from 'node:test';
import { runArrivals } from './schedule.mjs';

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
