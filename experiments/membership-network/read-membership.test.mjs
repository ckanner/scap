import assert from "node:assert/strict";
import test from "node:test";
import { readFreshMembership } from "./read-membership.mjs";

const view = {
  conf_state: { voters: [1, 2, 3], learners: [], voters_outgoing: [], learners_next: [], auto_leave: false },
  applied: 19, commit: 19,
};
const ready = (cost = 0) => ({ status: 200, raw: "ready", cost });
const reply = (status, data, cost = 0) => ({ status, raw: JSON.stringify(data), cost });

function fixture(t, steps, { nodes = [0], budget = 30_000, recordCost = 0 } = {}) {
  let clock = 0;
  const calls = [];
  const records = [];
  const pauses = [];
  const timeouts = [];
  t.mock.method(AbortSignal, "timeout", (milliseconds) => {
    timeouts.push(milliseconds);
    return new AbortController().signal;
  });
  const ports = {
    nodes,
    readinessUrl: (node) => `http://node-${node + 1}/readyz`,
    membershipUrl: (node) => `http://node-${node + 1}/v1/admin/membership`,
    token: "private-fixture-token",
    now: () => clock,
    pause: async (milliseconds) => { pauses.push(milliseconds); clock += milliseconds; },
    assertLive: () => {},
    record: async (value) => { records.push(value); clock += recordCost; },
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      assert.equal(options.method, "GET", "discovery must never submit a mutation");
      assert.equal(options.body, undefined);
      assert.equal(options.redirect, "manual");
      const step = steps[calls.length - 1];
      assert.ok(step, "unexpected additional request");
      clock += step.cost ?? 0;
      if (step.error) throw step.error;
      return {
        status: step.status,
        text: async () => {
          clock += step.bodyCost ?? 0;
          if (step.bodyError) throw step.bodyError;
          return step.raw;
        },
      };
    },
  };
  return { ports, calls, records, pauses, timeouts, now: () => clock, run: () => readFreshMembership(ports, budget) };
}

test("only a fresh authoritative 200 returns a complete configuration", async (t) => {
  for (const body of [view, { membership: view }]) {
    await t.test(body.membership ? "wrapped" : "direct", async (t) => {
      const f = fixture(t, [ready(), reply(200, body)], { nodes: [2] });
      assert.deepEqual(await f.run(), { leader: 2, view });
      assert.deepEqual(f.timeouts, [600, 6500]);
      assert.deepEqual(f.records.map((record) => [record.phase, record.node_id, record.http_status]), [
        ["readiness", 3, 200], ["authoritative", 3, 200],
      ]);
      assert.equal(f.calls[0].options.headers, undefined);
      assert.equal(f.calls[1].options.headers.authorization, "Bearer private-fixture-token");
      assert.equal(JSON.stringify(f.records).includes("private-fixture-token"), false);
    });
  }
});

test("explicit 409 NOT_LEADER is recorded and rediscovers without any POST or added wait", async (t) => {
  const f = fixture(t, [
    ready(), reply(409, { code: "NOT_LEADER" }),
    reply(503, { code: "NOT_LEADER" }), ready(), reply(200, { membership: view }),
  ], { nodes: [0, 1] });
  assert.deepEqual(await f.run(), { leader: 1, view });
  assert.deepEqual(f.calls.map(({ url }) => url), [
    "http://node-1/readyz", "http://node-1/v1/admin/membership",
    "http://node-1/readyz", "http://node-2/readyz", "http://node-2/v1/admin/membership",
  ]);
  assert.equal(f.calls.filter(({ options }) => options.method !== "GET").length, 0);
  assert.deepEqual(f.pauses, []);
  assert.deepEqual(f.records.map((record) => record.attempt), [1, 2, 3, 4, 5]);
  assert.equal(f.records[1].code, "NOT_LEADER");
  assert.equal(f.records[1].response_body, '{"code":"NOT_LEADER"}');
  assert.equal(f.records[2].http_status, 503, "readiness is only a hint, separate from the authoritative GET");
  assert.ok(f.records.every((record) => record.original_deadline_ms === 30_000));
});

test("all other authoritative errors and malformed responses fail without rediscovery", async (t) => {
  const failures = [
    ["configuration conflict", reply(409, { code: "MEMBERSHIP_CONFLICT" })],
    ["pending mutation", reply(409, { code: "MEMBERSHIP_PENDING" })],
    ["lagging learner", reply(409, { code: "LEARNER_NOT_CAUGHT_UP" })],
    ["unknown mutation", reply(503, { code: "MEMBERSHIP_UNKNOWN" })],
    ["wrong status with NOT_LEADER", reply(503, { code: "NOT_LEADER" })],
    ["unauthorized", reply(401, { code: "UNAUTHORIZED" })],
    ["forbidden", reply(403, { code: "UNAUTHORIZED" })],
    ["overloaded", reply(429, { code: "OVERLOADED" })],
    ["server error", reply(500, { code: "NOT_LEADER" })],
    ["redirect", reply(307, { code: "NOT_LEADER" })],
    ["missing error code", reply(409, {})],
    ["wrong code type", reply(409, { code: 409 })],
    ["different spelling", reply(409, { code: "not_leader" })],
    ["nested error code", reply(409, { error: { code: "NOT_LEADER" } })],
    ["null response", reply(409, null)],
    ["array response", reply(409, [{ code: "NOT_LEADER" }])],
    ["string response", reply(409, "NOT_LEADER")],
    ["malformed rejection", { status: 409, raw: '{"code":"NOT_LEADER"' }],
    ["malformed success", { status: 200, raw: "not JSON" }],
    ["missing configuration", reply(200, {})],
    ["incomplete configuration", reply(200, { conf_state: { voters: [1, 2, 3] } })],
    ["error disguised as success", reply(200, { ...view, code: "NOT_LEADER" })],
  ];
  for (const [name, response] of failures) {
    await t.test(name, async (t) => {
      const f = fixture(t, [ready(), response]);
      await assert.rejects(f.run());
      assert.equal(f.calls.length, 2);
      assert.equal(f.records.length, 2);
      assert.equal(f.records[1].http_status, response.status);
      assert.equal(f.records[1].response_body, response.raw);
      assert.deepEqual(f.pauses, []);
    });
  }
});

test("authoritative transport and response-body failures retain the error and never retry", async (t) => {
  for (const step of [
    { error: new TypeError("connection lost") },
    { error: new DOMException("deadline", "TimeoutError") },
    { status: 409, bodyError: new TypeError("response interrupted") },
  ]) {
    await t.test((step.error ?? step.bodyError).message, async (t) => {
      const f = fixture(t, [ready(), step]);
      await assert.rejects(f.run(), (error) => error === (step.error ?? step.bodyError));
      assert.equal(f.calls.length, 2);
      assert.equal(f.records[1].http_status, step.status ?? null);
      assert.deepEqual(f.records[1].transport_error, {
        name: (step.error ?? step.bodyError).name, message: (step.error ?? step.bodyError).message,
      });
    });
  }
});

test("repeated NOT_LEADER responses share one finite budget including discovery", async (t) => {
  const f = fixture(t, [
    ready(10), reply(409, { code: "NOT_LEADER" }, 30),
    ready(10), reply(409, { code: "NOT_LEADER" }, 30),
    ready(10), reply(409, { code: "NOT_LEADER" }, 10),
  ], { budget: 100 });
  await assert.rejects(f.run(), /original recovery budget/);
  assert.equal(f.now(), 100);
  assert.equal(f.calls.length, 6);
  assert.deepEqual(f.timeouts, [100, 90, 60, 50, 20, 10]);
  assert.equal(f.records.filter((record) => record.code === "NOT_LEADER").length, 3);
  assert.ok(f.records.every((record) => record.original_deadline_ms === 100));
  assert.deepEqual(f.pauses, []);
});

test("a 200 response that reaches the original deadline is recorded but cannot succeed", async (t) => {
  const f = fixture(t, [ready(4), { ...reply(200, view), bodyCost: 6 }], { budget: 10 });
  await assert.rejects(f.run(), /original recovery budget/);
  assert.deepEqual(f.timeouts, [10, 6]);
  assert.equal(f.records.at(-1).http_status, 200);
  assert.equal(f.records.at(-1).result_ms, 10);
  assert.equal(f.calls.length, 2);
});

test("recording attempts consumes the same original budget", async (t) => {
  const f = fixture(t, [ready(), reply(200, view)], { budget: 10, recordCost: 5 });
  await assert.rejects(f.run(), /original recovery budget/);
  assert.deepEqual(f.timeouts, [10, 5]);
  assert.equal(f.now(), 10);
  assert.equal(f.records.at(-1).http_status, 200);
});

test("every readiness probe and existing polling pause is capped by remaining time", async (t) => {
  const f = fixture(t, [reply(503, { code: "NOT_LEADER" }, 600), reply(503, { code: "NOT_LEADER" }, 100)], {
    nodes: [0, 1], budget: 750,
  });
  await assert.rejects(f.run(), /original recovery budget/);
  assert.deepEqual(f.timeouts, [600, 150]);
  assert.deepEqual(f.pauses, [50]);
  assert.equal(f.now(), 750);
  assert.ok(f.records.every((record) => record.phase === "readiness"));
});

test("a late readiness hint cannot start an authoritative GET", async (t) => {
  const f = fixture(t, [ready(10)], { budget: 10 });
  await assert.rejects(f.run(), /original recovery budget/);
  assert.equal(f.calls.length, 1);
  assert.equal(f.records[0].http_status, 200);
});

test("readiness transport failures are recorded as hints and do not hide membership failures", async (t) => {
  const f = fixture(t, [{ error: new TypeError("not listening") }, ready(), reply(503, { code: "MEMBERSHIP_UNKNOWN" })], { nodes: [0, 1] });
  await assert.rejects(f.run(), /fresh membership read must succeed/);
  assert.equal(f.calls.length, 3);
  assert.equal(f.records[0].transport_error.message, "not listening");
  assert.equal(f.records[2].code, "MEMBERSHIP_UNKNOWN");
});

test("evidence or daemon failures stop discovery instead of silently continuing", async (t) => {
  await t.test("evidence cannot be written", async (t) => {
    const f = fixture(t, [ready()]);
    f.ports.record = async () => { throw new Error("evidence unavailable"); };
    await assert.rejects(f.run(), /evidence unavailable/);
    assert.equal(f.calls.length, 1);
  });
  await t.test("unexpected daemon exit", async (t) => {
    const f = fixture(t, []);
    f.ports.assertLive = () => { throw new Error("unexpected exit"); };
    await assert.rejects(f.run(), /unexpected exit/);
    assert.equal(f.calls.length, 0);
  });
});
