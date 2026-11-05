import assert from "node:assert/strict";

// A readiness response is a discovery hint, not a lease over the next GET.
// This harness helper has no mutation port: all requests are explicit GETs.
export async function readFreshMembership({
  nodes, readinessUrl, membershipUrl, token, record, assertLive,
  fetchImpl = fetch, now = () => performance.now(),
  pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
}, budgetMs = 30_000) {
  const deadline = now() + budgetMs;
  let attempt = 0;
  const remaining = () => {
    const milliseconds = Math.floor(deadline - now());
    assert.ok(milliseconds > 0, "No authoritative membership read before the original recovery budget");
    return milliseconds;
  };

  async function get(node, phase) {
    const timeoutMs = Math.min(phase === "readiness" ? 600 : 6500, remaining());
    const invoked = now();
    let status = null;
    let raw = null;
    let data;
    let failure;
    let malformed = false;
    try {
      const response = await fetchImpl(phase === "readiness" ? readinessUrl(node) : membershipUrl(node), {
        method: "GET", redirect: "manual", signal: AbortSignal.timeout(timeoutMs),
        ...(phase === "authoritative" ? { headers: { authorization: "Bearer " + token } } : {}),
      });
      status = response.status;
      raw = await response.text();
      if (phase === "authoritative" || status !== 200) {
        try { data = JSON.parse(raw); }
        catch { malformed = true; }
      }
    } catch (error) { failure = error; }
    const object = data !== null && typeof data === "object" && !Array.isArray(data);
    await record({
      attempt: ++attempt, phase, node_id: node + 1, method: "GET",
      original_budget_ms: budgetMs, original_deadline_ms: deadline,
      timeout_ms: timeoutMs, invoked_ms: invoked, result_ms: now(),
      http_status: status, code: object ? data.code ?? null : null,
      response_body: raw, malformed_json: malformed,
      transport_error: failure ? { name: failure.name, message: failure.message } : null,
    });
    // A late HTTP 200 is retained as an attempt, but cannot extend the budget.
    remaining();
    if (phase === "authoritative") {
      if (failure) throw failure;
      assert.equal(malformed, false, "fresh membership read returned malformed JSON");
      assert.ok(object, "fresh membership read must return a JSON object");
    }
    return { status, data, failure };
  }

  async function discover() {
    for (;;) {
      remaining();
      assertLive();
      for (const node of nodes) {
        const result = await get(node, "readiness");
        if (!result.failure && result.status === 200) return node;
      }
      await pause(Math.min(100, remaining()));
    }
  }

  for (;;) {
    const leader = await discover();
    const result = await get(leader, "authoritative");
    if (result.status === 409 && result.data.code === "NOT_LEADER") continue;
    assert.equal(result.status, 200, "fresh membership read must succeed on the ready leader");
    assert.equal(result.data.code, undefined, "successful membership read must not contain an error code");
    const view = result.data.membership ?? result.data;
    assert.ok(view.conf_state, "membership must include the complete durable configuration");
    assert.ok(["voters", "learners", "voters_outgoing", "learners_next"].every((field) => Array.isArray(view.conf_state[field]))
      && typeof view.conf_state.auto_leave === "boolean", "membership must include the complete durable configuration");
    remaining();
    return { leader, view };
  }
}
