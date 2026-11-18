/** Bounded open-loop generator; completion never changes future arrival times. */
export async function runArrivals(calls, origin, plan, hooks) {
  const tasks = [], active = new Set();
  for (const call of calls) {
    const scheduled = origin + BigInt(call.offset_ns);
    await hooks.until(scheduled);
    hooks.offered(call, scheduled, active.size);
    if (active.size >= plan.client_inflight_limit) {
      hooks.rejected(call);
      continue;
    }
    const task = hooks.invoke(call, scheduled);
    active.add(task);
    tasks.push(task);
    task.then(() => active.delete(task), () => active.delete(task));
  }
  await hooks.until(origin + BigInt(plan.duration_ms) * 1_000_000n);
  hooks.arrivalsFinished(active.size);
  await Promise.all(tasks);
}
