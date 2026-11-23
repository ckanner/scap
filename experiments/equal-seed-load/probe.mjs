/** Equal-seed public-SDK probe. Original identities are never resubmitted. */
import { AsyncLocalStorage } from 'node:async_hooks';
import { existsSync, readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { runArrivals } from '../object-overload/schedule.mjs';
import { now, recorder, sha } from './record.mjs';

const [phase, configPath, directory] = process.argv.slice(2);
const config = JSON.parse(readFileSync(configPath));
const workload = JSON.parse(readFileSync(directory + '/workload.json'));
const { Client } = await import(pathToFileURL(config.source_root + '/sdk/node/src/client.js'));
const { append, save, read } = recorder(directory, phase, workload.plan.bounds);
const context = new AsyncLocalStorage(), pending = new Set();
const all = new Map(workload.calls.map((call) => [call.id, call]));
const selected = workload.calls.filter((call) => call.phase === phase);
let issued = 0, failures = 0;

async function capture(url, options) {
  const current = context.getStore();
  if (!current || ++current.posts !== 1) throw new Error('duplicate original POST');
  issued++;
  const headers = new Headers(options.headers);
  append('sdk.jsonl', { event: 'http_request', id: current.id, method: options.method,
    url: String(url), redirect: options.redirect, admission: headers.get('x-scap-admission'),
    token_sha256: sha(config.token), request: save(Buffer.from(options.body)) });
  try {
    const response = await globalThis.fetch(url, options);
    const raw = Buffer.from(await response.arrayBuffer());
    const rejection = response.headers.get('x-scap-rejection');
    append('sdk.jsonl', { event: 'http_response', id: current.id, status: response.status,
      response: save(raw), content_type: response.headers.get('content-type'),
      rejection_header: rejection,
      rejection_header_bytes: rejection === null ? null : save(Buffer.from(rejection, 'utf8')), complete: true });
    return new Response(raw, { status: response.status, headers: response.headers });
  } catch (error) {
    append('sdk.jsonl', { event: 'http_error', id: current.id, error_name: error.name });
    throw error;
  }
}
const client = new Client({ endpoint: config.endpoint + '/v1', token: config.token,
  scope: workload.plan.scope, principal: '11', allowInsecureHttp: true,
  timeoutMs: workload.plan.deadlines.client_ms, recoveryTimeoutMs: workload.plan.deadlines.client_recovery_ms,
  fetch: (url, options) => {
    const task = capture(url, options); context.getStore().http = task; pending.add(task);
    task.then(() => pending.delete(task), () => pending.delete(task)); return task;
  } });
const intents = new Map();
if (existsSync(directory + '/intents.jsonl')) {
  for (const line of readFileSync(directory + '/intents.jsonl', 'utf8').trim().split('\n')) {
    const entry = JSON.parse(line);
    if (intents.has(entry.id)) throw new Error('duplicate original intent');
    intents.set(entry.id, entry.serialized);
  }
}
function statements(call) {
  return call.statements.map((statement) => ({ sql: statement.sql,
    parameters: statement.params.map((value) => Object.hasOwn(value, 'integer') ?
      BigInt(value.integer) : read(workload.payloads[String(value.payload_row)])) }));
}
for (const call of selected) {
  if (call.operation !== 'execute') continue;
  if (intents.has(call.id)) throw new Error('SQL execute replay');
  const intent = client.prepare(statements(call), { epoch: '1', id: call.request_id });
  const serialized = save(Buffer.from(client.save(intent)));
  append('intents.jsonl', { event: 'prepared', id: call.id, serialized });
  intents.set(call.id, serialized);
}
const original = (id) => client.restore(read(intents.get(id)).toString('utf8'));

async function invoke(call, scheduled = now()) {
  return context.run({ id: call.id, posts: 0 }, async () => {
    append('sdk.jsonl', { event: 'call_started', id: call.id, scheduled_ns: scheduled.toString() });
    let value, failure;
    try {
      switch (call.operation) {
        case 'create': value = await client.create({ nonce: call.nonce }); break;
        case 'activate': value = await client.activate({ expectedRevision: '1', nonce: call.nonce }); break;
        case 'execute': value = await client.execute(original(call.id)); break;
        case 'status': value = await client.status(); break;
        case 'query': value = await client.query([{ sql: workload.final_sql, parameters: [] }]); break;
        case 'lookup': value = await client.lookup(original(call.original)); break;
        case 'cancel': value = await client.cancel(original(call.original)); break;
        default: throw new Error('unplanned operation');
      }
    } catch (error) {
      failure = { name: error.name, code: error.code ?? null, outcome: error.outcome ?? null,
        cause_code: error.cause?.code ?? null, resource_rejection: error.resourceRejection ?? null };
      if (error.receipt) failure.receipt = error.receipt;
      if (error.rawResult !== undefined) failure.raw_result = save(Buffer.from(error.rawResult));
    }
    const sdkTerminal = now();
    // A deadline can end the SDK promise before its abort finishes the original
    // fetch. Keep both clocks; the observed call interval includes that drain.
    await Promise.allSettled([context.getStore().http]);
    append('sdk.jsonl', { event: 'call_finished', id: call.id, ok: failure === undefined,
      error: failure ?? null, state: value?.state ?? null, sdk_terminal_ns: sdkTerminal.toString(),
      posts: context.getStore().posts });
    if (failure && (phase === 'seed_rows' || !Object.hasOwn(workload.plan.phases, phase))) failures++;
    return value;
  });
}
async function until(target) {
  while (now() < target) await delay(Math.max(1, Number(target - now()) / 1e6));
}
const origin = now();
append('sdk.jsonl', { event: 'phase_started', origin_ns: origin.toString(), pid: process.pid });
if (Object.hasOwn(workload.plan.phases, phase)) {
  await runArrivals(selected, origin,
    { ...workload.plan.phases[phase], client_inflight_limit: workload.plan.client_inflight_limit }, {
      until, invoke,
      offered(call, scheduled, active) { append('sdk.jsonl', { event: 'call_offered', id: call.id,
        scheduled_ns: scheduled.toString(), active }); },
      rejected(call) { append('sdk.jsonl', { event: 'generator_rejected', id: call.id,
        reason: 'client_inflight_limit', posts: 0 }); },
      arrivalsFinished(active) { append('sdk.jsonl', { event: 'arrivals_finished', active }); },
    });
} else if (phase === 'verify') {
  // All originals, including generator/service rejections, retain their original
  // identity. Cancel only an unknown result; never execute business SQL again.
  for (const call of all.values()) {
    if (call.operation !== 'execute') continue;
    const first = await invoke({ id: 'lookup-' + call.id, operation: 'lookup', original: call.id });
    if (first?.state === 'unknown') {
      await invoke({ id: 'cancel-' + call.id, operation: 'cancel', original: call.id });
      await invoke({ id: 'settled-' + call.id, operation: 'lookup', original: call.id });
    }
  }
  await invoke({ id: 'final', operation: 'query' });
} else {
  if (phase !== 'seed' || selected.length !== 3) throw new Error('unplanned phase');
  for (const call of selected) await invoke(call);
}
await Promise.allSettled([...pending]);
append('sdk.jsonl', { event: 'phase_finished', posts: issued, failures, pid: process.pid });
console.log(JSON.stringify({ phase, posts: issued, failures }));
if (failures) process.exitCode = 1;
