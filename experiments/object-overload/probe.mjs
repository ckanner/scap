/** Original inputs and bounded arrivals; the public SDK performs every operation. */
import { AsyncLocalStorage } from 'node:async_hooks';
import { createHash } from 'node:crypto';
import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync,
  rmdirSync, statSync, writeFileSync, writeSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { runArrivals } from './schedule.mjs';
import { until } from './arrival_clock.mjs';

const [phase, configPath, directory] = process.argv.slice(2);
const config = JSON.parse(readFileSync(configPath));
const workload = JSON.parse(readFileSync(directory + '/workload.json'));
const { Client } = await import(pathToFileURL(config.source_root + '/sdk/node/src/client.js'));
const now = () => process.hrtime.bigint();
const sha = (raw) => createHash('sha256').update(raw).digest('hex');
const context = new AsyncLocalStorage(), pendingHttp = new Set();
const all = new Map(workload.calls.map((call) => [call.id, call]));
const selected = workload.calls.filter((call) => call.phase === phase);
if (!selected.length) throw new Error('unplanned phase');
let issued = 0, failures = 0;

function append(file, fields) {
  const fd = openSync(directory + '/' + file, 'a', 0o600);
  try {
    writeSync(fd, JSON.stringify({ phase, monotonic_ns: now().toString(), ...fields }) + '\n');
    fsyncSync(fd);
  } finally { closeSync(fd); }
}

function save(raw) {
  if (raw.length > workload.plan.bounds.body_bytes) throw new Error('body evidence bound');
  const digest = sha(raw), name = 'raw/' + digest, path = directory + '/' + name;
  const lock = directory + '/raw-lock', deadline = Date.now() + 10000;
  for (;;) {
    try { mkdirSync(lock, { mode: 0o700 }); break; }
    catch (error) {
      if (error.code !== 'EEXIST' || Date.now() >= deadline) throw error;
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 5);
    }
  }
  try {
    if (!existsSync(path)) {
      const budgetPath = directory + '/raw-budget', used = Number(readFileSync(budgetPath, 'utf8'));
      if (!Number.isSafeInteger(used) || used < 0 || used + raw.length > workload.plan.bounds.raw_bytes)
        throw new Error('raw evidence budget');
      let fd = openSync(budgetPath, 'w', 0o600);
      try { writeFileSync(fd, String(used + raw.length) + '\n'); fsyncSync(fd); }
      finally { closeSync(fd); }
      fd = openSync(path, 'wx', 0o600);
      try { writeFileSync(fd, raw); fsyncSync(fd); }
      finally { closeSync(fd); }
    }
    if (statSync(path).size !== raw.length) throw new Error('raw body identity');
  } finally { rmdirSync(lock); }
  return { file: name, bytes: raw.length, sha256: digest };
}

function read(description) {
  if (!/^raw\/[0-9a-f]{64}$/.test(description.file)) throw new Error('input path');
  const raw = readFileSync(directory + '/' + description.file);
  if (raw.length !== description.bytes || sha(raw) !== description.sha256) throw new Error('input identity');
  return raw;
}

function observedFetch(scope) {
  return (url, options) => {
    const task = capture(url, options);
    pendingHttp.add(task);
    task.then(() => pendingHttp.delete(task), () => pendingHttp.delete(task));
    return task;
  };
  async function capture(url, options) {
    const current = context.getStore();
    if (!current || ++current.posts !== 1) throw new Error('duplicate original POST');
    issued++;
    const headers = new Headers(options.headers);
    append('sdk.jsonl', { event: 'http_request', id: current.id, scope,
      method: options.method, url: String(url), redirect: options.redirect,
      admission: headers.get('x-scap-admission'), request: save(Buffer.from(options.body)),
      token_sha256: sha(config.tokens[workload.plan.scopes[scope].tenant]) });
    try {
      const response = await globalThis.fetch(url, options);
      const raw = Buffer.from(await response.arrayBuffer());
      append('sdk.jsonl', { event: 'http_response', id: current.id, scope,
        status: response.status, complete: true, content_type: response.headers.get('content-type'),
        response: save(raw) });
      return new Response(raw, { status: response.status, headers: response.headers });
    } catch (error) {
      append('sdk.jsonl', { event: 'http_error', id: current.id, scope, error_name: error.name });
      throw error;
    }
  }
}

const clients = Object.fromEntries(Object.entries(workload.plan.scopes).map(([name, scope]) => [name,
  new Client({ endpoint: config.endpoint + '/v1', token: config.tokens[scope.tenant], scope,
    principal: scope.tenant === '7' ? '11' : '22', allowInsecureHttp: true,
    timeoutMs: workload.plan.deadlines.client_ms,
    recoveryTimeoutMs: workload.plan.deadlines.client_recovery_ms, fetch: observedFetch(name) })]));
const intents = new Map();
if (existsSync(directory + '/intents.jsonl')) {
  for (const line of readFileSync(directory + '/intents.jsonl', 'utf8').trim().split('\n')) {
    const item = JSON.parse(line);
    if (intents.has(item.id)) throw new Error('original identity duplicated');
    intents.set(item.id, item.serialized);
  }
}
function statements(call) {
  return call.statements.map((statement) => ({ sql: statement.sql,
    parameters: statement.params.map((value) => Object.hasOwn(value, 'integer') ?
      BigInt(value.integer) : read(workload.payloads[String(value.payload_row)])) }));
}
for (const call of selected) {
  if (call.operation !== 'execute') continue;
  if (intents.has(call.id)) throw new Error('execute would be repeated');
  const client = clients[call.scope];
  const request = client.prepare(statements(call), { epoch: '1', id: call.request_id });
  const serialized = save(Buffer.from(client.save(request)));
  append('intents.jsonl', { event: 'prepared', id: call.id, scope: call.scope, serialized });
  intents.set(call.id, serialized);
}
function original(identifier) {
  return clients[all.get(identifier).scope].restore(read(intents.get(identifier)).toString('utf8'));
}

async function invoke(call, scheduled) {
  return context.run({ id: call.id, posts: 0 }, async () => {
    append('sdk.jsonl', { event: 'call_started', id: call.id, scope: call.scope, scheduled_ns: scheduled.toString() });
    const client = clients[call.scope];
    let value, failure;
    try {
      switch (call.operation) {
        case 'create': value = await client.create({ nonce: call.nonce }); break;
        case 'activate': value = await client.activate({ expectedRevision: call.expected_revision, nonce: call.nonce }); break;
        case 'execute': value = await client.execute(original(call.id)); break;
        case 'query': value = await client.query(statements(call)); break;
        case 'status': value = await client.status(); break;
        case 'lookup': value = await client.lookup(original(call.original)); break;
        case 'cancel': value = await client.cancel(original(call.original)); break;
        default: throw new Error('unplanned operation');
      }
      if (value?.state === 'committed') {
        append('acks.jsonl', { event: 'committed', id: call.id, original: call.original ?? call.id,
          receipt: value.receipt, result: save(Buffer.from(value.rawResult)) });
      }
    } catch (error) {
      failure = { name: error.name, code: error.code ?? null, outcome: error.outcome ?? null };
      if (error.receipt) failure.receipt = error.receipt;
      if (error.receipt && error.rawResult !== undefined)
        append('acks.jsonl', { event: 'committed', id: call.id, original: call.original ?? call.id,
          receipt: error.receipt, result: save(Buffer.from(error.rawResult)) });
    }
    append('sdk.jsonl', { event: 'call_finished', id: call.id, scope: call.scope,
      ok: failure === undefined, error: failure ?? null, state: value?.state ?? null,
      posts: context.getStore().posts });
    if (failure && phase !== 'overload') failures++;
  });
}

const started = now();
append('sdk.jsonl', { event: 'phase_started', calls: selected.map((call) => call.id),
  origin_ns: started.toString(), pid: process.pid });
if (phase === 'overload') {
  await runArrivals(selected, started, workload.plan, {
    until,
    offered(call, scheduled, active) {
      append('sdk.jsonl', { event: 'call_offered', id: call.id, scope: call.scope,
        scheduled_ns: scheduled.toString(), active });
    },
    rejected(call) {
      append('sdk.jsonl', { event: 'generator_rejected', id: call.id, scope: call.scope,
        reason: 'client_inflight_limit', posts: 0 });
      failures++;
    },
    invoke,
    arrivalsFinished(active) {
      append('sdk.jsonl', { event: 'arrivals_finished', planned: selected.length, active });
    },
  });
} else {
  for (const call of selected) await invoke(call, now());
}
await Promise.allSettled([...pendingHttp]);
append('sdk.jsonl', { event: 'phase_finished', calls: selected.length, posts: issued, failures, pid: process.pid });
console.log(JSON.stringify({ phase, calls: selected.length, posts: issued, failures }));
if (failures) process.exitCode = 1;
