/** Fixed input scheduling and raw observations; every database call uses the public SDK. */
import { AsyncLocalStorage } from 'node:async_hooks';
import { createHash } from 'node:crypto';
import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, rmdirSync, statfsSync, statSync, writeFileSync, writeSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { statements as materializeStatements } from './input.mjs';

const [phase, configPath, evidence] = process.argv.slice(2);
const config = JSON.parse(readFileSync(configPath, 'utf8'));
const workload = JSON.parse(readFileSync(evidence + '/workload.json', 'utf8'));
const { Client } = await import(pathToFileURL(config.source_root + '/sdk/node/src/client.js'));
const now = () => process.hrtime.bigint().toString();
const sha = (raw) => createHash('sha256').update(raw).digest('hex');
const context = new AsyncLocalStorage();
let issued = 0;
const pending = new Set();

function append(file, value) {
  const fd = openSync(evidence + '/' + file, 'a', 0o600);
  try {
    writeSync(fd, JSON.stringify({ phase, monotonic_ns: now(), ...value }) + '\n');
    fsyncSync(fd);
  } finally { closeSync(fd); }
}
function save(raw) {
  if (raw.length > workload.plan.bounds.body_bytes) throw new Error('raw body exceeded bound');
  const digest = sha(raw), name = 'raw/' + digest, path = evidence + '/' + name;
  const lock = evidence + '/raw-lock', until = Date.now() + 10000;
  for (;;) {
    try { mkdirSync(lock, { mode: 0o700 }); break; }
    catch (error) {
      if (error.code !== 'EEXIST' || Date.now() >= until) throw error;
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 5);
    }
  }
  try {
    if (!existsSync(path)) {
      const budgetPath = evidence + '/raw-budget', total = Number(readFileSync(budgetPath, 'utf8'));
      if (!Number.isSafeInteger(total) || total < 0 || total + raw.length > workload.plan.bounds.raw_bytes)
        throw new Error('raw evidence byte budget exhausted');
      // Reserve before writing: failure can leak budget, never create more capacity.
      let fd = openSync(budgetPath, 'w', 0o600);
      try { writeFileSync(fd, String(total + raw.length) + '\n'); fsyncSync(fd); }
      finally { closeSync(fd); }
      fd = openSync(path, 'wx', 0o600);
      try { writeFileSync(fd, raw); fsyncSync(fd); }
      finally { closeSync(fd); }
    }
    if (statSync(path).size !== raw.length) throw new Error('raw body identity changed');
  } finally { rmdirSync(lock); }
  return { file: name, bytes: raw.length, sha256: digest };
}
function read(description) {
  if (!/^raw\/[0-9a-f]{64}$/.test(description.file)) throw new Error('input path');
  const raw = readFileSync(evidence + '/' + description.file);
  if (raw.length !== description.bytes || sha(raw) !== description.sha256) throw new Error('input body changed');
  return raw;
}

function observedFetch(scope) {
  return (url, options) => {
    const observation = capture(url, options);
    pending.add(observation);
    observation.then(() => pending.delete(observation), () => pending.delete(observation));
    return observation;
  };
  async function capture(url, options) {
    const call = context.getStore();
    if (!call || ++call.posts !== 1) throw new Error('duplicate or unbound original POST');
    issued++;
    const headers = new Headers(options.headers);
    const request = save(Buffer.from(options.body));
    append('sdk.jsonl', { event: 'http_request', id: call.id, scope, request,
      url: String(url), method: options.method, redirect: options.redirect,
      token_sha256: sha(config.tokens[workload.plan.scopes[scope].tenant]),
      admission: headers.get('x-scap-admission') });
    try {
      const response = await globalThis.fetch(url, options);
      const body = Buffer.from(await response.arrayBuffer());
      append('sdk.jsonl', { event: 'http_response', id: call.id, scope, status: response.status,
        response: save(body), content_type: response.headers.get('content-type'), complete: true });
      return new Response(body, { status: response.status, headers: response.headers });
    } catch (error) {
      append('sdk.jsonl', { event: 'http_error', id: call.id, scope, error_name: error.name });
      throw error;
    }
  }
}

const clients = Object.fromEntries(Object.entries(workload.plan.scopes).map(([name, scope]) => [name,
  new Client({ endpoint: config.endpoint + '/v1', token: config.tokens[scope.tenant], scope,
    principal: scope.tenant === '7' ? '11' : '22', allowInsecureHttp: true,
    timeoutMs: workload.plan.deadlines.client_ms, recoveryTimeoutMs: workload.plan.deadlines.client_recovery_ms,
    fetch: observedFetch(name) })]));
const all = new Map(workload.calls.map((call) => [call.id, call]));
const selected = workload.calls.filter((call) => call.phase === phase);
if (!selected.length) throw new Error('unplanned phase');
const intents = new Map();
if (existsSync(evidence + '/intents.jsonl')) {
  for (const line of readFileSync(evidence + '/intents.jsonl', 'utf8').trim().split('\n')) {
    const entry = JSON.parse(line);
    if (intents.has(entry.id)) throw new Error('original request identity duplicated');
    intents.set(entry.id, entry.serialized);
  }
}
function statements(call) {
  return materializeStatements(call, read);
}
// All inputs and serialized identities are persistent before the timed phase.
for (const call of selected) {
  if (call.operation !== 'execute') continue;
  if (intents.has(call.id)) throw new Error('business execute would be repeated');
  const client = clients[call.scope];
  const intent = client.prepare(statements(call), { epoch: '1', id: call.request_id });
  const serialized = save(Buffer.from(client.save(intent)));
  append('intents.jsonl', { event: 'prepared', id: call.id, scope: call.scope, serialized });
  intents.set(call.id, serialized);
}
function original(identifier) {
  const call = all.get(identifier);
  return clients[call.scope].restore(read(intents.get(identifier)).toString('utf8'));
}
let failures = 0;
const concurrency = workload.plan.measured[phase]?.[1] ?? (phase === 'cold-probes' ? 4 : 1);
const queued = now();
append('sdk.jsonl', { event: 'phase_started', calls: selected.map((call) => call.id), concurrency, queued_ns: queued, pid: process.pid });

async function invoke(call) {
  return context.run({ id: call.id, posts: 0 }, async () => {
    const space = statfsSync(evidence, { bigint: true });
    if (space.bavail * space.bsize < BigInt(workload.plan.bounds.minimum_free_bytes))
      throw new Error('owned fixture disk space guard before original POST');
    append('sdk.jsonl', { event: 'call_started', id: call.id, scope: call.scope, queued_ns: queued });
    const client = clients[call.scope];
    let value, failure;
    try {
      switch (call.operation) {
        case 'create': value = await client.create({ nonce: call.nonce }); break;
        case 'activate': value = await client.activate({ expectedRevision: call.expected_revision, nonce: call.nonce }); break;
        case 'execute': value = await client.execute(original(call.id)); break;
        case 'query': value = await client.query(statements(call)); break;
        case 'open': value = await client.open(); break;
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
      if (error.receipt && error.rawResult !== undefined) {
        append('acks.jsonl', { event: 'committed', id: call.id, original: call.original ?? call.id,
          receipt: error.receipt, result: save(Buffer.from(error.rawResult)) });
      }
    }
    append('sdk.jsonl', { event: 'call_finished', id: call.id, scope: call.scope,
      ok: failure === undefined, error: failure ?? null, state: value?.state ?? null,
      posts: context.getStore().posts });
    if (call.expected_error) {
      if (failure?.code !== call.expected_error) failures++;
    } else if (failure && !Object.hasOwn(workload.plan.measured, phase)) failures++;
  });
}

await Promise.all(Array.from({ length: concurrency }, async (_, lane) => {
  for (let index = lane; index < selected.length; index += concurrency) await invoke(selected[index]);
}));
// A client deadline can settle before its aborted fetch. Retain that original
// HTTP terminal observation instead of abandoning the recorder at process exit.
await Promise.allSettled([...pending]);
append('sdk.jsonl', { event: 'phase_finished', posts: issued, calls: selected.length, failures, pid: process.pid });
console.log(JSON.stringify({ phase, posts: issued, calls: selected.length, failures }));
if (failures) process.exitCode = 1;
