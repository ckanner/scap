/** Actual SDK probes: one frozen command, at most one original Fetch, no retry. */
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { closeSync, fsyncSync, openSync, readFileSync, writeSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { Client, OwnerClient } from '../../sdk/node/src/client.js';

const { plan, endpoints, tokens, evidence, sink } = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const sha = (raw) => createHash('sha256').update(raw).digest('hex');
const pendingFetches = new Set();
let sequence = 0, serial = 0, commandIndex = 0, pending = false;
let copiedClient, copiedCommand;

function emit(event, fields = {}) {
  const row = { schema: 1, sequence: ++sequence, event,
    monotonic_ns: process.hrtime.bigint().toString(), ...fields };
  const raw = JSON.stringify(row) + '\n';
  if (Buffer.byteLength(raw) > plan.bounds.node_response_bytes) throw new Error('bounded Node event exceeded');
  const fd = openSync(`${evidence}/node.jsonl`, 'a', 0o600);
  try { writeSync(fd, raw); fsyncSync(fd); } finally { closeSync(fd); }
  process.stdout.write(raw);
}

function safe(value) {
  if (typeof value === 'bigint') return { integer: value.toString() };
  if (value instanceof Uint8Array) {
    const raw = Buffer.from(value); return { bytes: raw.toString('base64'), sha256: sha(raw) };
  }
  if (Array.isArray(value)) return value.map(safe);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, safe(v)]));
  }
  return value;
}

async function boundedBody(response) {
  const reader = response.body.getReader(), pieces = [];
  let total = 0;
  try {
    for (;;) {
      const next = await reader.read();
      if (next.done) return Buffer.concat(pieces, total);
      total += next.value.byteLength;
      if (total > plan.bounds.node_response_bytes) {
        await reader.cancel(); throw new Error('bounded observed response exceeded');
      }
      pieces.push(Buffer.from(next.value));
    }
  } finally { reader.releaseLock(); }
}

function transport(commandName) {
  return (url, options) => {
    const command = typeof commandName === 'function' ? commandName() : commandName;
    const number = ++serial, body = Buffer.from(options.body), headers = new Headers(options.headers);
    if (body.byteLength > plan.bounds.request_bytes) throw new Error('bounded observed request exceeded');
    headers.set('X-SCAP-Fixture-Command', command);
    const credential = headers.get('authorization').replace(/^Bearer /, '');
    emit('http_request', { command, serial: number, url: String(url), method: options.method,
      body: body.toString('base64'), body_sha256: sha(body), credential_sha256: sha(credential),
      admission: headers.get('x-scap-admission'), redirect: options.redirect });
    const observed = (async () => {
      try {
        const response = await fetch(url, { ...options, headers });
        const raw = await boundedBody(response.clone());
        emit('http_response', { command, serial: number, status: response.status,
          body: raw.toString('base64'), body_sha256: sha(raw) });
        return response;
      } catch (error) {
        emit('http_error', { command, serial: number, name: error.name }); throw error;
      }
    })();
    pendingFetches.add(observed);
    observed.then(() => pendingFetches.delete(observed), () => pendingFetches.delete(observed));
    return observed;
  };
}

function options(command, fetcher = transport(command.id)) {
  return { endpoint: endpoints[command.worker], token: tokens[command.role], scope: plan.scope,
    principal: plan.principals[command.role] ?? plan.principals.writer, allowInsecureHttp: true,
    timeoutMs: plan.deadlines.client_ms, recoveryTimeoutMs: plan.deadlines.owner_ms, fetch: fetcher };
}

function routes(replacement = false) {
  return ['s', replacement ? 'q' : 'p'].map((worker) =>
    ({ workerInstance: plan.workers[worker], endpoint: endpoints[worker] }));
}

function owner(command, replacement = false, fetcher) {
  const { endpoint, ...rest } = options(command, fetcher);
  return new OwnerClient({ ...rest, bootstrapEndpoint: endpoint, routes: routes(replacement) });
}

async function execute(command) {
  const client = () => new Client(options(command));
  const args = command.arguments;
  switch (command.kind) {
    case 'create': return client().create(args);
    case 'activate': return client().activate(args);
    case 'execute': {
      const actual = client();
      const fixed = actual.prepare(plan.seed_sql.map((sql) => ({ sql, parameters: [] })), plan.request);
      const raw = actual.save(fixed), fd = openSync(`${evidence}/seed-request.json`, 'wx', 0o600);
      try { writeSync(fd, raw); fsyncSync(fd); } finally { closeSync(fd); }
      emit('saved_request', { command: command.id, raw: Buffer.from(raw).toString('base64'), sha256: sha(raw) });
      return actual.execute(fixed);
    }
    case 'policy': return client().setPolicy({ ...args, permissions: plan.policy });
    case 'revoke': return client().setPolicy({ ...args, permissions: plan.policy.map((p) =>
      p.principal === plan.principals.reader ? { ...p, read: false } : p) });
    case 'status': return client().status();
    case 'guarded': return client().guardedStatus(args.guard);
    case 'probe': return owner(command).probe(args.guard,
      args.timeoutMs === undefined ? undefined : { timeoutMs: args.timeoutMs });
    case 'copy_probe': {
      copiedCommand = command.id;
      const { endpoint, ...rest } = options(command, transport(() => copiedCommand));
      const original = routes();
      copiedClient = new OwnerClient({ ...rest, bootstrapEndpoint: endpoint, routes: original });
      emit('registry_constructed', { command: command.id, routes: original });
      original.find((r) => r.workerInstance === plan.workers.p).endpoint = sink;
      emit('caller_registry_mutated', { command: command.id, routes: original });
      return copiedClient.probe(args.guard);
    }
    case 'reuse_probe':
      copiedCommand = command.id;
      if (!copiedClient) throw new Error('original registry client missing');
      emit('original_client_reused', { command: command.id, created_by: 'copied_route' });
      return copiedClient.probe(args.guard);
    case 'new_probe':
      emit('replacement_registry_constructed', { command: command.id, routes: routes(true) });
      return owner(command, true).probe(args.guard);
    case 'raw_status': {
      const response = await transport(command.id)(endpoints[command.worker], {
        method: 'POST', redirect: 'error', signal: AbortSignal.timeout(plan.deadlines.client_ms),
        headers: { Authorization: `Bearer ${tokens[command.role]}`, 'Content-Type': 'application/json',
          'X-SCAP-Admission': 'control' },
        body: JSON.stringify({ version: 1, scope: plan.scope, operation: 'status', expected_worker_instance: args.guard }),
      });
      return { status: response.status, body: JSON.parse((await boundedBody(response)).toString()) };
    }
    case 'lookup': {
      const actual = client(); return actual.lookup(actual.restore(readFileSync(`${evidence}/seed-request.json`, 'utf8')));
    }
    case 'query': return client().query([{ sql: plan.query_sql, parameters: [] }]);
    default: throw new Error('unplanned operation');
  }
}

emit('hello', { self_pid: process.pid, pid_source: 'node_process.pid', version: process.version });
const input = createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of input) {
  const offered = JSON.parse(line);
  if (offered.id === 'shutdown') {
    if (pending) throw new Error('command pending during shutdown');
    await Promise.allSettled([...pendingFetches]);
    emit('finished', { commands: commandIndex, http_attempts: serial });
    input.close(); break;
  }
  const command = plan.commands[commandIndex];
  if (pending || !command || command.id !== offered.id) throw new Error('repeated, concurrent or unplanned command');
  commandIndex += 1; pending = true;
  emit('command_started', { command: command.id });
  execute(command).then((value) => emit('command_finished', { command: command.id, ok: true, value: safe(value) }),
    (error) => emit('command_finished', { command: command.id, ok: false,
      error: { name: error.name, code: error.code ?? null } })).finally(() => { pending = false; });
}
process.stdin.pause();
