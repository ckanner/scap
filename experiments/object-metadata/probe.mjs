/** One explicit SDK invocation per offered command; no retry or metadata model. */
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { openSync, closeSync, readFileSync, writeSync, fsyncSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { Client } from '../../sdk/node/src/client.js';
import { createLedger } from '../object-service/client_ledger.mjs';

const configuration = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const { plan, endpoints, tokens, evidence } = configuration;
const commands = new Map(plan.commands.map((command) => [command.id, command]));
const used = new Set(), pending = new Set(), observedFetches = new Set();
const sha = (raw) => createHash('sha256').update(raw).digest('hex');
const ledger = createLedger(evidence, 'metadata');
let sequence = 0, shutdown = false;

function bytes(prefix, raw) {
  const value = Buffer.from(raw);
  return { [`${prefix}_base64`]: value.toString('base64'), [`${prefix}_bytes`]: value.length,
    [`${prefix}_sha256`]: sha(value) };
}

function emit(event, fields = {}) {
  const row = { schema: 1, sequence: ++sequence, monotonic_ns: process.hrtime.bigint().toString(),
    event, node: 1, ...fields };
  const raw = JSON.stringify(row) + '\n';
  if (Buffer.byteLength(raw) > plan.limits.node_line_bytes) throw new Error('Fixture evidence line exceeds fixed limit');
  const descriptor = openSync(`${evidence}/metadata-node.jsonl`, 'a', 0o600);
  try { writeSync(descriptor, raw); fsyncSync(descriptor); } finally { closeSync(descriptor); }
  process.stdout.write(raw);
}

function safe(value) {
  if (typeof value === 'bigint') return { integer: value.toString() };
  if (value instanceof Uint8Array) return bytes('body', value);
  if (Array.isArray(value)) return value.map(safe);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, safe(child)]));
  }
  return value;
}

function failure(error) {
  const names = new Set(['ClientError', 'RemoteError', 'UnknownError', 'CommittedResultError',
    'TypeError', 'Error', 'AbortError', 'TimeoutError']);
  const codes = new Set(['INVALID', 'PROTOCOL', 'TRANSPORT', 'ABORTED', 'DEADLINE', 'UNKNOWN',
    'CORRUPT', 'CONFLICT', 'DENIED', 'UNAUTHENTICATED', 'BACKPRESSURE', 'UNAVAILABLE',
    'TARGET_MISMATCH', 'LIFECYCLE', 'COMMITTED_BUT_UNAVAILABLE']);
  return { name: names.has(error?.name) ? error.name : 'UNKNOWN',
    code: codes.has(error?.code) ? error.code : 'UNKNOWN' };
}

function client(command) {
  const original = ledger.transport(command.id);
  const fetch = (url, options) => {
    const headers = new Headers(options.headers);
    headers.set('X-SCAP-Fixture-Command', command.id);
    const authorization = headers.get('authorization');
    if (authorization !== `Bearer ${tokens[command.caller]}`) throw new Error('Fixture credential identity differs');
    emit('fetch_authorization', { command: command.id, worker: command.worker,
      credential_sha256: sha(tokens[command.caller]) });
    // The frozen recorder performs exactly one original Fetch. Signal, body,
    // redirect policy and product deadline are passed through unchanged.
    const observed = original(url, { ...options, headers });
    observedFetches.add(observed);
    observed.then(() => observedFetches.delete(observed), () => observedFetches.delete(observed));
    return observed;
  };
  return new Client({ endpoint: endpoints[command.worker], token: tokens[command.caller],
    scope: plan.scopes[command.scope], principal: plan.principals[command.caller],
    allowInsecureHttp: true, timeoutMs: plan.deadlines.client_ms,
    recoveryTimeoutMs: plan.deadlines.owner_ms, fetch });
}

async function execute(command) {
  const connection = client(command);
  switch (command.operation) {
    case 'create': return connection.create({ nonce: command.nonce });
    case 'activate': case 'takeover': return connection[command.operation]({
      expectedRevision: command.revision, nonce: command.nonce, expectedWorkerInstance: command.expected_worker });
    case 'status': return connection.status();
    case 'policy': return connection.setPolicy({ expectedRevision: command.revision,
      nonce: command.nonce, permissions: command.permissions });
    case 'execute': {
      const request = connection.prepare(plan.seed_sql.map((sql) => ({ sql, parameters: [] })), { epoch: '1', id: '1' });
      const raw = connection.save(request), file = `request-${command.scope}.json`;
      const descriptor = openSync(`${evidence}/${file}`, 'wx', 0o600);
      try { writeSync(descriptor, raw); fsyncSync(descriptor); } finally { closeSync(descriptor); }
      emit('saved_request', { command: command.id, scope: command.scope, file, ...bytes('raw', raw) });
      return connection.execute(request);
    }
    default: throw new Error('Unplanned fixture operation');
  }
}

emit('hello', { self_pid: process.pid, pid_source: 'node_process.pid', version: process.version });
const input = createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of input) {
  if (Buffer.byteLength(line) > plan.limits.node_line_bytes) throw new Error('Fixture command line exceeds fixed limit');
  const offered = JSON.parse(line);
  if (Object.keys(offered).length !== 1 || typeof offered.id !== 'string') throw new Error('Invalid operator input');
  if (offered.id === 'shutdown') {
    if (shutdown || used.size !== commands.size) throw new Error('Incomplete or repeated shutdown');
    shutdown = true;
    await Promise.all([...pending]);
    // A deadline can settle before an issued Fetch observer. Waiting for that
    // already-issued observer does not dispatch anything or renew its budget.
    await Promise.allSettled([...observedFetches]);
    ledger.close();
    emit('finished', { commands: used.size, http_attempts: ledger.attempts() });
    input.close();
    break;
  }
  const command = commands.get(offered.id);
  if (!command || used.has(command.id) || shutdown) throw new Error('Unplanned or repeated operator input');
  used.add(command.id);
  emit('command_started', { command: command.id });
  const work = execute(command).then(
    (value) => emit('command_finished', { command: command.id, call_id: ledger.last(command.id) ?? null, ok: true, value: safe(value) }),
    (error) => emit('command_finished', { command: command.id, call_id: ledger.last(command.id) ?? null, ok: false, error: failure(error) }));
  pending.add(work);
  work.then(() => pending.delete(work), () => pending.delete(work));
}
if (!shutdown) throw new Error('Operator closed input without explicit shutdown');
process.stdin.pause();
