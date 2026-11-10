/** Actual SDK process. Every original fetch and saved intent is observed. */
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { openSync, closeSync, readFileSync, writeSync, fsyncSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { Client, RoutedClient, OwnerClient } from '../../sdk/node/src/client.js';

const configuration = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const { plan, node, endpoints, tokens, evidence } = configuration;
const commands = new Map(plan.commands.map((value) => [value.id, value]));
const intents = new Map(), used = new Set(), pending = new Set(), observedFetches = new Set();
const sha = (value) => createHash('sha256').update(value).digest('hex');
let sequence = 0, serial = 0;

function emit(event, fields = {}) {
  const row = { schema: 1, node, sequence: ++sequence, monotonic_ns: process.hrtime.bigint().toString(), event, ...fields };
  const raw = JSON.stringify(row) + '\n';
  const descriptor = openSync(`${evidence}/node-${node}.jsonl`, 'a', 0o600);
  try { writeSync(descriptor, raw); fsyncSync(descriptor); } finally { closeSync(descriptor); }
  process.stdout.write(raw);
}

function safe(value) {
  if (typeof value === 'bigint') return { integer: value.toString() };
  if (value instanceof Uint8Array) {
    const bytes = Buffer.from(value); return { bytes: bytes.toString('base64'), sha256: sha(bytes) };
  }
  if (Array.isArray(value)) return value.map(safe);
  if (value !== null && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, safe(child)]));
  return value;
}

function failure(error) {
  const output = { name: error.name, code: error.code ?? null };
  for (const key of ['outcome', 'phase', 'intent', 'lastConfirmed', 'reference', 'receipt', 'rawResult']) {
    if (error[key] !== undefined) output[key] = safe(error[key]);
  }
  return output;
}

function save(kind, key, raw) {
  const file = `${kind}-${key}.json`;
  const descriptor = openSync(`${evidence}/${file}`, 'wx', 0o600);
  try { writeSync(descriptor, raw); fsyncSync(descriptor); } finally { closeSync(descriptor); }
  emit(`saved_${kind}`, { command: currentCommand(key), key, file, raw: Buffer.from(raw).toString('base64'), sha256: sha(raw) });
}

function currentCommand(key) { return key.startsWith('seed_') ? 'seed' : key; }

function transport(command) {
  return (url, options) => {
    const number = ++serial, body = Buffer.from(options.body), headers = new Headers(options.headers);
    headers.set('X-SCAP-Fixture-Command', command);
    const credential = headers.get('authorization').replace(/^Bearer /, '');
    emit('http_request', { command, serial: number, url: String(url), method: options.method,
      body: body.toString('base64'), body_sha256: sha(body), credential_sha256: sha(credential),
      admission: headers.get('x-scap-admission') });
    const observed = (async () => {
      try {
        const response = await globalThis.fetch(url, { ...options, headers });
        const raw = Buffer.from(await response.clone().arrayBuffer());
        emit('http_response', { command, serial: number, status: response.status,
          body: raw.toString('base64'), body_sha256: sha(raw) });
        return response;
      } catch (error) {
        emit('http_error', { command, serial: number, error_name: error.name });
        throw error;
      }
    })();
    observedFetches.add(observed);
    observed.then(() => observedFetches.delete(observed), () => observedFetches.delete(observed));
    return observed;
  };
}

function options(command, caller = 'writer') {
  const principal = plan.principals[caller] ?? plan.principals.writer;
  return { endpoint: endpoints[command.bootstrap ?? 'a'], token: tokens[caller],
    scope: plan.scopes[command.scope], principal, allowInsecureHttp: true,
    timeoutMs: plan.deadlines.client_ms, recoveryTimeoutMs: plan.deadlines.owner_ms,
    fetch: transport(command.id) };
}

function routedOptions(command, caller = command.caller ?? 'writer') {
  const { endpoint, ...rest } = options(command, caller);
  let routes = Object.entries(plan.workers).map(([key, workerInstance]) => ({ workerInstance, endpoint: endpoints[key] }));
  if (command.registry === 'misbound') {
    routes = routes.filter((route) => route.workerInstance !== plan.workers.c)
      .map((route) => route.workerInstance === plan.workers.b ? { ...route, endpoint: endpoints.c } : route);
  } else if (command.registry === 'unknown') routes = routes.filter((route) => route.workerInstance !== plan.workers.a);
  else if (command.registry === 'changed') {
    routes = routes.map((route) => ({ ...route, endpoint: route.workerInstance === plan.workers.b ? endpoints.c :
      route.workerInstance === plan.workers.c ? endpoints.b : route.endpoint }));
  }
  return { ...rest, bootstrapEndpoint: endpoint, routes };
}

function owner(command) { return new OwnerClient(routedOptions(command, 'manager')); }
function direct(command, caller = command.caller ?? 'writer') { return new Client(options(command, caller)); }
function request(client, key) { return client.restore(readFileSync(`${evidence}/request-${key}.json`, 'utf8')); }

function restored(client, command) {
  const file = `intent-${command.intent}.json`, raw = readFileSync(`${evidence}/${file}`, 'utf8');
  emit('restored_intent', { command: command.id, key: command.intent, file,
    raw: Buffer.from(raw).toString('base64'), sha256: sha(raw) });
  return client.restoreIntent(raw);
}

async function execute(command) {
  const scope = plan.scopes[command.scope];
  switch (command.operation) {
    case 'seed': {
      const acknowledgements = {};
      for (const [index, name] of plan.seed_scopes.entries()) {
        const client = direct({ ...command, scope: name });
        const nonce = plan.seed_nonce_base + index * 10;
        await client.create({ nonce: String(nonce) });
        await client.activate({ expectedRevision: '1', nonce: String(nonce + 1), expectedWorkerInstance: plan.workers.a });
        const fixed = client.prepare(plan.seed_sql.map((sql) => ({ sql, parameters: [] })), { epoch: '1', id: '1' });
        save('request', `seed_${name}`, client.save(fixed));
        acknowledgements[name] = await client.execute(fixed);
        await client.setPolicy({ expectedRevision: '3', nonce: String(nonce + 2), permissions: plan.policy });
      }
      return acknowledgements;
    }
    case 'prepare': {
      const client = owner(command), observed = await client.observe();
      const intent = client.prepareTakeover(observed, { targetWorker: plan.workers[command.target],
        takeoverNonce: command.takeover_nonce, activateNonce: command.activate_nonce });
      intents.set(command.id, intent); save('intent', command.id, client.saveIntent(intent));
      return { observed, intent };
    }
    case 'prepare_activation': {
      const client = owner(command), observed = await client.observe();
      const intent = client.prepareActivation(observed, { activateNonce: command.activate_nonce });
      intents.set(command.id, intent); save('intent', command.id, client.saveIntent(intent));
      return { observed, intent };
    }
    case 'reconcile': case 'reuse': return owner(command).reconcile(intents.get(command.intent));
    case 'inspect': return owner(command).inspect(intents.get(command.intent));
    case 'restore_reuse': {
      const client = owner(command); return client.reconcile(restored(client, command));
    }
    case 'restore_inspect': {
      const client = owner(command); return client.inspect(restored(client, command));
    }
    case 'restore_invalid_route': {
      const client = owner({ ...command, registry: 'changed' }); return restored(client, command);
    }
    case 'restore_wrong_scope': {
      const configured = routedOptions(command, 'manager');
      const client = new OwnerClient({ ...configured, scope: { ...scope, generation: '2' } });
      return restored(client, command);
    }
    case 'routed_execute': {
      const client = new RoutedClient(routedOptions(command));
      const fixed = client.prepare([{ sql: plan.write_sql, parameters: [] }], { epoch: '1', id: command.request_id });
      save('request', command.id, client.save(fixed));
      return client.execute(fixed, command.timeout_ms === undefined ? undefined : { timeoutMs: command.timeout_ms });
    }
    case 'routed_query': return new RoutedClient(routedOptions(command)).query([{ sql: plan.query_sql, parameters: [] }]);
    case 'lookup': case 'cancel': {
      const client = direct(command); return client[command.operation](request(client, command.request));
    }
    case 'status': return direct(command).status();
    case 'quota': return direct(command, 'manager').setQuota({ expectedRevision: command.revision, nonce: command.nonce, maxBytes: null });
    case 'revoke_admin': return direct(command, 'rescue').setPolicy({ expectedRevision: command.revision, nonce: command.nonce,
      permissions: plan.policy.map((permission) => permission.principal === plan.principals.manager ? { ...permission, admin: false } : permission) });
    case 'lifecycle': return direct(command, 'manager').setLifecycle({ expectedRevision: command.revision, nonce: command.nonce, lifecycle: 'maintenance' });
    default: throw new Error('Unplanned fixture operation');
  }
}

emit('hello', { self_pid: process.pid, pid_source: 'node_process.pid', version: process.version });
const input = createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of input) {
  const offered = JSON.parse(line);
  if (offered.id === 'shutdown') {
    if (pending.size !== 0) throw new Error('pending SDK calls at shutdown');
    // The SDK deadline can win its Promise race before an aborted Fetch has
    // emitted the final raw observation. This waits only for issued observers;
    // it does not renew a product deadline or dispatch another request.
    await Promise.allSettled([...observedFetches]);
    emit('finished', { commands: used.size, http_attempts: serial });
    input.close(); break;
  }
  const command = commands.get(offered.id);
  if (!command || used.has(command.id) || (command.node ?? 1) !== node) throw new Error('Unplanned or repeated operator input');
  used.add(command.id); emit('command_started', { command: command.id });
  const work = execute(command).then((value) => emit('command_finished', { command: command.id, ok: true, value: safe(value) }),
    (error) => emit('command_finished', { command: command.id, ok: false, error: failure(error) }));
  pending.add(work); work.finally(() => pending.delete(work));
}
process.stdin.pause();
