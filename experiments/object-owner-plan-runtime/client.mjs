/** Public SDK only. Originals survive controllers; Prepared brands never do. */
import { createHash } from 'node:crypto';
import { AsyncLocalStorage } from 'node:async_hooks';
import { closeSync, existsSync, fsyncSync, linkSync, openSync, readFileSync,
  unlinkSync, writeFileSync, writeSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { pathToFileURL } from 'node:url';

const [configuration, evidence, role] = process.argv.slice(2);
const config = JSON.parse(readFileSync(configuration, 'utf8'));
const { Client, CatalogueClient, OwnerPlanClient } = await import(
  pathToFileURL(config.source_root + '/sdk/node/src/client.js'));
const sha = (value) => createHash('sha256').update(value).digest('hex');
const safe = (value) => JSON.parse(JSON.stringify(value,
  (_, item) => typeof item === 'bigint' ? item.toString() : item));
let sequence = 0;
const invocation = new AsyncLocalStorage();

function emit(event, fields = {}) {
  const fd = openSync(evidence + '/sdk-' + role + '.jsonl', 'a', 0o600);
  try {
    writeSync(fd, JSON.stringify({ sequence: ++sequence, monotonic_ns: process.hrtime.bigint().toString(),
      event, role, ...fields }) + '\n'); fsyncSync(fd);
  } finally { closeSync(fd); }
}

function archive(value) {
  const bytes = Buffer.from(value), digest = sha(bytes), file = 'raw/' + digest;
  const temporary = evidence + '/raw/.sdk-' + role + '-' + process.pid + '-' + process.hrtime.bigint();
  const fd = openSync(temporary, 'wx', 0o600);
  try { writeFileSync(fd, bytes); fsyncSync(fd); } finally { closeSync(fd); }
  try {
    try { linkSync(temporary, evidence + '/' + file); }
    catch (error) {
      if (error.code !== 'EEXIST' || sha(readFileSync(evidence + '/' + file)) !== digest) throw error;
    }
  } finally { unlinkSync(temporary); }
  return { file, bytes: bytes.length, sha256: digest };
}

function ledger(path) {
  if (!existsSync(path)) return [];
  const raw = readFileSync(path, 'utf8');
  if (!raw.endsWith('\n')) throw new Error('incomplete original input ledger');
  return raw.trimEnd().split('\n').map((line) => JSON.parse(line));
}

function appendOriginal(file, row, event) {
  const path = evidence + '/' + file;
  if (ledger(path).some((previous) => previous.name === row.name))
    throw new Error('original identity was already saved');
  const bytes = Buffer.from(JSON.stringify(row) + '\n');
  const fd = openSync(path, 'a', 0o600);
  try { writeSync(fd, bytes); fsyncSync(fd); } finally { closeSync(fd); }
  emit(event, { name: row.name, original: archive(bytes) });
}

function original(file, name) {
  const matches = ledger(evidence + '/' + file).filter((row) => row.name === name);
  if (matches.length !== 1) throw new Error('missing or repeated original identity');
  return matches[0];
}

const databaseClients = new Map(), catalogues = new Map(), ownerClients = new Map();
const prepared = new Map(), pending = new Map();

function transport(principal) {
  if (!Object.hasOwn(config.tokens, principal)) throw new Error('unconfigured principal');
  return { token: config.tokens[principal], allowInsecureHttp: true,
    timeoutMs: config.timeouts.sdk_ms, recoveryTimeoutMs: config.timeouts.recovery_ms,
    fetch: async (url, options) => {
      const context = invocation.getStore();
      if (!context) throw new Error('Fetch has no original command context');
      const ordinal = ++context.attempts, command = context.command.id;
      emit('http_request', { command, ordinal, method: options.method, url: String(url),
        principal, token_sha256: sha(config.tokens[principal]), headers: Object.fromEntries(
          [...new Headers(options.headers)].filter(([name]) => name !== 'authorization')),
        request: archive(Buffer.from(options.body)) });
      try {
        const response = await globalThis.fetch(url, options);
        const bytes = Buffer.from(await response.arrayBuffer());
        emit('http_response', { command, ordinal, complete: true, status: response.status,
          response: archive(bytes) });
        return new Response(bytes, { status: response.status, headers: response.headers });
      } catch (error) {
        emit('http_error', { command, ordinal, name: error.name });
        throw error;
      }
    } };
}

function client(name, principal = '11') {
  const key = name + ':' + principal;
  if (!databaseClients.has(key)) databaseClients.set(key, new Client({ ...transport(principal),
    endpoint: config.endpoint + '/v1', scope: config.scopes[name], principal }));
  return databaseClients.get(key);
}

function catalogue(principal = '11') {
  if (!catalogues.has(principal)) catalogues.set(principal, new CatalogueClient({ ...transport(principal),
    endpoint: config.endpoint + '/v1/catalogue', deployment: '1', tenant: '7', principal }));
  return catalogues.get(principal);
}

function owner(name, principal = '11', bootstrap) {
  if (bootstrap !== undefined && !Object.hasOwn(config.workerEndpoints, bootstrap))
    throw new Error('unconfigured metadata bootstrap');
  const endpoint = bootstrap === undefined ? config.endpoint : config.workerEndpoints[bootstrap];
  const key = name + ':' + principal + ':' + endpoint;
  if (!ownerClients.has(key)) ownerClients.set(key, new OwnerPlanClient({ ...transport(principal),
    bootstrapEndpoint: endpoint + '/v1', routes: config.routes,
    scope: config.scopes[name], principal }));
  return ownerClients.get(key);
}

function statements(value) {
  return value.map((item) => {
    if (Object.keys(item).sort().join(',') !== 'params,sql' || !Array.isArray(item.params) || item.params.length)
      throw new Error('fixed native statement shape');
    return { sql: item.sql, parameters: [] };
  });
}

function sqlIntent(name, principal) {
  const originals = JSON.parse(readFileSync(evidence + '/intents.json', 'utf8'));
  if (!Object.hasOwn(originals, name)) throw new Error('missing original SQL identity');
  const saved = originals[name];
  return client(saved.scope_name, principal).restore(saved.serialized);
}

function savedOwner(name, principal) {
  const row = original('owner-inputs.jsonl', name);
  return owner(row.scope_name, principal).restoreInput(row.serialized);
}

function preparedOwner(name) {
  if (!prepared.has(name)) throw new Error('this controller has no verified Prepared value; inspect the original input');
  return prepared.get(name);
}

async function perform(command) {
  const principal = command.principal ?? '11', input = command.input, options = command.options;
  if (command.operation === 'prepare_sql') {
    if (existsSync(evidence + '/intents.json')) throw new Error('original SQL already saved');
    const originals = {};
    for (const spec of command.specs) {
      const value = client(spec.scope_name).prepare(statements(spec.statements),
        { epoch: spec.epoch, id: spec.request_id });
      const serialized = client(spec.scope_name).save(value);
      if (client(spec.scope_name).save(client(spec.scope_name).restore(serialized)) !== serialized)
        throw new Error('original SQL save/restore changed its identity');
      if (Object.hasOwn(originals, spec.name)) throw new Error('duplicate original SQL name');
      originals[spec.name] = { scope_name: spec.scope_name, serialized };
    }
    const bytes = Buffer.from(JSON.stringify(originals, null, 2) + '\n');
    const fd = openSync(evidence + '/intents.json', 'wx', 0o600);
    try { writeFileSync(fd, bytes); fsyncSync(fd); } finally { closeSync(fd); }
    emit('intents_prepared', { count: command.specs.length, original: archive(bytes) });
    return { prepared: command.specs.length };
  }
  if (command.operation === 'owner_save') {
    const value = owner(command.scope_name, principal);
    const tracked = value.prepareInput(input), serialized = value.saveInput(tracked);
    if (value.saveInput(value.restoreInput(serialized)) !== serialized)
      throw new Error('original owner save/restore changed its identity');
    appendOriginal('owner-inputs.jsonl', { name: command.intent, scope_name: command.scope_name,
      role, principal, serialized }, 'owner_input_saved');
    return safe(tracked);
  }
  if (command.operation.startsWith('owner_')) {
    const value = owner(command.scope_name, principal, command.bootstrap_worker), name = command.intent;
    switch (command.operation) {
      case 'owner_prepare': {
        const result = await value.prepare(savedOwner(name, principal), options);
        if (result.state === 'prepared') prepared.set(name, result.prepared);
        else pending.set(name, result);
        return result;
      }
      case 'owner_inspect': {
        const result = await value.inspect(savedOwner(name, principal), options);
        prepared.set(name, result.prepared);
        return result;
      }
      case 'owner_observe': return value.observe(input, options);
      case 'owner_claim': return value.claim(preparedOwner(name), options);
      case 'owner_resume': return value.resume(preparedOwner(name), options);
      case 'owner_abort': return value.abort(preparedOwner(name), options);
      case 'owner_claim_pending': return value.claim(pending.get(name), options);
      case 'owner_unbranded': {
        const copy = safe(preparedOwner(name));
        return value.claim(copy, options);
      }
      default: throw new Error('unplanned owner command');
    }
  }
  if (command.operation === 'named') {
    const value = catalogue(principal), tracked = value.prepareIntent(input);
    appendOriginal('named-intents.jsonl', { name: command.intent, scope_name: command.scope_name,
      role, principal, serialized: value.saveIntent(tracked) }, 'named_intent_prepared');
    return value.submit(tracked, options);
  }
  if (command.operation === 'named_submit') {
    const row = original('named-intents.jsonl', command.intent);
    return catalogue(principal).submit(catalogue(principal).restoreIntent(row.serialized), options);
  }
  const value = client(command.scope_name, principal);
  switch (command.operation) {
    case 'create': return value.create(input, options);
    case 'status': return value.status(options);
    case 'storage_status': return value.storageStatus(options);
    case 'retire_storage': return value.retireStorage(input, options);
    case 'open': return value.open(options);
    case 'activate': return value.activate(input, options);
    case 'takeover': return value.takeover(input, options);
    case 'policy': return value.setPolicy(input, options);
    case 'lifecycle': return value.setLifecycle(input, options);
    case 'close_full': return value.closeFull(input, options);
    case 'query': return value.query(statements(command.statements), options);
    case 'execute': return value.execute(sqlIntent(command.intent, principal), options);
    case 'lookup': return value.lookup(sqlIntent(command.intent, principal), options);
    case 'cancel': return value.cancel(sqlIntent(command.intent, principal), options);
    case 'compact_begin': return value.compactBegin(input, options);
    case 'compact_copy': return value.compactCopy(input, options);
    case 'compact_promote': return value.compactPromote(input, options);
    case 'compact_abort': return value.compactAbort(input, options);
    case 'gc_prepare': return value.gcPrepare(input, options);
    case 'gc_resume': return value.gcResume(input, options);
    default: throw new Error('unplanned public SDK operation');
  }
}

emit('sdk_started', { pid: process.pid });
process.stdout.write(JSON.stringify({ ready: true }) + '\n');
async function handle(line) {
  const context = { command: JSON.parse(line), attempts: 0 };
  return invocation.run(context, async () => {
  const current = context.command;
  emit('command_started', { command: current.id, input: archive(Buffer.from(line + '\n')) });
  let result;
  try {
    const value = await perform(current);
    result = { id: current.id, ok: true, value: value?.rawResult ?
      { state: value.state ?? 'committed', receipt: value.receipt, result: archive(value.rawResult) } : safe(value) };
  } catch (error) {
    result = { id: current.id, ok: false, error: { name: error.name, code: error.code ?? null,
      reference: error.reference === undefined ? null : safe(error.reference),
      receipt: error.receipt === undefined ? null : safe(error.receipt) } };
  }
  emit('command_finished', { command: current.id, attempts: context.attempts, result });
  process.stdout.write(JSON.stringify(result) + '\n');
  });
}
const running = new Set();
for await (const line of createInterface({ input: process.stdin, crlfDelay: Infinity })) {
  const result = handle(line);
  running.add(result);
  result.finally(() => running.delete(result));
}
await Promise.all(running);
emit('sdk_finished');
