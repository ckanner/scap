/** Actual SDK operations; saved originals and one raw Fetch exchange per call. */
import { createHash } from 'node:crypto';
import { closeSync, existsSync, fsyncSync, linkSync, openSync, readFileSync,
  unlinkSync, writeFileSync, writeSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { pathToFileURL } from 'node:url';

const [configuration, evidence, role] = process.argv.slice(2);
const config = JSON.parse(readFileSync(configuration, 'utf8'));
const { Client, CatalogueClient } = await import(pathToFileURL(config.source_root + '/sdk/node/src/client.js'));
const sha = (value) => createHash('sha256').update(value).digest('hex');
const safe = (value) => JSON.parse(JSON.stringify(value,
  (_, item) => typeof item === 'bigint' ? item.toString() : item));
let sequence = 0, current = null, attempts = 0;
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
const databaseClients = new Map(), catalogues = new Map();
function transport(principal) {
  return { token: config.tokens[principal], allowInsecureHttp: true, timeoutMs: 90000,
    recoveryTimeoutMs: 300000, fetch: async (url, options) => {
      const ordinal = ++attempts, command = current.id;
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
function statements(value) {
  return value.map((item) => {
    if (Object.keys(item).sort().join(',') !== 'params,sql' || !Array.isArray(item.params) || item.params.length)
      throw new Error('fixed native statement shape');
    return { sql: item.sql, parameters: [] };
  });
}
function sqlIntent(name) {
  const original = JSON.parse(readFileSync(evidence + '/intents.json', 'utf8'))[name];
  if (!original) throw new Error('missing original SQL identity');
  return client(original.scope_name).restore(original.serialized);
}
function namedIntent(name, principal) {
  const matches = readFileSync(evidence + '/named-intents.jsonl', 'utf8').trimEnd().split('\n')
    .map((line) => JSON.parse(line)).filter((item) => item.name === name);
  if (matches.length !== 1) throw new Error('missing or repeated original catalogue identity');
  return catalogue(principal).restoreIntent(matches[0].serialized);
}
async function perform(command) {
  if (command.operation === 'prepare') {
    if (existsSync(evidence + '/intents.json')) throw new Error('originals already saved');
    const originals = {};
    for (const input of command.specs) {
      const value = client(input.scope_name).prepare(statements(input.statements),
        { epoch: input.epoch, id: input.request_id });
      const serialized = client(input.scope_name).save(value);
      if (client(input.scope_name).save(client(input.scope_name).restore(serialized)) !== serialized)
        throw new Error('original SQL save/restore changed its identity');
      originals[input.name] = { scope_name: input.scope_name, serialized };
    }
    const bytes = Buffer.from(JSON.stringify(originals, null, 2) + '\n');
    const fd = openSync(evidence + '/intents.json', 'wx', 0o600);
    try { writeFileSync(fd, bytes); fsyncSync(fd); } finally { closeSync(fd); }
    emit('intents_prepared', { count: command.specs.length, original: archive(bytes) });
    return { prepared: command.specs.length };
  }
  const principal = command.principal ?? '11', input = command.input, options = command.options;
  if (command.operation === 'named') {
    const value = catalogue(principal), tracked = value.prepareIntent(input);
    const fd = openSync(evidence + '/named-intents.jsonl', 'a', 0o600);
    const saved = Buffer.from(JSON.stringify({ name: command.intent, role, principal,
      serialized: value.saveIntent(tracked) }) + '\n');
    try { writeSync(fd, saved); fsyncSync(fd); } finally { closeSync(fd); }
    emit('named_intent_prepared', { name: command.intent, original: archive(saved) });
    return value.submit(tracked, options);
  }
  if (command.operation === 'named_submit')
    return catalogue(principal).submit(namedIntent(command.intent, principal), options);
  const value = client(command.scope_name, principal);
  switch (command.operation) {
    case 'create': return value.create(input, options);
    case 'status': return value.status(options);
    case 'storage_status': return value.storageStatus(options);
    case 'retire_storage': return value.retireStorage(input, options);
    case 'activate': return value.activate(input, options);
    case 'takeover': return value.takeover(input, options);
    case 'policy': return value.setPolicy(input, options);
    case 'lifecycle': return value.setLifecycle(input, options);
    case 'query': return value.query(statements(command.statements), options);
    case 'execute': return value.execute(sqlIntent(command.intent), options);
    case 'lookup': return value.lookup(sqlIntent(command.intent), options);
    case 'compact_begin': return value.compactBegin(input, options);
    case 'compact_copy': return value.compactCopy(input, options);
    case 'compact_abort': return value.compactAbort(input, options);
    case 'gc_prepare': return value.gcPrepare(input, options);
    case 'gc_resume': return value.gcResume(input, options);
    default: throw new Error('unplanned actual SDK operation');
  }
}
emit('sdk_started', { pid: process.pid });
process.stdout.write(JSON.stringify({ ready: true }) + '\n');
for await (const line of createInterface({ input: process.stdin, crlfDelay: Infinity })) {
  current = JSON.parse(line); attempts = 0;
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
  emit('command_finished', { command: current.id, attempts, result });
  process.stdout.write(JSON.stringify(result) + '\n'); current = null;
}
emit('sdk_finished');
