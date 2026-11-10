/** Real SDK calls, original inputs, and raw Fetch results for the GC contract. */
import { createHash } from 'node:crypto';
import { closeSync, existsSync, fsyncSync, linkSync, openSync, readFileSync,
  unlinkSync, writeFileSync, writeSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { pathToFileURL } from 'node:url';

const [configPath, evidence, role] = process.argv.slice(2);
const config = JSON.parse(readFileSync(configPath, 'utf8'));
const { Client } = await import(pathToFileURL(config.source_root + '/sdk/node/src/client.js'));
const sha = (value) => createHash('sha256').update(value).digest('hex');
let sequence = 0, current = null, attempts = 0;
function safe(value) {
  return JSON.parse(JSON.stringify(value, (_, item) => typeof item === 'bigint' ? item.toString() : item));
}
function emit(event, fields = {}) {
  const row = { sequence: ++sequence, monotonic_ns: process.hrtime.bigint().toString(),
    event, role, ...fields };
  const fd = openSync(evidence + '/sdk-' + role + '.jsonl', 'a', 0o600);
  try { writeSync(fd, JSON.stringify(row) + '\n'); fsyncSync(fd); }
  finally { closeSync(fd); }
}
function archive(bytes) {
  const data = Buffer.from(bytes), digest = sha(data), file = 'raw/' + digest;
  const temporary = evidence + '/raw/.sdk-' + role + '-' + process.pid + '-' + process.hrtime.bigint();
  const fd = openSync(temporary, 'wx', 0o600);
  try { writeFileSync(fd, data); fsyncSync(fd); } finally { closeSync(fd); }
  try {
    try { linkSync(temporary, evidence + '/' + file); }
    catch (error) {
      if (error.code !== 'EEXIST' || sha(readFileSync(evidence + '/' + file)) !== digest) throw error;
    }
  } finally { unlinkSync(temporary); }
  return { file, bytes: data.length, sha256: digest };
}
const clients = new Map();
function client(scopeName) {
  if (!clients.has(scopeName)) {
    clients.set(scopeName, new Client({ endpoint: config.endpoint + '/v1', token: config.token,
      scope: config.scopes[scopeName], principal: '11', allowInsecureHttp: true,
      timeoutMs: 90000, recoveryTimeoutMs: 300000,
      fetch: async (url, options) => {
        const ordinal = ++attempts, commandId = current.id;
        emit('http_request', { command: commandId, ordinal, method: options.method, url: String(url),
          token_sha256: sha(config.token), headers: Object.fromEntries(
            [...new Headers(options.headers)].filter(([name]) => name !== 'authorization')),
          request: archive(Buffer.from(options.body)) });
        try {
          const response = await globalThis.fetch(url, options);
          const bytes = Buffer.from(await response.arrayBuffer());
          emit('http_response', { command: commandId, ordinal, status: response.status,
            complete: true, response: archive(bytes) });
          return new Response(bytes, { status: response.status, headers: response.headers });
        } catch (error) {
          emit('http_error', { command: commandId, ordinal, name: error.name });
          throw error;
        }
      },
    }));
  }
  return clients.get(scopeName);
}
function intent(name) {
  const all = JSON.parse(readFileSync(evidence + '/intents.json', 'utf8'));
  const original = all[name];
  if (!original) throw new Error('unknown original intent');
  return client(original.scope_name).restore(original.serialized);
}
function publicValue(value) {
  if (value?.rawResult) return { state: value.state ?? 'committed', receipt: value.receipt,
    result: archive(value.rawResult) };
  return safe(value);
}
function sdkStatements(statements) {
  return statements.map((statement) => {
    if (Object.keys(statement).sort().join(',') !== 'params,sql'
        || !Array.isArray(statement.params) || statement.params.length !== 0)
      throw new Error('fixed SQL inputs require empty native positional parameters');
    return { sql: statement.sql, parameters: [] };
  });
}
async function perform(command) {
  if (command.operation === 'prepare') {
    if (existsSync(evidence + '/intents.json')) throw new Error('original intents already exist');
    const originals = {};
    for (const spec of command.specs) {
      const value = client(spec.scope_name).prepare(sdkStatements(spec.statements),
        { epoch: spec.epoch, id: spec.request_id });
      originals[spec.name] = { scope_name: spec.scope_name, serialized: client(spec.scope_name).save(value) };
    }
    const bytes = Buffer.from(JSON.stringify(originals, null, 2) + '\n');
    const fd = openSync(evidence + '/intents.json', 'wx', 0o600);
    try { writeFileSync(fd, bytes); fsyncSync(fd); } finally { closeSync(fd); }
    emit('intents_prepared', { count: command.specs.length, original: archive(bytes) });
    return { prepared: command.specs.length };
  }
  const value = client(command.scope_name), input = command.input, options = command.options;
  switch (command.operation) {
    case 'status': return value.status(options);
    case 'open': return value.open(options);
    case 'takeover': return value.takeover(input, options);
    case 'activate': return value.activate(input, options);
    case 'policy': return value.setPolicy(input, options);
    case 'query': return value.query(sdkStatements(command.statements), options);
    case 'execute': return value.execute(intent(command.intent), options);
    case 'lookup': return value.lookup(intent(command.intent), options);
    case 'cancel': return value.cancel(intent(command.intent), options);
    case 'compact_begin': return value.compactBegin(input, options);
    case 'compact_copy': return value.compactCopy(input, options);
    case 'compact_promote': return value.compactPromote(input, options);
    case 'compact_abort': return value.compactAbort(input, options);
    case 'gc_prepare': return value.gcPrepare(input, options);
    case 'gc_resume': return value.gcResume(input, options);
    default: throw new Error('unplanned SDK operation');
  }
}
emit('sdk_started', { pid: process.pid });
process.stdout.write(JSON.stringify({ ready: true }) + '\n');
for await (const line of createInterface({ input: process.stdin, crlfDelay: Infinity })) {
  current = JSON.parse(line);
  attempts = 0;
  emit('command_started', { command: current.id, input: archive(Buffer.from(line + '\n')) });
  let result;
  try {
    result = { id: current.id, ok: true, value: publicValue(await perform(current)) };
  } catch (error) {
    result = { id: current.id, ok: false, error: { name: error.name, code: error.code ?? null,
      reference: error.reference === undefined ? null : safe(error.reference) } };
  }
  emit('command_finished', { command: current.id, attempts, result });
  process.stdout.write(JSON.stringify(result) + '\n');
  current = null;
}
emit('sdk_finished');
