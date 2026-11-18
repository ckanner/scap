/** Independent evidence auditor. Imports no SDK, producer helper or product codec. */
import { createHash } from 'node:crypto';
import { isUtf8 } from 'node:buffer';
import { isDeepStrictEqual } from 'node:util';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { pathToFileURL } from 'node:url';

export const CASES = Object.freeze([
  'native_source_snapshot_keeps_exact_random_and_blob_values',
  'empty_create_and_restore_share_the_first_winner_slot',
  'cancel_while_payload_get_is_held_permanently_fences_late_copy',
  'fresh_source_revocation_wins_over_a_completed_payload_prefix',
  'lost_http_response_and_sigkill_resume_original_operation_without_recopy',
  'completed_restore_missing_target_head_fails_closed_without_recreation',
  'source_payload_deleted_then_all_cache_lost_target_still_recovers',
]);
const SOURCE = { deployment: '1', tenant: '2', database: '3', incarnation: '4', generation: '5' };
const SOURCE_PREFIX = '/scap-test/scap-object/v1/1/2/3/inc/4/gen/5/storage/';
const SELECT = [{ sql: 'SELECT id,n,payload FROM saved ORDER BY id', params: [] }];
const MAX_BYTES = 16 * 1024 * 1024;
const hash = (value) => createHash('sha256').update(value).digest('hex');
export class AuditError extends Error { constructor(code) { super(code); this.name = 'AuditError'; } }
const need = (condition, code) => { if (!condition) throw new AuditError(code); };
const same = (left, right, code) => need(isDeepStrictEqual(left, right), code);
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const hexadecimal = (value) => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const uint = (value) => typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value) && BigInt(value) <= 0xffffffffffffffffn;
const exact = (value, fields, code) => need(object(value) &&
  isDeepStrictEqual(Object.keys(value).sort(), [...fields].sort()), code);
const scope = (value) => { exact(value, Object.keys(SOURCE), 'SCOPE');
  need(Object.values(value).every((number) => uint(number) && number !== '0'), 'SCOPE'); return value; };

export function base64(text) {
  need(typeof text === 'string' && text.length <= MAX_BYTES * 2 && text.length % 4 === 0 &&
    /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(text), 'BASE64');
  const raw = Buffer.from(text, 'base64');
  need(raw.toString('base64') === text && raw.length <= MAX_BYTES, 'BASE64');
  return raw;
}
export function byteRecord(value) {
  exact(value, ['base64', 'length', 'sha256'], 'BYTE_RECORD');
  const raw = base64(value.base64);
  need(Number.isSafeInteger(value.length) && raw.length === value.length && hash(raw) === value.sha256, 'BODY_HASH');
  return raw;
}
const pack = (raw) => ({ base64: raw.toString('base64'), length: raw.length, sha256: hash(raw) });

/** Reject duplicate members before JSON.parse; the parser remains independent of SDK validation. */
export function strictJson(raw, integers = false) {
  need(Buffer.isBuffer(raw) && raw.length <= MAX_BYTES && isUtf8(raw), 'JSON_BYTES');
  const text = raw.toString('utf8'), stack = [];
  for (let offset = 0; offset < text.length; offset++) {
    if (text[offset] === '"') {
      const first = offset++;
      while (offset < text.length && text[offset] !== '"') { if (text[offset] === '\\') offset++; offset++; }
      need(offset < text.length, 'JSON_STRING');
      if (stack.at(-1)?.key) {
        let key; try { key = JSON.parse(text.slice(first, offset + 1)); } catch { throw new AuditError('JSON_STRING'); }
        need(!stack.at(-1).keys.has(key), 'JSON_DUPLICATE');
        stack.at(-1).keys.add(key); stack.at(-1).key = false;
      }
    } else if (text[offset] === '{' || text[offset] === '[') {
      need(stack.length < 48, 'JSON_DEPTH');
      stack.push(text[offset] === '{' ? { keys: new Set(), key: true } : {});
    } else if (text[offset] === '}' || text[offset] === ']') stack.pop();
    else if (text[offset] === ',' && stack.at(-1)?.keys) stack.at(-1).key = true;
  }
  try {
    return JSON.parse(text, integers ? (_, value, context) => {
      if (typeof value !== 'number') return value;
      need(/^-?(0|[1-9][0-9]*)$/.test(context.source), 'JSON_INTEGER');
      return context.source;
    } : undefined);
  } catch (error) { if (error instanceof AuditError) throw error; throw new AuditError('JSON_SYNTAX'); }
}

/** Minimal SCAPRES1 reader with exact integers/blobs, bounds and no product-code imports. */
export function decodeResult(raw) {
  need(Buffer.isBuffer(raw) && raw.length <= MAX_BYTES, 'RESULT_BYTES');
  let offset = 0;
  const take = (length) => { need(Number.isSafeInteger(length) && length >= 0 && length <= raw.length - offset, 'RESULT_TRUNCATED');
    const value = raw.subarray(offset, offset + length); offset += length; return value; };
  const count = () => { const value = take(4).readUInt32LE(); need(value <= 65536, 'RESULT_COUNT'); return value; };
  const data = () => take(take(4).readUInt32LE());
  const text = () => { const value = data(); need(isUtf8(value), 'RESULT_UTF8'); return value.toString('utf8'); };
  same(take(8).toString('ascii'), 'SCAPRES1', 'RESULT_MAGIC');
  const statements = [];
  const statementCount = count();
  for (let s = 0; s < statementCount; s++) {
    const columns = [], rows = [], columnCount = count();
    for (let column = 0; column < columnCount; column++) columns.push(text());
    const rowCount = count(); need(columnCount * rowCount <= 65536, 'RESULT_CELLS');
    for (let row = 0; row < rowCount; row++) {
      const values = [];
      for (let column = 0; column < columnCount; column++) {
        switch (take(1)[0]) {
          case 0: values.push({ type: 'null' }); break;
          case 1: values.push({ type: 'integer', value: take(8).readBigInt64LE().toString() }); break;
          case 2: values.push({ type: 'real', bits: Buffer.from(take(8)).reverse().toString('hex') }); break;
          case 3: values.push({ type: 'text', value: text() }); break;
          case 4: values.push({ type: 'blob', ...pack(data()) }); break;
          default: throw new AuditError('RESULT_TAG');
        }
      }
      rows.push(values);
    }
    statements.push({ columns, rows, affected_rows: take(8).readBigUInt64LE().toString(),
      last_insert_rowid: take(8).readBigInt64LE().toString() });
  }
  need(offset === raw.length, 'RESULT_TRAILING');
  return { statements };
}

export function fingerprint(statements) {
  need(Array.isArray(statements) && statements.length <= 16, 'SQL_STATEMENTS');
  const chunks = [Buffer.from('SCAPSQL1')];
  const u32 = (value) => { const raw = Buffer.alloc(4); raw.writeUInt32LE(value); chunks.push(raw); };
  const variable = (value) => { u32(value.length); chunks.push(value); };
  u32(statements.length);
  for (const statement of statements) {
    exact(statement, ['sql', 'params'], 'SQL_STATEMENT');
    need(typeof statement.sql === 'string' && Array.isArray(statement.params), 'SQL_STATEMENT');
    variable(Buffer.from(statement.sql)); u32(statement.params.length);
    for (const parameter of statement.params) {
      const tag = { null: 0, integer: 1, real: 2, text: 3, blob: 4 }[parameter.type];
      need(tag !== undefined, 'SQL_PARAMETER'); chunks.push(Buffer.from([tag]));
      if (tag === 0) exact(parameter, ['type'], 'SQL_PARAMETER');
      else {
        exact(parameter, ['type', tag === 2 ? 'bits' : tag === 4 ? 'base64' : 'value'], 'SQL_PARAMETER');
        if (tag === 1) {
          need(typeof parameter.value === 'string' && /^-?(0|[1-9][0-9]*)$/.test(parameter.value), 'SQL_INTEGER');
          const value = BigInt(parameter.value); need(value >= -(1n << 63n) && value < (1n << 63n), 'SQL_INTEGER');
          const raw = Buffer.alloc(8); raw.writeBigInt64LE(value); chunks.push(raw);
        } else if (tag === 2) {
          need(/^[0-9a-f]{16}$/.test(parameter.bits), 'SQL_REAL'); chunks.push(Buffer.from(parameter.bits, 'hex').reverse());
        } else if (tag === 3) variable(Buffer.from(parameter.value));
        else variable(base64(parameter.base64));
      }
    }
  }
  return hash(Buffer.concat(chunks));
}

export function receiptHash(receipt, raw) {
  exact(receipt, ['scope', 'request', 'sequence', 'transition', 'data_root', 'result_hash'], 'RECEIPT');
  scope(receipt.scope); exact(receipt.request, ['epoch', 'id', 'principal', 'fingerprint'], 'RECEIPT_REQUEST');
  exact(receipt.transition, ['revision', 'nonce'], 'RECEIPT_TRANSITION');
  need([receipt.sequence, receipt.request.epoch, receipt.request.id, receipt.request.principal,
    receipt.transition.revision, receipt.transition.nonce].every(uint) &&
    [receipt.request.fingerprint, receipt.data_root, receipt.result_hash].every(hexadecimal), 'RECEIPT_VALUES');
  const s = receipt.scope, r = receipt.request, t = receipt.transition;
  const metadata = Buffer.from(`{"format":2,"scope":{"deployment":${s.deployment},"tenant":${s.tenant},` +
    `"database":${s.database},"incarnation":${s.incarnation},"generation":${s.generation}},` +
    `"payload":{"kind":"result","value":{"request":{"epoch":${r.epoch},"id":${r.id},"principal":${r.principal},` +
    `"fingerprint":"${r.fingerprint}"},"sequence":${receipt.sequence},"transition":{"revision":${t.revision},` +
    `"nonce":${t.nonce}},"data_root":"${receipt.data_root}","bytes":[]}}}`);
  const header = Buffer.alloc(20); header.write('SCAPOBJ2'); header.writeUInt32LE(metadata.length, 8);
  header.writeBigUInt64LE(BigInt(raw.length), 12);
  return hash(Buffer.concat([header, metadata, raw]));
}

const FIELDS = {
  case_begin: ['name'], case_end: ['name'],
  sdk_request: ['id', 'process', 'principal', 'method', 'path', 'admission', 'body'],
  sdk_response: ['id', 'status', 'content_type', 'body'], sdk_delivery_lost: ['id'],
  unknown_observed: ['id', 'code', 'reference'],
  s3_request: ['id', 'method', 'path', 'if_match', 'if_none_match'],
  s3_request_end: ['id', 'length', 'sha256'], s3_response: ['id', 'status', 'etag', 'length', 'sha256'],
  admin_request: ['id', 'method', 'path'], admin_response: ['id', 'status', 'length', 'sha256'],
  gate_armed: ['prefix'], gate_held: ['gate', 'request'], gate_released: ['gate'],
  service_spawned: ['process', 'pid', 'spawn_monotonic_ns', 'pid_source', 'worker', 'cache_id', 'cache_fresh', 'cache_empty', 'config_sha256'],
  service_ready: ['process', 'status', 'body'], signal_sent: ['process', 'signal', 'accepted'],
  service_reaped: ['process', 'code', 'signal', 'close_code', 'close_signal'], cache_deleted: ['process', 'cache_id', 'absent'],
  expectation: ['name', 'original_http', 'query_http', 'result', 'rows', 'receipt', 'raw_result'],
  intent_saved: ['operation', 'body'], checkpoint: ['name'], probe_complete: ['cases', 'processes', 'object_requests'],
};

export function readRecords(path) {
  const text = readFileSync(path, 'utf8'); need(text.endsWith('\n'), 'PARTIAL_LAST_RECORD');
  const lines = text.slice(0, -1).split('\n');
  need(lines.length <= 300000 && lines.every((line) => line.length > 0), 'RECORD_LINES');
  return lines.map((line) => strictJson(Buffer.from(line)));
}

export function audit(records) {
  need(Array.isArray(records) && records.length > 0 && records.length <= 300000, 'RECORDS');
  let current = 'setup', begun = 0, ended = 0;
  for (const [offset, row] of records.entries()) {
    need(object(row) && row.schema === 1 && row.seq === offset + 1, 'SEQUENCE_HOLE');
    need(Object.hasOwn(FIELDS, row.kind), 'RECORD_KIND');
    let extra = [];
    if (['s3_request_end', 's3_response'].includes(row.kind) && Object.hasOwn(row, 'body')) extra = ['body'];
    if (row.kind === 'checkpoint') extra = row.name === 'source_payloads_deleted' ? ['keys'] :
      row.name === 'authority_loss_before_delete' ? ['scope', 'path'] : row.name.startsWith('authority_loss_') ? ['path'] : [];
    exact(row, ['schema', 'seq', 'kind', 'stage', ...FIELDS[row.kind], ...extra], 'RECORD_FIELDS');
    if (row.kind === 'case_begin') {
      need(begun === ended && row.name === CASES[begun] && row.stage === row.name, 'CASE_ORDER');
      current = row.name; begun++;
    } else if (row.kind === 'case_end') { need(begun === ended + 1 && row.name === current, 'CASE_END'); ended++; }
    if (row.stage === 'teardown') { need(ended === CASES.length, 'EARLY_TEARDOWN'); current = 'teardown'; }
    need(row.stage === current, 'STAGE_BINDING');
  }
  need(begun === CASES.length && ended === CASES.length && records.at(-1).kind === 'probe_complete', 'INCOMPLETE_RUN');
  const of = (kind, predicate = () => true) => records.filter((row) => row.kind === kind && predicate(row));
  const one = (items, code) => { need(items.length === 1, code); return items[0]; };
  const event = (kind, predicate, code = kind) => one(of(kind, predicate), code);
  const checkpoint = (name) => event('checkpoint', (row) => row.name === name, 'CHECKPOINT');
  same(of('checkpoint').map((row) => row.name), ['completed_resume_begin', 'completed_resume_end',
    'authority_loss_before_delete', 'authority_loss_missing_verified', 'authority_loss_checks_end', 'source_payloads_deleted'], 'CHECKPOINT_SET');
  const complete = records.at(-1); same(complete.cases, CASES, 'COMPLETION_CASES');

  function pairs(requestKind, responseKind, endKind) {
    const requests = of(requestKind), responses = of(responseKind), ends = endKind ? of(endKind) : [];
    need(requests.length > 0 && requests.length === responses.length && (!endKind || requests.length === ends.length), 'REQUEST_PAIR_COUNT');
    const responseMap = new Map(responses.map((row) => [row.id, row]));
    const endMap = new Map(ends.map((row) => [row.id, row]));
    need(responseMap.size === responses.length && endMap.size === ends.length, 'DUPLICATE_RESPONSE');
    return requests.map((request, index) => {
      need(request.id === index + 1, 'REQUEST_ID_HOLE');
      const response = responseMap.get(request.id), end = endMap.get(request.id);
      need(response && response.seq > request.seq && response.stage === request.stage, 'REQUEST_PAIR');
      if (endKind) need(end && end.seq > request.seq && end.seq < response.seq && end.stage === request.stage, 'REQUEST_END');
      return { request, response, end };
    });
  }
  const http = pairs('sdk_request', 'sdk_response').map((item) => {
    const { request, response } = item;
    need(request.method === 'POST' && ['/v1', '/v1/catalogue'].includes(request.path) && ['3', '9'].includes(request.principal), 'HTTP_REQUEST');
    const q = strictJson(byteRecord(request.body)), envelope = strictJson(byteRecord(response.body));
    need(q.version === 1 && typeof q.operation === 'string', 'HTTP_VERSION');
    need(typeof response.content_type === 'string' && response.content_type.split(';')[0].trim() === 'application/json', 'HTTP_CONTENT_TYPE');
    if (envelope.ok === true) { exact(envelope, ['ok', 'value'], 'HTTP_ENVELOPE'); need(response.status === 200, 'HTTP_SUCCESS_STATUS'); }
    else {
      exact(envelope, ['ok', 'error'], 'HTTP_ENVELOPE'); need(envelope.ok === false, 'HTTP_ENVELOPE');
      const errors = { CONFLICT: 409, DENIED: 403, NOT_FOUND: 404, CORRUPT: 409 };
      need(Object.hasOwn(errors, envelope.error?.code) && response.status === errors[envelope.error.code], 'HTTP_ERROR_STATUS');
    }
    const catalogue = ['prepare_create', 'prepare_restore', 'resume_restore', 'inspect_restore', 'abort_restore', 'resolve_name'].includes(q.operation);
    need(request.path === (catalogue ? '/v1/catalogue' : '/v1'), 'HTTP_PATH');
    const requestFields = { create: ['nonce'], activate: ['expected_revision', 'nonce'], execute: ['request', 'statements'],
      query: ['statements'], status: [], snapshot_prepare: ['input'], snapshot_capture: ['reference'], snapshot_release: ['reference'],
      policy: ['expected_revision', 'nonce', 'permissions'], lifecycle: ['expected_revision', 'nonce', 'lifecycle'],
      retire_storage: ['expected_head_serial'], lookup: ['request'],
      prepare_restore: ['name', 'restore_operation', 'expected_name_revision', 'options', 'source_scope', 'snapshot'],
      prepare_create: ['name', 'create_operation', 'expected_name_revision', 'options'], resume_restore: ['reference'],
      inspect_restore: ['restore_operation', 'creator'], abort_restore: ['reference', 'control_operation', 'expected_name_revision', 'nonce'], resolve_name: ['name'] };
    need(Object.hasOwn(requestFields, q.operation), 'FIXED_OPERATION');
    exact(q, ['version', 'operation', ...(catalogue ? [] : ['scope']), ...requestFields[q.operation]], 'HTTP_REQUEST_FIELDS');
    if (!catalogue) scope(q.scope);
    if (q.operation === 'query') same(q.statements, SELECT, 'EXACT_QUERY_STATEMENTS');
    if (['create', 'activate', 'execute', 'snapshot_prepare', 'snapshot_capture', 'snapshot_release', 'policy', 'lifecycle', 'retire_storage'].includes(q.operation)) {
      same(q.scope, SOURCE, 'SOURCE_OPERATION_SCOPE');
    }
    if (envelope.ok && q.scope) {
      if (envelope.value.scope) same(envelope.value.scope, q.scope, 'HTTP_RESPONSE_SCOPE');
      if (envelope.value.status?.scope) same(envelope.value.status.scope, q.scope, 'HTTP_STATUS_SCOPE');
      if (envelope.value.prepared?.scope) same(envelope.value.prepared.scope, q.scope, 'HTTP_PREPARED_SCOPE');
    }
    const admission = q.operation === 'resume_restore' || q.operation === 'activate' ? 'recovery' : catalogue ? 'catalogue' :
      ['create', 'execute', 'query'].includes(q.operation) ? 'data' : 'control';
    need(request.admission === admission, 'HTTP_ADMISSION');
    return { ...item, q, envelope, a: envelope.value, error: envelope.error?.code };
  });
  const find = (operation, predicate = () => true) => http.filter((row) => row.q.operation === operation && predicate(row));
  const success = (row, code = 'HTTP_EXPECTED_SUCCESS') => { need(row.envelope.ok === true, code); return row.a; };
  const error = (row, code) => { need(row.error === code, `EXPECTED_${code}`); };
  const queryRows = (row) => decodeResult(base64(success(row).result));
  const abortCount = find('abort_restore').length;
  need(abortCount >= 1 && abortCount <= 4, 'CANCEL_ATTEMPTS');
  const sequence = [
    ['create', 'activate', 'execute', 'query', 'status', 'snapshot_prepare', 'snapshot_capture', 'execute', 'query'],
    ['prepare_restore', 'prepare_create', 'prepare_restore'],
    ['prepare_restore', 'resume_restore', 'resume_restore', 'resume_restore', 'inspect_restore', ...Array(abortCount).fill('abort_restore'), 'inspect_restore', 'resume_restore', 'resolve_name'],
    ['prepare_restore', 'resume_restore', 'resume_restore', 'resume_restore', 'status', 'policy', 'inspect_restore', 'status', 'policy', 'resume_restore', 'resume_restore', 'resume_restore', 'query'],
    ['resume_restore', 'resume_restore', 'resume_restore', 'inspect_restore', 'resume_restore', 'resume_restore', 'status', 'query', 'lookup', 'lookup'],
    ['prepare_restore', 'resume_restore', 'resume_restore', 'resume_restore', 'inspect_restore', 'resume_restore'],
    ['snapshot_release', 'status', 'lifecycle', 'retire_storage', 'query', 'resolve_name'],
  ];
  for (const [index, operations] of sequence.entries()) {
    same(http.filter((row) => row.request.stage === CASES[index]).map((row) => row.q.operation), operations, 'FIXED_CASE_REQUEST_SEQUENCE');
  }
  for (const row of http) {
    const adminStatus = row.q.operation === 'status' && row.request.stage === CASES[3] &&
      row === find('status', (candidate) => candidate.request.stage === CASES[3]).at(-1);
    need(row.request.principal === (adminStatus || (row.q.operation === 'policy' && row.q.nonce === '1204') ? '9' : '3'), 'FIXED_CALLER');
  }

  const objects = pairs('s3_request', 's3_response', 's3_request_end');
  for (const item of objects) {
    const { request, response, end } = item;
    need(['GET', 'PUT', 'DELETE', 'HEAD'].includes(request.method) && request.path.startsWith('/scap-test/') && !request.path.includes('?'), 'S3_REQUEST');
    need(Number.isInteger(response.status) && response.status >= 200 && response.status <= 599, 'S3_STATUS');
    for (const part of [end, response]) {
      need(Number.isSafeInteger(part.length) && part.length >= 0 && hexadecimal(part.sha256), 'S3_BODY_DIGEST');
      if (part.body) { const raw = byteRecord(part.body); need(raw.length === part.length && hash(raw) === part.sha256, 'S3_BODY_BINDING'); }
    }
    if (request.path.endsWith('/head')) {
      need(end.body !== undefined && response.body !== undefined, 'HEAD_BODY_REQUIRED');
      if (request.method === 'PUT' && response.status < 300) {
        need((request.if_none_match === '*' && request.if_match === null) ||
          (typeof request.if_match === 'string' && request.if_none_match === null), 'HEAD_CONDITION');
      }
    }
  }
  need(complete.object_requests === objects.length, 'S3_COMPLETION_COUNT');
  const admin = pairs('admin_request', 'admin_response');
  for (const item of admin) {
    need(['DELETE', 'GET'].includes(item.request.method) && item.request.path.startsWith('/scap-test/'), 'ADMIN_REQUEST');
    need(Number.isSafeInteger(item.response.length) && item.response.length >= 0 && hexadecimal(item.response.sha256), 'ADMIN_BODY');
  }

  const spawned = of('service_spawned'); need(spawned.length === 3 && complete.processes === 3, 'PROCESS_COUNT');
  const lifecycle = spawned.map((spawn, index) => {
    need(spawn.process === index + 1 && spawn.worker === String(2001 + index) && Number.isInteger(spawn.pid) && spawn.pid > 0 &&
      spawn.pid_source === 'owned_ChildProcess' && uint(spawn.spawn_monotonic_ns) && hexadecimal(spawn.config_sha256), 'PROCESS_IDENTITY');
    need(spawn.cache_fresh === true && spawn.cache_empty === true && spawn.cache_id === `cache-${spawn.worker}`, 'CACHE_FRESH');
    const match = (row) => row.process === spawn.process;
    const ready = event('service_ready', match), signal = event('signal_sent', match), reaped = event('service_reaped', match), removed = event('cache_deleted', match);
    need(ready.status === 200, 'PROCESS_READY'); byteRecord(ready.body);
    need(signal.signal === 'SIGKILL' && signal.accepted === true, 'PROCESS_KILL');
    need(reaped.code === null && reaped.signal === 'SIGKILL' && reaped.close_code === null && reaped.close_signal === 'SIGKILL', 'PROCESS_REAP');
    need(removed.absent === true && removed.cache_id === spawn.cache_id, 'CACHE_DELETE');
    need(spawn.seq < ready.seq && ready.seq < signal.seq && signal.seq < reaped.seq && reaped.seq < removed.seq, 'PROCESS_ORDER');
    return { spawn, ready, signal, reaped, removed };
  });
  for (let index = 1; index < lifecycle.length; index++) {
    need(lifecycle[index - 1].removed.seq < lifecycle[index].spawn.seq &&
      BigInt(lifecycle[index - 1].spawn.spawn_monotonic_ns) < BigInt(lifecycle[index].spawn.spawn_monotonic_ns), 'FRESH_PROCESS_ORDER');
  }
  for (const row of http) {
    const process = lifecycle[row.request.process - 1];
    need(process && process.ready.seq < row.request.seq && row.response.seq < process.signal.seq, 'HTTP_PROCESS_LIFETIME');
  }

  const expected = event('expectation', (row) => row.name === 'original');
  const original = one(http.filter((row) => row.request.id === expected.original_http), 'ORIGINAL_HTTP');
  const originalQuery = one(http.filter((row) => row.request.id === expected.query_http), 'ORIGINAL_QUERY_HTTP');
  same(original.q.scope, SOURCE, 'ORIGINAL_SCOPE'); need(original.q.operation === 'execute' && originalQuery.q.operation === 'query', 'ORIGINAL_OPERATIONS');
  same(original.q.request, { epoch: '1', id: '1', principal: '3', fingerprint: fingerprint(original.q.statements) }, 'ORIGINAL_REQUEST');
  same(original.q.statements.map((statement) => statement.sql), ['CREATE TABLE saved(id INTEGER PRIMARY KEY,n INTEGER,payload BLOB)',
    'INSERT INTO saved VALUES(1,random(),randomblob(180000))', 'INSERT INTO saved VALUES(2,?,?)', 'SELECT id,n,payload FROM saved ORDER BY id'], 'ORIGINAL_SQL');
  same(original.q.statements[2].params[0], { type: 'integer', value: '9007199254740993' }, 'ORIGINAL_INTEGER_INPUT');
  same(base64(original.q.statements[2].params[1].base64), Buffer.alloc(8192, 73), 'ORIGINAL_BLOB_INPUT');
  same(original.q.statements.map((statement) => statement.params.length), [0, 0, 2, 0], 'ORIGINAL_PARAMETERS');
  const committed = success(original); need(committed.state === 'committed', 'ORIGINAL_COMMITTED');
  const raw = base64(committed.result); same(byteRecord(expected.raw_result), raw, 'ORIGINAL_RAW');
  same(expected.receipt, committed.receipt, 'ORIGINAL_RECEIPT');
  same(committed.receipt.scope, SOURCE, 'RECEIPT_SCOPE'); same(committed.receipt.request, original.q.request, 'RECEIPT_REQUEST_BINDING');
  need(committed.receipt.result_hash === receiptHash(committed.receipt, raw), 'RECEIPT_HASH');
  same(decodeResult(raw), expected.result, 'ORIGINAL_TYPED_RESULT'); same(queryRows(originalQuery), expected.rows, 'ORIGINAL_TYPED_ROWS');
  same(expected.result.statements[3].rows, expected.rows.statements[0].rows, 'ORIGINAL_SELECT_ROWS');
  const rows = expected.rows.statements[0].rows;
  need(rows.length === 2 && rows[0].length === 3 && rows[1].length === 3, 'ORIGINAL_ROW_SHAPE');
  same(rows[0][0], { type: 'integer', value: '1' }, 'ORIGINAL_FIRST_ID'); need(rows[0][1].type === 'integer' && rows[0][2].type === 'blob', 'ORIGINAL_RANDOM_TYPES');
  need(byteRecord({ base64: rows[0][2].base64, length: rows[0][2].length, sha256: rows[0][2].sha256 }).length === 180000, 'ORIGINAL_RANDOM_BLOB');
  same(rows[1], [{ type: 'integer', value: '2' }, { type: 'integer', value: '9007199254740993' }, { type: 'blob', ...pack(Buffer.alloc(8192, 73)) }], 'ORIGINAL_EXACT_INTEGER');
  need(expected.seq > originalQuery.response.seq && originalQuery.request.seq > original.response.seq, 'EXPECTATION_ORDER');
  const executions = find('execute'); need(executions.length === 2, 'NO_SQL_REPLAY');
  const update = one(executions.filter((row) => row !== original), 'SOURCE_UPDATE');
  same(update.q.scope, SOURCE, 'SOURCE_UPDATE_SCOPE');
  same(update.q.request, { epoch: '1', id: '2', principal: '3', fingerprint: fingerprint(update.q.statements) }, 'SOURCE_UPDATE_REQUEST');
  same(update.q.statements, [{ sql: 'UPDATE saved SET n=0,payload=zeroblob(16)', params: [] }], 'SOURCE_UPDATE_SQL'); success(update);
  const changed = one(find('query', (row) => row.request.stage === CASES[0] && row !== originalQuery), 'SOURCE_CHANGED_QUERY');
  const changedRows = queryRows(changed); need(!isDeepStrictEqual(changedRows, expected.rows), 'SOURCE_MUST_CHANGE');
  for (const row of changedRows.statements[0].rows) {
    same(row[1], { type: 'integer', value: '0' }, 'SOURCE_CHANGED_INTEGER');
    same(row[2], { type: 'blob', ...pack(Buffer.alloc(16)) }, 'SOURCE_CHANGED_BLOB');
  }
  const snapshot = one(find('snapshot_prepare'), 'SNAPSHOT_PREPARE'), capture = one(find('snapshot_capture'), 'SNAPSHOT_CAPTURE');
  const retained = success(snapshot); success(capture);
  const created = one(find('create'), 'SOURCE_CREATE'), activated = one(find('activate'), 'SOURCE_ACTIVATE');
  need(created.q.nonce === '1' && success(created).transition.nonce === '1' && activated.q.nonce === '2' &&
    activated.q.expected_revision === created.a.revision && success(activated).transition.nonce === '2', 'SOURCE_CREATION_IDENTITY');
  const snapshotHead = one(find('status', (row) => row.request.stage === CASES[0]), 'SNAPSHOT_SOURCE_HEAD');
  same(snapshot.q.input, { creator: '3', operation: '900', expected_revision: success(snapshotHead).revision,
    expected_head_serial: snapshotHead.a.head_serial, label: 'retained original' }, 'SNAPSHOT_INPUT_IDENTITY');
  need(original.response.seq < snapshot.request.seq && snapshot.response.seq < capture.request.seq && capture.response.seq < update.request.seq, 'SNAPSHOT_ORDER');
  same(capture.q.reference, retained.reference, 'SNAPSHOT_REFERENCE');
  need(capture.a.state === 'retained', 'SNAPSHOT_RETAINED'); same(capture.a.accepted.point, retained.point, 'SNAPSHOT_POINT');

  const prepared = new Map();
  for (const row of find('prepare_restore', (row) => row.envelope.ok)) {
    const value = success(row), operation = row.q.restore_operation;
    need(!prepared.has(operation) && ['1001', '1002', '1003', '1004'].includes(operation), 'RESTORE_OPERATION_SET');
    const saved = event('intent_saved', (event) => event.operation === operation);
    const intent = strictJson(byteRecord(saved.body));
    const { version, ...action } = row.q;
    same(intent, { version, deployment: '1', tenant: '2', principal: '3', action }, 'SAVED_INTENT_BINDING');
    need(saved.seq < row.request.seq, 'SAVED_BEFORE_SUBMIT');
    const { operation: _, ...input } = action;
    same(value.input, input, 'PREPARED_INPUT'); same(value.input.source_scope, SOURCE, 'PREPARED_SOURCE');
    same(value.input.snapshot, retained.reference, 'PREPARED_SNAPSHOT'); same(value.point, retained.point, 'PREPARED_POINT');
    scope(value.reference.creation.scope); need(!isDeepStrictEqual(value.reference.creation.scope, SOURCE), 'FRESH_TARGET_SCOPE');
    need(value.reference.creation.scope.deployment === '1' && value.reference.creation.scope.tenant === '2' &&
      value.reference.creation.scope.database !== SOURCE.database, 'TARGET_AUTHORITY_SCOPE');
    same(input.options, { quota: { mode: 'default' } }, 'RESTORE_QUOTA_INPUT');
    need(value.reference.creation.creator === '3' && value.reference.creation.operation === operation &&
      value.reference.creation.name === input.name && value.reference.creation.expected_name_revision === null &&
      hexadecimal(value.reference.descriptor_hash), 'PREPARED_REFERENCE');
    prepared.set(operation, { row, value });
  }
  need(prepared.size === 4 && of('intent_saved').length === 4, 'PREPARED_COUNT');
  need(new Set([...prepared.values()].map(({ value }) => JSON.stringify(value.reference.creation.scope))).size === 4, 'UNIQUE_TARGET_SCOPES');
  const mainScope = prepared.get('1001').value.reference.creation.scope;
  for (const row of http.filter((row) => row.q.scope)) {
    let expectedScope = SOURCE;
    if (row.q.operation === 'query' && row.request.stage !== CASES[0]) {
      expectedScope = row.request.stage === CASES[3] ? prepared.get('1003').value.reference.creation.scope : mainScope;
    } else if (row.q.operation === 'status' && row.request.stage === CASES[4]) expectedScope = mainScope;
    else if (row.q.operation === 'lookup' && row === find('lookup')[0]) expectedScope = mainScope;
    same(row.q.scope, expectedScope, 'ALL_HTTP_SCOPE_BINDING');
  }
  for (const row of http.filter((row) => ['resume_restore', 'inspect_restore', 'abort_restore'].includes(row.q.operation))) {
    const id = row.q.reference?.creation.operation ?? row.q.restore_operation;
    const saved = prepared.get(id); need(saved && saved.row.response.seq < row.request.seq, 'RESTORE_ORIGINAL_IDENTITY');
    if (row.q.reference) same(row.q.reference, saved.value.reference, 'RESTORE_REFERENCE');
    else need(row.q.creator === '3', 'RESTORE_INSPECT_CREATOR');
    if (row.envelope.ok) {
      if (row.q.operation === 'abort_restore') same(row.a.creation, saved.value.reference.creation, 'ABORT_CREATION');
      else same(row.a.prepared, saved.value, 'RESTORE_PREPARED_IDENTITY');
    }
  }
  const phases = (operation) => find('resume_restore', (row) => row.q.reference.creation.operation === operation)
    .map((row) => row.error ?? row.a.phase);
  same(phases('1001'), ['reserved', 'copying', 'copied', 'bound', 'ready'], 'MAIN_PHASES');
  same(phases('1002'), ['reserved', 'copying', 'CONFLICT', 'aborted'], 'CANCEL_PHASES');
  same(phases('1003'), ['reserved', 'copying', 'DENIED', 'copied', 'bound', 'ready'], 'REVOKE_PHASES');
  same(phases('1004'), ['reserved', 'copying', 'copied', 'CORRUPT'], 'AUTHORITY_LOSS_PHASES');
  const conflicts = http.filter((row) => row.request.stage === CASES[1] && row.error);
  need(conflicts.length === 2, 'FIRST_WINNER_CONFLICTS');
  const empty = one(conflicts.filter((row) => row.q.operation === 'prepare_create'), 'FIRST_WINNER_EMPTY');
  const drift = one(conflicts.filter((row) => row.q.operation === 'prepare_restore'), 'FIRST_WINNER_DRIFT');
  error(empty, 'CONFLICT'); error(drift, 'CONFLICT');
  need(empty.q.create_operation === '1001' && empty.q.name === 'restored' && drift.q.restore_operation === '1001' && drift.q.name === 'changed', 'FIRST_WINNER_IDENTITY');
  same(empty.q, { version: 1, operation: 'prepare_create', name: 'restored', create_operation: '1001',
    expected_name_revision: null, options: { quota: { mode: 'default' } } }, 'FIRST_WINNER_CREATE_INPUT');
  same(drift.q, { version: 1, operation: 'prepare_restore', ...prepared.get('1001').value.input, name: 'changed' }, 'FIRST_WINNER_RESTORE_INPUT');

  const gates = of('gate_armed'); need(gates.length === 2, 'GATE_COUNT');
  for (const [index, armed] of gates.entries()) {
    const held = event('gate_held', (row) => row.gate === armed.seq), released = event('gate_released', (row) => row.gate === armed.seq);
    const object = objects.find((row) => row.request.id === held.request);
    need(armed.prefix === SOURCE_PREFIX.slice('/scap-test/'.length) && armed.stage === CASES[index + 2], 'GATE_SCOPE');
    need(object && object.request.method === 'GET' && object.request.path.startsWith(SOURCE_PREFIX) && object.response.status === 200, 'GATE_ACTUAL_PAYLOAD');
    need(armed.seq < object.request.seq && object.request.seq < held.seq && held.seq < released.seq && released.seq < object.response.seq, 'GATE_ORDER');
    const blocked = one(find('resume_restore', (row) => row.q.reference.creation.operation === String(1002 + index) &&
      row.request.seq < held.seq && row.response.seq > released.seq), 'BLOCKED_RESUME');
    error(blocked, index === 0 ? 'CONFLICT' : 'DENIED');
    if (index === 0) {
      const aborted = one(find('inspect_restore', (row) => row.q.restore_operation === '1002' && row.a?.phase === 'aborted'), 'CANCEL_DURABLE');
      need(held.seq < aborted.request.seq && aborted.response.seq < released.seq, 'CANCEL_BEFORE_LATE_COPY');
      const aborts = find('abort_restore'); need(aborts.length >= 1 && aborts.length <= 4, 'CANCEL_ATTEMPTS');
      for (const abort of aborts) { need(abort.q.control_operation === '1102' && abort.q.nonce === '1102' && abort.q.expected_name_revision === '1', 'CANCEL_IDENTITY'); success(abort); }
      need(aborts.at(-1).a.phase === 'aborted', 'CANCEL_COMPLETED');
      error(one(find('resolve_name', (row) => row.q.name === 'cancelled'), 'CANCEL_NAME'), 'NOT_FOUND');
    } else {
      const revoked = one(find('policy', (row) => row.q.nonce === '1203'), 'SOURCE_REVOKED'); success(revoked);
      const policyHeads = find('status', (row) => row.request.stage === CASES[3]);
      need(revoked.q.expected_revision === success(policyHeads[0]).revision && revoked.a.transition.nonce === '1203', 'REVOKE_REVISION');
      same(revoked.q.permissions, [{ principal: '9', read: true, write: true, admin: true }], 'REVOKED_POLICY');
      need(held.seq < revoked.request.seq && revoked.response.seq < released.seq && revoked.request.principal === '3', 'REVOKE_BEFORE_LATE_COPY');
      const restored = one(find('policy', (row) => row.q.nonce === '1204'), 'SOURCE_REAUTHORIZED'); success(restored);
      need(restored.q.expected_revision === success(policyHeads[1]).revision && restored.a.transition.nonce === '1204', 'REAUTHORIZE_REVISION');
      need(restored.request.principal === '9' && blocked.response.seq < restored.request.seq, 'ADMIN_REAUTHORIZE');
      same(restored.q.permissions, [{ principal: '3', read: true, write: true, admin: true },
        { principal: '9', read: true, write: true, admin: true }], 'RESTORED_POLICY');
    }
  }

  const lost = event('sdk_delivery_lost'), unknown = event('unknown_observed');
  const lostCall = one(http.filter((row) => row.request.id === lost.id), 'LOST_CALL');
  need(lostCall.q.operation === 'resume_restore' && lostCall.q.reference.creation.operation === '1001' &&
    lostCall.a?.phase === 'copied' && unknown.id === lost.id && unknown.code === 'UNKNOWN', 'LOST_COMMITTED_COPY');
  same(unknown.reference, { deployment: '1', tenant: '2', principal: '3', operation: 'resume_restore',
    intent: { version: 1, deployment: '1', tenant: '2', principal: '3',
      action: { operation: 'resume_restore', reference: prepared.get('1001').value.reference } } }, 'UNKNOWN_ORIGINAL_IDENTITY');
  need(lostCall.response.seq < lost.seq && lost.seq < unknown.seq && unknown.seq < lifecycle[0].signal.seq, 'LOST_RESPONSE_ORDER');
  const resumeBegin = checkpoint('completed_resume_begin'), resumeEnd = checkpoint('completed_resume_end');
  need(lifecycle[1].ready.seq < resumeBegin.seq && resumeBegin.seq < resumeEnd.seq, 'RESUME_AFTER_RESTART');
  const resumed = http.filter((row) => row.request.seq > resumeBegin.seq && row.response.seq < resumeEnd.seq);
  same(resumed.map((row) => [row.q.operation, success(row).phase]), [['inspect_restore', 'copied'], ['resume_restore', 'bound'], ['resume_restore', 'ready']], 'COMPLETED_RESUME_WINDOW');
  need(objects.every((row) => !(row.request.seq > resumeBegin.seq && row.request.seq < resumeEnd.seq &&
    row.request.method === 'GET' && row.request.path.startsWith(SOURCE_PREFIX))), 'NO_RECOPY');
  const target = prepared.get('1001').value.reference.creation.scope;
  const targetHead = `/scap-test/scap-object/v1/${target.deployment}/${target.tenant}/${target.database}/head`;
  const targetStatus = one(find('status', (row) => isDeepStrictEqual(row.q.scope, target)), 'TARGET_STATUS');
  need(success(targetStatus).sequence === '0' && targetStatus.a.active === false, 'TARGET_SEQUENCE_INACTIVE');
  const heads = objects.filter((row) => row.request.path === targetHead && row.request.method === 'GET' && row.response.status === 200 && row.request.seq > resumeEnd.seq);
  need(heads.length > 0, 'TARGET_HEAD_WITNESS');
  for (const row of heads) {
    const head = strictJson(byteRecord(row.response.body), true); same(head.scope, target, 'TARGET_HEAD_SCOPE');
    need(head.sequence === '0' && head.active === false && head.request_epoch === '1' && head.windows.length === 1 &&
      head.windows[0].count === '0' && head.windows[0].result_bytes === '0', 'TARGET_EMPTY_REQUESTS');
    need(head.restore_origin?.descriptor_hash === prepared.get('1001').value.reference.descriptor_hash && head.restore_origin.phase.kind === 'copied', 'TARGET_PROVENANCE');
  }
  const targetLookup = one(find('lookup', (row) => isDeepStrictEqual(row.q.scope, target)), 'TARGET_LOOKUP');
  same(targetLookup.q.request, original.q.request, 'TARGET_ORIGINAL_REQUEST'); same(success(targetLookup), { state: 'unknown' }, 'TARGET_NO_SOURCE_RECEIPT');
  const originalLookup = one(find('lookup', (row) => isDeepStrictEqual(row.q.scope, SOURCE)), 'SOURCE_LOOKUP');
  same(originalLookup.q.request, original.q.request, 'LOOKUP_ORIGINAL_IDENTITY');
  same(success(originalLookup), committed, 'LOOKUP_ORIGINAL_RESULT');
  need(receiptHash(originalLookup.a.receipt, base64(originalLookup.a.result)) === committed.receipt.result_hash, 'LOOKUP_RECEIPT_HASH');

  const authorityBefore = checkpoint('authority_loss_before_delete'), authorityMissing = checkpoint('authority_loss_missing_verified'), authorityEnd = checkpoint('authority_loss_checks_end');
  const authority = prepared.get('1004').value.reference.creation.scope;
  const authorityPath = `/scap-test/scap-object/v1/${authority.deployment}/${authority.tenant}/${authority.database}/head`;
  same(authorityBefore.scope, authority, 'MISSING_HEAD_SCOPE');
  need([authorityBefore, authorityMissing, authorityEnd].every((row) => row.path === authorityPath), 'MISSING_HEAD_PATH');
  const published = objects.filter((row) => row.request.path === authorityPath && row.request.method === 'PUT' && row.response.status < 300 && row.response.seq < authorityBefore.seq);
  const copiedHeads = published.map((row) => strictJson(byteRecord(row.end.body), true)).filter((head) => head.restore_origin?.phase.kind === 'copied');
  need(copiedHeads.length > 0, 'COPIED_HEAD_BEFORE_DELETE');
  const completionPath = '/scap-test/scap-object/v1/1/2/catalogue/v1/restore-completion/3/1004';
  const completionWrites = objects.filter((row) => row.request.path === completionPath && row.request.method === 'PUT' && row.response.status < 300 && row.response.seq < authorityBefore.seq);
  need(completionWrites.length > 0, 'PERMANENT_COMPLETION_WITNESS');
  need(copiedHeads.every((head) => head.restore_origin.descriptor_hash === prepared.get('1004').value.reference.descriptor_hash &&
    completionWrites.some((row) => row.end.sha256 === head.restore_origin.phase.completion_hash)), 'PERMANENT_COMPLETION_IDENTITY');
  const missingAdmin = admin.filter((row) => row.request.path === authorityPath);
  need(missingAdmin.length === 2 && missingAdmin[0].request.method === 'DELETE' && missingAdmin[0].response.status >= 200 && missingAdmin[0].response.status < 300 &&
    missingAdmin[1].request.method === 'GET' && missingAdmin[1].response.status === 404, 'MISSING_HEAD_DELETE_404');
  need(authorityBefore.seq < missingAdmin[0].request.seq && missingAdmin[0].response.seq < missingAdmin[1].request.seq &&
    missingAdmin[1].response.seq < authorityMissing.seq && authorityMissing.seq < authorityEnd.seq, 'MISSING_HEAD_ORDER');
  const missingChecks = http.filter((row) => row.request.seq > authorityMissing.seq && row.response.seq < authorityEnd.seq);
  same(missingChecks.map((row) => [row.q.operation, row.error]), [['inspect_restore', 'CORRUPT'], ['resume_restore', 'CORRUPT']], 'MISSING_HEAD_FAIL_CLOSED');
  need(objects.every((row) => !(row.request.path === authorityPath && row.request.method === 'PUT' && row.request.seq > missingAdmin[0].request.seq)), 'NO_HEAD_RECREATION');
  for (const check of missingChecks) {
    const reads = objects.filter((row) => row.request.method === 'GET' && check.request.seq < row.request.seq && row.response.seq < check.response.seq);
    const headReads = reads.filter((row) => row.request.path === authorityPath && row.response.status === 404);
    need(headReads.length === 2, 'MISSING_HEAD_ACTUAL_READ');
    need(reads.some((row) => row.request.path === completionPath && row.response.status === 200 &&
      row.response.sha256 === copiedHeads[0].restore_origin.phase.completion_hash &&
      headReads[0].response.seq < row.request.seq && row.response.seq < headReads[1].request.seq), 'MISSING_HEAD_COMPLETION_RECHECK');
  }

  const deleted = checkpoint('source_payloads_deleted');
  const observed = new Set(objects.filter((row) => ['GET', 'PUT'].includes(row.request.method) && row.response.status >= 200 && row.response.status < 300 &&
    row.request.path.startsWith(SOURCE_PREFIX) && row.response.seq < deleted.seq).map((row) => row.request.path));
  need(observed.size >= 6, 'SOURCE_MULTI_OBJECT');
  same([...deleted.keys].sort(), [...observed].sort(), 'SOURCE_PAYLOAD_INVENTORY');
  const sourceAdmin = admin.filter((row) => observed.has(row.request.path));
  need(sourceAdmin.length === observed.size * 2 && sourceAdmin.length + missingAdmin.length === admin.length, 'DELETE_EACH_OBSERVED_PAYLOAD');
  for (const key of observed) {
    const entries = sourceAdmin.filter((row) => row.request.path === key);
    need(entries.length === 2 && entries[0].request.method === 'DELETE' && entries[0].response.status >= 200 && entries[0].response.status < 300 &&
      entries[1].request.method === 'GET' && entries[1].response.status === 404 && entries[0].response.seq < entries[1].request.seq &&
      entries[1].response.seq < deleted.seq, 'SOURCE_DELETE_GET_404');
  }
  need(objects.every((row) => !(row.request.path.startsWith(SOURCE_PREFIX) && row.request.seq > deleted.seq)), 'NO_SOURCE_PAYLOAD_AFTER_DELETE');
  const release = one(find('snapshot_release'), 'SOURCE_RELEASE'), lifecycleChange = one(find('lifecycle'), 'SOURCE_DELETE'), retire = one(find('retire_storage'), 'SOURCE_RETIRE');
  success(release); need(success(lifecycleChange).lifecycle === 'deleted' && lifecycleChange.q.nonce === '1301', 'SOURCE_DELETED'); success(retire);
  same(release.q.reference, retained.reference, 'SOURCE_RELEASE_REFERENCE');
  const deletionHead = one(find('status', (row) => row.request.stage === CASES[6]), 'SOURCE_DELETION_HEAD');
  need(lifecycleChange.q.lifecycle === 'deleted' && lifecycleChange.q.expected_revision === success(deletionHead).revision &&
    lifecycleChange.a.transition.nonce === '1301' && retire.q.expected_head_serial === lifecycleChange.a.head_serial, 'SOURCE_DELETION_IDENTITY');
  need(release.response.seq < lifecycleChange.request.seq && lifecycleChange.response.seq < retire.request.seq &&
    retire.response.seq < sourceAdmin[0].request.seq, 'SOURCE_RETIRE_BEFORE_DELETE');
  need(authorityEnd.seq < release.request.seq && deleted.seq < lifecycle[1].signal.seq && lifecycle[1].removed.seq < lifecycle[2].spawn.seq, 'ALL_CACHE_LOSS_AFTER_DELETE');
  const cold = one(find('query', (row) => row.request.stage === CASES[6]), 'COLD_QUERY');
  need(cold.request.process === 3 && cold.request.seq > lifecycle[2].ready.seq, 'COLD_NEW_PROCESS');
  same(cold.q.scope, target, 'COLD_TARGET_SCOPE'); same(queryRows(cold), expected.rows, 'COLD_EXACT_ROWS');
  const targetPrefix = `/scap-test/scap-object/v1/${target.deployment}/${target.tenant}/${target.database}/inc/${target.incarnation}/gen/${target.generation}/storage/`;
  need(objects.some((row) => row.request.method === 'GET' && row.request.path.startsWith(targetPrefix) && row.response.status === 200 &&
    cold.request.seq < row.request.seq && row.response.seq < cold.response.seq), 'COLD_TARGET_PAYLOAD_READ');
  const resolved = one(find('resolve_name', (row) => row.q.name === 'restored'), 'COLD_RESOLVE');
  same(success(resolved).creation, prepared.get('1001').value.reference.creation, 'COLD_ORIGINAL_NAME');
  need(find('query').length === 5, 'QUERY_COUNT');
  for (const query of find('query', (row) => row.request.stage !== CASES[0])) {
    same(queryRows(query), expected.rows, 'RESTORED_EXACT_ROWS');
    const targetScope = query.request.stage === CASES[3] ? prepared.get('1003').value.reference.creation.scope : target;
    same(query.q.scope, targetScope, 'RESTORED_QUERY_SCOPE');
  }
  return { schema_version: 1, status: 'PASS', cases: CASES, records: records.length,
    sdk_calls: http.length, s3_calls: objects.length, administrative_calls: admin.length,
    removed_source_payloads: observed.size, service_processes: lifecycle.length,
    original_result_sha256: hash(raw), original_receipt_result_hash: committed.receipt.result_hash,
    authority_loss_target: authority, independent_of: ['SDK decoder', 'producer assertions', 'cases.json', 'result.json'],
    boundaries_not_run: ['AWS Standard', 'production IAM', 'cloud fault domains', 'capacity/SLO', 'cryptographic provenance of fixture observations'] };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const directory = resolve(process.argv[2] ?? '.');
  try {
    const result = audit(readRecords(join(directory, 'audit.jsonl')));
    writeFileSync(join(directory, 'independent-audit.json'), JSON.stringify(result, null, 2) + '\n');
    console.log(JSON.stringify(result));
  } catch (error) {
    const result = { schema_version: 1, status: 'FAILED', reason: error instanceof AuditError ? error.message : 'AUDITOR_EXCEPTION' };
    writeFileSync(join(directory, 'independent-audit.json'), JSON.stringify(result, null, 2) + '\n');
    console.error(JSON.stringify(result)); process.exitCode = 1;
  }
}
