/** Strict, lossless JSON boundary. These helpers do not perform I/O. */
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { fingerprint, decodeResult, FORMAT_LIMITS } from '../../node-codec/src/codec.js';
import { ClientError, RemoteError, UnknownError, CommittedResultError } from './errors.js';

const U64 = (1n << 64n) - 1n;
const I64_MIN = -(1n << 63n);
const I64_MAX = (1n << 63n) - 1n;
const SCOPE = ['deployment', 'tenant', 'database', 'incarnation', 'generation'];
const REQUEST = ['epoch', 'id', 'principal', 'fingerprint'];
const TRACKED = new WeakSet();

export function requireValue(ok, message) {
  if (!ok) throw new ClientError('INVALID', message);
}

export function record(value, required, optional = []) {
  requireValue(value !== null && typeof value === 'object' && !Array.isArray(value), 'Expected an object');
  const prototype = Object.getPrototypeOf(value);
  requireValue(prototype === Object.prototype || prototype === null, 'Expected a plain object');
  const keys = Reflect.ownKeys(value);
  requireValue(required.every((key) => Object.hasOwn(value, key)), 'Missing required field');
  for (const key of keys) {
    requireValue(required.includes(key) || optional.includes(key), 'Unknown field');
    requireValue(Object.hasOwn(Object.getOwnPropertyDescriptor(value, key), 'value'), 'Accessor fields are not accepted');
  }
  return value;
}

export function decimal(value, zero = false) {
  requireValue(typeof value === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(value), 'Expected a canonical decimal string');
  const number = BigInt(value);
  requireValue(number <= U64 && (zero || number !== 0n), 'Decimal outside the unsigned 64-bit range');
  return value;
}

function hash(value) {
  requireValue(typeof value === 'string' && /^[0-9a-f]{64}$/.test(value), 'Expected a SHA-256 identity');
  return value;
}

export function scope(value) {
  record(value, SCOPE);
  return Object.freeze(Object.fromEntries(SCOPE.map((key) => [key, decimal(value[key])])));
}

export function sameScope(actual, expected) {
  requireValue(SCOPE.every((key) => actual[key] === expected[key]), 'Database identity does not match');
}

function identity(value) {
  record(value, REQUEST);
  return Object.freeze({ epoch: decimal(value.epoch), id: decimal(value.id),
    principal: decimal(value.principal), fingerprint: hash(value.fingerprint) });
}

export function transition(value) {
  record(value, ['revision', 'nonce']);
  return Object.freeze({ revision: decimal(value.revision), nonce: decimal(value.nonce) });
}

export function receipt(value, expectedScope, expectedRequest) {
  record(value, ['scope', 'request', 'sequence', 'transition', 'data_root', 'result_hash']);
  const result = { scope: scope(value.scope), request: identity(value.request),
    sequence: decimal(value.sequence), transition: transition(value.transition),
    data_root: hash(value.data_root), result_hash: hash(value.result_hash) };
  sameScope(result.scope, expectedScope);
  requireValue(REQUEST.every((key) => result.request[key] === expectedRequest[key]), 'Receipt does not match the original request');
  requireValue(result.transition.nonce === result.request.id, 'Receipt transition does not match the request');
  return Object.freeze(result);
}

export function base64(value, maximum = FORMAT_LIMITS.maxResultBytes) {
  requireValue(typeof value === 'string' && value.length <= 4 * Math.ceil(maximum / 3), 'Encoded bytes exceed the response budget');
  const bytes = Buffer.from(value, 'base64');
  requireValue(bytes.length <= maximum && bytes.toString('base64') === value, 'Expected canonical base64');
  return bytes;
}

function copiedValue(value) {
  if (value === null || ['bigint', 'number', 'string'].includes(typeof value)) return value;
  requireValue(value instanceof Uint8Array && !(value.buffer instanceof SharedArrayBuffer), 'Expected an unshared byte array');
  return Buffer.from(value);
}

function encodedValue(value) {
  if (value === null) return Object.freeze({ type: 'null' });
  if (typeof value === 'bigint') return Object.freeze({ type: 'integer', value: value.toString() });
  if (typeof value === 'number') {
    const bytes = Buffer.alloc(8);
    bytes.writeDoubleBE(value);
    return Object.freeze({ type: 'real', bits: bytes.toString('hex') });
  }
  if (typeof value === 'string') return Object.freeze({ type: 'text', value });
  return Object.freeze({ type: 'blob', base64: value.toString('base64') });
}

/** Snapshot before hashing or sending: caller mutations cannot change a prepared request. */
export function encodeStatements(input) {
  requireValue(Array.isArray(input), 'Expected a statement array');
  const statements = input.map((statement) => {
    record(statement, ['sql', 'parameters']);
    requireValue(Array.isArray(statement.parameters), 'Expected positional parameters');
    return { sql: statement.sql, parameters: statement.parameters.map(copiedValue) };
  });
  const digest = fingerprint(statements);
  const wire = statements.map((statement) => Object.freeze({ sql: statement.sql,
    params: Object.freeze(statement.parameters.map(encodedValue)) }));
  return { fingerprint: digest, statements: Object.freeze(wire) };
}

function decodedValue(value) {
  record(value, ['type'], ['value', 'bits', 'base64']);
  switch (value.type) {
    case 'null':
      record(value, ['type']);
      return null;
    case 'integer': {
      record(value, ['type', 'value']);
      requireValue(typeof value.value === 'string' && /^(0|-?[1-9][0-9]{0,18})$/.test(value.value), 'Expected a canonical signed integer');
      const number = BigInt(value.value);
      requireValue(number >= I64_MIN && number <= I64_MAX, 'Integer outside signed 64-bit range');
      return number;
    }
    case 'real': {
      record(value, ['type', 'bits']);
      requireValue(typeof value.bits === 'string' && /^[0-9a-f]{16}$/.test(value.bits), 'Expected eight IEEE-754 bytes');
      const number = Buffer.from(value.bits, 'hex').readDoubleBE();
      requireValue(Number.isFinite(number), 'Nonfinite real is not supported');
      return number;
    }
    case 'text':
      record(value, ['type', 'value']);
      requireValue(typeof value.value === 'string', 'Expected text');
      return value.value;
    case 'blob':
      record(value, ['type', 'base64']);
      return base64(value.base64, FORMAT_LIMITS.maxValueBytes);
    default:
      throw new ClientError('INVALID', 'Unknown parameter type');
  }
}

export function prepare(input, requestIdentity, databaseScope) {
  record(requestIdentity, ['epoch', 'id', 'principal']);
  const fixedScope = scope(databaseScope);
  const encoded = encodeStatements(input);
  const request = identity({ ...requestIdentity, fingerprint: encoded.fingerprint });
  const tracked = Object.freeze({ scope: fixedScope, request, statements: encoded.statements });
  TRACKED.add(tracked);
  return tracked;
}

export function checkTracked(value, databaseScope, principal) {
  requireValue(TRACKED.has(value), 'Use prepare or restore to obtain a tracked request');
  sameScope(value.scope, databaseScope);
  requireValue(value.request.principal === principal, 'Request principal does not match the client');
  return value;
}

/** Restore a saved identity without allocating a new request or sending SQL. */
export function restore(serialized, databaseScope) {
  requireValue(typeof serialized === 'string', 'Expected a serialized tracked request');
  requireValue(Buffer.byteLength(serialized) <= 96 * 1024 * 1024, 'Saved request exceeds the wire budget');
  const saved = parseJson(serialized);
  record(saved, ['scope', 'request', 'statements']);
  const fixedScope = scope(saved.scope);
  sameScope(fixedScope, databaseScope);
  const request = identity(saved.request);
  requireValue(Array.isArray(saved.statements), 'Expected wire statements');
  const input = saved.statements.map((statement) => {
    record(statement, ['sql', 'params']);
    requireValue(Array.isArray(statement.params), 'Expected wire parameters');
    return { sql: statement.sql, parameters: statement.params.map(decodedValue) };
  });
  const tracked = prepare(input, { epoch: request.epoch, id: request.id, principal: request.principal }, fixedScope);
  requireValue(tracked.request.fingerprint === request.fingerprint, 'Saved fingerprint does not match its input');
  return tracked;
}

export function status(value, expectedScope) {
  record(value, ['scope', 'revision', 'sequence', 'owner_epoch', 'owner_instance', 'active',
    'auth_epoch', 'lifecycle', 'request_epoch', 'max_bytes', 'transition', 'retention']);
  const result = { ...value, scope: scope(value.scope), transition: transition(value.transition) };
  sameScope(result.scope, expectedScope);
  for (const key of ['revision', 'owner_epoch', 'owner_instance', 'auth_epoch', 'request_epoch']) decimal(value[key]);
  decimal(value.sequence, true);
  requireValue(typeof value.active === 'boolean', 'Expected owner activation state');
  lifecycle(value.lifecycle);
  quota(value.max_bytes);
  requireValue(result.transition.revision === result.revision, 'Status transition revision does not match');
  record(value.retention, ['max_entries', 'max_result_bytes', 'oldest_epoch']);
  requireValue(Number.isSafeInteger(value.retention.max_entries) && value.retention.max_entries > 0 &&
    value.retention.max_entries <= 65536, 'Invalid request retention count');
  decimal(value.retention.max_result_bytes);
  decimal(value.retention.oldest_epoch);
  requireValue(BigInt(value.retention.oldest_epoch) <= BigInt(value.request_epoch), 'Invalid retention epoch');
  result.retention = Object.freeze({ ...value.retention });
  return Object.freeze(result);
}

export function lifecycle(value) {
  requireValue(['ready', 'maintenance', 'deleted'].includes(value), 'Unknown lifecycle');
  return value;
}

export function quota(value) {
  if (value !== null) {
    decimal(value);
    requireValue(BigInt(value) % 4096n === 0n && BigInt(value) <= 4294967294n * 4096n,
      'Database quota must be page aligned and within the native page range');
  }
  return value;
}

export function permissions(value) {
  requireValue(Array.isArray(value) && value.length > 0 && value.length <= 1024, 'Expected a bounded permission list');
  const seen = new Set();
  const result = value.map((permission) => {
    record(permission, ['principal', 'read', 'write', 'admin']);
    decimal(permission.principal);
    requireValue(!seen.has(permission.principal), 'Duplicate policy principal');
    seen.add(permission.principal);
    requireValue(['read', 'write', 'admin'].every((key) => typeof permission[key] === 'boolean'), 'Expected permission booleans');
    return Object.freeze({ ...permission });
  });
  requireValue(result.some((permission) => permission.admin), 'Policy must retain an administrator');
  return Object.freeze(result);
}

/** Detect duplicate keys and excessive structure before JSON.parse can discard information. */
export function parseJson(text) {
  try {
    const stack = [];
    for (let i = 0; i < text.length; ++i) {
      const character = text[i];
      if (character === '"') {
        const begin = i++;
        while (i < text.length && text[i] !== '"') {
          if (text[i] === '\\') ++i;
          ++i;
        }
        const context = stack.at(-1);
        if (context?.key) {
          const key = JSON.parse(text.slice(begin, i + 1));
          requireValue(!context.keys.has(key), 'Duplicate JSON key');
          requireValue(context.keys.size < 128, 'Too many JSON keys');
          context.keys.add(key);
          context.key = false;
        }
      } else if (character === '{' || character === '[') {
        requireValue(stack.length < 32, 'JSON nesting is too deep');
        stack.push(character === '{' ? { key: true, keys: new Set() } : { key: false });
      } else if (character === '}' || character === ']') {
        stack.pop();
      } else if (character === ',' && stack.at(-1)?.keys) {
        stack.at(-1).key = true;
      }
    }
    return JSON.parse(text);
  } catch {
    throw new ClientError('INVALID', 'Malformed, duplicate-key or over-nested JSON');
  }
}

/**
 * result_hash names the whole SCAPOBJ2 Result object, not the naked SQL bytes.
 * All interpolated numbers/hashes below came through receipt validation. This
 * exact format-2 struct order matches scap_object::format::encode_object.
 * Decimal strings are never routed through a JavaScript Number.
 */
export function resultHash(value, raw) {
  const s = value.scope, r = value.request, t = value.transition;
  const metadata = Buffer.from(`{"format":2,"scope":{${SCOPE.map((key) => `"${key}":${s[key]}`).join(',')}},` +
    `"payload":{"kind":"result","value":{"request":{"epoch":${r.epoch},"id":${r.id},` +
    `"principal":${r.principal},"fingerprint":"${r.fingerprint}"},"sequence":${value.sequence},` +
    `"transition":{"revision":${t.revision},"nonce":${t.nonce}},"data_root":"${value.data_root}","bytes":[]}}}`);
  const header = Buffer.alloc(20);
  header.write('SCAPOBJ2');
  header.writeUInt32LE(metadata.length, 8);
  header.writeBigUInt64LE(BigInt(raw.length), 12);
  return createHash('sha256').update(header).update(metadata).update(raw).digest('hex');
}

export function committed(value, databaseScope, request, limits, allocation) {
  record(value, ['state', 'receipt', 'result']);
  requireValue(value.state === 'committed', 'Expected a committed result');
  const confirmed = receipt(value.receipt, databaseScope, request);
  const raw = base64(value.result);
  requireValue(resultHash(confirmed, raw) === confirmed.result_hash, 'Result digest does not match its receipt');
  try {
    return Object.freeze({ state: 'committed', receipt: confirmed, rawResult: raw,
      result: decodeResult(raw, limits, allocation) });
  } catch (error) {
    // The exact committed object has been verified. Client materialization or
    // result syntax failure does not undo the transaction or permit replay.
    throw new CommittedResultError(error.code, confirmed, raw);
  }
}

export function resolved(value, databaseScope, request, limits, allocation) {
  record(value, ['state'], ['transition', 'receipt', 'result']);
  if (value.state === 'committed') return committed(value, databaseScope, request, limits, allocation);
  if (value.state === 'cancelled') {
    record(value, ['state', 'transition']);
    const barrier = transition(value.transition);
    requireValue(barrier.nonce === request.id, 'Cancellation does not match the original request');
    return Object.freeze({ state: 'cancelled', transition: barrier });
  }
  record(value, ['state']);
  requireValue(['unknown', 'closed', 'retired'].includes(value.state), 'Unknown request resolution');
  return Object.freeze({ state: value.state });
}

const ERROR_STATUS = Object.freeze({
  UNAUTHENTICATED: 401, DENIED: 403, INVALID: 400, VERSION: 400, LIMIT: 413,
  BACKPRESSURE: 429, RECOVERY_BUSY: 429, UNKNOWN: 503, UNAVAILABLE: 503, DEADLINE: 503,
  COMMITTED_BUT_UNAVAILABLE: 503, LIFECYCLE: 409, FENCED: 409, CONFLICT: 409,
  REQUEST_CONFLICT: 409, WINDOW_FULL: 409, CLOSED: 409, RETIRED: 409, MISSING: 409,
  CORRUPT: 409, STALE_SNAPSHOT: 409, ENGINE: 409, CONFIG: 409, CACHE_IO: 409,
});

/** Only the versioned API envelope may provide an outcome; HTTP alone cannot. */
export function envelope(value, httpStatus, reference) {
  record(value, ['ok'], ['value', 'error']);
  if (value.ok === true) {
    record(value, ['ok', 'value']);
    requireValue(httpStatus === 200, 'Unexpected success HTTP status');
    return value.value;
  }
  requireValue(value.ok === false, 'Expected an explicit response outcome');
  record(value, ['ok', 'error']);
  const error = record(value.error, ['code', 'message'], ['receipt']);
  requireValue(typeof error.code === 'string' && Object.hasOwn(ERROR_STATUS, error.code) &&
    httpStatus === ERROR_STATUS[error.code], 'Unexpected error code or HTTP status');
  requireValue(typeof error.message === 'string' && error.message.length <= 1024, 'Invalid error message');
  if (Object.hasOwn(error, 'receipt')) {
    requireValue(error.code === 'COMMITTED_BUT_UNAVAILABLE' && reference.request !== undefined,
      'Unexpected receipt on failure');
    throw new CommittedResultError(error.code, receipt(error.receipt, reference.scope, reference.request));
  }
  if (error.code === 'UNKNOWN') throw new UnknownError(reference);
  // Never put a server-provided message into an exception: it may echo secrets.
  throw new RemoteError(error.code, `The server returned ${error.code}; no operation is retried`, reference);
}
