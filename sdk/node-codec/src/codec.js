/** Versioned SCAPSQL1 identity and SCAPRES1 result primitives; no network I/O. */
import { createHash } from 'node:crypto';
import { Buffer, isUtf8 } from 'node:buffer';

const U32 = 0xffffffff;
const I64_MIN = -(1n << 63n);
const I64_MAX = (1n << 63n) - 1n;
const REQUEST = Buffer.from('SCAPSQL1');
const RESULT = Buffer.from('SCAPRES1');

/** Wire capabilities, not today's SQL admission settings or an HTTP contract. */
export const FORMAT_LIMITS = Object.freeze({
  maxStatements: 65536, maxSqlBytes: 64 * 1024 * 1024, maxParameters: 32766,
  maxColumns: 2000, maxRows: U32, maxResultBytes: 64 * 1024 * 1024,
  maxValueBytes: 64 * 1024 * 1024, maxInputBytes: 64 * 1024 * 1024,
});
const ALLOCATION = Object.freeze({ maxRows: 1_000_000, maxValues: 1_000_000, maxColumns: 100_000 });

export class CodecError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'CodecError';
    this.code = code;
  }
}

function requireValue(ok, code, message) {
  if (!ok) throw new CodecError(code, message);
}

function configuration(overrides, defaults) {
  requireValue(overrides !== null && typeof overrides === 'object' && !Array.isArray(overrides),
    'INVALID', 'Limits must be an object');
  const result = { ...defaults };
  for (const [key, value] of Object.entries(overrides)) {
    requireValue(Object.hasOwn(defaults, key) && Number.isSafeInteger(value) && value > 0,
      'INVALID', 'Unknown or invalid limit');
    const ceiling = defaults === ALLOCATION ? U32 : defaults[key];
    requireValue(value <= ceiling, 'LIMIT', 'Limit exceeds format capability');
    result[key] = value;
  }
  if (defaults === FORMAT_LIMITS) {
    requireValue(result.maxResultBytes >= 12, 'INVALID', 'Result budget is smaller than its header');
  }
  return result;
}

function utf8(text, maximum) {
  requireValue(typeof text === 'string' && text.isWellFormed(), 'INVALID', 'Expected well-formed Unicode');
  requireValue(Buffer.byteLength(text, 'utf8') <= maximum, 'LIMIT', 'UTF-8 value exceeds byte budget');
  return Buffer.from(text, 'utf8');
}

function u32(value) {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32LE(value);
  return bytes;
}

function binary(value) {
  requireValue(value instanceof Uint8Array && !(value.buffer instanceof SharedArrayBuffer),
    'INVALID', 'Expected an unshared Uint8Array or Buffer');
  return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
}

/**
 * Exact typed identity. Integer parameters must be bigint; number means Real.
 * Whitespace, parameter ordering and negative zero are intentionally significant.
 * Only a hash is returned; it is not authorization, a request ID, or an ACK.
 */
export function fingerprint(statements, overrides = {}) {
  const limits = configuration(overrides, FORMAT_LIMITS);
  requireValue(Array.isArray(statements), 'INVALID', 'Expected a statement array');
  requireValue(statements.length > 0 && statements.length <= limits.maxStatements,
    'LIMIT', 'Expected a nonempty bounded statement array');
  let inputLeft = limits.maxInputBytes;
  let sqlLeft = limits.maxSqlBytes;
  const hash = createHash('sha256');
  function put(bytes) {
    requireValue(bytes.byteLength <= inputLeft, 'LIMIT', 'Aggregate encoded request exceeds budget');
    inputLeft -= bytes.byteLength;
    hash.update(bytes);
  }
  put(REQUEST);
  put(u32(statements.length));
  for (const statement of statements) {
    requireValue(statement !== null && typeof statement === 'object' &&
      typeof statement.sql === 'string' && statement.sql.length > 0 && !statement.sql.includes('\0') &&
      Array.isArray(statement.parameters), 'INVALID', 'Expected SQL and explicit positional parameters');
    const sql = utf8(statement.sql, sqlLeft);
    sqlLeft -= sql.length;
    requireValue(statement.parameters.length <= limits.maxParameters, 'LIMIT', 'Too many parameters');
    put(u32(sql.length));
    put(sql);
    put(u32(statement.parameters.length));
    for (const value of statement.parameters) {
      if (value === null) {
        put(Buffer.from([0]));
      } else if (typeof value === 'bigint') {
        requireValue(value >= I64_MIN && value <= I64_MAX, 'INVALID', 'Integer outside signed 64-bit range');
        const encoded = Buffer.alloc(9);
        encoded[0] = 1;
        encoded.writeBigInt64LE(value, 1);
        put(encoded);
      } else if (typeof value === 'number') {
        requireValue(Number.isFinite(value), 'INVALID', 'Nonfinite real is not supported');
        const encoded = Buffer.alloc(9);
        encoded[0] = 2;
        encoded.writeDoubleLE(value, 1);
        put(encoded);
      } else if (typeof value === 'string') {
        const encoded = utf8(value, limits.maxValueBytes);
        put(Buffer.from([3]));
        put(u32(encoded.length));
        put(encoded);
      } else {
        const encoded = binary(value);
        requireValue(encoded.length <= limits.maxValueBytes, 'LIMIT', 'BLOB exceeds byte budget');
        put(Buffer.from([4]));
        put(u32(encoded.length));
        put(encoded);
      }
    }
  }
  return hash.digest('hex');
}

function parse(input, limits, allocation) {
  const bytes = binary(input);
  requireValue(bytes.length <= limits.maxResultBytes, 'LIMIT', 'Encoded result exceeds byte budget');
  let offset = 0;
  function take(length) {
    requireValue(length <= bytes.length - offset, 'MALFORMED', 'Truncated result');
    const part = bytes.subarray(offset, offset + length);
    offset += length;
    return part;
  }
  function count(maximum) {
    const value = take(4).readUInt32LE();
    requireValue(value <= maximum, 'LIMIT', 'Result count exceeds budget');
    return value;
  }
  function valueBytes() { return take(count(limits.maxValueBytes)); }
  function text() {
    const raw = valueBytes();
    requireValue(isUtf8(raw), 'MALFORMED', 'Invalid UTF-8');
    // Buffer decoding preserves an initial U+FEFF, matching Rust String.
    return allocation ? raw.toString('utf8') : undefined;
  }
  function value() {
    const tag = take(1)[0];
    switch (tag) {
      case 0: return null;
      case 1: return take(8).readBigInt64LE();
      case 2: {
        const real = take(8).readDoubleLE();
        requireValue(Number.isFinite(real), 'INVALID', 'Nonfinite real');
        return real;
      }
      case 3: return text();
      case 4: {
        const raw = valueBytes();
        return allocation ? Buffer.from(raw) : undefined;
      }
      default: throw new CodecError('MALFORMED', 'Unknown value tag');
    }
  }
  requireValue(take(8).equals(RESULT), 'MALFORMED', 'Unknown result version');
  const statementsCount = count(limits.maxStatements);
  const statements = allocation ? [] : null;
  let rowsLeft = limits.maxRows;
  let decodedRowsLeft = allocation?.maxRows;
  let valuesLeft = allocation?.maxValues;
  let decodedColumnsLeft = allocation?.maxColumns;
  for (let s = 0; s < statementsCount; ++s) {
    const columnsCount = count(limits.maxColumns);
    if (allocation) {
      requireValue(columnsCount <= decodedColumnsLeft, 'LIMIT', 'Decoded columns exceed client allocation budget');
      decodedColumnsLeft -= columnsCount;
    }
    const columns = allocation ? [] : null;
    for (let c = 0; c < columnsCount; ++c) {
      const column = text();
      if (allocation) columns.push(column);
    }
    const rowsCount = count(rowsLeft);
    requireValue(columnsCount !== 0 || rowsCount === 0, 'MALFORMED', 'Zero-width rows');
    rowsLeft -= rowsCount;
    if (allocation) {
      requireValue(rowsCount <= decodedRowsLeft && rowsCount * columnsCount <= valuesLeft,
        'LIMIT', 'Decoded result exceeds client allocation budget');
      decodedRowsLeft -= rowsCount;
      valuesLeft -= rowsCount * columnsCount;
    }
    const rows = allocation ? [] : null;
    for (let r = 0; r < rowsCount; ++r) {
      const row = allocation ? [] : null;
      for (let c = 0; c < columnsCount; ++c) {
        const cell = value();
        if (allocation) row.push(cell);
      }
      if (allocation) rows.push(row);
    }
    const affectedRows = take(8).readBigUInt64LE();
    const lastInsertRowid = take(8).readBigInt64LE();
    if (allocation) statements.push({ columns, rows, affectedRows, lastInsertRowid });
  }
  requireValue(offset === bytes.length, 'MALFORMED', 'Trailing result bytes');
  return allocation ? { statements } : undefined;
}

/** Structural check without retaining a row graph or copying BLOBs/text. */
export function validateResult(bytes, overrides = {}) {
  parse(bytes, configuration(overrides, FORMAT_LIMITS), null);
}

/**
 * Materialize valid bytes with an independent, bounded client allocation policy.
 * A local LIMIT does not mean the SQL transaction failed or may be retried.
 * Every i64 and affected-row u64 is bigint; returned BLOBs own their bytes.
 */
export function decodeResult(bytes, overrides = {}, allocation = {}) {
  return parse(bytes, configuration(overrides, FORMAT_LIMITS), configuration(allocation, ALLOCATION));
}
