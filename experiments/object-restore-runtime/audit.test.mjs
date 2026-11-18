import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { decodeResult, fingerprint, byteRecord, strictJson, audit, readRecords, AuditError } from './audit.mjs';

const hash = (value) => createHash('sha256').update(value).digest('hex');
test('independent result decoder preserves integer, blob, text, real bits and original counters', () => {
  const parts = [Buffer.from('SCAPRES1')];
  const u32 = (value) => { const bytes = Buffer.alloc(4); bytes.writeUInt32LE(value); parts.push(bytes); };
  const sized = (value) => { const bytes = Buffer.from(value); u32(bytes.length); parts.push(bytes); };
  const i64 = (value) => { const bytes = Buffer.alloc(8); bytes.writeBigInt64LE(value); parts.push(bytes); };
  u32(1); u32(5); for (const name of ['n', 'b', 's', 'r', 'empty']) sized(name); u32(1);
  parts.push(Buffer.from([1])); i64(9007199254740993n);
  parts.push(Buffer.from([4])); sized(Buffer.from([0, 255, 0]));
  parts.push(Buffer.from([3])); sized('原值');
  parts.push(Buffer.from([2])); parts.push(Buffer.from('0000000000000080', 'hex'));
  parts.push(Buffer.from([0])); i64(2n); i64(-3n);
  const raw = Buffer.concat(parts), value = decodeResult(raw);
  assert.deepEqual(value.statements[0], { columns: ['n', 'b', 's', 'r', 'empty'], rows: [[
    { type: 'integer', value: '9007199254740993' }, { type: 'blob', base64: 'AP8A', length: 3, sha256: hash(Buffer.from([0, 255, 0])) },
    { type: 'text', value: '原值' }, { type: 'real', bits: '8000000000000000' }, { type: 'null' }]], affected_rows: '2', last_insert_rowid: '-3' });
  assert.throws(() => decodeResult(raw.subarray(0, -1)), /RESULT_TRUNCATED/);
  assert.throws(() => decodeResult(Buffer.concat([raw, Buffer.from([0])])), /RESULT_TRAILING/);
  const magic = Buffer.from(raw); magic[0] = 0; assert.throws(() => decodeResult(magic), /RESULT_MAGIC/);
});

test('independent SQL fingerprint uses precise values and canonical blobs', () => {
  const statements = [{ sql: 'SELECT ?', params: [{ type: 'integer', value: '9007199254740993' }] }];
  const bytes = Buffer.from('5343415053514c31010000000800000053454c454354203f01000000010100000000002000', 'hex');
  assert.equal(fingerprint(statements), hash(bytes));
  assert.notEqual(fingerprint([{ sql: 'SELECT ?', params: [{ type: 'integer', value: '9007199254740992' }] }]), hash(bytes));
  assert.throws(() => fingerprint([{ sql: 'SELECT ?', params: [{ type: 'blob', base64: 'YQ' }] }]), /BASE64/);
});

test('exact bodies and independent JSON reject duplicate, noncanonical or mismatched evidence', () => {
  const raw = Buffer.from('{"n":9007199254740993}');
  assert.deepEqual(strictJson(raw, true), { n: '9007199254740993' });
  assert.deepEqual(byteRecord({ base64: raw.toString('base64'), length: raw.length, sha256: hash(raw) }), raw);
  assert.throws(() => byteRecord({ base64: raw.toString('base64'), length: raw.length, sha256: '0'.repeat(64) }), /BODY_HASH/);
  assert.throws(() => strictJson(Buffer.from('{"a":1,"a":2}')), /JSON_DUPLICATE/);
  assert.throws(() => strictJson(Buffer.from([255])), /JSON_BYTES/);
  assert.throws(() => strictJson(Buffer.from('{')), /JSON_SYNTAX/);
});

test('empty, partial and ordinal-hole traces cannot report success', () => {
  assert.throws(() => audit([]), AuditError);
  assert.throws(() => audit([{ schema: 1, seq: 2, kind: 'case_begin', stage: 'setup', name: 'anything' }]), /SEQUENCE_HOLE/);
  const directory = mkdtempSync(join(tmpdir(), 'scap-auditor-test-'));
  try {
    const path = join(directory, 'partial.jsonl'); writeFileSync(path, '{"schema":1}');
    assert.throws(() => readRecords(path), /PARTIAL_LAST_RECORD/);
    writeFileSync(path, '{"schema":1,"schema":2}\n'); assert.throws(() => readRecords(path), /JSON_DUPLICATE/);
  } finally { rmSync(directory, { recursive: true }); }
});
