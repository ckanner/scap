import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { Buffer } from 'node:buffer';
import { CodecError, FORMAT_LIMITS, fingerprint, validateResult, decodeResult } from '../src/codec.js';

const SMALL = { maxStatements: 8, maxSqlBytes: 1024, maxParameters: 16, maxColumns: 16,
  maxRows: 32, maxResultBytes: 4096, maxValueBytes: 128, maxInputBytes: 4096 };
const empty = Buffer.from('534341505245533100000000', 'hex');
// Exact fixture from crates/scap-sql/src/tests.rs at main 8190506.
const golden = Buffer.from([
  83,67,65,80,82,69,83,49,1,0,0,0,1,0,0,0,1,0,0,0,120,1,0,0,0,1,42,
  0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,7,0,0,0,0,0,0,0,
]);
const goldenHash = Buffer.from([181,79,46,113,131,174,197,229,175,216,13,209,244,10,194,27,
  109,179,35,43,0,112,147,108,168,209,235,144,90,195,213,187]).toString('hex');
const stmt = (parameters = [], sql = 'SELECT ?1') => ({ sql, parameters });
const fail = (fn, code) => assert.throws(fn, error => error instanceof CodecError && error.code === code);

// Independent fixture encoder, deliberately not exported or used by production.
function le(value, width, signed = false) {
  const bytes = new Uint8Array(width), view = new DataView(bytes.buffer);
  if (width === 4) view.setUint32(0, value, true);
  else if (signed) view.setBigInt64(0, value, true);
  else view.setBigUint64(0, value, true);
  return Buffer.from(bytes);
}
function stringBytes(text) {
  const raw = Buffer.from(text); return [le(raw.length, 4), raw];
}
function wireValue(value) {
  if (value === null) return [Buffer.from([0])];
  if (typeof value === 'bigint') return [Buffer.from([1]), le(value, 8, true)];
  if (typeof value === 'number') {
    const bytes = new Uint8Array(8); new DataView(bytes.buffer).setFloat64(0, value, true);
    return [Buffer.from([2]), Buffer.from(bytes)];
  }
  if (typeof value === 'string') return [Buffer.from([3]), ...stringBytes(value)];
  return [Buffer.from([4]), le(value.length, 4), Buffer.from(value)];
}
function result(statements) {
  const out = [Buffer.from('SCAPRES1'), le(statements.length, 4)];
  for (const row of statements) {
    out.push(le(row.columns.length, 4));
    for (const name of row.columns) out.push(...stringBytes(name));
    out.push(le(row.rows.length, 4));
    for (const values of row.rows) for (const value of values) out.push(...wireValue(value));
    out.push(le(row.affectedRows, 8), le(row.lastInsertRowid, 8, true));
  }
  return Buffer.concat(out);
}
function one(value) {
  return result([{columns: ['x'], rows: [[value]], affectedRows: 1n, lastInsertRowid: 7n}]);
}
function referenceFingerprint(statements) {
  const parts = [Buffer.from('SCAPSQL1'), le(statements.length, 4)];
  for (const statement of statements) {
    parts.push(...stringBytes(statement.sql), le(statement.parameters.length, 4));
    for (const value of statement.parameters) parts.push(...wireValue(value));
  }
  return createHash('sha256').update(Buffer.concat(parts)).digest('hex');
}

// No HTTP mock is described as a running S3 database. These are codec tests.
test('matches the independent Rust v1 hash and result vectors exactly', () => {
  assert.equal(fingerprint([stmt([42n])]), goldenHash);
  assert.equal(fingerprint([stmt([42n])], SMALL), goldenHash);
  assert.deepEqual(decodeResult(golden), {statements:[{columns:['x'],rows:[[42n]],affectedRows:1n,lastInsertRowid:7n}]});
  assert.equal(validateResult(golden), undefined);
  assert.deepEqual(decodeResult(empty), {statements:[]});
  assert.equal(validateResult(empty), undefined);
  assert.equal(new CodecError('INVALID', 'test').name, 'CodecError');
});

test('all typed values keep exact bits, BOM, NUL, UTF-8 and owned BLOB data', () => {
  const values = [null, -(1n<<63n), (1n<<63n)-1n, -0, 0, Number.MIN_VALUE, Number.MAX_VALUE,
    '\ufeff原结果\0😀', '', Buffer.from([0,255,42]), Buffer.alloc(0)];
  const rows = [{columns:values.map((_,i)=>i===0?'\ufeffn':String(i)), rows:[values],
    affectedRows:(1n<<64n)-1n, lastInsertRowid:-(1n<<63n)},
    {columns:[],rows:[],affectedRows:0n,lastInsertRowid:0n}];
  const bytes = result(rows), before = Buffer.from(bytes);
  assert.deepEqual(decodeResult(bytes), {statements:rows});
  assert.equal(validateResult(bytes), undefined);
  assert.equal(Object.is(decodeResult(bytes).statements[0].rows[0][3], -0), true);
  assert.deepEqual(bytes, before);
  const decoded = decodeResult(one(Buffer.from([1,2,3])));
  decoded.statements[0].rows[0][0][0] = 9;
  const independent = one(Buffer.from([1,2,3]));
  const copy = decodeResult(independent); independent.fill(0);
  assert.deepEqual(copy.statements[0].rows[0][0], Buffer.from([1,2,3]));
});

test('fingerprints distinguish whitespace, parameter order, types and negative zero', () => {
  const base = stmt([null,42n,-0,'文\0😀',Buffer.from([255,0])]);
  assert.equal(fingerprint([base]), referenceFingerprint([base]));
  const variants = [stmt(base.parameters,'SELECT ?1 '), stmt([42n,null,-0,'文\0😀',Buffer.from([255,0])]),
    stmt([null,42,-0,'文\0😀',Buffer.from([255,0])]),stmt([null,42n,0,'文\0😀',Buffer.from([255,0])])];
  for (const changed of variants) assert.notEqual(fingerprint([base]), fingerprint([changed]));
  assert.notEqual(fingerprint([base]),fingerprint([base,base]));
  const backing = Uint8Array.of(9,1,2,8);
  assert.equal(fingerprint([stmt([backing.subarray(1,3)])]),referenceFingerprint([stmt([Buffer.from([1,2])])]));
});

test('finite values and valid text agree with independent encoding over a generated corpus', () => {
  let seed = 0x12345678;
  const random = () => (seed = (Math.imul(seed,1664525)+1013904223)>>>0);
  for (let i=0;i<256;++i) {
    const values=[BigInt(random())-2147483648n,random()/17-100,`x\ufeff😀${i}\0`,
      Buffer.from([random()&255,random()&255]),null];
    const input=[stmt(values,`SELECT ?1 /*${i}*/`)];
    assert.equal(fingerprint(input),referenceFingerprint(input));
    for(const value of values) {
      const encoded=one(value); validateResult(encoded,SMALL);
      assert.deepEqual(decodeResult(encoded,SMALL).statements[0].rows[0][0],value);
    }
  }
});

test('rejects unsupported values, lossy Unicode, invalid SQL and signed integer overflow', () => {
  for (const value of [NaN,Infinity,-Infinity,1n<<63n, -(1n<<63n)-1n, true, false, {}, [], undefined,
                       '\ud800','\udfff', new DataView(new ArrayBuffer(4)),new Uint8Array(new SharedArrayBuffer(4))]) {
    fail(()=>fingerprint([stmt([value])]),'INVALID');
  }
  for (const statements of [null,{},'sql',42]) fail(()=>fingerprint(statements),'INVALID');
  fail(()=>fingerprint([]),'LIMIT');
  for (const statement of [null,42,{}, {sql:1,parameters:[]},stmt([],''),stmt([],'select\0 1'),
                           {sql:'select 1'}, {sql:'select 1',parameters:null},stmt([],'\ud800')]) {
    fail(()=>fingerprint([statement]),'INVALID');
  }
  assert.equal(fingerprint([stmt([null,'',new Uint8Array()])]),referenceFingerprint([stmt([null,'',Buffer.alloc(0)])]));
});

test('all limit keys are positive bounded integers and immutable defaults stay unchanged', () => {
  assert.equal(Object.isFrozen(FORMAT_LIMITS),true);
  for (const value of [null,1,[],true]) {
    fail(()=>fingerprint([stmt()],value),'INVALID');
    fail(()=>decodeResult(empty,value),'INVALID');
  }
  fail(()=>fingerprint([stmt()],{unexpected:1}),'INVALID');
  for (const key of Object.keys(FORMAT_LIMITS)) {
    for (const value of [0,-1,NaN,1.5,'1',undefined]) fail(()=>fingerprint([stmt()],{[key]:value}),'INVALID');
    fail(()=>fingerprint([stmt()],{[key]:FORMAT_LIMITS[key]+1}),'LIMIT');
  }
  fail(()=>fingerprint([stmt()],{maxResultBytes:11}),'INVALID');
  fail(()=>decodeResult(empty,{},null),'INVALID');
  fail(()=>decodeResult(empty,{}, {maxRows:0}),'INVALID');
  fail(()=>decodeResult(empty,{}, {maxValues:0x100000000}),'LIMIT');
  assert.deepEqual(decodeResult(empty,{}, {maxValues:0xffffffff}),{statements:[]});
});

test('request limits count UTF-8 and complete wire encoding, including empty values', () => {
  fail(()=>fingerprint([stmt(),stmt()],{maxStatements:1}),'LIMIT');
  fail(()=>fingerprint([stmt([1n,2n])],{maxParameters:1}),'LIMIT');
  fail(()=>fingerprint([stmt([],'文')],{maxSqlBytes:2}),'LIMIT');
  assert.equal(fingerprint([stmt([],'文')],{maxSqlBytes:3}),referenceFingerprint([stmt([],'文')]));
  fail(()=>fingerprint([stmt([],'a'),stmt([],'a')],{maxSqlBytes:1}),'LIMIT');
  fail(()=>fingerprint([stmt(['文'])],{maxValueBytes:2}),'LIMIT');
  fail(()=>fingerprint([stmt([Buffer.alloc(3)])],{maxValueBytes:2}),'LIMIT');
  for(const size of [1,8,11,12,19,20]) fail(()=>fingerprint([stmt([],'a')],{maxInputBytes:size}),'LIMIT');
  assert.equal(fingerprint([stmt([],'a')],{maxInputBytes:21}),referenceFingerprint([stmt([],'a')]));
  fail(()=>fingerprint([stmt([null],'a')],{maxInputBytes:21}),'LIMIT');
  fail(()=>fingerprint([stmt([''],'a')],{maxInputBytes:25}),'LIMIT');
  assert.equal(fingerprint([stmt([''],'a')],{maxInputBytes:26}),referenceFingerprint([stmt([''],'a')]));
});

test('all result truncations and extra trailing bytes fail, including each typed payload', () => {
  for(const value of [null,1n,2.5,'文',Buffer.from([1,2,3])]) {
    const bytes=one(value);
    for(let end=0;end<bytes.length;++end) {
      fail(()=>decodeResult(bytes.subarray(0,end),SMALL),'MALFORMED');
      fail(()=>validateResult(bytes.subarray(0,end),SMALL),'MALFORMED');
    }
    fail(()=>validateResult(Buffer.concat([bytes,Buffer.from([0])])),'MALFORMED');
    fail(()=>decodeResult(Buffer.concat([bytes,empty])),'MALFORMED');
  }
});

test('wrong frame version, tags, UTF-8 and nonfinite results are rejected', () => {
  const changed=Buffer.from(golden);changed[0]^=1;
  fail(()=>validateResult(changed),'MALFORMED');
  for(const tag of [5,99,255]) {const bytes=Buffer.from(golden);bytes[25]=tag;fail(()=>decodeResult(bytes),'MALFORMED');}
  for(const real of [NaN,Infinity,-Infinity]) {fail(()=>validateResult(one(real)),'INVALID');fail(()=>decodeResult(one(real)),'INVALID');}
  const column=Buffer.from(golden);column[20]=255;
  fail(()=>validateResult(column),'MALFORMED');
  const text=one('x');text[30]=255;fail(()=>decodeResult(text),'MALFORMED');
  validateResult(one(Buffer.from([255])));
  for(const bad of [null,{},'wire',new DataView(new ArrayBuffer(4)),new Uint8Array(new SharedArrayBuffer(20))]) {
    fail(()=>decodeResult(bad),'INVALID');
  }
});

test('wire count, value, aggregate row and exact byte budgets are enforced', () => {
  const bytes=one('文');
  fail(()=>validateResult(bytes,{maxResultBytes:bytes.length-1}),'LIMIT');
  validateResult(bytes,{maxResultBytes:bytes.length});
  fail(()=>decodeResult(bytes,{maxValueBytes:2}),'LIMIT');
  const repeated=result(Array.from({length:2},()=>({columns:['a','b'],rows:[[null,null]],affectedRows:0n,lastInsertRowid:0n})));
  fail(()=>validateResult(repeated,{maxStatements:1}),'LIMIT');
  fail(()=>decodeResult(repeated,{maxColumns:1}),'LIMIT');
  fail(()=>validateResult(repeated,{maxRows:1}),'LIMIT');
  const zeroWidth=Buffer.concat([Buffer.from('SCAPRES1'),le(1,4),le(0,4),le(1,4),Buffer.alloc(16)]);
  fail(()=>validateResult(zeroWidth),'MALFORMED');
  const noRows=result([{columns:['x'],rows:[],affectedRows:0n,lastInsertRowid:0n}]);
  assert.deepEqual(decodeResult(noRows).statements[0].rows,[]);validateResult(noRows);
});

test('materialization has a separate explicit client budget, not a commit verdict', () => {
  const encoded=result([{columns:['a','b'],rows:[[null,null],[null,null]],affectedRows:0n,lastInsertRowid:0n}]);
  validateResult(encoded);
  fail(()=>decodeResult(encoded,{}, {maxRows:1}),'LIMIT');
  fail(()=>decodeResult(encoded,{}, {maxValues:3}),'LIMIT');
  assert.equal(decodeResult(encoded,{}, {maxRows:2,maxValues:4}).statements[0].rows.length,2);
  const two=result(Array.from({length:2},()=>({columns:['x'],rows:[[null]],affectedRows:0n,lastInsertRowid:0n})));
  fail(()=>decodeResult(two,{}, {maxRows:1}),'LIMIT');
  fail(()=>decodeResult(two,{}, {maxValues:1}),'LIMIT');
  fail(()=>decodeResult(two,{}, {maxColumns:1}),'LIMIT');
  const columnOnly=result(Array.from({length:2},()=>({columns:['',''],rows:[],affectedRows:0n,lastInsertRowid:0n})));
  validateResult(columnOnly);
  fail(()=>decodeResult(columnOnly,{}, {maxColumns:3}),'LIMIT');
  assert.equal(decodeResult(columnOnly,{}, {maxColumns:4}).statements.length,2);
});

test('huge untrusted counts cannot force preallocation or zero-width loops', () => {
  const statements=Buffer.concat([Buffer.from('SCAPRES1'),le(0xffffffff,4)]);
  fail(()=>validateResult(statements),'LIMIT');
  const columns=Buffer.concat([Buffer.from('SCAPRES1'),le(1,4),le(0xffffffff,4)]);
  fail(()=>validateResult(columns),'LIMIT');
  const rows=Buffer.from(golden);rows.writeUInt32LE(0xffffffff,21);
  fail(()=>decodeResult(rows),'LIMIT');fail(()=>validateResult(rows),'MALFORMED');
  const value=one('x');value.writeUInt32LE(0xffffffff,26);
  fail(()=>validateResult(value),'LIMIT');
});

test('every single-byte mutation is rejected or round-trips exactly without input mutation', () => {
  const encoded=result([{columns:['n','i','r','t','b'],
    rows:[[null,-(1n<<63n),-0,'\ufeff文\0',Buffer.from([0,255])]],
    affectedRows:(1n<<64n)-1n,lastInsertRowid:-(1n<<63n)}]);
  function classification(fn) {
    try {return {value:fn(),code:'OK'};} catch(error) {
      assert.ok(error instanceof CodecError);
      return {code:error.code};
    }
  }
  for(let position=0;position<encoded.length;++position) {
    for(let byte=0;byte<256;++byte) {
      const changed=Buffer.from(encoded);changed[position]=byte;
      const before=Buffer.from(changed);
      const scan=classification(()=>validateResult(changed,SMALL));
      const graph=classification(()=>decodeResult(changed,SMALL));
      assert.equal(graph.code,scan.code);
      if(graph.code==='OK') assert.deepEqual(result(graph.value.statements),changed);
      assert.deepEqual(changed,before);
    }
  }
});
