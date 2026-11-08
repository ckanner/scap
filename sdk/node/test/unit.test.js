import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { inspect } from 'node:util';
import { performance } from 'node:perf_hooks';
import { Client, ClientError, RemoteError, UnknownError, CommittedResultError,
  decodeResult, validateResult } from '../src/client.js';
import { Transport, duration } from '../src/transport.js';
import * as wire from '../src/wire.js';
// One test process owns every production profile; no integration maps are merged.
import './catalogue.test.js';
import './discovery.test.js';

const SCOPE = { deployment: '1', tenant: '2', database: '9007199254740993', incarnation: '4', generation: '5' };
const TOKEN = 'synthetic-unit-only-bearer-credential';
const PRINCIPAL = '17';
const OPTIONS = { endpoint: 'http://127.0.0.1:8123/v1', token: TOKEN, scope: SCOPE, principal: PRINCIPAL };
const IDS = { epoch: '3', id: '9007199254740995' };
const SQL = [{ sql: 'SELECT ?1', parameters: [42n] }];
const U64 = (1n << 64n) - 1n;
const EMPTY = Buffer.from('534341505245533100000000', 'hex');
const clone = (value) => JSON.parse(JSON.stringify(value));
const invalid = (fn) => assert.throws(fn, (e) => e instanceof ClientError && e.code === 'INVALID');
const rejectCode = (promise, code) => assert.rejects(promise, (e) => e.code === code);
const success = (value, status = 200, headers = {}) => new Response(JSON.stringify({ ok: true, value }),
  { status, headers: { 'content-type': 'application/json', ...headers } });
const failure = (code, status, extra = {}) => new Response(JSON.stringify({ ok: false, error: { code, message: code, ...extra } }),
  { status, headers: { 'content-type': 'application/json' } });
const client = (fetcher, extra = {}) => new Client({ ...OPTIONS, fetch: fetcher, ...extra });
const tracked = (c) => c.prepare(SQL, IDS);

// Independent test-only result encoder. It is never imported by production.
function numeric(value, bytes, signed = false) {
  const array = new Uint8Array(bytes), view = new DataView(array.buffer);
  if (bytes === 4) view.setUint32(0, value, true);
  else if (signed) view.setBigInt64(0, value, true);
  else view.setBigUint64(0, value, true);
  return Buffer.from(array);
}
function typed(value) {
  if (value === null) return [Buffer.from([0])];
  if (typeof value === 'bigint') return [Buffer.from([1]), numeric(value, 8, true)];
  if (typeof value === 'number') {
    const array = new Uint8Array(8); new DataView(array.buffer).setFloat64(0, value, true);
    return [Buffer.from([2]), Buffer.from(array)];
  }
  const bytes = Buffer.from(value);
  return [Buffer.from([typeof value === 'string' ? 3 : 4]), numeric(bytes.length, 4), bytes];
}
function result(values = [42n]) {
  const fields = values.map((_, i) => `c${i}`);
  const parts = [Buffer.from('SCAPRES1'), numeric(1, 4), numeric(fields.length, 4)];
  for (const field of fields) { const bytes = Buffer.from(field); parts.push(numeric(bytes.length, 4), bytes); }
  parts.push(numeric(1, 4));
  for (const value of values) parts.push(...typed(value));
  parts.push(numeric(U64, 8), numeric(-(1n << 63n), 8, true));
  return Buffer.concat(parts);
}
// Struct traversal, instead of the production string template. BigInt leaves
// become exact JSON numeric tokens, including identities beyond 2^53.
function jsonIntegers(value) {
  if (typeof value === 'bigint') return String(value);
  if (Array.isArray(value)) return `[${value.map(jsonIntegers).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.entries(value).map(([key, child]) => `${JSON.stringify(key)}:${jsonIntegers(child)}`).join(',')}}`;
  }
  return JSON.stringify(value);
}
function objectBytes(receipt, raw) {
  const request = receipt.request, transition = receipt.transition;
  const metadata = Buffer.from(jsonIntegers({ format: 2,
    scope: Object.fromEntries(Object.entries(receipt.scope).map(([key, value]) => [key, BigInt(value)])),
    payload: { kind: 'result', value: {
      request: { epoch: BigInt(request.epoch), id: BigInt(request.id), principal: BigInt(request.principal), fingerprint: request.fingerprint },
      sequence: BigInt(receipt.sequence), transition: { revision: BigInt(transition.revision), nonce: BigInt(transition.nonce) },
      data_root: receipt.data_root, bytes: [],
    } },
  }));
  return Buffer.concat([Buffer.from('SCAPOBJ2'), numeric(metadata.length, 4), numeric(BigInt(raw.length), 8), metadata, raw]);
}
function commit(request, raw = result()) {
  const receipt = { scope: clone(request.scope), request: clone(request.request), sequence: '9007199254740997',
    transition: { revision: '9007199254740999', nonce: request.request.id }, data_root: 'a'.repeat(64), result_hash: '' };
  receipt.result_hash = createHash('sha256').update(objectBytes(receipt, raw)).digest('hex');
  return { state: 'committed', receipt, result: raw.toString('base64') };
}
function statusValue(action = {}) {
  const revision = action.operation === 'create' ? '1' : String(BigInt(action.expected_revision ?? '10') + 1n);
  return { scope: clone(SCOPE), revision, sequence: '0', owner_epoch: '2', owner_instance: '3', active: true,
    auth_epoch: '4', lifecycle: 'ready', request_epoch: '3', max_bytes: '10737418240',
    transition: { revision, nonce: action.nonce ?? '9' },
    retention: { max_entries: 4096, max_result_bytes: '268435456', oldest_epoch: '1' } };
}

test('plain records reject accessors, symbol fields, foreign prototypes and absent keys', () => {
  assert.deepEqual(wire.record({}, []), {});
  const plain = Object.create(null); plain.a = 1; assert.equal(wire.record(plain, ['a']), plain);
  assert.deepEqual(wire.record({ a: 1, b: 2 }, ['a'], ['b']), { a: 1, b: 2 });
  for (const value of [null, undefined, 1, 'x', true, [], new Date()]) invalid(() => wire.record(value, []));
  invalid(() => wire.record({}, ['missing']));
  invalid(() => wire.record({ a: 1 }, []));
  invalid(() => wire.record({ [Symbol('secret')]: 1 }, []));
  let accessed = false;
  invalid(() => wire.record({ get a() { accessed = true; return 1; } }, ['a']));
  assert.equal(accessed, false);
});

test('identities retain canonical full-width unsigned integers', () => {
  for (const value of ['1', '9007199254740993', String(U64)]) assert.equal(wire.decimal(value), value);
  assert.equal(wire.decimal('0', true), '0');
  for (const value of [0, 1n, null, '', '0', '01', '+1', '-1', '1e1', '1.0', String(U64 + 1n), '0x1', '1 '.trimEnd() + ' ']) {
    invalid(() => wire.decimal(value));
  }
  const fixed = wire.scope(SCOPE); assert.deepEqual(fixed, SCOPE); assert.equal(Object.isFrozen(fixed), true);
  wire.sameScope(fixed, SCOPE);
  for (const key of Object.keys(SCOPE)) invalid(() => wire.sameScope({ ...SCOPE, [key]: '9' }, SCOPE));
  assert.deepEqual(wire.transition({ revision: '2', nonce: '3' }), { revision: '2', nonce: '3' });
  invalid(() => wire.transition({ revision: '0', nonce: '3' }));
  invalid(() => wire.transition({ revision: '2', nonce: '3', extra: true }));
});

test('prepared SQL owns mutable values and preserves every typed value, including negative zero', () => {
  const c = new Client(OPTIONS), blob = Buffer.from([0, 255, 42]);
  const input = [{ sql: 'SELECT ?1', parameters: [null, -1n, U64 >> 1n, -0, 0, '\ufeff文\0😀', blob] }];
  const t = c.prepare(input, IDS), serialized = c.save(t);
  blob.fill(9); input[0].sql = 'DROP TABLE x'; input[0].parameters.push('changed'); input.push(SQL[0]);
  assert.equal(c.save(t), serialized);
  assert.deepEqual(c.restore(serialized), t);
  assert.equal(c.principal, PRINCIPAL); assert.deepEqual(c.scope, SCOPE);
  assert.equal(t.statements[0].params[3].bits, '8000000000000000');
  assert.equal(t.statements[0].params[4].bits, '0000000000000000');
  assert.equal(t.statements[0].params[6].base64, 'AP8q');
  for (const value of [t, t.request, t.scope, t.statements, t.statements[0], t.statements[0].params, ...t.statements[0].params]) {
    assert.equal(Object.isFrozen(value), true);
  }
  assert.throws(() => { t.scope.tenant = '9'; }, TypeError);
  const subarray = new Uint8Array([9, 1, 2, 9]).subarray(1, 3);
  assert.equal(c.prepare([{sql:'SELECT ?1',parameters:[subarray]}], IDS).statements[0].params[0].base64, 'AQI=');
});

test('invalid statement and saved-request inputs are rejected before any network call', () => {
  const c = client(() => assert.fail('unexpected fetch'));
  for (const value of [null, {}, 'sql']) invalid(() => c.prepare(value, IDS));
  invalid(() => c.prepare([{ sql: 'SELECT 1', parameters: null }], IDS));
  invalid(() => c.prepare(SQL, { ...IDS, principal: '99' }));
  for (const value of [true, {}, [], new DataView(new ArrayBuffer(3)), new Uint8Array(new SharedArrayBuffer(3))]) {
    invalid(() => c.prepare([{ sql: 'SELECT ?1', parameters: [value] }], IDS));
  }
  for (const value of [NaN, Infinity, -(1n<<63n)-1n, 1n<<63n, '\ud800']) {
    assert.throws(() => c.prepare([{sql:'SELECT ?1',parameters:[value]}], IDS));
  }
  const t = tracked(c);
  invalid(() => c.save(clone(t)));
  invalid(() => c.save(client(()=>{} ,{ principal: '18' }).prepare(SQL, IDS)));
  invalid(() => c.save(client(()=>{}, {scope:{...SCOPE,tenant:'9'}}).prepare(SQL, IDS)));
  invalid(() => c.restore(null));
  invalid(() => c.restore(' '.repeat(96*1024*1024+1)));
  for (const value of ['{', '{"bad', '[]', '{"scope":1,"scope":2}']) invalid(() => c.restore(value));
  const saved = clone(t);
  for (const key of ['epoch','id','principal','fingerprint']) {
    const bad = clone(saved); bad.request[key] = key === 'fingerprint' ? 'A'.repeat(64) : '0';
    invalid(() => c.restore(JSON.stringify(bad)));
  }
  const wrongHash=clone(saved); wrongHash.request.fingerprint='b'.repeat(64);
  invalid(()=>c.restore(JSON.stringify(wrongHash)));
  const wrongPrincipal=clone(saved); wrongPrincipal.request.principal='18';
  invalid(()=>c.restore(JSON.stringify(wrongPrincipal)));
  const wrongScope=clone(saved); wrongScope.scope.database='8';
  invalid(()=>c.restore(JSON.stringify(wrongScope)));
  for(const value of [null,{},'x']) {
    const bad=clone(saved);bad.statements=value;invalid(()=>c.restore(JSON.stringify(bad)));
    const nested=clone(saved);nested.statements[0].params=value;invalid(()=>c.restore(JSON.stringify(nested)));
  }
});

test('saved wire parameters reject lossy, ambiguous and surplus representations', () => {
  const c=new Client(OPTIONS), template=clone(tracked(c));
  const badParameters=[{type:'new'}, {type:'null',value:0}, {type:'integer',value:42},
    ...['-0','00','+1','1.0',String(1n<<63n),String(-(1n<<63n)-1n)].map(value=>({type:'integer',value})),
    {type:'real',bits:'0'}, {type:'real',bits:'7ff0000000000000'}, {type:'real',bits:'7FF0000000000000'},
    {type:'text',value:3}, {type:'text',value:'\ud800'}, {type:'blob',base64:'YQ'}, {type:'blob',base64:'YQ==\n'}];
  for(const parameter of badParameters) {
    const saved=clone(template);saved.statements[0].params=[parameter];
    assert.throws(()=>c.restore(JSON.stringify(saved)));
  }
  assert.equal(wire.base64('YQ==',1).toString(),'a');
  assert.deepEqual(wire.base64(''),Buffer.alloc(0));
  invalid(()=>wire.base64('YWJj',1));
  invalid(()=>wire.base64('YWJjZA==',1));
  invalid(()=>wire.base64(null));
});

test('strict JSON preserves normal strings but rejects duplicate escaped keys and deep graphs', () => {
  for(const value of ['root',[1,2,{ a:'escaped " \\ \n',b:'x' }],{ a:[1,{b:'2'}],c:null },true,2]) {
    assert.deepEqual(wire.parseJson(JSON.stringify(value)),value);
  }
  assert.deepEqual(wire.parseJson(' ["text", null, {"a":1}] '),['text',null,{a:1}]);
  for(const text of ['{"a":1,"a":2}', '{"a":1,"\\u0061":2}', '{"x":{"k":1,"k":2}}',
    '['.repeat(33)+'0'+']'.repeat(33), JSON.stringify(Object.fromEntries(Array.from({length:129},(_,i)=>['k'+i,i]))),
    '{"a', '{"a\\', ']', '{]', '{"a":"truncated', '{"a":1,}', 'undefined']) invalid(()=>wire.parseJson(text));
  assert.equal(wire.parseJson('['.repeat(32)+'0'+']'.repeat(32))[0][0][0][0] instanceof Array,true);
});

test('status validates the current identity and retains the declared retention boundary', () => {
  const value=statusValue();assert.deepEqual(wire.status(value,SCOPE),value);
  assert.equal(Object.isFrozen(wire.status(value,SCOPE).retention),true);
  const mutate=(fn)=>{const bad=clone(value);fn(bad);invalid(()=>wire.status(bad,SCOPE));};
  mutate(x=>x.scope.tenant='8'); mutate(x=>x.active=1); mutate(x=>x.lifecycle='old');
  mutate(x=>x.sequence='-1'); mutate(x=>x.transition.revision='4');
  for(const key of ['revision','owner_epoch','owner_instance','auth_epoch','request_epoch']) mutate(x=>x[key]='0');
  for(const count of [0,-1,1.5,'1',65537]) mutate(x=>x.retention.max_entries=count);
  mutate(x=>x.retention.max_result_bytes='0');mutate(x=>x.retention.oldest_epoch='0');
  mutate(x=>x.retention.oldest_epoch='4');mutate(x=>delete x.retention.max_entries);
  mutate(x=>x.max_bytes='1');mutate(x=>x.extra=true);
  const unbounded={...value,max_bytes:null}; assert.equal(wire.status(unbounded,SCOPE).max_bytes,null);
  for(const state of ['ready','maintenance','deleted']) assert.equal(wire.lifecycle(state),state);
  invalid(()=>wire.lifecycle('Ready'));
});

test('quota and policies enforce the durable page and administrator constraints', () => {
  assert.equal(wire.quota(null),null);assert.equal(wire.quota('4096'),'4096');
  assert.equal(wire.quota(String(4294967294n*4096n)),String(4294967294n*4096n));
  for(const value of ['0','1','4097',String(4294967295n*4096n),undefined]) invalid(()=>wire.quota(value));
  const permissions=[{principal:'1',read:true,write:true,admin:true},{principal:'2',read:true,write:false,admin:false}];
  assert.deepEqual(wire.permissions(permissions),permissions);
  assert.equal(Object.isFrozen(wire.permissions(permissions)[0]),true);
  for(const value of [null,{},[],Array(1025).fill(permissions[0]),[permissions[0],permissions[0]],
    [{...permissions[0],principal:'0'}],[{...permissions[0],read:1}],[{...permissions[0],admin:false}],
    [{...permissions[0],unknown:1}]]) invalid(()=>wire.permissions(value));
});

test('receipt fields and whole-object digest bind raw results without lossy identity conversions', () => {
  const c=new Client(OPTIONS),t=tracked(c),raw=result([null,-(1n<<63n),(1n<<63n)-1n,-0,'\ufeff文\0😀',Buffer.from([0,255])]);
  const value=commit(t,raw), receipt=wire.receipt(value.receipt,SCOPE,t.request);
  assert.equal(wire.resultHash(receipt,raw),createHash('sha256').update(objectBytes(receipt,raw)).digest('hex'));
  assert.notEqual(receipt.result_hash,createHash('sha256').update(raw).digest('hex'));
  assert.equal(Object.isFrozen(receipt),true);
  const decoded=wire.committed(value,SCOPE,t.request,{},{});
  assert.deepEqual(decoded.rawResult,raw);assert.deepEqual(decoded.receipt,value.receipt);
  assert.equal(decoded.result.statements[0].affectedRows,U64);
  assert.equal(decoded.result.statements[0].lastInsertRowid,-(1n<<63n));
  assert.equal(Object.is(decoded.result.statements[0].rows[0][3],-0),true);
  assert.equal(decoded.result.statements[0].rows[0][4],'\ufeff文\0😀');
  assert.deepEqual(decoded.result.statements[0].rows[0][5],Buffer.from([0,255]));
  assert.equal(validateResult(raw),undefined);assert.deepEqual(decodeResult(raw),decoded.result);
  for(const key of Object.keys(t.request)) {
    const bad=clone(value.receipt);bad.request[key]=key==='fingerprint'?'b'.repeat(64):'6';
    invalid(()=>wire.receipt(bad,SCOPE,t.request));
  }
  for(const update of [x=>x.transition.nonce='9',x=>x.scope.tenant='9',x=>x.sequence='0',
    x=>x.data_root='?',x=>x.result_hash='?',x=>x.other=0]) {
    const bad=clone(value.receipt);update(bad);invalid(()=>wire.receipt(bad,SCOPE,t.request));
  }
  const altered=clone(value);altered.result=EMPTY.toString('base64');
  invalid(()=>wire.committed(altered,SCOPE,t.request,{},{}));
  invalid(()=>wire.committed({...value,state:'cancelled'},SCOPE,t.request,{},{}));
});

test('committed materialization failures retain the original receipt and verified bytes', () => {
  const c=new Client(OPTIONS),t=tracked(c),value=commit(t,result([1n,2n]));
  for(const [limits,allocation] of [[{}, {maxValues:1}],[{maxResultBytes:12},{}],[{maxColumns:1},{}]]) {
    assert.throws(()=>wire.committed(value,SCOPE,t.request,limits,allocation),e=>e instanceof CommittedResultError&&
      e.outcome==='committed'&&e.code==='LIMIT'&&e.receipt.result_hash===value.receipt.result_hash&&e.rawResult.equals(Buffer.from(value.result,'base64')));
  }
  const invalidResult=commit(t,Buffer.from('not a SCAP result'));
  assert.throws(()=>wire.committed(invalidResult,SCOPE,t.request,{},{}),e=>e instanceof CommittedResultError&&e.code==='MALFORMED');
});

test('lookup distinguishes committed, cancelled, unknown, closed and retired without retry decisions', () => {
  const c=new Client(OPTIONS),t=tracked(c),value=commit(t);
  assert.equal(wire.resolved(value,SCOPE,t.request,{},{}).state,'committed');
  const cancelled={state:'cancelled',transition:{revision:'7',nonce:t.request.id}};
  assert.deepEqual(wire.resolved(cancelled,SCOPE,t.request,{},{}),cancelled);
  for(const state of ['unknown','closed','retired']) assert.deepEqual(wire.resolved({state},SCOPE,t.request,{},{}),{state});
  for(const bad of [{state:'cancelled',transition:{revision:'7',nonce:'8'}},{state:'cancelled'},
    {state:'unknown',receipt:value.receipt},{state:'other'}, {state:'closed',extra:true}]) {
    invalid(()=>wire.resolved(bad,SCOPE,t.request,{},{}));
  }
});

test('strict HTTP envelopes reject status/body contradictions and sanitize remote messages', () => {
  const t=tracked(new Client(OPTIONS)),reference={scope:SCOPE,request:t.request};
  assert.deepEqual(wire.envelope({ok:true,value:{x:1}},200,reference),{x:1});
  const statuses={UNAUTHENTICATED:401,DENIED:403,INVALID:400,VERSION:400,LIMIT:413,BACKPRESSURE:429,RECOVERY_BUSY:429,
    UNAVAILABLE:503,DEADLINE:503,COMMITTED_BUT_UNAVAILABLE:503,LIFECYCLE:409,FENCED:409,CONFLICT:409,REQUEST_CONFLICT:409,
    WINDOW_FULL:409,CLOSED:409,RETIRED:409,MISSING:409,CORRUPT:409,STALE_SNAPSHOT:409,ENGINE:409,CONFIG:409,CACHE_IO:409};
  for(const [code,status] of Object.entries(statuses)) {
    assert.throws(()=>wire.envelope({ok:false,error:{code,message:TOKEN}},status,reference),e=>{
      assert.ok(e instanceof RemoteError);assert.equal(e.code,code);assert.equal(e.outcome,'unresolved');
      assert.equal(e.reference,reference);assert.ok(!inspect(e).includes(TOKEN));return true;
    });
  }
  assert.throws(()=>wire.envelope({ok:false,error:{code:'UNKNOWN',message:'UNKNOWN'}},503,reference),UnknownError);
  const receipt=commit(t).receipt;
  assert.throws(()=>wire.envelope({ok:false,error:{code:'COMMITTED_BUT_UNAVAILABLE',message:'x',receipt}},503,reference),e=>
    e instanceof CommittedResultError&&e.outcome==='committed'&&e.rawResult===undefined);
  for(const [body,status] of [[{ok:true,value:{}},201],[{ok:true,value:{}},503],[{ok:1,value:{}},200],
    [{ok:true,value:{},error:{}},200],[{ok:false,error:{code:'DENIED',message:'x'}},500],
    [{ok:false,error:{code:'FUTURE',message:'x'}},409],[{ok:false,error:{code:'DENIED',message:2}},403],
    [{ok:false,error:{code:'DENIED',message:'x'.repeat(1025)}},403],
    [{ok:false,error:{code:'DENIED',message:'x',receipt}},403]]) invalid(()=>wire.envelope(body,status,reference));
  invalid(()=>wire.envelope({ok:false,error:{code:'COMMITTED_BUT_UNAVAILABLE',message:'x',receipt}},503,{scope:SCOPE}));
});

test('constructor validates endpoints, secrets, budgets and trusted transport inputs', () => {
  const c=new Client(OPTIONS);assert.ok(!inspect(c).includes(TOKEN));
  for(const url of ['https://example.com/v1','http://localhost/v1','http://[::1]/v1']) new Client({...OPTIONS,endpoint:url});
  new Client({...OPTIONS,endpoint:'http://example.com/v1',allowInsecureHttp:true});
  for(const endpoint of [null,'bad','ftp://example.com/v1','http://example.com/v1','https://u:p@example.com/v1',
    'https://example.com/v1?key=x','https://example.com/v1#x','https://example.com/']) invalid(()=>new Client({...OPTIONS,endpoint}));
  for(const token of [null,'short','a'.repeat(1025),' '.repeat(32),'a'.repeat(31)+'\n','a'.repeat(31)+'中']) invalid(()=>new Client({...OPTIONS,token}));
  for(const extra of [{allowInsecureHttp:1},{fetch:null},{timeoutMs:0},{recoveryTimeoutMs:0},{maxRequestBytes:0},{maxResponseBytes:0},
    {maxRequestBytes:96*1024*1024+1},{maxResponseBytes:1.5},{unknown:1}]) invalid(()=>new Client({...OPTIONS,...extra}));
  for(const value of [0,-1,1.5,'1',2147483648]) invalid(()=>duration(value));
  assert.equal(duration(1),1);assert.equal(duration(2147483647),2147483647);
  new Client({...OPTIONS,resultLimits:{maxResultBytes:12},allocation:{maxRows:1,maxColumns:1,maxValues:1},fetch:()=>{}});
  for(const extra of [{resultLimits:null},{allocation:null},{resultLimits:{unknown:1}},{allocation:{unknown:1}},
    {resultLimits:{maxResultBytes:11}},{allocation:{maxRows:0}}]) assert.throws(()=>new Client({...OPTIONS,...extra}));
});

test('all client operations send exact typed v1 calls and admission classes exactly once', async () => {
  const requests=[];
  const c=client(async (url,init)=>{
    const body=JSON.parse(init.body);requests.push({url,init,body});
    assert.equal(body.version,1);assert.deepEqual(body.scope,SCOPE);
    assert.equal(init.method,'POST');assert.equal(init.redirect,'error');assert.equal(init.cache,'no-store');
    assert.equal(init.credentials,'omit');assert.equal(init.headers.authorization,`Bearer ${TOKEN}`);
    if(body.operation==='query') return success({result:result([-0,1n]).toString('base64')});
    if(body.operation==='execute') return success(commit(t));
    if(body.operation==='lookup') return success({state:'unknown'});
    if(body.operation==='cancel') return success({state:'cancelled',transition:{revision:'99',nonce:t.request.id}});
    return success(statusValue(body),200,{'content-type':'Application/JSON; charset=utf-8'});
  });
  const t=tracked(c);
  assert.equal((await c.create({nonce:'7'})).revision,'1');
  assert.equal((await c.status()).request_epoch,'3');
  assert.equal((await c.open({timeoutMs:1000})).scope.database,SCOPE.database);
  const query=await c.query([{sql:'SELECT ?1, ?2',parameters:[-0,1n]}]);
  assert.equal(Object.is(query.statements[0].rows[0][0],-0),true);
  assert.equal((await c.execute(t)).state,'committed');
  assert.equal((await c.lookup(t)).state,'unknown');assert.equal((await c.cancel(t)).state,'cancelled');
  for(const method of ['activate','takeover','closeFull']) await c[method]({expectedRevision:'10',nonce:'8'});
  await c.setQuota({expectedRevision:'10',nonce:'8',maxBytes:null});
  const permissions=[{principal:PRINCIPAL,read:true,write:true,admin:true}];
  await c.setPolicy({expectedRevision:'10',nonce:'8',permissions});
  await c.setLifecycle({expectedRevision:'10',nonce:'8',lifecycle:'maintenance'});
  assert.deepEqual(requests.map(x=>x.body.operation),['create','status','open','query','execute','lookup','cancel',
    'activate','takeover','close_full','quota','policy','lifecycle']);
  for(const {body,init} of requests) {
    const expected=['open','activate'].includes(body.operation)?'recovery':['create','query','execute'].includes(body.operation)?'data':'control';
    assert.equal(init.headers['x-scap-admission'],expected);assert.equal(init.signal.aborted,true);
  }
  assert.deepEqual(requests[4].body.request,t.request);assert.deepEqual(requests[4].body.statements,t.statements);
  assert.equal(requests[10].body.max_bytes,null);assert.deepEqual(requests[11].body.permissions,permissions);
});

test('each local identity or administrative preflight failure sends zero requests', async () => {
  let calls=0;const c=client(async()=>{calls++;return success({});});const t=tracked(c);
  for(const method of ['execute','lookup','cancel']) invalid(()=>c[method](clone(t)));
  invalid(()=>c.create({nonce:'0'}));
  for(const method of ['activate','takeover','closeFull']) {
    invalid(()=>c[method]({expectedRevision:'0',nonce:'1'}));
    invalid(()=>c[method]({expectedRevision:'1',nonce:'0'}));
    invalid(()=>c[method]({expectedRevision:'1',nonce:'1',extra:2}));
  }
  invalid(()=>c.setQuota({expectedRevision:'1',nonce:'1'}));
  invalid(()=>c.setPolicy({expectedRevision:'1',nonce:'1',permissions:[]}));
  invalid(()=>c.setLifecycle({expectedRevision:'1',nonce:'1',lifecycle:'bad'}));
  await rejectCode(c.execute(t,{signal:null}),'INVALID');
  await rejectCode(c.execute(t,{timeoutMs:null}),'INVALID');
  await rejectCode(c.execute(t,{unknown:1}),'INVALID');
  const small=client(async()=>{calls++;return success({});},{maxRequestBytes:1});
  await rejectCode(small.execute(tracked(small)),'LIMIT');
  assert.equal(calls,0);
});

test('administrative response must prove the exact requested revision and nonce', async () => {
  for(const change of [x=>x.revision=x.transition.revision='13',x=>x.transition.nonce='99',x=>x.scope.database='99']) {
    const c=client(async()=>{const value=statusValue({expected_revision:'10',nonce:'8'});change(value);return success(value);});
    await assert.rejects(c.activate({expectedRevision:'10',nonce:'8'}),UnknownError);
  }
});

test('successful HTTP status alone cannot turn an invalid receipt or body into an ACK', async () => {
  const alterations=[value=>value.receipt.request.id='9',value=>value.receipt.scope.generation='9',
    value=>value.receipt.result_hash='b'.repeat(64),value=>value.result=EMPTY.toString('base64'),
    value=>value.result='not base64!',value=>value.state='unknown',value=>value.extra=true];
  for(const alter of alterations) {
    let calls=0;const c=client(async()=>{calls++;const value=commit(t);alter(value);return success(value);});const t=tracked(c);
    await assert.rejects(c.execute(t),e=>e instanceof UnknownError&&e.reference.request.id===t.request.id);
    assert.equal(calls,1);
  }
  const c=client(async()=>success({result:EMPTY.toString('base64')},201));
  await assert.rejects(c.query(SQL),ClientError);
});

test('verified commit and server failure errors propagate without retries or loss of identity', async () => {
  let calls=0;
  const c=client(async()=>{calls++;return success(commit(t,result([1n,2n])));},{allocation:{maxValues:1}});const t=tracked(c);
  await assert.rejects(c.execute(t),e=>e instanceof CommittedResultError&&e.rawResult.length>0&&e.code==='LIMIT');
  assert.equal(calls,1);
  for(const [code,status] of [['BACKPRESSURE',429],['CONFLICT',409],['FENCED',409],['UNKNOWN',503]]) {
    const d=client(async()=>{calls++;return failure(code,status);});const request=tracked(d);const before=calls;
    await assert.rejects(d.execute(request),e=>(e instanceof RemoteError||e instanceof UnknownError)&&e.reference.request.id===request.request.id);
    assert.equal(calls,before+1);
  }
  const d=client(async()=>failure('COMMITTED_BUT_UNAVAILABLE',503,{receipt:commit(u).receipt}));const u=tracked(d);
  await assert.rejects(d.execute(u),e=>e instanceof CommittedResultError&&e.receipt.request.id===u.request.id);
  const query=client(async()=>success({result:result([1n,2n]).toString('base64')}),{allocation:{maxValues:1}});
  await rejectCode(query.query(SQL),'LIMIT');
});

test('response intake rejects redirects, missing bodies, bad content types, lengths and UTF-8', async () => {
  const jsonHeaders={'content-type':'application/json'};
  const factories=[()=>({}),()=>new Response('{}'),()=>new Response('{}',{headers:{'content-type':'text/html'}}),
    ()=>{const r=success({});Object.defineProperty(r,'redirected',{value:true});return r;},
    ()=>new Response(null,{headers:jsonHeaders}),
    ...['-1','01','x'].map(length=>()=>new Response('{}',{headers:{...jsonHeaders,'content-length':length}})),
    ()=>new Response(Buffer.from([0xff]),{headers:jsonHeaders}),
    ()=>new Response('{"ok":true,"ok":false}',{headers:jsonHeaders}),
    ()=>new Response('not JSON '+TOKEN,{headers:jsonHeaders}),
    ()=>new Response(new ReadableStream({start(control){control.enqueue('not bytes');control.close();}}),{headers:jsonHeaders})];
  for(const factory of factories) {
    const c=client(factory),t=tracked(c);
    await assert.rejects(c.execute(t),e=>e instanceof UnknownError&&!inspect(e).includes(TOKEN));
  }
  let calls=0;
  const tooBig=client(()=>{calls++;return new Response('{}',{headers:{...jsonHeaders,'content-length':'33'}});},{maxResponseBytes:32});
  await assert.rejects(tooBig.execute(tracked(tooBig)),e=>e instanceof UnknownError&&e.cause.code==='LIMIT');
  const streamed=client(()=>new Response(new ReadableStream({start(control){
    control.enqueue(Buffer.alloc(16));control.enqueue(Buffer.alloc(17));control.close();}}),{headers:jsonHeaders}),{maxResponseBytes:32});
  await assert.rejects(streamed.execute(tracked(streamed)),e=>e instanceof UnknownError&&e.cause.code==='LIMIT');
  const text=JSON.stringify({ok:true,value:{result:EMPTY.toString('base64')}});
  const exact=client(()=>new Response(text,{headers:{...jsonHeaders,'content-length':String(Buffer.byteLength(text))}}),{maxResponseBytes:Buffer.byteLength(text)});
  assert.deepEqual(await exact.query(SQL),{statements:[]});assert.equal(calls,1);
});

test('network failures preserve uncertainty and never expose credentials or SQL in exceptions', async () => {
  for(const fetcher of [()=>{throw new Error(TOKEN);},async()=>{throw new Error(TOKEN);},
    ()=>new Response(new ReadableStream({start(control){control.error(new Error(TOKEN));}}),{headers:{'content-type':'application/json'}})]) {
    const c=client(fetcher),t=c.prepare([{sql:"SELECT 'SQL-SENSITIVE'",parameters:[]}],IDS);
    await assert.rejects(c.execute(t),e=>{assert.ok(e instanceof UnknownError);assert.equal(e.outcome,'unknown');
      assert.equal(e.cause.code,'TRANSPORT');assert.ok(!inspect(e).includes(TOKEN));assert.ok(!inspect(e).includes('SQL-SENSITIVE'));return true;});
    await assert.rejects(c.status(),e=>e instanceof ClientError&&!(e instanceof UnknownError)&&e.code==='TRANSPORT');
  }
});

test('pre-abort sends nothing; in-flight abort keeps request identity and cancels the one HTTP attempt', async () => {
  let calls=0;
  const pre=new AbortController();pre.abort('secret-reason');
  const c=client(async()=>{calls++;return success({});});await rejectCode(c.execute(tracked(c),{signal:pre.signal}),'ABORTED');
  assert.equal(calls,0);
  const abort=new AbortController();let sentSignal;
  const d=client((url,init)=>{calls++;sentSignal=init.signal;queueMicrotask(()=>abort.abort(TOKEN));return new Promise(()=>{});});
  const t=tracked(d);
  await assert.rejects(d.execute(t,{signal:abort.signal}),e=>e instanceof UnknownError&&e.cause.code==='ABORTED'&&e.reference.request.id===t.request.id);
  assert.equal(calls,1);assert.equal(sentSignal.aborted,true);
});

test('the original timeout bounds fetch and stalled body reads, including recovery defaults', async () => {
  let calls=0;
  const c=client(()=>{calls++;return new Promise(()=>{});},{timeoutMs:5,recoveryTimeoutMs:10});
  await assert.rejects(c.execute(tracked(c)),e=>e instanceof UnknownError&&e.cause.code==='DEADLINE');
  await rejectCode(c.status(),'DEADLINE');await rejectCode(c.open(),'DEADLINE');
  assert.equal(calls,3);
  const d=client(()=>new Response(new ReadableStream({start(control){control.enqueue(Buffer.from('{'));}}),
    {headers:{'content-type':'application/json'}}),{timeoutMs:5});
  await assert.rejects(d.execute(tracked(d)),e=>e instanceof UnknownError&&e.cause.code==='DEADLINE');
});

test('synchronous response decoding counts against the same deadline and retains known commits', async () => {
  const t=tracked(new Client(OPTIONS)),receipt=commit(t).receipt;
  const transport=new Transport({endpoint:OPTIONS.endpoint,token:TOKEN,fetch:()=>success({}),timeoutMs:5});
  const slow=(value)=>{const end=performance.now()+15;while(performance.now()<end){};return value;};
  await assert.rejects(transport.call({operation:'execute'},{scope:SCOPE,request:t.request},()=>slow({state:'committed',receipt,rawResult:EMPTY})),
    e=>e instanceof CommittedResultError&&e.code==='DEADLINE'&&e.receipt===receipt);
  await rejectCode(transport.call({operation:'status'},{scope:SCOPE},()=>slow({})),'DEADLINE');
});

test('error classes expose explicit outcome data without making a replay decision', () => {
  const cause=new Error('test'),reference={scope:SCOPE};
  const local=new ClientError('INVALID','invalid',cause);assert.equal(local.cause,cause);assert.equal(local.name,'ClientError');
  const unknown=new UnknownError(reference,cause);assert.equal(unknown.cause,cause);assert.equal(unknown.reference,reference);
  const remote=new RemoteError('CLOSED','closed',reference);assert.equal(remote.name,'RemoteError');
  const committed=new CommittedResultError('LIMIT',{},EMPTY,cause);assert.equal(committed.cause,cause);assert.equal(committed.name,'CommittedResultError');
});
