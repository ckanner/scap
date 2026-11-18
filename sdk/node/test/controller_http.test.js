/** Unit-only lifecycle/fault injection; real sockets are tested separately. */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import http from 'node:http';
import https from 'node:https';
import dns from 'node:dns';
import { performance } from 'node:perf_hooks';
import { ControllerHttp } from '../src/controller_http.js';
import { OwnerController } from '../src/controller.js';
import { ClientError } from '../src/errors.js';
import { policy } from './controller_policy.test.js';
import { head, OPTIONS } from './owner_fixture.js';

const URL = 'http://worker.test/v1';
const SECRET = 'synthetic-controller-secret-never-in-errors';
const code = (expected) => (error) => error instanceof ClientError && error.code === expected &&
  !String(error).includes(SECRET) && error.cause === undefined;
const input = (controller = new AbortController(), extra = {}) => ({ method: 'POST', body: '{}',
  signal: controller.signal, headers: { authorization: 'Bearer ' + SECRET, 'content-type': 'application/json' },
  redirect: 'error', cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer', ...extra });

class Socket extends EventEmitter {
  closed = false;
  destroyed = false;
  destroy() { this.destroyed = true; }
  finish() { if (!this.closed) { this.closed = true; this.emit('close'); } }
}

class Request extends EventEmitter {
  socket = null;
  destroyed = false;
  closed = false;
  body;
  end(body) { this.body = body; }
  destroy() { this.destroyed = true; }
  finish() { if (!this.closed) { this.closed = true; this.emit('close'); } }
}

class Incoming extends EventEmitter {
  constructor(extra) {
    super();
    Object.assign(this, { statusCode: 200, rawHeaders: ['content-type', 'application/json'],
      complete: true, destroyed: false }, extra);
  }
  destroy() { this.destroyed = true; }
}

function fixture(t, options) {
  const calls = [];
  const factory = (url, args, received) => {
    const request = new Request();
    calls.push({ url, args, received, request });
    return request;
  };
  t.mock.method(http, 'request', factory);
  t.mock.method(https, 'request', factory);
  const transport = new ControllerHttp(options);
  const socket = (index = 0) => {
    const value = new Socket(), call = calls[index];
    call.request.socket = value;
    call.request.emit('socket', value);
    return value;
  };
  const receive = (index = 0, extra) => {
    const value = new Incoming(extra);
    calls[index].received(value);
    return value;
  };
  const finish = (index = 0) => {
    calls[index].request.finish();
    calls[index].request.socket?.finish();
  };
  t.after(async () => {
    for (let index = 0; index < calls.length; ++index) finish(index);
    await transport.close();
  });
  return { transport, calls, socket, receive, finish };
}

test('controller HTTP constructor and request validation dispatch no unsupported input', async (t) => {
  for (const value of [null, [], { unknown: 1 }, { maxRequests: 0 }, { maxRequests: 9 },
    { maxRequests: 1.5 }, { maxRequests: '1' }]) assert.throws(() => new ControllerHttp(value), code('INVALID'));
  const io = fixture(t);
  const bad = [null, [], { ...input(), extra: SECRET }, input(undefined, { method: 'GET' }),
    input(undefined, { signal: {} }), input(undefined, { body: null }), input(undefined, { body: new Uint8Array(new SharedArrayBuffer(1)) }),
    input(undefined, { headers: null }), input(undefined, { headers: [] }),
    input(undefined, { headers: { authorization: 'a', Authorization: 'b' } }),
    input(undefined, { headers: { host: 'elsewhere' } }), input(undefined, { headers: { x: 1 } }),
    input(undefined, { headers: { x: 'bad\r\n' + SECRET } }), input(undefined, { headers: { 'bad name': 'x' } }),
    input(undefined, { headers: { [Symbol('not a header')]: 'x' } }),
    input(undefined, { headers: { get x() { throw new Error(SECRET); } } }),
    input(undefined, { headers: Object.fromEntries(Array.from({ length: 61 }, (_, i) => ['x-' + i, 'v'])) })];
  for (const name of ['redirect', 'cache', 'credentials', 'referrerPolicy']) bad.push(input(undefined, { [name]: 'unsupported' }));
  for (const init of bad) await assert.rejects(io.transport.fetch(URL, init), code('INVALID'));
  for (const target of [0, {}, 'broken', 'ftp://worker.test/v1', 'http://user:password@worker.test/v1',
    'http://worker.test/v1?q=x', 'http://worker.test/v1#fragment', 'http://worker.test:0/v1', 'http://w/' + 'x'.repeat(2048)]) {
    await assert.rejects(io.transport.fetch(target, input()), code('INVALID'));
  }
  await assert.rejects(io.transport.fetch(URL, input(undefined, { body: 'x'.repeat(16385) })), code('LIMIT'));
  await assert.rejects(io.transport.fetch(URL, input(undefined, { headers: { x: 'a'.repeat(16384) } })), code('LIMIT'));
  assert.equal(io.calls.length, 0);
  assert.deepEqual(io.transport.snapshot(), { closed: false, active: 0, peak: 0, started: 0, completed: 0 });
});

test('controller HTTP bound fetch sends exact copied bytes and has no agent or family racing', async (t) => {
  const io = fixture(t), controller = new AbortController(), bytes = new Uint8Array([1, 2, 3]);
  const fetch = io.transport.fetch;
  const pending = fetch(new globalThis.URL(URL), input(controller, { body: bytes,
    redirect: undefined, cache: undefined, credentials: undefined, referrerPolicy: undefined }));
  bytes[0] = 255;
  const call = io.calls[0], socket = io.socket();
  assert.deepEqual([...call.request.body], [1, 2, 3]);
  assert.equal(call.args.agent, false); assert.equal(call.args.autoSelectFamily, false);
  assert.equal(call.args.rejectUnauthorized, true); assert.equal(call.args.maxHeaderSize, 16384);
  assert.equal(call.request.maxHeadersCount, 65);
  assert.equal(call.args.headers.connection, 'close'); assert.equal(call.args.headers['content-length'], '3');
  assert.equal(call.args.headers['accept-encoding'], 'identity');
  assert.equal(call.args.headers.authorization, 'Bearer ' + SECRET);
  const response = io.receive(0, { rawHeaders: ['content-length', '2', 'content-encoding', 'identity'] });
  response.emit('data', Buffer.from('{}')); response.emit('end');
  const result = await pending;
  assert.ok(result instanceof Response); assert.equal(await result.text(), '{}');
  assert.equal(result.redirected, false); assert.equal(io.transport.snapshot().active, 1);
  call.request.finish();
  assert.equal(io.transport.snapshot().active, 1);
  socket.finish();
  assert.deepEqual(io.transport.snapshot(), { closed: false, active: 0, peak: 1, started: 1, completed: 1 });
  assert.equal(Object.isFrozen(io.transport.snapshot()), true);
  assert.equal(JSON.stringify(io.transport.snapshot()).includes(SECRET), false);
});

test('successful response survives later SDK abort but admission waits for actual socket close', async (t) => {
  const io = fixture(t, { maxRequests: 1 }), controller = new AbortController();
  const pending = io.transport.fetch(URL, input(controller)), socket = io.socket();
  io.calls[0].request.emit('socket', socket); // A duplicate event is not another owned socket.
  const response = io.receive(); response.emit('data', Buffer.from('original')); response.emit('end');
  const result = await pending;
  controller.abort(new Error(SECRET));
  assert.equal(await result.text(), 'original');
  assert.equal(io.calls[0].request.destroyed, true); assert.equal(socket.destroyed, true);
  io.calls[0].request.finish();
  await assert.rejects(io.transport.fetch(URL, input()), code('LIMIT'));
  assert.equal(io.calls.length, 1);
  socket.finish();
  response.emit('close');
  assert.equal(io.transport.snapshot().active, 0);
});

test('abort before dispatch is local and abort during signal registration creates no HTTP request', async (t) => {
  const io = fixture(t), already = new AbortController(); already.abort();
  await assert.rejects(io.transport.fetch(URL, input(already)), code('ABORTED'));
  const controller = new AbortController(), add = controller.signal.addEventListener;
  t.mock.method(controller.signal, 'addEventListener', function (...args) {
    add.call(this, ...args); controller.abort(new Error(SECRET));
  });
  await assert.rejects(io.transport.fetch(URL, input(controller)), code('ABORTED'));
  assert.equal(io.calls.length, 0);
  assert.deepEqual(io.transport.snapshot(), { closed: false, active: 0, peak: 1, started: 1, completed: 1 });
});

test('abort before socket and response assignment still destroys their later owned resources', async (t) => {
  const io = fixture(t), controller = new AbortController();
  const pending = io.transport.fetch(URL, input(controller));
  controller.abort(); await assert.rejects(pending, code('ABORTED'));
  const socket = io.socket(), response = io.receive();
  assert.equal(socket.destroyed, true); assert.equal(response.destroyed, true);
  response.emit('error', new Error(SECRET)); response.emit('aborted');
  io.finish(); assert.equal(io.transport.snapshot().active, 0);
});

test('HTTP request or response close before verified end settles a fixed unresolved failure', async (t) => {
  const io = fixture(t);
  for (const kind of ['request', 'response', 'aborted', 'error', 'incomplete', 'wrong-length']) {
    const index = io.calls.length, pending = io.transport.fetch(URL, input());
    io.socket(index);
    if (kind === 'request') io.calls[index].request.finish();
    else {
      const response = io.receive(index, kind === 'wrong-length' ? { rawHeaders: ['content-length', '2'] } : {});
      if (kind === 'incomplete') { response.complete = false; response.emit('end'); }
      else if (kind === 'wrong-length') { response.emit('data', Buffer.from('x')); response.emit('end'); }
      else response.emit(kind === 'response' ? 'close' : kind, new Error(SECRET));
      response.emit('data', Buffer.from('ignored')); response.emit('end');
    }
    await assert.rejects(pending, code('TRANSPORT'));
    io.finish(index);
  }
  assert.equal(io.transport.snapshot().active, 0);
});

test('redirects, bodyless responses and malformed or excessive headers are rejected', async (t) => {
  const io = fixture(t);
  const cases = [
    [{ statusCode: 199 }, 'INVALID'], [{ statusCode: 204 }, 'INVALID'], [{ statusCode: 205 }, 'INVALID'],
    [{ statusCode: 307 }, 'INVALID'], [{ statusCode: 600 }, 'INVALID'],
    [{ rawHeaders: ['x', 'a', 'X', 'b'] }, 'INVALID'], [{ rawHeaders: ['bad header', 'x'] }, 'INVALID'],
    [{ rawHeaders: ['content-length', '01'] }, 'INVALID'], [{ rawHeaders: ['content-length', '65537'] }, 'LIMIT'],
    [{ rawHeaders: ['content-encoding', 'gzip'] }, 'INVALID'],
    [{ rawHeaders: ['transfer-encoding', 'gzip'] }, 'INVALID'],
    [{ rawHeaders: ['transfer-encoding', 'chunked', 'content-length', '2'] }, 'INVALID'],
    [{ rawHeaders: Array.from({ length: 65 }, (_, i) => ['x-' + i, 'v']).flat() }, 'LIMIT'],
    [{ rawHeaders: ['large', 'x'.repeat(16384)] }, 'LIMIT'],
  ];
  for (const [extra, expected] of cases) {
    const index = io.calls.length, pending = io.transport.fetch(URL, input());
    io.socket(index); const response = io.receive(index, extra);
    await assert.rejects(pending, code(expected));
    assert.equal(response.destroyed, true); io.finish(index);
  }
  assert.equal(io.transport.snapshot().active, 0);
});

test('captured response bytes allow exactly 64KiB and fail before the next byte is retained', async (t) => {
  const io = fixture(t);
  const ok = io.transport.fetch(URL, input()), socket = io.socket();
  const response = io.receive(0, { rawHeaders: ['transfer-encoding', 'chunked'] });
  response.emit('data', Buffer.alloc(65536, 65)); response.emit('end');
  assert.equal((await (await ok).arrayBuffer()).byteLength, 65536);
  io.calls[0].request.finish(); socket.finish();
  const bad = io.transport.fetch(URL, input()); io.socket(1);
  const oversized = io.receive(1);
  oversized.emit('data', Buffer.alloc(65536)); oversized.emit('data', Buffer.from([1]));
  oversized.emit('data', Buffer.from([2])); oversized.emit('end');
  await assert.rejects(bad, code('LIMIT')); io.finish(1);
});

test('Node errors are sanitized and TLS or parser faults are not classified as worker death', async (t) => {
  const io = fixture(t);
  for (const [reason, expected] of [[undefined, 'TRANSPORT'], [{ code: 'ECONNRESET' }, 'TRANSPORT'],
    [{ code: 'HPE_HEADER_OVERFLOW' }, 'LIMIT'], [{ code: 'HPE_UNEXPECTED_CONTENT_LENGTH' }, 'INVALID'],
    [{ code: 'DEPTH_ZERO_SELF_SIGNED_CERT' }, 'INVALID']]) {
    const index = io.calls.length, pending = io.transport.fetch(URL, input()); io.socket(index);
    io.calls[index].request.emit('error', reason === undefined ? undefined : Object.assign(new Error(SECRET), reason));
    await assert.rejects(pending, code(expected)); io.finish(index);
  }
});

test('all documented X509 failures and TLS protocol errors are non-death observations', async (t) => {
  const io = fixture(t);
  // Node 22.16 TLS X509 error codes, independently enumerated from its manual.
  const certificates = ['UNABLE_TO_GET_ISSUER_CERT', 'UNABLE_TO_GET_CRL',
    'UNABLE_TO_DECRYPT_CERT_SIGNATURE', 'UNABLE_TO_DECRYPT_CRL_SIGNATURE',
    'UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY', 'CERT_SIGNATURE_FAILURE', 'CRL_SIGNATURE_FAILURE',
    'CERT_NOT_YET_VALID', 'CERT_HAS_EXPIRED', 'CRL_NOT_YET_VALID', 'CRL_HAS_EXPIRED',
    'ERROR_IN_CERT_NOT_BEFORE_FIELD', 'ERROR_IN_CERT_NOT_AFTER_FIELD',
    'ERROR_IN_CRL_LAST_UPDATE_FIELD', 'ERROR_IN_CRL_NEXT_UPDATE_FIELD',
    'DEPTH_ZERO_SELF_SIGNED_CERT', 'SELF_SIGNED_CERT_IN_CHAIN', 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
    'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_CHAIN_TOO_LONG', 'CERT_REVOKED', 'INVALID_CA',
    'PATH_LENGTH_EXCEEDED', 'INVALID_PURPOSE', 'CERT_UNTRUSTED', 'CERT_REJECTED', 'HOSTNAME_MISMATCH'];
  for (const cause of [...certificates, 'ERR_TLS_CERT_ALTNAME_INVALID', 'ERR_TLS_DH_PARAM_SIZE',
    'ERR_TLS_INVALID_PROTOCOL_VERSION', 'ERR_SSL_WRONG_VERSION_NUMBER', 'ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION', 'EPROTO']) {
    const index = io.calls.length, pending = io.transport.fetch(URL, input()); io.socket(index);
    io.calls[index].request.emit('error', Object.assign(new Error(SECRET), { code: cause }));
    await assert.rejects(pending, code('INVALID')); io.finish(index);
  }
  const index = io.calls.length, pending = io.transport.fetch(URL, input()); io.socket(index);
  io.calls[index].request.emit('error', Object.assign(new Error(SECRET), { code: 'OUT_OF_MEM' }));
  await assert.rejects(pending, code('LIMIT')); io.finish(index);
  assert.equal(io.transport.snapshot().active, 0);
});

test('repeated certificate or TLS protocol rejection cannot mature an automatic takeover window', async (t) => {
  let now = 0;
  t.mock.method(performance, 'now', () => now);
  const io = fixture(t), calls = [], status = head();
  let cause = 'CERT_REJECTED';
  const factory = (_url, _args, received) => {
    const request = new Request();
    request.end = (bytes) => {
      const value = JSON.parse(bytes); calls.push(value);
      queueMicrotask(() => {
        if (value.expected_worker_instance === '100') {
          request.emit('error', Object.assign(new Error(SECRET), { code: cause }));
        } else {
          const response = new Incoming(); received(response);
          response.emit('data', Buffer.from(JSON.stringify({ ok: true, value: status })));
          response.emit('end');
        }
        request.finish();
      });
    };
    return request;
  };
  t.mock.method(https, 'request', factory);
  const p = policy({ metadataEndpoints: ['https://metadata.test/v1'], workers: [
    { workerInstance: '100', endpoint: 'https://owner.test/v1', rank: 0 },
    { workerInstance: '200', endpoint: 'https://target.test/v1', rank: 1 },
  ] });
  for (cause of ['CERT_REJECTED', 'CERT_REVOKED', 'ERR_TLS_DH_PARAM_SIZE', 'ERR_SSL_WRONG_VERSION_NUMBER', 'EPROTO']) {
    now = 0;
    const controller = new OwnerController({ policy: p, token: OPTIONS.token, fetch: io.transport.fetch });
    try {
      for (const tick of [0, 5000, 10000, 15000]) {
        now = tick;
        const report = await controller.tick();
        assert.equal(report.state, 'blocked'); assert.equal(report.reason, 'INVALID');
        assert.equal(report.httpCalls, 2); assert.equal(report.mutations, 0);
      }
    } finally { await controller.close(); }
  }
  assert.equal(calls.length, 40);
  assert.ok(calls.every((call) => call.operation === 'status'));
  await io.transport.close();
  assert.equal(io.transport.snapshot().active, 0);
});

test('informational, upgrade and CONNECT sockets cannot escape lifetime ownership', async (t) => {
  const io = fixture(t);
  for (const kind of ['information', 'upgrade', 'connect']) {
    const index = io.calls.length, pending = io.transport.fetch(URL, input());
    const socket = new Socket();
    io.calls[index].request.emit(kind, {}, socket, Buffer.from(SECRET));
    await assert.rejects(pending, code('INVALID'));
    io.calls[index].request.finish();
    if (kind !== 'information') {
      assert.equal(socket.destroyed, true); assert.equal(io.transport.snapshot().active, 1);
      socket.finish();
    }
    assert.equal(io.transport.snapshot().active, 0);
  }
});

test('constructor and end failures retain only resources actually returned by Node', async (t) => {
  const io = fixture(t);
  t.mock.method(http, 'request', () => { throw new Error(SECRET); });
  await assert.rejects(io.transport.fetch(URL, input()), code('TRANSPORT'));
  assert.equal(io.transport.snapshot().active, 0);
  const request = new Request(), socket = new Socket(); request.socket = socket;
  t.mock.method(http, 'request', () => request);
  t.mock.method(request, 'end', () => { throw new Error(SECRET); });
  await assert.rejects(io.transport.fetch(URL, input()), code('TRANSPORT'));
  assert.equal(io.transport.snapshot().active, 1); assert.equal(socket.destroyed, true);
  request.finish(); socket.finish();
  const closedSocket = new Socket(); closedSocket.finish();
  const closedRequest = new Request(); closedRequest.socket = closedSocket;
  t.mock.method(http, 'request', () => closedRequest);
  const pending = io.transport.fetch(URL, input()); closedRequest.emit('error', new Error(SECRET));
  await assert.rejects(pending, code('TRANSPORT')); closedRequest.finish();
  assert.equal(io.transport.snapshot().active, 0);
});

test('Response materialization failure destroys the owned request and preserves no token', async (t) => {
  const io = fixture(t), pending = io.transport.fetch(URL, input()); io.socket();
  const response = io.receive();
  t.mock.method(globalThis, 'Response', function () { throw new Error(SECRET); });
  response.emit('end');
  await assert.rejects(pending, code('INVALID')); io.finish();
});

test('aborted DNS remains admitted until the actual builtin callback completes', async (t) => {
  const io = fixture(t, { maxRequests: 1 }), controller = new AbortController();
  let done, callbacks = 0;
  t.mock.method(dns, 'lookup', (_host, _options, callback) => { done = callback; });
  const pending = io.transport.fetch(URL, input(controller)); io.socket();
  io.calls[0].args.lookup('worker.test', { all: false }, () => { ++callbacks; });
  controller.abort(); await assert.rejects(pending, code('ABORTED')); io.finish();
  assert.equal(io.transport.snapshot().active, 1);
  await assert.rejects(io.transport.fetch(URL, input()), code('LIMIT'));
  let closed = false; const closing = io.transport.close().then(() => { closed = true; });
  assert.equal(io.transport.close(), io.transport.close());
  await Promise.resolve(); assert.equal(closed, false);
  done(null, '127.0.0.1', 4); done(null, '127.0.0.1', 4);
  await closing;
  assert.equal(callbacks, 1);
  assert.deepEqual(io.transport.snapshot(), { closed: true, active: 0, peak: 1, started: 1, completed: 1 });
  await assert.rejects(io.transport.fetch(URL, input()), code('CLOSED'));
});

test('DNS synchronous failure and callback cleanup do not leak the admission lease', async (t) => {
  const io = fixture(t);
  t.mock.method(dns, 'lookup', () => { throw new Error(SECRET); });
  const pending = io.transport.fetch(URL, input()); io.socket();
  io.calls[0].args.lookup('worker.test', {}, (error) => io.calls[0].request.emit('error', error));
  await assert.rejects(pending, code('TRANSPORT')); io.finish();
  assert.equal(io.transport.snapshot().active, 0);
});

test('abort inside Node construction prevents a later lookup and end from starting', async (t) => {
  const io = fixture(t), controller = new AbortController(), request = new Request();
  let result;
  t.mock.method(dns, 'lookup', () => assert.fail('stopped request must not start DNS'));
  t.mock.method(http, 'request', (_url, options) => {
    controller.abort();
    options.lookup('worker.test', {}, (error) => { result = error; });
    return request;
  });
  await assert.rejects(io.transport.fetch(URL, input(controller)), code('ABORTED'));
  assert.equal(result.code, 'ABORTED'); assert.equal(request.destroyed, true); assert.equal(request.body, undefined);
  request.finish(); assert.equal(io.transport.snapshot().active, 0);
});

test('default eight slots have no implicit HTTP queue and HTTPS keeps certificate verification', async (t) => {
  const io = fixture(t), pending = [];
  for (let index = 0; index < 8; ++index) {
    pending.push(io.transport.fetch('https://worker.test/v1', input())); io.socket(index);
  }
  await assert.rejects(io.transport.fetch(URL, input()), code('LIMIT'));
  assert.equal(io.calls.length, 8); assert.equal(io.transport.snapshot().peak, 8);
  for (const call of io.calls) assert.equal(call.args.rejectUnauthorized, true);
  const checks = pending.map((p) => assert.rejects(p, code('CLOSED')));
  let stopped = false; const closing = io.transport.close().then(() => { stopped = true; });
  await Promise.all(checks); await Promise.resolve(); assert.equal(stopped, false);
  for (let index = 0; index < 8; ++index) io.finish(index);
  await closing; assert.equal(io.transport.snapshot().completed, 8);
});

test('quiesce joins old DNS and sockets before reopening admission, without closing the transport', async (t) => {
  const io = fixture(t); let done;
  t.mock.method(dns, 'lookup', (_host, _options, callback) => { done = callback; });
  const pending = io.transport.fetch(URL, input()); io.socket();
  io.calls[0].args.lookup('worker.test', {}, () => {});
  const checked = assert.rejects(pending, code('ABORTED'));
  const joined = io.transport.quiesce();
  assert.equal(io.transport.quiesce(), joined);
  await checked;
  assert.equal(io.calls[0].request.destroyed, true);
  assert.equal(io.transport.snapshot().closed, false);
  await assert.rejects(io.transport.fetch(URL, input()), code('LIMIT'));
  io.finish();
  let complete = false; const observed = joined.then(() => { complete = true; });
  await Promise.resolve(); assert.equal(complete, false);
  done(null, '127.0.0.1', 4); await observed;
  assert.equal(io.transport.snapshot().active, 0);
  const next = io.transport.fetch(URL, input()); io.socket(1);
  const response = io.receive(1); response.emit('data', Buffer.from('{}')); response.emit('end');
  assert.equal(await (await next).text(), '{}'); io.finish(1);
  await io.transport.quiesce();
  assert.deepEqual(io.transport.snapshot(), { closed: false, active: 0, peak: 1, started: 2, completed: 2 });
});

test('close racing quiesce joins the same originals and never reopens a closed transport', async (t) => {
  const io = fixture(t), pending = io.transport.fetch(URL, input()); io.socket();
  const checked = assert.rejects(pending, code('ABORTED'));
  const joined = io.transport.quiesce(), closing = io.transport.close();
  assert.equal(io.transport.quiesce(), closing);
  await checked;
  io.finish(); await Promise.all([joined, closing]);
  await assert.rejects(io.transport.fetch(URL, input()), code('CLOSED'));
  assert.deepEqual(io.transport.snapshot(), { closed: true, active: 0, peak: 1, started: 1, completed: 1 });
});
