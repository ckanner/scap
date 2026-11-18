/** Real Node sockets, separate from the exact unit-only coverage profiles. */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import dns from 'node:dns';
import { once } from 'node:events';
import { gzipSync } from 'node:zlib';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ControllerHttp } from '../src/controller_http.js';
import { Client, ClientError } from '../src/client.js';

const TOKEN = 'synthetic-controller-loopback-credential';
const SCOPE = { deployment: '1', tenant: '2', database: '3', incarnation: '1', generation: '1' };
const code = (value) => (error) => error instanceof ClientError && error.code === value && !String(error).includes(TOKEN);
const init = (signal, body = '{}') => ({ method: 'POST', body, signal,
  headers: { authorization: 'Bearer ' + TOKEN, 'content-type': 'application/json' }, redirect: 'error' });

async function server(t, handler, tls) {
  const app = tls ? https.createServer(tls, handler) : http.createServer(handler);
  const sockets = new Set();
  app.on('connection', (socket) => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  app.on('tlsClientError', () => {});
  app.listen(0, '127.0.0.1'); await once(app, 'listening');
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve, reject) => app.close((error) => error ? reject(error) : resolve()));
  });
  return { app, sockets, endpoint: `${tls ? 'https' : 'http'}://127.0.0.1:${app.address().port}/v1` };
}

function transport(t, maxRequests = 8) {
  const value = new ControllerHttp({ maxRequests });
  t.after(() => value.close());
  return value;
}

function signal(t, milliseconds = 2000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), milliseconds);
  t.after(() => clearTimeout(timer));
  return controller;
}

test('real owned HTTP composes with the SDK and captures one chunked JSON response', { timeout: 5000 }, async (t) => {
  const calls = [];
  const app = await server(t, async (request, response) => {
    const chunks = []; for await (const chunk of request) chunks.push(chunk);
    calls.push({ method: request.method, url: request.url, headers: request.headers, body: Buffer.concat(chunks) });
    response.writeHead(200, { 'content-type': 'application/json' });
    response.write('{"ok":true,'); response.end('"value":{"result":"U0NBUFJFUzEAAAAA"}}');
  });
  const owned = transport(t);
  const client = new Client({ endpoint: app.endpoint, token: TOKEN, scope: SCOPE, principal: '7', fetch: owned.fetch });
  assert.deepEqual(await client.query([{ sql: 'SELECT 1', parameters: [] }]), { statements: [] });
  await owned.close();
  assert.equal(calls.length, 1); assert.equal(calls[0].method, 'POST'); assert.equal(calls[0].url, '/v1');
  assert.equal(calls[0].headers.authorization, 'Bearer ' + TOKEN);
  assert.equal(calls[0].headers.connection, 'close'); assert.equal(calls[0].headers['accept-encoding'], 'identity');
  assert.equal(calls[0].headers['content-length'], String(calls[0].body.length));
  assert.deepEqual(owned.snapshot(), { closed: true, active: 0, peak: 1, started: 1, completed: 1 });
});

test('real redirects do not forward credentials or make another attempt', { timeout: 5000 }, async (t) => {
  let source = 0, destination = 0;
  const target = await server(t, (_request, response) => { ++destination; response.end('{}'); });
  const origin = await server(t, (_request, response) => {
    ++source; response.writeHead(307, { location: target.endpoint }); response.end('{}');
  });
  const owned = transport(t), original = signal(t);
  await assert.rejects(owned.fetch(origin.endpoint, init(original.signal)), code('INVALID'));
  await owned.close();
  assert.equal(source, 1); assert.equal(destination, 0); assert.equal(owned.snapshot().completed, 1);
});

test('real 101 upgrades and 103 information settle errors and close their owned sockets', { timeout: 5000 }, async (t) => {
  let calls = 0;
  const app = await server(t, (request, response) => {
    ++calls;
    if (calls === 1) {
      request.socket.write('HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: test\r\n\r\n');
    } else {
      response.writeEarlyHints({ link: '</example>; rel=preload' });
      response.end('{}');
    }
  });
  const owned = transport(t), original = signal(t);
  await assert.rejects(owned.fetch(app.endpoint, init(original.signal)), code('INVALID'));
  await assert.rejects(owned.fetch(app.endpoint, init(original.signal)), code('INVALID'));
  await owned.close();
  assert.equal(calls, 2); assert.equal(owned.snapshot().active, 0); assert.equal(owned.snapshot().completed, 2);
});

test('real progress cannot renew the original abort signal and incomplete bytes never become a response', { timeout: 5000 }, async (t) => {
  let calls = 0, writes = 0, started;
  const arrived = new Promise((resolve) => { started = resolve; });
  const app = await server(t, (_request, response) => {
    ++calls;
    response.writeHead(200, { 'content-type': 'application/json' }); response.write('{'); started();
    const timer = setInterval(() => { ++writes; response.write(' '); }, 10);
    response.on('close', () => clearInterval(timer));
  });
  const owned = transport(t), original = signal(t);
  const pending = owned.fetch(app.endpoint, init(original.signal));
  const checked = assert.rejects(pending, code('ABORTED'));
  await arrived;
  await new Promise((resolve) => setTimeout(resolve, 45));
  original.abort(); await checked; await owned.close();
  assert.equal(calls, 1); assert.ok(writes >= 1); assert.equal(owned.snapshot().active, 0);
});

test('real declared, streamed, header and encoding limits reject without transparent decompression', { timeout: 5000 }, async (t) => {
  let calls = 0;
  const app = await server(t, (_request, response) => {
    ++calls;
    if (calls === 1) response.writeHead(200, { 'content-length': '65537' }).end('x'.repeat(65537));
    else if (calls === 2) {
      response.writeHead(200); response.write('x'.repeat(32768)); response.end('x'.repeat(32769));
    } else if (calls === 3) response.writeHead(200, { large: 'x'.repeat(16384) }).end('{}');
    else if (calls === 4) {
      const body = gzipSync(Buffer.from('x'.repeat(131072)));
      response.writeHead(200, { 'content-encoding': 'gzip', 'content-length': String(body.length) }).end(body);
    } else if (calls === 5) response.writeHead(200, { 'content-length': '10', connection: 'close' }).end('x');
    else response.writeHead(200, Object.fromEntries(Array.from({ length: 65 }, (_, i) => ['x-' + i, 'v']))).end('{}');
  });
  const owned = transport(t), original = signal(t);
  for (const expected of ['LIMIT', 'LIMIT', 'LIMIT', 'INVALID', 'TRANSPORT', 'LIMIT']) {
    await assert.rejects(owned.fetch(app.endpoint, init(original.signal)), code(expected));
  }
  await owned.close();
  assert.equal(calls, 6); assert.equal(owned.snapshot().active, 0); assert.equal(owned.snapshot().completed, 6);
});

test('real admission has no queued ninth attempt and close joins requests already admitted', { timeout: 5000 }, async (t) => {
  let calls = 0, arrived;
  const ready = new Promise((resolve) => { arrived = resolve; });
  const app = await server(t, (_request, _response) => { if (++calls === 2) arrived(); });
  const owned = transport(t, 2), original = signal(t);
  const first = owned.fetch(app.endpoint, init(original.signal));
  const second = owned.fetch(app.endpoint, init(original.signal));
  const checks = Promise.all([assert.rejects(first, code('CLOSED')), assert.rejects(second, code('CLOSED'))]);
  await assert.rejects(owned.fetch(app.endpoint, init(original.signal)), code('LIMIT'));
  await ready; await owned.close(); await checks;
  assert.equal(calls, 2);
  assert.deepEqual(owned.snapshot(), { closed: true, active: 0, peak: 2, started: 2, completed: 2 });
});

test('real ClientRequest abort retains its slot through a delayed builtin DNS callback', { timeout: 5000 }, async (t) => {
  let calls = 0, callback;
  const app = await server(t, (_request, response) => { ++calls; response.end('{}'); });
  const original = signal(t), owned = transport(t, 1);
  t.mock.method(dns, 'lookup', (_host, options, done) => {
    assert.notEqual(options.all, true); callback = done;
  });
  const endpoint = app.endpoint.replace('127.0.0.1', 'delayed-owner.invalid');
  const pending = owned.fetch(endpoint, init(original.signal));
  const checked = assert.rejects(pending, code('ABORTED'));
  try {
    assert.equal(typeof callback, 'function');
    original.abort(); await checked;
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(owned.snapshot().active, 1);
    await assert.rejects(owned.fetch(app.endpoint, init(new AbortController().signal)), code('LIMIT'));
    let complete = false; const closing = owned.close().then(() => { complete = true; });
    await new Promise((resolve) => setImmediate(resolve)); assert.equal(complete, false);
    callback(null, '127.0.0.1', 4); callback = null;
    await closing;
    assert.equal(calls, 0); assert.equal(owned.snapshot().active, 0);
  } finally {
    callback?.(null, '127.0.0.1', 4);
  }
});

test('explicit HTTPS verification rejects a self-signed peer even under insecure process defaults', { timeout: 15000 }, async (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'scap-controller-tls-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const key = join(directory, 'key.pem'), cert = join(directory, 'cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
    '-subj', '/CN=localhost', '-keyout', key, '-out', cert], { stdio: 'ignore', timeout: 10000 });
  let calls = 0;
  const app = await server(t, (_request, response) => { ++calls; response.end('{}'); },
    { key: readFileSync(key), cert: readFileSync(cert) });
  const owned = transport(t), original = signal(t);
  const previous = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
  try {
    await assert.rejects(owned.fetch(app.endpoint, init(original.signal)), code('INVALID'));
  } finally {
    if (previous === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    else process.env.NODE_TLS_REJECT_UNAUTHORIZED = previous;
  }
  await owned.close();
  assert.equal(calls, 0); assert.equal(owned.snapshot().active, 0);
});

test('a real TLS connection to a plaintext HTTP endpoint is rejected without a worker-death classification', { timeout: 5000 }, async (t) => {
  let calls = 0;
  const app = await server(t, (_request, response) => { ++calls; response.end('{}'); });
  const owned = transport(t), original = signal(t);
  await assert.rejects(owned.fetch(app.endpoint.replace('http:', 'https:'), init(original.signal)), code('INVALID'));
  await owned.close();
  assert.equal(calls, 0); assert.equal(owned.snapshot().active, 0);
  assert.equal(owned.snapshot().started, 1); assert.equal(owned.snapshot().completed, 1);
});

test('real ClientRequest quiescence waits for delayed DNS before reopening transport admission', { timeout: 5000 }, async (t) => {
  let calls = 0, callback;
  const app = await server(t, (_request, response) => { ++calls; response.end('{}'); });
  const owned = transport(t), original = signal(t);
  t.mock.method(dns, 'lookup', (_host, options, done) => {
    assert.notEqual(options.all, true); callback = done;
  });
  const endpoint = app.endpoint.replace('127.0.0.1', 'quiescing-owner.invalid');
  const pending = owned.fetch(endpoint, init(original.signal));
  const checked = assert.rejects(pending, code('ABORTED'));
  try {
    assert.equal(typeof callback, 'function');
    let complete = false; const joined = owned.quiesce().then(() => { complete = true; });
    await checked; await new Promise((resolve) => setImmediate(resolve));
    assert.equal(complete, false); assert.equal(owned.snapshot().active, 1);
    await assert.rejects(owned.fetch(app.endpoint, init(original.signal)), code('LIMIT'));
    callback(null, '127.0.0.1', 4); callback = null; await joined;
    assert.equal(calls, 0); assert.equal(owned.snapshot().active, 0);
    const result = await owned.fetch(app.endpoint, init(original.signal));
    assert.equal(await result.text(), '{}'); await owned.close();
    assert.equal(calls, 1); assert.equal(owned.snapshot().completed, 2);
  } finally {
    callback?.(null, '127.0.0.1', 4);
  }
});
