/** Controlled Fetch/stream/diagnostics tests; no listening socket or real HTTP attempt. */
import assert from 'node:assert/strict';
import { channel } from 'node:diagnostics_channel';
import { EventEmitter } from 'node:events';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setImmediate as tick } from 'node:timers/promises';
import test from 'node:test';
import { createLedger } from './client_ledger.mjs';
import { createObservation, LIMITS, safeError } from './client_transport.mjs';

const secret = 'fixture-private-token-should-never-enter-transport-observation';
const input = () => ({ method: 'POST', body: '{"version":1,"operation":"list_names","cursor":null}',
  headers: { authorization: `Bearer ${secret}`, 'content-type': 'application/json', 'x-scap-admission': 'discovery' },
  signal: new AbortController().signal, redirect: 'error' });
const response = () => new Response('{"ok":true,"value":{"names":[]}}', {
  status: 200, headers: { 'content-type': 'application/json' } });
const publish = (name, data) => channel('undici:' + name).publish(data);
function rows(directory, name = 'http-client-transport.jsonl') {
  return readFileSync(join(directory, name), 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse);
}
function fixture(t, fetcher) {
  const directory = mkdtempSync(join(tmpdir(), 'scap-client-observation-unit-'));
  const ledger = createLedger(directory, 'unit', { fetch: fetcher });
  t.after(() => { ledger.close(); rmSync(directory, { recursive: true, force: true }); });
  return { directory, ledger, invoke: ledger.transport('reader:1') };
}
function direct(t) {
  const captured = [];
  const observer = createObservation((batch) => captured.push(...batch));
  t.after(() => observer.close());
  return { captured, observer };
}
function privateFields(value, names) {
  for (const name of names) Object.defineProperty(value, name, {
    get() { throw new Error('forbidden observation read: ' + name); },
  });
  return value;
}

test('only fixed names/codes survive, including hostile or missing properties', () => {
  const error = privateFields({ name: 'TypeError', code: secret,
    cause: { code: 'ECONNRESET', message: secret } }, ['message', 'stack', 'url', 'headers']);
  assert.deepEqual(safeError(error), { error_name: 'TypeError', error_code: 'UNKNOWN', cause_code: 'ECONNRESET' });
  assert.deepEqual(safeError({ name: secret, code: 5, cause: { code: secret } }),
    { error_name: 'UNKNOWN', error_code: 'UNKNOWN', cause_code: 'UNKNOWN' });
  assert.deepEqual(safeError(privateFields({}, ['name', 'code', 'cause'])), safeError(null));
  assert.equal(JSON.stringify(safeError(error)).includes(secret), false);
});

test('one original Fetch and original arguments survive; absent diagnostics remain UNKNOWN', async (t) => {
  let count = 0, seen;
  const f = fixture(t, (url, options) => { count++; seen = [url, options]; return response(); });
  const options = input(), url = 'http://127.0.0.1:1234/v1/discovery';
  const received = await f.invoke(url, options);
  assert.equal(await received.text(), '{"ok":true,"value":{"names":[]}}');
  assert.equal(count, 1); assert.equal(f.ledger.attempts(), 1);
  assert.deepEqual(seen, [url, options]); assert.equal(seen[1], options);
  const raw = rows(f.directory, 'http-client-ledger.jsonl');
  assert.deepEqual(raw.map((row) => row.event), ['client_process_hello', 'http_request', 'http_response']);
  assert.equal(Buffer.from(raw[1].body, 'base64').toString(), options.body);
  assert.equal(Buffer.from(raw[2].body, 'base64').toString(), '{"ok":true,"value":{"names":[]}}');
  const observed = rows(f.directory), end = observed.at(-1);
  assert.equal(end.event, 'call_observation_finished');
  assert.equal(end.request_identity, 'UNKNOWN'); assert.equal(end.connection_identity, 'UNKNOWN');
  assert.equal(observed.some((row) => row.event === 'fetch_response_headers' && row.status === 200), true);
  assert.equal(JSON.stringify(observed).includes(secret), false);
});

test('a controlled body stall preserves observed headers before body completion', async (t) => {
  let body;
  const f = fixture(t, () => new Response(new ReadableStream({ start(controller) { body = controller; } }),
    { status: 200, headers: { 'content-type': 'application/json' } }));
  const pending = f.invoke('http://127.0.0.1:1234/v1/discovery', input());
  await tick();
  f.ledger.append('checkpoint.jsonl', { event: 'controlled_body_still_pending' });
  const before = rows(f.directory);
  assert.equal(before.some((row) => row.event === 'fetch_response_headers'), true);
  assert.equal(before.some((row) => row.event === 'fetch_body_started'), true);
  assert.equal(before.some((row) => row.event === 'fetch_body_complete'), false);
  assert.equal(rows(f.directory, 'http-client-ledger.jsonl').some((row) => row.event === 'http_response'), false);
  body.enqueue(new TextEncoder().encode('{"ok":true}')); body.close();
  assert.equal(await (await pending).text(), '{"ok":true}');
  assert.equal(rows(f.directory).filter((row) => row.event === 'fetch_body_complete').length, 1);
});

test('Fetch failure is distinct from headers-observed body failure, without secrets or retry', async (t) => {
  const original = Object.assign(new TypeError(secret), { cause: { code: 'ECONNRESET', message: secret } });
  let calls = 0;
  const f = fixture(t, () => { calls++; throw original; });
  await assert.rejects(f.invoke('http://127.0.0.1:1234/v1/discovery', input()), (error) => error === original);
  const failure = rows(f.directory).find((row) => row.event === 'fetch_failure');
  assert.equal(failure.stage, 'fetch'); assert.equal(failure.cause_code, 'ECONNRESET');
  assert.equal(rows(f.directory).some((row) => row.event === 'fetch_response_headers'), false);
  assert.equal(calls, 1); assert.equal(JSON.stringify(rows(f.directory)).includes(secret), false);
});

test('a stream failure records body stage even though no complete HTTP response exists', async (t) => {
  let body, calls = 0;
  const f = fixture(t, () => { calls++; return new Response(new ReadableStream({
    start(controller) { body = controller; },
  }), { status: 200, headers: { 'content-type': 'application/json' } }); });
  const pending = f.invoke('http://127.0.0.1:1234/v1/discovery', input());
  const rejected = assert.rejects(pending);
  await tick();
  body.error(Object.assign(new TypeError(secret), { cause: { code: 'UND_ERR_SOCKET', message: secret } }));
  await rejected;
  const observed = rows(f.directory), failure = observed.find((row) => row.event === 'fetch_failure');
  assert.equal(failure.stage, 'body'); assert.equal(failure.cause_code, 'UND_ERR_SOCKET');
  assert.equal(observed.some((row) => row.event === 'fetch_response_headers' && row.status === 200), true);
  assert.equal(observed.some((row) => row.event === 'fetch_body_complete'), false);
  assert.equal(rows(f.directory, 'http-client-ledger.jsonl').at(-1).event, 'http_transport_error');
  assert.equal(calls, 1); assert.equal(JSON.stringify(observed).includes(secret), false);
});

test('only ALS plus the same request binds a socket; close belongs to the connection, not last call', async (t) => {
  const socket = privateFields(new EventEmitter(), ['address', 'remoteAddress', 'localAddress']);
  let count = 0;
  const f = fixture(t, () => {
    count++;
    const request = privateFields({}, ['headers', 'path', 'origin']);
    publish('request:create', { request });
    publish('client:sendHeaders', privateFields({ request, socket }, ['headers']));
    publish('request:headers', { request, response: privateFields({ statusCode: 200 }, ['headers', 'statusText']) });
    publish('request:trailers', privateFields({ request }, ['trailers']));
    return response();
  });
  await f.invoke('http://127.0.0.1:1234/v1/discovery', input());
  const unrelated = {};
  publish('request:create', { request: unrelated }); // Deliberately outside the original Fetch ALS.
  publish('client:sendHeaders', { request: unrelated, socket });
  await f.invoke('http://127.0.0.1:1234/v1/discovery', input());
  assert.equal(socket.listenerCount('end'), 1); assert.equal(socket.listenerCount('close'), 1);
  assert.equal(socket.listenerCount('error'), 1);
  socket.emit('end'); socket.emit('close', false);
  f.ledger.close();
  const observed = rows(f.directory), sends = observed.filter((row) => row.event === 'request_send_headers');
  assert.equal(sends.length, 2); assert.notEqual(sends[0].call_id, sends[1].call_id);
  assert.equal(sends[0].connection_id, sends[1].connection_id);
  assert.equal(observed.filter((row) => row.event === 'request_created').length, 2);
  const closed = observed.find((row) => row.event === 'socket_close');
  assert.equal(closed.connection_id, sends[0].connection_id); assert.equal('call_id' in closed, false);
  assert.equal(socket.listenerCount('end'), 0); assert.equal(socket.listenerCount('close'), 0);
  assert.equal(socket.listenerCount('error'), 0); assert.equal(count, 2);
  assert.equal(observed.some((row) => row.event === 'observation_incomplete'), false);
});

test('concurrent contexts keep their own request identities when completion order reverses', async (t) => {
  const { observer, captured } = direct(t), one = observer.begin('unit:1'), two = observer.begin('unit:2');
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const first = observer.run(one, async () => {
    await gate;
    const request = {}; publish('request:create', { request }); publish('request:error', {
      request, error: { name: 'SocketError', code: 'UND_ERR_SOCKET', message: secret },
    });
  });
  await observer.run(two, async () => { publish('request:create', { request: {} }); });
  release(); await first;
  observer.finish(one, 'failed', 'fetch'); observer.finish(two, 'response', 'evidence');
  assert.deepEqual(captured.filter((row) => row.event === 'request_created').map((row) => row.call_id), ['unit:2', 'unit:1']);
  assert.equal(captured.find((row) => row.event === 'request_error').call_id, 'unit:1');
});

test('per-call overflow is explicitly INCOMPLETE and never causes another dispatch', (t) => {
  const { observer, captured } = direct(t), call = observer.begin('unit:bounded');
  observer.run(call, () => {
    const request = {}; publish('request:create', { request });
    for (let index = 0; index < LIMITS.callEvents + 2; index++) publish('request:headers', { request, response: { statusCode: 200 } });
  });
  observer.finish(call, 'response', 'evidence'); observer.close();
  assert.equal(captured.filter((row) => row.reason === 'call_event_limit').length, 1);
  assert.equal(captured.at(-1).observation_status, 'INCOMPLETE');
  assert.ok(captured.filter((row) => row.call_id === call.id).length <= LIMITS.callEvents + 1);
});

test('pending queue has one explicit overflow marker and failed flush does not grow the batch', (t) => {
  let fail = true, size, captured, last;
  const observer = createObservation((batch) => {
    size = batch.length;
    if (fail) throw new Error('controlled evidence sink failure');
    captured = [...batch];
  });
  t.after(() => { fail = false; observer.close(); });
  for (let index = 0; index < LIMITS.pendingEvents + 10; index++) last = observer.begin('unit:' + index);
  assert.throws(() => observer.flush(), /controlled evidence sink failure/);
  assert.equal(size, LIMITS.pendingEvents + 1);
  fail = false; observer.flush();
  assert.equal(captured.length, LIMITS.pendingEvents + 1);
  assert.equal(captured.filter((row) => row.reason === 'pending_event_limit').length, 1);
  observer.finish(last, 'failed', 'fetch');
  assert.equal(captured.at(-1).observation_status, 'INCOMPLETE');
});

test('per-connection overflow and bounded active tracking are reported without closing sockets', (t) => {
  const { observer, captured } = direct(t), sockets = [];
  for (let index = 0; index <= LIMITS.activeConnections; index++) {
    const socket = privateFields(new EventEmitter(), ['destroy', 'end', 'setTimeout', 'address']);
    sockets.push(socket);
    const call = observer.begin('unit:' + index);
    observer.run(call, () => {
      const request = {}; publish('request:create', { request }); publish('client:sendHeaders', { request, socket });
    });
    observer.finish(call, 'response', 'evidence');
  }
  for (let index = 0; index <= LIMITS.connectionEvents; index++) sockets[0].emit('error', { code: 'ECONNRESET' });
  observer.close();
  assert.equal(captured.filter((row) => row.reason === 'active_connection_limit').length, 1);
  assert.equal(captured.filter((row) => row.reason === 'connection_event_limit').length, 1);
  assert.equal(captured.at(-1).observation_status, 'INCOMPLETE');
  for (const socket of sockets) assert.equal(socket.listenerCount('close'), 0);
});

test('request fanout is bounded and duplicate identity is never rebound to the latest call', (t) => {
  const { observer, captured } = direct(t), request = {};
  const original = observer.begin('unit:original'), newer = observer.begin('unit:newer');
  observer.run(original, () => publish('request:create', { request }));
  observer.run(newer, () => publish('request:create', { request }));
  publish('request:error', { request, error: { name: 'Error', code: 'ECONNRESET' } });
  const many = observer.begin('unit:fanout');
  observer.run(many, () => {
    for (let index = 0; index <= LIMITS.callRequests; index++) publish('request:create', { request: {} });
  });
  const connections = observer.begin('unit:connections'), same = {}, socket = new EventEmitter();
  observer.run(connections, () => {
    publish('request:create', { request: same });
    for (let index = 0; index <= LIMITS.callConnections; index++) publish('client:sendHeaders', {
      request: same, socket: index === 0 ? socket : new EventEmitter(),
    });
  });
  socket.emit('close', false);
  const closed = observer.begin('unit:closed'), reuse = {};
  observer.run(closed, () => {
    publish('request:create', { request: reuse });
    publish('client:sendHeaders', { request: reuse, socket });
  });
  observer.begin(secret + '/not-a-call-id');
  observer.close();
  assert.equal(captured.find((row) => row.event === 'request_error').call_id, 'unit:original');
  assert.equal(captured.some((row) => row.reason === 'request_identity_reused' && row.call_id === 'unit:newer'), true);
  assert.equal(captured.some((row) => row.reason === 'call_request_limit' && row.call_id === 'unit:fanout'), true);
  assert.equal(captured.some((row) => row.reason === 'call_connection_limit' && row.call_id === 'unit:connections'), true);
  assert.equal(captured.some((row) => row.reason === 'closed_socket_identity_reused'), true);
  assert.equal(captured.some((row) => row.reason === 'call_identifier_unavailable'), true);
  assert.equal(JSON.stringify(captured).includes(secret), false);
});
