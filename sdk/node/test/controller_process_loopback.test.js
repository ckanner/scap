/** Actual Node child processes and loopback sockets; never merged into unit profiles. */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn, execFileSync } from 'node:child_process';
import { once } from 'node:events';
import { head, SCOPE, OPTIONS } from './owner_fixture.js';

const entry = fileURLToPath(new URL('../bin/owner-controller.mjs', import.meta.url));
const variable = 'SCAP_CONTROLLER_PROCESS_LOOPBACK_TOKEN';

function bounded(promise, label) {
  let timer;
  return Promise.race([promise, new Promise((_resolve, reject) => {
    timer = setTimeout(() => reject(new Error(label + ' exceeded the fixed five-second fixture bound')), 5000);
  })]).finally(() => clearTimeout(timer));
}

async function backend(t, respond) {
  const requests = [], sockets = new Set();
  const server = http.createServer((request, response) => {
    const chunks = []; request.on('data', (chunk) => chunks.push(chunk));
    request.on('end', () => {
      assert.equal(request.method, 'POST'); assert.equal(request.url, '/v1');
      assert.equal(request.headers.authorization, 'Bearer ' + OPTIONS.token);
      const body = JSON.parse(Buffer.concat(chunks)); requests.push(body); respond(body, response);
    });
  });
  server.on('connection', (socket) => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)); });
  return { endpoint: `http://127.0.0.1:${server.address().port}/v1`, requests, sockets };
}

function child(t, endpoint, value) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'scap-controller-process-'));
  const configuration = path.join(directory, 'controller.json');
  const config = value ?? { version: 1, scopes: [{ tokenEnv: variable, policy: {
    scope: SCOPE, authorityId: 'process-loopback', principal: '7', metadataEndpoints: [endpoint],
    workers: [{ workerInstance: '100', endpoint, rank: 0 }],
    modes: { takeover: true, activate: true, cancel: true },
  } }] };
  fs.writeFileSync(configuration, JSON.stringify(config), { mode: 0o600 });
  const environment = { ...process.env, [variable]: OPTIONS.token }; delete environment.NODE_V8_COVERAGE;
  const processChild = spawn(process.execPath, [entry, configuration], { env: environment, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '', err = '', firstLine;
  const first = new Promise((resolve) => { firstLine = resolve; });
  processChild.stdout.on('data', (bytes) => {
    out += bytes; assert.ok(Buffer.byteLength(out) <= 256 * 1024);
    if (out.includes('\n')) firstLine(JSON.parse(out.slice(0, out.indexOf('\n'))));
  });
  processChild.stderr.on('data', (bytes) => { err += bytes; assert.ok(Buffer.byteLength(err) <= 16384); });
  const exited = once(processChild, 'exit');
  t.after(async () => {
    if (processChild.exitCode === null && processChild.signalCode === null) processChild.kill('SIGKILL');
    await exited; fs.rmSync(directory, { recursive: true });
  });
  return { process: processChild, first, exited, stdout: () => out, stderr: () => err };
}

test('CLI reads a real bounded config, emits a healthy observation and joins on SIGTERM', async (t) => {
  const service = await backend(t, (_body, response) => {
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ ok: true, value: head() }));
  });
  const cli = child(t, service.endpoint), report = await bounded(cli.first, 'first report');
  assert.equal(report.state, 'healthy'); assert.equal(report.nativeSession, 'NOT_CERTIFIED');
  assert.equal(report.httpCalls, 2); assert.equal(report.mutations, 0);
  assert.equal(cli.stdout().includes(OPTIONS.token), false);
  cli.process.kill('SIGTERM'); assert.deepEqual(await bounded(cli.exited, 'SIGTERM join'), [0, null]);
  assert.deepEqual(service.requests.map((request) => request.operation), ['status', 'status']);
  assert.equal(service.requests[1].expected_worker_instance, '100'); assert.equal(cli.stderr(), '');
});

test('SIGINT aborts an actual stalled HTTP attempt and waits for its socket to close', async (t) => {
  let admitted; const requestSeen = new Promise((resolve) => { admitted = resolve; });
  const service = await backend(t, () => admitted()), cli = child(t, service.endpoint);
  await bounded(requestSeen, 'stalled request admission'); assert.equal(service.sockets.size, 1);
  const socket = [...service.sockets][0], closed = once(socket, 'close');
  cli.process.kill('SIGINT'); assert.deepEqual(await bounded(cli.exited, 'SIGINT join'), [0, null]);
  await bounded(closed, 'peer socket close'); assert.equal(service.sockets.size, 0);
  assert.equal(service.requests.length, 1); assert.equal(service.requests[0].operation, 'status');
  assert.equal(cli.stderr(), '');
});

test('invalid configuration prints no raw values, and opening a FIFO cannot hang before the regular-file guard', async (t) => {
  const cli = child(t, 'http://127.0.0.1:1/v1', { version: 1, scopes: [], secret: OPTIONS.token });
  assert.deepEqual(await bounded(cli.exited, 'invalid configuration'), [1, null]);
  assert.equal(cli.stderr().includes(OPTIONS.token), false); assert.equal(cli.stdout(), '');
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'scap-controller-fifo-')), fifo = path.join(directory, 'input');
  t.after(() => fs.rmSync(directory, { recursive: true })); execFileSync('mkfifo', [fifo]);
  const environment = { ...process.env }; delete environment.NODE_V8_COVERAGE;
  const blocked = spawn(process.execPath, [entry, fifo], { env: environment, stdio: ['ignore', 'pipe', 'pipe'] });
  const exited = once(blocked, 'exit'); blocked.stdout.resume(); blocked.stderr.resume();
  t.after(async () => { if (blocked.exitCode === null && blocked.signalCode === null) blocked.kill('SIGKILL'); await exited; });
  assert.deepEqual(await bounded(exited, 'FIFO guard'), [1, null]);
});
