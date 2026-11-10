import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import timers from 'node:timers/promises';
import { readControllerEntries, runControllerFleet, controllerMain } from '../src/controller_process.js';
import { OwnerControllerFleet } from '../src/controller_fleet.js';
import { config, policy } from './controller_policy.test.js';
import { OPTIONS } from './owner_fixture.js';

const variable = 'SCAP_UNIT_CONTROLLER_PROCESS_TOKEN';
const document = () => ({ version: 1, scopes: [{ policy: config(), tokenEnv: variable }] });
const environment = { [variable]: OPTIONS.token };

function file(t, value, { regular = true, size, changed = {}, step = 65537, openError = false, readError = false } = {}) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(JSON.stringify(value));
  let reads = 0, stats = 0, closed = 0;
  t.mock.method(fs, 'openSync', (_path, flags) => {
    assert.equal(flags & fs.constants.O_NONBLOCK, fs.constants.O_NONBLOCK);
    if (openError) throw new Error('private-path'); return 43;
  });
  t.mock.method(fs, 'fstatSync', (fd, options) => {
    assert.equal(fd, 43); assert.equal(options.bigint, true);
    return { isFile: () => regular, size: size ?? BigInt(bytes.length), mtimeNs: 1n, ctimeNs: 1n,
      ...(stats++ === 0 ? {} : changed) };
  });
  t.mock.method(fs, 'readSync', (fd, buffer, offset, length, position) => {
    assert.equal(fd, 43); reads++;
    if (readError) throw new Error('private-read-error');
    const count = Math.min(step, length, bytes.length - position);
    bytes.copy(buffer, offset, position, position + count); return count;
  });
  t.mock.method(fs, 'closeSync', (fd) => { assert.equal(fd, 43); closed++; });
  return { reads: () => reads, closed: () => closed };
}

test('configuration uses bounded exact file reads, explicit environment credentials and immutable policies', (t) => {
  const port = file(t, document(), { step: 127 }), entries = readControllerEntries('/config.json', environment);
  assert.equal(entries.length, 1); assert.equal(entries[0].token, OPTIONS.token);
  assert.equal(entries[0].policy.digest, policy().digest); assert.ok(port.reads() > 2); assert.equal(port.closed(), 1);
  assert.equal(Object.isFrozen(entries), true); assert.equal(Object.isFrozen(entries[0]), true);
  const previous = process.env[variable]; process.env[variable] = OPTIONS.token;
  try { assert.equal(readControllerEntries('/config.json')[0].token, OPTIONS.token); }
  finally { if (previous === undefined) delete process.env[variable]; else process.env[variable] = previous; }
});

test('configuration rejects oversized, changing, nonregular, unreadable and malformed files without secret diagnostics', (t) => {
  const cases = [
    [document(), { regular: false }], [document(), { size: 65537n }],
    [Buffer.alloc(65537, 32), { size: 65536n }], [document(), { changed: { size: 2n } }],
    [document(), { changed: { mtimeNs: 2n } }], [document(), { changed: { ctimeNs: 2n } }],
    [document(), { openError: true }], [document(), { readError: true }],
    [Buffer.from([0xff]), {}], [Buffer.from('{'), {}],
  ];
  for (const [value, options] of cases) {
    const port = file(t, value, options);
    assert.throws(() => readControllerEntries('/private-path', environment), (error) =>
      error.code === 'CONFIG' && !error.message.includes('private') && error.cause === undefined);
    assert.equal(port.closed(), options.openError ? 0 : 1); t.mock.restoreAll();
  }
  assert.throws(() => readControllerEntries('', environment), { code: 'CONFIG' });
});

test('configuration rejects ambiguous schema, absent or inherited credentials and invalid policies', (t) => {
  const changes = [
    (value) => { value.version = 2; }, (value) => { value.extra = true; },
    (value) => { value.scopes = null; }, (value) => { value.scopes = []; },
    (value) => { value.scopes = Array(129).fill({}); },
    (value) => { value.scopes[0].token = OPTIONS.token; },
    (value) => { value.scopes[0].tokenEnv = 'bad variable'; },
    (value) => { value.scopes[0].tokenEnv = 7; },
    (value) => { value.scopes[0].policy.workers[0].rank = -1; },
  ];
  for (const change of changes) {
    const value = document(); change(value); const port = file(t, value);
    assert.throws(() => readControllerEntries('/config', environment), { code: 'CONFIG' });
    assert.equal(port.closed(), 1); t.mock.restoreAll();
  }
  for (const env of [{}, Object.create(environment), { [variable]: 'short' }, { [variable]: 42 }]) {
    file(t, document()); assert.throws(() => readControllerEntries('/config', env), { code: 'CONFIG' }); t.mock.restoreAll();
  }
});

function fleet(closer = async () => {}) {
  return new OwnerControllerFleet({ entries: [{ policy: policy(), token: OPTIONS.token }],
    transport: { fetch: () => { throw new Error('unexpected network'); }, close: closer } });
}

test('process loop writes bounded completed reports, polls without a round queue, and joins fleet resources', async (t) => {
  const stopped = new AbortController(), writes = [];
  let polls = 0, waits = 0, finishClose, completed = false;
  const pendingClose = new Promise((resolve) => { finishClose = resolve; }), f = fleet(() => pendingClose);
  t.mock.method(f, 'poll', () => { polls++; });
  t.mock.method(f, 'takeReports', () => [{ version: 1, state: 'blocked', reason: 'TEST_REPORT', nativeSession: 'NOT_CERTIFIED' }]);
  t.mock.method(fs, 'writeSync', (fd, bytes) => { assert.equal(fd, 7); writes.push(bytes.toString()); return bytes.length; });
  t.mock.method(timers, 'setTimeout', async (delay, _value, options) => {
    assert.equal(delay, 250); assert.equal(options.signal, stopped.signal);
    if (++waits === 2) { stopped.abort(); throw new Error('aborted'); }
  });
  const running = runControllerFleet(f, { signal: stopped.signal, outputFd: 7 }).then(() => { completed = true; });
  for (let index = 0; index < 8; index++) await Promise.resolve();
  assert.equal(polls, 2); assert.equal(writes.length, 2); assert.equal(completed, false);
  assert.equal(JSON.parse(writes[0]).nativeSession, 'NOT_CERTIFIED');
  assert.equal(f.snapshot().closed, true); finishClose(); await running; assert.equal(completed, true);
});

test('output failure, partial write, report overflow and timer failure stop new admission and close the fleet', async (t) => {
  for (const kind of ['write', 'partial', 'size', 'timer']) {
    const stopped = new AbortController(); let closed = 0, polls = 0;
    const f = fleet(async () => { closed++; });
    t.mock.method(f, 'poll', () => { polls++; });
    t.mock.method(f, 'takeReports', () => [kind === 'size' ? { value: 'x'.repeat(131072) } : { state: 'healthy' }]);
    t.mock.method(fs, 'writeSync', (fd, bytes) => {
      assert.equal(fd, 1); if (kind === 'write') throw new Error('secret destination');
      return kind === 'partial' ? bytes.length - 1 : bytes.length;
    });
    t.mock.method(timers, 'setTimeout', async () => { throw new Error('timer failed'); });
    await assert.rejects(runControllerFleet(f, { signal: stopped.signal }),
      kind === 'timer' ? /timer failed/ : { code: 'OUTPUT' });
    assert.equal(polls, 1); assert.equal(closed, 1); t.mock.restoreAll();
  }
});

test('preaborted process loop closes without admission and invalid arguments never start work', async () => {
  let closed = 0; const f = fleet(async () => { closed++; }), signal = AbortSignal.abort();
  await runControllerFleet(f, { signal }); assert.equal(closed, 1);
  await assert.rejects(runControllerFleet({}, { signal }));
  for (const options of [{ signal: null }, { signal, outputFd: -1 }, { signal, extra: true }]) {
    const other = fleet(); await assert.rejects(runControllerFleet(other, options)); await other.close();
  }
});

test('CLI uses one file, handles real signal delivery, removes listeners, and never prints raw diagnostics', async (t) => {
  file(t, document()); const argv = process.argv, previous = process.env[variable];
  process.argv = ['node', 'owner-controller.mjs', '/config']; process.env[variable] = OPTIONS.token;
  t.after(() => { process.argv = argv; if (previous === undefined) delete process.env[variable]; else process.env[variable] = previous; });
  const before = ['SIGINT', 'SIGTERM'].map((event) => process.listenerCount(event));
  t.mock.method(OwnerControllerFleet.prototype, 'poll', () => {
    process.emit('SIGTERM'); process.emit('SIGTERM'); process.emit('SIGINT');
  });
  t.mock.method(timers, 'setTimeout', async () => { throw new Error('aborted'); });
  assert.equal(await controllerMain(), 0);
  assert.deepEqual(['SIGINT', 'SIGTERM'].map((event) => process.listenerCount(event)), before);
  process.argv = ['node', 'owner-controller.mjs'];
  const messages = [];
  const output = t.mock.method(fs, 'writeSync', (fd, bytes) => { assert.equal(fd, 2); messages.push(String(bytes)); return bytes.length; });
  assert.equal(await controllerMain(), 1); assert.equal(messages.length, 1);
  assert.equal(messages[0].includes(OPTIONS.token), false); output.mock.restore();
  t.mock.method(fs, 'writeSync', () => { throw new Error('private destination'); });
  assert.equal(await controllerMain(), 1);
});
