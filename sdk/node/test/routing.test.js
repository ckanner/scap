import { test } from 'node:test';
import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { Client, RoutedClient, ClientError, RemoteError, UnknownError, CommittedResultError, RouteError } from '../src/client.js';
import { RouteRegistry } from '../src/route_registry.js';
import { OPTIONS, SCOPE, A, B, EMPTY, clone, head, success, failure, commit, script } from './owner_fixture.js';

const SQL = [{ sql: 'SELECT ?1', parameters: [7n] }];
const ids = { epoch: '3', id: '51' };
const invalid = (fn) => assert.throws(fn, (e) => e instanceof ClientError && e.code === 'INVALID');

test('trusted routes validate and bound every endpoint and retain immutable caller context', () => {
  for (const routes of [null, [], Array(257).fill(OPTIONS.routes[0]),
    [{ workerInstance: '0', endpoint: A }], [OPTIONS.routes[0], OPTIONS.routes[0]],
    [OPTIONS.routes[0], { workerInstance: '200', endpoint: A }],
    [{ workerInstance: '100', endpoint: 'https://user:password@example.com/v1' }],
    [{ workerInstance: '100', endpoint: 'https://example.com/' }],
    [{ workerInstance: '100', endpoint: `https://example.com/${'x'.repeat(2048)}` }],
    [{ workerInstance: '100', endpoint: 7 }], [{ workerInstance: '100', endpoint: A, token: 'extra' }]]) {
    invalid(() => new RoutedClient({ ...OPTIONS, routes }));
  }
  invalid(() => new RoutedClient({ ...OPTIONS, bootstrapEndpoint: 'x'.repeat(2049) }));
  const many = Array.from({ length: 40 }, (_, i) => ({ workerInstance: String(i + 1), endpoint: `https://example.com/${i}/${'x'.repeat(1700)}` }));
  invalid(() => new RoutedClient({ ...OPTIONS, routes: many }));
  const options = { ...clone(OPTIONS), resultLimits: { maxRows: 5 }, allocation: { maxRows: 5 } };
  const registry = new RouteRegistry(options);
  const reordered = new RouteRegistry({ ...OPTIONS, routes: [...OPTIONS.routes].reverse() });
  assert.equal(registry.digest, reordered.digest);
  new RouteRegistry({ ...OPTIONS, routes: [OPTIONS.routes[1], { workerInstance: '50', endpoint: 'https://example.com/v1' }, OPTIONS.routes[0]] });
  options.scope.tenant = '99'; options.routes[1].endpoint = 'https://evil.invalid/v1';
  options.resultLimits.maxRows = 0; options.allocation.maxRows = 0;
  assert.equal(registry.direct.scope.tenant, '2'); assert.equal(registry.endpoint('200'), B);
  assert.equal(registry.timeout, 30000); assert.equal(registry.recoveryTimeout, 1800000);
  const configured = new RouteRegistry({ ...OPTIONS, timeoutMs: 42, recoveryTimeoutMs: 84 });
  assert.equal(configured.timeout, 42); assert.equal(configured.recoveryTimeout, 84);
  assert.throws(() => registry.endpoint('300'), { code: 'UNROUTABLE' });
});

test('routed writes discover fresh owner once and preserve the original prepared request', async () => {
  const io = script([head({ owner_instance: '200' }), (_url, body) => success(commit(body.scope, body.request)),
    head(), { state: 'unknown' }, { state: 'cancelled', transition: { revision: '12', nonce: ids.id } }]);
  const db = new RoutedClient({ ...OPTIONS, fetch: io.fetch });
  assert.deepEqual(db.scope, SCOPE); assert.equal(db.principal, '7');
  const request = db.prepare(SQL, ids), restored = db.restore(db.save(request));
  const result = await db.execute(restored);
  assert.equal(result.state, 'committed'); assert.deepEqual(result.receipt.request, request.request);
  assert.deepEqual(io.calls.map((c) => [c.url, c.body.operation]), [[A, 'status'], [B, 'execute']]);
  assert.deepEqual(io.calls[1].body.statements, request.statements);
  await db.status(); assert.equal((await db.lookup(request)).state, 'unknown');
  assert.equal((await db.cancel(request)).state, 'cancelled');
  assert.deepEqual(io.calls.slice(2).map((c) => [c.url, c.body.operation]), [[A, 'status'], [A, 'lookup'], [A, 'cancel']]);
});

test('routed query snapshots caller parameters before discovery and permits Maintenance reads', async () => {
  const bytes = new Uint8Array([1, 2]), input = [{ sql: 'SELECT ?1', parameters: [bytes] }];
  const io = script([() => { bytes.fill(9); input[0].sql = 'DROP TABLE x'; return success(head({ lifecycle: 'maintenance', active: false })); },
    { result: EMPTY.toString('base64') }]);
  const db = new RoutedClient({ ...OPTIONS, fetch: io.fetch });
  assert.deepEqual((await db.query(input)).statements, []);
  assert.equal(io.calls[1].body.statements[0].sql, 'SELECT ?1');
  assert.equal(io.calls[1].body.statements[0].params[0].base64, 'AQI=');
  assert.equal(io.calls[1].url, A);
});

test('routing failures never dispatch SQL or attempt takeover', async () => {
  for (const [status, code, operation] of [
    [head({ owner_instance: '300' }), 'UNROUTABLE', 'execute'], [head({ active: false }), 'OWNER_INACTIVE', 'execute'],
    [head({ lifecycle: 'maintenance' }), 'LIFECYCLE', 'execute'], [head({ lifecycle: 'deleted' }), 'LIFECYCLE', 'execute'],
    [head({ lifecycle: 'deleted' }), 'LIFECYCLE', 'query'], [head({ scope: { ...SCOPE, generation: '6' } }), 'INVALID', 'execute'],
  ]) {
    const io = script([status]), db = new RoutedClient({ ...OPTIONS, fetch: io.fetch });
    await assert.rejects(db[operation](operation === 'execute' ? db.prepare(SQL, ids) : SQL),
      (e) => e instanceof RouteError && e.code === code && e.outcome === 'not_sent');
    assert.equal(io.calls.length, 1);
  }
  for (const [code, http] of [['DENIED', 403], ['BACKPRESSURE', 429], ['UNKNOWN', 503]]) {
    const io = script([() => failure(code, http)]), db = new RoutedClient({ ...OPTIONS, fetch: io.fetch });
    await assert.rejects(db.execute(db.prepare(SQL, ids)), (e) => e instanceof RouteError && e.code === code);
    assert.equal(io.calls.length, 1);
  }
  const io = script([]), db = new RoutedClient({ ...OPTIONS, fetch: io.fetch });
  await assert.rejects(db.execute({}), RouteError); assert.equal(io.calls.length, 0);
  const controller = new AbortController(); controller.abort();
  await assert.rejects(db.query(SQL, { signal: controller.signal }), { code: 'ABORTED' });
});

test('after one SQL dispatch FENCED, conflict and transport uncertainty never reroute or replay', async () => {
  for (const next of [() => failure('FENCED'), () => failure('CONFLICT'), () => { throw new Error('secret'); },
    () => failure('UNKNOWN', 503)]) {
    const io = script([head({ owner_instance: '200' }), next]), db = new RoutedClient({ ...OPTIONS, fetch: io.fetch });
    const request = db.prepare(SQL, ids);
    await assert.rejects(db.execute(request), (e) => (e instanceof RemoteError || e instanceof UnknownError) && e.reference.request.id === ids.id);
    assert.deepEqual(io.calls.map((c) => c.body.operation), ['status', 'execute']);
  }
});

test('optional destination guard is sent exactly and retained in direct UNKNOWN references', async () => {
  const io = script([head({ revision: '11', transition: { revision: '11', nonce: '21' } }),
    () => { throw new Error('lost response'); }, () => failure('TARGET_MISMATCH')]);
  const db = new Client({ endpoint: A, token: OPTIONS.token, scope: SCOPE, principal: '7', fetch: io.fetch });
  const input = { expectedRevision: '10', nonce: '21', expectedWorkerInstance: '100' };
  await db.takeover(input);
  assert.equal(io.calls[0].body.expected_worker_instance, '100');
  await assert.rejects(db.activate(input), (e) => e instanceof UnknownError && e.reference.expectedWorkerInstance === '100');
  await assert.rejects(db.takeover(input), (e) => e instanceof RemoteError && e.code === 'TARGET_MISMATCH');
  for (const expectedWorkerInstance of ['0', null, 100, '01']) invalid(() => db.takeover({ ...input, expectedWorkerInstance }));
  invalid(() => db.closeFull(input));
});

test('absolute routed deadline forbids a business Fetch after synchronous serialization', async (t) => {
  let now = 0;
  t.mock.method(performance, 'now', () => now);
  const original = JSON.stringify;
  t.mock.method(JSON, 'stringify', (value, ...rest) => {
    const result = original(value, ...rest);
    if (value?.operation === 'execute') now = 11;
    return result;
  });
  const io = script([head()]), db = new RoutedClient({ ...OPTIONS, fetch: io.fetch });
  await assert.rejects(db.execute(db.prepare(SQL, ids), { timeoutMs: 10 }),
    (e) => e instanceof RouteError && e.outcome === 'not_sent');
  assert.deepEqual(io.calls.map((c) => c.body.operation), ['status']);
});

test('absolute routed deadline preserves a verified commit after the final materialization', async (t) => {
  let now = 0;
  t.mock.method(performance, 'now', () => now);
  const original = JSON.stringify;
  t.mock.method(JSON, 'stringify', (value, ...rest) => {
    const result = original(value, ...rest);
    if (value?.operation === 'execute') now = 9.5;
    return result;
  });
  const io = script([() => { now = 9; return success(head()); }, (_url, body) => {
    now = 10.1; return success(commit(body.scope, body.request));
  }]);
  const db = new RoutedClient({ ...OPTIONS, fetch: io.fetch }), request = db.prepare(SQL, ids);
  await assert.rejects(db.execute(request, { timeoutMs: 10 }),
    (e) => e instanceof CommittedResultError && e.code === 'DEADLINE' && e.receipt.request.id === ids.id);
  assert.equal(io.calls.length, 2);
});
