import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Client, CatalogueClient, ClientError, RemoteError, UnknownError } from '../src/client.js';
import * as wire from '../src/wire.js';
import { head, SCOPE, clone, success, failure } from './owner_fixture.js';

const DIRECT = { endpoint: 'http://127.0.0.1:8123/v1', token: 'synthetic-terminal-only-credential', scope: SCOPE, principal: '7' };
const NAMED = { endpoint: 'http://127.0.0.1:8123/v1/catalogue', token: DIRECT.token,
  deployment: SCOPE.deployment, tenant: SCOPE.tenant, principal: '7' };
// A current ADMIN may differ from the original creator and need not provision.
const CREATION = { creator: '19', operation: '23', name: 'deleted-name', scope: SCOPE, expected_name_revision: null };
const deleted = () => head({ lifecycle: 'deleted' });
function sealed() {
  const value = deleted();
  value.active = false; value.head_serial = '11'; value.storage.terminal = { serial: '11' };
  return value;
}
function checkpoint() {
  const value = sealed(); value.head_serial = '12';
  value.storage.sweep = { serial: '12', generation: '1', next_after: null, exhausted: true,
    pending: 1, applied: 0, observed_absent: 0, condition_mismatch: 0 };
  return value;
}
const sweepReport = (status = checkpoint()) => ({ status, generation: '1', scanned: 1, next_after: null, exhausted: true });
const invalid = (fn) => assert.throws(fn, (e) => e instanceof ClientError && e.code === 'INVALID');

test('terminal metadata has required presence, frozen allocation and strictly later checkpoint serial', () => {
  for (const value of [deleted(), sealed(), checkpoint()]) {
    assert.deepEqual(wire.storageStatus(value, SCOPE), value);
  }
  const result = wire.storageStatus(sealed(), SCOPE);
  assert.equal(Object.isFrozen(result.storage.terminal), true);
  for (const mutate of [
    (v) => delete v.storage.terminal,
    (v) => v.storage.terminal = {},
    (v) => v.storage.terminal.serial = '0',
    (v) => v.storage.terminal.extra = 'untrusted',
    (v) => v.storage.terminal.serial = '12',
    (v) => v.storage.terminal.serial = '10',
    (v) => v.storage.terminal.serial = '9',
    (v) => v.storage.allocated_through = '11',
    (v) => v.lifecycle = 'ready',
    (v) => v.lifecycle = 'maintenance',
    (v) => v.active = true,
    (v) => v.storage.plan = { serial: '10', source: '1', target: '2', phase: 'sealed' },
  ]) {
    const value = sealed(); mutate(value); invalid(() => wire.status(value, SCOPE));
  }
  invalid(() => wire.storageStatus(head(), SCOPE));
  for (const serial of ['10', '11']) {
    const value = checkpoint(); value.storage.sweep.serial = serial;
    invalid(() => wire.status(value, SCOPE));
  }
  const large = sealed(); large.head_serial = '18446744073709551615';
  large.storage.terminal.serial = large.head_serial;
  assert.deepEqual(wire.storageStatus(large, SCOPE), large);
});

test('terminal sweep may collect historical A but unsealed Deleted never grants retirement', () => {
  assert.deepEqual(wire.sweepReport(sweepReport(), SCOPE), sweepReport());
  const cleared = sealed(); cleared.head_serial = '14';
  assert.deepEqual(wire.sweepReport(sweepReport(cleared), SCOPE), sweepReport(cleared));
  for (const mutate of [
    (v) => v.status.storage.terminal = null,
    (v) => v.generation = '2',
    (v) => v.status.storage.sweep.generation = '2',
  ]) {
    const value = sweepReport(); mutate(value); invalid(() => wire.sweepReport(value, SCOPE));
  }
});

test('direct retirement sends one control POST and keeps its original physical serial', async () => {
  const calls = [];
  const client = new Client({ ...DIRECT, fetch: async (_url, init) => {
    const body = JSON.parse(init.body); calls.push({ body, admission: init.headers['x-scap-admission'] });
    return success(body.operation === 'storage_status' ? deleted() : sealed());
  } });
  assert.deepEqual(await client.storageStatus(), deleted());
  assert.deepEqual(await client.retireStorage({ expectedHeadSerial: '10' }), sealed());
  assert.deepEqual(calls, [
    { body: { version: 1, scope: SCOPE, operation: 'storage_status' }, admission: 'control' },
    { body: { version: 1, scope: SCOPE, operation: 'retire_storage', expected_head_serial: '10' }, admission: 'control' },
  ]);
  for (const input of [{}, { expectedHeadSerial: 10 }, { expectedHeadSerial: '0' },
    { expectedHeadSerial: '10', etag: 'forbidden' }]) invalid(() => client.retireStorage(input));
  assert.equal(calls.length, 2);
  for (const value of [deleted(), { ...deleted(), head_serial: '11' }, checkpoint(), { ...sealed(), head_serial: '12' },
    { ...sealed(), storage: { ...sealed().storage, terminal: { serial: '10' } } }]) {
    const bad = new Client({ ...DIRECT, fetch: async () => success(value) });
    await assert.rejects(bad.retireStorage({ expectedHeadSerial: '10' }), (e) => e instanceof UnknownError);
  }
  // A later checkpoint publication can advance HEAD without installing a new
  // seal. Its serial alone cannot acknowledge this original retire operation.
  const priorSeal = { ...sealed(), head_serial: '12' };
  assert.deepEqual(wire.storageStatus(priorSeal, SCOPE), priorSeal);
  const unrelated = new Client({ ...DIRECT, fetch: async () => success(priorSeal) });
  await assert.rejects(unrelated.retireStorage({ expectedHeadSerial: '11' }),
    (e) => e instanceof UnknownError && e.reference.expectedHeadSerial === '11');
});

test('named storage management persists exact Creation and condition without creator-only admission', async () => {
  const calls = [];
  const client = new CatalogueClient({ ...NAMED, fetch: async (_url, init) => {
    const body = JSON.parse(init.body); calls.push({ body, admission: init.headers['x-scap-admission'] });
    return success(body.operation === 'named_storage_status' ? deleted() : sealed());
  } });
  assert.deepEqual(await client.storageStatus(CREATION), deleted());
  const input = { creation: CREATION, expected_head_serial: '10' };
  const original = client.prepareIntent({ operation: 'retire_named_storage', ...input });
  const saved = client.saveIntent(original);
  assert.deepEqual(await client.submit(client.restoreIntent(saved)), sealed());
  assert.deepEqual(await client.retireStorage(input), sealed());
  assert.deepEqual(calls.map((c) => c.body.operation), ['named_storage_status', 'retire_named_storage', 'retire_named_storage']);
  assert(calls.every((c) => c.admission === 'catalogue'));
  assert.deepEqual(calls[1].body, { version: 1, operation: 'retire_named_storage', ...input });
  assert.equal(client.saveIntent(original), saved);
  invalid(() => client.retireStorage({ creation: CREATION }));
  invalid(() => client.retireStorage({ ...input, expected_head_serial: '0' }));
  invalid(() => client.storageStatus({ ...CREATION, scope: { ...SCOPE, tenant: '999' } }));
  invalid(() => client.retireStorage({ ...input, expected_head_serial: '10', keys: ['forbidden'] }));
  assert.equal(calls.length, 3);
  for (const operation of ['named_storage_status', 'retire_named_storage']) {
    const action = operation === 'named_storage_status' ? { operation, creation: CREATION } : { operation, ...input };
    const intent = client.prepareIntent(action);
    assert.deepEqual(client.restoreIntent(client.saveIntent(intent)), intent);
  }
});

test('retirement UNKNOWN preserves original intent and metadata reads never turn transport failure into replay', async () => {
  for (const named of [false, true]) {
    let calls = 0;
    const client = named ? new CatalogueClient({ ...NAMED, fetch: async () => { calls++; throw Error('lost'); } }) :
      new Client({ ...DIRECT, fetch: async () => { calls++; throw Error('lost'); } });
    const input = named ? { creation: CREATION, expected_head_serial: '10' } : { expectedHeadSerial: '10' };
    await assert.rejects(client.retireStorage(input), (e) => {
      assert(e instanceof UnknownError);
      if (named) assert.equal(e.reference.intent.action.expected_head_serial, '10');
      else assert.equal(e.reference.expectedHeadSerial, '10');
      return true;
    });
    await assert.rejects(named ? client.storageStatus(CREATION) : client.storageStatus(),
      (e) => e instanceof ClientError && !(e instanceof UnknownError) && e.code === 'TRANSPORT');
    assert.equal(calls, 2);
  }
  for (const code of ['CONFLICT', 'DENIED', 'IDENTITY_CONFLICT', 'LIFECYCLE']) {
    const http = code === 'DENIED' ? 403 : 409;
    const client = new Client({ ...DIRECT, fetch: async () => failure(code, http) });
    await assert.rejects(client.retireStorage({ expectedHeadSerial: '10' }),
      (e) => e instanceof RemoteError && e.code === code && e.outcome === 'unresolved');
  }
});

test('GC uses its existing recovery class for a sealed final generation and preserves terminal metadata', async () => {
  const calls = [];
  const client = new Client({ ...DIRECT, fetch: async (_url, init) => {
    const body = JSON.parse(init.body); calls.push({ body, admission: init.headers['x-scap-admission'] });
    if (body.operation === 'gc_prepare') return success(sweepReport());
    const done = sealed(); done.head_serial = '14'; return success(sweepReport(done));
  } });
  assert.equal((await client.gcPrepare({ expectedHeadSerial: '11', generation: '1', after: null })).status.storage.terminal.serial, '11');
  assert.equal((await client.gcResume({ batchSerial: '12' })).status.storage.terminal.serial, '11');
  assert(calls.every((c) => c.admission === 'recovery'));
  assert.equal(calls.length, 2);
});
