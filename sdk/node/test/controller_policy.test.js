import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createControllerPolicy, controllerNonces, controllerScopeKey, checkControllerPolicy,
  belongsToController, CONTROLLER_LIMITS } from '../src/controller_policy.js';
import { SCOPE, A, B, clone } from './owner_fixture.js';

export const config = (extra = {}) => ({ scope: clone(SCOPE), authorityId: 'deployment-test', principal: '7',
  metadataEndpoints: [A, B], workers: [{ workerInstance: '100', endpoint: A, rank: 0 },
    { workerInstance: '200', endpoint: B, rank: 1 }], modes: { takeover: true, activate: true, cancel: true }, ...extra });
export const policy = (extra = {}) => createControllerPolicy(config(extra));
export const input = (p, extra = {}) => ({ creator: '7', operation: '10', expected_revision: '10',
  expected_head_serial: '10', mode: 'activate', target_worker: '100', nonces: p.nonces, ...extra });

test('policy commits the complete canonical policy to four lossless fixed u64 words', () => {
  const c = config(), p = createControllerPolicy(c);
  assert.equal(checkControllerPolicy(p), p);
  assert.equal(p.digest, createHash('sha256').update(Buffer.from('SCAPOWNERPOLICY1\0')).update(p.canonical).digest('hex'));
  const bytes = Buffer.alloc(32);
  ['claim', 'cancel', 'activate', 'abort'].forEach((key, index) => bytes.writeBigUInt64BE(BigInt(p.nonces[key]), index * 8));
  assert.equal(bytes.toString('hex'), p.digest);
  const shuffled = config({ workers: [...c.workers].reverse(), metadataEndpoints: [...c.metadataEndpoints].reverse(),
    scope: Object.fromEntries(Object.entries(SCOPE).reverse()), modes: { cancel: true, activate: true, takeover: true } });
  assert.equal(createControllerPolicy(shuffled).canonical, p.canonical);
  assert.equal(controllerScopeKey(shuffled.scope), controllerScopeKey(SCOPE));
  c.workers[0].rank = 99; c.metadataEndpoints[0] = 'https://wrong.example/v1';
  assert.equal(p.workers[0].rank, 0); assert.equal(p.metadataEndpoints[0], A);
  for (const value of [p, p.scope, p.workers, p.workers[0], p.metadataEndpoints, p.modes, p.nonces, p.limits, p.limits.backoffMs]) {
    assert.equal(Object.isFrozen(value), true);
  }
  assert.throws(() => checkControllerPolicy(clone(p)));
  assert.equal(belongsToController(p, input(p)), true);
  for (const change of [{ creator: '8' }, { operation: '9' }, { nonces: { ...p.nonces, abort: '1' } },
    { mode: 'unrecognized' }, { target_worker: '300' }]) assert.equal(belongsToController(p, input(p, change)), false);
  assert.notEqual(policy({ authorityId: 'different' }).digest, p.digest);
  assert.notEqual(policy({ recoveryTimeoutMs: 5000 }).digest, p.digest);
  assert.equal(CONTROLLER_LIMITS.httpCalls, 8); assert.equal(CONTROLLER_LIMITS.mutations, 1);
});

test('policy rejects malformed or ambiguous registries and refuses unusable digest words without salting', () => {
  for (const digest of ['0'.repeat(64), '1'.repeat(64), 'A'.repeat(64), 'f'.repeat(63), null]) assert.throws(() => controllerNonces(digest));
  const mutations = [
    (x) => x.extra = true, (x) => x.scope.generation = '0', (x) => x.principal = '01',
    (x) => x.allowInsecureHttp = null, (x) => x.recoveryTimeoutMs = 0, (x) => x.recoveryTimeoutMs = 1800001,
    (x) => x.authorityId = '', (x) => x.authorityId = 'contains space',
    (x) => x.metadataEndpoints = [], (x) => x.metadataEndpoints = [A, A],
    (x) => x.metadataEndpoints = Array(5).fill(A), (x) => x.metadataEndpoints = ['not-a-url'],
    (x) => x.metadataEndpoints = ['https://user:password@example.test/v1'],
    (x) => x.metadataEndpoints = ['https://example.test/'], (x) => x.metadataEndpoints = ['https://example.test/v1?query=1'],
    (x) => x.metadataEndpoints = ['https://example.test/v1#fragment'], (x) => x.metadataEndpoints = ['http://example.test/v1'],
    (x) => x.metadataEndpoints = ['ftp://example.test/v1'], (x) => x.metadataEndpoints = [7],
    (x) => x.metadataEndpoints = ['https://example.test/' + 'a'.repeat(2048)],
    (x) => x.workers = [], (x) => x.workers = Array(257).fill(x.workers[0]),
    (x) => x.workers[0].rank = -1, (x) => x.workers[0].rank = 65536, (x) => x.workers[0].rank = 0.5,
    (x) => x.workers[1].rank = 0, (x) => x.workers[1].workerInstance = '100', (x) => x.workers[1].endpoint = A,
    (x) => x.modes.activate = 1,
    (x) => x.workers = Array.from({ length: 64 }, (_, i) => ({ workerInstance: String(i + 1), rank: i,
      endpoint: 'https://example.test/' + String(i) + 'a'.repeat(1024) })),
  ];
  for (const change of mutations) { const value = config(); change(value); assert.throws(() => createControllerPolicy(value)); }
  assert.equal(policy({ allowInsecureHttp: true, metadataEndpoints: ['http://example.test/v1'] }).allowInsecureHttp, true);
  assert.equal(policy({ metadataEndpoints: ['https://example.test/v1'] }).metadataEndpoints[0], 'https://example.test/v1');
});
