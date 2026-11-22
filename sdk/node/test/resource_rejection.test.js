/** Advisory metadata cannot create a new operation outcome or retry policy. */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseResourceRejection, resourceRejection } from '../src/resource_rejection.js';
import { Transport } from '../src/transport.js';
import { Client, RemoteError, UnknownError, CommittedResultError } from '../src/client.js';
import { SCOPE, commit } from './owner_fixture.js';

const HEADER = 'v=1;reason=intake_data_requests_tenant;used=40;limit=40;requested=1';
const COUNTED = {
  BACKPRESSURE: [
    'intake_data_requests_global', 'intake_data_requests_tenant', 'intake_data_body_global', 'intake_data_body_tenant',
    'intake_control_requests_global', 'intake_control_requests_tenant', 'intake_control_body_global', 'intake_control_body_tenant',
    'intake_recovery_requests_global', 'intake_recovery_requests_tenant', 'intake_recovery_body_global', 'intake_recovery_body_tenant',
    'intake_catalogue_requests_global', 'intake_catalogue_requests_tenant', 'intake_catalogue_body_global', 'intake_catalogue_body_tenant',
    'queue_global_total', 'queue_global_data', 'queue_tenant_total', 'queue_tenant_data', 'queue_database_total', 'queue_database_data',
    'actors_global', 'actors_tenant', 'output_base_shared_global', 'output_base_shared_tenant',
    'output_base_control_global', 'output_base_control_tenant', 'catalogue_queue_global', 'catalogue_queue_tenant',
    'catalogue_queue_name', 'restore_queue_global', 'restore_queue_tenant', 'restore_queue_name',
    'discovery_global', 'discovery_tenant', 'discovery_threads',
  ],
  LIMIT: ['output_growth_global', 'output_growth_tenant'],
  RECOVERY_BUSY: ['restore_staging_global', 'restore_staging_tenant'],
};
const SOURCES = {
  BACKPRESSURE: ['actor_draining', 'output_base_allocation'],
  LIMIT: ['output_growth_allocation'],
  RECOVERY_BUSY: ['native_recovery_busy', 'native_recovery_closed'],
};
const OPTIONS = { endpoint: 'http://127.0.0.1:8123/v1', token: 'synthetic-diagnostic-test-only-token' };
const REFERENCE = { scope: SCOPE, request: { epoch: '1', id: '9', principal: '7', fingerprint: 'a'.repeat(64) } };
const errorBody = (code, extra = {}) => ({ ok: false, error: { code, message: 'synthetic untrusted text', ...extra } });
const response = (body, status, header = HEADER) => new Response(JSON.stringify(body), {
  status, headers: { 'content-type': 'application/json', ...(header === null ? {} : { 'x-scap-rejection': header }) },
});

test('fixed counted and source-only rejection codebooks preserve immutable decimal strings', () => {
  assert.equal(Object.values(COUNTED).flat().length, 41);
  assert.equal(Object.values(SOURCES).flat().length, 5);
  for (const [code, reasons] of Object.entries(COUNTED)) for (const reason of reasons) {
    const value = parseResourceRejection(`v=1;reason=${reason};used=40;limit=40;requested=1`, code);
    assert.deepEqual(value, { version: 1, reason, used: '40', limit: '40', requested: '1' });
    assert.equal(Object.isFrozen(value), true);
    assert.throws(() => { value.used = '0'; }, TypeError);
    assert.equal(parseResourceRejection(`v=1;reason=${reason}`, code), undefined);
  }
  for (const [code, reasons] of Object.entries(SOURCES)) for (const reason of reasons) {
    const value = parseResourceRejection(`v=1;reason=${reason}`, code);
    assert.deepEqual(value, { version: 1, reason });
    assert.equal(Object.isFrozen(value), true);
    assert.equal(parseResourceRejection(`v=1;reason=${reason};used=1;limit=1;requested=1`, code), undefined);
  }
});

test('diagnostics reject unknown versions, reasons, codes, duplicate fields and noncanonical grammar', () => {
  const bad = [undefined, null, 1, {}, '', 'x'.repeat(257), HEADER + '\n', HEADER + '\r\n',
    'v=1;reason=actor_draining\n', 'v=1;reason=actor_draining\r\n',
    'v=1;reason=read_active_global', HEADER.replace('v=1', 'v=2'), HEADER.toUpperCase(),
    HEADER.replace('used=40', 'used=040'), HEADER.replace('used=40', 'used=-1'),
    HEADER.replace('used=40', 'used=4e1'), HEADER.replace('used=40', 'used=４０'),
    HEADER.replace('limit=40', 'limit=0'), HEADER.replace('requested=1', 'requested=0'),
    HEADER.replace('limit=40;requested=1', 'requested=1;limit=40'), HEADER + ';tenant=secret',
    HEADER + ';used=40', ' ' + HEADER, HEADER + ' ', HEADER + ', ' + HEADER];
  for (const value of bad) assert.equal(parseResourceRejection(value, 'BACKPRESSURE'), undefined, String(value));
  for (const code of [undefined, null, 429, 'LIMIT', 'UNKNOWN', 'COMMITTED_BUT_UNAVAILABLE', 'anything']) {
    assert.equal(parseResourceRejection(HEADER, code), undefined);
    assert.equal(parseResourceRejection('v=1;reason=actor_draining', code), undefined);
  }
  assert.equal(parseResourceRejection('v=1;reason=unknown', undefined), undefined);
  assert.equal(parseResourceRejection('v=1;reason=unknown;used=1;limit=1;requested=1', undefined), undefined);
});

test('u64 fields remain lossless and only an actual strict capacity violation is accepted', () => {
  const header = (used, limit, requested) => `v=1;reason=queue_database_data;used=${used};limit=${limit};requested=${requested}`;
  for (const [used, limit, requested] of [
    ['18446744073709551616', '18446744073709551615', '1'],
    ['0', '18446744073709551616', '1'], ['0', '1', '18446744073709551616'],
    ['41', '40', '1'], ['0', '40', '1'], ['39', '40', '1'],
  ]) assert.equal(parseResourceRejection(header(used, limit, requested), 'BACKPRESSURE'), undefined);
  for (const [used, limit, requested] of [
    ['9007199254740993', '9007199254740993', '1'],
    ['18446744073709551615', '18446744073709551615', '18446744073709551615'],
    ['0', '1', '2'],
  ]) assert.deepEqual(parseResourceRejection(header(used, limit, requested), 'BACKPRESSURE'),
    { version: 1, reason: 'queue_database_data', used, limit, requested });
});

test('missing or throwing optional header access yields no diagnostic', () => {
  assert.equal(resourceRejection(new Headers(), 'BACKPRESSURE'), undefined);
  assert.deepEqual(resourceRejection(new Headers({ 'x-scap-rejection': HEADER }), 'BACKPRESSURE'),
    { version: 1, reason: 'intake_data_requests_tenant', used: '40', limit: '40', requested: '1' });
  assert.equal(resourceRejection({ get() { throw new Error('untrusted header getter'); } }, 'BACKPRESSURE'), undefined);
});

test('validated remote rejection attaches readonly metadata without retrying or changing unresolved outcome', async () => {
  for (const [code, status, header, expected] of [
    ['BACKPRESSURE', 429, HEADER, { version: 1, reason: 'intake_data_requests_tenant', used: '40', limit: '40', requested: '1' }],
    ['LIMIT', 413, 'v=1;reason=output_growth_tenant;used=7;limit=8;requested=2',
      { version: 1, reason: 'output_growth_tenant', used: '7', limit: '8', requested: '2' }],
    ['RECOVERY_BUSY', 429, 'v=1;reason=native_recovery_busy', { version: 1, reason: 'native_recovery_busy' }],
    ['BACKPRESSURE', 429, null, undefined], ['BACKPRESSURE', 429, HEADER + ', ' + HEADER, undefined],
    ['BACKPRESSURE', 429, 'x'.repeat(257), undefined], ['LIMIT', 413, HEADER, undefined],
  ]) {
    let sent = 0;
    const transport = new Transport({ ...OPTIONS, fetch: async () => { ++sent; return response(errorBody(code), status, header); } });
    await assert.rejects(transport.call({ operation: 'execute' }, REFERENCE, () => assert.fail('must not decode error')), (error) => {
      assert.equal(error instanceof RemoteError, true);
      assert.equal(error.code, code); assert.equal(error.outcome, 'unresolved');
      assert.equal(error.reference, REFERENCE); assert.deepEqual(error.resourceRejection, expected);
      assert.equal(String(error).includes('untrusted'), false);
      if (expected !== undefined) {
        assert.equal(Object.isFrozen(error.resourceRejection), true);
        assert.throws(() => { error.resourceRejection = undefined; }, TypeError);
      } else assert.equal(Object.hasOwn(error, 'resourceRejection'), false);
      return true;
    });
    assert.equal(sent, 1);
  }
});

test('invalid metadata access preserves the already verified error envelope', async () => {
  const supplied = response(errorBody('BACKPRESSURE'), 429);
  const get = supplied.headers.get.bind(supplied.headers);
  supplied.headers.get = (name) => { if (name === 'x-scap-rejection') throw new Error('untrusted'); return get(name); };
  const transport = new Transport({ ...OPTIONS, fetch: async () => supplied });
  await assert.rejects(transport.call({ operation: 'execute' }, REFERENCE, () => {}), (error) =>
    error instanceof RemoteError && error.code === 'BACKPRESSURE' && error.outcome === 'unresolved' &&
    !Object.hasOwn(error, 'resourceRejection'));
});

test('metadata cannot replace UNKNOWN, a receipt, a malformed envelope, or a verified success', async () => {
  const receipt = commit(SCOPE, REFERENCE.request).receipt;
  for (const [body, status, expected] of [
    [errorBody('UNKNOWN'), 503, UnknownError],
    [errorBody('COMMITTED_BUT_UNAVAILABLE', { receipt }), 503, CommittedResultError],
    [errorBody('BACKPRESSURE'), 503, UnknownError],
    [errorBody('BACKPRESSURE', { receipt }), 429, UnknownError],
    [{ ok: 'false', error: { code: 'BACKPRESSURE', message: '' } }, 429, UnknownError],
  ]) {
    const supplied = response(body, status), get = supplied.headers.get.bind(supplied.headers);
    let metadataReads = 0;
    supplied.headers.get = (name) => { if (name === 'x-scap-rejection') ++metadataReads; return get(name); };
    const transport = new Transport({ ...OPTIONS, fetch: async () => supplied });
    await assert.rejects(transport.call({ operation: 'execute' }, REFERENCE, () => assert.fail('must not decode error')), (error) => {
      assert.equal(error instanceof expected, true);
      assert.equal(Object.hasOwn(error, 'resourceRejection'), false);
      if (expected === CommittedResultError) assert.deepEqual(error.receipt, receipt);
      else assert.equal(error.reference, REFERENCE);
      return true;
    });
    assert.equal(metadataReads, 0);
  }
  let sent = 0, metadataReads = 0;
  const client = new Client({ ...OPTIONS, scope: SCOPE, principal: '7', fetch: async (_url, init) => {
    ++sent;
    const original = JSON.parse(init.body), supplied = response({ ok: true, value: commit(SCOPE, original.request) }, 200);
    const get = supplied.headers.get.bind(supplied.headers);
    supplied.headers.get = (name) => { if (name === 'x-scap-rejection') ++metadataReads; return get(name); };
    return supplied;
  } });
  const original = client.prepare([{ sql: 'SELECT 1', parameters: [] }], { epoch: '1', id: '9' });
  const result = await client.execute(original);
  assert.equal(result.state, 'committed'); assert.deepEqual(result.receipt.request, original.request);
  assert.equal(sent, 1); assert.equal(metadataReads, 0);
});
