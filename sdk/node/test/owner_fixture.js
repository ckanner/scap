import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';

export const SCOPE = { deployment: '1', tenant: '2', database: '3', incarnation: '4', generation: '5' };
export const A = 'http://127.0.0.1:8100/v1', B = 'http://127.0.0.1:8200/v1';
export const OPTIONS = { bootstrapEndpoint: A,
  routes: [{ workerInstance: '100', endpoint: A }, { workerInstance: '200', endpoint: B }],
  token: 'synthetic-owner-test-only-credential', scope: SCOPE, principal: '7' };
export const EMPTY = Buffer.from('534341505245533100000000', 'hex');
export const clone = (value) => JSON.parse(JSON.stringify(value));
export function head(changes = {}) {
  const revision = changes.revision ?? '10';
  return { scope: clone(SCOPE), revision, head_serial: revision, owner_plan: null,
    storage: { active_generation: '1', allocated_through: '1', plan: null, sweep: null, terminal: null },
    sequence: '0', owner_epoch: '2', owner_instance: '100', active: true,
    auth_epoch: '1', lifecycle: 'ready', request_epoch: '3', max_bytes: null,
    retention: { max_entries: 4096, max_result_bytes: '268435456', oldest_epoch: '1' },
    transition: { revision, nonce: '9' }, ...changes };
}
export const claim = () => head({ revision: '11', owner_epoch: '3', owner_instance: '200', active: false,
  transition: { revision: '11', nonce: '21' } });
export const activated = () => head({ revision: '12', owner_epoch: '3', owner_instance: '200', active: true,
  transition: { revision: '12', nonce: '22' } });
export const takeover = { targetWorker: '200', takeoverNonce: '21', activateNonce: '22' };
export const success = (value) => new Response(JSON.stringify({ ok: true, value }),
  { status: 200, headers: { 'content-type': 'application/json' } });
export const failure = (code, status = 409) => new Response(JSON.stringify({ ok: false, error: { code, message: code } }),
  { status, headers: { 'content-type': 'application/json' } });

/** Independent little-endian object envelope fixture, with full-width JSON integers. */
export function commit(scope, request) {
  const receipt = { scope, request, sequence: '1', transition: { revision: '11', nonce: request.id },
    data_root: 'a'.repeat(64), result_hash: '' };
  function integers(value) {
    if (typeof value === 'bigint') return String(value);
    if (Array.isArray(value)) return `[${value.map(integers).join(',')}]`;
    if (value !== null && typeof value === 'object') {
      return `{${Object.entries(value).map(([key, child]) => `${JSON.stringify(key)}:${integers(child)}`).join(',')}}`;
    }
    return JSON.stringify(value);
  }
  const metadata = Buffer.from(integers({ format: 2,
    scope: Object.fromEntries(Object.entries(scope).map(([key, value]) => [key, BigInt(value)])),
    payload: { kind: 'result', value: {
      request: { epoch: BigInt(request.epoch), id: BigInt(request.id), principal: BigInt(request.principal), fingerprint: request.fingerprint },
      sequence: 1n, transition: { revision: 11n, nonce: BigInt(request.id) }, data_root: receipt.data_root, bytes: [],
    } },
  }));
  const sizes = Buffer.alloc(12);
  sizes.writeUInt32LE(metadata.length); sizes.writeBigUInt64LE(BigInt(EMPTY.length), 4);
  receipt.result_hash = createHash('sha256').update(Buffer.concat([Buffer.from('SCAPOBJ2'), sizes, metadata, EMPTY])).digest('hex');
  return { state: 'committed', receipt, result: EMPTY.toString('base64') };
}

export function script(responses) {
  const calls = [];
  const fetch = async (url, init) => {
    const body = JSON.parse(init.body);
    calls.push({ url, body, init });
    const next = responses.shift();
    if (next === undefined) throw new Error('unexpected extra request');
    return typeof next === 'function' ? next(url, body, init) : success(next);
  };
  return { calls, fetch };
}
