/** Fixed, explicit owner policy. No token, clock, lease or server-provided URL is authority. */
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { record, requireValue, decimal, scope } from './wire.js';

export const CONTROLLER_LIMITS = Object.freeze({
  scopes: 128, workers: 256, metadataEndpoints: 4, policyBytes: 65536,
  ticks: 8, tenantTicks: 4, recoveries: 1, httpCalls: 8, mutations: 1,
  requestBytes: 16384, responseBytes: 65536, headerBytes: 16384,
  timeoutMs: 30000, recoveryTimeoutMs: 1800000, probeTimeoutMs: 1000, tickIntervalMs: 5000,
  failureCount: 3, failureIntervalMs: 1000, failureSpanMs: 5000,
  backoffMs: Object.freeze([5000, 10000, 20000, 40000, 60000]),
});

const BRANDED = new WeakSet();
const PHASES = ['claim', 'cancel', 'activate', 'abort'];

/** Four lossless big-endian u64 words; reject, never salt or truncate, an unusable digest. */
export function controllerNonces(digest) {
  requireValue(typeof digest === 'string' && /^[0-9a-f]{64}$/.test(digest), 'Expected a full policy SHA-256');
  const bytes = Buffer.from(digest, 'hex');
  const values = PHASES.map((_, index) => bytes.readBigUInt64BE(index * 8).toString());
  requireValue(values.every((value) => value !== '0') && new Set(values).size === 4,
    'Policy digest must contain four nonzero distinct u64 words');
  return Object.freeze(Object.fromEntries(PHASES.map((phase, index) => [phase, values[index]])));
}

function endpoint(value, insecure) {
  requireValue(typeof value === 'string' && Buffer.byteLength(value) <= 2048, 'Expected a bounded endpoint');
  let url;
  try { url = new URL(value); } catch { throw new TypeError('Invalid controller endpoint'); }
  requireValue(url.username === '' && url.password === '' && url.search === '' && url.hash === '' &&
    url.pathname !== '/', 'Controller endpoints require an API path and no credentials, query or fragment');
  requireValue(url.protocol === 'https:' || (url.protocol === 'http:' &&
    (insecure || ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname))), 'Controller endpoint requires HTTPS');
  return url.href;
}

export function controllerScopeKey(value) { return JSON.stringify(scope(value)); }

/** Canonical collection order is independent of caller object/array order. */
export function createControllerPolicy(value) {
  record(value, ['scope', 'authorityId', 'principal', 'metadataEndpoints', 'workers', 'modes'],
    ['allowInsecureHttp', 'recoveryTimeoutMs', 'retiredWorkers']);
  const insecure = value.allowInsecureHttp === undefined ? false : value.allowInsecureHttp;
  requireValue(typeof insecure === 'boolean', 'Expected explicit HTTP permission');
  const recoveryTimeoutMs = value.recoveryTimeoutMs === undefined ? CONTROLLER_LIMITS.recoveryTimeoutMs : value.recoveryTimeoutMs;
  requireValue(Number.isSafeInteger(recoveryTimeoutMs) && recoveryTimeoutMs > 0 &&
    recoveryTimeoutMs <= CONTROLLER_LIMITS.recoveryTimeoutMs, 'Recovery deadline exceeds controller policy');
  requireValue(typeof value.authorityId === 'string' && /^[A-Za-z0-9_.:-]{1,128}$/.test(value.authorityId),
    'Expected a bounded authority identity');
  requireValue(Array.isArray(value.metadataEndpoints) && value.metadataEndpoints.length > 0 &&
    value.metadataEndpoints.length <= CONTROLLER_LIMITS.metadataEndpoints, 'Expected one to four metadata endpoints');
  const metadataEndpoints = value.metadataEndpoints.map((item) => endpoint(item, insecure)).sort();
  requireValue(new Set(metadataEndpoints).size === metadataEndpoints.length, 'Duplicate metadata endpoint');
  requireValue(Array.isArray(value.workers) && value.workers.length > 0 &&
    value.workers.length <= CONTROLLER_LIMITS.workers, 'Expected one to 256 fixed worker incarnations');
  const workers = value.workers.map((worker) => {
    record(worker, ['workerInstance', 'endpoint', 'rank']);
    requireValue(Number.isSafeInteger(worker.rank) && worker.rank >= 0 && worker.rank <= 65535,
      'Expected a bounded worker rank');
    return Object.freeze({ workerInstance: decimal(worker.workerInstance), endpoint: endpoint(worker.endpoint, insecure),
      rank: worker.rank });
  }).sort((a, b) => a.rank - b.rank);
  const retiredWorkers = value.retiredWorkers === undefined ? [] : value.retiredWorkers;
  requireValue(Array.isArray(retiredWorkers) && retiredWorkers.length <= workers.length,
    'Expected a bounded explicit worker retirement list');
  const retired = Object.freeze(retiredWorkers.map((id) => decimal(id)).sort((a, b) => BigInt(a) < BigInt(b) ? -1 : 1));
  requireValue(new Set(retired).size === retired.length &&
    retired.every((id) => workers.some((worker) => worker.workerInstance === id)),
    'Retire only distinct registered worker identities');
  for (const key of ['workerInstance', 'rank']) {
    requireValue(new Set(workers.map((worker) => worker[key])).size === workers.length, 'Duplicate worker, endpoint or rank');
  }
  const live = workers.filter((worker) => !retired.includes(worker.workerInstance));
  requireValue(new Set(live.map((worker) => worker.endpoint)).size === live.length,
    'An endpoint cannot represent two live worker incarnations');
  record(value.modes, ['takeover', 'activate', 'cancel']);
  const modes = Object.freeze(Object.fromEntries(['takeover', 'activate', 'cancel'].map((key) => {
    requireValue(typeof value.modes[key] === 'boolean', 'Expected an explicit automatic owner mode');
    return [key, value.modes[key]];
  })));
  const policy = { version: 1, scope: scope(value.scope), authorityId: value.authorityId,
    principal: decimal(value.principal), metadataEndpoints: Object.freeze(metadataEndpoints),
    workers: Object.freeze(workers), modes, allowInsecureHttp: insecure,
    limits: Object.freeze({ ...CONTROLLER_LIMITS, recoveryTimeoutMs }),
    // Preserve the original v1 commitment byte-for-byte for policies without
    // retirement. Every retirement decision is included in the new digest.
    ...(retired.length === 0 ? {} : { retiredWorkers: retired }) };
  const canonical = JSON.stringify(policy);
  requireValue(Buffer.byteLength(canonical) <= CONTROLLER_LIMITS.policyBytes, 'Controller policy exceeds 64 KiB');
  const digest = createHash('sha256').update('SCAPOWNERPOLICY1\0').update(canonical).digest('hex');
  const fixed = Object.freeze({ ...policy, canonical, digest, nonces: controllerNonces(digest) });
  BRANDED.add(fixed);
  return fixed;
}

export function checkControllerPolicy(value) {
  requireValue(BRANDED.has(value), 'Construct a fixed controller policy before starting it');
  return value;
}

/** Input has already passed the strict owner wire decoder. This verifies the entire policy commitment. */
export function belongsToController(policy, input) {
  return input.creator === policy.principal && input.operation === input.expected_head_serial &&
    PHASES.every((phase) => input.nonces[phase] === policy.nonces[phase]) &&
    policy.modes[input.mode] === true && policy.workers.some((worker) => worker.workerInstance === input.target_worker);
}
