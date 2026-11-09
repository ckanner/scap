/** Fixed administrative transitions; restored descriptions never imply unsent. */
import { Buffer } from 'node:buffer';
import { ClientError } from './errors.js';
import { record, requireValue, decimal, scope, sameScope, status, parseJson } from './wire.js';

const TRACKED = new WeakMap();
const FIELDS = ['version', 'scope', 'principal', 'registryDigest', 'mode', 'baseRevision',
  'baseOwnerEpoch', 'baseOwnerInstance', 'baseActive', 'targetWorker', 'takeoverNonce', 'activateNonce'];

export function increment(value, by = 1n) { return decimal(String(BigInt(value) + by)); }

function normalize(value, registry) {
  record(value, FIELDS);
  requireValue(value.version === 1 && ['takeover', 'activate'].includes(value.mode), 'Unsupported owner intent');
  const fixed = { ...value, scope: scope(value.scope) };
  sameScope(fixed.scope, registry.direct.scope);
  requireValue(decimal(value.principal) === registry.direct.principal && value.registryDigest === registry.digest,
    'Owner intent does not match this principal and trusted registry');
  for (const key of ['baseRevision', 'baseOwnerEpoch', 'baseOwnerInstance', 'targetWorker', 'activateNonce']) decimal(value[key]);
  requireValue(typeof value.baseActive === 'boolean', 'Expected the observed activation state');
  registry.endpoint(value.targetWorker);
  if (value.mode === 'takeover') {
    decimal(value.takeoverNonce);
    requireValue(value.targetWorker !== value.baseOwnerInstance && value.takeoverNonce !== value.activateNonce,
      'Takeover requires a different worker and distinct transition nonces');
    increment(value.baseRevision, 2n);
    increment(value.baseOwnerEpoch);
  } else {
    requireValue(value.takeoverNonce === null && !value.baseActive && value.targetWorker === value.baseOwnerInstance,
      'Activation requires the current inactive owner');
    increment(value.baseRevision);
  }
  return Object.freeze(fixed);
}

export function prepareIntent(registry, observed, input, mode) {
  const head = status(observed, registry.direct.scope);
  requireValue(head.lifecycle === 'ready', 'Owner transitions require the Ready lifecycle');
  record(input, mode === 'takeover' ? ['targetWorker', 'takeoverNonce', 'activateNonce'] : ['activateNonce']);
  const intent = normalize({ version: 1, scope: head.scope, principal: registry.direct.principal,
    registryDigest: registry.digest, mode, baseRevision: head.revision, baseOwnerEpoch: head.owner_epoch,
    baseOwnerInstance: head.owner_instance, baseActive: head.active,
    targetWorker: mode === 'takeover' ? input.targetWorker : head.owner_instance,
    takeoverNonce: mode === 'takeover' ? input.takeoverNonce : null, activateNonce: input.activateNonce }, registry);
  TRACKED.set(intent, true);
  return intent;
}

export function checkIntent(intent, registry) {
  requireValue(TRACKED.has(intent), 'Use prepare or restore to obtain an owner intent');
  normalize(intent, registry);
  return intent;
}

export function consumeIntent(intent, registry) {
  checkIntent(intent, registry);
  if (!TRACKED.get(intent)) throw new ClientError('INTENT_USED', 'Only a newly prepared owner intent can be dispatched once');
  // Consume before the first read: an interruption never resets dispatch rights.
  TRACKED.set(intent, false);
}

export function saveIntent(intent, registry) { return JSON.stringify(checkIntent(intent, registry)); }

export function restoreIntent(serialized, registry) {
  requireValue(typeof serialized === 'string' && Buffer.byteLength(serialized) <= 16384,
    'Saved owner intent exceeds its 16 KiB budget');
  const intent = normalize(parseJson(serialized), registry);
  TRACKED.set(intent, false);
  return intent;
}

export function matchesBase(intent, head) {
  return head.revision === intent.baseRevision && head.owner_epoch === intent.baseOwnerEpoch &&
    head.owner_instance === intent.baseOwnerInstance && head.active === intent.baseActive && head.lifecycle === 'ready';
}

export function expected(intent, phase) {
  const takeover = intent.mode === 'takeover';
  return { revision: increment(intent.baseRevision, phase === 'activate' && takeover ? 2n : 1n),
    nonce: phase === 'takeover' ? intent.takeoverNonce : intent.activateNonce,
    owner: intent.targetWorker, epoch: takeover ? increment(intent.baseOwnerEpoch) : intent.baseOwnerEpoch,
    active: phase === 'activate' };
}

export function matchesTransition(intent, phase, head) {
  const candidate = expected(intent, phase);
  return head.revision === candidate.revision && head.transition.nonce === candidate.nonce &&
    head.owner_instance === candidate.owner && head.owner_epoch === candidate.epoch &&
    head.active === candidate.active && head.lifecycle === 'ready';
}

export function inspectIntent(intent, head) {
  let state;
  if (matchesTransition(intent, 'activate', head)) state = 'activation_accepted';
  else if (intent.mode === 'takeover' && matchesTransition(intent, 'takeover', head)) state = 'takeover_accepted';
  else if (matchesBase(intent, head)) state = 'base_observed';
  else if (head.lifecycle !== 'ready') state = 'blocked';
  else if (BigInt(head.revision) <= BigInt(intent.baseRevision)) state = 'unresolved';
  else if (head.owner_instance === intent.targetWorker && head.owner_epoch === expected(intent, 'activate').epoch) {
    state = head.active ? 'target_active' : 'target_inactive';
  } else state = 'superseded';
  return Object.freeze({ state, intent, status: head });
}
