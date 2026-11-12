/** Durable owner inputs and historical observations; none is a native Session. */
import { Buffer } from 'node:buffer';
import { record, requireValue, decimal, scope, sameScope, parseJson, status,
  ownerReference, sameOwnerReference, ownerPlan, ownerPending } from './wire.js';

const SAVED = new WeakSet(), PREPARED = new WeakSet();
const INPUT = ['creator', 'operation', 'expected_revision', 'expected_head_serial', 'mode', 'target_worker', 'nonces'];
const NONCES = ['claim', 'cancel', 'activate', 'abort'];
const MAX_BASE = (1n << 64n) - 3n;

export function identity(value) {
  record(value, ['creator', 'operation']);
  return Object.freeze({ creator: decimal(value.creator), operation: decimal(value.operation) });
}

function sameIdentity(left, right) {
  requireValue(left.creator === right.creator && left.operation === right.operation,
    'Owner operation identity does not match');
}

export function input(value) {
  record(value, INPUT);
  record(value.nonces, NONCES);
  const fixed = Object.fromEntries(INPUT.slice(0, 4).map((key) => [key, decimal(value[key])]));
  requireValue(BigInt(fixed.expected_revision) <= BigInt(fixed.expected_head_serial),
    'Original owner counters are inconsistent');
  requireValue(['takeover', 'activate'].includes(value.mode), 'Unknown owner mode');
  const nonces = Object.freeze(Object.fromEntries(NONCES.map((key) => [key, decimal(value.nonces[key])])));
  requireValue(new Set(Object.values(nonces)).size === 4, 'Owner phase nonces must be distinct');
  return Object.freeze({ ...fixed, mode: value.mode, target_worker: decimal(value.target_worker), nonces });
}

/** Save this complete input before prepare; no server-generated hash is needed to recover it. */
export function prepareInput(value, databaseScope) {
  const saved = Object.freeze({ version: 1, scope: scope(databaseScope), input: input(value) });
  SAVED.add(saved);
  return saved;
}

export function checkSaved(value, databaseScope) {
  requireValue(SAVED.has(value), 'Use prepareInput or restoreInput to obtain a saved owner input');
  sameScope(value.scope, databaseScope);
  return value;
}

export function saveInput(value, databaseScope) {
  return JSON.stringify(checkSaved(value, databaseScope));
}

export function restoreInput(serialized, databaseScope) {
  requireValue(typeof serialized === 'string' && Buffer.byteLength(serialized) <= 16384,
    'Saved owner input exceeds its 16 KiB budget');
  const value = parseJson(serialized);
  record(value, ['version', 'scope', 'input']);
  requireValue(value.version === 1, 'Unsupported saved owner input version');
  sameScope(scope(value.scope), databaseScope);
  return prepareInput(value.input, databaseScope);
}

function prepared(value, databaseScope, expectedInput) {
  record(value, ['scope', 'input', 'reference']);
  const fixed = Object.freeze({ scope: scope(value.scope), input: input(value.input),
    reference: ownerReference(value.reference) });
  sameScope(fixed.scope, databaseScope);
  sameIdentity(fixed.reference, fixed.input);
  requireValue(BigInt(fixed.input.expected_revision) <= MAX_BASE && BigInt(fixed.input.expected_head_serial) <= MAX_BASE,
    'Prepared descriptor lacks its admission and terminal counter reserve');
  if (expectedInput !== undefined) requireValue(JSON.stringify(fixed.input) === JSON.stringify(expectedInput),
    'Stored owner descriptor does not match the complete original input');
  return fixed;
}

function verified(value) {
  PREPARED.add(value);
  return value;
}

export function checkPrepared(value, databaseScope) {
  requireValue(PREPARED.has(value), 'Use prepare or inspect with the saved input before mutating an owner plan');
  sameScope(value.scope, databaseScope);
  return value;
}

export function preparation(value, databaseScope, expectedInput) {
  record(value, ['state'], ['prepared', 'reference']);
  if (value.state === 'pending') {
    record(value, ['state', 'reference']);
    const reference = ownerReference(value.reference);
    // This is the currently accepted blocker, which may belong to another
    // creator/operation. It is not this invocation's prepared descriptor.
    return Object.freeze({ state: 'pending', reference });
  }
  record(value, ['state', 'prepared']);
  requireValue(value.state === 'prepared', 'Unknown owner preparation state');
  return Object.freeze({ state: 'prepared', prepared: verified(prepared(value.prepared, databaseScope, expectedInput)) });
}

function acceptance(value, saved, head) {
  const plan = ownerPlan(value), a = plan.admission, p = plan.phase, original = saved.input;
  requireValue(sameOwnerReference(plan.reference, saved.reference), 'Accepted history belongs to another descriptor');
  requireValue(BigInt(a.revision) === BigInt(original.expected_revision) + 1n &&
    BigInt(a.head_serial) === BigInt(original.expected_head_serial) + 1n, 'Owner admission changed the original base');
  const nonce = { claimed: 'claim', cancelling: 'cancel', active: 'activate', aborted: 'abort' }[p.kind];
  requireValue(p.nonce === original.nonces[nonce], 'Owner phase nonce does not match its original input');
  if (a.kind === 'claim' || original.mode === 'activate') {
    requireValue(p.owner_instance === original.target_worker, 'Accepted owner differs from the fixed target');
  }
  if (a.kind === 'claim' && original.mode === 'takeover') {
    requireValue(BigInt(p.owner_epoch) >= 2n, 'Takeover did not advance an existing owner epoch');
  }
  requireValue(head.owner_plan !== null, 'Accepted owner history requires a current durable marker');
  if (sameOwnerReference(head.owner_plan.reference, saved.reference)) {
    requireValue(JSON.stringify(head.owner_plan) === JSON.stringify(plan), 'Current and accepted owner markers disagree');
  } else {
    requireValue(!ownerPending(plan) && BigInt(p.revision) < BigInt(head.owner_plan.admission.revision) &&
      BigInt(p.head_serial) < BigInt(head.owner_plan.admission.head_serial),
    'Superseded owner proof must be terminal and precede the current admission');
  }
  return plan;
}

/** Identity-only reads are useful history, but do not mint a mutation-capable SDK value. */
export function observation(value, databaseScope, expectedIdentity, expectedInput) {
  record(value, ['state', 'status', 'prepared', 'accepted']);
  const fixed = prepared(value.prepared, databaseScope, expectedInput);
  sameIdentity(fixed.reference, expectedIdentity);
  const head = status(value.status, databaseScope);
  if (head.owner_plan !== null && head.owner_plan.reference.creator === fixed.reference.creator &&
    head.owner_plan.reference.operation === fixed.reference.operation) {
    requireValue(sameOwnerReference(head.owner_plan.reference, fixed.reference),
      'Current marker changes an immutable operation descriptor');
  }
  let accepted = null;
  if (value.accepted === null) {
    requireValue(['prepared', 'fenced'].includes(value.state), 'Owner history is missing its accepted marker');
    requireValue(head.owner_plan === null || !sameOwnerReference(head.owner_plan.reference, fixed.reference),
      'Current accepted marker cannot be omitted from history');
    if (value.state === 'prepared') {
      requireValue(head.revision === fixed.input.expected_revision && head.head_serial === fixed.input.expected_head_serial &&
        head.lifecycle === 'ready' && head.storage.plan === null && head.storage.sweep === null && head.storage.terminal === null &&
        (head.owner_plan === null || !ownerPending(head.owner_plan)), 'Prepared observation no longer matches its original base');
      if (fixed.input.mode === 'activate') requireValue(!head.active && head.owner_instance === fixed.input.target_worker,
        'Activation requires the original inactive owner');
    }
  } else {
    accepted = acceptance(value.accepted, fixed, head);
    requireValue(value.state === accepted.phase.kind, 'Owner observation state contradicts its accepted phase');
  }
  return Object.freeze({ state: value.state, status: head,
    prepared: expectedInput === undefined ? fixed : verified(fixed), accepted });
}
