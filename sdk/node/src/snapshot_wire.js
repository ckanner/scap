/** Saved snapshot inputs, retained identities, and bounded metadata observations. */
import { Buffer } from 'node:buffer';
import { record, requireValue, decimal, scope, sameScope, parseJson, status, ownerPending } from './wire.js';

const SAVED = new WeakSet(), PREPARED = new WeakSet();
const MAX_PAGES = 4294967294;
const MAX_BYTES = 64n * BigInt(MAX_PAGES) * 4096n;

function hash(value) {
  requireValue(typeof value === 'string' && /^[0-9a-f]{64}$/.test(value), 'Expected a snapshot SHA-256 identity');
  return value;
}

function label(value) {
  requireValue(typeof value === 'string' && value.length !== 0 && value.isWellFormed() &&
    Buffer.byteLength(value) <= 128 && !/\p{Cc}/u.test(value), 'Snapshot label must be 1–128 UTF-8 bytes without control characters');
  return value;
}

export function identity(value) {
  record(value, ['creator', 'operation']);
  return Object.freeze({ creator: decimal(value.creator), operation: decimal(value.operation) });
}

function sameIdentity(left, right) {
  requireValue(left.creator === right.creator && left.operation === right.operation, 'Snapshot operation identity changed');
}

export function input(value) {
  record(value, ['creator', 'operation', 'expected_revision', 'expected_head_serial', 'label']);
  const fixed = Object.freeze({ creator: decimal(value.creator), operation: decimal(value.operation),
    expected_revision: decimal(value.expected_revision), expected_head_serial: decimal(value.expected_head_serial),
    label: label(value.label) });
  requireValue(BigInt(fixed.expected_revision) <= BigInt(fixed.expected_head_serial), 'Snapshot base counters are inconsistent');
  return fixed;
}

export function prepareInput(value, databaseScope) {
  const saved = Object.freeze({ version: 1, scope: scope(databaseScope), input: input(value) });
  SAVED.add(saved);
  return saved;
}

export function checkSaved(value, databaseScope) {
  requireValue(SAVED.has(value), 'Save the complete snapshot input before prepare');
  sameScope(value.scope, databaseScope);
  return value;
}

export function saveInput(value, databaseScope) {
  return JSON.stringify(checkSaved(value, databaseScope));
}

export function restoreInput(serialized, databaseScope) {
  requireValue(typeof serialized === 'string' && Buffer.byteLength(serialized) <= 16384,
    'Saved snapshot input exceeds its 16 KiB budget');
  const value = parseJson(serialized);
  record(value, ['version', 'scope', 'input']);
  requireValue(value.version === 1, 'Unsupported saved snapshot input version');
  sameScope(scope(value.scope), databaseScope);
  return prepareInput(value.input, databaseScope);
}

export function reference(value) {
  record(value, ['creator', 'operation', 'capture_serial', 'descriptor_hash']);
  return Object.freeze({ creator: decimal(value.creator), operation: decimal(value.operation),
    capture_serial: decimal(value.capture_serial), descriptor_hash: hash(value.descriptor_hash) });
}

export function point(value) {
  record(value, ['data_root', 'page_count', 'sequence', 'source_revision']);
  requireValue(Number.isSafeInteger(value.page_count) && value.page_count >= 0 && value.page_count <= MAX_PAGES,
    'Snapshot page count exceeds the persisted format');
  return Object.freeze({ data_root: hash(value.data_root), page_count: value.page_count,
    sequence: decimal(value.sequence, true), source_revision: decimal(value.source_revision) });
}

function entry(value) {
  record(value, ['reference', 'label', 'point']);
  const fixed = Object.freeze({ reference: reference(value.reference), label: label(value.label), point: point(value.point) });
  requireValue(BigInt(fixed.point.source_revision) < BigInt(fixed.reference.capture_serial),
    'Snapshot source revision must precede capture');
  return fixed;
}

export function limits(value) {
  record(value, ['max_points', 'max_logical_bytes']);
  requireValue(Number.isSafeInteger(value.max_points) && value.max_points >= 0 && value.max_points <= 64,
    'Snapshot count limit must be between zero and 64');
  const bytes = decimal(value.max_logical_bytes, true);
  requireValue(BigInt(bytes) <= MAX_BYTES, 'Snapshot logical bytes exceed the persisted format');
  return Object.freeze({ max_points: value.max_points, max_logical_bytes: bytes });
}

function prepared(value, databaseScope, expectedInput) {
  record(value, ['scope', 'input', 'reference', 'point']);
  const fixed = Object.freeze({ scope: scope(value.scope), input: input(value.input),
    reference: reference(value.reference), point: point(value.point) });
  sameScope(fixed.scope, databaseScope);
  sameIdentity(fixed.reference, fixed.input);
  requireValue(BigInt(fixed.reference.capture_serial) === BigInt(fixed.input.expected_head_serial) + 1n &&
    fixed.point.source_revision === fixed.input.expected_revision, 'Snapshot descriptor changed the original base');
  if (expectedInput !== undefined) {
    requireValue(JSON.stringify(fixed.input) === JSON.stringify(expectedInput), 'Snapshot descriptor changed the saved input');
    PREPARED.add(fixed);
  }
  return fixed;
}

export function preparation(value, databaseScope, expectedInput) {
  return prepared(value, databaseScope, expectedInput);
}

export function checkPrepared(value, databaseScope) {
  requireValue(PREPARED.has(value), 'Use prepare or inspect with the saved input before a snapshot mutation');
  sameScope(value.scope, databaseScope);
  return value;
}

function pointInHead(value, head) {
  requireValue(BigInt(value.reference.capture_serial) <= BigInt(head.head_serial) &&
    BigInt(value.point.source_revision) <= BigInt(head.revision) &&
    BigInt(value.point.sequence) <= BigInt(head.sequence), 'Snapshot refers to a future authority state');
}

export function observation(value, databaseScope, expectedIdentity, expectedInput, expectedReference) {
  record(value, ['state', 'status', 'prepared', 'accepted']);
  const fixed = prepared(value.prepared, databaseScope, expectedInput), head = status(value.status, databaseScope);
  sameIdentity(fixed.reference, expectedIdentity);
  if (expectedReference !== undefined) requireValue(JSON.stringify(fixed.reference) === JSON.stringify(expectedReference),
    'Snapshot observation changed the original reference');
  let accepted = null;
  if (value.accepted === null) {
    requireValue(['prepared', 'fenced'].includes(value.state), 'Snapshot history omitted an accepted point');
    if (value.state === 'prepared') {
      requireValue(head.revision === fixed.input.expected_revision && head.head_serial === fixed.input.expected_head_serial &&
        head.lifecycle === 'ready' && head.storage.plan === null && head.storage.sweep === null && head.storage.terminal === null &&
        (head.owner_plan === null || !ownerPending(head.owner_plan)), 'Prepared snapshot no longer matches its original base');
    } else {
      requireValue(BigInt(head.head_serial) >= BigInt(fixed.reference.capture_serial), 'A fenced snapshot needs a later HEAD');
    }
  } else {
    accepted = entry(value.accepted);
    requireValue(JSON.stringify(accepted.reference) === JSON.stringify(fixed.reference) &&
      JSON.stringify(accepted.point) === JSON.stringify(fixed.point) && accepted.label === fixed.input.label,
    'Accepted snapshot differs from its permanent descriptor');
    pointInHead(accepted, head);
    requireValue(['retained', 'released_observed'].includes(value.state), 'Unknown accepted snapshot state');
    if (value.state === 'retained') requireValue(head.storage.terminal === null, 'Terminal storage cannot retain a snapshot');
    else requireValue(BigInt(head.head_serial) > BigInt(fixed.reference.capture_serial), 'Release observation needs a later HEAD');
  }
  return Object.freeze({ state: value.state, status: head, prepared: fixed, accepted });
}

export function listing(value, databaseScope) {
  record(value, ['status', 'snapshots', 'limits']);
  const head = status(value.status, databaseScope);
  requireValue(Array.isArray(value.snapshots) && value.snapshots.length <= 64, 'Snapshot list exceeds its fixed bound');
  const points = value.snapshots.map(entry), policy = value.limits === null ? null : limits(value.limits);
  requireValue(policy !== null || points.length === 0, 'Retained points require persistent limits');
  requireValue(head.storage.terminal === null || points.length === 0, 'Terminal storage cannot retain snapshots');
  let serial = 0n, bytes = 0n;
  const identities = new Set(), labels = new Set();
  for (const saved of points) {
    pointInHead(saved, head);
    const key = `${saved.reference.creator}/${saved.reference.operation}`;
    requireValue(BigInt(saved.reference.capture_serial) > serial && !identities.has(key) && !labels.has(saved.label),
      'Snapshot identities, labels and serial order must be unique');
    serial = BigInt(saved.reference.capture_serial);
    identities.add(key); labels.add(saved.label);
    bytes += BigInt(saved.point.page_count) * 4096n;
  }
  if (policy !== null) requireValue(points.length <= policy.max_points && bytes <= BigInt(policy.max_logical_bytes),
    'Retained snapshots exceed the persistent policy');
  return Object.freeze({ status: head, snapshots: Object.freeze(points), limits: policy });
}
