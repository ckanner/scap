/** Strict read-only pages. Exhausted metadata traversal is not full recovery. */
import { Buffer } from 'node:buffer';
import * as wire from './wire.js';
import * as catalogue from './catalogue_wire.js';

const STOPPED = ['INVALID', 'DENIED', 'LIMIT', 'CONFLICT', 'UNKNOWN', 'CORRUPT', 'SNAPSHOT_EXPIRED'];
const KINDS = ['name', 'create', 'control', 'abort_proof', 'head', 'orphan_prefix'];
const STATES = ['descriptor_only', 'reserved', 'provisioning', 'bound', 'ready', 'maintenance',
  'aborting', 'aborted', 'deleting', 'deleted', 'name_conflict', 'identity_conflict', 'control_admitted', 'orphan'];
const USAGE = { list_pages: 4, candidates: 128, exact_gets: 512,
  list_bytes: 4 * 1024 * 1024, metadata_bytes: 16 * 1024 * 1024 };

export function cursor(value) {
  if (value === null) return null;
  wire.requireValue(typeof value === 'string' && value.length <= 16384 && /^[A-Za-z0-9_-]+$/.test(value),
    'Expected a bounded opaque cursor or explicit null');
  return value;
}

function revision(value) { return value === null ? null : wire.decimal(value); }

function progress(value, exhausted) {
  const token = cursor(value.cursor);
  wire.requireValue(typeof exhausted === 'boolean' && exhausted === (token === null),
    'Traversal exhaustion and cursor disagree');
  wire.requireValue(value.stopped === null || STOPPED.includes(value.stopped), 'Unknown discovery stop reason');
  wire.requireValue(!exhausted || value.stopped === null, 'Failed traversal cannot be exhausted');
  return { cursor: token, stopped: value.stopped };
}

function entries(value) {
  wire.requireValue(Array.isArray(value) && value.length <= 128, 'Discovery page exceeds candidate budget');
  return value;
}

export function names(value, context) {
  wire.record(value, ['names', 'cursor', 'traversal_exhausted', 'stopped']);
  const page = progress(value, value.traversal_exhausted);
  const names = entries(value.names).map((item) => {
    wire.record(item, ['creation', 'binding_revision', 'head_revision']);
    return Object.freeze({ creation: catalogue.creation(item.creation, context),
      binding_revision: wire.decimal(item.binding_revision), head_revision: wire.decimal(item.head_revision) });
  });
  return Object.freeze({ ...page, names: Object.freeze(names), traversal_exhausted: value.traversal_exhausted });
}

function record(value, context) {
  wire.record(value, ['key', 'kind', 'state', 'creation', 'scope', 'control', 'binding_revision', 'head_revision']);
  wire.requireValue(typeof value.key === 'string' && value.key.isWellFormed() && Buffer.byteLength(value.key) <= 1024 &&
    value.key.startsWith(`scap-object/v1/${context.deployment}/`) && !/[\u0000-\u001f\u007f]/u.test(value.key),
  'Record key does not belong to this deployment');
  wire.requireValue(KINDS.includes(value.kind) && STATES.includes(value.state), 'Unknown inventory classification');
  const scope = value.scope === null ? null : wire.scope(value.scope);
  wire.requireValue(scope === null || scope.deployment === context.deployment, 'Foreign inventory scope');
  // Explicit deployment capability permits other tenants. It never grants SQL
  // permissions; an operator must use the current database authorization later.
  const creation = value.creation === null ? null : catalogue.creation(value.creation,
    { ...context, tenant: wire.scope(value.creation.scope).tenant });
  if (scope !== null && creation !== null) wire.sameScope(scope, creation.scope);
  const observed = value.control === null ? null : control(value.control);
  wire.requireValue((value.kind === 'control') === (observed !== null), 'Control classification and original intent disagree');
  wire.requireValue(observed === null || creation !== null, 'An original control requires its creation identity');
  return Object.freeze({ key: value.key, kind: value.kind, state: value.state, scope, creation,
    control: observed, binding_revision: revision(value.binding_revision), head_revision: revision(value.head_revision) });
}

function control(value) {
  wire.record(value, ['kind', 'principal', 'operation', 'expected_name_revision', 'expected_head_revision', 'nonce']);
  wire.requireValue(['abort', 'delete'].includes(value.kind), 'Unknown original control kind');
  const head = revision(value.expected_head_revision);
  wire.requireValue((value.kind === 'abort') === (head === null), 'Original control HEAD condition is inconsistent');
  return Object.freeze({ kind: value.kind, principal: wire.decimal(value.principal), operation: wire.decimal(value.operation),
    expected_name_revision: wire.decimal(value.expected_name_revision), expected_head_revision: head, nonce: wire.decimal(value.nonce) });
}

export function inventory(value, context) {
  wire.record(value, ['records', 'cursor', 'completion', 'usage', 'stopped']);
  const completion = wire.record(value.completion, ['traversal_exhausted', 'preexisting_slots_covered',
    'metadata_classified', 'data_recovery', 'recovery_complete']);
  const page = progress(value, completion.traversal_exhausted);
  wire.requireValue(completion.preexisting_slots_covered === completion.traversal_exhausted &&
    completion.data_recovery === 'not_run' && completion.recovery_complete === false,
  'Metadata inventory cannot claim data recovery or a snapshot');
  const classified = wire.decimal(completion.metadata_classified, true);
  wire.record(value.usage, Object.keys(USAGE));
  const usage = Object.fromEntries(Object.entries(USAGE).map(([key, maximum]) => {
    const count = value.usage[key];
    wire.requireValue(Number.isSafeInteger(count) && count >= 0 && count <= maximum, 'Invalid discovery cost');
    return [key, count];
  }));
  return Object.freeze({ ...page, records: Object.freeze(entries(value.records).map((item) => record(item, context))),
    usage: Object.freeze(usage), completion: Object.freeze({ ...completion, metadata_classified: classified }) });
}
