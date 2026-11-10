/** Strict catalogue DTOs and durable client intent identity; no I/O. */
import { Buffer } from 'node:buffer';
import * as wire from './wire.js';

const TRACKED = new WeakSet();
const CONTEXT = ['deployment', 'tenant', 'principal'];
const CREATION = ['creator', 'operation', 'name', 'scope', 'expected_name_revision'];
const ACTIONS = Object.freeze({
  prepare_create: ['name', 'create_operation', 'expected_name_revision', 'options'],
  resume_create: ['creation'],
  abort_create: ['creation', 'control_operation', 'expected_name_revision', 'nonce'],
  inspect_create_operation: ['create_operation'],
  resolve_name: ['name'],
  delete_name: ['creation', 'control_operation', 'expected_name_revision', 'expected_head_revision', 'nonce'],
  named_storage_status: ['creation'],
  retire_named_storage: ['creation', 'expected_head_serial'],
});
const FIELDS = [...new Set(Object.values(ACTIONS).flat())];
const CREATE_PHASES = ['not_reserved', 'reserved', 'provisioning', 'bound', 'ready',
  'aborting', 'aborted', 'deleting', 'deleted', 'name_conflict', 'identity_conflict'];
const ABORT_PHASES = ['not_reserved', 'cannot_abort_bound', 'aborting', 'aborted'];
const DELETE_PHASES = ['not_deleted', 'deleting', 'deleted'];

export function context(value) {
  wire.record(value, CONTEXT);
  return Object.freeze(Object.fromEntries(CONTEXT.map((key) => [key, wire.decimal(value[key])])));
}

function sameContext(actual, expected) {
  wire.requireValue(CONTEXT.every((key) => actual[key] === expected[key]),
    'Catalogue authority or caller does not match the saved intent');
}

function name(value) {
  wire.requireValue(typeof value === 'string' && value.isWellFormed() && value.length > 0 &&
    Buffer.byteLength(value) <= 128 && !/[\u0000-\u001f\u007f-\u009f]/u.test(value),
  'Name must contain 1 to 128 UTF-8 bytes without control characters');
  return value;
}

function revision(value) { return value === null ? null : wire.decimal(value); }

export function creation(value, caller) {
  wire.record(value, CREATION);
  const result = { creator: wire.decimal(value.creator), operation: wire.decimal(value.operation),
    name: name(value.name), scope: wire.scope(value.scope),
    expected_name_revision: revision(value.expected_name_revision) };
  wire.requireValue(result.scope.deployment === caller.deployment && result.scope.tenant === caller.tenant,
    'Creation belongs to another catalogue authority');
  return Object.freeze(result);
}

function sameCreation(actual, expected) {
  wire.sameScope(actual.scope, expected.scope);
  wire.requireValue(['creator', 'operation', 'name', 'expected_name_revision'].every((key) =>
    actual[key] === expected[key]), 'Response changed the original creation identity');
}

function quotaChoice(value) {
  wire.record(value, ['mode'], ['max_bytes']);
  wire.requireValue(['default', 'unlimited', 'limited'].includes(value.mode), 'Unknown quota choice');
  if (value.mode === 'limited') {
    wire.record(value, ['mode', 'max_bytes']);
    wire.decimal(value.max_bytes);
    return Object.freeze({ mode: value.mode, max_bytes: wire.quota(value.max_bytes) });
  }
  wire.record(value, ['mode']);
  return Object.freeze({ mode: value.mode });
}

function action(value, caller) {
  wire.record(value, ['operation'], FIELDS);
  const operation = value.operation;
  wire.requireValue(typeof operation === 'string' && Object.hasOwn(ACTIONS, operation), 'Unknown catalogue operation');
  wire.record(value, ['operation', ...ACTIONS[operation]]);
  const result = { operation };
  if (operation === 'prepare_create' || operation === 'resolve_name') result.name = name(value.name);
  if (operation === 'prepare_create' || operation === 'inspect_create_operation') {
    result.create_operation = wire.decimal(value.create_operation);
  }
  if (operation === 'prepare_create') {
    result.expected_name_revision = revision(value.expected_name_revision);
    wire.record(value.options, ['quota']);
    result.options = Object.freeze({ quota: quotaChoice(value.options.quota) });
  }
  if (Object.hasOwn(value, 'creation')) {
    result.creation = creation(value.creation, caller);
    if (operation === 'resume_create' || operation === 'abort_create') {
      wire.requireValue(result.creation.creator === caller.principal, 'Only the original creator may resume or abort creation');
    }
  }
  if (operation === 'abort_create' || operation === 'delete_name') {
    result.control_operation = wire.decimal(value.control_operation);
    result.expected_name_revision = wire.decimal(value.expected_name_revision);
    result.nonce = wire.decimal(value.nonce);
  }
  if (operation === 'delete_name') result.expected_head_revision = wire.decimal(value.expected_head_revision);
  if (operation === 'retire_named_storage') result.expected_head_serial = wire.decimal(value.expected_head_serial);
  return Object.freeze(result);
}

export function prepare(input, caller) {
  const result = Object.freeze({ version: 1, ...caller, action: action(input, caller) });
  TRACKED.add(result);
  return result;
}

export function checkTracked(value, caller) {
  wire.requireValue(TRACKED.has(value), 'Use prepareIntent or restoreIntent to obtain a tracked catalogue intent');
  sameContext(value, caller);
  return value;
}

export function restore(serialized, caller) {
  wire.requireValue(typeof serialized === 'string' && Buffer.byteLength(serialized) <= 65536,
    'Saved catalogue intent must be a string of at most 64 KiB');
  const saved = wire.parseJson(serialized);
  wire.record(saved, ['version', ...CONTEXT, 'action']);
  wire.requireValue(saved.version === 1, 'Unsupported saved catalogue intent version');
  const savedContext = context(Object.fromEntries(CONTEXT.map((key) => [key, saved[key]])));
  sameContext(savedContext, caller);
  return prepare(saved.action, caller);
}

function policy(value) {
  wire.record(value.initial_quota, ['max_bytes']);
  wire.record(value.retention, ['max_entries', 'max_result_bytes']);
  wire.requireValue(Number.isSafeInteger(value.retention.max_entries) && value.retention.max_entries > 0 &&
    value.retention.max_entries <= 65536, 'Invalid request retention count');
  return { initial_quota: Object.freeze({ max_bytes: wire.quota(value.initial_quota.max_bytes) }),
    retention: Object.freeze({ max_entries: value.retention.max_entries,
      max_result_bytes: wire.decimal(value.retention.max_result_bytes) }) };
}

function progress(value, phases) {
  wire.requireValue(phases.includes(value.phase), 'Unknown catalogue progress phase');
  return { phase: value.phase, binding_revision: revision(value.binding_revision),
    head_revision: revision(value.head_revision) };
}

/** Validate the response against the exact intent, never inferred current conditions. */
export function decode(value, intent) {
  const input = intent.action;
  const operation = input.operation;
  if (operation === 'named_storage_status') return wire.storageStatus(value, input.creation.scope);
  if (operation === 'retire_named_storage') return wire.retiredStorage(value, input.creation.scope, input.expected_head_serial);
  if (operation === 'resolve_name') {
    wire.record(value, ['creation', 'binding_revision', 'head']);
    const result = { creation: creation(value.creation, intent), binding_revision: wire.decimal(value.binding_revision) };
    wire.requireValue(result.creation.name === input.name, 'Resolved another name');
    result.head = wire.status(value.head, result.creation.scope);
    wire.requireValue(result.head.lifecycle !== 'deleted', 'Deleted databases cannot be resolved');
    return Object.freeze(result);
  }
  if (operation === 'abort_create' || operation === 'delete_name') {
    wire.record(value, ['creation', 'operation', 'nonce', 'phase', 'binding_revision', 'head_revision']);
    const result = { creation: creation(value.creation, intent), operation: wire.decimal(value.operation),
      nonce: wire.decimal(value.nonce), ...progress(value, operation === 'abort_create' ? ABORT_PHASES : DELETE_PHASES) };
    sameCreation(result.creation, input.creation);
    wire.requireValue(result.operation === input.control_operation && result.nonce === input.nonce,
      'Response changed the original control identity');
    return Object.freeze(result);
  }
  const prepared = operation === 'prepare_create';
  wire.record(value, ['creation', 'initial_quota', 'retention',
    ...(prepared ? [] : ['phase', 'binding_revision', 'head_revision'])]);
  const result = { creation: creation(value.creation, intent), ...policy(value) };
  if (operation === 'resume_create') sameCreation(result.creation, input.creation);
  else {
    wire.requireValue(result.creation.creator === intent.principal && result.creation.operation === input.create_operation,
      'Response changed the caller or create operation');
  }
  if (prepared) {
    wire.requireValue(result.creation.name === input.name &&
      result.creation.expected_name_revision === input.expected_name_revision, 'Prepared descriptor changed the original name condition');
    const quota = input.options.quota;
    if (quota.mode !== 'default') wire.requireValue(result.initial_quota.max_bytes ===
      (quota.mode === 'unlimited' ? null : quota.max_bytes), 'Prepared descriptor changed the explicit initial quota');
  } else Object.assign(result, progress(value, CREATE_PHASES));
  return Object.freeze(result);
}
