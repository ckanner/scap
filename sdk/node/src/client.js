/** Explicit S3-native database requests. Every method sends at most one POST. */
import { decodeResult, FORMAT_LIMITS } from '../../node-codec/src/codec.js';
import { Buffer } from 'node:buffer';
import * as wire from './wire.js';
import { Transport } from './transport.js';

export { ClientError, RemoteError, UnknownError, CommittedResultError, RouteError } from './errors.js';
export { CatalogueClient } from './catalogue.js';
export { DiscoveryClient } from './discovery.js';
export { RoutedClient } from './routed.js';
export { OwnerClient } from './owner.js';
export { OwnerReconcileError } from './errors.js';
export { decodeResult, validateResult } from '../../node-codec/src/codec.js';

const EMPTY = Buffer.from('534341505245533100000000', 'hex');
const TRANSPORT = ['endpoint', 'token', 'fetch', 'timeoutMs', 'recoveryTimeoutMs',
  'maxRequestBytes', 'maxResponseBytes', 'allowInsecureHttp'];

export class Client {
  #scope;
  #principal;
  #transport;
  #limits;
  #allocation;

  constructor(options) {
    wire.record(options, ['endpoint', 'token', 'scope', 'principal'],
      [...TRANSPORT, 'resultLimits', 'allocation']);
    this.#scope = wire.scope(options.scope);
    this.#principal = wire.decimal(options.principal);
    const { resultLimits = {}, allocation = {} } = options;
    wire.record(resultLimits, [], Object.keys(FORMAT_LIMITS));
    wire.record(allocation, [], ['maxRows', 'maxValues', 'maxColumns']);
    this.#limits = Object.freeze({ ...resultLimits });
    this.#allocation = Object.freeze({ ...allocation });
    // Validate materialization budgets before sending any operation.
    decodeResult(EMPTY, this.#limits, this.#allocation);
    this.#transport = new Transport(Object.fromEntries(TRANSPORT
      .filter((key) => Object.hasOwn(options, key)).map((key) => [key, options[key]])));
  }

  get scope() { return this.#scope; }
  get principal() { return this.#principal; }

  prepare(statements, request) {
    wire.record(request, ['epoch', 'id']);
    return wire.prepare(statements, { ...request, principal: this.#principal }, this.#scope);
  }

  save(request) {
    return JSON.stringify(wire.checkTracked(request, this.#scope, this.#principal));
  }

  restore(serialized) {
    return wire.checkTracked(wire.restore(serialized, this.#scope), this.#scope, this.#principal);
  }

  #call(action, decode, options) {
    const reference = Object.freeze({ scope: this.#scope, operation: action.operation,
      ...(action.request === undefined ? {} : { request: action.request }),
      ...(action.nonce === undefined ? {} : { nonce: action.nonce }),
      ...(action.expected_worker_instance === undefined ? {} : { expectedWorkerInstance: action.expected_worker_instance }),
      ...(action.expected_revision === undefined ? {} : { expectedRevision: action.expected_revision }) });
    return this.#transport.call({ version: 1, scope: this.#scope, ...action }, reference, decode, options);
  }

  #status(action, options, expectedRevision, nonce) {
    return this.#call(action, (value) => {
      const result = wire.status(value, this.#scope);
      if (expectedRevision !== undefined) {
        wire.requireValue(BigInt(result.revision) === BigInt(expectedRevision) + 1n &&
          result.transition.nonce === nonce, 'Administrative result does not match the requested transition');
      }
      return result;
    }, options);
  }

  status(options) { return this.#status({ operation: 'status' }, options); }

  guardedStatus(workerInstance, options) {
    return this.#status({ operation: 'status', expected_worker_instance: wire.decimal(workerInstance) }, options);
  }

  open(options) { return this.#status({ operation: 'open' }, options); }

  create(input, options) {
    wire.record(input, ['nonce']);
    const nonce = wire.decimal(input.nonce);
    return this.#status({ operation: 'create', nonce }, options, '0', nonce);
  }

  query(statements, options) {
    const encoded = wire.encodeStatements(statements);
    return this.#call({ operation: 'query', statements: encoded.statements }, (value) => {
      wire.record(value, ['result']);
      return decodeResult(wire.base64(value.result), this.#limits, this.#allocation);
    }, options);
  }

  execute(input, options) {
    const request = wire.checkTracked(input, this.#scope, this.#principal);
    return this.#call({ operation: 'execute', request: request.request, statements: request.statements },
      (value) => wire.committed(value, this.#scope, request.request, this.#limits, this.#allocation), options);
  }

  #resolve(operation, input, options) {
    const request = wire.checkTracked(input, this.#scope, this.#principal);
    return this.#call({ operation, request: request.request },
      (value) => wire.resolved(value, this.#scope, request.request, this.#limits, this.#allocation), options);
  }

  lookup(request, options) { return this.#resolve('lookup', request, options); }

  cancel(request, options) { return this.#resolve('cancel', request, options); }

  #admin(operation, input, extra, options) {
    const revision = wire.decimal(input.expectedRevision), nonce = wire.decimal(input.nonce);
    return this.#status({ operation, expected_revision: revision, nonce, ...extra }, options, revision, nonce);
  }

  activate(input, options) {
    return this.#owner('activate', input, options);
  }

  takeover(input, options) {
    return this.#owner('takeover', input, options);
  }

  #owner(operation, input, options) {
    wire.record(input, ['expectedRevision', 'nonce'], ['expectedWorkerInstance']);
    const extra = Object.hasOwn(input, 'expectedWorkerInstance') ?
      { expected_worker_instance: wire.decimal(input.expectedWorkerInstance) } : {};
    return this.#admin(operation, input, extra, options);
  }

  closeFull(input, options) {
    wire.record(input, ['expectedRevision', 'nonce']);
    return this.#admin('close_full', input, {}, options);
  }

  setQuota(input, options) {
    wire.record(input, ['expectedRevision', 'nonce', 'maxBytes']);
    return this.#admin('quota', input, { max_bytes: wire.quota(input.maxBytes) }, options);
  }

  setPolicy(input, options) {
    wire.record(input, ['expectedRevision', 'nonce', 'permissions']);
    return this.#admin('policy', input, { permissions: wire.permissions(input.permissions) }, options);
  }

  setLifecycle(input, options) {
    wire.record(input, ['expectedRevision', 'nonce', 'lifecycle']);
    return this.#admin('lifecycle', input, { lifecycle: wire.lifecycle(input.lifecycle) }, options);
  }
}
