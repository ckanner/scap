/** Name catalogue operations, each issuing one explicit original-intent POST. */
import * as wire from './wire.js';
import * as catalogue from './catalogue_wire.js';
import { Transport } from './transport.js';

const TRANSPORT = ['endpoint', 'token', 'fetch', 'timeoutMs', 'recoveryTimeoutMs',
  'maxRequestBytes', 'maxResponseBytes', 'allowInsecureHttp'];

export class CatalogueClient {
  #context;
  #transport;

  constructor(options) {
    wire.record(options, ['endpoint', 'token', 'deployment', 'tenant', 'principal'], TRANSPORT);
    this.#context = catalogue.context({ deployment: options.deployment, tenant: options.tenant, principal: options.principal });
    this.#transport = new Transport(Object.fromEntries(TRANSPORT
      .filter((key) => Object.hasOwn(options, key)).map((key) => [key, options[key]])));
  }

  get deployment() { return this.#context.deployment; }
  get tenant() { return this.#context.tenant; }
  get principal() { return this.#context.principal; }

  prepareIntent(action) { return catalogue.prepare(action, this.#context); }
  saveIntent(intent) { return JSON.stringify(catalogue.checkTracked(intent, this.#context)); }
  restoreIntent(serialized) { return catalogue.restore(serialized, this.#context); }

  submit(input, options) {
    const intent = catalogue.checkTracked(input, this.#context);
    const reference = Object.freeze({ ...this.#context, operation: intent.action.operation, intent });
    return this.#transport.call({ version: 1, ...intent.action }, reference,
      (value) => catalogue.decode(value, intent), options);
  }

  prepareCreate(input, options) {
    wire.record(input, ['name', 'create_operation', 'expected_name_revision', 'options']);
    return this.submit(this.prepareIntent({ operation: 'prepare_create', ...input }), options);
  }

  resumeCreate(creation, options) {
    return this.submit(this.prepareIntent({ operation: 'resume_create', creation }), options);
  }

  abortCreate(input, options) {
    wire.record(input, ['creation', 'control_operation', 'expected_name_revision', 'nonce']);
    return this.submit(this.prepareIntent({ operation: 'abort_create', ...input }), options);
  }

  inspectCreateOperation(createOperation, options) {
    return this.submit(this.prepareIntent({ operation: 'inspect_create_operation', create_operation: createOperation }), options);
  }

  prepareRestore(input, options) {
    wire.record(input, ['name', 'restore_operation', 'expected_name_revision', 'options', 'source_scope', 'snapshot']);
    return this.submit(this.prepareIntent({ operation: 'prepare_restore', ...input }), options);
  }

  resumeRestore(reference, options) {
    return this.submit(this.prepareIntent({ operation: 'resume_restore', reference }), options);
  }

  inspectRestore(restoreOperation, options) {
    return this.submit(this.prepareIntent({ operation: 'inspect_restore', creator: this.#context.principal,
      restore_operation: restoreOperation }), options);
  }

  abortRestore(input, options) {
    wire.record(input, ['reference', 'control_operation', 'expected_name_revision', 'nonce']);
    return this.submit(this.prepareIntent({ operation: 'abort_restore', ...input }), options);
  }

  resolveName(name, options) {
    return this.submit(this.prepareIntent({ operation: 'resolve_name', name }), options);
  }

  deleteName(input, options) {
    wire.record(input, ['creation', 'control_operation', 'expected_name_revision', 'expected_head_revision', 'nonce']);
    return this.submit(this.prepareIntent({ operation: 'delete_name', ...input }), options);
  }

  storageStatus(creation, options) {
    return this.submit(this.prepareIntent({ operation: 'named_storage_status', creation }), options);
  }

  retireStorage(input, options) {
    wire.record(input, ['creation', 'expected_head_serial']);
    return this.submit(this.prepareIntent({ operation: 'retire_named_storage', ...input }), options);
  }
}
