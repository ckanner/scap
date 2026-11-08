/** One explicit page per call; no automatic retry, scan, or cursor restart. */
import * as wire from './wire.js';
import * as catalogue from './catalogue_wire.js';
import * as discovery from './discovery_wire.js';
import { Transport } from './transport.js';

const TRANSPORT = ['endpoint', 'token', 'fetch', 'timeoutMs', 'recoveryTimeoutMs',
  'maxRequestBytes', 'maxResponseBytes', 'allowInsecureHttp'];

export class DiscoveryClient {
  #context;
  #transport;

  constructor(options) {
    wire.record(options, ['endpoint', 'token', 'deployment', 'tenant', 'principal'], TRANSPORT);
    this.#context = catalogue.context({ deployment: options.deployment, tenant: options.tenant, principal: options.principal });
    const transport = Object.fromEntries(TRANSPORT.filter((key) => Object.hasOwn(options, key)).map((key) => [key, options[key]]));
    for (const [key, maximum] of [['maxRequestBytes', 65536], ['maxResponseBytes', 1048576]]) {
      const value = transport[key] === undefined ? maximum : transport[key];
      wire.requireValue(Number.isSafeInteger(value) && value > 0 && value <= maximum, 'Invalid discovery transport budget');
      transport[key] = value;
    }
    this.#transport = new Transport(transport);
  }

  get deployment() { return this.#context.deployment; }
  get tenant() { return this.#context.tenant; }
  get principal() { return this.#context.principal; }

  #page(operation, cursor, decode, options) {
    const reference = Object.freeze({ ...this.#context, operation });
    return this.#transport.call({ version: 1, operation, cursor: discovery.cursor(cursor) }, reference,
      (value) => decode(value, this.#context), options);
  }

  listNames(cursor = null, options) {
    return this.#page('list_names', cursor, discovery.names, options);
  }

  deploymentInventory(cursor = null, options) {
    return this.#page('deployment_inventory', cursor, discovery.inventory, options);
  }
}
