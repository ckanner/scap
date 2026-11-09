/** Local endpoint allowlist. A server never supplies a credential destination. */
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { Client } from './client.js';
import { ClientError } from './errors.js';
import { record, decimal, requireValue } from './wire.js';

const OPTIONAL = ['fetch', 'timeoutMs', 'recoveryTimeoutMs', 'maxRequestBytes',
  'maxResponseBytes', 'allowInsecureHttp', 'resultLimits', 'allocation'];

export class RouteRegistry {
  #options;
  #fetch;
  #routes = new Map();
  #bootstrap;
  #direct;
  #digest;

  constructor(options) {
    record(options, ['bootstrapEndpoint', 'routes', 'token', 'scope', 'principal'], OPTIONAL);
    requireValue(Array.isArray(options.routes) && options.routes.length > 0 && options.routes.length <= 256,
      'Expected between one and 256 trusted worker routes');
    this.#options = Object.fromEntries(['token', 'scope', 'principal', ...OPTIONAL]
      .filter((key) => Object.hasOwn(options, key)).map((key) => [key, options[key]]));
    const bounded = (value) => requireValue(typeof value === 'string' && Buffer.byteLength(value) <= 2048,
      'Endpoint exceeds the 2048-byte routing budget');
    bounded(options.bootstrapEndpoint);
    this.#direct = new Client({ ...this.#options, endpoint: options.bootstrapEndpoint });
    this.#bootstrap = new URL(options.bootstrapEndpoint).href;
    // Retain validated copies, including result budgets, rather than mutable
    // caller objects which could change a later per-operation Client.
    this.#options = Object.freeze({ ...this.#options, scope: this.#direct.scope,
      resultLimits: Object.freeze({ ...options.resultLimits }), allocation: Object.freeze({ ...options.allocation }) });
    this.#fetch = options.fetch ?? globalThis.fetch;
    const endpoints = new Set();
    let bytes = Buffer.byteLength(this.#bootstrap);
    for (const route of options.routes) {
      record(route, ['workerInstance', 'endpoint']);
      const worker = decimal(route.workerInstance);
      bounded(route.endpoint);
      // Reuse the direct transport's TLS, credential and URL validation.
      new Client({ ...this.#options, endpoint: route.endpoint });
      const endpoint = new URL(route.endpoint).href;
      bytes += Buffer.byteLength(worker) + Buffer.byteLength(endpoint);
      requireValue(bytes <= 65536, 'Trusted route configuration exceeds 64 KiB');
      requireValue(!this.#routes.has(worker) && !endpoints.has(endpoint), 'Duplicate worker or endpoint route');
      this.#routes.set(worker, endpoint);
      endpoints.add(endpoint);
    }
    const routes = [...this.#routes].sort(([left], [right]) => BigInt(left) < BigInt(right) ? -1 : 1);
    // A surviving metadata bootstrap may inspect old intents. It does not
    // change any fixed administrative destination or grant dispatch rights.
    this.#digest = createHash('sha256').update(JSON.stringify(routes)).digest('hex');
  }

  get direct() { return this.#direct; }
  get digest() { return this.#digest; }
  get timeout() { return this.#options.timeoutMs ?? 30000; }
  get recoveryTimeout() { return this.#options.recoveryTimeoutMs ?? 1800000; }

  endpoint(worker) {
    const endpoint = this.#routes.get(decimal(worker));
    if (endpoint === undefined) throw new ClientError('UNROUTABLE', 'The current or requested owner has no trusted route');
    return endpoint;
  }

  client(worker, budget, phase) {
    const endpoint = worker === null ? this.#bootstrap : this.endpoint(worker);
    return new Client({ ...this.#options, endpoint, fetch: budget.fetch(this.#fetch, phase) });
  }
}
