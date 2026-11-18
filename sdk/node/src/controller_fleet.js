/** Finite scheduler. One slot owns its tick until completion; polling never queues another round. */
import { Buffer } from 'node:buffer';
import { performance } from 'node:perf_hooks';
import { OwnerController } from './controller.js';
import { ControllerHttp } from './controller_http.js';
import { CONTROLLER_LIMITS, checkControllerPolicy, controllerScopeKey } from './controller_policy.js';
import { ClientError } from './errors.js';
import { record, requireValue } from './wire.js';

export class OwnerControllerFleet {
  #controllers = new Map(); #active = new Map(); #tenants = new Map(); #reports = new Map();
  #transport; #recoveries = 0; #cursor = 0; #closed = false; #closing;

  constructor(options) {
    record(options, ['entries'], ['transport']);
    requireValue(Array.isArray(options.entries) && options.entries.length > 0 &&
      options.entries.length <= CONTROLLER_LIMITS.scopes, 'Expected one to 128 configured Scopes');
    let bytes = 0;
    const workers = new Map(), endpoints = new Map(), entries = [];
    for (const entry of options.entries) {
      record(entry, ['policy', 'token']);
      const policy = checkControllerPolicy(entry.policy), key = controllerScopeKey(policy.scope);
      requireValue(!entries.some((item) => item.key === key), 'Duplicate configured Scope');
      bytes += Buffer.byteLength(policy.canonical);
      requireValue(bytes <= CONTROLLER_LIMITS.policyBytes, 'Combined controller policies exceed 64 KiB');
      for (const worker of policy.workers) {
        const id = policy.authorityId + ':' + worker.workerInstance;
        const endpoint = policy.authorityId + ':' + worker.endpoint;
        const route = JSON.stringify(worker);
        requireValue(!workers.has(id) || workers.get(id) === route, 'A worker incarnation changed its fixed route or rank');
        requireValue(!endpoints.has(endpoint) || endpoints.get(endpoint) === id, 'An endpoint represents two worker incarnations');
        workers.set(id, route); endpoints.set(endpoint, id);
      }
      requireValue(workers.size <= CONTROLLER_LIMITS.workers, 'Fleet exceeds 256 fixed worker incarnations');
      entries.push({ key, policy, token: entry.token });
    }
    this.#transport = options.transport === undefined ? new ControllerHttp() : options.transport;
    requireValue(this.#transport !== null && typeof this.#transport.fetch === 'function' &&
      typeof this.#transport.close === 'function', 'Expected an owned HTTP transport with a joinable close');
    for (const { key, policy, token } of entries) {
      const tenant = policy.scope.deployment + ':' + policy.scope.tenant;
      this.#controllers.set(key, { tenant, controller: new OwnerController({ policy, token,
        fetch: (...args) => this.#transport.fetch(...args) }) });
    }
  }

  snapshot() {
    return Object.freeze({ closed: this.#closed, scopes: this.#controllers.size, active: this.#active.size,
      recoveries: this.#recoveries, pendingReports: this.#reports.size });
  }

  /** Latest report per Scope, bounded by the fixed configuration; this is not a complete event log. */
  takeReports() {
    const reports = Object.freeze([...this.#reports.values()]);
    this.#reports.clear();
    return reports;
  }

  poll() {
    if (this.#closed) throw new ClientError('ABORTED', 'The fleet is closed');
    const entries = [...this.#controllers], now = performance.now(), start = this.#cursor;
    let started = 0;
    for (let offset = 0; offset < entries.length && this.#active.size < CONTROLLER_LIMITS.ticks; offset++) {
      const index = (start + offset) % entries.length, [key, { tenant, controller }] = entries[index];
      const tenantCount = this.#tenants.get(tenant) ?? 0;
      if (this.#active.has(key) || controller.nextTickAt > now || tenantCount >= CONTROLLER_LIMITS.tenantTicks ||
        (controller.needsRecovery && this.#recoveries >= CONTROLLER_LIMITS.recoveries)) continue;
      const recovery = controller.needsRecovery;
      this.#tenants.set(tenant, tenantCount + 1);
      if (recovery) this.#recoveries++;
      const finished = controller.tick().then((report) => { this.#reports.set(key, report); }, () => {
        this.#reports.set(key, Object.freeze({ version: 1, scope: controller.policy.scope,
          policyDigest: controller.policy.digest, state: 'blocked', reason: 'CONTROLLER_FAILURE',
          nativeSession: 'NOT_CERTIFIED' }));
      }).then(() => {
        this.#active.delete(key);
        const remaining = this.#tenants.get(tenant) - 1;
        if (remaining === 0) this.#tenants.delete(tenant); else this.#tenants.set(tenant, remaining);
        if (recovery) this.#recoveries--;
      });
      this.#active.set(key, finished); this.#cursor = (index + 1) % entries.length; started++;
    }
    return Object.freeze({ started, ...this.snapshot() });
  }

  close() {
    if (this.#closing !== undefined) return this.#closing;
    this.#closed = true;
    this.#closing = (async () => {
      await Promise.all([...this.#controllers.values()].map(({ controller }) => controller.close()));
      await Promise.all(this.#active.values());
      await this.#transport.close();
    })();
    return this.#closing;
  }
}
