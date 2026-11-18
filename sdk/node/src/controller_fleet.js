/** Finite scheduler. One slot owns its tick until completion; polling never queues another round. */
import { Buffer } from 'node:buffer';
import { performance } from 'node:perf_hooks';
import { OwnerController } from './controller.js';
import { ControllerHttp } from './controller_http.js';
import { CONTROLLER_LIMITS, controllerScopeKey } from './controller_policy.js';
import { controllerLineage, extendsLineage, retiredWorker } from './controller_lineage.js';
import { ClientError } from './errors.js';
import { decimal, record, requireValue } from './wire.js';

function configuration(supplied, previous = new Map()) {
  requireValue(Array.isArray(supplied) && supplied.length > 0 && supplied.length <= CONTROLLER_LIMITS.scopes,
    'Expected one to 128 configured Scopes');
  const entries = new Map(), known = new Map(previous);
  for (const entry of supplied) {
    record(entry, ['policy', 'token'], ['previousPolicies']);
    const lineage = controllerLineage(entry.policy, entry.previousPolicies), policy = lineage.at(-1);
    const key = controllerScopeKey(policy.scope);
    requireValue(!entries.has(key), 'Duplicate configured Scope');
    if (previous.has(key)) extendsLineage(previous.get(key), lineage);
    known.set(key, lineage);
    entries.set(key, { policy, token: entry.token, previousPolicies: lineage.slice(0, -1) });
  }
  requireValue(known.size <= CONTROLLER_LIMITS.scopes, 'Fleet lifetime exceeds 128 distinct Scopes');
  let bytes = 0;
  const workers = new Map(), retired = new Set();
  for (const lineage of known.values()) {
    const policy = lineage.at(-1);
    for (const historical of lineage) bytes += Buffer.byteLength(historical.canonical);
    requireValue(bytes <= CONTROLLER_LIMITS.policyBytes, 'Combined controller history exceeds 64 KiB');
    for (const worker of policy.workers) {
      const id = policy.authorityId + ':' + worker.workerInstance, route = JSON.stringify(worker);
      requireValue(!workers.has(id) || workers.get(id).route === route, 'A worker incarnation changed its fixed route or rank');
      workers.set(id, { route, endpoint: policy.authorityId + ':' + worker.endpoint });
      if (retiredWorker(policy, worker.workerInstance)) retired.add(id);
    }
  }
  requireValue(workers.size <= CONTROLLER_LIMITS.workers, 'Fleet lifetime exceeds 256 worker incarnations');
  const endpoints = new Set();
  for (const [id, worker] of workers) {
    if (retired.has(id)) continue;
    requireValue(!endpoints.has(worker.endpoint), 'An endpoint represents two live worker incarnations');
    endpoints.add(worker.endpoint);
  }
  for (const { policy } of entries.values()) {
    for (const worker of policy.workers) {
      requireValue(!retired.has(policy.authorityId + ':' + worker.workerInstance) || retiredWorker(policy, worker.workerInstance),
        'A retired incarnation cannot remain active in another Scope');
    }
  }
  return { entries, known };
}

export class OwnerControllerFleet {
  #controllers = new Map(); #active = new Map(); #tenants = new Map(); #reports = new Map();
  #transport; #recoveries = 0; #cursor = 0; #closed = false; #closing;
  #known; #revision; #reloading; #updating = false; #predecessors = new Map();

  constructor(options) {
    record(options, ['entries'], ['transport', 'revision']);
    this.#revision = options.revision === undefined ? null : decimal(options.revision);
    const { entries, known } = configuration(options.entries);
    this.#known = known;
    this.#transport = options.transport === undefined ? new ControllerHttp() : options.transport;
    requireValue(this.#transport !== null && typeof this.#transport.fetch === 'function' &&
      typeof this.#transport.close === 'function', 'Expected an owned HTTP transport with a joinable close');
    requireValue(this.#revision === null || typeof this.#transport.quiesce === 'function',
      'A dynamic fleet requires a transport that can quiesce original network resources');
    this.#controllers = this.#construct(entries);
  }

  #construct(entries) {
    const controllers = new Map();
    for (const [key, { policy, token, previousPolicies }] of entries) {
      const tenant = policy.scope.deployment + ':' + policy.scope.tenant;
      controllers.set(key, { tenant, controller: new OwnerController({ policy, token, previousPolicies,
        fetch: (...args) => this.#transport.fetch(...args) }) });
    }
    return controllers;
  }

  get revision() { return this.#revision; }
  get updating() { return this.#updating; }

  /** Validate first; stop admission and join all old ticks before one snapshot swap. */
  replace(options) {
    if (this.#closed) return Promise.reject(new ClientError('ABORTED', 'The fleet is closed'));
    if (this.#updating) return Promise.reject(new ClientError('BACKPRESSURE', 'A fleet reload already owns the transition'));
    let revision, configured, controllers;
    try {
      record(options, ['revision', 'entries']);
      revision = decimal(options.revision);
      requireValue(this.#revision !== null && BigInt(revision) > BigInt(this.#revision), 'Fleet revision must strictly advance');
      configured = configuration(options.entries, this.#known);
      controllers = this.#construct(configured.entries);
    } catch (error) { return Promise.reject(error); }
    this.#updating = true;
    this.#reloading = (async () => {
      await Promise.all([...this.#controllers.values()].map(({ controller }) => controller.close()));
      await Promise.all(this.#active.values());
      await this.#transport.quiesce();
      if (this.#closed) throw new ClientError('ABORTED', 'Shutdown superseded the fleet reload');
      for (const [key, { controller }] of this.#controllers) this.#predecessors.set(key, controller);
      for (const [key, { controller }] of controllers) {
        const previous = this.#predecessors.get(key);
        if (previous !== undefined) controller.inheritUncertainty(previous);
      }
      this.#controllers = controllers; this.#known = configured.known;
      this.#revision = revision; this.#cursor = 0;
      return Object.freeze({ revision, scopes: controllers.size });
    })().catch((error) => {
      // Configuration rejection happens before this transition. Once old
      // controllers close, a broken join contract cannot leave a live fleet.
      this.#closed = true;
      throw error;
    }).finally(() => { this.#updating = false; });
    return this.#reloading;
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
    if (this.#updating) return Object.freeze({ started: 0, ...this.snapshot() });
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
      try { await this.#reloading; } catch { /* Shutdown still joins the old controllers and transport. */ }
      await Promise.all([...this.#controllers.values()].map(({ controller }) => controller.close()));
      await Promise.all(this.#active.values());
      await this.#transport.close();
    })();
    return this.#closing;
  }
}
