/** One finite Scope, one original tick deadline and at most one durable owner step. */
import { performance } from 'node:perf_hooks';
import { isDeepStrictEqual } from 'node:util';
import { Client } from './client.js';
import { OwnerPlanClient } from './owner_plan.js';
import { OperationBudget } from './operation_budget.js';
import { ClientError, RemoteError, UnknownError } from './errors.js';
import { record, requireValue, sameOwnerReference, ownerPending } from './wire.js';
import { checkControllerPolicy, belongsToController } from './controller_policy.js';

const U64 = (1n << 64n) - 1n;
const MUTATIONS = new Set(['owner_prepare', 'owner_claim', 'owner_resume', 'owner_abort']);
const READS = new Set(['status', 'owner_inspect']);
const SUSPECT = (error) => error instanceof ClientError && !(error instanceof RemoteError) &&
  ['TRANSPORT', 'DEADLINE'].includes(error.code);
const safeCode = (error) => error instanceof ClientError && /^[A-Z_]{1,40}$/.test(error.code) ? error.code : 'CLIENT';

export class OwnerController {
  #policy; #common; #fetch; #busy = false; #closed = false; #budget;
  #done = Promise.resolve(); #release;
  #base = null; #prepared = null; #windows = new Map(); #candidate = 0; #metadata = null;
  #recovery = false; #unknown = false; #lastUncertain = null; #next = 0; #backoff = 0; #last = null;

  constructor(options) {
    record(options, ['policy', 'token', 'fetch']);
    this.#policy = checkControllerPolicy(options.policy);
    requireValue(typeof options.fetch === 'function', 'Expected the owned controller HTTP transport');
    this.#fetch = options.fetch;
    const p = this.#policy;
    this.#common = Object.freeze({ scope: p.scope, principal: p.principal, token: options.token,
      allowInsecureHttp: p.allowInsecureHttp, maxRequestBytes: p.limits.requestBytes,
      maxResponseBytes: p.limits.responseBytes, timeoutMs: p.limits.timeoutMs,
      recoveryTimeoutMs: p.limits.recoveryTimeoutMs });
    // Validate credentials and the real SDK configuration before retaining any work.
    new Client({ ...this.#common, endpoint: p.metadataEndpoints[0], fetch: this.#fetch });
  }

  get policy() { return this.#policy; }
  get needsRecovery() { return this.#recovery; }
  get nextTickAt() { return this.#next; }
  get lastReport() { return this.#last; }

  async close() { this.#closed = true; this.#budget?.close(); await this.#done; }

  async tick(options = {}) {
    const recovery = this.#recovery, maximum = recovery ? this.#policy.limits.recoveryTimeoutMs : this.#policy.limits.timeoutMs;
    const budget = new OperationBudget(maximum, options);
    const context = { budget, recovery, calls: 0, mutations: 0, head: null, phase: null, endpoint: null, original: null };
    try {
      requireValue(options.timeoutMs === undefined || options.timeoutMs <= maximum, 'Tick cannot extend its policy deadline');
      if (this.#busy) throw new ClientError('BACKPRESSURE', 'A Scope already has an owned tick');
      if (this.#closed) throw new ClientError('ABORTED', 'The controller is closed');
      if (performance.now() < this.#next) {
        budget.check();
        const report = this.#report(context, 'waiting', 'INTERVAL');
        budget.close();
        return report;
      }
    } catch (error) { budget.close(); throw error; }
    this.#busy = true; this.#budget = budget;
    this.#done = new Promise((resolve) => { this.#release = resolve; });
    let outcome;
    try {
      outcome = await this.#advance(context);
      budget.check();
      this.#backoff = 0;
      this.#next = performance.now() + this.#policy.limits.tickIntervalMs;
    } catch (error) {
      this.#windows.clear();
      const uncertain = error instanceof UnknownError || (context.mutations > 0 && !(error instanceof RemoteError));
      const code = uncertain ? 'UNKNOWN' : safeCode(error);
      if (uncertain) {
        this.#unknown = true;
        this.#lastUncertain = context.original ?? Object.freeze({ operation: error.reference.operation,
          reference: JSON.stringify(error.reference) });
      }
      if (['BACKPRESSURE', 'RECOVERY_BUSY', 'LIMIT'].includes(code)) {
        const delays = this.#policy.limits.backoffMs;
        this.#next = performance.now() + delays[this.#backoff];
        this.#backoff = Math.min(this.#backoff + 1, delays.length - 1);
        outcome = ['waiting', code];
      } else {
        this.#next = performance.now() + this.#policy.limits.tickIntervalMs;
        outcome = [uncertain ? 'unknown' : 'blocked', code];
      }
    } finally {
      budget.close(); this.#budget = undefined; this.#busy = false; this.#release();
    }
    return this.#report(context, ...outcome);
  }

  #report(context, state, reason) {
    const value = Object.freeze({ version: 1, scope: this.#policy.scope, policyDigest: this.#policy.digest,
      state, reason, currentAuthority: context.head, acceptedPhase: context.phase,
      httpCalls: context.calls, mutations: context.mutations, recoveryBudget: context.recovery,
      pastUnknown: this.#unknown, lastUncertainCall: this.#lastUncertain,
      nativeSession: 'NOT_CERTIFIED', nextTickAt: this.#next });
    this.#last = value;
    return value;
  }

  #network(context) {
    return context.budget.fetch((url, init) => {
      const operation = JSON.parse(init.body).operation;
      requireValue(READS.has(operation) || MUTATIONS.has(operation), 'Controller cannot dispatch SQL or another API');
      if (context.calls >= this.#policy.limits.httpCalls) throw new ClientError('LIMIT', 'Tick HTTP admission is exhausted');
      if (MUTATIONS.has(operation)) {
        if (context.mutations >= 1) throw new ClientError('LIMIT', 'Only one owner mutation is admitted per tick');
        context.mutations++;
        context.original = Object.freeze({ operation, request: init.body });
      }
      context.calls++;
      return this.#fetch(url, init);
    }, 'controller');
  }

  #direct(context, endpoint) { return new Client({ ...this.#common, endpoint, fetch: this.#network(context) }); }
  #owner(context) {
    return new OwnerPlanClient({ ...this.#common, bootstrapEndpoint: context.endpoint,
      routes: this.#policy.workers.map(({ workerInstance, endpoint }) => ({ workerInstance, endpoint })),
      fetch: this.#network(context) });
  }
  #probeOptions(context) {
    const options = context.budget.options();
    return { ...options, timeoutMs: Math.min(options.timeoutMs, this.#policy.limits.probeTimeoutMs) };
  }
  #worker(id) { return this.#policy.workers.find((worker) => worker.workerInstance === id); }

  async #authority(context, excluded = null) {
    // A successful allowlisted endpoint is only a routing hint. Every use still
    // performs a new authority read; no HEAD or permission is served from cache.
    const endpoints = [...this.#policy.metadataEndpoints].sort((a, b) =>
      a === this.#metadata ? -1 : b === this.#metadata ? 1 : 0);
    for (const endpoint of endpoints) {
      if (endpoint === excluded) continue;
      try {
        const head = await this.#direct(context, endpoint).status(this.#probeOptions(context));
        context.budget.check();
        this.#metadata = endpoint;
        return { head, endpoint };
      } catch (error) {
        context.budget.check();
        if (!SUSPECT(error)) throw error;
      }
    }
    throw new ClientError('UNAVAILABLE', 'No independent fresh metadata authority was observed');
  }

  #unchanged(context, head) {
    if (!isDeepStrictEqual(context.head, head)) throw new ClientError('STALE', 'Authority changed during this tick');
  }

  async #probe(context, worker, slot) {
    try {
      const head = await this.#direct(context, worker.endpoint).guardedStatus(worker.workerInstance, this.#probeOptions(context));
      this.#unchanged(context, head);
      this.#windows.delete(slot);
      return { healthy: true, mature: false };
    } catch (error) {
      context.budget.check();
      if (!SUSPECT(error)) throw error;
      const confirmation = await this.#authority(context, worker.endpoint);
      this.#unchanged(context, confirmation.head);
      const now = performance.now(), previous = this.#windows.get(slot), limits = this.#policy.limits;
      let window = previous;
      if (window === undefined || window.worker !== worker.workerInstance) {
        window = { worker: worker.workerInstance, first: now, last: now, count: 1 };
      } else if (now - window.last >= limits.failureIntervalMs) {
        window = { ...window, last: now, count: Math.min(window.count + 1, limits.failureCount) };
      }
      this.#windows.set(slot, window);
      return { healthy: false, mature: window.count >= limits.failureCount && now - window.first >= limits.failureSpanMs };
    }
  }

  #sameObservation(context, observation) {
    this.#unchanged(context, observation.status);
    if (!belongsToController(this.#policy, observation.prepared.input)) {
      throw new ClientError('POLICY', 'The durable first winner belongs to a foreign owner policy');
    }
  }

  async #mutate(context, method, value) {
    const result = await this.#owner(context)[method](value, context.budget.options());
    context.budget.check();
    if (result.state === 'prepared') {
      this.#prepared = result.prepared;
      return ['prepared', 'ORIGINAL_INPUT_VERIFIED'];
    }
    if (result.state === 'pending') return ['waiting', 'ACCEPTED_PLAN_CHANGED'];
    context.head = result.status; context.phase = result.accepted?.phase.kind ?? null;
    this.#recovery = result.state === 'claimed';
    return [result.state === 'active' ? 'active_observed' : result.state, 'VERIFIED_OWNER_OBSERVATION'];
  }

  async #advance(context) {
    const authority = await this.#authority(context);
    context.head = authority.head; context.endpoint = authority.endpoint;
    const head = context.head, policy = this.#policy;
    if (!isDeepStrictEqual(this.#base, head)) {
      this.#base = head; this.#windows.clear(); this.#prepared = null; this.#candidate = 0;
    }
    this.#recovery = head.owner_plan?.phase.kind === 'claimed';
    if (head.lifecycle !== 'ready' || head.storage.plan !== null || head.storage.sweep !== null || head.storage.terminal !== null) {
      return ['blocked', 'LIFECYCLE_OR_STORAGE_MAINTENANCE'];
    }
    const current = this.#worker(head.owner_instance);
    if (current === undefined) return ['blocked', 'UNKNOWN_OWNER'];
    if (head.owner_plan !== null) {
      if (head.owner_plan.reference.creator !== policy.principal) return ['blocked', 'FOREIGN_CREATOR'];
      const observation = await this.#owner(context).observe({ creator: head.owner_plan.reference.creator,
        operation: head.owner_plan.reference.operation }, context.budget.options());
      this.#sameObservation(context, observation);
      // ownerObserve verifies the requested immutable identity against the current
      // marker; the strict decoder rejects a missing or different accepted plan.
      // #sameObservation also requires this exact initial current HEAD.
      context.phase = observation.accepted.phase.kind;
      if (ownerPending(observation.accepted)) return this.#accepted(context, observation);
    }
    const health = await this.#probe(context, current, 'owner');
    if (head.active && health.healthy) return ['healthy', 'CURRENT_OWNER_RESPONDED'];
    if (!health.healthy && !health.mature) return ['waiting', 'OWNER_SUSPICION_INCOMPLETE'];
    if (health.healthy && !policy.modes.activate) return ['blocked', 'AUTOMATIC_ACTIVATION_DISABLED'];
    if (!health.healthy && !policy.modes.takeover) return ['blocked', 'AUTOMATIC_TAKEOVER_DISABLED'];
    if (BigInt(head.revision) > U64 - 2n || BigInt(head.head_serial) > U64 - 2n ||
      (!health.healthy && BigInt(head.owner_epoch) === U64)) return ['blocked', 'COUNTER_RESERVE_EXHAUSTED'];
    return this.#unaccepted(context, current, health);
  }

  async #accepted(context, observation) {
    const client = this.#owner(context), saved = client.prepareInput(observation.prepared.input);
    const inspected = await client.inspect(saved, context.budget.options());
    this.#sameObservation(context, inspected);
    if (inspected.state === 'cancelling') {
      return this.#policy.modes.cancel ? this.#mutate(context, 'abort', inspected.prepared) : ['blocked', 'AUTOMATIC_CANCEL_DISABLED'];
    }
    const target = this.#worker(inspected.prepared.input.target_worker);
    const health = await this.#probe(context, target, 'target');
    if (!health.healthy) {
      if (!health.mature) return ['waiting', 'TARGET_SUSPICION_INCOMPLETE'];
      return this.#policy.modes.cancel ? this.#mutate(context, 'abort', inspected.prepared) : ['blocked', 'AUTOMATIC_CANCEL_DISABLED'];
    }
    if (!context.recovery) return ['waiting', 'RECOVERY_REQUIRES_NEXT_TICK_BUDGET'];
    return this.#mutate(context, 'resume', inspected.prepared);
  }

  async #unaccepted(context, current, health) {
    const client = this.#owner(context), head = context.head, p = this.#policy;
    const identity = { creator: p.principal, operation: head.head_serial };
    let observation;
    try { observation = await client.observe(identity, context.budget.options()); }
    catch (error) { if (!(error instanceof RemoteError && error.code === 'MISSING')) throw error; }
    if (observation !== undefined) {
      this.#sameObservation(context, observation);
      const input = observation.prepared.input, target = this.#worker(input.target_worker);
      if (this.#prepared !== null && (!sameOwnerReference(this.#prepared.reference, observation.prepared.reference) ||
        !isDeepStrictEqual(this.#prepared.input, input))) {
        throw new ClientError('CORRUPT', 'The immutable first winner contradicts the previously verified descriptor');
      }
      if (observation.state !== 'prepared' || (input.mode === 'activate' ?
        head.active || input.target_worker !== current.workerInstance : target.rank <= current.rank)) {
        return ['blocked', 'FIRST_WINNER_BASE_OR_RANK_MISMATCH'];
      }
      // #advance already returned for a healthy active owner. A healthy inactive
      // owner cannot activate while a first-winner takeover occupies this S.
      // Explicitly cancel that fixed plan, then a later S may prepare activation.
      const cancelInactive = input.mode === 'takeover' && health.healthy;
      const targetHealth = cancelInactive ? null : input.target_worker === current.workerInstance ?
        health : await this.#probe(context, target, 'target');
      const cancel = cancelInactive || !targetHealth.healthy;
      if (cancel && !cancelInactive && (!health.mature || !targetHealth.mature)) return ['waiting', 'FIXED_TARGET_SUSPICION_INCOMPLETE'];
      if (cancel && !p.modes.cancel) return ['blocked', 'AUTOMATIC_CANCEL_DISABLED'];
      const saved = client.prepareInput(input);
      if (this.#prepared === null) {
        return this.#mutate(context, 'prepare', saved);
      }
      const inspected = await client.inspect(saved, context.budget.options());
      this.#sameObservation(context, inspected);
      if (inspected.state !== 'prepared') return ['waiting', 'FIRST_WINNER_CHANGED'];
      return this.#mutate(context, cancel ? 'abort' : 'claim', inspected.prepared);
    }
    let target = current;
    if (!health.healthy) {
      const higher = p.workers.filter((worker) => worker.rank > current.rank);
      if (higher.length === 0) return ['blocked', 'REGISTRY_RANK_EXHAUSTED'];
      target = higher[this.#candidate % higher.length];
      this.#candidate = (this.#candidate + 1) % higher.length;
      if (!(await this.#probe(context, target, 'target')).healthy) return ['waiting', 'CANDIDATE_UNAVAILABLE'];
    }
    const saved = client.prepareInput({ ...identity, expected_revision: head.revision, expected_head_serial: head.head_serial,
      mode: health.healthy ? 'activate' : 'takeover', target_worker: target.workerInstance, nonces: p.nonces });
    return this.#mutate(context, 'prepare', saved);
  }
}
