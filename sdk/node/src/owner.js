/** Explicit, bounded owner coordination over existing authenticated endpoints. */
import { RouteRegistry } from './route_registry.js';
import { OperationBudget } from './operation_budget.js';
import { ClientError, RemoteError, UnknownError, OwnerReconcileError } from './errors.js';
import * as owner from './owner_intent.js';

export class OwnerClient {
  #registry;
  constructor(options) { this.#registry = new RouteRegistry(options); }
  get scope() { return this.#registry.direct.scope; }
  get principal() { return this.#registry.direct.principal; }
  observe(options) { return this.#registry.direct.status(options); }

  async probe(workerInstance, options) {
    const budget = new OperationBudget(this.#registry.timeout, options);
    let result;
    try {
      const status = await this.#registry.client(workerInstance, budget, 'probe')
        .guardedStatus(workerInstance, budget.options());
      result = budget.finish(status);
    } catch (error) {
      // The inner transport sees this budget's signal as an external abort.
      // Preserve the original operation's first deadline/abort at the exit.
      budget.check();
      throw error;
    } finally { budget.close(); }
    return result;
  }

  prepareTakeover(observed, input) { return owner.prepareIntent(this.#registry, observed, input, 'takeover'); }
  prepareActivation(observed, input) { return owner.prepareIntent(this.#registry, observed, input, 'activate'); }
  saveIntent(intent) { return owner.saveIntent(intent, this.#registry); }
  restoreIntent(serialized) { return owner.restoreIntent(serialized, this.#registry); }

  async inspect(intent, options) {
    const budget = new OperationBudget(this.#registry.timeout, options);
    try {
      owner.checkIntent(intent, this.#registry);
      const status = await this.#registry.client(null, budget, 'inspect').status(budget.options());
      return budget.finish(owner.inspectIntent(intent, status));
    } finally { budget.close(); }
  }

  async reconcile(intent, options) {
    const budget = new OperationBudget(this.#registry.recoveryTimeout, options);
    let phase = 'observe', lastConfirmed = null, result, validated = false;
    try {
      owner.checkIntent(intent, this.#registry);
      validated = true;
      owner.consumeIntent(intent, this.#registry);
      const current = await this.#registry.client(null, budget, phase).status(budget.options());
      budget.check();
      if (!owner.matchesBase(intent, current)) throw new ClientError('SUPERSEDED', 'The original owner observation no longer matches');
      for (const step of intent.mode === 'takeover' ? ['takeover', 'activate'] : ['activate']) {
        phase = step;
        const transition = owner.expected(intent, phase);
        const input = { expectedRevision: String(BigInt(transition.revision) - 1n), nonce: transition.nonce,
          expectedWorkerInstance: intent.targetWorker };
        const status = await this.#registry.client(intent.targetWorker, budget, phase)[phase](input, budget.options());
        if (!owner.matchesTransition(intent, phase, status)) {
          throw new UnknownError(Object.freeze({ scope: this.scope, operation: phase,
            expectedRevision: input.expectedRevision, nonce: input.nonce, expectedWorkerInstance: intent.targetWorker }));
        }
        lastConfirmed = status;
        budget.check();
      }
      result = Object.freeze({ state: 'active', intent, status: lastConfirmed });
    } catch (error) {
      // Invalid caller objects may contain secrets or arbitrary graphs. Only
      // a checked, immutable descriptor is safe to retain in an outcome error.
      if (!validated) throw error;
      // Verified remote rejection stays distinct from a lost response. The
      // original intent and last confirmed phase survive either failure.
      const dispatched = phase !== 'observe' && budget.dispatched(phase);
      const uncertain = dispatched && !(error instanceof RemoteError) && lastConfirmed?.transition.nonce !== owner.expected(intent, phase).nonce;
      throw new OwnerReconcileError(intent, phase, lastConfirmed, dispatched, uncertain, error);
    } finally { budget.close(); }
    return result;
  }
}
