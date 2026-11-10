/** Explicit durable administration. Each network method makes one bounded POST. */
import { RouteRegistry } from './route_registry.js';
import { OperationBudget } from './operation_budget.js';
import { ClientError, RemoteError, UnknownError } from './errors.js';
import * as owner from './owner_plan_wire.js';

export class OwnerPlanClient {
  #registry;
  constructor(options) { this.#registry = new RouteRegistry(options); }
  get scope() { return this.#registry.direct.scope; }
  get principal() { return this.#registry.direct.principal; }
  prepareInput(input) { return owner.prepareInput(input, this.scope); }
  saveInput(input) { return owner.saveInput(input, this.scope); }
  restoreInput(serialized) { return owner.restoreInput(serialized, this.scope); }

  prepare(input, options) { return this.#call('prepare', input, options); }
  inspect(input, options) { return this.#call('inspect', input, options); }
  observe(identity, options) { return this.#call('observe', identity, options); }
  claim(prepared, options) { return this.#call('claim', prepared, options); }
  resume(prepared, options) { return this.#call('resume', prepared, options); }
  abort(prepared, options) { return this.#call('abort', prepared, options); }

  async #call(method, supplied, options) {
    const budget = new OperationBudget(method === 'resume' ? this.#registry.recoveryTimeout : this.#registry.timeout, options);
    const read = method === 'inspect' || method === 'observe';
    const operation = `owner_${method === 'observe' ? 'inspect' : method}`;
    let reference, result;
    try {
      const value = ['prepare', 'inspect'].includes(method) ? owner.checkSaved(supplied, this.scope).input :
        method === 'observe' ? owner.identity(supplied) : owner.checkPrepared(supplied, this.scope);
      const worker = ['claim', 'resume'].includes(method) ? value.input.target_worker : null;
      reference = Object.freeze({ scope: this.scope, operation,
        ...(method === 'prepare' ? { ownerInput: value } : read ? { ownerIdentity: owner.identity({ creator: value.creator,
          operation: value.operation }) } : { ownerPlan: value.reference }),
        ...(worker === null ? {} : { expectedWorkerInstance: worker }) });
      const client = this.#registry.client(worker, budget, operation);
      const name = `owner${method[0].toUpperCase()}${method.slice(1)}`;
      result = budget.finish(await client[name](value, budget.options()));
    } catch (error) {
      if (error instanceof RemoteError) throw error;
      // The inner transport sees this budget as an external AbortSignal.
      // Preserve the first original deadline/abort without renewing the call.
      let cause = error;
      try { budget.check(); } catch (stopped) { cause = stopped; }
      if (error instanceof UnknownError) {
        if (cause === error) throw error;
        throw new UnknownError(error.reference, cause);
      }
      if (!read && budget.dispatched(operation)) {
        throw new UnknownError(reference, new ClientError(cause.code, 'The original owner operation ended after dispatch'));
      }
      throw cause;
    } finally { budget.close(); }
    return result;
  }
}
