/** Fresh owner discovery followed by at most one original business request. */
import { RouteRegistry } from './route_registry.js';
import { OperationBudget } from './operation_budget.js';
import { ClientError, RouteError } from './errors.js';
import { checkTracked, copyStatements } from './wire.js';

export class RoutedClient {
  #registry;
  constructor(options) { this.#registry = new RouteRegistry(options); }
  get scope() { return this.#registry.direct.scope; }
  get principal() { return this.#registry.direct.principal; }
  prepare(statements, request) { return this.#registry.direct.prepare(statements, request); }
  save(request) { return this.#registry.direct.save(request); }
  restore(serialized) { return this.#registry.direct.restore(serialized); }
  status(options) { return this.#registry.direct.status(options); }
  lookup(request, options) { return this.#registry.direct.lookup(request, options); }
  cancel(request, options) { return this.#registry.direct.cancel(request, options); }

  query(statements, options) { return this.#route('query', statements, options); }
  execute(request, options) { return this.#route('execute', request, options); }

  async #route(operation, input, options) {
    const budget = new OperationBudget(this.#registry.timeout, options);
    let result;
    try {
      const fixed = operation === 'execute' ? checkTracked(input, this.scope, this.principal) : copyStatements(input);
      const status = await this.#registry.client(null, budget, 'status').status(budget.options());
      if (status.lifecycle === 'deleted' || (operation === 'execute' && status.lifecycle !== 'ready')) {
        throw new ClientError('LIFECYCLE', 'The current lifecycle does not permit this routed operation');
      }
      if (operation === 'execute' && !status.active) {
        throw new ClientError('OWNER_INACTIVE', 'The current owner must be explicitly recovered and activated');
      }
      const client = this.#registry.client(status.owner_instance, budget, operation);
      result = budget.finish(await client[operation](fixed, budget.options()));
    } catch (error) {
      // A status failure may itself carry UNKNOWN. It did not send this SQL.
      if (!budget.dispatched(operation)) throw new RouteError(error);
      throw error;
    } finally { budget.close(); }
    return result;
  }
}
