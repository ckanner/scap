/** A composition owns one deadline, including synchronous work before Fetch. */
import { performance } from 'node:perf_hooks';
import { duration } from './transport.js';
import { record, requireValue } from './wire.js';
import { ClientError, CommittedResultError } from './errors.js';

export class OperationBudget {
  #deadline;
  #controller = new AbortController();
  #signal;
  #onAbort;
  #timer;
  #stopped;
  #dispatched = new Set();

  constructor(defaultTimeout, options = {}) {
    const started = performance.now();
    record(options, [], ['timeoutMs', 'signal']);
    const timeout = duration(options.timeoutMs === undefined ? defaultTimeout : options.timeoutMs);
    this.#signal = options.signal;
    requireValue(this.#signal === undefined || this.#signal instanceof AbortSignal, 'Expected an AbortSignal');
    if (this.#signal?.aborted) throw new ClientError('ABORTED', 'The operation was aborted before transport');
    this.#deadline = started + timeout;
    this.#onAbort = () => this.#stop('ABORTED');
    this.#signal?.addEventListener('abort', this.#onAbort, { once: true });
    this.#timer = setTimeout(() => this.#stop('DEADLINE'), timeout);
  }

  #stop(code) {
    if (this.#stopped === undefined) this.#stopped = code;
    this.#controller.abort();
  }

  check() {
    if (performance.now() >= this.#deadline) this.#stop('DEADLINE');
    if (this.#stopped !== undefined) {
      throw new ClientError(this.#stopped, 'The original operation deadline or abort ended this call');
    }
  }

  options() {
    this.check();
    return { timeoutMs: Math.max(1, Math.ceil(this.#deadline - performance.now())), signal: this.#controller.signal };
  }

  fetch(fetcher, phase) {
    return (...args) => {
      // Inner Transport may have spent time serializing after options(). A
      // timer alone cannot stop synchronous JavaScript from dispatching late.
      this.check();
      this.#dispatched.add(phase);
      return fetcher(...args);
    };
  }

  dispatched(phase) { return this.#dispatched.has(phase); }

  finish(value) {
    try { this.check(); } catch (error) {
      if (value.state === 'committed') {
        throw new CommittedResultError(error.code, value.receipt, value.rawResult);
      }
      throw error;
    }
    return value;
  }

  close() {
    clearTimeout(this.#timer);
    this.#signal?.removeEventListener('abort', this.#onAbort);
    this.#controller.abort();
  }
}
