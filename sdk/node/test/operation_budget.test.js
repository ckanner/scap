import { test } from 'node:test';
import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { OperationBudget } from '../src/operation_budget.js';
import { ClientError, CommittedResultError, RouteError, OwnerReconcileError } from '../src/errors.js';

test('composition budget validates inputs and rejects pre-abort without allocating a timer', () => {
  for (const options of [null, { extra: 1 }, { signal: null }, { timeoutMs: 0 }, { timeoutMs: Infinity }]) {
    assert.throws(() => new OperationBudget(10, options), ClientError);
  }
  const controller = new AbortController(); controller.abort();
  assert.throws(() => new OperationBudget(10, { signal: controller.signal }), { code: 'ABORTED' });
});

test('composition budget checks absolute time before the actual fetch effect and after materialization', (t) => {
  let now = 0, sent = 0;
  t.mock.method(performance, 'now', () => now);
  const budget = new OperationBudget(10);
  assert.equal(budget.options().timeoutMs, 10);
  const fetch = budget.fetch(() => { sent++; return 'response'; }, 'execute');
  assert.equal(budget.dispatched('execute'), false);
  assert.equal(fetch(), 'response');
  assert.equal(budget.dispatched('execute'), true);
  const value = { state: 'queried' }; assert.equal(budget.finish(value), value);
  now = 11;
  assert.throws(fetch, { code: 'DEADLINE' }); assert.equal(sent, 1);
  assert.throws(() => budget.options(), { code: 'DEADLINE' });
  assert.throws(() => budget.finish(value), { code: 'DEADLINE' });
  const receipt = { original: true }, rawResult = new Uint8Array([1]);
  assert.throws(() => budget.finish({ state: 'committed', receipt, rawResult }),
    (e) => e instanceof CommittedResultError && e.receipt === receipt && e.rawResult === rawResult);
  budget.close();
});

test('composition abort and timer retain the first stop reason and release their listeners', (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const controller = new AbortController();
  const budget = new OperationBudget(50, { timeoutMs: 20, signal: controller.signal });
  const signal = budget.options().signal;
  t.mock.timers.tick(20);
  assert.equal(signal.aborted, true);
  controller.abort();
  assert.throws(() => budget.check(), { code: 'DEADLINE' });
  budget.close();
  const second = new AbortController(), next = new OperationBudget(50, { signal: second.signal });
  second.abort();
  assert.throws(() => next.check(), { code: 'ABORTED' });
  next.close();
});

test('new composition errors expose outcomes but never retain arbitrary thrown text', () => {
  for (const error of [new Error('secret bearer'), new ClientError('bad code secret', 'secret')]) {
    const routed = new RouteError(error);
    assert.equal(routed.code, 'CLIENT'); assert.equal(routed.outcome, 'not_sent');
    assert.equal(JSON.stringify(routed).includes('secret'), false);
  }
  assert.equal(new RouteError(new ClientError('DENIED', 'secret')).code, 'DENIED');
  const cases = [
    [null, false, false, 'not_sent'], [null, true, false, 'unresolved'],
    [{ active: false }, true, false, 'partial'], [{ active: true }, true, false, 'active'],
    [null, true, true, 'unknown'],
  ];
  for (const [known, sent, uncertain, outcome] of cases) {
    const error = new OwnerReconcileError({}, 'takeover', known, sent, uncertain, new ClientError('DEADLINE', 'secret'));
    assert.equal(error.outcome, outcome); assert.equal(error.lastConfirmed, known);
    assert.equal(JSON.stringify(error).includes('secret'), false);
  }
});
