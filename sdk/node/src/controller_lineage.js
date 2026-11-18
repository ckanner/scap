/** Explicit bounded deployment history; a server response cannot authorize a policy. */
import { isDeepStrictEqual } from 'node:util';
import { Buffer } from 'node:buffer';
import { checkControllerPolicy, CONTROLLER_LIMITS } from './controller_policy.js';
import { requireValue } from './wire.js';

export const POLICY_HISTORY_LIMIT = 16;

export function retiredWorker(policy, worker) {
  return policy.retiredWorkers?.includes(worker) ?? false;
}

/** Only membership, irreversible retirement and trusted metadata routes evolve. */
export function controllerLineage(policy, previousPolicies = []) {
  checkControllerPolicy(policy);
  requireValue(Array.isArray(previousPolicies) && previousPolicies.length <= POLICY_HISTORY_LIMIT,
    'Controller history exceeds sixteen previous policies');
  const lineage = [...previousPolicies.map(checkControllerPolicy), policy];
  requireValue(new Set(lineage.map((item) => item.digest)).size === lineage.length,
    'Controller policy history contains a duplicate');
  let bytes = 0;
  for (let index = 0; index < lineage.length; index++) {
    const current = lineage[index];
    bytes += Buffer.byteLength(current.canonical);
    requireValue(bytes <= CONTROLLER_LIMITS.policyBytes, 'Controller history exceeds 64 KiB');
    if (index === 0) continue;
    const previous = lineage[index - 1];
    for (const key of ['scope', 'authorityId', 'principal', 'modes', 'allowInsecureHttp', 'limits']) {
      requireValue(isDeepStrictEqual(previous[key], current[key]), 'Controller history changes fixed authority or permissions');
    }
    const oldWorkers = new Map(previous.workers.map((worker) => [worker.workerInstance, worker]));
    for (const worker of previous.workers) {
      requireValue(current.workers.some((item) => isDeepStrictEqual(item, worker)),
        'A historical worker identity, endpoint or rank changed');
      requireValue(!retiredWorker(previous, worker.workerInstance) || retiredWorker(current, worker.workerInstance),
        'A retired worker cannot be reactivated');
    }
    const maximum = previous.workers.at(-1).rank;
    for (const worker of current.workers) {
      requireValue(oldWorkers.has(worker.workerInstance) || worker.rank > maximum,
        'New worker ranks must exceed every previous rank');
    }
  }
  return Object.freeze(lineage);
}

/** A reload keeps every previous commitment, including removed Scope history. */
export function extendsLineage(previous, next) {
  requireValue(next.length >= previous.length && previous.every((policy, index) => policy.digest === next[index].digest),
    'Reload cannot discard or rewrite previously admitted policy history');
}

/** Retired routes remain evidence only; duplicate endpoints select the live incarnation. */
export function controllerRoutes(policy) {
  const routes = new Map();
  for (const worker of policy.workers) {
    if (!routes.has(worker.endpoint) || !retiredWorker(policy, worker.workerInstance)) {
      routes.set(worker.endpoint, { workerInstance: worker.workerInstance, endpoint: worker.endpoint });
    }
  }
  return [...routes.values()];
}
