/** Bounded local configuration and a finite, joinable controller process loop. */
import fs from 'node:fs';
import { Buffer } from 'node:buffer';
import timers from 'node:timers/promises';
import { OwnerControllerFleet } from './controller_fleet.js';
import { createControllerPolicy, CONTROLLER_LIMITS } from './controller_policy.js';
import { ClientError } from './errors.js';
import { decimal, parseJson, record, requireValue } from './wire.js';
import { controllerLineage } from './controller_lineage.js';

const CONFIG_BYTES = 64 * 1024;
const REPORT_BYTES = 128 * 1024;

/** Credentials are resolved from explicit environment names, never stored in this JSON. */
export function readControllerEntries(path, environment = process.env) {
  return readControllerConfiguration(path, environment).entries;
}

/** Version 2 adds an explicit deployment revision and complete bounded policy history. */
export function readControllerConfiguration(path, environment = process.env) {
  let fd, configuration;
  try {
    requireValue(typeof path === 'string' && path.length > 0, 'Expected a configuration path');
    fd = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NONBLOCK);
    const before = fs.fstatSync(fd, { bigint: true });
    requireValue(before.isFile() && before.size <= CONFIG_BYTES, 'Expected a bounded regular configuration file');
    const bytes = Buffer.alloc(CONFIG_BYTES + 1);
    let length = 0;
    while (length < bytes.length) {
      const count = fs.readSync(fd, bytes, length, bytes.length - length, length);
      if (count === 0) break;
      length += count;
    }
    const after = fs.fstatSync(fd, { bigint: true });
    requireValue(length <= CONFIG_BYTES && BigInt(length) === before.size && before.size === after.size &&
      before.mtimeNs === after.mtimeNs && before.ctimeNs === after.ctimeNs, 'Configuration changed while being read');
    const value = parseJson(new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, length)));
    record(value, ['version', 'scopes'], ['revision']);
    requireValue((value.version === 1 && value.revision === undefined) || value.version === 2,
      'Expected controller configuration version one or two');
    const revision = value.version === 2 ? decimal(value.revision) : null;
    requireValue(Array.isArray(value.scopes) && value.scopes.length > 0 &&
      value.scopes.length <= CONTROLLER_LIMITS.scopes, 'Expected one to 128 configured Scopes');
    const entries = Object.freeze(value.scopes.map((entry) => {
      record(entry, ['policy', 'tokenEnv'], value.version === 2 ? ['previousPolicies'] : []);
      requireValue(typeof entry.tokenEnv === 'string' && /^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(entry.tokenEnv) &&
        Object.hasOwn(environment, entry.tokenEnv), 'Expected an explicit credential environment variable');
      const token = environment[entry.tokenEnv];
      requireValue(typeof token === 'string' && /^[\x21-\x7e]{32,1024}$/.test(token), 'Expected a bounded credential');
      const policy = createControllerPolicy(entry.policy);
      if (value.version === 1) return Object.freeze({ policy, token });
      requireValue(Array.isArray(entry.previousPolicies), 'Version two requires explicit complete policy history');
      const previousPolicies = Object.freeze(entry.previousPolicies.map(createControllerPolicy));
      controllerLineage(policy, previousPolicies);
      return Object.freeze({ policy, token, previousPolicies });
    }));
    configuration = Object.freeze({ revision, entries });
  } catch { throw new ClientError('CONFIG', 'Invalid bounded controller configuration'); }
  finally { if (fd !== undefined) fs.closeSync(fd); }
  return configuration;
}

function writeReport(fd, report) {
  try {
    const bytes = Buffer.from(JSON.stringify(report) + '\n');
    requireValue(bytes.length <= REPORT_BYTES, 'Controller report exceeds its output bound');
    // A single synchronous write creates no user-space logging queue. EAGAIN,
    // a partial write or another error stops admission instead of buffering.
    requireValue(fs.writeSync(fd, bytes) === bytes.length, 'Incomplete controller report write');
  } catch { throw new ClientError('OUTPUT', 'The bounded controller report could not be written'); }
}

/** Own the fleet until shutdown; the output fd stays caller-owned. */
export async function runControllerFleet(fleet, options) {
  requireValue(fleet instanceof OwnerControllerFleet, 'Expected an owned controller fleet');
  record(options, ['signal'], ['outputFd', 'reload']);
  const { signal, outputFd = 1 } = options;
  requireValue(signal instanceof AbortSignal && Number.isSafeInteger(outputFd) && outputFd >= 0,
    'Expected a shutdown signal and output descriptor');
  requireValue(options.reload === undefined || typeof options.reload === 'function', 'Expected a bounded reload source');
  try {
    while (!signal.aborted) {
      if (options.reload !== undefined) {
        let report;
        try {
          const configuration = options.reload();
          if (configuration !== null) {
            const changed = await fleet.replace(configuration);
            report = { version: 1, event: 'fleet_reloaded', ...changed };
          }
        } catch {
          report = { version: 1, event: 'fleet_reload_rejected', revision: fleet.revision };
        }
        if (report !== undefined) writeReport(outputFd, report);
        if (signal.aborted) break;
      }
      fleet.poll();
      for (const report of fleet.takeReports()) writeReport(outputFd, report);
      try { await timers.setTimeout(250, undefined, { signal }); }
      catch (error) { if (!signal.aborted) throw error; }
    }
  } finally { await fleet.close(); }
}

/** Thin CLI assembly calls this covered implementation; no credentials or raw errors are printed. */
export async function controllerMain() {
  const stopped = new AbortController(), stop = () => stopped.abort();
  let reloadRequested = false;
  const reload = () => { reloadRequested = true; };
  let result = 0;
  process.on('SIGINT', stop); process.on('SIGTERM', stop);
  process.on('SIGHUP', reload);
  try {
    requireValue(process.argv.length === 3, 'Expected one configuration path');
    const path = process.argv[2], configuration = readControllerConfiguration(path);
    const fleet = new OwnerControllerFleet({ entries: configuration.entries,
      ...(configuration.revision === null ? {} : { revision: configuration.revision }) });
    await runControllerFleet(fleet, { signal: stopped.signal, reload: () => {
      if (!reloadRequested) return null;
      reloadRequested = false;
      return readControllerConfiguration(path);
    } });
  } catch {
    try { fs.writeSync(2, 'scap-owner-controller: stopped; check the bounded configuration, credentials and report destination\n'); }
    catch { /* A broken diagnostic destination must not skip owned-resource cleanup. */ }
    result = 1;
  } finally {
    process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop);
    process.removeListener('SIGHUP', reload);
  }
  return result;
}
