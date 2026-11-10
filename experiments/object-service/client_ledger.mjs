/** Fixture-only evidence capture. It performs no retries or result decoding. */
import { createHash } from 'node:crypto';
import { openSync, writeSync, fsyncSync, closeSync } from 'node:fs';
import { createObservation, safeError } from './client_transport.mjs';

const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
const now = () => process.hrtime.bigint().toString();

export function createLedger(directory, phase, { fetch: fetcher = globalThis.fetch } = {}) {
  let attempts = 0;
  const latest = new Map();
  let observation;
  function writeRows(file, rows) {
    const descriptor = openSync(directory + '/' + file, 'a', 0o600);
    try {
      for (const row of rows) writeSync(descriptor, JSON.stringify({ schema: 1, phase, ...row }) + '\n');
      fsyncSync(descriptor);
    } finally { closeSync(descriptor); }
  }
  function append(file, value) {
    writeRows(file, [{ monotonic_ns: now(), ...value }]);
    observation?.flush();
  }
  observation = createObservation((rows) => writeRows('http-client-transport.jsonl', rows));
  const atExit = () => observation.close();
  process.once('exit', atExit);
  function close() { process.removeListener('exit', atExit); observation.close(); }
  function transport(client) {
    return async (url, options) => {
      const id = `${phase}:${process.pid}:${++attempts}`;
      latest.set(client, id);
      const body = Buffer.from(options.body, 'utf8');
      const headers = new Headers(options.headers);
      append('http-client-ledger.jsonl', { event: 'http_request', call_id: id, client,
        url: String(url), method: options.method,
        headers: { 'content-type': headers.get('content-type'), 'x-scap-admission': headers.get('x-scap-admission') },
        body: body.toString('base64'), body_sha256: sha(body) });
      const observed = observation.begin(id);
      let stage = 'fetch', outcome = 'failed';
      try {
        const response = await observation.run(observed, () => fetcher(url, options));
        stage = 'response_headers';
        const status = response.status;
        observation.event(observed, 'fetch_response_headers', {
          status: Number.isInteger(status) && status >= 100 && status <= 599 ? status : 'UNKNOWN' });
        stage = 'body';
        observation.event(observed, 'fetch_body_started');
        const raw = Buffer.from(await response.clone().arrayBuffer());
        observation.event(observed, 'fetch_body_complete');
        stage = 'evidence';
        append('http-client-ledger.jsonl', { event: 'http_response', call_id: id, client,
          status: response.status, headers: { 'content-type': response.headers.get('content-type') },
          body: raw.toString('base64'), body_sha256: sha(raw) });
        outcome = 'response';
        return response;
      } catch (error) {
        const safe = safeError(error);
        observation.event(observed, 'fetch_failure', { stage, ...safe });
        append('http-client-ledger.jsonl', { event: 'http_transport_error', call_id: id, client,
          error_name: safe.error_name });
        throw error;
      } finally {
        observation.finish(observed, outcome, stage);
      }
    };
  }
  append('http-client-ledger.jsonl', { event: 'client_process_hello',
    self_pid: process.pid, pid_source: 'node_process.pid' });
  return { append, transport, last: (client) => latest.get(client), attempts: () => attempts, close };
}
