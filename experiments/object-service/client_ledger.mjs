/** Fixture-only evidence capture. It performs no retries or result decoding. */
import { createHash } from 'node:crypto';
import { openSync, writeSync, fsyncSync, closeSync } from 'node:fs';

const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
const now = () => process.hrtime.bigint().toString();

export function createLedger(directory, phase) {
  let attempts = 0;
  const latest = new Map();
  function append(file, value) {
    const descriptor = openSync(directory + '/' + file, 'a', 0o600);
    try {
      writeSync(descriptor, JSON.stringify({ schema: 1, phase, monotonic_ns: now(), ...value }) + '\n');
      fsyncSync(descriptor);
    } finally { closeSync(descriptor); }
  }
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
      try {
        const response = await globalThis.fetch(url, options);
        const raw = Buffer.from(await response.clone().arrayBuffer());
        append('http-client-ledger.jsonl', { event: 'http_response', call_id: id, client,
          status: response.status, headers: { 'content-type': response.headers.get('content-type') },
          body: raw.toString('base64'), body_sha256: sha(raw) });
        return response;
      } catch (error) {
        append('http-client-ledger.jsonl', { event: 'http_transport_error', call_id: id, client,
          error_name: error.name });
        throw error;
      }
    };
  }
  append('http-client-ledger.jsonl', { event: 'client_process_hello',
    self_pid: process.pid, pid_source: 'node_process.pid' });
  return { append, transport, last: (client) => latest.get(client), attempts: () => attempts };
}
