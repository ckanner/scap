/** Fixture observations only. Never log Authorization, cookies or credentials. */
import { appendFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';

export const sha = (value) => createHash('sha256').update(value).digest('hex');
export const bytes = (value) => {
  const buffer = Buffer.from(value);
  return { base64: buffer.toString('base64'), length: buffer.length, sha256: sha(buffer) };
};

export class Recorder {
  constructor(directory) {
    this.path = join(directory, 'audit.jsonl');
    this.stage = 'setup';
    this.sequence = 0;
    this.http = 0;
    this.s3 = 0;
    this.admin = 0;
    // Exclusive creation prevents a new run from appending to old evidence.
    appendFileSync(this.path, '', { flag: 'wx' });
  }

  emit(kind, fields = {}, stage = this.stage) {
    const row = { schema: 1, seq: ++this.sequence, kind, stage, ...fields };
    appendFileSync(this.path, JSON.stringify(row) + '\n');
    return row.seq;
  }

  fetch(owned, principal = '3', loseReply = false) {
    return async (url, options) => {
      const id = ++this.http, stage = this.stage;
      this.emit('sdk_request', { id, process: owned.id, principal, method: options.method,
        path: new URL(url).pathname, admission: options.headers['x-scap-admission'],
        body: bytes(Buffer.from(options.body, 'utf8')) }, stage);
      let response;
      try {
        response = await fetch(url, options);
        const body = Buffer.from(await response.clone().arrayBuffer());
        this.emit('sdk_response', { id, status: response.status,
          content_type: response.headers.get('content-type'), body: bytes(body) }, stage);
      } catch {
        this.emit('sdk_transport_failure', { id }, stage);
        throw new Error('fixture observed HTTP transport failure');
      }
      if (loseReply) {
        await response.arrayBuffer();
        this.lostHttp = id;
        this.emit('sdk_delivery_lost', { id }, stage);
        throw new Error('injected lost HTTP reply after complete response');
      }
      return response;
    };
  }
}

export function processIdentity(pid) {
  // The owned ChildProcess handle and its wait events identify the process.
  // /proc/<pid> is deliberately not inferred across container PID namespaces.
  return { pid, spawn_monotonic_ns: process.hrtime.bigint().toString(), pid_source: 'owned_ChildProcess' };
}

export function typedResult(result) {
  const cell = (value) => {
    if (value === null) return { type: 'null' };
    if (typeof value === 'bigint') return { type: 'integer', value: value.toString() };
    if (typeof value === 'string') return { type: 'text', value };
    if (typeof value === 'number') {
      const encoded = Buffer.alloc(8); encoded.writeDoubleBE(value);
      return { type: 'real', bits: encoded.toString('hex') };
    }
    if (!(value instanceof Uint8Array)) throw new Error('unsupported observed SQL value');
    return { type: 'blob', ...bytes(value) };
  };
  return { statements: result.statements.map((statement) => ({ columns: statement.columns,
    rows: statement.rows.map((row) => row.map(cell)), affected_rows: statement.affectedRows.toString(),
    last_insert_rowid: statement.lastInsertRowid.toString() })) };
}
