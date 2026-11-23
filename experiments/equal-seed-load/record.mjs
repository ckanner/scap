/** Original-byte capture with cell-wide SDK/intent budgets across phases. */
import { existsSync, readFileSync, openSync, writeSync, fsyncSync, closeSync } from 'node:fs';
import { recorder as originalRecorder, now, sha } from '../group-commit-load/record.mjs';
export { now, sha };

export function recorder(directory, phase, bounds) {
  const original = originalRecorder(directory, phase, bounds);
  const counts = new Map();
  let posts = 0;
  for (const name of ['sdk.jsonl', 'intents.jsonl']) {
    const bytes = existsSync(directory + '/' + name) ? readFileSync(directory + '/' + name) : Buffer.alloc(0);
    const lines = bytes.length ? bytes.toString('utf8').trimEnd().split('\n') : [];
    if (bytes.length && bytes.at(-1) !== 10) throw new Error('incomplete prior ledger');
    counts.set(name, { rows: lines.length, bytes: bytes.length });
    if (name === 'sdk.jsonl') posts = lines.filter((line) => JSON.parse(line).event === 'http_request').length;
  }
  function append(file, fields) {
    if (!counts.has(file)) throw new Error('unplanned ledger');
    const current = counts.get(file), sdk = file === 'sdk.jsonl';
    const line = JSON.stringify({ phase, monotonic_ns: now().toString(), ...fields }) + '\n';
    const size = Buffer.byteLength(line);
    if (current.rows + 1 > (sdk ? bounds.sdk_rows : bounds.intent_rows) ||
        current.bytes + size > (sdk ? bounds.sdk_bytes : bounds.intent_bytes)) throw new Error('cell ledger budget');
    if (fields.event === 'http_request' && posts + 1 > bounds.http_posts) throw new Error('original POST budget');
    const fd = openSync(directory + '/' + file, 'a', 0o600);
    try { writeSync(fd, line); fsyncSync(fd); } finally { closeSync(fd); }
    current.rows++; current.bytes += size;
    if (fields.event === 'http_request') posts++;
  }
  return { append, save: original.save, read: original.read };
}
