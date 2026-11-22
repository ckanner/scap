/** Bounded original-byte observation. No retry, scheduling or product hooks. */
import { createHash } from 'node:crypto';
import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync,
  rmdirSync, statSync, writeFileSync, writeSync } from 'node:fs';

export const sha = (raw) => createHash('sha256').update(raw).digest('hex');
export const now = () => process.hrtime.bigint();

export function recorder(directory, phase, bounds) {
  let count = 0, bytes = 0;
  function append(file, fields) {
    const text = JSON.stringify({ phase, monotonic_ns: now().toString(), ...fields }) + '\n';
    if (++count > bounds.trace_rows || (bytes += Buffer.byteLength(text)) > bounds.trace_bytes)
      throw new Error('client trace bound');
    const fd = openSync(directory + '/' + file, 'a', 0o600);
    try { writeSync(fd, text); fsyncSync(fd); } finally { closeSync(fd); }
  }
  function save(raw) {
    if (raw.length > bounds.body_bytes) throw new Error('raw body bound');
    const digest = sha(raw), file = 'raw/' + digest, path = directory + '/' + file;
    const lock = directory + '/raw-lock', deadline = Date.now() + 10000;
    for (;;) {
      try { mkdirSync(lock, { mode: 0o700 }); break; }
      catch (error) {
        if (error.code !== 'EEXIST' || Date.now() >= deadline) throw error;
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 5);
      }
    }
    try {
      if (!existsSync(path)) {
        const budget = directory + '/raw-budget', used = Number(readFileSync(budget, 'utf8'));
        if (!Number.isSafeInteger(used) || used < 0 || used + raw.length > bounds.raw_bytes)
          throw new Error('raw byte budget');
        let fd = openSync(budget, 'w', 0o600);
        try { writeFileSync(fd, String(used + raw.length) + '\n'); fsyncSync(fd); }
        finally { closeSync(fd); }
        fd = openSync(path, 'wx', 0o600);
        try { writeFileSync(fd, raw); fsyncSync(fd); } finally { closeSync(fd); }
      }
      if (statSync(path).size !== raw.length) throw new Error('raw identity changed');
    } finally { rmdirSync(lock); }
    return { file, bytes: raw.length, sha256: digest };
  }
  function read(value) {
    if (!/^raw\/[0-9a-f]{64}$/.test(value.file)) throw new Error('raw path');
    const raw = readFileSync(directory + '/' + value.file);
    if (raw.length !== value.bytes || sha(raw) !== value.sha256) throw new Error('raw identity');
    return raw;
  }
  return { append, save, read };
}
