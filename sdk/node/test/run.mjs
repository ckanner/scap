import { mkdtempSync, mkdirSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const root = fileURLToPath(new URL('..', import.meta.url));
const directory = process.env.NODE_V8_COVERAGE === undefined ?
  mkdtempSync(join(tmpdir(), 'scap-node-unit-')) : resolve(process.env.NODE_V8_COVERAGE);
mkdirSync(directory, { recursive: true });
if (readdirSync(directory).some((name) => /^coverage-.*\.json$/.test(name))) {
  throw new Error('Unit profiles must start empty; use a new NODE_V8_COVERAGE directory');
}
const environment = { ...process.env, NODE_V8_COVERAGE: directory };
const run = spawnSync(process.execPath, ['--test', '--experimental-test-coverage',
  '--test-coverage-include=src/*.js', '--test-coverage-lines=100', '--test-coverage-functions=100',
  '--test-coverage-branches=100', 'test/unit.test.js'], { cwd: root, env: environment, stdio: 'inherit' });
if (run.status !== 0) process.exit(run.status ?? 1);
const gate = spawnSync(process.execPath, ['test/check-coverage.mjs'], { cwd: root, env: environment, stdio: 'inherit' });
process.exit(gate.status ?? 1);
