import { readdirSync, readFileSync, statSync, lstatSync } from 'node:fs';
import { resolve, join, extname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

function requireValue(ok, message) { if (!ok) throw new Error(message); }

export function check(expected, reports) {
  requireValue(expected.size > 0, 'Empty production source inventory');
  const found = new Map();
  for (const report of reports) {
    for (const script of report.result) {
      if (!script.url.startsWith('file:')) continue;
      const path = fileURLToPath(script.url);
      if (!expected.has(path)) continue;
      requireValue(!found.has(path), 'Duplicate production profile');
      const functions = script.functions;
      requireValue(functions.length > 0, 'Empty function denominator');
      let ranges = 0;
      for (const fn of functions) {
        requireValue(fn.isBlockCoverage === true && fn.ranges.length > 0, 'Missing block coverage map');
        for (const region of fn.ranges) {
          const { count, startOffset, endOffset } = region;
          requireValue(Number.isSafeInteger(count) && count > 0 && Number.isSafeInteger(startOffset) &&
            Number.isSafeInteger(endOffset) && startOffset >= 0 && startOffset < endOffset &&
            endOffset <= expected.get(path), 'Invalid or uncovered V8 counter');
          ++ranges;
        }
      }
      found.set(path, { functions: functions.length, ranges });
    }
  }
  requireValue(found.size === expected.size, 'Missing production profile');
  return found;
}

function selfTest() {
  const path = '/test/production.js';
  const expected = new Map([[path, 10]]);
  const good = { result: [{ url: pathToFileURL(path).href,
    functions: [{ isBlockCoverage: true, ranges: [{ startOffset: 0, endOffset: 10, count: 1 }] }] }] };
  check(expected, [good]);
  const rejected = (fn) => { let failed = false; try { fn(); } catch { failed = true; } requireValue(failed, 'Coverage gate accepted a negative control'); };
  rejected(() => check(new Map(), []));
  rejected(() => check(expected, []));
  rejected(() => check(expected, [good, good]));
  const changed = (mutate) => { const report = structuredClone(good); mutate(report.result[0].functions[0]); rejected(() => check(expected, [report])); };
  for (const count of [0, -1, 1.5, '1']) changed((fn) => { fn.ranges[0].count = count; });
  for (const [startOffset, endOffset] of [[-1, 10], [0, 11], [1, 1], [1.5, 10]]) changed((fn) => Object.assign(fn.ranges[0], { startOffset, endOffset }));
  changed((fn) => { fn.isBlockCoverage = false; });
  changed((fn) => { fn.ranges = []; });
  rejected(() => check(expected, [{ result: [{ url: pathToFileURL(path).href, functions: [] }] }]));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  selfTest();
  requireValue(typeof process.env.NODE_V8_COVERAGE === 'string', 'NODE_V8_COVERAGE must identify the fresh unit profiles');
  const source = fileURLToPath(new URL('../src/', import.meta.url)), expected = new Map();
  for (const name of readdirSync(source)) {
    const path = join(source, name);
    requireValue(!lstatSync(path).isSymbolicLink() && statSync(path).isFile(), 'Unclassified source entry');
    // Declaration files contain no executable code; any other source format
    // needs an explicit supported coverage collector before it may be added.
    if (name.endsWith('.d.ts')) continue;
    requireValue(extname(path) === '.js', 'Unclassified production source');
    expected.set(path, readFileSync(path, 'utf8').length);
  }
  const directory = resolve(process.env.NODE_V8_COVERAGE);
  const profiles = readdirSync(directory).filter((name) => /^coverage-.*\.json$/.test(name));
  requireValue(profiles.length > 0, 'No raw unit V8 profiles');
  const result = check(expected, profiles.map((name) => JSON.parse(readFileSync(join(directory, name), 'utf8'))));
  console.log('Exact unit-only V8 coverage per module:', Object.fromEntries([...result].map(([path, counts]) => [path.slice(source.length), counts])));
  console.log('Coverage gate negative controls passed; HTTP/native/S3 acceptance remains separate.');
}
