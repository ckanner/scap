#!/usr/bin/env python3
"""Generate the frozen finite inventory. Independent checking is a later process."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import platform
import signal
import subprocess
import sys
import time
import traceback

from cases import cases
from controls import controls

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
MAX_SECONDS = 180
MAX_BYTES = 512 * 1024 * 1024


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


def sha(value):
    return hashlib.sha256(value).hexdigest()


def source():
    files = sorted([*HERE.glob('*.py'), HERE / 'PLAN.md', HERE / 'README.md',
                    HERE.parent / 'object-owner-plan-model/model.py',
                    HERE.parent / 'object-owner-plan-model/oracle.py', ROOT / 'AGENTS.md',
                    ROOT / 'docs/architecture/owner-controller-plan.md',
                    ROOT / 'docs/architecture/owner-controller-v2.md'])
    hashes = {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in files}
    revision = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True,
                              capture_output=True, timeout=10)
    if revision.returncode:
        head, dirty = None, 'NO_GIT_REPOSITORY'
    else:
        head = revision.stdout.strip()
        dirty = subprocess.run(['git', 'status', '--porcelain', '--', *hashes], cwd=ROOT, check=True,
                               capture_output=True, text=True, timeout=10).stdout
    return {'repository_head': head, 'dirty_declared_inputs': dirty, 'files': hashes,
            'sha256': sha(canonical(hashes).encode())}


class Output:
    def __init__(self, path):
        self.path, self.bytes = path, 0
        path.mkdir(parents=True, exist_ok=False)

    def save(self, name, value):
        data = (canonical(value) + '\n').encode()
        if self.bytes + len(data) > MAX_BYTES:
            raise RuntimeError('fixed evidence byte budget exhausted')
        path = self.path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as stream: stream.write(data)
        self.bytes += len(data)
        return {'file': name, 'sha256': sha(data), 'bytes': len(data)}


def run(path, diagnostic=False):
    output = Output(path)
    started = time.time()
    report = {'status': 'FAILED', 'diagnostic': diagnostic, 'production_controller': 'NOT_EXECUTED',
              'native_sqlite_http_s3': 'NOT_RUN', 'aws': 'NOT_RUN', 'throughput_slo': 'NOT_RUN'}
    def expire(_signal, _frame):
        raise TimeoutError('fixed 180-second execution deadline')
    previous = signal.signal(signal.SIGALRM, expire)
    signal.alarm(MAX_SECONDS)
    try:
        before = source()
        assert diagnostic or not before['dirty_declared_inputs'], 'formal run requires committed declared inputs'
        binary = Path(sys.executable).resolve()
        output.save('inputs.json', {'schema': 1, 'source': before, 'diagnostic': diagnostic,
                    'started_epoch': started, 'deadline_epoch': started + MAX_SECONDS,
                    'python': {'path': str(binary), 'version': platform.python_version(), 'sha256': sha(binary.read_bytes())},
                    'limits': {'seconds': MAX_SECONDS, 'evidence_bytes': MAX_BYTES, 'processes': 1,
                               'configured_workers': 3, 'replacement_worker': 4, 'controllers': 2,
                               'scope': 1, 'maximum_counter': 40, 'calls_per_tick': 8, 'mutations_per_tick': 1}})
        positive, negative = cases(), controls()
        assert len(positive) == 402 and len(negative) == 40
        assert len({c.name for c in positive}) == 402 and len({c.name for c in negative}) == 40
        families = dict(sorted(Counter(c.family for c in positive).items()))
        assert families['prepare-race'] == 360
        inventory = {'positive': [{'name': c.name, 'family': c.family} for c in positive],
                     'negative': [{'name': c.name, 'rule': c.rule} for c in negative], 'families': families}
        output.save('inventory.json', inventory)
        manifest, fingerprints = [], set()
        for row in positive:
            trace = row.build().trace(row.name)
            fingerprint = sha(canonical({'protocol': trace['protocol']['events'], 'controller': trace['controller']}).encode())
            assert fingerprint not in fingerprints, 'duplicate raw two-ledger history: ' + row.name
            fingerprints.add(fingerprint)
            saved = output.save('positive/' + row.name + '.json', trace)
            manifest.append({'kind': 'positive', 'name': row.name, 'family': row.family,
                             'raw_history_sha256': fingerprint, **saved})
        for row in negative:
            saved = output.save('negative/' + row.name + '.json', row.build())
            manifest.append({'kind': 'negative', 'name': row.name, 'rule': row.rule, **saved})
        after = source()
        assert before == after, 'declared sources changed during generation'
        output.save('source-after.json', after)
        output.save('traces.json', manifest)
        report.update(status='GENERATED', positive_cases=402, unique_raw_histories=len(fingerprints),
                      negative_controls=40, families=families, source_sha256=before['sha256'],
                      independent_oracle='NOT_RUN', controls='NOT_RUN', evidence_bytes=output.bytes)
    except BaseException as error:
        report.update(error=type(error).__name__, message=str(error))
        output.save('exploration-failure.json', {'error': type(error).__name__, 'message': str(error),
                                                'traceback': traceback.format_exc()})
    finally:
        signal.alarm(0); signal.signal(signal.SIGALRM, previous)
        report['elapsed_seconds'] = time.time()-started
        output.save('exploration.json', report)
    print(canonical(report))
    return report['status'] == 'GENERATED'


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('directory', type=Path)
    parser.add_argument('--diagnostic', action='store_true')
    args = parser.parse_args()
    raise SystemExit(0 if run(args.directory, args.diagnostic) else 1)
