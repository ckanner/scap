#!/usr/bin/env python3
"""Eight fixed-cap cells using the unchanged equal-seed process lifecycle."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import time

import shared
import spec

# Resolve both runners before any child or monitor thread can start. Their Cell
# classes keep their own cap-specific spec binding for the whole process life.
RUNTIMES = shared.runtimes()
common = RUNTIMES[8]


def run(args):
    for name in ('binary', 'node', 'weed', 'build_record', 'evidence'):
        setattr(args, name, getattr(args, name).resolve())
    common.preflight(args)
    args.evidence.mkdir(parents=True, mode=0o700, exist_ok=False)
    before = common.fixture()
    report = {'status': 'FAILED', 'profile': spec.NAME, 'aws_standard': 'NOT_RUN',
              'production_slo': 'NOT_RUN', 'cells': []}
    matrix_start_ns = time.monotonic_ns()
    until = matrix_start_ns / 1_000_000_000 + spec.DEADLINES['run_seconds']
    try:
        common.build.verify(args.build_record, args.binary)
        (args.evidence / 'build').mkdir()
        receipt = common.build.capture_receipt(args.build_record, args.binary, args.evidence / 'build')
        with tarfile.open(args.evidence / 'fixture-source.tar', 'w') as archive:
            for name in before:
                archive.add(shared.ROOT / name, arcname=name, recursive=False)
        inputs = {'fixture': before, 'fixture_archive_sha256': common.sha(args.evidence / 'fixture-source.tar'),
            'matrix_start_ns': matrix_start_ns,
            'fixture_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=shared.ROOT, text=True).strip(),
            'build_source_commit': receipt['source_commit'],
            'tools': {name: {'path': str(path), 'sha256': common.sha(path)} for name, path in (
                ('scapd', args.binary), ('node', args.node), ('weed', args.weed),
                ('python', Path(sys.executable).resolve()))}}
        shared.support.save_json(args.evidence / 'inputs.json', inputs)
        shared.support.save_json(args.evidence / 'plan.json', spec.matrix_plan())
        for item in spec.cells():
            observed = {**item, 'status': 'FAILED'}
            report['cells'].append(observed)
            cell = RUNTIMES[item['max_members']].Cell(args, item, until)
            try:
                cell.setup()
                cell.observe()
                observed['status'] = 'OBSERVED_NOT_AUDITED'
                observed['diagnostic_status'] = cell.diagnostic_status
            finally:
                observed['diagnostic_status'] = cell.diagnostic_status
                observed['cleanup_errors'] = cell.close()
                if observed['cleanup_errors']:
                    raise RuntimeError(observed['cleanup_errors'])
            print(json.dumps(observed), flush=True)
        common.build.verify(args.build_record, args.binary)
        if common.fixture() != before or any(common.sha(value['path']) != value['sha256']
                                             for value in inputs['tools'].values()):
            raise ValueError('frozen source/tool changed during actual run')
        shared.support.save_json(args.evidence / 'fixture-after.json', common.fixture())
        shared.observer.check_filesystem(args.evidence)
        report['status'] = 'OBSERVED_NOT_AUDITED'
    except BaseException as error:
        report['error'] = repr(error)
        raise
    finally:
        report['finished_ns'] = time.monotonic_ns()
        shared.support.save_json(args.evidence / 'result.json', report)
    print(json.dumps(report), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('binary', 'build-record', 'weed', 'node', 'evidence'):
        parser.add_argument('--' + name, type=Path, required=True)
    run(parser.parse_args())
