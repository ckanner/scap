#!/usr/bin/env python3
"""Reproducible bounded exploration and persistent, independently checked traces."""
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
from counterexamples import negatives
from oracle import audit, canonical, Violation


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
MAX_SECONDS = 120
MAX_BYTES = 256 * 1024 * 1024
POSITIVE_COUNT = 989
NEGATIVE_COUNT = 48
EXPECTED_FAMILIES = {'claim_cancel': 140, 'two_resume': 504, 'resume_abort': 252}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def source():
    files = sorted([*HERE.glob('*.py'), HERE / 'README.md', HERE / 'PLAN.md',
                    ROOT / 'docs/architecture/accepted-owner-plan.md',
                    ROOT / 'docs/architecture/owner-controller-plan.md', ROOT / 'AGENTS.md'])
    rows = {str(path.relative_to(ROOT)): digest(path.read_bytes()) for path in files}
    revision = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, check=True,
                              text=True, capture_output=True, timeout=10).stdout.strip()
    changed = subprocess.run(['git', 'status', '--porcelain', '--', *rows], cwd=ROOT, check=True,
                             text=True, capture_output=True, timeout=10).stdout
    return {'repository_head': revision, 'files': rows, 'dirty_declared_inputs': changed,
            'sha256': digest(canonical(rows).encode())}


class Output:
    def __init__(self, directory):
        self.directory = directory
        directory.mkdir(parents=True, exist_ok=False)
        self.bytes = 0

    def save(self, name, value):
        encoded = (canonical(value) + '\n').encode()
        if self.bytes + len(encoded) > MAX_BYTES:
            raise RuntimeError('fixed evidence byte budget exhausted')
        path = self.directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as stream:
            stream.write(encoded)
        self.bytes += len(encoded)
        return {'file': name, 'sha256': digest(encoded), 'bytes': len(encoded)}


def check_inventory(positive, negative):
    assert len(positive) == POSITIVE_COUNT and len(negative) == NEGATIVE_COUNT
    assert len({row.name for row in positive}) == len(positive)
    assert len({row.name for row in negative}) == len(negative)
    counts = Counter(row.family for row in positive)
    assert {name: counts[name] for name in EXPECTED_FAMILIES} == EXPECTED_FAMILIES
    return dict(sorted(counts.items()))


def run(directory, diagnostic=False):
    output = Output(directory)
    started = time.monotonic()
    report = {'status': 'FAILED', 'production': 'NOT_EXECUTED_BY_MODEL', 'controller': 'NOT_IMPLEMENTED',
              'native_sqlite_http_s3': 'NOT_RUN', 'aws': 'NOT_RUN', 'diagnostic': diagnostic,
              'bound_seconds': MAX_SECONDS, 'bound_evidence_bytes': MAX_BYTES}
    def expired(_signum, _frame):
        raise TimeoutError('fixed exploration deadline')
    previous = signal.signal(signal.SIGALRM, expired)
    signal.alarm(MAX_SECONDS)
    try:
        before = source()
        assert diagnostic or not before['dirty_declared_inputs'], 'formal run requires committed declared inputs'
        executable = Path(sys.executable).resolve()
        inputs = {'schema': 1, 'source': before,
                  'python': {'path': str(executable), 'sha256': digest(executable.read_bytes()),
                             'version': platform.python_version()},
                  'limits': {'seconds': MAX_SECONDS, 'evidence_bytes': MAX_BYTES,
                             'processes': 1, 'maximum_counter': 20,
                             'Scopes': 1, 'simultaneously_racing_calls': 2},
                  'diagnostic': diagnostic}
        output.save('inputs.json', inputs)
        positive, negative = cases(), negatives()
        families = check_inventory(positive, negative)
        output.save('inventory.json', {'positive': [{'name': row.name, 'family': row.family} for row in positive],
                                      'negative': [{'name': row.name, 'rule': row.rule} for row in negative],
                                      'families': families})
        manifest, totals, states, edges = [], Counter(), set(), set()
        original = None
        for case in positive:
            world = case.build()
            value = world.trace(case.name)
            location = output.save('positive/' + case.name + '.json', value)
            checked = audit(value, strict_scenario=True)
            manifest.append({'kind': 'positive', 'name': case.name, **location,
                             'events': len(value['events']), 'audit_sha256': digest(canonical(checked).encode())})
            for key, number in checked.items():
                if type(number) is int:
                    totals[key] += number
            prior = None
            keys = {event['io']: event['key'] for event in value['events'] if event['event'] == 's3_put_invoked'}
            # Count the durable states/edges actually present in histories; these
            # are not advertised as every state of an unbounded protocol.
            for event in value['events']:
                if event['event'] == 'initial':
                    state = digest(event['objects']['scap-object/v1/1/7/91/head']['body'].encode())
                elif (event['event'] == 's3_put_effect' and event['result']['status'] == 200 and
                      keys[event['io']] == 'scap-object/v1/1/7/91/head'):
                    state = digest(event['result']['value']['body'].encode())
                else:
                    continue
                states.add(state)
                if prior is not None:
                    edges.add((prior, state))
                prior = state
            if case.name == 'proof-0-claim':
                original = (value, checked)
        assert original is not None
        original_before = digest(canonical(original[0]).encode())
        # Three positive controls explicitly exclude controller summary authority.
        positive_controls = [{'name': 'original-designated-proof-history',
                              'result': audit(original[0], strict_scenario=True) == original[1]}]
        altered = json.loads(canonical(original[0]))
        altered['summary'] = {'status': 'fabricated', 'owner': 'wrong', 'passed': False}
        positive_controls.append({'name': 'fabricated-controller-summary-ignored',
                                  'result': audit(altered, strict_scenario=True) == original[1]})
        negative_results = []
        for control in negative:
            value = control.build()
            location = output.save('negative/' + control.name + '.json', value)
            try:
                audit(value)
            except Violation as error:
                result = {'name': control.name, 'expected': control.rule, 'actual': error.rule,
                          'message': str(error), 'passed': error.rule == control.rule, **location}
                negative_results.append(result)
                if not result['passed']:
                    output.save('negative-failure.json', result)
                    raise AssertionError('counterexample failed at the wrong semantic boundary') from error
            else:
                output.save('negative-failure.json', {'name': control.name, 'false_pass': True})
                raise AssertionError('counterexample was incorrectly accepted')
        positive_controls.append({'name': 'original-rechecked-after-all-negative-mutations',
            'result': audit(original[0], strict_scenario=True) == original[1] and digest(canonical(original[0]).encode()) == original_before})
        assert all(row['result'] for row in positive_controls)
        after = source()
        assert before == after, 'declared source changed during exploration'
        output.save('source-after.json', after)
        output.save('traces.json', manifest)
        output.save('controls.json', {'status': 'PASSED', 'positive_controls': positive_controls,
                                     'negative_controls': negative_results})
        report.update(status='PASSED', positive_cases=len(positive), negative_controls=len(negative),
                      positive_controls=len(positive_controls), families=families,
                      aggregate=dict(sorted(totals.items())), observed_head_states=len(states),
                      observed_head_edges=len(edges), source_sha256=before['sha256'])
    except BaseException as error:
        report['error'] = repr(error)
        output.save('failure.json', {'error': repr(error), 'traceback': traceback.format_exc()})
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
        report['elapsed_seconds'] = time.monotonic() - started
        report['evidence_bytes_before_report'] = output.bytes
        output.save('report.json', report)
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--diagnostic', action='store_true')
    args = parser.parse_args()
    result = run(args.output.resolve(), args.diagnostic)
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(result['status'] != 'PASSED')


if __name__ == '__main__':
    main()
