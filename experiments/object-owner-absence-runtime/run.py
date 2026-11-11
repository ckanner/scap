#!/usr/bin/env python3
"""Observe real S3 absence responses racing with accepted owner publication."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import signal
import tempfile
import time
import traceback

import absence_spec as spec
from absence_support import Harness, io


def state(value, wanted):
    assert value['state'] == wanted, (wanted, value)
    return value


def arrived(gate):
    assert gate.arrived.wait(15), 'original fault arrival deadline'


def release(proxy, gate):
    proxy.release(gate)
    assert gate.finished.wait(15), 'original fault completion deadline'


def compete(suite, name, original, supersede):
    prepared = state(suite.owner('prepare', original, name + '-competing-prepare',
                               bootstrap_worker='9402'), 'prepared')
    claimed = state(suite.owner('claim', original, name + '-competing-claim',
                              bootstrap_worker='9402'), 'claimed')
    if not supersede:
        return prepared, claimed
    aborted = state(suite.owner('abort', original, name + '-competing-abort',
                              bootstrap_worker='9402'), 'aborted')
    successor = suite.new_plan(name, 2, head=aborted['status'])
    state(suite.owner('prepare', successor, bootstrap_worker='9402'), 'prepared')
    state(suite.owner('abort', successor, name + '-replacement-cancel',
                      bootstrap_worker='9402'), 'cancelling')
    terminal = state(suite.owner('abort', successor, name + '-replacement-abort',
                                bootstrap_worker='9402'), 'aborted')
    return prepared, terminal


def scenario(suite, name):
    suite.phase(name + '-original-absence-race')
    original = suite.new_plan(name, 1)
    value = suite.saved[original]['input']
    path = spec.owner_path(name, 'descriptor', value['creator'], value['operation'])
    gate = suite.proxies['C'].arm(name + '-real-404', 'GET', path, 'hold', stage='after_response')
    suite.owner_begin('prepare', original, name + '-original-prepare')
    arrived(gate)
    if name == 'proof':
        # The first backend 404 is real. Keep the second exact HEAD response
        # before delivery, after both descriptor reads observed real absence.
        # A new gate can be armed while the previous matched handler is held.
        second = suite.proxies['C'].arm('proof-stable-head2', 'GET', spec.head_path(name),
                                       'hold', stage='after_response', occurrence=2)
        release(suite.proxies['C'], gate)
        arrived(second)
        winner, terminal = compete(suite, name, original, True)
        release(suite.proxies['C'], second)
        suite.finish('C', name + '-original-prepare', 'CONFLICT')
    else:
        winner, terminal = compete(suite, name, original, name == 'superseded')
        release(suite.proxies['C'], gate)
        observed = state(suite.finish('C', name + '-original-prepare'), 'prepared')
        assert observed['prepared'] == winner['prepared']
    expected = 'claimed' if name == 'current' else 'aborted'
    state(suite.owner('inspect', original, name + '-original-history'), expected)
    # This fresh call on the original daemon must still be healthy; a latched
    # Corrupt would prevent it. Recovery then opens real native SQLite on B.
    after = suite.status(name, name + '-healthy-status')
    assert after == terminal['status']
    if name == 'current':
        state(suite.owner('resume', original), 'active')
    else:
        recovery = suite.new_plan(name, 3, head=after)
        suite.prepare_claim_resume(recovery)
    for counter in (1, 2):
        intent = f'{name}-{counter:03d}'
        result = suite.call('C', 'recovered-' + intent, 'lookup', name, intent=intent)
        assert result['state'] == 'committed' and result['result'] == suite.originals[intent]['result']
    suite.call('C', name + '-business-query', 'query', name,
               statements=[{'sql': 'SELECT id,counter,payload FROM witness ORDER BY id', 'params': []}])


def run(args):
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=False, mode=0o700)
    private = Path(tempfile.mkdtemp(prefix='scap-absence-private-', dir=evidence.parent))
    private.chmod(0o700)
    suite = Harness(args, evidence, private, spec, 'experiments/object-owner-absence-runtime/PLAN.md')
    summary = {'schema': 1, 'status': 'FAILED', 'private': str(private), 'private_removed': False,
               'error': None, 'aws_standard': 'NOT_RUN', 'production_slo': 'NOT_RUN'}
    started = time.monotonic()

    def deadline(_signum, _frame):
        raise TimeoutError('fixed absence fixture deadline')

    previous = signal.signal(signal.SIGALRM, deadline)
    signal.alarm(spec.TIMEOUTS['whole_seconds'])
    successful = False
    try:
        suite.setup()
        for name in spec.SCOPES:
            suite.seed_small(name)
        for name in spec.SCOPES:
            scenario(suite, name)
        assert len(suite.originals) == 6 and len(suite.saved) == 7
        io.save(evidence / 'original-results.json', io.encoded(suite.originals))
        for proxy in suite.proxies.values():
            for gate in proxy.gates:
                assert gate.finished.wait(5) and not gate.aborted and gate.used == 1
        suite.verify_source()
        successful = True
    except BaseException as error:
        summary['error'] = repr(error)
        io.save(evidence / 'failure.txt', traceback.format_exc().encode())
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
        errors = suite.cleanup(successful)
        summary['cleanup_errors'] = errors
        if successful and not errors:
            shutil.rmtree(private)
            summary.update(status='OBSERVED_NOT_AUDITED', private_removed=not private.exists())
        summary['elapsed_seconds'] = time.monotonic() - started
        io.save(evidence / 'summary.json', io.encoded(summary))
    print(json.dumps(summary, sort_keys=True))
    return 0 if summary['status'] == 'OBSERVED_NOT_AUDITED' else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('server', 'build-record', 'worker', 'seed-build-record', 'weed', 'evidence'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--node', default='node')
    args = parser.parse_args()
    for name in ('server', 'build_record', 'worker', 'seed_build_record', 'weed'):
        setattr(args, name, getattr(args, name).resolve())
    raise SystemExit(run(args))
