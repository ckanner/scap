#!/usr/bin/env python3
"""Fixed S1 calls on actual HTTP/Node, native SQLite and signed local S3."""
import argparse
import json
from pathlib import Path
import shutil
import signal
import tempfile
import time
import traceback

from harness import Harness
import spec
import support as io


def state(value, expected):
    assert value['state'] == expected, (expected, value)
    return value


def snapshot(suite, operation, name, identifier=None, role='C', **fields):
    return suite.call(role, identifier or name + '-' + operation, 'snapshot_' + operation, intent=name, **fields)


def lost(suite, identifier, operation, point):
    gate = suite.http[suite.workers['C']].arm(identifier, 'snapshot_' + operation,
                                            mode='drop', stage='after_response')
    snapshot(suite, operation, point, identifier, expect='UNKNOWN',
             options={'timeoutMs': spec.TIMEOUTS['original_unknown_ms']})
    assert gate.arrived.wait(15) and gate.finished.wait(15) and not gate.aborted


def history(suite):
    suite.seed_native()
    suite.phase('warm-owner-and-original-point-one')
    plan = suite.new_plan('bulk', 1)
    active = suite.prepare_claim_resume(plan)
    listing = suite.call('C', 'set-original-limits', 'snapshot_limits', input={
        'expectedRevision': active['status']['revision'], 'nonce': suite.next_nonce(), 'limits': spec.SNAPSHOT_LIMITS})
    suite.save_snapshot(spec.POINTS[0], listing['status'])
    snapshot(suite, 'prepare', 'point-one')
    lost(suite, 'capture-original-ack', 'capture', 'point-one')
    first = state(snapshot(suite, 'inspect', 'point-one', role='A'), 'retained')
    suite.call('C', 'point-one-list', 'snapshot_list')
    head = suite.call('A', 'close-window-one', 'close_full', input={
        'expectedRevision': first['status']['revision'], 'nonce': suite.next_nonce()})
    for number in (3, 4):
        name = f'original-{number}'
        suite.record_original(name, suite.call('A', 'execute-' + name, 'execute', intent=name))

    suite.phase('original-point-two-and-third-window')
    head = suite.status('bulk', 'point-two-base')
    suite.save_snapshot(spec.POINTS[1], head)
    snapshot(suite, 'prepare', 'point-two')
    second = state(snapshot(suite, 'capture', 'point-two'), 'retained')
    assert first['accepted']['point']['data_root'] != second['accepted']['point']['data_root']
    assert first['accepted']['point']['page_count'] < second['accepted']['point']['page_count']
    suite.call('A', 'close-window-two', 'close_full', input={
        'expectedRevision': second['status']['revision'], 'nonce': suite.next_nonce()})
    for number in (5, 6):
        name = f'original-{number}'
        suite.record_original(name, suite.call('A', 'execute-' + name, 'execute', intent=name))
    listing = suite.call('C', 'two-points-before-copy', 'snapshot_list')
    assert len(listing['snapshots']) == 2

    suite.phase('copy-complete-current-and-held-closures')
    begun = suite.call('C', 'copy-begin', 'compact_begin', input={'expectedHeadSerial': listing['status']['head_serial']})
    serial = begun['storage']['plan']['serial']
    suite.call('C', 'copy-seal', 'compact_copy', input={'planSerial': serial})
    suite.call('C', 'copy-promote', 'compact_promote', input={'planSerial': serial})
    suite.sweep(1, 'retired-one')

    suite.phase('all-compute-cache-loss')
    for role in tuple(suite.clients):
        suite.stop_sdk(role)
    for role in tuple(suite.services):
        suite.stop_service(role)
    suite.start_service('C', 9503)
    suite.start_sdk('C')
    suite.phase('cold-full-owner-recovery')
    plan = suite.new_plan('bulk', 2)
    suite.prepare_claim_resume(plan)
    for original in suite.specs:
        value = suite.call('C', 'cold-lookup-' + original['name'], 'lookup', intent=original['name'])
        assert value['state'] == 'committed' and value['result'] == suite.originals[original['name']]['result']
        suite.trace.emit('cold_original_recovered', name=original['name'], receipt=value['receipt'], result=value['result'])
    suite.call('C', 'cold-current-query', 'query', statements=[{
        'sql': 'SELECT counter,payload FROM witness WHERE id=1', 'params': []}])
    state(snapshot(suite, 'inspect', 'point-one', 'cold-point-one'), 'retained')
    state(snapshot(suite, 'inspect', 'point-two', 'cold-point-two'), 'retained')
    suite.call('C', 'cold-two-points-list', 'snapshot_list')

    suite.phase('original-release-unknown-and-deleted-cleanup')
    lost(suite, 'release-original-ack', 'release', 'point-one')
    first = state(snapshot(suite, 'inspect', 'point-one', 'released-point-one'), 'released_observed')
    deleted = suite.call('C', 'delete-with-point-two', 'lifecycle', input={
        'expectedRevision': first['status']['revision'], 'nonce': suite.next_nonce(), 'lifecycle': 'deleted'})
    suite.call('C', 'seal-with-held-point-rejected', 'retire_storage', expect='CONFLICT',
               input={'expectedHeadSerial': deleted['head_serial']})
    state(snapshot(suite, 'release', 'point-two', 'deleted-release-point-two'), 'released_observed')
    second = state(snapshot(suite, 'inspect', 'point-two', 'deleted-point-two'), 'released_observed')
    suite.call('C', 'terminal-seal', 'retire_storage', input={'expectedHeadSerial': second['status']['head_serial']})
    suite.sweep(2, 'terminal-two')
    state(snapshot(suite, 'inspect', 'point-one', 'terminal-point-one'), 'released_observed')
    state(snapshot(suite, 'inspect', 'point-two', 'terminal-point-two'), 'released_observed')
    suite.call('C', 'terminal-empty-list', 'snapshot_list')
    suite.saved_results()


def run(args):
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=False, mode=0o700)
    private = Path(tempfile.mkdtemp(prefix='scap-snapshot-private-', dir=evidence.parent))
    private.chmod(0o700)
    suite = Harness(args, evidence, private)
    summary = {'schema': 1, 'status': 'FAILED', 'private': str(private), 'private_removed': False,
               'aws_standard': 'NOT_RUN', 'production_slo': 'NOT_RUN', 'restore_s2': 'NOT_RUN', 'error': None}
    started = time.monotonic()

    def deadline(_signum, _frame):
        raise TimeoutError('fixed snapshot whole-fixture deadline')

    previous = signal.signal(signal.SIGALRM, deadline)
    signal.alarm(spec.TIMEOUTS['whole_seconds'])
    successful = False
    try:
        suite.setup()
        history(suite)
        for proxy in (*suite.proxies.values(), *suite.http.values()):
            assert all(gate.finished.wait(5) and not gate.aborted for gate in proxy.gates)
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
    parser = argparse.ArgumentParser()
    for name in ('server', 'build-record', 'worker', 'seed-build-record', 'weed', 'evidence'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--node', default='node')
    arguments = parser.parse_args()
    for name in ('server', 'build_record', 'worker', 'seed_build_record', 'weed'):
        setattr(arguments, name, getattr(arguments, name).resolve())
    raise SystemExit(run(arguments))
