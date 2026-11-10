#!/usr/bin/env python3
"""Eight fixed terminal-retirement families on real scapd/native SQLite/S3."""
from __future__ import annotations

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

UNKNOWN = {'timeoutMs': spec.TIMEOUTS['original_unknown_ms']}


def arrived(gate):
    assert gate.arrived.wait(15), 'original fault arrival deadline'
    return gate.observed


def release(suite, role, gate):
    suite.proxies[role].release(gate)
    assert gate.finished.wait(15), 'original fault completion deadline'


def start_held(suite, role, identifier, operation, name, gate, **fields):
    suite.begin(role, identifier, operation, name, **fields)
    return arrived(gate)


def control(suite, name, kind, head=None):
    value = {'operation': 'delete_name' if kind == 'delete' else 'abort_create',
             'creation': spec.creation(name), 'control_operation': str(9000 + int(spec.creation(name)['operation'])),
             'expected_name_revision': '2' if kind == 'delete' else '1', 'nonce': suite.next_nonce()}
    if kind == 'delete':
        assert head is not None
        value['expected_head_revision'] = head['revision']
    return value


def first_page(suite, name, path, label, restart=True, bucket_fault=False):
    target = path.rsplit('/', 1)[1]
    assert len(target) == 64 and int(target, 16) > 0
    report = suite.prepare_gc(name, 1, label, f'{int(target, 16) - 1:064x}')
    assert report['status']['storage']['sweep'] is not None
    if restart:
        suite.restart_b(label)
    if bucket_fault:
        gate = suite.proxies['B'].arm(label + '-bucket-error', 'GET', path, 'no_such_bucket')
        batch = report['status']['storage']['sweep']['serial']
        suite.call('B', label + '-unknown', 'gc_resume', name, expect='UNKNOWN', input={'batchSerial': batch})
        arrived(gate)
        assert gate.finished.wait(5)
        observed = suite.status(name, label + '-pending', deleted=True)
        assert observed['storage']['sweep']['serial'] == batch and observed['storage']['sweep']['pending'] > 0
    suite.resume_gc(name, report, label + '-resume')
    return report


def late(suite):
    suite.phase('direct-late-seal-final-active')
    suite.create_direct('late')
    suite.seed('late')
    suite.call('C', 'late-live-storage-rejected', 'storage_status', 'late', expect='LIFECYCLE')
    suite.abort_copy('late', 'late-abandoned-generation')
    put = suite.proxies['A'].arm('late-original-put', 'PUT', spec.prefix('late', 1), 'hold')
    start_held(suite, 'A', 'late-original-sql', 'execute', 'late', put, intent='late-3', options=UNKNOWN)
    suite.finish('A', 'late-original-sql', 'UNKNOWN')
    read = suite.proxies['R'].arm('late-original-read', 'GET', spec.prefix('late', 1), 'hold')
    cut = start_held(suite, 'R', 'late-old-lookup', 'lookup', 'late', read, intent='late-1')
    started = time.monotonic()
    deleted = suite.delete_direct('late', 'late-delete')
    suite.call('B', 'late-unsealed-active-forbidden', 'gc_prepare', 'late', expect='LIFECYCLE', input={
        'expectedHeadSerial': deleted['head_serial'], 'generation': '1', 'after': None})
    suite.call('C', 'late-no-admin-storage', 'storage_status', 'late', expect='DENIED', principal='12')
    seal = suite.proxies['C'].arm('late-original-seal', 'PUT', spec.head_path('late'), 'hold')
    start_held(suite, 'C', 'late-seal-unknown', 'retire_storage', 'late', seal,
               input={'expectedHeadSerial': deleted['head_serial']}, options=UNKNOWN)
    suite.finish('C', 'late-seal-unknown', 'UNKNOWN')
    before = suite.status('late', 'late-observed-before-effect', deleted=True)
    assert before['storage']['terminal'] is None and before['head_serial'] == deleted['head_serial']
    release(suite, 'C', seal)
    terminal = suite.status('late', 'late-observed-after-effect', deleted=True)
    assert terminal['storage']['terminal']['serial'] == terminal['head_serial']
    for suffix, serial in (('original', deleted['head_serial']), ('current', terminal['head_serial'])):
        suite.call('C', 'late-repeat-seal-' + suffix, 'retire_storage', 'late', expect='CONFLICT',
                   input={'expectedHeadSerial': serial})
    suite.call('B', 'late-unallocated-forbidden', 'gc_prepare', 'late', expect='FENCED', input={
        'expectedHeadSerial': terminal['head_serial'], 'generation': '3', 'after': None})
    first_page(suite, 'late', cut['path'], 'late-checkpoint', bucket_fault=True)
    release(suite, 'R', read)
    suite.finish('R', 'late-old-lookup', 'SNAPSHOT_EXPIRED')
    elapsed = time.monotonic() - started
    assert elapsed * 1000 < spec.TIMEOUTS['old_reader_observation_ms']
    suite.trace.emit('old_read_finished', scope_name='late', seconds=elapsed, expected='SNAPSHOT_EXPIRED')
    suite.sweep('late', 1, 'late-first-g1')
    suite.sweep('late', 2, 'late-abandoned-g2')
    release(suite, 'A', put)
    suite.sweep('late', 1, 'late-new-round-after-put')


def race(suite):
    suite.phase('direct-original-seal-race-and-old-cas')
    suite.create_direct('race')
    suite.seed('race')
    old = suite.proxies['A'].arm('race-original-sql-cas', 'PUT', spec.head_path('race'), 'hold')
    start_held(suite, 'A', 'race-old-sql', 'execute', 'race', old, intent='race-3', options=UNKNOWN)
    suite.finish('A', 'race-old-sql', 'UNKNOWN')
    deleted = suite.delete_direct('race', 'race-delete')
    gates = {}
    for role in ('C', 'R'):
        gates[role] = suite.proxies[role].arm('race-seal-' + role, 'PUT', spec.head_path('race'), 'hold')
        start_held(suite, role, 'race-seal-' + role, 'retire_storage', 'race', gates[role],
                   input={'expectedHeadSerial': deleted['head_serial']})
    release(suite, 'C', gates['C'])
    suite.finish('C', 'race-seal-C')
    release(suite, 'R', gates['R'])
    suite.finish('R', 'race-seal-R', 'CONFLICT')
    release(suite, 'A', old)
    suite.sweep('race', 1, 'race-all-payload')


def committed_reply(suite):
    suite.phase('known-committed-original-reply-after-terminal')
    suite.create_direct('receipt')
    suite.seed('receipt')
    gate = suite.proxies['A'].arm('receipt-original-success', 'PUT', spec.head_path('receipt'),
                                  'hold', stage='after_response')
    start_held(suite, 'A', 'receipt-delayed-sql', 'execute', 'receipt', gate, intent='receipt-3')
    started = time.monotonic()
    suite.delete_direct('receipt', 'receipt-delete')
    suite.seal('receipt', 'receipt-seal')
    suite.sweep('receipt', 1, 'receipt-all-payload')
    release(suite, 'A', gate)
    value = suite.finish('A', 'receipt-delayed-sql')
    elapsed = time.monotonic() - started
    assert elapsed * 1000 < spec.TIMEOUTS['receipt_observation_ms']
    suite.record_original('receipt-3', value)
    suite.trace.emit('delayed_commit_finished', seconds=elapsed, original='receipt-3')


def before_release(suite):
    name = 'before'
    suite.phase('named-seal-before-release')
    suite.create_name(name)
    suite.seed(name)
    suite.named('C', 'before-live-storage-rejected', name,
        {'operation': 'named_storage_status', 'creation': spec.creation(name)}, expect='CONFLICT')
    head = suite.status(name, 'before-delete-base')
    action = control(suite, name, 'delete', head)
    old = suite.proxies['A'].arm('before-old-release', 'PUT', spec.catalogue_path('name', name), 'hold')
    suite.named_begin('A', 'before-delete-original', name, action, options=UNKNOWN)
    arrived(old)
    suite.finish('A', 'before-delete-original', 'UNKNOWN')
    suite.named('C', 'before-no-admin-storage', name,
        {'operation': 'named_storage_status', 'creation': spec.creation(name)}, expect='DENIED', principal='12')
    suite.seal(name, 'before-seal')
    prepared = suite.prepare_gc(name, 1, 'before-pending')
    assert prepared['status']['storage']['sweep'] is not None
    suite.restart_b('before-pending')
    moving = suite.proxies['R'].arm('before-unstable-name-view', 'GET',
        spec.catalogue_path('name', name), 'hold', occurrence=2)
    suite.named_begin('R', 'before-unstable-observation', name,
        {'operation': 'named_storage_status', 'creation': spec.creation(name)})
    arrived(moving)
    resumed = suite.call('B', 'before-delete-resumed', 'named_submit', name, intent='before-delete-original')
    assert resumed['phase'] == 'deleted'
    release(suite, 'R', moving)
    suite.finish('R', 'before-unstable-observation', 'CONFLICT')
    suite.create_name('before_successor', 'B')
    suite.seed('before_successor', 'B')
    release(suite, 'A', old)
    suite.resume_gc(name, prepared, 'before-checkpoint-resumed')
    suite.sweep(name, 1, 'before-all-payload')


def after_reuse(suite):
    name = 'after'
    suite.phase('named-seal-after-name-reuse')
    suite.create_name(name)
    suite.seed(name)
    action = control(suite, name, 'delete', suite.status(name, 'after-delete-base'))
    result = suite.named('B', 'after-delete-original', name, action)
    assert result['phase'] == 'deleted'
    suite.create_name('after_successor', 'B')
    suite.seed('after_successor', 'B')
    before = suite.status(name, 'after-seal-base', deleted=True)
    lost = suite.proxies['C'].arm('after-named-seal-response-lost', 'PUT', spec.head_path(name),
                                 'drop', stage='after_response')
    suite.named('C', 'after-seal-unknown', name, {'operation': 'retire_named_storage',
        'creation': spec.creation(name), 'expected_head_serial': before['head_serial']}, expect='UNKNOWN')
    arrived(lost)
    assert lost.finished.wait(5)
    terminal = suite.status(name, 'after-seal-observed', deleted=True)
    assert terminal['storage']['terminal']['serial'] == terminal['head_serial']
    for suffix, serial in (('original', before['head_serial']), ('current', terminal['head_serial'])):
        suite.named('C', 'after-repeat-seal-' + suffix, name, {'operation': 'retire_named_storage',
            'creation': spec.creation(name), 'expected_head_serial': serial}, expect='CONFLICT')
    suite.sweep(name, 1, 'after-all-payload')


def provision_pending(suite, name):
    suite.prepare_name(name)
    gate = suite.proxies['A'].arm(name + '-old-bind', 'PUT', spec.catalogue_path('name', name),
                                  'hold', occurrence=2)
    suite.named_begin('A', name + '-resume-original', name,
        {'operation': 'resume_create', 'creation': spec.creation(name)}, options=UNKNOWN)
    arrived(gate)
    suite.finish('A', name + '-resume-original', 'UNKNOWN')
    return gate


def own_deleted(suite, name, proof_present):
    suite.phase('own-deleted-' + name)
    bind = provision_pending(suite, name)
    action = control(suite, name, 'abort')
    path = spec.catalogue_path('name' if proof_present else 'abort-proof', name)
    gate = suite.proxies['B'].arm(name + '-old-abort', 'PUT', path, 'hold', occurrence=2 if proof_present else 1)
    suite.named_begin('B', name + '-abort-original', name, action, options=UNKNOWN)
    arrived(gate)
    suite.finish('B', name + '-abort-original', 'UNKNOWN')
    suite.seal(name, name + '-seal', 'R')
    prepared = suite.prepare_gc(name, 1, name + '-pending')
    assert prepared['status']['storage']['sweep'] is not None
    suite.restart_b(name + '-pending')
    if not proof_present:
        release(suite, 'B', gate)
    result = suite.call('B', name + '-abort-resumed', 'named_submit', name, intent=name + '-abort-original')
    assert result['phase'] == 'aborted'
    if proof_present:
        release(suite, 'B', gate)
    release(suite, 'A', bind)
    suite.resume_gc(name, prepared, name + '-checkpoint-resumed')
    suite.sweep(name, 1, name + '-all-payload')


def absent(suite):
    name = 'fence_absent'
    suite.phase('fence-absent-terminal-head-permanent')
    suite.prepare_name(name)
    old = suite.proxies['A'].arm('fence-absent-old-head', 'PUT', spec.head_path(name), 'hold')
    suite.named_begin('A', 'fence-absent-resume-original', name,
        {'operation': 'resume_create', 'creation': spec.creation(name)}, options=UNKNOWN)
    arrived(old)
    suite.finish('A', 'fence-absent-resume-original', 'UNKNOWN')
    result = suite.named('B', 'fence-absent-abort-original', name, control(suite, name, 'abort'))
    assert result['phase'] == 'aborted'
    suite.seal(name, 'fence-absent-seal')
    prepared = suite.prepare_gc(name, 1, 'fence-absent-pending')
    assert prepared['status']['storage']['sweep'] is not None
    suite.restart_b('fence-absent-pending')
    result = suite.call('B', 'fence-absent-abort-resumed', 'named_submit', name,
                        intent='fence-absent-abort-original')
    assert result['phase'] == 'aborted'
    release(suite, 'A', old)
    suite.resume_gc(name, prepared, 'fence-absent-checkpoint-resumed')
    suite.sweep(name, 1, 'fence-absent-all-payload')


def foreign(suite):
    name = 'foreign_loser'
    suite.phase('foreign-occupied-source-never-authorizes-retirement')
    suite.prepare_name(name)
    old = suite.proxies['A'].arm('foreign-loser-old-head', 'PUT', spec.head_path(name), 'hold')
    suite.named_begin('A', 'foreign-loser-resume-original', name,
        {'operation': 'resume_create', 'creation': spec.creation(name)}, options=UNKNOWN)
    arrived(old)
    suite.finish('A', 'foreign-loser-resume-original', 'UNKNOWN')
    suite.create_direct('foreign', 'B')
    suite.seed('foreign', 'B')
    lost = suite.proxies['B'].arm('foreign-abort-release-lost', 'PUT', spec.catalogue_path('name', name),
        'drop', stage='after_response', occurrence=2)
    suite.named('B', 'foreign-abort-original', name, control(suite, name, 'abort'), expect='UNKNOWN')
    arrived(lost)
    assert lost.finished.wait(5)
    suite.restart_b('foreign-original-abort')
    result = suite.call('B', 'foreign-abort-resumed', 'named_submit', name, intent='foreign-abort-original')
    assert result['phase'] == 'aborted'
    suite.named('C', 'foreign-storage-denied', name,
        {'operation': 'named_storage_status', 'creation': spec.creation(name)}, expect='IDENTITY_CONFLICT')
    foreign_head = suite.status('foreign', 'foreign-current-base')
    suite.named('C', 'foreign-seal-denied', name, {'operation': 'retire_named_storage',
        'creation': spec.creation(name), 'expected_head_serial': foreign_head['head_serial']}, expect='IDENTITY_CONFLICT')
    release(suite, 'A', old)


def diagnostics(suite):
    suite.phase('diagnostic-old-terminal-serial')
    suite.create_direct('stale')
    suite.seed('stale')
    suite.abort_copy('stale', 'stale-real-technical-gap')
    original = suite.status('stale', 'stale-original-authority')
    gate = suite.proxies['R'].arm('stale-old-read', 'GET', spec.prefix('stale', 1), 'hold')
    observed = start_held(suite, 'R', 'stale-old-lookup', 'lookup', 'stale', gate, intent='stale-1')
    started = time.monotonic()
    suite.delete_direct('stale', 'stale-delete')
    suite.seal('stale', 'stale-seal')
    first_page(suite, 'stale', observed['path'], 'stale-checkpoint', restart=False)
    suite.sweep('stale', 1, 'stale-all-g1')
    suite.sweep('stale', 2, 'stale-all-g2')
    suite.corrupt_only('stale', 'old-terminal-serial', {'terminal_serial': int(original['head_serial'])})
    release(suite, 'R', gate)
    suite.finish('R', 'stale-old-lookup', 'MISSING')
    elapsed = time.monotonic() - started
    assert elapsed * 1000 < spec.TIMEOUTS['old_reader_observation_ms']
    suite.trace.emit('old_read_finished', scope_name='stale', seconds=elapsed, expected='MISSING')

    suite.phase('diagnostic-checkpoint-not-after-seal')
    suite.create_direct('bad_sweep')
    suite.seed('bad_sweep')
    head = suite.status('bad_sweep', 'bad-sweep-admin-base')
    head = suite.call('B', 'bad-sweep-admin-only', 'policy', 'bad_sweep', input={
        'expectedRevision': head['revision'], 'nonce': suite.next_nonce(),
        'permissions': [{'principal': '11', 'read': False, 'write': False, 'admin': True}]})
    suite.call('B', 'bad-sweep-delete-status', 'status', 'bad_sweep', expect='DENIED')
    suite.call('B', 'bad-sweep-delete', 'lifecycle', 'bad_sweep', input={
        'expectedRevision': head['revision'], 'nonce': suite.next_nonce(), 'lifecycle': 'deleted'})
    suite.seal('bad_sweep', 'bad-sweep-seal-without-read-or-provision')
    prepared = suite.prepare_gc('bad_sweep', 1, 'bad-sweep-pending')
    assert prepared['status']['storage']['sweep'] is not None
    suite.corrupt_only('bad_sweep', 'checkpoint-before-seal', {'sweep_serial': 'terminal_serial'})
    suite.call('C', 'bad-sweep-observe-rejected', 'storage_status', 'bad_sweep', expect='CORRUPT')
    suite.call('B', 'bad-sweep-resume-rejected', 'gc_resume', 'bad_sweep', expect='CORRUPT',
        input={'batchSerial': prepared['status']['storage']['sweep']['serial']})


def cold(suite):
    suite.phase('all-compute-cache-loss')
    for role in spec.ROLES:
        suite.stop_service(role)
    suite.start_service('B', int(suite.workers['B']) + 100)
    for name in spec.SURVIVORS:
        suite.activate(name, 'cold-' + name, 'B')
        for counter in (1, 2):
            original = name + '-' + str(counter)
            value = suite.call('B', 'cold-lookup-' + original, 'lookup', name, intent=original)
            assert {'receipt': value['receipt'], 'result': value['result']} == suite.originals[original]
            suite.trace.emit('cold_original_recovered', name=original, receipt=value['receipt'], result=value['result'])
        suite.call('B', 'cold-query-' + name, 'query', name,
            statements=[{'sql': 'SELECT id,counter,payload FROM witness ORDER BY id', 'params': []}])
    for name in ('late', 'race', 'receipt', 'before', 'after', 'proof_present', 'proof_absent', 'fence_absent'):
        suite.status(name, 'cold-terminal-' + name, deleted=True)
        suite.call('B', 'cold-ordinary-status-' + name, 'status', name, expect='LIFECYCLE')
        if name in spec.SEEDED:
            suite.call('B', 'cold-ordinary-lookup-' + name, 'lookup', name,
                        expect='LIFECYCLE', intent=name + '-1')
    io.save(suite.evidence / 'original-results.json', io.encoded(suite.originals))
    assert len(suite.originals) == 21


def run(args):
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=False, mode=0o700)
    private = Path(tempfile.mkdtemp(prefix='scap-terminal-private-', dir=evidence.parent))
    private.chmod(0o700)
    suite = Harness(args, evidence, private)
    summary = {'schema': 1, 'status': 'FAILED', 'private': str(private), 'private_removed': False,
               'aws_standard': 'NOT_RUN', 'production_slo': 'NOT_RUN',
               'permanent_prefix_emptiness': 'NOT_CLAIMED', 'error': None}
    started = time.monotonic()

    def deadline(_signum, _frame):
        raise TimeoutError('fixed terminal whole-fixture deadline')

    previous = signal.signal(signal.SIGALRM, deadline)
    signal.alarm(spec.TIMEOUTS['whole_seconds'])
    successful = False
    try:
        suite.setup()
        late(suite)
        race(suite)
        committed_reply(suite)
        before_release(suite)
        after_reuse(suite)
        own_deleted(suite, 'proof_present', True)
        own_deleted(suite, 'proof_absent', False)
        absent(suite)
        foreign(suite)
        diagnostics(suite)
        cold(suite)
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
    for name in ('server', 'build-record', 'weed', 'evidence'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--node', default='node')
    arguments = parser.parse_args()
    for name in ('server', 'build_record', 'weed'):
        setattr(arguments, name, getattr(arguments, name).resolve())
    raise SystemExit(run(arguments))
