#!/usr/bin/env python3
"""Fixed HEAD8 public owner operations on actual native SQLite and signed S3."""
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
FAULTS = {row[0]: row[1:] for row in spec.FAULTS}


def arrived(gate):
    assert gate.arrived.wait(15), 'original fault arrival deadline'
    return gate.observed


def released(proxy, gate):
    proxy.release(gate)
    assert gate.finished.wait(15), 'original fault completion deadline'


def s3(suite, identifier, role, method, path, **fields):
    layer, mode, stage = FAULTS[identifier]
    assert layer == 's3'
    return suite.proxies[role].arm(identifier, method, path, mode, stage=stage, **fields)


def http(suite, identifier, worker, operation):
    layer, mode, stage = FAULTS[identifier]
    assert layer == 'http'
    return suite.http[str(worker)].arm(identifier, operation, mode=mode, stage=stage)


def owner_key(suite, name, kind):
    original = suite.saved[name]
    value = original['input']
    return spec.owner_path(original['scope_name'], kind, value['creator'], value['operation'])


def state(value, expected):
    assert value['state'] == expected, (expected, value)
    return value


def observe(suite, name, label, expected, **fields):
    value = suite.saved[name]['input']
    return state(suite.owner('observe', name, label, input={key: value[key] for key in ('creator', 'operation')},
                             **fields), expected)


def seed(suite):
    suite.seed_bulk()
    suite.phase('initial-small-scopes')
    for name in spec.SCOPES:
        if name not in ('bulk', 'named_successor'):
            suite.seed_small(name)


def bulk(suite):
    name = 'bulk'
    suite.phase('bulk-original-input-and-lost-acks')
    p1 = suite.new_plan(name, 1)
    gate = http(suite, 'bulk-prepare-ack', 9103, 'owner_prepare')
    suite.owner('prepare', p1, expect='UNKNOWN')
    arrived(gate)
    suite.restart_sdk('C', 'after-original-prepare-ack-loss')
    changed = suite.policy(name, 'bulk-change-original-base')
    state(suite.owner('inspect', p1, 'bulk-original-fenced-inspect'), 'fenced')
    variant = suite.save_variant(p1, p1 + '-changed-base', changed)
    suite.owner('prepare', variant, expect='CONFLICT')
    state(suite.owner('prepare', p1, 'bulk-original-prepare-again'), 'prepared')
    state(suite.owner('claim', p1, 'bulk-original-claim-fenced'), 'fenced')
    p2 = suite.new_plan(name, 2)
    state(suite.owner('prepare', p2), 'prepared')
    gate = http(suite, 'bulk-claim-ack', 9102, 'owner_claim')
    suite.owner('claim', p2, expect='UNKNOWN')
    arrived(gate)
    suite.restart_sdk('C', 'after-original-claim-ack-loss')
    claimed = state(suite.owner('inspect', p2, 'bulk-original-claimed-inspect'), 'claimed')
    state(suite.owner('claim', p2, 'bulk-explicit-claim-observation'), 'claimed')

    suite.phase('bulk-pending-read-and-write-fence')
    head = claimed['status']
    suite.call('B', 'bulk-pending-query', 'query', name,
        statements=[{'sql': 'SELECT id,counter,payload FROM witness ORDER BY id', 'params': []}])
    value = suite.call('B', 'bulk-pending-lookup', 'lookup', name, intent='bulk-001')
    assert value['result'] == suite.originals['bulk-001']['result']
    cancelled = suite.call('B', 'bulk-pending-known-cancel', 'cancel', name, intent='bulk-cancel')
    assert cancelled['state'] == 'cancelled'
    suite.call('B', 'bulk-pending-original-execute-rejected', 'execute', name,
               intent='bulk-001', expect='FENCED')
    suite.call('B', 'bulk-pending-new-execute-rejected', 'execute', name,
               intent='bulk-blocked', expect='FENCED')
    suite.call('B', 'bulk-pending-new-cancel-rejected', 'cancel', name,
               intent='bulk-blocked', expect='FENCED')
    for operation, fields in (
        ('close_full', {'expectedRevision': head['revision'], 'nonce': suite.next_nonce()}),
        ('lifecycle', {'expectedRevision': head['revision'], 'nonce': suite.next_nonce(), 'lifecycle': 'maintenance'}),
        ('compact_begin', {'expectedHeadSerial': head['head_serial']}),
        ('gc_prepare', {'expectedHeadSerial': head['head_serial'], 'generation': '1', 'after': None}),
        ('takeover', {'expectedRevision': head['revision'], 'nonce': suite.next_nonce(), 'expectedWorkerInstance': '9103'}),
        ('activate', {'expectedRevision': head['revision'], 'nonce': suite.next_nonce(), 'expectedWorkerInstance': '9102'}),
    ):
        role = 'B' if operation == 'activate' else 'C'
        suite.call(role, 'bulk-pending-' + operation, operation, name, expect='FENCED', input=fields)

    suite.phase('bulk-complete-recovery-ack-loss')
    gate = http(suite, 'bulk-resume-ack', 9102, 'owner_resume')
    suite.owner('resume', p2, expect='UNKNOWN')
    arrived(gate)
    suite.restart_sdk('C', 'after-original-resume-ack-loss')
    state(suite.owner('inspect', p2, 'bulk-original-active-inspect'), 'active')
    state(suite.owner('resume', p2, 'bulk-explicit-resume-history'), 'active')


def late_prepare(suite):
    name = 'late_prepare'
    suite.phase('prepare-invoke-process-exit-effect')
    p1 = suite.new_plan(name, 1)
    gate = s3(suite, 'late-descriptor-put', 'A', 'PUT', owner_key(suite, p1, 'descriptor'))
    suite.owner_begin('prepare', p1, 'late-prepare-original', bootstrap_worker='9101', options=UNKNOWN)
    arrived(gate)
    suite.finish('C', 'late-prepare-original', 'UNKNOWN')
    suite.stop_service('A', crash=True)
    released(suite.proxies['A'], gate)
    state(suite.owner('inspect', p1, 'late-prepare-original-inspected'), 'prepared')
    state(suite.owner('claim', p1), 'claimed')
    state(suite.owner('resume', p1), 'active')


def claim_cancel(suite):
    name = 'claim_cancel'
    suite.phase('claim-cancel-cancelling-ack-loss')
    p1 = suite.new_plan(name, 1)
    state(suite.owner('prepare', p1), 'prepared')
    gate = s3(suite, 'claim-cancel-old-claim', 'B', 'PUT', spec.head_path(name))
    suite.owner_begin('claim', p1, 'claim-cancel-original-claim', options=UNKNOWN)
    arrived(gate)
    suite.finish('C', 'claim-cancel-original-claim', 'UNKNOWN')
    ack = http(suite, 'cancelling-ack', 9104, 'owner_abort')
    suite.owner('abort', p1, 'claim-cancel-original-cancel', expect='UNKNOWN', bootstrap_worker='9104')
    arrived(ack)
    suite.stop_service('R', crash=True)
    suite.start_service('R', 9204)
    cancelled = state(suite.owner('inspect', p1, 'claim-cancel-inspect-cancelling'), 'cancelling')
    record = next(row for row in spec.exceptional_plans() if row.get('scope_name') == name)
    blocking = suite.save_plan(record, cancelled['status'])
    pending = state(suite.owner('prepare', blocking, principal='12'), 'pending')
    assert pending['reference'] == cancelled['prepared']['reference']
    suite.owner('claim_pending', blocking, 'claim-cancel-pending-is-not-prepared', expect='INVALID', principal='12')
    state(suite.owner('abort', p1, 'claim-cancel-complete-abort'), 'aborted')
    released(suite.proxies['B'], gate)
    state(suite.owner('resume', p1, 'claim-cancel-aborted-history'), 'aborted')
    suite.prepare_claim_resume(suite.new_plan(name, 2))


def claim_wins(suite):
    name = 'claim_wins'
    suite.phase('claim-cancel-original-etag-race')
    record = next(row for row in spec.exceptional_plans() if row.get('scope_name') == name)
    invalid = suite.save_plan(record, suite.status(name, name + '-invalid-base'))
    suite.owner('prepare', invalid, expect='FENCED')
    p1 = suite.new_plan(name, 1)
    state(suite.owner('prepare', p1), 'prepared')
    claim = s3(suite, 'claim-wins-claim', 'B', 'PUT', spec.head_path(name))
    suite.owner_begin('claim', p1, 'claim-wins-original-claim')
    arrived(claim)
    cancel = s3(suite, 'claim-wins-cancel', 'C', 'PUT', spec.head_path(name))
    suite.owner_begin('abort', p1, 'claim-wins-original-cancel')
    arrived(cancel)
    released(suite.proxies['B'], claim)
    state(suite.finish('C', 'claim-wins-original-claim'), 'claimed')
    released(suite.proxies['C'], cancel)
    suite.finish('C', 'claim-wins-original-cancel', 'CONFLICT')
    state(suite.owner('abort', p1, 'claim-wins-explicit-abort'), 'aborted')
    suite.prepare_claim_resume(suite.new_plan(name, 2))


def resume_cancel(suite):
    name = 'resume_cancel'
    suite.phase('resume-abort-abort-wins')
    p1 = suite.new_plan(name, 1)
    state(suite.owner('prepare', p1), 'prepared')
    state(suite.owner('claim', p1), 'claimed')
    gate = s3(suite, 'resume-cancel-active', 'B', 'PUT', spec.head_path(name))
    suite.owner_begin('resume', p1, 'resume-cancel-original-active')
    arrived(gate)
    state(suite.owner('abort', p1), 'aborted')
    released(suite.proxies['B'], gate)
    suite.finish('C', 'resume-cancel-original-active', 'CONFLICT')
    suite.prepare_claim_resume(suite.new_plan(name, 2))


def resume_wins(suite):
    name = 'resume_wins'
    suite.phase('resume-abort-and-same-actor-second-resume')
    p1 = suite.new_plan(name, 1)
    state(suite.owner('prepare', p1), 'prepared')
    state(suite.owner('claim', p1), 'claimed')
    active = s3(suite, 'resume-wins-active', 'B', 'PUT', spec.head_path(name))
    suite.owner_begin('resume', p1, 'resume-wins-first')
    arrived(active)
    queued = suite.trace.watch('http_proxy_forward_finished', role='B-9102', operation='owner_resume')
    suite.owner_begin('resume', p1, 'resume-wins-queued-second')
    assert queued.wait(15), 'second original resume forwarded while first CAS held'
    abort = s3(suite, 'resume-wins-abort', 'C', 'PUT', spec.head_path(name))
    suite.owner_begin('abort', p1, 'resume-wins-original-abort')
    arrived(abort)
    released(suite.proxies['B'], active)
    state(suite.finish('C', 'resume-wins-first'), 'active')
    state(suite.finish('C', 'resume-wins-queued-second'), 'active')
    released(suite.proxies['C'], abort)
    suite.finish('C', 'resume-wins-original-abort', 'CONFLICT')
    state(suite.owner('abort', p1, 'resume-wins-active-history'), 'active')
    suite.extra_sql(name)


def acl(suite):
    name = 'acl'
    suite.phase('resume-fresh-acl-and-prepare-before-history')
    p1 = suite.new_plan(name, 1)
    state(suite.owner('prepare', p1), 'prepared')
    state(suite.owner('claim', p1), 'claimed')
    first = s3(suite, 'acl-change-payload', 'B', 'GET', spec.prefix(name, 1))
    suite.owner_begin('resume', p1, 'acl-resume-old-head')
    arrived(first)
    suite.policy(name, 'acl-keep-admin-change', write11=False)
    released(suite.proxies['B'], first)
    suite.finish('C', 'acl-resume-old-head', 'CONFLICT')
    second = s3(suite, 'acl-revoke-payload', 'B', 'GET', spec.prefix(name, 1))
    suite.owner_begin('resume', p1, 'acl-resume-revoked')
    arrived(second)
    suite.policy(name, 'acl-withdraw-admin', admin11=False, read11=False, write11=False, principal='12')
    released(suite.proxies['B'], second)
    suite.finish('C', 'acl-resume-revoked', 'DENIED')
    suite.owner('resume', p1, 'acl-fresh-denied-resume', expect='DENIED')
    suite.policy(name, 'acl-restore-for-original-prepare', principal='12')
    descriptor = s3(suite, 'acl-prepare-descriptor', 'C', 'GET', owner_key(suite, p1, 'descriptor'))
    suite.owner_begin('prepare', p1, 'acl-delayed-prepare')
    arrived(descriptor)
    suite.policy(name, 'acl-withdraw-before-descriptor-delivery', admin11=False, read11=False, write11=False, principal='12')
    released(suite.proxies['C'], descriptor)
    suite.finish('C', 'acl-delayed-prepare', 'DENIED')
    state(suite.owner('inspect', p1, 'acl-current-admin-inspect', principal='12'), 'claimed')
    state(suite.owner('resume', p1, 'acl-current-admin-resume', principal='12'), 'active')
    suite.policy(name, 'acl-original-reader-restored-without-admin', admin11=False, principal='12')


def legacy(suite):
    name = 'legacy'
    suite.phase('legacy-takeover-cas-and-late-http-activation')
    p1 = suite.new_plan(name, 1)
    state(suite.owner('prepare', p1), 'prepared')
    original = suite.saved[p1]['input']
    gate = s3(suite, 'legacy-takeover', 'B', 'PUT', spec.head_path(name))
    suite.begin('B', 'legacy-original-takeover', 'takeover', name, input={
        'expectedRevision': original['expected_revision'], 'nonce': suite.next_nonce(), 'expectedWorkerInstance': '9102'})
    arrived(gate)
    claimed = state(suite.owner('claim', p1), 'claimed')
    released(suite.proxies['B'], gate)
    suite.finish('B', 'legacy-original-takeover', 'CONFLICT')
    delayed = http(suite, 'legacy-activation-delayed', 9102, 'activate')
    suite.begin('B', 'legacy-original-late-activation', 'activate', name, options=UNKNOWN, input={
        'expectedRevision': str(int(claimed['status']['revision']) + 1),
        'nonce': suite.next_nonce(), 'expectedWorkerInstance': '9102'})
    arrived(delayed)
    suite.finish('B', 'legacy-original-late-activation', 'UNKNOWN')
    state(suite.owner('abort', p1), 'aborted')
    released(suite.http['9102'], delayed)
    suite.prepare_claim_resume(suite.new_plan(name, 2))


def proof_claim(suite):
    name = 'proof_claim'
    suite.phase('claim-preserves-original-terminal-proof')
    p1 = suite.new_plan(name, 1)
    suite.prepare_claim_resume(p1)
    suite.extra_sql(name)
    suite.policy(name, 'proof-claim-later-acl')
    p2 = suite.new_plan(name, 2)
    state(suite.owner('prepare', p2), 'prepared')
    proof_path = owner_key(suite, p1, 'proof')
    put = s3(suite, 'claim-proof-put-ack', 'B', 'PUT', proof_path)
    suite.owner('claim', p2, 'proof-claim-put-unknown', expect='UNKNOWN')
    arrived(put)
    get = s3(suite, 'claim-proof-read-ack', 'B', 'GET', proof_path)
    suite.owner('claim', p2, 'proof-claim-get-unknown', expect='UNKNOWN')
    arrived(get)
    state(suite.owner('claim', p2, 'proof-claim-final-claim'), 'claimed')
    active = state(suite.owner('resume', p2), 'active')
    observe(suite, p1, 'proof-claim-original-history', 'active')
    missing = s3(suite, 'old-proof-missing', 'C', 'GET', proof_path)
    observe(suite, p1, 'proof-claim-missing-is-unknown-history', 'fenced')
    arrived(missing)
    observe(suite, p1, 'proof-claim-original-history-restored', 'active')
    admission = active['status']['owner_plan']['admission']
    wrong = s3(suite, 'old-proof-not-before-admission', 'Z', 'GET', proof_path,
        mutation={'kind': 'proof_at_admission', 'revision': int(admission['revision']),
                  'head_serial': int(admission['head_serial'])})
    original = suite.saved[p1]['input']
    suite.owner('observe', p1, 'proof-claim-bad-admission-rejected', expect='CORRUPT', bootstrap_worker='9106',
                input={key: original[key] for key in ('creator', 'operation')})
    arrived(wrong)


def proof_cancel(suite):
    name = 'proof_cancel'
    suite.phase('cancel-preserves-original-aborted-proof')
    p1 = suite.new_plan(name, 1)
    state(suite.owner('prepare', p1), 'prepared')
    state(suite.owner('claim', p1), 'claimed')
    state(suite.owner('abort', p1), 'aborted')
    suite.policy(name, 'proof-cancel-later-acl')
    p2 = suite.new_plan(name, 2)
    state(suite.owner('prepare', p2), 'prepared')
    gate = s3(suite, 'cancel-proof-read-ack', 'C', 'GET', owner_key(suite, p1, 'proof'))
    suite.owner('abort', p2, 'proof-cancel-original-unknown', expect='UNKNOWN')
    arrived(gate)
    state(suite.owner('abort', p2, 'proof-cancel-accepted-cancelling'), 'cancelling')
    state(suite.owner('abort', p2, 'proof-cancel-complete-abort'), 'aborted')
    suite.prepare_claim_resume(suite.new_plan(name, 3))
    observe(suite, p1, 'proof-cancel-original-history', 'aborted')


def named_history(suite):
    name = 'named_old'
    suite.phase('named-pending-delete-control-and-history')
    p1 = suite.new_plan(name, 1)
    state(suite.owner('prepare', p1), 'prepared')
    claimed = state(suite.owner('claim', p1), 'claimed')
    suite.named('named-pending-original-delete', name, {'operation': 'delete_name',
        'creation': spec.creation(name), 'control_operation': '97001', 'expected_name_revision': '2',
        'expected_head_revision': claimed['status']['revision'], 'nonce': suite.next_nonce()}, expect='CONFLICT')
    state(suite.owner('resume', p1), 'active')
    suite.extra_sql(name)
    p2 = suite.new_plan(name, 2)
    current = suite.prepare_claim_resume(p2)
    deleted = suite.named('named-new-explicit-delete', name, {'operation': 'delete_name',
        'creation': spec.creation(name), 'control_operation': '97002', 'expected_name_revision': '2',
        'expected_head_revision': current['status']['revision'], 'nonce': suite.next_nonce()})
    assert deleted['phase'] == 'deleted'
    state(suite.owner('inspect', p2, 'named-deleted-owner-history'), 'active')
    storage = suite.named('named-terminal-storage-base', name,
        {'operation': 'named_storage_status', 'creation': spec.creation(name)})
    sealed = suite.named('named-explicit-storage-seal', name, {'operation': 'retire_named_storage',
        'creation': spec.creation(name), 'expected_head_serial': storage['head_serial']})
    assert sealed['storage']['terminal']['serial'] == sealed['head_serial']
    suite.sweep_named_old()
    observe(suite, p1, 'named-proof-after-payload-gc', 'active')
    state(suite.owner('inspect', p2, 'named-current-after-payload-gc'), 'active')
    suite.seed_small('named_successor', 'C')
    state(suite.owner('inspect', p1, 'named-proof-after-name-reuse'), 'active')
    state(suite.owner('inspect', p2, 'named-current-after-name-reuse'), 'active')
    for counter in (1, 2, 3):
        suite.call('C', f'named-deleted-original-{counter}', 'lookup', name,
                   intent=f'{name}-{counter:03d}', expect='LIFECYCLE')


def missing_descriptor(suite):
    name = 'missing_descriptor'
    suite.phase('missing-descriptor-and-stable-hash-corruption')
    p1 = suite.new_plan(name, 1)
    suite.prepare_claim_resume(p1)
    p2 = suite.new_plan(name, 2)
    active = suite.prepare_claim_resume(p2)
    missing = s3(suite, 'current-descriptor-missing', 'C', 'GET', owner_key(suite, p2, 'descriptor'))
    suite.owner('prepare', p2, 'missing-current-descriptor-rejected', expect='CORRUPT')
    arrived(missing)
    variant = suite.save_variant(p1, p1 + '-changed-base', active['status'])
    old = s3(suite, 'historical-descriptor-missing', 'R', 'GET', owner_key(suite, p1, 'descriptor'))
    suite.owner('prepare', variant, 'missing-historical-descriptor-rejected', expect='CORRUPT', bootstrap_worker='9204')
    arrived(old)
    reference = active['prepared']['reference']
    changed_hash = ('0' if reference['descriptor_hash'] != '0' * 64 else '1') * 64
    wrong = s3(suite, 'same-id-different-hash', 'G', 'GET', spec.head_path(name), uses=2,
        mutation={'kind': 'same_id_hash', 'creator': int(reference['creator']),
                  'operation': int(reference['operation']), 'descriptor_hash': changed_hash})
    suite.owner('inspect', p2, 'same-id-different-hash-rejected', expect='CORRUPT', bootstrap_worker='9105')
    arrived(wrong)
    assert wrong.used == 2 and wrong.finished.wait(5)


def budget(suite, name, role, identifier):
    suite.phase(name + '-same-actor-budget-is-not-quarantine')
    p1 = suite.new_plan(name, 1)
    state(suite.owner('prepare', p1), 'prepared')
    state(suite.owner('claim', p1), 'claimed')
    gate = s3(suite, identifier, role, 'GET', owner_key(suite, p1, 'descriptor'))
    suite.owner_begin('resume', p1, name + '-limited-resume')
    arrived(gate)
    queued = suite.trace.watch('http_proxy_forward_finished', role=role + '-' + suite.workers[role], operation='query')
    suite.begin(role, name + '-queued-query', 'query', name,
                statements=[{'sql': 'SELECT id,counter,payload FROM witness ORDER BY id', 'params': []}])
    assert queued.wait(15), 'same-scope query forwarded while original resume held'
    released(suite.proxies[role], gate)
    suite.finish('C', name + '-limited-resume', 'LIMIT')
    query = suite.finish(role, name + '-queued-query')
    suite.trace.emit('same_actor_query_after_budget', scope_name=name, worker=suite.workers[role],
                     role=role, service=suite.services[role][0].id, result=query)
    state(suite.owner('abort', p1), 'aborted')
    suite.prepare_claim_resume(suite.new_plan(name, 2))


def target_death(suite):
    name = 'target_death'
    suite.phase('claim-invoke-process-exit-effect')
    p1 = suite.new_plan(name, 1)
    state(suite.owner('prepare', p1), 'prepared')
    gate = s3(suite, 'dead-worker-claim', 'B', 'PUT', spec.head_path(name))
    suite.owner_begin('claim', p1, 'dead-worker-original-claim', options=UNKNOWN)
    arrived(gate)
    suite.finish('C', 'dead-worker-original-claim', 'UNKNOWN')
    suite.stop_service('B', crash=True)
    released(suite.proxies['B'], gate)
    state(suite.owner('inspect', p1, 'dead-worker-claim-inspected'), 'claimed')
    suite.start_service('B', 9202)
    suite.owner('claim', p1, 'replacement-worker-old-claim', expect='TARGET_MISMATCH')
    suite.owner('resume', p1, 'replacement-worker-old-resume', expect='TARGET_MISMATCH')
    state(suite.owner('abort', p1), 'aborted')
    suite.prepare_claim_resume(suite.new_plan(name, 2))


def resume_death(suite):
    name = 'resume_death'
    suite.phase('resume-invoke-process-exit-effect')
    p1 = suite.new_plan(name, 1)
    state(suite.owner('prepare', p1), 'prepared')
    state(suite.owner('claim', p1), 'claimed')
    gate = s3(suite, 'dead-worker-resume', 'R', 'PUT', spec.head_path(name))
    suite.owner_begin('resume', p1, 'dead-worker-original-active', options=UNKNOWN)
    arrived(gate)
    suite.finish('C', 'dead-worker-original-active', 'UNKNOWN')
    suite.stop_service('R', crash=True)
    released(suite.proxies['R'], gate)
    state(suite.owner('inspect', p1, 'dead-worker-active-inspected'), 'active')
    state(suite.owner('abort', p1, 'dead-worker-active-history'), 'active')
    suite.start_service('R', 9304)
    suite.owner('resume', p1, 'replacement-worker-original-active', expect='TARGET_MISMATCH')
    suite.prepare_claim_resume(suite.new_plan(name, 2))


def cold(suite):
    suite.phase('all-compute-cache-loss')
    for role in tuple(suite.clients):
        suite.stop_sdk(role)
    for role in tuple(suite.services):
        suite.stop_service(role)
    suite.start_service('C', 9203)
    suite.start_sdk('C')
    for name in spec.SURVIVORS:
        prior = spec.WARM_PLANS[name]
        if prior:
            state(suite.owner('inspect', f'{name}-p{len(prior)}', name + '-cold-original-history', principal='12'), 'active')
        plan = suite.new_plan(name, len(prior) + 1)
        suite.prepare_claim_resume(plan, principal='12')
        for original in suite.specs:
            if original['scope_name'] != name or original['purpose'] in ('cancel', 'blocked'):
                continue
            value = suite.call('C', 'cold-lookup-' + original['name'], 'lookup', name, intent=original['name'])
            assert value['state'] == 'committed' and value['result'] == suite.originals[original['name']]['result']
            suite.trace.emit('cold_original_recovered', name=original['name'], receipt=value['receipt'], result=value['result'])
        suite.call('C', 'cold-query-' + name, 'query', name,
            statements=[{'sql': 'SELECT id,counter,payload FROM witness ORDER BY id', 'params': []}])
    observe(suite, 'bulk-p1', 'bulk-cold-original-unaccepted-history', 'fenced', principal='12')
    cancelled = suite.call('C', 'cold-original-cancel', 'lookup', 'bulk', intent='bulk-cancel')
    assert cancelled['state'] == 'cancelled'
    unknown = suite.call('C', 'cold-original-blocked', 'lookup', 'bulk', intent='bulk-blocked')
    assert unknown['state'] == 'unknown'
    assert len(suite.originals) == spec.EXPECTED['sql_committed']
    assert len(suite.saved) == spec.EXPECTED['saved_owner_inputs']
    io.save(suite.evidence / 'original-results.json', io.encoded(suite.originals))


def run(args):
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=False, mode=0o700)
    private = Path(tempfile.mkdtemp(prefix='scap-owner-private-', dir=evidence.parent))
    private.chmod(0o700)
    suite = Harness(args, evidence, private)
    summary = {'schema': 1, 'status': 'FAILED', 'private': str(private), 'private_removed': False,
               'aws_standard': 'NOT_RUN', 'production_slo': 'NOT_RUN',
               'automatic_failover_controller': 'NOT_IMPLEMENTED_BY_THIS_FIXTURE', 'error': None}
    started = time.monotonic()

    def deadline(_signum, _frame):
        raise TimeoutError('fixed owner-plan whole-fixture deadline')

    previous = signal.signal(signal.SIGALRM, deadline)
    signal.alarm(spec.TIMEOUTS['whole_seconds'])
    successful = False
    try:
        suite.setup()
        seed(suite)
        bulk(suite)
        late_prepare(suite)
        claim_cancel(suite)
        claim_wins(suite)
        resume_cancel(suite)
        resume_wins(suite)
        acl(suite)
        legacy(suite)
        proof_claim(suite)
        proof_cancel(suite)
        named_history(suite)
        missing_descriptor(suite)
        budget(suite, 'budget_gets', 'G', 'gets-budget-descriptor')
        budget(suite, 'budget_bytes', 'Z', 'bytes-budget-descriptor')
        target_death(suite)
        resume_death(suite)
        cold(suite)
        for proxy in (*suite.proxies.values(), *suite.http.values()):
            for gate in proxy.gates:
                assert gate.finished.wait(5) and not gate.aborted
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
