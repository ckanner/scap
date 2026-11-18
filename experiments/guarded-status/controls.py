#!/usr/bin/env python3
"""Mutate independently audited original evidence; never alter actual source/history."""
from __future__ import annotations
import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path
import shutil
from urllib.parse import urlparse

import oracle


def matching(rows, event, command=None):
    return oracle.only([r for r in rows if r['event'] == event and
        (command is None or r.get('command') == command)], 'control needs one original event')


def renumber(rows, *, node=False):
    rows.sort(key=lambda row: int(row['monotonic_ns']))
    for index, row in enumerate(rows, 1):
        row['sequence'] = index


def set_body(row, field, digest, value):
    raw = json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode()
    row[field] = base64.b64encode(raw).decode()
    row[digest] = hashlib.sha256(raw).hexdigest()
    return raw


def missing_fetch(data):
    row = matching(data['node'], 'http_request', 'guarded_nonowner')
    data['node'].remove(row)
    renumber(data['node'], node=True)


def extra_post(data):
    row = copy.deepcopy(matching(data['events'], 'http_request', 'wrong_worker'))
    row['monotonic_ns'] += 1
    row['http_serial'] = 30
    data['events'].append(row)
    renumber(data['events'])


def wrong_guard(data):
    name = 'guarded_nonowner'
    fetch = matching(data['node'], 'http_request', name)
    body = oracle.parse(oracle.b64(fetch['body']))
    body['expected_worker_instance'] = '9101'
    set_body(fetch, 'body', 'body_sha256', body)
    for row in data['events']:
        if row.get('command') == name and 'request_body' in row:
            set_body(row, 'request_body', 'request_sha256', body)


def guard_removed(data):
    name = 'replaced_old_route'
    fetch = matching(data['node'], 'http_request', name)
    body = oracle.parse(oracle.b64(fetch['body']))
    del body['expected_worker_instance']
    set_body(fetch, 'body', 'body_sha256', body)
    for row in data['events']:
        if row.get('command') == name and 'request_body' in row:
            set_body(row, 'request_body', 'request_sha256', body)


def wrong_credential(data):
    name = 'manager_fresh'
    digest = data['configuration']['credential_sha256']['blind']
    matching(data['node'], 'http_request', name)['credential_sha256'] = digest
    for row in data['events']:
        if row.get('command') == name and 'credential_sha256' in row:
            row['credential_sha256'] = digest


def wrong_creation_admission(data):
    matching(data['node'], 'http_request', 'seed_create')['admission'] = 'control'


def untrusted_destination(data):
    matching(data['node'], 'http_request', 'copied_route')['url'] = data['configuration']['sink']


def followed_redirect(data):
    matching(data['node'], 'http_request', 'copied_route')['redirect'] = 'follow'


def guarded_request_issued_s3(data):
    source = oracle.only([r for r in data['history'] if r['event'] == 'object_request' and
        r['phase'] == 'guarded_nonowner'], 'control original metadata GET')
    source_serial = source['request_serial']
    rows = [copy.deepcopy(r) for r in data['history'] if r.get('request_serial') == source_serial]
    call = matching(data['events'], 'http_request', 'wrong_worker')
    response = matching(data['events'], 'http_response', 'wrong_worker')
    maximum = max(r.get('request_serial', 0) for r in data['history'])
    oracle.require(response['monotonic_ns'] - call['monotonic_ns'] > len(rows) + 2, 'control needs real HTTP interval')
    for offset, row in enumerate(rows, 1):
        row['phase'] = 'wrong_worker'
        row['request_serial'] = maximum + 1
        row['monotonic_ns'] = call['monotonic_ns'] + offset
    data['history'].extend(rows)
    renumber(data['history'])


def foreign_daemon_head(data):
    for row in data['history']:
        if row.get('phase') == 'reader_denied' and 'request_serial' in row:
            row['worker'] = 'q'
            # Keep the hypothetical foreign daemon's wire authority coherent;
            # the intended counterexample is the original HTTP receiver binding.
            row['signing']['host'] = urlparse(data['configuration']['s3_endpoints']['q']).netloc


def stale_acl(data):
    old = oracle.only([r for r in data['history'] if r['event'] == 'object_response' and
        r['phase'] == 'legacy_status'], 'control original prior HEAD')
    for row in data['history']:
        if row.get('phase') == 'reader_denied' and row['event'] in ('object_response', 'object_response_delivered'):
            for key in ('response_body', 'response_bytes', 'response_sha256', 'head_response_bytes', 'etag'):
                row[key] = copy.deepcopy(old[key])


def split_head_etag(data):
    row = oracle.only([r for r in data['history'] if r['event'] == 'object_response' and
        r['phase'] == 'manager_fresh'], 'control fresh HEAD')
    row['etag'] = '"another-original-response"'


def status_mutates_s3(data):
    response = oracle.only([r for r in data['history'] if r['event'] == 'object_response'
        and r['phase'] == 'manager_fresh'], 'control original successful status HEAD')
    body = oracle.b64(response['response_body'])
    for row in data['history']:
        if row.get('phase') == 'manager_fresh' and 'request_serial' in row:
            row['method'] = 'PUT'
            row['if_none_match'] = '*'
            row['request_body'] = base64.b64encode(body).decode()
            row['request_bytes'] = len(body)
            row['request_sha256'] = oracle.sha(body)
            row['head_request_bytes'] = list(body)
            row['signing']['payload_sha256'] = oracle.sha(body)


def false_wait4(data):
    matching(data['events'], 'node_stopped')['kernel_usage']['source'] = 'sampled_unowned_pid'


def reused_worker_identity(data):
    data['service_configs']['q']['worker_instance'] = '9202'


def reconstructed_old_client(data):
    matching(data['node'], 'original_client_reused')['created_by'] = 'replacement_new_registry'


def early_deadline_release(data):
    observed = matching(data['events'], 'sdk_completion_observed', 'deadline_probe')
    matching(data['events'], 'fault_released')['monotonic_ns'] = observed['monotonic_ns'] - 1
    renumber(data['events'])


def unknown_becomes_success(data):
    matching(data['node'], 'command_finished', 'authority_unavailable')['ok'] = True
    matching(data['events'], 'sdk_completion_observed', 'authority_unavailable')['ok'] = True


def lost_original_receipt(data):
    matching(data['node'], 'command_finished', 'final_seed_lookup')['value']['receipt']['sequence'] = '2'


def payload_cache_created(data):
    row = oracle.only([r for r in data['events'] if r['event'] == 'cache_snapshot' and
        r['label'] == 'old_probe_before_kill'], 'control original empty cache')
    row['files'] = [{'path': 'database.db', 'bytes': 4096, 'sha256': '0' * 64}]


def wrong_binary(data):
    row = oracle.only([r for r in data['events'] if r['event'] == 'service_started' and r['worker'] == 'q'],
        'control actual replacement')
    row['binary']['sha256'] = '0' * 64


def missing_join(data):
    row = oracle.only([r for r in data['events'] if r['event'] == 'listener_closed' and r['name'] == 'http-p'],
        'control actual closed listener')
    row['handlers_joined'] = False


def replacement_ready_after_probes(data):
    ready = oracle.only([r for r in data['events'] if r['event'] == 'service_ready' and r['worker'] == 'q'],
        'control needs original Q readiness')
    response = matching(data['events'], 'http_response', 'replacement_legacy_status')
    stop = oracle.only([r for r in data['events'] if r['event'] == 'service_stop_requested' and r['worker'] == 'q'],
        'control needs original Q stop')
    oracle.require(response['monotonic_ns'] + 1 < stop['monotonic_ns'], 'control needs original Q lifetime tail')
    ready['monotonic_ns'] = response['monotonic_ns'] + 1
    renumber(data['events'])


def http_listener_started_after_request(data):
    start = oracle.only([r for r in data['events'] if r['event'] == 'listener_started' and r['name'] == 'http-p'],
        'control needs original HTTP listener')
    request = matching(data['events'], 'http_request', 'legacy_status')
    response = matching(data['events'], 'http_response', 'legacy_status')
    oracle.require(request['monotonic_ns'] + 1 < response['monotonic_ns'], 'control needs original HTTP interval')
    start['monotonic_ns'] = request['monotonic_ns'] + 1
    renumber(data['events'])


def s3_listener_closed_before_response(data):
    stop = oracle.only([r for r in data['events'] if r['event'] == 'listener_closed' and r['name'] == 's3-q'],
        'control needs original Q S3 listener')
    response = oracle.only([r for r in data['history'] if r['event'] == 'object_response' and
        r['phase'] == 'replacement_new_registry'], 'control needs original Q HEAD response')
    stop['monotonic_ns'] = response['monotonic_ns'] - 1
    renumber(data['events'])


def node_clock_before_spawn(data):
    hello = matching(data['node'], 'hello')
    start = matching(data['events'], 'node_started')
    stamp = start['spawn_requested_ns'] - 1
    oracle.require(0 < stamp < int(data['node'][1]['monotonic_ns']), 'control needs original Node clock interval')
    hello['monotonic_ns'] = str(stamp)


def node_clock_after_pipe_observation(data):
    hello = matching(data['node'], 'hello')
    wrapper = oracle.only([r for r in data['events'] if r['event'] == 'node_event' and
        oracle.parse(oracle.b64(r['raw']))['event'] == 'hello'], 'control needs original hello pipe observation')
    stamp = wrapper['monotonic_ns'] + 1
    oracle.require(stamp < int(data['node'][1]['monotonic_ns']), 'control needs original hello/next-command gap')
    hello['monotonic_ns'] = str(stamp)


def fault_entered_on_another_request(data):
    row = oracle.only([r for r in data['events'] if r['event'] == 'fault_entered' and r['id'] == 'deadline_hold'],
        'control needs original held response')
    row['http_serial'] = matching(data['events'], 'http_request', 'response_lost')['http_serial']


def deadline_hold_entered_after_sdk_outcome(data):
    row = oracle.only([r for r in data['events'] if r['event'] == 'fault_entered' and r['id'] == 'deadline_hold'],
        'control needs original held response')
    finish = matching(data['node'], 'command_finished', 'deadline_probe')
    observed = matching(data['events'], 'sdk_completion_observed', 'deadline_probe')
    stamp = int(finish['monotonic_ns']) + 1
    oracle.require(stamp < observed['monotonic_ns'], 'control needs original SDK/parent observation gap')
    row['monotonic_ns'] = stamp
    renumber(data['events'])


def unaccounted_listener_handler(data):
    row = oracle.only([r for r in data['events'] if r['event'] == 'listener_closed' and r['name'] == 'http-p'],
        'control needs original HTTP handler count')
    row['accepted_handlers'] += 1


def duplicate_listener_identity(data):
    row = oracle.only([r for r in data['events'] if r['event'] == 'listener_started'
        and r['name'] == 's3-q'], 'control needs original Q listener')
    row['name'] = 's3-p'


# Each counterexample must reach its specified semantic boundary. A missing
# field, unrelated digest/clock failure or any other ValueError is not a pass.
CASES = (
    (missing_fetch, 'original Fetch denominator'),
    (extra_post, 'HTTP event denominator: http_request'),
    (wrong_guard, 'original wire action changed: guarded_nonowner'),
    (guard_removed, 'original wire action changed: replaced_old_route'),
    (wrong_credential, 'credential identity changed'),
    (wrong_creation_admission, 'admission class changed'),
    (untrusted_destination, 'credential destination changed'),
    (followed_redirect, 'SDK method/redirect changed'),
    (guarded_request_issued_s3, 'guard/auth/fresh HEAD order changed: wrong_worker'),
    (foreign_daemon_head, 'S3 came from wrong daemon instance'),
    (stale_acl, 'object versions violate original real-time invocation/response intervals'),
    (split_head_etag, 'delivery changed original backend body/ETag/status'),
    (status_mutates_s3, 'metadata probe performed payload/native I/O or mutation'),
    (false_wait4, 'real owned wait4 is missing/wrong'),
    (reused_worker_identity, 'daemon instance/address binding'),
    (reconstructed_old_client, 'wrong original client reused'),
    (early_deadline_release, 'held response released before original SDK deadline outcome'),
    (unknown_becomes_success, 'SDK error classification changed: authority_unavailable'),
    (lost_original_receipt, 'SDK lost original commit knowledge'),
    (payload_cache_created, 'metadata probe opened payload files'),
    (wrong_binary, 'daemon binary not original release'),
    (missing_join, 'listener/handler lifetime leaked'),
    (replacement_ready_after_probes, 'HTTP outside actual receiving daemon ready/lifetime'),
    (http_listener_started_after_request, 'HTTP event outside original listener lifetime'),
    (s3_listener_closed_before_response, 'S3 event outside original listener lifetime'),
    (node_clock_before_spawn, 'Node clock is outside original child/parent observation'),
    (node_clock_after_pipe_observation, 'Node clock is outside original child/parent observation'),
    (fault_entered_on_another_request, 'fault witness binds another original request'),
    (deadline_hold_entered_after_sdk_outcome, 'HTTP fault entered after original SDK outcome'),
    (unaccounted_listener_handler, 'listener accepted an unaccounted connection/request'),
    (duplicate_listener_identity, 'listener denominator'),
)


def file_inventory(directory):
    return {str(path.relative_to(directory)): {'bytes': path.stat().st_size,
        'sha256': oracle.sha(path.read_bytes())} for path in sorted(directory.rglob('*')) if path.is_file()}


def main(evidence, output):
    evidence, output = evidence.resolve(), output.resolve()
    oracle.require(not output.exists() and not output.is_relative_to(evidence), 'fresh separate controls output required')
    output.mkdir(parents=True)
    before = file_inventory(evidence)
    baseline = oracle.audit(evidence)
    data = oracle.load_projection(evidence)
    build = oracle.build_audit.receipt(evidence, True, profile='service', require_artifacts=True, source_root=oracle.ROOT)
    negative = []
    for mutation, expected in CASES:
        changed = copy.deepcopy(data)
        mutation(changed)
        try:
            oracle.audit_projection(changed, build)
        except ValueError as error:
            oracle.equal(str(error), expected, 'control rejected at another rule: ' + mutation.__name__)
            negative.append({'case': mutation.__name__, 'status': 'REJECTED', 'reason': str(error),
                'expected_rejection': expected, 'control_kind': 'audited_semantic_projection'})
        else:
            raise AssertionError('counterfeit evidence accepted: ' + mutation.__name__)
    oracle.require(not any(p.is_symlink() for p in evidence.rglob('*')), 'positive copy cannot follow evidence symlinks')
    positive = output / 'positive-original-copy'
    shutil.copytree(evidence, positive)
    oracle.equal(file_inventory(positive), before, 'positive evidence copy bytes changed')
    oracle.equal(oracle.audit(positive), baseline, 'original complete copy failed independent audit')
    oracle.equal(file_inventory(evidence), before, 'controls modified original evidence')
    report = {'schema': 1, 'status': 'PASSED_WITHIN_FIXED_CONTROL_SCOPE',
        'negative_controls': negative, 'negative_count': len(negative), 'positive_original_copies': 1,
        'positive_files': len(before), 'original_unchanged': True, 'original_files': before,
        'actual_inputs_modified': False, 'aws_standard': 'NOT_RUN'}
    with (output / 'controls.json').open('x') as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write('\n')
    print(json.dumps({'status': report['status'], 'negative_count': len(negative), 'positive_original_copies': 1}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    main(args.evidence, args.output)
