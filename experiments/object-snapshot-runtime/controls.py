#!/usr/bin/env python3
"""Ten complete evidence copies must fail the named independent guard."""
import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil

import audit_evidence as e
import audit_model as m
import oracle

description = importlib.util.spec_from_file_location('snapshot_evidence_mutations',
    Path(__file__).resolve().parent.parent / 'object-owner-plan-runtime/controls.py')
prior = importlib.util.module_from_spec(description)
description.loader.exec_module(prior)
encoded, replace, save_rows, put_raw, replace_blob = prior.encoded, prior.replace, prior.save_rows, prior.put_raw, prior.replace_blob
S3_STAGES = {'s3_handler_started', 's3_request', 's3_forward_started', 's3_backend_response',
             's3_delivery_started', 's3_delivery_finished', 's3_handler_finished'}


def events(directory, mutate, reorder=False):
    path = directory / 'events.jsonl'
    values = e.rows(path)
    mutate(values)
    save_rows(path, values, reorder=reorder)


def product(directory, operation):
    values = e.rows(directory / 'events.jsonl')
    matches = [row for row in values if row['event'] == 'http_proxy_backend_response' and row['operation'] == operation]
    assert len(matches) == 2 if operation in ('snapshot_capture', 'snapshot_release') else len(matches) == 1
    return matches[0]


def omitted_held_root(directory):
    values = e.rows(directory / 'events.jsonl')
    descriptor = next(row for row in values if row['event'] == 's3_request' and row['method'] == 'PUT'
                      and row['path'].endswith('/snapshot/v1/descriptor/11/880001'))
    point = m.wire.parse(e.raw(directory, descriptor['request']))['point']
    path = m.prefix(e.SCOPE, 2) + point['data_root']
    forwarded = next(row for row in values if row['event'] == 'http_proxy_forward_started'
                     and row['role'] == 'C-9503' and row['operation'] == 'owner_resume')
    complete = e.one(values, 'http_proxy_backend_response', role='C-9503', serial=forwarded['serial'])
    removed = {(row['role'], row['serial']) for row in values if row['event'] == 's3_request' and row['method'] == 'GET'
               and row['path'] == path and e.moment(forwarded) < e.moment(row) < e.moment(complete)}
    assert removed
    values = [row for row in values if row['event'] not in S3_STAGES or (row['role'], row['serial']) not in removed]
    # Model a defective verifier genuinely skipping a held Manifest. Keep the
    # complete remaining exchange denominator closed so omission is detected
    # by the full cold closure guard, not by a broken evidence counter.
    for role in ('seed', 'A', 'C'):
        serials = sorted({row['serial'] for row in values if row['event'] == 's3_request' and row['role'] == role})
        mapping = dict(zip(serials, range(1, len(serials) + 1)))
        for row in values:
            if row.get('role') != role:
                continue
            if row['event'] in S3_STAGES:
                row['serial'] = mapping[row['serial']]
            elif row['event'] == 's3_proxy_stopped':
                row['request_count'] = len(serials)
    save_rows(directory / 'events.jsonl', values)


def replaced_copy_basis(directory):
    values = e.rows(directory / 'events.jsonl')
    for row in values:
        if row['event'] != 's3_request' or row['method'] != 'PUT' or row['path'] != oracle.HEAD_PATH:
            continue
        value = m.wire.parse(e.raw(directory, row['request']))
        plan = value['storage']['plan']
        if plan is not None and plan['phase'] == 'copying':
            assert len(plan['basis']['snapshots']) == 2
            plan['basis']['snapshots'] = plan['basis']['snapshots'][1:]
            replace_blob(directory, row['request'], m.encoded(value))
            return
    raise AssertionError('missing original copy plan')


def changed_snapshot_response(directory, scope=False):
    values = e.rows(directory / 'events.jsonl')
    captured = [row for row in values if row['event'] == 'http_proxy_backend_response'
                and row['operation'] == 'snapshot_capture']
    assert len(captured) == 2
    row = captured[0]
    group = [event for event in values if event.get('role') == row['role']
             and event.get('serial') == row['serial'] and event['event'].startswith('http_proxy_')]
    # This is the original capture whose HTTP ACK was suppressed. Its bytes
    # also occur in a later, independently delivered inspect response. Give
    # only this exchange a new reference; changing every content alias would
    # corrupt that later SDK/HTTP pair before the intended snapshot guard.
    assert sum(event['event'] == 'http_proxy_delivery_suppressed' for event in group) == 1
    assert not any(event['event'] in ('http_proxy_delivery_started', 'http_proxy_delivery_finished') for event in group)
    value = m.wire.parse(e.raw(directory, row['response']))
    if scope:
        value['value']['prepared']['scope']['incarnation'] = '2'
    else:
        old = value['value']['prepared']['reference']['descriptor_hash']
        value['value']['prepared']['reference']['descriptor_hash'] = ('0' if old[0] != '0' else '1') + old[1:]
    row['response'] = put_raw(directory, m.encoded(value))
    if 'content-length' in row.get('headers', {}):
        row['headers']['content-length'] = str(row['response']['bytes'])
    save_rows(directory / 'events.jsonl', values)


def proof_after_removal(directory):
    values = e.rows(directory / 'events.jsonl')
    path = oracle.BASE + 'snapshot/v1/proof/11/880001'
    proof_put = next(row for row in values if row['event'] == 's3_request' and row['method'] == 'PUT' and row['path'] == path)
    removed = next(row for row in values if row['event'] == 's3_request' and row['method'] == 'PUT'
                   and row['path'] == oracle.HEAD_PATH and e.moment(row) > e.moment(proof_put)
                   and len(m.wire.parse(e.raw(directory, row['request'])).get('snapshots', [])) == 1)
    removed_complete = e.one(values, 's3_backend_response', role=removed['role'], serial=removed['serial'])
    reply = product(directory, 'snapshot_release')
    identifiers = {(row['role'], row['serial']) for row in values if row['event'] == 's3_request' and row['path'] == path
                   and e.moment(proof_put) <= e.moment(row) < e.moment(removed)}
    moved = [row for row in values if row['event'] in S3_STAGES and (row['role'], row['serial']) in identifiers]
    assert moved and any(row['event'] == 's3_request' and row['method'] == 'GET' for row in moved)
    start, end = e.moment(removed_complete), e.moment(reply)
    assert end - start > len(moved) + 1
    for index, row in enumerate(sorted(moved, key=e.moment), 1):
        row['monotonic_ns'] = start + (end - start) * index // (len(moved) + 1)
    save_rows(directory / 'events.jsonl', values, reorder=True)


def unknown_relabelled(directory):
    observed = product(directory, 'snapshot_capture')
    value = m.wire.parse(e.raw(directory, observed['response']))['value']
    result = {'id': 'capture-original-ack', 'ok': True, 'value': value}
    for path in sorted(directory.glob('sdk-*.jsonl')):
        values = e.rows(path)
        changed = False
        for row in values:
            if row['event'] == 'command_finished' and row['command'] == 'capture-original-ack':
                assert row['result']['ok'] is False
                row['result'] = result; changed = True
        if changed:
            save_rows(path, values)
    def change(values):
        for row in values:
            if row['event'] == 'child_output' and row['id'].startswith('sdk-'):
                old = m.wire.parse(e.raw(directory, row['raw']))
                if old.get('id') == 'capture-original-ack':
                    row['raw'] = put_raw(directory, encoded(result))
    events(directory, change)


def missing_http_exchange(directory):
    def change(values):
        request = next(row for row in values if row['event'] == 'http_proxy_request' and row['operation'] == 'snapshot_list')
        values[:] = [row for row in values if not (row['event'].startswith('http_proxy_')
            and row.get('role') == request['role'] and row.get('serial') == request['serial'])]
    events(directory, change)


def missing_s3_exchange(directory):
    def change(values):
        request = next(row for row in values if row['event'] == 's3_request' and row['method'] == 'GET' and '/objects/' in row['path'])
        values[:] = [row for row in values if not (row['event'] in S3_STAGES
            and row['role'] == request['role'] and row['serial'] == request['serial'])]
    events(directory, change)


def changed_original_result(directory):
    def change(values):
        original = e.one(values, 'original_ack', name='original-3')
        raw = bytearray(e.raw(directory, original['result']))
        raw[-25] ^= 1
        original['result'] = put_raw(directory, bytes(raw))
    events(directory, change)


def deleted_permanent_metadata(directory):
    def change(values):
        request = next(row for row in values if row['event'] == 's3_request' and row['method'] == 'DELETE'
                       and '/storage/2/objects/' in row['path'])
        for row in values:
            if row['event'] in S3_STAGES and row['role'] == request['role'] and row['serial'] == request['serial']:
                row['path'] = oracle.BASE + 'snapshot/v1/descriptor/11/880001'
    events(directory, change)


CASES = (
    ('omit-held-root-from-cold-recovery', 'cold-complete-held-recovery', omitted_held_root),
    ('replace-copy-held-basis', 'copy-frozen-held-basis', replaced_copy_basis),
    ('change-original-snapshot-reference', 'original-snapshot-observation-reference', changed_snapshot_response),
    ('change-original-snapshot-scope', 'snapshot-observation-full-scope', lambda path: changed_snapshot_response(path, scope=True)),
    ('remove-before-permanent-proof', 'release-proof-before-remove', proof_after_removal),
    ('relabel-original-unknown-as-ack', 'original-unknown-not-overwritten', unknown_relabelled),
    ('omit-original-http-exchange', 'http-proxy-closed-denominator', missing_http_exchange),
    ('omit-original-s3-exchange', 's3-closed-denominator', missing_s3_exchange),
    ('change-original-result-bytes', 'original-result-bytes', changed_original_result),
    ('delete-permanent-snapshot-metadata', 'permanent-control-metadata-not-deleted', deleted_permanent_metadata),
)


def inventory(directory):
    return {path.relative_to(directory).as_posix(): {'bytes': path.stat().st_size, 'sha256': m.sha(path.read_bytes())}
            for path in sorted(directory.rglob('*')) if path.is_file()}


def run(evidence, destination):
    original_inventory = inventory(evidence)
    positive = oracle.audit(evidence)
    destination.mkdir(parents=True, exist_ok=False)
    results = []
    for name, expected, mutation in CASES:
        target = destination / name
        shutil.copytree(evidence, target, copy_function=os.link)
        mutation(target)
        result = {'name': name, 'expected_guard': expected, 'observed_guard': None, 'status': 'FAILED'}
        try:
            oracle.audit(target)
        except m.Rejected as error:
            result['observed_guard'] = error.rule
            if error.rule == expected:
                result['status'] = 'REJECTED'
        except Exception as error:
            result['error'] = repr(error)
        replace(target / 'control.json', encoded(result))
        results.append(result)
    unchanged = inventory(evidence) == original_inventory
    value = {'schema': 1, 'status': 'PASSED' if unchanged and all(row['status'] == 'REJECTED' for row in results) else 'FAILED',
             'positive_profile': positive['profile'], 'positive_originals_unchanged': unchanged,
             'positive_inventory_sha256': m.sha(encoded(original_inventory)), 'controls': results}
    replace(destination / 'positive-inventory.json', encoded(original_inventory))
    replace(destination / 'manifest.json', encoded(value))
    return value


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    arguments = parser.parse_args()
    result = run(arguments.evidence.resolve(), arguments.out.resolve())
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result['status'] == 'PASSED' else 1)
