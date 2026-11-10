#!/usr/bin/env python3
"""Persist whole counterfactual histories; require each named semantic rejection."""
from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import shutil

import oracle
from audit_model import Rejected, sha, wire
from audit_evidence import moment, raw, rows


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def replace_file(path, value):
    # Every fixture copy initially hardlinks original files. Break the link first.
    path.unlink(missing_ok=True)
    with path.open('xb') as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())


def save_rows(path, values, reorder=False):
    if reorder:
        values.sort(key=moment)
    for index, value in enumerate(values):
        value['sequence'] = index + 1
    replace_file(path, b''.join(encoded(value) for value in values))


def put_raw(directory, value):
    digest = sha(value)
    path = directory / 'raw' / digest
    if path.exists():
        assert path.read_bytes() == value
    else:
        with path.open('xb') as stream:
            stream.write(value)
    return {'file': 'raw/' + digest, 'bytes': len(value), 'sha256': digest}


def walk_replace(value, old, new):
    if isinstance(value, dict):
        if value == old:
            return copy.deepcopy(new)
        return {key: walk_replace(item, old, new) for key, item in value.items()}
    if isinstance(value, list):
        return [walk_replace(item, old, new) for item in value]
    return value


def change_authority(directory, predicate, mutation):
    history = rows(directory / 'events.jsonl')
    selected = []
    for row in history:
        if row['event'] != 's3_request' or row['method'] != 'PUT' or not row['path'].endswith('/head'):
            continue
        value = wire.parse(raw(directory, row['request']))
        if predicate(value):
            selected.append((row, value))
    assert selected
    request, value = selected[0]
    old = request['request']
    mutation(value)
    new = put_raw(directory, json.dumps(value, separators=(',', ':')).encode())
    for path in [directory / 'events.jsonl', *sorted(directory.glob('sdk-*.jsonl'))]:
        changed = []
        for row in rows(path):
            original_payload = row.get('request') == old and row['event'] == 's3_request'
            updated = walk_replace(row, old, new)
            if original_payload:
                updated['headers']['content-length'] = str(new['bytes'])
                updated['headers']['x-amz-content-sha256'] = new['sha256']
            changed.append(updated)
        save_rows(path, changed)


def first_terminal(value):
    return value['format'] == 7 and value['scope']['database'] == 6101 and value['storage']['sweep'] is None


def first_checkpoint(value):
    return value['format'] == 7 and value['scope']['database'] == 6101 and value['storage']['sweep'] is not None


def change_s3_group(directory, choose, mutation):
    history = rows(directory / 'events.jsonl')
    request = next(row for row in history if row['event'] == 's3_request' and choose(row))
    group = [row for row in history if row.get('role') == request['role'] and row.get('serial') == request['serial']
             and row['event'].startswith('s3_')]
    mutation(request, group, history)
    save_rows(directory / 'events.jsonl', history)


def update_command_result(directory, role, command, mutation, http=None):
    ledger = rows(directory / f'sdk-{role}.jsonl')
    done = next(row for row in ledger if row['event'] == 'command_finished' and row['command'] == command)
    mutation(done['result'])
    if http is not None:
        response = next(row for row in ledger if row['event'] == 'http_response' and row['command'] == command)
        body = wire.parse(raw(directory, response['response']))
        response['status'], body = http(response['status'], body)
        response['response'] = put_raw(directory, json.dumps(body, separators=(',', ':')).encode())
    save_rows(directory / f'sdk-{role}.jsonl', ledger)
    history = rows(directory / 'events.jsonl')
    outputs = [row for row in history if row['event'] == 'child_output' and row['id'] == 'sdk-' + role
               and wire.parse(raw(directory, row['raw'])).get('id') == command]
    assert len(outputs) == 1
    outputs[0]['raw'] = put_raw(directory, json.dumps(done['result'], separators=(',', ':')).encode() + b'\n')
    save_rows(directory / 'events.jsonl', history)


def omit_exchange(directory, selector, preserve_denominator=False):
    history = rows(directory / 'events.jsonl')
    selected = next(row for row in history if row['event'] == 's3_request' and selector(row, history))
    role, serial = selected['role'], selected['serial']
    history = [row for row in history if not (row.get('role') == role and row.get('serial') == serial and row['event'].startswith('s3_'))]
    if preserve_denominator:
        for row in history:
            if row.get('role') == role and 'serial' in row and row['serial'] > serial:
                row['serial'] -= 1
            if row['event'] == 's3_proxy_stopped' and row['role'] == role:
                row['request_count'] -= 1
    save_rows(directory / 'events.jsonl', history)


def missing_control(directory):
    ledger = rows(directory / 'sdk-C.jsonl')
    call = next(row for row in ledger if row['event'] == 'http_request' and row['command'] == 'before-seal')
    done = next(row for row in ledger if row['event'] == 'command_finished' and row['command'] == 'before-seal')
    omit_exchange(directory, lambda row, _history: row['role'] == 'C' and row['method'] == 'GET'
                  and '/catalogue/v1/control/11/delete/' in row['path'] and moment(call) < moment(row) < moment(done), True)


def unstable_success(directory):
    ledger = rows(directory / 'sdk-R.jsonl')
    start = next(row for row in ledger if row['event'] == 'http_request' and row['command'] == 'before-unstable-observation')
    history = rows(directory / 'events.jsonl')
    response = next(row for row in history if row['event'] == 's3_backend_response' and row['role'] == 'R'
                    and row['path'].endswith('/head') and row['status'] == 200 and moment(row) > moment(start))
    status = oracle.projection(wire.parse(raw(directory, response['response'])))
    update_command_result(directory, 'R', 'before-unstable-observation',
        lambda result: (result.clear(), result.update(id='before-unstable-observation', ok=True, value=status)),
        lambda _status, body: (200, {**{key: value for key, value in body.items() if key not in ('error', 'value')}, 'ok': True, 'value': status}))


def old_read_too_early(directory):
    history = rows(directory / 'events.jsonl')
    arrival = next(row for row in history if row['event'] == 'fault_arrived' and row['id'] == 'late-original-read')
    selected = [row for row in history if row.get('role') == arrival['role'] and row.get('serial') == arrival['serial']
                and row['event'] in ('s3_forward_started', 's3_backend_response', 's3_delivery_started', 's3_delivery_finished', 's3_handler_finished')
                or row.get('id') == 'late-original-read' and row['event'] in ('fault_release_requested', 'fault_forward_resumed')]
    selected.sort(key=moment)
    for offset, row in enumerate(selected):
        row['monotonic_ns'] = moment(arrival) + 1000 + offset * 1000
    save_rows(directory / 'events.jsonl', history, True)


def replay_http(directory):
    ledger = rows(directory / 'sdk-A.jsonl')
    original = next(row for row in ledger if row['event'] == 'http_request' and row['command'] == 'execute-late-1')
    duplicate = copy.deepcopy(original)
    duplicate['ordinal'] = 2
    duplicate['monotonic_ns'] = str(moment(original) + 1)
    ledger.insert(ledger.index(original) + 1, duplicate)
    next(row for row in ledger if row['event'] == 'command_finished' and row['command'] == 'execute-late-1')['attempts'] = 2
    save_rows(directory / 'sdk-A.jsonl', ledger)


def stale_expired(directory):
    ledger = rows(directory / 'sdk-R.jsonl')
    status = next(row['status'] for row in ledger if row['event'] == 'http_response' and row['command'] == 'late-old-lookup')
    update_command_result(directory, 'R', 'stale-old-lookup',
        lambda result: result['error'].update(code='SNAPSHOT_EXPIRED'),
        lambda _status, body: (status, {**body, 'error': {**body['error'], 'code': 'SNAPSHOT_EXPIRED'}}))


def original_ack_removed(directory):
    history = rows(directory / 'events.jsonl')
    removed = next(row for row in history if row['event'] == 'original_ack')
    history.remove(removed)
    save_rows(directory / 'events.jsonl', history)


def original_bytes_removed(directory):
    path = directory / 'original-results.json'
    value = wire.parse(path.read_bytes())
    value.pop('late-1')
    replace_file(path, encoded(value))


def false_wait4(directory):
    history = rows(directory / 'events.jsonl')
    next(row for row in history if row['event'] == 'child_stopped' and row['id'].startswith('service-'))['usage']['source'] = 'guessed_pid'
    save_rows(directory / 'events.jsonl', history)


def bad_proof(directory):
    history = rows(directory / 'events.jsonl')
    request = next(row for row in history if row['event'] == 's3_request' and row['method'] == 'PUT'
                   and '/abort-proof/' in row['path'] and wire.parse(raw(directory, row['request']))['barrier']['kind'] == 'own_deleted')
    old = request['request']
    value = wire.parse(raw(directory, old))
    value['barrier']['transition']['nonce'] += 1
    new = put_raw(directory, json.dumps(value, separators=(',', ':')).encode())
    for row in history:
        original = row.get('request') == old and row['event'] == 's3_request'
        changed = walk_replace(row, old, new)
        row.clear(); row.update(changed)
        if original:
            row['headers']['content-length'] = str(new['bytes'])
            row['headers']['x-amz-content-sha256'] = new['sha256']
    save_rows(directory / 'events.jsonl', history)


def bucket_as_key(directory):
    history = rows(directory / 'events.jsonl')
    selected = next(row for row in history if row['event'] == 's3_delivery_started' and row['origin'] == 'fixture_no_such_bucket')
    selected['response'] = put_raw(directory, raw(directory, selected['response']).replace(b'NoSuchBucket', b'NoSuchKey'))
    save_rows(directory / 'events.jsonl', history)


def lost_known_receipt(directory):
    def change(result):
        result.clear()
        result.update(id='receipt-delayed-sql', ok=False, error={'name': 'RemoteError', 'code': 'MISSING', 'reference': None, 'receipt': None})
    ledger = rows(directory / 'sdk-R.jsonl')
    missing = next(row for row in ledger if row['event'] == 'http_response' and row['command'] == 'stale-old-lookup')
    body = wire.parse(raw(directory, missing['response']))
    update_command_result(directory, 'A', 'receipt-delayed-sql', change, lambda _status, _body: (missing['status'], body))


def cases():
    return [
        ('missing_original_ack', 'original-ack-denominator', original_ack_removed),
        ('missing_complete_original_bytes', 'full-original-result-ledger', original_bytes_removed),
        ('whole_s3_exchange_missing', 's3-closed-denominator',
         lambda d: omit_exchange(d, lambda row, history: row['role'] == 'O' and row['method'] == 'GET')),
        ('s3_stage_path_changed', 's3-original-method-path', lambda d: change_s3_group(d,
            lambda row: row['method'] == 'DELETE', lambda request, group, history:
                next(row for row in group if row['event'] == 's3_backend_response').update(path=request['path'] + '-different'))),
        ('signed_payload_hash_changed', 'signed-public-payload', lambda d: change_s3_group(d,
            lambda row: row['method'] == 'PUT', lambda request, group, history:
                request['headers'].update({'x-amz-content-sha256': 'f' * 64}))),
        ('seal_changes_business_barrier', 'seal-business-preservation', lambda d: change_authority(d, first_terminal,
            lambda value: value['transition'].update(nonce=value['transition']['nonce'] + 1))),
        ('seal_without_deleted', 'terminal-deleted-inactive', lambda d: change_authority(d, first_terminal,
            lambda value: value.update(lifecycle='ready'))),
        ('terminal_not_after_business_revision', 'terminal-after-business-revision', lambda d: change_authority(d, first_terminal,
            lambda value: value['storage']['terminal'].update(serial=value['revision']))),
        ('seal_allocates_another_generation', 'one-way-terminal-seal', lambda d: change_authority(d, first_terminal,
            lambda value: value['storage'].update(allocated_through=value['storage']['allocated_through'] + 1))),
        ('terminal_serial_rewritten', 'terminal-allocation-frozen', lambda d: change_authority(d, first_checkpoint,
            lambda value: value['storage']['terminal'].update(serial=value['storage']['terminal']['serial'] - 1))),
        ('checkpoint_not_after_terminal', 'checkpoint-after-terminal', lambda d: change_authority(d, first_checkpoint,
            lambda value: value['storage']['sweep'].update(serial=value['storage']['terminal']['serial']))),
        ('delete_permanent_head', 'permanent-metadata-never-deleted', lambda d: change_s3_group(d,
            lambda row: row['method'] == 'DELETE', lambda request, group, history:
                [row.update(path='/scap-test/scap-object/v1/1/7/6101/head') for row in group])),
        ('delete_unallocated_generation', 'delete-terminal-retirement-proof', lambda d: change_s3_group(d,
            lambda row: row['method'] == 'DELETE', lambda request, group, history:
                [row.update(path=row['path'].replace('/storage/1/', '/storage/99/')) for row in group])),
        ('delete_refreshes_original_etag', 'delete-immutable-original-etag', lambda d: change_s3_group(d,
            lambda row: row['method'] == 'DELETE', lambda request, group, history:
                request['headers'].update({'if-match': '"refreshed-etag"'}))),
        ('missing_original_control_read', 'named-source-read-exact-record', missing_control),
        ('unstable_name_view_accepted', 'stable-name-double-exact-read', unstable_success),
        ('proof_business_barrier_changed', 'own-proof-business-barrier', bad_proof),
        ('sql_http_replayed', 'one-original-http-post', replay_http),
        ('unknown_original_reference_lost', 'original-unknown-reference', lambda d: update_command_result(d, 'C',
            'late-seal-unknown', lambda result: result['error'].update(reference=None))),
        ('unknown_rewritten_after_observation', 'original-unknown-not-overwritten', lambda d: update_command_result(d, 'C',
            'late-seal-unknown', lambda result: (result.clear(), result.update(id='late-seal-unknown', ok=True, value={'observed': True})))),
        ('stale_barrier_claimed_expired', 'old-read-precise-source-result', stale_expired),
        ('old_read_forwarded_before_delete', 'delete-before-original-read-forward', old_read_too_early),
        ('bucket_error_called_key_absence', 'bucket-is-not-key-absence', bucket_as_key),
        ('known_commit_downgraded', 'original-native-ack', lost_known_receipt),
        ('owned_wait4_forged', 'owned-wait4', false_wait4),
    ]


def inventory(directory):
    return {path.relative_to(directory).as_posix(): sha(path.read_bytes())
            for path in sorted(directory.rglob('*')) if path.is_file()}


def run(source, output):
    source, output = source.resolve(), output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {'schema': 1, 'status': 'FAILED', 'source': str(source), 'negative_controls': [],
              'negative_count': 0, 'positive_count': 0, 'error': None}
    before = inventory(source)
    try:
        report['original_audit'] = oracle.audit(source)
        positive = output / 'positive'
        shutil.copytree(source, positive, copy_function=os.link)
        report['positive_audit'] = oracle.audit(positive)
        report['positive_count'] = 1
        for name, boundary, mutate in cases():
            destination = output / name
            shutil.copytree(source, destination, copy_function=os.link)
            mutate(destination)
            try:
                oracle.audit(destination)
            except Rejected as error:
                if error.rule != boundary:
                    raise AssertionError(f'{name}: expected {boundary}, reached {error.rule}') from error
                report['negative_controls'].append({'case': name, 'rejected_by': error.rule})
            else:
                raise AssertionError(name + ': counterfactual accepted')
        report['negative_count'] = len(report['negative_controls'])
        report['original_unchanged'] = inventory(source) == before
        assert report['original_unchanged'] and report['negative_count'] == 25
        report['status'] = 'PASSED'
    except BaseException as error:
        report['error'] = repr(error)
    finally:
        report['source_inventory'] = before
        replace_file(output / 'controls.json', encoded(report))
    print(json.dumps({key: report[key] for key in ('status', 'negative_count', 'positive_count', 'error')}, sort_keys=True))
    return 0 if report['status'] == 'PASSED' else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('source', type=Path)
    parser.add_argument('output', type=Path)
    arguments = parser.parse_args()
    raise SystemExit(run(arguments.source, arguments.output))
