#!/usr/bin/env python3
"""Whole-history negative copies, each required to fail its semantic boundary."""
from __future__ import annotations

import argparse
import base64
import copy
import json
import os
from pathlib import Path
import shutil
import struct

import oracle
from audit_model import Rejected, head_path, sha, wire


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def replace_file(path, value):
    # Copies can share immutable inode data. A mutation must first break its link.
    if path.exists():
        path.unlink()
    path.write_bytes(value)


class Copy:
    def __init__(self, root):
        self.root = root
        self.events = oracle.rows(root / 'events.jsonl')
        self.sdk = {role: oracle.rows(root / ('sdk-' + role + '.jsonl')) for role in ('A', 'B', 'R')}

    def bytes(self, description):
        return oracle.raw(self.root, description)

    def artifact(self, value):
        name = sha(value)
        path = self.root / 'raw' / name
        if not path.exists():
            path.write_bytes(value)
        else:
            assert path.read_bytes() == value
        return {'file': 'raw/' + name, 'sha256': name, 'bytes': len(value)}

    def body(self, row, name):
        return wire.parse(self.bytes(row[name]))

    def replace_raw_everywhere(self, old, value):
        new = self.artifact(value)

        def replace(item):
            if isinstance(item, dict):
                if item == old:
                    return new.copy()
                changed = {key: replace(child) for key, child in item.items()}
                if item.get('request') == old and 'headers' in changed and 'content-length' in changed['headers']:
                    changed['headers']['content-length'] = str(len(value))
                if item.get('request') == old and 'headers' in changed and 'x-amz-content-sha256' in changed['headers']:
                    if changed['headers']['x-amz-content-sha256'] != 'UNSIGNED-PAYLOAD':
                        changed['headers']['x-amz-content-sha256'] = sha(value)
                if item.get('response') == old and 'headers' in changed and 'content-length' in changed['headers']:
                    changed['headers']['content-length'] = str(len(value))
                return changed
            if isinstance(item, list):
                return [replace(child) for child in item]
            return item

        self.events = replace(self.events)
        self.sdk = replace(self.sdk)

    def fault(self, identifier):
        row = oracle.one(self.events, 'fault_arrived', id=identifier)
        return row['role'], row['serial']

    def exchange(self, identifier):
        role, serial = self.fault(identifier)
        return [row for row in self.events if row.get('role') == role and row.get('serial') == serial
                and row['event'].startswith('s3_')]

    def call(self, identifier):
        for role, rows in self.sdk.items():
            selected = [row for row in rows if row.get('command') == identifier]
            if selected:
                return role, selected
        raise AssertionError('original call missing')

    def input(self, identifier, field, value):
        role, rows = self.call(identifier)
        start = oracle.one(rows, 'command_started', command=identifier)
        command = self.body(start, 'input')
        command['input'][field] = value
        original = start['input']
        replacement = self.artifact(encoded(command))
        start['input'] = replacement
        for row in self.events:
            if row['event'] == 'child_input' and row['id'] == 'sdk-' + role and row['raw'] == original:
                row['raw'] = replacement
        request = oracle.one(rows, 'http_request', command=identifier)
        body = self.body(request, 'request')
        mapping = {'batchSerial': 'batch_serial', 'after': 'after'}
        body[mapping[field]] = value
        request['request'] = self.artifact(encoded(body))
        done = oracle.one(rows, 'command_finished', command=identifier)
        if not done['result']['ok'] and isinstance(done['result']['error']['reference'], dict):
            reference = done['result']['error']['reference']
            if field in reference:
                reference[field] = value
                for row in self.events:
                    if row['event'] == 'child_output' and row['id'] == 'sdk-' + role:
                        output = self.body(row, 'raw')
                        if output.get('id') == identifier:
                            output['error']['reference'][field] = value
                            row['raw'] = self.artifact(encoded(output))

    def response(self, identifier, transform):
        role, rows = self.call(identifier)
        response = oracle.one(rows, 'http_response', command=identifier)
        body = self.body(response, 'response')
        transform(body['value'])
        response['response'] = self.artifact(encoded(body))
        done = oracle.one(rows, 'command_finished', command=identifier)
        done['result']['value'] = body['value']
        for row in self.events:
            if row['event'] == 'child_output' and row['id'] == 'sdk-' + role:
                value = self.body(row, 'raw')
                if value.get('id') == identifier:
                    value['value'] = body['value']
                    row['raw'] = self.artifact(encoded(value))

    def move_forward(self, identifier, before):
        role, serial = self.fault(identifier)
        rows = [row for row in self.events if
                (row.get('role') == role and row.get('serial') == serial and row['event'] in
                 ('s3_forward_started', 's3_backend_response', 's3_delivery_started', 's3_delivery_finished', 's3_handler_finished'))
                or (row.get('id') == identifier and row['event'] in ('fault_release_requested', 'fault_forward_resumed'))]
        rows.sort(key=oracle.moment)
        base = oracle.moment(before) - len(rows) - 2
        for offset, row in enumerate(rows):
            row['monotonic_ns'] = base + offset

    def save(self):
        self.events.sort(key=oracle.moment)
        for sequence, row in enumerate(self.events, 1):
            row['sequence'] = sequence
        replace_file(self.root / 'events.jsonl', b''.join(encoded(row) for row in self.events))
        for role, rows in self.sdk.items():
            rows.sort(key=oracle.moment)
            for sequence, row in enumerate(rows, 1):
                row['sequence'] = sequence
            replace_file(self.root / ('sdk-' + role + '.jsonl'), b''.join(encoded(row) for row in rows))


def mutate(value, case):
    if case == 'missing_original_ack':
        row = oracle.one(value.events, 'seed_ack', name='main-001')
        value.events.remove(row)
    elif case in ('closed_window_result_not_received', 'target_not_read_back'):
        ack = oracle.one(value.events, 'seed_ack', name='main-001')
        suffix = '/storage/' + ('1' if case == 'closed_window_result_not_received' else '2') + '/objects/' + ack['receipt']['result_hash']
        selected = [row for row in value.events if row['event'] == 's3_request' and row['role'] == 'B'
                    and row['method'] == 'GET' and row['path'].endswith(suffix)
                    and row['phase'] == 'main-full-retained-copy']
        assert selected
        for request in selected:
            delivery = oracle.one(value.events, 's3_delivery_finished', role='B', serial=request['serial'])
            delivery.update(complete=False, failure='ConnectionResetError')
    elif case == 'same_key_changed_target_bytes':
        request = next(row for row in value.events if row['event'] == 's3_request' and row['method'] == 'PUT'
                       and row['role'] == 'B' and '/4101/' in row['path'] and '/storage/2/objects/' in row['path'])
        original = value.bytes(request['request'])
        changed = original[:-1] + bytes([original[-1] ^ 1])
        request['request'] = value.artifact(changed)
        if request['headers']['x-amz-content-sha256'] != 'UNSIGNED-PAYLOAD':
            request['headers']['x-amz-content-sha256'] = sha(changed)
    elif case == 'whole_s3_exchange_missing':
        selected = next(row for row in value.events if row['event'] == 's3_request' and row['role'] == 'B'
                        and row['method'] == 'GET' and '/objects/' in row['path']
                        and row['phase'] == 'main-full-retained-copy')
        value.events = [row for row in value.events if not
                        (row.get('role') == 'B' and row.get('serial') == selected['serial'])]
    elif case == 'unsealed_publication':
        for row in value.events:
            if row['event'] == 's3_request' and row['method'] == 'PUT' and head_path(row['path']) == 4101:
                head = value.body(row, 'request')
                if head['storage']['plan'] is not None and head['storage']['plan']['phase'] == 'sealed':
                    head['storage']['plan']['phase'] = 'copying'
                    value.replace_raw_everywhere(row['request'], encoded(head))
                    break
        else:
            raise AssertionError('sealed publication missing')
    elif case == 'historical_receipt_root_copied':
        ack = oracle.one(value.events, 'seed_ack', name='main-001')
        old_hash = ack['receipt']['data_root']
        source_path = f'/scap-test/scap-object/v1/1/7/4101/inc/1/gen/1/storage/1/objects/{old_hash}'
        source = next(row for row in value.events if row['event'] == 's3_request'
                      and row['method'] == 'PUT' and row['path'] == source_path)
        template = next(row for row in value.events if row['event'] == 's3_request' and row['method'] == 'PUT'
                        and row['role'] == 'B' and '/4101/' in row['path'] and '/storage/2/objects/' in row['path'])
        group = [copy.deepcopy(row) for row in value.events if row.get('role') == 'B'
                 and row.get('serial') == template['serial'] and row['event'].startswith('s3_')]
        seal = next(row for row in value.events if row['event'] == 's3_request' and row['method'] == 'PUT'
                    and head_path(row['path']) == 4101 and value.body(row, 'request')['storage']['plan'] is not None
                    and value.body(row, 'request')['storage']['plan']['phase'] == 'sealed')
        serial = seal['serial']
        seal_start = oracle.one(value.events, 's3_handler_started', role='B', serial=serial)
        start = oracle.moment(seal_start) - len(group) - 2
        for row in value.events:
            if row.get('role') == 'B' and isinstance(row.get('serial'), int) and row['serial'] >= serial:
                row['serial'] += 1
        oracle.one(value.events, 's3_proxy_stopped', role='B')['request_count'] += 1
        for offset, row in enumerate(sorted(group, key=oracle.moment)):
            row.update(serial=serial, path=source_path.replace('/storage/1/', '/storage/2/'), monotonic_ns=start + offset)
            if row['event'] == 's3_request':
                row['request'] = source['request'].copy()
                row['headers']['content-length'] = str(source['request']['bytes'])
                if row['headers']['x-amz-content-sha256'] != 'UNSIGNED-PAYLOAD':
                    row['headers']['x-amz-content-sha256'] = source['request']['sha256']
            if row['event'] == 's3_backend_response':
                row['headers']['etag'] = '"control-historical-root"'
            value.events.append(row)
    elif case == 'delete_active_generation':
        for row in value.exchange('accepted-delete-response-loss'):
            row['path'] = row['path'].replace('/storage/2/', '/storage/1/')
    elif case == 'delete_without_original_batch':
        role, rows = value.call('aborted-delete-unknown')
        request = value.body(oracle.one(rows, 'http_request', command='aborted-delete-unknown'), 'request')
        value.input('aborted-delete-unknown', 'batchSerial', str(int(request['batch_serial']) + 100000))
    elif case == 'refreshed_delete_etag':
        changed = oracle.one(value.events, 'same_bytes_new_backend_etag')
        role, rows = value.call('aborted-old-batch-resume')
        begin = oracle.moment(oracle.one(rows, 'http_request', command='aborted-old-batch-resume'))
        end = oracle.moment(oracle.one(rows, 'http_response', command='aborted-old-batch-resume'))
        request = next(row for row in value.events if row['event'] == 's3_request' and row['method'] == 'DELETE'
                       and row['path'] == changed['key'] and begin < oracle.moment(row) < end)
        request['headers']['if-match'] = changed['new_etag']
    elif case == 'unknown_relabelled_applied':
        for row in value.events:
            if row['event'] == 's3_request' and row['method'] == 'PUT' and head_path(row['path']) == 4103:
                head = value.body(row, 'request')
                sweep = head['storage']['sweep']
                if sweep is not None and any(e['disposition'] == 'condition_mismatch' for e in sweep['entries']):
                    for entry in sweep['entries']:
                        if entry['disposition'] == 'condition_mismatch':
                            entry['disposition'] = 'applied'
                    value.replace_raw_everywhere(row['request'], encoded(head))
                    break
        else:
            raise AssertionError('actual mismatch disposition missing')
    elif case == 'bucket_error_cleared_checkpoint':
        value.response('aborted-after-bucket-unknown', lambda body: body['storage'].update(sweep=None))
    elif case == 'late_put_not_accepted':
        for row in value.exchange('late-source-put'):
            if row['event'] in ('s3_backend_response', 's3_delivery_started'):
                row['status'] = 412
    elif case == 'new_round_reused_frontier':
        value.input('main-late-round-from-start-0-prepare', 'after', '0' * 64)
    elif case == 'old_cas_falsely_accepted':
        for row in value.exchange('old-head-cas'):
            if row['event'] in ('s3_backend_response', 's3_delivery_started'):
                row['status'] = 200
                if 'headers' in row:
                    row['headers']['etag'] = '"forged-acceptance"'
    elif case == 'old_get_released_before_delete':
        role, serial = value.fault('old-source-get')
        path = oracle.one(value.events, 's3_request', role=role, serial=serial)['path']
        deletion = next(row for row in value.events if row['event'] == 's3_request'
                        and row['method'] == 'DELETE' and row['path'] == path)
        value.move_forward('old-source-get', deletion)
    elif case == 'late_delete_before_next_promotion':
        promote = []
        for row in value.events:
            if row['event'] == 's3_request' and row['method'] == 'PUT' and head_path(row['path']) == 4102:
                candidate = value.body(row, 'request')
                if candidate['storage']['active_generation'] == 3:
                    promote.append(row)
        assert promote
        value.move_forward('late-original-delete', promote[0])
    elif case == 'sql_http_retry':
        role, rows = value.call('main-late-put-execute')
        request = oracle.one(rows, 'http_request', command='main-late-put-execute')
        extra = copy.deepcopy(request)
        extra['ordinal'] = 2
        extra['monotonic_ns'] = str(oracle.moment(request) + 1)
        value.sdk[role].append(extra)
        oracle.one(rows, 'command_finished', command='main-late-put-execute')['attempts'] = 2
    elif case == 'unknown_reference_lost':
        role, rows = value.call('aborted-delete-unknown')
        oracle.one(rows, 'command_finished', command='aborted-delete-unknown')['result']['error']['reference'] = None
        for row in value.events:
            if row['event'] == 'child_output' and row['id'] == 'sdk-' + role:
                output = value.body(row, 'raw')
                if output.get('id') == 'aborted-delete-unknown':
                    output['error']['reference'] = None
                    row['raw'] = value.artifact(encoded(output))
    elif case == 'forged_child_wait4':
        stopped = next(row for row in value.events if row['event'] == 'child_stopped' and row['id'].startswith('service-'))
        stopped['usage']['source'] = 'claimed_without_kernel_wait'
    elif case == 'missing_full_original_result':
        path = value.root / 'original-results.json'
        records = wire.parse(path.read_bytes())
        del records['main-001']
        replace_file(path, encoded(records))
    elif case == 'cancel_barrier_lost':
        value.response('cold-main-cancel-lookup', lambda body: (body.clear(), body.update(state='unknown')))
    elif case == 'business_effect_replayed':
        role, rows = value.call('cold-query-main')
        response = oracle.one(rows, 'http_response', command='cold-query-main')
        body = value.body(response, 'response')
        result = bytearray(wire.b64(body['value']['result']))
        assert result[:8] == b'SCAPRES1' and struct.unpack_from('<II', result, 8) == (1, 3)
        position = 16
        for name in (b'id', b'counter', b'payload'):
            size = struct.unpack_from('<I', result, position)[0]
            position += 4
            assert result[position:position + size] == name
            position += size
        assert struct.unpack_from('<I', result, position)[0] == 1
        position += 4
        assert result[position:position + 9] == b'\x01' + struct.pack('<q', 1)
        position += 9
        assert result[position:position + 9] == b'\x01' + struct.pack('<q', 260)
        result[position:position + 9] = b'\x01' + struct.pack('<q', 261)
        body['value']['result'] = base64.b64encode(result).decode()
        response['response'] = value.artifact(encoded(body))
    else:
        raise AssertionError(case)


CASES = {
    'missing_original_ack': 'original-ack-denominator',
    'closed_window_result_not_received': 'copy-source-edge-and-target-put',
    'same_key_changed_target_bytes': 'immutable-bytes-key',
    'whole_s3_exchange_missing': 'original-s3-request-denominator',
    'target_not_read_back': 'seal-before-exact-target-readback',
    'unsealed_publication': 'seal-transition',
    'historical_receipt_root_copied': 'copy-roots-include-receipt-only-history',
    'delete_active_generation': 'delete-retirement-proof',
    'delete_without_original_batch': 'delete-retirement-proof',
    'refreshed_delete_etag': 'delete-original-etag',
    'unknown_relabelled_applied': 'known-disposition-requires-delivered-outcome',
    'bucket_error_cleared_checkpoint': 'no-such-bucket-keeps-exact-checkpoint',
    'late_put_not_accepted': 'late-put-new-round-from-start',
    'new_round_reused_frontier': 'original-exclusive-frontier',
    'old_cas_falsely_accepted': 'original-head-cas',
    'old_get_released_before_delete': 'old-read-deleted-before-forward',
    'late_delete_before_next_promotion': 'late-delete-after-next-generation',
    'sql_http_retry': 'single-post-no-replay',
    'unknown_reference_lost': 'original-unknown-reference',
    'forged_child_wait4': 'owned-wait4',
    'missing_full_original_result': 'original-result-ledger',
    'cancel_barrier_lost': 'cancel-survives-copy',
    'business_effect_replayed': 'single-effect-business-state',
}


def inventory(root):
    return {str(path.relative_to(root)): sha(path.read_bytes())
            for path in sorted(root.rglob('*')) if path.is_file()}


def run(source, destination):
    source, destination = source.resolve(), destination.resolve()
    destination.mkdir(parents=True, exist_ok=False)
    original = inventory(source)
    report = {'schema': 1, 'status': 'FAILED', 'source': str(source), 'source_inventory': original,
              'negative_controls': [], 'error': None, 'scope': 'Whole copied raw histories; exact semantic rejection boundary required.'}
    try:
        report['original_audit'] = oracle.audit(source)
        positive = destination / 'positive'
        shutil.copytree(source, positive, copy_function=os.link)
        report['positive_audit'] = oracle.audit(positive)
        for case, expected in CASES.items():
            copy_root = destination / case
            shutil.copytree(source, copy_root, copy_function=os.link)
            value = Copy(copy_root)
            mutate(value, case)
            value.save()
            try:
                oracle.audit(copy_root)
            except Rejected as error:
                assert error.rule == expected, (case, 'unrelated boundary', error.rule, expected)
                report['negative_controls'].append({'case': case, 'rejected_by': error.rule})
            else:
                raise AssertionError('negative history accepted: ' + case)
        assert inventory(source) == original, 'original evidence changed'
        report.update(status='PASSED', negative_count=len(CASES), positive_count=1, original_unchanged=True)
    except BaseException as error:
        report['error'] = repr(error)
    finally:
        (destination / 'controls.json').write_bytes(encoded(report))
    print(json.dumps({'status': report['status'], 'negative_count': len(report['negative_controls']), 'error': report['error']}))
    return 0 if report['status'] == 'PASSED' else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('source', type=Path)
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    raise SystemExit(run(args.source, args.destination))
