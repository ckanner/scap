#!/usr/bin/env python3
"""Semantic mutations of complete actual histories; originals stay unchanged."""
import argparse
import json
import os
from pathlib import Path
import shutil

import oracle as o
import spec


def replace(path, data):
    temporary = path.with_name(path.name + '.control-tmp')
    temporary.write_bytes(data)
    temporary.replace(path)


def save(path, value):
    replace(path, (json.dumps(value, sort_keys=True, indent=2) + '\n').encode())


def ledger(path, edit):
    values = [json.loads(line) for line in path.read_text().splitlines()]
    edit(values)
    replace(path, ''.join(json.dumps(row, sort_keys=True) + '\n' for row in values).encode())


def store(directory, body):
    digest = o.digest(body)
    path = directory / 'raw' / digest
    if not path.exists():
        budget = directory / 'raw-budget'
        charged = int(budget.read_text()) + len(body)
        if charged > spec.BOUNDS['raw_bytes']:
            raise ValueError('negative-control evidence budget')
        replace(budget, f'{charged}\n'.encode())
        replace(path, body)
    return {'file': 'raw/' + digest, 'bytes': len(body), 'sha256': digest}


def body(directory, identifier, change, event='http_response'):
    field = 'response' if event == 'http_response' else 'request'

    def edit(values):
        row = next(r for r in values if r['event'] == event and r['id'] == identifier)
        value = json.loads((directory / row[field]['file']).read_bytes())
        change(value)
        row[field] = store(directory, json.dumps(value, separators=(',', ':')).encode())

    ledger(directory / 'sdk.jsonl', edit)


def mutate(directory, case):
    if case == 'missing_offer':
        ledger(directory / 'sdk.jsonl', lambda values: values.__setitem__(slice(None), [r for r in values
            if not (r['event'] == 'call_offered' and r['id'] == 'overload-hot-959')]))
    elif case == 'shifted_schedule':
        ledger(directory / 'sdk.jsonl', lambda values: next(r for r in values
            if r['event'] == 'call_offered' and r['id'] == 'overload-hot-1').update(scheduled_ns='1'))
    elif case == 'missing_slow_call':
        def edit(values):
            starts = {r['id']: o.moment(r) for r in values if r['event'] == 'call_started'}
            slow = max((r for r in values if r['event'] == 'call_finished' and r['phase'] == 'overload'),
                       key=lambda r: o.moment(r) - starts[r['id']])
            values.remove(slow)
        ledger(directory / 'sdk.jsonl', edit)
    elif case == 'fabricated_success':
        def edit(values):
            row = next(r for r in values if r['event'] == 'call_finished' and (r.get('error') or {}).get('code') == 'BACKPRESSURE')
            row.update(ok=True, error=None)
        ledger(directory / 'sdk.jsonl', edit)
    elif case == 'progress_after_window':
        def edit(values):
            start = next(r for r in values if r['event'] == 'phase_started' and r['phase'] == 'overload')
            after = int(start['origin_ns']) + 6_000_000_000
            for row in values:
                if row['event'] == 'call_finished' and row['id'].startswith('overload-quiet-') and int(row['id'].rsplit('-', 1)[1]) < 20:
                    row['monotonic_ns'] = str(after)
        ledger(directory / 'sdk.jsonl', edit)
    elif case == 'request_identity_changed':
        body(directory, 'single-0', lambda value: value['request'].update(id='99999'), 'http_request')
    elif case == 'original_receipt_changed':
        body(directory, 'verify-single-0-0', lambda value: value['value']['receipt'].update(sequence='99999'))
    elif case == 'final_payload_changed':
        import base64
        def edit(value):
            data = bytearray(base64.b64decode(value['value']['result']))
            offset = data.find(spec.payload(0))
            if offset < 0:
                raise ValueError('original exact payload missing')
            data[offset] ^= 1
            value['value']['result'] = base64.b64encode(data).decode()
        body(directory, 'rows-single', edit)
    elif case == 'publication_exchange_missing':
        ledger(directory / 's3.jsonl', lambda values: next(r for r in values if r['event'] == 'response'
            and r['phase'] == 'single' and r['method'] == 'PUT' and r['path'].endswith('/head')).update(event='omitted_publication'))
    elif case == 'whole_tail_exchange_missing':
        def edit(values):
            last = max(r['request_serial'] for r in values if r['event'] == 'request')
            values[:] = [r for r in values if r['request_serial'] != last]
            for index, row in enumerate(values, 1):
                row['sequence'] = index
        ledger(directory / 's3.jsonl', edit)
    elif case == 'readback_after_publication':
        calls = o.rows(directory / 'sdk.jsonl')
        reply = next(r for r in calls if r['event'] == 'http_response' and r['id'] == 'single-0')
        receipt = o.wire.parse(o.raw(directory, reply['response']))['value']['receipt']
        def edit(values):
            put = next(r for r in values if r['event'] == 'request' and r['method'] == 'PUT'
                       and r['path'].endswith('/head') and r['phase'] == 'single')
            response = next(r for r in values if r['event'] == 'response' and r['request_serial'] == put['request_serial'])
            get = next(r for r in values if r['event'] == 'request' and r['method'] == 'GET'
                       and r['path'].endswith('/' + receipt['result_hash']))
            changed = [r for r in values if r['request_serial'] == get['request_serial'] and r['event'] in ('response', 'delivered')]
            for index, row in enumerate(changed, 1):
                row['monotonic_ns'] = o.moment(response) + index
            values.sort(key=o.moment)
            for index, row in enumerate(values, 1):
                row['sequence'] = index
        ledger(directory / 's3.jsonl', edit)
    elif case == 'worker_unconditional_create':
        def edit(values):
            for row in values:
                if row['path'].startswith('/scap-test/scap-worker/') and row['method'] == 'PUT':
                    row.update(if_match=None, if_none_match=None)
        ledger(directory / 's3.jsonl', edit)
    elif case == 'wrong_binary':
        value = json.loads((directory / 'inputs.json').read_bytes())
        value['tools']['scapd']['sha256'] = 'f' * 64
        save(directory / 'inputs.json', value)
    elif case == 'wrong_owned_process':
        ledger(directory / 'resources.jsonl', lambda values: values[0]['identity'].update(start_ticks=1))
    elif case == 'missing_resource_samples':
        replace(directory / 'resources.jsonl', b'')
    elif case == 'unreaped_service':
        ledger(directory / 'events.jsonl', lambda values: next(r for r in values
            if r['event'] == 'service_stopped')['usage'].update(source='unverified_process'))
    elif case == 'private_directory_not_removed':
        ledger(directory / 'events.jsonl', lambda values: next(r for r in values
            if r['event'] == 'private_removed').update(exists=True))
    elif case == 'batch_as_independent_transactions':
        value = json.loads((directory / 'workload.json').read_bytes())
        value['plan']['batch_statements'] = 1
        save(directory / 'workload.json', value)
    else:
        raise ValueError(case)


CASES = {'missing_offer': 'offered-denominator', 'shifted_schedule': 'fixed-arrival-schedule',
         'missing_slow_call': 'http-denominator', 'fabricated_success': 'sdk-success',
         'progress_after_window': 'tenant-window-progress', 'request_identity_changed': 'original-http-input',
         'original_receipt_changed': 'committed-wire', 'final_payload_changed': 'complete-business-values',
         'publication_exchange_missing': 's3-proxy-error', 'whole_tail_exchange_missing': 's3-denominator',
         'readback_after_publication': 'closure-before-head',
         'worker_unconditional_create': 'worker-claim-create-only', 'wrong_binary': 'runtime-binary',
         'wrong_owned_process': 'resource-process-identity', 'missing_resource_samples': 'resource-samples',
         'unreaped_service': 'owned-service-exit', 'private_directory_not_removed': 'private-cleanup',
         'batch_as_independent_transactions': 'fixed-plan'}


def run(evidence, output):
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    result = {'status': 'FAILED', 'negative_controls': [], 'positive_controls': 0}
    try:
        original = o.audit(evidence)
        save(output / 'original-oracle.json', original)
        positive = output / 'summary_changed'
        shutil.copytree(evidence, positive, copy_function=os.link)
        replace(positive / 'summary.json', b'{"status":"invented success"}\n')
        if o.audit(positive) != original:
            raise AssertionError('oracle trusted summary')
        result['positive_controls'] += 1
        for name, rule in CASES.items():
            copy = output / name
            shutil.copytree(evidence, copy, copy_function=os.link)
            mutate(copy, name)
            try:
                o.audit(copy)
            except o.Rejected as error:
                if error.rule != rule:
                    raise AssertionError((name, rule, error.rule)) from error
                result['negative_controls'].append({'case': name, 'rejected_by': error.rule})
            else:
                raise AssertionError('counterexample accepted: ' + name)
        if o.audit(evidence) != original:
            raise AssertionError('original evidence changed')
        result['status'] = 'PASSED'
    finally:
        save(output / 'controls.json', result)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('evidence', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.evidence.resolve(), args.output.resolve()), sort_keys=True))
