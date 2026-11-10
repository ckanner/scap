#!/usr/bin/env python3
"""Corrupt independent copies of actual observations, never the source evidence."""
import argparse
import base64
import json
import os
from pathlib import Path
import shutil

import oracle


def replace(path, raw):
    temporary = path.with_name(path.name + '.control-tmp')
    temporary.write_bytes(raw)
    temporary.replace(path)


def ledger(path, change):
    values = [json.loads(line) for line in path.read_text().splitlines()]
    change(values)
    replace(path, ''.join(json.dumps(row, sort_keys=True) + '\n' for row in values).encode())


def body(directory, identifier, change, kind='http_response'):
    field = 'response' if kind == 'http_response' else 'request'
    def edit(values):
        row = next(r for r in values if r['event'] == kind and r['id'] == identifier)
        value = json.loads((directory / row[field]['file']).read_bytes())
        change(value)
        raw = json.dumps(value, separators=(',', ':')).encode()
        digest = oracle.digest(raw)
        path = directory / 'raw' / digest
        replace(path, raw)
        row[field] = {'file': 'raw/' + digest, 'bytes': len(raw), 'sha256': digest}
    ledger(directory / 'sdk.jsonl', edit)


def mutate(directory, case):
    if case == 'missing_call':
        ledger(directory / 'sdk.jsonl', lambda values: values.__setitem__(slice(None), [v for v in values
            if not (v['event'] == 'call_finished' and v['id'] == 'write_same-63')]))
    elif case == 'slow_sample_removed':
        def edit(values):
            begin = next(v for v in values if v['event'] == 'call_started' and v['id'] == 'write_same-0')
            next(v for v in values if v['event'] == 'call_finished' and v['id'] == 'write_same-0')['monotonic_ns'] = begin['monotonic_ns']
        ledger(directory / 'sdk.jsonl', edit)
    elif case == 'request_identity_changed':
        body(directory, 'write_same-0', lambda value: value['request'].update(id='999'), 'http_request')
    elif case == 'retained_result_changed':
        body(directory, 'verify-write_same-0-0', lambda value: value['value']['receipt'].update(sequence='999'))
    elif case == 'cold_blob_changed':
        def edit(value):
            data = bytearray(base64.b64decode(value['value']['result']))
            data[-17] ^= 1
            value['value']['result'] = base64.b64encode(data).decode()
        body(directory, 'rows-cold-0', edit)
    elif case == 'publication_missing':
        def edit(values):
            value = next(v for v in values if v['event'] == 'response' and v.get('phase') == 'write_seq'
                         and v.get('method') == 'PUT' and v.get('path', '').endswith('/head'))
            value['event'] = 'omitted_publication'
        ledger(directory / 's3.jsonl', edit)
    elif case == 'whole_tail_exchange_missing':
        def edit(values):
            last = max(v['request_serial'] for v in values if v['event'] == 'request')
            values[:] = [v for v in values if v.get('request_serial') != last]
            for number, value in enumerate(values, 1):
                value['sequence'] = number
        ledger(directory / 's3.jsonl', edit)
    elif case == 'warm_hidden_download':
        def edit(values):
            number = next(v['request_serial'] for v in values if v['event'] == 'request'
                          and v['phase'] == 'cold-open' and '/objects/' in v['path'])
            for value in values:
                if value.get('request_serial') == number and 'phase' in value:
                    value['phase'] = 'read_same'
        ledger(directory / 's3.jsonl', edit)
    elif case == 'busy_error_changed':
        body(directory, 'recovery-busy', lambda value: value['error'].update(code='UNKNOWN'))
    elif case == 'gate_released_early':
        def edit(values):
            arrived = next(v for v in values if v['event'] == 'gate_arrived')
            next(v for v in values if v['event'] == 'gate_released')['monotonic_ns'] = arrived['monotonic_ns'] + 1
        ledger(directory / 's3.jsonl', edit)
    elif case == 'wrong_process':
        ledger(directory / 'resources-1.jsonl', lambda values: values[0]['identity'].update(start_ticks=1))
    elif case == 'missing_samples':
        replace(directory / 'resources-1.jsonl', b'')
    elif case == 'wrong_binary':
        path = directory / 'inputs.json'
        value = json.loads(path.read_bytes()); value['tools']['scapd']['sha256'] = 'f' * 64
        replace(path, json.dumps(value).encode())
    elif case == 'unreaped_service':
        ledger(directory / 'events.jsonl', lambda values: next(v for v in values
            if v['event'] == 'service_stopped')['usage'].update(source='controller_summary'))
    else:
        raise ValueError(case)


CASES = {'missing_call': 'http-denominator', 'slow_sample_removed': 'call-clock',
         'request_identity_changed': 'original-http-input', 'retained_result_changed': 'committed-wire',
         'cold_blob_changed': 'complete-business-values', 'publication_missing': 's3-exchange',
         'whole_tail_exchange_missing': 's3-denominator',
         'warm_hidden_download': 'warm-head-only', 'busy_error_changed': 'sdk-error-code',
         'gate_released_early': 'hot-before-gate-release', 'wrong_process': 'resource-process-identity',
         'missing_samples': 'resource-samples', 'wrong_binary': 'runtime-binary',
         'unreaped_service': 'owned-service-exit'}


def save(path, value):
    replace(path, (json.dumps(value, sort_keys=True, indent=2) + '\n').encode())


def run(evidence, output):
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    outcomes = []
    result = {'status': 'FAILED', 'positive_controls': 0, 'negative_controls': outcomes}
    try:
        original = oracle.audit(evidence)
        save(output / 'original-oracle.json', original)
        copy = output / 'positive-summary-changed'
        shutil.copytree(evidence, copy, copy_function=os.link)
        replace(copy / 'summary.json', b'{"status":"fabricated controller text"}\n')
        if oracle.audit(copy) != original:
            raise AssertionError('oracle trusted controller summary')
        result['positive_controls'] += 2
        for name, rule in CASES.items():
            copy = output / name
            shutil.copytree(evidence, copy, copy_function=os.link)
            mutate(copy, name)
            try:
                oracle.audit(copy)
            except oracle.Rejected as error:
                if error.rule != rule:
                    save(copy / 'control-result.json', {'status': 'FAILED', 'expected': rule, 'actual': error.rule})
                    raise AssertionError((name, rule, error.rule)) from error
                outcomes.append({'case': name, 'rejected_by': rule})
                save(copy / 'control-result.json', {'status': 'PASSED', 'rejected_by': rule})
            except BaseException as error:
                save(copy / 'control-result.json', {'status': 'FAILED', 'expected': rule, 'error': repr(error)})
                raise
            else:
                save(copy / 'control-result.json', {'status': 'FAILED', 'expected': rule, 'actual': 'accepted'})
                raise AssertionError('negative control accepted: ' + name)
        if oracle.audit(evidence) != original:
            raise AssertionError('controls modified original evidence')
        result.update(status='PASSED', positive_controls=result['positive_controls'] + 1)
        return result
    except BaseException as error:
        result['error'] = repr(error)
        raise
    finally:
        save(output / 'controls.json', result)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('evidence', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.evidence.resolve(), args.output.resolve()), sort_keys=True))
