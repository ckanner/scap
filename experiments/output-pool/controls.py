#!/usr/bin/env python3
"""Mutate real observations in separate copies; demand exact rejection rules."""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('scap_output_controls_oracle', HERE / 'oracle.py')
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)


def write(path, raw):
    # Copies use hardlinks for large raw bodies; replace rather than mutate an
    # inode shared with original evidence. Original failures are never edited.
    temporary = path.with_suffix(path.suffix + '.control-tmp')
    temporary.write_bytes(raw)
    temporary.replace(path)


def ledger(path, change):
    values = [json.loads(line) for line in path.read_text().splitlines()]
    change(values)
    write(path, ''.join(json.dumps(row, sort_keys=True) + '\n' for row in values).encode())


def response(directory, identifier, change, ledger_name='sdk.jsonl'):
    def alter(values):
        row = next(row for row in values if row['event'] == 'http_response' and row['id'] == identifier)
        path = directory / row['response']['file']
        value = json.loads(path.read_bytes())
        change(value)
        raw = json.dumps(value, separators=(',', ':')).encode()
        write(path, raw)
        row['response'] = {'file': path.name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
    ledger(directory / ledger_name, alter)


STARTUP_CASES = {
    'worker_missing_readback': 'worker-identity-request-denominator',
    'worker_wrong_body': 'worker-identity-exact-body',
    'worker_changed_etag': 'worker-identity-same-etag',
    'worker_replacement_create': 'worker-identity-absent-only',
    'worker_wrong_instance': 'worker-identity-exact-key',
    'worker_after_ready': 'worker-identity-before-ready',
}


def startup_mutation(directory, name):
    """Change a full original exchange coherently, not only its summary row."""
    path = '/scap-test/scap-worker/v1/instances/5001'
    ready = next(r for r in oracle.rows(directory / 'events.jsonl') if r['event'] == 'service_ready')
    def alter(values):
        claims = [r for r in values if r.get('path') == path]
        put = next(r for r in claims if r['event'] == 'object_response' and r['method'] == 'PUT')
        get = next(r for r in claims if r['event'] == 'object_request' and r['method'] == 'GET')
        if name == 'worker_missing_readback':
            values[:] = [r for r in values if r.get('request_serial') != get['request_serial']]
            serials = {old: new for new, old in enumerate(sorted({r['request_serial'] for r in values
                                                                 if 'request_serial' in r}), 1)}
            for row in values:
                if 'request_serial' in row:
                    row['request_serial'] = serials[row['request_serial']]
        elif name == 'worker_wrong_body':
            wrong = hashlib.sha256(b'SCAP-WORKER-INSTANCE-v1\0' + (5002).to_bytes(8, 'big')).hexdigest()
            for row in claims:
                if row['method'] == 'PUT':
                    row['request_sha256'] = wrong
                elif row['event'] in ('object_response', 'object_response_delivered'):
                    row['response_sha256'] = wrong
        elif name == 'worker_changed_etag':
            for row in claims:
                if row['method'] == 'GET' and row['event'] in ('object_response', 'object_response_delivered'):
                    row['etag'] = '"different-original-readback"'
        elif name == 'worker_replacement_create':
            for row in claims:
                if row['method'] == 'PUT':
                    row.update(if_none_match=None, if_match=put['etag'])
        elif name == 'worker_wrong_instance':
            for row in claims:
                row['path'] = '/scap-test/scap-worker/v1/instances/5002'
        elif name == 'worker_after_ready':
            delta = oracle.time_of(ready) + 1 - oracle.time_of(get)
            for row in claims:
                if row['method'] == 'GET':
                    row['monotonic_ns'] = oracle.time_of(row) + delta
            values.sort(key=oracle.time_of)
        else:
            raise ValueError(name)
    ledger(directory / 'history.jsonl', alter)


def mutate(directory, name):
    if name in STARTUP_CASES:
        startup_mutation(directory, name)
    elif name == 'wrong_limit':
        response(directory, 'tenant-limit-1', lambda value: value['error'].update(code='UNKNOWN'))
    elif name == 'different_principal':
        config = json.loads((directory / 'service-config.json').read_bytes())
        token_hash = next(c['sha256'] for c in config['credentials'] if c['principal'] == '11')
        ledger(directory / 'sdk.jsonl', lambda values: next(r for r in values if r['event'] == 'http_request'
               and r['id'] == 'tenant-limit-1').update(token_sha256=token_hash))
    elif name == 'extra_execute':
        def extra(values):
            row = dict(next(r for r in values if r['event'] == 'http_request' and r['id'] == 'insert-1'))
            row['id'] = 'insert-replayed'
            values.append(row)
        ledger(directory / 'sdk.jsonl', extra)
    elif name == 'cbu_receipt_changed':
        response(directory, 'insert-1', lambda value: value['error']['receipt'].update(sequence='99'))
    elif name == 'hold_already_read':
        ledger(directory / 'events.jsonl', lambda values: next(r for r in values if r['event'] == 'slow_headers'
               and r['id'] == 'a2').update(body_bytes_read=1))
    elif name == 'missing_publication':
        ledger(directory / 'history.jsonl', lambda values: values.__setitem__(slice(None),
            [r for r in values if not (r['event'] == 'object_response' and r.get('phase') == 'insert'
             and r.get('method') == 'PUT' and r.get('path', '').endswith('/head'))]))
    elif name == 'count_two':
        def change(value):
            raw = bytearray(base64.b64decode(value['value']['result']))
            # COUNT's only i64 scalar is immediately before affected_rows and rowid.
            raw[-24:-16] = (2).to_bytes(8, 'little', signed=True)
            value['value']['result'] = base64.b64encode(raw).decode()
        response(directory, 'count-1', change)
    elif name == 'recovered_blob_changed':
        def change(value):
            raw = bytearray(base64.b64decode(value['value']['result']))
            raw[-17] = 1
            value['value']['result'] = base64.b64encode(raw).decode()
        response(directory, 'a2', change, 'events.jsonl')
    elif name == 'commit_after_release':
        events = [json.loads(line) for line in (directory / 'events.jsonl').read_text().splitlines()]
        end = next(r['monotonic_ns'] for r in events if r['event'] == 'slow_disconnected' and r['id'] == 'a1')
        def alter(values):
            for row in values:
                if row.get('id') == 'insert-1' and row['event'] in ('http_request', 'http_response'):
                    row['monotonic_ns'] = str(end + (1 if row['event'] == 'http_request' else 2))
        ledger(directory / 'sdk.jsonl', alter)
    else:
        raise ValueError(name)


CASES = {'wrong_limit': 'pressure-limit', 'different_principal': 'tenant-principal',
    'extra_execute': 'http-denominator', 'cbu_receipt_changed': 'lookup-receipt',
    'hold_already_read': 'slow-consumer', 'missing_publication': 'one-business-head-publication',
    'count_two': 'single-effect', 'recovered_blob_changed': 'large-result-bytes',
    'commit_after_release': 'pressure-held-during-commit', **STARTUP_CASES}


def run(evidence):
    original = oracle.audit(evidence)
    results = []
    with tempfile.TemporaryDirectory(prefix='scap-output-controls-', dir=evidence.parent) as parent:
        for name, rule in CASES.items():
            copy = Path(parent) / name
            shutil.copytree(evidence, copy, copy_function=os.link)
            mutate(copy, name)
            try:
                oracle.audit(copy)
            except oracle.Rejected as error:
                if error.rule != rule:
                    raise AssertionError((name, rule, error.rule)) from error
                results.append({'case': name, 'rejected_by': rule})
            else:
                raise AssertionError('negative control was accepted: ' + name)
            shutil.rmtree(copy)
    # Re-reading the actual original is a positive control and catches an
    # accidental hardlink mutation in this observer, not just in the oracle.
    if oracle.audit(evidence) != original:
        raise AssertionError('original evidence changed during controls')
    return {'status': 'PASSED', 'positive_original': 2, 'negative_controls': results}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('evidence', type=Path)
    print(json.dumps(run(parser.parse_args().evidence.resolve()), sort_keys=True))
