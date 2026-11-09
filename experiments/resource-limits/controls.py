#!/usr/bin/env python3
"""Apply rejected counterexamples to copies of a complete actual observation."""
import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path
import shutil
import tempfile

import oracle


def encoded(value):
    return json.dumps(value, separators=(',', ':')).encode()


def replace_body(row, value):
    raw = encoded(value)
    row['body'], row['sha256'] = base64.b64encode(raw).decode(), hashlib.sha256(raw).hexdigest()


def worker(row, alter):
    value = oracle.parse(oracle.raw(row, 'raw'))
    alter(value)
    raw = encoded(value) + b'\n'
    row['raw'], row['sha256'] = base64.b64encode(raw).decode(), hashlib.sha256(raw).hexdigest()


def mutation(name, rows):
    selected = lambda event, label: next(r for r in rows if r['event'] == event and r.get('id') == label)
    if name == 'missing-response':
        rows.remove(selected('http_response', 'timeout_control'))
    elif name == 'duplicate-execute-attempt':
        rows.append(copy.deepcopy(selected('http_input', 'timeout_execute')))
    elif name == 'wrong-backpressure':
        selected('http_response', 'timeout_same_tenant')['status'] = 200
    elif name == 'changed-original-id':
        row = selected('http_input', 'original_cancel')
        body = oracle.parse(oracle.raw(row)); body['request']['id'] = '2'; replace_body(row, body)
    elif name == 'false-committed-unknown':
        replace_body(selected('http_response', 'original_lookup'), {'ok': True, 'value': {'state': 'committed'}})
    elif name == 'missing-cancellation-proof':
        replace_body(selected('http_response', 'cancelled_lookup'), {'ok': True, 'value': {'state': 'unknown'}})
    elif name == 'lost-body-reservation':
        row = [r for r in rows if r['event'] == 'worker_event' and
               (v := oracle.parse(oracle.raw(r, 'raw')))['event'] == 'admission_observed'
               and v['fields']['id'].startswith('body-held-')][-1]
        worker(row, lambda v: v['fields'].update(data_available=2))
    elif name == 'extended-original-deadline':
        row = next(r for r in rows if r['event'] == 'worker_event' and
                   oracle.parse(oracle.raw(r, 'raw'))['event'] == 'head_pause_returned')
        worker(row, lambda v: v['fields'].update(deadline_elapsed=False))
    elif name == 'worker-completed-before-release':
        row = next(r for r in rows if r['event'] == 'worker_event' and
                   (v := oracle.parse(oracle.raw(r, 'raw')))['event'] == 'worker_completed' and v['fields']['operation'] == 'execute')
        worker(row, lambda v: v.update(sequence=1))
    elif name == 'missing-kernel-wait4':
        next(r for r in rows if r['event'] == 'worker_stopped')['kernel_usage']['available'] = False
    elif name == 'backend-identity-reused':
        row = next(r for r in rows if r['event'] == 'backend_stopped')
        row['processes'][0]['pid'] += 1
    elif name == 'unsigned-backend-readable':
        next(r for r in rows if r['event'] == 'unsigned_backend_response')['status'] = 200
    elif name == 'changed-large-result':
        row = selected('http_response', 'response_held')
        body = oracle.parse(oracle.raw(row)); value = bytearray(oracle.b64(body['value']['result'])); value[-1] ^= 1
        body['value']['result'] = base64.b64encode(value).decode(); replace_body(row, body)
    else:
        raise AssertionError(name)


def run(path):
    oracle.audit(path)
    names = ('missing-response', 'duplicate-execute-attempt', 'wrong-backpressure', 'changed-original-id',
             'false-committed-unknown', 'missing-cancellation-proof', 'lost-body-reservation',
             'extended-original-deadline', 'worker-completed-before-release', 'missing-kernel-wait4',
             'backend-identity-reused', 'unsigned-backend-readable', 'changed-large-result')
    report = {'schema': 1, 'positive_controls': 1, 'negative_controls': []}
    original = oracle.rows(path / 'events.jsonl')
    with tempfile.TemporaryDirectory(prefix='scap-resource-controls-') as directory:
        copy_path = Path(directory) / 'evidence'
        shutil.copytree(path, copy_path)
        for name in names:
            changed = copy.deepcopy(original)
            mutation(name, changed)
            (copy_path / 'events.jsonl').write_text(''.join(json.dumps(row, sort_keys=True) + '\n' for row in changed))
            try:
                oracle.audit(copy_path)
            except (ValueError, AssertionError) as error:
                report['negative_controls'].append({'name': name, 'rejected': True, 'reason': str(error)})
            else:
                raise AssertionError('independent audit accepted counterexample: ' + name)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('evidence', type=Path)
    args = parser.parse_args()
    print(json.dumps(run(args.evidence.resolve()), indent=2, sort_keys=True))
