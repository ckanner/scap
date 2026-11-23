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


def add_completed_sample(lane, *, acquired):
    """Keep all local equations valid so the external cohort/hold check decides."""
    if acquired:
        lane['acquired'] = str(int(lane['acquired']) + 1)
    lane['released'] = str(int(lane['released']) + 1)
    lane['active'] = str(int(lane['acquired']) - int(lane['released']))
    for interval in lane['intervals']:
        interval['completed'] = str(int(interval['completed']) + 1)
        interval['total_us'] = str(int(interval['total_us']) + 1)
        interval['buckets'][0] = str(int(interval['buckets'][0]) + 1)


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
    elif name in ('lifecycle-invalid', 'lifecycle-premature-release', 'lifecycle-lost-sample', 'lifecycle-wrong-cohort'):
        phase = 'after-http-timeout-' if name == 'lifecycle-premature-release' else 'final-'
        row = [r for r in rows if r['event'] == 'worker_event' and
               (v := oracle.parse(oracle.raw(r, 'raw')))['event'] == 'admission_observed'
               and v['fields']['id'].startswith(phase)][-1]
        def change(value):
            snapshot = value['fields']['lifecycle']
            data = snapshot['lanes'][0]
            if name == 'lifecycle-invalid':
                snapshot['valid'] = False
            elif name == 'lifecycle-premature-release':
                add_completed_sample(data, acquired=False)
            elif name == 'lifecycle-lost-sample':
                data['intervals'][-1]['buckets'] = ['0'] * 19
            else:
                add_completed_sample(data, acquired=True)
        worker(row, change)
    elif name == 'lifecycle-swapped-held-phases':
        def swapped(label):
            for before, after in (('body-held-', 'slow-response-'), ('slow-response-', 'body-held-')):
                if label.startswith(before):
                    return after + label[len(before):]
            return label
        for row in rows:
            if row['event'] == 'operator_command':
                value = oracle.parse(oracle.raw(row, 'raw'))
                if value['operation'] == 'observe':
                    worker(row, lambda value: value.update(id=swapped(value['id'])))
            elif row['event'] == 'worker_event':
                value = oracle.parse(oracle.raw(row, 'raw'))
                if value['event'] == 'admission_observed':
                    worker(row, lambda value: value['fields'].update(id=swapped(value['fields']['id'])))
    elif name == 'lifecycle-unmatched-observation':
        row = next(r for r in rows if r['event'] == 'operator_command' and
                   (value := oracle.parse(oracle.raw(r, 'raw')))['operation'] == 'observe'
                   and value['id'].startswith('final-'))
        worker(row, lambda value: value.update(id='unmatched-observation-0'))
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
        # Preserve the original rejected-gate witness: the final byte is the
        # last_insert_rowid footer, not a BLOB payload byte.
        row = selected('http_response', 'response_held')
        body = oracle.parse(oracle.raw(row)); value = bytearray(oracle.b64(body['value']['result'])); value[-1] ^= 1
        body['value']['result'] = base64.b64encode(value).decode(); replace_body(row, body)
    elif name == 'changed-large-blob':
        row = selected('http_response', 'response_held')
        body = oracle.parse(oracle.raw(row)); value = bytearray(oracle.b64(body['value']['result']))
        # SCAPRES1 header + statement/column counts + eight known names +
        # row count + first BLOB's tag/length: change its first actual byte.
        offset = 8 + 4 + 4 + sum(4 + len(('value' + str(i)).encode()) for i in range(8)) + 4 + 1 + 4
        assert value[offset - 5] == 4 and int.from_bytes(value[offset - 4:offset], 'little') == 1048576
        value[offset] ^= 1
        body['value']['result'] = base64.b64encode(value).decode(); replace_body(row, body)
    else:
        raise AssertionError(name)


def run(path):
    oracle.audit(path)
    names = ('missing-response', 'duplicate-execute-attempt', 'wrong-backpressure', 'changed-original-id',
             'false-committed-unknown', 'missing-cancellation-proof', 'lost-body-reservation',
             'extended-original-deadline', 'worker-completed-before-release', 'missing-kernel-wait4',
             'backend-identity-reused', 'unsigned-backend-readable', 'changed-large-result', 'changed-large-blob',
             'lifecycle-invalid', 'lifecycle-premature-release', 'lifecycle-lost-sample', 'lifecycle-wrong-cohort',
             'lifecycle-swapped-held-phases', 'lifecycle-unmatched-observation')
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
