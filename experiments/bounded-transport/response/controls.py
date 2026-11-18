#!/usr/bin/env python3
"""Reject altered copies of one actual observation; never edits original evidence."""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile

from oracle import audit, common, rows, wire

spec = importlib.util.spec_from_file_location('scap_response_startup_controls', common.HERE / 'controls.py')
startup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(startup)


def replace(path, records):
    # The directory is a hardlinked clone. Unlink before writing any mutation.
    path.unlink()
    path.write_text(''.join(json.dumps(row, sort_keys=True) + '\n' for row in records))


def modify(directory, case):
    if case in startup.STARTUP_CASES:
        startup.startup_mutation(directory, case)
        return
    path = directory / 'events.jsonl'
    events = rows(path)
    if case == 'missing-response':
        events = [r for r in events if not (r['event'] == 'http_response' and r.get('id') == 'stalled')]
        for index, row in enumerate(events, 1):
            row['sequence'] = index
    elif case in ('complete-response', 'no-peer-close'):
        row = next(r for r in events if r['event'] == 'http_response' and r['id'] == 'stalled')
        if case == 'complete-response':
            row['complete'] = True
        else:
            row.update(peer_eof=False, peer_failure=None)
    elif case == 'prefetched-body':
        next(r for r in events if r['event'] == 'slow_headers' and r['id'] == 'stalled')['body_bytes_read'] = 1
    elif case == 'client-disconnect':
        events.append({'event': 'slow_disconnected', 'id': 'stalled', 'method': 'TCP_RST',
                       'sequence': len(events) + 1, 'monotonic_ns': events[-1]['monotonic_ns'] + 1})
    elif case == 'sql-replay':
        original = next(r for r in events if r['event'] == 'http_request' and r['id'] == 'committed')
        events.append({**original, 'id': 'committed-replay', 'sequence': len(events) + 1,
                       'monotonic_ns': events[-1]['monotonic_ns'] + 1})
    elif case == 'forced-exit':
        next(r for r in events if r['event'] == 'service_stopped')['status'] = -9
    elif case == 'unsigned-backend':
        next(r for r in events if r['event'] == 'unsigned_probe')['status'] = 200
    elif case in ('unconditional-head', 'missing-result-readback'):
        path = directory / 'history.jsonl'
        events = rows(path)
        if case == 'unconditional-head':
            for row in events:
                if (row['event'] == 'object_response' and row['phase'] == 'committed'
                        and row['method'] == 'PUT' and row['path'].endswith('/head')):
                    row['if_match'] = None
        else:
            lookup = wire.parse((directory / 'lookup-1.response.json').read_bytes())
            suffix = '/' + lookup['value']['receipt']['result_hash']
            events = [r for r in events if not (r['event'] == 'object_response'
                and r['phase'] == 'committed' and r['method'] == 'GET' and r['path'].endswith(suffix))]
    else:
        raise ValueError('unknown control')
    replace(path, events)


def controls(evidence):
    assert audit(evidence)['status'] == 'PASSED'
    expected = {
        'missing-response': 'http-denominator', 'complete-response': 'peer-truncated',
        'no-peer-close': 'peer-closed', 'prefetched-body': 'slow-consumer',
        'client-disconnect': 'no-client-disconnect', 'sql-replay': 'http-denominator',
        'forced-exit': 'owned-exit', 'unsigned-backend': 'signed-backend',
        'unconditional-head': 'head-cas', 'missing-result-readback': 'result-readback',
        **startup.STARTUP_CASES,
    }
    observed = {}
    for case, rule in expected.items():
        with tempfile.TemporaryDirectory(prefix='scap-response-negative-', dir=evidence.parent) as temporary:
            clone = Path(temporary) / 'copy'
            shutil.copytree(evidence, clone, copy_function=os.link)
            modify(clone, case)
            try:
                audit(clone)
            except common.Rejected as error:
                assert error.rule == rule, (case, rule, error.rule)
                observed[case] = error.rule
            else:
                raise AssertionError('control was accepted: ' + case)
    # A mutation must not have changed any hardlinked original file.
    assert audit(evidence)['status'] == 'PASSED'
    return {'status': 'PASSED', 'negative_controls': observed, 'count': len(observed)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('evidence', type=Path)
    print(json.dumps(controls(parser.parse_args().evidence.resolve()), sort_keys=True))
