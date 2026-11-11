"""Persist targeted counterfactuals; preserve every original raw byte."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import time

from absence_audit import audit
from absence_decode import evidence as e, model as m, controls

c = controls()


def omit_http(directory):
    history = e.rows(directory / 'events.jsonl')
    first = next(row for row in history if row['event'] == 'http_proxy_request')
    remaining = [row for row in history if not (row['event'].startswith('http_proxy_')
                 and row.get('role') == first['role'] and row.get('serial') == first['serial'])]
    c.save_rows(directory / 'events.jsonl', remaining)


def omit_read(directory, name, kind, ordinal):
    _, _, _, _, history, group = c.proxy_command(directory, name)
    start, end = e.moment(group['http_proxy_forward_started']), e.moment(group['http_proxy_backend_response'])
    def matching(row):
        path = row['path']
        return (row['event'] == 's3_request' and row['role'] == 'C' and row['method'] == 'GET'
                and start < e.moment(row) < end and
                (path.endswith('/head') if kind == 'head' else '/owner/v1/' + kind + '/' in path))
    selected = [row for row in history if row['event'] == 's3_request' and matching(row)]
    row = selected[ordinal - 1]
    c.omit_s3(directory, lambda value, _: value['role'] == 'C' and value['serial'] == row['serial'], True)


def missing_gate(directory):
    c.events(directory, lambda rows: rows.remove(e.one(rows, 'fault_arrived', id='current-real-404')))


def wrong_stage(directory):
    def mutate(rows):
        e.one(rows, 'fault_armed', id='current-real-404')['stage'] = 'before_forward'
        e.one(rows, 'fault_arrived', id='current-real-404')['stage'] = 'before_forward'
    c.events(directory, mutate)


def stale_etag(directory):
    def mutate(rows):
        row = next(row for row in rows if row['event'] == 's3_request' and row['method'] == 'PUT'
                   and row['path'].endswith('/head') and 'if-match' in row['headers'])
        row['headers']['if-match'] = '"control-stale-etag"'
    c.events(directory, mutate)


def changed_lookup(directory):
    _, _, _, _, _, group = c.proxy_command(directory, 'recovered-superseded-002')
    # Keep the other Scope's receipt and bytes internally consistent. Otherwise
    # the decoder would reject its hash before testing original-result binding.
    other = m.wire.parse(e.raw(directory, group['http_proxy_backend_response']['response']))['value']
    c.change_product(directory, 'recovered-current-002', lambda body: body.__setitem__('value', other))


def cases():
    return (
        ('whole-s3-exchange-omitted', lambda d: c.omit_s3(d, lambda row, _: row['role'] == 'A' and row['serial'] == 1), 's3-closed-denominator'),
        ('whole-http-exchange-omitted', omit_http, 'http-proxy-closed-denominator'),
        ('real-404-hold-omitted', missing_gate, 'absence-four-real-response-holds'),
        ('hold-before-real-response', wrong_stage, 'absence-fixed-real-hold-profile'),
        ('original-first-winner-called-fenced', lambda d: c.change_product(d, 'current-original-prepare',
            lambda body: body['value'].__setitem__('state', 'fenced')), 'absence-original-prepared-winner'),
        ('proof-race-called-corrupt', lambda d: c.change_product(d, 'proof-original-prepare',
            lambda body: body['error'].__setitem__('code', 'CORRUPT')), 'proof-race-not-corrupt-or-unknown'),
        ('current-second-descriptor-omitted', lambda d: omit_read(d, 'current-original-prepare', 'descriptor', 2),
         'absence-original-two-descriptor-reads'),
        ('proof-second-real-404-omitted', lambda d: omit_read(d, 'proof-original-prepare', 'descriptor', 2),
         'absence-original-two-descriptor-reads'),
        ('proof-late-head-barrier-omitted', lambda d: omit_read(d, 'proof-original-prepare', 'head', 3),
         'proof-after-absence-fresh-head-conflict'),
        ('proof-late-get-omitted', lambda d: omit_read(d, 'proof-original-prepare', 'proof', 1),
         'proof-after-absence-fresh-head-conflict'),
        ('permanent-proof-is-pending', c.pending_proof, 'owner-proof-terminal-only'),
        ('accepted-head-uses-stale-etag', stale_etag, 'original-head-etag'),
        ('retained-result-from-other-scope', changed_lookup, 'absence-original-results-retained'),
    )


def run(source, output):
    source, output = source.resolve(), output.resolve()
    if output == source or source in output.parents:
        raise ValueError('control output must be new and outside original evidence')
    output.mkdir(parents=True, exist_ok=False)
    original = c.inventory(source)
    baseline = audit(source)
    need = len(cases()) == len({name for name, _, _ in cases()}) == 13
    assert need
    report = {'schema': 1, 'status': 'RUNNING', 'source': str(source), 'baseline': baseline,
              'negative_controls': [], 'positive_controls': [], 'original_unchanged': False}
    c.replace(output / 'controls.json', c.encoded(report))
    for name, mutate, expected in (*cases(), ('unchanged-positive', None, None)):
        target = output / name
        shutil.copytree(source, target, copy_function=os.link)
        started = time.monotonic()
        result = {'name': name, 'evidence': str(target), 'expected': expected, 'status': 'FAILED'}
        try:
            if mutate is not None:
                mutate(target)
            result['audit'] = audit(target)
            if expected is None and result['audit']['status'] == 'PASSED':
                result['status'] = 'PASSED'
        except m.Rejected as error:
            result['observed'] = error.rule
            if error.rule == expected:
                result['status'] = 'PASSED'
        except BaseException as error:
            result['error'] = repr(error)
        result['elapsed_seconds'] = time.monotonic() - started
        c.replace(target / 'control-result.json', c.encoded(result))
        report['positive_controls' if expected is None else 'negative_controls'].append(result)
        c.replace(output / 'controls.json', c.encoded(report))
        print(json.dumps({key: result.get(key) for key in ('name', 'status', 'expected', 'observed', 'error')}, sort_keys=True), flush=True)
    report['original_unchanged'] = c.inventory(source) == original
    report['original_file_count'] = len(original)
    report['status'] = ('PASSED' if report['original_unchanged'] and
        all(row['status'] == 'PASSED' for row in report['negative_controls'] + report['positive_controls']) else 'FAILED')
    report['controller_sha256'] = m.sha(Path(__file__).read_bytes())
    c.replace(output / 'controls.json', c.encoded(report))
    return report
