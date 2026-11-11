#!/usr/bin/env python3
"""Persist complete counterfactual histories and require the named rejection."""
from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import shutil
import time

import oracle
import audit_evidence as e
import audit_model as m


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def replace(path, data):
    # Copies use hardlinks only for immutable input. Break a link before writing.
    path.unlink(missing_ok=True)
    with path.open('xb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def save_rows(path, rows, reorder=False):
    if reorder:
        rows.sort(key=e.moment)
    for index, row in enumerate(rows, 1):
        row['sequence'] = index
    replace(path, b''.join(encoded(row) for row in rows))


def put_raw(directory, data):
    digest = m.sha(data)
    path = directory / 'raw' / digest
    if path.exists():
        assert path.read_bytes() == data
    else:
        with path.open('xb') as stream:
            stream.write(data)
    return {'file': 'raw/' + digest, 'bytes': len(data), 'sha256': digest}


def walk(value, old, new):
    if isinstance(value, dict):
        if value == old:
            return copy.deepcopy(new)
        return {key: walk(item, old, new) for key, item in value.items()}
    if isinstance(value, list):
        return [walk(item, old, new) for item in value]
    return value


def replace_blob(directory, old, data):
    new = put_raw(directory, data)
    for path in [directory / 'events.jsonl', *sorted(directory.glob('sdk-*.jsonl'))]:
        changed = []
        for row in e.rows(path):
            request = row.get('request') == old and row['event'] == 's3_request'
            response = row.get('response') == old and row['event'] in ('s3_backend_response', 's3_delivery_started')
            row = walk(row, old, new)
            if request:
                row['headers']['content-length'] = str(new['bytes'])
                row['headers']['x-amz-content-sha256'] = new['sha256']
            elif response and 'content-length' in row['headers']:
                row['headers']['content-length'] = str(new['bytes'])
            changed.append(row)
        save_rows(path, changed)


def events(directory, mutate, reorder=False):
    path = directory / 'events.jsonl'
    rows = e.rows(path)
    mutate(rows)
    save_rows(path, rows, reorder)


def command(directory, name):
    matches = []
    for path in sorted(directory.glob('sdk-*.jsonl')):
        ledger = e.rows(path)
        found = [row for row in ledger if row['event'] == 'command_finished' and row['command'] == name]
        if found:
            request = e.one(ledger, 'http_request', command=name)
            matches.append((path, ledger, request, found[0]))
    assert len(matches) == 1, name
    return matches[0]


def proxy_command(directory, name):
    path, ledger, request, done = command(directory, name)
    history = e.rows(directory / 'events.jsonl')
    starts = {row['role']: row for row in history if row['event'] == 'http_proxy_started'}
    matches = [row for row in history if row['event'] == 'http_proxy_request'
        and row['request'] == request['request'] and starts[row['role']]['endpoint'] + row['path'] == request['url']
        and e.moment(request) < e.moment(row) < e.moment(done)]
    assert len(matches) == 1, name
    front = matches[0]
    group = {row['event']: row for row in history if row.get('role') == front['role']
             and row.get('serial') == front['serial'] and row['event'].startswith('http_proxy_')}
    return path, ledger, request, done, history, group


def mirror_result(directory, path, ledger, done):
    save_rows(path, ledger)
    history = e.rows(directory / 'events.jsonl')
    outputs = [row for row in history if row['event'] == 'child_output' and row['id'] == path.stem
               and m.wire.parse(e.raw(directory, row['raw'])).get('id') == done['command']]
    assert len(outputs) == 1
    outputs[0]['raw'] = put_raw(directory, encoded(done['result']))
    save_rows(directory / 'events.jsonl', history)


def change_result(directory, name, mutation):
    path, ledger, _, done = command(directory, name)
    mutation(done['result'])
    mirror_result(directory, path, ledger, done)


def change_product(directory, name, mutation):
    path, ledger, _, done, history, group = proxy_command(directory, name)
    backend = group['http_proxy_backend_response']
    body = m.wire.parse(e.raw(directory, backend['response']))
    mutation(body)
    changed = put_raw(directory, m.encoded(body))
    for event in ('http_proxy_backend_response', 'http_proxy_delivery_started'):
        row = group[event]
        row['response'] = changed
        if 'headers' in row and 'content-length' in row['headers']:
            row['headers']['content-length'] = str(changed['bytes'])
    response = e.one(ledger, 'http_response', command=name)
    response['response'] = changed
    if body['ok']:
        value = copy.deepcopy(body['value'])
        if isinstance(value, dict) and isinstance(value.get('result'), str):
            value['result'] = put_raw(directory, m.wire.b64(value['result']))
        done['result']['value'] = value
    else:
        done['result']['error']['code'] = body['error']['code']
    save_rows(directory / 'events.jsonl', history)
    mirror_result(directory, path, ledger, done)


def omit_s3(directory, choose, preserve_denominator=False):
    history = e.rows(directory / 'events.jsonl')
    chosen = {(row['role'], row['serial']) for row in history if row['event'] == 's3_request' and choose(row, history)}
    assert chosen
    removed = {}
    for role, serial in chosen:
        removed.setdefault(role, []).append(serial)
    history = [row for row in history if not (row['event'].startswith(('s3_', 'fault_'))
               and (row.get('role'), row.get('serial')) in chosen)]
    if preserve_denominator:
        for row in history:
            role = row.get('role')
            if role not in removed:
                continue
            if row['event'] == 's3_proxy_stopped':
                row['request_count'] -= len(removed[role])
            if 'serial' in row:
                row['serial'] -= sum(serial < row['serial'] for serial in removed[role])
    save_rows(directory / 'events.jsonl', history)


def mutate_head(directory, predicate, mutation):
    history = e.rows(directory / 'events.jsonl')
    found = []
    for row in history:
        if row['event'] == 's3_request' and row['method'] == 'PUT' and row['path'].endswith('/head'):
            value = m.wire.parse(e.raw(directory, row['request']))
            if predicate(value):
                found.append((row, value))
    assert found
    row, value = found[0]
    mutation(value)
    replace_blob(directory, row['request'], m.encoded(value))


def owner_blob(directory, kind, mutation, redigest=False):
    history = e.rows(directory / 'events.jsonl')
    row = next(row for row in history if row['event'] == 's3_request' and row['method'] == 'PUT'
               and '/owner/v1/' + kind + '/' in row['path'])
    value = m.wire.parse(e.raw(directory, row['request']))
    mutation(value)
    if redigest:
        value['input_digest'] = m.sha(m.encoded([value['version'], value['scope'],
            m.canonical_input(value['input']), m.ordered(value['base'], m.BASE)]))
    replace_blob(directory, row['request'], m.encoded(value))


def pending_proof(directory):
    history = e.rows(directory / 'events.jsonl')
    row = next(row for row in history if row['event'] == 's3_request' and row['method'] == 'PUT'
               and '/owner/v1/proof/' in row['path'])
    proof = m.wire.parse(e.raw(directory, row['request']))
    markers = []
    for event in history:
        if event['event'] == 's3_request' and event['method'] == 'PUT' and event['path'].endswith('/head'):
            head = m.wire.parse(e.raw(directory, event['request']))
            marker = head.get('owner_plan')
            if marker is not None and marker['reference'] == proof['marker']['reference'] and marker['phase']['kind'] in ('claimed', 'cancelling'):
                markers.append(marker)
    assert markers
    proof['marker'] = markers[0]
    replace_blob(directory, row['request'], m.encoded(proof))


def missing_native_ack(directory):
    def mutate(rows):
        rows.remove(next(row for row in rows if row['event'] == 'native_original_ack'))
    events(directory, mutate)


def missing_cold(directory):
    def mutate(rows):
        rows.remove(next(row for row in rows if row['event'] == 'cold_original_recovered'))
    events(directory, mutate)


def missing_result(directory):
    row = next(row for row in e.rows(directory / 'events.jsonl') if row['event'] == 'native_original_ack')
    (directory / row['result']['file']).unlink()


def missing_http_exchange(directory):
    def mutate(rows):
        selected = next(row for row in rows if row['event'] == 'http_proxy_request')
        rows[:] = [row for row in rows if not (row['event'].startswith('http_proxy_')
                    and row.get('role') == selected['role'] and row.get('serial') == selected['serial'])]
    events(directory, mutate)


def method_mismatch(directory):
    def mutate(rows):
        row = next(row for row in rows if row['event'] == 's3_backend_response')
        row['method'] = 'DELETE' if row['method'] != 'DELETE' else 'GET'
    events(directory, mutate)


def payload_hash(directory):
    def mutate(rows):
        row = next(row for row in rows if row['event'] == 's3_request' and row['method'] == 'PUT')
        row['headers']['x-amz-content-sha256'] = '0' * 64
    events(directory, mutate)


def http_body(directory):
    def mutate(rows):
        selected = next(row for row in rows if row['event'] == 'http_proxy_request')
        original = m.wire.parse(e.raw(directory, selected['request']))
        original['fixture_extra'] = 1
        raw = put_raw(directory, m.encoded(original))
        for row in rows:
            if row.get('role') == selected['role'] and row.get('serial') == selected['serial'] and row['event'] in (
                    'http_proxy_request', 'http_proxy_forward_started'):
                row['request'] = raw
                row['headers']['content-length'] = str(raw['bytes'])
    events(directory, mutate)


def missing_saved(directory):
    values = e.rows(directory / 'owner-inputs.jsonl')
    replace(directory / 'owner-inputs.jsonl', b''.join(encoded(row) for row in values[1:]))


def sql_workload(directory):
    path = directory / 'inputs.json'
    value = m.wire.parse(path.read_bytes())
    value['specs'][0]['statements'][-1]['sql'] = 'SELECT 1'
    replace(path, encoded(value))


def retry(directory):
    path, ledger, request, done = command(directory, 'bulk-p1-prepare')
    another = copy.deepcopy(request)
    another['ordinal'], another['monotonic_ns'] = 2, str(e.moment(request) + 1)
    ledger.insert(ledger.index(request) + 1, another)
    done['attempts'] = 2
    save_rows(path, ledger)


def wait4(directory):
    def mutate(rows):
        row = next(row for row in rows if row['event'] == 'child_stopped' and row['id'] == 'service-B-1')
        row['usage']['source'] = 'guessed_external_pid'
    events(directory, mutate)


def reuse_worker(directory):
    def mutate(rows):
        row = next(row for row in rows if row['event'] == 'service_ready' and row['worker'] == '9202')
        row['worker'] = '9102'
    events(directory, mutate)


def delete_permanent(directory):
    def mutate(rows):
        original = next(row for row in rows if row['event'] == 's3_request' and row['method'] == 'DELETE')
        permanent = next(row['path'] for row in rows if row['event'] == 's3_request' and '/owner/v1/proof/' in row['path'])
        for row in rows:
            if row.get('role') == original['role'] and row.get('serial') == original['serial'] and row['event'].startswith('s3_'):
                row['path'] = permanent
    events(directory, mutate)


def checkpoint_etag(directory):
    history = e.rows(directory / 'events.jsonl')
    rows = []
    for row in history:
        if row['event'] == 's3_request' and row['method'] == 'PUT' and row['path'].endswith('/head'):
            head = m.wire.parse(e.raw(directory, row['request']))
            sweep = head['storage']['sweep']
            if sweep is not None:
                rows.append((row, head))
    assert rows
    first = rows[0][1]['storage']['sweep']['serial']
    seen = set()
    for row, head in rows:
        if head['storage']['sweep']['serial'] == first and row['request']['sha256'] not in seen:
            seen.add(row['request']['sha256'])
            head['storage']['sweep']['entries'][0]['etag'] = '"refreshed-etag"'
            replace_blob(directory, row['request'], m.encoded(head))


def missing_proof_read(directory):
    _, _, _, _, _, group = proxy_command(directory, 'proof-claim-final-claim')
    start, end = e.moment(group['http_proxy_forward_started']), e.moment(group['http_proxy_backend_response'])
    omit_s3(directory, lambda row, _: row['role'] == 'B' and row['method'] == 'GET'
             and '/owner/v1/proof/' in row['path'] and start < e.moment(row) < end, True)


def missing_retained_read(directory):
    _, _, _, _, history, group = proxy_command(directory, 'bulk-p2-resume')
    start, end = e.moment(group['http_proxy_forward_started']), e.moment(group['http_proxy_backend_response'])
    selected = None
    for row in history:
        if (row['event'] == 's3_backend_response' and row['role'] == 'B' and row['method'] == 'GET'
                and row['status'] == 200 and '/objects/' in row['path'] and start < e.moment(row) < end):
            if m.envelope(e.raw(directory, row['response']), row['path'])[0] == 'result':
                selected = row['path']
                break
    assert selected is not None
    omit_s3(directory, lambda row, _: row['role'] == 'B' and row['method'] == 'GET'
             and row['path'] == selected and start < e.moment(row) < end, True)


def missing_fresh_head(directory, name, role):
    _, _, _, _, history, group = proxy_command(directory, name)
    start, end = e.moment(group['http_proxy_forward_started']), e.moment(group['http_proxy_backend_response'])
    payload = [row for row in history if row['event'] == 's3_request' and row['role'] == role
               and row['method'] == 'GET' and '/objects/' in row['path'] and start < e.moment(row) < end]
    assert payload
    after = min(e.moment(row) for row in payload)
    # Only pre-CAS HEAD2, retaining any exact post-publication observations.
    puts = [row for row in history if row['event'] == 's3_request' and row['role'] == role
            and row['method'] == 'PUT' and row['path'].endswith('/head') and start < e.moment(row) < end]
    before = min((e.moment(row) for row in puts), default=end)
    omit_s3(directory, lambda row, _: row['role'] == role and row['method'] == 'GET'
             and row['path'].endswith('/head') and after < e.moment(row) < before, True)


def premature_effect(directory, identifier, child):
    def mutate(rows):
        arrival = e.one(rows, 'fault_arrived', id=identifier)
        stop = e.one(rows, 'child_stopped', id=child)
        requested = e.one(rows, 'child_stop_requested', id=child)
        chosen = [row for row in rows if row.get('role') == arrival['role'] and row.get('serial') == arrival['serial']
                  and row['event'] in ('s3_forward_started', 's3_backend_response', 's3_delivery_started',
                                       's3_delivery_finished', 's3_handler_finished')
                  or row.get('id') == identifier and row['event'] in ('fault_release_requested', 'fault_forward_resumed')]
        chosen.sort(key=e.moment)
        start = (e.moment(requested) + e.moment(stop)) // 2
        assert start + len(chosen) < e.moment(stop)
        for index, row in enumerate(chosen):
            row['monotonic_ns'] = start + index
    events(directory, mutate, True)


def early_legacy(directory):
    _, _, _, done, _, group = proxy_command(directory, 'legacy-original-late-activation')
    def mutate(rows):
        selected = [row for row in rows if row.get('id') == 'legacy-activation-delayed'
                    and row['event'] in ('http_proxy_release_requested', 'http_proxy_fault_released')
                    or row.get('role') == group['http_proxy_request']['role']
                    and row.get('serial') == group['http_proxy_request']['serial']
                    and row['event'] in ('http_proxy_forward_started', 'http_proxy_forward_finished')]
        selected.sort(key=e.moment)
        for index, row in enumerate(selected):
            row['monotonic_ns'] = e.moment(done) + index + 1
    events(directory, mutate, True)


def missing_second_delivery(directory, identifier):
    def mutate(rows):
        row = next(row for row in rows if row['event'] == 'fault_arrived'
                   and row['id'] == identifier and row['use'] == 2)
        rows.remove(row)
    events(directory, mutate)


def no_queued_query(directory):
    _, _, _, _, _, group = proxy_command(directory, 'budget_gets-queued-query')
    def mutate(rows):
        release = e.one(rows, 'fault_forward_resumed', id='gets-budget-descriptor')
        row = next(row for row in rows if row['event'] == 'http_proxy_forward_finished'
                   and row['role'] == group['http_proxy_request']['role']
                   and row['serial'] == group['http_proxy_request']['serial'])
        row['monotonic_ns'] = e.moment(release) + 1
    events(directory, mutate, True)


def wrong_cold_result(directory):
    _, _, _, _, _, source = proxy_command(directory, 'cold-query-claim_cancel')
    value = m.wire.parse(e.raw(directory, source['http_proxy_backend_response']['response']))['value']['result']
    change_product(directory, 'cold-query-budget_gets', lambda body: body['value'].__setitem__('result', value))


def later_proof(value):
    value['marker']['phase']['revision'] += 1
    value['marker']['phase']['head_serial'] += 1


def cases():
    return (
        ('missing-native-ack', missing_native_ack, 'original-ack-ledger-denominator'),
        ('missing-cold-lookup-witness', missing_cold, 'cold-original-denominator'),
        ('missing-complete-original-result', missing_result, 'raw-file'),
        ('whole-s3-exchange-omitted', lambda d: omit_s3(d, lambda row, _: row['role'] == 'seed' and row['serial'] == 1), 's3-closed-denominator'),
        ('whole-http-exchange-omitted', missing_http_exchange, 'http-proxy-closed-denominator'),
        ('s3-method-path-group-mismatch', method_mismatch, 's3-original-method-path'),
        ('signed-payload-hash-mismatch', payload_hash, 'signed-original-payload-hash'),
        ('http-body-differs-from-sdk-original', http_body, 'original-sdk-real-http-request'),
        ('missing-saved-owner-input', missing_saved, 'owner-saved-input-denominator'),
        ('changed-fixed-sql-workload', sql_workload, 'fixed-original-sql-workload'),
        ('lost-owner-input-in-original-unknown', lambda d: change_result(d, 'bulk-p1-prepare', lambda r: r['error']['reference'].pop('ownerInput')), 'original-unknown-reference'),
        ('unknown-overwritten-by-later-knowledge', lambda d: change_result(d, 'bulk-p1-prepare', lambda r: r['error'].__setitem__('code', 'FENCED')), 'original-unknown-not-overwritten'),
        ('automatic-original-post-retry', retry, 'one-original-http-post'),
        ('guessed-process-usage', wait4, 'owned-wait4'),
        ('reused-worker-incarnation', reuse_worker, 'worker-instance-never-reused'),
        ('gc-deletes-permanent-owner-proof', delete_permanent, 'permanent-owner-and-catalogue-metadata-never-delete'),
        ('gc-refreshes-original-checkpoint-etag', checkpoint_etag, 'delete-original-checkpoint-etag'),
        ('pending-head-claims-active', lambda d: mutate_head(d, lambda h: h.get('owner_plan', {}).get('phase', {}).get('kind') == 'claimed', lambda h: h.__setitem__('active', True)), 'owner-non-active-inactive'),
        ('same-revision-phase-nonce-mismatch', lambda d: mutate_head(d, lambda h: 'owner_plan' in h, lambda h: h['transition'].__setitem__('nonce', h['transition']['nonce'] + 100)), 'owner-same-revision-nonce'),
        ('cancelling-changes-original-owner', lambda d: mutate_head(d, lambda h: h.get('owner_plan', {}).get('phase', {}).get('kind') == 'cancelling', lambda h: (h.__setitem__('owner_instance', 9999), h['owner_plan']['phase'].__setitem__('owner_instance', 9999))), 'owner-cancelling-keeps-original-tuple'),
        ('terminal-owner-technical-gap', lambda d: mutate_head(d, lambda h: h.get('owner_plan', {}).get('phase', {}).get('kind') == 'active', lambda h: h['owner_plan']['phase'].__setitem__('head_serial', h['owner_plan']['phase']['head_serial'] + 1)), 'owner-no-technical-gap'),
        ('resume-changes-original-sql-root', lambda d: mutate_head(d, lambda h: h.get('owner_plan', {}).get('phase', {}).get('kind') == 'active', lambda h: h.__setitem__('data_root', 'f' * 64)), 'owner-phase-preserves-business'),
        ('permanent-proof-is-pending', pending_proof, 'owner-proof-terminal-only'),
        ('proof-rebases-historical-phase', lambda d: owner_blob(d, 'proof', later_proof), 'proof-original-terminal-history'),
        ('descriptor-input-digest-changed', lambda d: owner_blob(d, 'descriptor', lambda v: v.__setitem__('input_digest', '0' * 64)), 'owner-original-input-digest'),
        ('descriptor-base-etag-rebased', lambda d: owner_blob(d, 'descriptor', lambda v: v['base'].__setitem__('etag', '"new-observation"'), True), 'owner-exact-original-head'),
        ('descriptor-base-head-hash-rebased', lambda d: owner_blob(d, 'descriptor', lambda v: v['base'].__setitem__('head_hash', '0' * 64), True), 'owner-exact-original-head'),
        ('replacement-without-proof-exact-read', missing_proof_read, 'proof-exact-readback-before-replacement'),
        ('resume-omits-original-retained-result', missing_retained_read, 'resume-complete-data-and-retained-closure'),
        ('resume-omits-final-fresh-head', lambda d: missing_fresh_head(d, 'bulk-p2-resume', 'B'), 'resume-fresh-exact-head-after-complete-recovery'),
        ('descriptor-effect-before-process-exit', lambda d: premature_effect(d, 'late-descriptor-put', 'service-A-1'), 'original-s3-effect-after-owned-process-exit'),
        ('claim-effect-before-process-exit', lambda d: premature_effect(d, 'dead-worker-claim', 'service-B-1'), 'original-s3-effect-after-owned-process-exit'),
        ('resume-effect-before-process-exit', lambda d: premature_effect(d, 'dead-worker-resume', 'service-R-2'), 'original-s3-effect-after-owned-process-exit'),
        ('legacy-http-forwarded-before-abort', early_legacy, 'legacy-http-after-adoption-is-fenced-even-matching-revision'),
        ('acl-failure-without-fresh-observation', lambda d: missing_fresh_head(d, 'acl-resume-old-head', 'B'), 'original-operation-fresh-admin-barrier'),
        ('second-stable-hash-fault-omitted', lambda d: missing_second_delivery(d, 'same-id-different-hash'), 'complete-fault-delivery-denominator'),
        ('second-current-missing-omitted', lambda d: missing_second_delivery(d, 'current-descriptor-missing'), 'complete-fault-delivery-denominator'),
        ('second-historical-missing-omitted', lambda d: missing_second_delivery(d, 'historical-descriptor-missing'), 'complete-fault-delivery-denominator'),
        ('missing-proof-called-aborted', lambda d: change_product(d, 'proof-claim-missing-is-unknown-history', lambda b: b['value'].__setitem__('state', 'aborted')), 'unknown-history-is-not-not-applied'),
        ('local-budget-called-corruption', lambda d: change_product(d, 'budget_gets-limited-resume', lambda b: b['error'].__setitem__('code', 'CORRUPT')), 'all-original-error-and-unknown-results'),
        ('query-not-forwarded-during-held-resume', no_queued_query, 'same-actor-budget-failure-then-original-row'),
        ('cold-business-result-from-other-scope', wrong_cold_result, 'single-effect-business-state'),
    )


def inventory(directory):
    return {str(path.relative_to(directory)): m.sha(path.read_bytes()) for path in sorted(directory.rglob('*')) if path.is_file()}


def run(source, output):
    source, output = source.resolve(), output.resolve()
    if output == source or source in output.parents:
        raise ValueError('control output must be a new directory outside the original evidence')
    output.mkdir(parents=True, exist_ok=False)
    original = inventory(source)
    assert len(cases()) == 42 and len({name for name, _, _ in cases()}) == 42
    baseline = oracle.audit(source)
    report = {'schema': 1, 'status': 'RUNNING', 'source': str(source), 'baseline': baseline,
              'negative_controls': [], 'positive_controls': [], 'original_unchanged': False}
    replace(output / 'controls.json', encoded(report))
    all_passed = True
    for name, mutate, expected in (*cases(), ('unchanged-positive', None, None)):
        target = output / name
        shutil.copytree(source, target, copy_function=os.link)
        started = time.monotonic()
        result = {'name': name, 'evidence': str(target), 'expected': expected, 'status': 'FAILED'}
        try:
            if mutate is not None:
                mutate(target)
            audited = oracle.audit(target)
            result['audit'] = audited
            if expected is None and audited['status'] == 'PASSED':
                result['status'] = 'PASSED'
        except m.Rejected as error:
            result['observed'] = error.rule
            if expected == error.rule:
                result['status'] = 'PASSED'
        except BaseException as error:
            result['error'] = repr(error)
        result['elapsed_seconds'] = time.monotonic() - started
        replace(target / 'control-result.json', encoded(result))
        report['positive_controls' if expected is None else 'negative_controls'].append(result)
        all_passed &= result['status'] == 'PASSED'
        replace(output / 'controls.json', encoded(report))
        print(json.dumps({key: result[key] for key in ('name', 'status', 'expected', 'elapsed_seconds')}
                         | {'observed': result.get('observed'), 'error': result.get('error')}, sort_keys=True), flush=True)
    report['original_unchanged'] = inventory(source) == original
    report['original_file_count'] = len(original)
    report['status'] = 'PASSED' if all_passed and report['original_unchanged'] else 'FAILED'
    report['controller_sha256'] = m.sha(Path(__file__).read_bytes())
    replace(output / 'controls.json', encoded(report))
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    arguments = parser.parse_args()
    report = run(arguments.evidence, arguments.output)
    print(json.dumps({'status': report['status'], 'controls': str(arguments.output / 'controls.json')}, sort_keys=True))
    raise SystemExit(0 if report['status'] == 'PASSED' else 1)
