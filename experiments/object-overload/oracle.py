#!/usr/bin/env python3
"""Independent raw-history audit; never imports runner or product modules."""
from __future__ import annotations

import argparse
import base64
from collections import Counter, defaultdict
import hashlib
import json
import math
from pathlib import Path
import re
import tarfile

import shared
import spec

wire = shared.module('overload_independent_wire', shared.ROOT / 'experiments/object-service/audit_wire.py')


class Rejected(ValueError):
    def __init__(self, rule):
        self.rule = rule
        super().__init__(rule)


def need(value, rule):
    if not value:
        raise Rejected(rule)


def same(left, right, rule):
    need(json.dumps(left, sort_keys=True) == json.dumps(right, sort_keys=True), rule)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def moment(row):
    value = row['monotonic_ns']
    need(type(value) is int or type(value) is str and value.isdecimal(), 'clock-format')
    value = int(value)
    need(value > 0, 'clock-format')
    return value


def one(values, rule):
    need(len(values) == 1, rule)
    return values[0]


def rows(path):
    need(path.is_file(), 'ledger-missing')
    result = []
    with path.open('rb') as stream:
        while line := stream.readline(1024 * 1024 + 1):
            need(line.endswith(b'\n') and len(line) <= 1024 * 1024, 'ledger-framing')
            result.append(wire.parse(line))
            need(len(result) <= spec.BOUNDS['trace_rows'], 'ledger-bound')
    return result


def raw(directory, value):
    need(type(value) is dict and set(value) == {'file', 'bytes', 'sha256'}, 'raw-description')
    need(type(value['file']) is str and re.fullmatch(r'raw/[0-9a-f]{64}', value['file'])
         and value['file'] == 'raw/' + value['sha256'], 'raw-path')
    path = directory / value['file']
    need(path.is_file() and not path.is_symlink(), 'raw-missing')
    need(type(value['bytes']) is int and 0 <= value['bytes'] <= spec.BOUNDS['body_bytes']
         and path.stat().st_size == value['bytes'], 'raw-integrity')
    data = path.read_bytes()
    need(len(data) == value['bytes'] and digest(data) == value['sha256'], 'raw-integrity')
    return data


def percentiles(values):
    need(bool(values) and all(type(n) in (int, float) and math.isfinite(n) and n >= 0 for n in values),
         'latency-values')
    ordered = sorted(values)
    return {'samples': len(values), **{name: ordered[math.ceil(fraction * len(ordered)) - 1]
        for name, fraction in (('p50', .5), ('p95', .95), ('p99', .99))}, 'maximum': ordered[-1]}


def concurrent(intervals):
    events = sorted((time, delta) for start, end in intervals for time, delta in ((start, 1), (end, -1)))
    active = maximum = 0
    for _, delta in events:
        active += delta
        need(active >= 0, 'call-interval')
        maximum = max(maximum, active)
    need(active == 0, 'call-interval')
    return maximum


def archive_inputs(path, expected, rule):
    with tarfile.open(path) as archive:
        members = archive.getmembers()
        need(len(members) == len(expected) and {m.name for m in members} == set(expected), rule)
        for member in members:
            need(member.isfile() and digest(archive.extractfile(member).read()) == expected[member.name], rule)


def identity(directory, inputs):
    expected = {path.relative_to(shared.ROOT).as_posix(): digest(path.read_bytes())
                for path in shared.fixture_files()}
    same(inputs['fixture'], expected, 'fixture-source')
    need(re.fullmatch('[0-9a-f]{40}', inputs['fixture_commit']) is not None, 'fixture-commit')
    archive = directory / 'fixture-source.tar'
    need(digest(archive.read_bytes()) == inputs['fixture_archive_sha256'], 'fixture-archive')
    archive_inputs(archive, expected, 'fixture-archive')
    root = directory / 'runtime-build'
    receipt = wire.parse((root / 'build-receipt.json').read_bytes())
    need(receipt['status'] == 'passed' and receipt['profile'] == 'release'
         and receipt['exit_code'] == 0, 'runtime-build')
    same(receipt['binary'], inputs['tools']['scapd'], 'runtime-binary')
    same(receipt['inputs'], inputs['runtime_inputs'], 'runtime-inputs')
    need(receipt['source_commit'] == inputs['runtime_source_commit'], 'runtime-commit')
    record = receipt['archived_evidence']
    for name, checksum in (('source_archive', 'source_archive_sha256'), ('source_manifest', 'source_manifest_sha256')):
        need(digest((root / record[name]).read_bytes()) == record[checksum], 'runtime-archive')
    manifest = wire.parse((root / record['source_manifest']).read_bytes())
    same(manifest, {'schema': 1, 'source_commit': receipt['source_commit'], 'inputs': receipt['inputs']},
         'runtime-source-manifest')
    archive_inputs(root / record['source_archive'], receipt['inputs'], 'runtime-source-bytes')
    for name in ('cargo.stdout.jsonl', 'cargo.stderr.log'):
        need(digest((root / ('build-' + name)).read_bytes()) == receipt[name + '_sha256'], 'runtime-build-log')
    cargo = rows(root / 'build-cargo.stdout.jsonl')
    need(cargo[-1].get('reason') == 'build-finished' and cargo[-1].get('success') is True, 'runtime-build-finished')
    for name in ('experiments/object-service/audit_wire.py', 'experiments/object-network/head5_audit.py'):
        need(expected[name] == receipt['inputs'][name], 'independent-reader-source')


def workload(directory):
    value = wire.parse((directory / 'workload.json').read_bytes())
    same(value['plan'], spec.PLAN, 'fixed-plan')
    expected = spec.calls()
    for item in expected:
        statements = spec.statements(item)
        if statements is not None:
            item['statements'] = statements
    same(value['calls'], expected, 'workload-denominator')
    wanted = {str(row) for item in expected for row in item.get('rows', [])}
    need(set(value['payloads']) == wanted, 'payload-denominator')
    for number, description in value['payloads'].items():
        need(raw(directory, description) == spec.payload(int(number)), 'fixed-payload')
    return {item['id']: item for item in expected}


def statements(item):
    return [{'sql': statement['sql'], 'params': [
        {'type': 'integer', 'value': value['integer']} if 'integer' in value else
        {'type': 'blob', 'base64': base64.b64encode(spec.payload(value['payload_row'])).decode()}
        for value in statement['params']]} for statement in item['statements']]


def outcome(finish):
    if finish['ok']:
        return 'success'
    error = finish['error']
    if error.get('outcome') == 'committed':
        return 'committed_unavailable'
    if error.get('outcome') == 'unknown' or error.get('code') in ('UNKNOWN', 'UNAVAILABLE', 'DEADLINE'):
        return 'unknown'
    return 'rejected' if error.get('name') == 'RemoteError' else 'transport_error'


def http(directory, planned, config):
    history = rows(directory / 'sdk.jsonl')
    events = defaultdict(dict)
    for row in history:
        if 'id' not in row:
            continue
        need(row['id'] in planned and row['id'] not in events[row['event']], 'http-denominator')
        events[row['event']][row['id']] = row
    need(not events['generator_rejected'], 'generator-rejected')
    for kind in ('call_started', 'call_finished', 'http_request'):
        need(set(events[kind]) == set(planned), 'http-denominator')
    need(set(events['http_response']).isdisjoint(events['http_error']) and
         set(events['http_response']) | set(events['http_error']) == set(planned), 'http-terminal-denominator')
    prepares = rows(directory / 'intents.jsonl')
    originals = {i for i, item in planned.items() if item['operation'] == 'execute'}
    need(len(prepares) == len(originals) and {row['id'] for row in prepares} == originals,
         'original-execute-denominator')
    saved = {row['id']: (wire.parse(raw(directory, row['serialized'])), row) for row in prepares}
    credentials = {item['tenant']: item for item in config['credentials']}
    calls = {}
    for identifier, item in planned.items():
        begin, finish, sent = (events[k][identifier] for k in ('call_started', 'call_finished', 'http_request'))
        need(type(finish['ok']) is bool, 'sdk-outcome-type')
        terminal = events['http_response'].get(identifier) or events['http_error'][identifier]
        need(begin['phase'] == finish['phase'] == sent['phase'] == terminal['phase'] == item['phase'], 'call-phase')
        need(int(begin['scheduled_ns']) <= moment(begin) < moment(sent) < moment(terminal)
             and moment(begin) < moment(finish), 'call-clock')
        need(finish['posts'] == 1 and sent['method'] == 'POST' and sent['redirect'] == 'error', 'single-original-post')
        scope, operation = spec.SCOPES[item['scope']], item['operation']
        need(sent['scope'] == item['scope'] and sent['token_sha256'] == credentials[scope['tenant']]['sha256'],
             'credential-binding')
        body = wire.parse(raw(directory, sent['request']))
        expected = {'version': 1, 'scope': scope, 'operation': operation}
        if operation in ('create', 'activate'):
            expected['nonce'] = item['nonce']
        if operation == 'activate':
            expected['expected_revision'] = item['expected_revision']
        if operation in ('execute', 'query'):
            expected['statements'] = statements(item)
        if operation in ('execute', 'lookup', 'cancel'):
            original = item if operation == 'execute' else planned[item['original']]
            request = {'epoch': '1', 'id': original['request_id'],
                       'principal': credentials[scope['tenant']]['principal'],
                       'fingerprint': wire.fingerprint(statements(original))}
            expected['request'] = request
            if operation == 'execute':
                serialized, before = saved[identifier]
                need(moment(before) < moment(begin), 'input-before-execute')
                same(serialized, {'scope': scope, 'request': request, 'statements': expected['statements']},
                     'serialized-request')
        same(body, expected, 'original-http-input')
        admission = 'data' if operation in ('create', 'execute', 'query') else 'recovery' if operation == 'activate' else 'control'
        need(sent['admission'] == admission, 'admission-class')
        value = None
        if terminal['event'] == 'http_response':
            need(terminal['complete'] is True, 'complete-http-response')
            value = wire.parse(raw(directory, terminal['response']))
            need(type(value) is dict and type(value.get('ok')) is bool, 'http-envelope')
            if value['ok']:
                need(terminal['status'] == 200 and set(value) == {'ok', 'value'}, 'http-success')
            else:
                need(terminal['status'] != 200 and set(value) == {'ok', 'error'}
                     and type(value['error']['code']) is str, 'http-rejection')
        if finish['ok']:
            need(value is not None and value['ok'] and finish['error'] is None
                 and moment(terminal) < moment(finish), 'sdk-success')
            if operation in ('execute', 'lookup', 'cancel'):
                need(finish['state'] == value['value'].get('state'), 'sdk-state')
        else:
            error = finish['error']
            need(type(error) is dict and type(error.get('name')) is str, 'sdk-error')
            if value is not None and not value['ok'] and moment(terminal) < moment(finish):
                need(error.get('code') == value['error']['code'], 'sdk-error-code')
        if item['phase'] != 'overload':
            need(finish['ok'], 'required-call-success')
        calls[identifier] = {'item': item, 'begin': begin, 'finish': finish, 'sent': sent,
                            'terminal': terminal, 'body': body, 'value': value, 'category': outcome(finish)}
    for phase in spec.PHASES:
        start = one([row for row in history if row['event'] == 'phase_started' and row['phase'] == phase], 'phase-start')
        end = one([row for row in history if row['event'] == 'phase_finished' and row['phase'] == phase], 'phase-end')
        group = [call for call in calls.values() if call['item']['phase'] == phase]
        need(start['calls'] == [item['id'] for item in planned.values() if item['phase'] == phase]
             and end['calls'] == end['posts'] == len(group) and end['failures'] == 0, 'phase-counts')
        need(all(moment(start) < moment(c['begin']) < moment(c['finish']) < moment(end)
                 and moment(c['terminal']) < moment(end) for c in group), 'phase-interval')
        need(concurrent([(moment(c['begin']), moment(c['finish'])) for c in group]) <=
             (spec.CLIENT_INFLIGHT if phase == 'overload' else 1), 'client-inflight-bound')
    return calls, history


def arrivals(calls, history):
    group = {i: call for i, call in calls.items() if call['item']['phase'] == 'overload'}
    offered = [row for row in history if row['event'] == 'call_offered']
    need(len(offered) == len(group) and {row['id'] for row in offered} == set(group), 'offered-denominator')
    start = one([row for row in history if row['event'] == 'phase_started' and row['phase'] == 'overload'], 'phase-start')
    finish = one([row for row in history if row['event'] == 'arrivals_finished'], 'arrivals-finished')
    origin = int(start['origin_ns'])
    need(0 < origin <= moment(start) and moment(finish) >= origin + spec.DURATION_MS * 1_000_000
         and finish['planned'] == len(group), 'original-arrival-window')
    lag = []
    for row in offered:
        call = group[row['id']]
        scheduled = origin + call['item']['offset_ns']
        need(int(row['scheduled_ns']) == int(call['begin']['scheduled_ns']) == scheduled, 'fixed-arrival-schedule')
        need(scheduled <= moment(row) < moment(call['begin']), 'offered-order')
        need(type(row['active']) is int and 0 <= row['active'] < spec.CLIENT_INFLIGHT, 'client-inflight-bound')
        delay = (moment(call['begin']) - scheduled) / 1e6
        need(delay <= spec.MAX_OFFER_LAG_MS, 'offered-rate-not-reached')
        lag.append(delay)
    hot = [c for c in group.values() if c['item']['lane'] == 'hot']
    need(any(c['finish']['error'] and c['finish']['error'].get('code') == 'BACKPRESSURE' for c in hot),
         'overload-not-observed')
    windows = []
    for offset in range(0, spec.DURATION_MS, spec.PROGRESS_WINDOW_MS):
        progress = {}
        for lane in spec.ARRIVALS:
            subset = [c for c in group.values() if c['item']['lane'] == lane and
                      offset * 1_000_000 <= c['item']['offset_ns'] < (offset + spec.PROGRESS_WINDOW_MS) * 1_000_000]
            end_ns = origin + (offset + spec.PROGRESS_WINDOW_MS) * 1_000_000
            success = [c for c in subset if c['finish']['ok'] and moment(c['finish']) <= end_ns
                       and (lane != 'hot' or c['finish']['state'] == 'committed')]
            need(bool(success), 'tenant-window-progress')
            progress[lane] = {'offered': len(subset), 'completed_successfully_in_window': len(success),
                              'outcomes': dict(Counter(c['category'] for c in subset))}
        windows.append({'offset_ms': offset, 'lanes': progress})
    return {'duration_ms': spec.DURATION_MS, 'offered': len(group),
            'scheduled_per_second': len(group) * 1000 / spec.DURATION_MS,
            'generator_rejected': 0, 'offer_lag_ms': percentiles(lag), 'progress_windows': windows}


def results(directory, calls):
    committed, final, expected_acks = {}, {}, {}
    originals = {i for i, c in calls.items() if c['item']['operation'] == 'execute'}
    for identifier, call in calls.items():
        item, envelope = call['item'], call['value']
        if envelope is None or not envelope['ok'] or item['operation'] not in ('execute', 'lookup', 'cancel'):
            continue
        value, original = envelope['value'], item.get('original', identifier)
        if value.get('state') == 'committed':
            try:
                data, decoded = wire.committed(value)
            except (ValueError, KeyError):
                raise Rejected('committed-wire') from None
            same(value['receipt']['request'], call['body']['request'], 'receipt-request')
            same(value['receipt']['scope'], call['body']['scope'], 'receipt-scope')
            if original in committed:
                same(value['receipt'], committed[original]['receipt'], 'original-receipt')
                need(data == committed[original]['raw'], 'original-result')
            else:
                committed[original] = {'receipt': value['receipt'], 'raw': data, 'decoded': decoded}
            if call['finish']['ok'] or call['finish']['error'].get('outcome') == 'committed':
                expected_acks[identifier] = (value['receipt'], data, original)
        elif value.get('state') == 'cancelled':
            need(value['transition']['nonce'] == call['body']['request']['id'], 'cancellation-identity')
        else:
            need(value.get('state') == 'unknown' and item['operation'] == 'lookup', 'request-resolution')
        if item.get('original') and identifier.endswith('-2'):
            need(value.get('state') in ('committed', 'cancelled'), 'final-original-resolution')
            final[original] = value['state']
    need(set(final) == originals, 'resolution-denominator')
    need({i for i, state in final.items() if state == 'committed'} == set(committed), 'final-commit-set')
    acks = rows(directory / 'acks.jsonl')
    need(len(acks) == len(expected_acks) and {row['id'] for row in acks} == set(expected_acks), 'ack-denominator')
    for row in acks:
        receipt, data, original = expected_acks[row['id']]
        same(row['receipt'], receipt, 'ack-receipt')
        need(raw(directory, row['result']) == data and row['original'] == original, 'ack-result')
        need(moment(calls[row['id']]['terminal']) < moment(row) < moment(calls[row['id']]['finish']),
             'ack-persisted-before-return')
    expected = {name: {} for name in spec.SCOPES}
    for original, record in committed.items():
        item = calls[original]['item']
        if item.get('kind') != 'insert':
            continue
        need(len(record['decoded']) == len(item['rows']), 'batch-statement-count')
        for number, table in zip(item['rows'], record['decoded']):
            need(number not in expected[item['scope']], 'duplicate-business-row')
            expected[item['scope']][number] = spec.payload(number)
            need(table['columns'] == ['id', 'payload', 'witness'] and len(table['rows']) == 1
                 and table['rows'][0][:2] == [number, spec.payload(number)]
                 and type(table['rows'][0][2]) is int, 'original-insert-result')
    for name in ('single', 'batch'):
        need(set(expected[name]) == set(range(spec.LOGICAL_ROWS)), 'same-logical-work')
    audited = set()
    for identifier, call in calls.items():
        item = call['item']
        if item['operation'] != 'query' or not call['finish']['ok']:
            continue
        decoded = wire.result(wire.b64(call['value']['value']['result']))
        need(len(decoded) == 1, 'query-statements')
        wanted = expected[item['scope']]
        if item['kind'] == 'all_rows':
            need(decoded[0]['columns'] == ['id', 'payload'] and decoded[0]['rows'] ==
                 [[number, wanted[number]] for number in sorted(wanted)], 'complete-business-values')
            audited.add(item['scope'])
        else:
            need(decoded[0]['columns'] == ['n', 'total'] and decoded[0]['rows'] == [[len(wanted), sum(wanted)]],
                 'count-result')
    need(audited == set(spec.SCOPES), 'data-audit-denominator')
    return committed, {'original_executes': len(originals), 'final_states': dict(Counter(final.values())),
                       'ack_observations': len(acks), 'verified_rows': {name: len(v) for name, v in expected.items()}}


def audit(directory):
    directory = Path(directory)
    inputs = wire.parse((directory / 'inputs.json').read_bytes())
    identity(directory, inputs)
    config = wire.parse((directory / 'service-config.json').read_bytes())
    for key, value in (('admission', spec.ADMISSION), ('cache', spec.CACHE), ('transport', spec.TRANSPORT), ('output', spec.OUTPUT)):
        same(config[key], value, 'fixed-service-profile')
    need(config['worker_instance'] == str(spec.WORKER) and config['s3']['timeout_ms'] == 15000
         and config['execution'] == {'result_memory_bytes': 134217728}, 'fixed-runtime-profile')
    planned = workload(directory)
    calls, history = http(directory, planned, config)
    offered = arrivals(calls, history)
    committed, result_summary = results(directory, calls)
    events = rows(directory / 'events.jsonl')
    need([row['sequence'] for row in events] == list(range(1, len(events) + 1)), 'event-sequence')
    # Imported only at the audit boundary: these files use this independent
    # reader's helpers and never load the service or runner.
    import wire_audit
    import resource_audit
    network = wire_audit.audit(directory, calls, committed, events)
    resource_summary = resource_audit.audit(directory, events, inputs)
    measured = {}
    for phase in spec.MEASURED:
        group = [c for c in calls.values() if c['item']['phase'] == phase]
        elapsed = (max(moment(c['finish']) for c in group) - min(moment(c['begin']) for c in group)) / 1e9
        need(elapsed > 0, 'measurement-time')
        counter = Counter(c['category'] for c in group)
        selected = [r for r in network['requests'].values() if r['phase'] == phase]
        successful = [c for c in group if c['finish']['ok'] and c['item']['operation'] == 'execute'
                      and c['finish']['state'] == 'committed']
        logical = sum(len(c['item'].get('rows', [])) for c in successful)
        measured[phase] = {'offered': len(group), 'outcomes': dict(counter), 'elapsed_seconds_with_drain': elapsed,
            'successful_transactions': len(successful), 'successful_logical_operations': logical,
            'successful_transactions_per_second': len(successful) / elapsed,
            'successful_logical_operations_per_second': logical / elapsed,
            'call_latency_ms': percentiles([(moment(c['finish']) - moment(c['begin'])) / 1e6 for c in group]),
            'latency_from_planned_arrival_ms': percentiles([
                (moment(c['finish']) - int(c['begin']['scheduled_ns'])) / 1e6 for c in group]),
            's3_requests': len(selected), 's3_methods': dict(Counter(r['method'] for r in selected)),
            's3_request_body_bytes': sum(r['request_bytes'] for r in selected),
            's3_response_body_bytes': sum(network['responses'][serial]['response_bytes']
                for serial, row in network['requests'].items() if row['phase'] == phase)}
    return {'status': 'PASSED', 'http_posts': len(calls), 'all_outcomes': dict(Counter(c['category'] for c in calls.values())),
            'open_loop': offered, 'measured': measured, 'results': result_summary,
            'resources': resource_summary, 's3_authority': network['authority'],
            's3_requests': len(network['requests']), 'worker_claims': network['worker_claims'],
            'publication_closures': network['publication_closures'],
            'aws_standard': 'NOT_RUN', 'production_slo_passed': False,
            'sampled_resource_peak_is_hard_bound': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('evidence', type=Path)
    print(json.dumps(audit(parser.parse_args().evidence), sort_keys=True))
