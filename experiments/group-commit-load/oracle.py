#!/usr/bin/env python3
"""Independent raw HTTP/S3 audit and paired measurements; no runner/product imports."""
import argparse
import base64
from collections import Counter, defaultdict
import hashlib
import json
import math
from pathlib import Path
import re
import sqlite3
import struct
import tarfile
import tempfile

import shared
import spec

wire = shared.module('group_load_independent_wire', shared.ROOT / 'experiments/object-service/audit_wire.py')
HEAD = '/scap-test/scap-object/v1/1/7/1301/head'
PREFIX = '/scap-test/scap-object/v1/1/7/1301/inc/1/gen/1/storage/1/objects/'
WORKER = '/scap-test/scap-worker/v1/instances/' + str(spec.WORKER)


class Rejected(ValueError):
    def __init__(self, rule):
        self.rule = rule
        super().__init__(rule)


def need(value, rule):
    if not value:
        raise Rejected(rule)


def same(left, right, rule):
    need(left == right, rule)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def moment(row):
    value = row['monotonic_ns']
    need(type(value) is int or type(value) is str and value.isascii() and value.isdecimal(), 'clock-format')
    need(int(value) > 0, 'clock-format')
    return int(value)


def one(values, rule):
    need(len(values) == 1, rule)
    return values[0]


def rows(path):
    need(path.is_file() and not path.is_symlink(), 'ledger-missing')
    with path.open('rb') as stream:
        result = []
        while line := stream.readline(1024 * 1024 + 1):
            need(line.endswith(b'\n') and len(line) <= 1024 * 1024, 'ledger-framing')
            result.append(wire.parse(line))
            need(len(result) <= spec.BOUNDS['trace_rows'], 'ledger-bound')
    return result


def raw(directory, value):
    need(type(value) is dict and set(value) == {'file', 'bytes', 'sha256'}, 'raw-description')
    need(type(value['file']) is str and re.fullmatch('raw/[0-9a-f]{64}', value['file'])
         and value['file'] == 'raw/' + value['sha256'], 'raw-path')
    path = directory / value['file']
    need(path.is_file() and not path.is_symlink(), 'raw-missing')
    need(type(value['bytes']) is int and 0 <= value['bytes'] <= spec.BOUNDS['body_bytes']
         and path.stat().st_size == value['bytes'], 'raw-integrity')
    data = path.read_bytes()
    need(digest(data) == value['sha256'], 'raw-integrity')
    return data


def percentiles(values):
    need(all(type(n) in (int, float) and math.isfinite(n) and n >= 0 for n in values), 'latency-values')
    ordered = sorted(values)
    return {'samples': len(values), **{name: ordered[math.ceil(fraction * len(ordered)) - 1] if ordered else None
            for name, fraction in (('p50', .5), ('p95', .95), ('p99', .99))},
            'maximum': ordered[-1] if ordered else None}


def archive(path, expected, rule):
    with tarfile.open(path) as stream:
        members = stream.getmembers()
        need(len(members) == len(expected) and {m.name for m in members} == set(expected), rule)
        for member in members:
            need(member.isfile() and digest(stream.extractfile(member).read()) == expected[member.name], rule)


def provenance(directory):
    inputs = wire.parse((directory / 'inputs.json').read_bytes())
    expected = {path.relative_to(shared.ROOT).as_posix(): digest(path.read_bytes()) for path in shared.fixture_files()}
    same(inputs['fixture'], expected, 'fixture-source')
    same(wire.parse((directory / 'fixture-after.json').read_bytes()), expected, 'fixture-after')
    need(digest((directory / 'fixture-source.tar').read_bytes()) == inputs['fixture_archive_sha256'], 'fixture-archive')
    archive(directory / 'fixture-source.tar', expected, 'fixture-archive')
    root = directory / 'build'
    receipt = wire.parse((root / 'build-receipt.json').read_bytes())
    need(receipt['status'] == 'passed' and receipt['profile'] == 'release' and receipt['exit_code'] == 0,
         'runtime-build')
    same(receipt['binary'], inputs['tools']['scapd'], 'runtime-binary')
    same(receipt['source_commit'], inputs['build_source_commit'], 'runtime-commit')
    saved = receipt['archived_evidence']
    for name in ('source_archive', 'source_manifest'):
        need(digest((root / saved[name]).read_bytes()) == saved[name + '_sha256'], 'runtime-archive')
    manifest = wire.parse((root / saved['source_manifest']).read_bytes())
    same(manifest, {'schema': 1, 'source_commit': receipt['source_commit'], 'inputs': receipt['inputs']},
         'runtime-manifest')
    archive(root / saved['source_archive'], receipt['inputs'], 'runtime-source-bytes')
    for name in ('cargo.stdout.jsonl', 'cargo.stderr.log'):
        need(digest((root / ('build-' + name)).read_bytes()) == receipt[name + '_sha256'], 'runtime-build-log')
    cargo = rows(root / 'build-cargo.stdout.jsonl')
    need(cargo[-1].get('reason') == 'build-finished' and cargo[-1].get('success') is True, 'runtime-build-finished')
    for name in ('experiments/object-service/audit_wire.py', 'experiments/object-network/head5_audit.py'):
        need(expected[name] == receipt['inputs'][name], 'independent-reader-source')
    return inputs


def statements(item):
    return [{'sql': statement['sql'], 'params': [
        {'type': 'integer', 'value': value['integer']} if 'integer' in value else
        {'type': 'blob', 'base64': base64.b64encode(spec.payload(value['payload_row'])).decode()}
        for value in statement['params']]} for statement in item['statements']]


def intent(item):
    return {'epoch': '1', 'id': item['request_id'], 'principal': '11',
            'fingerprint': wire.fingerprint(statements(item))}


def observed_outcome(call):
    finish = call['finish']
    if finish['ok']:
        return 'success'
    error = finish['error']
    if error.get('outcome') == 'committed':
        return 'committed_unavailable'
    if error.get('outcome') == 'unknown' or error.get('code') in ('UNKNOWN', 'UNAVAILABLE', 'DEADLINE'):
        return 'unknown'
    return 'rejected' if error.get('name') == 'RemoteError' else 'transport_error'


def validate_terminal(start, finish, terminal, reply, operation='execute'):
    """Bind SDK accounting to the separately captured original HTTP terminal."""
    need(moment(start) < moment(finish), 'http-clock')
    need(moment(terminal) < moment(finish), 'http-terminal-before-finish')
    error = finish['error']
    sdk_end = int(finish['sdk_terminal_ns'])
    need(moment(start) < sdk_end <= moment(finish), 'sdk-terminal-clock')
    if isinstance(error, dict) and error.get('cause_code') == 'DEADLINE':
        # The SDK may lose its fetch/reader Promise race before the observer
        # drains a full response. A non-committed synchronous decode can also
        # cross the same original deadline. Neither makes a write an ACK.
        budget = spec.DEADLINES['client_recovery_ms' if operation == 'activate' else 'client_ms']
        need(not finish['ok'] and sdk_end - moment(start) >= budget * 1000000, 'sdk-transport-deadline')
        need(finish['state'] is None, 'sdk-http-outcome')
        if operation in ('status', 'query'):
            need(error.get('name') == 'ClientError' and error.get('code') == 'DEADLINE'
                 and error.get('outcome') is None, 'sdk-http-outcome')
        else:
            need(error.get('name') == 'UnknownError' and error.get('code') == 'UNKNOWN'
                 and error.get('outcome') == 'unknown', 'sdk-http-outcome')
        return
    if reply is not None:
        need(moment(terminal) <= sdk_end, 'sdk-response-before-terminal')
    if reply is not None and reply['ok'] is True:
        need(terminal['status'] == 200, 'http-success')
        if finish['ok']:
            need(error is None, 'sdk-http-outcome')
            same(finish['state'], reply['value'].get('state'), 'sdk-state')
        else:
            # This bounded workload cannot exceed the fixed decoder budget. A
            # verified commit may still cross the original synchronous decode
            # deadline, which the public SDK reports with its exact receipt.
            need(isinstance(error, dict) and error.get('name') == 'CommittedResultError' and
                 error.get('code') == 'DEADLINE' and error.get('outcome') == 'committed' and
                 reply['value'].get('state') == 'committed', 'sdk-http-outcome')
            need(int(finish['sdk_terminal_ns']) - moment(start) >= spec.DEADLINES['client_ms'] * 1000000,
                 'sdk-committed-deadline')
            same(error.get('receipt'), reply['value']['receipt'], 'sdk-committed-receipt')
            need('raw_result' in error, 'sdk-committed-result')
    elif reply is not None:
        need(reply['ok'] is False and not finish['ok'] and isinstance(error, dict), 'sdk-http-outcome')
        code = reply['error']['code']
        same(error.get('code'), code, 'sdk-error-code')
        if 'receipt' in reply['error']:
            need(code == 'COMMITTED_BUT_UNAVAILABLE' and error.get('name') == 'CommittedResultError' and
                 error.get('outcome') == 'committed', 'sdk-http-outcome')
            same(error.get('receipt'), reply['error']['receipt'], 'sdk-committed-receipt')
        elif code == 'UNKNOWN':
            need(error.get('name') == 'UnknownError' and error.get('outcome') == 'unknown', 'sdk-http-outcome')
        else:
            need(error.get('name') == 'RemoteError' and error.get('outcome') == 'unresolved', 'sdk-http-outcome')
    else:
        need(terminal['event'] == 'http_error' and not finish['ok'] and isinstance(error, dict), 'sdk-http-outcome')
        if operation in ('status', 'query'):
            need(error.get('name') == 'ClientError' and error.get('code') in ('TRANSPORT', 'DEADLINE')
                 and error.get('outcome') is None, 'sdk-http-outcome')
        else:
            need(error.get('name') == 'UnknownError' and error.get('code') == 'UNKNOWN' and
                 error.get('outcome') == 'unknown', 'sdk-http-outcome')


def measured_elapsed(origin, arrival_finished, endings):
    return max(arrival_finished, *endings) - origin


def active_bounds(row, calls):
    # The outer scheduler removes a task in a later Promise microtask than the
    # inner call_finished record. A finished task may still occupy a slot, so
    # use proven bounds rather than an incorrect timestamp equality.
    started = sum(moment(call['start']) < moment(row) for call in calls)
    unfinished = sum(moment(call['start']) < moment(row) < moment(call['finish']) for call in calls)
    need(type(row['active']) is int and unfinished <= row['active'] <= started
         and row['active'] < spec.PLAN['client_inflight_limit'], 'generator-active-count')


def client(directory, config, history, prepares):
    planned = {item['id']: item for item in spec.calls()}
    originals = {key: item for key, item in planned.items() if item['operation'] == 'execute'}
    events = defaultdict(dict)
    allowed = {'phase_started', 'phase_finished', 'call_offered', 'arrivals_finished',
               'generator_rejected', 'call_started', 'call_finished', 'http_request', 'http_response', 'http_error'}
    for row in history:
        need(row['event'] in allowed, 'client-event-kind')
        if 'id' in row:
            need(row['id'] not in events[row['event']], 'http-denominator')
            events[row['event']][row['id']] = row
    need(len(prepares) == len(originals) and {row['id'] for row in prepares} == set(originals), 'intent-denominator')
    for row in prepares:
        saved = wire.parse(raw(directory, row['serialized']))
        same(saved['scope'], spec.SCOPE, 'intent-scope')
        same(saved['request'], intent(originals[row['id']]), 'intent-identity')
        same(saved['statements'], statements(originals[row['id']]), 'intent-statements')
    rejected = events['generator_rejected']
    need(set(rejected) <= {key for key, item in planned.items() if item['phase'] in spec.PHASES}, 'generator-denominator')
    # Even if every previous task remains active, the frozen phase offers at
    # most 132 calls against 192 slots. A client-capacity rejection is impossible.
    need(all(sum(item['phase'] == phase for item in planned.values()) < spec.PLAN['client_inflight_limit']
             for phase in spec.PHASES) and not rejected, 'generator-impossible-rejection')
    sent_ids = set(events['http_request'])
    need(set(events['call_started']) == set(events['call_finished']) == sent_ids, 'http-denominator')
    need(sent_ids.isdisjoint(rejected) and set(planned) - set(rejected) <= sent_ids, 'original-denominator')
    need(set(events['http_response']).isdisjoint(events['http_error']) and
         set(events['http_response']) | set(events['http_error']) == sent_ids, 'http-terminal-denominator')
    calls = {}
    for identifier in sent_ids:
        start, finish, request = (events[key][identifier] for key in ('call_started', 'call_finished', 'http_request'))
        terminal = events['http_response'].get(identifier) or events['http_error'][identifier]
        need(moment(start) < moment(request) < moment(terminal) and moment(start) < moment(finish), 'http-clock')
        need(finish['posts'] == 1 and request['method'] == 'POST' and request['redirect'] == 'error', 'single-original-post')
        need(request['token_sha256'] == config['credentials'][0]['sha256'] and
             request['url'] == 'http://' + config['listen'] + '/v1', 'http-route-credential')
        body = wire.parse(raw(directory, request['request']))
        same(body['scope'], spec.SCOPE, 'http-scope')
        need(body['version'] == 1 and type(finish['ok']) is bool, 'http-shape')
        reply = wire.parse(raw(directory, terminal['response'])) if terminal['event'] == 'http_response' else None
        validate_terminal(start, finish, terminal, reply, body['operation'])
        if reply is not None and reply['ok'] and not finish['ok'] and finish['error'].get('outcome') == 'committed':
            same(raw(directory, finish['error']['raw_result']), wire.b64(reply['value']['result']), 'sdk-committed-result')
        calls[identifier] = {'body': body, 'reply': reply, 'start': start, 'finish': finish,
                             'request': request, 'terminal': terminal}
    for identifier, item in planned.items():
        if identifier in rejected:
            need(rejected[identifier]['posts'] == 0 and rejected[identifier]['reason'] == 'client_inflight_limit',
                 'generator-outcome')
            continue
        call = calls[identifier]
        expected = {'version': 1, 'scope': spec.SCOPE, 'operation': item['operation']}
        if item['operation'] == 'execute':
            expected.update(request=intent(item), statements=statements(item))
        elif item['operation'] == 'create':
            expected['nonce'] = item['nonce']
        elif item['operation'] == 'activate':
            expected.update(nonce=item['nonce'], expected_revision='1')
        same(call['body'], expected, 'original-http-input')
        same(call['start']['phase'], item['phase'], 'original-phase')
    measured = {}
    for phase, settings in spec.PHASES.items():
        selected = {key: item for key, item in planned.items() if item['phase'] == phase}
        start = one([row for row in history if row['event'] == 'phase_started' and row['phase'] == phase], 'phase-boundary')
        finish = one([row for row in history if row['event'] == 'phase_finished' and row['phase'] == phase], 'phase-boundary')
        drained = one([row for row in history if row['event'] == 'arrivals_finished' and row['phase'] == phase], 'arrival-boundary')
        origin = int(start['origin_ns'])
        need(moment(drained) >= origin + settings['duration_ms'] * 1000000 and moment(finish) >= moment(drained), 'arrival-duration')
        offered = {key: row for key, row in events['call_offered'].items() if row['phase'] == phase}
        same(set(offered), set(selected), 'arrival-denominator')
        lags, latencies, service_latencies, controls = [], defaultdict(list), defaultdict(list), []
        outcomes = Counter()
        endings = []
        for key, item in selected.items():
            schedule = origin + item['offset_ns']
            row = offered[key]
            need(int(row['scheduled_ns']) == schedule and moment(row) >= schedule, 'fixed-arrival')
            active_bounds(row, [call for identifier, call in calls.items() if identifier in selected])
            lags.append((moment(row) - schedule) / 1e6)
            if key in rejected:
                end, outcome = moment(rejected[key]), 'generator_rejected'
                need(row['active'] >= spec.PLAN['client_inflight_limit'], 'generator-capacity')
            else:
                call = calls[key]
                need(int(call['start']['scheduled_ns']) == schedule and moment(call['start']) >= moment(row), 'offered-before-call')
                end, outcome = moment(call['finish']), observed_outcome(call)
            need(end <= moment(finish), 'phase-drained')
            if item['operation'] == 'execute':
                outcomes[outcome] += 1
                latencies[outcome].append((end - schedule) / 1e6)
                endings.append(end)
                if key not in rejected:
                    service_latencies[outcome].append((end - moment(calls[key]['start'])) / 1e6)
            else:
                controls.append({'outcome': outcome, 'milliseconds': (end - schedule) / 1e6})
        need(max(lags) <= spec.PLAN['max_offer_lag_ms'], 'offered-lag')
        need(sum(outcomes.values()) == settings['count'], 'measured-denominator')
        need(sum(len(value) for value in service_latencies.values()) == settings['count'] -
             sum(key in rejected for key, item in selected.items() if item['operation'] == 'execute'), 'sql-latency-denominator')
        elapsed = measured_elapsed(origin, moment(drained), endings)
        measured[phase] = {'offered_transactions': settings['count'], 'terminal_counts': dict(outcomes),
            'success_rate': outcomes['success'] / settings['count'],
            'offered_rate_per_second': settings['rate'], 'drained_seconds': elapsed / 1e9,
            'successful_transactions_per_second_until_drained': outcomes['success'] * 1e9 / elapsed,
            'scheduled_to_terminal_ms': {key: percentiles(value) for key, value in latencies.items()},
            'scheduled_to_terminal_all_ms': percentiles([n for value in latencies.values() for n in value]),
            'invoke_to_terminal_ms': {key: percentiles(value) for key, value in service_latencies.items()},
            'offer_lag_ms': percentiles(lags), 'control_outcomes': dict(Counter(row['outcome'] for row in controls)),
            'control_scheduled_to_terminal_ms': percentiles([row['milliseconds'] for row in controls])}
    return planned, calls, measured


def settlement(planned, calls):
    originals = {key: item for key, item in planned.items() if item['operation'] == 'execute'}
    permitted = set(planned) | {'final'}
    committed, cancelled = {}, set()
    for key, item in originals.items():
        identifier = 'lookup-' + key
        permitted.add(identifier)
        need(identifier in calls and calls[identifier]['finish']['ok'], 'lookup-denominator')
        lookup = calls[identifier]
        expected = {'version': 1, 'scope': spec.SCOPE, 'operation': 'lookup', 'request': intent(item)}
        same(lookup['body'], expected, 'lookup-original-identity')
        value = lookup['reply']['value']
        if value['state'] == 'unknown':
            permitted.update(('cancel-' + key, 'settled-' + key))
            for name, operation in (('cancel-' + key, 'cancel'), ('settled-' + key, 'lookup')):
                need(name in calls and calls[name]['finish']['ok'], 'settlement-denominator')
                same(calls[name]['body'], {**expected, 'operation': operation}, 'settlement-original-identity')
            cancelled_value = calls['cancel-' + key]['reply']['value']
            value = calls['settled-' + key]['reply']['value']
            need(value['state'] in ('committed', 'cancelled'), 'settlement-terminal')
            same(value, cancelled_value, 'settlement-stable')
        need(value['state'] in ('committed', 'cancelled'), 'settlement-terminal')
        original = calls.get(key)
        if value['state'] == 'committed':
            need(original is not None, 'never-dispatched-commit')
            result, decoded = wire.committed(value)
            same(value['receipt']['request'], intent(item), 'receipt-original-identity')
            if original['reply'] is not None and original['reply']['ok']:
                same(value, original['reply']['value'], 'original-random-result')
            if original['reply'] is not None and not original['reply']['ok'] and 'receipt' in original['reply']['error']:
                same(value['receipt'], original['reply']['error']['receipt'], 'original-committed-receipt')
            if key != 'schema':
                need(len(decoded) == 1 and decoded[0]['columns'] == ['id', 'payload', 'witness']
                     and len(decoded[0]['rows']) == 1 and decoded[0]['affected_rows'] == 1, 'result-shape')
                row = decoded[0]['rows'][0]
                same(row[:2], [item['row'], spec.payload(item['row'])], 'result-original-input')
                need(type(row[2]) is int, 'random-witness')
            committed[key] = {'value': value, 'raw': result, 'decoded': decoded}
        else:
            need(original is None or not original['finish']['ok'], 'ack-lost-after-settlement')
            cancelled.add(key)
    same(set(calls) - set(planned), permitted - set(planned), 'verification-call-denominator')
    need('schema' in committed and calls['create']['finish']['ok'] and calls['activate']['finish']['ok'], 'seed-success')
    final = calls['final']
    same(final['body'], {'version': 1, 'scope': spec.SCOPE, 'operation': 'query',
         'statements': [{'sql': spec.ALL_ROWS, 'params': []}]}, 'final-query-input')
    need(final['finish']['ok'], 'final-query-success')
    decoded = wire.result(wire.b64(final['reply']['value']['result']))
    expected_rows = sorted((entry['decoded'][0]['rows'][0] for key, entry in committed.items() if key != 'schema'), key=lambda row: row[0])
    need(len(decoded) == 1 and decoded[0]['columns'] == ['id', 'payload', 'witness'], 'final-row-shape')
    same(decoded[0]['rows'], expected_rows, 'final-rows')
    return committed, cancelled, expected_rows


def frame(data, key):
    need(len(data) >= 20 and data[:8] == b'SCAPOBJ2' and key == PREFIX + digest(data), 'immutable-frame')
    size, length = struct.unpack_from('<IQ', data, 8)
    need(size <= 65516 and 20 + size + length == len(data), 'immutable-frame-length')
    header = wire.parse(data[20:20 + size])
    same(header['scope'], {key: int(value) for key, value in spec.SCOPE.items()}, 'immutable-scope')
    need(header['format'] == 2, 'immutable-format')
    return header['payload']['kind'], header['payload']['value'], data[20 + size:]


def closure(objects, head):
    wire.head5_profile(head)
    same(head['scope'], {key: int(value) for key, value in spec.SCOPE.items()}, 'head-scope')
    need(len(head['windows']) == 1 and head['windows'][0]['epoch'] == head['request_epoch'] == 1, 'retained-epoch')
    dependencies, visiting = set(), set()
    def load(checksum, expected):
        key = PREFIX + checksum
        need(key in objects, 'publication-closure')
        kind, value, data = frame(objects[key], key)
        need(kind == expected, 'dependency-type')
        dependencies.add(key)
        return value, data
    manifest, body = load(head['data_root'], 'manifest')
    need(not body and 0 <= manifest['page_count'] <= 32, 'fixed-image-bound')
    if manifest['page_count']:
        node, body = load(manifest['root'], 'node')
        need(not body and node['level'] == node['first_chunk'] == 0 and len(node['children']) == 1, 'fixed-image-node')
        chunk, image = load(node['children'][0], 'chunk')
        need(chunk == {'first_page': 1, 'bytes': []} and len(image) == manifest['page_count'] * 4096, 'fixed-image-chunk')
    else:
        need(manifest['root'] is None, 'empty-image')
        image = b''
    def index(checksum):
        need(checksum not in visiting and len(visiting) < 12, 'index-cycle')
        visiting.add(checksum)
        value, body = load(checksum, 'index')
        need(not body and value['epoch'] == 1, 'index-epoch')
        if value['kind'] == 'leaf':
            entries = value['entries']
        else:
            need(value['kind'] == 'branch' and 0 < len(value['children']) <= 256, 'index-branch')
            entries = [entry for child in value['children'] for entry in index(child['hash'])]
        visiting.remove(checksum)
        return entries
    entries = index(head['windows'][0]['root'])
    need(len(entries) == head['windows'][0]['count'] <= 161 and
         sum(entry['result_bytes'] for entry in entries) == head['windows'][0]['result_bytes'], 'retained-denominator')
    ids = [entry['request']['id'] for entry in entries]
    need(ids == sorted(set(ids)), 'retained-order')
    stored = {}
    for entry in entries:
        need(entry['request']['epoch'] == 1 and entry['request']['principal'] == 11, 'retained-identity')
        outcome = entry['outcome']
        if outcome['state'] == 'committed':
            value, data = load(outcome['result'], 'result')
            need(value['bytes'] == [] and len(data) == entry['result_bytes'], 'retained-result-size')
            same(value['request'], entry['request'], 'retained-result-identity')
            wire.result(data)
            stored[entry['request']['id']] = {'metadata': value, 'raw': data, 'hash': outcome['result']}
        else:
            need(outcome['state'] == 'cancelled' and entry['result_bytes'] == 0, 'retained-cancellation')
    return {'dependencies': dependencies, 'entries': {entry['request']['id']: entry for entry in entries},
            'stored': stored, 'image': image}


def publication(previous, current, before, after, enabled):
    old, new = before['entries'], after['entries']
    need(set(old) <= set(new) and all(old[key] == new[key] for key in old), 'retained-unchanged')
    added = set(new) - set(old)
    count = current['sequence'] - previous['sequence']
    need(count >= 0, 'sequence-regression')
    if count:
        need(1 <= count <= (spec.PROFILE['max_members'] if enabled else 1), 'group-width')
        need(len(added) == count and all(new[key]['outcome']['state'] == 'committed' for key in added), 'group-fresh-identities')
        ordered = sorted((after['stored'][key]['metadata'] for key in added), key=lambda value: value['sequence'])
        for offset, value in enumerate(ordered, 1):
            need(value['sequence'] == previous['sequence'] + offset and
                 value['transition'] == {'revision': previous['revision'] + offset, 'nonce': value['request']['id']},
                 'group-member-sequence')
        last = ordered[-1]
        allowed = dict(previous, revision=previous['revision'] + count, sequence=previous['sequence'] + count,
            head_serial=previous['head_serial'] + count, transition=last['transition'],
            data_root=last['data_root'], windows=current['windows'])
    else:
        need(len(added) <= 1, 'control-width')
        allowed = dict(previous, revision=previous['revision'] + 1, head_serial=previous['head_serial'] + 1,
                       transition=current['transition'])
        if added:
            key = next(iter(added))
            need(new[key]['outcome']['state'] == 'cancelled' and
                 current['transition'] == {'revision': allowed['revision'], 'nonce': key}, 'control-cancellation')
            allowed['windows'] = current['windows']
        else:
            need(not previous['active'] and current['active'] and current['transition']['nonce'] == 2, 'control-activation')
            allowed['active'] = True
    same(current, allowed, 'protected-head-fields')
    return count


def phase_intervals(events):
    phases = ('seed', *spec.PHASES, 'verify')
    same([row['phase'] for row in events if row['event'] == 'phase_started'], list(phases), 'runner-phase-order')
    same([row['phase'] for row in events if row['event'] == 'phase_finished'], list(phases), 'runner-phase-order')
    ranges = {'startup': (moment(one([row for row in events if row['event'] == 'service_start_requested'], 'startup-boundary')),
                          moment(one([row for row in events if row['event'] == 'service_started'], 'startup-boundary')))}
    for phase in phases:
        begin = one([row for row in events if row['event'] == 'phase_started' and row['phase'] == phase], 'runner-phase-boundary')
        end = one([row for row in events if row['event'] == 'phase_finished' and row['phase'] == phase], 'runner-phase-boundary')
        need(moment(begin) < moment(end), 'runner-phase-clock')
        ranges[phase] = moment(begin), moment(end)
    ordered = list(ranges.values())
    need(all(left[1] < right[0] for left, right in zip(ordered, ordered[1:])), 'runner-phase-clock')
    return ranges


def network(directory, history, events, committed, cancelled, calls, final_rows, enabled):
    same([row['sequence'] for row in history], list(range(1, len(history) + 1)), 's3-trace-denominator')
    need(all(row['event'] in ('request', 'forwarded', 'response', 'delivered') for row in history), 'no-artificial-gates')
    groups = defaultdict(list)
    for row in history:
        groups[row['request_serial']].append(row)
    stopped = one([row for row in events if row['event'] == 'proxy_stopped'], 'proxy-stopped')
    need(not stopped['errors'] and sorted(groups) == list(range(1, stopped['request_count'] + 1)), 's3-denominator')
    objects, created, reads, heads, requests, responses = {}, {}, defaultdict(list), [], {}, {}
    metrics = defaultdict(lambda: {'requests': 0, 'request_body_bytes': 0, 'response_body_bytes': 0,
                                    'head_put_attempts': 0, 'head_put_accepted': 0, 'groups': Counter()})
    intervals = phase_intervals(events)
    for serial, items in groups.items():
        q, f, r, d = (one([row for row in items if row['event'] == event], 's3-exchange')
                      for event in ('request', 'forwarded', 'response', 'delivered'))
        need(len(items) == 4 and moment(q) < moment(f) < moment(r) <= moment(d), 's3-clock')
        need(q['phase'] in intervals and intervals[q['phase']][0] < moment(q)
             and moment(r) < intervals[q['phase']][1], 's3-phase-interval')
        for row in items:
            for key in ('phase', 'method', 'path', 'request', 'if_match', 'if_none_match', 'signing'):
                same(row[key], q[key], 's3-request-identity')
        for key in ('status', 'response', 'etag'):
            same(r[key], d[key], 's3-delivery')
        body, reply = raw(directory, q['request']), raw(directory, r['response'])
        need(q['method'] in ('GET', 'PUT') and (q['path'] in (HEAD, WORKER) or
             re.fullmatch(re.escape(PREFIX) + '[0-9a-f]{64}', q['path'])), 's3-namespace')
        need(r['status'] in ((200, 404) if q['method'] == 'GET' else (200, 412)), 's3-status')
        need(q['signing']['payload_sha256'] == digest(body) and
             {'host', 'x-amz-date', 'x-amz-content-sha256'} <= set(q['signing']['signed_headers']), 'signed-s3')
        row = metrics[q['phase']]
        row['requests'] += 1; row['request_body_bytes'] += len(body); row['response_body_bytes'] += len(reply)
        if q['method'] == 'GET':
            need(not body and q['if_match'] is None and q['if_none_match'] is None, 'get-conditions')
            if r['status'] == 200:
                reads[(q['path'], digest(reply))].append((moment(q), moment(r), r['etag']))
        else:
            need((q['if_none_match'] == '*' and q['if_match'] is None) or
                 (q['if_none_match'] is None and isinstance(q['if_match'], str)), 'put-conditions')
            if q['path'] == HEAD:
                row['head_put_attempts'] += 1
            if r['status'] == 200:
                need(bool(r['etag']), 'put-etag')
                if q['path'] == HEAD:
                    row['head_put_accepted'] += 1
                    heads.append((q, r, wire.parse(body)))
                else:
                    need(q['if_none_match'] == '*', 'immutable-create-only')
                    need(q['path'] not in objects, 'immutable-created-once')
                    if q['path'].startswith(PREFIX):
                        frame(body, q['path'])
                    objects[q['path']] = body
                    created[q['path']] = (q, r)
        requests[serial], responses[serial] = q, r
    # Validate each actual original HEAD version; group sizes are observed deltas,
    # and each delta must be backed by independent retained records and results.
    chain = sorted(heads, key=lambda entry: entry[2]['head_serial'])
    need(chain and chain[0][0]['if_none_match'] == '*' and chain[0][2]['sequence'] == 0, 'head-root')
    all_etags = {response['etag'] for _, response, _ in chain}
    need(len(all_etags) == len(chain), 'head-etag-unique')
    by_etag = {response['etag']: raw(directory, request['request']) for request, response, _ in chain}
    for serial, q in requests.items():
        r = responses[serial]
        if q['method'] == 'GET' and r['status'] == 200:
            data = raw(directory, r['response'])
            if q['path'] == HEAD:
                need(r['etag'] in by_etag and data == by_etag[r['etag']], 'observed-head-version')
            else:
                need(q['path'] in objects and data == objects[q['path']], 'observed-immutable-version')
    for index, (q, r, head) in enumerate(chain):
        after = closure(objects, head)
        for key in after['dependencies']:
            need(key in created and moment(created[key][1]) < moment(q) and
                 any(moment(created[key][1]) < end < moment(q) for _, end, _ in reads[(key, digest(objects[key]))]),
                 'closure-before-head')
        if index:
            old_q, old_r, previous = chain[index - 1]
            need(q['if_match'] == old_r['etag'] and moment(old_r) < moment(q), 'original-head-cas')
            need(any(etag == q['if_match'] and end < moment(q) for _, end, etag in reads[(HEAD, digest(raw(directory, old_q['request'])))]),
                 'head-cas-readback')
            count = publication(previous, head, before, after, enabled)
            if count:
                metrics[q['phase']]['groups'][str(count)] += 1
                for identifier in set(after['stored']) - set(before['stored']):
                    stored = after['stored'][identifier]
                    matches = [value for value in committed.values() if int(value['value']['receipt']['request']['id']) == identifier]
                    match = one(matches, 'published-original-result')
                    original_key = one([key for key, value in committed.items()
                                        if value is match], 'published-original-call')
                    need(original_key in calls and moment(calls[original_key]['request']) < moment(q), 'original-request-before-head')
                    receipt = match['value']['receipt']
                    need(receipt['result_hash'] == stored['hash'] and match['raw'] == stored['raw'] and
                         int(receipt['sequence']) == stored['metadata']['sequence'], 'stored-original-result')
                    for call in calls.values():
                        value = call['reply']['value'] if call['reply'] is not None and call['reply']['ok'] else None
                        if value and value.get('state') == 'committed' and int(value['receipt']['request']['id']) == identifier:
                            need(moment(r) < moment(call['terminal']), 'head-before-ack')
        else:
            need(not after['entries'] and head['head_serial'] == head['revision'] == 1, 'head-initial')
        for begin, end, etag in reads[(HEAD, digest(raw(directory, q['request'])))]:
            need(etag == r['etag'] and moment(q) < end and
                 (index + 1 == len(chain) or begin < moment(chain[index + 1][1])), 'head-read-version')
        before = after
    same(set(before['stored']), {int(value['value']['receipt']['request']['id']) for value in committed.values()}, 'durable-committed-denominator')
    planned = {item['id']: item for item in spec.calls()}
    same(set(before['entries']) - set(before['stored']),
         {int(planned[key]['request_id']) for key in cancelled}, 'durable-cancelled-denominator')
    # Independently rebuild the final SQLite file from S3 object bytes.
    with tempfile.TemporaryDirectory(prefix='scap-group-load-audit-') as temporary:
        path = Path(temporary) / 'image.sqlite'
        path.write_bytes(before['image'])
        connection = sqlite3.connect('file:' + str(path) + '?mode=ro&immutable=1', uri=True)
        try:
            same(connection.execute('PRAGMA integrity_check').fetchall(), [('ok',)], 's3-image-integrity')
            same([list(row) for row in connection.execute(spec.ALL_ROWS)], final_rows, 's3-final-rows')
        finally:
            connection.close()
    for row in metrics.values():
        row['groups'] = dict(row['groups'])
        row['independent_transactions_published'] = sum(int(size) * count for size, count in row['groups'].items())
    return {'phases': dict(metrics), 'all_requests': len(groups),
            'all_request_body_bytes': sum(row['request_body_bytes'] for row in metrics.values()),
            'all_response_body_bytes': sum(row['response_body_bytes'] for row in metrics.values()),
            's3_final_rows_verified': len(final_rows), 's3_integrity_check': 'ok'}


def audit_round(directory, enabled, projections=None):
    projections = projections or {}
    load = lambda name: projections.get(name, rows(directory / name))
    config = projections.get('service-config.json', wire.parse((directory / 'service-config.json').read_bytes()))
    expected = spec.configuration(config['listen'], config['cache_directory'], config['s3']['endpoint'],
                                  config['credentials'][0]['sha256'], enabled)
    same(config, expected, 'paired-configuration')
    workload = wire.parse((directory / 'workload.json').read_bytes())
    same(workload['plan'], spec.PLAN, 'fixed-plan')
    same(workload['calls'], spec.calls(), 'fixed-workload')
    same(workload['final_sql'], spec.ALL_ROWS, 'fixed-final-query')
    wanted = {str(item['row']) for item in spec.calls() if 'row' in item}
    same(set(workload['payloads']), wanted, 'payload-denominator')
    for row, description in workload['payloads'].items():
        same(raw(directory, description), spec.payload(int(row)), 'fixed-payload')
    planned, calls, measured = client(directory, config, load('sdk.jsonl'), load('intents.jsonl'))
    committed, cancelled, final_rows = settlement(planned, calls)
    events = load('events.jsonl')
    started = one([row for row in events if row['event'] == 'service_started'], 'owned-service')
    stopped = one([row for row in events if row['event'] == 'service_stopped'], 'owned-service')
    launched = one([row for row in events if row['event'] == 'service_start_requested'], 'owned-service-config')
    need(launched['configuration_sha256'] == digest((directory / 'service-config.json').read_bytes()), 'observed-config-bytes')
    inputs = wire.parse((directory.parent / 'inputs.json').read_bytes())
    backend = one([row for row in events if row['event'] == 'backend_started'], 'owned-backend')
    need(backend['binary_sha256'] == inputs['tools']['weed']['sha256'], 'observed-backend-binary')
    need(started['identity'] == stopped['identity'] and stopped['status'] == 0 and stopped['cache_empty'], 'service-cleanup')
    for phase in ('seed', *spec.PHASES, 'verify'):
        begin = one([row for row in events if row['event'] == 'node_started' and row['phase'] == phase], 'owned-node')
        end = one([row for row in events if row['event'] == 'node_stopped' and row['phase'] == phase], 'owned-node')
        need(begin['identity'] == end['identity'] and end['status'] == 0, 'node-cleanup')
        need(begin['binary_sha256'] == inputs['tools']['node']['sha256'], 'observed-node-binary')
    samples = load('resources.jsonl')
    need(samples and all(row['identity'] == started['identity'] and
         moment(started) < moment(row) < moment(stopped) for row in samples), 'resource-identity')
    net = network(directory, load('s3.jsonl'), events, committed, cancelled, calls, final_rows, enabled)
    for phase, row in measured.items():
        row['s3'] = net['phases'].get(phase, {})
        row['settled_committed'] = sum(key in committed for key, item in planned.items()
                                       if item['phase'] == phase and item['operation'] == 'execute')
        row['settled_cancelled'] = sum(key in cancelled for key, item in planned.items()
                                       if item['phase'] == phase and item['operation'] == 'execute')
        need(row['settled_committed'] + row['settled_cancelled'] == row['offered_transactions'], 'settled-denominator')
    return {'group_commit': enabled, 'measurements': measured, 's3_total': net,
            'originals_verified': len(committed) + len(cancelled) - 1,
            'committed_rows': len(final_rows), 'binary': started['binary'],
            'sampled_peak_rss_bytes': max(row['metrics']['VmRSS'] for row in samples),
            'sampled_peak_cache_allocated_bytes': max(row['cache']['allocated_bytes'] for row in samples),
            'sampled_resource_peak_is_hard_bound': False}


def round_boundaries(directory):
    boundaries = []
    for name, _ in spec.ROUNDS:
        events = rows(directory / name / 'events.jsonl')
        boundaries.append(tuple(moment(one([row for row in events if row['event'] == event], 'round-backend-boundary'))
                                for event in ('backend_started', 'backend_stopped')))
    return boundaries


def validate_round_order(boundaries):
    need(len(boundaries) == len(spec.ROUNDS) and all(begin < end for begin, end in boundaries)
         and all(left[1] < right[0] for left, right in zip(boundaries, boundaries[1:])), 'round-run-order')


def verify(directory):
    directory = Path(directory)
    same(wire.parse((directory / 'plan.json').read_bytes()), spec.PLAN, 'fixed-plan')
    result = wire.parse((directory / 'result.json').read_bytes())
    need(result['status'] == 'OBSERVED_NOT_AUDITED' and result['aws_standard'] == result['production_slo'] == 'NOT_RUN', 'run-completion')
    need([(row['name'], row['group_commit']) for row in result['rounds']] == list(spec.ROUNDS), 'round-order')
    need(all(row['status'] == 'OBSERVED_NOT_AUDITED' and not row['cleanup_errors'] for row in result['rounds']), 'round-completion')
    validate_round_order(round_boundaries(directory))
    inputs = provenance(directory)
    rounds = {name: audit_round(directory / name, enabled) for name, enabled in spec.ROUNDS}
    need(all(row['binary'] == inputs['tools']['scapd'] for row in rounds.values()), 'observed-service-binary')
    pairs = []
    for off, on in (('off-1', 'on-1'), ('off-2', 'on-2')):
        phases = {}
        for phase in spec.PHASES:
            baseline, grouped = rounds[off]['measurements'][phase], rounds[on]['measurements'][phase]
            off_rate = baseline['successful_transactions_per_second_until_drained']
            on_rate = grouped['successful_transactions_per_second_until_drained']
            phases[phase] = {'on_over_off_successful_rate_ratio': on_rate / off_rate if off_rate else None,
                'actually_grouped_transactions': sum(int(size) * count for size, count in grouped['s3'].get('groups', {}).items() if int(size) > 1),
                'comparison': 'observed paired local samples; no improvement threshold'}
        pairs.append({'off': off, 'on': on, 'phases': phases})
    return {'status': 'PASSED', 'rounds': rounds, 'pairs': pairs,
            'original_independent_transactions': sum(row['originals_verified'] for row in rounds.values()),
            'runtime_commit': inputs['build_source_commit'], 'aws_standard': 'NOT_RUN', 'production_slo': 'NOT_RUN',
            'limits': ['p99 is a nearest-rank sample quantile, not a stable production tail estimate',
                'raw-byte capture/fsync, local proxy and resource sampling add observer overhead',
                'request bytes count bodies, not HTTP headers, TLS or AWS bills',
                'scheduled-to-terminal includes client scheduling, network and service queueing; no internal queue-only claim',
                'groups may remain size one; a successful audit does not require grouping or speedup']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    print(json.dumps(verify(parser.parse_args().evidence), indent=2, sort_keys=True))
