#!/usr/bin/env python3
"""Independent raw-history audit and measurement; imports no runner or product."""
from __future__ import annotations

import argparse
import base64
from collections import Counter, defaultdict
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import re
import struct
import tarfile

import spec

HERE = Path(__file__).resolve().parent
definition = importlib.util.spec_from_file_location('load_independent_wire', HERE.parent / 'object-service/audit_wire.py')
wire = importlib.util.module_from_spec(definition)
definition.loader.exec_module(wire)


class Rejected(ValueError):
    def __init__(self, rule):
        self.rule = rule
        super().__init__(rule)


def need(value, rule):
    if not value:
        raise Rejected(rule)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def same(left, right, rule):
    need(json.dumps(left, sort_keys=True) == json.dumps(right, sort_keys=True), rule)


def rows(path):
    result = []
    need(path.is_file(), 'ledger-missing')
    with path.open('rb') as source:
        while line := source.readline(1024 * 1024 + 1):
            need(len(line) <= 1024 * 1024 and line.endswith(b'\n'), 'ledger-framing')
            result.append(wire.parse(line))
            need(len(result) <= spec.BOUNDS['trace_rows'], 'ledger-row-bound')
    return result


def raw(directory, description):
    need(type(description) is dict and set(description) == {'file', 'bytes', 'sha256'}, 'raw-description')
    name = description['file']
    need(type(name) is str and re.fullmatch(r'raw/[0-9a-f]{64}', name) is not None
         and name == 'raw/' + description['sha256'], 'raw-path')
    path = directory / name
    need(path.is_file() and not path.is_symlink(), 'raw-missing')
    length = description['bytes']
    need(type(length) is int and 0 <= length <= spec.BOUNDS['body_bytes']
         and path.stat().st_size == length, 'raw-integrity')
    value = path.read_bytes()
    need(len(value) == length and digest(value) == description['sha256'], 'raw-integrity')
    return value


def moment(row):
    value = row['monotonic_ns']
    need(type(value) is int or type(value) is str and value.isdecimal(), 'clock-format')
    value = int(value)
    need(value > 0, 'clock-format')
    return value


def one(values, rule):
    need(len(values) == 1, rule)
    return values[0]


def percentiles(values):
    need(bool(values) and all(type(n) in (int, float) and math.isfinite(n) and n >= 0 for n in values), 'latency-values')
    ordered = sorted(values)
    return {'samples': len(ordered), 'p50': ordered[math.ceil(.50 * len(ordered)) - 1],
            'p95': ordered[math.ceil(.95 * len(ordered)) - 1],
            'p99': ordered[math.ceil(.99 * len(ordered)) - 1], 'maximum': ordered[-1]}


def concurrent(intervals):
    events = sorted((time, delta) for start, end in intervals for time, delta in ((start, 1), (end, -1)))
    active = maximum = 0
    for _, delta in events:
        active += delta
        need(active >= 0, 'call-interval')
        maximum = max(maximum, active)
    need(active == 0, 'call-interval')
    return maximum


def outcome(finish):
    if finish['ok']:
        return 'success'
    error = finish['error']
    if error.get('outcome') == 'committed':
        return 'committed_unavailable'
    if error.get('outcome') == 'unknown' or error.get('code') in ('UNKNOWN', 'UNAVAILABLE', 'DEADLINE'):
        return 'unknown'
    return 'rejected' if error.get('name') == 'RemoteError' else 'transport_error'


def identity(directory, inputs):
    current = {p.name: digest(p.read_bytes()) for p in sorted(HERE.iterdir())
               if p.is_file() and p.suffix in ('.py', '.mjs', '.md')}
    same(inputs['fixture'], current, 'fixture-auditor-source')
    need(re.fullmatch('[0-9a-f]{40}', inputs['fixture_commit']) is not None, 'fixture-commit')
    archived = directory / 'fixture-source.tar'
    need(digest(archived.read_bytes()) == inputs['fixture_archive_sha256'], 'fixture-archive')
    with tarfile.open(archived) as archive:
        members = archive.getmembers()
        need(len(members) == len(inputs['fixture']) and len({m.name for m in members}) == len(members), 'fixture-count')
        for member in members:
            need(member.isfile() and member.name in inputs['fixture'], 'fixture-member')
            need(digest(archive.extractfile(member).read()) == inputs['fixture'][member.name], 'fixture-bytes')
    need(inputs['plan_sha256'] == inputs['fixture']['PLAN.md'] == digest((HERE / 'PLAN.md').read_bytes()), 'frozen-plan')
    source = directory / 'runtime-build'
    receipt = wire.parse((source / 'build-receipt.json').read_bytes())
    need(receipt['status'] == 'passed' and receipt['profile'] == 'release' and receipt['exit_code'] == 0, 'runtime-build')
    same(receipt['binary'], inputs['tools']['scapd'], 'runtime-binary')
    same(receipt['inputs'], inputs['runtime_inputs'], 'runtime-inputs')
    need(receipt['source_commit'] == inputs['runtime_source_commit'], 'runtime-commit')
    archive = receipt['archived_evidence']
    for name, field in (('source_archive', 'source_archive_sha256'), ('source_manifest', 'source_manifest_sha256')):
        need(digest((source / archive[name]).read_bytes()) == archive[field], 'runtime-archive')
    manifest = wire.parse((source / archive['source_manifest']).read_bytes())
    same(manifest, {'schema': 1, 'source_commit': receipt['source_commit'], 'inputs': receipt['inputs']}, 'runtime-source-manifest')
    with tarfile.open(source / archive['source_archive']) as stream:
        members = stream.getmembers()
        need(len(members) == len(receipt['inputs']) and len({m.name for m in members}) == len(members), 'runtime-source-count')
        for member in members:
            need(member.isfile() and member.name in receipt['inputs'], 'runtime-source-member')
            need(digest(stream.extractfile(member).read()) == receipt['inputs'][member.name], 'runtime-source-bytes')
    for name in ('cargo.stdout.jsonl', 'cargo.stderr.log'):
        need(digest((source / ('build-' + name)).read_bytes()) == receipt[name + '_sha256'], 'runtime-build-log')
    cargo = rows(source / 'build-cargo.stdout.jsonl')
    need(cargo[-1].get('reason') == 'build-finished' and cargo[-1].get('success') is True, 'runtime-build-finished')
    # The independent reader itself must be the one included in the runtime source freeze.
    for name in ('object-service/audit_wire.py', 'object-network/head5_audit.py'):
        need(digest((HERE.parent / name).read_bytes()) == receipt['inputs']['experiments/' + name], 'independent-reader-source')


def workload_audit(directory):
    value = wire.parse((directory / 'workload.json').read_bytes())
    same(value['plan'], spec.PLAN, 'workload-plan')
    expected = spec.calls()
    need(len(value['calls']) == len(expected) == 871, 'workload-denominator')
    for actual, fixed in zip(value['calls'], expected):
        payloads = actual.get('payloads', {})
        need(set(payloads) == {str(row) for row in fixed.get('rows', [])}, 'input-payload-denominator')
        for description in payloads.values():
            data = raw(directory, description)
            need(len(data) == fixed['blob_bytes'] and len(set(data)) > 128, 'input-payload-extent')
        expanded = dict(fixed)
        if payloads:
            expanded['payloads'] = payloads
        statements = spec.statements(fixed, payloads)
        if statements is not None:
            expanded['statements'] = statements
        same(actual, expanded, 'workload-call')
    hashes = [p['sha256'] for item in value['calls'] for p in item.get('payloads', {}).values()]
    need(len(hashes) == len(set(hashes)), 'input-independent-bytes')
    return {item['id']: item for item in value['calls']}


def statements(directory, planned):
    return [{'sql': item['sql'], 'params': [
        {'type': 'integer', 'value': value['integer']} if 'integer' in value else
        {'type': 'blob', 'base64': base64.b64encode(raw(directory, value['blob'])).decode()}
        for value in item['params']]} for item in planned['statements']]


def http_audit(directory, planned, config):
    sdk = rows(directory / 'sdk.jsonl')
    by_event = defaultdict(dict)
    for row in sdk:
        if 'id' in row:
            need(row['id'] in planned and row['id'] not in by_event[row['event']], 'http-denominator')
            by_event[row['event']][row['id']] = row
    ids = set(planned)
    for kind in ('call_started', 'call_finished', 'http_request'):
        need(set(by_event[kind]) == ids, 'http-denominator')
    need(set(by_event['http_response']).isdisjoint(by_event['http_error'])
         and set(by_event['http_response']) | set(by_event['http_error']) == ids, 'http-terminal-denominator')
    prepared = rows(directory / 'intents.jsonl')
    need(len(prepared) == 185 and {r['id'] for r in prepared} == {i for i, v in planned.items() if v['operation'] == 'execute'}, 'original-execute-denominator')
    intents = {}
    for row in prepared:
        value = wire.parse(raw(directory, row['serialized']))
        # Public serialized TrackedRequest is independently tied to its actual POST below.
        intents[row['id']] = (value, row)
    credentials = {c['tenant']: c for c in config['credentials']}
    calls, outcomes = {}, Counter()
    for identifier, item in planned.items():
        begin, finish, sent = (by_event[k][identifier] for k in ('call_started', 'call_finished', 'http_request'))
        terminal = by_event['http_response'].get(identifier) or by_event['http_error'][identifier]
        need(begin['phase'] == finish['phase'] == sent['phase'] == terminal['phase'] == item['phase'], 'call-phase')
        need(int(begin['queued_ns']) <= moment(begin) < moment(sent) < moment(terminal)
             and moment(begin) < moment(finish), 'call-clock')
        need(finish['posts'] == 1 and sent['method'] == 'POST' and sent['redirect'] == 'error', 'single-original-post')
        scope = spec.SCOPES[item['scope']]
        need(sent['token_sha256'] == credentials[scope['tenant']]['sha256'], 'credential-binding')
        body = wire.parse(raw(directory, sent['request']))
        expected = {'version': 1, 'scope': scope, 'operation': item['operation']}
        operation = item['operation']
        if operation in ('create', 'activate'):
            expected['nonce'] = item['nonce']
        if operation == 'activate':
            expected['expected_revision'] = item['expected_revision']
        if operation in ('execute', 'query'):
            expected['statements'] = statements(directory, item)
        if operation in ('execute', 'lookup', 'cancel'):
            original = item if operation == 'execute' else planned[item['original']]
            request = {'epoch': '1', 'id': original['request_id'],
                       'principal': credentials[scope['tenant']]['principal'],
                       'fingerprint': wire.fingerprint(statements(directory, original))}
            expected['request'] = request
            if operation == 'execute':
                value, input_row = intents[identifier]
                need(moment(input_row) < moment(begin), 'input-before-execute')
                same(value['request'], request, 'serialized-request')
                same(value['scope'], scope, 'serialized-scope')
        same(body, expected, 'original-http-input')
        admission = 'data' if operation in ('create', 'execute', 'query') else 'recovery' if operation in ('activate', 'open') else 'control'
        need(sent['admission'] == admission, 'admission-class')
        value = None
        if terminal['event'] == 'http_response':
            need(terminal['complete'] is True, 'complete-http-response')
            value = wire.parse(raw(directory, terminal['response']))
            need(type(value) is dict and type(value.get('ok')) is bool, 'http-envelope')
            if value['ok']:
                need(terminal['status'] == 200 and set(value) == {'ok', 'value'}, 'http-success')
            else:
                need(terminal['status'] != 200 and set(value) == {'ok', 'error'} and type(value['error']['code']) is str, 'http-rejection')
        if finish['ok']:
            need(value is not None and value['ok'] and finish['error'] is None
                 and moment(terminal) < moment(finish), 'sdk-success')
        else:
            error = finish['error']
            need(type(error) is dict and type(error.get('name')) is str, 'sdk-error')
            code = error.get('code')
            if value is not None and not value['ok'] and moment(terminal) < moment(finish):
                need(code == value['error']['code'], 'sdk-error-code')
        category = outcome(finish)
        if item.get('expected_error'):
            need(not finish['ok'] and finish['error']['code'] == item['expected_error']
                 and terminal.get('status') == 429, 'recovery-busy')
        elif item['phase'] not in spec.MEASURED:
            need(finish['ok'], 'required-call-success')
        outcomes[category] += 1
        calls[identifier] = {'item': item, 'begin': begin, 'finish': finish, 'sent': sent,
                             'terminal': terminal, 'body': body, 'value': value, 'category': category}
    starts = [r for r in sdk if r['event'] == 'phase_started']
    ends = [r for r in sdk if r['event'] == 'phase_finished']
    need(Counter(r['phase'] for r in starts) == Counter(spec.PHASES)
         and Counter(r['phase'] for r in ends) == Counter(spec.PHASES), 'phase-denominator')
    for phase in spec.PHASES:
        first = one([r for r in starts if r['phase'] == phase], 'phase-start')
        last = one([r for r in ends if r['phase'] == phase], 'phase-end')
        group = [value for value in calls.values() if value['item']['phase'] == phase]
        need(first['calls'] == [r['id'] for r in planned.values() if r['phase'] == phase]
             and last['calls'] == last['posts'] == len(group) and last['failures'] == 0, 'phase-counts')
        cap = spec.MEASURED[phase][1] if phase in spec.MEASURED else 4 if phase == 'cold-probes' else 1
        need(first['concurrency'] == cap and concurrent([(moment(c['begin']), moment(c['finish'])) for c in group]) <= cap, 'offered-concurrency')
        need(all(moment(first) <= moment(c['begin']) < moment(c['finish']) < moment(last) for c in group), 'phase-interval')
    return calls, outcomes


def results_audit(directory, calls):
    committed, resolutions = {}, {}
    expected_acks = {}
    for identifier, call in calls.items():
        item, envelope = call['item'], call['value']
        if envelope is None or not envelope['ok'] or item['operation'] not in ('execute', 'lookup', 'cancel'):
            continue
        value = envelope['value']
        original = item.get('original', identifier)
        request = call['body']['request']
        if value.get('state') == 'committed':
            try:
                data, decoded = wire.committed(value)
            except (ValueError, KeyError):
                raise Rejected('committed-wire') from None
            same(value['receipt']['request'], request, 'receipt-request')
            same(value['receipt']['scope'], call['body']['scope'], 'receipt-scope')
            if original in committed:
                old = committed[original]
                same(value['receipt'], old['receipt'], 'original-receipt')
                need(data == old['raw'], 'original-result')
            else:
                committed[original] = {'receipt': value['receipt'], 'raw': data, 'decoded': decoded}
            if call['finish']['ok'] or call['finish']['error'].get('outcome') == 'committed':
                expected_acks[identifier] = (value['receipt'], data, original)
        elif value.get('state') == 'cancelled':
            need(value['transition']['nonce'] == request['id'], 'cancellation-identity')
        else:
            need(value.get('state') == 'unknown' and item['operation'] == 'lookup', 'request-resolution')
        if item.get('original') and identifier.endswith('-2'):
            need(value.get('state') in ('committed', 'cancelled'), 'final-original-resolution')
            resolutions[original] = value['state']
    acks = rows(directory / 'acks.jsonl')
    need(len(acks) == len(expected_acks) and len({r['id'] for r in acks}) == len(acks), 'ack-denominator')
    for row in acks:
        need(row['id'] in expected_acks, 'ack-denominator')
        receipt, data, original = expected_acks[row['id']]
        same(row['receipt'], receipt, 'ack-receipt')
        need(raw(directory, row['result']) == data and row['original'] == original, 'ack-result')
        need(moment(calls[row['id']]['terminal']) < moment(row) < moment(calls[row['id']]['finish']), 'ack-persisted-before-return')
    measured_writes = {i for i, c in calls.items() if c['item']['phase'].startswith('write_')}
    need(set(resolutions) == measured_writes, 'write-resolution-denominator')
    for identifier, call in calls.items():
        error = call['finish']['error']
        if error is not None and error.get('receipt') is not None:
            original = call['item'].get('original', identifier)
            need(original in committed, 'known-commit-resolution')
            same(error['receipt'], committed[original]['receipt'], 'known-original-receipt')
    expected = {scope: {} for scope in spec.SCOPES}
    for identifier, saved in committed.items():
        original = calls[identifier]['item']
        kind = original['kind']
        if kind in ('insert', 'bulk'):
            for row in original['rows']:
                need(row not in expected[original['scope']], 'duplicate-business-row')
                expected[original['scope']][row] = raw(directory, original['payloads'][str(row)])
            output = saved['decoded']
            if kind == 'insert':
                need(len(output) == 1 and output[0]['columns'] == ['id', 'payload', 'witness']
                     and len(output[0]['rows']) == 1, 'original-insert-result')
                row = output[0]['rows'][0]
                need(row[:2] == [original['rows'][0], expected[original['scope']][original['rows'][0]]]
                     and type(row[2]) is int, 'original-insert-values')
            else:
                need(len(output) == 2 and output[0]['columns'] == ['id']
                     and output[0]['rows'] == [[row] for row in original['rows']]
                     and output[1]['columns'] == ['witness'] and len(output[1]['rows']) == 1
                     and type(output[1]['rows'][0][0]) is int, 'original-bulk-result')
    covered = defaultdict(set)
    for identifier, call in calls.items():
        item = call['item']
        if item['operation'] != 'query' or not call['finish']['ok']:
            continue
        decoded = wire.result(wire.b64(call['value']['value']['result']))
        need(len(decoded) == 1, 'query-statements')
        table = expected[item['scope']]
        if item['kind'] == 'counts':
            need(decoded[0]['columns'] == ['n', 'total'] and decoded[0]['rows'] == [[len(table), sum(table)]], 'count-result')
        else:
            ids = sorted(row for row in table if item['kind'] == 'all_rows' or item['first'] <= row < item['last'])
            need(decoded[0]['columns'] == ['id', 'payload']
                 and decoded[0]['rows'] == [[row, table[row]] for row in ids], 'complete-business-values')
            need(not covered[item['scope']].intersection(ids), 'duplicate-data-audit')
            covered[item['scope']].update(ids)
    need(all(covered[name] == set(table) for name, table in expected.items()), 'data-audit-denominator')
    need(sum(len(data) for data in expected['cold'].values()) == spec.PLAN['cold_user_bytes'], 'cold-data-capacity')
    return committed, {'original_committed': len(committed), 'measured_write_resolutions': dict(Counter(resolutions.values())),
                       'verified_rows': {name: len(table) for name, table in expected.items()}, 'ack_observations': len(acks)}


def frame(raw_value, path, scope):
    need(raw_value[:8] == b'SCAPOBJ2' and len(raw_value) >= 20 and path.rsplit('/', 1)[1] == digest(raw_value), 'immutable-frame')
    meta_size, data_size = struct.unpack_from('<IQ', raw_value, 8)
    need(meta_size <= 65516 and 20 + meta_size + data_size == len(raw_value), 'immutable-frame-length')
    value = wire.parse(raw_value[20:20 + meta_size])
    same(value['scope'], scope, 'immutable-scope')
    need(value['format'] == 2 and set(value['payload']) == {'kind', 'value'}, 'immutable-format')
    return value['payload']['kind'], value['payload']['value'], raw_value[20 + meta_size:]


def publication_before_acks(calls, original, published):
    for identifier, call in calls.items():
        if call['item'].get('original', identifier) != original:
            continue
        envelope = call['value']
        if envelope is None:
            continue
        acknowledged = (envelope['ok'] and envelope['value'].get('state') == 'committed') or (
            not envelope['ok'] and 'receipt' in envelope['error'])
        if acknowledged:
            need(published < moment(call['terminal']), 'head-before-every-committed-ack')


def s3_audit(directory, calls, committed, final_request_count):
    history = rows(directory / 's3.jsonl')
    need([r['sequence'] for r in history] == list(range(1, len(history) + 1)), 's3-trace-sequence')
    need(not any(r['event'] == 'proxy_error' for r in history), 's3-proxy-error')
    groups = defaultdict(list)
    for row in history:
        if row['event'] in ('request', 'forwarded', 'response', 'delivered', 'gate_arrived'):
            groups[row['request_serial']].append(row)
    need(type(final_request_count) is int and 0 < final_request_count <= spec.BOUNDS['s3_requests']
         and sorted(groups) == list(range(1, final_request_count + 1)), 's3-denominator')
    requests, responses, bodies, accepted = {}, {}, {}, []
    prefixes = {}
    heads = {}
    for name, scope in spec.SCOPES.items():
        prefix = ('/scap-test/scap-object/v1/{deployment}/{tenant}/{database}/inc/{incarnation}/gen/{generation}/storage/1/objects/').format(**scope)
        prefixes[name] = prefix
        heads[name] = ('/scap-test/scap-object/v1/{deployment}/{tenant}/{database}/head').format(**scope)
    for serial, group in groups.items():
        request, forward, response, delivered = (one([r for r in group if r['event'] == kind], 's3-exchange')
                                                for kind in ('request', 'forwarded', 'response', 'delivered'))
        need(moment(request) < moment(forward) < moment(response) <= moment(delivered), 's3-clock')
        for other in group:
            for name in ('phase', 'method', 'path', 'request', 'if_match', 'if_none_match', 'signing'):
                same(other[name], request[name], 's3-original-request')
        for name in ('status', 'response', 'etag'):
            same(delivered[name], response[name], 's3-original-response')
        request_raw, response_raw = raw(directory, request['request']), raw(directory, response['response'])
        path, method = request['path'], request['method']
        bound = [name for name in spec.SCOPES if path == heads[name] or re.fullmatch(re.escape(prefixes[name]) + '[0-9a-f]{64}', path)]
        need(len(bound) == 1 and method in ('GET', 'PUT'), 's3-exact-namespace')
        signature = request['signing']
        need({'host', 'x-amz-date', 'x-amz-content-sha256'} <= set(signature['signed_headers'])
             and re.fullmatch('[0-9a-f]{64}', signature['access_key_sha256']) is not None
             and signature['payload_sha256'] == digest(request_raw), 'signed-s3')
        normalized = {'monotonic_ns': moment(request), 'phase': request['phase'], 'method': method, 'path': path,
            'request_bytes': len(request_raw), 'request_sha256': digest(request_raw), 'if_match': request['if_match'],
            'if_none_match': request['if_none_match']}
        normalized_response = {**normalized, 'monotonic_ns': moment(response), 'status': response['status'],
            'response_bytes': len(response_raw), 'response_sha256': digest(response_raw), 'etag': response['etag']}
        if path.endswith('/head'):
            normalized['head_request_bytes'] = list(request_raw)
            normalized_response['head_request_bytes'] = list(request_raw)
            normalized_response['head_response_bytes'] = list(response_raw)
        if method == 'GET':
            need(not request_raw and request['if_match'] is None and request['if_none_match'] is None, 's3-get-conditions')
            if '/objects/' in path and response['status'] == 200:
                frame(response_raw, path, {k: int(v) for k, v in spec.SCOPES[bound[0]].items()})
        else:
            need((request['if_match'] is None and request['if_none_match'] == '*') or
                 (type(request['if_match']) is str and request['if_none_match'] is None), 's3-put-conditions')
            if response['status'] == 200:
                accepted.append((request, response, request_raw))
                if '/objects/' in path:
                    need(request['if_none_match'] == '*' and request['if_match'] is None, 'immutable-create-only')
                    frame(request_raw, path, {k: int(v) for k, v in spec.SCOPES[bound[0]].items()})
                    bodies[path] = request_raw
        requests[serial], responses[serial] = normalized, normalized_response
    try:
        authority = wire.object_versions(requests, responses)
    except (ValueError, KeyError):
        raise Rejected('original-s3-authority') from None
    for identifier, saved in committed.items():
        call = calls[identifier]
        scope_name, receipt = call['item']['scope'], saved['receipt']
        publications = [(q, r, wire.parse(data)) for q, r, data in accepted if q['path'] == heads[scope_name]
                        and wire.parse(data)['sequence'] == int(receipt['sequence'])
                        and wire.parse(data)['transition'] == {k: int(v) for k, v in receipt['transition'].items()}]
        q, r, head = one(publications, 'one-original-publication')
        need(head['data_root'] == receipt['data_root'], 'publication-data-root')
        key = prefixes[scope_name] + receipt['result_hash']
        put, put_response, raw_result = one([(p, a, data) for p, a, data in accepted if p['path'] == key], 'durable-result-put')
        need(moment(put_response) < moment(q) and put['if_none_match'] == '*', 'result-before-head')
        readbacks = [v for serial, v in responses.items() if requests[serial]['method'] == 'GET'
                     and v['path'] == key and v['status'] == 200 and v['response_sha256'] == receipt['result_hash']
                     and moment(put_response) < v['monotonic_ns'] < moment(q)]
        need(bool(readbacks), 'durable-result-readback')
        kind, value, result_bytes = frame(raw_result, key, head['scope'])
        need(kind == 'result' and result_bytes == saved['raw'], 'durable-original-result')
        publication_before_acks(calls, identifier, moment(r))
    # Warm measured queries must remain one fresh HEAD each, without hidden downloads.
    for phase in ('read_same', 'read_multi'):
        selected = [v for v in requests.values() if v['phase'] == phase]
        need(len(selected) == 64 and all(v['method'] == 'GET' and v['path'].endswith('/head') for v in selected), 'warm-head-only')
    warm = calls['cold-warm']
    during = [r for r in requests.values() if moment(warm['sent']) < r['monotonic_ns'] < moment(warm['terminal'])]
    need(len(during) == 1 and during[0]['method'] == 'GET' and during[0]['path'] == heads['cold'], 'warm-cold-head-only')
    return history, requests, responses, accepted, bodies, authority, heads, prefixes


def cold_audit(directory, calls, network, events):
    history, requests, responses, accepted, bodies, _, heads, prefixes = network
    arrived = one([r for r in history if r['event'] == 'gate_arrived'], 'one-cold-gate')
    release = one([r for r in history if r['event'] == 'gate_released'], 'one-cold-release')
    cold = calls['cold-open']
    probes = [c for c in calls.values() if c['item']['phase'] == 'cold-probes']
    need(moment(cold['sent']) < moment(arrived) < moment(release) < moment(cold['terminal']), 'cold-gate-order')
    need(max(moment(c['finish']) for c in probes) - moment(arrived) <= spec.DEADLINES['probe_ms'] * 1000000,
         'hot-control-budget')
    need(all(moment(arrived) < moment(c['sent']) < moment(c['finish']) < moment(release) for c in probes), 'hot-before-gate-release')
    need(moment(release) - moment(arrived) < spec.DEADLINES['gate_hold_ms'] * 1000000, 'gate-original-deadline')
    busy = calls['recovery-busy']
    need(not any(v['path'] == heads['seq'] or v['path'].startswith(prefixes['seq']) for v in requests.values()
                 if moment(busy['sent']) < v['monotonic_ns'] < moment(busy['terminal'])), 'recovery-permit-before-s3')
    head = wire.parse([data for q, _, data in accepted if q['path'] == heads['cold']][-1])
    prefix = prefixes['cold']
    needed, data_pages = set(), []
    def load(digest_value, kind):
        path = prefix + digest_value
        need(path in bodies, 'cold-closure-missing')
        actual, value, data = frame(bodies[path], path, head['scope'])
        need(actual == kind, 'cold-closure-type')
        needed.add(path)
        return value, data
    manifest, raw_manifest = load(head['data_root'], 'manifest')
    need(not raw_manifest and manifest['page_count'] * 4096 >= spec.PLAN['cold_user_bytes'], 'cold-image-capacity')
    def node(value_hash, expected_level=None):
        value, data = load(value_hash, 'node')
        need(not data and type(value['level']) is int and 0 <= value['level'] <= 4
             and (expected_level is None or value['level'] == expected_level), 'cold-tree-level')
        need(0 < len(value['children']) <= 256, 'cold-tree-width')
        for child in value['children']:
            if value['level']:
                node(child, value['level'] - 1)
            else:
                chunk, raw_chunk = load(child, 'chunk')
                need(chunk['first_page'] == 1 + sum(data_pages) and chunk['bytes'] == []
                     and 0 < len(raw_chunk) <= 131072 and len(raw_chunk) % 4096 == 0, 'cold-chunk-geometry')
                data_pages.append(len(raw_chunk) // 4096)
    node(manifest['root'])
    need(sum(data_pages) == manifest['page_count'] and arrived['path'] in needed, 'cold-complete-data-closure')
    # This frozen workload has at most 65 retained requests in any window.
    for window in head['windows']:
        index, data = load(window['root'], 'index')
        need(not data and index['kind'] == 'leaf' and index['epoch'] == window['epoch']
             and len(index['entries']) == window['count'], 'cold-index-closure')
        sizes = 0
        for entry in index['entries']:
            outcome = entry['outcome']
            need(outcome['state'] == 'committed', 'cold-original-commits')
            value, data = load(outcome['result'], 'result')
            same(value['request'], entry['request'], 'cold-retained-identity')
            need(value['transition']['nonce'] == entry['request']['id'] and len(data) == entry['result_bytes'], 'cold-retained-result')
            wire.result(data); sizes += len(data)
        need(sizes == window['result_bytes'], 'cold-window-size')
    got = {v['path'] for serial, v in responses.items() if requests[serial]['method'] == 'GET' and v['status'] == 200
           and moment(cold['sent']) < requests[serial]['monotonic_ns'] < v['monotonic_ns'] < moment(cold['terminal'])}
    need(needed <= got, 'cold-all-dependencies-downloaded')
    removed = one([r for r in events if r['event'] == 'compute_cache_removed'], 'all-compute-loss')
    need(removed['exists'] is False and removed['instance'] == 1
         and moment(removed) < moment(cold['sent']), 'all-compute-loss')
    restarted = one([r for r in events if r['event'] == 'service_started' and r['instance'] == 2], 'fresh-cache-start')
    same(restarted['initial_cache'], {'logical_bytes': 0, 'allocated_bytes': 0, 'files': 0, 'races': 0}, 'fresh-cache-start')
    need(restarted['cache'] != removed['path'] and moment(removed) < moment(restarted) < moment(cold['sent']), 'fresh-cache-start')
    return {'user_bytes': spec.PLAN['cold_user_bytes'], 'database_pages': manifest['page_count'],
            'downloaded_dependencies': len(needed), 'open_ms': (moment(cold['finish']) - moment(cold['begin'])) / 1e6,
            'gate_hold_ms': (moment(release) - moment(arrived)) / 1e6, 'hot_control_calls': len(probes)}


def process_stat(value):
    need(type(value) is str and ' (' in value and ')' in value, 'proc-stat')
    try:
        pid = int(value.split(' (', 1)[0]); fields = value[value.rfind(')') + 2:].split()
        start = int(fields[19])
    except (ValueError, IndexError):
        raise Rejected('proc-stat') from None
    need(pid > 0 and start > 0, 'proc-stat')
    return pid, start


def resource_audit(directory, events, inputs):
    starts = [r for r in events if r['event'] == 'service_started']
    stops = [r for r in events if r['event'] == 'service_stopped']
    need([r['instance'] for r in starts] == [1, 2] and [r['instance'] for r in stops] == [1, 2], 'service-lifetimes')
    result = []
    for start, stop in zip(starts, stops):
        same(start['identity'], stop['identity'], 'owned-process-identity')
        same(start['binary'], inputs['tools']['scapd'], 'running-binary')
        identity = start['identity']
        need(start['proof']['source'] == identity['proc_source'] == 'owned_pre_exec_proc_self_fd'
             and process_stat(start['proof']['stat']) == (identity['proc_pid'], identity['start_ticks'])
             and start['proof']['boot_id'] == identity['boot_id'], 'owned-proc-handoff')
        need(stop['status'] == 0 and stop['forced'] is False and stop['usage']['source'] == 'kernel_wait4_owned_child', 'owned-service-exit')
        samples = rows(directory / f"resources-{start['instance']}.jsonl")
        need(bool(samples) and len(samples) <= spec.BOUNDS['samples'] and
             [r['sample'] for r in samples] == list(range(1, len(samples) + 1)), 'resource-samples')
        memory, descriptors, threads, gaps, hwm, disks = [], [], [], [], [], []
        for row in samples:
            same(row['identity'], identity, 'resource-process-identity')
            need(process_stat(row['stat_raw']) == (identity['proc_pid'], identity['start_ticks']), 'resource-start-ticks')
            values = {}
            for line in row['status_raw'].splitlines():
                if ':' not in line: continue
                key, text = line.split(':', 1)
                if key in ('Pid', 'Threads', 'VmRSS', 'VmHWM'):
                    parts = text.split()
                    need(key not in values and parts and parts[0].isdecimal(), 'resource-status')
                    factor = 1024 if key.startswith('Vm') else 1
                    need(parts[1:] == (['kB'] if factor == 1024 else []), 'resource-units')
                    values[key] = int(parts[0]) * factor
            need(set(values) == {'Pid', 'Threads', 'VmRSS', 'VmHWM'} and min(values.values()) > 0, 'resource-unavailable')
            same(row['metrics'], values, 'resource-derived-metrics')
            need(values['Pid'] == identity['proc_pid'], 'resource-status-pid')
            for name in ('fd_names', 'task_names'):
                names = row[name]
                need(type(names) is list and bool(names) and len(names) == len(set(names))
                     and all(type(v) is str and v.isdecimal() for v in names), 'resource-directory-list')
            need(moment(start) <= moment(row) < row['completed_ns'] < moment(stop), 'resource-lifetime')
            need(row['filesystem_free_bytes'] >= spec.BOUNDS['minimum_free_bytes'], 'disk-space-guard')
            for name in ('cache', 'backend'):
                need(set(row[name]) == {'logical_bytes', 'allocated_bytes', 'files', 'races'}
                     and all(type(n) is int and n >= 0 for n in row[name].values()), 'disk-sample')
            memory.append(values['VmRSS']); hwm.append(values['VmHWM'])
            descriptors.append(len(row['fd_names'])); threads.append(values['Threads']); disks.append(row)
        gaps = [(moment(b) - moment(a)) / 1e6 for a, b in zip(samples, samples[1:])]
        need(all(gap > 0 for gap in gaps), 'resource-sample-order')
        result.append({'instance': start['instance'], 'samples': len(samples), 'maximum_sample_gap_ms': max(gaps, default=None),
            'first_sample_delay_ms': (moment(samples[0]) - moment(start)) / 1e6,
            'last_sample_to_exit_ms': (moment(stop) - samples[-1]['completed_ns']) / 1e6,
            'maximum_sample_collection_ms': max((r['completed_ns'] - moment(r)) / 1e6 for r in samples),
            'sampled_rss_peak_bytes': max(memory), 'sampled_hwm_max_bytes': max(hwm),
            'observed_hwm_decreases': sum(b < a for a, b in zip(hwm, hwm[1:])),
            'sampled_fd_peak': max(descriptors), 'sampled_thread_peak': max(threads),
            'kernel_lifetime_maxrss_bytes': stop['usage']['maxrss_bytes'],
            'sampled_cache_allocated_peak_bytes': max(r['cache']['allocated_bytes'] for r in disks),
            'sampled_cache_logical_peak_bytes': max(r['cache']['logical_bytes'] for r in disks),
            'sampled_backend_allocated_peak_bytes': max(r['backend']['allocated_bytes'] for r in disks),
            'sampled_backend_logical_peak_bytes': max(r['backend']['logical_bytes'] for r in disks),
            'hard_peak_or_limit_proved': False})
    nodes = [r for r in events if r['event'] == 'node_stopped']
    need(Counter(r['phase'] for r in nodes) == Counter(spec.PHASES) and all(r['status'] == 0 and r['forced'] is False
         and r['usage']['source'] == 'kernel_wait4_owned_child' for r in nodes), 'owned-sdk-exits')
    proxy = one([r for r in events if r['event'] == 'proxy_stopped'], 'proxy-cleanup')
    need(proxy['joined'] is True and proxy['errors'] == [], 'proxy-cleanup')
    backend = one([r for r in events if r['event'] == 'backend_stopped'], 'backend-cleanup')
    need(len(backend['processes']) == 4 and all(p['wait_status'] == -9
         and p['kernel_usage']['source'] == 'kernel_wait4_owned_child' for p in backend['processes']), 'backend-cleanup')
    return result


def audit(directory):
    directory = Path(directory)
    inputs = wire.parse((directory / 'inputs.json').read_bytes())
    identity(directory, inputs)
    config = wire.parse((directory / 'service-config-1.json').read_bytes())
    second = wire.parse((directory / 'service-config-2.json').read_bytes())
    for key, expected in (('admission', spec.ADMISSION), ('cache', spec.CACHE), ('transport', spec.TRANSPORT), ('output', spec.OUTPUT)):
        same(config[key], expected, 'fixed-service-profile')
    changed = dict(second); changed['cache_directory'] = config['cache_directory']
    same(changed, config, 'same-restarted-configuration')
    need(config['s3']['timeout_ms'] == 15000 and config['worker_instance'] == '5001'
         and config['execution'] == {'result_memory_bytes': 134217728}, 'fixed-runtime-profile')
    planned = workload_audit(directory)
    calls, outcomes = http_audit(directory, planned, config)
    committed, result_summary = results_audit(directory, calls)
    events = rows(directory / 'events.jsonl')
    need([r['sequence'] for r in events] == list(range(1, len(events) + 1)), 'event-sequence')
    space = one([r for r in events if r['event'] == 'startup_space'], 'startup-space')
    need(space['required_bytes'] == spec.BOUNDS['startup_free_bytes']
         and space['filesystem_free_bytes'] >= space['required_bytes'], 'startup-space')
    raw_files = list((directory / 'raw').iterdir())
    need(all(p.is_file() and not p.is_symlink() and re.fullmatch('[0-9a-f]{64}', p.name) for p in raw_files), 'raw-directory')
    raw_bytes = sum(p.stat().st_size for p in raw_files)
    need(raw_bytes <= int((directory / 'raw-budget').read_text()) <= spec.BOUNDS['raw_bytes'], 'raw-budget')
    readiness = [r for r in events if r['event'] == 'readiness_probe']
    for instance in (1, 2):
        final = [r for r in readiness if r['instance'] == instance][-1:]
        need(bool(final) and final[0]['status'] == 200
             and wire.parse(raw(directory, final[0]['response'])) == {'status': 'alive', 'protocol': 1}, 'readiness-proof')
    unsigned = one([r for r in events if r['event'] == 'unsigned_probe'], 'signed-backend')
    need(unsigned['status'] == 403, 'signed-backend')
    raw(directory, unsigned['response'])
    proxy = one([r for r in events if r['event'] == 'proxy_stopped'], 'proxy-cleanup')
    network = s3_audit(directory, calls, committed, proxy['request_count'])
    cold = cold_audit(directory, calls, network, events)
    resources = resource_audit(directory, events, inputs)
    measured = {}
    for phase, (count, cap) in spec.MEASURED.items():
        selected = [c for c in calls.values() if c['item']['phase'] == phase]
        need(len(selected) == count, 'measured-denominator')
        elapsed = (max(moment(c['finish']) for c in selected) - min(moment(c['begin']) for c in selected)) / 1e9
        need(elapsed > 0, 'measurement-time')
        s3 = [r for r in network[1].values() if r['phase'] == phase]
        selected_ids = {n for n, r in network[1].items() if r['phase'] == phase}
        response_bytes = sum(network[2][n]['response_bytes'] for n in selected_ids)
        counts = Counter(c['category'] for c in selected)
        measured[phase] = {'offered': count, 'concurrency_limit': cap, 'observed_concurrency': concurrent([
            (moment(c['begin']), moment(c['finish'])) for c in selected]), 'outcomes': dict(counts),
            'elapsed_seconds': elapsed, 'offered_per_second': count / elapsed, 'success_per_second': counts['success'] / elapsed,
            'request_latency_ms_including_service_queue': percentiles([(moment(c['finish']) - moment(c['begin'])) / 1e6 for c in selected]),
            'latency_ms_including_generator_queue': percentiles([(moment(c['finish']) - int(c['begin']['queued_ns'])) / 1e6 for c in selected]),
            's3_requests': len(s3), 's3_methods': dict(Counter(r['method'] for r in s3)),
            's3_request_body_bytes': sum(r['request_bytes'] for r in s3), 's3_response_body_bytes': response_bytes}
    return {'status': 'PASSED', 'measurement_scope': 'fixed local instrumented observation, unchanged release product',
            'http_posts': len(calls), 'all_outcomes': dict(outcomes), 'measured': measured, 'cold_recovery': cold,
            'results': result_summary, 'resources': resources, 's3_authority': network[5],
            's3_requests': len(network[1]), 'aws_standard': 'NOT_RUN', 'production_slo_passed': False,
            'readiness_gets': len(readiness), 'raw_evidence_unique_bytes': raw_bytes,
            'sampled_resource_peak_is_hard_bound': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('evidence', type=Path)
    print(json.dumps(audit(parser.parse_args().evidence), sort_keys=True))
