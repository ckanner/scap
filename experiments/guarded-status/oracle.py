#!/usr/bin/env python3
"""Independent read-only audit; no runner, SDK, product or input interpreter imports."""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / 'experiments/object-service'))
from audit_wire import (b64, committed, equal, fingerprint, object_exchanges,
    object_versions, parse, require, result, sha256_text)
from owner_oracle import object_frame, sdk_result, status_from_head
specification = importlib.util.spec_from_file_location('guarded_build_audit',
    ROOT / 'experiments/object-network/audit_build.py')
build_audit = importlib.util.module_from_spec(specification)
specification.loader.exec_module(build_audit)

INPUT_SHA = '2aea330e124be3272bf2335e667cd8f7ee84f87714ea4390ce30a6a78f8931cb'
SCOPE = {'deployment': '1', 'tenant': '7', 'database': '3101', 'incarnation': '1', 'generation': '1'}
WORKERS = {'s': '9101', 'p': '9202', 'q': '9303'}
PRINCIPALS = {'writer': '11', 'manager': '12', 'reader': '13', 'blind': '14', 'foreign': '21'}
POLICY = [{'principal': str(n), 'read': r, 'write': w, 'admin': a}
    for n, r, w, a in ((11, True, True, False), (12, True, False, True),
        (13, True, False, False), (14, False, False, True))]
REVOKED = [{**p, 'read': False} if p['principal'] == '13' else p for p in POLICY]
SEED_SQL = ['CREATE TABLE witness(n INTEGER PRIMARY KEY)', 'INSERT INTO witness(n) VALUES(1) RETURNING n']
QUERY_SQL = 'SELECT n FROM witness ORDER BY n'
HEAD = '/scap-test/scap-object/v1/1/7/3101/head'
PREFIX = '/scap-test/scap-object/v1/1/7/3101/inc/1/gen/1/storage/1/objects/'
DEADLINES = {'ordinary_ms': 15000, 'recovery_ms': 30000, 's3_ms': 10000,
    'client_ms': 20000, 'owner_ms': 35000, 'short_ms': 250,
    'gate_seconds': 10, 'child_seconds': 40, 'ready_seconds': 20, 'actor_idle_ms': 5000}

# Independent matrix: id, actual receiver, wire operation, role, service status,
# SDK code (or '-'), explicit worker field (or '-' for absence).
MATRIX = '''
seed_create s create writer 200 - -
seed_activate s activate writer 200 - 9101
seed_sql s execute writer 200 - -
seed_policy s policy writer 200 - -
legacy_status p status reader 200 - -
guarded_nonowner p status reader 200 - 9202
copied_route p status manager 200 - 9202
unroutable p status manager 0 UNROUTABLE 9999
wrong_worker p status reader 409 TARGET_MISMATCH 9101
null_guard p status reader 400 INVALID null
zero_guard p status reader 400 INVALID 0
leading_zero_guard p status reader 400 INVALID 09202
number_guard p status reader 400 INVALID number:9202
overflow_guard p status reader 400 INVALID 18446744073709551616
max_guard p status reader 409 TARGET_MISMATCH 18446744073709551615
invalid_token p status invalid 401 UNAUTHENTICATED 9101
foreign_scope p status foreign 403 DENIED 9101
revoke_reader s policy manager 200 - -
reader_denied p status reader 403 DENIED 9202
reader_wrong_target p status reader 409 TARGET_MISMATCH 9101
blind_denied p status blind 403 DENIED 9202
manager_fresh p status manager 200 - 9202
authority_unavailable p status manager 503 UNKNOWN 9202
response_lost p status manager 200 TRANSPORT 9202
deadline_probe p status manager 200 DEADLINE 9202
replaced_old_route q status manager 409 TARGET_MISMATCH 9202
replacement_new_registry q status manager 200 - 9303
replacement_legacy_status q status manager 200 - -
final_seed_lookup s lookup writer 200 - -
final_query s query writer 200 - -
'''
CASES = {}
for line in MATRIX.strip().splitlines():
    name, worker, operation, role, status, code, guard = line.split()
    CASES[name] = {'worker': worker, 'operation': operation, 'role': role,
        'status': int(status), 'code': None if code == '-' else code, 'guard': guard}
RAW = {'null_guard', 'zero_guard', 'leading_zero_guard', 'number_guard', 'overflow_guard'}
LOST = {'response_lost', 'deadline_probe'}
FRESH = {'legacy_status': 4, 'guarded_nonowner': 4, 'copied_route': 4,
    'reader_denied': 5, 'blind_denied': 5, 'manager_fresh': 5,
    'response_lost': 5, 'deadline_probe': 5,
    'replacement_new_registry': 5, 'replacement_legacy_status': 5}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def only(values, message):
    require(len(values) == 1, message)
    return values[0]


def moment(row):
    value = row['monotonic_ns']
    require(type(value) is int and value > 0, 'invalid parent timestamp')
    return value


def numbered(rows, *, node=False):
    require(rows and len(rows) <= 50000, 'bounded complete trace required')
    previous = 0
    for index, row in enumerate(rows, 1):
        require(row.get('schema') == 1 and type(row['sequence']) is int and row['sequence'] == index,
            'trace sequence gap/duplicate')
        value = row['monotonic_ns']
        if node:
            require(isinstance(value, str) and re.fullmatch('[1-9][0-9]*', value), 'Node clock is not canonical')
            value = int(value)
        require(type(value) is int and value > previous, 'trace clock reordered')
        previous = value


def capture(row, field, digest, maximum=4194304):
    raw = b64(row[field])
    require(len(raw) <= maximum and sha(raw) == row[digest], 'complete captured body/digest differs')
    return raw


def envelope(raw):
    value = parse(raw)
    require(type(value.get('ok')) is bool, 'missing explicit HTTP outcome')
    require(set(value) == ({'ok', 'value'} if value['ok'] else {'ok', 'error'}), 'HTTP envelope fields')
    if not value['ok']:
        require(set(value['error']) == {'code', 'message'} and value['error']['code'] == value['error']['message'],
            'noncanonical service rejection')
    return value


def original_request():
    statements = [{'sql': sql, 'params': []} for sql in SEED_SQL]
    return {'scope': SCOPE, 'request': {'epoch': '1', 'id': '1', 'principal': '11',
        'fingerprint': fingerprint(statements)}, 'statements': statements}


def action(name):
    case = CASES[name]
    body = {'version': 1, 'scope': SCOPE, 'operation': case['operation']}
    if name == 'seed_create':
        body['nonce'] = '31001'
    elif name == 'seed_activate':
        body.update(expected_revision='1', nonce='31002')
    elif name == 'seed_sql':
        body.update({k: v for k, v in original_request().items() if k != 'scope'})
    elif name in ('seed_policy', 'revoke_reader'):
        body.update(expected_revision='3' if name == 'seed_policy' else '4',
            nonce='31003' if name == 'seed_policy' else '31004',
            permissions=POLICY if name == 'seed_policy' else REVOKED)
    elif name == 'final_seed_lookup':
        body['request'] = original_request()['request']
    elif name == 'final_query':
        body['statements'] = [{'sql': QUERY_SQL, 'params': []}]
    guard = case['guard']
    if guard != '-':
        body['expected_worker_instance'] = None if guard == 'null' else (9202 if guard == 'number:9202' else guard)
    return body


def node_clock_audit(data):
    """Bind the same-host hrtime clock to owned spawn and pipe observations.

    The byte-for-byte raw/pipe bijection is independently checked on load.
    A semantic control may change the decoded projection, so this function
    checks causal clocks without substituting the pipe's bytes for that view.
    """
    events, node = data['events'], data['node']
    start = only([r for r in events if r['event'] == 'node_started'], 'one actual Node child required')
    stop = only([r for r in events if r['event'] == 'node_stopped'], 'Node stop missing')
    spawn = start['spawn_requested_ns']
    require(type(spawn) is int and 0 < spawn <= start['identity']['spawn_monotonic_ns'] <= moment(start),
        'Node original spawn boundary is invalid')
    wrappers = [r for r in events if r['event'] == 'node_event']
    require(len(wrappers) == len(node), 'SDK raw/parent ledger bijection failed')
    for wrapper, row in zip(wrappers, node):
        require(wrapper['node'] == start['node'] == stop['node'] == 1 and
            moment(start) < moment(wrapper) < moment(stop) and
            spawn <= int(row['monotonic_ns']) <= moment(wrapper),
            'Node clock is outside original child/parent observation')
    offers = [r for r in events if r['event'] == 'operator_command']
    observed = [r for r in events if r['event'] == 'sdk_completion_observed']
    equal([r['command'] for r in observed], list(CASES), 'parent SDK completion denominator changed')
    for index, (name, observation) in enumerate(zip(CASES, observed)):
        offer = offers[index]
        begin = only([r for r in node if r['event'] == 'command_started' and r['command'] == name],
            'one original SDK invocation required')
        finish = only([r for r in node if r['event'] == 'command_finished' and r['command'] == name],
            'one original SDK outcome required')
        wrapper = wrappers[finish['sequence'] - 1]
        require(offer['node'] == 1 and moment(offer) < int(begin['monotonic_ns']) and
            moment(wrapper) < moment(observation) < moment(offers[index + 1]),
            'parent offer/SDK outcome observation order changed')
        equal(parse(capture(offer, 'raw', 'sha256', 65536)), {'id': name}, 'operator changed original command bytes')
        equal(observation['ok'], finish['ok'], 'parent changed original SDK outcome')
    shutdown = offers[-1]
    finished = only([r for r in node if r['event'] == 'finished'], 'Node finish missing')
    require(shutdown['node'] == 1 and moment(shutdown) < int(finished['monotonic_ns']),
        'Node finished before original shutdown command')
    equal(parse(capture(shutdown, 'raw', 'sha256', 65536)), {'id': 'shutdown'}, 'shutdown command bytes changed')


def http_audit(data):
    events, node, config = data['events'], data['node'], data['configuration']
    numbered(events)
    numbered(node, node=True)
    starts = [r for r in node if r['event'] == 'command_started']
    ends = [r for r in node if r['event'] == 'command_finished']
    equal([r['command'] for r in starts], list(CASES), 'SDK offered command order/denominator changed')
    equal([r['command'] for r in ends], list(CASES), 'SDK completed command order/denominator changed')
    equal([r['id'] for r in events if r['event'] == 'operator_command'], [*CASES, 'shutdown'],
        'operator changed command denominator')
    require(len([r for r in node if r['event'] == 'http_request']) == 29, 'original Fetch denominator')
    require(len([r for r in node if r['event'] in ('http_response', 'http_error')]) == 29, 'Fetch terminal denominator')
    for event, count in (('http_request', 29), ('http_forwarded', 29), ('http_response', 29),
            ('http_delivered', 27), ('http_response_suppressed', 2)):
        require(sum(r['event'] == event for r in events) == count, 'HTTP event denominator: ' + event)
    equal([r['http_serial'] for r in events if r['event'] == 'http_request'], list(range(1, 30)), 'HTTP serial gap')
    equal([r['serial'] for r in node if r['event'] == 'http_request'], list(range(1, 30)), 'Fetch serial gap')
    node_clock_audit(data)
    operations, calls, by_command = {}, {}, {}
    for name, begin, finish in zip(CASES, starts, ends):
        require(int(begin['monotonic_ns']) < int(finish['monotonic_ns']), 'SDK outcome before invocation')
        operations[name] = {'start': begin, 'finish': finish}
        case = CASES[name]
        issued = [r for r in node if r['event'] == 'http_request' and r['command'] == name]
        relayed = [r for r in events if r['event'] == 'http_request' and r['command'] == name]
        if name == 'unroutable':
            require(not issued and not relayed, 'unroutable dispatched HTTP')
        else:
            fetch = only(issued, 'one original Fetch required')
            request = only(relayed, 'one actual POST required')
            require(int(begin['monotonic_ns']) < int(fetch['monotonic_ns']) < int(finish['monotonic_ns'])
                and int(fetch['monotonic_ns']) < moment(request), 'Fetch outside original SDK invocation')
            equal(fetch['url'], config['endpoints'][case['worker']], 'credential destination changed')
            require(fetch['method'] == 'POST' and fetch['redirect'] == 'error', 'SDK method/redirect changed')
            equal(fetch['admission'], 'recovery' if name == 'seed_activate' else
                ('data' if case['operation'] in ('create', 'execute', 'query') else 'control'), 'admission class changed')
            body = capture(fetch, 'body', 'body_sha256', 65536)
            equal(parse(body), action(name), 'original wire action changed: ' + name)
            equal(capture(request, 'request_body', 'request_sha256', 65536), body, 'relay changed original request')
            require(request['worker'] == ('s' if case['worker'] == 's' else 'p') and
                request['path'] == '/v1' and request['method'] == 'POST', 'HTTP slot changed')
            for row in (fetch, request):
                equal(row['credential_sha256'], config['credential_sha256'][case['role']], 'credential identity changed')
            serial = request['http_serial']
            # Fault witnesses also carry this serial, but are not wire rows.
            # Their exact original binding is proved separately in fault_audit.
            stages = [r for r in events if r.get('http_serial') == serial and r['event'] in
                ('http_request', 'http_forwarded', 'http_response', 'http_delivered', 'http_response_suppressed')]
            response = only([r for r in stages if r['event'] == 'http_response'], 'one service response required')
            forward = only([r for r in stages if r['event'] == 'http_forwarded'], 'one service forwarding required')
            require(moment(request) < moment(forward) < moment(response), 'HTTP causal forwarding interval')
            for row in stages:
                for field in ('worker', 'command', 'method', 'path', 'request_body', 'request_sha256', 'credential_sha256'):
                    equal(row[field], request[field], 'HTTP event changed original request: ' + field)
            raw = capture(response, 'response_body', 'response_sha256')
            value = envelope(raw)
            require(response['origin'] == 'service' and response['status'] == case['status'], 'service response status/origin')
            equal(response['suppressed'], name == 'response_lost', 'service response suppression disposition')
            terminal = only([r for r in node if r.get('serial') == fetch['serial'] and
                r['event'] in ('http_response', 'http_error')], 'one original Fetch terminal required')
            require(terminal['command'] == name and int(fetch['monotonic_ns']) < int(terminal['monotonic_ns'])
                and moment(response) < int(terminal['monotonic_ns']), 'Fetch terminal lost original response/command')
            # At an elapsed SDK deadline, the already issued raw Fetch can
            # settle later. The final Node marker waits for that observer too.
            if name != 'deadline_probe':
                require(int(terminal['monotonic_ns']) < int(finish['monotonic_ns']),
                    'SDK outcome preceded original Fetch completion')
            delivered = [r for r in stages if r['event'] == 'http_delivered']
            suppressed = [r for r in stages if r['event'] == 'http_response_suppressed']
            if name in LOST:
                require(not delivered and len(suppressed) == 1 and terminal['event'] == 'http_error', 'lost response silently delivered')
                equal(suppressed[0]['reason'], 'explicit_response_loss' if name == 'response_lost'
                    else 'original_client_deadline', 'unplanned response loss boundary')
            else:
                delivery = only(delivered, 'original HTTP response not delivered')
                require(not suppressed and moment(response) < moment(delivery), 'HTTP delivery ordering')
                for field in ('status', 'response_body', 'response_sha256', 'headers', 'origin', 'suppressed'):
                    equal(delivery[field], response[field], 'delivery changed original response: ' + field)
                require(terminal['event'] == 'http_response', 'unexpected Fetch failure')
                equal(terminal['status'], response['status'], 'Fetch status changed')
                equal(capture(terminal, 'body', 'body_sha256', 1048576), raw, 'Fetch body changed')
            if case['status'] != 200:
                equal(value, {'ok': False, 'error': {'code': case['code'], 'message': case['code']}}, 'wrong remote rejection')
            else:
                require(value['ok'] is True, 'successful service response is error')
            call = {'request': request, 'response': response, 'body': parse(body), 'value': value,
                'name': name, 'worker': case['worker'], 'fetch': fetch, 'finish': finish,
                'terminal': terminal, 'stages': stages}
            calls[serial] = call
            by_command[name] = call
        if name in RAW:
            equal(finish['value'], {'status': case['status'], 'body': by_command[name]['value']}, 'raw response changed')
            require(finish['ok'] is True, 'raw fixture did not finish')
        elif case['code'] is not None:
            require(finish['ok'] is False and finish['error']['code'] == case['code'], 'SDK error classification changed: ' + name)
        else:
            require(finish['ok'] is True, 'SDK successful operation failed: ' + name)
    finished = only([r for r in node if r['event'] == 'finished'], 'Node finish missing')
    equal((finished['commands'], finished['http_attempts']), (30, 29), 'Node totals changed')
    require(all(int(row['monotonic_ns']) < int(finished['monotonic_ns']) for row in node if row is not finished),
        'Node finished before original Fetch observers settled')
    return {'calls': calls, 'by_command': by_command, 'operations': operations}


def network_audit(data, http):
    history = data['history']
    numbered(history)
    equal([r['phase'] for r in history if r['event'] == 'phase_started'], list(CASES), 'S3 phase order changed')
    requests, responses = object_exchanges(history, phases=set(CASES), blackhole_phases={'authority_unavailable'})
    objects, accepted, bindings, by_command = {}, {}, {}, defaultdict(list)
    for number, request in requests.items():
        name = request['phase']
        require(name in http['by_command'], 'S3 outside an offered POST')
        call = http['by_command'][name]
        require(request['worker'] == call['worker'], 'S3 came from wrong daemon instance')
        require(moment(call['request']) < moment(request) < moment(call['response']), 'S3 outside original HTTP interval')
        if number in responses:
            require(moment(responses[number]) < moment(call['response']), 'HTTP ACK preceded backend response')
        binding = only([n for n, c in http['calls'].items() if c is call], 'unique HTTP binding')
        bindings[number] = {binding}
        by_command[name].append(number)
        signing = request['signing']
        require(signing['algorithm'] == 'AWS4-HMAC-SHA256' and
            signing['access_key_sha256'] == data['configuration']['access_key_sha256'], 'wrong product SigV4 credential')
        require(re.fullmatch('[0-9]{8}/us-east-1/s3/aws4_request', signing['credential_scope']), 'SigV4 scope changed')
        require(signing['signed_headers'] == sorted(set(signing['signed_headers'])) and
            {'host', 'x-amz-date', 'x-amz-content-sha256'} <= set(signing['signed_headers']), 'SigV4 fields missing')
        equal(signing['host'], urlparse(data['configuration']['s3_endpoints'][request['worker']]).netloc, 'SigV4 host changed')
        equal(signing['payload_sha256'], request['request_sha256'], 'signed payload differs')
        for row in [r for r in history if r.get('request_serial') == number]:
            equal(row['worker'], request['worker'], 'object event changed daemon')
            equal(row['signing'], signing, 'object event changed signing')
            capture(row, 'request_body', 'request_sha256')
            if 'response_body' in row:
                capture(row, 'response_body', 'response_sha256')
        if request['worker'] in ('p', 'q'):
            require(request['method'] == 'GET' and request['path'] == HEAD, 'metadata probe performed payload/native I/O or mutation')
        response = responses.get(number)
        if '/objects/' in request['path'] and response and response['status'] == 200:
            raw = b64(request['request_body']) if request['method'] == 'PUT' else b64(response['response_body'])
            object_frame(raw, request['path'])
            if request['path'] in objects:
                equal(raw, objects[request['path']], 'immutable bytes changed')
            objects[request['path']] = raw
            if request['method'] == 'PUT':
                accepted[request['path']] = number
    for name, case in CASES.items():
        if case['operation'] != 'status':
            continue
        require(len(by_command[name]) == (1 if name in FRESH or name == 'authority_unavailable' else 0),
            'guard/auth/fresh HEAD order changed: ' + name)
    equal(Counter(r['worker'] for r in requests.values() if r['worker'] in ('p', 'q')),
        Counter({'p': 9, 'q': 2}), 'metadata HEAD GET denominator')
    require(sum(r['worker'] == 'p' for r in responses.values()) == 8, 'forwarded P HEAD denominator')
    versions = object_versions(requests, responses, calls=http['calls'], bindings=bindings)
    return {'requests': requests, 'responses': responses, 'objects': objects, 'accepted': accepted,
        'by_command': by_command, 'versions': versions}


def data_closure(objects, digest):
    selected = set()
    def load(digest, kind):
        path = PREFIX + sha256_text(digest)
        require(path in objects, 'missing complete data dependency')
        selected.add(path)
        payload, raw = object_frame(objects[path], path)
        require(set(payload) == {'kind', 'value'} and payload['kind'] == kind, 'wrong typed closure member')
        return payload['value'], raw
    manifest, raw = load(digest, 'manifest')
    require(not raw and set(manifest) == {'page_count', 'root'} and type(manifest['page_count']) is int
        and 0 <= manifest['page_count'] <= 32, 'fixed tiny database extent changed')
    if manifest['page_count'] == 0:
        require(manifest['root'] is None, 'empty image has a root')
        return selected
    node, raw = load(manifest['root'], 'node')
    equal(node, {'level': 0, 'first_chunk': 0, 'children': node['children']}, 'data node extent changed')
    require(not raw and len(node['children']) == 1, 'fixed data root children changed')
    chunk, raw = load(node['children'][0], 'chunk')
    equal(chunk, {'first_page': 1, 'bytes': []}, 'chunk metadata changed')
    require(len(raw) == manifest['page_count'] * 4096 and raw[:18] == b'SQLite format 3\0\x10\0',
        'complete private SQLite image extent changed')
    return selected


def durable_audit(data, http, net):
    calls, requests, responses = http['by_command'], net['requests'], net['responses']
    seed = calls['seed_sql']['value']['value']
    raw, decoded = committed(seed)
    equal(decoded, [{'columns': [], 'rows': [], 'affected_rows': 0, 'last_insert_rowid': 0},
        {'columns': ['n'], 'rows': [[1]], 'affected_rows': 1, 'last_insert_rowid': 1}], 'original SQL result changed')
    receipt = seed['receipt']
    equal(receipt['scope'], SCOPE, 'receipt Scope changed')
    equal(receipt['request'], original_request()['request'], 'original SQL identity changed')
    equal(receipt['transition'], {'revision': '3', 'nonce': '1'}, 'SQL transition changed')
    require(receipt['sequence'] == '1', 'SQL sequence changed')
    equal(calls['final_seed_lookup']['value']['value'], seed, 'later lookup changed original committed receipt/bytes')
    for name in ('seed_sql', 'final_seed_lookup'):
        equal(calls[name]['finish']['value'], {'state': 'committed', 'receipt': receipt,
            'rawResult': {'bytes': seed['result'], 'sha256': sha(raw)}, 'result': sdk_result(decoded)},
            'SDK lost original commit knowledge')
    query = calls['final_query']['value']['value']
    require(set(query) == {'result'}, 'query response shape changed')
    query_decoded = result(b64(query['result']))
    equal(query_decoded, [{'columns': ['n'], 'rows': [[1]], 'affected_rows': 0, 'last_insert_rowid': 0}],
        'final query has replayed/missing SQL effect')
    equal(calls['final_query']['finish']['value'], sdk_result(query_decoded), 'SDK query result changed')
    saved = only([r for r in data['node'] if r['event'] == 'saved_request'], 'one saved request required')
    equal(parse(capture(saved, 'raw', 'sha256', 65536)), original_request(), 'saved SQL request changed')
    require(saved['command'] == 'seed_sql' and int(saved['monotonic_ns']) < int(calls['seed_sql']['fetch']['monotonic_ns']),
        'SQL request not persisted before dispatch')
    heads, previous = {}, None
    put = [(n, r) for n, r in requests.items() if r['method'] == 'PUT' and r['path'] == HEAD]
    require(len(put) == 5 and all(responses[n]['status'] == 200 for n, _ in put), 'HEAD publication denominator changed')
    expected_names = ['seed_create', 'seed_activate', 'seed_sql', 'seed_policy', 'revoke_reader']
    for revision, (number, request), name in zip(range(1, 6), put, expected_names):
        require(request['phase'] == name and request['worker'] == 's', 'unexpected HEAD writer')
        head = parse(b64(request['request_body']))
        nonce = (31001, 31002, 1, 31003, 31004)[revision - 1]
        if previous is None:
            expected = {**head, 'format': 6, 'scope': {k: int(v) for k, v in SCOPE.items()},
                'head_serial': 1, 'storage': {'active_generation': 1, 'allocated_through': 1, 'plan': None, 'sweep': None},
                'revision': 1, 'transition': {'revision': 1, 'nonce': nonce}, 'sequence': 0,
                'owner_epoch': 1, 'owner_instance': 9101, 'active': False, 'auth_epoch': 1,
                'policy': [{'principal': 11, 'read': True, 'write': True, 'admin': True}],
                'lifecycle': 'ready', 'creation': None, 'deletion': None, 'quota': {'max_bytes': 10737418240},
                'retention': {'max_entries': 4096, 'max_result_bytes': 268435456}, 'request_epoch': 1}
        else:
            expected = {**previous, 'head_serial': revision, 'revision': revision,
                'transition': {'revision': revision, 'nonce': nonce}}
            if revision == 2:
                expected['active'] = True
            elif revision == 3:
                expected.update(sequence=1, data_root=receipt['data_root'], windows=head['windows'])
            else:
                expected.update(auth_epoch=revision - 2, policy=[{**p, 'principal': int(p['principal'])}
                    for p in (POLICY if revision == 4 else REVOKED)])
        equal(head, expected, 'HEAD transition changed unrelated state')
        closure = data_closure(net['objects'], head['data_root'])
        require(head['request_epoch'] == 1 and len(head['windows']) == 1, 'fixed request window changed')
        window = head['windows'][0]
        path = PREFIX + window['root']
        require(path in net['objects'], 'missing retained root')
        payload, index_raw = object_frame(net['objects'][path], path)
        count = 0 if revision < 3 else 1
        expected_entries = []
        if count:
            native_request = {k: int(v) if k != 'fingerprint' else v for k, v in receipt['request'].items()}
            expected_entries = [{'request': native_request, 'outcome': {'state': 'committed',
                'result': receipt['result_hash']}, 'result_bytes': len(raw)}]
            result_path = PREFIX + receipt['result_hash']
            require(result_path in net['objects'], 'missing retained original result')
            rp, rr = object_frame(net['objects'][result_path], result_path)
            equal(rp, {'kind': 'result', 'value': {'request': native_request, 'sequence': 1,
                'transition': {'revision': 3, 'nonce': 1}, 'data_root': receipt['data_root'], 'bytes': []}},
                'retained result metadata changed')
            equal(rr, raw, 'retained result bytes changed')
            closure.add(result_path)
            closure.update(data_closure(net['objects'], receipt['data_root']))
        equal(payload, {'kind': 'index', 'value': {'kind': 'leaf', 'epoch': 1, 'entries': expected_entries}},
            'retained index identity/outcome changed')
        require(not index_raw and window['epoch'] == 1 and window['count'] == count and
            window['result_bytes'] == (len(raw) if count else 0), 'retained window totals changed')
        closure.add(path)
        for dependency in closure:
            require(dependency in net['accepted'] and moment(responses[net['accepted'][dependency]]) < moment(request),
                'HEAD publication preceded durable closure')
            accepted_at = moment(responses[net['accepted'][dependency]])
            verified = [serial for serial, get in requests.items() if get['method'] == 'GET'
                and get['path'] == dependency and serial in responses and responses[serial]['status'] == 200
                and accepted_at < moment(get) < moment(responses[serial]) < moment(request)
                and b64(responses[serial]['response_body']) == net['objects'][dependency]]
            require(verified, 'HEAD publication lacks original exact dependency readback')
        if name != 'seed_sql':
            equal(calls[name]['value']['value'], status_from_head(head), 'management ACK differs from original HEAD')
            equal(calls[name]['finish']['value'], status_from_head(head), 'SDK management ACK changed')
        heads[revision] = head
        previous = head
    for name, revision in FRESH.items():
        number = only(net['by_command'][name], 'fresh probe lacks exactly one HEAD read')
        equal(parse(b64(responses[number]['response_body'])), heads[revision], 'fresh probe read wrong HEAD/ACL')
        if CASES[name]['status'] == 200:
            equal(calls[name]['value']['value'], status_from_head(heads[revision]), 'status differs from original same-GET HEAD')
            if name not in LOST:
                equal(calls[name]['finish']['value'], status_from_head(heads[revision]), 'SDK status changed')
    return {'head_publications': 5, 'sql_identities': 1, 'original_result_sha256': sha(raw), 'final_revision': 5}


def credential_audit(credentials, identities):
    """Compare complete credential records as a multiset, preserving duplicates.

    Authentication binds the digest to its trusted principal and tenant; it
    does not depend on the order of configuration entries. Canonical JSON
    preserves every field and type while avoiding a dict that would silently
    collapse duplicate credentials.
    """
    expected = [{'sha256': identities[role], 'deployment': '1',
        'tenant': '8' if role == 'foreign' else '7', 'principal': principal,
        'provision': role == 'writer'} for role, principal in PRINCIPALS.items()]
    require(type(credentials) is list, 'trusted credential partition changed')
    def records(values):
        return Counter(json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False)
            for value in values)
    equal(records(credentials), records(expected), 'trusted credential partition changed')


def configuration_audit(data):
    config = data['configuration']
    equal(config['scope'], SCOPE, 'configured logical Scope changed')
    equal(config['workers'], WORKERS, 'worker identities changed')
    require(config['endpoints']['p'] == config['endpoints']['q'] and
        config['daemon_ports']['p'] == config['daemon_ports']['q'], 'replacement did not reuse exact endpoint')
    require(config['daemon_ports']['s'] != config['daemon_ports']['p'], 'seed and probe share daemon')
    require(len(set(config['s3_endpoints'].values())) == 3, 'S3 traces cannot distinguish workers')
    for url in [*config['endpoints'].values(), *config['s3_endpoints'].values(), config['sink'], config['backend_endpoint']]:
        parsed = urlparse(url)
        require(parsed.scheme == 'http' and parsed.hostname == '127.0.0.1' and parsed.port and
            not parsed.username and not parsed.password and not parsed.query and not parsed.fragment,
            'fixture endpoint escaped trusted local host')
    require(all(urlparse(url).path == '/v1' for url in [*config['endpoints'].values(), config['sink']]) and
        all(urlparse(url).path == '' for url in [*config['s3_endpoints'].values(), config['backend_endpoint']]),
        'fixture endpoint path changed')
    require(set(config['credential_sha256']) == {*PRINCIPALS, 'invalid'}, 'credential denominator')
    require(len(set(config['credential_sha256'].values())) == 6, 'credential identities collapsed')
    require(len(set(x['cache_directory'] for x in data['service_configs'].values())) == 3, 'daemons share private SQLite directory')
    common = None
    for worker in WORKERS:
        service = data['service_configs'][worker]
        require(service['version'] == 1 and service['worker_instance'] == WORKERS[worker] and
            service['listen'] == f"127.0.0.1:{config['daemon_ports'][worker]}", 'daemon instance/address binding')
        credential_audit(service['credentials'], config['credential_sha256'])
        s3 = service['s3']
        equal(s3, {'endpoint': config['s3_endpoints'][worker], 'region': 'us-east-1', 'bucket': 'scap-test',
            'access_key_env': 'SCAP_TEST_ACCESS', 'secret_key_env': 'SCAP_TEST_SECRET',
            'session_token_env': None, 'allow_http': True, 'timeout_ms': 10000}, 'S3 service configuration changed')
        require(service['admission']['timeout_ms'] == 15000 and service['admission']['recovery_timeout_ms'] == 30000
            and service['admission']['actor_idle_timeout_ms'] == 5000, 'original service deadlines changed')
        equal(service['cache'], {'pages_per_actor': 65536, 'parallel_recoveries': 1}, 'native cache settings changed')
        equal(service['execution'], {'result_memory_bytes': 134217728}, 'native result budget changed')
        if common is not None:
            equal(service['admission'], common, 'worker admission settings differ')
        common = service['admission']


def fault_audit(data, http, net):
    events, node, config = data['events'], data['node'], data['configuration']
    expected = {
        'authority_blackhole': {'id': 'authority_blackhole', 'channel': 's3', 'kind': 'blackhole',
            'worker': 'p', 'method': 'GET', 'path': HEAD, 'stage': 'before_forward'},
        'response_loss': {'id': 'response_loss', 'channel': 'http', 'kind': 'drop',
            'worker': 'p', 'command': 'response_lost', 'operation': 'status'},
        'deadline_hold': {'id': 'deadline_hold', 'channel': 'http', 'kind': 'hold',
            'worker': 'p', 'command': 'deadline_probe', 'operation': 'status', 'discard_after_release': True},
    }
    metadata = {'schema', 'sequence', 'event', 'monotonic_ns'}
    def fields(row):
        return {key: value for key, value in row.items() if key not in metadata}
    for event in ('fault_armed', 'fault_entered'):
        equal(Counter(r['id'] for r in events if r['event'] == event), Counter(expected.keys()), 'fault denominator changed')
    require(not any(r['event'] in ('unexpected_sink_request', 'fault_cleanup_release', 'fault_expired',
        'service_forced_cleanup', 'node_forced_cleanup', 'http_fixture_failed') for r in events), 'unplanned fault/cleanup/fallback')
    entered_by_id = {}
    for identifier, rule in expected.items():
        armed = only([r for r in events if r['event'] == 'fault_armed' and r['id'] == identifier], 'fault arm')
        entered = only([r for r in events if r['event'] == 'fault_entered' and r['id'] == identifier], 'fault enter')
        equal(fields(armed), rule, 'fault arm selector changed')
        name = rule.get('command', 'authority_unavailable')
        offer = only([r for r in events if r['event'] == 'operator_command' and r['id'] == name], 'fault command offer')
        require(moment(armed) < moment(offer) < moment(entered), 'fault boundary changed')
        if rule['channel'] == 's3':
            serial = only(net['by_command'][name], 'blackhole original request missing')
            request = net['requests'][serial]
            equal(fields(entered), {**rule, 'request_serial': serial}, 'fault witness binds another original request')
            witness = only([r for r in data['history'] if r['event'] == 'transport_fault_observed'],
                'one original S3 blackhole witness required')
            require(witness['request_serial'] == serial and witness['mode'] == 'blackhole' and
                witness['stage'] == 'before_forward' and serial not in net['responses'],
                'blackhole witness changed original request/effect')
            suppressed = only([r for r in events if r['event'] == 's3_request_suppressed'], 'blackhole suppression missing')
            equal(fields(suppressed), {'id': identifier, 'request_serial': serial},
                'blackhole suppression changed original request')
            require(moment(request) < moment(entered) < moment(witness) < moment(suppressed)
                < moment(http['by_command'][name]['response']), 'blackhole original suppression order changed')
        else:
            call = http['by_command'][name]
            serial = call['request']['http_serial']
            equal(fields(entered), {**rule, 'http_serial': serial}, 'fault witness binds another original request')
            require(call['response']['status'] == 200 and moment(call['response']) < moment(entered)
                < int(call['finish']['monotonic_ns']), 'HTTP fault entered after original SDK outcome')
            suppressed = only([r for r in events if r['event'] == 'http_response_suppressed' and r['id'] == identifier],
                'original fault suppression missing')
            require(suppressed['http_serial'] == serial and moment(entered) < moment(suppressed),
                'HTTP suppression changed original fault')
            if identifier == 'response_loss':
                require(moment(suppressed) < int(call['terminal']['monotonic_ns']),
                    'Fetch failed before original explicit response loss')
        entered_by_id[identifier] = entered
    equal([r['id'] for r in events if r['event'] == 'fault_released'], ['deadline_hold'], 'unexpected fault release')
    release = only([r for r in events if r['event'] == 'fault_released'], 'deadline release')
    equal(fields(release), {'id': 'deadline_hold',
        'http_serial': http['by_command']['deadline_probe']['request']['http_serial']},
        'fault release binds another original request')
    observed = only([r for r in events if r['event'] == 'sdk_completion_observed' and
        r['command'] == 'deadline_probe'], 'parent did not observe deadline result')
    require(moment(entered_by_id['deadline_hold']) < moment(observed) < moment(release),
        'held response released before original SDK deadline outcome')
    operation = http['operations']['deadline_probe']
    require(int(operation['finish']['monotonic_ns']) - int(operation['start']['monotonic_ns']) >= 250000000,
        'SDK deadline returned before original ordinary budget')
    dropped = only([r for r in events if r['event'] == 'http_response_suppressed' and r['id'] == 'deadline_hold'],
        'held response not discarded')
    require(moment(release) < moment(dropped), 'held response discarded before explicit release')
    original = [{'workerInstance': WORKERS[w], 'endpoint': config['endpoints'][w]} for w in ('s', 'p')]
    copied = only([r for r in node if r['event'] == 'registry_constructed'], 'original registry absent')
    require(copied['command'] == 'copied_route', 'registry constructed for another command')
    equal(copied['routes'], original, 'original trusted registry changed')
    mutated = only([r for r in node if r['event'] == 'caller_registry_mutated'], 'caller mutation absent')
    require(mutated['command'] == 'copied_route', 'registry mutated for another command')
    equal(mutated['routes'], [original[0], {**original[1], 'endpoint': config['sink']}], 'caller mutation changed test')
    require(int(copied['monotonic_ns']) < int(mutated['monotonic_ns']) <
        int(http['by_command']['copied_route']['fetch']['monotonic_ns']), 'registry copy/mutation order')
    reuse = only([r for r in node if r['event'] == 'original_client_reused'], 'old client was reconstructed')
    equal((reuse['command'], reuse['created_by']), ('replaced_old_route', 'copied_route'), 'wrong original client reused')
    require(int(http['operations']['replaced_old_route']['start']['monotonic_ns']) < int(reuse['monotonic_ns'])
        < int(http['by_command']['replaced_old_route']['fetch']['monotonic_ns']), 'original client reuse after dispatch')
    replacement = only([r for r in node if r['event'] == 'replacement_registry_constructed'], 'new registry absent')
    require(replacement['command'] == 'replacement_new_registry' and
        int(http['operations']['replacement_new_registry']['start']['monotonic_ns']) < int(replacement['monotonic_ns'])
        < int(http['by_command']['replacement_new_registry']['fetch']['monotonic_ns']), 'replacement registry after dispatch')
    equal(replacement['routes'], [{'workerInstance': WORKERS[w], 'endpoint': config['endpoints'][w]}
        for w in ('s', 'q')], 'replacement registry did not explicitly replace P')


def process_audit(data, build, http, net):
    events, config = data['events'], data['configuration']
    owned = build_audit.OwnedChildren()
    def pair(starts, stops, key):
        equal(Counter(r[key] for r in starts), Counter(r[key] for r in stops), 'child start/stop denominator changed')
        return [(start, only([r for r in stops if r[key] == start[key]], 'child has multiple/no stops')) for start in starts]
    def stopped(start, stop, expected):
        equal(stop['identity'], start['identity'], 'stopped another child incarnation')
        require(stop['wait_status'] == expected and stop['kernel_usage']['available'] is True and
            stop['kernel_usage']['source'] == 'kernel_wait4_owned_child', 'real owned wait4 is missing/wrong')
        owned.register(start['identity'], moment(stop))
        require(start['identity']['spawn_monotonic_ns'] <= moment(start) < moment(stop), 'child lifetime ordering')
    starts = [r for r in events if r['event'] == 'service_started']
    stops = [r for r in events if r['event'] == 'service_stopped']
    stop_requests = [r for r in events if r['event'] == 'service_stop_requested']
    equal([r['worker'] for r in starts], ['s', 'p', 'q'], 'daemon child denominator/order')
    equal(Counter(r['worker'] for r in stop_requests), Counter(WORKERS.keys()), 'daemon stop request denominator')
    equal(Counter(r['worker'] for r in events if r['event'] == 'service_ready'),
        Counter(WORKERS.keys()), 'daemon readiness denominator')
    services = {}
    for start, stop in pair(starts, stops, 'worker'):
        worker = start['worker']
        stopped(start, stop, -9 if worker == 'p' else 0)
        require(stop['termination_error'] is None, 'forced daemon cleanup')
        equal(start['binary'], build['binary'], 'daemon binary not original release')
        require(start['configuration_sha256'] == data['file_hashes']['service-' + worker + '.json'], 'daemon config bytes changed')
        require(stop['stdout_sha256'] == data['file_hashes']['service-' + worker + '.log'], 'daemon log changed')
        equal(start['cache_directory'], data['service_configs'][worker]['cache_directory'], 'daemon cache changed')
        equal(start['backend_endpoint'], f"http://127.0.0.1:{config['daemon_ports'][worker]}",
            'daemon native endpoint changed')
        equal(start['configuration_file'], 'service-' + worker + '.json', 'daemon configuration file changed')
        ready = only([r for r in events if r['event'] == 'service_ready' and r['worker'] == worker], 'daemon readiness missing')
        equal(ready['identity'], start['identity'], 'readiness from another child')
        require(ready['status'] == 200 and parse(capture(ready, 'body', 'sha256', 4096)) ==
            {'status': 'alive', 'protocol': 1} and moment(start) < moment(ready) < moment(stop), 'daemon readiness wrong')
        requested = only([r for r in stop_requests if r['worker'] == worker], 'one daemon stop request required')
        equal(requested['identity'], start['identity'], 'stop requested for another daemon incarnation')
        reason = 'instance_replaced' if worker == 'p' else 'cleanup'
        require(requested['reason'] == stop['reason'] == reason and
            requested['signal'] == ('SIGKILL' if worker == 'p' else 'SIGINT') and
            moment(ready) < moment(requested) < moment(stop), 'daemon original stop order changed')
        services[worker] = {'start': start, 'ready': ready, 'stop_requested': requested, 'stop': stop}
    # The HTTP relay retains slot "p" across replacement. The independent
    # command matrix, original native port and distinct child lifetimes bind
    # these calls to P or Q, rather than treating the endpoint label as identity.
    for call in http['calls'].values():
        service = services[call['worker']]
        require(moment(service['ready']) < moment(call['request']) < moment(call['response'])
            < moment(service['stop_requested']), 'HTTP outside actual receiving daemon ready/lifetime')
    for serial, request in net['requests'].items():
        service = services[request['worker']]
        require(moment(service['ready']) < moment(request) < moment(service['stop_requested']),
            'S3 outside original daemon ready/lifetime')
        if serial in net['responses']:
            require(moment(net['responses'][serial]) < moment(service['stop_requested']),
                'S3 response after original daemon stop request')
    removed = only([r for r in events if r['event'] == 'cache_removed'], 'old cache loss missing')
    require(removed['worker'] == 'p' and removed['observed_absence'] is True and
        removed['path'] == data['service_configs']['p']['cache_directory'], 'removed another cache')
    require(moment(services['p']['stop']) < moment(removed) < moment(services['q']['start']),
        'replacement preceded actual kill/wait4/cache loss')
    snapshots = [r for r in events if r['event'] == 'cache_snapshot']
    equal([(r['worker'], r['label']) for r in snapshots], [('p', 'initial_probe_cache'),
        ('p', 'old_probe_before_kill'), ('q', 'replacement_empty_cache'), ('q', 'replacement_after_probes')],
        'empty-cache observation denominator')
    require(all(r['files'] == [] and r['path'] == data['service_configs'][r['worker']]['cache_directory']
        for r in snapshots), 'metadata probe opened payload files')
    require(moment(services['p']['ready']) < moment(snapshots[0]) < moment(http['by_command']['legacy_status']['request']) and
        int(http['operations']['deadline_probe']['finish']['monotonic_ns']) < moment(snapshots[1])
        < moment(services['p']['stop_requested']) and
        moment(services['q']['ready']) < moment(snapshots[2]) < moment(http['by_command']['replaced_old_route']['request']) and
        int(http['operations']['replacement_legacy_status']['finish']['monotonic_ns']) < moment(snapshots[3])
        < moment(services['q']['stop_requested']), 'cache observation did not bracket original probes')
    backend_starts = [r for r in events if r['event'] == 'backend_child_started']
    backend_stops = [r for r in events if r['event'] == 'backend_child_stopped']
    equal([r['role'] for r in backend_starts], ['master', 'volume', 'filer', 's3'], 'backend child denominator')
    for start, stop in pair(backend_starts, backend_stops, 'role'):
        stopped(start, stop, -9)
        require(start['binary_sha256'] == data['tools']['weed']['sha256'], 'backend executable changed')
    backend_ready = only([r for r in events if r['event'] == 'backend_ready'], 'backend readiness missing')
    equal(backend_ready['endpoint'], config['backend_endpoint'], 'backend readiness endpoint changed')
    require(all(moment(start) < moment(backend_ready) for start in backend_starts), 'backend ready before original child spawn')
    for row in data['history']:
        if row['event'] in ('object_forwarded', 'object_response'):
            require(moment(backend_ready) < moment(row) and all(moment(row) < moment(stop) for stop in backend_stops),
                'S3 effect outside original backend child lifetime')
    node_start = only([r for r in events if r['event'] == 'node_started'], 'one actual Node child required')
    node_stop = only([r for r in events if r['event'] == 'node_stopped'], 'Node stop missing')
    stopped(node_start, node_stop, 0)
    node_request = only([r for r in events if r['event'] == 'node_stop_requested'], 'Node stop request missing')
    equal(node_request['identity'], node_start['identity'], 'stop requested for another Node incarnation')
    shutdown = only([r for r in events if r['event'] == 'operator_command' and r['id'] == 'shutdown'], 'Node shutdown offer missing')
    require(node_request['node'] == 1 and node_request['forced'] is False and
        int(http['operations']['final_query']['finish']['monotonic_ns']) < moment(node_request) < moment(shutdown)
        < moment(node_stop), 'Node original shutdown order changed')
    equal(node_start['binary'], data['tools']['node'], 'SDK child binary differs from verified tool')
    hello = only([r for r in data['node'] if r['event'] == 'hello'], 'Node process hello missing')
    require(hello['self_pid'] == node_start['identity']['pid'] and hello['pid_source'] == 'node_process.pid'
        and hello['version'] == 'v22.16.0', 'SDK process identity/version differs')
    require(node_stop['forced'] is False and node_stop['termination_error'] is None and node_stop['reader_joined'] is True,
        'SDK did not exit/join naturally')
    require(node_stop['ledger_sha256'] == data['file_hashes']['node.jsonl'] and
        node_stop['stderr_sha256'] == data['file_hashes']['node-1.stderr.log'], 'original SDK logs changed')
    require(len(owned.incarnations) == 8, 'workload child denominator')
    require(data['tools']['node']['version'] == 'v22.16.0' and
        '4.51 153ab668c99731a6d29492bf6c61d0b4fa701101' in data['tools']['weed']['version'], 'unpinned workload tools')
    for name in ('node', 'weed'):
        probe = data['version_processes'][name]
        require(probe['wait_status'] == 0 and probe['kernel_usage']['available'] is True and
            probe['kernel_usage']['source'] == 'kernel_wait4_owned_child', 'version check child not owned/waited')
        require(probe['sha256'] == data['tools'][name]['sha256'] and
            probe['log_sha256'] == data['file_hashes'][name + '-version.log'], 'tool version bytes changed')
        owned.register(probe['identity'], probe['end_monotonic_ns'])
    require(len(owned.incarnations) == 10, 'total owned child denominator')
    listeners = [r for r in events if r['event'] == 'listener_started']
    closed = [r for r in events if r['event'] == 'listener_closed']
    equal(Counter(r['name'] for r in listeners),
        Counter(['sink', 's3-s', 's3-p', 's3-q', 'http-s', 'http-p']), 'listener denominator')
    listener_urls = {'sink': config['sink'].removesuffix('/v1'),
        **{'s3-' + worker: config['s3_endpoints'][worker] for worker in WORKERS},
        **{'http-' + worker: config['endpoints'][worker].removesuffix('/v1') for worker in ('s', 'p')}}
    require(len(set(listener_urls.values())) == 6, 'distinct listener endpoints collapsed')
    listener_counts = {'sink': 0, 'http-s': 7, 'http-p': 22,
        **{'s3-' + worker: sum(r['worker'] == worker for r in net['requests'].values()) for worker in WORKERS}}
    listener_lifetimes = {}
    for start, stop in pair(listeners, closed, 'name'):
        require(start['descriptor'] >= 0 and stop['descriptor'] == -1 and stop['thread_joined'] is True
            and stop['handlers_joined'] is True and moment(start) < moment(stop), 'listener/handler lifetime leaked')
        equal(start['url'], listener_urls[start['name']], 'listener endpoint differs from original destination')
        require(type(stop['accepted_handlers']) is int and 0 <= stop['accepted_handlers'] <= 4096,
            'listener handler bound')
        # Each frozen relay handler handles one request then closes. This also
        # rejects accepted but unrecorded/failed headers and unexpected sink use.
        require(stop['accepted_handlers'] == listener_counts[start['name']],
            'listener accepted an unaccounted connection/request')
        listener_lifetimes[start['name']] = (moment(start), moment(stop))
    for call in http['calls'].values():
        lower, upper = listener_lifetimes['http-' + call['request']['worker']]
        require(all(lower < moment(row) < upper for row in call['stages']),
            'HTTP event outside original listener lifetime')
    for row in data['history']:
        if 'request_serial' in row:
            lower, upper = listener_lifetimes['s3-' + row['worker']]
            require(lower < moment(row) < upper, 'S3 event outside original listener lifetime')
    # Response-delivery records are made after write(). They may be observed
    # after the caller/daemon has completed, but must precede handler join.
    proxy = only([r for r in events if r['event'] == 'proxy_stopped'], 'proxy stop missing')
    require(proxy['errors'] == [] and proxy['http_requests'] == 29 and proxy['s3_requests'] == len(net['requests'])
        and all(moment(stop) < moment(proxy) for stop in closed), 'proxy failed or omitted original exchange/join')
    cleanup = only([r for r in events if r['event'] == 'cleanup_finished'], 'cleanup result missing')
    require(cleanup['errors'] == [] and cleanup['private_preserved'] is True, 'unobserved cleanup/private disposal')
    for row in events:
        if row['event'] in ('node_stopped', 'service_stopped', 'backend_child_stopped', 'listener_closed'):
            require(moment(row) < moment(cleanup), 'cleanup preceded owned termination')
    unsigned = only([r for r in events if r['event'] == 'backend_unsigned_probe'], 'signed backend enforcement probe missing')
    capture(unsigned, 'body', 'sha256', 65536)
    require(unsigned['status'] == 403 and moment(backend_ready) < moment(unsigned)
        < min(moment(start) for start in listeners), 'backend accepted unsigned request or probe order changed')
    return {'workload_children': 8, 'version_children': 2, 'listeners_joined': 6}


def audit_projection(data, build):
    configuration_audit(data)
    http = http_audit(data)
    net = network_audit(data, http)
    durable = durable_audit(data, http, net)
    fault_audit(data, http, net)
    processes = process_audit(data, build, http, net)
    require(data['summary']['status'] == 'OBSERVED_NOT_AUDITED' and data['summary']['source_unchanged'] is True
        and data['summary']['cleanup_errors'] == [] and data['summary']['private_deleted'] is False,
        'original run did not finish cleanly')
    summary = data['summary']
    require(type(summary['started_monotonic_ns']) is int and type(summary['ended_monotonic_ns']) is int and
        summary['whole_run_within_original_bound'] is True and
        0 < summary['ended_monotonic_ns'] - summary['started_monotonic_ns'] <= 300000000000 and
        all(summary['started_monotonic_ns'] <= moment(row) <= summary['ended_monotonic_ns']
            for row in [*data['events'], *data['history']]), 'original whole-run/cleanup bound exceeded')
    return {'schema': 1, 'status': 'PASSED', 'commands': 30, 'posts': 29,
        'head_reads_p': 9, 'head_reads_q': 2, 's3_exchanges': len(net['requests']),
        'versions': net['versions'], 'durable': durable, 'processes': processes,
        'authority_only_status': True, 'automatic_failover': 'NOT_IMPLEMENTED',
        'aws_standard': 'NOT_RUN', 'production_slo': 'NOT_RUN'}


def load_projection(directory):
    directory = Path(directory)
    def rows(name):
        raw = (directory / name).read_bytes()
        require(raw and raw.endswith(b'\n') and len(raw) <= 268435456, 'incomplete or oversized original ledger')
        return [parse(line) for line in raw.splitlines()]
    require(sha((directory / 'inputs.json').read_bytes()) == INPUT_SHA, 'frozen input identity changed')
    data = {name: parse((directory / (name + '.json')).read_bytes())
        for name in ('summary', 'configuration', 'tools')}
    data.update(events=rows('events.jsonl'), history=rows('history.jsonl'), node=rows('node.jsonl'),
        service_configs={worker: parse((directory / ('service-' + worker + '.json')).read_bytes()) for worker in WORKERS},
        version_processes={name: parse((directory / (name + '-version-process.json')).read_bytes()) for name in ('node', 'weed')})
    data['file_hashes'] = {p.name: sha(p.read_bytes()) for p in directory.iterdir() if p.is_file()
        and p.name in {'node.jsonl', 'node-1.stderr.log', 'node-version.log', 'weed-version.log',
            *(f'service-{w}.{ext}' for w in WORKERS for ext in ('json', 'log'))}}
    wrappers = [r for r in data['events'] if r['event'] == 'node_event']
    original = (directory / 'node.jsonl').read_bytes().splitlines(keepends=True)
    require(len(wrappers) == len(original) == len(data['node']), 'SDK raw/parent ledger bijection failed')
    for wrapper, raw, parsed in zip(wrappers, original, data['node']):
        equal(capture(wrapper, 'raw', 'sha256', 1048576), raw, 'parent changed original SDK bytes')
        equal(parse(raw), parsed, 'Node trace projection differs')
    saved = only([r for r in data['node'] if r['event'] == 'saved_request'], 'saved request missing')
    equal((directory / 'seed-request.json').read_bytes(), b64(saved['raw']), 'persisted original SQL request changed')
    return data


def audit(directory, *, require_artifacts=True):
    directory = Path(directory)
    data = load_projection(directory)
    source = {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in sorted(HERE.iterdir()) if p.is_file()}
    equal(data['summary']['fixture_sources_before'], source, 'fixture source changed before independent audit')
    equal(data['summary']['fixture_sources_after'], source, 'fixture source changed during actual run')
    build = build_audit.receipt(directory, True, profile='service', require_artifacts=require_artifacts, source_root=ROOT)
    return audit_projection(data, build)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(not args.output.exists(), 'refuse to overwrite original audit')
    report = audit(args.evidence)
    with args.output.open('x') as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write('\n')
    print(json.dumps(report, sort_keys=True), flush=True)
