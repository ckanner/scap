#!/usr/bin/env python3
"""Independent, read-only owner contract audit over original byte/process traces.

No controller, fixture specification, SDK or service module is imported. The
offered command matrix below is deliberately independent of owner_spec.py.
Synthetic unit tests of this verifier do not count as real service evidence.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import signal
import struct
from urllib.parse import urlparse

from audit_wire import (b64, committed, decimal, equal, fingerprint, object_exchanges,
                        object_versions, parse, require, result, sha256_text)

WORKERS = {'a': '7101', 'b': '7202', 'c': '7303', 'd': '7404'}
NAMES = ('route', 'guard', 'race', 'late', 'lost_claim', 'lost_activation', 'corrupt',
         'acl', 'lifecycle', 'deadline', 'cold', 'recovery', 'rejects')
SCOPES = {name: {'deployment': '1', 'tenant': '7', 'database': str(1001 + index),
                 'incarnation': '1', 'generation': '1'} for index, name in enumerate(NAMES)}
PRINCIPALS = {'writer': '11', 'manager': '12', 'reader': '13', 'blind_admin': '14', 'rescue': '15'}
POLICY = [{'principal': str(principal), 'read': read, 'write': write, 'admin': admin}
          for principal, read, write, admin in ((11, True, True, False), (12, True, False, True),
                                               (13, True, False, False), (14, False, False, True),
                                               (15, True, False, True))]
SEED_SQL = ['CREATE TABLE witness(n INTEGER PRIMARY KEY)', 'INSERT INTO witness(n) VALUES(1) RETURNING n']
WRITE_SQL = 'INSERT INTO witness(n) VALUES(2) RETURNING n'
QUERY_SQL = 'SELECT n FROM witness ORDER BY n'
INITIAL_QUOTA_BYTES = 10737418240
INITIAL_RETENTION = {'max_entries': 4096, 'max_result_bytes': 268435456}
DEADLINES = {'ordinary_ms': 15000, 'recovery_ms': 30000, 's3_ms': 10000,
             'client_ms': 20000, 'owner_ms': 35000, 'short_ms': 250,
             'gate_seconds': 10, 'child_seconds': 40, 'ready_seconds': 20, 'actor_idle_ms': 5000}

# Tokens are destination:operation:observed-disposition. Dropped/deadline denote
# actual attempts, never permissions to omit the request or replay it elsewhere.
MATRIX = '''
seed - seed -
route_prepare route prepare a:status:200
route_reconcile route reconcile a:status:200,b:takeover:200,b:activate:200
route_write route routed_execute a:status:200,b:execute:200
route_lookup route lookup a:lookup:200
route_query route routed_query a:status:200,b:query:200
guard_prepare guard prepare a:status:200
guard_reconcile guard reconcile a:status:200,c:takeover:409
guard_inspect guard inspect a:status:200
race_prepare_b race prepare a:status:200
race_prepare_c race prepare a:status:200
race_b race reconcile a:status:200,b:takeover:200,b:activate:200
race_c race reconcile a:status:200,c:takeover:409
race_inspect_c race inspect a:status:200
late_prepare late prepare a:status:200
late_write late routed_execute a:status:200,a:execute:409
late_reconcile late reconcile c:status:200,b:takeover:200,b:activate:200
late_lookup late lookup a:lookup:200
late_cancel late cancel a:cancel:200
late_cancelled late lookup a:lookup:200
late_query late routed_query a:status:200,b:query:200
claim_prepare lost_claim prepare a:status:200
claim_lost lost_claim reconcile a:status:200,b:takeover:dropped
claim_inspect lost_claim inspect a:status:200
claim_reuse lost_claim reuse -
claim_restored_reuse lost_claim restore_reuse -
claim_activation_prepare lost_claim prepare_activation a:status:200
claim_activation lost_claim reconcile a:status:200,b:activate:200
activation_prepare lost_activation prepare a:status:200
activation_lost lost_activation reconcile a:status:200,b:takeover:200,b:activate:dropped
activation_advance lost_activation quota a:quota:200
activation_inspect lost_activation inspect a:status:200
corrupt_prepare corrupt prepare a:status:200
corrupt_reconcile corrupt reconcile a:status:200,b:takeover:200,b:activate:409
corrupt_inspect corrupt inspect a:status:200
corrupt_activation_prepare corrupt prepare_activation a:status:200
corrupt_activation corrupt reconcile a:status:200,b:activate:200
corrupt_query corrupt routed_query a:status:200,b:query:200
acl_prepare acl prepare a:status:200
acl_reconcile acl reconcile a:status:200,b:takeover:403
acl_revoke acl revoke_admin a:policy:200
acl_reuse acl reuse -
lifecycle_prepare lifecycle prepare a:status:200
lifecycle_change lifecycle lifecycle a:lifecycle:200
lifecycle_reconcile lifecycle reconcile a:status:200
lifecycle_inspect lifecycle inspect a:status:200
lifecycle_write lifecycle routed_execute a:status:200
recovery_warm route routed_query a:status:200,b:query:200
recovery_prepare recovery prepare a:status:200
recovery_reconcile recovery reconcile a:status:200,b:takeover:200,b:activate:200
recovery_hot route routed_query a:status:200,b:query:200
recovery_control recovery status a:status:200
reject_unknown_route rejects routed_execute a:status:200
reject_auth rejects routed_execute a:status:401
reject_read rejects routed_execute a:status:403
busy_held rejects status a:status:200
reject_busy rejects routed_execute a:status:429
reject_redirect rejects routed_execute a:status:redirect
reject_authority rejects routed_execute a:status:503
deadline_write deadline routed_execute a:status:deadline
cold_write cold routed_execute a:status:200,a:execute:200
bootstrap_inspect lost_activation restore_inspect c:status:200
bootstrap_reuse lost_activation restore_reuse -
bootstrap_changed_route lost_activation restore_invalid_route -
bootstrap_wrong_scope lost_activation restore_wrong_scope -
cold_prepare cold prepare c:status:200
cold_reconcile cold reconcile c:status:200,d:takeover:200,d:activate:200
cold_lookup_seed cold lookup c:lookup:200
cold_lookup_write cold lookup c:lookup:200
cold_query cold routed_query c:status:200,d:query:200
'''

CASES = {}
for _line in MATRIX.strip().splitlines():
    _name, _scope, _operation, _calls = _line.split()
    CASES[_name] = {'scope': None if _scope == '-' else _scope, 'operation': _operation,
                   'http': [] if _calls == '-' else [tuple(token.split(':')) for token in _calls.split(',')]}

PREPARED = {
    'route_prepare': ('route', 'b', '4', '1', 'a', True, '101', '102'),
    'guard_prepare': ('guard', 'b', '4', '1', 'a', True, '201', '202'),
    'race_prepare_b': ('race', 'b', '4', '1', 'a', True, '301', '302'),
    'race_prepare_c': ('race', 'c', '4', '1', 'a', True, '303', '304'),
    'late_prepare': ('late', 'b', '4', '1', 'a', True, '401', '402'),
    'claim_prepare': ('lost_claim', 'b', '4', '1', 'a', True, '501', '502'),
    'claim_activation_prepare': ('lost_claim', 'b', '5', '2', 'b', False, None, '503'),
    'activation_prepare': ('lost_activation', 'b', '4', '1', 'a', True, '601', '602'),
    'corrupt_prepare': ('corrupt', 'b', '4', '1', 'a', True, '701', '702'),
    'corrupt_activation_prepare': ('corrupt', 'b', '5', '2', 'b', False, None, '703'),
    'acl_prepare': ('acl', 'b', '4', '1', 'a', True, '801', '802'),
    'lifecycle_prepare': ('lifecycle', 'b', '4', '1', 'a', True, '901', '902'),
    'recovery_prepare': ('recovery', 'b', '4', '1', 'a', True, '1001', '1002'),
    'cold_prepare': ('cold', 'd', '5', '1', 'a', True, '1101', '1102'),
}
INTENT_FOR = {
    **{name: name for name in PREPARED},
    **dict.fromkeys(('route_reconcile',), 'route_prepare'),
    **dict.fromkeys(('guard_reconcile', 'guard_inspect'), 'guard_prepare'),
    'race_b': 'race_prepare_b', 'race_c': 'race_prepare_c', 'race_inspect_c': 'race_prepare_c',
    'late_reconcile': 'late_prepare',
    **dict.fromkeys(('claim_lost', 'claim_inspect', 'claim_reuse', 'claim_restored_reuse'), 'claim_prepare'),
    'claim_activation': 'claim_activation_prepare',
    **dict.fromkeys(('activation_lost', 'activation_inspect', 'bootstrap_inspect', 'bootstrap_reuse',
                     'bootstrap_changed_route', 'bootstrap_wrong_scope'), 'activation_prepare'),
    **dict.fromkeys(('corrupt_reconcile', 'corrupt_inspect'), 'corrupt_prepare'),
    'corrupt_activation': 'corrupt_activation_prepare',
    **dict.fromkeys(('acl_reconcile', 'acl_reuse'), 'acl_prepare'),
    **dict.fromkeys(('lifecycle_reconcile', 'lifecycle_inspect'), 'lifecycle_prepare'),
    'recovery_reconcile': 'recovery_prepare', 'cold_reconcile': 'cold_prepare',
}
REQUEST_FOR = {'route_lookup': 'route_write', 'late_lookup': 'late_write', 'late_cancel': 'late_write',
               'late_cancelled': 'late_write', 'cold_lookup_seed': 'seed_cold', 'cold_lookup_write': 'cold_write'}
REQUEST_IDS = {'route_write': '2', 'late_write': '2', 'lifecycle_write': '2', 'deadline_write': '2',
               'cold_write': '2', **{name: str(index) for index, name in enumerate(
                   ('reject_unknown_route', 'reject_auth', 'reject_read', 'reject_busy', 'reject_redirect', 'reject_authority'), 2)}}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def rows(directory, name):
    raw = (Path(directory) / name).read_bytes()
    require(raw and raw.endswith(b'\n'), name + ': incomplete original ledger')
    return [parse(line) for line in raw.splitlines()]


def only(values, message):
    require(len(values) == 1, message)
    return values[0]


def stamp(row):
    value = row['monotonic_ns']
    require(type(value) is int or isinstance(value, str) and re.fullmatch(r'[1-9][0-9]*', value),
            'invalid original monotonic clock')
    require(int(value) > 0, 'invalid original monotonic clock')
    return int(value)


def numbered(ledger, *, node=False):
    require(ledger, 'empty original ledger')
    require(all(type(row.get('schema')) is int and row['schema'] == 1 and type(row.get('sequence')) is int
                for row in ledger), 'trace schema/sequence type changed')
    equal([row['sequence'] for row in ledger], list(range(1, len(ledger) + 1)), 'missing/repeated original trace row')
    require(all(type(row['monotonic_ns']) is (str if node else int) for row in ledger), 'trace clock representation changed')
    require(all(stamp(left) < stamp(right) for left, right in zip(ledger, ledger[1:])), 'original trace clock order')


def bounded_bytes(row, field, digest_field, maximum=4 * 1024 * 1024):
    raw = b64(row[field])
    require(len(raw) <= maximum and sha(raw) == sha256_text(row[digest_field]), 'complete original bytes/digest changed: ' + field)
    return raw


def plan(value):
    require(type(value.get('schema')) is int and value['schema'] == 1 and
            value['profile'] == 'explicit-owner-real-transport-v1', 'owner plan identity changed')
    for key, expected in (('workers', WORKERS), ('scopes', SCOPES), ('seed_scopes', list(NAMES)), ('principals', PRINCIPALS), ('policy', POLICY),
                          ('seed_sql', SEED_SQL), ('write_sql', WRITE_SQL), ('query_sql', QUERY_SQL), ('deadlines', DEADLINES),
                          ('seed_nonce_base', 10000)):
        equal(value[key], expected, 'frozen owner plan changed: ' + key)
    for key, expected in (('automatic_failure_detector', 'NOT_IMPLEMENTED'), ('automatic_controller', 'NOT_IMPLEMENTED'),
                          ('automatic_registry_roll_forward', 'NOT_IMPLEMENTED'), ('aws_standard', 'NOT_RUN'), ('production_slo', 'NOT_RUN')):
        equal(value[key], expected, 'unexecuted owner capability claimed: ' + key)
    commands = value['commands']
    equal([item['id'] for item in commands], list(CASES), 'offered command denominator/order changed')
    for item in commands:
        name, fixed = item['id'], CASES[item['id']]
        require(set(item) <= {'id', 'scope', 'operation', 'phase', 'http', 'target', 'takeover_nonce', 'activate_nonce',
                             'intent', 'bootstrap', 'registry', 'request', 'request_id', 'revision', 'nonce', 'caller', 'timeout_ms', 'node'},
                'unreviewed owner plan command field')
        equal(item['scope'], fixed['scope'], 'command scope changed')
        equal(item['operation'], fixed['operation'], 'command kind changed')
        equal(item['http'], [[worker, operation, int(status) if status.isdecimal() else status]
                             for worker, operation, status in fixed['http']], 'fixed HTTP denominator changed')
        expected_phase = 'seed' if name == 'seed' else 'recovery' if name in ('recovery_warm', 'recovery_hot') else fixed['scope']
        equal(item['phase'], expected_phase, 'command phase changed')
        if name in PREPARED:
            scope, target, revision, epoch, owner, active, takeover, activate = PREPARED[name]
            equal(item['activate_nonce'], activate, 'original activation nonce changed')
            if takeover is not None:
                equal([item['target'], item['takeover_nonce']], [target, takeover], 'original takeover target/nonce changed')
        if name in INTENT_FOR and name not in PREPARED:
            equal(item['intent'], INTENT_FOR[name], 'command names another original intent')
        if name in REQUEST_FOR:
            equal(item['request'], REQUEST_FOR[name], 'lookup/cancel names another original request')
        if name in REQUEST_IDS:
            equal(item['request_id'], REQUEST_IDS[name], 'original request identity changed')
        equal(item.get('node', 1), 2 if name.startswith('bootstrap_') or name.startswith('cold_') and name != 'cold_write' else 1,
              'command assigned to another actual Node incarnation')
        equal(item.get('bootstrap', 'a'), 'c' if name == 'late_reconcile' or name.startswith('bootstrap_') or name.startswith('cold_') and name != 'cold_write' else 'a',
              'explicit bootstrap destination changed')
        equal(item.get('registry'), 'misbound' if name.startswith('guard_') else 'unknown' if name == 'reject_unknown_route' else None,
              'configured trusted mutation registry changed')
        equal(item.get('timeout_ms'), 250 if name == 'deadline_write' else None, 'fixed absolute operation deadline changed')
        if name in ('activation_advance', 'acl_revoke', 'lifecycle_change'):
            equal([item['revision'], item['nonce']], ['6', '603'] if name == 'activation_advance' else
                  ['4', '803'] if name == 'acl_revoke' else ['4', '903'], 'explicit competing administrative identity changed')
        expected_caller = {'acl_revoke': 'rescue', 'recovery_control': 'manager', 'busy_held': 'manager',
                           'reject_auth': 'invalid', 'reject_read': 'blind_admin'}.get(name)
        equal(item.get('caller'), expected_caller, 'command authenticated caller changed')
    require(len(CASES) == 70 and sum(len(value['http']) for value in CASES.values()) + 52 == 144,
            'independent owner denominator is not frozen')
    return {item['id']: item for item in commands}


def statement(sql):
    return {'sql': sql, 'params': []}


def tracked(scope, identifier, *, seed=False, principal='11'):
    statements = [statement(sql) for sql in SEED_SQL] if seed else [statement(WRITE_SQL)]
    return {'scope': SCOPES[scope], 'request': {'epoch': '1', 'id': identifier, 'principal': principal,
                                             'fingerprint': fingerprint(statements)}, 'statements': statements}


def envelope(raw):
    value = parse(raw)
    require(type(value.get('ok')) is bool, 'HTTP envelope lacks explicit outcome')
    require(set(value) == ({'ok', 'value'} if value['ok'] else {'ok', 'error'}), 'HTTP envelope fields changed')
    if not value['ok']:
        require(set(value['error']) == {'code', 'message'} and value['error']['code'] == value['error']['message'],
                'unplanned service rejection envelope')
    return value


def value_of(call):
    require(call['value']['ok'] is True and call['response']['status'] == 200, 'expected original successful service response')
    return call['value']['value']


def caller(command, operation):
    if command in ('reject_auth',): return 'invalid'
    if command == 'reject_read': return 'blind_admin'
    if command == 'acl_revoke': return 'rescue'
    if command == 'seed' or operation in ('execute', 'query', 'lookup', 'cancel') or CASES[command]['operation'] in ('routed_execute', 'routed_query'): return 'writer'
    return 'manager'


def native_policy(value):
    return [{**entry, 'principal': int(entry['principal'])} for entry in value]


def initial_limits(head):
    equal(head['quota'], {'max_bytes': INITIAL_QUOTA_BYTES}, 'initial persisted quota differs from frozen service default')
    equal(head['retention'], INITIAL_RETENTION, 'initial persisted retention differs from frozen service default')


def status_from_head(head):
    return {'scope': {key: str(number) for key, number in head['scope'].items()},
            **{key: str(head[key]) for key in ('revision', 'sequence', 'owner_epoch', 'owner_instance', 'auth_epoch', 'request_epoch')},
            'active': head['active'], 'lifecycle': head['lifecycle'],
            'max_bytes': None if head['quota']['max_bytes'] is None else str(head['quota']['max_bytes']),
            'transition': {key: str(value) for key, value in head['transition'].items()},
            'retention': {'max_entries': head['retention']['max_entries'],
                          'max_result_bytes': str(head['retention']['max_result_bytes']),
                          'oldest_epoch': str(head['windows'][-1]['epoch'] if head['windows'] else head['request_epoch'])}}


def result_expected(raw, *, seed=False, values=None, inserted=None):
    decoded = result(raw)
    expected = []
    if seed:
        expected.append({'columns': [], 'rows': [], 'affected_rows': 0, 'last_insert_rowid': 0})
        inserted = 1
    expected.append({'columns': ['n'], 'rows': [[value] for value in (values if values is not None else [inserted])],
                     'affected_rows': 0 if inserted is None else 1, 'last_insert_rowid': inserted or 0})
    equal(decoded, expected, 'complete SQLite result/metadata differs from fixed workload')
    return decoded


def sdk_result(decoded):
    return {'statements': [{'columns': row['columns'], 'rows': [[{'integer': str(value)} for value in values] for values in row['rows']],
             'affectedRows': {'integer': str(row['affected_rows'])},
             'lastInsertRowid': {'integer': str(row['last_insert_rowid'])}} for row in decoded]}


def object_frame(raw, path):
    require(raw[:8] == b'SCAPOBJ2' and len(raw) >= 20 and sha(raw) == path.rsplit('/', 1)[1], 'immutable object body/key changed')
    metadata_length, raw_length = struct.unpack_from('<IQ', raw, 8)
    require(20 + metadata_length + raw_length == len(raw), 'immutable frame extent changed')
    metadata = parse(raw[20:20 + metadata_length])
    require(set(metadata) == {'format', 'scope', 'payload'} and type(metadata['format']) is int and metadata['format'] == 2,
            'immutable frame metadata changed')
    scope = metadata['scope']
    require(all(type(value) is int and value > 0 for value in scope.values()), 'immutable scope numeric type changed')
    expected = '/scap-test/scap-object/v1/{deployment}/{tenant}/{database}/inc/{incarnation}/gen/{generation}/storage/1/objects/'.format(**scope)
    require(path == expected + sha(raw), 'immutable frame scope/key changed')
    return metadata['payload'], raw[20 + metadata_length:]


def data_closure(objects, scope, root):
    prefix = '/scap-test/scap-object/v1/{deployment}/{tenant}/{database}/inc/{incarnation}/gen/{generation}/storage/1/objects/'.format(**SCOPES[scope])
    selected = set()
    def load(digest, kind):
        path = prefix + sha256_text(digest)
        require(path in objects, 'missing complete data dependency')
        selected.add(path)
        payload, raw = object_frame(objects[path], path)
        require(set(payload) == {'kind', 'value'} and payload['kind'] == kind, 'wrong typed data dependency')
        return payload['value'], raw
    manifest, raw = load(root, 'manifest')
    require(not raw and set(manifest) == {'page_count', 'root'} and type(manifest['page_count']) is int and
            0 <= manifest['page_count'] <= 32, 'owner fixture database extent changed')
    if manifest['page_count'] == 0:
        require(manifest['root'] is None, 'empty image retained a data root')
        return selected
    node, raw = load(manifest['root'], 'node')
    equal(node, {'level': 0, 'first_chunk': 0, 'children': node['children']}, 'data node extent changed')
    require(not raw and len(node['children']) == 1, 'owner fixture root children changed')
    chunk, raw = load(node['children'][0], 'chunk')
    equal(chunk, {'first_page': 1, 'bytes': []}, 'data chunk metadata changed')
    require(len(raw) == manifest['page_count'] * 4096 and raw[:18] == b'SQLite format 3\0\x10\0', 'complete SQLite image extent changed')
    return selected


def registry_digest(routes):
    ordered = sorted(routes, key=lambda item: int(item[0]))
    return sha(json.dumps(ordered, ensure_ascii=False, separators=(',', ':')).encode())


def expected_intent(name, routes):
    scope, target, revision, epoch, owner, active, takeover, activate = PREPARED[name]
    return {'version': 1, 'scope': SCOPES[scope], 'principal': '12', 'registryDigest': registry_digest(routes),
            'mode': 'activate' if takeover is None else 'takeover', 'baseRevision': revision,
            'baseOwnerEpoch': epoch, 'baseOwnerInstance': WORKERS[owner], 'baseActive': active,
            'targetWorker': WORKERS[target], 'takeoverNonce': takeover, 'activateNonce': activate}


def expected_action(command, operation, *, scope=None):
    name = scope or CASES[command]['scope']
    body = {'version': 1, 'scope': SCOPES[name], 'operation': operation}
    if command == 'seed':
        nonce = 10000 + NAMES.index(name) * 10
        if operation == 'create': body['nonce'] = str(nonce)
        elif operation == 'activate': body.update(expected_revision='1', nonce=str(nonce + 1), expected_worker_instance=WORKERS['a'])
        elif operation == 'execute':
            original = tracked(name, '1', seed=True)
            body.update(request=original['request'], statements=original['statements'])
        elif operation == 'policy': body.update(expected_revision='3', nonce=str(nonce + 2), permissions=POLICY)
        else: raise ValueError('unexpected seed operation')
    elif operation in ('takeover', 'activate'):
        prepared = INTENT_FOR[command]
        _, target, revision, epoch, owner, active, takeover, activate = PREPARED[prepared]
        body.update(expected_revision=str(int(revision) + (operation == 'activate' and takeover is not None)),
                    nonce=takeover if operation == 'takeover' else activate, expected_worker_instance=WORKERS[target])
    elif operation == 'execute':
        original = tracked(name, REQUEST_IDS[command], principal=PRINCIPALS.get(caller(command, operation), '11'))
        body.update(request=original['request'], statements=original['statements'])
    elif operation == 'query': body['statements'] = [statement(QUERY_SQL)]
    elif operation in ('lookup', 'cancel'):
        original = REQUEST_FOR[command]
        body['request'] = tracked(name, '1' if original.startswith('seed_') else '2', seed=original.startswith('seed_'))['request']
    elif operation == 'quota': body.update(expected_revision='6', nonce='603', max_bytes=None)
    elif operation == 'policy':
        changed = [{**entry, 'admin': False} if entry['principal'] == '12' else entry for entry in POLICY]
        body.update(expected_revision='4', nonce='803', permissions=changed)
    elif operation == 'lifecycle': body.update(expected_revision='4', nonce='903', lifecycle='maintenance')
    else: require(operation == 'status', 'unplanned operation')
    return body


def node_traces(directory, events, specifications):
    nodes, operations, saved = {}, {}, {}
    parent_nodes = defaultdict(list)
    for row in events:
        if row['event'] == 'node_event':
            require(row['node'] in (1, 2) and type(row['node']) is int, 'node event identity changed')
            raw = bounded_bytes(row, 'raw', 'sha256')
            require(raw.endswith(b'\n') and raw.count(b'\n') == 1, 'Node record is not one original complete line')
            inner = parse(raw)
            require(stamp(inner) < stamp(row), 'parent observed Node output before emission')
            parent_nodes[row['node']].append(raw)
    for node in (1, 2):
        path = Path(directory) / f'node-{node}.jsonl'
        raw = path.read_bytes()
        equal(raw, b''.join(parent_nodes[node]), 'independent Node fsync ledger differs from original stdout records')
        trace = rows(directory, path.name)
        numbered(trace, node=True)
        require(all(type(row.get('node')) is int and row['node'] == node and row['event'] in
                    {'hello', 'finished', 'command_started', 'command_finished', 'saved_intent', 'saved_request',
                     'restored_intent', 'http_request', 'http_response', 'http_error'} for row in trace),
                'Node trace contains an unowned/unplanned event')
        nodes[node] = trace
        require(trace[0]['event'] == 'hello', 'Node self PID witness is not first')
        for row in trace[1:]:
            if row['event'] == 'finished':
                require(row is trace[-1], 'Node finished before final original event')
                continue
            name = row.get('command')
            require(name in specifications and specifications[name].get('node', 1) == node, 'Node effect belongs to an unoffered command')
        for name, specification in specifications.items():
            if specification.get('node', 1) != node: continue
            command = [row for row in trace if row.get('command') == name]
            begin = only([row for row in command if row['event'] == 'command_started'], 'command start denominator changed')
            finish = only([row for row in command if row['event'] == 'command_finished'], 'command outcome denominator changed')
            require(command[0] is begin and type(finish['ok']) is bool,
                    'SDK effects outside original command interval')
            require(all(stamp(row) <= stamp(finish) or name == 'deadline_write' and row['event'] == 'http_error'
                        for row in command), 'post-completion SDK effect is not a settling aborted read')
            require(stamp(finish) - stamp(begin) < DEADLINES['child_seconds'] * 10**9, 'command exceeded fixed harness bound')
            offered = only([row for row in events if row['event'] == 'operator_command' and row['id'] == name], 'offered input missing/repeated')
            equal(parse(bounded_bytes(offered, 'raw', 'sha256', 65536)), {'id': name}, 'operator sent unplanned input')
            require(offered['node'] == node and stamp(offered) < stamp(begin), 'input was not persisted before SDK effects')
            operations[name] = {'start': begin, 'finish': finish, 'trace': command, 'node': node}
            for row in command:
                if row['event'] in ('saved_intent', 'saved_request'):
                    require(row['key'] not in saved, 'saved identity silently overwritten')
                    raw = bounded_bytes(row, 'raw', 'sha256', 16384)
                    saved[row['key']] = {'event': row, 'raw': raw, 'value': parse(raw)}
    require(len(operations) == 70 and len([row for row in events if row['event'] == 'operator_command' and row['id'] != 'shutdown']) == 70,
            'unaccounted offered command')
    shutdowns = [row for row in events if row['event'] == 'operator_command' and row['id'] == 'shutdown']
    equal(Counter(row['node'] for row in shutdowns), Counter((1, 2)), 'shutdown controls missing/repeated')
    for node, trace in nodes.items():
        finished = trace[-1]
        require(finished['event'] == 'finished', 'Node final complete observation omitted')
        count = sum(item['node'] == node for item in operations.values())
        attempts = sum(row['event'] == 'http_request' for row in trace)
        equal([finished['commands'], finished['http_attempts']], [count, attempts], 'Node final denominator hid an invocation/retry')
        offered = only([row for row in shutdowns if row['node'] == node], 'shutdown control inventory')
        equal(parse(bounded_bytes(offered, 'raw', 'sha256', 65536)), {'id': 'shutdown'}, 'shutdown input changed')
        require(max(stamp(item['finish']) for item in operations.values() if item['node'] == node) < stamp(offered) < stamp(finished),
                'Node shutdown preceded original workload completion')
    return nodes, operations, saved


def http_exchanges(events, nodes, operations, configuration):
    endpoints, credentials = configuration['endpoints'], configuration['credential_sha256']
    require(set(endpoints) == set(WORKERS), 'trusted endpoint inventory changed')
    require(len(set(endpoints.values())) == 4, 'worker routes alias the same original service relay')
    for endpoint in endpoints.values():
        value = urlparse(endpoint)
        require(value.scheme == 'http' and value.hostname == '127.0.0.1' and value.port and value.path == '/v1'
                and not value.username and not value.password and not value.query and not value.fragment, 'untrusted fixture destination')
    require(set(credentials) == set(PRINCIPALS) | {'invalid'} and len(set(credentials.values())) == 6, 'credential role inventory changed')
    for digest in credentials.values(): sha256_text(digest)
    relay = defaultdict(list)
    for row in events:
        if row['event'] in ('http_request', 'http_forwarded', 'http_response', 'http_delivered', 'http_response_suppressed'):
            relay[row['http_serial']].append(row)
    require(all(type(serial) is int for serial in relay) and sorted(relay) == list(range(1, 145)),
            'actual relay POST denominator is not exactly 144')
    calls, binding = {}, {}
    for node, trace in nodes.items():
        requests = [row for row in trace if row['event'] == 'http_request']
        equal([row['serial'] for row in requests], list(range(1, len(requests) + 1)), 'Node Fetch attempt serial gap/retry')
        for request in requests:
            name, serial = request['command'], request['serial']
            raw = bounded_bytes(request, 'body', 'body_sha256', 65536)
            equal(request['method'], 'POST', 'actual Fetch method changed')
            require(request['url'] in endpoints.values(), 'Fetch followed an untrusted destination')
            worker = next(key for key, endpoint in endpoints.items() if endpoint == request['url'])
            body = parse(raw)
            admission = 'recovery' if body['operation'] in ('activate', 'open') else 'data' if body['operation'] in ('create', 'execute', 'query') else 'control'
            equal(request['admission'], admission, 'original SDK admission class changed')
            role = caller(name, body['operation'])
            equal(request['credential_sha256'], credentials[role], 'Fetch used another authenticated principal')
            original = only([row for rows_ in relay.values() for row in rows_ if row['event'] == 'http_request' and
                             row['command'] == name and row['worker'] == worker and b64(row['request_body']) == raw],
                            'Fetch has no unique matching real HTTP request')
            number = original['http_serial']
            require(number not in binding, 'two Fetch attempts bound the same actual POST')
            binding[number] = (node, serial)
            require(stamp(request) < stamp(original), 'relay request preceded original Fetch')
            trace_rows = relay[number]
            groups = {event: [row for row in trace_rows if row['event'] == event]
                      for event in ('http_forwarded', 'http_response', 'http_delivered', 'http_response_suppressed')}
            response = only(groups['http_response'], 'actual service/redirect response omitted/duplicated')
            require(stamp(original) < stamp(response), 'response preceded actual POST')
            for row in trace_rows:
                for key in ('http_serial', 'worker', 'command', 'method', 'path', 'request_body', 'request_sha256', 'credential_sha256'):
                    equal(row[key], original[key], 'HTTP relay changed original request: ' + key)
                bounded_bytes(row, 'request_body', 'request_sha256', 65536)
            require(original['method'] == 'POST' and original['path'] == '/v1', 'relay accepted another operation endpoint')
            equal(original['credential_sha256'], request['credential_sha256'], 'credential changed in actual relay')
            response_raw = bounded_bytes(response, 'response_body', 'response_sha256')
            actual = [row for row in trace if row.get('serial') == serial and row['event'] in ('http_response', 'http_error')]
            terminal = only(actual, 'Fetch terminal outcome omitted/duplicated')
            require(stamp(response) < stamp(terminal), 'Fetch completed before original relay response')
            if response['origin'] == 'fault_redirect':
                require(name == 'reject_redirect' and response['status'] == 307 and not response_raw and
                        not groups['http_forwarded'] and terminal['event'] == 'http_error', 'redirect was forwarded/followed')
                value = None
            else:
                require(response['origin'] == 'service', 'fabricated owner response origin')
                forwarded = only(groups['http_forwarded'], 'service response has no actual forwarded request')
                require(stamp(original) < stamp(forwarded) < stamp(response), 'invalid actual HTTP forwarding interval')
                value = envelope(response_raw)
            if name in ('claim_lost', 'activation_lost') and body['operation'] != 'status' and (
                    name == 'claim_lost' or body['operation'] == 'activate'):
                require(response['status'] == 200 and response['suppressed'] is True and not groups['http_delivered'] and
                        terminal['event'] == 'http_error', 'lost response was not an actual successful service mutation')
                suppressed = only(groups['http_response_suppressed'], 'missing original response loss terminal')
                require(suppressed['reason'] == 'explicit_response_loss' and stamp(response) < stamp(suppressed) < stamp(terminal),
                        'response loss ordering changed')
            elif name == 'deadline_write':
                require(response['status'] == 200 and terminal['event'] == 'http_error' and not groups['http_delivered'],
                        'deadline did not stop at original status')
                suppressed = only(groups['http_response_suppressed'], 'missing deadline response suppression')
                require(suppressed['reason'] == 'original_client_deadline' and stamp(operations[name]['finish']) < stamp(suppressed),
                        'deadline response discarded before original Fetch timed out')
            else:
                require(response['suppressed'] is False and not groups['http_response_suppressed'], 'unplanned HTTP response loss')
                delivered = only(groups['http_delivered'], 'original response was not delivered')
                require(stamp(response) < stamp(delivered), 'HTTP delivery preceded service response')
                for key in ('status', 'response_body', 'response_sha256', 'headers', 'origin', 'suppressed'):
                    equal(delivered[key], response[key], 'HTTP delivery changed original response')
                if terminal['event'] == 'http_response':
                    equal(bounded_bytes(terminal, 'body', 'body_sha256'), response_raw, 'Fetch received another original response')
                    equal(terminal['status'], response['status'], 'Fetch status changed')
                else: require(name == 'reject_redirect', 'unplanned Fetch transport error')
            calls[number] = {'request': original, 'response': response, 'body': body, 'value': value,
                             'fetch': request, 'terminal': terminal, 'node': node, 'worker': worker, 'command': name}
    require(set(binding) == set(relay), 'extra HTTP POST had no original SDK Fetch')
    by_command = defaultdict(list)
    for call in sorted(calls.values(), key=lambda call: stamp(call['fetch'])):
        by_command[call['command']].append(call)
    for name, case in CASES.items():
        expected = [('a', operation, '200') for _ in NAMES for operation in ('create', 'activate', 'execute', 'policy')] if name == 'seed' else case['http']
        selected = by_command[name]
        require(len(selected) == len(expected), 'SQL replay/omitted phase: ' + name)
        for index, (call, (worker, operation, disposition)) in enumerate(zip(selected, expected)):
            equal([call['worker'], call['body']['operation']], [worker, operation], 'actual route/phase changed: ' + name)
            expected_status = 200 if disposition in ('dropped', 'deadline') else 307 if disposition == 'redirect' else int(disposition)
            equal(call['response']['status'], expected_status, 'actual phase status changed: ' + name)
            equal(call['body'], expected_action(name, operation, scope=NAMES[index // 4] if name == 'seed' else None),
                  'original phase body/identity/guard changed: ' + name)
            operation_interval = operations[name]
            require(stamp(operation_interval['start']) < stamp(call['fetch']) < stamp(operation_interval['finish']) and
                    stamp(call['fetch']) < stamp(call['terminal']) and
                    (stamp(call['terminal']) < stamp(operation_interval['finish']) or name == 'deadline_write'),
                    'Fetch dispatch outside offered operation interval')
            if index:
                require(stamp(selected[index - 1]['terminal']) < stamp(call['fetch']), 'later phase dispatched before original prior outcome')
    return calls, by_command


def sdk_committed(value, *, seed=False):
    raw, _ = committed(value)
    decoded = result_expected(raw, seed=seed, inserted=None if seed else 2)
    return {'state': 'committed', 'receipt': value['receipt'], 'rawResult': {'bytes': value['result'], 'sha256': sha(raw)},
            'result': sdk_result(decoded)}


def sdk_outcomes(directory, nodes, operations, saved, by_command, configuration):
    endpoints = configuration['endpoints']
    trusted = [[WORKERS[key], endpoints[key]] for key in WORKERS]
    misbound = [[WORKERS[key], endpoints['c'] if key == 'b' else endpoints[key]] for key in ('a', 'b', 'd')]
    expected_saved = {name: expected_intent(name, misbound if name == 'guard_prepare' else trusted) for name in PREPARED}
    for scope in NAMES:
        expected_saved['seed_' + scope] = tracked(scope, '1', seed=True)
    for name, identifier in REQUEST_IDS.items():
        expected_saved[name] = tracked(CASES[name]['scope'], identifier,
                                       principal=PRINCIPALS.get(caller(name, 'execute'), '11'))
    equal(sorted(saved), sorted(expected_saved), 'saved original identity denominator changed')
    for key, original in saved.items():
        row = original['event']
        kind = 'intent' if key in PREPARED else 'request'
        equal(row['event'], 'saved_' + kind, 'saved descriptor kind changed')
        equal(row['file'], f'{kind}-{key}.json', 'saved original file path changed')
        equal(original['value'], expected_saved[key], 'saved original input/nonce/registry changed: ' + key)
        equal((Path(directory) / row['file']).read_bytes(), original['raw'], 'saved original file bytes changed')
        for call in by_command[row['command']]:
            effects = ('takeover', 'activate') if kind == 'intent' else ('execute',)
            if call['body']['operation'] in effects and call['body']['scope'] == original['value']['scope']:
                require(stamp(row) < stamp(call['fetch']), 'descriptor was not persisted before first effect')
    restores = [row for trace in nodes.values() for row in trace if row['event'] == 'restored_intent']
    equal(Counter(row['command'] for row in restores), Counter(('claim_restored_reuse', 'bootstrap_inspect', 'bootstrap_reuse',
                                                              'bootstrap_changed_route', 'bootstrap_wrong_scope')),
          'restored intent denominator changed')
    for row in restores:
        key = INTENT_FOR[row['command']]
        require(row['key'] == key and row['file'] == saved[key]['event']['file'], 'restore used another saved identity')
        equal(bounded_bytes(row, 'raw', 'sha256', 16384), saved[key]['raw'], 'restore regenerated original intent')
        require(stamp(saved[key]['event']) < stamp(row), 'restore preceded original persistence')

    inspect_states = {'guard_inspect': 'base_observed', 'race_inspect_c': 'superseded', 'claim_inspect': 'takeover_accepted',
                      'activation_inspect': 'target_active', 'corrupt_inspect': 'takeover_accepted',
                      'lifecycle_inspect': 'blocked', 'bootstrap_inspect': 'target_active'}
    owner_errors = {
        'guard_reconcile': ('TARGET_MISMATCH', 'takeover', 'unresolved', False),
        'race_c': ('CONFLICT', 'takeover', 'unresolved', False),
        'claim_lost': ('UNKNOWN', 'takeover', 'unknown', False),
        'claim_reuse': ('INTENT_USED', 'observe', 'not_sent', False),
        'claim_restored_reuse': ('INTENT_USED', 'observe', 'not_sent', False),
        'activation_lost': ('UNKNOWN', 'activate', 'unknown', True),
        'corrupt_reconcile': ('CORRUPT', 'activate', 'partial', True),
        'acl_reconcile': ('DENIED', 'takeover', 'unresolved', False),
        'acl_reuse': ('INTENT_USED', 'observe', 'not_sent', False),
        'lifecycle_reconcile': ('SUPERSEDED', 'observe', 'not_sent', False),
        'bootstrap_reuse': ('INTENT_USED', 'observe', 'not_sent', False),
    }
    routed_errors = {'reject_unknown_route': {'UNROUTABLE'}, 'reject_auth': {'UNAUTHENTICATED'},
                     'reject_read': {'DENIED'}, 'reject_busy': {'BACKPRESSURE'}, 'reject_redirect': {'TRANSPORT'},
                     'reject_authority': {'UNKNOWN'}, 'deadline_write': {'ABORTED', 'DEADLINE'},
                     'lifecycle_write': {'LIFECYCLE'}}
    rejection_codes = {('guard_reconcile', 'takeover'): 'TARGET_MISMATCH', ('race_c', 'takeover'): 'CONFLICT',
                       ('late_write', 'execute'): 'CONFLICT', ('corrupt_reconcile', 'activate'): 'CORRUPT',
                       ('acl_reconcile', 'takeover'): 'DENIED', ('reject_auth', 'status'): 'UNAUTHENTICATED',
                       ('reject_read', 'status'): 'DENIED', ('reject_busy', 'status'): 'BACKPRESSURE',
                       ('reject_authority', 'status'): 'UNKNOWN'}
    for command, calls in by_command.items():
        for call in calls:
            if call['value'] is not None and not call['value']['ok']:
                equal(call['value']['error'], {'code': rejection_codes[(command, call['body']['operation'])],
                                              'message': rejection_codes[(command, call['body']['operation'])]},
                      'service refusal classification changed')
    for name, operation in operations.items():
        finish, calls = operation['finish'], by_command[name]
        expected_error = None
        if name in owner_errors:
            code, phase, outcome, confirmed = owner_errors[name]
            last = value_of(only([call for call in calls if call['body']['operation'] == 'takeover'], 'confirmed owner phase')) if confirmed else None
            expected_error = {'name': 'OwnerReconcileError', 'code': code, 'phase': phase, 'outcome': outcome,
                              'intent': expected_saved[INTENT_FOR[name]], 'lastConfirmed': last}
        elif name in routed_errors:
            require(finish['ok'] is False, 'pre-business rejection claimed success')
            require(finish['error']['code'] in routed_errors[name], 'pre-business failure code changed')
            expected_error = {'name': 'RouteError', 'code': finish['error']['code'], 'outcome': 'not_sent'}
        elif name in ('bootstrap_changed_route', 'bootstrap_wrong_scope'):
            expected_error = {'name': 'ClientError', 'code': 'INVALID'}
        elif name == 'late_write':
            expected_error = {'name': 'RemoteError', 'code': 'CONFLICT', 'outcome': 'unresolved',
                              'reference': {'scope': SCOPES['late'], 'operation': 'execute', 'request': expected_saved[name]['request']}}
        if expected_error is not None:
            require(finish['ok'] is False and 'value' not in finish, 'failed SDK operation reported success')
            equal(finish['error'], expected_error, 'SDK outcome/retained original reference changed: ' + name)
            continue
        require(finish['ok'] is True and 'error' not in finish, 'successful fixed SDK operation failed: ' + name)
        kind = CASES[name]['operation']
        if name == 'seed':
            expected = {scope: sdk_committed(value_of(calls[index * 4 + 2]), seed=True) for index, scope in enumerate(NAMES)}
        elif name in PREPARED:
            expected = {'observed': value_of(calls[0]), 'intent': expected_saved[name]}
        elif kind == 'reconcile':
            expected = {'state': 'active', 'intent': expected_saved[INTENT_FOR[name]], 'status': value_of(calls[-1])}
        elif name in inspect_states:
            expected = {'state': inspect_states[name], 'intent': expected_saved[INTENT_FOR[name]], 'status': value_of(calls[0])}
        elif kind == 'routed_query':
            value = value_of(calls[-1])
            require(set(value) == {'result'}, 'query result fields changed')
            values = [1] if name in ('late_query', 'corrupt_query') else [1, 2]
            expected = sdk_result(result_expected(b64(value['result']), values=values))
        elif kind in ('routed_execute', 'lookup', 'cancel'):
            value = value_of(calls[-1])
            expected = sdk_committed(value, seed=name == 'cold_lookup_seed') if value['state'] == 'committed' else value
            if name == 'late_lookup': equal(value, {'state': 'unknown'}, 'rejected write was treated as committed/cancelled')
            if name in ('late_cancel', 'late_cancelled'):
                equal(value, {'state': 'cancelled', 'transition': {'revision': '7', 'nonce': '2'}}, 'original cancellation barrier changed')
        else:
            expected = value_of(calls[-1])
        equal(finish['value'], expected, 'SDK result differs from original HTTP bytes/typed metadata: ' + name)
    for lookup, original, seed in (('route_lookup', 'route_write', False), ('cold_lookup_write', 'cold_write', False)):
        equal(value_of(by_command[lookup][0]), value_of(by_command[original][-1]), 'lookup regenerated original committed receipt/result')
    cold_seed = NAMES.index('cold') * 4 + 2
    equal(value_of(by_command['cold_lookup_seed'][0]), value_of(by_command['seed'][cold_seed]), 'cold lookup lost original seed ACK')
    return expected_saved


def corruption_versions(path, requests, responses):
    writes = [(serial, request, responses[serial]) for serial, request in requests.items()
              if request['path'] == path and request['method'] == 'PUT' and responses[serial]['status'] == 200]
    require(len(writes) == 3, 'corruption/repair did not contain exactly three actual object versions')
    writes.sort(key=lambda item: stamp(item[1]))
    (first, source, original), (second, corrupt, bad), (third, restore, repaired) = writes
    raw = b64(source['request_body'])
    changed = bytes([raw[0] ^ 128]) + raw[1:]
    require(source['worker'] == 'a' and source['if_none_match'] == '*' and source['if_match'] is None,
            'original corruption target was not a conditional immutable create')
    require(corrupt['worker'] == restore['worker'] == 'fixture' and corrupt['if_none_match'] is None and restore['if_none_match'] is None,
            'intentional corruption escaped the two explicit operator calls')
    require(corrupt['if_match'] == original['etag'] and restore['if_match'] == bad['etag'], 'corruption/repair lost original ETag')
    require(bad['etag'] != original['etag'] and repaired['etag'] != bad['etag'], 'changed corrupt bytes reused an incompatible ETag')
    equal(b64(corrupt['request_body']), changed, 'corruption changed more than its fixed first byte')
    equal(b64(restore['request_body']), raw, 'repair did not restore exact original immutable bytes')
    require(stamp(original) < stamp(corrupt) < stamp(bad) < stamp(restore) < stamp(repaired), 'actual corruption/repair effect order changed')
    for serial, request in requests.items():
        if request['path'] != path or request['method'] != 'GET': continue
        response = responses[serial]
        require(response['status'] == 200, 'corruption target disappeared')
        candidates = [(index, item) for index, item in enumerate(writes)
                      if response['etag'] == item[2]['etag'] and b64(response['response_body']) == b64(item[1]['request_body'])]
        require(any(stamp(item[1]) < stamp(response) and
                    (index == 2 or stamp(request) < stamp(writes[index + 1][2])) for index, item in candidates),
                'corruption GET body/ETag has no possible original version interval')
    return raw, changed, (first, second, third)


def network(history, events, calls, by_command, configuration):
    numbered(history)
    allowed = {'phase_started', 'object_request', 'object_forwarded', 'object_response',
               'object_response_delivered', 'transport_fault_observed'}
    require(all(row['event'] in allowed for row in history), 'unplanned or failed real S3 trace event')
    phases = set(NAMES) | {'seed', 'setup', 'bootstrap', 'cleanup'}
    requests, responses = object_exchanges(history, phases=phases, blackhole_phases={'rejects'})
    objects, accepted_objects, bindings, by_call = {}, {}, {}, defaultdict(list)
    seed_corrupt = value_of(by_command['seed'][NAMES.index('corrupt') * 4 + 2])['receipt']
    corrupt_path = '/scap-test/scap-object/v1/1/7/' + SCOPES['corrupt']['database'] + '/inc/1/gen/1/storage/1/objects/' + seed_corrupt['data_root']
    original, changed, corruption = corruption_versions(corrupt_path, requests, responses)
    fixture_requests = [serial for serial, request in requests.items() if request['worker'] == 'fixture']
    equal(sorted(fixture_requests), sorted(corruption[1:]), 'operator made extra S3 requests outside the two explicit corrupt/repair PUTs')
    for serial, request in requests.items():
        worker = request['worker']
        require(worker in set(WORKERS) | {'fixture'}, 'S3 request has unowned worker identity')
        signing = request['signing']
        require(signing['algorithm'] == 'AWS4-HMAC-SHA256' and
                signing['access_key_sha256'] == configuration['backend']['access_key_sha256'], 'S3 request signing principal changed')
        require(re.fullmatch(r'[0-9]{8}/us-east-1/s3/aws4_request', signing['credential_scope']) and
                re.fullmatch(r'[0-9]{8}T[0-9]{6}Z', signing['date']) and signing['credential_scope'].startswith(signing['date'][:8]),
                'S3 signing date/scope changed')
        sha256_text(signing['signature_sha256'])
        headers = signing['signed_headers']
        equal(headers, sorted(set(headers)), 'noncanonical signed header list')
        require({'host', 'x-amz-content-sha256', 'x-amz-date'} <= set(headers) and
                signing['payload_sha256'] == request['request_sha256'], 'S3 signature omitted original request bytes')
        expected_endpoint = configuration['backend']['fixture_endpoint'] if worker == 'fixture' else configuration['s3_endpoints'][worker]
        require(signing['host'] == urlparse(expected_endpoint).netloc, 'S3 signed another endpoint')
        raw = bounded_bytes(request, 'request_body', 'request_sha256')
        require(len(raw) == request['request_bytes'], 'S3 complete request length changed')
        for row in [row for row in history if row.get('request_serial') == serial]:
            for key in ('worker', 'request_body', 'signing'):
                equal(row[key], request[key], 'original S3 request changed across relay stages')
            if 'response_body' in row:
                raw_response = bounded_bytes(row, 'response_body', 'response_sha256')
                require(len(raw_response) == row['response_bytes'], 'S3 complete response length changed')
                equal(row['response_body'], responses[serial]['response_body'], 'delivered S3 bytes differ from original backend')
        if worker != 'fixture':
            matching = {number for number, call in calls.items() if call['worker'] == worker and
                        request['path'].startswith('/scap-test/scap-object/v1/1/7/' + call['body']['scope']['database'] + '/') and
                        stamp(call['request']) < stamp(request) < stamp(call['response']) and
                        (serial not in responses or stamp(responses[serial]) < stamp(call['response']))}
            require(len(matching) == 1, 'S3 operation has no unique original authenticated HTTP call interval')
            number = next(iter(matching)); bindings[serial] = matching; by_call[number].append(serial)
            command = calls[number]['command']
            phase = 'seed' if command == 'seed' else 'recovery' if command in ('recovery_warm', 'recovery_hot') else CASES[command]['scope']
            equal(request['phase'], phase, 'original S3 phase was relabeled independently of its invoking call')
        if serial not in responses: continue
        response = responses[serial]
        if request['path'].endswith('/head'):
            equal(list(raw), request['head_request_bytes'], 'HEAD request raw capture differs')
            equal(list(b64(response['response_body'])), response['head_response_bytes'], 'HEAD response raw capture differs')
        elif response['status'] == 200:
            body = raw if request['method'] == 'PUT' else b64(response['response_body'])
            if request['path'] == corrupt_path and body == changed: continue
            object_frame(body, request['path'])
            if request['path'] in objects: equal(body, objects[request['path']], 'immutable dependency changed bytes')
            objects[request['path']] = body
            if request['method'] == 'PUT' and request['worker'] != 'fixture': accepted_objects[request['path']] = serial
    regular = {serial: request for serial, request in requests.items() if request['path'] != corrupt_path}
    version_report = object_versions(regular, {serial: response for serial, response in responses.items() if serial in regular},
                                     calls=calls, bindings={serial: bindings[serial] for serial in regular})
    return {'requests': requests, 'responses': responses, 'objects': objects, 'accepted_objects': accepted_objects,
            'bindings': bindings, 'by_call': by_call, 'versions': version_report, 'corrupt_path': corrupt_path,
            'corruption_serials': corruption, 'corrupt_original': original, 'corrupt_changed': changed}


def retained_closure(net, scope, head, receipts):
    prefix = '/scap-test/scap-object/v1/{deployment}/{tenant}/{database}/inc/{incarnation}/gen/{generation}/storage/1/objects/'.format(**SCOPES[scope])
    require(head['request_epoch'] == 1 and len(head['windows']) == 1, 'fixture unexpectedly rotated retained request epoch')
    window = head['windows'][0]
    index_path = prefix + window['root']
    require(index_path in net['objects'], 'missing complete retained index dependency')
    payload, raw = object_frame(net['objects'][index_path], index_path)
    require(not raw and payload['kind'] == 'index', 'retained root is not a complete index object')
    index = payload['value']
    require(set(index) == {'kind', 'epoch', 'entries'} and index['kind'] == 'leaf' and index['epoch'] == 1, 'fixed request leaf extent changed')
    entries = index['entries']
    require(type(window['count']) is int and len(entries) == window['count'] <= 2 and window['epoch'] == 1,
            'retained entry count/epoch changed')
    expected_ids = list(range(1, len(entries) + 1))
    equal([entry['request']['id'] for entry in entries], expected_ids, 'retained original identity order changed')
    selected, total = {index_path}, 0
    for entry in entries:
        require(set(entry) == {'request', 'outcome', 'result_bytes'}, 'retained entry fields changed')
        identifier = entry['request']['id']
        expected_request = tracked(scope, str(identifier), seed=identifier == 1)['request']
        native_request = {key: int(value) if key != 'fingerprint' else value for key, value in expected_request.items()}
        equal(entry['request'], native_request, 'retained fingerprint/principal/original identity changed')
        if scope == 'late' and identifier == 2:
            equal(entry['outcome'], {'state': 'cancelled', 'transition': {'revision': 7, 'nonce': 2}}, 'cancel barrier changed')
            require(entry['result_bytes'] == 0 and type(entry['result_bytes']) is int, 'cancel retained a result payload')
            continue
        require(set(entry['outcome']) == {'state', 'result'} and entry['outcome']['state'] == 'committed', 'committed identity lost result')
        path = prefix + entry['outcome']['result']
        require(path in net['objects'], 'missing original retained result object')
        selected.add(path)
        payload, result_raw = object_frame(net['objects'][path], path)
        require(payload['kind'] == 'result', 'retained result has wrong object type')
        metadata = payload['value']
        expected = receipts[(scope, identifier)]
        receipt = expected['receipt']
        native = {'request': native_request, 'sequence': int(receipt['sequence']),
                  'transition': {key: int(value) for key, value in receipt['transition'].items()},
                  'data_root': receipt['data_root'], 'bytes': []}
        equal(metadata, native, 'retained result metadata differs from original receipt')
        equal(result_raw, b64(expected['result']), 'retained result bytes differ from original ACK')
        require(entry['outcome']['result'] == receipt['result_hash'] and type(entry['result_bytes']) is int and
                entry['result_bytes'] == len(result_raw), 'retained result object identity/length changed')
        total += len(result_raw)
        selected.update(data_closure(net['objects'], scope, receipt['data_root']))
    require(type(window['result_bytes']) is int and window['result_bytes'] == total, 'retained complete byte count changed')
    return selected


def head_history(net, calls, by_command):
    requests, responses = net['requests'], net['responses']
    accepted, rejected, heads, receipts = defaultdict(list), [], {}, {}
    for call in calls.values():
        if call['body']['operation'] == 'execute' and call['response']['status'] == 200:
            value = value_of(call)
            raw, _ = committed(value)
            scope = next(name for name, fixed in SCOPES.items() if fixed == call['body']['scope'])
            identifier = int(call['body']['request']['id'])
            receipt = value['receipt']
            equal(receipt['scope'], SCOPES[scope], 'ACK receipt entered another database')
            equal(receipt['request'], call['body']['request'], 'ACK changed original SQL identity')
            equal(receipt['transition'], {'revision': '3' if identifier == 1 else '7' if scope == 'route' else '5',
                                          'nonce': str(identifier)}, 'ACK original transition changed')
            require(receipt['sequence'] == str(identifier), 'ACK original commit sequence changed')
            result_expected(raw, seed=identifier == 1, inserted=None if identifier == 1 else 2)
            receipts[(scope, identifier)] = value
    require(len(receipts) == 15, 'successful original SQL ACK denominator changed')
    for serial, request in requests.items():
        if request['method'] != 'PUT' or not request['path'].endswith('/head'): continue
        head = parse(b64(request['request_body']))
        scope = only([name for name, expected in SCOPES.items() if head['scope'] == {key: int(value) for key, value in expected.items()}],
                     'HEAD belongs to unoffered scope')
        number = only(list(net['bindings'][serial]), 'HEAD has no unique original HTTP action')
        item = {'serial': serial, 'head': head, 'call': calls[number], 'number': number}
        if responses[serial]['status'] == 200: accepted[scope].append(item)
        else: rejected.append(item)
    additions = {
        'route': [('route_reconcile', 'takeover'), ('route_reconcile', 'activate'), ('route_write', 'execute')],
        'race': [('race_b', 'takeover'), ('race_b', 'activate')],
        'late': [('late_reconcile', 'takeover'), ('late_reconcile', 'activate'), ('late_cancel', 'cancel')],
        'lost_claim': [('claim_lost', 'takeover'), ('claim_activation', 'activate')],
        'lost_activation': [('activation_lost', 'takeover'), ('activation_lost', 'activate'), ('activation_advance', 'quota')],
        'corrupt': [('corrupt_reconcile', 'takeover'), ('corrupt_activation', 'activate')],
        'acl': [('acl_revoke', 'policy')], 'lifecycle': [('lifecycle_change', 'lifecycle')],
        'cold': [('cold_write', 'execute'), ('cold_reconcile', 'takeover'), ('cold_reconcile', 'activate')],
        'recovery': [('recovery_reconcile', 'takeover'), ('recovery_reconcile', 'activate')],
    }
    for scope in NAMES:
        chain = sorted(accepted[scope], key=lambda item: item['head']['revision'])
        equal([(item['call']['command'], item['call']['body']['operation']) for item in chain],
              [('seed', operation) for operation in ('create', 'activate', 'execute', 'policy')] + additions.get(scope, []),
              'accepted durable owner/business transition denominator changed: ' + scope)
        previous = None
        for revision, item in enumerate(chain, 1):
            head, call, serial = item['head'], item['call'], item['serial']
            action = call['body']; operation = action['operation']
            require(type(head['revision']) is int and head['revision'] == revision and type(head['active']) is bool,
                    'HEAD revision/activation type changed')
            require(set(head) == {'format', 'scope', 'head_serial', 'storage', 'revision', 'transition', 'sequence', 'owner_epoch', 'owner_instance',
                                 'active', 'auth_epoch', 'policy', 'lifecycle', 'creation', 'deletion', 'data_root', 'quota',
                                 'retention', 'request_epoch', 'windows'}, 'HEAD durable fields changed')
            equal(head['scope'], {key: int(value) for key, value in SCOPES[scope].items()}, 'HEAD native scope changed')
            nonce = int(action['request']['id'] if operation in ('execute', 'cancel') else action['nonce'])
            equal(head['transition'], {'revision': revision, 'nonce': nonce}, 'original transition identity changed')
            if previous is None:
                initial_limits(head)
                expected = {**head, 'format': 5, 'head_serial': 1,
                            'storage': {'active_generation': 1, 'allocated_through': 1},
                            'revision': 1, 'sequence': 0, 'owner_epoch': 1,
                            'owner_instance': int(WORKERS['a']), 'active': False, 'auth_epoch': 1,
                            'policy': [{'principal': 11, 'read': True, 'write': True, 'admin': True}],
                            'lifecycle': 'ready', 'creation': None, 'deletion': None,
                            'quota': {'max_bytes': INITIAL_QUOTA_BYTES}, 'retention': INITIAL_RETENTION, 'request_epoch': 1}
                require(head['windows'][0]['count'] == 0, 'initial HEAD contains business history')
            else:
                expected = {**previous, 'head_serial': previous['head_serial'] + 1,
                            'revision': revision, 'transition': {'revision': revision, 'nonce': nonce}}
                if operation == 'takeover':
                    expected.update(owner_epoch=previous['owner_epoch'] + 1, owner_instance=int(WORKERS[call['worker']]), active=False)
                elif operation == 'activate': expected['active'] = True
                elif operation == 'policy': expected.update(auth_epoch=previous['auth_epoch'] + 1, policy=native_policy(action['permissions']))
                elif operation == 'lifecycle': expected['lifecycle'] = 'maintenance'
                elif operation == 'quota': expected['quota'] = {'max_bytes': None}
                elif operation in ('execute', 'cancel'):
                    expected['windows'] = head['windows']
                    require(head['windows'][0]['count'] == previous['windows'][0]['count'] + 1, 'one original request added multiple/no outcomes')
                    if operation == 'execute':
                        expected.update(sequence=previous['sequence'] + 1, data_root=receipts[(scope, nonce)]['receipt']['data_root'])
                else: raise ValueError('unplanned durable action')
            equal(head, expected, 'durable transition changed unrelated owner/ACL/data/retention state: ' + scope)
            closure = data_closure(net['objects'], scope, head['data_root'])
            closure.update(retained_closure(net, scope, head, receipts))
            for path in closure:
                require(path in net['accepted_objects'] and stamp(responses[net['accepted_objects'][path]]) < stamp(requests[serial]),
                        'HEAD publication preceded a complete durable dependency')
            if operation in ('create', 'takeover', 'activate', 'policy', 'quota', 'lifecycle'):
                equal(value_of(call), status_from_head(head), 'administrative ACK differs from actual accepted HEAD')
            heads[(scope, revision)] = item
            previous = head
    require(sum(map(len, accepted.values())) == 74, 'accepted HEAD denominator changed')
    equal(sorted((item['call']['command'], item['call']['body']['operation']) for item in rejected),
          [('late_write', 'execute'), ('race_c', 'takeover')], 'unexpected or hidden rejected HEAD candidate')
    for item in rejected:
        scope = CASES[item['call']['command']]['scope']
        base, winner = heads[(scope, 4)], heads[(scope, 5)]
        request = requests[item['serial']]
        require(request['if_match'] == requests[winner['serial']]['if_match'] == responses[base['serial']]['etag'],
                'stale candidate rebound to a fresh ETag')
        require(item['head']['revision'] == 5 and item['head']['transition'] == {'revision': 5, 'nonce': 303 if scope == 'race' else 2},
                'stale candidate minted a new transition identity')
        require(stamp(responses[winner['serial']]) < stamp(responses[item['serial']]), 'original loser rejected before winning publication')
    for number, call in calls.items():
        serials = net['by_call'][number]
        operation = call['body']['operation']
        if operation == 'status':
            require(all(requests[serial]['method'] == 'GET' and requests[serial]['path'].endswith('/head') for serial in serials),
                    'metadata discovery downloaded data or mutated authority')
            if call['response']['status'] == 200:
                witnesses = [parse(b64(responses[serial]['response_body'])) for serial in serials if serial in responses and responses[serial]['status'] == 200]
                require(len(witnesses) == 1, 'status did not use exactly one fresh exact HEAD')
                equal(value_of(call), status_from_head(witnesses[0]), 'status returned cached/other HEAD authority')
        if (call['command'], operation) in (('guard_reconcile', 'takeover'), ('reject_auth', 'status'), ('reject_busy', 'status')):
            require(not serials, 'pre-admission/target rejection touched S3 authority')
        if operation == 'activate' and call['response']['status'] == 200 and call['command'] != 'seed':
            scope = CASES[call['command']]['scope']
            accepted_head = only([item['head'] for item in accepted[scope] if item['number'] == number], 'activation accepted HEAD witness')
            needed = data_closure(net['objects'], scope, accepted_head['data_root'])
            reads = {requests[serial]['path'] for serial in serials if requests[serial]['method'] == 'GET' and
                     serial in responses and responses[serial]['status'] == 200}
            require(needed <= reads, 'activation did not download the complete current data closure')
    return {'heads': heads, 'accepted': accepted, 'rejected': rejected, 'receipts': receipts,
            'accepted_head_publications': 74, 'rejected_original_head_candidates': 2, 'original_sql_acks': 15}


def configuration_files(directory, value):
    require(value['schema'] == 1 and type(value['schema']) is int, 'public configuration schema changed')
    equal(value['workers'], WORKERS, 'configured actual worker identities changed')
    require(set(value['services']) == set(WORKERS), 'configured service denominator changed')
    endpoints = {}
    admission = {'active_database_actors': 20, 'active_database_actors_per_tenant': 16,
                 'actor_idle_timeout_ms': 5000, 'control_workers': 2, 'queued_total': 64,
                 'queued_per_tenant': 32, 'queued_per_database': 8, 'reserved_controls': 2,
                 'data_intake': 8, 'control_intake': 4, 'recovery_intake': 2, 'max_body_bytes': 65536,
                 'timeout_ms': 15000, 'recovery_timeout_ms': 30000}
    for name, count, tenant in (('data', 8, 4), ('control', 4, 1), ('recovery', 2, 1)):
        admission[name + '_profile'] = {'version': 1, 'requests_per_tenant': tenant,
                                        'body_bytes': count * 65536, 'body_bytes_per_tenant': tenant * 65536}
    for worker, configured in value['services'].items():
        filename = 'service-' + worker + '.json'
        require(configured['configuration_file'] == filename and configured['worker_instance'] == WORKERS[worker],
                'service configuration identity changed')
        config = parse((Path(directory) / filename).read_bytes())
        expected = {'version': 1, 'listen': urlparse(configured['backend_endpoint']).netloc,
                    'worker_instance': WORKERS[worker], 'cache_directory': configured['cache_directory'],
                    'admission': admission, 'cache': {'pages_per_actor': 65536, 'parallel_recoveries': 1},
                    'execution': {'result_memory_bytes': 134217728},
                    'credentials': [{'sha256': value['credential_sha256'][role], 'deployment': '1', 'tenant': '7',
                                     'principal': principal, 'provision': role == 'writer'} for role, principal in PRINCIPALS.items()],
                    's3': {'endpoint': config['s3']['endpoint'], 'region': 'us-east-1', 'bucket': 'scap-test',
                           'access_key_env': 'SCAP_TEST_ACCESS', 'secret_key_env': 'SCAP_TEST_SECRET',
                           'session_token_env': None, 'allow_http': True, 'timeout_ms': 10000}}
        equal(config, expected, 'actual daemon admission/authority configuration changed: ' + worker)
        endpoint = urlparse(config['s3']['endpoint'])
        require(endpoint.scheme == 'http' and endpoint.hostname == '127.0.0.1' and endpoint.port and endpoint.path == ''
                and not endpoint.username and not endpoint.password and not endpoint.query and not endpoint.fragment,
                'actual daemon has another S3 authority destination')
        endpoints[worker] = config['s3']['endpoint']
    require(len(set(endpoints.values()) | {value['backend']['fixture_endpoint'], value['backend']['endpoint']}) == 6,
            'actual object relay/backend destinations alias')
    return {**value, 's3_endpoints': endpoints}


def identity(value):
    require(value.get('pid_source') == 'owned_Popen_child' and type(value.get('pid')) is int and value['pid'] > 0 and
            type(value.get('spawn_monotonic_ns')) is int and value['spawn_monotonic_ns'] > 0, 'missing owned child identity')
    return {key: value[key] for key in ('pid', 'spawn_monotonic_ns', 'pid_source')}


def wait4(value, expected):
    require(type(value['wait_status']) is int and value['wait_status'] == expected, 'unexpected original child exit status')
    usage = value['kernel_usage']
    require(usage['available'] is True and usage['source'] == 'kernel_wait4_owned_child' and
            type(usage['maxrss_bytes']) is int and usage['maxrss_bytes'] > 0, 'missing original kernel wait4/usage')
    for key in ('user_seconds', 'system_seconds'):
        require(type(usage[key]) in (float, int) and usage[key] >= 0, 'invalid original kernel CPU usage')


def node_shutdown(start, requested, stop, marker):
    equal(identity(start['identity']), identity(requested['identity']), 'Node stop request targets another original child')
    equal(identity(start['identity']), identity(stop['identity']), 'Node wait4 belongs to another actual process')
    require(requested['forced'] is False and stop['forced'] is False and
            stamp(start) < stamp(requested) < stamp(marker) < stamp(stop), 'Node graceful shutdown order/force changed')


def process_proof(directory, events, nodes, operations, saved, calls, net, configuration, build):
    groups = defaultdict(list)
    for row in events: groups[row['event']].append(row)
    tools = parse((Path(directory) / 'owner-tools.json').read_bytes())
    require(set(tools) == {'node', 'weed', 'curl'}, 'actual tool inventory changed')
    require(tools['node']['version'] == 'v22.16.0' and
            '4.51 153ab668c99731a6d29492bf6c61d0b4fa701101' in tools['weed']['version'] and
            tools['weed']['sha256'] == 'eb9adf3a75b53c32f5ad9ba856e1fb652dae03dc6f6222673c3f88c0cbd25d0e',
            'actual Node/backend build is not the pinned fixture')
    for value in tools.values():
        require(set(value) == {'path', 'sha256', 'version'} and Path(value['path']).is_absolute(), 'tool provenance fields changed')
        sha256_text(value['sha256'])
        require(isinstance(value['version'], str) and value['version'], 'missing actual tool version')
        path = Path(value['path'])
        if path.exists(): require(sha(path.read_bytes()) == value['sha256'], 'retrieved tool bytes changed')
    incarnations, lifetimes, services = set(), defaultdict(list), {}
    def register(start, stop):
        observed = identity(start); end = stamp(stop)
        pid, born = observed['pid'], observed['spawn_monotonic_ns']
        require(born < end and (pid, born) not in incarnations and
                all(end <= left or right <= born for left, right in lifetimes[pid]), 'one child impersonates overlapping independent processes')
        incarnations.add((pid, born)); lifetimes[pid].append((born, end))
    equal(Counter(row['worker'] for row in groups['service_started']), Counter(WORKERS.keys()), 'actual daemon process denominator changed')
    for worker in WORKERS:
        start = only([row for row in groups['service_started'] if row['worker'] == worker], 'service start inventory')
        ready = only([row for row in groups['service_ready'] if row['worker'] == worker], 'service readiness inventory')
        requested = only([row for row in groups['service_stop_requested'] if row['worker'] == worker], 'service stop request inventory')
        stop = only([row for row in groups['service_stopped'] if row['worker'] == worker], 'service wait4 inventory')
        ident = identity(start['identity']); register(ident, stop)
        for row in (ready, requested, stop): equal(identity(row['identity']), ident, 'service effect/wait4 belongs to another incarnation')
        require(ident['spawn_monotonic_ns'] <= stamp(start) < stamp(ready) < stamp(requested) < stamp(stop), 'owned service lifetime order changed')
        equal(start['binary'], build['binary'], 'owned daemon ran another actual release executable')
        configured = configuration['services'][worker]
        for key in ('backend_endpoint', 'cache_directory', 'configuration_file'):
            equal(start[key], configured[key], 'owned service differs from its exact configuration')
        require(start['configuration_sha256'] == sha((Path(directory) / configured['configuration_file']).read_bytes()),
                'owned daemon read different original configuration bytes')
        equal(parse(bounded_bytes(ready, 'body', 'sha256', 4096)), {'status': 'alive', 'protocol': 1}, 'original daemon readiness response changed')
        require(ready['status'] == 200, 'daemon was not ready')
        wait4(stop, -signal.SIGKILL if worker == 'a' else 0)
        equal([requested['reason'], stop['reason'], requested['signal']],
              ['old_owner_loss', 'old_owner_loss', 'SIGKILL'] if worker == 'a' else ['cleanup', 'cleanup', 'SIGINT'],
              'original service shutdown mode changed')
        require(stop['stdout_sha256'] == sha((Path(directory) / ('service-' + worker + '.log')).read_bytes()), 'original daemon output changed')
        services[worker] = (start, ready, requested, stop)
    for call in calls.values():
        _, ready, requested, _ = services[call['worker']]
        require(stamp(ready) < stamp(call['request']) < stamp(call['response']) < stamp(requested), 'HTTP call outside owned live service')
    backend = only(groups['backend_started'], 'actual backend start inventory')
    stopped = only(groups['backend_stopped'], 'actual backend stop inventory')
    equal(backend['binary'], tools['weed'], 'backend ran another extracted executable')
    equal(backend['access_key_sha256'], configuration['backend']['access_key_sha256'], 'backend signature identity differs')
    for row in (backend, stopped): equal(Counter(item['role'] for item in row['processes']), Counter(('master', 'volume', 'filer', 's3')),
                                        'backend process role denominator changed')
    for role in ('master', 'volume', 'filer', 's3'):
        first = only([row for row in backend['processes'] if row['role'] == role], 'backend original child')
        last = only([row for row in stopped['processes'] if row['role'] == role], 'backend original wait4')
        equal(identity(first), identity(last), 'backend wait4 belongs to another child')
        register(first, stopped); wait4(last, -signal.SIGKILL)
        require(first['spawn_monotonic_ns'] < stamp(backend) < stamp(stopped), 'backend lifetime order changed')
    for request in net['requests'].values():
        require(stamp(backend) < stamp(request) < stamp(stopped), 'S3 request outside owned backend lifetime')
    node_lives = {}
    equal(Counter(row['node'] for row in groups['node_stop_requested']), Counter((1, 2)), 'Node stop-request denominator changed')
    for node in (1, 2):
        start = only([row for row in groups['node_started'] if row['node'] == node], 'Node process start inventory')
        requested = only([row for row in groups['node_stop_requested'] if row['node'] == node], 'Node original stop request')
        stop = only([row for row in groups['node_stopped'] if row['node'] == node], 'Node process wait4 inventory')
        register(start['identity'], stop); wait4(stop, 0)
        node_shutdown(start, requested, stop, nodes[node][-1])
        shutdown = only([row for row in groups['operator_command'] if row['node'] == node and row['id'] == 'shutdown'], 'Node shutdown operator control')
        require(max(stamp(value['finish']) for value in operations.values() if value['node'] == node) < stamp(requested) < stamp(shutdown),
                'Node stop request preceded workload completion or followed shutdown input')
        equal(start['binary'], tools['node'], 'SDK ran under another Node executable')
        hello = nodes[node][0]
        require(type(start['spawn_requested_ns']) is int and start['spawn_requested_ns'] <= start['identity']['spawn_monotonic_ns'] <= stamp(start),
                'Node lacks pre-spawn observation')
        require(hello['self_pid'] == start['identity']['pid'] and type(hello['self_pid']) is int and hello['pid_source'] == 'node_process.pid'
                and hello['version'] == 'v22.16.0' and start['spawn_requested_ns'] < stamp(hello) < stamp(stop), 'SDK self-PID/lifetime changed')
        require(stop['forced'] is False and all(stamp(hello) <= stamp(row) < stamp(stop) for row in nodes[node]),
                'SDK original events fall outside actual process lifetime')
        require(stop['ledger_sha256'] == sha((Path(directory) / f'node-{node}.jsonl').read_bytes()) and
                stop['stderr_sha256'] == sha((Path(directory) / f'node-{node}.stderr.log').read_bytes()), 'original Node output changed')
        node_lives[node] = (start, stop)
    saved_files = only(groups['saved_files_observed'], 'original persistent intent readback inventory')
    require(saved_files['after_node'] == 1 and stamp(node_lives[1][1]) < stamp(saved_files) < node_lives[2][0]['spawn_requested_ns'],
            'saved intent readback did not cross actual Node process loss')
    equal(saved_files['files'], {original['event']['file']: sha(original['raw']) for key, original in saved.items()
                                if key != 'cold_prepare'}, 'persisted request/intent readback bytes changed')
    removed = only(groups['cache_removed'], 'old owner cache destruction inventory')
    require(removed['worker'] == 'a' and removed['path'] == services['a'][0]['cache_directory'] and removed['observed_absence'] is True and
            stamp(services['a'][3]) < stamp(removed) < services['d'][0]['identity']['spawn_monotonic_ns'],
            'replacement existed before genuine old owner/cache loss')
    require(stamp(node_lives[1][1]) < stamp(services['a'][2]) < stamp(services['a'][3]) < node_lives[2][0]['spawn_requested_ns'],
            'fresh SDK/owner did not follow original process loss')
    caches = groups['cache_observed']
    equal(Counter(row['label'] for row in caches), Counter(('before_target_guard', 'after_target_guard', 'new_worker_empty_cache')),
          'cache observation inventory changed')
    before = only([row for row in caches if row['label'] == 'before_target_guard'], 'target guard before witness')
    after = only([row for row in caches if row['label'] == 'after_target_guard'], 'target guard after witness')
    require(before['worker'] == after['worker'] == 'c' and before['path'] == after['path'] == services['c'][0]['cache_directory'],
            'target guard checked another cache')
    equal([before['files'], before['directories']], [after['files'], after['directories']], 'misbound target altered local cache')
    require(stamp(before) < stamp(operations['guard_prepare']['start']) < stamp(operations['guard_inspect']['finish']) < stamp(after),
            'cache guard observations did not surround the actual operation')
    empty = only([row for row in caches if row['label'] == 'new_worker_empty_cache'], 'fresh owner empty cache witness')
    require(empty['worker'] == 'd' and empty['path'] == services['d'][0]['cache_directory'] and empty['files'] == [] and
            stamp(services['d'][1]) < stamp(empty) < stamp(operations['cold_prepare']['start']), 'new owner inherited a native cache')
    for identifier in ('corrupt_manifest', 'restore_manifest'):
        start = only([row for row in groups['fixture_process_started'] if row['id'] == identifier], 'operator curl original process inventory')
        stop = only([row for row in groups['fixture_process_stopped'] if row['id'] == identifier], 'operator curl wait4 inventory')
        register(start['identity'], stop); wait4(stop, 0)
        equal(identity(start['identity']), identity(stop['identity']), 'operator curl wait4 differs')
        equal(start['binary'], tools['curl'], 'operator PUT ran another curl binary')
        require(stop['status'] == 200 and stamp(start) < stamp(stop), 'operator conditional PUT did not succeed')
        for suffix, key in (('headers', 'headers_sha256'), ('stdout', 'stdout_sha256'), ('stderr', 'stderr_sha256')):
            require(stop[key] == sha((Path(directory) / (identifier + '.' + suffix)).read_bytes()), 'original curl output changed')
        equal((Path(directory) / (identifier + '.body')).read_bytes(), bounded_bytes(stop, 'body', 'sha256'), 'curl body witness changed')
        require((Path(directory) / (identifier + '.stdout')).read_bytes() == b'200' and
                (Path(directory) / (identifier + '.stderr')).read_bytes() == b'', 'operator conditional PUT terminal output changed')
    require(len(incarnations) == 12, 'owned service/backend/SDK/corruption child denominator changed')
    cleanup = only(groups['cleanup_finished'], 'cleanup completion inventory')
    proxy = only(groups['proxy_stopped'], 'actual relay shutdown inventory')
    require(cleanup['errors'] == proxy['errors'] == [] and proxy['http_requests'] == 144 and
            proxy['s3_requests'] == len(net['requests']), 'actual relay/process cleanup or denominator failed')
    created = only(groups['private_created'], 'private runtime creation inventory')
    removing = only(groups['private_remove_started'], 'private runtime removal boundary')
    gone = only(groups['private_removed'], 'private runtime absence observation')
    for row in (removing, gone):
        equal({key: row[key] for key in ('path', 'device', 'inode')}, {key: created[key] for key in ('path', 'device', 'inode')},
              'removed private runtime differs from created directory identity')
    require(Path(created['path']).is_absolute() and Path(created['path']).name.startswith('scap-owner-private-')
            and str(Path(created['path'])).startswith('/tmp/') and type(created['device']) is int and type(created['inode']) is int,
            'private runtime was not isolated in the observed /tmp run')
    require(gone['observed_absence'] is True and stamp(created) < stamp(backend) < stamp(proxy) < stamp(stopped) < stamp(cleanup)
            < stamp(removing) < stamp(gone) and all(stamp(row) < stamp(removing) for row in groups['service_stopped'] + groups['node_stopped']
                                                  + groups['fixture_process_stopped']), 'private cleanup preceded owned process/relay exit')
    # Historical absence is an original observation, never inferred by stat'ing
    # a reused archived pathname after the run has ended.
    return {'audited_child_incarnations': 12, 'service_processes': 4, 'sdk_processes': 2,
            'kernel_wait4': 'verified', 'old_owner_and_cache_loss': 'verified', 'private_cleanup_observation': 'verified'}


def fault_proof(events, history, operations, calls, by_command, net, heads, configuration):
    groups = defaultdict(list)
    for row in events: groups[row['event']].append(row)
    requests, responses = net['requests'], net['responses']
    def path(scope): return '/scap-test/scap-object/v1/1/7/' + SCOPES[scope]['database'] + '/head'
    expected = {
        'race_b': {'channel': 's3', 'worker': 'b', 'method': 'PUT', 'path': path('race'), 'nonce': '301', 'kind': 'hold', 'stage': 'before_forward'},
        'race_c': {'channel': 's3', 'worker': 'c', 'method': 'PUT', 'path': path('race'), 'nonce': '303', 'kind': 'hold', 'stage': 'before_forward'},
        'late_put': {'channel': 's3', 'worker': 'a', 'method': 'PUT', 'path': path('late'), 'nonce': '2', 'kind': 'hold', 'stage': 'before_forward'},
        'lost_claim_response': {'channel': 'http', 'worker': 'b', 'command': 'claim_lost', 'operation': 'takeover', 'kind': 'drop', 'stage': 'after_response'},
        'lost_activation_response': {'channel': 'http', 'worker': 'b', 'command': 'activation_lost', 'operation': 'activate', 'kind': 'drop', 'stage': 'after_response'},
        'corrupt_claim_received': {'channel': 'http', 'worker': 'b', 'command': 'corrupt_reconcile', 'operation': 'takeover', 'kind': 'hold', 'stage': 'after_response'},
        'acl_status_received': {'channel': 'http', 'worker': 'a', 'command': 'acl_reconcile', 'operation': 'status', 'kind': 'hold', 'stage': 'after_response'},
        'recovery_claim_received': {'channel': 'http', 'worker': 'b', 'command': 'recovery_reconcile', 'operation': 'takeover', 'kind': 'hold', 'stage': 'after_response'},
        'recovery_read': {'channel': 's3', 'worker': 'b', 'method': 'GET', 'path': None, 'kind': 'hold', 'stage': 'before_forward'},
        'busy_read': {'channel': 's3', 'worker': 'a', 'method': 'GET', 'path': path('rejects'), 'kind': 'hold', 'stage': 'before_forward'},
        'redirect_status': {'channel': 'http', 'worker': 'a', 'command': 'reject_redirect', 'operation': 'status', 'kind': 'redirect', 'stage': 'before_forward'},
        'authority_blackhole': {'channel': 's3', 'worker': 'a', 'method': 'GET', 'path': path('rejects'), 'kind': 'blackhole', 'stage': 'before_forward'},
        'deadline_status_received': {'channel': 'http', 'worker': 'a', 'command': 'deadline_write', 'operation': 'status', 'kind': 'hold',
                                     'stage': 'after_response', 'discard_after_release': True},
    }
    recovered = heads['heads'][('recovery', 5)]['head']['data_root']
    expected['recovery_read']['path'] = '/scap-test/scap-object/v1/1/7/' + SCOPES['recovery']['database'] + '/inc/1/gen/1/storage/1/objects/' + recovered
    equal(Counter(row['id'] for row in groups['fault_armed']), Counter(expected.keys()), 'original armed fault denominator changed')
    equal(Counter(row['id'] for row in groups['fault_entered']), Counter(expected.keys()), 'original entered fault denominator changed')
    equal(Counter(row['id'] for row in groups['fault_released']), Counter(key for key, value in expected.items() if value['kind'] == 'hold'),
          'missing/extra original hold release')
    observed = {}
    for key, fields in expected.items():
        armed = only([row for row in groups['fault_armed'] if row['id'] == key], 'fault armed inventory')
        entered = only([row for row in groups['fault_entered'] if row['id'] == key], 'fault entered inventory')
        equal({name: armed[name] for name in fields}, fields, 'fault armed on another original effect: ' + key)
        equal({name: entered[name] for name in fields}, fields, 'observed fault fields changed: ' + key)
        require(stamp(armed) < stamp(entered), 'fault observed before being armed')
        release = None
        if fields['kind'] == 'hold':
            release = only([row for row in groups['fault_released'] if row['id'] == key], 'hold release inventory')
            require(stamp(entered) < stamp(release) and stamp(release) - stamp(entered) < DEADLINES['gate_seconds'] * 10**9,
                    'original gate expired or released before observation')
        if fields['channel'] == 's3':
            serial = entered['request_serial']; request = requests[serial]
            equal({name: request[name] for name in ('worker', 'method', 'path')}, {name: fields[name] for name in ('worker', 'method', 'path')},
                  'object fault serial binds another original request')
            require(stamp(request) < stamp(entered), 'object hold entered before original request')
            marker = only([row for row in history if row['event'] == 'transport_fault_observed' and row['request_serial'] == serial],
                          'object fault lacks original relay witness')
            require(marker['mode'] == fields['kind'] and stamp(entered) < stamp(marker), 'object fault changed mode/order')
            if release is not None:
                require(release['request_serial'] == serial, 'released another original object request')
                forwarded = only([row for row in history if row['event'] == 'object_forwarded' and row['request_serial'] == serial],
                                 'released original object never forwarded')
                require(stamp(release) < stamp(forwarded) < stamp(responses[serial]), 'held object forwarded before actual release')
            else:
                require(key == 'authority_blackhole' and serial not in responses, 'unplanned object response omission')
                suppressed = only(groups['s3_request_suppressed'], 'blackhole terminal inventory')
                require(suppressed['id'] == key and suppressed['request_serial'] == serial and stamp(entered) < stamp(suppressed),
                        'blackhole terminal binds another original request')
        else:
            serial = entered['http_serial']; call = calls[serial]
            equal([call['worker'], call['command'], call['body']['operation']],
                  [fields['worker'], fields['command'], fields['operation']], 'HTTP fault serial binds another original phase')
            if fields['kind'] == 'redirect':
                require(stamp(call['request']) < stamp(entered) < stamp(call['response']), 'redirect injection boundary changed')
            else:
                require(stamp(call['response']) < stamp(entered), 'HTTP loss/hold occurred before actual service response')
                if release is not None:
                    require(release['http_serial'] == serial, 'released another original HTTP response')
                    event = 'http_response_suppressed' if key == 'deadline_status_received' else 'http_delivered'
                    delivered = only([row for row in groups[event] if row['http_serial'] == serial], 'held HTTP response terminal')
                    require(stamp(release) < stamp(delivered), 'original HTTP response escaped the hold')
        observed[key] = (armed, entered, release, serial)
    require(len([row for row in history if row['event'] == 'transport_fault_observed']) == 6, 'unaccounted object fault/retry')
    b, c = observed['race_b'], observed['race_c']
    require(stamp(b[1]) < stamp(c[1]) < stamp(b[2]) < stamp(operations['race_b']['finish']) < stamp(c[2]),
            'same-ETag competitors were not both held before winner publication')
    require(requests[b[3]]['if_match'] == requests[c[3]]['if_match'] and responses[b[3]]['status'] == 200 and responses[c[3]]['status'] == 412,
            'actual race did not contain one winner and one original 412')
    late = observed['late_put']
    require(stamp(late[1]) < stamp(operations['late_reconcile']['start']) < stamp(operations['late_reconcile']['finish']) < stamp(late[2]) and
            responses[late[3]]['status'] == 412, 'old writer was not resumed after complete ownership activation')
    for key in ('lost_claim_response', 'lost_activation_response'):
        record = observed[key]
        require(calls[record[3]]['response']['status'] == 200 and calls[record[3]]['response']['suppressed'] is True,
                'UNKNOWN did not follow actual accepted administrative response loss')
    corrupt_hold = observed['corrupt_claim_received']
    corrupt_start = only([row for row in groups['fixture_put_started'] if row['id'] == 'corrupt_manifest'], 'corruption original input')
    repaired_start = only([row for row in groups['fixture_put_started'] if row['id'] == 'restore_manifest'], 'repair original input')
    for row, serial, payload in ((corrupt_start, net['corruption_serials'][1], net['corrupt_changed']),
                                 (repaired_start, net['corruption_serials'][2], net['corrupt_original'])):
        original = requests[serial]
        require(row['path'] == net['corrupt_path'] and row['if_match'] == original['if_match'], 'operator PUT body/ETag input changed')
        equal(bounded_bytes(row, 'body', 'sha256'), payload, 'operator PUT payload differs from actual signed body')
        require(stamp(row) < stamp(original) < stamp(responses[serial]), 'operator PUT did not follow persisted original input')
        source = responses[row['source_read_serial']]
        require(requests[row['source_read_serial']]['path'] == net['corrupt_path'] and source['status'] == 200 and
                b64(source['response_body']) == net['corrupt_original'] and stamp(source) < stamp(row), 'operator lost original exact manifest read')
    require(stamp(corrupt_hold[1]) < stamp(corrupt_start) < stamp(responses[net['corruption_serials'][1]]) < stamp(corrupt_hold[2]) and
            stamp(operations['corrupt_reconcile']['finish']) < stamp(repaired_start), 'corruption was not isolated between accepted claim and failed activation')
    failed = only([call for call in by_command['corrupt_reconcile'] if call['body']['operation'] == 'activate'], 'corrupt activation attempt')
    failed_reads = [serial for serial in net['by_call'][failed['request']['http_serial']] if requests[serial]['path'] == net['corrupt_path'] and
                    requests[serial]['method'] == 'GET' and serial in responses and b64(responses[serial]['response_body']) == net['corrupt_changed']]
    require(failed_reads, 'corrupt activation did not observe actual corrupt remote dependency bytes')
    cache = only(groups['quarantined_cache_observed'], 'quarantined Engine cache identity witness')
    removed = only(groups['quarantined_cache_removed'], 'quarantined Engine cache destruction witness')
    require(cache['worker'] == removed['worker'] == 'b' and cache['path'] == removed['path'] and
            Path(cache['path']).parent == Path(configuration['services']['b']['cache_directory']) and
            type(cache['device']) is int and type(cache['inode']) is int and removed['observed_absence'] is True,
            'repair substituted another Engine cache identity')
    require(stamp(operations['corrupt_reconcile']['finish']) < stamp(cache) < stamp(repaired_start) <
            stamp(responses[net['corruption_serials'][2]]) < stamp(removed) < stamp(operations['corrupt_activation_prepare']['start']),
            'activation-only repair did not follow genuine quarantined cache destruction')
    acl = observed['acl_status_received']
    require(stamp(acl[1]) < stamp(operations['acl_revoke']['start']) < stamp(operations['acl_revoke']['finish']) < stamp(acl[2]),
            'ADMIN revocation did not race the held original read-authorized observation')
    require(value_of(calls[acl[3]])['revision'] == '4' and value_of(by_command['acl_revoke'][0])['revision'] == '5',
            'ACL test replaced original held status with fresh metadata')
    recovery = observed['recovery_read']
    for name in ('recovery_hot', 'recovery_control'):
        require(stamp(recovery[1]) < stamp(operations[name]['start']) < stamp(operations[name]['finish']) < stamp(recovery[2]),
                'hot/control probe did not finish during blocked cold recovery')
        for call in by_command[name]:
            require(all(requests[serial]['method'] == 'GET' and requests[serial]['path'].endswith('/head')
                        for serial in net['by_call'][call['request']['http_serial']]), 'hot/control probe downloaded cold data during recovery hold')
    busy = observed['busy_read']
    require(stamp(busy[1]) < stamp(operations['reject_busy']['start']) < stamp(operations['reject_busy']['finish']) < stamp(busy[2]),
            'backpressure was not observed while actual original admission remained held')
    sink = only(groups['redirect_sink_started'], 'redirect sink inventory')
    redirect = calls[observed['redirect_status'][3]]
    require(sink['url'] not in configuration['endpoints'].values() and
            redirect['response']['headers'] == [['Location', sink['url']]], 'redirect escaped the recorded untrusted sink')
    deadline = observed['deadline_status_received']
    require(stamp(deadline[1]) < stamp(operations['deadline_write']['finish']) < stamp(deadline[2]),
            'absolute deadline did not finish before original metadata response release')
    unsigned = only(groups['backend_unsigned_probe'], 'unsigned backend enforcement witness')
    require(unsigned['endpoint'] == configuration['backend']['endpoint'] and unsigned['method'] == 'GET' and
            unsigned['path'] == '/scap-test/fixture-ready' and unsigned['request_body'] == '' and unsigned['authorization'] is None and
            unsigned['status'] == 403 and stamp(unsigned) < stamp(operations['seed']['start']), 'backend accepted an unsigned actual readiness request')
    bounded_bytes(unsigned, 'response_body', 'response_sha256', 65536)
    return {'planned_faults': 13, 'observed_holds': 9, 'lost_actual_successful_responses': 2,
            'actual_corrupt_restore_puts': 2, 'no_untrusted_redirect_request': True, 'blocked_recovery_hot_and_control': 'verified'}


def build_receipt(directory, require_artifacts):
    path = Path(__file__).resolve().parent.parent / 'object-network' / 'audit_build.py'
    specification = importlib.util.spec_from_file_location('owner_independent_archived_build_audit', path)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module.receipt(directory, True, profile='service', require_artifacts=require_artifacts)


def audit(directory, *, require_artifacts=True):
    directory = Path(directory).resolve()
    specifications = plan(parse((directory / 'owner-plan.json').read_bytes()))
    events = rows(directory, 'events.jsonl'); numbered(events)
    allowed = {'private_created', 'backend_started', 'backend_unsigned_probe', 'redirect_sink_started', 'service_started', 'service_ready',
               'node_started', 'node_event', 'operator_command', 'http_request', 'http_forwarded', 'http_response', 'http_delivered',
               'http_response_suppressed', 'fault_armed', 'fault_entered', 'fault_released', 's3_request_suppressed',
               'fixture_put_started', 'fixture_process_started', 'fixture_process_stopped', 'quarantined_cache_observed',
               'quarantined_cache_removed', 'cache_observed', 'service_stop_requested', 'service_stopped', 'node_stop_requested', 'node_stopped',
               'saved_files_observed', 'cache_removed', 'proxy_stopped', 'backend_stopped', 'cleanup_finished',
               'private_remove_started', 'private_removed'}
    require(all(row['event'] in allowed for row in events), 'unplanned/failed/expired/forced owner fixture event')
    require(all(row.get('termination_error') is None for row in events), 'owned process termination required forced cleanup')
    equal([row['id'] for row in events if row['event'] == 'operator_command' and row['id'] != 'shutdown'], list(CASES),
          'original offered-operation order/denominator changed')
    configuration = configuration_files(directory, parse((directory / 'owner-configuration.json').read_bytes()))
    nodes, operations, saved = node_traces(directory, events, specifications)
    calls, by_command = http_exchanges(events, nodes, operations, configuration)
    sdk_outcomes(directory, nodes, operations, saved, by_command, configuration)
    history = rows(directory, 'history.jsonl')
    net = network(history, events, calls, by_command, configuration)
    heads = head_history(net, calls, by_command)
    faults = fault_proof(events, history, operations, calls, by_command, net, heads, configuration)
    build = build_receipt(directory, require_artifacts)
    processes = process_proof(directory, events, nodes, operations, saved, calls, net, configuration, build)
    files = {path.relative_to(directory).as_posix(): sha(path.read_bytes()) for path in sorted(directory.iterdir())
             if path.is_file() and path.name not in {'owner-summary.json', 'owner-oracle.json', 'summary.json'}}
    return {'schema': 1, 'status': 'passed', 'profile': 'independent-explicit-owner-real-transport-v1',
            'commands': 70, 'original_http_posts': 144, 'original_sql_acks': heads['original_sql_acks'],
            'accepted_head_publications': heads['accepted_head_publications'], 'rejected_original_head_candidates': 2,
            's3_requests': len(net['requests']), 'object_versions': net['versions'], 'faults': faults, 'processes': processes,
            'build': build, 'input_files': files, 'evidence_sha256': sha(json.dumps(files, sort_keys=True, separators=(',', ':')).encode()),
            'automatic_failure_detector': 'NOT_IMPLEMENTED', 'automatic_controller': 'NOT_IMPLEMENTED',
            'automatic_registry_roll_forward': 'NOT_IMPLEMENTED', 'aws_standard': 'NOT_RUN', 'production_slo': 'NOT_RUN'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--offline-archive', action='store_true', help='explicitly allow unavailable local build artifacts; never claims full build verification')
    arguments = parser.parse_args()
    print(json.dumps(audit(arguments.evidence, require_artifacts=not arguments.offline_archive), indent=2, sort_keys=True))




