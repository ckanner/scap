"""Closed original process, SDK, HTTP and S3 evidence; no product imports."""
from collections import Counter
import importlib.util
from pathlib import Path
from urllib.parse import urlsplit

import audit_model as model
from audit_model import need, wire

description = importlib.util.spec_from_file_location('snapshot_original_evidence',
    Path(__file__).resolve().parent.parent / 'object-owner-plan-runtime/audit_evidence.py')
prior = importlib.util.module_from_spec(description)
description.loader.exec_module(prior)
raw, rows, moment, selection, one = prior.raw, prior.rows, prior.moment, prior.selection, prior.one
identity, http_exchanges, s3_exchanges = prior.identity, prior.http_exchanges, prior.s3_exchanges
native, query_result = prior.native, prior.query_result

SCOPE = {'deployment': 1, 'tenant': 7, 'database': 8201, 'incarnation': 1, 'generation': 1}
PUBLIC_SCOPE = {key: str(value) for key, value in SCOPE.items()}
WORKERS = {'A': (9401,), 'C': (9403, 9503)}


def compute_loss(events, starts, stops, configurations):
    cold = one(events, 'scenario_phase', label='all-compute-cache-loss')
    cold_start = starts['service-C-2']
    removed = selection(events, 'cache_removed')
    need({row['service'] for row in removed} == {'service-A-1', 'service-C-1'} and len(removed) == 2,
         'all-warm-cache-loss-denominator')
    for name in ('service-A-1', 'service-C-1', 'sdk-A-1', 'sdk-C-1'):
        need(moment(cold) < moment(stops[name]) < moment(cold_start), 'all-warm-wait4-before-cold')
    for row in removed:
        name = row['service']
        need(row['existed'] and row['absent'] and row['path'] == configurations[name]['cache_directory']
             and moment(stops[name]) < moment(row) < moment(cold_start), 'owned-cache-loss-before-cold-spawn')
    paths = [configuration['cache_directory'] for configuration in configurations.values()]
    need(len(paths) == len(set(paths)) == 3, 'unique-daemon-cache-incarnations')
    native = one(events, 'native_cache_removed')
    warm = one(events, 'scenario_phase', label='warm-owner-and-original-point-one')
    need(native['absent'] is True and moment(stops['native-seed']) < moment(native) < moment(warm),
         'native-owned-exit-and-cache-loss-before-owner')


def processes(directory, inputs, events):
    starts, stops = {}, {}
    for event, result in (('child_started', starts), ('child_stopped', stops)):
        for row in selection(events, event):
            need(row['id'] not in result, 'owned-child-denominator')
            result[row['id']] = row
    need(set(starts) == set(stops) == {'node-version', 'weed-version', 'native-seed',
         'service-A-1', 'service-C-1', 'service-C-2', 'sdk-A-1', 'sdk-C-1', 'sdk-C-2'}, 'fixed-process-denominator')
    unique = set()
    for name, first in starts.items():
        last = stops[name]
        need(first['identity'] == last['identity'] and first['identity']['pid_source'] == 'owned_Popen_child'
             and moment(first) < moment(last), 'owned-original-child')
        key = (first['identity']['pid'], first['identity']['spawn_monotonic_ns'])
        need(key not in unique, 'owned-child-incarnation'); unique.add(key)
        need(last['forced'] is False and last['crash'] is False and last['status'] == 0
             and last['usage'].get('available') is True
             and last['usage'].get('source') == 'kernel_wait4_owned_child', 'owned-wait4')
        raw(directory, last['stderr'])
        tool = 'scapd' if name.startswith('service-') else 'native-seed' if name == 'native-seed' else 'weed' if name == 'weed-version' else 'node'
        need(first['command'][0] == inputs['tools'][tool]['path'] and
             first['executable_sha256'] == inputs['tools'][tool]['sha256'], 'owned-executable')
    ready = selection(events, 'service_ready')
    need(len(ready) == 3 and len({row['worker'] for row in ready}) == 3, 'worker-instance-never-reused')
    configurations = {}
    for role, workers in WORKERS.items():
        observations = sorted((row for row in ready if row['role'] == role), key=moment)
        need([int(row['worker']) for row in observations] == list(workers), 'fixed-worker-incarnation-order')
        for row in observations:
            value = wire.parse((directory / (row['id'] + '.json')).read_bytes())
            configurations[row['id']] = value
            need(value['worker_instance'] == row['worker'] and value['s3']['timeout_ms'] == 120000
                 and value['admission']['timeout_ms'] == 120000 and value['admission']['recovery_timeout_ms'] == 300000
                 and value['owner_recovery'] == {'payload_gets': 1048576, 'payload_bytes': 68719476736}, 'original-server-budgets')
            need((value['gc'] is not None) == (role == 'C'), 'explicit-gc-capability')
            if value['gc'] is not None:
                need(value['gc']['access_key_env'] != value['s3']['access_key_env']
                     and value['gc']['secret_key_env'] != value['s3']['secret_key_env'], 'independent-gc-credentials')
    backend, stopped = one(events, 'backend_started'), one(events, 'backend_stopped')
    need(len(backend['identities']) == len(stopped['processes']) == 4, 'backend-process-denominator')
    for first, last in zip(backend['identities'], stopped['processes']):
        need(all(last.get(key) == value for key, value in first.items()) and last['wait_status'] == -9
             and last['kernel_usage'].get('source') == 'kernel_wait4_owned_child', 'backend-owned-wait4')
    need(backend['normal_access_sha256'] != backend['gc_access_sha256'] and
         one(events, 'unsigned_probe')['status'] == 403, 'actual-signed-backend')
    for event, expected in (('s3_proxy_stopped', {'seed', 'A', 'C'}),
                            ('http_proxy_closed', {'A-9401', 'C-9403', 'C-9503'})):
        values = selection(events, event)
        need(len(values) == len(expected) and {row['role'] for row in values} == expected
             and all(row['joined'] is True and row['errors'] == [] for row in values), 'owned-proxy-cleanup')
    need(one(events, 'cleanup_finished')['errors'] == [], 'owned-cleanup-complete')
    restart = one(ready, 'service_ready', role='C', worker='9503')
    need(moment(starts['service-C-2']) < moment(restart), 'cold-owned-spawn-before-ready')
    compute_loss(events, starts, stops, configurations)
    return backend, configurations


def originals(directory, inputs):
    need(inputs['scopes'] == {'bulk': PUBLIC_SCOPE} and inputs['workers'] == {'A': [9401], 'C': [9403, 9503]}
         and inputs['native_worker'] == 9300, 'fixed-scope-worker-denominator')
    need(inputs['limits'] == {'quota_bytes': 67108864, 'retention_entries': 2, 'retention_result_bytes': 268435456},
         'fixed-native-retention')
    specs, saved = {}, wire.parse((directory / 'intents.json').read_bytes())
    for counter in range(1, 7):
        name = f'original-{counter}'
        statements = ([{'sql': 'CREATE TABLE witness(id INTEGER PRIMARY KEY, counter INTEGER NOT NULL, payload BLOB NOT NULL)',
                        'params': []}] if counter == 1 else [])
        size = 64 if counter <= 2 else 196608
        sql = f'INSERT INTO witness VALUES(1,{counter},randomblob({size}))' if counter == 1 else f'UPDATE witness SET counter={counter},payload=randomblob({size}) WHERE id=1'
        statements.append({'sql': sql + ' RETURNING counter,payload,random() AS nonce', 'params': []})
        specs[name] = {'name': name, 'scope_name': 'bulk', 'epoch': str((counter - 1) // 2 + 1),
            'request_id': str((counter - 1) % 2 + 1), 'counter': counter,
            'purpose': 'seed' if counter <= 2 else 'public', 'statements': statements}
    need(inputs['specs'] == list(specs.values()) and set(saved) == set(specs), 'frozen-six-original-sql')
    for name, row in saved.items():
        value, source = wire.parse(row['serialized']), specs[name]
        request = {'epoch': source['epoch'], 'id': source['request_id'], 'principal': '11',
                   'fingerprint': wire.fingerprint(source['statements'])}
        need(set(row) == {'scope_name', 'serialized'} and row['scope_name'] == 'bulk'
             and value == {'scope': PUBLIC_SCOPE, 'request': request, 'statements': source['statements']}, 'original-sql-fingerprint')
        row['decoded'] = value
    ledgers = {}
    for kind, expected in (('owner', {'bulk-p1', 'bulk-p2'}), ('snapshot', {'point-one', 'point-two'})):
        table = {}
        for row in rows(directory / (kind + '-inputs.jsonl')):
            need(set(row) == {'name', 'scope_name', 'role', 'principal', 'serialized'} and row['name'] not in table,
                 kind + '-original-input-unique')
            value = wire.parse(row['serialized'])
            need(set(value) == {'version', 'scope', 'input'} and value['version'] == 1 and value['scope'] == PUBLIC_SCOPE
                 and row['scope_name'] == 'bulk' and row['principal'] == '11', kind + '-saved-input-scope')
            parsed = native(value['input'])
            (model.owner_input if kind == 'owner' else model.snapshot_input)(parsed)
            table[row['name']] = {**row, 'decoded': value, 'native': parsed}
        need(set(table) == expected, kind + '-saved-input-denominator')
        ledgers[kind] = table
    for ordinal, worker in ((1, 9401), (2, 9503)):
        value = ledgers['owner'][f'bulk-p{ordinal}']['native']
        need(value['creator'] == 11 and value['operation'] == 890000 + ordinal and value['mode'] == 'takeover'
             and value['target_worker'] == worker and value['nonces'] == dict(zip(('claim', 'cancel', 'activate', 'abort'),
             range(8900000 + ordinal * 10 + 1, 8900000 + ordinal * 10 + 5))), 'fixed-owner-original')
    for name, operation, counter in (('point-one', 880001, 2), ('point-two', 880002, 4)):
        value = ledgers['snapshot'][name]['native']
        need(value['creator'] == 11 and value['operation'] == operation and value['label'] == f'after-original-{counter}',
             'fixed-snapshot-original')
    return saved, ledgers['owner'], ledgers['snapshot']


def saved_inputs(directory, ledgers, owners, snapshots):
    """Index verified fsync originals before considering any controller's RPCs.

    Controller creation order is not operation order. A controller which starts
    first may inspect an input durably saved later by a different controller.
    The second pass still binds each save to its owned command and output.
    """
    originals = {'owner': owners, 'snapshot': snapshots}
    saved = {'owner': {}, 'snapshot': {}}
    for ledger in ledgers:
        for row in ledger:
            if row['event'] not in ('owner_input_saved', 'snapshot_input_saved'):
                continue
            kind = row['event'].split('_')[0]
            name = row['name']
            need(name in originals[kind] and name not in saved[kind], kind + '-fsync-original-unique')
            original = originals[kind][name]
            need(wire.parse(raw(directory, row['original'])) == {key: value for key, value in original.items()
                 if key not in ('decoded', 'native')}, kind + '-input-fsync-original')
            saved[kind][name] = row
    need(all(set(saved[kind]) == set(originals[kind]) for kind in originals), 'all-original-inputs-fsynced')
    return saved


def sdk(directory, inputs, events, configurations, originals, owners, snapshots):
    calls, local = {}, {}
    children = [child for child in selection(events, 'child_started') if child['id'].startswith('sdk-')]
    ledgers = {child['id']: rows(directory / (child['id'] + '.jsonl')) for child in children}
    saved_at = saved_inputs(directory, ledgers.values(), owners, snapshots)
    for child in children:
        identifier = child['id']
        role = identifier.removeprefix('sdk-')
        ledger = ledgers[identifier]
        need([row['sequence'] for row in ledger] == list(range(1, len(ledger) + 1))
             and all(row['role'] == role for row in ledger)
             and all(moment(a) <= moment(b) for a, b in zip(ledger, ledger[1:])), 'sdk-closed-sequence')
        one(ledger, 'sdk_started'); one(ledger, 'sdk_finished')
        starts = selection(ledger, 'command_started')
        need(len(starts) == len(selection(ledger, 'command_finished')), 'sdk-command-denominator')
        sent, received = {}, {}
        for event, destination in (('child_input', sent), ('child_output', received)):
            for row in selection(events, event, id=identifier):
                value = wire.parse(raw(directory, row['raw']))
                key = None if value == {'ready': True} else value['id']
                need(key not in destination, 'owned-sdk-command-unique'); destination[key] = row
        need(len(sent) == len(starts) and len(received) == len(starts) + 1 and None in received,
             'owned-sdk-command-denominator')
        for start in starts:
            name = start['command']
            need(name not in calls and name not in local, 'original-command-unique')
            command = wire.parse(raw(directory, start['input']))
            done = one(ledger, 'command_finished', command=name)
            need(command['id'] == name and wire.parse(raw(directory, sent[name]['raw'])) == command
                 and wire.parse(raw(directory, received[name]['raw'])) == done['result'], 'owned-sdk-original-bytes')
            need(moment(sent[name]) <= moment(start) < moment(done) <= moment(received[name]), 'original-sdk-command-order')
            dispatch = one(events, 'sdk_dispatch', id=name)
            need(dispatch['sdk'] == identifier and dispatch['operation'] == command['operation']
                 and dispatch['scope_name'] == command['scope_name'], 'original-dispatch-context')
            requests = selection(ledger, 'http_request', command=name)
            call = {'name': name, 'sdk': role, 'controller': role.split('-')[0], 'command': command,
                    'start': start, 'done': done, 'result': done['result'], 'response': None}
            operation = command['operation']
            if operation in ('prepare_sql', 'owner_save', 'snapshot_save'):
                need(not requests and done['attempts'] == 0, 'local-sdk-no-product-dispatch')
                if operation == 'prepare_sql':
                    need(command['specs'] == inputs['specs'] and done['result'] ==
                         {'id': name, 'ok': True, 'value': {'prepared': 6}}, 'all-original-sql-prepared')
                    need(raw(directory, one(ledger, 'intents_prepared')['original']) == (directory / 'intents.json').read_bytes(),
                         'saved-sql-original-ledger')
                else:
                    kind = operation.removesuffix('_save')
                    original = (owners if kind == 'owner' else snapshots)[command['intent']]
                    need(original['role'] == role and original['principal'] == command.get('principal', '11')
                         and command['input'] == original['decoded']['input'] and done['result'] ==
                         {'id': name, 'ok': True, 'value': original['decoded']}, kind + '-input-saved-before-dispatch')
                    saved = one(ledger, kind + '_input_saved', name=command['intent'])
                    need(wire.parse(raw(directory, saved['original'])) == {key: value for key, value in original.items()
                         if key not in ('decoded', 'native')} and moment(saved) < moment(done), kind + '-input-fsync-original')
                    need(saved_at[kind][command['intent']] == saved, kind + '-same-original-fsync-event')
                local[name] = call
                continue
            need(len(requests) == done['attempts'] == 1, 'one-original-http-post')
            request = requests[0]
            need(request['method'] == 'POST' and request['ordinal'] == 1 and moment(start) <= moment(request) < moment(done), 'original-post-order')
            body = wire.parse(raw(directory, request['request']))
            principal = command.get('principal', '11')
            credential = next(value for value in configurations['service-C-1']['credentials'] if value['principal'] == principal)
            need(request['principal'] == principal and request['token_sha256'] == credential['sha256'], 'actual-http-principal')
            need(body['version'] == 1 and body['operation'] == operation and body['scope'] == PUBLIC_SCOPE
                 and urlsplit(request['url']).path == '/v1', 'original-database-action')
            if operation in ('execute', 'lookup'):
                original = originals[command['intent']]['decoded']
                need(body['request'] == original['request'] and (operation != 'execute' or body['statements'] == original['statements']),
                     'original-sql-request-identity')
            elif operation.startswith(('owner_', 'snapshot_')) and operation not in ('snapshot_list', 'snapshot_limits'):
                kind = operation.split('_')[0]
                saved = (owners if kind == 'owner' else snapshots)[command['intent']]
                need(moment(saved_at[kind][command['intent']]) < moment(request), kind + '-save-before-dispatch')
                if operation.endswith('_prepare'):
                    need(body['input'] == saved['decoded']['input'], kind + '-original-prepare-input')
                elif operation.endswith('_inspect'):
                    need(body['identity'] == {key: saved['decoded']['input'][key] for key in ('creator', 'operation')},
                         kind + '-original-inspect-identity')
                else:
                    reference = body['plan' if kind == 'owner' else 'reference']
                    need(all(reference[key] == saved['decoded']['input'][key] for key in ('creator', 'operation')),
                         kind + '-original-reference')
                    if kind == 'owner':
                        need(body['expected_worker_instance'] == saved['decoded']['input']['target_worker'], 'original-fixed-owner-target')
                need(request['headers'].get('x-scap-admission') == ('recovery' if operation == 'owner_resume' else 'control'),
                     'original-control-admission')
            else:
                mapping = {'expectedHeadSerial': 'expected_head_serial', 'planSerial': 'plan_serial',
                           'batchSerial': 'batch_serial', 'expectedRevision': 'expected_revision'}
                if command.get('input') is not None:
                    need(all(body.get(mapping.get(key, key)) == value for key, value in command['input'].items()), 'original-control-candidate')
            responses, errors = selection(ledger, 'http_response', command=name), selection(ledger, 'http_error', command=name)
            need(len(responses) + len(errors) == 1, 'original-http-terminal-denominator')
            terminal = (responses or errors)[0]
            need(moment(request) < moment(terminal) <= moment(done), 'original-http-terminal-order')
            if responses:
                value = wire.parse(raw(directory, terminal['response']))
                need(terminal['complete'] is True and value['ok'] == done['result']['ok'], 'original-client-knowledge')
                if value['ok']:
                    need(terminal['status'] == 200 and set(value) == {'ok', 'value'}, 'original-ack-envelope')
                    public = value['value']
                    if operation in ('execute', 'lookup', 'query'):
                        payload = wire.b64(public['result']); wire.result(payload)
                        if operation == 'query':
                            need(done['result']['value'] == query_result(payload), 'sdk-original-query-values')
                        else:
                            need(raw(directory, done['result']['value']['result']) == payload
                                 and done['result']['value']['receipt'] == public['receipt'], 'sdk-original-full-result')
                    else:
                        need(done['result']['value'] == public, 'sdk-public-result-exact')
                else:
                    need(value['error']['code'] == done['result']['error']['code'], 'sdk-original-error')
                call.update(response=terminal, response_body=value)
            else:
                need(done['result']['ok'] is False and done['result']['error']['code'] == 'UNKNOWN', 'original-unknown-not-overwritten')
                need(done['result']['error']['reference'] == {'scope': PUBLIC_SCOPE, 'operation': operation,
                     'snapshotReference': body['reference']}, 'original-unknown-reference')
            call.update(request=request, body=body, terminal=terminal, principal=principal)
            calls[name] = call
        need(len(selection(ledger, 'http_request')) == sum(value['sdk'] == role for value in calls.values()), 'all-sdk-posts-accounted')
    need(len(local) == 5 and Counter(value['command']['operation'] for value in local.values()) ==
         {'prepare_sql': 1, 'owner_save': 2, 'snapshot_save': 2}, 'local-original-denominator')
    return calls, local
