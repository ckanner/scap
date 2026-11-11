"""Independent raw-evidence verdict for actual owner-prepare absence races.

This module imports no runner, input producer, transport, or product verifier.
The shared helpers are the independently implemented HEAD/owner/HTTP decoders.
"""
from __future__ import annotations

from collections import Counter
import json
from pathlib import Path

from absence_decode import evidence as e, model as m, base_oracle as o

need, wire = m.need, m.wire
NAMES = ('current', 'superseded', 'proof')
SCOPES = {name: dict(zip(m.SCOPE, map(str, (1, 7, database, 1, 1))))
          for name, database in zip(NAMES, (7301, 7302, 7303))}
COUNTS = {'current': (2, 1, 1, 0, 1), 'superseded': (4, 2, 1, 3, 1), 'proof': (4, 2, 1, 3, 1)}
WORKERS = {'A': [9401], 'B': [9402], 'C': [9403]}
FAULTS = [[name + '-real-404', 's3', 'hold', 'after_response'] for name in NAMES]
FAULTS += [['proof-stable-head2', 's3', 'hold', 'after_response']]


def fixed_inputs(inputs):
    need(inputs['scopes'] == SCOPES and inputs['workers'] == WORKERS and inputs['named'] == {}
         and inputs['native_worker'] == 9400 and inputs['exceptional_plans'] == [], 'absence-fixed-scope-inputs')
    need(inputs['faults'] == FAULTS and inputs['owner_rpc'] == {k: list(v) for k, v in COUNTS.items()},
         'absence-fixed-fault-and-post-denominator')
    need(inputs['timeouts'] == {'sdk_ms': 90000, 'recovery_ms': 300000, 'http_ms': 120000,
         's3_ms': 120000, 'original_unknown_ms': 1500, 'hold_seconds': 180, 'whole_seconds': 1200}
         and inputs['limits'] == {'quota_bytes': 67108864, 'retention_entries': 129,
                                 'retention_result_bytes': 268435456}, 'absence-original-limits')
    need(inputs['expected'] == {'scopes': 3, 'sql_originals': 6, 'sql_committed': 6, 'lookups': 6,
         'business_queries': 3, 'saved_owner_inputs': 7, 'descriptors': 7, 'proofs': 4, 'owner_posts': 27,
         'claimed': 5, 'cancelling': 2, 'active': 3, 'aborted': 4, 's3_faults': 4,
         'service_incarnations': 3, 'sdk_incarnations': 3, 'owned_wait4': 12}, 'absence-fixed-denominator')


def processes(directory, inputs, events):
    starts = {row['id']: row for row in e.selection(events, 'child_started')}
    stops = {row['id']: row for row in e.selection(events, 'child_stopped')}
    expected = {prefix + role + '-1' for prefix in ('service-', 'sdk-') for role in WORKERS}
    expected |= {'node-version', 'weed-version'}
    need(set(starts) == set(stops) == expected and len(e.selection(events, 'child_started')) == 8
         and len(e.selection(events, 'child_stopped')) == 8, 'absence-owned-process-denominator')
    identities = set()
    for name, first in starts.items():
        last, identity = stops[name], first['identity']
        key = (identity['pid'], identity['spawn_monotonic_ns'])
        need(key not in identities and identity == last['identity'] and identity['pid_source'] == 'owned_Popen_child'
             and e.moment(first) < e.moment(last), 'owned-original-child')
        identities.add(key)
        need(last['forced'] is False and last['crash'] is False and last['status'] == 0
             and last['usage'].get('available') is True
             and last['usage'].get('source') == 'kernel_wait4_owned_child', 'owned-wait4')
        raw = e.raw(directory, last['stderr'])
        tool = 'scapd' if name.startswith('service-') else 'weed' if name == 'weed-version' else 'node'
        need(first['command'][0] == inputs['tools'][tool]['path']
             and first['executable_sha256'] == inputs['tools'][tool]['sha256'], 'owned-executable')
        if name == 'node-version':
            need(raw.strip() == b'v22.16.0', 'fixed-node-version')
        elif name == 'weed-version':
            need(b'4.51' in raw and b'153ab668c99731a6d29492bf6c61d0b4fa701101' in raw, 'fixed-weed-version')
    configurations = {}
    ready = e.selection(events, 'service_ready')
    need(len(ready) == 3 and {(row['role'], row['worker'], row['id']) for row in ready}
         == {(role, str(workers[0]), 'service-' + role + '-1') for role, workers in WORKERS.items()},
         'absence-distinct-daemon-incarnations')
    for role, workers in WORKERS.items():
        name = 'service-' + role + '-1'
        value = wire.parse((directory / (name + '.json')).read_bytes())
        need(value['worker_instance'] == str(workers[0]) and value['s3']['timeout_ms'] == 120000
             and value['admission']['timeout_ms'] == 120000
             and value['admission']['recovery_timeout_ms'] == 300000
             and value['admission']['control_workers'] == 4
             and value['transport']['response_timeout_ms'] == 120000
             and value['owner_recovery'] == {'payload_gets': 1048576, 'payload_bytes': 68719476736},
             'absence-original-server-limits')
        configurations[name] = value
    backend, ended = e.one(events, 'backend_started'), e.one(events, 'backend_stopped')
    need(len(backend['identities']) == len(ended['processes']) == 4, 'backend-process-denominator')
    for first, last in zip(backend['identities'], ended['processes']):
        need(all(last.get(key) == value for key, value in first.items()) and last['wait_status'] == -9
             and last['kernel_usage'].get('source') == 'kernel_wait4_owned_child', 'backend-owned-wait4')
    need(e.one(events, 'unsigned_probe')['status'] == 403
         and backend['normal_access_sha256'] != backend['gc_access_sha256'], 'actual-signed-backend')
    closed = e.selection(events, 's3_proxy_stopped')
    need(len(closed) == 4 and {row['role'] for row in closed} == {'seed', 'A', 'B', 'C'}
         and all(row['joined'] is True and row['errors'] == [] for row in closed), 'owned-s3-proxy-cleanup')
    need(e.one(events, 'cleanup_finished')['errors'] == [], 'owned-cleanup-complete')
    return backend, configurations, ready


def originals(directory, inputs):
    expected = {}
    for name in NAMES:
        for counter in (1, 2):
            statements = ([{'sql': 'CREATE TABLE witness(id INTEGER PRIMARY KEY, counter INTEGER NOT NULL, payload BLOB NOT NULL)',
                            'params': []}] if counter == 1 else [])
            sql = ('INSERT INTO witness VALUES(1,1,randomblob(64))' if counter == 1 else
                   'UPDATE witness SET counter=2,payload=randomblob(64) WHERE id=1')
            statements += [{'sql': sql + ' RETURNING counter,payload,random() AS nonce', 'params': []}]
            identifier = f'{name}-{counter:03d}'
            expected[identifier] = {'name': identifier, 'scope_name': name, 'epoch': '1', 'request_id': str(counter),
                                    'statements': statements, 'purpose': 'seed', 'counter': counter}
    need(len(inputs['specs']) == 6 and {row['name']: row for row in inputs['specs']} == expected,
         'absence-fixed-original-sql')
    sql = wire.parse((directory / 'intents.json').read_bytes())
    need(set(sql) == set(expected), 'saved-sql-denominator')
    for name, row in sql.items():
        value, fixed = wire.parse(row['serialized']), expected[name]
        need(set(row) == {'scope_name', 'serialized'} and set(value) == {'scope', 'request', 'statements'}
             and row['scope_name'] == fixed['scope_name'] and value['scope'] == SCOPES[fixed['scope_name']]
             and value['statements'] == fixed['statements'] and value['request'] == {
                 'epoch': '1', 'id': fixed['request_id'], 'principal': '11',
                 'fingerprint': wire.fingerprint(fixed['statements'])}, 'original-sql-fingerprint')
        row['decoded'] = value
    plans = []
    for index, name in enumerate(NAMES, 1):
        for ordinal in range(1, 2 if name == 'current' else 4):
            operation = 810000 + index * 100 + ordinal
            plans.append({'name': f'{name}-p{ordinal}', 'scope_name': name, 'creator': '11',
                'operation': str(operation), 'mode': 'takeover' if ordinal == 1 else 'activate',
                'target_worker': '9402', 'nonces': {key: str(operation * 10 + offset)
                    for offset, key in enumerate(m.NONCES, 1)}})
    need(inputs['plans'] == plans, 'absence-fixed-owner-input')
    owners = {}
    for row in e.rows(directory / 'owner-inputs.jsonl'):
        need(row['name'] not in owners, 'owner-original-input-unique')
        value = wire.parse(row['serialized'])
        fixed = next((plan for plan in plans if plan['name'] == row['name']), None)
        need(fixed is not None and set(value) == {'version', 'scope', 'input'} and value['version'] == 1
             and value['scope'] == SCOPES[fixed['scope_name']] and row['scope_name'] == fixed['scope_name']
             and row['principal'] == '11' and row['role'] == 'C-1'
             and all(value['input'][key] == fixed[key] for key in ('creator', 'operation', 'mode', 'target_worker', 'nonces')),
             'absence-fixed-saved-owner')
        owners[row['name']] = {**row, 'decoded': value, 'native': m.owner_input(e.native(value['input']))}
    need(len(owners) == 7 and set(owners) == {plan['name'] for plan in plans}, 'owner-saved-input-denominator')
    return expected, sql, owners


def delivered_before(first, second):
    return e.moment(first['group']['s3_delivery_finished']) < e.moment(second['request'])


def race_barriers(name, original, observations, descriptor, proof, latest):
    """Check the physical read order, independently of the runner's gates."""
    path = descriptor['exchange']['request']['path']
    reads = [row for row in observations if row['request']['method'] == 'GET' and row['request']['path'] == path]
    heads = [row for row in observations if row.get('read_head') is not None and row['delivered']]
    need(len(reads) == 2 and all(row['delivered'] for row in reads)
         and reads[0]['backend']['status'] == 404, 'absence-original-two-descriptor-reads')
    first, second = reads
    if name != 'proof':
        need(second['backend']['status'] == 200 and second.get('read_owner') is descriptor
             and len(heads) == 2 and heads[0]['read_head'] is latest and heads[1]['read_head'] is latest
             and delivered_before(first, heads[0]) and delivered_before(heads[0], second)
             and delivered_before(second, heads[1]), 'absence-reread-original-winner-stable-head')
        expected = {'state': 'prepared', 'prepared': {
            'scope': o.public(descriptor['value']['scope']), 'input': o.public(descriptor['value']['input']),
            'reference': o.public(m.reference(descriptor['value']))}}
        need(original['product_body'] == {'ok': True, 'value': expected}, 'absence-original-prepared-winner')
    else:
        proof_reads = [row for row in observations if row.get('read_owner') is proof and row['delivered']]
        need(second['backend']['status'] == 404 and len(heads) == 3 and len(proof_reads) == 1
             and heads[0]['bytes'] == heads[1]['bytes']
             and heads[0]['backend']['headers']['etag'] == heads[1]['backend']['headers']['etag']
             and heads[2]['read_head'] is latest and heads[2]['bytes'] != heads[1]['bytes']
             and heads[2]['backend']['headers']['etag'] != heads[1]['backend']['headers']['etag']
             and delivered_before(first, heads[0]) and delivered_before(heads[0], second)
             and delivered_before(second, heads[1]) and delivered_before(heads[1], proof_reads[0])
             and delivered_before(proof_reads[0], heads[2]), 'proof-after-absence-fresh-head-conflict')
        need(original['product_body']['ok'] is False and original['product_body']['error']['code'] == 'CONFLICT'
             and original['result']['error']['code'] == 'CONFLICT', 'proof-race-not-corrupt-or-unknown')
    need(all(row['request']['method'] == 'GET' for row in observations), 'absence-original-does-not-rebuild-or-publish')


def races(inputs, events, calls, values, heads, records):
    need(len(e.selection(events, 'fault_armed')) == len(e.selection(events, 'fault_arrived')) == 4
         and not e.selection(events, 'http_proxy_fault_armed') and not e.selection(events, 'fault_body_replaced')
         and not e.selection(events, 'fault_suppressed'), 'absence-four-real-response-holds')
    gates = {}
    for identifier, _, _, _ in FAULTS:
        armed, reached = e.one(events, 'fault_armed', id=identifier), e.one(events, 'fault_arrived', id=identifier)
        release = e.one(events, 'fault_release_requested', id=identifier)
        resumed = e.one(events, 'fault_forward_resumed', id=identifier)
        need(armed['role'] == reached['role'] == 'C' and armed['method'] == 'GET'
             and armed['mode'] == reached['mode'] == 'hold' and armed['stage'] == reached['stage'] == 'after_response'
             and reached['use'] == reached['uses'] == armed['uses'] == 1
             and armed['occurrence'] == (2 if identifier == 'proof-stable-head2' else 1), 'absence-fixed-real-hold-profile')
        row = values.identities[('C', reached['serial'])]
        need(row['request']['method'] == 'GET' and row['request']['path'] == armed['prefix']
             and row['backend'] is not None and row['delivered']
             and row['group']['s3_delivery_started']['origin'] == 'backend'
             and row['backend']['status'] == (200 if identifier == 'proof-stable-head2' else 404),
             'absence-unmodified-real-backend-response')
        need(e.moment(armed) < e.moment(row['request']) < e.moment(row['backend']) < e.moment(reached)
             < e.moment(release) <= e.moment(resumed) < e.moment(row['group']['s3_delivery_started'])
             and 0 < e.moment(resumed) - e.moment(reached) < 180_000_000_000, 'absence-real-response-held-before-delivery')
        gates[identifier] = row
    for name, logical in SCOPES.items():
        original = calls[name + '-original-prepare']
        need(original['role'] == 'C' and original['body']['operation'] == 'owner_prepare'
             and 0 < e.moment(original['product']) - e.moment(original['request']) < 30_000_000_000,
             'absence-original-daemon-and-deadline')
        within = values.for_call(original)
        first = gates[name + '-real-404']
        need(first in within, 'absence-original-404-invocation')
        reference = original['body']['input']
        descriptor = records[o.owner_path(e.native(logical), 'descriptor', reference)]
        competing = calls[name + '-competing-prepare']
        need(competing['role'] == 'B' and competing['body']['input'] == original['body']['input']
             and competing['product_body']['ok'] is True, 'absence-independent-original-input-competitor')
        terminal = calls[name + ('-competing-claim' if name == 'current' else '-replacement-abort')]
        latest = next(row for row in heads[int(logical['database'])]
                      if str(row['head']['head_serial']) == terminal['product_body']['value']['status']['head_serial'])
        held = gates['proof-stable-head2'] if name == 'proof' else first
        need(held in within and e.moment(held['backend']) < e.moment(competing['request'])
             < e.moment(descriptor['exchange']['backend']) < e.moment(terminal['product'])
             < e.moment(held['group']['s3_delivery_started']), 'absence-competitor-between-real-observation-and-delivery')
        proof = records.get(o.owner_path(e.native(logical), 'proof', reference))
        if name != 'current':
            need(proof is not None and proof['value']['marker']['phase']['kind'] == 'aborted'
                 and e.moment(held['backend']) < e.moment(proof['exchange']['backend'])
                 < e.moment(latest['exchange']['backend']), 'absence-real-proof-before-replacement')
        race_barriers(name, original, within, descriptor, proof, latest)
        status = calls[name + '-healthy-status']
        history = calls[name + '-original-history']
        need(status['role'] == history['role'] == 'C' and status['product_body']['ok'] is True
             and status['product_body']['value'] == o.projection(latest['head'])
             and history['product_body']['ok'] is True
             and history['product_body']['value']['state'] == ('claimed' if name == 'current' else 'aborted')
             and e.moment(original['product']) < e.moment(history['request']) < e.moment(status['request']),
             'absence-original-daemon-remains-healthy')
    errors = {name: call['result']['error']['code'] for name, call in calls.items() if not call['result']['ok']}
    need(errors == {'proof-original-prepare': 'CONFLICT'}, 'absence-only-predeclared-conflict')
    return {'real_404_holds': 3, 'real_stable_head_holds': 1, 'prepared_winners': 2, 'proof_conflicts': 1}


def sql_results(directory, inputs, events, specs, originals, calls, heads, values, objects, closures):
    executions = [call for call in calls.values() if call['body']['operation'] == 'execute']
    need(len(executions) == 6 and len(e.selection(events, 'original_ack')) == 6, 'absence-six-original-native-sql-acks')
    actual = {}
    recorded = wire.parse((directory / 'original-results.json').read_bytes())
    need(set(recorded) == set(specs), 'original-result-ledger-denominator')
    for call in executions:
        name = call['command']['intent']
        need(name not in actual and call['role'] == 'A', 'sql-original-success-once')
        result, _ = wire.committed(call['product_body']['value'])
        receipt = call['product_body']['value']['receipt']
        original = originals[name]['decoded']
        need(receipt['scope'] == original['scope'] and receipt['request'] == original['request']
             and wire.receipt_hash(receipt, result) == receipt['result_hash'], 'original-complete-sql-receipt')
        decoded = wire.result(result)
        need(decoded[-1]['columns'] == ['counter', 'payload', 'nonce'] and len(decoded[-1]['rows']) == 1
             and decoded[-1]['rows'][0][0] == specs[name]['counter']
             and type(decoded[-1]['rows'][0][1]) is bytes and len(decoded[-1]['rows'][0][1]) == 64
             and type(decoded[-1]['rows'][0][2]) is int and decoded[-1]['affected_rows'] == 1,
             'original-nondeterministic-sql-result')
        published = [row for row in heads[int(receipt['scope']['database'])]
                     if row['head']['sequence'] == int(receipt['sequence'])
                     and row['head']['transition'] == e.native(receipt['transition'])
                     and row['head']['data_root'] == receipt['data_root']]
        need(len(published) == 1 and e.moment(call['request']) < e.moment(published[0]['exchange']['request'])
             < e.moment(published[0]['exchange']['backend']) < e.moment(call['product']), 'original-head-before-sql-ack')
        found = closures.get(published[0]['head'])['results'].get((1, int(specs[name]['request_id'])))
        need(found is not None and found[0] == receipt['result_hash'] and found[2] == result
             and found[1]['request'] == e.native(receipt['request']), 'original-result-in-published-index')
        ack = e.one(events, 'original_ack', name=name)
        need(ack['receipt'] == receipt and e.raw(directory, ack['result']) == result
             and recorded[name] == {'receipt': receipt, 'result': ack['result']}, 'original-ack-ledger-bytes')
        lookup = calls['recovered-' + name]
        need(lookup['role'] == 'C' and lookup['body']['operation'] == 'lookup'
             and lookup['product_body']['value']['receipt'] == receipt
             and wire.committed(lookup['product_body']['value'])[0] == result, 'absence-original-results-retained')
        actual[name] = {'decoded': decoded, 'receipt': receipt, 'result': result}
    need(sum(call['body']['operation'] == 'lookup' for call in calls.values()) == 6
         and sum(call['body']['operation'] == 'query' for call in calls.values()) == 3, 'absence-lookup-and-query-denominator')
    for name in NAMES:
        o.check_query(calls[name + '-business-query'], actual[name + '-002'], 2)
        final = heads[int(SCOPES[name]['database'])][-1]['head']
        closure = closures.get(final)
        need(final['active'] and final['owner_instance'] == 9402 and final['owner_plan']['phase']['kind'] == 'active'
             and len(closure['results']) == len(closure['entries']) == 2, 'absence-final-native-recovery')
    return len(actual)


def audit(directory):
    directory = Path(directory)
    inputs = wire.parse((directory / 'inputs.json').read_bytes())
    events = e.rows(directory / 'events.jsonl')
    need([row['sequence'] for row in events] == list(range(1, len(events) + 1))
         and all(e.moment(a) <= e.moment(b) for a, b in zip(events, events[1:])), 'event-ledger-order')
    fixed_inputs(inputs)
    e.identity(directory, inputs, events, 'experiments/object-owner-absence-runtime/PLAN.md')
    backend, configurations, ready = processes(directory, inputs, events)
    specs, original, owners = originals(directory, inputs)
    calls, local = e.sdk(directory, inputs, events, configurations, original, owners, {},
                         sql_count=6, saved_count=7, owner_counts=COUNTS)
    e.http_exchanges(directory, events, calls, expected_count=3)
    values = e.s3_exchanges(directory, events, backend)
    need(all(row['backend'] is not None and row['delivered'] and row['request']['method'] != 'DELETE'
             and row['group']['s3_delivery_started']['origin'] == 'backend' for row in values),
         'absence-only-real-s3-no-delete-or-fabrication')
    heads, objects, records, metadata = e.histories(directory, inputs, values)
    need(not metadata, 'absence-no-unplanned-catalogue')
    closures = o.Closures(objects)
    o.durable_dependencies(heads, values, closures)
    descriptors, phases, recovered = o.owner_protocol(inputs, owners, heads, records, calls, values, ready, closures,
        descriptor_count=7, proof_count=4, phase_counts={'owner_claim': 5, 'owner_cancel': 2, 'owner_active': 3, 'owner_abort': 4},
        admissions={'current': 1, 'superseded': 3, 'proof': 3})
    actual_races = races(inputs, events, calls, values, heads, records)
    observed = o.public_observations(inputs, owners, descriptors, records, heads, calls, values)
    sql = sql_results(directory, inputs, events, specs, original, calls, heads, values, objects, closures)
    summary = wire.parse((directory / 'summary.json').read_bytes())
    need(summary['status'] == 'OBSERVED_NOT_AUDITED' and summary['private_removed'] is True
         and summary['cleanup_errors'] == [] and summary['error'] is None and 0 < summary['elapsed_seconds'] < 1200,
         'successful-bounded-observation-cleanup')
    return {'schema': 1, 'status': 'PASSED', 'profile': 'head8-real-owner-absence-races-v1',
        'fixture_source_commit': inputs['commit'], 'runtime_source_commit': inputs['runtime_source_commit'],
        'http_posts': len(calls), 'owner_posts': 27, 's3_requests': len(values), 'saved_owner_inputs': 7,
        'descriptors': 7, 'proofs': 4, 'phases': dict(phases), 'races': actual_races,
        'original_native_sql_acks': sql, 'original_lookups': 6, 'business_queries': 3,
        'recovered_closures': recovered, 'exact_status_observations': observed, 'owned_wait4': 12,
        'aws_standard': 'NOT_RUN', 'production_slo': 'NOT_RUN',
        'source_sha256': {name: m.sha((directory / name).read_bytes()) for name in
            ('inputs.json', 'events.jsonl', 'intents.json', 'owner-inputs.jsonl', 'original-results.json')}}
