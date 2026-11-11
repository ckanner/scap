#!/usr/bin/env python3
"""Independent verdict from original process, HTTP, S3, HEAD8 and SQL bytes."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
import xml.etree.ElementTree as ET

import audit_model as m
import audit_evidence as e
from audit_model import need, Rejected, sha, wire


def public(value):
    if isinstance(value, dict):
        return {key: public(item) for key, item in value.items()}
    if isinstance(value, list):
        return [public(item) for item in value]
    return str(value) if type(value) is int else value


def projection(head):
    result = {key: str(head[key]) for key in ('revision', 'head_serial', 'sequence', 'owner_epoch',
                                             'owner_instance', 'auth_epoch', 'request_epoch')}
    storage = head['storage']
    result.update(owner_plan=public(head.get('owner_plan')), scope=public(head['scope']),
        active=head['active'], lifecycle=head['lifecycle'],
        max_bytes=None if head['quota']['max_bytes'] is None else str(head['quota']['max_bytes']),
        transition=public(head['transition']), retention={'max_entries': head['retention']['max_entries'],
            'max_result_bytes': str(head['retention']['max_result_bytes']), 'oldest_epoch': str(head['windows'][-1]['epoch'])},
        storage={'active_generation': str(storage['active_generation']), 'allocated_through': str(storage['allocated_through']),
                 'plan': None, 'sweep': None,
                 'terminal': None if storage.get('terminal') is None else {'serial': str(storage['terminal']['serial'])}})
    if storage['plan'] is not None:
        result['storage']['plan'] = {key: storage['plan'][key] if key == 'phase' else str(storage['plan'][key])
                                    for key in ('serial', 'source', 'target', 'phase')}
    if storage['sweep'] is not None:
        batch = storage['sweep']
        value = {'serial': str(batch['serial']), 'generation': str(batch['generation']),
                 'next_after': batch['next_after'], 'exhausted': batch['exhausted']}
        value.update({kind: sum(entry['disposition'] == kind for entry in batch['entries'])
                      for kind in ('pending', 'applied', 'observed_absent', 'condition_mismatch')})
        result['storage']['sweep'] = value
    return result


def head_slot(logical):
    return f'/scap-test/scap-object/v1/1/7/{logical["database"]}/head'


def owner_path(logical, kind, reference):
    return (f'/scap-test/scap-object/v1/1/7/{logical["database"]}/inc/{logical["incarnation"]}'
            f'/gen/{logical["generation"]}/owner/v1/{kind}/{reference["creator"]}/{reference["operation"]}')


def successful(value):
    return value['backend'] is not None and value['backend']['status'] in (200, 204)


def candidates(call, exchange, operations=None):
    request = exchange['request']
    terminal = call['proxy'].get('backend_response') or call['proxy'].get('backend_failure')
    logical = call['body'].get('scope', call['body'].get('creation', {}).get('scope'))
    return (call['role'] == request['role'] and logical is not None
            and int(logical['database']) == e.path_database(request['path'])
            and e.moment(call['proxy']['forward_started']) < e.moment(request) < e.moment(terminal)
            and (operations is None or call['body']['operation'] in operations))


def original_call(exchange, calls, operations):
    matches = [call for call in calls.values() if candidates(call, exchange, operations)]
    if 'head_record' in exchange:
        record = exchange['head_record']
        marker = record['head'].get('owner_plan')
        if record['kind'].startswith('owner_'):
            matches = [call for call in matches if e.native(call['body'].get('plan')) == marker['reference']]
    # Both same-target resume requests can overlap while queued. The first has
    # already invoked its final conditional PUT before the second dispatch.
    matches = [call for call in matches if e.moment(call['request']) < e.moment(exchange['request'])]
    need(len(matches) == 1, 'original-publication-call')
    return matches[0]


def authorized(call, record, exchange, values):
    previous = record['previous']['head']
    need(any(permission['principal'] == int(call['principal']) and permission['admin'] for permission in previous['policy']),
         'fresh-current-admin-at-publication')
    reads = [value for value in values.for_call(call, e.moment(exchange['request']))
             if value.get('read_head') is record['previous'] and value['delivered']
             and e.moment(value['group']['s3_delivery_finished']) < e.moment(exchange['request'])]
    need(reads, 'original-authorized-head-get-before-publication')


class Closures:
    def __init__(self, objects):
        self.objects, self.cache = objects, {}

    def get(self, head):
        key = (m.scope_key(head['scope']), head['storage']['active_generation'], head['data_root'],
               tuple((window['epoch'], window['root'], window['count'], window['result_bytes']) for window in head['windows']))
        if key not in self.cache:
            self.cache[key] = m.Graph(self.objects, head['scope'], head['storage']['active_generation']).closure(head)
        closure = self.cache[key]
        for _, result, _ in closure['results'].values():
            need(result['sequence'] <= head['sequence'] and result['transition']['revision'] <= head['revision'], 'closure-original-result-counters')
        for entry in closure['entries']:
            if entry['outcome']['state'] == 'cancelled':
                need(entry['outcome']['transition']['revision'] <= head['revision'], 'closure-original-cancel-counter')
        return closure


def durable_dependencies(heads, values, closures):
    first = {}
    for value in values.method('PUT'):
        if '/objects/' in value['request']['path'] and successful(value):
            first.setdefault(value['request']['path'], value)
    for history in heads.values():
        for record in history:
            if record['head']['storage'].get('terminal') is not None:
                continue
            closure = closures.get(record['head'])
            publication = record['exchange']
            for path in closure['dependencies']:
                need(path in first and e.moment(first[path]['backend']) < e.moment(publication['request']), 'dependency-durable-before-head')
                readbacks = [value for value in values.at_path(path) if value['request']['method'] == 'GET'
                    and value['delivered'] and value['backend']['status'] == 200
                    and e.moment(value['group']['s3_delivery_finished']) < e.moment(publication['request'])]
                need(readbacks, 'immutable-exact-readback-before-head')


def owner_protocol(inputs, owners, heads, records, calls, values, ready, closures,
                   descriptor_count=46, proof_count=28, phase_counts=None, admissions=None):
    if phase_counts is None:
        phase_counts = {'owner_claim': 43, 'owner_cancel': 2, 'owner_active': 36, 'owner_abort': 9}
    if admissions is None:
        admissions = {name: count + (name != 'named_old') - (name == 'bulk')
                      for name, count in zip(e.NAMES, e.WARM_COUNTS)}
    descriptors = {m.reference(row['value'])['descriptor_hash']: row for row in records.values() if row['kind'] == 'descriptor'}
    proofs = [row for row in records.values() if row['kind'] == 'proof']
    need(len(descriptors) == descriptor_count and len(proofs) == proof_count
         and len(records) == descriptor_count + proof_count, 'permanent-owner-record-denominator')
    by_identity = {}
    for digest, record in descriptors.items():
        descriptor, exchange = record['value'], record['exchange']
        original, base = descriptor['input'], descriptor['base']
        identity = (m.scope_key(descriptor['scope']), original['creator'], original['operation'])
        need(identity not in by_identity, 'one-descriptor-per-full-identity')
        by_identity[identity] = record
        matching_saved = [saved for saved in owners.values() if saved['native'] == original
                          and e.native(saved['decoded']['scope']) == descriptor['scope']]
        need(len(matching_saved) == 1, 'descriptor-complete-saved-original-input')
        record['original_name'] = matching_saved[0]['name']
        history = heads[descriptor['scope']['database']]
        bases = [row for row in history if row['head']['head_serial'] == base['head_serial']
                 and row['head']['scope'] == descriptor['scope']]
        need(len(bases) == 1, 'descriptor-original-head-version')
        original_head = bases[0]
        m.descriptor_base(descriptor, original_head['head'], original_head['exchange']['backend']['headers']['etag'])
        call = original_call(exchange, calls, {'owner_prepare'})
        need(e.native(call['body']['input']) == original and int(call['principal']) == original['creator'], 'descriptor-original-prepare-caller')
        reads = [value for value in values.for_call(call, e.moment(exchange['request']))
                 if value.get('read_head') is original_head and value['delivered']]
        need(reads and any(permission['principal'] == int(call['principal']) and permission['admin']
                          for permission in original_head['head']['policy']), 'prepare-fresh-original-admin-head')
        record['call'], record['basis'] = call, original_head
    for record in proofs:
        proof, exchange = record['value'], record['exchange']
        descriptor = descriptors.get(proof['marker']['reference']['descriptor_hash'])
        need(descriptor is not None and descriptor['value']['scope'] == proof['scope'], 'proof-original-descriptor')
        m.descriptor_marker(descriptor['value'], proof['marker'])
        prior = [row for row in heads[proof['scope']['database']]
                 if row['head'].get('owner_plan') == proof['marker']
                 and e.moment(row['exchange']['backend']) < e.moment(exchange['request'])]
        need(prior, 'proof-original-terminal-history')
        record['original_name'] = descriptor['original_name']
    phases, recovered = Counter(), []
    for history in heads.values():
        for record in history:
            head, kind, exchange = record['head'], record['kind'], record['exchange']
            marker = head.get('owner_plan')
            if marker is not None:
                descriptor = descriptors.get(marker['reference']['descriptor_hash'])
                need(descriptor is not None and descriptor['value']['scope'] == head['scope'], 'head-owner-original-descriptor')
                m.descriptor_marker(descriptor['value'], marker)
            if not kind.startswith('owner_'):
                continue
            phases[kind] += 1
            operation = {'owner_claim': 'owner_claim', 'owner_cancel': 'owner_abort',
                         'owner_active': 'owner_resume', 'owner_abort': 'owner_abort'}[kind]
            call = original_call(exchange, calls, {operation})
            record['call'] = call
            authorized(call, record, exchange, values)
            observations = values.for_call(call, e.moment(exchange['request']))
            descriptor_reads = [value for value in observations if value.get('read_owner') is descriptor and value['delivered']]
            need(descriptor_reads, 'phase-exact-original-descriptor-read')
            if kind in ('owner_claim', 'owner_active'):
                current = [row for row in ready if row['role'] == call['role']
                           and e.moment(row) < e.moment(call['proxy']['forward_started'])]
                need(current and int(current[-1]['worker']) == descriptor['value']['input']['target_worker']
                     and call['body']['expected_worker_instance'] == current[-1]['worker'], 'owner-actual-target-incarnation')
            if kind in ('owner_claim', 'owner_cancel'):
                m.descriptor_base(descriptor['value'], record['previous']['head'], exchange['request']['headers']['if-match'])
                previous = record['previous']['head'].get('owner_plan')
                if previous is not None:
                    path = owner_path(head['scope'], 'proof', previous['reference'])
                    proof = records.get(path)
                    need(proof is not None and proof['value'] == {'version': 1, 'scope': head['scope'], 'marker': previous},
                         'replacement-preserves-original-terminal-proof')
                    puts = [value for value in observations if value['request']['method'] == 'PUT' and value['request']['path'] == path
                            and value['backend'] is not None and value['backend']['status'] in (200, 412)
                            and value['request']['headers'].get('if-none-match') == '*'
                            and value['payload'] == proof['exchange']['payload']]
                    gets = [value for value in observations if value['request']['method'] == 'GET'
                            and value['request']['path'] == path and value['delivered']
                            and value.get('read_owner') is proof]
                    need(puts and gets and any(e.moment(put['backend']) < e.moment(get['request'])
                         < e.moment(get['group']['s3_delivery_finished']) < e.moment(exchange['request'])
                         for put in puts for get in gets), 'proof-exact-readback-before-replacement')
            if kind == 'owner_active':
                basis = record['previous']['head']
                closure = closures.get(basis)
                complete_at = 0
                for path in closure['dependencies']:
                    reads = [value for value in observations if value['request']['path'] == path
                             and value['request']['method'] == 'GET' and value['delivered']
                             and value['backend']['status'] == 200]
                    need(reads, 'resume-complete-data-and-retained-closure')
                    complete_at = max(complete_at, min(e.moment(value['group']['s3_delivery_finished']) for value in reads))
                fresh = [value for value in observations if value.get('read_head') is record['previous']
                         and value['delivered'] and complete_at < e.moment(value['request'])]
                need(fresh, 'resume-fresh-exact-head-after-complete-recovery')
                recovered.append({'scope': public(head['scope']), 'original': descriptor['original_name'],
                    'dependencies': len(closure['dependencies']), 'retained_entries': len(closure['entries']),
                    'retained_results': len(closure['results']), 'levels': closure['index_levels']})
    need(phases == phase_counts, 'fixed-owner-phase-denominator')
    for name, count in admissions.items():
        history = heads[int(inputs['scopes'][name]['database'])]
        admitted = {row['head']['owner_plan']['reference']['descriptor_hash'] for row in history
                    if row['kind'] in ('owner_claim', 'owner_cancel')}
        need(len(admitted) == count, 'per-scope-owner-admissions')
    return descriptors, phases, recovered


def public_observations(inputs, owners, descriptors, records, heads, calls, values):
    count = 0
    for call in calls.values():
        product = call['product_body']
        if product is None or not product['ok']:
            continue
        value = product['value']
        status = value.get('status', value) if isinstance(value, dict) else None
        observed = None
        if isinstance(status, dict) and 'head_serial' in status:
            database = int(status['scope']['database'])
            matches = [record for record in heads[database] if projection(record['head']) == status
                       and e.moment(record['exchange']['backend']) < e.moment(call['product'])]
            need(len(matches) == 1, 'public-exact-durable-status')
            observed = matches[0]
            count += 1
        operation = call['body']['operation']
        if not operation.startswith('owner_'):
            continue
        saved = owners[call['command']['intent']]
        observations = values.for_call(call)
        if operation == 'owner_prepare' and value['state'] == 'pending':
            need(set(value) == {'state', 'reference'}, 'pending-has-no-prepared-capability')
            ref = m.owner_reference(e.native(value['reference']))
            reads = [record for record in observations if record.get('read_head') is not None and record['delivered']
                     and record['read_head']['head'].get('owner_plan') is not None
                     and record['read_head']['head']['owner_plan']['reference'] == ref
                     and record['read_head']['head']['owner_plan']['phase']['kind'] in ('claimed', 'cancelling')]
            need(reads and value['reference']['operation'] != saved['decoded']['input']['operation'], 'pending-is-other-accepted-plan')
            continue
        prepared = value['prepared']
        need(set(prepared) == {'scope', 'input', 'reference'} and prepared['scope'] == saved['decoded']['scope']
             and prepared['input'] == saved['decoded']['input'], 'public-full-original-owner-input')
        ref = m.owner_reference(e.native(prepared['reference']))
        descriptor = descriptors.get(ref['descriptor_hash'])
        need(descriptor is not None and ref == m.reference(descriptor['value'])
             and descriptor['value']['input'] == saved['native'], 'public-original-owner-reference')
        need(any(record.get('read_owner') is descriptor and record['delivered'] for record in observations),
             'public-descriptor-exact-readback')
        if operation == 'owner_prepare':
            need(set(value) == {'state', 'prepared'} and value['state'] == 'prepared', 'public-preparation-shape')
            continue
        need(set(value) == {'state', 'status', 'prepared', 'accepted'} and observed is not None, 'public-owner-observation-shape')
        current = observed['head']
        marker = current.get('owner_plan')
        if marker is not None and all(marker['reference'][key] == ref[key] for key in ('creator', 'operation')):
            need(marker['reference'] == ref, 'same-owner-id-hash-cannot-be-fenced-history')
        accepted = value['accepted']
        if accepted is None:
            need(value['state'] in ('prepared', 'fenced') and (marker is None or marker['reference'] != ref),
                 'unknown-history-is-not-not-applied')
            if value['state'] == 'prepared':
                m.descriptor_base(descriptor['value'], current, observed['exchange']['backend']['headers']['etag'])
            else:
                base = descriptor['value']['base']
                need(current['head_serial'] != base['head_serial'] or current['revision'] != base['revision']
                     or observed['exchange']['backend']['headers']['etag'] != base['etag'], 'fenced-original-base')
        else:
            accepted = e.native(accepted)
            m.descriptor_marker(descriptor['value'], accepted)
            need(value['state'] == accepted['phase']['kind'], 'accepted-state-is-historical-marker')
            if marker is not None and marker['reference'] == ref:
                need(accepted == marker, 'current-accepted-marker-exact')
            else:
                proof = records.get(owner_path(current['scope'], 'proof', ref))
                need(proof is not None and proof['value']['marker'] == accepted, 'accepted-original-permanent-proof')
                m.proof_before(proof['value'], descriptor['value'], current)
                need(any(record.get('read_owner') is proof and record['delivered'] for record in observations), 'history-proof-exact-read')
        if operation == 'owner_inspect':
            need(not any('/objects/' in row['request']['path'] for row in observations), 'owner-history-metadata-only')
            reads = [row for row in observations if row.get('read_head') is observed and row['delivered']]
            descriptor_reads = [row for row in observations if row.get('read_owner') is descriptor and row['delivered']]
            need(len(reads) >= 2 and e.moment(reads[0]['group']['s3_delivery_finished'])
                 < e.moment(descriptor_reads[0]['request']) < e.moment(reads[-1]['request'])
                 and any(permission['principal'] == int(call['principal']) and permission['admin']
                         for permission in current['policy']), 'owner-history-fresh-stable-admin-observation')
    return count


def originals_audit(directory, inputs, events, specs, originals, calls, heads, values, objects, closures):
    """All actual native/HTTP ACK bytes, then every original cold lookup."""
    actual, native_commands = {}, Counter()
    sent = e.selection(events, 'child_input', id='native-seed')
    received = e.selection(events, 'child_output', id='native-seed')
    need(len(sent) == 273 and len(received) == 274
         and wire.parse(e.raw(directory, received[0]['raw']))['ready'] is True, 'native-command-denominator')
    config = wire.parse((directory / 'native-seed-config.json').read_bytes())
    need(config['scope'] == e.native(inputs['scopes']['bulk']) and config['worker'] == 9000
         and config['principal'] == 11 and config['provision'] is True
         and config['fixture_limits'] == {'quota_bytes': 67108864, 'retention_entries': 129,
                                         'retention_result_bytes': 268435456}, 'native-original-configuration')

    def accepted(name, receipt, result, start, terminal, role):
        need(name not in actual, 'sql-original-success-once')
        original, item = originals[name]['decoded'], specs[name]
        need(receipt['request'] == original['request'] and receipt['scope'] == original['scope']
             and wire.receipt_hash(receipt, result) == receipt['result_hash'], 'original-complete-sql-receipt')
        decoded = wire.result(result)
        returned = decoded[-1]
        need(len(decoded) == len(item['statements']) and returned['columns'] == ['counter', 'payload', 'nonce']
             and len(returned['rows']) == 1 and returned['rows'][0][0] == item['counter']
             and type(returned['rows'][0][1]) is bytes and len(returned['rows'][0][1]) == 64
             and type(returned['rows'][0][2]) is int and returned['affected_rows'] == 1, 'original-nondeterministic-sql-result')
        records = [record for record in heads[int(receipt['scope']['database'])]
            if record['head']['scope'] == e.native(receipt['scope'])
            and record['head']['sequence'] == int(receipt['sequence'])
            and record['head']['transition'] == e.native(receipt['transition'])
            and record['head']['data_root'] == receipt['data_root']]
        need(len(records) == 1, 'original-ack-one-head-publication')
        record, request = records[0], records[0]['exchange']['request']
        need(request['role'] == role and start < e.moment(request)
             < e.moment(record['exchange']['backend']) < terminal, 'original-head-before-sql-ack')
        closure = closures.get(record['head'])
        found = closure['results'].get((int(receipt['request']['epoch']), int(receipt['request']['id'])))
        need(found is not None and found[0] == receipt['result_hash'] and found[2] == result
             and found[1]['request'] == e.native(receipt['request'])
             and found[1]['transition'] == e.native(receipt['transition']), 'original-result-in-published-index')
        path = m.prefix(record['head']['scope'], record['head']['storage']['active_generation']) + receipt['result_hash']
        puts = [value for value in values.at_path(path) if value['request']['method'] == 'PUT' and successful(value)
                and value['request']['role'] == role and start < e.moment(value['request'])
                < e.moment(value['backend']) < e.moment(request)]
        need(len(puts) == 1 and objects[path] == puts[0]['payload'], 'original-ack-durable-result-object')
        actual[name] = {'receipt': receipt, 'result': result, 'decoded': decoded, 'publication': record}

    cancelled = None
    for before, after in zip(sent, received[1:]):
        request, response = wire.parse(e.raw(directory, before['raw'])), wire.parse(e.raw(directory, after['raw']))
        need(response['ok'] is True and e.moment(before) < e.moment(after), 'native-original-response')
        operation = request['op']
        native_commands[operation] += 1
        if operation == 'session_execute':
            matched = [item for item in specs.values() if item['scope_name'] == 'bulk' and item['purpose'] == 'seed'
                       and request['epoch'] == int(item['epoch']) and request['id'] == int(item['request_id'])]
            need(len(matched) == 1, 'native-original-input')
            item = matched[0]
            need(request == {'op': 'session_execute', 'epoch': int(item['epoch']), 'id': int(item['request_id']),
                 'budget_ms': 8000, 'statements': [{'sql': statement['sql'], 'parameters': []}
                                                 for statement in item['statements']]}, 'native-original-sql-bytes')
            accepted(item['name'], public(response['value']['receipt']), bytes(response['value']['result']['encoded']),
                     e.moment(before), e.moment(after), 'seed')
        elif operation == 'cancel':
            need(cancelled is None and request == {'op': 'cancel', 'epoch': 3, 'id': 3,
                 'statements': [{'sql': item['sql'], 'parameters': []} for item in specs['bulk-cancel']['statements']]}
                 and response['value']['state'] == 'cancelled', 'native-original-cancel')
            cancelled = public(response['value'])
    need(native_commands == {'create': 1, 'activate_session': 1, 'session_execute': 260, 'status': 3,
         'close_full': 2, 'session_close': 3, 'session_open': 2, 'cancel': 1}, 'native-operation-denominator')
    executions = [call for call in calls.values() if call['body']['operation'] == 'execute']
    need(len(executions) == 37, 'all-http-sql-attempts')
    for call in executions:
        if not call['result']['ok']:
            need(call['name'] in ('bulk-pending-original-execute-rejected', 'bulk-pending-new-execute-rejected')
                 and call['result']['error']['code'] == 'FENCED', 'only-predeclared-rejected-execute-probes')
            continue
        value = call['response_body']['value']
        result, _ = wire.committed(value)
        accepted(call['command']['intent'], value['receipt'], result, e.moment(call['request']),
                 e.moment(call['response']), call['role'])
    need(len(actual) == 295 and len([name for name in actual if name.startswith('bulk-')]) == 260,
         'all-native-and-http-original-acks')
    recorded = wire.parse((directory / 'original-results.json').read_bytes())
    need(set(recorded) == set(actual), 'original-result-ledger-denominator')
    native_acks, http_acks = e.selection(events, 'native_original_ack'), e.selection(events, 'original_ack')
    need(len(native_acks) == 260 and len(http_acks) == 35
         and len({row['name'] for row in native_acks + http_acks}) == 295, 'original-ack-ledger-denominator')
    for row in native_acks + http_acks:
        name = row['name']
        need(public(row['receipt']) == actual[name]['receipt'] and e.raw(directory, row['result']) == actual[name]['result']
             and recorded[name] == {'receipt': row['receipt'], 'result': row['result']}, 'original-ack-ledger-bytes')
    cold = [call for call in calls.values() if call['name'].startswith('cold-lookup-')]
    need(len(cold) == 292 and len(e.selection(events, 'cold_original_recovered')) == 292, 'cold-original-denominator')
    for call in cold:
        name = call['command']['intent']
        need(call['response_body']['ok'] is True and call['role'] == 'C'
             and call['request']['url'].startswith(e.one(events, 'http_proxy_started', role='C-9203')['endpoint']),
             'cold-new-worker-original-lookup')
        returned, _ = wire.committed(call['response_body']['value'])
        need(name in actual and returned == actual[name]['result']
             and call['response_body']['value']['receipt'] == actual[name]['receipt'], 'original-result-not-preserved')
        marker = e.one(events, 'cold_original_recovered', name=name)
        need(e.raw(directory, marker['result']) == returned
             and marker['receipt'] == actual[name]['receipt'], 'cold-original-ledger-bytes')
    survivors = set(e.NAMES) - {'named_old'}
    for name in survivors:
        count = 260 if name == 'bulk' else 3 if name in ('resume_wins', 'proof_claim') else 2
        check_query(calls['cold-query-' + name], actual[f'{name}-{count:03d}'], count)
    for identifier, name in (('bulk-pending-query', 'bulk'), ('budget_gets-queued-query', 'budget_gets'),
                             ('budget_bytes-queued-query', 'budget_bytes')):
        count = 260 if name == 'bulk' else 2
        check_query(calls[identifier], actual[f'{name}-{count:03d}'], count)
    need(calls['bulk-pending-lookup']['response_body']['value']['receipt'] == actual['bulk-001']['receipt']
         and wire.b64(calls['bulk-pending-lookup']['response_body']['value']['result']) == actual['bulk-001']['result'],
         'pending-original-read-allowed')
    need(cancelled is not None and public(e.one(events, 'original_cancel')['value']) == cancelled
         and calls['cold-original-cancel']['response_body']['value'] == cancelled
         and calls['bulk-pending-known-cancel']['response_body']['value'] == cancelled, 'original-cancel-retained')
    need(calls['cold-original-blocked']['response_body']['value'] == {'state': 'unknown'}, 'pending-sql-never-committed')
    seeded = e.one(events, 'seed_completed', scope_name='bulk')['head']
    need([window['count'] for window in seeded['windows']] == [3, 129, 129]
         and seeded['request_epoch'] == 3 and seeded['sequence'] == 260
         and [row['counter'] for row in e.selection(events, 'window_closed')] == [129, 258], 'three-real-retained-windows')
    final = heads[7201][-1]['head']
    closure = closures.get(final)
    need(len(closure['entries']) == 261 and len(closure['results']) == 260
         and max(closure['index_levels']) >= 1, 'complete-branched-retained-history')
    cancel_entries = [entry for entry in closure['entries'] if entry['request'] == e.native(originals['bulk-cancel']['decoded']['request'])]
    need(len(cancel_entries) == 1 and public(cancel_entries[0]['outcome']) == cancelled, 'original-cancel-published-index')
    return actual


def check_query(call, original, counter):
    need(call['body']['statements'] == [{'sql': 'SELECT id,counter,payload FROM witness ORDER BY id', 'params': []}]
         and call['response_body']['ok'] is True, 'original-business-query')
    decoded = wire.result(wire.b64(call['response_body']['value']['result']))
    need(len(decoded) == 1 and decoded[0]['columns'] == ['id', 'counter', 'payload']
         and decoded[0]['rows'] == [[1, counter, original['decoded'][-1]['rows'][0][1]]], 'single-effect-business-state')


def delete_control_input(call, record):
    action, control, exchange = call['body'], record['value'], record['exchange']
    need(action['operation'] == 'delete_name' and control['kind'] == 'delete'
         and control['creation'] == e.native(action['creation'])
         and str(control['operation']) == action['control_operation']
         and str(control['principal']) == call['principal']
         and all(str(control[key]) == action[key] for key in ('expected_name_revision', 'expected_head_revision', 'nonce'))
         and call['role'] == exchange['request']['role']
         and e.moment(call['proxy']['forward_started']) < e.moment(exchange['request'])
         < e.moment(exchange['backend']) < e.moment(call['product']), 'original-named-delete-control-input')


def gc_and_catalogue(inputs, events, calls, heads, metadata, values, backend):
    logical = e.native(inputs['scopes']['named_old'])
    history = heads[logical['database']]
    terminal = [record for record in history if record['kind'] == 'terminal']
    need(len(terminal) == 1 and terminal[0]['head']['format'] == 8
         and terminal[0]['head']['owner_plan'] == terminal[0]['previous']['head']['owner_plan'], 'named-terminal-preserves-owner-history')
    deletions = list(values.method('DELETE'))
    need(deletions, 'real-final-generation-delete')
    for value in deletions:
        request = value['request']
        need('/objects/' in request['path'], 'permanent-owner-and-catalogue-metadata-never-delete')
        scope, generation, digest = m.object_path(request['path'])
        need(scope == logical and generation == 1 and request['role'] == 'C'
             and request['access_sha256'] == backend['gc_access_sha256'], 'dedicated-final-generation-collector')
        call = original_call(value, calls, {'gc_resume'})
        reads = [item for item in values.for_call(call, e.moment(request))
                 if item.get('read_head') is not None and item['delivered']]
        need(reads, 'delete-without-fresh-checkpoint')
        head = reads[-1]['read_head']['head']
        batch = head['storage']['sweep']
        need(head['storage'].get('terminal') is not None and m.retired(head['storage'], generation)
             and batch is not None and batch['serial'] == int(call['body']['batch_serial'])
             and batch['generation'] == generation, 'final-generation-durable-retirement')
        matches = [entry for entry in batch['entries'] if '/scap-test/' + entry['key'] == request['path']]
        need(len(matches) == 1 and matches[0]['hash'] == digest and matches[0]['disposition'] == 'pending'
             and request['headers'].get('if-match') == matches[0]['etag']
             and request['headers'].get('if-none-match') is None, 'delete-original-checkpoint-etag')
        need(successful(value) and value['delivered'], 'actual-final-delete-completed')
    checkpoints = Counter()
    for record in history:
        if record['kind'] not in ('prepare', 'progress', 'clear'):
            continue
        kind, current, exchange = record['kind'], record['head'], record['exchange']
        checkpoints[kind] += 1
        call = original_call(exchange, calls, {'gc_prepare' if kind == 'prepare' else 'gc_resume'})
        authorized(call, record, exchange, values)
        within = [item for item in values.for_call(call, e.moment(exchange['request']))
                  if item['backend'] is not None and e.moment(item['backend']) < e.moment(exchange['request'])]
        if kind == 'prepare':
            sweep = current['storage']['sweep']
            need(int(call['body']['expected_head_serial']) == record['previous']['head']['head_serial']
                 and int(call['body']['generation']) == 1, 'gc-original-authority')
            listings = [item for item in within if item['request']['method'] == 'GET'
                        and parse_qs(urlsplit(item['request']['path']).query).get('list-type') == ['2']]
            need(len(listings) == 1 and listings[0]['delivered'], 'one-bounded-list-page')
            listing, prefix = listings[0], m.prefix(logical, 1).removeprefix('/scap-test/')
            query = parse_qs(urlsplit(listing['request']['path']).query)
            need(query.get('prefix') == [prefix] and query.get('max-keys') == ['32']
                 and query.get('start-after', []) == ([] if call['body']['after'] is None else [prefix + call['body']['after']]),
                 'original-exclusive-gc-frontier')
            document = ET.fromstring(listing['bytes'])
            keys = [item.text for container in document if container.tag.rsplit('}', 1)[-1] == 'Contents'
                    for item in container if item.tag.rsplit('}', 1)[-1] == 'Key']
            need(keys == sorted(set(keys)) and 0 < len(keys) <= 32, 'list-page-denominator')
            for entry in sweep['entries']:
                reads = [item for item in within if item['request']['path'] == '/scap-test/' + entry['key']
                         and item['request']['method'] == 'GET' and item['delivered'] and item['backend']['status'] == 200
                         and item['backend']['headers'].get('etag') == entry['etag']
                         and item['request']['access_sha256'] == backend['gc_access_sha256']]
                need(entry['key'] in keys and reads, 'checkpoint-original-listed-etag')
            need(not any(item['request']['method'] == 'DELETE' for item in within), 'prepare-never-deletes')
        elif kind == 'progress':
            for before, after in zip(record['previous']['head']['storage']['sweep']['entries'], current['storage']['sweep']['entries']):
                if before['disposition'] == after['disposition']:
                    continue
                need(after['disposition'] == 'applied' and any(item['request']['method'] == 'DELETE'
                     and item['request']['path'] == '/scap-test/' + before['key']
                     and item['request']['headers'].get('if-match') == before['etag']
                     and successful(item) and item['delivered'] for item in within), 'known-gc-outcome-before-checkpoint')
        else:
            need(any(item.get('read_head') is record['previous'] and item['delivered'] for item in within),
                 'settled-checkpoint-exact-before-clear')
    need(checkpoints['prepare'] >= 1 and checkpoints['prepare'] == checkpoints['clear']
         and history[-1]['head']['storage']['sweep'] is None, 'all-final-generation-checkpoints-complete')
    pages = e.selection(events, 'sweep_page_finished')
    need(1 <= len(pages) <= 32 and [row['page'] for row in pages] == list(range(len(pages)))
         and all(row['label'] == 'named-terminal' for row in pages)
         and e.one(events, 'sweep_round_finished', label='named-terminal')['pages'] == len(pages), 'bounded-complete-sweep-round')
    after = None
    for row in pages:
        call = calls[f'named-terminal-{row["page"]}-prepare']
        need(call['body']['after'] == after and call['response_body']['ok'] is True
             and call['response_body']['value'] == row['report'], 'original-gc-page-response')
        after = row['report']['next_after']
    need(pages[-1]['report']['exhausted'] is True, 'observed-final-sweep-frontier')
    all_metadata = [record for history in metadata.values() for record in history]
    need(Counter(row['kind'] for row in all_metadata) == {'descriptor': 2, 'control': 2, 'name': 5},
         'real-named-metadata-denominator')
    names = sorted((row for row in all_metadata if row['kind'] == 'name'), key=lambda row: row['value']['revision'])
    need([row['value']['revision'] for row in names] == [1, 2, 3, 4, 5]
         and [row['value']['state'] for row in names] == ['reserved', 'bound', 'tombstone', 'reserved', 'bound']
         and all(row['value']['creation'] == e.native(inputs['named']['named_old' if index < 3 else 'named_successor'])
                 for index, row in enumerate(names)), 'original-name-delete-and-new-creation')
    controls = {row['value']['operation']: row for row in all_metadata if row['kind'] == 'control'}
    need(set(controls) == {97001, 97002}, 'distinct-original-delete-controls')
    for operation, identifier in ((97001, 'named-pending-original-delete'), (97002, 'named-new-explicit-delete')):
        call, record = calls[identifier], controls[operation]
        delete_control_input(call, record)
    rejected = calls['named-pending-original-delete']
    changes = [value for value in values.for_call(rejected) if value['request']['method'] == 'PUT' and successful(value)]
    need(changes and all(value.get('metadata_record') is controls[97001] for value in changes),
         'pending-delete-only-fixed-control-no-head-name-payload')
    deleted = [row for row in history if row['head']['lifecycle'] == 'deleted' and row['previous'] is not None
               and row['previous']['head']['lifecycle'] != 'deleted']
    need(len(deleted) == 1 and deleted[0]['head']['deletion']['operation'] == 97002
         and deleted[0]['head']['deletion']['descriptor_hash'] == sha(controls[97002]['exchange']['payload'])
         and names[2]['value']['control'] == controls[97002]['value'], 'new-delete-original-business-barrier')
    need(deleted[0]['head']['owner_plan'] == deleted[0]['previous']['head']['owner_plan']
         and all(row['head']['owner_plan'] == deleted[0]['head']['owner_plan'] for row in history
                 if e.moment(row['exchange']['backend']) >= e.moment(deleted[0]['exchange']['backend'])), 'deleted-terminal-original-owner-tuple')
    return {'delete_requests': len(deletions), 'accepted_deletes': len(deletions),
            'checkpoints': checkpoints['prepare'], 'named_records': len(all_metadata)}


UNKNOWN_CALLS = frozenset(('bulk-p1-prepare', 'bulk-p2-claim', 'bulk-p2-resume', 'late-prepare-original',
    'claim-cancel-original-claim', 'claim-cancel-original-cancel', 'proof-claim-put-unknown',
    'proof-claim-get-unknown', 'proof-cancel-original-unknown', 'dead-worker-original-claim',
    'dead-worker-original-active', 'legacy-original-late-activation'))

ERROR_CALLS = {
    'bulk-p1-changed-base-prepare': 'CONFLICT', 'claim_wins-p91-prepare': 'FENCED',
    'claim-wins-original-cancel': 'CONFLICT', 'resume-cancel-original-active': 'CONFLICT',
    'resume-wins-original-abort': 'CONFLICT', 'acl-resume-old-head': 'CONFLICT',
    'acl-resume-revoked': 'DENIED', 'acl-fresh-denied-resume': 'DENIED', 'acl-delayed-prepare': 'DENIED',
    'legacy-original-takeover': 'CONFLICT', 'named-pending-original-delete': 'CONFLICT',
    'missing-current-descriptor-rejected': 'CORRUPT', 'missing-historical-descriptor-rejected': 'CORRUPT',
    'same-id-different-hash-rejected': 'CORRUPT', 'proof-claim-bad-admission-rejected': 'CORRUPT',
    'budget_gets-limited-resume': 'LIMIT', 'budget_bytes-limited-resume': 'LIMIT',
    'replacement-worker-old-claim': 'TARGET_MISMATCH', 'replacement-worker-old-resume': 'TARGET_MISMATCH',
    'replacement-worker-original-active': 'TARGET_MISMATCH',
    **{name: 'UNKNOWN' for name in UNKNOWN_CALLS},
    **{'bulk-pending-' + suffix: 'FENCED' for suffix in ('original-execute-rejected', 'new-execute-rejected',
       'new-cancel-rejected', 'close_full', 'lifecycle', 'compact_begin', 'gc_prepare', 'takeover', 'activate')},
    **{f'named-deleted-original-{number}': 'LIFECYCLE' for number in (1, 2, 3)}}

# Independent names/roles/calls, not imported from the runner's fault table.
FAULT_BINDINGS = (
    ('bulk-prepare-ack', 'http', 'drop', 'after_response', 'C-9103', 'bulk-p1-prepare'),
    ('bulk-claim-ack', 'http', 'drop', 'after_response', 'B-9102', 'bulk-p2-claim'),
    ('bulk-resume-ack', 'http', 'drop', 'after_response', 'B-9102', 'bulk-p2-resume'),
    ('cancelling-ack', 'http', 'drop', 'after_response', 'R-9104', 'claim-cancel-original-cancel'),
    ('legacy-activation-delayed', 'http', 'hold', 'before_forward', 'B-9102', 'legacy-original-late-activation'),
    ('late-descriptor-put', 's3', 'hold', 'before_forward', 'A', 'late-prepare-original'),
    ('claim-cancel-old-claim', 's3', 'hold', 'before_forward', 'B', 'claim-cancel-original-claim'),
    ('claim-wins-claim', 's3', 'hold', 'before_forward', 'B', 'claim-wins-original-claim'),
    ('claim-wins-cancel', 's3', 'hold', 'before_forward', 'C', 'claim-wins-original-cancel'),
    ('resume-cancel-active', 's3', 'hold', 'before_forward', 'B', 'resume-cancel-original-active'),
    ('resume-wins-active', 's3', 'hold', 'before_forward', 'B', 'resume-wins-first'),
    ('resume-wins-abort', 's3', 'hold', 'before_forward', 'C', 'resume-wins-original-abort'),
    ('acl-change-payload', 's3', 'hold', 'before_forward', 'B', 'acl-resume-old-head'),
    ('acl-revoke-payload', 's3', 'hold', 'before_forward', 'B', 'acl-resume-revoked'),
    ('acl-prepare-descriptor', 's3', 'hold', 'before_forward', 'C', 'acl-delayed-prepare'),
    ('dead-worker-claim', 's3', 'hold', 'before_forward', 'B', 'dead-worker-original-claim'),
    ('dead-worker-resume', 's3', 'hold', 'before_forward', 'R', 'dead-worker-original-active'),
    ('legacy-takeover', 's3', 'hold', 'before_forward', 'C', 'legacy-original-takeover'),
    ('claim-proof-put-ack', 's3', 'drop', 'after_response', 'B', 'proof-claim-put-unknown'),
    ('claim-proof-read-ack', 's3', 'drop', 'after_response', 'B', 'proof-claim-get-unknown'),
    ('old-proof-missing', 's3', 'no_such_key', 'before_forward', 'C', 'proof-claim-missing-is-unknown-history'),
    ('old-proof-not-before-admission', 's3', 'replace_body', 'after_response', 'Z', 'proof-claim-bad-admission-rejected'),
    ('cancel-proof-read-ack', 's3', 'drop', 'after_response', 'C', 'proof-cancel-original-unknown'),
    ('current-descriptor-missing', 's3', 'no_such_key', 'before_forward', 'C', 'missing-current-descriptor-rejected'),
    ('historical-descriptor-missing', 's3', 'no_such_key', 'before_forward', 'R', 'missing-historical-descriptor-rejected'),
    ('same-id-different-hash', 's3', 'replace_body', 'after_response', 'G', 'same-id-different-hash-rejected'),
    ('gets-budget-descriptor', 's3', 'hold', 'before_forward', 'G', 'budget_gets-limited-resume'),
    ('bytes-budget-descriptor', 's3', 'hold', 'before_forward', 'Z', 'budget_bytes-limited-resume'))


def original_errors(calls):
    actual = {name: call['result']['error']['code'] for name, call in calls.items() if not call['result']['ok']}
    need(actual == ERROR_CALLS, 'all-original-error-and-unknown-results')
    for name, expected in ERROR_CALLS.items():
        product = calls[name]['product_body']
        if expected != 'UNKNOWN':
            need(product is not None and product['ok'] is False and product['error']['code'] == expected,
                 'actual-product-error-not-runner-label')
    return Counter(actual.values())


def descriptor_absence_barrier(pair, observations):
    need(len(pair) == 2 and pair[0]['request']['path'] == pair[1]['request']['path']
         and all(item['backend'] is None and item['delivery_complete']
                 and item['group']['s3_delivery_started']['status'] == 404 for item in pair),
         'two-original-descriptor-missing-deliveries')
    first, second = pair
    heads = [item for item in observations if item.get('read_head') is not None and item['delivered']]
    before = [item for item in heads if e.moment(first['group']['s3_delivery_finished'])
              < e.moment(item['request']) and e.moment(item['group']['s3_delivery_finished'])
              < e.moment(second['request'])]
    after = [item for item in heads if e.moment(second['group']['s3_delivery_finished'])
             < e.moment(item['request'])]
    need(len(before) == 1 and after and before[0]['bytes'] == after[0]['bytes']
         and before[0]['backend']['headers']['etag'] == after[0]['backend']['headers']['etag']
         and before[0]['read_head'] is after[0]['read_head'], 'missing-descriptor-stable-head-barrier')
    return before[0], after


def complete_fault_delivery(events):
    need(len(e.selection(events, 'fault_armed')) == 23 and len(e.selection(events, 'http_proxy_fault_armed')) == 5
         and len(e.selection(events, 'fault_arrived')) == 26
         and len(e.selection(events, 'http_proxy_fault_arrived')) == 5, 'complete-fault-delivery-denominator')


def forwarded_while_held(call, events, identifier):
    release = e.one(events, 'fault_release_requested', id=identifier)
    return e.moment(call['proxy']['forward_finished']) < e.moment(release)


def fault_audit(directory, inputs, events, calls, values, http, heads, owners, records, stopped):
    expected = {row[0]: row for row in FAULT_BINDINGS}
    need(len(expected) == 28 and inputs['faults'] == [list(row[:4]) for row in FAULT_BINDINGS], 'fixed-fault-profile')
    complete_fault_delivery(events)
    faults, holds = {}, {}
    for identifier, layer, mode, stage, role, name in FAULT_BINDINGS:
        before = 'http_proxy_' if layer == 'http' else ''
        armed = e.one(events, before + 'fault_armed', id=identifier)
        arrivals = e.selection(events, before + 'fault_arrived', id=identifier)
        uses = 2 if identifier in ('same-id-different-hash', 'current-descriptor-missing',
                                  'historical-descriptor-missing') else 1
        need(len(arrivals) == uses and armed['role'] == role and armed['mode'] == mode
             and armed['stage'] == stage and armed['occurrence'] == 1, 'original-fault-arm-and-use')
        call, selected = calls[name], []
        for index, arrived in enumerate(arrivals, 1):
            need(arrived['role'] == role and arrived['mode'] == mode and arrived['stage'] == stage
                 and e.moment(armed) < e.moment(arrived), 'original-fault-delivery')
            if layer == 's3':
                value = values.identities[(role, arrived['serial'])]
                need(value in values.for_call(call) and arrived['use'] == index and arrived['uses'] == uses
                     and value['request']['method'] == armed['method']
                     and value['request']['path'].startswith(armed['prefix']), 'fault-original-s3-call')
                selected.append(value)
                group = value['group']
                if stage == 'after_response':
                    need(value['backend'] is not None and e.moment(value['backend']) < e.moment(arrived), 'fault-after-actual-s3-effect')
            else:
                group = http[(role, arrived['serial'])]
                need(group is call['proxy'] and group['request']['operation'] == armed['operation'], 'fault-original-http-call')
                if stage == 'after_response':
                    need(e.moment(group['backend_response']) < e.moment(arrived), 'fault-after-actual-product-response')
            if mode == 'hold':
                release = e.one(events, 'http_proxy_release_requested' if layer == 'http' else 'fault_release_requested', id=identifier)
                resumed = e.one(events, 'http_proxy_fault_released' if layer == 'http' else 'fault_forward_resumed', id=identifier)
                held = (e.moment(resumed) - e.moment(arrived)) / 1e9
                need(e.moment(arrived) < e.moment(release) <= e.moment(resumed) and 0 < held < 180,
                     'original-hold-deadline')
                forward = group['forward_started' if layer == 'http' else 's3_forward_started']
                need(e.moment(resumed) < e.moment(forward), 'release-before-original-forward')
                holds[identifier] = held
            elif mode == 'drop':
                suppressed = e.one(events, 'http_proxy_delivery_suppressed' if layer == 'http' else 'fault_suppressed',
                                   role=role, serial=arrived['serial'])
                need(suppressed['id'] == identifier and suppressed['aborted'] is False
                     and ('delivery_started' if layer == 'http' else 's3_delivery_started') not in group,
                     'original-response-suppressed-not-delivered')
            else:
                need(value['delivery_complete'] and e.moment(group['s3_delivery_finished']) < e.moment(call['product']),
                     'original-fault-actually-delivered')
        faults[identifier] = selected[0] if uses == 1 and layer == 's3' else selected
    for identifier, child in (('late-descriptor-put', 'service-A-1'), ('dead-worker-claim', 'service-B-1'),
                               ('dead-worker-resume', 'service-R-2')):
        value = faults[identifier]
        call = calls[expected[identifier][-1]]
        need(value['backend']['status'] == 200 and e.moment(value['request']) < e.moment(call['terminal'])
             < e.moment(stopped[child]) < e.moment(value['group']['s3_forward_started'])
             < e.moment(value['backend']), 'original-s3-effect-after-owned-process-exit')
        need(call['product'] is None and 'backend_failure' in call['proxy'], 'dead-caller-has-no-fabricated-ack')
    for name in ('replacement-worker-old-claim', 'replacement-worker-old-resume', 'replacement-worker-original-active'):
        call = calls[name]
        expected_worker = '9102' if 'old-' in name else '9204'
        need(call['body']['expected_worker_instance'] == expected_worker
             and not values.for_call(call), 'replacement-incarnation-rejects-before-s3')
    for identifier, code in (('claim-cancel-old-claim', 412), ('claim-wins-claim', 200), ('claim-wins-cancel', 412),
                             ('resume-cancel-active', 412), ('resume-wins-active', 200), ('resume-wins-abort', 412),
                             ('legacy-takeover', 412)):
        value = faults[identifier]
        need(value['request']['method'] == 'PUT' and value['backend']['status'] == code
             and isinstance(value['request']['headers'].get('if-match'), str), 'original-race-actual-conditional-outcome')
    for left, right in (('claim-wins-claim', 'claim-wins-cancel'), ('resume-wins-active', 'resume-wins-abort')):
        first, second = faults[left], faults[right]
        need(first['request']['headers']['if-match'] == second['request']['headers']['if-match']
             and e.moment(second['request']) < e.moment(first['backend']) < e.moment(second['group']['s3_forward_started']),
             'competing-original-etag-never-rebased')
    for identifier, kind in (('claim-cancel-old-claim', 'owner_abort'), ('resume-cancel-active', 'owner_abort'),
                              ('legacy-takeover', 'owner_claim')):
        value = faults[identifier]
        winners = [record for record in heads[e.path_database(value['request']['path'])] if record['kind'] == kind
                   and e.moment(value['request']) < e.moment(record['exchange']['backend'])
                   < e.moment(value['group']['s3_forward_started'])]
        need(len(winners) == 1, 'prior-owner-phase-fences-late-original-cas')
    first, second = calls['resume-wins-first'], calls['resume-wins-queued-second']
    active = faults['resume-wins-active']
    need(e.moment(active['request']) < e.moment(second['proxy']['forward_finished'])
         < e.moment(active['group']['s3_forward_started'])
         and forwarded_while_held(second, events, 'resume-wins-active')
         and first['product_body']['value'] == second['product_body']['value'], 'same-actor-second-resume-is-history')
    later_puts = [value for value in values.for_call(second) if value['request']['method'] == 'PUT'
                  and m.head_path(value['request']['path']) is not None]
    need(not later_puts, 'second-resume-no-second-active-publication')
    takeover, claim = calls['legacy-original-takeover'], calls['legacy-p1-claim']
    need(takeover['role'] == 'C' and takeover['body']['expected_worker_instance'] == '9103'
         and claim['role'] == 'B' and claim['body']['expected_worker_instance'] == '9102',
         'legacy-race-independent-daemons')
    legacy = calls['legacy-original-late-activation']
    aborted = [row for row in heads[7210] if row['kind'] == 'owner_abort'][0]
    need(e.moment(aborted['exchange']['backend']) < e.moment(legacy['proxy']['forward_started'])
         and legacy['body']['expected_revision'] == str(aborted['head']['revision'])
         and legacy['product_body']['ok'] is False and legacy['product_body']['error']['code'] == 'FENCED',
         'legacy-http-after-adoption-is-fenced-even-matching-revision')
    for identifier, update in (('acl-change-payload', 'acl-keep-admin-change'),
                                ('acl-revoke-payload', 'acl-withdraw-admin'),
                                ('acl-prepare-descriptor', 'acl-withdraw-before-descriptor-delivery')):
        value, call = faults[identifier], calls[expected[identifier][-1]]
        policy = calls[update]
        need(value['request']['role'] != policy['role'],
             'acl-change-on-independent-daemon')
        need(e.moment(value['request']) < e.moment(policy['request']) < e.moment(policy['product'])
             < e.moment(value['group']['s3_forward_started']), 'actual-acl-change-during-original-read')
        response = policy['product_body']['value']
        current = next(row for row in heads[7207] if str(row['head']['head_serial']) == response['head_serial'])
        reads = [item for item in values.for_call(call) if item.get('read_head') is current and item['delivered']
                 and e.moment(value['group']['s3_delivery_finished']) < e.moment(item['request'])]
        need(reads and not any(item.get('head_record') is not None for item in values.for_call(call)),
             'original-operation-fresh-admin-barrier')
    need(calls['acl-current-admin-resume']['principal'] == '12'
         and owners['acl-p1']['decoded']['input']['creator'] == '11', 'saved-creator-is-not-current-authority')
    for identifier in ('claim-proof-put-ack', 'claim-proof-read-ack', 'cancel-proof-read-ack'):
        value, call = faults[identifier], calls[expected[identifier][-1]]
        need(value['backend']['status'] in (200, 412) and '/owner/v1/proof/' in value['request']['path']
             and not any(item.get('head_record') is not None for item in values.for_call(call)),
             'proof-unknown-cannot-replace-original-marker')
    lost = calls['proof-claim-missing-is-unknown-history']['product_body']['value']
    restored = calls['proof-claim-original-history-restored']['product_body']['value']
    need(lost['state'] == 'fenced' and lost['accepted'] is None and restored['state'] == 'active'
         and restored['accepted'] is not None and lost['prepared'] == restored['prepared'], 'missing-proof-is-unknown-history')
    for identifier in ('current-descriptor-missing', 'historical-descriptor-missing', 'same-id-different-hash',
                       'old-proof-not-before-admission'):
        name = expected[identifier][-1]
        call = calls[name]
        prior_errors = [other for other in calls.values() if other['front'] == call['front']
                        and other['command']['scope_name'] == call['command']['scope_name']
                        and not other['result']['ok'] and other['result']['error']['code'] == 'CORRUPT'
                        and e.moment(other['request']) < e.moment(call['request'])]
        need(not prior_errors and not any(item['request']['method'] != 'GET' for item in values.for_call(call)),
             'independent-live-lineage-consumes-corruption-fault')
    for identifier in ('current-descriptor-missing', 'historical-descriptor-missing'):
        pair = faults[identifier]
        call = calls[expected[identifier][-1]]
        descriptor_absence_barrier(pair, values.for_call(call))
    old = faults['historical-descriptor-missing'][1]
    old_call = calls[expected['historical-descriptor-missing'][-1]]
    proof_path = old['request']['path'].replace('/descriptor/', '/proof/')
    proof_reads = [item for item in values.for_call(old_call) if item['request']['path'] == proof_path and item['delivered']
                   and item['backend']['status'] == 200]
    need(proof_path in records and proof_reads, 'missing-historical-descriptor-has-real-proof')
    before, after = descriptor_absence_barrier(faults['historical-descriptor-missing'], values.for_call(old_call))
    need(any(head['read_head'] is before['read_head'] and head['bytes'] == before['bytes']
         and head['backend']['headers']['etag'] == before['backend']['headers']['etag']
         and e.moment(proof['group']['s3_delivery_finished']) < e.moment(head['request'])
         for head in after for proof in proof_reads), 'missing-historical-proof-stable-head-barrier')
    bad = faults['same-id-different-hash']
    need(len(bad) == 2 and bad[0]['bytes'] == bad[1]['bytes']
         and bad[0]['delivery_bytes'] == bad[1]['delivery_bytes']
         and bad[0]['backend']['headers']['etag'] == bad[1]['backend']['headers']['etag'],
         'same-id-hash-stable-two-head-barrier')
    for name, identifier in (('budget_gets', 'gets-budget-descriptor'), ('budget_bytes', 'bytes-budget-descriptor')):
        limited, query, held = calls[name + '-limited-resume'], calls[name + '-queued-query'], faults[identifier]
        need(limited['front'] == query['front'] and limited['body']['scope'] == query['body']['scope']
             and limited['request']['headers']['x-scap-admission'] == 'recovery'
             and query['request']['headers']['x-scap-admission'] == 'data'
             and e.moment(held['request']) < e.moment(query['proxy']['forward_finished'])
             < e.moment(held['group']['s3_forward_started']) < e.moment(limited['product'])
             and forwarded_while_held(query, events, identifier)
             and e.moment(held['group']['s3_delivery_finished']) < e.moment(query['product']),
             'same-actor-budget-failure-then-original-row')
        # HTTP response-reader threads need not run in actor completion order.
        # The query was already forwarded to the same Scope/worker while that
        # actor's recovery was held; its actual payload reads start only after
        # the original descriptor has been delivered and recovery can finish.
        query_data = [item for item in values.for_call(query)
                      if item['request']['method'] == 'GET' and '/objects/' in item['request']['path']]
        need(query_data and all(e.moment(held['group']['s3_delivery_finished']) < e.moment(item['request'])
                                for item in query_data), 'same-actor-query-after-held-budget-read')
        need(not any(item.get('head_record') is not None for item in values.for_call(limited)), 'budget-no-active-publication')
        witness = e.one(events, 'same_actor_query_after_budget', scope_name=name)
        need(witness['service'] == ('service-G-1' if name == 'budget_gets' else 'service-Z-1')
             and witness['result'] == query['result']['value'], 'same-actor-original-business-witness')
    return {'groups': 28, 's3_groups': 23, 's3_deliveries': 26, 'http_groups': 5,
            'original_unknowns': 12, 'after_owned_exit_effects': 3, 'original_hold_seconds': holds}


def audit(directory):
    directory = Path(directory)
    inputs = wire.parse((directory / 'inputs.json').read_bytes())
    events = e.EventIndex(e.rows(directory / 'events.jsonl'))
    need([row['sequence'] for row in events] == list(range(1, len(events) + 1))
         and all(e.moment(before) <= e.moment(after) for before, after in zip(events, events[1:])), 'event-ledger-order')
    e.fixed_inputs(inputs)
    e.identity(directory, inputs, events)
    backend, configurations, started, stopped = e.processes(directory, inputs, events)
    specs, originals, owners, named = e.original_inputs(directory, inputs, events)
    calls, local = e.sdk(directory, inputs, events, configurations, originals, owners, named)
    http, _ = e.http_exchanges(directory, events, calls)
    errors = original_errors(calls)
    # Check the fixed fault denominator before decoding Missing deliveries,
    # whose per-response checks also require their original fault witness.
    complete_fault_delivery(events)
    values = e.s3_exchanges(directory, events, backend)
    heads, objects, records, metadata = e.histories(directory, inputs, values)
    closures = Closures(objects)
    durable_dependencies(heads, values, closures)
    descriptors, phases, recovered = owner_protocol(inputs, owners, heads, records, calls, values,
                                                   e.selection(events, 'service_ready'), closures)
    observed = public_observations(inputs, owners, descriptors, records, heads, calls, values)
    actual = originals_audit(directory, inputs, events, specs, originals, calls, heads, values, objects, closures)
    gc = gc_and_catalogue(inputs, events, calls, heads, metadata, values, backend)
    faults = fault_audit(directory, inputs, events, calls, values, http, heads, owners, records, stopped)
    summary = wire.parse((directory / 'summary.json').read_bytes())
    need(summary['status'] == 'OBSERVED_NOT_AUDITED' and summary['private_removed'] is True
         and summary['cleanup_errors'] == [] and summary['error'] is None
         and 0 < summary['elapsed_seconds'] < 1200, 'successful-bounded-observation-cleanup')
    final = {name: heads[int(scope['database'])][-1]['head'] for name, scope in inputs['scopes'].items()}
    need(all(head['owner_plan']['phase']['kind'] == 'active' for head in final.values())
         and all(head['active'] and head['owner_instance'] == 9203 and head['lifecycle'] == 'ready'
                 for name, head in final.items() if name != 'named_old'), 'all-surviving-scopes-cold-active')
    return {'schema': 1, 'status': 'PASSED', 'profile': 'head8-owner-plan-native-http-signed-s3-v1',
        'fixture_source_commit': inputs['commit'], 'runtime_source_commit': inputs['runtime_source_commit'],
        'http_posts': len(calls), 'owner_posts': 200, 's3_requests': len(values),
        'saved_owner_inputs': 50, 'permanent_descriptors': 46, 'permanent_proofs': 28,
        'accepted_phases': dict(phases), 'recovered_closures': recovered, 'exact_status_observations': observed,
        'original_sql_acks': len(actual), 'native_original_sql_acks': 260, 'cold_original_lookups': 292,
        'closed_retained_windows': 2, 'current_retained_entries': 261, 'cold_original_cancelled': 1,
        'cold_blocked_unknown': 1, 'cold_business_queries': 16, 'original_errors': dict(errors),
        'owned_wait4': len(stopped) + 4, 'service_incarnations': 10, 'sdk_incarnations': 10,
        'warm_service_cache_losses': 9, 'faults': faults, 'gc': gc,
        'aws_standard': 'NOT_RUN', 'production_slo': 'NOT_RUN', 'automatic_controller': 'NOT_TESTED',
        'permanent_prefix_emptiness': 'NOT_CLAIMED',
        'source_sha256': {name: sha((directory / name).read_bytes()) for name in
            ('inputs.json', 'events.jsonl', 'intents.json', 'owner-inputs.jsonl', 'named-intents.jsonl', 'original-results.json')}}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    print(json.dumps(audit(parser.parse_args().evidence), sort_keys=True))
