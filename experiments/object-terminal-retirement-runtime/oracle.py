#!/usr/bin/env python3
"""Audit terminal retirement from original public HTTP and actual signed S3 bytes."""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
import xml.etree.ElementTree as ET

from audit_model import (Graph, Rejected, advance, digest, envelope, head_path, need,
                         object_path, prefix, retired, scope_key, sha, wire)
import audit_evidence as evidence
import spec as fixed
from audit_evidence import moment, one, raw, select, within, same_scope, original_call


def projection(head):
    result = {key: str(head[key]) for key in ('revision', 'head_serial', 'sequence', 'owner_epoch',
                                             'owner_instance', 'auth_epoch', 'request_epoch')}
    storage = head['storage']
    result.update(scope={key: str(value) for key, value in head['scope'].items()},
        active=head['active'], lifecycle=head['lifecycle'],
        max_bytes=None if head['quota']['max_bytes'] is None else str(head['quota']['max_bytes']),
        transition={key: str(value) for key, value in head['transition'].items()},
        retention={'max_entries': head['retention']['max_entries'],
                   'max_result_bytes': str(head['retention']['max_result_bytes']),
                   'oldest_epoch': str(head['windows'][-1]['epoch'])},
        storage={'active_generation': str(storage['active_generation']),
                 'allocated_through': str(storage['allocated_through']), 'plan': None, 'sweep': None,
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


def public_terminal(value):
    serial = wire.decimal(value['head_serial'])
    revision = wire.decimal(value['revision'])
    storage = value['storage']
    need(set(storage) == {'active_generation', 'allocated_through', 'plan', 'sweep', 'terminal'}, 'public-storage-shape')
    terminal = storage['terminal']
    if terminal is not None:
        need(set(terminal) == {'serial'}, 'public-terminal-shape')
        bound = wire.decimal(terminal['serial'])
        need(wire.decimal(storage['allocated_through']) < bound <= serial, 'public-terminal-allocation')
        need(revision < bound, 'public-terminal-after-business-revision')
        need(value['lifecycle'] == 'deleted' and value['active'] is False and storage['plan'] is None, 'public-terminal-deleted')
        if storage['sweep'] is not None:
            need(wire.decimal(storage['sweep']['serial']) > bound, 'public-checkpoint-after-terminal')


def public_statuses(calls, heads):
    count = 0
    for call in calls.values():
        if call['response'] is None or not call['response_body']['ok']:
            continue
        value = call['response_body']['value']
        if 'status' in value:
            value = value['status']
        if 'head_serial' not in value:
            continue
        public_terminal(value)
        database = int(value['scope']['database'])
        matching = [record for record in heads[database] if record['kind'] != 'explicit_fault'
                    and projection(record['head']) == value
                    and moment(record['exchange']['backend']) < moment(call['response'])]
        need(matching, 'public-exact-durable-status')
        if call['body']['operation'] in ('storage_status', 'named_storage_status'):
            need(value['lifecycle'] == 'deleted', 'dedicated-deleted-observation')
        count += 1
    return count


def no_such_key(exchange):
    if exchange['backend'] is None or exchange['backend']['status'] != 404:
        return False
    try:
        document = ET.fromstring(exchange['bytes'])
    except ET.ParseError:
        return False
    return document.tag == 'Error' and document.findtext('Code') == 'NoSuchKey'


def durable_objects(closure, call, publication, values):
    for path in closure['dependencies']:
        puts = [x for x in values.at_path(path) if x['request']['method'] == 'PUT' and x['request']['path'] == path
                and x['backend'] is not None and x['backend']['status'] in (200, 412)
                and moment(x['backend']) < moment(publication['request'])]
        need(puts, 'durable-dependency-put')
        reads = [x for x in values.at_path(path) if x['request']['method'] == 'GET' and x['request']['path'] == path
                 and x['backend'] is not None and x['backend']['status'] == 200 and x['delivered']
                 and moment(x['group']['s3_delivery_finished']) < moment(publication['request'])]
        need(reads, 'durable-dependency-exact-readback')


def publications(heads, objects, values, calls):
    copies = []
    for history in heads.values():
        for record in history:
            current, exchange = record['head'], record['exchange']
            if record['kind'] in ('business', 'create') and current['lifecycle'] != 'deleted':
                closure = Graph(objects, current['scope'], current['storage']['active_generation']).closure(current)
                durable_objects(closure, exchange.get('call'), exchange, values)
            if record['kind'] == 'copy_seal':
                plan = current['storage']['plan']
                call = original_call(exchange, calls, {'compact_copy'})
                need(int(call['body']['plan_serial']) == plan['serial'], 'copy-original-plan')
                source = Graph(objects, current['scope'], plan['source']).closure(plan['basis'])
                target = Graph(objects, current['scope'], plan['target']).closure(plan['basis'])
                need({path.rsplit('/', 1)[1] for path in source['dependencies']} ==
                     {path.rsplit('/', 1)[1] for path in target['dependencies']}, 'copy-complete-closure')
                for old in source['dependencies']:
                    new = prefix(current['scope'], plan['target']) + old.rsplit('/', 1)[1]
                    need(objects[old] == objects[new], 'copy-same-original-frame')
                    read = [x for x in values.at_path(old) if within(call, x, moment(exchange['request']))
                            and x['request']['method'] == 'GET' and x['request']['path'] == old
                            and x['backend']['status'] == 200 and x['delivered']]
                    put = [x for x in values.at_path(new) if within(call, x, moment(exchange['request']))
                           and x['request']['method'] == 'PUT' and x['request']['path'] == new
                           and x['payload'] == objects[old] and x['backend']['status'] in (200, 412)]
                    target_read = [x for x in values.at_path(new) if within(call, x, moment(exchange['request']))
                                   and x['request']['method'] == 'GET' and x['request']['path'] == new
                                   and x['backend']['status'] == 200 and x['delivered'] and x['bytes'] == objects[old]]
                    need(read and put and target_read, 'copy-actual-source-target-readback')
                copies.append({'scope': current['scope'], 'source': plan['source'], 'target': plan['target'],
                               'dependencies': len(source['dependencies']), 'retained_results': len(source['results'])})
    need(len(copies) == 2, 'two-real-technical-gaps')
    return copies


def originals(directory, inputs, events, specifications, saved, calls, heads, objects, values):
    acknowledgments = select(events, 'original_ack')
    expected = set(specifications) - {'late-3', 'race-3'}
    need(len(acknowledgments) == 21 and {row['name'] for row in acknowledgments} == expected, 'original-ack-denominator')
    records = wire.parse((directory / 'original-results.json').read_bytes())
    need(set(records) == expected, 'full-original-result-ledger')
    actual = {}
    for marker in acknowledgments:
        name = marker['name']
        call_name = 'receipt-delayed-sql' if name == 'receipt-3' else 'execute-' + name
        call = calls[call_name]
        need(call['response'] is not None and call['response_body']['ok'] is True, 'original-native-ack')
        value = call['response_body']['value']
        result, decoded = wire.committed(value)
        receipt = value['receipt']
        need(receipt['scope'] == saved[name]['decoded']['scope'] and receipt['request'] == saved[name]['decoded']['request'], 'original-receipt-identity')
        row = decoded[-1]
        need(row['columns'] == ['counter', 'payload', 'nonce'] and len(row['rows']) == 1
             and row['rows'][0][0] == specifications[name]['counter'] and isinstance(row['rows'][0][1], bytes)
             and len(row['rows'][0][1]) == 64 and type(row['rows'][0][2]) is int and row['affected_rows'] == 1, 'actual-native-sql-result')
        need(raw(directory, marker['result']) == result and marker['receipt'] == receipt
             and records[name] == {'receipt': receipt, 'result': marker['result']}
             and call['result']['value'] == {'state': 'committed', 'receipt': receipt, 'result': marker['result']}, 'original-ack-full-bytes')
        logical = {key: int(number) for key, number in receipt['scope'].items()}
        published = [record for record in heads[logical['database']] if record['kind'] == 'business'
                     and record['head']['sequence'] == int(receipt['sequence'])
                     and record['head']['transition'] == {key: int(number) for key, number in receipt['transition'].items()}
                     and record['head']['data_root'] == receipt['data_root']
                     and within(call, record['exchange'], moment(call['response']))]
        need(len(published) == 1, 'ack-after-original-conditional-publication')
        publication = published[0]
        closure = Graph(objects, logical, publication['head']['storage']['active_generation']).closure(publication['head'])
        key = (int(receipt['request']['epoch']), int(receipt['request']['id']))
        need(key in closure['results'] and closure['results'][key][0] == receipt['result_hash']
             and closure['results'][key][2] == result, 'ack-complete-retained-index')
        path = prefix(logical, publication['head']['storage']['active_generation']) + receipt['result_hash']
        puts = [x for x in values.at_path(path) if within(call, x, moment(publication['exchange']['request']))
                and x['request']['method'] == 'PUT' and x['request']['path'] == path and x['backend']['status'] == 200]
        readbacks = [x for x in values.at_path(path) if within(call, x, moment(publication['exchange']['request']))
                     and x['request']['method'] == 'GET' and x['request']['path'] == path
                     and x['backend']['status'] == 200 and x['delivered']]
        need(len(puts) == 1 and readbacks and all(x['bytes'] == puts[0]['payload'] for x in readbacks), 'ack-result-durable-and-read-back')
        actual[name] = {'receipt': receipt, 'result': result, 'decoded': decoded, 'publication': publication}
    for name in ('before_successor', 'after_successor', 'foreign'):
        for counter in (1, 2):
            original = name + '-' + str(counter)
            call = calls['cold-lookup-' + original]
            result, _ = wire.committed(call['response_body']['value'])
            need(result == actual[original]['result'] and call['response_body']['value']['receipt'] == actual[original]['receipt'], 'survivor-cold-original-bytes')
            mark = one(events, 'cold_original_recovered', name=original)
            need(raw(directory, mark['result']) == result and mark['receipt'] == actual[original]['receipt'], 'cold-original-ledger')
        query = calls['cold-query-' + name]
        need(query['body']['statements'] == [{'sql': 'SELECT id,counter,payload FROM witness ORDER BY id', 'params': []}], 'cold-all-row-query')
        returned = wire.result(wire.b64(query['response_body']['value']['result']))
        need(len(returned) == 1 and returned[0]['columns'] == ['id', 'counter', 'payload']
             and returned[0]['rows'] == [[1, 2, actual[name + '-2']['decoded'][-1]['rows'][0][1]]], 'survivor-single-native-effect')
    need(len(select(events, 'cold_original_recovered')) == 6, 'cold-original-denominator')
    return actual


def gc(values, heads, calls, backend):
    deletions = list(values.method('DELETE'))
    need(deletions, 'real-terminal-deletes-required')
    for deletion in deletions:
        request = deletion['request']
        need('/objects/' in request['path'], 'permanent-metadata-never-deleted')
        logical, generation, name = object_path(request['path'])
        need(request['role'] == 'B' and request['access_sha256'] == backend['gc_access_sha256'], 'dedicated-delete-capability')
        call = original_call(deletion, calls, {'gc_resume'})
        need(same_scope(call, logical), 'gc-original-full-scope')
        reads = [x for x in values.for_call(call, moment(request)) if x['request']['method'] == 'GET'
                 and head_path(x['request']['path']) == logical['database'] and x.get('read_head') is not None and x['delivered']]
        need(reads, 'delete-fresh-durable-checkpoint')
        basis = reads[-1]['read_head']['head']
        checkpoint = basis['storage']['sweep']
        need(basis['scope'] == logical and basis['storage'].get('terminal') is not None
             and retired(basis['storage'], generation) and checkpoint is not None
             and checkpoint['serial'] == int(call['body']['batch_serial']) and checkpoint['generation'] == generation,
             'delete-terminal-retirement-proof')
        entries = [entry for entry in checkpoint['entries'] if '/scap-test/' + entry['key'] == request['path']]
        need(len(entries) == 1 and entries[0]['hash'] == name and entries[0]['disposition'] == 'pending', 'delete-original-candidate')
        need(request['headers'].get('if-match') == entries[0]['etag'] and request['headers'].get('if-none-match') is None, 'delete-immutable-original-etag')
    for history in heads.values():
        for record in history:
            kind, head, exchange = record['kind'], record['head'], record['exchange']
            if kind not in ('prepare', 'progress', 'clear'):
                continue
            call = original_call(exchange, calls, {'gc_prepare'} if kind == 'prepare' else {'gc_resume'})
            observed = values.for_call(call, moment(exchange['request']))
            if kind == 'prepare':
                checkpoint = head['storage']['sweep']
                need(int(call['body']['expected_head_serial']) == record['previous']['head']['head_serial']
                     and int(call['body']['generation']) == checkpoint['generation'], 'prepare-original-head-candidate')
                listings = [x for x in observed if x['request']['method'] == 'GET'
                            and parse_qs(urlsplit(x['request']['path']).query).get('list-type') == ['2']]
                need(len(listings) == 1, 'one-bounded-list-page')
                listing = listings[0]
                query = parse_qs(urlsplit(listing['request']['path']).query)
                expected_prefix = prefix(head['scope'], checkpoint['generation']).removeprefix('/scap-test/')
                after = call['body']['after']
                need(query.get('prefix') == [expected_prefix] and query.get('max-keys') == ['32']
                     and query.get('start-after', []) == ([] if after is None else [expected_prefix + after]), 'original-list-frontier')
                document = ET.fromstring(listing['bytes'])
                keys = [child.text for container in document if container.tag.rsplit('}', 1)[-1] == 'Contents'
                        for child in container if child.tag.rsplit('}', 1)[-1] == 'Key']
                need(keys == sorted(set(keys)) and 0 < len(keys) <= 32, 'bounded-list-denominator')
                for entry in checkpoint['entries']:
                    need(entry['key'] in keys, 'checkpoint-original-listed-key')
                    inspected = [x for x in observed if x['request']['method'] == 'GET'
                                 and x['request']['path'] == '/scap-test/' + entry['key']
                                 and x['backend']['status'] == 200 and x['delivered']
                                 and x['backend']['headers'].get('etag') == entry['etag']
                                 and x['request']['access_sha256'] == backend['gc_access_sha256']]
                    need(inspected, 'checkpoint-original-inspected-etag')
                need(not [x for x in observed if x['request']['method'] == 'DELETE'], 'prepare-no-delete')
            elif kind == 'progress':
                old = record['previous']['head']['storage']['sweep']
                for before, after in zip(old['entries'], head['storage']['sweep']['entries']):
                    if before['disposition'] == after['disposition']:
                        continue
                    candidates = [x for x in observed if x['request']['path'] == '/scap-test/' + before['key'] and x['delivered']]
                    if after['disposition'] == 'applied':
                        accepted = [x for x in candidates if x['request']['method'] == 'DELETE'
                                    and x['request']['headers'].get('if-match') == before['etag'] and x['backend']['status'] in (200, 204)]
                    elif after['disposition'] == 'condition_mismatch':
                        accepted = [x for x in candidates if x['request']['method'] == 'DELETE'
                                    and x['request']['headers'].get('if-match') == before['etag'] and x['backend']['status'] == 412]
                    else:
                        accepted = [x for x in candidates if x['request']['method'] in ('GET', 'DELETE') and no_such_key(x)]
                    need(accepted, 'checkpoint-known-delivered-outcome')
            else:
                need(any(x.get('read_head') is record['previous'] and x['delivered'] for x in observed), 'settled-checkpoint-exact-before-clear')
    return deletions


def mark(control, raw_control):
    return {key: control[key] for key in ('kind', 'principal', 'operation', 'expected_name_revision',
                                        'expected_head_revision', 'nonce')} | {'descriptor_hash': sha(raw_control)}


def metadata_protocol(metadata, heads, values, calls):
    records = [record for history in metadata.values() for record in history]
    descriptors = {sha(record['exchange']['payload']): record for record in records if record['kind'] == 'descriptor'}
    controls = {sha(record['exchange']['payload']): record for record in records if record['kind'] == 'control'}
    proofs = {sha(record['exchange']['payload']): record for record in records if record['kind'] == 'proof'}
    need(len(descriptors) == 8 and len(controls) == 6 and len(proofs) == 4, 'permanent-record-denominator')
    for record in records:
        kind, value, exchange = record['kind'], record['value'], record['exchange']
        if kind == 'descriptor':
            continue
        original = value['control'] if kind == 'proof' else value
        origin = original['origin']
        need(origin['descriptor_hash'] in descriptors, 'real-original-descriptor')
        descriptor = descriptors[origin['descriptor_hash']]
        need(descriptor['value']['creation'] == original['creation']
             and origin == {'creator': original['creation']['creator'], 'operation': original['creation']['operation'],
                            'name_hash': sha(original['creation']['name'].encode()),
                            'descriptor_hash': sha(descriptor['exchange']['payload'])}, 'original-origin-binding')
        if kind == 'name':
            previous = record['previous']
            if previous is None:
                need(value['state'] == 'reserved' and value['revision'] == 1, 'initial-name-reservation')
            else:
                old = previous['value']
                need(value['revision'] == old['revision'] + 1, 'name-one-step')
                if value['creation'] != old['creation']:
                    need(old['state'] == 'tombstone' and value['state'] == 'reserved'
                         and value['creation']['expected_name_revision'] == old['revision'], 'name-reuse-original-condition')
                else:
                    need((old['state'], value['state']) in (('reserved', 'bound'), ('reserved', 'aborting'),
                         ('bound', 'tombstone'), ('aborting', 'tombstone')), 'name-monotonic-stage')
            if value['control'] is not None:
                matching = [row for row in controls.values() if row['value'] == value['control']]
                need(len(matching) == 1 and moment(matching[0]['exchange']['backend']) < moment(exchange['request']), 'name-durable-original-control')
            if value['state'] == 'tombstone':
                if value['control']['kind'] == 'abort':
                    need(value['proof'] in proofs and proofs[value['proof']]['value']['control'] == value['control']
                         and moment(proofs[value['proof']]['exchange']['backend']) < moment(exchange['request']), 'name-durable-original-proof')
                else:
                    valid = [row for row in heads[value['creation']['scope']['database']] if row['head']['scope'] == value['creation']['scope']
                             and row['head']['lifecycle'] == 'deleted' and row['head']['deletion'] == mark(value['control'], matching[0]['exchange']['payload'])
                             and moment(row['exchange']['backend']) < moment(exchange['request'])]
                    need(valid, 'name-release-after-original-delete')
        elif kind == 'proof':
            actual_control = [row for row in controls.values() if row['value'] == value['control']]
            need(len(actual_control) == 1 and moment(actual_control[0]['exchange']['backend']) < moment(exchange['request']), 'proof-durable-original-control')
            barrier = value['barrier']
            observed = [x for x in values if x['request']['role'] == exchange['request']['role']
                        and x['request']['method'] == 'GET' and x.get('read_head') is not None
                        and x['read_head']['head']['scope']['database'] == original['creation']['scope']['database']
                        and x['delivered'] and moment(x['group']['s3_delivery_finished']) < moment(exchange['request'])]
            need(observed, 'proof-original-exact-head')
            if barrier['kind'] == 'own_deleted':
                valid = [x for x in observed if x['read_head']['head']['scope'] == original['creation']['scope']
                         and x['read_head']['head']['creation'] == original['origin']
                         and x['read_head']['head']['lifecycle'] == 'deleted'
                         and x['read_head']['head']['transition'] == barrier['transition']
                         and x['read_head']['head']['deletion'] == mark(original, actual_control[0]['exchange']['payload'])]
            else:
                valid = [x for x in observed if x['read_head']['head']['scope'] == barrier['scope']
                         and x['read_head']['head']['creation'] == barrier['creation']]
            need(valid, 'proof-original-business-or-foreign-barrier')

    def source(call, head, cutoff):
        logical = head['scope']
        need(head['creation'] is not None and head['deletion'] is not None
             and same_scope(call, logical), 'named-original-own-head')
        origin = head['creation']
        need(origin['descriptor_hash'] in descriptors and head['deletion']['descriptor_hash'] in controls, 'named-real-source-records')
        descriptor, deletion = descriptors[origin['descriptor_hash']], controls[head['deletion']['descriptor_hash']]
        creation, control = descriptor['value']['creation'], deletion['value']
        expected_creation = call['body']['creation']
        native = {key: int(value) if key in ('creator', 'operation') else
                  {k: int(v) for k, v in value.items()} if key == 'scope' else
                  None if value is None else int(value) if key == 'expected_name_revision' else value
                  for key, value in expected_creation.items()}
        need(creation == native and control['creation'] == native and control['origin'] == origin
             and head['deletion'] == mark(control, deletion['exchange']['payload']), 'named-exact-deletion-origin')
        observed = [x for x in values.for_call(call, cutoff) if x['request']['method'] == 'GET' and x['delivered']]
        for record in (descriptor, deletion):
            need(any(x.get('read_metadata') is record for x in observed), 'named-source-read-exact-record')
        name_path = '/scap-test/scap-object/v1/1/7/catalogue/v1/name/' + sha(creation['name'].encode())
        names = [x for x in observed if x['request']['path'] == name_path]
        need(len(names) == 2 and all(x.get('read_metadata') is not None for x in names)
             and names[0]['bytes'] == names[1]['bytes']
             and names[0]['backend']['headers'].get('etag') == names[1]['backend']['headers'].get('etag'), 'stable-name-double-exact-read')
        name = names[0]['read_metadata']['value']
        proof_path = f'/scap-test/scap-object/v1/1/7/catalogue/v1/abort-proof/{creation["creator"]}/{creation["operation"]}'
        proof_reads = [x for x in observed if x['request']['path'] == proof_path]
        head_reads = [x for x in observed if x.get('read_head') is not None and x['read_head']['head'] == head]
        need(len(proof_reads) == 1 and head_reads and moment(names[0]['request']) < moment(proof_reads[0]['request'])
             < moment(head_reads[0]['request']) < moment(names[1]['request']), 'proof-before-head-stable-view')
        if control['kind'] == 'delete':
            need(no_such_key(proof_reads[0]), 'delete-no-abort-proof')
            need(name['creation'] == creation and name['state'] in ('bound', 'tombstone')
                 or name['creation'] != creation and name['revision'] > (creation['expected_name_revision'] or 0) + 3,
                 'deleted-source-survives-name-reuse')
        elif proof_reads[0]['backend']['status'] == 200:
            proof = proof_reads[0].get('read_metadata')
            need(proof is not None and proof['kind'] == 'proof' and proof['value']['control'] == control
                 and proof['value']['barrier'] == {'kind': 'own_deleted', 'transition': head['transition']}, 'own-proof-original-business-transition')
        else:
            need(no_such_key(proof_reads[0]) and name['creation'] == creation and name['state'] == 'aborting'
                 and name['control'] == control, 'own-deleted-before-proof-authority')
        need(head['lifecycle'] == 'deleted' and any(permission['principal'] == int(call['request']['principal'])
             and permission['admin'] for permission in head['policy']), 'fresh-current-admin')
        return name, proof_reads[0]

    seals = []
    for history in heads.values():
        for record in history:
            if record['kind'] != 'terminal':
                continue
            exchange, previous, current = record['exchange'], record['previous']['head'], record['head']
            operation = 'retire_storage' if previous['creation'] is None else 'retire_named_storage'
            call = original_call(exchange, calls, {operation})
            need(same_scope(call, current['scope']) and int(call['body']['expected_head_serial']) == previous['head_serial'], 'seal-original-public-candidate')
            if operation == 'retire_named_storage':
                source(call, previous, moment(exchange['request']))
            else:
                need(previous['deletion'] is None, 'direct-seal-no-named-origin')
            need(call['role'] in ('C', 'R'), 'seal-independent-of-gc-configuration')
            seals.append(record)
    need(len(seals) == 10, 'terminal-seal-denominator')
    for call in calls.values():
        if call['body']['operation'] != 'named_storage_status' or call['response'] is None or not call['response_body']['ok']:
            continue
        value = call['response_body']['value']
        head = next(record['head'] for record in heads[int(value['scope']['database'])]
                    if record['kind'] != 'explicit_fault' and projection(record['head']) == value)
        source(call, head, moment(call['response']))
    return seals, {'descriptors': len(descriptors), 'controls': len(controls), 'proofs': len(proofs),
                   'name_mutations': sum(record['kind'] == 'name' for record in records)}


def fault_record(events, values, name):
    armed, arrived = one(events, 'fault_armed', id=name), one(events, 'fault_arrived', id=name)
    found = values.identities.get((arrived['role'], arrived['serial']))
    match = [] if found is None else [found]
    need(len(match) == 1, 'fault-original-exchange')
    exchange = match[0]
    need(armed['role'] == arrived['role'] and armed['method'] == exchange['request']['method']
         and exchange['request']['path'].startswith(armed['prefix']) and armed['stage'] == arrived['stage']
         and moment(armed) < moment(exchange['request']) < moment(arrived), 'fault-original-cut')
    if armed['mode'] == 'hold':
        released = one(events, 'fault_release_requested', id=name)
        resumed = one(events, 'fault_forward_resumed', id=name)
        need(moment(arrived) < moment(released) <= moment(resumed)
             and moment(resumed) - moment(arrived) < 180_000_000_000, 'original-hold-deadline')
        target = exchange['group']['s3_forward_started'] if armed['stage'] == 'before_forward' else exchange['group']['s3_delivery_started']
        need(moment(resumed) < moment(target), 'original-held-transport-resumed')
        return exchange, arrived, released
    need(armed['mode'] in ('drop', 'no_such_bucket'), 'planned-fault-mode')
    return exchange, arrived, None


def no_writes(call, values, rule):
    need(not [x for x in values.for_call(call) if x['request']['method'] in ('PUT', 'DELETE')
              and moment(x['request']) < moment(call['done'])], rule)


def errors(calls, values):
    expected = {
        'late-live-storage-rejected': 'LIFECYCLE', 'before-live-storage-rejected': 'CONFLICT',
        'late-unsealed-active-forbidden': 'LIFECYCLE', 'late-no-admin-storage': 'DENIED',
        'before-no-admin-storage': 'DENIED', 'late-unallocated-forbidden': 'FENCED',
        'race-seal-R': 'CONFLICT', 'before-unstable-observation': 'CONFLICT',
        'foreign-storage-denied': 'IDENTITY_CONFLICT', 'foreign-seal-denied': 'IDENTITY_CONFLICT',
        'stale-old-lookup': 'MISSING', 'bad-sweep-observe-rejected': 'CORRUPT', 'bad-sweep-resume-rejected': 'CORRUPT',
        'bad-sweep-delete-status': 'DENIED',
    }
    expected.update({name: 'CONFLICT' for name in ('late-repeat-seal-original', 'late-repeat-seal-current',
                                                 'after-repeat-seal-original', 'after-repeat-seal-current')})
    for name in ('late', 'race', 'receipt', 'before', 'after', 'proof_present', 'proof_absent', 'fence_absent'):
        expected['cold-ordinary-status-' + name] = 'LIFECYCLE'
        if name in ('late', 'race', 'receipt', 'before', 'after'):
            expected['cold-ordinary-lookup-' + name] = 'LIFECYCLE'
    for name, code in expected.items():
        call = calls[name]
        need(call['result']['ok'] is False and call['result']['error']['code'] == code, 'specific-fail-closed-result')
        if name != 'race-seal-R':
            no_writes(call, values, 'rejected-operation-no-mutation')
    unknown = ('late-original-sql', 'late-seal-unknown', 'race-old-sql', 'before-delete-original',
        'after-seal-unknown', 'proof_present-resume-original', 'proof_present-abort-original',
        'proof_absent-resume-original', 'proof_absent-abort-original', 'fence-absent-resume-original',
        'foreign-loser-resume-original', 'foreign-abort-original', 'late-checkpoint-unknown')
    for name in unknown:
        need(calls[name]['result']['ok'] is False and calls[name]['result']['error']['code'] == 'UNKNOWN', 'original-unknown-not-overwritten')
    return len(unknown)


def admin_only_retirement(calls, heads):
    policy, denied, deletion, seal = (calls[name] for name in ('bad-sweep-admin-only',
        'bad-sweep-delete-status', 'bad-sweep-delete', 'bad-sweep-seal-without-read-or-provision'))
    permissions = [{'principal': '11', 'read': False, 'write': False, 'admin': True}]
    need(policy['body']['permissions'] == permissions
         and all(call['request']['principal'] == '11' for call in (policy, denied, deletion, seal)),
         'admin-only-original-principal')
    need(policy['result']['ok'] and deletion['result']['ok'] and seal['result']['ok']
         and denied['result']['ok'] is False and denied['result']['error']['code'] == 'DENIED',
         'admin-only-read-denied')
    need(deletion['body']['expected_revision'] == policy['response_body']['value']['revision'],
         'admin-only-delete-original-policy-revision')
    need(all(moment(left['done']) < moment(right['request'])
             for left, right in zip((policy, denied, deletion), (denied, deletion, seal))),
         'admin-only-original-call-order')
    database = int(policy['body']['scope']['database'])
    preserved = [record['head'] for record in heads[database]
                 if moment(policy['request']) < moment(record['exchange']['backend']) < moment(seal['done'])]
    native = [{**permissions[0], 'principal': 11}]
    need(preserved and all(head['policy'] == native for head in preserved)
         and preserved[-1]['storage'].get('terminal') is not None,
         'admin-only-policy-preserved-through-seal')


def name_reads_before_move(values, call, moving):
    return [x for x in values.for_call(call, moment(moving['request']))
            if x['request']['method'] == 'GET' and x['request']['path'] == moving['request']['path']
            and x['backend'] is not None and x['backend']['status'] == 200 and x['delivered']]


def faults(directory, inputs, events, calls, values, heads, objects, originals, deletions, seals):
    identifiers = {row['id'] for row in select(events, 'fault_armed')}
    expected = {'late-original-put', 'late-original-read', 'late-original-seal', 'late-checkpoint-bucket-error',
        'race-original-sql-cas', 'race-seal-C', 'race-seal-R', 'receipt-original-success', 'before-old-release',
        'before-unstable-name-view', 'after-named-seal-response-lost', 'proof_present-old-bind',
        'proof_present-old-abort', 'proof_absent-old-bind', 'proof_absent-old-abort', 'fence-absent-old-head',
        'foreign-loser-old-head', 'foreign-abort-release-lost', 'stale-old-read'}
    need(identifiers == expected and len(select(events, 'fault_armed')) == len(expected), 'fixed-fault-denominator')
    cuts = {name: fault_record(events, values, name) for name in sorted(identifiers)}
    late_seal, _, release = cuts['late-original-seal']
    need(late_seal['backend']['status'] == 200 and moment(calls['late-seal-unknown']['done']) <
         moment(calls['late-observed-before-effect']['request']) < moment(calls['late-observed-before-effect']['done'])
         < moment(release) < moment(calls['late-observed-after-effect']['request']), 'late-seal-unknown-observe-before-after')
    need(calls['late-observed-before-effect']['response_body']['value']['storage']['terminal'] is None
         and calls['late-observed-after-effect']['response_body']['value']['storage']['terminal'] is not None,
         'original-unknown-does-not-resolve-itself')
    lost_named, _, _ = cuts['after-named-seal-response-lost']
    need(lost_named['backend']['status'] == 200 and not lost_named['delivered']
         and calls['after-seal-observed']['response_body']['value']['storage']['terminal'] is not None,
         'named-original-unknown-after-effect')

    first, second = cuts['race-seal-C'][0], cuts['race-seal-R'][0]
    need(first['backend']['status'] == 200 and second['backend']['status'] == 412
         and first['request']['headers']['if-match'] == second['request']['headers']['if-match']
         and first['payload'] == second['payload']
         and moment(second['request']) < moment(first['backend']) < moment(second['group']['s3_forward_started']), 'fixed-original-seal-race')
    for name in ('race-original-sql-cas', 'before-old-release', 'proof_present-old-bind', 'proof_present-old-abort',
                 'proof_absent-old-bind', 'fence-absent-old-head', 'foreign-loser-old-head'):
        need(cuts[name][0]['backend']['status'] == 412, 'late-original-candidate-condition-failed')

    for scope_name, cut_name, result_code in (('late', 'late-original-read', 'SNAPSHOT_EXPIRED'), ('stale', 'stale-old-read', 'MISSING')):
        held, arrival, released = cuts[cut_name]
        call = calls['late-old-lookup' if scope_name == 'late' else 'stale-old-lookup']
        need(no_such_key(held), 'old-read-actual-no-such-key')
        erased = [x for x in deletions if x['request']['path'] == held['request']['path'] and x['backend'] is not None
                  and x['backend']['status'] in (200, 204) and moment(arrival) < moment(x['backend']) < moment(released)]
        need(erased, 'delete-before-original-read-forward')
        old_reads = [x for x in values.for_call(call, moment(held['request'])) if x.get('read_head') is not None and x['delivered']]
        fresh = [x for x in values if x['request']['role'] == call['role'] and x.get('read_head') is not None
                 and x['delivered'] and moment(held['backend']) < moment(x['request']) < moment(call['done'])]
        need(len(old_reads) == len(fresh) == 1, 'one-original-context-one-fresh-diagnostic')
        original, final = old_reads[0]['read_head']['head'], fresh[0]['read_head']['head']
        need(final['head_serial'] > original['head_serial'] and final['storage']['active_generation'] >= original['storage']['active_generation']
             and final['storage']['allocated_through'] >= original['storage']['allocated_through']
             and old_reads[0]['backend']['headers']['etag'] != fresh[0]['backend']['headers']['etag'], 'fresh-fenced-old-context')
        if scope_name == 'late':
            need(final['storage']['terminal']['serial'] > original['head_serial'], 'expiry-after-original-terminal-barrier')
        else:
            need(final['storage']['terminal']['serial'] == original['head_serial']
                 and final['revision'] < final['storage']['terminal']['serial'], 'stale-barrier-static-valid-independent-cut')
        need(call['result']['error']['code'] == result_code, 'old-read-precise-source-result')
        need(moment(call['done']) - moment(call['request']) < 30_000_000_000, 'original-reader-observation-bound')

    late_put, _, late_release = cuts['late-original-put']
    need(late_put['backend']['status'] == 200, 'late-original-put-actually-accepted')
    new_round = [call for call in calls.values() if call['command']['id'].startswith('late-new-round-after-put-')
                 and call['body']['operation'] == 'gc_prepare']
    need(new_round and min(new_round, key=lambda call: moment(call['request']))['body']['after'] is None,
         'late-put-new-scan-from-start')
    need(any(x['request']['path'] == late_put['request']['path'] and x['backend'] is not None
             and x['backend']['status'] in (200, 204) and moment(late_put['backend']) < moment(x['request']) for x in deletions),
         'late-put-subsequent-conditional-collection')

    receipt, receipt_arrived, receipt_released = cuts['receipt-original-success']
    need(receipt['backend']['status'] == 200 and receipt['delivered'], 'known-original-publication-success')
    original = originals['receipt-3']
    terminal = next(record for record in seals if record['head']['scope'] == original['publication']['head']['scope'])
    need(moment(receipt['backend']) < moment(terminal['exchange']['backend']) < moment(receipt_released)
         < moment(calls['receipt-delayed-sql']['response']), 'committed-original-reply-after-terminal')
    closure = Graph(objects, terminal['head']['scope'], terminal['head']['storage']['active_generation']).closure(terminal['head'])
    for path in closure['dependencies']:
        need(any(x['request']['path'] == path and x['backend'] is not None and x['backend']['status'] in (200, 204)
                 and moment(terminal['exchange']['backend']) < moment(x['backend']) < moment(receipt_released) for x in deletions),
             'committed-closure-deleted-before-original-reply')
    need(calls['receipt-delayed-sql']['result']['ok'] is True
         and moment(calls['receipt-delayed-sql']['done']) - moment(receipt_arrived) < 30_000_000_000,
         'known-receipt-not-downgraded')

    for scope_name, prefix_name in (('before', 'before'), ('proof_present', 'proof_present'),
                                   ('proof_absent', 'proof_absent'), ('fence_absent', 'fence-absent')):
        command = prefix_name + ('-delete-resumed' if scope_name == 'before' else '-abort-resumed')
        call = calls[command]
        observed = [x for x in values.for_call(call, moment(call['response'])) if x.get('read_head') is not None and x['delivered']]
        need(observed and any(x['read_head']['head']['storage'].get('terminal') is not None
             and x['read_head']['head']['storage']['sweep'] is not None for x in observed), 'metadata-recovery-during-pending-terminal-gc')
        need(not [x for x in values.for_call(call) if '/objects/' in x['request']['path']
                  and moment(x['request']) < moment(call['response'])], 'metadata-recovery-no-retired-payload')
    moving, _, moving_release = cuts['before-unstable-name-view']
    need(moment(calls['before-delete-resumed']['response']) < moment(moving_release)
         and moving['backend']['status'] == 200, 'changed-name-between-exact-reads')
    name_first = name_reads_before_move(values, calls['before-unstable-observation'], moving)
    need(len(name_first) == 1 and name_first[0]['bytes'] != moving['bytes'], 'unstable-name-actual-change')
    before_release_cut = cuts['before-old-release'][0]
    new_scope = {key: int(value) for key, value in inputs['scopes']['before_successor'].items()}
    new_head = heads[new_scope['database']][0]
    need(moment(new_head['exchange']['backend']) < moment(before_release_cut['group']['s3_forward_started']), 'old-name-release-after-successor')

    present_seal = next(record for record in seals if record['head']['scope']['database'] == int(inputs['scopes']['proof_present']['database']))
    absent_seal = next(record for record in seals if record['head']['scope']['database'] == int(inputs['scopes']['proof_absent']['database']))
    present_cut = cuts['proof_present-old-abort'][0]
    proof_reads = [x for x in values if x.get('read_metadata') is not None and x['read_metadata']['kind'] == 'proof'
                   and x['read_metadata']['value']['control']['creation']['scope'] == present_seal['head']['scope'] and x['delivered']
                   and moment(x['group']['s3_delivery_finished']) < moment(present_cut['request'])]
    need(proof_reads and moment(present_cut['request']) < moment(present_seal['exchange']['request']), 'own-proof-present-before-seal')
    absent_cut = cuts['proof_absent-old-abort'][0]
    need(absent_cut['backend']['status'] == 200 and moment(absent_cut['request']) < moment(absent_seal['exchange']['backend'])
         < moment(absent_cut['group']['s3_forward_started']), 'own-original-proof-after-seal')

    bucket = cuts['late-checkpoint-bucket-error'][0]
    need(bucket['backend'] is None and bucket['group']['s3_delivery_started']['origin'] == 'fixture_no_such_bucket', 'bucket-error-original-injection')
    document = ET.fromstring(raw(directory, bucket['group']['s3_delivery_started']['response']))
    need(document.tag == 'Error' and document.findtext('Code') == 'NoSuchBucket', 'bucket-is-not-key-absence')
    pending = calls['late-checkpoint-pending']['response_body']['value']['storage']['sweep']
    need(pending is not None and pending['serial'] == calls['late-checkpoint-unknown']['body']['batch_serial'] and pending['pending'] > 0,
         'bucket-error-keeps-original-pending-checkpoint')
    unknown_end = moment(calls['late-checkpoint-unknown']['done'])
    unknown_start = moment(calls['late-checkpoint-unknown']['request'])
    need(not [record for history in heads.values() for record in history if record['kind'] in ('progress', 'clear')
              and unknown_start < moment(record['exchange']['request']) < unknown_end], 'bucket-error-no-invented-disposition')
    bad_database = int(inputs['scopes']['bad_sweep']['database'])
    fault = next(record for record in heads[bad_database] if record['kind'] == 'explicit_fault')
    need(not [x for x in values if moment(x['request']) > moment(fault['exchange']['backend'])
              and x['request']['method'] in ('PUT', 'DELETE') and x['request']['role'] != 'O'
              and (head_path(x['request']['path']) == bad_database or f'/{bad_database}/inc/' in x['request']['path'])],
         'invalid-checkpoint-never-mutates')
    surviving = {int(inputs['scopes'][name]['database']) for name in ('before_successor', 'after_successor', 'foreign')}
    need(not [x for x in deletions if object_path(x['request']['path'])[0]['database'] in surviving], 'successor-and-foreign-not-collected')
    need(not [record for database in surviving for record in heads[database] if record['kind'] == 'terminal'], 'survivor-never-sealed')
    admin_only_retirement(calls, heads)
    return {'faults': len(expected), 'original_unknowns': errors(calls, values),
            'old_context_expired': 1, 'stale_terminal_context_rejected_as_missing': 1,
            'committed_original_reply_after_collection': 1, 'named_source_recovery_with_pending_gc': 4,
            'admin_only_retirement_without_read': 1}


def audit(directory):
    directory = Path(directory).resolve()
    inputs = wire.parse((directory / 'inputs.json').read_bytes())
    need(inputs['scopes'] == fixed.SCOPES and inputs['specs'] == fixed.inputs()
         and inputs['named'] == {name: fixed.creation(name) for name in fixed.NAMED}
         and inputs['max_sweep_pages'] == 32, 'exact-frozen-logical-inputs')
    events = evidence.rows(directory / 'events.jsonl')
    need([row['sequence'] for row in events] == list(range(1, len(events) + 1)), 'event-closed-sequence')
    need(all(moment(a) <= moment(b) for a, b in zip(events, events[1:])), 'event-monotonic-order')
    need(inputs['timeouts'] == {'sdk_ms': 90000, 'recovery_ms': 300000, 'http_ms': 120000,
        's3_ms': 120000, 'original_unknown_ms': 1500, 'hold_seconds': 180,
        'old_reader_observation_ms': 30000, 'receipt_observation_ms': 30000, 'whole_seconds': 1200}, 'frozen-original-budgets')
    evidence.identity(directory, inputs, events)
    backend, configurations, process_report = evidence.processes(directory, inputs, events)
    specifications, saved, named = evidence.original_inputs(directory, inputs)
    calls = evidence.sdk(directory, inputs, events, configurations, saved, named)
    values = evidence.exchanges(directory, events, backend)
    heads, objects, metadata = evidence.histories(directory, inputs, events, calls, values)
    public_count = public_statuses(calls, heads)
    copy_report = publications(heads, objects, values, calls)
    original_results = originals(directory, inputs, events, specifications, saved, calls, heads, objects, values)
    deletions = gc(values, heads, calls, backend)
    seals, metadata_report = metadata_protocol(metadata, heads, values, calls)
    fault_report = faults(directory, inputs, events, calls, values, heads, objects, original_results, deletions, seals)
    summary = wire.parse((directory / 'summary.json').read_bytes())
    need(summary['status'] == 'OBSERVED_NOT_AUDITED' and summary['cleanup_errors'] == []
         and summary['private_removed'] is True and summary['elapsed_seconds'] < 1200, 'actual-bounded-run-complete')
    return {'schema': 1, 'status': 'PASSED', 'profile': 'head7-terminal-retirement-native-http-signed-s3-v1',
        'fixture_source_commit': inputs['commit'], 'runtime_source_commit': inputs['runtime_source_commit'],
        'http_posts': len(calls), 's3_requests': len(values), 'original_sql_inputs': 23,
        'native_original_acks': len(original_results), 'cold_survivor_lookups': 6,
        'terminal_seals': len(seals), 'public_status_observations': public_count,
        'copy_closures': copy_report, 'catalogue': metadata_report,
        'head_transitions': dict(Counter(record['kind'] for history in heads.values() for record in history)),
        'gc': {'delete_requests': len(deletions), 'actual_accepted_deletes': sum(
            x['backend'] is not None and x['backend']['status'] in (200, 204) for x in deletions)},
        'faults': fault_report, 'processes': process_report,
        'aws_standard': 'NOT_RUN', 'production_slo': 'NOT_RUN', 'permanent_prefix_emptiness': 'NOT_CLAIMED',
        'losing_foreign_scope_orphans': 'NOT_RECLAIMED', 'post_delete_payload_lookup': 'LIFECYCLE',
        'source_sha256': {name: sha((directory / name).read_bytes()) for name in
            ('inputs.json', 'events.jsonl', 'intents.json', 'named-intents.jsonl', 'original-results.json',
             'sdk-A.jsonl', 'sdk-B.jsonl', 'sdk-C.jsonl', 'sdk-R.jsonl')}}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('evidence', type=Path)
    argument = parser.parse_args()
    try:
        result = audit(argument.evidence)
    except BaseException as error:
        print(json.dumps({'status': 'FAILED', 'error': str(error), 'type': type(error).__name__}, sort_keys=True))
        raise SystemExit(1)
    print(json.dumps(result, sort_keys=True))
