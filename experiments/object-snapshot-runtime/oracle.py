#!/usr/bin/env python3
"""Independent S1 verdict from original bytes, authority transitions and ACKs."""
import argparse
from collections import Counter
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
from urllib.parse import parse_qs, urlsplit
import xml.etree.ElementTree as ET
from xml.parsers import expat

import audit_evidence as e
import audit_model as m
from audit_model import need, Rejected, wire, sha

description = importlib.util.spec_from_file_location('snapshot_legacy_oracle',
    Path(__file__).resolve().parent.parent / 'object-owner-plan-runtime/oracle.py')
prior = importlib.util.module_from_spec(description)
description.loader.exec_module(prior)
projection, public = prior.projection, prior.public
HEAD_PATH = '/scap-test/scap-object/v1/1/7/8201/head'
BASE = '/scap-test/scap-object/v1/1/7/8201/inc/1/gen/1/'
S3_XML_NAMESPACE = 'http://s3.amazonaws.com/doc/2006-03-01/'


def within(call, exchange):
    return (call['role'] == exchange['request']['role'] and
            e.moment(call['proxy']['forward_started']) < e.moment(exchange['request']) <
            e.moment(call['proxy']['backend_response']))


def reads(call, values):
    return [value for value in values if within(call, value) and value['request']['method'] == 'GET'
            and value['delivered'] and value['backend']['status'] == 200]


def accepted(value):
    return value['backend'] is not None and value['backend']['status'] in (200, 204)


def fixed_calls(events, calls):
    fixed = {
        'bulk-p1-base': 'status', 'bulk-p1-prepare': 'owner_prepare', 'bulk-p1-claim': 'owner_claim',
        'bulk-p1-resume': 'owner_resume', 'set-original-limits': 'snapshot_limits',
        'point-one-prepare': 'snapshot_prepare', 'capture-original-ack': 'snapshot_capture',
        'point-one-inspect': 'snapshot_inspect', 'point-one-list': 'snapshot_list',
        'close-window-one': 'close_full', 'point-two-base': 'status', 'point-two-prepare': 'snapshot_prepare',
        'point-two-capture': 'snapshot_capture', 'close-window-two': 'close_full',
        'two-points-before-copy': 'snapshot_list', 'copy-begin': 'compact_begin',
        'copy-seal': 'compact_copy', 'copy-promote': 'compact_promote',
        'bulk-p2-base': 'status', 'bulk-p2-prepare': 'owner_prepare', 'bulk-p2-claim': 'owner_claim',
        'bulk-p2-resume': 'owner_resume', 'cold-current-query': 'query',
        'cold-point-one': 'snapshot_inspect', 'cold-point-two': 'snapshot_inspect',
        'cold-two-points-list': 'snapshot_list', 'release-original-ack': 'snapshot_release',
        'released-point-one': 'snapshot_inspect', 'delete-with-point-two': 'lifecycle',
        'seal-with-held-point-rejected': 'retire_storage', 'deleted-release-point-two': 'snapshot_release',
        'deleted-point-two': 'snapshot_inspect', 'terminal-seal': 'retire_storage',
        'terminal-point-one': 'snapshot_inspect', 'terminal-point-two': 'snapshot_inspect',
        'terminal-empty-list': 'snapshot_list'}
    fixed.update((f'execute-original-{number}', 'execute') for number in range(3, 7))
    fixed.update((f'cold-lookup-original-{number}', 'lookup') for number in range(1, 7))
    rounds = e.selection(events, 'sweep_round_finished')
    need(len(rounds) == 2 and {row['label'] for row in rounds} == {'retired-one', 'terminal-two'}, 'two-complete-sweep-rounds')
    for row in rounds:
        need(type(row['pages']) is int and 1 <= row['pages'] <= 32, 'bounded-sweep-denominator')
        for page in range(row['pages']):
            label = f'{row["label"]}-{page}'
            fixed.update({label + '-storage': 'status' if row['label'] == 'retired-one' else 'storage_status',
                          label + '-prepare': 'gc_prepare', label + '-resume': 'gc_resume'})
    need(set(calls) == set(fixed) and all(calls[key]['body']['operation'] == value for key, value in fixed.items()),
         'fixed-public-call-denominator')
    errors = {name: call['result']['error']['code'] for name, call in calls.items() if not call['result']['ok']}
    need(errors == {'capture-original-ack': 'UNKNOWN', 'release-original-ack': 'UNKNOWN',
                    'seal-with-held-point-rejected': 'CONFLICT'}, 'original-errors-fixed')
    for name in ('capture-original-ack', 'release-original-ack'):
        call = calls[name]
        need(call['response'] is None and call['product_body']['ok'] is True
             and 'delivery_started' not in call['proxy'], 'original-unknown-not-overwritten')
        armed = e.one(events, 'http_proxy_fault_armed', id=name)
        arrived = e.one(events, 'http_proxy_fault_arrived', id=name)
        need(armed['mode'] == arrived['mode'] == 'drop' and armed['stage'] == arrived['stage'] == 'after_response'
             and arrived['operation'] == call['body']['operation'] and arrived['role'] == call['front'], 'actual-original-ack-loss')
    need(len(e.selection(events, 'http_proxy_fault_armed')) == 2 and not e.selection(events, 'fault_armed'), 'fixed-two-http-faults')
    return fixed


def list_witness(exchange, live):
    query = parse_qs(urlsplit(exchange['request']['path']).query)
    need(query.get('list-type') == ['2'] and query.get('max-keys') == ['32'] and len(query.get('prefix', [])) == 1,
         'retired-list-prefix-bound')
    prefix = '/scap-test/' + query['prefix'][0]
    need(prefix in (BASE + 'storage/1/objects/', BASE + 'storage/2/objects/'), 'payload-only-list-prefix')
    after = '/scap-test/' + query['start-after'][0] if 'start-after' in query else ''
    root = ET.fromstring(exchange['bytes'])
    keys = [node.text for node in root.findall('.//{*}Contents/{*}Key')]
    expected = sorted(path for path in live if path.startswith(prefix) and path > after)
    need(keys == [path.removeprefix('/scap-test/') for path in expected[:32]], 'complete-retired-list-page')
    truncated = root.find('{*}IsTruncated')
    need(truncated is not None and truncated.text == ('true' if len(expected) > 32 else 'false'), 'complete-list-frontier')
    exchange['listed'] = ['/scap-test/' + key for key in keys]


def gc_flat_xml(raw, root_name, allowed, namespace_required):
    """Independently decode bounded, flat capability metadata; no DTD or aliases."""
    need(len(raw) <= 32768, 'bounded-gc-capability-response')
    fields, stack = {}, []
    parser = expat.ParserCreate()

    def start(name, attributes):
        if not stack:
            need(name == root_name and (attributes == {'xmlns': S3_XML_NAMESPACE}
                 or not namespace_required and attributes == {}), 'gc-capability-xml')
        else:
            need(len(stack) == 1 and name in allowed and name not in fields
                 and not attributes, 'gc-capability-xml')
            fields[name] = ''
        stack.append(name)

    def characters(text):
        if len(stack) == 2:
            fields[stack[-1]] += text
        else:
            need(all(char in ' \t\r\n' for char in text), 'gc-capability-xml')

    def forbidden(*_args):
        need(False, 'gc-capability-xml')

    def declaration(version, encoding, standalone):
        need(version == '1.0' and encoding in (None, 'UTF-8') and standalone == -1,
             'gc-capability-xml')

    parser.StartElementHandler = start
    parser.EndElementHandler = lambda _name: stack.pop()
    parser.CharacterDataHandler = characters
    parser.XmlDeclHandler = declaration
    parser.StartDoctypeDeclHandler = forbidden
    parser.StartCdataSectionHandler = forbidden
    parser.CommentHandler = forbidden
    parser.ProcessingInstructionHandler = forbidden
    try:
        # Parsing decoded UTF-8 prevents implicit UTF-16 transcoding. A single
        # leading UTF-8 BOM is valid, just as in the declared transport format.
        parser.Parse(raw.decode('utf-8-sig'), True)
    except (UnicodeDecodeError, expat.ExpatError):
        need(False, 'gc-capability-xml')
    return fields


def bucket_query_witness(exchange, backend):
    """GC bucket preflights are GETs with a query, but are never object LISTs."""
    request, response = exchange['request'], exchange['backend']
    url = urlsplit(request['path'])
    need(url.path == '/scap-test' and url.query in ('versioning', 'object-lock'), 'gc-bucket-query-shape')
    need(request['role'] == 'C' and request['access_sha256'] == backend['gc_access_sha256'],
         'dedicated-gc-capability-check')
    if url.query == 'versioning':
        need(response['status'] == 200, 'gc-versioning-status')
        fields = gc_flat_xml(exchange['bytes'], 'VersioningConfiguration', {'Status', 'MFADelete'}, True)
        need(not fields, 'gc-bucket-unversioned')
    else:
        need(response['status'] == 404, 'gc-object-lock-status')
        fields = gc_flat_xml(exchange['bytes'], 'Error',
                             {'Code', 'Message', 'RequestId', 'HostId', 'Resource', 'BucketName', 'Key'}, False)
        need(fields.get('Code') == 'ObjectLockConfigurationNotFoundError', 'gc-object-lock-disabled')


def query_witness(exchange, live, backend):
    query = urlsplit(exchange['request']['path']).query
    if query in ('versioning', 'object-lock'):
        bucket_query_witness(exchange, backend)
    else:
        need(exchange['backend']['status'] == 200, 'actual-list-response')
        list_witness(exchange, live)


def histories(values, backend):
    heads, live, snapshots, owner_records, all_objects = [], {}, {}, {}, {}
    known = {m.scope_key(e.SCOPE)}
    ordered = sorted(values, key=lambda value: e.moment(value['backend']))
    for exchange in ordered:
        request, response = exchange['request'], exchange['backend']
        need(response is not None and exchange['delivered'], 'unmodified-s3-exchange')
        method, path, status = request['method'], request['path'], response['status']
        if method == 'GET':
            if '?' in path:
                query_witness(exchange, live, backend)
            elif status == 200:
                need(path in live and live[path]['bytes'] == exchange['bytes']
                     and live[path]['etag'] == response['headers'].get('etag'), 'actual-exact-read-version')
                exchange['read'] = live[path]
            else:
                need(status == 404 and path not in live, 'actual-missing-version')
            continue
        if method == 'DELETE':
            need('/snapshot/' not in path and '/owner/' not in path, 'permanent-control-metadata-not-deleted')
            need('/objects/' in path and heads and request['access_sha256'] == backend['gc_access_sha256'], 'dedicated-payload-delete')
            current = heads[-1]['head']; batch = current['storage']['sweep']
            entries = [] if batch is None else [item for item in batch['entries'] if '/scap-test/' + item['key'] == path]
            need(len(entries) == 1 and entries[0]['disposition'] == 'pending' and request['headers'].get('if-match') == entries[0]['etag']
                 and m.legacy.retired(current['storage'], batch['generation']), 'original-retired-checkpoint-delete')
            need(path in live and live[path]['etag'] == request['headers']['if-match'] and status in (200, 204), 'exact-original-delete-effect')
            del live[path]
            continue
        need(method == 'PUT', 'original-object-operation')
        if status == 412:
            need(path in live and request['headers'].get('if-none-match') == '*' and '/objects/' in path
                 and live[path]['bytes'] == exchange['payload'], 'only-identical-immutable-create-conflict')
            continue
        need(status == 200 and isinstance(response['headers'].get('etag'), str), 'accepted-object-write')
        stored = {'bytes': exchange['payload'], 'etag': response['headers']['etag'], 'exchange': exchange}
        if path == HEAD_PATH:
            head = m.head(exchange['payload'], known)
            need(head['scope'] == e.SCOPE, 'physical-head-full-scope')
            previous = heads[-1] if heads else None
            if previous is None:
                need(head['head_serial'] == head['revision'] == 1 and request['headers'].get('if-none-match') == '*', 'initial-absent-head')
                kind = 'create'
            else:
                need(request['headers'].get('if-match') == previous['stored']['etag']
                     and request['headers'].get('if-none-match') is None, 'original-head-etag')
                matching = [value for value in values if value['request']['role'] == request['role']
                    and value['request']['path'] == path and value['request']['method'] == 'GET'
                    and value['delivered'] and value['backend']['status'] == 200
                    and value['bytes'] == previous['stored']['bytes'] and value['backend']['headers'].get('etag') == request['headers']['if-match']
                    and e.moment(value['group']['s3_delivery_finished']) < e.moment(request)]
                need(matching, 'same-exact-get-body-etag')
                kind = m.advance(previous['head'], head)
            record = {'head': head, 'kind': kind, 'exchange': exchange, 'stored': stored, 'previous': previous,
                      'live': dict(live)}
            stored['head_record'] = record
            heads.append(record)
        else:
            need(path not in live and request['headers'].get('if-none-match') == '*' and request['headers'].get('if-match') is None,
                 'immutable-original-absent')
            if '/snapshot/v1/' in path:
                _logical, kind, _creator, _operation = m.snapshot_key(path)
                value, item = m.descriptor(exchange['payload'], path) if kind == 'descriptor' else (m.proof(exchange['payload'], path), None)
                snapshots[path] = {**stored, 'kind': kind, 'value': value, 'entry': item}
            elif '/owner/v1/' in path:
                _logical, kind, _creator, _operation = m.legacy.owner_key(path)
                value = m.legacy.descriptor(exchange['payload'], path) if kind == 'descriptor' else m.legacy.proof(exchange['payload'], path)
                owner_records[path] = {**stored, 'kind': kind, 'value': value}
            else:
                m.envelope(exchange['payload'], path)
                all_objects[path] = exchange['payload']
        live[path] = stored
    need(heads and heads[-1]['head']['format'] == 9 and heads[-1]['head']['lifecycle'] == 'deleted'
         and heads[-1]['head']['snapshots'] == [] and 'terminal' in heads[-1]['head']['storage'], 'final-head9-terminal')
    need(not any('/objects/' in path for path in live), 'complete-terminal-payload-reclamation')
    return heads, live, snapshots, owner_records, all_objects


def closures(heads, values):
    result = {}
    for record in heads:
        head = record['head']
        if 'terminal' in head['storage']:
            continue
        objects = {path: value['bytes'] for path, value in record['live'].items() if '/objects/' in path}
        closure = m.Graph(objects, head['scope'], head['storage']['active_generation']).complete(head)
        for path in closure['dependencies']:
            stored = record['live'][path]
            need(e.moment(stored['exchange']['backend']) < e.moment(record['exchange']['request']), 'dependency-durable-before-head')
            readback = [value for value in values.at_path(path) if value['request']['method'] == 'GET' and value['delivered']
                and value['backend']['status'] == 200 and value['bytes'] == stored['bytes']
                and e.moment(value['group']['s3_delivery_finished']) < e.moment(record['exchange']['request'])]
            need(readback, 'immutable-exact-readback-before-head')
        record['closure'] = closure
        result[head['head_serial']] = closure
    return result


def point_public(value):
    return {**value, 'sequence': str(value['sequence']), 'source_revision': str(value['source_revision'])}


def entry_public(value):
    return {'reference': public(value['reference']), 'label': value['label'], 'point': point_public(value['point'])}


def prepared_public(descriptor):
    return {'scope': public(descriptor['value']['scope']), 'input': public(descriptor['value']['input']),
            'reference': public(descriptor['entry']['reference']), 'point': point_public(descriptor['entry']['point'])}


def find_public_head(calls, name, heads):
    value = calls[name]['product_body']['value']
    status = value.get('status', value)
    matching = [record for record in heads if projection(record['head']) == status]
    need(len(matching) == 1, 'public-exact-head-observation')
    return matching[0]


def snapshot_protocol(directory, originals, records, heads, final, calls, values):
    descriptors = {record['value']['input']['operation']: record for record in records.values() if record['kind'] == 'descriptor'}
    proofs = {record['value']['entry']['reference']['operation']: record for record in records.values() if record['kind'] == 'proof'}
    need(set(descriptors) == set(proofs) == {880001, 880002} and len(records) == 4, 'permanent-snapshot-record-denominator')
    need(all(path in final and final[path]['bytes'] == record['bytes'] and final[path]['etag'] == record['etag'] for path, record in records.items()),
         'permanent-snapshot-metadata-survives')
    capture_records = [record for record in heads if record['kind'] == 'snapshot_capture']
    release_records = [record for record in heads if record['kind'] == 'snapshot_release']
    need(len(capture_records) == len(release_records) == 2, 'snapshot-publication-denominator')
    for name, operation, counter in (('point-one', 880001, 2), ('point-two', 880002, 4)):
        record = descriptors[operation]; value, item = record['value'], record['entry']
        need(value['input'] == originals[name]['native'], 'descriptor-original-saved-input')
        matching = [head for head in heads if head['head']['head_serial'] == value['base']['head_serial']]
        need(len(matching) == 1, 'snapshot-original-base-present')
        base = matching[0]
        need(base['stored']['etag'] == value['base']['etag'] and sha(m.canonical_head(base['head'])) == value['base']['head_hash']
             and value['point']['data_root'] == base['head']['data_root'] and value['point']['sequence'] == counter == base['head']['sequence']
             and value['point']['source_revision'] == base['head']['revision'], 'snapshot-original-current-base')
        need(len(base['closure']['image']) == value['point']['page_count'] * 4096, 'snapshot-original-manifest-pages')
        capture = next((head for head in capture_records if item in head['head']['snapshots']), None)
        need(capture is not None and capture['previous'] is base and capture['head']['snapshots'][-1] == item,
             'snapshot-full-reference-accepted')
        need(proofs[operation]['value']['entry'] == item, 'snapshot-permanent-proof-original')
        release = [head for head in release_records if item in head['previous']['head']['snapshots'] and item not in head['head']['snapshots']]
        need(len(release) == 1 and e.moment(proofs[operation]['exchange']['backend']) < e.moment(release[0]['exchange']['request']),
             'release-proof-before-remove')
        proof_reads = [exchange for exchange in values.at_path(BASE + f'snapshot/v1/proof/11/{operation}')
            if exchange['request']['method'] == 'GET' and exchange['delivered'] and exchange['backend']['status'] == 200
            and e.moment(exchange['group']['s3_delivery_finished']) < e.moment(release[0]['exchange']['request'])]
        need(proof_reads, 'release-proof-readback-before-remove')
    need(descriptors[880001]['entry']['point']['page_count'] < descriptors[880002]['entry']['point']['page_count']
         and descriptors[880001]['entry']['point']['data_root'] != descriptors[880002]['entry']['point']['data_root'], 'two-distinct-native-geometries')
    for name, call in calls.items():
        operation = call['body']['operation']
        if not operation.startswith('snapshot_'):
            continue
        value = call['product_body']['value']
        if operation == 'snapshot_prepare':
            record = descriptors[int(call['body']['input']['operation'])]
            need(value == prepared_public(record), 'prepared-original-snapshot')
            continue
        head = find_public_head(calls, name, heads)
        published_here = within(call, head['exchange'])
        authorized_head = head['previous'] if published_here else head
        need(any(exchange.get('read', {}).get('head_record') is authorized_head for exchange in reads(call, values)),
             'fresh-snapshot-head-observation')
        if operation in ('snapshot_list', 'snapshot_limits'):
            expected = {'status': projection(head['head']), 'snapshots': [entry_public(item) for item in head['head']['snapshots']],
                        'limits': {'max_points': 2, 'max_logical_bytes': '4194304'}}
            need(value == expected, 'exact-bounded-snapshot-list')
            continue
        original = call['command']['intent']; descriptor = descriptors[originals[original]['native']['operation']]
        item = descriptor['entry']
        need(value['prepared']['scope'] == public(descriptor['value']['scope']), 'snapshot-observation-full-scope')
        need(value['prepared'] == prepared_public(descriptor) and value['accepted'] == entry_public(item), 'original-snapshot-observation-reference')
        retained = item in head['head']['snapshots']
        need(value['state'] == ('retained' if retained else 'released_observed'), 'snapshot-observation-history')
        if not retained:
            need(head['head']['head_serial'] > item['reference']['capture_serial'] and
                 any(exchange['request']['path'] == BASE + f'snapshot/v1/proof/11/{item["reference"]["operation"]}'
                     for exchange in reads(call, values)), 'released-observed-permanent-proof')
        if operation in ('snapshot_capture', 'snapshot_release'):
            need(call['body']['reference'] == public(item['reference']), 'original-snapshot-mutation-reference')
            mutations = [record for record in heads if within(call, record['exchange'])]
            need(len(mutations) == 1 and mutations[0]['kind'] == operation, 'one-original-snapshot-cas')
            previous = mutations[0]['previous']['head']
            need(any(permission['principal'] == 11 and permission['admin'] and
                 (operation != 'snapshot_capture' or permission['read']) for permission in previous['policy']), 'fresh-snapshot-permission')
    return descriptors


def original_sql(directory, events, inputs, originals, calls, heads):
    acks = {}
    child_inputs = [wire.parse(e.raw(directory, row['raw'])) for row in e.selection(events, 'child_input', id='native-seed')]
    child_outputs = [wire.parse(e.raw(directory, row['raw'])) for row in e.selection(events, 'child_output', id='native-seed')]
    need(len(child_inputs) == 6 and len(child_outputs) == 7 and child_outputs[0]['ready'] is True, 'native-original-command-denominator')
    need([row['op'] for row in child_inputs] == ['create', 'activate_session', 'session_execute', 'session_execute', 'status', 'session_close'],
         'native-original-command-sequence')
    for number in range(1, 7):
        name = f'original-{number}'
        if number <= 2:
            command, answer = child_inputs[number + 1], child_outputs[number + 2]
            need(answer['ok'] is True and command['epoch'] == 1 and command['id'] == number and command['statements'] ==
                 [{'sql': item['sql'], 'parameters': []} for item in inputs['specs'][number - 1]['statements']], 'native-original-sql-bytes')
            receipt, data = public(answer['value']['receipt']), bytes(answer['value']['result']['encoded'])
            acknowledgement = e.one(events, 'native_original_ack', name=name)
        else:
            call = calls['execute-' + name]
            value = call['response_body']['value']
            data, _decoded = wire.committed(value)
            receipt = value['receipt']
            acknowledgement = e.one(events, 'original_ack', name=name)
        need(receipt['scope'] == e.PUBLIC_SCOPE and receipt['request'] == originals[name]['decoded']['request']
             and receipt['sequence'] == str(number) and wire.receipt_hash(receipt, data) == receipt['result_hash'], 'original-ack-receipt-identity')
        need(public(acknowledgement['receipt']) == receipt and e.raw(directory, acknowledgement['result']) == data, 'original-result-bytes')
        statements = wire.result(data)
        rows = statements[-1]['rows']
        need(statements[-1]['columns'] == ['counter', 'payload', 'nonce'] and len(rows) == 1 and rows[0][0] == number
             and type(rows[0][2]) is int and type(rows[0][1]) is bytes and len(rows[0][1]) == (64 if number <= 2 else 196608),
             'original-random-blob-return')
        published = [record for record in heads if record['head']['revision'] == int(receipt['transition']['revision'])
                     and record['head']['data_root'] == receipt['data_root'] and record['head']['sequence'] == number]
        need(published and e.moment(published[0]['exchange']['backend']) < e.moment(acknowledgement), 'original-ack-after-publication')
        acks[name] = {'receipt': receipt, 'raw': data, 'row': rows[0]}
    need(len(e.selection(events, 'native_original_ack')) == 2 and len(e.selection(events, 'original_ack')) == 4, 'six-original-ack-denominator')
    for name, original in acks.items():
        value = calls['cold-lookup-' + name]['response_body']['value']
        need(value['state'] == 'committed' and value['receipt'] == original['receipt'] and wire.b64(value['result']) == original['raw'],
             'cold-original-result-exact')
        marker = e.one(events, 'cold_original_recovered', name=name)
        need(marker['receipt'] == original['receipt'] and e.raw(directory, marker['result']) == original['raw'], 'cold-original-result-marker')
    need(len(e.selection(events, 'cold_original_recovered')) == 6, 'cold-six-original-denominator')
    snapshot = e.wire.parse((directory / 'original-results.json').read_bytes())
    need(set(snapshot) == set(acks) and all(public(snapshot[name]['receipt']) == value['receipt'] and
         e.raw(directory, snapshot[name]['result']) == value['raw'] for name, value in acks.items()), 'saved-original-ack-ledger')
    current = wire.result(wire.b64(calls['cold-current-query']['response_body']['value']['result']))
    need(current[0]['rows'] == [acks['original-6']['row'][:2]], 'cold-business-from-original-ack')
    return acks


def image_witness(image, expected):
    # SCAP's complete canonical page image can retain SQLite's WAL-mode header.
    # A :memory: deserialize tries opening a WAL. An immutable read-only copy
    # reads those already verified pages without changing header or data bytes.
    with tempfile.TemporaryDirectory(prefix='scap-snapshot-audit-') as directory:
        path = Path(directory) / 'image.sqlite'
        path.write_bytes(image)
        path.chmod(0o400)
        database = sqlite3.connect(path.as_uri() + '?mode=ro&immutable=1', uri=True)
        try:
            need(database.execute('PRAGMA integrity_check').fetchall() == [('ok',)], 'native-image-integrity')
            need(database.execute('SELECT counter,payload FROM witness WHERE id=1').fetchall() == [tuple(expected[:2])],
                 'retained-business-from-original-ack')
        finally:
            database.close()
        need(path.read_bytes() == image and list(Path(directory).iterdir()) == [path], 'native-audit-copy-unchanged')


def copy_and_cold(heads, calls, values, originals, owner_records, acks):
    for kind in ('begin', 'copy_seal', 'promote', 'terminal'):
        need(sum(record['kind'] == kind for record in heads) == 1, 'one-' + kind)
    begin = next(record for record in heads if record['kind'] == 'begin')
    basis = begin['head']['storage']['plan']['basis']
    need(basis['snapshots'] == begin['previous']['head']['snapshots'] and len(basis['snapshots']) == 2
         and basis['snapshot_limits'] == begin['previous']['head']['snapshot_limits'], 'copy-frozen-held-basis')
    sealed = next(record for record in heads if record['kind'] == 'copy_seal')
    objects = {path: stored['bytes'] for path, stored in sealed['live'].items() if '/objects/' in path}
    source = m.Graph(objects, e.SCOPE, 1).complete(basis)
    target = m.Graph(objects, e.SCOPE, 2).complete(basis)
    need({path.replace('/storage/1/', '/storage/2/') for path in source['dependencies']} == target['dependencies'], 'copy-all-held-and-result-closures')
    for path in source['dependencies']:
        copied = path.replace('/storage/1/', '/storage/2/')
        need(objects[path] == objects[copied], 'copy-exact-immutable-bytes')
        need(any(value['request']['path'] == copied for value in reads(calls['copy-seal'], values)), 'copy-exact-target-readback')
    need(len(source['held']) == 2 and len(source['results']) == 6 and len(basis['windows']) == 3, 'copy-three-windows-two-held-roots')
    image_witness(target['image'], acks['original-6']['row'])
    for retained, image, _dependencies in target['held']:
        number = 2 if retained['reference']['operation'] == 880001 else 4
        image_witness(image, acks[f'original-{number}']['row'])
    cold = calls['bulk-p2-resume']
    need(cold['front'] == 'C-9503' and cold['product_body']['value']['state'] == 'active', 'cold-new-owner-active')
    active = find_public_head(calls, 'bulk-p2-resume', heads)
    need(active['head']['active'] and active['head']['owner_instance'] == 9503
         and active['head']['storage']['active_generation'] == 2, 'cold-only-current-physical-generation')
    observed = {value['request']['path'] for value in reads(cold, values)}
    need(active['closure']['dependencies'] <= observed, 'cold-complete-held-recovery')
    need(not any('/storage/1/objects/' in value['request']['path'] for value in reads(cold, values)), 'cold-never-falls-back-retired-generation')
    for request, (_digest, result, data) in active['closure']['results'].items():
        number = (request[0] - 1) * 2 + request[1]
        original = acks[f'original-{number}']
        need(data == original['raw'] and result['request'] == e.native(original['receipt']['request']), 'cold-retained-result-closure-original')
    need(Counter(record['kind'] for record in owner_records.values()) == {'descriptor': 2, 'proof': 1}, 'two-owner-original-descriptors')
    for name in ('bulk-p1', 'bulk-p2'):
        saved = originals[name]['native']
        descriptors = [value for value in owner_records.values() if value['kind'] == 'descriptor' and value['value']['input'] == saved]
        need(len(descriptors) == 1, 'owner-saved-original-descriptor')
        descriptor = descriptors[0]['value']
        bases = [record for record in heads if record['head']['head_serial'] == descriptor['base']['head_serial']]
        need(len(bases) == 1 and bases[0]['stored']['etag'] == descriptor['base']['etag']
             and sha(m.canonical_head(bases[0]['head'])) == descriptor['base']['head_hash'], 'owner-full-head9-base-hash')
        reference = m.legacy.reference(descriptor)
        for method, phase in (('claim', 'claimed'), ('resume', 'active')):
            call = calls[name + '-' + method]
            need(call['body']['plan'] == public(reference) and call['product_body']['value']['state'] == phase, 'owner-original-full-reference')
            record = find_public_head(calls, name + '-' + method, heads)
            need(record['head']['owner_plan']['reference'] == reference, 'owner-accepted-original-plan')


def gc_page_chain(events, calls):
    pages = []
    cold = e.one(events, 'scenario_phase', label='all-compute-cache-loss')
    for label, generation in (('retired-one', '1'), ('terminal-two', '2')):
        start = e.one(events, 'sweep_round_started', label=label)
        end = e.one(events, 'sweep_round_finished', label=label)
        need(start['generation'] == int(generation) and start['after'] is None and e.moment(start) < e.moment(end),
             'fixed-sweep-round-origin')
        observed = e.selection(events, 'sweep_page_finished', label=label)
        need(type(end['pages']) is int and 1 <= end['pages'] <= 32 and
             [row['page'] for row in observed] == list(range(end['pages'])), 'complete-sweep-page-denominator')
        after = None
        previous = start
        for page, event in enumerate(observed):
            identifier = f'{label}-{page}'
            status, prepare, resume = (calls[identifier + suffix] for suffix in ('-storage', '-prepare', '-resume'))
            before = status['product_body']['value']
            request = prepare['body']
            report, completed = prepare['product_body']['value'], resume['product_body']['value']
            need(request['generation'] == report['generation'] == completed['generation'] == generation,
                 'fixed-sweep-generation')
            need(request['after'] == after and request['expected_head_serial'] == before['head_serial'], 'original-exclusive-sweep-frontier')
            need(type(report['scanned']) is int and 1 <= report['scanned'] <= 32 and completed['scanned'] == report['scanned'],
                 'complete-sweep-scan-count')
            exhausted = page == end['pages'] - 1
            need(report['exhausted'] is exhausted and completed['exhausted'] is exhausted, 'terminal-sweep-exhausted')
            if exhausted:
                need(report['next_after'] is None, 'terminal-sweep-null-frontier')
            else:
                m.digest(report['next_after'])
                need(after is None or after < report['next_after'], 'strict-increasing-sweep-frontier')
            need(completed['next_after'] == report['next_after'], 'resume-original-sweep-frontier')
            batch = report['status']['storage']['sweep']
            need(batch is not None and batch['serial'] == report['status']['head_serial']
                 and int(batch['serial']) == int(before['head_serial']) + 1
                 and batch['generation'] == generation and batch['next_after'] == report['next_after']
                 and batch['exhausted'] is exhausted and resume['body']['batch_serial'] == batch['serial']
                 and completed['status']['storage']['sweep'] is None
                 and int(completed['status']['head_serial']) > int(batch['serial']), 'original-sweep-checkpoint-chain')
            need(event['report'] == report, 'sweep-marker-original-product-report')
            need(e.moment(previous) < e.moment(status['proxy']['forward_started'])
                 < e.moment(status['proxy']['backend_response']) < e.moment(prepare['proxy']['forward_started'])
                 < e.moment(prepare['proxy']['backend_response']) < e.moment(resume['proxy']['forward_started'])
                 < e.moment(resume['proxy']['backend_response']) < e.moment(event) < e.moment(end), 'sweep-owned-page-order')
            pages.append((label, page, generation, prepare, resume, report))
            after, previous = report['next_after'], event
        if generation == '1':
            need(e.moment(end) < e.moment(cold), 'retired-generation-finished-before-compute-loss')
    return pages


def gc_protocol(events, calls, heads, values, backend):
    pages = gc_page_chain(events, calls)
    for label, page, generation, prepare, resume, report in pages:
        identifier = f'{label}-{page}'
        before = find_public_head(calls, identifier + '-storage', heads)
        prepared = find_public_head(calls, identifier + '-prepare', heads)
        completed = find_public_head(calls, identifier + '-resume', heads)
        batch = prepared['head']['storage']['sweep']
        need(m.legacy.retired(before['head']['storage'], int(generation)), 'gc-original-generation-retired')
        # Only list_witness can add this key after validating the original
        # ListObjectsV2 request and complete 32-key page. Versioning preflights
        # also return 200 but must not inflate the list-page denominator.
        listed = [value for value in reads(prepare, values) if 'listed' in value]
        # The daemon supplies Listings from its ordinary S3 handle. A listing
        # is only candidate discovery; the typed GETs below and every DELETE
        # must still use the separately configured GC identity.
        need(len(listed) == 1 and listed[0]['request']['access_sha256'] == backend['normal_access_sha256'],
             'one-original-candidate-list-page')
        query = parse_qs(urlsplit(listed[0]['request']['path']).query)
        prefix = m.prefix(e.SCOPE, int(generation)).removeprefix('/scap-test/')
        expected_after = [] if prepare['body']['after'] is None else [prefix + prepare['body']['after']]
        need(query.get('prefix') == [prefix] and query.get('start-after', []) == expected_after, 'original-list-exclusive-frontier')
        keys = listed[0]['listed']
        need(len(keys) == report['scanned'] and keys == ['/scap-test/' + item['key'] for item in batch['entries']],
             'complete-listed-checkpoint-entries')
        for item in batch['entries']:
            exact = [value for value in reads(prepare, values) if value['request']['path'] == '/scap-test/' + item['key']
                     and value['request']['access_sha256'] == backend['gc_access_sha256']
                     and value['backend']['headers'].get('etag') == item['etag']]
            need(exact, 'dedicated-exact-gc-get-before-checkpoint')
        if report['exhausted']:
            need(not any(path.startswith(m.prefix(e.SCOPE, int(generation))) for path in completed['live']), 'complete-retired-round-absence')


def audit(directory):
    directory = Path(directory)
    inputs = wire.parse((directory / 'inputs.json').read_bytes())
    events = e.rows(directory / 'events.jsonl')
    need([row['sequence'] for row in events] == list(range(1, len(events) + 1)) and
         all(e.moment(a) <= e.moment(b) for a, b in zip(events, events[1:])), 'event-ledger-order')
    e.identity(directory, inputs, events, 'experiments/object-snapshot-runtime/PLAN.md')
    backend, configurations = e.processes(directory, inputs, events)
    originals, owners, snapshots = e.originals(directory, inputs)
    calls, local = e.sdk(directory, inputs, events, configurations, originals, owners, snapshots)
    e.http_exchanges(directory, events, calls, expected_count=3)
    fixed_calls(events, calls)
    values = e.s3_exchanges(directory, events, backend)
    heads, final, records, owner_records, _objects = histories(values, backend)
    closures(heads, values)
    snapshot_protocol(directory, snapshots, records, heads, final, calls, values)
    acks = original_sql(directory, events, inputs, originals, calls, heads)
    copy_and_cold(heads, calls, values, owners, owner_records, acks)
    gc_protocol(events, calls, heads, values, backend)
    summary = wire.parse((directory / 'summary.json').read_bytes())
    need(summary['status'] == 'OBSERVED_NOT_AUDITED' and summary['private_removed'] is True
         and summary['cleanup_errors'] == [] and summary['error'] is None and 0 < summary['elapsed_seconds'] < 600,
         'successful-bounded-observation-cleanup')
    return {'schema': 1, 'status': 'PASSED', 'profile': 'head9-s1-native-http-signed-s3-v1',
            'fixture_source_commit': inputs['commit'], 'runtime_source_commit': inputs['runtime_source_commit'],
            'http_posts': len(calls), 's3_requests': len(values), 'sql_original_acks': 6, 'cold_original_lookups': 6,
            'snapshot_descriptors': 2, 'snapshot_proofs': 2, 'held_roots_in_copy_and_cold_recovery': 2,
            'original_unknowns': 2, 'sweep_rounds': 2, 'owned_wait4': 13,
            'oracle_python_sqlite': sqlite3.sqlite_version, 'aws_standard': 'NOT_RUN', 'production_slo': 'NOT_RUN', 'restore_s2': 'NOT_RUN',
            'source_sha256': {name: sha((directory / name).read_bytes()) for name in
                ('inputs.json', 'events.jsonl', 'intents.json', 'owner-inputs.jsonl', 'snapshot-inputs.jsonl', 'original-results.json')}}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    print(json.dumps(audit(parser.parse_args().evidence), sort_keys=True))
