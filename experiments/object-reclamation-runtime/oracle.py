#!/usr/bin/env python3
"""Audit raw inputs, native ACKs, HTTP/S3 intervals and durable HEAD6 changes.

This oracle never calls the runner, product decoder, SDK, or legacy S3 mutation
verdict. Complete retained graphs and GC authorizations are reconstructed here.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import tarfile
from urllib.parse import parse_qs, urlsplit
import xml.etree.ElementTree as ET

from audit_model import (BASIS, Graph, Rejected, advance, digest, envelope, head,
                         head_path, need, object_path, prefix, retired, scope, sha, wire)


def rows(path):
    need(path.is_file(), 'ledger-missing')
    raw = path.read_bytes()
    need(raw and raw.endswith(b'\n'), 'ledger-framing')
    return [wire.parse(line) for line in raw.splitlines()]


def raw(directory, description):
    need(set(description) == {'file', 'bytes', 'sha256'}, 'raw-description')
    name = digest(description['sha256'])
    need(description['file'] == 'raw/' + name, 'raw-path')
    path = directory / 'raw' / name
    need(path.is_file() and not path.is_symlink() and type(description['bytes']) is int
         and 0 <= description['bytes'] <= 67108864, 'raw-file')
    value = path.read_bytes()
    need(len(value) == description['bytes'] and sha(value) == name, 'raw-integrity')
    return value


def moment(row):
    value = row['monotonic_ns']
    need(type(value) is int or isinstance(value, str) and value.isdecimal(), 'observation-time')
    return int(value)


def selection(rows_value, event, **fields):
    return [row for row in rows_value if row['event'] == event and
            all(row.get(name) == value for name, value in fields.items())]


def one(rows_value, event, **fields):
    result = selection(rows_value, event, **fields)
    need(len(result) == 1, 'one-' + event)
    return result[0]


def archive(path, expected):
    with tarfile.open(path) as file:
        members = file.getmembers()
        need(len(members) == len(expected) and len({m.name for m in members}) == len(members), 'archive-denominator')
        for member in members:
            need(member.isfile() and member.name in expected, 'archive-member')
            data = file.extractfile(member).read()
            need(sha(data) == expected[member.name], 'archive-source-bytes')


def identity(directory, inputs, events):
    source = wire.parse((directory / 'source.json').read_bytes())
    files = source['files']
    need(source['commit'] == inputs['commit'] and source['source_sha256'] == inputs['source_sha256']
         and sha(json.dumps(files, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode()) == source['source_sha256'], 'source-identity')
    need(sha((directory / 'source.tar').read_bytes()) == inputs['source_archive_sha256'], 'source-archive')
    expected = {row['path']: row['sha256'] for row in files}
    need(len(expected) == len(files), 'source-duplicate')
    archive(directory / 'source.tar', expected)
    with tarfile.open(directory / 'source.tar') as file:
        for row in files:
            data = file.extractfile(row['path']).read()
            need(len(data) == row['bytes'] and hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == row['git_blob'], 'committed-source-bytes')
    need(inputs['plan_sha256'] == expected['experiments/object-reclamation-runtime/PLAN.md'], 'frozen-plan')
    receipts = {}
    for name, tool, stdout_key, stderr_key in (
            ('service-build', 'scapd', 'cargo.stdout.jsonl_sha256', 'cargo.stderr.log_sha256'),
            ('seed-build', 'native-seed', 'build_stdout_sha256', 'build_stderr_sha256')):
        root = directory / name
        receipt = wire.parse((root / 'build-receipt.json').read_bytes())
        need(receipt['status'] == 'passed' and receipt['exit_code'] == 0 and receipt['profile'] == 'release'
             and receipt['source_commit'] == inputs['runtime_source_commit'], 'original-release-build')
        need(receipt['binary'] == inputs['tools'][tool] and all(expected.get(k) == v for k, v in receipt['inputs'].items()), 'release-source-binding')
        need(Path(receipt['binary']['path']).is_file() and sha(Path(receipt['binary']['path']).read_bytes()) == receipt['binary']['sha256'], 'actual-native-binary')
        need(receipt['native_archives'], 'native-archive-required')
        for path, digest_value in receipt['native_archives'].items():
            need(Path(path).is_file() and sha(Path(path).read_bytes()) == digest_value, 'actual-native-archive')
        archived = receipt['archived_evidence']
        for key, hash_key in (('source_archive', 'source_archive_sha256'), ('source_manifest', 'source_manifest_sha256')):
            need(sha((root / archived[key]).read_bytes()) == archived[hash_key], 'release-archive')
        archive(root / archived['source_archive'], receipt['inputs'])
        need(sha((root / 'build-cargo.stdout.jsonl').read_bytes()) == receipt[stdout_key]
             and sha((root / 'build-cargo.stderr.log').read_bytes()) == receipt[stderr_key], 'original-cargo-log')
        cargo = rows(root / 'build-cargo.stdout.jsonl')
        need(cargo[-1].get('reason') == 'build-finished' and cargo[-1].get('success') is True, 'cargo-finished')
        artifacts = [row for row in cargo if row.get('reason') == 'compiler-artifact'
                     and row.get('executable') == receipt['binary']['path']]
        need(artifacts and artifacts[-1]['profile']['opt_level'] == '3', 'original-release-artifact')
        receipts[name] = receipt
    verified = one(events, 'source_verified')
    need(verified['commit'] == source['commit'] and verified['source_sha256'] == source['source_sha256'], 'source-after')
    return receipts


def process_audit(directory, inputs, events):
    starts = {r['id']: r for r in selection(events, 'child_started')}
    stops = {r['id']: r for r in selection(events, 'child_stopped')}
    need(len(starts) == len(selection(events, 'child_started')) and set(starts) == set(stops)
         and len(stops) == len(selection(events, 'child_stopped')), 'owned-child-denominator')
    identities = set()
    for name, start in starts.items():
        stop = stops[name]
        identity_value = start['identity']
        need(identity_value == stop['identity'] and identity_value['pid_source'] == 'owned_Popen_child'
             and moment(start) < moment(stop), 'owned-child-identity')
        key = (identity_value['pid'], identity_value['spawn_monotonic_ns'])
        need(key not in identities, 'child-incarnation-reused')
        identities.add(key)
        need(stop['forced'] is False and stop['status'] == (-9 if stop['crash'] else 0)
             and stop['usage'].get('source') == 'kernel_wait4_owned_child'
             and stop['usage'].get('available') is True, 'owned-wait4')
        raw(directory, stop['stderr'])
        tool = ('scapd' if name.startswith('service-') else 'native-seed' if name.startswith('seed-')
                else 'node' if name.startswith('sdk-') or name == 'node-version' else 'weed')
        need(start['executable_sha256'] == inputs['tools'][tool]['sha256']
             and start['command'][0] == inputs['tools'][tool]['path'], 'owned-executable')
    services = [name for name in starts if name.startswith('service-')]
    need(len(services) == 7 and len([n for n in starts if n.startswith('seed-')]) == 3
         and len([n for n in starts if n.startswith('sdk-')]) == 3, 'process-profile')
    ready = selection(events, 'service_ready')
    need(len(ready) == len(services) and len({r['worker'] for r in ready}) == len(services), 'worker-instance-reuse')
    for row in ready:
        configuration = wire.parse((directory / (row['id'] + '.json')).read_bytes())
        need(configuration['worker_instance'] == row['worker'] and configuration['s3']['timeout_ms'] == 120000
             and configuration['admission']['timeout_ms'] == 120000
             and configuration['admission']['recovery_timeout_ms'] == 300000, 'original-service-config')
        need((configuration['gc'] is not None) == (row['role'] == 'B'), 'gc-opt-in')
        if row['role'] == 'B':
            need(configuration['gc']['deployment'] == '1'
                 and configuration['gc']['access_key_env'] != configuration['s3']['access_key_env']
                 and configuration['gc']['secret_key_env'] != configuration['s3']['secret_key_env'], 'gc-distinct-capability')
    backend_start, backend_stop = one(events, 'backend_started'), one(events, 'backend_stopped')
    need(len(backend_start['identities']) == len(backend_stop['processes']) == 4, 'backend-process-denominator')
    for start, stop in zip(backend_start['identities'], backend_stop['processes']):
        need(all(stop.get(k) == v for k, v in start.items()) and stop['wait_status'] == -9
             and stop['kernel_usage'].get('source') == 'kernel_wait4_owned_child', 'backend-owned-wait4')
    need(backend_start['normal_access_sha256'] != backend_start['gc_access_sha256'], 'gc-distinct-principal')
    need(one(events, 'unsigned_probe')['status'] == 403, 'backend-authentication')
    proxies = selection(events, 's3_proxy_stopped')
    need({r['role'] for r in proxies} == {'seed', 'A', 'B', 'R'} and len(proxies) == 4
         and all(r['joined'] is True and r['errors'] == [] for r in proxies), 'owned-proxy-cleanup')
    need(one(events, 'cleanup_finished')['errors'] == [], 'cleanup-errors')
    cold = one(events, 'scenario_phase', label='all-compute-cache-loss')
    removals = selection(events, 'cache_removed')
    need(len(removals) == 6 and all(r['existed'] and r['absent'] for r in removals), 'actual-cache-loss')
    final_starts = [r for r in ready if moment(r) > moment(cold)]
    need(len(final_starts) == 1 and final_starts[0]['role'] == 'B', 'cold-new-process')
    for role in ('A', 'B', 'R'):
        removed = [r for r in removals if r['role'] == role and moment(r) > moment(cold)]
        need(len(removed) == 1 and moment(removed[0]) < moment(final_starts[0]), 'complete-compute-loss-before-recovery')
    return backend_start, {'services': 7, 'native_seed': 3, 'sdk': 3, 'tool_versions': 2,
                           'backend': 4, 'owned_wait4': len(stops) + 4, 'cache_losses': len(removals)}


def original_inputs(directory, inputs, events):
    specifications = inputs['specs']
    expected_names = {f'main-{i:03d}' for i in range(1, 261)} | {'fence-001', 'fence-002', 'aborted-001', 'aborted-002',
                       'main-cancel', 'main-late-put', 'fence-old-cas'}
    need(len(specifications) == 267 and {s['name'] for s in specifications} == expected_names, 'original-input-denominator')
    by_name = {s['name']: s for s in specifications}
    intents = wire.parse((directory / 'intents.json').read_bytes())
    need(set(intents) == expected_names, 'saved-intent-denominator')
    for name, record in intents.items():
        value = wire.parse(record['serialized'])
        spec = by_name[name]
        database = {'main': 4101, 'fence': 4102, 'aborted': 4103}[spec['scope_name']]
        need(value['scope'] == {k: str(v) for k, v in scope(database).items()}
             and value['statements'] == spec['statements']
             and value['request'] == {'epoch': spec['epoch'], 'id': spec['request_id'], 'principal': '11',
                                      'fingerprint': wire.fingerprint(spec['statements'])}, 'original-request-fingerprint')
        record['decoded'] = value
    return by_name, intents


def sdk_audit(directory, inputs, events, intents):
    calls = {}
    for role in ('A', 'B', 'R'):
        ledger = rows(directory / ('sdk-' + role + '.jsonl'))
        need([r['sequence'] for r in ledger] == list(range(1, len(ledger) + 1))
             and all(moment(a) <= moment(b) for a, b in zip(ledger, ledger[1:])), 'sdk-ledger-order')
        for start in selection(ledger, 'command_started'):
            name = start['command']
            need(name not in calls, 'duplicate-sdk-command')
            command = wire.parse(raw(directory, start['input']))
            done = one(ledger, 'command_finished', command=name)
            need(moment(start) < moment(done), 'sdk-call-order')
            child_inputs = [r for r in selection(events, 'child_input', id='sdk-' + role)
                            if wire.parse(raw(directory, r['raw'])).get('id') == name]
            need(len(child_inputs) == 1 and wire.parse(raw(directory, child_inputs[0]['raw'])) == command, 'original-child-sdk-input')
            child_outputs = [r for r in selection(events, 'child_output', id='sdk-' + role)
                             if wire.parse(raw(directory, r['raw'])).get('id') == name]
            need(len(child_outputs) == 1 and wire.parse(raw(directory, child_outputs[0]['raw'])) == done['result'], 'original-child-sdk-output')
            requests = selection(ledger, 'http_request', command=name)
            responses = selection(ledger, 'http_response', command=name)
            errors = selection(ledger, 'http_error', command=name)
            if command['operation'] == 'prepare':
                need(name == 'prepare-inputs' and not requests and done['attempts'] == 0, 'prepare-no-dispatch')
                prepared = one(ledger, 'intents_prepared')
                need(raw(directory, prepared['original']) == (directory / 'intents.json').read_bytes()
                     and moment(prepared) < moment(selection(events, 'seed_ack')[0]), 'original-intents-before-execution')
                continue
            need(len(requests) == done['attempts'] == 1, 'single-post-no-replay')
            request = requests[0]
            need(request['method'] == 'POST' and request['ordinal'] == 1
                 and len(responses) + len(errors) == 1, 'http-original-attempt')
            body = wire.parse(raw(directory, request['request']))
            configuration = wire.parse((directory / ('service-' + role + '-1.json')).read_bytes())
            need(request['token_sha256'] == configuration['credentials'][0]['sha256'], 'http-original-credential')
            operation = command['operation']
            wire_operation = 'policy' if operation == 'policy' else operation
            need(body['version'] == 1 and body['operation'] == wire_operation
                 and body['scope'] == inputs['scopes'][command['scope_name']], 'http-original-operation')
            if operation in ('execute', 'lookup', 'cancel'):
                original = intents[command['intent']]['decoded']
                need(body['request'] == original['request'], 'http-original-request')
                if operation == 'execute':
                    need(body['statements'] == original['statements'], 'sql-input-changed')
            if operation in ('gc_prepare', 'gc_resume', 'compact_copy'):
                need(request['headers'].get('x-scap-admission') == 'recovery', 'maintenance-recovery-lane')
            mappings = {'compact_begin': {'expectedHeadSerial': 'expected_head_serial'},
                        'compact_copy': {'planSerial': 'plan_serial'},
                        'compact_promote': {'planSerial': 'plan_serial'},
                        'compact_abort': {'planSerial': 'plan_serial'},
                        'gc_prepare': {'expectedHeadSerial': 'expected_head_serial', 'generation': 'generation', 'after': 'after'},
                        'gc_resume': {'batchSerial': 'batch_serial'}}
            if operation in mappings:
                need(all(command['input'][key] == body[value] for key, value in mappings[operation].items()),
                     'original-maintenance-input')
            entry = {'role': role, 'command': command, 'start': start, 'done': done,
                     'request': request, 'body': body, 'response': None, 'result': done['result']}
            if responses:
                response = responses[0]
                need(response['complete'] is True and moment(request) < moment(response), 'http-complete-response')
                body_value = wire.parse(raw(directory, response['response']))
                need(body_value['ok'] == done['result']['ok'], 'sdk-response-knowledge')
                if body_value['ok']:
                    need(response['status'] == 200, 'http-success-status')
                    if operation not in ('query', 'execute', 'lookup', 'cancel'):
                        need(done['result']['value'] == body_value['value'], 'sdk-exact-status-result')
                else:
                    need(done['result']['error']['code'] == body_value['error']['code'], 'sdk-error-code')
                entry.update(response=response, response_body=body_value)
            else:
                need(done['result']['ok'] is False and done['result']['error']['code'] == 'UNKNOWN', 'original-unknown-knowledge')
            calls[name] = entry
    needed = {'main-old-reader', 'main-late-put-execute', 'fence-old-execute', 'fence-delete-original',
              'fence-delete-restart-resume', 'aborted-delete-unknown', 'aborted-old-batch-resume',
              'aborted-bucket-unknown', 'aborted-new-batch-resume', 'aborted-old-batch-conflict'}
    need(needed <= set(calls), 'required-fault-invocations')
    executions = {name for name, call in calls.items() if call['body']['operation'] == 'execute'}
    need(executions == {'main-late-put-execute', 'fence-old-execute'}, 'business-sql-not-replayed')
    for name in executions | {'fence-delete-original', 'aborted-delete-unknown', 'aborted-bucket-unknown'}:
        call = calls[name]
        need(call['result']['ok'] is False and call['result']['error']['code'] == 'UNKNOWN', 'original-unknown-knowledge')
        expected = {'scope': call['body']['scope'], 'operation': call['body']['operation']}
        if call['body']['operation'] == 'execute':
            expected['request'] = call['body']['request']
        else:
            expected['batchSerial'] = call['body']['batch_serial']
        need(call['result']['error']['reference'] == expected, 'original-unknown-reference')
    need(calls['main-old-reader']['result']['error']['code'] == 'SNAPSHOT_EXPIRED', 'old-reader-expired')
    need(moment(calls['main-old-reader']['done']) - moment(calls['main-old-reader']['start']) < 30_000_000_000,
         'old-reader-observation-bound')
    return calls


def request_call(request, calls):
    database = head_path(urlsplit(request['path']).path)
    if database is None and '/objects/' in urlsplit(request['path']).path:
        database = object_path(urlsplit(request['path']).path)[0]
    if request['role'] == 'seed':
        return None
    candidates = [call for call in calls.values() if call['role'] == request['role']
                  and moment(call['request']) < moment(request)
                  and (database is None or int(call['body']['scope']['database']) == database)]
    need(candidates, 's3-without-original-call')
    return max(candidates, key=lambda value: moment(value['request']))


def exchange_integrity(groups, final_counts):
    by_role = defaultdict(set)
    for (role, serial), group in groups.items():
        need(type(serial) is int and serial > 0, 'original-s3-request-denominator')
        by_role[role].add(serial)
        need('s3_request' in group, 's3-complete-lifecycle')
        request = group['s3_request']
        need(all(row.get('method') == request['method'] and row.get('path') == request['path']
                 for row in group.values()), 's3-stage-original-method-path')
    need(set(by_role) <= set(final_counts), 'original-s3-request-denominator')
    for role, count in final_counts.items():
        need(type(count) is int and count >= 0 and sorted(by_role.get(role, set())) == list(range(1, count + 1)),
             'original-s3-request-denominator')


def payload_integrity(request, payload):
    need(int(request['headers'].get('content-length', '0')) == len(payload), 's3-request-length')
    need(request['headers'].get('x-amz-content-sha256') in ('UNSIGNED-PAYLOAD', sha(payload)),
         'public-signed-payload-hash')


def s3_audit(directory, events, calls, backend):
    groups = defaultdict(dict)
    kinds = ('s3_request', 's3_forward_started', 's3_backend_response', 's3_delivery_started', 's3_delivery_finished', 's3_handler_started', 's3_handler_finished')
    for event in events:
        if event['event'] not in kinds:
            continue
        key = (event['role'], event['serial'])
        need(event['event'] not in groups[key], 's3-duplicate-stage')
        groups[key][event['event']] = event
    exchange_integrity(groups, {row['role']: row['request_count'] for row in selection(events, 's3_proxy_stopped')})
    exchanges = []
    for key, group in groups.items():
        need(all(stage in group for stage in ('s3_request', 's3_handler_started', 's3_handler_finished')), 's3-complete-lifecycle')
        request = group['s3_request']
        need(request['signature_valid'] is True and request['access_sha256'] in
             (backend['normal_access_sha256'], backend['gc_access_sha256']), 'actual-signed-request')
        need(moment(group['s3_handler_started']) <= moment(request) < moment(group['s3_handler_finished']), 's3-handler-order')
        payload = raw(directory, request['request'])
        payload_integrity(request, payload)
        call = request_call(request, calls)
        exchange = {'request': request, 'payload': payload, 'call': call, 'group': group,
                    'backend': group.get('s3_backend_response'), 'delivered': False}
        for stage in ('s3_backend_response', 's3_delivery_started'):
            if stage in group:
                raw(directory, group[stage]['response'])
        if exchange['backend'] is not None:
            need('s3_forward_started' in group and moment(request) <= moment(group['s3_forward_started'])
                 < moment(exchange['backend']) < moment(group['s3_handler_finished']), 'actual-backend-interval')
            exchange['bytes'] = raw(directory, exchange['backend']['response'])
        else:
            need('s3_forward_started' not in group and group['s3_delivery_started']['origin'] == 'fixture_no_such_bucket', 'unaccounted-backend-response')
        if 's3_delivery_started' in group:
            delivered = group['s3_delivery_started']
            need('s3_delivery_finished' in group and moment(delivered) <= moment(group['s3_delivery_finished']), 'delivery-lifecycle')
            if delivered['origin'] == 'backend':
                need(exchange['backend'] is not None and delivered['status'] == exchange['backend']['status']
                     and delivered['response'] == exchange['backend']['response']
                     and moment(exchange['backend']) < moment(delivered), 'unmodified-backend-response')
                exchange['delivered'] = group['s3_delivery_finished']['complete'] is True
        exchanges.append(exchange)
    exchanges.sort(key=lambda value: moment(value['request']))
    need(not selection(events, 's3_fixture_error'), 'fixture-network-error')
    heads, mutations, objects = defaultdict(list), defaultdict(list), {}
    accepted = [x for x in exchanges if x['backend'] is not None and x['request']['method'] == 'PUT'
                and x['backend']['status'] == 200]
    accepted.sort(key=lambda value: moment(value['backend']))
    for exchange in accepted:
        request, response, payload = exchange['request'], exchange['backend'], exchange['payload']
        database = head_path(request['path'])
        if database is not None:
            value = head(payload, database)
            previous = heads[database][-1] if heads[database] else None
            if previous is None:
                need(value['head_serial'] == value['revision'] == 1 and request['headers'].get('if-none-match') == '*'
                     and request['role'] == 'seed', 'initial-head-absent')
                kind = 'create'
            else:
                need(moment(previous['exchange']['backend']) < moment(exchange['group']['s3_forward_started']), 'head-mutation-overlap')
                need(request['headers'].get('if-match') == previous['exchange']['backend']['headers'].get('etag')
                     and request['headers'].get('if-none-match') is None, 'original-head-cas')
                if exchange['call'] is None:
                    seed_name = {4101: 'main', 4102: 'fence', 4103: 'aborted'}[database]
                    contexts = [r for r in selection(events, 'child_input', id='seed-' + seed_name)
                                if moment(r) < moment(request)]
                    need(contexts, 'native-publication-original-call')
                    context_start = moment(contexts[-1])
                else:
                    context_start = moment(exchange['call']['request'])
                reads = [x for x in exchanges if x['request']['role'] == request['role']
                         and x['request']['method'] == 'GET' and x['request']['path'] == request['path']
                         and x['backend'] is not None and x['backend']['status'] == 200
                         and x['backend']['headers'].get('etag') == request['headers']['if-match']
                         and x.get('bytes') == previous['exchange']['payload'] and x['delivered']
                         and context_start < moment(x['request'])
                         < moment(x['group']['s3_delivery_finished']) < moment(request)]
                need(reads, 'same-get-head-body-etag')
                kind = advance(previous['head'], value)
            record = {'head': value, 'exchange': exchange, 'kind': kind, 'previous': previous}
            heads[database].append(record)
            exchange['head_record'] = record
        else:
            need(request['headers'].get('if-none-match') == '*' and request['headers'].get('if-match') is None, 'immutable-absent-put')
            envelope(payload, request['path'])
            if request['path'] in objects:
                need(objects[request['path']] == payload, 'immutable-identity-reused')
            objects[request['path']] = payload
        need(isinstance(response['headers'].get('etag'), str), 'actual-backend-etag')
        mutations[request['path']].append(exchange)
    need(set(heads) == {4101, 4102, 4103}, 'head-database-denominator')
    for exchange in exchanges:
        request, response = exchange['request'], exchange['backend']
        if request['method'] == 'GET' and response is not None and response['status'] == 200 and '/objects/' in request['path']:
            envelope(exchange['bytes'], request['path'])
            if request['path'] in objects:
                need(objects[request['path']] == exchange['bytes'], 'exact-immutable-readback')
            else:
                objects[request['path']] = exchange['bytes']
        if request['method'] == 'GET' and response is not None and response['status'] == 200 and head_path(request['path']) is not None:
            database = head_path(request['path'])
            head(exchange['bytes'], database)
            matches = [h for h in heads[database] if h['exchange']['payload'] == exchange['bytes']
                       and h['exchange']['backend']['headers'].get('etag') == response['headers'].get('etag')
                       and moment(h['exchange']['backend']) < moment(response)]
            need(len(matches) == 1, 'exact-head-version')
            exchange['read_head'] = matches[0]
    return exchanges, heads, objects


def wire_receipt(value):
    return {**value, 'scope': {k: str(v) for k, v in value['scope'].items()},
            'request': {k: str(v) if k != 'fingerprint' else v for k, v in value['request'].items()},
            'sequence': str(value['sequence']), 'transition': {k: str(v) for k, v in value['transition'].items()}}


def originals_audit(directory, events, specs, intents, calls, heads, exchanges):
    acks = selection(events, 'seed_ack')
    need(len(acks) == 264 and len({a['name'] for a in acks}) == 264, 'original-ack-denominator')
    records = wire.parse((directory / 'original-results.json').read_bytes())
    need(set(records) == {a['name'] for a in acks}, 'original-result-ledger')
    actual = {}
    native_execute, native_cancel = 0, 0
    for name in ('main', 'fence', 'aborted'):
        identifier = 'seed-' + name
        inputs = selection(events, 'child_input', id=identifier)
        outputs = selection(events, 'child_output', id=identifier)
        need(len(outputs) == len(inputs) + 1 and wire.parse(raw(directory, outputs[0]['raw']))['ready'] is True,
             'native-command-denominator')
        for input_row, output_row in zip(inputs, outputs[1:]):
            request = wire.parse(raw(directory, input_row['raw']))
            response = wire.parse(raw(directory, output_row['raw']))
            need(response['ok'] is True and moment(input_row) < moment(output_row), 'native-original-response')
            operation = request['op']
            need(operation in ('create', 'activate_session', 'status', 'session_execute', 'close_full',
                               'session_close', 'session_open', 'cancel'), 'unplanned-native-operation')
            if operation == 'session_execute':
                native_execute += 1
                matched = [s for s in specs.values() if s['scope_name'] == name and s['purpose'] == 'seed'
                           and int(s['epoch']) == request['epoch'] and int(s['request_id']) == request['id']]
                need(len(matched) == 1, 'native-original-input')
                spec = matched[0]
                need(request['statements'] == [{'sql': s['sql'], 'parameters': []} for s in spec['statements']]
                     and spec['name'] not in actual, 'native-sql-replayed')
                value = response['value']
                result = bytes(value['result']['encoded'])
                receipt = wire_receipt(value['receipt'])
                need(receipt['request'] == intents[spec['name']]['decoded']['request']
                     and receipt['scope'] == intents[spec['name']]['decoded']['scope']
                     and wire.receipt_hash(receipt, result) == receipt['result_hash'], 'native-original-receipt')
                decoded = wire.result(result)
                row = decoded[-1]
                need(row['columns'] == ['counter', 'payload', 'nonce'] and len(row['rows']) == 1
                     and row['rows'][0][0] == spec['counter'] and type(row['rows'][0][1]) is bytes
                     and len(row['rows'][0][1]) == 64 and type(row['rows'][0][2]) is int
                     and row['affected_rows'] == 1, 'native-original-sql-result')
                publications = [row for row in heads[int(receipt['scope']['database'])]
                                if row['exchange']['request']['role'] == 'seed'
                                and row['head']['sequence'] == int(receipt['sequence'])
                                and row['head']['transition'] == {k: int(v) for k, v in receipt['transition'].items()}
                                and row['head']['data_root'] == receipt['data_root']
                                and moment(input_row) < moment(row['exchange']['request'])
                                < moment(row['exchange']['backend']) < moment(output_row)]
                need(len(publications) == 1, 'native-ack-original-head-publication')
                publication = publications[0]['exchange']
                result_path = prefix(int(receipt['scope']['database']), 1) + receipt['result_hash']
                put = [x for x in exchanges if x['request']['method'] == 'PUT' and x['request']['role'] == 'seed'
                       and x['request']['path'] == result_path and x['backend'] is not None and x['backend']['status'] == 200
                       and moment(input_row) < moment(x['request']) < moment(x['backend']) < moment(publication['request'])]
                need(len(put) == 1, 'native-ack-durable-result-object')
                readback = [x for x in exchanges if x['request']['method'] == 'GET' and x['request']['role'] == 'seed'
                            and x['request']['path'] == result_path and x['backend'] is not None and x['backend']['status'] == 200
                            and x['bytes'] == put[0]['payload'] and x['delivered']
                            and moment(put[0]['backend']) < moment(x['request'])
                            < moment(x['group']['s3_delivery_finished']) < moment(publication['request'])]
                need(readback, 'native-ack-exact-result-readback')
                actual[spec['name']] = {'receipt': receipt, 'result': result, 'decoded': decoded}
            if operation == 'cancel':
                native_cancel += 1
                need(name == 'main' and request['epoch'] == 3 and request['id'] == 3
                     and response['value']['state'] == 'cancelled', 'original-cancel-barrier')
    need(native_execute == 264 and native_cancel == 1, 'native-sql-denominator')
    for ack in acks:
        original = actual[ack['name']]
        need(wire_receipt(ack['receipt']) == original['receipt']
             and raw(directory, ack['result']) == original['result']
             and records[ack['name']] == {'receipt': ack['receipt'], 'result': ack['result']}, 'original-ack-bytes')
        call = calls['cold-lookup-' + ack['name']]
        need(call['response'] is not None and call['response_body']['ok'] is True, 'cold-original-lookup')
        value = call['response_body']['value']
        returned, decoded = wire.committed(value)
        need(returned == original['result'] and value['receipt'] == original['receipt'], 'original-result-not-preserved')
        need(call['body']['request'] == intents[ack['name']]['decoded']['request'], 'cold-original-request')
        marker = one(events, 'cold_original_recovered', name=ack['name'])
        need(raw(directory, marker['result']) == returned and marker['receipt'] == original['receipt'], 'cold-original-ledger')
    for name, last, count in (('main', 'main-260', 260), ('fence', 'fence-002', 2), ('aborted', 'aborted-002', 2)):
        call = calls['cold-query-' + name]
        need(call['body']['statements'] == [{'sql': 'SELECT id,counter,payload FROM witness ORDER BY id', 'params': []}], 'cold-business-query-input')
        decoded = wire.result(wire.b64(call['response_body']['value']['result']))
        expected = [[1, count, actual[last]['decoded'][-1]['rows'][0][1]]]
        need(len(decoded) == 1 and decoded[0]['columns'] == ['id', 'counter', 'payload']
             and decoded[0]['rows'] == expected, 'single-effect-business-state')
    barrier = one(events, 'original_cancel')['value']
    expected_barrier = {'state': 'cancelled', 'transition': {k: str(v) for k, v in barrier['transition'].items()}}
    need(calls['cold-main-cancel-lookup']['response_body']['value'] == expected_barrier, 'cancel-survives-copy')
    for name in ('cold-main-late-lookup', 'cold-fence-old-lookup'):
        need(calls[name]['response_body']['value'] == {'state': 'unknown'}, 'old-sql-not-committed')
    completed = selection(events, 'seed_completed')
    need(len(completed) == 3, 'seed-scope-denominator')
    main = one(events, 'seed_completed', scope_name='main')['head']
    need([w['count'] for w in main['windows']] == [3, 129, 129] and main['request_epoch'] == 3
         and main['sequence'] == 260, 'three-real-retained-windows')
    closed = selection(events, 'window_closed')
    need([r['counter'] for r in closed] == [129, 258], 'two-real-window-closes')
    return actual


def copy_audit(exchanges, heads, objects, originals):
    counts, summaries = Counter(), []
    for database, history in heads.items():
        for record in history:
            counts[record['kind']] += 1
            if record['kind'] != 'seal':
                continue
            previous = record['previous']['head']
            plan = previous['storage']['plan']
            basis = plan['basis']
            source = Graph(objects, database, plan['source']).closure(basis)
            target = Graph(objects, database, plan['target']).closure(basis)
            need(source['image'] == target['image'] and set(source['results']) == set(target['results']), 'copy-complete-closure')
            before = moment(record['exchange']['request'])
            created = [r for r in history if r['kind'] == 'begin' and r['head']['storage']['plan']['serial'] == plan['serial']]
            need(len(created) == 1, 'original-copy-plan')
            after = moment(created[0]['exchange']['backend'])
            source_paths, target_paths = source['dependencies'], target['dependencies']
            for path in source_paths:
                name = path.rsplit('/', 1)[-1]
                destination = prefix(database, plan['target']) + name
                need(destination in target_paths and objects[path] == objects[destination], 'copy-original-frame-bytes')
                reads = [x for x in exchanges if x['request']['method'] == 'GET' and x['request']['path'] == path
                         and x['request']['role'] == 'B' and x['backend'] is not None and x['backend']['status'] == 200
                         and x.get('bytes') == objects[path] and x['delivered']
                         and after < moment(x['request']) < moment(x['group']['s3_delivery_finished']) < before]
                writes = [x for x in exchanges if x['request']['method'] == 'PUT' and x['request']['path'] == destination
                          and x['request']['role'] == 'B' and x['backend'] is not None and x['backend']['status'] in (200, 412)
                          and x['payload'] == objects[path] and after < moment(x['request']) < moment(x['backend']) < before]
                need(reads and writes, 'copy-source-edge-and-target-put')
                write = writes[-1]
                readbacks = [x for x in exchanges if x['request']['method'] == 'GET' and x['request']['path'] == destination
                             and x['request']['role'] == 'B' and x['backend'] is not None and x['backend']['status'] == 200
                             and x.get('bytes') == objects[path] and x['delivered']
                             and moment(write['backend']) < moment(x['request'])
                             < moment(x['group']['s3_delivery_finished']) < before]
                need(readbacks, 'seal-before-exact-target-readback')
            uploaded = {x['request']['path'] for x in exchanges if x['request']['method'] == 'PUT'
                        and x['request']['path'].startswith(prefix(database, plan['target']))
                        and after < moment(x['request']) < before}
            need(uploaded == target_paths, 'copy-roots-include-receipt-only-history')
            if database == 4101:
                need(len(source['results']) == 260 and len(source['entries']) == 261
                     and len(basis['windows']) == 3 and source['index_levels'].count(1) >= 2, 'all-closed-window-results-copied')
                for name, original in originals.items():
                    if not name.startswith('main-'):
                        continue
                    request = original['receipt']['request']
                    item = source['results'][(int(request['epoch']), int(request['id']))]
                    need(item[0] == original['receipt']['result_hash'] and item[2] == original['result'], 'copied-original-result-bytes')
                historical = {value[1]['data_root'] for value in source['results'].values()}
                excluded = historical - {p.rsplit('/', 1)[-1] for p in source_paths}
                need(excluded and all(prefix(database, plan['target']) + name not in uploaded for name in excluded), 'historical-receipt-root-not-edge')
            summaries.append({'database': database, 'source': plan['source'], 'target': plan['target'],
                              'dependencies': len(source_paths), 'retained_results': len(source['results']),
                              'retained_entries': len(source['entries']), 'plan_serial': plan['serial']})
    need(counts['begin'] == counts['seal'] == 4 and counts['promote'] == 3 and counts['abort'] == 1, 'copy-transition-denominator')
    main_promoted = next(r for r in heads[4101] if r['kind'] == 'promote')['head']
    need(main_promoted['policy'] == [{'principal': 11, 'read': True, 'write': True, 'admin': True},
                                    {'principal': 12, 'read': True, 'write': False, 'admin': False}], 'acl-update-survives-promotion')
    return summaries, counts


def no_such_key(exchange):
    if exchange['backend'] is None or exchange['backend']['status'] != 404:
        return False
    try:
        document = ET.fromstring(exchange['bytes'])
    except ET.ParseError:
        return False
    return document.tag == 'Error' and document.findtext('Code') == 'NoSuchKey'


def gc_audit(exchanges, heads, backend):
    deletions = [x for x in exchanges if x['request']['method'] == 'DELETE']
    need(deletions, 'real-delete-required')
    for deletion in deletions:
        request, call = deletion['request'], deletion['call']
        database, generation, name = object_path(request['path'])
        need(request['role'] == 'B' and request['access_sha256'] == backend['gc_access_sha256'], 'delete-dedicated-capability')
        need(call is not None and call['body']['operation'] == 'gc_resume', 'delete-original-gc-call')
        batch = int(call['body']['batch_serial'])
        observations = [x for x in exchanges if x['request']['method'] == 'GET' and x['request']['role'] == 'B'
                        and x['request']['path'] == f'/scap-test/scap-object/v1/1/7/{database}/head'
                        and x.get('read_head') is not None and x['delivered']
                        and moment(call['request']) < moment(x['request'])
                        < moment(x['group']['s3_delivery_finished']) < moment(request)]
        need(observations, 'delete-without-fresh-checkpoint')
        basis = observations[-1]['read_head']['head']
        sweep = basis['storage']['sweep']
        need(retired(basis['storage'], generation) and sweep is not None
             and sweep['serial'] == batch and sweep['generation'] == generation, 'delete-retirement-proof')
        candidates = [e for e in sweep['entries'] if '/' + 'scap-test/' + e['key'] == request['path']]
        need(len(candidates) == 1 and candidates[0]['hash'] == name
             and candidates[0]['disposition'] == 'pending', 'delete-original-candidate')
        need(request['headers'].get('if-match') == candidates[0]['etag']
             and request['headers'].get('if-none-match') is None, 'delete-original-etag')
    for database, history in heads.items():
        for record in history:
            kind, current = record['kind'], record['head']
            if kind not in ('prepare', 'progress', 'clear'):
                continue
            exchange = record['exchange']
            call = exchange['call']
            need(call is not None and call['body']['operation'] == ('gc_prepare' if kind == 'prepare' else 'gc_resume'), 'checkpoint-original-operation')
            within = [x for x in exchanges if x['request']['role'] == 'B'
                      and moment(call['request']) < moment(x['request'])
                      and x['backend'] is not None and moment(x['backend']) < moment(exchange['request'])]
            if kind == 'prepare':
                sweep = current['storage']['sweep']
                need(int(call['body']['expected_head_serial']) == record['previous']['head']['head_serial']
                     and int(call['body']['generation']) == sweep['generation'], 'prepare-original-head')
                listings = [x for x in within if x['request']['method'] == 'GET'
                            and parse_qs(urlsplit(x['request']['path']).query).get('list-type') == ['2']]
                need(len(listings) == 1, 'one-bounded-list-page')
                listing = listings[0]
                query = parse_qs(urlsplit(listing['request']['path']).query)
                expected_prefix = prefix(database, sweep['generation']).removeprefix('/scap-test/')
                need(query.get('prefix') == [expected_prefix] and query.get('max-keys') == ['32'], 'retired-list-prefix-bound')
                cursor = call['body']['after']
                need(query.get('start-after', []) == ([] if cursor is None else [expected_prefix + cursor]), 'original-exclusive-frontier')
                document = ET.fromstring(listing['bytes'])
                keys = [child.text for container in document if container.tag.rsplit('}', 1)[-1] == 'Contents'
                        for child in container if child.tag.rsplit('}', 1)[-1] == 'Key']
                need(keys == sorted(set(keys)) and 0 < len(keys) <= 32, 'list-page-denominator')
                for entry in sweep['entries']:
                    need(entry['key'] in keys, 'checkpoint-not-listed')
                    reads = [x for x in within if x['request']['method'] == 'GET' and x['request']['path'] == '/scap-test/' + entry['key']
                             and x['backend']['status'] == 200 and x['delivered']
                             and x['backend']['headers'].get('etag') == entry['etag']
                             and x['request']['access_sha256'] == backend['gc_access_sha256']]
                    need(reads, 'checkpoint-original-exact-etag')
                need(not [x for x in within if x['request']['method'] == 'DELETE'], 'prepare-must-not-delete')
            if kind == 'progress':
                previous = record['previous']['head']['storage']['sweep']
                for old, new in zip(previous['entries'], current['storage']['sweep']['entries']):
                    if old['disposition'] == new['disposition']:
                        continue
                    candidates = [x for x in within if x['request']['path'] == '/scap-test/' + old['key'] and x['delivered']]
                    if new['disposition'] == 'applied':
                        valid = [x for x in candidates if x['request']['method'] == 'DELETE'
                                 and x['request']['headers'].get('if-match') == old['etag'] and x['backend']['status'] in (200, 204)]
                    elif new['disposition'] == 'condition_mismatch':
                        valid = [x for x in candidates if x['request']['method'] == 'DELETE'
                                 and x['request']['headers'].get('if-match') == old['etag'] and x['backend']['status'] == 412]
                    else:
                        valid = [x for x in candidates if x['request']['method'] in ('GET', 'DELETE') and no_such_key(x)]
                    need(valid, 'known-disposition-requires-delivered-outcome')
            if kind == 'clear':
                previous = record['previous']
                observations = [x for x in within if x.get('read_head') is previous and x['delivered']]
                need(observations, 'settled-checkpoint-exact-before-clear')
    return {'delete_requests': len(deletions),
            'actual_accepted_deletes': sum(x['backend'] is not None and x['backend']['status'] in (200, 204) for x in deletions),
            'actual_condition_mismatches': sum(x['backend'] is not None and x['backend']['status'] == 412 for x in deletions)}


def fault_audit(directory, events, calls, exchanges, heads):
    by_key = {(x['request']['role'], x['request']['serial']): x for x in exchanges}
    armed = {r['id']: r for r in selection(events, 'fault_armed')}
    expected = {'late-source-put', 'old-source-get', 'old-head-cas', 'late-original-delete',
                'accepted-delete-response-loss', 'inspect-no-such-bucket'}
    need(set(armed) == expected, 'fault-denominator')
    faults = {}
    for name, original in armed.items():
        arrived = one(events, 'fault_arrived', id=name)
        exchange = by_key[(arrived['role'], arrived['serial'])]
        need(moment(original) < moment(exchange['request']) < moment(arrived)
             and original['mode'] == arrived['mode'] and original['stage'] == arrived['stage'], 'fault-original-transport')
        group = exchange['group']
        if original['mode'] == 'hold':
            released = one(events, 'fault_release_requested', id=name)
            resumed = one(events, 'fault_forward_resumed', id=name)
            need(original['stage'] == 'before_forward'
                 and moment(arrived) < moment(released) <= moment(resumed)
                 < moment(group['s3_forward_started']) < moment(exchange['backend']), 'fault-before-real-backend')
        elif original['mode'] == 'drop':
            suppressed = one(events, 'fault_suppressed', id=name)
            need(original['stage'] == 'after_response' and suppressed['aborted'] is False
                 and moment(exchange['backend']) < moment(arrived) <= moment(suppressed)
                 and 's3_delivery_started' not in group, 'accepted-delete-response-actually-lost')
        else:
            need(original['mode'] == 'no_such_bucket' and exchange['backend'] is None
                 and group['s3_delivery_started']['status'] == 404
                 and raw(directory, group['s3_delivery_started']['response']) == b'<Error><Code>NoSuchBucket</Code><Message>fixture</Message></Error>',
                 'no-such-bucket-explicit-injection')
        faults[name] = exchange

    reader = faults['old-source-get']
    original_head_reads = [x for x in exchanges if x['request']['role'] == 'R' and x.get('read_head') is not None]
    need(len(original_head_reads) == 2 and no_such_key(reader) and reader['delivered'], 'old-read-actual-missing')
    old, fresh = original_head_reads
    need(old['read_head']['head']['storage']['active_generation'] == 1
         and old['read_head']['head']['storage']['plan']['phase'] == 'sealed'
         and moment(old['backend']) < moment(reader['request'])
         and moment(reader['group']['s3_delivery_finished']) < moment(fresh['request']), 'single-original-context-diagnosis')
    before, after = old['read_head']['head'], fresh['read_head']['head']
    need(after['head_serial'] > before['head_serial'] and after['storage']['allocated_through'] >= before['storage']['allocated_through']
         and retired(after['storage'], 1) and old['backend']['headers']['etag'] != fresh['backend']['headers']['etag'], 'strict-retirement-fence')
    need(moment(fresh['group']['s3_delivery_finished']) < moment(calls['main-old-reader']['response']), 'expiry-after-authority-proof')
    target = one(events, 'reader_target_frontier')
    need(target['hash'] == reader['request']['path'].rsplit('/', 1)[-1]
         and target['after'] == f'{int(target["hash"], 16) - 1:064x}', 'targeted-first-frontier')
    first = calls['main-reader-first-prepare']
    need(first['body']['after'] == target['after'], 'targeted-original-prepare')
    batch = first['response_body']['value']['status']['storage']['sweep']['serial']
    restart_start = one(events, 'maintenance_restart_started', label='main-persisted-reader-batch')
    restart_end = one(events, 'maintenance_restart_finished', label='main-persisted-reader-batch')
    need(moment(first['response']) < moment(restart_start) < moment(restart_end)
         < moment(calls['main-reader-first-resume']['request'])
         and calls['main-reader-first-resume']['body']['batch_serial'] == batch, 'persistent-checkpoint-restart')
    deleted_reader = [x for x in exchanges if x['request']['method'] == 'DELETE'
                      and x['request']['path'] == reader['request']['path'] and x['backend'] is not None
                      and x['backend']['status'] in (200, 204)
                      and moment(x['backend']) < moment(reader['group']['s3_forward_started'])]
    need(deleted_reader, 'old-read-deleted-before-forward')

    late = faults['late-source-put']
    first_done = one(events, 'sweep_round_finished', label='main-full-first-round')
    second_start = one(events, 'sweep_round_started', label='main-late-round-from-start')
    need(late['backend']['status'] == 200 and moment(first_done) < moment(late['group']['s3_forward_started'])
         < moment(late['backend']) < moment(second_start) and second_start['after'] is None
         and calls['main-late-round-from-start-0-prepare']['body']['after'] is None, 'late-put-new-round-from-start')
    late_deletes = [x for x in exchanges if x['request']['method'] == 'DELETE' and x['request']['path'] == late['request']['path']
                   and x['backend'] is not None and x['backend']['status'] in (200, 204)
                   and moment(second_start) < moment(x['request'])]
    need(late_deletes, 'late-put-must-be-collected')
    need(len([x for x in exchanges if x['request']['method'] == 'PUT' and x['request']['role'] == 'A'
              and x['request']['path'].endswith('/4101/head') and x['backend'] is not None
              and x['backend']['status'] == 200 and moment(x['request']) > moment(late['request'])]) == 0,
         'late-sql-no-new-authority')
    old_cas = faults['old-head-cas']
    need(old_cas['backend']['status'] == 412, 'old-cas-real-backend-conflict')
    original_if_match = old_cas['request']['headers'].get('if-match')
    original_head = [x for x in exchanges if x['request']['role'] == 'A' and x.get('read_head') is not None
                     and x['request']['path'] == old_cas['request']['path'] and x['delivered']
                     and x['backend']['headers'].get('etag') == original_if_match
                     and moment(calls['fence-old-execute']['request']) < moment(x['request'])
                     < moment(x['group']['s3_delivery_finished']) < moment(old_cas['request'])]
    need(original_head, 'old-cas-original-same-get-etag')
    candidate = head(old_cas['payload'], 4102)
    need(advance(original_head[-1]['read_head']['head'], candidate) == 'business', 'old-cas-original-candidate')
    promoted = [r for r in heads[4102] if r['kind'] == 'promote']
    need(len(promoted) == 2 and moment(promoted[0]['exchange']['backend']) < moment(old_cas['group']['s3_forward_started']), 'old-cas-after-fence')
    old_delete = faults['late-original-delete']
    need(moment(calls['fence-delete-original']['done']) < moment(calls['fence-delete-restart-resume']['request'])
         < moment(calls['fence-delete-restart-resume']['response'])
         < moment(promoted[1]['exchange']['backend']) < moment(old_delete['group']['s3_forward_started']), 'late-delete-after-next-generation')
    need(object_path(old_delete['request']['path'])[1] == 1 and promoted[1]['head']['storage']['active_generation'] == 3,
         'late-delete-bound-to-old-key')

    lost = faults['accepted-delete-response-loss']
    need(lost['backend']['status'] in (200, 204), 'unknown-delete-actually-applied')
    unknown = calls['aborted-after-unknown']['response_body']['value']
    original_batch = calls['aborted-delete-unknown']['body']['batch_serial']
    need(unknown['storage']['sweep']['serial'] == original_batch and unknown['storage']['sweep']['pending'] > 0, 'unknown-keeps-checkpoint')
    changed = one(events, 'same_bytes_new_backend_etag')
    need(changed['key'] == lost['request']['path'] and changed['old_etag'] == lost['request']['headers']['if-match']
         and changed['new_etag'] != changed['old_etag'], 'original-etag-not-refreshed')
    operator = {r['id']: r for r in selection(events, 'operator_request')}
    need(set(operator) == {'accepted-delete-observed-absent', 'multipart-create', 'multipart-part',
                           'multipart-complete', 'multipart-readback', 'conflict-preserved-new-object'}, 'operator-operation-denominator')
    for name, request in operator.items():
        response = one(events, 'operator_response', id=name)
        need(moment(request) < moment(response) and request['path'].split('?', 1)[0] == changed['key']
             and request['method'] in ('GET', 'POST', 'PUT'), 'operator-retired-object-only')
        raw(directory, request['request'])
        raw(directory, response['response'])
    part = operator['multipart-part']
    readback = one(events, 'operator_response', id='multipart-readback')
    retained = one(events, 'operator_response', id='conflict-preserved-new-object')
    need(part['method'] == 'PUT' and raw(directory, part['request']) == raw(directory, changed['original'])
         and readback['status'] == retained['status'] == 200
         and readback['headers']['etag'] == retained['headers']['etag'] == changed['new_etag']
         and raw(directory, readback['response']) == raw(directory, retained['response']) == raw(directory, changed['original']), 'actual-multipart-same-bytes-new-etag')
    old_resume = calls['aborted-old-batch-resume']
    conflicts = [x for x in exchanges if x['request']['method'] == 'DELETE' and x['request']['path'] == changed['key']
                 and x['request']['headers'].get('if-match') == changed['old_etag'] and x['backend'] is not None
                 and x['backend']['status'] == 412 and x['delivered']
                 and moment(old_resume['request']) < moment(x['request']) < moment(old_resume['response'])]
    need(len(conflicts) == 1 and moment(readback) < moment(conflicts[0]['request']) < moment(retained), 'new-etag-requires-real-original-412')
    injected = faults['inspect-no-such-bucket']
    failed_call = calls['aborted-bucket-unknown']
    before_checkpoint = calls['aborted-fresh-new-etag-prepare']['response_body']['value']['status']
    after_checkpoint = calls['aborted-after-bucket-unknown']['response_body']['value']
    need(before_checkpoint == after_checkpoint, 'no-such-bucket-keeps-exact-checkpoint')
    need(not [x for x in exchanges if x['request']['method'] in ('PUT', 'DELETE') and x['request']['role'] == 'B'
              and moment(failed_call['request']) < moment(x['request']) < moment(failed_call['response'])], 'no-such-bucket-never-disposed')
    final_deletes = [x for x in exchanges if x['request']['method'] == 'DELETE' and x['request']['path'] == changed['key']
                     and x['request']['headers'].get('if-match') == changed['new_etag'] and x['backend'] is not None
                     and x['backend']['status'] in (200, 204) and x['delivered']
                     and moment(failed_call['response']) < moment(x['request'])]
    need(len(final_deletes) == 1, 'new-independent-checkpoint-etag')
    need(calls['aborted-old-batch-conflict']['result']['error']['code'] == 'CONFLICT', 'completed-old-batch-conflict')
    return {'faults': len(faults), 'original_unknowns': 5, 'old_source_expiries': 1,
            'same_bytes_backend_etag_change': True, 'late_original_put_collected': True,
            'late_delete_after_new_promotion': True}


def audit(directory):
    directory = Path(directory)
    inputs = wire.parse((directory / 'inputs.json').read_bytes())
    events = rows(directory / 'events.jsonl')
    need([r['sequence'] for r in events] == list(range(1, len(events) + 1))
         and all(moment(a) <= moment(b) for a, b in zip(events, events[1:])), 'event-ledger-order')
    identity(directory, inputs, events)
    backend, processes = process_audit(directory, inputs, events)
    specs, intents = original_inputs(directory, inputs, events)
    calls = sdk_audit(directory, inputs, events, intents)
    exchanges, heads, objects = s3_audit(directory, events, calls, backend)
    originals = originals_audit(directory, events, specs, intents, calls, heads, exchanges)
    copies, transitions = copy_audit(exchanges, heads, objects, originals)
    gc = gc_audit(exchanges, heads, backend)
    faults = fault_audit(directory, events, calls, exchanges, heads)
    summary = wire.parse((directory / 'summary.json').read_bytes())
    need(summary['status'] == 'OBSERVED_NOT_AUDITED' and summary['private_removed'] is True
         and summary['cleanup_errors'] == [] and summary['error'] is None, 'successful-observation-cleanup')
    return {'schema': 1, 'status': 'PASSED', 'profile': 'explicit-head6-reclamation-native-http-signed-s3-v1',
            'fixture_source_commit': inputs['commit'], 'runtime_source_commit': inputs['runtime_source_commit'],
            'http_posts': len(calls), 's3_requests': len(exchanges),
            'native_original_sql_acks': len(originals), 'main_original_sql_acks': 260,
            'main_retained_windows': 3, 'original_cancellations': 1, 'cold_original_lookups': 264,
            'copy_closures': copies, 'head_transitions': dict(transitions), 'gc': gc, 'faults': faults,
            'processes': processes, 'aws_standard': 'NOT_RUN', 'production_slo': 'NOT_RUN',
            'deleted_final_active_generation': 'PROTECTED_NOT_RECLAIMED',
            'permanent_prefix_emptiness': 'NOT_CLAIMED',
            'source_sha256': {name: sha((directory / name).read_bytes())
                              for name in ('inputs.json', 'events.jsonl', 'intents.json', 'original-results.json',
                                           'sdk-A.jsonl', 'sdk-B.jsonl', 'sdk-R.jsonl')}}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('evidence', type=Path)
    print(json.dumps(audit(parser.parse_args().evidence), sort_keys=True))
