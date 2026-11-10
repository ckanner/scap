#!/usr/bin/env python3
"""Independent raw-history audit. Does not import runner, SDK or pool code."""
from __future__ import annotations

import argparse
import base64
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path
import tarfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('scap_output_independent_wire', HERE.parent / 'object-service/audit_wire.py')
wire = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wire)


class Rejected(ValueError):
    def __init__(self, rule):
        self.rule = rule
        super().__init__(rule)


def need(condition, rule):
    if not condition:
        raise Rejected(rule)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def rows(path):
    need(path.is_file(), 'ledger-missing')
    result = []
    with path.open('rb') as stream:
        while line := stream.readline(1024 * 1024 + 1):
            need(len(line) <= 1024 * 1024 and line.endswith(b'\n'), 'ledger-framing')
            result.append(wire.parse(line))
    return result


def raw(directory, description):
    need(set(description) == {'file', 'bytes', 'sha256'}, 'raw-description')
    name = description['file']
    need(isinstance(name, str) and name == Path(name).name, 'raw-path')
    path = directory / name
    need(path.is_file() and not path.is_symlink(), 'raw-file-missing')
    need(type(description['bytes']) is int and 0 <= description['bytes'] <= 96 * 1024 * 1024,
         'raw-bound')
    need(path.stat().st_size == description['bytes'], 'raw-integrity')
    value = path.read_bytes()
    need(len(value) == description['bytes'] and digest(value) == description['sha256'], 'raw-integrity')
    return value


def time_of(row):
    value = row['monotonic_ns']
    need(type(value) is int or isinstance(value, str) and value.isdecimal(), 'observation-time')
    return int(value)


def scope(tenant):
    return {'deployment': '1', 'tenant': tenant, 'database': '101' if tenant == '7' else '202',
            'incarnation': '1', 'generation': '1'}


def large(value):
    decoded = wire.result(wire.b64(value['result']))
    need(len(decoded) == 1 and decoded[0]['columns'] == ['b' + str(i) for i in range(16)]
         and len(decoded[0]['rows']) == 1, 'large-result-shape')
    for item in decoded[0]['rows'][0]:
        need(type(item) is bytes and len(item) == 2097152 and item.count(0) == len(item), 'large-result-bytes')
    return decoded


def identity(directory, inputs):
    archive = directory / 'fixture-source.tar'
    need(digest(archive.read_bytes()) == inputs['fixture_archive_sha256'], 'fixture-archive')
    with tarfile.open(archive) as source:
        members = source.getmembers()
        need(len(members) == len(inputs['fixture']), 'fixture-count')
        need(len({m.name for m in members}) == len(members), 'fixture-duplicate')
        for member in members:
            need(member.isfile() and member.name in inputs['fixture'], 'fixture-member')
            need(digest(source.extractfile(member).read()) == inputs['fixture'][member.name], 'fixture-bytes')
    need(inputs['plan_sha256'] == inputs['fixture']['PLAN.md'], 'frozen-plan')
    build_dir = directory / 'runtime-build'
    receipt = wire.parse((build_dir / 'build-receipt.json').read_bytes())
    need(receipt['status'] == 'passed' and receipt['exit_code'] == 0 and receipt['profile'] == 'release',
         'runtime-build')
    need(receipt['source_commit'] == inputs['runtime_source_commit']
         and receipt['inputs'] == inputs['runtime_inputs'], 'runtime-source')
    need(receipt['binary'] == inputs['tools']['scapd'], 'runtime-binary')
    saved = receipt['archived_evidence']
    for key, hash_key in (('source_archive', 'source_archive_sha256'),
                          ('source_manifest', 'source_manifest_sha256')):
        need(digest((build_dir / saved[key]).read_bytes()) == saved[hash_key], 'runtime-archive')
    with tarfile.open(build_dir / saved['source_archive']) as source:
        members = source.getmembers()
        need(len(members) == len(receipt['inputs']), 'runtime-source-count')
        need(len({m.name for m in members}) == len(members), 'runtime-source-duplicate')
        for member in members:
            need(member.isfile() and member.name in receipt['inputs'], 'runtime-source-member')
            need(digest(source.extractfile(member).read()) == receipt['inputs'][member.name], 'runtime-source-bytes')
    for name, key in (('build-cargo.stdout.jsonl', 'cargo.stdout.jsonl_sha256'),
                      ('build-cargo.stderr.log', 'cargo.stderr.log_sha256')):
        need(digest((build_dir / name).read_bytes()) == receipt[key], 'runtime-build-log')
    events = rows(build_dir / 'build-cargo.stdout.jsonl')
    need(events[-1].get('reason') == 'build-finished' and events[-1].get('success') is True,
         'runtime-build-finished')


def audit(directory):
    directory = Path(directory)
    inputs = wire.parse((directory / 'inputs.json').read_bytes())
    identity(directory, inputs)
    config = wire.parse((directory / 'service-config.json').read_bytes())
    need(config['output'] == {'version': 1, 'bytes': 268435456, 'bytes_per_tenant': 201326592,
         'control_bytes': 8388608, 'control_bytes_per_tenant': 1048576}, 'pool-profile')
    transport = config['transport']
    need(transport['max_connections'] == 64, 'connection-profile')
    if inputs['profile'] == 'bounded':
        need(transport['response_timeout_ms'] == 120000 and transport['shutdown_timeout_ms'] == 30000,
             'transport-profile')
    else:
        need(inputs['profile'] == 'baseline' and 'response_timeout_ms' not in transport
             and 'shutdown_timeout_ms' not in transport, 'transport-profile')
    credentials = {c['sha256']: c for c in config['credentials']}
    need(len(credentials) == 3 and {(c['tenant'], c['principal']) for c in credentials.values()}
         == {('7', '11'), ('7', '12'), ('8', '22')}, 'credential-profile')
    events, sdk = rows(directory / 'events.jsonl'), rows(directory / 'sdk.jsonl')
    need([r['sequence'] for r in events] == list(range(1, len(events) + 1)), 'event-sequence')
    need(all(time_of(a) <= time_of(b) for a, b in zip(events, events[1:])), 'event-order')
    requests, responses = {}, {}
    for row in [*events, *sdk]:
        kind = row['event']
        if kind not in ('http_request', 'http_response'):
            continue
        target = requests if kind == 'http_request' else responses
        need(row['id'] not in target, 'http-duplicate')
        target[row['id']] = row
        body = wire.parse(raw(directory, row['request' if kind == 'http_request' else 'response']))
        row['body'] = body
    expected = {f'setup-{i}' for i in range(1, 8)} | {'a1', 'a2', 'a3', 'b1'} | {
        phase + '-1' for phase in ('tenant-limit', 'global-limit', 'control', 'insert',
                                  'after-disconnect', 'lookup', 'count')}
    need(set(requests) == expected and len(requests) == 18, 'http-denominator')
    need(set(responses) == expected - {'a1'}, 'response-denominator')
    for name, request in requests.items():
        tenant = '8' if name in ('b1', 'global-limit-1', 'setup-6', 'setup-7') else '7'
        need(request['body']['version'] == 1 and request['body']['scope'] == scope(tenant), 'request-scope')
        credential = credentials.get(request['token_sha256'])
        need(credential is not None and credential['tenant'] == tenant, 'request-credential')
        if name == 'tenant-limit-1':
            need(credential['principal'] == '12', 'tenant-principal')
        if name in responses:
            need(time_of(request) < time_of(responses[name]) and responses[name]['complete'] is True, 'response-time')
    for name in ('tenant-limit-1', 'global-limit-1'):
        need(responses[name]['status'] == 413 and responses[name]['body']['ok'] is False
             and responses[name]['body']['error']['code'] == 'LIMIT', 'pressure-limit')
        need(requests[name]['body']['operation'] == 'query', 'pressure-query')
    control = responses['control-1']['body']
    need(responses['control-1']['status'] == 200 and control['ok'] is True
         and control['value']['active'] is True and requests['control-1']['body']['operation'] == 'status',
         'protected-control')
    held = {r['id']: r for r in events if r['event'] == 'slow_headers'}
    need(set(held) == {'a1', 'a2', 'a3', 'b1'}, 'hold-denominator')
    ends = {r['id']: r for r in events if r['event'] in ('slow_drain_started', 'slow_disconnected')}
    need(set(ends) == set(held), 'hold-end-denominator')
    for name, start in held.items():
        header = raw(directory, start['headers']).decode('latin1')
        need(header.startswith('HTTP/1.1 200 ') and '\r\n\r\n' == header[-4:], 'slow-header')
        need(start['body_bytes_read'] == 0 and 4096 <= start['receive_buffer'] <= 16384,
             'slow-consumer')
        need(start['content_length'] > 42 * 1024 * 1024 and start['status'] == 200, 'slow-length')
        need(time_of(requests[name]) < time_of(start) < time_of(ends[name]), 'hold-time')
        need(time_of(start) < time_of(requests['insert-1']) < time_of(responses['insert-1']) < time_of(ends[name]),
             'pressure-held-during-commit')
        if name != 'b1':
            need(time_of(start) < time_of(requests['tenant-limit-1']) < time_of(responses['tenant-limit-1']) < time_of(ends[name]),
                 'tenant-pressure-interval')
        need(time_of(start) < time_of(requests['global-limit-1']) < time_of(responses['global-limit-1']) < time_of(ends[name]),
             'global-pressure-interval')
        need(time_of(start) < time_of(requests['control-1']) < time_of(responses['control-1']) < time_of(ends[name]),
             'protected-control-interval')
        if inputs['profile'] == 'bounded':
            need(time_of(ends[name]) - time_of(start) < 120_000_000_000, 'hold-expired')
        if name != 'a1':
            need(start['content_length'] == responses[name]['response']['bytes'], 'slow-complete-length')
            need(responses[name]['status'] == 200 and responses[name]['body']['ok'] is True, 'slow-success')
            large(responses[name]['body']['value'])
    need(ends['a1']['event'] == 'slow_disconnected' and ends['a1']['method'] == 'TCP_RST'
         and time_of(ends['a1']) < time_of(requests['after-disconnect-1']), 'disconnect-release')
    need(responses['after-disconnect-1']['status'] == 200 and responses['after-disconnect-1']['body']['ok'] is True,
         'release-success')
    large(responses['after-disconnect-1']['body']['value'])
    intent_record = wire.parse((directory / 'intent.json').read_bytes())
    intent = wire.parse(intent_record['serialized'])
    original = requests['insert-1']['body']
    need(int(intent_record['prepared_monotonic_ns']) < time_of(requests['a1']), 'intent-before-pressure')
    need(original['operation'] == 'execute' and original['scope'] == intent['scope']
         and original['request'] == intent['request'] and original['statements'] == intent['statements'], 'original-intent')
    need(original['request']['id'] == '2' and original['request']['principal'] == '11'
         and original['request']['fingerprint'] == wire.fingerprint(original['statements']), 'original-fingerprint')
    inserts = [r for r in requests.values() if r['body']['operation'] == 'execute'
               and r['body']['request'] == original['request']]
    need(len(inserts) == 1, 'sql-not-replayed')
    cbu = responses['insert-1']['body']
    need(responses['insert-1']['status'] == 503 and cbu['ok'] is False
         and cbu['error']['code'] == 'COMMITTED_BUT_UNAVAILABLE', 'committed-knowledge')
    receipt = cbu['error']['receipt']
    need(receipt['scope'] == original['scope'] and receipt['request'] == original['request'], 'committed-receipt')
    lookup = responses['lookup-1']['body']
    need(requests['lookup-1']['body']['operation'] == 'lookup'
         and requests['lookup-1']['body']['request'] == original['request'], 'lookup-original')
    need(responses['lookup-1']['status'] == 200 and lookup['ok'] is True
         and lookup['value']['state'] == 'committed' and lookup['value']['receipt'] == receipt, 'lookup-receipt')
    recovered, decoded = wire.committed(lookup['value'])
    large(lookup['value'])
    need(decoded[0]['affected_rows'] == 1 and decoded[0]['last_insert_rowid'] == 1, 'committed-row-effect')
    count = responses['count-1']['body']
    need(responses['count-1']['status'] == 200 and count['ok'] is True
         and wire.result(wire.b64(count['value']['result']))[0]['rows'] == [[1]], 'single-effect')
    s3 = rows(directory / 'history.jsonl')
    accepted = [r for r in s3 if r['event'] == 'object_response' and r['method'] == 'PUT' and r['status'] == 200]
    need(all(r['response_origin'] == 'backend' and r['suppressed'] is False for r in accepted), 'real-s3-acceptance')
    publications = [r for r in accepted if r['phase'] == 'insert' and r['path'].endswith('/head')]
    need(len(publications) == 1, 'one-business-head-publication')
    publication = publications[0]
    head = wire.parse(bytes(publication['head_request_bytes']))
    need(time_of(requests['insert-1']) < time_of(publication) < time_of(responses['insert-1']), 'publication-time')
    need(head['scope'] == {k: int(v) for k, v in receipt['scope'].items()}
         and head['sequence'] == int(receipt['sequence']) and head['data_root'] == receipt['data_root']
         and head['transition'] == {k: int(v) for k, v in receipt['transition'].items()}, 'head-receipt')
    need(isinstance(publication['if_match'], str) and publication['if_none_match'] is None, 'head-cas')
    reads = [r for r in s3 if r['event'] == 'object_response' and r['method'] == 'GET' and r['status'] == 200
             and r['path'] == publication['path'] and time_of(r) < time_of(publication)
             and r['etag'] == publication['if_match']]
    need(bool(reads), 'original-head-etag')
    result_puts = [r for r in accepted if r['phase'] == 'insert' and r['path'].endswith('/' + receipt['result_hash'])]
    need(len(result_puts) == 1 and result_puts[0]['request_sha256'] == receipt['result_hash']
         and result_puts[0]['if_none_match'] == '*' and result_puts[0]['if_match'] is None, 'durable-result-put')
    result_put = result_puts[0]
    readbacks = [r for r in s3 if r['event'] == 'object_response' and r['method'] == 'GET' and r['status'] == 200
                and r['path'] == result_put['path'] and r['response_sha256'] == receipt['result_hash']
                and result_put['request_bytes'] == r['response_bytes']
                and time_of(result_put) < time_of(r) < time_of(publication)]
    need(bool(readbacks), 'durable-result-readback')
    unsigned = [r for r in events if r['event'] == 'unsigned_probe']
    need(len(unsigned) == 1 and unsigned[0]['status'] == 403, 'signed-backend')
    phases = ('setup', 'tenant-limit', 'global-limit', 'control', 'insert', 'after-disconnect', 'lookup', 'count')
    stopped = [r for r in events if r['event'] == 'node_stopped']
    need(tuple(r['phase'] for r in stopped) == phases and all(r['status'] == 0 and not r['forced']
         and r['usage'].get('source') == 'kernel_wait4_owned_child' for r in stopped), 'sdk-processes')
    service = [r for r in events if r['event'] == 'service_stopped']
    backend = [r for r in events if r['event'] == 'backend_stopped']
    proxy = [r for r in events if r['event'] == 'proxy_stopped']
    need(len(service) == len(backend) == len(proxy) == 1 and service[0]['status'] == 0
         and service[0]['usage'].get('source') == 'kernel_wait4_owned_child'
         and proxy[0]['joined'] is True and proxy[0]['errors'] == [], 'owned-cleanup')
    need(len(backend[0]['processes']) == 4 and all(p['wait_status'] == -9
         and p['kernel_usage'].get('source') == 'kernel_wait4_owned_child' for p in backend[0]['processes']), 'backend-cleanup')
    return {'status': 'PASSED', 'profile': inputs['profile'], 'http_posts': len(requests),
        'complete_responses': len(responses), 'held_responses': 4, 'reset_without_body': 1,
        'tenant_limit': 1, 'global_limit': 1, 'protected_controls': 1, 'business_sql_executions': 1,
        'committed_result_bytes': len(recovered), 'committed_result_sha256': digest(recovered),
        'physical_s3_requests': len([r for r in s3 if r['event'] == 'object_request']),
        'sdk_processes': len(stopped), 'aws_standard': 'NOT_RUN', 'production_slo_passed': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('evidence', type=Path)
    print(json.dumps(audit(parser.parse_args().evidence), sort_keys=True))
