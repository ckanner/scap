#!/usr/bin/env python3
"""Read-only aggregation of the fixed four samples, with original wire checks.

This is a diagnostic reader, not the formal object-load acceptance oracle.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re

from causal import PHASES, module, save, sha


def delta(before, after):
    result = [y - x for x, y in zip(before, after)]
    if len(before) != len(after) or any(value < 0 for value in result):
        raise ValueError('counter shape or monotonicity')
    return result


def wire_audit(directory, source, profile, run):
    module('spec', source / 'experiments/object-load/spec.py')
    reader = module('causal_original_reader', source / 'experiments/object-load/oracle.py')
    need, same, moment = reader.need, reader.same, reader.moment
    history = reader.rows(directory / 's3.jsonl')
    need([row['sequence'] for row in history] == list(range(1, len(history) + 1)), 'sequence')
    groups, cache = defaultdict(list), {}
    for row in history:
        need(row['event'] in ('request', 'forwarded', 'response', 'delivered'), 'unexpected-event')
        groups[row['request_serial']].append(row)
    need(sorted(groups) == list(range(1, run['proxy']['requests'] + 1)), 'exchange-denominator')
    def raw(description):
        key = tuple(sorted(description.items()))
        if key not in cache:
            cache[key] = reader.raw(directory, description)
        return cache[key]
    scope_names = {('7', '101'): 'seq', ('7', '102'): 'same', ('7', '201'): 'm0',
                   ('7', '202'): 'm1', ('8', '301'): 'm2', ('8', '302'): 'm3'}
    requests, responses, results, heads = {}, {}, [], []
    for serial, group in groups.items():
        need([row['event'] for row in group] == ['request', 'forwarded', 'response', 'delivered'], 'exchange')
        request, forwarded, response, delivered = group
        need(moment(request) < moment(forwarded) < moment(response) <= moment(delivered), 'exchange-time')
        for other in group:
            for name in ('phase', 'method', 'path', 'request', 'if_match', 'if_none_match', 'signing'):
                same(other[name], request[name], 'original-request')
        for name in ('status', 'response', 'etag'):
            same(delivered[name], response[name], 'original-response')
        body, returned = raw(request['request']), raw(response['response'])
        match = re.fullmatch(r'/scap-test/scap-object/v1/1/(7|8)/(101|102|201|202|301|302)/(head|inc/1/gen/1/storage/1/objects/[0-9a-f]{64})', request['path'])
        need(match is not None and match.group(1, 2) in scope_names, 'exact-namespace')
        tenant, database = match.group(1, 2)
        scope = {'deployment': 1, 'tenant': int(tenant), 'database': int(database), 'incarnation': 1, 'generation': 1}
        signature = request['signing']
        need({'host', 'x-amz-date', 'x-amz-content-sha256'} <= set(signature['signed_headers'])
             and signature['payload_sha256'] == hashlib.sha256(body).hexdigest(), 'signed-body')
        method, path = request['method'], request['path']
        if method == 'GET':
            need(not body and request['if_match'] is None and request['if_none_match'] is None, 'get-condition')
        else:
            need(method == 'PUT' and ((request['if_match'] is None and request['if_none_match'] == '*')
                 or (isinstance(request['if_match'], str) and request['if_none_match'] is None)), 'put-condition')
        if '/objects/' in path:
            if method == 'PUT':
                need(request['if_match'] is None and request['if_none_match'] == '*', 'immutable-create')
                kind, value, content = reader.frame(body, path, scope)
                if response['status'] == 200 and kind == 'result':
                    results.append((scope, value, content, request, response))
            elif response['status'] == 200:
                reader.frame(returned, path, scope)
        elif method == 'PUT' and response['status'] == 200:
            heads.append((reader.wire.parse(body), request, response))
        normalized = {'monotonic_ns': moment(request), 'phase': request['phase'], 'method': method,
            'path': path, 'request_bytes': len(body), 'request_sha256': hashlib.sha256(body).hexdigest(),
            'if_match': request['if_match'], 'if_none_match': request['if_none_match']}
        normalized_response = {**normalized, 'monotonic_ns': moment(response), 'status': response['status'],
            'response_bytes': len(returned), 'response_sha256': hashlib.sha256(returned).hexdigest(), 'etag': response['etag']}
        if path.endswith('/head'):
            normalized['head_request_bytes'] = list(body)
            normalized_response.update(head_request_bytes=list(body), head_response_bytes=list(returned))
        requests[serial], responses[serial] = normalized, normalized_response
    authority = reader.wire.object_versions(requests, responses)
    for original in profile['originals']:
        saved = reader.wire.parse(original['serialized'])
        scope = {key: int(value) for key, value in saved['scope'].items()}
        identity = {key: (value if key == 'fingerprint' else int(value)) for key, value in saved['request'].items()}
        need(reader.wire.fingerprint(saved['statements']) == identity['fingerprint'], 'original-statement-binding')
        matching = [item for item in results if item[0] == scope and item[1]['request'] == identity]
        need(len(matching) == 1, 'one-original-result')
        _, value, content, put, accepted = matching[0]
        need(content == reader.wire.b64(original['raw']), 'durable-original-bytes')
        publications = [(head, call) for head, call, _ in heads if head['scope'] == scope
                        and head['sequence'] == value['sequence'] and head['transition'] == value['transition']]
        need(len(publications) == 1, 'one-original-head')
        head, publication = publications[0]
        need(head['data_root'] == value['data_root'] and moment(accepted) < moment(publication), 'result-before-head')
        need(any(call['method'] == 'GET' and call['path'] == put['path'] and responses[number]['status'] == 200
                 and responses[number]['response_sha256'] == put['request']['sha256']
                 and moment(accepted) < moment(responses[number]) < moment(publication)
                 for number, call in requests.items()), 'result-readback-before-head')
    phase_counts = {}
    for phase in profile['phases']:
        selected = {number: call for number, call in requests.items() if call['phase'] == phase['phase']}
        counts = Counter(call['method'] for call in selected.values())
        sizes = {'GET': sum(responses[number]['response_bytes'] for number, call in selected.items() if call['method'] == 'GET'),
                 'PUT': sum(call['request_bytes'] for call in selected.values() if call['method'] == 'PUT')}
        for method, name in (('GET', 's3_get'), ('PUT', 's3_put')):
            index = phase['before']['stage_names'].index(name)
            measured = delta(phase['before']['stages'][index], phase['after']['stages'][index])
            need((measured[0], measured[5]) == (counts[method], sizes[method]), 'wire-vs-service-counts')
        phase_counts[phase['phase']] = {'methods': dict(counts), 'body_bytes': sizes}
    return {'status': 'PASSED_DIAGNOSTIC_WIRE_CHECKS', 's3_exchanges': len(groups), 'authority': authority,
            'original_result_put_readback_head_bindings': len(profile['originals']), 'phases': phase_counts,
            'formal_http_ack_interval_binding': 'NOT_CAPTURED_FOR_DIAGNOSTIC'}


def summarize(work):
    order = json.loads((work / 'historical-profile-order-complete.json').read_text())
    output, fingerprints = [], []
    for case in order['order']:
        directory = work / ('historical-profile-' + case['case'])
        profile = json.loads((directory / 'profile.json').read_text())
        run = json.loads((directory / 'run.json').read_text())
        if (run['status'] != 'PASSED_DIAGNOSTIC_OUTCOMES' or run['cleanup_errors'] or not run['source_unchanged']
                or run['service_exit']['code'] != 0 or len(profile['observations']) != 280
                or len(profile['calls']) != 144 or len(profile['originals']) != 112
                or not all(call['ok'] for call in profile['calls'])):
            raise ValueError('sample identity, cleanup or denominator')
        fingerprints.append(sorted((item['request_sha256'], item['bytes']) for item in profile['observations']))
        phases = {}
        for phase in profile['phases']:
            before, after = phase['before'], phase['after']
            names = before['stage_names']
            if names != after['stage_names']:
                raise ValueError('stage identity')
            observer_before, observer_after = phase['observer_before'], phase['observer_after']
            latencies = sorted(call['elapsed_ns'] for call in profile['calls'] if call['phase'] == phase['phase'])
            phases[phase['phase']] = {'calls': phase['count'], 'concurrency': phase['concurrency'],
                'elapsed_ns': phase['elapsed_ns'], 'success_per_second': phase['count'] * 1e9 / phase['elapsed_ns'],
                'latency_ns': {str(percent): latencies[max(0, (len(latencies) * percent + 99) // 100 - 1)] for percent in (50, 95, 99, 100)},
                'service_process_cpu_ns': after['process_cpu_ns'] - before['process_cpu_ns'],
                'service_allocation_calls': after['rust_allocation_calls'] - before['rust_allocation_calls'],
                'service_requested_bytes': after['rust_requested_bytes'] - before['rust_requested_bytes'],
                'service_stage_columns': before['stage_columns'],
                'service_stages': {name: delta(before['stages'][index], after['stages'][index]) for index, name in enumerate(names)},
                'http_connect_started_completed_reused': delta(before['http_connect_started_completed_reused'], after['http_connect_started_completed_reused']),
                'observer_process_cpu_ns': observer_after['process_cpu_ns'] - observer_before['process_cpu_ns'],
                'observer_stage_columns': observer_before['columns'],
                'observer_stages': {name: delta(observer_before['stages'].get(name, [0] * 4), value)
                                    for name, value in observer_after['stages'].items()}}
        output.append({**case, 'source_commit': run['build']['source_commit'], 'binary_sha256': run['build']['binary_sha256'],
            'source_manifest_sha256': run['build']['source_manifest_sha256'], 'profile_sha256': sha(directory / 'profile.json'),
            'run_record_sha256': sha(directory / 'run.json'), 'phases': phases,
            'wire': wire_audit(directory, Path(run['build']['source_root']), profile, run) if case['mode'] == 'evidence'
                    else {'status': 'NOT_CAPTURED_DIRECT_DIAGNOSTIC'}})
    if not all(value == fingerprints[0] for value in fingerprints):
        raise ValueError('workload request-body multiset changed')
    comparisons = {}
    for mode in ('direct', 'evidence'):
        base = next(item for item in output if item['code'] == 'baseline' and item['mode'] == mode)
        proof = next(item for item in output if item['code'] == 'proof' and item['mode'] == mode)
        comparisons[mode] = {phase: {'proof_tps_delta_percent':
            (base['phases'][phase]['elapsed_ns'] / proof['phases'][phase]['elapsed_ns'] - 1) * 100}
            for phase in PHASES}
    return {'schema': 1, 'diagnostic_only': True, 'status': 'FOUR_FIXED_SAMPLES_AUDITED',
            'historical_24_percent_regression': 'UNATTRIBUTED_NOT_CLEARED',
            'production_slo_passed': False, 'aws_standard': 'NOT_RUN',
            'all_280_request_body_multisets_equal': True, 'samples': output, 'comparisons': comparisons,
            'frozen_order_sha256': sha(work / 'historical-profile-order-complete.json'),
            'raw_retention': 'Outside Git; original four samples and every observation retained'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('work', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    value = summarize(args.work.resolve())
    save(args.output, value)
    print(json.dumps({'status': value['status'], 'samples': len(value['samples']),
                      'historical_regression': value['historical_24_percent_regression']}))
