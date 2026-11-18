#!/usr/bin/env python3
"""Read original bytes independently; import no controller, model or product code."""
from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


old = load('dynamic_fixed_history_auditor', HERE.parent / 'object-controller-runtime/oracle.py')
matrix = load('dynamic_matrix_wire_auditor', HERE.parent / 'object-controller-matrix/oracle.py')
wire = old.wire
need, select, one, sha = old.need, old.select, old.one, old.sha


def policy_digest(raw):
    limits = {'scopes': 128, 'workers': 256, 'metadataEndpoints': 4, 'policyBytes': 65536,
        'ticks': 8, 'tenantTicks': 4, 'recoveries': 1, 'httpCalls': 8, 'mutations': 1,
        'requestBytes': 16384, 'responseBytes': 65536, 'headerBytes': 16384,
        'timeoutMs': 30000, 'recoveryTimeoutMs': raw.get('recoveryTimeoutMs', 1800000),
        'probeTimeoutMs': 1000, 'tickIntervalMs': 5000, 'failureCount': 3,
        'failureIntervalMs': 1000, 'failureSpanMs': 5000,
        'backoffMs': [5000, 10000, 20000, 40000, 60000]}
    scope = {key: raw['scope'][key] for key in ('deployment', 'tenant', 'database', 'incarnation', 'generation')}
    workers = [{key: worker[key] for key in ('workerInstance', 'endpoint', 'rank')}
               for worker in sorted(raw['workers'], key=lambda worker: worker['rank'])]
    canonical = {'version': 1, 'scope': scope, 'authorityId': raw['authorityId'],
        'principal': raw['principal'], 'metadataEndpoints': sorted(raw['metadataEndpoints']),
        'workers': workers, 'modes': {key: raw['modes'][key] for key in ('takeover', 'activate', 'cancel')},
        'allowInsecureHttp': raw.get('allowInsecureHttp', False), 'limits': limits}
    retired = raw.get('retiredWorkers', [])
    if retired:
        canonical['retiredWorkers'] = sorted(retired, key=int)
    digest = sha(b'SCAPOWNERPOLICY1\0' + json.dumps(canonical, separators=(',', ':'), ensure_ascii=False).encode())
    words = [str(int(digest[index:index + 16], 16)) for index in range(0, 64, 16)]
    need('0' not in words and len(set(words)) == 4, 'policy-full-nonces')
    return {'digest': digest, 'nonces': dict(zip(('claim', 'cancel', 'activate', 'abort'), words))}


def configurations(events, read, scope):
    records = select(events, 'dynamic_configuration')
    labels = ['initial', 'retire-A', 'retire-B', 'retire-C-register-D', 'D-ready', 'rollback', 'revival']
    need([row['label'] for row in records] == labels, 'complete-dynamic-configurations')
    configs = {row['label']: wire.parse(read(row['config'])) for row in records}
    need([configs[label].get('revision') for label in labels] == ['1', '2', '3', '4', '5', '2', '6'], 'fixed-revision-inputs')
    policies = [configs[label]['scopes'][0]['policy'] for label in labels[:4]]
    endpoints = {row['role']: row['endpoint'] + '/v1' for row in select(events, 'http_proxy_started')}
    need(set(endpoints) == {'A', 'B', 'C'}, 'fixed-http-routes')
    expected = {'scope': scope, 'authorityId': 'controller-runtime-private-s3', 'principal': '12',
        'metadataEndpoints': [endpoints['C']], 'workers': [
            {'workerInstance': '9601', 'endpoint': endpoints['A'], 'rank': 0},
            {'workerInstance': '9602', 'endpoint': endpoints['B'], 'rank': 1}],
        'modes': {'takeover': True, 'activate': True, 'cancel': True},
        'allowInsecureHttp': True, 'recoveryTimeoutMs': 60000}
    need(policies[0] == expected, 'fixed-initial-policy')
    expected = deepcopy(expected)
    expected['workers'].append({'workerInstance': '9603', 'endpoint': endpoints['C'], 'rank': 2})
    expected['retiredWorkers'] = ['9601']
    need(policies[1] == expected, 'fixed-A-retirement')
    expected = deepcopy(expected); expected['retiredWorkers'] = ['9601', '9602']
    need(policies[2] == expected, 'fixed-B-retirement')
    expected = deepcopy(expected)
    expected['workers'].append({'workerInstance': '9604', 'endpoint': endpoints['A'], 'rank': 3})
    expected['retiredWorkers'] = ['9601', '9602', '9603']
    need(policies[3] == expected, 'fixed-C-retirement-and-endpoint-reuse')
    for label, count in zip(labels[:6], [0, 1, 2, 3, 3, 1]):
        value = configs[label]
        need(set(value) == {'version', 'revision', 'scopes'} and value['version'] == 2 and len(value['scopes']) == 1,
             'bounded-config-schema')
        entry = value['scopes'][0]
        need(set(entry) == {'policy', 'previousPolicies', 'tokenEnv'} and
             entry['previousPolicies'] == policies[:count] and entry['policy'] == policies[count]
             and entry['tokenEnv'] == 'SCAP_CONTROLLER_RUNTIME_TOKEN', 'complete-original-policy-history')
    revived = deepcopy(policies[3]); revived['retiredWorkers'].remove('9603')
    need(configs['revival']['scopes'][0] == {'policy': revived, 'previousPolicies': policies,
         'tokenEnv': 'SCAP_CONTROLLER_RUNTIME_TOKEN'}, 'real-revival-attempt')
    return policies, [policy_digest(policy) for policy in policies]


def processes(events, read):
    required = {'service-A', 'service-B', 'service-C', 'service-A-2', 'controller-dynamic',
                'business-initialize', 'business-unknown', 'business-revoke', 'business-verify'}
    starts, stops = select(events, 'child_started'), select(events, 'child_stopped')
    need(len(starts) == len(stops) == 9 and {row['id'] for row in starts} == {row['id'] for row in stops} == required,
         'owned-process-denominator')
    ownership = old.build_audit.OwnedChildren()
    for start in starts:
        stop = one(events, 'child_stopped', id=start['id'])
        need(start['identity'] == stop['identity'] and start['sequence'] < stop['sequence']
             and stop['forced'] is False and stop['crash'] is False and stop['status'] == 0
             and stop['usage']['source'] == 'kernel_wait4_owned_child' and stop['usage']['available'] is True,
             'owned-wait4')
        ownership.register(start['identity'], stop['monotonic_ns']); read(stop['stderr'])
    exited = one(events, 'child_stopped', id='service-A')
    replacement = one(events, 'child_started', id='service-A-2')
    cache = one(events, 'cache_removed')
    created = one(events, 'replacement_cache_created')
    need(cache['id'] == 'service-A' and cache['existed'] and cache['absent'] and
         exited['sequence'] < cache['sequence'] < created['sequence'] < replacement['sequence'] and
         created['empty'] is True and type(created['device']) is int and type(created['inode']) is int,
         'replacement-after-owned-exit-and-private-cache-loss')
    ready = one(events, 'service_ready', id='service-A-2')
    need(ready['worker'] == '9604' and ready['role'] == 'A' and ready['incarnation'] == 2,
         'new-identity-on-original-endpoint')
    backend, stopped = one(events, 'backend_started'), one(events, 'backend_stopped')
    need(len(backend['identities']) == len(stopped['processes']) == 4, 'real-s3-processes')
    for start, stop in zip(backend['identities'], stopped['processes']):
        need(all(stop.get(key) == value for key, value in start.items()) and stop['wait_status'] == -9 and
             stop['kernel_usage']['source'] == 'kernel_wait4_owned_child', 'backend-owned-exit')
    need(one(events, 'unsigned_probe')['status'] == 403, 'unsigned-s3-rejected')
    need(one(events, 'cleanup_finished')['errors'] == [] and one(events, 'private_removed')['absent'], 'complete-cleanup')


def node_sources(directory, events):
    files = {row['path']: row for row in wire.parse((directory / 'source.json').read_bytes())['files']}
    receipt = wire.parse((directory / 'service-build/build-receipt.json').read_bytes())
    matrix.release_source_equivalence(files, receipt['inputs'])
    starts = [row for row in select(events, 'child_started') if not row['id'].startswith('service-')]
    bindings = select(events, 'dynamic_node_source')
    need(len(bindings) == len(starts), 'node-entry-inventory')
    for start in starts:
        bound = one(events, 'dynamic_node_source', id=start['id'])
        expected = ('sdk/node/bin/owner-controller.mjs' if start['id'] == 'controller-dynamic' else
                    'experiments/object-dynamic-fleet-runtime/revoke.mjs' if start['id'] == 'business-revoke' else
                    'experiments/object-controller-runtime/client.mjs')
        path = Path(bound['entry'])
        need(bound['relative'] == expected and start['command'][1] == str(path) and path.is_absolute() and
             bound['sha256'] == files[expected]['sha256'] == old.build_audit.file_digest(path)
             and bound['sequence'] < start['sequence'], 'actual-node-entry-source')
    spec = wire.parse((directory / 'dynamic-inputs.json').read_bytes())
    need(spec['plan'] == 'experiments/object-dynamic-fleet-runtime/PLAN.md' and
         spec['plan_sha256'] == files[spec['plan']]['sha256'] and spec['replacement_worker'] == '9604' and
         spec['whole_seconds'] == 180 and spec['stage_seconds'] == 75, 'fixed-dynamic-plan')


def service_configuration(directory, events, read):
    values = {}
    for name, worker in [('service-A', '9601'), ('service-B', '9602'), ('service-C', '9603'), ('service-A-2', '9604')]:
        recorded = one(events, 'dynamic_service_configuration', id=name)
        started = one(events, 'child_started', id=name)
        raw = read(recorded['config'])
        need(raw == (directory / (name + '.json')).read_bytes() and recorded['path'] == started['command'][1]
             and recorded['sequence'] < started['sequence'], 'actual-service-config-source')
        value = wire.parse(raw)
        need(value['worker_instance'] == worker, 'actual-service-config-identity')
        values[name] = value
    first, second = deepcopy(values['service-A']), deepcopy(values['service-A-2'])
    old_cache, new_cache = first.pop('cache_directory'), second.pop('cache_directory')
    first.pop('worker_instance'); second.pop('worker_instance')
    need(first == second and old_cache != new_cache and one(events, 'cache_removed')['path'] == old_cache and
         one(events, 'replacement_cache_created')['path'] == new_cache, 'same-endpoint-new-private-process')


def fixed_owner_recipes(mutations, commitments):
    need(Counter(call['body']['operation'] for call in mutations) == {
        'owner_prepare': 3, 'owner_claim': 3, 'owner_resume': 2, 'owner_abort': 1}, 'fixed-owner-mutation-denominator')
    prepares = [call for call in mutations if call['body']['operation'] == 'owner_prepare']
    originals = {}
    for call, target, policy in zip(prepares, ['9602', '9603', '9604'], commitments[1:]):
        value = call['value']['value']; original = call['body']['input']
        need(original['creator'] == '12' and original['operation'] == original['expected_head_serial'] and
             original['mode'] == 'takeover' and original['target_worker'] == target and
             original['nonces'] == policy['nonces'], 'prepare-exact-current-policy')
        originals[target] = value['prepared']
    for call in mutations:
        name = call['body']['operation']
        if name == 'owner_prepare':
            continue
        value = call['value']['value']; target = value['prepared']['input']['target_worker']
        need(target in originals and value['prepared'] == originals[target] and
             call['body']['plan'] == originals[target]['reference'], 'original-recipe-never-rebased')
        if name in ('owner_claim', 'owner_resume'):
            need(call['body'].get('expected_worker_instance') == target, 'original-target-guard')
        if name == 'owner_resume':
            need(target in ('9603', '9604'), 'retired-target-never-resumed')
        if name == 'owner_abort':
            need(target == '9602', 'original-retired-plan-aborted')
    return originals


def controller_history(events, calls, heads, descriptors, policies, commitments, read, scope):
    controllers = [call for call in calls if call['request']['principal'] == '12']
    need(bool(controllers) and all(call['body']['operation'] in matrix.ALLOWED for call in controllers), 'controller-never-sql')
    mutations = [call for call in controllers if call['body']['operation'] in matrix.MUTATIONS]
    originals = fixed_owner_recipes(mutations, commitments)
    for call in controllers:
        if matrix.successful(call):
            if call['body']['operation'] == 'status':
                matrix.observed_status(call, call['value']['value'], heads)
            else:
                matrix.owner_observation(call, descriptors, heads, scope)
    cut = one(events, 'http_proxy_delivery_suppressed', id='claim-ack-loss')
    lost = next(call for call in mutations if call['body']['operation'] == 'owner_claim')
    need((lost['request']['role'], lost['request']['serial']) == (cut['role'], cut['serial']) and
         lost['value']['value']['state'] == 'claimed', 'original-B-claim-ack-loss')
    mismatch = [call for call in controllers if call['request']['phase'] == 'endpoint-mismatch']
    need(any(matrix.error_code(call) == 'TARGET_MISMATCH' and call['body'].get('expected_worker_instance') == '9604'
             for call in mismatch) and all(call['body']['operation'] not in matrix.MUTATIONS for call in mismatch),
         'mismatch-blocks-with-original-new-guard')
    for phase in ('rollback-rejected', 'revival-rejected'):
        need(not any(call['request']['phase'] == phase for call in mutations), 'rejected-reload-no-mutation')
    denied = [call for call in controllers if call['request']['phase'] == 'authority-revoked']
    need(any(matrix.error_code(call) == 'DENIED' for call in denied) and
         all(call['body']['operation'] not in matrix.MUTATIONS for call in denied), 'revocation-blocks-mutation')
    accepted = [row for row in heads if row['request']['method'] == 'PUT']
    need(accepted[-1]['head']['owner_instance'] == 9604 and accepted[-1]['head']['owner_epoch'] == 4 and
         accepted[-1]['head']['active'] and accepted[-1]['head']['sequence'] == 3, 'final-original-data-on-new-owner')
    for target, epoch in [('9602', 2), ('9603', 3), ('9604', 4)]:
        group = [row for row in accepted if (row['head'].get('owner_plan') or {}).get('reference') ==
                 {key: int(value) if key != 'descriptor_hash' else value for key, value in originals[target]['reference'].items()}]
        need(group and all(row['head']['owner_instance'] == int(target) and row['head']['owner_epoch'] == epoch
                           for row in group), 'monotonic-owner-epochs')
    reports_ref = one(events, 'controller_reports', id='controller-dynamic')['raw']
    need(reports_ref == one(events, 'child_stopped', id='controller-dynamic')['stderr'], 'original-controller-output')
    raw = read(reports_ref)
    need(raw.endswith(b'\n'), 'complete-controller-output')
    reports = [wire.parse(line) for line in raw.splitlines()]
    reloads = [row for row in reports if row.get('event') == 'fleet_reloaded']
    rejected = [row for row in reports if row.get('event') == 'fleet_reload_rejected']
    need([row['revision'] for row in reloads] == ['2', '3', '4', '5'] and
         len(rejected) == 2 and all(row['revision'] == '5' for row in rejected), 'monotonic-successful-reloads')
    ticks = [row for row in reports if 'state' in row]
    need(sum(row['httpCalls'] for row in ticks) == len(controllers) and
         sum(row['mutations'] for row in ticks) == len(mutations) and
         all(0 <= row['httpCalls'] <= 8 and 0 <= row['mutations'] <= 1 for row in ticks), 'complete-tick-call-budget')
    unknowns = [row for row in ticks if row['state'] == 'unknown']
    need(len(unknowns) == 1 and unknowns[0]['lastUncertainCall']['operation'] == 'owner_claim', 'one-original-controller-unknown')
    original_unknown = unknowns[0]['lastUncertainCall']
    uncertain = False
    for row in ticks:
        uncertain |= row is unknowns[0]
        need(not uncertain or (row['pastUnknown'] and row['lastUncertainCall'] == original_unknown), 'unknown-survives-all-reloads')
        need(row['nativeSession'] == 'NOT_CERTIFIED', 'reports-do-not-manufacture-native-authority')
    return {'controller_http_calls': len(controllers), 'controller_reports': len(ticks), 'mutations': len(mutations),
            'original_recipes': originals, 'reports': reports}


def authority_revocation(calls, business):
    revoked = one(business, 'controller_authority_revoked')
    changes = [call for call in calls if call['body']['operation'] == 'policy' and call['request']['phase'] == 'authority-revoked']
    need(len(changes) == 1 and changes[0]['body']['permissions'] == [
        {'principal': '11', 'read': True, 'write': True, 'admin': True}] and
        changes[0]['value']['value']['revision'] == revoked['revision'], 'real-controller-authority-revocation')


def audit_history(directory, events, business, ledger, read):
    inputs = wire.parse((directory / 'inputs.json').read_bytes())
    processes(events, read)
    service_configuration(directory, events, read)
    policies, commitments = configurations(events, read, inputs['scope'])
    calls = matrix.http_exchanges(events, read)
    exchanges, heads, descriptors = matrix.s3_exchanges(events, read, inputs['scope'])
    controllers = controller_history(events, calls, heads, descriptors, policies, commitments, read, inputs['scope'])
    http = [call['request'] for call in calls]
    responses = {(call['request']['role'], call['request']['serial']): call['value'] for call in calls if call['response']}
    old.business(directory, events, http, responses, business, ledger, read)
    authority_revocation(calls, business)
    summary = wire.parse((directory / 'summary.json').read_bytes())
    need(summary['status'] == 'OBSERVED_NOT_AUDITED' and summary['cleanup_errors'] == [] and
         0 < summary['elapsed_seconds'] < 180, 'complete-bounded-actual')
    return {'status': 'PASS_DYNAMIC_TRUSTED_FLEET', 'services': 4, 'controller_processes': 1,
        'controller_http_calls': controllers['controller_http_calls'], 'controller_reports': controllers['controller_reports'],
        'owner_mutations': controllers['mutations'], 'http_requests': len(calls), 's3_requests': len(exchanges),
        'reloads': 4, 'rejected_reloads': 2, 'original_sql_requests': 3, 'original_client_acks': 2,
        'preserved_business_unknowns': 1, 'preserved_controller_unknowns': 1, 'cold_original_lookups': 3,
        'independent_distributed_registry': 'NOT_IMPLEMENTED', 'aws_standard': 'NOT_RUN', 'production_slo': 'NOT_RUN'}


def audit(directory):
    directory = Path(directory)
    events = old.read_rows(directory / 'events.jsonl')
    need([row['sequence'] for row in events] == list(range(1, len(events) + 1)), 'complete-event-sequence')
    old.sources(directory, events); node_sources(directory, events)
    return audit_history(directory, events, old.read_rows(directory / 'business.jsonl'),
        old.read_rows(directory / 'http-client-ledger.jsonl'), lambda ref: old.raw_file(directory, ref))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('evidence', type=Path)
    print(json.dumps(audit(parser.parse_args().evidence), sort_keys=True))
