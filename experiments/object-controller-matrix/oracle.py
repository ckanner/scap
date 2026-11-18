#!/usr/bin/env python3
"""Independent controller matrix audit from original HTTP, S3 and process bytes.

No controller, fixture scheduler, model or product validator is imported. CLI
reports are checked for consistency; they never establish accepted authority.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import tarfile

HERE = Path(__file__).resolve().parent
CASES = (
    'C1_same_policy_prepare_restart', 'C2_same_creator_policy',
    'C2_different_creators', 'C2_manual_marker', 'C3_claimed_abort',
    'C3_cancelling_restart', 'C3_healthy_original', 'C4_revoked_authority',
    'C4_worker_mismatch', 'C4_resource_refusal', 'C4_s3_unavailable',
    'C5_shutdown_deadline',
)
MUTATIONS = frozenset(('owner_prepare', 'owner_claim', 'owner_resume', 'owner_abort'))
ALLOWED = MUTATIONS | {'status', 'owner_inspect'}
ERROR_STATUS = {
    'UNAUTHENTICATED': 401, 'DENIED': 403, 'NOT_FOUND': 404,
    'INVALID': 400, 'VERSION': 400, 'CURSOR_INVALID': 400, 'LIMIT': 413,
    'BACKPRESSURE': 429, 'RECOVERY_BUSY': 429,
    'UNKNOWN': 503, 'UNAVAILABLE': 503, 'DEADLINE': 503, 'COMMITTED_BUT_UNAVAILABLE': 503,
    **dict.fromkeys(('LIFECYCLE', 'FENCED', 'CONFLICT', 'TARGET_MISMATCH', 'REQUEST_CONFLICT',
        'WINDOW_FULL', 'CLOSED', 'RETIRED', 'MISSING', 'CORRUPT', 'IDENTITY_CONFLICT',
        'STALE_SNAPSHOT', 'ENGINE', 'CONFIG', 'CACHE_IO', 'SNAPSHOT_EXPIRED', 'GC_DISABLED',
        'GC_UNSUPPORTED'), 409),
}


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


wire = load('controller_matrix_wire_auditor', HERE.parent / 'object-service/audit_wire.py')
build_audit = load('controller_matrix_build_auditor', HERE.parent / 'object-network/audit_build.py')


class Rejected(ValueError):
    pass


def need(condition, guard):
    if not condition:
        raise Rejected(guard)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def select(rows, event, **fields):
    return [row for row in rows if row['event'] == event
            and all(row.get(key) == value for key, value in fields.items())]


def one(rows, event, **fields):
    values = select(rows, event, **fields)
    need(len(values) == 1, 'one-' + event)
    return values[0]


def read_rows(path):
    raw = Path(path).read_bytes()
    need(bool(raw) and raw.endswith(b'\n'), 'complete-ledger')
    return [wire.parse(line) for line in raw.splitlines()]


def raw_file(directory, ref):
    need(isinstance(ref, dict) and set(ref) == {'file', 'bytes', 'sha256'}, 'raw-fields')
    digest = ref['sha256']
    need(isinstance(digest, str) and re.fullmatch('[0-9a-f]{64}', digest)
         and ref['file'] == 'raw/' + digest, 'raw-path')
    path = directory / ref['file']
    need(path.is_file() and not path.is_symlink(), 'raw-file')
    raw = path.read_bytes()
    need(type(ref['bytes']) is int and len(raw) == ref['bytes'] and sha(raw) == digest, 'raw-hash')
    return raw


def public(value):
    if isinstance(value, dict):
        return {key: public(item) for key, item in value.items()}
    if isinstance(value, list):
        return [public(item) for item in value]
    return str(value) if type(value) is int else value


def projection(head):
    """Independent public status projection, using the actual S3 HEAD bytes."""
    result = {key: str(head[key]) for key in ('revision', 'head_serial', 'sequence',
              'owner_epoch', 'owner_instance', 'auth_epoch', 'request_epoch')}
    storage = head['storage']
    need(storage['plan'] is None and storage['sweep'] is None and storage.get('terminal') is None,
         'matrix-no-storage-maintenance')
    result.update(scope=public(head['scope']), owner_plan=public(head.get('owner_plan')),
        active=head['active'], lifecycle=head['lifecycle'], transition=public(head['transition']),
        max_bytes=None if head['quota']['max_bytes'] is None else str(head['quota']['max_bytes']),
        retention={'max_entries': head['retention']['max_entries'],
                   'max_result_bytes': str(head['retention']['max_result_bytes']),
                   'oldest_epoch': str(head['windows'][-1]['epoch'])},
        storage={'active_generation': str(storage['active_generation']),
                 'allocated_through': str(storage['allocated_through']),
                 'plan': None, 'sweep': None, 'terminal': None})
    return result


def policy_digest(raw):
    """Reconstruct the published policy commitment without using the SDK."""
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
    digest = sha(b'SCAPOWNERPOLICY1\0' + json.dumps(canonical, separators=(',', ':'), ensure_ascii=False).encode())
    words = [str(int(digest[index:index + 16], 16)) for index in range(0, 64, 16)]
    need('0' not in words and len(set(words)) == 4, 'policy-full-nonces')
    return digest, dict(zip(('claim', 'cancel', 'activate', 'abort'), words))


def release_source_inputs(files):
    """Derive the complete service-build input set from the captured source.

    These are the fixed rules of object-service/build.py, independently
    expressed here. Do not import that builder or trust a historical file
    count: a new eligible file must also occur in the original build receipt.
    The caller has verified every captured file against source.tar first.
    """
    roots = {'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml'}
    need(roots <= files.keys(), 'release-required-root-inputs')
    directories = ('crates/', 'sdk/node/', 'sdk/node-codec/',
                   'experiments/object-service/', 'experiments/object-network/')
    suffixes = {'.rs', '.py', '.js', '.mjs', '.ts'}
    names = {'Cargo.toml', 'Cargo.lock', 'package.json'}
    expected = {}
    for name, record in files.items():
        need(isinstance(name, str) and bool(name), 'release-source-path')
        path = PurePosixPath(name)
        need(bool(path.parts) and not path.is_absolute() and path.as_posix() == name
             and '..' not in path.parts, 'release-source-path')
        if name in roots or (name.startswith(directories)
                             and (path.suffix in suffixes or path.name in names)):
            expected[name] = record['sha256']
    return expected


def release_source_equivalence(files, observed):
    need(observed == release_source_inputs(files), 'release-source-equivalence')


def sources(directory, events):
    inputs = wire.parse((directory / 'inputs.json').read_bytes())
    source = wire.parse((directory / 'source.json').read_bytes())
    files = source['files']
    expected = {row['path']: row for row in files}
    need(len(expected) == len(files) and source['commit'] == inputs['source_commit'], 'source-commit')
    fingerprint = sha(json.dumps(files, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode())
    need(fingerprint == source['source_sha256'] == inputs['source_sha256'], 'source-fingerprint')
    need(inputs['plan_sha256'] == expected['experiments/object-controller-matrix/PLAN.md']['sha256'], 'fixed-plan')
    javascript = {path: row['sha256'] for path, row in expected.items()
        if path.startswith(('sdk/node/', 'sdk/node-codec/')) or path in (
            'experiments/object-controller-matrix/client.mjs',
            'experiments/object-service/client_ledger.mjs',
            'experiments/object-service/client_transport.mjs')}
    need(inputs.get('javascript_inputs') == javascript and
         isinstance(inputs.get('source_root'), str) and Path(inputs['source_root']).is_absolute(),
         'javascript-source-manifest')
    need(inputs.get('node_environment') == {'node_options': 'absent',
         'node_path': 'unset-for-owned-node-children'}, 'fixed-node-environment')
    need(sha((directory / 'source.tar').read_bytes()) == inputs['source_archive_sha256'], 'source-archive')
    with tarfile.open(directory / 'source.tar') as archive:
        members = archive.getmembers()
        need(len(members) == len(files) and {member.name for member in members} == set(expected), 'source-inventory')
        for member in members:
            need(member.isfile(), 'source-regular')
            raw = archive.extractfile(member).read()
            original = expected[member.name]
            need(len(raw) == original['bytes'] and sha(raw) == original['sha256'] and
                 hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == original['git_blob'],
                 'source-bytes')
    receipt = build_audit.receipt(directory / 'service-build', profile='service')
    need(receipt['binary'] == inputs['tools']['scapd'], 'actual-release-binary')
    original = wire.parse((directory / 'service-build/build-receipt.json').read_bytes())
    release_source_equivalence(expected, original['inputs'])
    need(inputs['node_version'] == 'v22.16.0', 'fixed-node-version')
    for tool in inputs['tools'].values():
        path = Path(tool['path'])
        need(path.is_file() and build_audit.file_digest(path) == tool['sha256'], 'actual-tool-bytes')
    after = one(events, 'source_verified')
    need(after['commit'] == source['commit'] and after['source_sha256'] == fingerprint, 'source-unchanged')
    return inputs


def fixed_inputs(directory, inputs):
    identifier = inputs.get('case_id')
    need(identifier in CASES, 'fixed-case-id')
    index = CASES.index(identifier)
    expected = {'version': 1, 'case_id': identifier,
        'scope': {'deployment': '1', 'tenant': '7', 'database': str(8701 + index),
                  'incarnation': '1', 'generation': '1'},
        'workers': {'A': 9601, 'B': 9602, 'C': 9603, 'M': 9605},
        'limits': {'tick_ms': 5000, 'failure_count': 3, 'failure_interval_ms': 1000,
            'failure_span_ms': 5000, 'probe_ms': 1000, 'tick_deadline_ms': 30000,
            'recovery_deadline_ms': 60000, 'http_per_tick': 8, 'mutation_per_tick': 1,
            'stage_seconds': 75, 'business_seconds': 45, 'post_fault_reports': 2},
        'whole_seconds': 240 if identifier in ('C1_same_policy_prepare_restart', 'C3_claimed_abort') else 180,
        'sql_requests': 3, 'client_acks': 2, 'business_unknowns': 1, 'snapshots': 1,
        'source_authority': 'signed-local-s3',
        'worker_b_actual': 9604 if identifier == 'C4_worker_mismatch' else 9602,
        'zero_recovery_budget': identifier == 'C4_resource_refusal',
        'control_intake_occupant': identifier == 'C4_resource_refusal',
        'metadata_s3_timeout_ms': 15000 if identifier == 'C4_resource_refusal' else 5000,
        'metadata_routes': 2 if identifier == 'C4_s3_unavailable' else 1,
        'three_rank_workers': identifier in ('C1_same_policy_prepare_restart', 'C2_same_creator_policy')}
    raw = (directory / 'scenario.json').read_bytes()
    need(wire.parse(raw) == expected and sha(raw) == inputs['scenario_sha256'] and
         all(inputs.get(key) == value for key, value in expected.items()), 'fixed-scenario')
    return identifier


def node_source_binding(start, events, inputs):
    """Bind the real interpreter entry and its closed first-party input set."""
    binding = one(events, 'node_source_bound', id=start['id'])
    relative = ('sdk/node/bin/owner-controller.mjs' if start['id'].startswith('controller-')
                else 'experiments/object-controller-matrix/client.mjs')
    expected = str(Path(inputs['source_root']) / relative)
    need((start['id'].startswith('controller-') or start['id'].startswith('business-')) and
         len(start['command']) >= 2 and start['command'][1] == expected == binding.get('entrypoint') and
         binding.get('source_root') == inputs['source_root'], 'production-node-entrypoint')
    need(binding.get('source_sha256') == inputs['source_sha256'] and
         binding.get('javascript_inputs') == inputs['javascript_inputs'] and
         binding.get('entrypoint_sha256') == inputs['javascript_inputs'].get(relative), 'actual-node-source-inputs')
    need(binding.get('runtime_options_absent') is True, 'bound-node-runtime-options')
    need(binding['sequence'] < start['sequence'], 'node-source-before-spawn')


def processes(events, read, inputs):
    starts, stops = select(events, 'child_started'), select(events, 'child_stopped')
    need(bool(starts) and len(starts) == len(stops) and
         len({row['id'] for row in starts}) == len(starts) and
         {row['id'] for row in starts} == {row['id'] for row in stops}, 'owned-process-denominator')
    ownership = build_audit.OwnedChildren()
    bindings = select(events, 'node_source_bound')
    expected_node_ids = {row['id'] for row in starts if not row['id'].startswith('service-')}
    need(len(bindings) == len(expected_node_ids) and {row['id'] for row in bindings} == expected_node_ids,
         'node-source-inventory')
    for start in starts:
        stop = one(events, 'child_stopped', id=start['id'])
        need(start['identity'] == stop['identity'] and start['sequence'] < stop['sequence']
             and stop['forced'] is False and stop['usage']['source'] == 'kernel_wait4_owned_child'
             and stop['usage']['available'] is True, 'owned-wait4')
        ownership.register(start['identity'], stop['monotonic_ns'])
        need(stop['status'] == (-9 if stop['crash'] else 0), 'owned-process-outcome')
        tool = inputs['tools']['scapd' if start['id'].startswith('service-') else 'node']
        need(start['command'][0] == tool['path'] and start['executable_sha256'] == tool['sha256'], 'actual-owned-executable')
        if not start['id'].startswith('service-'):
            node_source_binding(start, events, inputs)
        read(stop['stderr'])
    for cache in select(events, 'cache_removed'):
        stop = one(events, 'child_stopped', id=cache['id'])
        need(cache['existed'] and cache['absent'] and stop['sequence'] < cache['sequence'], 'cache-loss-after-owned-exit')
    backend, stopped = one(events, 'backend_started'), one(events, 'backend_stopped')
    need(backend['binary'] == inputs['tools']['weed'] and
         len(backend['identities']) == len(stopped['processes']) == 4, 'actual-s3-processes')
    for start, stop in zip(backend['identities'], stopped['processes']):
        need(all(stop.get(key) == value for key, value in start.items()) and stop['wait_status'] == -9
             and stop['kernel_usage']['source'] == 'kernel_wait4_owned_child', 'backend-owned-exit')
    need(one(events, 'unsigned_probe')['status'] == 403, 'unsigned-s3-rejected')
    need(one(events, 'cleanup_finished')['errors'] == [] and one(events, 'private_removed')['absent'], 'complete-cleanup')
    return starts, stops


def http_exchanges(events, read):
    requests = select(events, 'http_proxy_request')
    need(bool(requests) and len({(r['role'], r['serial']) for r in requests}) == len(requests), 'http-unique-requests')
    calls = []
    for request in requests:
        fields = {key: request[key] for key in ('role', 'serial')}
        need(request['sequence'] < one(events, 'http_proxy_handler_finished', **fields)['sequence'], 'closed-http-handler')
        body = wire.parse(read(request['request']))
        need(body['operation'] == request['operation'], 'http-original-operation')
        responses = select(events, 'http_proxy_backend_response', **fields)
        failures = select(events, 'http_proxy_backend_failure', **fields)
        cuts = [row for row in select(events, 'http_proxy_delivery_suppressed', **fields)
                if row['stage'] == 'before_forward']
        need(len(responses) + len(failures) + len(cuts) == 1, 'closed-http-backend')
        if cuts:
            need(request['operation'] == 'status' and request['principal'] in ('12', '13')
                 and not select(events, 'http_proxy_forward_started', **fields), 'bounded-real-probe-cut')
        response = responses[0] if responses else None
        value = None if response is None else wire.parse(read(response['response']))
        if response:
            need(request['sequence'] < response['sequence'], 'http-response-order')
            need(isinstance(value, dict) and type(value.get('ok')) is bool, 'original-http-envelope')
            if value['ok']:
                need(set(value) == {'ok', 'value'} and response['status'] == 200, 'original-http-success-status')
            else:
                error = value.get('error')
                need(set(value) == {'ok', 'error'} and isinstance(error, dict) and
                     isinstance(error.get('code'), str) and error['code'] in ERROR_STATUS and
                     response['status'] == ERROR_STATUS[error['code']], 'original-http-error-status')
            delivered = select(events, 'http_proxy_delivery_finished', **fields)
            suppressed = select(events, 'http_proxy_delivery_suppressed', **fields)
            need(len(delivered) + len(suppressed) == 1, 'closed-http-delivery')
        calls.append({'request': request, 'body': body, 'response': response, 'value': value,
                      'failure': failures[0] if failures else None, 'cut': cuts[0] if cuts else None})
    closed = select(events, 'http_proxy_closed')
    need(bool(closed) and len({row['role'] for row in closed}) == len(closed), 'http-listener-inventory')
    need(all(row['joined'] and row['errors'] == [] and row['request_count'] ==
         len([request for request in requests if request['role'] == row['role']]) for row in closed), 'http-listener-closure')
    need(not select(events, 'http_proxy_fixture_error'), 'no-http-observer-errors')
    return calls


def s3_exchanges(events, read, scope):
    requests = select(events, 's3_request')
    need(bool(requests) and all(row['signature_valid'] is True for row in requests), 'actual-s3-signatures')
    keys = {(row['role'], row['serial']) for row in requests}
    need(len(keys) == len(requests), 's3-unique-requests')
    for event in ('s3_handler_started', 's3_handler_finished'):
        rows = select(events, event)
        need(len(rows) == len(requests) and {(row['role'], row['serial']) for row in rows} == keys, 'closed-s3-handlers')
    exchanges, heads, descriptors, candidates = [], [], {}, []
    head_key = '/scap-test/scap-object/v1/{deployment}/{tenant}/{database}/head'.format(**scope)
    for request in requests:
        fields = {key: request[key] for key in ('role', 'serial')}
        responses = select(events, 's3_backend_response', **fields)
        suppressed = select(events, 'fault_suppressed', **fields)
        need(len(responses) <= 1 and (len(responses) == 1 or len(suppressed) == 1), 'closed-s3-backend')
        raw = read(request['request'])
        need(request['method'] in ('GET', 'PUT'), 'matrix-no-delete')
        if request['method'] == 'PUT':
            headers = request['headers']
            need(bool(headers.get('if-match')) != bool(headers.get('if-none-match')), 'conditional-s3-put')
            if request['path'] != head_key:
                need(headers.get('if-none-match') == '*', 'immutable-conditional-create')
            else:
                head = wire.parse(raw)
                need(public(head['scope']) == scope, 'head-full-scope')
                candidates.append({'request': request, 'head': head, 'raw': raw})
        response = responses[0] if responses else None
        if response:
            need(request['sequence'] < response['sequence'], 's3-response-order')
            data = read(response['response'])
            deliveries = select(events, 's3_delivery_finished', **fields)
            need(len(deliveries) + len(suppressed) == 1, 'closed-s3-delivery')
            if response['status'] in (200, 201, 204):
                body = raw if request['method'] == 'PUT' else data
                if request['path'] == head_key:
                    head = wire.parse(body)
                    need(public(head['scope']) == scope, 'head-full-scope')
                    heads.append({'request': request, 'response': response, 'head': head,
                                  'raw': body, 'etag': response['headers'].get('etag')})
                if '/owner/v1/descriptor/' in request['path']:
                    descriptor = wire.parse(body)
                    need(public(descriptor['scope']) == scope and descriptor['version'] == 1, 'descriptor-full-scope')
                    digest = sha(body)
                    prior = descriptors.get(request['path'])
                    need(prior is None or prior['raw'] == body, 'immutable-first-winner')
                    occurrence = {'request': request, 'response': response}
                    descriptors[request['path']] = {'raw': body, 'hash': digest, 'record': descriptor,
                        'occurrences': ([] if prior is None else prior['occurrences']) + [occurrence]}
        exchanges.append({'request': request, 'response': response})
    need(bool(heads), 'actual-head-authority')
    # A rejected 412 candidate still needs its own original GET and unchanged
    # condition. Rejection alone says nothing about whether it was rebased.
    for item in candidates:
        original_head_candidate(item, heads)
    accepted = [value for value in heads if value['request']['method'] == 'PUT']
    need(len({value['head']['head_serial'] for value in accepted}) == len(accepted), 'one-successful-head-per-serial')
    closed = select(events, 's3_proxy_stopped')
    need(bool(closed) and len({row['role'] for row in closed}) == len(closed) and
         all(row['joined'] and row['errors'] == [] and row['request_count'] ==
             len([request for request in requests if request['role'] == row['role']]) for row in closed), 's3-listener-closure')
    need(not select(events, 's3_fixture_error') and not select(events, 'fault_body_replaced'), 'no-s3-observer-errors')
    wire.closed_worker_claims(events, read, one(events, 'backend_started')['normal_access_sha256'], check=need)
    return exchanges, heads, descriptors


def original_head_candidate(item, heads):
    request, head = item['request'], item['head']
    condition = request['headers'].get('if-match')
    if condition:
        previous = [value for value in heads if value['request']['method'] == 'GET'
                    and value['request']['role'] == request['role'] and value['etag'] == condition
                    and value['response']['sequence'] < request['sequence']]
        need(bool(previous), 'head-original-exact-get')
        need(all(value['raw'] == previous[0]['raw'] for value in previous), 'etag-no-aba')
        need(head['head_serial'] == previous[0]['head']['head_serial'] + 1, 'head-original-next-serial')
    else:
        need(request['headers'].get('if-none-match') == '*' and head['head_serial'] == 1, 'head-initial-absent')


def late_same_candidate(request, winner):
    need(request['headers'].get('if-match') == winner['request']['headers'].get('if-match') and
         request['request'] == winner['request']['request'], 'late-original-candidate-unchanged')


def successful(call):
    return (call['response'] is not None and call['response']['status'] == 200 and
            isinstance(call['value'], dict) and call['value'].get('ok') is True)


def error_code(call):
    value = call['value']
    return value.get('error', {}).get('code') if isinstance(value, dict) and value.get('ok') is False else None


def observed_status(call, value, heads):
    need(isinstance(value, dict), 'actual-http-status-shape')
    matches = [item for item in heads if item['request']['role'] == call['request']['role'] and
               call['request']['sequence'] < item['request']['sequence'] and
               item['response']['sequence'] < call['response']['sequence'] and projection(item['head']) == value]
    need(bool(matches), 'http-status-from-original-s3')
    return matches[-1]['head']


def owner_observation(call, descriptors, heads, scope):
    """An owner observation is accepted only with its real descriptor and HEAD."""
    need(successful(call), 'real-owner-http-success')
    value = call['value']['value']
    prepared = value.get('prepared')
    need(isinstance(prepared, dict) and prepared.get('scope') == scope, 'original-owner-scope')
    reference = prepared.get('reference')
    need(isinstance(reference, dict), 'original-owner-reference')
    path = ('/scap-test/scap-object/v1/{deployment}/{tenant}/{database}/inc/{incarnation}'
            '/gen/{generation}/owner/v1/descriptor/{creator}/{operation}').format(**scope, **reference)
    original = descriptors.get(path)
    need(original is not None and reference.get('descriptor_hash') == original['hash'] and
         prepared.get('input') == public(original['record']['input']), 'original-owner-descriptor')
    occurrences = original['occurrences']
    need(any(item['request']['method'] == 'PUT' and item['response']['sequence'] < call['response']['sequence']
             for item in occurrences) and any(item['request']['method'] == 'GET' and
             item['request']['role'] == call['request']['role'] and
             call['request']['sequence'] < item['request']['sequence'] < item['response']['sequence'] < call['response']['sequence']
             for item in occurrences), 'descriptor-persisted-and-read-before-http')
    request = call['body']
    if request['operation'] == 'owner_prepare':
        need(request['input'] == prepared['input'], 'prepare-first-winner-input')
    if request['operation'] in ('owner_claim', 'owner_resume', 'owner_abort'):
        need(request['plan'] == reference, 'mutation-original-reference')
    if request['operation'] in ('owner_claim', 'owner_resume'):
        need(request.get('expected_worker_instance') == prepared['input']['target_worker'], 'owner-actual-target-guard')
    state = value.get('state')
    need(state in ('prepared', 'claimed', 'cancelling', 'active', 'aborted', 'fenced'), 'known-owner-observation')
    if state == 'prepared' and request['operation'] == 'owner_prepare':
        need(set(value) == {'state', 'prepared'}, 'prepared-response-fields')
        return value
    status = value.get('status')
    actual = observed_status(call, status, heads)
    accepted = value.get('accepted')
    if state == 'prepared':
        need(accepted is None, 'unaccepted-prepared-observation')
    if accepted is not None:
        need(accepted.get('reference') == reference, 'accepted-original-reference')
        phase, admission, fixed = accepted['phase'], accepted['admission'], prepared['input']
        need(admission['kind'] in ('claim', 'cancel') and
             admission['revision'] == str(int(fixed['expected_revision']) + 1) and
             admission['head_serial'] == str(int(fixed['expected_head_serial']) + 1), 'accepted-original-admission')
        kind = phase['kind']
        need(kind in ('claimed', 'cancelling', 'active', 'aborted'), 'accepted-known-phase')
        nonce = {'claimed': 'claim', 'cancelling': 'cancel', 'active': 'activate', 'aborted': 'abort'}[kind]
        need(phase['nonce'] == fixed['nonces'][nonce], 'accepted-original-nonce')
        if state in ('claimed', 'cancelling', 'active', 'aborted'):
            need(kind == state and status['owner_plan'] == accepted, 'accepted-current-marker')
            need(status['owner_instance'] == phase['owner_instance'] and status['owner_epoch'] == phase['owner_epoch']
                 and status['revision'] == phase['revision'] and status['head_serial'] == phase['head_serial']
                 and status['transition'] == {'revision': phase['revision'], 'nonce': phase['nonce']},
                 'accepted-current-authority')
            need(status['active'] is (state == 'active'), 'real-active-authority')
            if state in ('active', 'claimed'):
                need(phase['owner_instance'] == fixed['target_worker'], 'accepted-fixed-target')
    elif state in ('claimed', 'cancelling', 'active', 'aborted'):
        need(False, 'accepted-current-marker')
    need(actual['sequence'] == 3, 'owner-preserves-business-sequence')
    return value


def controllers(directory, events, calls, heads, descriptors, read, inputs):
    controller_calls = [call for call in calls if call['request']['principal'] in ('12', '13')]
    need(bool(controller_calls) and all(call['body']['operation'] in ALLOWED for call in controller_calls), 'controller-never-sql')
    configurations, reports = {}, {}
    for event in select(events, 'controller_configuration'):
        config = wire.parse(read(event['config']))
        need(config == wire.parse((directory / event['file']).read_bytes()) and config.get('version') == 1
             and len(config['scopes']) == 1, 'original-controller-configuration')
        raw = config['scopes'][0]['policy']
        endpoints = {row['role']: row['endpoint'] + '/v1' for row in select(events, 'http_proxy_started')}
        roles = ['A', 'B', 'C'] if inputs['three_rank_workers'] else ['A', 'B']
        if inputs['case_id'] == 'C2_same_creator_policy' and event['id'] == 'controller-two':
            roles = ['A', 'C', 'B']
        principal = '13' if inputs['case_id'] == 'C2_different_creators' and event['id'] == 'controller-two' else '12'
        expected = {'scope': inputs['scope'], 'authorityId': 'controller-matrix-private-s3', 'principal': principal,
            'metadataEndpoints': [endpoints[role] for role in (['M', 'C'] if inputs['metadata_routes'] == 2 else ['M'])],
            'workers': [{'workerInstance': str(inputs['workers'][role]), 'endpoint': endpoints[role], 'rank': rank}
                        for rank, role in enumerate(roles)],
            'modes': {'takeover': True, 'activate': True, 'cancel': True}, 'allowInsecureHttp': True,
            'recoveryTimeoutMs': 60000}
        need(raw == expected and config['scopes'][0]['tokenEnv'] == 'SCAP_CONTROLLER_MATRIX_TOKEN', 'fixed-controller-policy')
        digest, nonces = policy_digest(raw)
        need(raw['scope'] == inputs['scope'] and raw['principal'] == event['principal'], 'controller-config-scope')
        configurations[event['id']] = {'raw': raw, 'digest': digest, 'nonces': nonces, 'event': event}
    need(set(configurations) == {row['id'] for row in select(events, 'child_started')
                                if row['id'].startswith('controller-')}, 'controller-config-inventory')
    for name, configuration in configurations.items():
        output = one(events, 'controller_reports', id=name)
        stop = one(events, 'child_stopped', id=name)
        need(output['raw'] == stop['stderr'], 'original-controller-output')
        raw = read(output['raw'])
        need(not raw or raw.endswith(b'\n'), 'complete-controller-output')
        values = [wire.parse(line) for line in raw.splitlines()]
        for value in values:
            need(value['scope'] == inputs['scope'] and value['policyDigest'] == configuration['digest'], 'full-policy-report')
            need(type(value['httpCalls']) is int and 0 <= value['httpCalls'] <= 8 and
                 type(value['mutations']) is int and 0 <= value['mutations'] <= 1, 'per-tick-admission')
            need(value['nativeSession'] == 'NOT_CERTIFIED', 'report-not-native-certificate')
            if value.get('currentAuthority') is not None:
                need(any(projection(item['head']) == value['currentAuthority'] for item in heads), 'report-actual-authority')
            if value['state'] == 'active_observed':
                start = one(events, 'child_started', id=name)
                matching = [call for call in controller_calls if call['request']['principal'] == configuration['raw']['principal']
                            and start['sequence'] < call['request']['sequence'] < stop['sequence'] and successful(call)
                            and call['body']['operation'] in MUTATIONS and call['value']['value'].get('state') == 'active'
                            and call['value']['value'].get('status') == value['currentAuthority']]
                need(bool(matching) and value['acceptedPhase'] == 'active', 'active-report-has-original-http')
        reports[name] = values
        for observed in select(events, 'controller_report_observed', id=name):
            index = observed['line_index']
            need(type(index) is int and 0 <= index < len(values) and observed['report'] == values[index], 'original-report-line')
    for call in controller_calls:
        operation = call['body']['operation']
        if operation == 'owner_prepare':
            fixed = call['body']['input']
            candidates = [config for config in configurations.values() if
                          config['raw']['principal'] == call['request']['principal'] and config['nonces'] == fixed['nonces']]
            need(bool(candidates) and fixed['creator'] == call['request']['principal'] and
                 fixed['operation'] == fixed['expected_head_serial'] and
                 any(fixed['target_worker'] in {worker['workerInstance'] for worker in config['raw']['workers']}
                     for config in candidates), 'policy-full-original-input')
        if operation.startswith('owner_') and successful(call):
            owner_observation(call, descriptors, heads, inputs['scope'])
        elif operation == 'status' and successful(call):
            observed_status(call, call['value']['value'], heads)
    # Reports can be lost during SIGINT, and overlapping same-principal CLIs do
    # not carry a per-tick identity on the wire. Do not invent that attribution.
    need(sum(value['httpCalls'] for values in reports.values() for value in values) <= len(controller_calls),
         'reported-calls-within-original-ledger')
    need(sum(value['mutations'] for values in reports.values() for value in values) <=
         sum(call['body']['operation'] in MUTATIONS for call in controller_calls), 'reported-mutations-within-original-ledger')
    base = next((item['head'] for item in heads if item['head']['sequence'] == 3), None)
    need(base is not None, 'original-business-head')
    for item in heads:
        head = item['head']
        if head['head_serial'] >= base['head_serial']:
            need(all(head.get(key) == base.get(key) for key in
                 ('sequence', 'data_root', 'windows', 'snapshots', 'restore_origin')), 'owner-preserves-data-and-snapshots')
    return configurations, reports, controller_calls


def business(directory, events, calls, rows, ledger, read, heads):
    """Bind original SDK acknowledgements and recovery to each original byte stream."""
    endpoints = {row['role']: row['endpoint'] for row in select(events, 'http_proxy_started')}
    actual = [call for call in calls if call['request']['principal'] == '11']
    identifier = wire.parse((directory / 'scenario.json').read_bytes())['case_id']
    expected = Counter({'create': 1, 'activate': 1, 'open': 1, 'policy': 1, 'execute': 3, 'status': 4,
        'lookup': 3, 'query': 1, 'snapshot_prepare': 1, 'snapshot_capture': 1, 'snapshot_inspect': 1})
    if identifier == 'C4_revoked_authority':
        expected.update({'status': 1, 'policy': 1})
    elif identifier in ('C4_resource_refusal', 'C4_s3_unavailable'):
        expected.update({'status': 1})
    elif identifier == 'C2_manual_marker':
        expected.update({'status': 1, 'owner_prepare': 1, 'owner_claim': 1})
    need(Counter(call['body']['operation'] for call in actual) == expected, 'fixed-business-operations-no-manual-repair')
    unmatched = list(actual)
    correspondence = {}
    client_requests = select(ledger, 'http_request')
    for request in client_requests:
        raw = wire.b64(request['body'])
        need(sha(raw) == request['body_sha256'], 'original-sdk-request-hash')
        matches = [call for call in unmatched if read(call['request']['request']) == raw and
                   request['url'] == endpoints[call['request']['role']] + call['request']['path']]
        need(bool(matches), 'original-business-request')
        call = matches[0]
        unmatched.remove(call)
        correspondence[request['call_id']] = call
        responses = select(ledger, 'http_response', call_id=request['call_id'])
        failures = select(ledger, 'http_transport_error', call_id=request['call_id'])
        need(len(responses) + len(failures) == 1, 'complete-business-result')
        if responses:
            result = responses[0]
            need(call['response'] is not None and result['status'] == call['response']['status'] and
                 wire.b64(result['body']) == read(call['response']['response']) and
                 sha(wire.b64(result['body'])) == result['body_sha256'], 'actual-business-response')
    need(not unmatched and len(correspondence) == len(client_requests), 'complete-business-http')
    executes = [call for call in calls if call['body']['operation'] == 'execute']
    need(len(executes) == 3 and all(call['request']['principal'] == '11' and
         call['request']['role'] == 'A' for call in executes), 'sql-executed-once-only')
    saved = wire.parse((directory / 'intents.json').read_bytes())
    need(len(saved) == 3, 'three-original-intents')
    originals = {}
    for index, call in enumerate(executes, 1):
        original = wire.parse(saved[index - 1])
        need(call['body']['request'] == original['request'] and call['body']['statements'] == original['statements']
             and original['request']['id'] == str(index), 'saved-original-sql')
        need(successful(call) and call['value']['value']['state'] == 'committed', 'original-server-commit')
        value = call['value']['value']
        raw = wire.b64(value['result'])
        need(wire.receipt_hash(value['receipt'], raw) == value['receipt']['result_hash'], 'original-result-hash')
        decoded = wire.result(raw)[-1]['rows']
        need(len(decoded) == 1 and decoded[0][0] == index and len(decoded[0][1]) == 64
             and type(decoded[0][2]) is int, 'native-random-sql')
        originals[index] = value
    acks = select(rows, 'original_ack')
    need(len(acks) == 2 and {row['id'] for row in acks} == {1, 2}, 'two-original-client-acks')
    for ack in acks:
        call = correspondence[ack['call']]
        need(ack['value'] == originals[ack['id']] and call['body']['operation'] == 'execute', 'original-ack-bytes')
        need(one(events, 'http_proxy_delivery_finished', role=call['request']['role'],
                 serial=call['request']['serial'])['complete'], 'ack-was-delivered')
    unknown = one(rows, 'original_unknown')
    need(unknown['id'] == 3 and unknown['outcome'] == 'UNKNOWN' and unknown['attempts'] == 1, 'business-unknown-preserved')
    call = correspondence[unknown['call']]
    lost = one(events, 'http_proxy_delivery_suppressed', id='business-ack-loss')
    need(lost['role'] == call['request']['role'] and lost['serial'] == call['request']['serial']
         and lost['stage'] == 'after_response', 'unknown-from-real-response-loss')
    recovered = select(rows, 'recovered_lookup')
    need(len(recovered) == 3 and {row['id'] for row in recovered} == {1, 2, 3}, 'three-original-lookups')
    for row in recovered:
        call = correspondence[row['call']]
        need(row['value'] == originals[row['id']] and successful(call) and call['body']['operation'] == 'lookup'
             and call['value']['value'] == row['value'], 'recovered-original-result')
    query = correspondence[one(rows, 'recovered_query')['call']]
    need(successful(query) and query['body']['operation'] == 'query' and
         wire.result(wire.b64(query['value']['value']['result']))[0]['rows'] ==
         wire.result(wire.b64(originals[3]['result']))[-1]['rows'], 'no-sql-replay-counter-and-random')
    captured = correspondence[one(rows, 'snapshot_captured')['call']]
    retained = correspondence[one(rows, 'snapshot_retained')['call']]
    need(successful(captured) and successful(retained), 'real-snapshot-observations')
    first, last = captured['value']['value'], retained['value']['value']
    need(first['state'] == last['state'] == 'retained' and first['prepared']['reference'] == last['prepared']['reference']
         and first['prepared']['point'] == last['prepared']['point'] and first['prepared']['point']['sequence'] == '2',
         'snapshot-preserved')
    guard = one(rows, 'stale_guard')
    call = correspondence[guard['call']]
    need(guard['outcome'] == 'TARGET_MISMATCH' and error_code(call) == 'TARGET_MISMATCH', 'stale-worker-guard-rejected')
    need(not any(call['request']['sequence'] < row['sequence'] < call['response']['sequence']
                 for row in select(events, 's3_request')), 'stale-worker-guard-no-io')
    final = one(rows, 'final_authority')
    call = correspondence[final['call']]
    need(successful(call) and call['body']['operation'] == 'status' and call['value']['value'] == final['value'],
         'final-actual-authority')
    observed_status(call, final['value'], heads)
    published = [item for item in heads if item['request']['method'] == 'PUT']
    need(bool(published), 'final-authority-published')
    latest = max(published, key=lambda item: item['head']['head_serial'])
    verification = phase(events, 'verification')
    need(all(stop['sequence'] < verification for stop in select(events, 'child_stopped')
             if stop['id'].startswith('controller-')) and
         all(item['response']['sequence'] < verification for item in published), 'verification-after-writers-joined')
    need(projection(latest['head']) == final['value'] and any(
         item['request']['method'] == 'GET' and item['request']['role'] == call['request']['role'] and
         call['request']['sequence'] < item['request']['sequence'] < item['response']['sequence'] < call['response']['sequence']
         and item['raw'] == latest['raw'] and item['etag'] == latest['etag'] for item in heads),
         'final-is-latest-published-authority')
    return final['value'], correspondence


def phase(events, label):
    return one(events, 'scenario_phase', label=label)['sequence']


def operation(calls, name):
    return [call for call in calls if call['body']['operation'] == name]


def state(calls, name):
    return [call for call in calls if successful(call) and call['value']['value'].get('state') == name]


def head_changes(heads, name):
    return [item for item in heads if item['request']['method'] == 'PUT' and
            (item['head'].get('owner_plan') or {}).get('phase', {}).get('kind') == name]


def reports_with(reports, name, status, reason=None):
    return [value for value in reports[name] if value['state'] == status and
            (reason is None or value['reason'] == reason)]


def fresh_blocked_reports(events, reports, label, reason, guard):
    cut = one(events, 'controller_report_cut')
    need(phase(events, label) < cut['sequence'] and cut['id'] in reports and
         type(cut['line_count']) is int and 0 <= cut['line_count'] <= len(reports[cut['id']]), guard)
    fresh = [row for row in select(events, 'controller_report_observed', id=cut['id'])
             if row['sequence'] > cut['sequence'] and row['line_index'] >= cut['line_count']
             and row['report']['state'] == 'blocked' and row['report'].get('reason') == reason]
    need(len({row['line_index'] for row in fresh}) >= 2, guard)


def no_mutations_after(calls, start, guard):
    need(not any(call['request']['sequence'] > start and call['body']['operation'] in MUTATIONS
                 for call in calls), guard)


def simultaneous(events, first='controller-one', second='controller-two'):
    a, b = [one(events, 'child_started', id=name) for name in (first, second)]
    x, y = [one(events, 'child_stopped', id=name) for name in (first, second)]
    need(a['sequence'] < y['sequence'] and b['sequence'] < x['sequence'], 'real-controller-overlap')


def joined_restart(events, old, new):
    start = one(events, 'child_started', id=new)
    need(all(one(events, 'child_stopped', id=name)['sequence'] < start['sequence'] for name in old),
         'controller-restart-joined')


def response_loss(events, calls, identifier, expected_operation, expected_state):
    lost = one(events, 'http_proxy_delivery_suppressed', id=identifier)
    matches = [call for call in calls if call['request']['role'] == lost['role'] and call['request']['serial'] == lost['serial']]
    need(len(matches) == 1 and matches[0]['body']['operation'] == expected_operation and successful(matches[0]) and
         matches[0]['value']['value']['state'] == expected_state and lost['stage'] == 'after_response', 'real-owner-response-loss')
    return matches[0]


def fixed_failure_window(events, calls, role, before, guard):
    failures = [call for call in operation(calls, 'status') if call['request']['role'] == role and
                call['request']['sequence'] < before and (call['failure'] is not None or call['cut'] is not None)]
    need(len(failures) >= 3, guard)
    times = sorted(call['request']['monotonic_ns'] for call in failures)
    first = times[0]
    second = next((observed for observed in times if observed - first >= 1_000_000_000), None)
    # Earliest first/second leave the most room for a qualifying third. A greedy
    # chain of every intervening failure can incorrectly discard a valid last
    # observation, for example [0, 1, 4.5, 5.1] seconds.
    need(second is not None and any(observed - second >= 1_000_000_000 and
         observed - first >= 5_000_000_000 for observed in times), guard)


def case_history(identifier, events, calls, controller_calls, heads, configurations, reports,
                 final, correspondence, business_rows):
    mutations = [call for call in controller_calls if call['body']['operation'] in MUTATIONS]
    prepares, claims = operation(controller_calls, 'owner_prepare'), operation(controller_calls, 'owner_claim')
    resumes, aborts = operation(controller_calls, 'owner_resume'), operation(controller_calls, 'owner_abort')
    active, claimed, cancelling, aborted = [head_changes(heads, name) for name in ('active', 'claimed', 'cancelling', 'aborted')]
    need(final['sequence'] == '3' and final['scope']['database'] == str(8701 + CASES.index(identifier)), 'fixed-final-scope')
    if identifier not in ('C2_manual_marker', 'C3_healthy_original', 'C4_revoked_authority', 'C4_s3_unavailable'):
        stopped = one(events, 'child_stopped', id='service-A')
        removed = one(events, 'cache_removed', id='service-A')
        need(stopped['crash'] and phase(events, 'owner-loss') < stopped['sequence'] < removed['sequence'],
             'real-owner-loss-and-cache-removal')
    if identifier == 'C1_same_policy_prepare_restart':
        simultaneous(events)
        joined_restart(events, ('controller-one', 'controller-two'), 'controller-three')
        need(len(configurations) == 3 and len({value['digest'] for value in configurations.values()}) == 1, 'same-policy-restart')
        need(len(prepares) == 3 and {call['body']['input']['target_worker'] for call in prepares[:2]} == {'9602', '9603'}
             and len({(call['body']['input']['creator'], call['body']['input']['operation']) for call in prepares}) == 1,
             'competing-original-targets')
        first = response_loss(events, prepares, 'first-prepare-held', 'owner_prepare', 'prepared')
        fixed = first['body']['input']
        candidate_cut = one(events, 'http_proxy_cut_started', id='first-b-candidate')
        original_cuts = [call for call in controller_calls if call['cut'] is not None and
                         call['cut']['id'].startswith('first-b-candidate-')]
        observed = [row for row in select(events, 'controller_report_observed', id='controller-one')
                    if row['report']['state'] == 'waiting' and row['report'].get('reason') == 'CANDIDATE_UNAVAILABLE']
        second_start = one(events, 'child_started', id='controller-two')
        need(candidate_cut['role'] == 'B' and candidate_cut['count'] == 1 and len(original_cuts) == 1 and
             original_cuts[0]['body'].get('expected_worker_instance') == '9602' and
             original_cuts[0]['request']['role'] == 'B' and len(observed) == 1 and
             candidate_cut['sequence'] < original_cuts[0]['cut']['sequence'] < observed[0]['sequence'] <
             second_start['sequence'] < first['request']['sequence'], 'real-first-candidate-failure')
        need(fixed['target_worker'] == '9603' and prepares[-1]['body']['input'] == fixed, 'adopt-first-winner-without-local-input')
        need(sum(error_code(call) == 'CONFLICT' for call in prepares) == 1 and len(claims) == len(resumes) == 1 and
             not aborts and len(active) == len(claimed) == 1, 'one-first-winner-publication')
        reference = first['value']['value']['prepared']['reference']
        need(all(call['body']['plan'] == reference for call in claims + resumes) and final['owner_plan']['reference'] == reference
             and final['owner_instance'] == '9603' and final['active'], 'first-winner-final-authority')
        need(any(value.get('lastUncertainCall', {}).get('operation') == 'owner_prepare'
                 for value in reports_with(reports, 'controller-one', 'unknown', 'UNKNOWN')), 'prepare-unknown-preserved')
    elif identifier in ('C2_same_creator_policy', 'C2_different_creators'):
        simultaneous(events)
        need(len(configurations) == 2 and len({value['digest'] for value in configurations.values()}) == 2,
             'distinct-full-policies')
        need(len(prepares) == 2 and len(active) == len(claimed) == 1 and not cancelling and not aborted and not aborts,
             'one-accepted-competing-plan')
        need(final['active'] and final['owner_plan']['phase']['kind'] == 'active', 'winner-actually-active')
        if identifier == 'C2_same_creator_policy':
            need(len({call['body']['input']['creator'] for call in prepares}) == 1 and
                 sum(error_code(call) == 'CONFLICT' for call in prepares) == 1 and len(claims) == len(resumes) == 1,
                 'same-creator-policy-conflict')
            no_mutations_after(controller_calls, phase(events, 'foreign-policy-blocked'), 'foreign-policy-no-failback')
            fresh_blocked_reports(events, reports, 'foreign-policy-blocked', 'POLICY',
                                  'foreign-policy-remains-blocked')
        else:
            need({call['body']['input']['creator'] for call in prepares} == {'12', '13'} and len(claims) == 2
                 and len(resumes) == 1, 'two-creators-original-claims')
            no_mutations_after(controller_calls, phase(events, 'foreign-creator-blocked'), 'foreign-creator-no-mutation')
            fresh_blocked_reports(events, reports, 'foreign-creator-blocked', 'FOREIGN_CREATOR',
                                  'foreign-creator-remains-blocked')
    elif identifier == 'C2_manual_marker':
        manual = [call for call in calls if call['request']['principal'] == '11' and call['body']['operation'] in MUTATIONS]
        need(not mutations and Counter(call['body']['operation'] for call in manual) == {'owner_prepare': 1, 'owner_claim': 1}
             and len(claimed) == 1 and not active and final['owner_plan']['reference']['creator'] == '11'
             and final['owner_plan']['phase']['kind'] == 'claimed' and not final['active'], 'manual-plan-remains-blocked')
        need(len(reports_with(reports, 'controller-one', 'blocked', 'FOREIGN_CREATOR')) >= 2, 'manual-marker-observed')
    elif identifier in ('C3_claimed_abort', 'C3_cancelling_restart'):
        simultaneous(events)
        need(len(aborted) == 1 and not active and not final['active'] and
             final['owner_plan']['phase']['kind'] == 'aborted', 'cancelled-plan-never-active')
        reference = final['owner_plan']['reference']
        need(all(call['body']['plan'] == reference for call in claims + resumes + aborts), 'cancel-original-plan-only')
        need(bool(aborts), 'automatic-abort-observed')
        fixed_failure_window(events, controller_calls, 'B', aborts[0]['request']['sequence'], 'real-target-failure-window')
        if identifier == 'C3_claimed_abort':
            need(len(claimed) == 1 and not cancelling and len(aborts) == len(claims) == len(resumes) == 1,
                 'claimed-abort-is-one-terminal-step')
            gate, label, late = 'original-resume-held', 'late-original-resume', resumes[0]
        else:
            need(not claimed and len(cancelling) == 1 and len(aborts) == 2 and len(claims) == 1 and not resumes,
                 'unaccepted-cancel-two-stages')
            response_loss(events, aborts, 'cancelling-ack-loss', 'owner_abort', 'cancelling')
            joined_restart(events, ('controller-one', 'controller-two'), 'controller-three')
            gate, label, late = 'original-claim-held', 'late-original-claim', claims[0]
        arrived = one(events, 'http_proxy_fault_arrived', id=gate)
        released = one(events, 'http_proxy_release_requested', id=gate)
        need(arrived['sequence'] < aborted[0]['response']['sequence'] < phase(events, label) <= released['sequence']
             < late['response']['sequence'] and successful(late) and late['value']['value']['state'] == 'aborted',
             'late-original-request-observes-aborted')
    elif identifier == 'C3_healthy_original':
        need(len(prepares) == 1 and len(mutations) == 1 and not active and not claimed and not cancelling and not aborted
             and final['owner_instance'] == '9601' and final['active'] and final['owner_plan'] is None,
             'healthy-original-not-deactivated')
        no_mutations_after(controller_calls, phase(events, 'original-owner-restored'), 'healthy-original-no-mutation')
        need(len(reports_with(reports, 'controller-one', 'healthy', 'CURRENT_OWNER_RESPONDED')) >= 2,
             'fresh-healthy-original-observed')
        need(not any(row['crash'] for row in select(events, 'child_stopped')), 'healthy-owner-physically-alive')
    elif identifier == 'C4_revoked_authority':
        denied = [call for call in controller_calls if error_code(call) == 'DENIED']
        need(not mutations and len(denied) >= 2 and final['active'] and final['owner_instance'] == '9601',
             'revocation-blocks-controller')
        revoked = correspondence[one(business_rows, 'authority_revoked')['call']]
        need(successful(revoked) and revoked['body']['operation'] == 'policy' and
             all(revoked['response']['sequence'] < call['request']['sequence'] for call in denied), 'actual-current-revocation')
        policy = revoked['body']['permissions']
        latest = max((item for item in heads if item['request']['method'] == 'PUT'),
                     key=lambda item: item['head']['head_serial'])
        before = [item for item in heads if item['request']['method'] == 'GET' and
                  item['request']['role'] == revoked['request']['role'] and
                  revoked['request']['sequence'] < item['request']['sequence'] < item['response']['sequence'] <
                  latest['request']['sequence']]
        need(policy == [{'principal': principal, 'read': True, 'write': principal == '11', 'admin': True}
                        for principal in ('11', '13')] and public(latest['head']['policy']) == policy and
             any(latest['head']['auth_epoch'] == item['head']['auth_epoch'] + 1 and
                 latest['head']['revision'] == item['head']['revision'] + 1 for item in before) and
             latest['response']['sequence'] < revoked['response']['sequence'], 'revocation-is-current-head-policy')
    elif identifier == 'C4_worker_mismatch':
        mismatches = [call for call in controller_calls if error_code(call) == 'TARGET_MISMATCH']
        need(not mutations and len(mismatches) >= 2 and final['owner_instance'] == '9601' and final['owner_plan'] is None,
             'actual-worker-mismatch-blocks-controller')
        ready = one(events, 'service_ready', role='B')
        need(ready['worker'] == '9604', 'different-actual-worker')
        for call in mismatches:
            need(call['request']['role'] == 'B' and call['body'].get('expected_worker_instance') == '9602' and
                 not any(item['role'] == 'B' and call['request']['sequence'] < item['sequence'] <
                         call['response']['sequence'] for item in select(events, 's3_request')), 'wrong-worker-guard-before-s3')
    elif identifier == 'C4_resource_refusal':
        busy = [call for call in controller_calls if error_code(call) == 'BACKPRESSURE']
        limited = [call for call in controller_calls if error_code(call) == 'LIMIT']
        need(bool(busy) and all(call['response']['status'] == 429 for call in busy), 'actual-resource-429')
        arrived = one(events, 'fault_arrived', id='control-intake-status-held')
        released = one(events, 'fault_release_requested', id='control-intake-status-held')
        need(all(arrived['sequence'] < call['request']['sequence'] < call['response']['sequence'] < released['sequence']
                 for call in busy), '429-while-original-intake-owned')
        need(len(limited) >= 2 and all(call['body']['operation'] == 'owner_resume' and call['response']['status'] == 413
             for call in limited) and len(claimed) == 1 and not active and not aborts and not final['active']
             and final['owner_plan']['phase']['kind'] == 'claimed', 'real-budget-refusal-not-death')
        need(limited[1]['request']['monotonic_ns'] - limited[0]['request']['monotonic_ns'] >= 5_000_000_000,
             'real-resource-backoff')
    elif identifier == 'C4_s3_unavailable':
        unavailable = [call for call in controller_calls if error_code(call) == 'UNKNOWN']
        need(not mutations and len(unavailable) == 1 and final['active'] and final['owner_instance'] == '9601',
             's3-unavailable-not-owner-death')
        need(unavailable[0]['response']['status'] == 503 and
             len(reports_with(reports, 'controller-one', 'unknown', 'UNKNOWN')) == 1, 'metadata-unknown-preserved')
        routes = one(events, 'metadata_routes_observed')
        lost = one(events, 'fault_suppressed', id='metadata-s3-disconnect')
        need(lost['role'] == routes['preferred'] == unavailable[0]['request']['role'], 'unavailable-from-real-s3-loss')
        alternate = correspondence[one(business_rows, 'alternate_authority')['call']]
        need(successful(alternate) and alternate['request']['role'] == routes['alternate'] != routes['preferred'],
             'independent-metadata-route-actually-healthy')
        need(len(reports_with(reports, 'controller-one', 'healthy')) >= 2, 'fresh-read-after-s3-recovery')
    elif identifier == 'C5_shutdown_deadline':
        joined_restart(events, ('controller-one',), 'controller-two')
        held = one(events, 'http_proxy_fault_arrived', id='original-probe-held')
        released = one(events, 'http_proxy_release_requested', id='original-probe-held')
        need(released['monotonic_ns'] - held['monotonic_ns'] >= 1_000_000_000,
             'original-probe-deadline-exercised')
        original = one(events, 'fault_arrived', id='original-active-cas-held')
        stopped = one(events, 'child_stopped', id='controller-one')
        release = one(events, 'fault_release_requested', id='original-active-cas-held')
        need(original['sequence'] < stopped['sequence'] < release['sequence'], 'shutdown-does-not-cancel-server-effect')
        need(len(active) == len(claimed) == 1 and final['active'] and final['owner_instance'] == '9602',
             'fresh-controller-actual-activation')
        response = one(events, 's3_backend_response', role=original['role'], serial=original['serial'])
        request = one(events, 's3_request', role=original['role'], serial=original['serial'])
        need(request['headers'].get('if-match') and request['sequence'] < stopped['sequence'] and
             active[0]['response']['sequence'] < release['sequence'] < response['sequence'] and response['status'] == 412,
             'late-original-cas-is-rejected')
        late_same_candidate(request, active[0])
        need(len(prepares) == len(claims) == 1 and len(resumes) == 2 and not aborts, 'restart-no-new-plan-or-sql')
    else:
        need(False, 'fixed-case-id')
    return {'owner_mutations': Counter(call['body']['operation'] for call in mutations),
            'accepted_head_phases': {'claimed': len(claimed), 'cancelling': len(cancelling),
                                     'active': len(active), 'aborted': len(aborted)}}


def service_configuration(directory, events, calls, inputs):
    configs = {}
    for role, worker in inputs['workers'].items():
        config = wire.parse((directory / ('service-' + role + '.json')).read_bytes())
        actual_worker = inputs['worker_b_actual'] if role == 'B' else worker
        need(config['worker_instance'] == str(actual_worker) and config['gc'] is None, 'fixed-service-worker')
        need(config['s3']['timeout_ms'] == (inputs['metadata_s3_timeout_ms'] if role == 'M' else 5000)
             and config['admission']['timeout_ms'] == 30000 and config['admission']['recovery_timeout_ms'] == 60000,
             'fixed-service-deadlines')
        if role == 'B' and inputs['zero_recovery_budget']:
            need(config['owner_recovery'] == {'payload_gets': 0, 'payload_bytes': 0}, 'actual-zero-recovery-budget')
        if role == 'M' and inputs['control_intake_occupant']:
            need(config['admission']['control_intake'] == 1, 'actual-single-control-intake')
        ready = one(events, 'service_ready', role=role)
        need(ready['worker'] == str(actual_worker), 'actual-service-worker')
        configs[role] = config
    for call in calls:
        request = call['request']
        matches = [entry for entry in configs[request['role']]['credentials'] if
                   entry['sha256'] == request['token_sha256']]
        need(len(matches) == 1 and matches[0]['principal'] == request['principal'] and
             matches[0]['deployment'] == inputs['scope']['deployment'] and matches[0]['tenant'] == inputs['scope']['tenant'],
             'actual-authenticated-principal')


def audit_history(directory, inputs, events, rows, ledger, read):
    identifier = fixed_inputs(directory, inputs)
    need([row['sequence'] for row in events] == list(range(1, len(events) + 1)) and
         all(before['monotonic_ns'] <= after['monotonic_ns'] for before, after in zip(events, events[1:])),
         'complete-event-sequence')
    starts, stops = processes(events, read, inputs)
    calls = http_exchanges(events, read)
    service_configuration(directory, events, calls, inputs)
    exchanges, heads, descriptors = s3_exchanges(events, read, inputs['scope'])
    configurations, reports, controller_calls = controllers(directory, events, calls, heads, descriptors, read, inputs)
    final, correspondence = business(directory, events, calls, rows, ledger, read, heads)
    details = case_history(identifier, events, calls, controller_calls, heads, configurations, reports,
                           final, correspondence, rows)
    summary = wire.parse((directory / 'summary.json').read_bytes())
    need(summary['status'] == 'OBSERVED_NOT_AUDITED' and summary['case_id'] == identifier and
         summary['cleanup_errors'] == [] and 'error' not in summary and 'source_error' not in summary and
         0 < summary['elapsed_seconds'] <= inputs['whole_seconds'], 'bounded-observation-completed')
    return {'status': 'PASS_CONTROLLER_MATRIX_CASE', 'case_id': identifier,
        'source_commit': inputs['source_commit'], 'source_sha256': inputs['source_sha256'],
        'http_posts': len(calls), 'controller_http_posts': len(controller_calls), 's3_requests': len(exchanges),
        'owned_children': len(starts), 'controller_processes': len(configurations),
        'reports': sum(len(values) for values in reports.values()), 'original_sql': 3, 'client_acks': 2,
        'business_unknowns': 1, 'original_lookups': 3, 'retained_snapshots': 1,
        'final_authority': final, **details, 'aws': 'NOT_RUN', 'production_slo': 'NOT_RUN',
        'per_process_tick_wire_attribution': 'NOT_CLAIMED'}


def audit_case(directory):
    directory = Path(directory)
    events = read_rows(directory / 'events.jsonl')
    inputs = sources(directory, events)
    return audit_history(directory, inputs, events, read_rows(directory / 'business.jsonl'),
                         read_rows(directory / 'http-client-ledger.jsonl'), lambda ref: raw_file(directory, ref))


def audit(directory):
    directory = Path(directory)
    inventory = wire.parse((directory / 'cases.json').read_bytes())
    need(inventory == {'version': 1, 'expected': list(CASES), 'selected': list(CASES), 'complete': True},
         'complete-fixed-matrix')
    cases = [audit_case(directory / identifier) for identifier in CASES]
    need(len({value['source_commit'] for value in cases}) == 1 and
         len({value['source_sha256'] for value in cases}) == 1, 'same-frozen-matrix-source')
    return {'status': 'PASS_COMPLETE_CONTROLLER_MATRIX', 'case_count': len(cases), 'cases': cases,
        'source_commit': cases[0]['source_commit'],
        'totals': {key: sum(value[key] for value in cases) for key in ('http_posts', 'controller_http_posts',
            's3_requests', 'owned_children', 'controller_processes', 'original_sql', 'client_acks',
            'business_unknowns', 'original_lookups', 'retained_snapshots')},
        'aws': 'NOT_RUN', 'production_slo': 'NOT_RUN'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    parser.add_argument('--case-only', action='store_true', help='audit one case without a complete-matrix verdict')
    args = parser.parse_args()
    print(json.dumps(audit_case(args.evidence) if args.case_only else audit(args.evidence), sort_keys=True))
