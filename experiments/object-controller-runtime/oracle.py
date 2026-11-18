#!/usr/bin/env python3
"""Independent raw-evidence checks. Imports no SDK, controller or product code."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path
import tarfile

HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


wire = load('controller_independent_wire', HERE.parent / 'object-service/audit_wire.py')
build_audit = load('controller_independent_build', HERE.parent / 'object-network/audit_build.py')


class Rejected(ValueError):
    pass


def need(condition, guard):
    if not condition:
        raise Rejected(guard)


def read_rows(path):
    raw = Path(path).read_bytes()
    need(bool(raw) and raw.endswith(b'\n'), 'complete-ledger')
    return [wire.parse(line) for line in raw.splitlines()]


def select(rows, event, **fields):
    return [row for row in rows if row['event'] == event and all(row.get(key) == value for key, value in fields.items())]


def one(rows, event, **fields):
    values = select(rows, event, **fields)
    need(len(values) == 1, 'one-' + event)
    return values[0]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def raw_file(directory, description):
    need(set(description) == {'file', 'bytes', 'sha256'}, 'raw-fields')
    digest = description['sha256']
    need(isinstance(digest, str) and len(digest) == 64 and all(c in '0123456789abcdef' for c in digest)
         and description['file'] == 'raw/' + digest, 'raw-path')
    path = directory / description['file']
    need(not path.is_symlink() and path.is_file(), 'raw-file')
    value = path.read_bytes()
    need(len(value) == description['bytes'] and sha(value) == digest, 'raw-hash')
    return value


def sources(directory, events):
    inputs = wire.parse((directory / 'inputs.json').read_bytes())
    source = wire.parse((directory / 'source.json').read_bytes())
    files = source['files']
    need(source['source_sha256'] == inputs['source_sha256'] == sha(
        json.dumps(files, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode()), 'source-fingerprint')
    need(source['commit'] == inputs['source_commit'], 'source-commit')
    expected = {row['path']: row for row in files}
    need(len(expected) == len(files) and inputs['plan_sha256'] ==
         expected['experiments/object-controller-runtime/PLAN.md']['sha256'], 'fixed-plan')
    need(sha((directory / 'source.tar').read_bytes()) == inputs['source_archive_sha256'], 'source-archive')
    with tarfile.open(directory / 'source.tar') as archive:
        members = archive.getmembers()
        need(len(members) == len(files) and {m.name for m in members} == set(expected), 'source-inventory')
        for member in members:
            need(member.isfile(), 'source-regular')
            value = archive.extractfile(member).read()
            row = expected[member.name]
            need(len(value) == row['bytes'] and sha(value) == row['sha256'] and
                 hashlib.sha1(b'blob ' + str(len(value)).encode() + b'\0' + value).hexdigest() == row['git_blob'],
                 'source-bytes')
    receipt = build_audit.receipt(directory / 'service-build', profile='service')
    need(receipt['binary'] == inputs['tools']['scapd'], 'actual-release-binary')
    need(inputs['node_version'] == 'v22.16.0', 'fixed-node-version')
    for tool in inputs['tools'].values():
        path = Path(tool['path'])
        need(path.is_file() and build_audit.file_digest(path) == tool['sha256'], 'actual-tool-bytes')
    for start in select(events, 'child_started'):
        tool = inputs['tools']['scapd' if start['id'].startswith('service-') else 'node']
        need(start['command'][0] == tool['path'] and start['executable_sha256'] == tool['sha256'],
             'actual-owned-executable')
    need(one(events, 'backend_started')['binary'] == inputs['tools']['weed'], 'actual-s3-binary')
    full_receipt = wire.parse((directory / 'service-build/build-receipt.json').read_bytes())
    need(all(expected.get(path, {}).get('sha256') == digest for path, digest in full_receipt['inputs'].items()),
         'release-source-equivalence')
    after = one(events, 'source_verified')
    need(after['commit'] == source['commit'] and after['source_sha256'] == source['source_sha256'], 'source-unchanged')
    need(inputs['scope'] == {'deployment': '1', 'tenant': '7', 'database': '8601',
                            'incarnation': '1', 'generation': '1'} and inputs['workers'] == {'A': 9601, 'B': 9602, 'C': 9603},
         'fixed-topology')
    return inputs


def processes(events, read):
    required = {'service-A', 'service-B', 'service-C', 'controller-one', 'controller-two',
                'business-initialize', 'business-unknown', 'business-verify'}
    starts = select(events, 'child_started')
    stops = select(events, 'child_stopped')
    need(len(starts) == len(stops) == 8 and {row['id'] for row in starts} == {row['id'] for row in stops} == required,
         'owned-process-denominator')
    ownership = build_audit.OwnedChildren()
    for start in starts:
        stop = one(events, 'child_stopped', id=start['id'])
        need(start['identity'] == stop['identity'] and start['sequence'] < stop['sequence']
             and stop['forced'] is False and stop['usage']['source'] == 'kernel_wait4_owned_child'
             and stop['usage']['available'] is True, 'owned-wait4')
        ownership.register(start['identity'], stop['monotonic_ns'])
        crashed = start['id'] == 'service-A'
        need(stop['crash'] == crashed and stop['status'] == (-9 if crashed else 0), 'fixed-process-outcome')
        read(stop['stderr'])
    exit_a = one(events, 'child_stopped', id='service-A')
    cache = one(events, 'cache_removed')
    need(cache['id'] == 'service-A' and cache['existed'] and cache['absent'] and
         cache['sequence'] > exit_a['sequence'], 'cache-loss-after-owned-exit')
    first_exit = one(events, 'child_stopped', id='controller-one')
    second_start = one(events, 'child_started', id='controller-two')
    need(first_exit['sequence'] < second_start['sequence'], 'controller-restart-joined')
    for start in [row for row in starts if row['id'].startswith('controller-')]:
        need(start['command'][1].endswith('/sdk/node/bin/owner-controller.mjs'), 'production-controller-cli')
    backend, stopped = one(events, 'backend_started'), one(events, 'backend_stopped')
    need(len(backend['identities']) == len(stopped['processes']) == 4, 'real-s3-processes')
    for start, stop in zip(backend['identities'], stopped['processes']):
        need(all(stop.get(key) == value for key, value in start.items()) and stop['wait_status'] == -9
             and stop['kernel_usage']['source'] == 'kernel_wait4_owned_child', 'backend-owned-exit')
    need(one(events, 'unsigned_probe')['status'] == 403, 'unsigned-s3-rejected')
    need(one(events, 'cleanup_finished')['errors'] == [] and one(events, 'private_removed')['absent'], 'complete-cleanup')
    return cache['sequence']


def exchanges(events, read):
    requests = select(events, 's3_request')
    need(bool(requests) and all(row['signature_valid'] is True for row in requests), 'actual-s3-signatures')
    s3_keys = {(row['role'], row['serial']) for row in requests}
    need(len(s3_keys) == len(requests), 's3-unique-requests')
    for event in ('s3_handler_started', 's3_forward_started', 's3_backend_response',
                  's3_delivery_started', 's3_delivery_finished', 's3_handler_finished'):
        values = select(events, event)
        need(len(values) == len(requests) and {(row['role'], row['serial']) for row in values} == s3_keys,
             'closed-s3-exchanges')
    for request in requests:
        fields = {key: request[key] for key in ('role', 'serial')}
        response = one(events, 's3_backend_response', **fields)
        delivery = one(events, 's3_delivery_finished', **fields)
        need(request['sequence'] < response['sequence'] < delivery['sequence'] and delivery['complete'], 's3-request-order')
        need(request['method'] in ('GET', 'PUT'), 's3-fixed-methods')
        read(request['request']); read(response['response'])
        if request['method'] == 'PUT':
            headers = request['headers']
            need(bool(headers.get('if-match')) != bool(headers.get('if-none-match')), 'conditional-s3-put')
    need(any(row['method'] == 'PUT' and row['path'] == '/scap-test/scap-object/v1/1/7/8601/head'
             and row['headers'].get('if-match') for row in requests), 'head-cas-observed')
    closed = select(events, 's3_proxy_stopped')
    need(len(closed) == 3 and {row['role'] for row in closed} == {'A', 'B', 'C'} and
         all(row['joined'] and not row['errors'] and row['request_count'] ==
             len([request for request in requests if request['role'] == row['role']]) for row in closed), 's3-listener-closure')
    http = select(events, 'http_proxy_request')
    need(len({(r['role'], r['serial']) for r in http}) == len(http), 'http-unique-requests')
    responses = {}
    for request in http:
        fields = {key: request[key] for key in ('role', 'serial')}
        need(request['sequence'] < one(events, 'http_proxy_handler_finished', **fields)['sequence'], 'closed-http-handler')
        successes = select(events, 'http_proxy_backend_response', **fields)
        failures = select(events, 'http_proxy_backend_failure', **fields)
        need(len(successes) + len(failures) == 1, 'closed-http-backend')
        body = wire.parse(read(request['request']))
        need(body['operation'] == request['operation'], 'http-original-operation')
        if failures:
            need(request['role'] == 'A' and request['principal'] == '12' and body['operation'] == 'status'
                 and failures[0]['failure'] == 'ConnectionRefusedError', 'only-old-owner-unavailable')
        else:
            response = successes[0]
            responses[(request['role'], request['serial'])] = wire.parse(read(response['response']))
            delivered = select(events, 'http_proxy_delivery_finished', **fields)
            suppressed = select(events, 'http_proxy_delivery_suppressed', **fields)
            need(len(delivered) + len(suppressed) == 1 and
                 (not delivered or delivered[0]['complete']), 'closed-http-delivery')
    closed_http = select(events, 'http_proxy_closed')
    need(len(closed_http) == 3 and all(row['joined'] and row['errors'] == [] and row['request_count'] ==
         len([request for request in http if request['role'] == row['role']]) for row in closed_http), 'http-listener-closure')
    need(not select(events, 'http_proxy_fixture_error') and not select(events, 's3_fixture_error'), 'no-observer-errors')
    wire.closed_worker_claims(events, read, one(events, 'backend_started')['normal_access_sha256'], check=need)
    return http, responses


def owner_observation(response, http_status, original_input, scope, reference, state):
    """Validate the real HTTP observation against the original fixed owner input."""
    step = 'claim' if state == 'claimed' else 'resume'
    value = response.get('value') if isinstance(response, dict) else None
    need(isinstance(response, dict) and http_status == 200 and response.get('ok') is True and isinstance(value, dict),
         'real-' + step + '-success')
    need(value.get('state') == state, 'real-' + step + '-' + state + '-state')
    accepted = value.get('accepted')
    need(value.get('prepared') == {'input': original_input, 'scope': scope, 'reference': reference}
         and isinstance(accepted, dict) and accepted.get('reference') == reference,
         step + '-original-plan')
    status = value.get('status')
    need(isinstance(status, dict) and status.get('owner_plan') == accepted, step + '-current-marker')
    revision, serial = (wire.decimal(original_input[key]) + 1
                        for key in ('expected_revision', 'expected_head_serial'))
    admission = {'kind': 'claim', 'revision': str(revision), 'head_serial': str(serial)}
    active = state == 'active'
    nonce = original_input['nonces']['activate' if active else 'claim']
    # This frozen history performs exactly the first takeover from epoch 1/A.
    phase = {'kind': state, 'nonce': nonce, 'owner_epoch': '2', 'owner_instance': '9602',
             'revision': str(revision + int(active)), 'head_serial': str(serial + int(active))}
    need(accepted.get('admission') == admission and accepted.get('phase') == phase,
         step + '-accepted-phase')
    need(status.get('active') is active and status.get('owner_instance') == '9602'
         and status.get('owner_epoch') == phase['owner_epoch'] and status.get('scope') == scope
         and status.get('lifecycle') == 'ready' and status.get('revision') == phase['revision']
         and status.get('head_serial') == phase['head_serial']
         and status.get('transition') == {'nonce': nonce, 'revision': phase['revision']},
         step + '-active-authority')
    return value


def controllers(events, http, responses, read, cache_sequence):
    allowed = {'status', 'owner_inspect', 'owner_prepare', 'owner_claim', 'owner_resume', 'owner_abort'}
    calls = [row for row in http if row['principal'] == '12']
    need(bool(calls) and all(row['operation'] in allowed for row in calls), 'controller-never-sql')
    mutations = [row for row in calls if row['operation'] not in ('status', 'owner_inspect')]
    need(Counter(row['operation'] for row in mutations) == {'owner_prepare': 1, 'owner_claim': 1, 'owner_resume': 1},
         'fixed-owner-mutations-no-replay')
    reports = []
    for name in ('controller-one', 'controller-two'):
        original = one(events, 'controller_reports', id=name)
        need(original['raw'] == one(events, 'child_stopped', id=name)['stderr'], 'original-controller-output')
        raw = read(original['raw'])
        need(raw and raw.endswith(b'\n'), 'complete-controller-output')
        values = [wire.parse(line) for line in raw.splitlines()]
        for value in values:
            need(type(value['httpCalls']) is int and 0 <= value['httpCalls'] <= 8 and
                 type(value['mutations']) is int and 0 <= value['mutations'] <= 1, 'per-tick-admission')
        if name == 'controller-one':
            need(any(row['state'] == 'healthy' and row['mutations'] == 0 for row in values), 'healthy-owner-read-only')
            unknown = [row for row in values if row['state'] == 'unknown']
            need(len(unknown) == 1 and unknown[0]['reason'] == 'UNKNOWN' and unknown[0]['pastUnknown'] and
                 unknown[0]['lastUncertainCall']['operation'] == 'owner_claim', 'claim-unknown-preserved')
        else:
            active = [row for row in values if row['state'] == 'active_observed']
            need(len(active) == 1 and active[0]['recoveryBudget'] and
                 active[0]['currentAuthority']['owner_instance'] == '9602' and
                 active[0]['currentAuthority']['active'], 'automatic-cold-owner-active')
        reports.extend(values)
    need(len({row['policyDigest'] for row in reports}) == 1, 'restart-same-policy')
    need(sum(row['httpCalls'] for row in reports) == len(calls) and
         sum(row['mutations'] for row in reports) == len(mutations), 'complete-controller-call-budget')
    prepare, claim, resume = [next(row for row in mutations if row['operation'] == name)
                              for name in ('owner_prepare', 'owner_claim', 'owner_resume')]
    bodies = [wire.parse(read(row['request'])) for row in (prepare, claim, resume)]
    need(cache_sequence < prepare['sequence'] < claim['sequence'] < resume['sequence'], 'owner-after-cache-loss')
    need(bodies[0]['input']['creator'] == '12' and bodies[0]['input']['target_worker'] == '9602' and
         bodies[0]['input']['mode'] == 'takeover', 'automatic-fixed-target')
    need(bodies[1]['plan'] == bodies[2]['plan'] and bodies[1]['expected_worker_instance'] ==
         bodies[2]['expected_worker_instance'] == '9602', 'resume-original-accepted-plan')
    suppressions = select(events, 'http_proxy_delivery_suppressed')
    need(len(suppressions) == 2 and {r['id'] for r in suppressions} == {'business-ack-loss', 'claim-ack-loss'},
         'fixed-successful-response-losses')
    lost = one(events, 'http_proxy_delivery_suppressed', id='claim-ack-loss')
    need((lost['role'], lost['serial']) == (claim['role'], claim['serial']) and
         responses[(claim['role'], claim['serial'])]['ok'], 'real-claim-success-before-loss')
    claim_response = one(events, 'http_proxy_backend_response', role=claim['role'], serial=claim['serial'])
    resume_response = one(events, 'http_proxy_backend_response', role=resume['role'], serial=resume['serial'])
    original_input, scope, reference = bodies[0]['input'], bodies[0]['scope'], bodies[1]['plan']
    claimed = owner_observation(responses[(claim['role'], claim['serial'])], claim_response['status'],
                                original_input, scope, reference, 'claimed')
    resumed = owner_observation(responses[(resume['role'], resume['serial'])], resume_response['status'],
                                original_input, scope, reference, 'active')
    need(resumed['accepted']['admission'] == claimed['accepted']['admission']
         and resumed['status']['sequence'] == claimed['status']['sequence'], 'resume-original-admission')
    need(active[0]['currentAuthority'] == resumed['status']
         and active[0]['acceptedPhase'] == resumed['accepted']['phase']['kind'], 'resume-report-matches-http')
    reads = [row for row in select(events, 's3_request') if row['role'] == 'B' and row['method'] == 'GET'
             and '/objects/' in row['path'] and cache_sequence < row['sequence'] < resume_response['sequence']]
    need(bool(reads), 'cold-owner-real-s3-reads')
    failures = [row for row in select(events, 'http_proxy_backend_failure') if row['role'] == 'A'
                and cache_sequence < row['sequence'] < prepare['sequence']]
    need(len(failures) >= 3 and failures[-1]['monotonic_ns'] - failures[0]['monotonic_ns'] >= 5000000000,
         'real-failure-window')
    return len(reports), len(calls)


def business(directory, events, http, responses, rows, client, read):
    requests = select(client, 'http_request')
    correspondence = {}
    for phase in ('initialize', 'unknown', 'verify'):
        source = [row for row in requests if row['phase'] == phase]
        label = {'initialize': 'initialize', 'unknown': 'business-unknown', 'verify': 'cold-verification'}[phase]
        observed = [row for row in http if row['principal'] == '11' and row['phase'] == label]
        need(len(source) == len(observed), 'complete-business-http')
        for left, right in zip(source, observed):
            need(wire.b64(left['body']) == read(right['request']) and
                 sha(wire.b64(left['body'])) == left['body_sha256'], 'original-business-request')
            correspondence[left['call_id']] = right
            result = select(client, 'http_response', call_id=left['call_id'])
            failed = select(client, 'http_transport_error', call_id=left['call_id'])
            need(len(result) + len(failed) == 1, 'complete-business-result')
            if result:
                observed_response = one(events, 'http_proxy_backend_response', role=right['role'], serial=right['serial'])
                need(wire.b64(result[0]['body']) == read(observed_response['response']), 'actual-business-response')
    executes = [row for row in http if row['operation'] == 'execute']
    need(len(executes) == 3 and all(row['principal'] == '11' and row['role'] == 'A' for row in executes), 'sql-executed-once-only')
    intents = wire.parse((directory / 'intents.json').read_bytes())
    need(len(intents) == 3, 'three-original-intents')
    originals = {}
    for index, request in enumerate(executes, 1):
        body = wire.parse(read(request['request']))
        saved = wire.parse(intents[index - 1])
        need(body['request'] == saved['request'] and body['statements'] == saved['statements'] and
             body['request']['id'] == str(index), 'saved-original-sql')
        value = responses[(request['role'], request['serial'])]
        need(value['ok'] and value['value']['state'] == 'committed', 'original-server-commit')
        original = value['value']
        raw = wire.b64(original['result'])
        need(wire.receipt_hash(original['receipt'], raw) == original['receipt']['result_hash'], 'original-result-hash')
        decoded = wire.result(raw)[-1]['rows']
        need(len(decoded) == 1 and decoded[0][0] == index and len(decoded[0][1]) == 64 and
             type(decoded[0][2]) is int, 'native-random-sql')
        originals[index] = original
    acks = select(rows, 'original_ack')
    need(len(acks) == 2 and {row['id'] for row in acks} == {1, 2}, 'two-original-client-acks')
    for row in acks:
        need(row['value'] == originals[row['id']], 'original-ack-bytes')
        exchange = correspondence[row['call']]
        need(exchange['operation'] == 'execute' and
             one(events, 'http_proxy_delivery_finished', role=exchange['role'], serial=exchange['serial'])['complete'], 'ack-was-delivered')
    unknown = one(rows, 'original_unknown')
    need(unknown['id'] == 3 and unknown['outcome'] == 'UNKNOWN' and unknown['attempts'] == 1, 'business-unknown-preserved')
    exchange = correspondence[unknown['call']]
    need(one(events, 'http_proxy_delivery_suppressed', id='business-ack-loss')['serial'] == exchange['serial'], 'unknown-from-real-loss')
    recovered = select(rows, 'recovered_lookup')
    need(len(recovered) == 3 and {row['id'] for row in recovered} == {1, 2, 3}, 'three-cold-lookups')
    for row in recovered:
        need(row['value'] == originals[row['id']], 'recovered-original-result')
        exchange = correspondence[row['call']]
        need(exchange['operation'] == 'lookup' and responses[(exchange['role'], exchange['serial'])]['value'] == row['value'],
             'lookup-actual-response')
    query = correspondence[one(rows, 'recovered_query')['call']]
    value = responses[(query['role'], query['serial'])]
    need(value['ok'] and wire.result(wire.b64(value['value']['result']))[0]['rows'] ==
         wire.result(wire.b64(originals[3]['result']))[-1]['rows'], 'no-sql-replay-counter-and-random')
    captured = correspondence[one(rows, 'snapshot_captured')['call']]
    held = correspondence[one(rows, 'snapshot_retained')['call']]
    original = responses[(captured['role'], captured['serial'])]['value']
    current = responses[(held['role'], held['serial'])]['value']
    need(original['state'] == current['state'] == 'retained' and original['prepared']['reference'] == current['prepared']['reference']
         and original['prepared']['point'] == current['prepared']['point'] and
         original['prepared']['point']['sequence'] == '2', 'snapshot-survives-controller')
    guard = one(rows, 'stale_guard')
    exchange = correspondence[guard['call']]
    response = one(events, 'http_proxy_backend_response', role=exchange['role'], serial=exchange['serial'])
    value = responses[(exchange['role'], exchange['serial'])]
    need(guard['outcome'] == 'TARGET_MISMATCH' and not value['ok'] and value['error']['code'] == 'TARGET_MISMATCH',
         'stale-worker-guard-rejected')
    need(not any(exchange['sequence'] < row['sequence'] < response['sequence'] for row in select(events, 's3_request')),
         'stale-guard-no-s3-side-effect')


def audit_history(directory, events, rows, client, read):
    cache = processes(events, read)
    http, responses = exchanges(events, read)
    reports, calls = controllers(events, http, responses, read, cache)
    business(directory, events, http, responses, rows, client, read)
    return {'status': 'PASS_FIXED_CONTROLLER_HISTORY', 'services': 3, 'controller_processes': 2,
            'controller_reports': reports, 'controller_http_calls': calls, 'client_acks': 2,
            'preserved_business_unknowns': 1, 'preserved_claim_unknowns': 1, 'cold_lookups': 3,
            'snapshot_points_preserved': 1, 'aws': 'NOT_RUN', 'production_slo': 'NOT_RUN'}


def audit(directory):
    directory = Path(directory)
    events = read_rows(directory / 'events.jsonl')
    need([row['sequence'] for row in events] == list(range(1, len(events) + 1)), 'complete-event-sequence')
    sources(directory, events)
    return audit_history(directory, events, read_rows(directory / 'business.jsonl'),
                         read_rows(directory / 'http-client-ledger.jsonl'), lambda ref: raw_file(directory, ref))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('evidence', type=Path)
    args = parser.parse_args()
    print(json.dumps(audit(args.evidence), sort_keys=True))
