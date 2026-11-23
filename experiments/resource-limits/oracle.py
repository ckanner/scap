#!/usr/bin/env python3
"""Independent read-only resource audit; does not import the controller/product."""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
import tarfile

import lifecycle_oracle

from spec import BACKPRESSURE, CALLS, CHECK_SQL, LARGE_SQL, PLAN, PROFILE, SCOPES, SMALL_SQL, UNKNOWN_SQL

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'object-service'))
from audit_wire import b64, equal, fingerprint, object_exchanges, object_versions, owned_startup_interval, parse, require, result  # noqa: E402


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def rows(path):
    raw = path.read_bytes()
    require(raw and raw.endswith(b'\n'), 'incomplete trace')
    return [parse(line) for line in raw.splitlines()]


def numbered(values):
    equal([v['sequence'] for v in values], list(range(1, len(values) + 1)), 'trace sequence gap')
    require(all(type(v['sequence']) is int and type(v.get('schema')) is int and v['schema'] == 1
                for v in values), 'invalid trace schema')
    moments = [v['monotonic_ns'] for v in values]
    require(all(type(n) is int and n > 0 for n in moments), 'invalid trace clock')
    require(all(a < b for a, b in zip(moments, moments[1:])), 'trace clock order')


def only(values, why):
    require(len(values) == 1, why)
    return values[0]


def raw(row, body='body', digest='sha256'):
    value = b64(row[body])
    require(sha(value) == row[digest], 'raw byte digest mismatch')
    return value


def event(all_rows, name):
    return only([r for r in all_rows if r['event'] == name], 'missing or duplicate ' + name)


def keyed(all_rows, name):
    found = [r for r in all_rows if r['event'] == name]
    require(len(found) == len({r['id'] for r in found}), 'duplicate operation identity')
    return {r['id']: r for r in found}


def original_intent(value):
    expected = {'scope': SCOPES['a'], 'statements': [{'sql': UNKNOWN_SQL, 'params': []}],
                'request': {'epoch': '1', 'id': '1', 'principal': '11',
                            'fingerprint': fingerprint([{'sql': UNKNOWN_SQL, 'params': []}])}}
    equal(value, expected, 'original SDK intent differs from frozen SQL identity')


def expected_call(label, original):
    name = 'b' if label.startswith('b_') or label.endswith('other_tenant') else 'a'
    body = {'version': 1, 'scope': SCOPES[name]}
    if label.endswith('_create'):
        body.update(operation='create', nonce='501' if name == 'a' else '511')
    elif label.endswith('_activate'):
        body.update(operation='activate', expected_revision='1', nonce='502' if name == 'a' else '512')
    elif label.endswith('_control'):
        body.update(operation='status')
    elif label == 'timeout_execute':
        body.update(operation='execute', request=original['request'], statements=original['statements'])
    elif label in ('original_lookup', 'original_cancel', 'cancelled_lookup'):
        body.update(operation='cancel' if label == 'original_cancel' else 'lookup', request=original['request'])
    else:
        sql = LARGE_SQL if label == 'response_held' else CHECK_SQL if label == 'effect_check' else SMALL_SQL
        body.update(operation='query', statements=[{'sql': sql, 'params': []}])
    return body, ('rival' if label in BACKPRESSURE else name)


def http(all_rows, original):
    requests, responses, headers, sent = (keyed(all_rows, name) for name in
        ('http_input', 'http_response', 'http_headers', 'http_body_sent'))
    equal(list(requests), list(CALLS), 'offered HTTP denominator/order changed')
    for collection in (responses, headers, sent):
        equal(sorted(collection), sorted(CALLS), 'missing or extra HTTP outcome')
    calls = {}
    for label in CALLS:
        first, last, head, send = (v[label] for v in (requests, responses, headers, sent))
        request_raw, response_raw = raw(first), raw(last)
        body, principal = expected_call(label, original)
        equal(parse(request_raw), body, 'HTTP request differs from frozen input')
        equal(first['principal'], principal, 'wrong authenticated principal label')
        admission = 'control' if body['operation'] in ('status', 'lookup', 'cancel') else (
            'recovery' if body['operation'] == 'activate' else 'data')
        equal(first['admission'], admission, 'admission class changed')
        equal((first['method'], first['path']), ('POST', '/v1'), 'HTTP route changed')
        require(first['partial'] is (label == 'body_held') and first['slow'] is (label == 'response_held'),
                'transport fault labels changed')
        require(first['monotonic_ns'] < send['monotonic_ns'] < head['monotonic_ns'] < last['monotonic_ns'],
                'HTTP raw input/send/headers/response order')
        prefix = request_raw[:1] if label == 'body_held' else request_raw
        equal((send['bytes'], send['total_bytes'], send['sha256']), (len(prefix), len(request_raw), sha(prefix)),
              'actual sent prefix differs')
        expected = 429 if label in BACKPRESSURE else 503 if label == 'timeout_execute' else 200
        require(type(last['status']) is int and last['status'] == head['status'] == expected, 'wrong HTTP outcome')
        value = parse(response_raw)
        if expected != 200:
            code = 'BACKPRESSURE' if expected == 429 else 'UNKNOWN'
            equal(value, {'ok': False, 'error': {'code': code, 'message': code}}, 'wrong failure semantics')
        else:
            require(set(value) == {'ok', 'value'} and value['ok'] is True, 'invalid success envelope')
        calls[label] = {'request': first, 'response': last, 'headers': head, 'body': body, 'value': value}
    completed = event(all_rows, 'http_body_completed')
    require(completed['id'] == 'body_held', 'completed another upload')
    tail = raw(requests['body_held'])[1:]
    equal((completed['bytes'], completed['sha256']), (len(tail), sha(tail)), 'completed upload differs from original input')
    for label in ('body_same_tenant', 'body_other_tenant', 'body_control'):
        require(sent['body_held']['monotonic_ns'] < requests[label]['monotonic_ns'] <
                responses[label]['monotonic_ns'] < completed['monotonic_ns'], 'probe ran after upload completed')
    require(completed['monotonic_ns'] < headers['body_held']['monotonic_ns'], 'upload response preceded final body')
    for label in ('response_same_tenant', 'response_other_tenant', 'response_control'):
        require(headers['response_held']['monotonic_ns'] < requests[label]['monotonic_ns'] <
                responses[label]['monotonic_ns'] < responses['response_held']['monotonic_ns'],
                'slow response probe ran outside held response')
    buffer = event(all_rows, 'receive_buffer')
    require(buffer['id'] == 'response_held' and buffer['configured'] == PLAN['socket_receive_buffer']
            and type(buffer['observed']) is int and buffer['observed'] > 0, 'missing actual receive-buffer setting')
    return calls


def values(calls):
    for label, call in calls.items():
        if call['response']['status'] != 200:
            continue
        value, operation = call['value']['value'], call['body']['operation']
        if operation == 'query':
            require(set(value) == {'result'}, 'query fields changed')
            decoded = result(b64(value['result']))
            require(len(decoded) == 1 and decoded[0]['affected_rows'] == 0
                    and decoded[0]['last_insert_rowid'] == 0, 'query result shape/metadata')
            if label == 'response_held':
                equal(decoded[0]['columns'], ['value' + str(i) for i in range(8)], 'large result columns changed')
                require(len(decoded[0]['rows']) == 1 and len(decoded[0]['rows'][0]) == 8, 'large result row shape')
                require(all(type(v) is bytes and len(v) == 1048576 and v == bytes(1048576)
                            for v in decoded[0]['rows'][0]), 'large result bytes changed')
            else:
                equal(decoded[0]['columns'], ['effects'] if label == 'effect_check' else ['witness'], 'query columns')
                equal(decoded[0]['rows'], [[0 if label == 'effect_check' else 7]], 'query values changed')
                require(type(decoded[0]['rows'][0][0]) is int, 'integer query value changed wire type')
        elif operation in ('create', 'activate', 'status'):
            equal(value['scope'], call['body']['scope'], 'returned scope changed')
            require(value['owner_instance'] == PLAN['worker_instance'] and value['sequence'] == '0', 'SQL unexpectedly committed')
            revision = '1' if operation == 'create' else '3' if label == 'response_control' else '2'
            require(value['revision'] == revision and value['active'] is (operation != 'create'), 'unexpected authority state')
        elif label == 'original_lookup':
            equal(value, {'state': 'unknown'}, 'UNKNOWN became absent/committed or was retried')
        else:
            require(value['state'] == 'cancelled' and set(value) == {'state', 'transition'}, 'original cancellation barrier missing')
            require(value['transition'] == {'revision': '3', 'nonce': '1'}, 'cancel used another transition')
    equal(calls['original_cancel']['value'], calls['cancelled_lookup']['value'], 'cancellation proof changed')


def observation_windows(all_rows, calls, originals, events, complete_row, release_row):
    """Bind every snapshot to its original command and external phase window.

    Quota and registry are separate reads. Intermediate polls may legitimately
    see the refund-to-aggregation gap; they must still belong to this exact
    bounded observation sequence and retain their actual source timestamps.
    """
    commands = [(row, parse(raw(row, 'raw'))) for row in all_rows if row['event'] == 'operator_command']
    offered = [(row, value) for row, value in commands if value['operation'] == 'observe']
    observed = [(row, value) for row, value in zip(originals, events) if value['event'] == 'admission_observed']
    require(all(set(value) == {'operation', 'id'} and isinstance(value['id'], str)
                for _, value in offered), 'observation command fields')
    require(all(set(value['fields']) == {'id', 'data_available', 'control_available', 'recovery_available', 'lifecycle'}
                and isinstance(value['fields']['id'], str) for _, value in observed), 'observation event fields')
    require(all(type(value['fields'][key]) is int and 0 <= value['fields'][key] <= 2
                for _, value in observed for key in ('data_available', 'control_available', 'recovery_available')),
            'observation quota counter')
    by_command = {value['id']: row for row, value in offered}
    by_observation = {value['fields']['id']: row for row, value in observed}
    require(len(by_command) == len(offered) and len(by_observation) == len(observed), 'duplicate observation identity')
    equal(sorted(by_command), sorted(by_observation), 'observe command/event identity mismatch')
    shutdown = only([row for row, value in commands if value['operation'] == 'shutdown'], 'missing observation shutdown boundary')
    first_byte = keyed(all_rows, 'http_body_sent')['body_held']['monotonic_ns']
    full_body = event(all_rows, 'http_body_completed')['monotonic_ns']
    windows = {
        'body-held': (first_byte, full_body),
        'body-released': (calls['body_held']['response']['monotonic_ns'], calls['body_after']['request']['monotonic_ns']),
        'after-http-timeout': (calls['timeout_execute']['response']['monotonic_ns'], release_row['monotonic_ns']),
        'worker-released': (max(calls['timeout_control']['response']['monotonic_ns'], complete_row['monotonic_ns']),
                            calls['after_worker']['request']['monotonic_ns']),
        'slow-response': (calls['response_held']['headers']['monotonic_ns'], calls['response_held']['response']['monotonic_ns']),
        'response-released': (calls['response_held']['response']['monotonic_ns'], calls['response_after']['request']['monotonic_ns']),
        'final': (calls['response_after']['response']['monotonic_ns'], shutdown['monotonic_ns']),
    }
    command_indices = {phase: [] for phase in lifecycle_oracle.PHASES}
    observed_indices = {phase: [] for phase in lifecycle_oracle.PHASES}
    for row, value in offered:
        phase, index = lifecycle_oracle.phase_id(value['id'])
        command_indices[phase].append(index)
        observed_row = by_observation[value['id']]
        lower, upper = windows[phase]
        require(lower < row['monotonic_ns'] < observed_row['monotonic_ns'] < upper,
                'observation command/event outside phase window: ' + phase)
    for _, value in observed:
        phase, index = lifecycle_oracle.phase_id(value['fields']['id'])
        observed_indices[phase].append(index)
    for phase in lifecycle_oracle.PHASES:
        indices = command_indices[phase]
        require(1 <= len(indices) <= 100 and indices == list(range(len(indices)))
                and observed_indices[phase] == indices, 'observation phase index gap or order: ' + phase)


def worker_events(all_rows, calls):
    originals = [row for row in all_rows if row['event'] == 'worker_event']
    require(all(len(raw(row, 'raw')) <= PLAN['max_worker_event_bytes'] for row in originals), 'worker event byte bound')
    events = [parse(raw(row, 'raw')) for row in originals]
    equal([v['sequence'] for v in events], list(range(1, len(events) + 1)), 'worker output sequence gap')
    require(all(v['schema'] == 1 and type(v['elapsed_ns']) is int and v['elapsed_ns'] >= 0 for v in events), 'worker clock schema')
    require(all(a['elapsed_ns'] <= b['elapsed_ns'] for a, b in zip(events, events[1:])), 'worker clock reversed')
    require(not any(v['event'] == 'head_pause_expired' for v in events), 'pause expired instead of explicit release')
    commands = [parse(raw(row, 'raw')) for row in all_rows if row['event'] == 'operator_command']
    require(len(commands) == len({r['id'] for r in commands}), 'operator command repeated')
    for kind, expected in [('arm', {'operation': 'arm', 'id': 'pause', 'key': PLAN['pause_key']}),
                           ('release', {'operation': 'release', 'id': 'release'}),
                           ('shutdown', {'operation': 'shutdown', 'id': 'shutdown'})]:
        equal(only([v for v in commands if v['operation'] == kind], 'missing explicit operator ' + kind), expected, 'operator changed')
    require(all(v['operation'] in ('arm', 'release', 'observe', 'shutdown') for v in commands), 'unplanned operator command')
    entered = event(events, 'head_pause_entered')
    released = event(events, 'pause_released')
    returned = event(events, 'head_pause_returned')
    require(entered['fields']['key'] == released['fields']['key'] == returned['fields']['key'] == PLAN['pause_key'], 'paused another HEAD')
    require(entered['fields']['deadline_remaining_ns'] > 0 and returned['fields']['deadline_elapsed'] is True
            and returned['fields']['outcome'] == 'error', 'original deadline was extended or response fabricated')
    require(entered['sequence'] < released['sequence'] < returned['sequence'], 'pause return preceded explicit release')
    starts = [v for v in events if v['event'] == 'worker_entered']
    ends = [v for v in events if v['event'] == 'worker_completed']
    require(len(starts) == len(ends) == len(CALLS) - len(BACKPRESSURE), 'missing/extra actual worker call')
    equal(sorted(v['fields']['serial'] for v in starts), list(range(1, len(starts) + 1)), 'worker call serial gap')
    equal(sorted(v['fields']['serial'] for v in ends), list(range(1, len(starts) + 1)), 'worker completion serial gap')
    require(all(v['fields']['principal'] in (11, 22) for v in starts), 'refused principal entered worker')
    expected_workers = Counter((call['body']['operation'], int(call['body']['scope']['tenant']),
        11 if call['request']['principal'] == 'a' else 22, int(call['body']['scope']['database']))
        for label, call in calls.items() if label not in BACKPRESSURE)
    observed_workers = Counter((v['fields']['operation'], v['fields']['tenant'],
        v['fields']['principal'], v['fields']['database']) for v in starts)
    require(expected_workers == observed_workers, 'worker operation/identity inventory differs from actual HTTP')
    for start in starts:
        finish = only([v for v in ends if v['fields']['serial'] == start['fields']['serial']], 'missing worker completion')
        for key in ('operation', 'tenant', 'principal', 'database'):
            equal(start['fields'][key], finish['fields'][key], 'completion bound another worker call')
        require(finish['sequence'] > start['sequence'], 'worker completion preceded entry')
        require(finish['fields']['outcome'] == ('UNKNOWN' if start['fields']['operation'] == 'execute' else 'ok'),
                'unexpected completed worker outcome')
    execution = only([v for v in starts if v['fields']['operation'] == 'execute'], 'original execute was retried')
    complete = only([v for v in ends if v['fields']['serial'] == execution['fields']['serial']], 'missing original worker completion')
    require(execution['sequence'] < entered['sequence'] < released['sequence'] < complete['sequence'], 'worker did not outlive pause')
    require(complete['fields']['outcome'] == 'UNKNOWN', 'paused worker changed unknown semantics')
    release_row = originals[released['sequence'] - 1]
    for label in ('timeout_same_tenant', 'timeout_other_tenant', 'timeout_control'):
        require(calls['timeout_execute']['response']['monotonic_ns'] < calls[label]['request']['monotonic_ns'] <
                calls[label]['response']['monotonic_ns'] < release_row['monotonic_ns'], 'probe did not run after timeout and before release')
    require(originals[complete['sequence'] - 1]['monotonic_ns'] < calls['after_worker']['request']['monotonic_ns'],
            'post-worker probe preceded actual completion')
    observations = [v for v in events if v['event'] == 'admission_observed']
    observation_windows(all_rows, calls, originals, events, originals[complete['sequence'] - 1], release_row)
    lifecycle = lifecycle_oracle.observations(events, calls, BACKPRESSURE)
    for phase in ('body-held', 'after-http-timeout', 'slow-response'):
        selected = [v for v in observations if v['fields']['id'].startswith(phase + '-')]
        require(1 <= len(selected) <= 100 and selected[-1]['fields']['data_available'] == 1, 'held intake was not directly observed')
        require(all(v['fields']['control_available'] == 2 and v['fields']['recovery_available'] == 2 for v in selected),
                'data hold consumed independent admission classes')
    for phase, finished, following in (('body-released', 'body_held', 'body_after'),
                                      ('worker-released', 'timeout_control', 'after_worker'),
                                      ('response-released', 'response_held', 'response_after')):
        selected = [v for v in observations if v['fields']['id'].startswith(phase + '-')]
        require(1 <= len(selected) <= 100 and selected[-1]['fields']['data_available'] == 2,
                'intake was not restored after actual completion')
        row = originals[selected[-1]['sequence'] - 1]
        require(calls[finished]['response']['monotonic_ns'] < row['monotonic_ns'] <
                calls[following]['request']['monotonic_ns'], 'restored intake observation outside release interval')
        if phase == 'worker-released':
            require(originals[complete['sequence'] - 1]['monotonic_ns'] < row['monotonic_ns'],
                    'intake restore observed before original worker completed')
    event(events, 'worker_process_finished')
    return {'observed_calls': len(starts), 'explicit_pause': 1, 'server_timeouts_with_live_worker': 1,
            'late_worker_outcome': complete['fields']['outcome'], 'lifecycle': lifecycle}


def processes(all_rows, build):
    pairs = [('prepare_started', 'prepare_stopped', 0), ('worker_started', 'worker_stopped', 0)]
    identities = set()
    for before, after, code in pairs:
        start, stop = event(all_rows, before), event(all_rows, after)
        equal(start['identity'], stop['identity'], 'owned process identity changed')
        identity = start['identity']
        require(identity['pid_source'] == 'owned_Popen_child' and type(identity['pid']) is int and identity['pid'] > 0,
                'not an owned child')
        identities.add((identity['pid'], identity['spawn_monotonic_ns']))
        require(start['monotonic_ns'] < stop['monotonic_ns'] and stop['wait_status'] == code, 'owned child completion changed')
        usage = stop['kernel_usage']
        require(usage['available'] is True and usage['source'] == 'kernel_wait4_owned_child' and usage['maxrss_bytes'] > 0,
                'missing owned wait4 evidence')
        if before == 'worker_started':
            equal(start['binary'], build['binary'], 'actual worker differs from release build')
        require(stop['forced'] is False, 'workload process was forcibly killed')
    first, last = event(all_rows, 'backend_started'), event(all_rows, 'backend_stopped')
    require(first['monotonic_ns'] < last['monotonic_ns'], 'backend lifecycle reversed')
    starts = {p['role']: p for p in first['processes']}
    stops = {p['role']: p for p in last['processes']}
    equal(sorted(starts), ['filer', 'master', 's3', 'volume'], 'backend process inventory')
    equal(sorted(stops), sorted(starts), 'backend shutdown inventory')
    for role, start in starts.items():
        stop = stops[role]
        for key in ('pid', 'spawn_monotonic_ns', 'pid_source'):
            equal(start[key], stop[key], 'backend identity changed')
        identities.add((start['pid'], start['spawn_monotonic_ns']))
        require(start['pid_source'] == 'owned_Popen_child' and stop['wait_status'] == -9, 'backend not owned/reaped')
        usage = stop['kernel_usage']
        require(usage['available'] is True and usage['source'] == 'kernel_wait4_owned_child' and usage['maxrss_bytes'] > 0,
                'backend lacks owned wait4')
    require(len(identities) == 6, 'owned process identity reused')
    equal(event(all_rows, 'proxy_stopped')['errors'], [], 'proxy failed')
    equal(event(all_rows, 'cleanup_finished')['errors'], [], 'cleanup failed')
    return {'owned_workload_processes': 6, 'all_recorded_children_reaped': True}


def worker_startup(all_rows):
    listening = only([row for row in all_rows if row['event'] == 'worker_event'
                      and parse(raw(row, 'raw'))['event'] == 'listening'], 'worker listening inventory')
    return {'worker': PLAN['worker_instance'], 'role': None,
            **owned_startup_interval(event(all_rows, 'worker_started'), listening)}


def build_evidence(directory):
    receipt = parse((directory / 'build.json').read_bytes())
    require(receipt['status'] == 'passed' and receipt['exit_code'] == 0 and receipt['source_dirty'] is False,
            'build was not accepted frozen source')
    require(receipt['profile'] == 'release', 'wrong build profile')
    for name, digest in receipt['logs'].items():
        require(sha((directory / ('build-' + name)).read_bytes()) == digest, 'build log changed')
    cargo = rows(directory / 'build-cargo.stdout.jsonl')
    require(cargo[-1] == {'reason': 'build-finished', 'success': True}
            and sum(r.get('reason') == 'build-finished' for r in cargo) == 1, 'Cargo did not finish exactly once')
    binary = receipt['binary']
    require(sha(Path(binary['path']).read_bytes()) == binary['sha256'], 'actual worker binary changed')
    executables = [r for r in cargo if r.get('reason') == 'compiler-artifact' and r.get('executable')]
    require(len(executables) == 1 and executables[0]['target']['name'] == 'scap-resource-limits'
            and executables[0]['executable'] == binary['path'] and executables[0]['profile']['test'] is False,
            'Cargo executable identity differs')
    require(receipt['native_archives'], 'native archive identity missing')
    native = [r for r in cargo if r.get('reason') == 'build-script-executed'
              and r.get('package_id', '').rsplit('#', 1)[-1].split('@', 1)[0] == 'libsql-ffi']
    require(len(native) == 1, 'missing/duplicate Cargo native build event')
    native_directory = Path(native[0]['out_dir']).resolve()
    require(native_directory.parent.parent == Path(receipt['target']) / 'release' / 'build', 'native archive escaped release build')
    equal({str(p.resolve()): sha(p.read_bytes()) for p in native_directory.rglob('*.a')}, receipt['native_archives'],
          'native archive receipt not bound to actual Cargo output')
    for path, digest in receipt['native_archives'].items():
        require(sha(Path(path).read_bytes()) == digest, 'native archive changed')
    for tool in receipt['tools'].values():
        require(sha(Path(tool['path']).read_bytes()) == tool['sha256'], 'compiler tool changed')
    archive = directory / 'source.tar'
    require(sha(archive.read_bytes()) == receipt['source_archive_sha256'], 'source archive changed')
    with tarfile.open(archive) as source:
        members = source.getmembers()
        require(len(members) == len(receipt['inputs']), 'source archive denominator')
        require(len({m.name for m in members}) == len(members), 'duplicate source member')
        for member in members:
            require(member.isfile() and not member.name.startswith('/') and '..' not in Path(member.name).parts,
                    'unsafe/non-file source member')
            require(member.name in receipt['inputs'] and sha(source.extractfile(member).read()) == receipt['inputs'][member.name],
                    'archived source differs from actual build inputs')
    return receipt


def audit(directory):
    directory = Path(directory)
    equal(parse((directory / 'plan.json').read_bytes()), PLAN, 'frozen resource plan changed')
    build = build_evidence(directory)
    original = parse((directory / 'original-intent.json').read_bytes())
    original_intent(original)
    all_rows = rows(directory / 'events.jsonl')
    numbered(all_rows)
    preparing = event(all_rows, 'prepare_started')
    equal(parse(raw(preparing, 'input', 'input_sha256')), {'scope': SCOPES['a'], 'sql': UNKNOWN_SQL},
          'original SDK input changed')
    require(sha(Path(preparing['binary']['path']).read_bytes()) == preparing['binary']['sha256'],
            'original SDK runtime changed')
    prepared = event(all_rows, 'prepare_stopped')
    equal(parse(raw(prepared, 'stdout', 'stdout_sha256')), original, 'intent is not the actual SDK child output')
    calls = http(all_rows, original)
    values(calls)
    worker = worker_events(all_rows, calls)
    process = processes(all_rows, build)
    config_raw = (directory / 'configuration.json').read_bytes()
    require(sha(config_raw) == event(all_rows, 'worker_started')['configuration_sha256'], 'actual service configuration changed')
    config = parse(config_raw)
    diagnostics = config['lifecycle_diagnostics']
    require(set(diagnostics) == {'version', 'token_sha256'} and diagnostics['version'] == PLAN['lifecycle_version']
            and isinstance(diagnostics['token_sha256'], str) and len(diagnostics['token_sha256']) == 64
            and all(char in '0123456789abcdef' for char in diagnostics['token_sha256']), 'lifecycle configuration changed')
    credentials = config['credentials']
    require(len(credentials) == 3 and len({v['sha256'] for v in credentials}) == 3, 'credential identity denominator')
    require(diagnostics['token_sha256'] not in {v['sha256'] for v in credentials}, 'diagnostic credential is not independent')
    for label, tenant, principal in (('a', '7', '11'), ('rival', '7', '13'), ('b', '8', '22')):
        credential = only([v for v in credentials if v['tenant'] == tenant and v['principal'] == principal],
                          'missing/duplicate configured principal')
        require(credential['deployment'] == '1' and credential['provision'] is True, 'configured credential changed')
        for call in calls.values():
            if call['request']['principal'] == label:
                equal(call['request']['credential_sha256'], credential['sha256'], 'actual HTTP credential differs from principal')
    for name in ('data_profile', 'control_profile', 'recovery_profile'):
        equal(config['admission'][name], PROFILE, 'resource profile changed')
    for name in ('data_intake', 'control_intake', 'recovery_intake'):
        require(config['admission'][name] == 2, 'global intake changed')
    require(config['admission']['max_body_bytes'] == PLAN['body_bytes'] and
            config['admission']['timeout_ms'] == PLAN['timeout_ms'], 'actual deadline/body profile changed')
    history = rows(directory / 'history.jsonl')
    numbered(history)
    startups = [worker_startup(all_rows)]
    requests, responses = object_exchanges(history, phases=set(CALLS), startups=startups)
    for row in history:
        if row['event'].startswith('object_'):
            payload = b64(row['request_body'])
            require(len(payload) == row['request_bytes'] and sha(payload) == row['request_sha256'], 'S3 request bytes changed')
            signing = row['signing']
            require(signing['algorithm'] == 'AWS4-HMAC-SHA256' and signing['payload_sha256'] == sha(payload)
                    and signing['access_key_sha256'] == event(all_rows, 'backend_started')['access_key_sha256'],
                    'S3 signing identity changed')
            if row['event'] in ('object_response', 'object_response_delivered'):
                payload = b64(row['response_body'])
                require(len(payload) == row['response_bytes'] and sha(payload) == row['response_sha256'], 'S3 response bytes changed')
    bindings = {serial: {row['phase']} for serial, row in requests.items()}
    versions = object_versions(requests, responses, calls=calls, bindings=bindings)
    head_puts = [row for row in requests.values() if row['method'] == 'PUT' and row['path'].endswith('/head')]
    equal(Counter(row['phase'] for row in head_puts), Counter(('a_create', 'a_activate', 'b_create', 'b_activate', 'original_cancel')),
          'unexpected original execute or extra HEAD publication')
    unauthorized = event(all_rows, 'unsigned_backend_response')
    require(unauthorized['status'] == 403 and len(raw(unauthorized)) <= 65536, 'backend allowed unsigned authority access')
    equal(event(all_rows, 'unsigned_backend_input'), {**event(all_rows, 'unsigned_backend_input'),
          'method': 'GET', 'path': '/scap-test/' + PLAN['pause_key'], 'authorization_present': False}, 'wrong unsigned probe')
    summary = parse((directory / 'summary.json').read_bytes())
    require(summary['source_unchanged'] is True and summary['private_deleted'] is True
            and not Path(summary['private_directory']).exists(), 'source/cleanup completion missing')
    return {'schema': 1, 'status': 'passed', 'http_calls': len(calls), 'backpressure': len(BACKPRESSURE),
            'original_execute_attempts': 1, 'original_unknown': 1, 'original_cancellation_proved': True,
            's3_requests': len(requests), 'object_versions': versions, 'worker': worker, 'processes': process,
            'transport_holds': ['incomplete_body', 'server_timeout_with_running_worker', 'slow_response'],
            'final_bytes_clone_proof': PLAN['final_bytes_clone_proof'], 'aws_standard': 'NOT_RUN',
            'production_slo': 'NOT_RUN', 'evidence_sha256': {name: sha((directory / name).read_bytes())
              for name in ('events.jsonl', 'history.jsonl', 'plan.json', 'original-intent.json', 'configuration.json')}}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('evidence', type=Path)
    args = parser.parse_args()
    print(json.dumps(audit(args.evidence), indent=2, sort_keys=True))
