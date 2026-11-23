#!/usr/bin/env python3
"""Independent original-byte audit for equal-seed-v1; no runner/product import."""
import argparse
from collections import Counter
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import sqlite3
import struct
import tempfile
import time

import lifecycle
import shared
import spec

base = shared.reader()
Rejected, need, same, moment, raw, one = base.Rejected, base.need, base.same, base.moment, base.raw, base.one


@contextmanager
def deadline(seconds):
    def expired(*_):
        raise Rejected('independent-audit-deadline')
    old = signal.signal(signal.SIGALRM, expired)
    previous = signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, *previous)
        signal.signal(signal.SIGALRM, old)


def ledger(path, row_limit, byte_limit):
    need(path.is_file() and not path.is_symlink() and path.stat().st_size <= byte_limit, 'ledger-byte-budget')
    result = base.rows(path)
    need(len(result) <= row_limit, 'ledger-row-budget')
    return result


def configuration(config, enabled, contract):
    profile = config.get('lifecycle_diagnostics', {})
    need(set(profile) == {'version', 'token_sha256'} and type(profile['version']) is int
         and profile['version'] == 1 and type(profile['token_sha256']) is str
         and re.fullmatch('[0-9a-f]{64}', profile['token_sha256']) is not None, 'diagnostic-profile')
    expected = spec.configuration(config['listen'], config['cache_directory'], config['s3']['endpoint'],
        config['credentials'][0]['sha256'], enabled, contract, profile['token_sha256'])
    same(config, expected, 'paired-configuration')


def s3_exchanges(rows):
    same([row['sequence'] for row in rows], list(range(1, len(rows) + 1)), 's3-trace-denominator')
    exchanges = {}
    for row in rows:
        exchanges.setdefault(row['request_serial'], []).append(row)
    for items in exchanges.values():
        need(len(items) == 4 and Counter(row['event'] for row in items)
             == Counter(('request', 'forwarded', 'response', 'delivered')), 's3-exchange')


def head_conditions(directory, rows):
    replies = {row['request_serial']: row for row in rows if row['event'] == 'response'}
    heads = []
    for row in rows:
        if row['event'] == 'request' and row['method'] == 'PUT' and row['path'] == base.HEAD:
            response = replies[row['request_serial']]
            if response['status'] == 200:
                head = base.wire.parse(raw(directory, row['request']))
                heads.append((head['head_serial'], row, response))
    heads.sort(key=lambda value: value[0])
    need(heads and heads[0][1]['if_none_match'] == '*', 'head-root')
    for (_, _, previous), (_, request, _) in zip(heads, heads[1:]):
        need(request['if_match'] == previous['etag'] and moment(previous) < moment(request), 'original-head-cas')


def round_boundaries(directory):
    result = []
    for cell in spec.cells():
        events = base.rows(Path(directory) / cell['name'] / 'events.jsonl')
        starts = [row for row in events if row['event'] == 'envelope_process_started' and row['role'] == 'backend']
        ends = [row for row in events if row['event'] == 'envelope_process_reaped' and row['role'] == 'backend']
        need(len(starts) == len(ends) == 4, 'round-backend-boundary')
        result.append((min(row['spawn_requested_ns'] for row in starts), max(moment(row) for row in ends)))
    return result


def validate_round_order(boundaries):
    need(len(boundaries) == len(spec.cells()) and all(begin < end for begin, end in boundaries)
         and all(left[1] < right[0] for left, right in zip(boundaries, boundaries[1:])), 'round-run-order')


def stage_deadlines(events, contract):
    ranges = base.phase_intervals(events, contract)
    start = one([row for row in events if row['event'] == 'cell_started'], 'cell-start')
    final = one([row for row in events if row['event'] == 'cell_final_allocation'], 'cell-finish')
    service = one([row for row in events if row['event'] == 'service_started'], 'owned-service')
    need(moment(service) - moment(start) <= spec.DEADLINES['startup_seconds'] * 1_000_000_000,
         'startup-deadline')
    for name, beginning, ending, seconds in (
            ('seed', ranges['seed'][0], ranges['seed_rows'][1], spec.DEADLINES['seed_seconds']),
            ('load', *ranges['load'], spec.DEADLINES['load_seconds']),
            ('settlement', *ranges['verify'], spec.DEADLINES['settlement_seconds'])):
        need(ending - beginning <= seconds * 1_000_000_000, name + '-deadline')
    need(moment(final) <= start['deadline_ns']
         and moment(final) - moment(start) <= spec.DEADLINES['cell_seconds'] * 1_000_000_000, 'cell-deadline')


def seed_ack(planned, calls):
    selected = {key for key, item in planned.items() if item['phase'] == 'seed_rows'
                and item['operation'] == 'execute'}
    need(len(selected) == spec.SEED_ROWS, 'seed-denominator')
    need(all(calls[key]['finish']['ok'] and calls[key]['reply'] is not None
             and calls[key]['reply']['ok'] and calls[key]['reply']['value']['state'] == 'committed'
             for key in selected), 'seed-original-ack')


def expected_cohort(planned, calls):
    expected = {lane: 0 for lane in spec.LANES}
    for key, item in planned.items():
        if item['phase'] != 'load':
            continue
        call = calls[key]
        # A transport-only observation cannot distinguish pre-acquire loss from
        # acquired work. Preserve UNKNOWN; do not invent an exact denominator.
        need(call['reply'] is not None, 'cohort-acquire-unresolved')
        lane = 'data' if item['operation'] == 'execute' else 'control'
        rejection = call['rejection']
        if rejection is not None and rejection['reason'].startswith('intake_' + lane + '_'):
            continue
        expected[lane] += 1
    return expected


def lane_for_operation(operation):
    if operation == 'activate':
        return 'recovery'
    return 'data' if operation in ('execute', 'create', 'query') else 'control'


def complete_intervals(delta, planned, calls, phases=('load',)):
    proven = {lane: 0 for lane in spec.LANES}
    for key, item in planned.items():
        if item['phase'] not in phases:
            continue
        call = calls[key]
        if call['finish']['ok'] and call['reply'] is not None and call['reply']['ok']:
            proven[lane_for_operation(item['operation'])] += 1
    for lane, count in proven.items():
        for interval in delta['lanes'][lane]['intervals'].values():
            need(interval['completed'] >= count, 'lifecycle-success-interval-complete')
    return proven


def seed_baseline(snapshot, planned, calls):
    expected = {lane: 0 for lane in spec.LANES}
    for key, item in planned.items():
        if item['phase'] not in ('seed', 'seed_rows'):
            continue
        call = calls[key]
        need(call['finish']['ok'] and call['reply'] is not None and call['reply']['ok'], 'baseline-seed-ack')
        expected[lane_for_operation(item['operation'])] += 1
    for lane, count in expected.items():
        value = snapshot['lanes'][lane]
        need(value['acquired'] == value['released'] == count and value['active'] == 0,
             'lifecycle-seed-cohort-denominator')
    complete_intervals(snapshot, planned, calls, ('seed', 'seed_rows'))
    return expected


def diagnostic_windows(rows, seed_end, load_start, load_end, settlement_start):
    counts = Counter(row['boundary'] for row in rows)
    need(set(counts) == {'baseline', 'end'} and all(1 <= value <= 8 for value in counts.values()),
         'diagnostic-boundary-budget')
    same([row['boundary'] for row in rows], ['baseline'] * counts['baseline'] + ['end'] * counts['end'],
         'diagnostic-boundary-order')
    previous = 0
    for row in rows:
        need(previous < row['request_ns'] < row['response_ns'], 'diagnostic-request-order')
        previous = row['response_ns']
        lower, upper = (seed_end, load_start) if row['boundary'] == 'baseline' else (load_end, settlement_start)
        need(lower < row['request_ns'] < row['response_ns'] < upper, 'diagnostic-poll-window')


def diagnostic_cohort(directory, config, events, rows, planned, calls):
    need(0 < len(rows) <= spec.BOUNDS['diagnostic_gets'], 'diagnostic-denominator')
    same([row['attempt'] for row in rows], list(range(1, len(rows) + 1)), 'diagnostic-attempt-order')
    request_digest = config['lifecycle_diagnostics']['token_sha256']
    need(request_digest != config['credentials'][0]['sha256'], 'diagnostic-independent-credential')
    total = 0
    observations = {}
    for row in rows:
        need(row['boundary'] in ('baseline', 'end') and row['event'] in
             ('diagnostic_response', 'diagnostic_error'), 'diagnostic-event')
        same(row['request'], {'method': 'GET', 'url': 'http://' + config['listen'] + '/diagnostics/lifecycle',
                             'token_sha256': request_digest}, 'diagnostic-request-source')
        need(type(row['request_ns']) is int and type(row['response_ns']) is int
             and row['request_ns'] < row['response_ns'], 'diagnostic-clock')
        if 'response' in row:
            body = raw(directory, row['response'])
            need(len(body) <= spec.BOUNDS['diagnostic_response_bytes'], 'diagnostic-body-budget')
            total += len(body)
            if row.get('status') == 200:
                try:
                    observations[row['attempt']] = lifecycle.parse(base.wire.parse(body))
                except lifecycle.Invalid as error:
                    raise Rejected(error.rule) from error
    need(total <= spec.BOUNDS['diagnostic_bytes'], 'diagnostic-total-budget')
    selected = {}
    for boundary in ('baseline', 'end'):
        marker = one([row for row in events if row['event'] == 'diagnostic_boundary'
                      and row['boundary'] == boundary], 'diagnostic-boundary')
        original = one([row for row in rows if row['attempt'] == marker['attempt']
                        and row['boundary'] == boundary], 'diagnostic-boundary-source')
        need(original['event'] == 'diagnostic_response' and original['status'] == 200
             and original['attempt'] in observations, 'diagnostic-success')
        same(original['response'], marker['response'], 'diagnostic-boundary-source')
        same(original['response_ns'], marker['response_ns'], 'diagnostic-boundary-source')
        need(marker['response_ns'] <= moment(marker), 'diagnostic-boundary-clock')
        need(original['attempt'] == max(row['attempt'] for row in rows if row['boundary'] == boundary),
             'diagnostic-last-poll')
        need(not any(lifecycle.quiescent(observations[row['attempt']]) for row in rows
                     if row['boundary'] == boundary and row['attempt'] < original['attempt']
                     and row['attempt'] in observations), 'diagnostic-first-quiescent-poll')
        selected[boundary] = observations[original['attempt']], original
    baseline, baseline_raw = selected['baseline']
    end, end_raw = selected['end']
    load_start = moment(one([row for row in events if row['event'] == 'phase_started'
                            and row['phase'] == 'load'], 'load-start'))
    settle_start = moment(one([row for row in events if row['event'] == 'phase_started'
                              and row['phase'] == 'verify'], 'settlement-start'))
    seed_terminals = [moment(call['finish']) for key, call in calls.items()
                      if key in planned and planned[key]['phase'] in ('seed', 'seed_rows')]
    load_terminals = [moment(call['finish']) for key, call in calls.items()
                      if key in planned and planned[key]['phase'] == 'load']
    diagnostic_windows(rows, max(seed_terminals), load_start, max(load_terminals), settle_start)
    need(max(seed_terminals) < baseline_raw['request_ns'] < baseline_raw['response_ns'] < load_start,
         'diagnostic-baseline-cohort')
    need(max(load_terminals) < end_raw['request_ns'] < end_raw['response_ns'] < settle_start,
         'diagnostic-end-cohort')
    try:
        difference = lifecycle.cohort(baseline, end, expected_cohort(planned, calls))
    except lifecycle.Invalid as error:
        raise Rejected(error.rule) from error
    baseline_expected = seed_baseline(baseline, planned, calls)
    proven = complete_intervals(difference, planned, calls)
    return {'status': 'PASSED', 'baseline_attempt': baseline_raw['attempt'],
            'end_attempt': end_raw['attempt'], 'get_attempts': len(rows), 'response_bytes': total,
            'expected_acquires': expected_cohort(planned, calls), 'proven_complete_successes': proven,
            'baseline_expected_acquires': baseline_expected, 'delta': difference,
            'interpretation': 'Quiescent load cohort; overlapping intervals are not additive; histogram bins are not exact quantiles.'}


def index_geometry(objects, head, contract):
    seen = set()
    def visit(checksum, expected_level=None, child=False):
        need(checksum not in seen, 'request-index-cycle-or-alias')
        seen.add(checksum)
        need(len(seen) <= contract.retained_entries // 64 + 1, 'request-index-node-budget')
        key = base.PREFIX + checksum
        need(key in objects, 'request-index-dependency')
        kind, value, body = base.frame(objects[key], key)
        need(kind == 'index' and not body and value['epoch'] == 1, 'request-index-frame')
        if value['kind'] == 'leaf':
            entries = value['entries']
            level = 0
            need(len(entries) <= 128 and (not child or len(entries) >= 64), 'request-index-leaf-width')
        else:
            need(value['kind'] == 'branch' and value['level'] == 1 and not child
                 and 2 <= len(value['children']) <= 20, 'request-index-branch-width')
            level, entries = 1, []
            for reference in value['children']:
                rows, _ = visit(reference['hash'], 0, True)
                ids = [entry['request']['id'] for entry in rows]
                same(reference['summary'], {'first': ids[0], 'last': ids[-1], 'count': len(rows),
                    'result_bytes': sum(entry['result_bytes'] for entry in rows)}, 'request-index-summary')
                entries.extend(rows)
        need(expected_level is None or expected_level == level, 'request-index-level')
        ids = [entry['request']['id'] for entry in entries]
        need(ids == sorted(set(ids)), 'request-index-order')
        return entries, level
    entries, level = visit(head['windows'][0]['root'])
    same(len(entries), head['windows'][0]['count'], 'request-index-denominator')
    return {'level': level, 'nodes': len(seen), 'retained_entries': len(entries),
            'result_bytes': sum(entry['result_bytes'] for entry in entries)}


def sqlite_geometry(image, expected_rows):
    need(image and len(image) % 4096 == 0 and image[:16] == b'SQLite format 3\0', 'image-header')
    need(struct.unpack_from('>I', image, 36)[0] == 0, 'image-freelist')
    with tempfile.TemporaryDirectory(prefix='scap-equal-seed-oracle-') as temporary:
        path = Path(temporary) / 'image.sqlite'
        path.write_bytes(image)
        connection = sqlite3.connect('file:' + str(path) + '?mode=ro&immutable=1', uri=True)
        try:
            same(connection.execute('PRAGMA integrity_check').fetchall(), [('ok',)], 'equal-seed-image-integrity')
            same(connection.execute('PRAGMA freelist_count').fetchone(), (0,), 'image-freelist')
            tables = connection.execute("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY name").fetchall()
            same(tables, [('table', 'paired', 'paired', spec.DDL)], 'fixed-image-schema')
            rows = [list(row) for row in connection.execute(spec.ALL_ROWS)]
            same(rows, expected_rows, 'equal-seed-image-rows')
            pages = connection.execute('SELECT name,pageno,pagetype FROM dbstat ORDER BY pageno').fetchall()
            need(len(pages) == len(image) // 4096 and {row[1] for row in pages} == set(range(1, len(pages) + 1))
                 and all(row[0] in ('sqlite_schema', 'paired') and row[2] in ('leaf', 'internal') for row in pages),
                 'image-page-kinds')
        finally:
            connection.close()
    return {'page_count': len(image) // 4096, 'rows': len(rows), 'schema': tables,
            'freelist_pages': 0, 'overflow_pages': 0}


def geometry_and_cost(directory, s3, events, contract, committed):
    requests = {row['request_serial']: row for row in s3 if row['event'] == 'request'}
    responses = {row['request_serial']: row for row in s3 if row['event'] == 'response'}
    objects, heads = {}, []
    costs = {}
    for serial, request in requests.items():
        response = responses[serial]
        costs.setdefault(request['phase'], Counter())[f"{request['method']}:{response['status']}"] += 1
        if request['method'] != 'PUT' or response['status'] != 200:
            continue
        if request['path'].startswith(base.PREFIX):
            objects[request['path']] = raw(directory, request['request'])
        elif request['path'] == base.HEAD:
            heads.append((moment(response), base.wire.parse(raw(directory, request['request'])), request['request']))
    heads.sort(key=lambda value: value[0])
    load_start = moment(one([row for row in events if row['event'] == 'phase_started'
                            and row['phase'] == 'load'], 'load-start'))
    seed = [value for value in heads if value[0] < load_start][-1]
    final = heads[-1]
    max_nodes = 0
    for _, head, _ in heads:
        geometry = index_geometry(objects, head, contract)
        max_nodes = max(max_nodes, geometry['nodes'])
    seed_closure = base.closure(objects, seed[1], contract)
    final_closure = base.closure(objects, final[1], contract)
    seed_rows = sorted((value['decoded'][0]['rows'][0] for key, value in committed.items()
                        if key.startswith('seed_rows-')), key=lambda row: row[0])
    final_rows = sorted((value['decoded'][0]['rows'][0] for key, value in committed.items()
                         if key != 'schema'), key=lambda row: row[0])
    seed_geometry = sqlite_geometry(seed_closure['image'], seed_rows)
    final_geometry = sqlite_geometry(final_closure['image'], final_rows)
    seed_index = index_geometry(objects, seed[1], contract)
    need(len(seed_rows) == spec.SEED_ROWS and seed_index['retained_entries'] == spec.SEED_ROWS + 1
         and seed_index['result_bytes'] == 36 + 343 * spec.SEED_ROWS, 'equal-seed-retention')
    same([row[:2] for row in seed_rows], [[index, spec.payload(index)] for index in range(spec.SEED_ROWS)],
         'equal-seed-input')
    for key, value in committed.items():
        same(len(value['raw']), 36 if key == 'schema' else 343, 'fixed-original-result-length')
    live = final_closure['dependencies']
    orphan = set(objects) - live
    return {'seed': {**seed_geometry, 'index_level': seed_index['level'],
                    'retained_entries': seed_index['retained_entries'], 'result_bytes': seed_index['result_bytes'],
                    'data_tree_level': 0, 'request_epoch': seed[1]['request_epoch'],
                    'warm_rule': 'fresh backend and cache, original seed ACK and drain, no restart'},
            'seed_source': {'head': seed[2], 'data_root': seed[1]['data_root'],
                            'request_root': seed[1]['windows'][0]['root']},
            'final_image': final_geometry, 'maximum_request_index_nodes': max_nodes,
            's3_method_status_counts': {phase: dict(value) for phase, value in costs.items()},
            'storage': {'all_created_immutable_objects': len(objects),
                'all_created_immutable_bytes': sum(map(len, objects.values())),
                'final_live_objects': len(live), 'final_live_bytes': sum(len(objects[key]) for key in live),
                'orphan_objects': len(orphan), 'orphan_bytes': sum(len(objects[key]) for key in orphan),
                'gc': 'disabled', 'excludes': 'worker identity and mutable HEAD versions'}}


def process_fields(raw_status, complete=True):
    selected = {}
    for line in raw_status.splitlines():
        if ':' not in line:
            continue
        key, value = line.split(':', 1)
        if key in ('Pid', 'Threads', 'VmRSS', 'VmHWM'):
            parts = value.split()
            need(key not in selected and parts and parts[0].isdecimal(), 'resource-status')
            need(parts[1:] == (['kB'] if key.startswith('Vm') else []), 'resource-status-units')
            selected[key] = int(parts[0]) * (1024 if key.startswith('Vm') else 1)
    need(not complete or set(selected) == {'Pid', 'Threads', 'VmRSS', 'VmHWM'}, 'resource-status-fields')
    return selected


def exit_stat_state(raw_stat, identity):
    need(type(raw_stat) is str and len(raw_stat.encode()) <= 16384, 'resource-exit-probe-raw')
    try:
        fields = raw_stat[raw_stat.rfind(')') + 2:].split()
        pid = int(raw_stat[:raw_stat.index(' (')])
        start_ticks = int(fields[19])
        state = fields[0]
    except (ValueError, IndexError):
        raise Rejected('resource-exit-probe-raw')
    need(pid == identity['proc_pid'] and start_ticks == identity['start_ticks'],
         'resource-exit-probe-identity')
    return state


def exit_probe(process):
    """Independent bounded evidence of the short mm-teardown to Z transition."""
    need(process.get('exit_raced') is True and process.get('state') == 'Z'
         and not ({'metrics', 'status_raw', 'fd_names', 'task_names'} & set(process)),
         'resource-exit-race-proof')
    identity = process['identity']
    need(exit_stat_state(process.get('initial_stat_raw'), identity) != 'Z'
         and type(process.get('observation_error')) is str, 'resource-exit-race-proof')
    proof = process.get('exit_probe')
    need(type(proof) is dict and set(proof) == {
        'operation', 'failed_status_raw', 'failure_ns', 'deadline_ns', 'error_type', 'errno', 'reads'},
        'resource-exit-probe-shape')
    begin, end = process['started_ns'], process['completed_ns']
    need(all(type(value) is int for value in (begin, end, proof['failure_ns'], proof['deadline_ns']))
         and begin <= proof['failure_ns'] <= end <= proof['deadline_ns'] == begin + 10_000_000,
         'resource-exit-probe-clock')
    operation, status = proof['operation'], proof['failed_status_raw']
    need(operation in ('status_read', 'status_fields', 'fd_names', 'task_names'),
         'resource-exit-probe-operation')
    if operation == 'status_read':
        need(status is None, 'resource-exit-probe-status')
    else:
        need(type(status) is str and len(status.encode()) <= 16384, 'resource-exit-probe-status')
        metrics = process_fields(status, complete=operation != 'status_fields')
        need(metrics.get('Pid') == identity['proc_pid'], 'resource-exit-probe-status')
        if operation == 'status_fields':
            need(set(metrics) != {'Pid', 'Threads', 'VmRSS', 'VmHWM'} or min(metrics.values()) <= 0,
                 'resource-exit-probe-status')
        else:
            need(min(metrics.values()) > 0, 'resource-exit-probe-status')
    if operation == 'status_fields':
        need(proof['error_type'] == 'ValueError' and proof['errno'] is None, 'resource-exit-probe-error')
    else:
        need(proof['error_type'] == 'FileNotFoundError' and proof['errno'] == 2, 'resource-exit-probe-error')
    reads = proof['reads']
    need(type(reads) is list and 1 <= len(reads) <= 8, 'resource-exit-probe-denominator')
    previous = proof['failure_ns']
    for index, read in enumerate(reads):
        need(type(read) is dict and set(read) == {'started_ns', 'completed_ns', 'stat_raw'},
             'resource-exit-probe-shape')
        need(type(read['started_ns']) is int and type(read['completed_ns']) is int
             and previous + (1_000_000 if index else 0) <= read['started_ns'] <= read['completed_ns'] <= end,
             'resource-exit-probe-clock')
        state = exit_stat_state(read['stat_raw'], identity)
        need((state == 'Z') == (index == len(reads) - 1), 'resource-exit-probe-terminal')
        previous = read['completed_ns']
    need(previous <= end and reads[-1]['stat_raw'] == process['stat_raw'], 'resource-exit-probe-terminal')


def process_presence(sample, starts, ends):
    locked = sample['locked_ns']
    need(type(locked) is int and moment(sample) <= locked <= sample['completed_ns'], 'resource-locked-clock')
    expected = {pid for pid in starts if moment(starts[pid]) < locked < moment(ends[pid])}
    owned = [row for row in sample['processes'] if row['role'] != 'observer']
    observers = [row for row in sample['processes'] if row['role'] == 'observer']
    need(len(observers) == 1 and len(owned) == len(expected)
         and {row['identity']['pid'] for row in owned} == expected, 'resource-live-process-denominator')
    need(all(locked <= row['started_ns'] <= row['completed_ns'] <= sample['completed_ns']
             for row in sample['processes']), 'resource-process-sample-clock')


def owned_inventory(events):
    start_rows = [row for row in events if row['event'] == 'envelope_process_started']
    end_rows = [row for row in events if row['event'] == 'envelope_process_reaped']
    need(len(start_rows) == len(end_rows) == 9, 'resource-process-denominator')
    starts = {row['identity']['pid']: row for row in start_rows}
    ends = {row['identity']['pid']: row for row in end_rows}
    need(len(starts) == len(ends) == 9 and set(starts) == set(ends), 'resource-process-denominator')
    return starts, ends


def resource_envelope(directory, events, samples, projections, inputs):
    need(not any(row['event'] in ('monitor_failed', 'owned_exit_probe_failed') for row in events),
         'resource-monitor-failure')
    need(samples and len(samples) <= spec.BOUNDS['samples'], 'resource-sample-denominator')
    starts, ends = owned_inventory(events)
    same(Counter(row['role'] for row in starts.values()), Counter({'backend': 4, 'node': 4, 'service': 1}),
         'resource-process-roles')
    original_service = one([row for row in events if row['event'] == 'service_started'], 'owned-service')
    original_nodes = [row for row in events if row['event'] == 'node_started']
    original_backend = one([row for row in events if row['event'] == 'backend_started'], 'owned-backend')['identities']
    need(len(original_nodes) == len(original_backend) == 4, 'resource-original-process-denominator')
    bindings = [('service', original_service['identity']),
                *(('node', row['identity']) for row in original_nodes),
                *(('backend', {key: value for key, value in row.items() if key != 'role'}) for row in original_backend)]
    need(len({identity['pid'] for _, identity in bindings}) == 9, 'resource-original-process-denominator')
    for role, identity in bindings:
        need(identity['pid'] in starts and starts[identity['pid']]['role'] == role,
             'resource-original-process-role')
        same(starts[identity['pid']]['identity'], identity, 'resource-original-process-identity')
    sealed = one([row for row in events if row['event'] == 'envelope_sealed_prefix'], 'resource-sealed-prefix')
    encoded = json.dumps(sealed['entries'], sort_keys=True, separators=(',', ':')).encode() + b'\n'
    same(hashlib.sha256(encoded).hexdigest(), sealed['sha256'], 'resource-sealed-prefix-hash')
    names = [cell['name'] for cell in spec.cells()]
    same(set(sealed['entries']), {'build', 'inputs.json', 'plan.json', 'fixture-source.tar'}
         | set(names[:names.index(directory.name)]), 'resource-sealed-prefix-members')
    # File byte lengths and counts survive an archive/extraction. Original
    # allocation observations are retained separately; do not pretend a later
    # filesystem has the same blocks or directory representation.
    for name, expected in sealed['entries'].items():
        path = directory.parent / name
        files = [path] if path.is_file() else [item for item in path.rglob('*') if item.is_file()]
        need(all(not item.is_symlink() for item in files), 'resource-sealed-symlink')
        need(len(files) == expected['files'] and sum(item.stat().st_size for item in files) == expected['file_bytes'],
             'resource-sealed-prefix-changed')
    for pid, row in starts.items():
        expected = inputs['tools'][{'service': 'scapd', 'node': 'node', 'backend': 'weed'}[row['role']]]
        same(row['executable'], expected['path'], 'resource-process-source')
        same(row['identity'], ends[pid]['identity'], 'resource-process-identity')
        same(row['role'], ends[pid]['role'], 'resource-process-role')
        need(row['proof']['source'] == 'owned_pre_exec_proc_self_fd'
             and row['identity']['proc_source'] == row['proof']['source'], 'resource-owned-proof')
        need(moment(row) < moment(ends[pid]) and ends[pid]['usage']['source'] == 'kernel_wait4_owned_child'
             and ends[pid]['usage']['available'], 'resource-owned-lifetime')
        need(type(row['spawn_requested_ns']) is int and 0 < row['spawn_requested_ns']
             <= row['identity']['spawn_monotonic_ns'] <= moment(row), 'resource-spawn-clock')
        need(ends[pid]['usage']['maxrss_bytes'] <= spec.PROCESS_LIMITS[row['role']]['rss_bytes'], 'resource-terminal-rss')
    peaks = {role: {key: 0 for key in ('rss_bytes', 'fds', 'tasks')} for role in spec.PROCESS_LIMITS}
    previous = None
    observer_identity = None
    by_number = {}
    for number, sample in enumerate(samples, 1):
        need(sample['event'] == 'envelope_sample' and sample['sample'] == number
             and sample['acceptance_is_hard_cap'] is False, 'resource-sample-sequence')
        begin = moment(sample)
        need(type(sample['completed_ns']) is int and begin <= sample['completed_ns'], 'resource-sample-clock')
        same(sample['interval_ns'], None if previous is None else begin - previous, 'resource-sample-span')
        need(previous is None or previous < begin, 'resource-sample-order')
        previous = begin
        process_presence(sample, starts, ends)
        same(sample['sealed_prefix_sha256'], sealed['sha256'], 'resource-sealed-prefix-source')
        totals = {role: {key: 0 for key in ('rss_bytes', 'fds', 'tasks')} for role in spec.PROCESS_LIMITS}
        ids = set()
        for process in sample['processes']:
            role, identity = process['role'], process['identity']
            need(role in spec.PROCESS_LIMITS, 'resource-role')
            stat = process['stat_raw']
            close = stat.rfind(')')
            fields = stat[close + 2:].split()
            need(int(stat[:stat.index(' (')]) == identity['proc_pid'] and int(fields[19]) == identity['start_ticks'],
                 'resource-raw-identity')
            need(identity['proc_pid'] not in ids, 'resource-duplicate-process')
            ids.add(identity['proc_pid'])
            if role == 'observer':
                need(identity['source'] == 'observer_proc_self_fd', 'resource-observer-proof')
                if observer_identity is None:
                    observer_identity = identity
                same(identity, observer_identity, 'resource-observer-identity')
            else:
                pid = identity['pid']
                need(pid in starts and starts[pid]['role'] == role
                     and moment(starts[pid]) < process['started_ns'] <= process['completed_ns'] < moment(ends[pid]),
                     'resource-owned-interval')
                same(identity, starts[pid]['identity'], 'resource-sample-identity')
            need(process['state'] == fields[0], 'resource-state')
            exit_keys = {'exit_raced', 'initial_stat_raw', 'observation_error', 'exit_probe'} & set(process)
            if exit_keys:
                need(exit_keys == {'exit_raced', 'initial_stat_raw', 'observation_error', 'exit_probe'},
                     'resource-exit-probe-shape')
                exit_probe(process)
            if process['state'] == 'Z':
                need('metrics' not in process, 'resource-zombie-not-zero')
                continue
            metrics = process_fields(process['status_raw'])
            same(metrics, process['metrics'], 'resource-original-status')
            need(metrics['Pid'] == identity['proc_pid'], 'resource-status-pid')
            for key in ('fd_names', 'task_names'):
                values = process[key]
                need(type(values) is list and values == sorted(set(values), key=int)
                     and all(type(value) is str and value.isdecimal() for value in values), 'resource-name-array')
            totals[role]['rss_bytes'] += metrics['VmRSS']
            totals[role]['fds'] += len(process['fd_names'])
            totals[role]['tasks'] += len(process['task_names'])
        same(totals, sample['totals'], 'resource-role-totals')
        for role, values in totals.items():
            for key, value in values.items():
                need(value <= spec.PROCESS_LIMITS[role][key], 'resource-acceptance-ceiling')
                peaks[role][key] = max(peaks[role][key], value)
        filesystem = sample['filesystem']
        need(filesystem['evidence']['allocated_bytes'] + filesystem['private']['allocated_bytes']
             <= spec.BOUNDS['matrix_bytes'], 'resource-disk-ceiling')
        need(filesystem['evidence']['inodes'] + filesystem['private']['inodes']
             <= spec.BOUNDS['matrix_inodes'], 'resource-inode-ceiling')
        need(filesystem['filesystem_free_bytes'] >= spec.BOUNDS['minimum_free_bytes'], 'resource-free-reserve')
        if sample['backend'] is not None:
            need(sample['backend']['allocated_bytes'] <= spec.BOUNDS['backend_bytes'], 'resource-backend-ceiling')
        by_number[number] = sample
    for sample in projections:
        original = by_number.get(sample['envelope_sample'])
        need(original is not None, 'resource-projection-source')
        source = one([row for row in original['processes'] if row['role'] == 'service'], 'resource-projection-service')
        for key in ('identity', 'stat_raw', 'status_raw', 'fd_names', 'task_names', 'metrics'):
            same(sample[key], source[key], 'resource-projection-source')
        for key in ('monotonic_ns', 'completed_ns', 'phase'):
            same(sample[key], original[key], 'resource-projection-clock')
    need(projections and {row['phase'] for row in projections} >= {'seed_rows', 'load', 'verify'}, 'resource-phase-coverage')
    gaps = [sample['interval_ns'] / 1e6 for sample in samples if sample['interval_ns'] is not None]
    return {'sample_ticks': len(samples), 'target_interval_ms': spec.BOUNDS['sample_interval_ms'],
            'actual_interval_ms': base.percentiles(gaps), 'role_sampled_peaks': peaks,
            'kernel_wait4': [{'role': row['role'], 'identity': row['identity'], 'usage': row['usage']}
                             for row in ends.values()],
            'hard_cap': False, 'limitation': 'Sampling can miss overshoot; actual sample spans and kernel terminal RSS are retained.'}


def audit_cell(directory, enabled, contract, projections=None):
    directory, projections = Path(directory), projections or {}
    def load(name, limit, size):
        rows = ledger(directory / name, limit, size)
        value = projections.get(name, rows)
        need(len(value) <= limit, 'ledger-row-budget')
        return value
    config = projections.get('service-config.json', base.wire.parse((directory / 'service-config.json').read_bytes()))
    configuration(config, enabled, contract)
    workload = base.wire.parse((directory / 'workload.json').read_bytes())
    same(workload['plan'], contract.plan, 'fixed-plan')
    same(workload['calls'], spec.calls(contract), 'fixed-workload')
    same(workload['final_sql'], spec.ALL_ROWS, 'fixed-final-query')
    wanted = {str(item['row']) for item in spec.calls(contract) if 'row' in item}
    same(set(workload['payloads']), wanted, 'payload-denominator')
    for row, description in workload['payloads'].items():
        same(raw(directory, description), spec.payload(int(row)), 'fixed-payload')
    sdk = load('sdk.jsonl', spec.BOUNDS['sdk_rows'], spec.BOUNDS['sdk_bytes'])
    intents = load('intents.jsonl', contract.retained_entries, spec.BOUNDS['intent_bytes'])
    need(sum(row['event'] == 'http_request' for row in sdk) <= spec.BOUNDS['http_posts'], 'http-post-budget')
    planned, calls, measured = base.client(directory, config, sdk, intents, contract)
    seed_ack(planned, calls)
    committed, cancelled, final_rows = base.settlement(planned, calls)
    events = load('events.jsonl', spec.BOUNDS['events_rows'], spec.BOUNDS['events_bytes'])
    stage_deadlines(events, contract)
    started = one([row for row in events if row['event'] == 'service_started'], 'owned-service')
    stopped = one([row for row in events if row['event'] == 'service_stopped'], 'owned-service')
    launched = one([row for row in events if row['event'] == 'service_start_requested'], 'owned-service-config')
    cell_started = one([row for row in events if row['event'] == 'cell_started'], 'cell-start')
    need(launched['empty_cache'] is True and launched['group_commit'] is enabled, 'fresh-cell-cache')
    same(config['cache_directory'], str(Path(cell_started['private_directory']) / 'cache'), 'cell-cache-directory')
    need(launched['configuration_sha256'] == base.digest((directory / 'service-config.json').read_bytes()), 'observed-config-bytes')
    inputs = base.wire.parse((directory.parent / 'inputs.json').read_bytes())
    backend = one([row for row in events if row['event'] == 'backend_started'], 'owned-backend')
    need(backend['binary_sha256'] == inputs['tools']['weed']['sha256'], 'observed-backend-binary')
    need(started['identity'] == stopped['identity'] and stopped['status'] == 0 and stopped['cache_empty'], 'service-cleanup')
    for phase in ('seed', *contract.phases, 'verify'):
        begin = one([row for row in events if row['event'] == 'node_started' and row['phase'] == phase], 'owned-node')
        end = one([row for row in events if row['event'] == 'node_stopped' and row['phase'] == phase], 'owned-node')
        need(begin['identity'] == end['identity'] and end['status'] == 0, 'node-cleanup')
        need(begin['binary_sha256'] == inputs['tools']['node']['sha256'], 'observed-node-binary')
    diagnostic = diagnostic_cohort(directory, config, events,
        load('diagnostics.jsonl', spec.BOUNDS['diagnostic_gets'], spec.BOUNDS['diagnostic_ledger_bytes']), planned, calls)
    samples = load('resources.jsonl', spec.BOUNDS['samples'], spec.BOUNDS['sample_bytes'])
    envelope = load('envelope.jsonl', spec.BOUNDS['samples'], spec.BOUNDS['sample_bytes'])
    need(sum((directory / name).stat().st_size for name in ('resources.jsonl', 'envelope.jsonl'))
         <= spec.BOUNDS['sample_bytes'], 'resource-aggregate-byte-budget')
    need(samples and all(row['identity'] == started['identity'] and moment(started) < moment(row) < moment(stopped)
                        for row in samples), 'resource-identity')
    monitored = resource_envelope(directory, events, envelope, samples, inputs)
    s3 = load('s3.jsonl', spec.BOUNDS['trace_rows'], spec.BOUNDS['trace_bytes'])
    need(sum(row['event'] == 'request' for row in s3) <= spec.BOUNDS['s3_requests'], 's3-attempt-budget')
    s3_exchanges(s3)
    head_conditions(directory, s3)
    net = base.network(directory, s3, events, committed, cancelled, calls, final_rows, enabled, contract)
    geometry = geometry_and_cost(directory, s3, events, contract, committed)
    for phase, row in measured.items():
        row['s3'] = net['phases'].get(phase, {})
        row['settled_committed'] = sum(key in committed for key, item in planned.items()
                                       if item['phase'] == phase and item['operation'] == 'execute')
        row['settled_cancelled'] = sum(key in cancelled for key, item in planned.items()
                                       if item['phase'] == phase and item['operation'] == 'execute')
        need(row['settled_committed'] + row['settled_cancelled'] == row['offered_transactions'], 'settled-denominator')
        origin = int(one([event for event in sdk if event['event'] == 'phase_started' and event['phase'] == phase],
                         'phase-boundary')['origin_ns'])
        end = origin + contract.phases[phase]['duration_ms'] * 1000000
        row['original_ack_count'] = row['terminal_counts'].get('success', 0)
        row['original_ack_within_offer_window'] = sum(call['finish']['ok'] and int(call['finish']['sdk_terminal_ns']) < end
            for key, call in calls.items() if key in planned and planned[key]['phase'] == phase
            and planned[key]['operation'] == 'execute')
        for denominator, count in (('offered', row['offered_transactions']), ('original_ack', row['original_ack_count'])):
            row['cost_per_' + denominator] = {key: row['s3'][key] / count if count else None
                for key in ('requests', 'request_body_bytes', 'response_body_bytes')}
    need(sum(path.stat().st_size for path in (directory / 'raw').iterdir()) <= spec.BOUNDS['raw_bytes'], 'raw-total-budget')
    return {'group_commit': enabled, 'rate': contract.rate, 'measurements': measured,
            'lifecycle': diagnostic, 'geometry_and_cost': geometry, 'resources': monitored,
            's3_total': net, 'originals_verified': len(committed) + len(cancelled) - 1,
            'committed_rows': len(final_rows), 'binary': started['binary']}


def comparison(off, on):
    baseline, grouped = off['measurements']['load'], on['measurements']['load']
    def tail(value, controls=False):
        if controls:
            return value['control_scheduled_to_terminal_ms']['p99']
        return value['scheduled_to_terminal_ms'].get('success', {}).get('p99')
    checks = {'original_ack_not_reduced': grouped['original_ack_count'] >= baseline['original_ack_count'],
              'offer_window_ack_not_reduced': grouped['original_ack_within_offer_window'] >= baseline['original_ack_within_offer_window']}
    costs = []
    for label, left, right in (
        ('success_p99', tail(baseline), tail(grouped)),
        ('control_p99', tail(baseline, True), tail(grouped, True)),
        ('s3_requests_per_ack', baseline['cost_per_original_ack']['requests'], grouped['cost_per_original_ack']['requests']),
        ('body_bytes_per_ack', sum(baseline['cost_per_original_ack'][key] or 0 for key in ('request_body_bytes', 'response_body_bytes')),
         sum(grouped['cost_per_original_ack'][key] or 0 for key in ('request_body_bytes', 'response_body_bytes')))):
        checks[label + '_within_5_percent'] = left is not None and right is not None and left > 0 and right <= left * 1.05
        costs.append({'metric': label, 'off': left, 'on': right, 'on_over_off': right / left if left else None})
    improvement = baseline['original_ack_count'] > 0 and grouped['original_ack_count'] >= baseline['original_ack_count'] * 1.05
    left, right = baseline['cost_per_original_ack']['requests'], grouped['cost_per_original_ack']['requests']
    improvement |= left is not None and right is not None and left > 0 and right <= left * .95
    checks['predeclared_target_improved_5_percent'] = improvement
    return {'criteria_met': all(checks.values()), 'checks': checks, 'comparisons': costs,
            'interpretation': 'Local finite-growth paired sample; evidence validity does not require improvement.'}


def matrix_inputs(directory):
    same(base.wire.parse((directory / 'plan.json').read_bytes()), spec.matrix_plan(), 'fixed-matrix-plan')
    result = base.wire.parse((directory / 'result.json').read_bytes())
    need(result['status'] == 'OBSERVED_NOT_AUDITED' and result['profile'] == spec.NAME
         and result['aws_standard'] == result['production_slo'] == 'NOT_RUN', 'run-completion')
    same([{key: row[key] for key in ('name', 'group_commit', 'rate', 'contract')} for row in result['cells']],
         spec.cells(), 'cell-order')
    need(all(row['status'] == 'OBSERVED_NOT_AUDITED' and not row['cleanup_errors'] for row in result['cells']), 'cell-completion')
    inputs = base.provenance(directory)
    validate_round_order(round_boundaries(directory))
    private = []
    for cell in spec.cells():
        events = base.rows(directory / cell['name'] / 'events.jsonl')
        private.append(one([row for row in events if row['event'] == 'cell_started'], 'cell-start')['private_directory'])
    need(len(set(private)) == len(spec.cells()), 'fresh-private-cell-directories')
    need(type(inputs['matrix_start_ns']) is int and type(result['finished_ns']) is int
         and 0 < result['finished_ns'] - inputs['matrix_start_ns'] <= spec.DEADLINES['run_seconds'] * 1_000_000_000,
         'matrix-deadline')
    return inputs


def verify(directory):
    directory = Path(directory)
    extra_started = time.monotonic()
    with deadline(spec.DEADLINES['matrix_audit_seconds']):
        inputs = matrix_inputs(directory)
    extra_used = time.monotonic() - extra_started
    audited, seed = {}, None
    for cell in spec.cells():
        with deadline(spec.DEADLINES['audit_seconds']):
            report = audit_cell(directory / cell['name'], cell['group_commit'], spec.CONTRACTS[cell['rate']])
        same(report['binary'], inputs['tools']['scapd'], 'observed-service-binary')
        geometry = report['geometry_and_cost']['seed']
        if seed is None:
            seed = geometry
        same(geometry, seed, 'equal-seed-geometry')
        audited[cell['name']] = report
    extra_started = time.monotonic()
    remaining = spec.DEADLINES['matrix_audit_seconds'] - extra_used
    need(remaining > 0, 'independent-audit-deadline')
    with deadline(remaining):
        pairs = []
        for rate in spec.RATES:
            for suffix in ('1', '2'):
                off, on = f'rate-{rate}-off-{suffix}', f'rate-{rate}-on-{suffix}'
                pairs.append({'rate': rate, 'off': off, 'on': on, **comparison(audited[off], audited[on])})
        allocated = inodes = 0
        for path in directory.rglob('*'):
            need(not path.is_symlink(), 'evidence-symlink')
            inodes += 1
            allocated += path.stat().st_blocks * 512
        need(allocated <= spec.BOUNDS['matrix_bytes'] and inodes <= spec.BOUNDS['matrix_inodes'], 'matrix-final-budget')
    extra_used += time.monotonic() - extra_started
    return {'status': 'PASSED', 'profile': spec.NAME, 'cells': audited, 'pairs': pairs,
            'improvement_criteria_met_all_pairs': all(pair['criteria_met'] for pair in pairs),
            'measured_inserts': 5632, 'seed_inserts': 2048, 'equal_seed': seed,
            'runtime_commit': inputs['build_source_commit'], 'aws_standard': 'NOT_RUN',
            'production_slo': 'NOT_RUN', 'finite_growth_not_steady_state': True,
            'evidence_allocated_bytes': allocated, 'evidence_inodes': inodes,
            'matrix_extra_audit_seconds_used': extra_used}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    print(json.dumps(verify(parser.parse_args().evidence), indent=2, sort_keys=True))
