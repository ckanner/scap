#!/usr/bin/env python3
"""New independent audit of the unchanged fixed gib1 capacity contract.

This is not the missing historical audit_capacity_gib1.py. It never imports the
capacity controller or production code. Original wire readers and the archived
build auditor are imported explicitly from the frozen repository and identified
in the report. All original evidence and the closed SQLite image are read only.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys

GIB = 1 << 30
BLOB = 1 << 16
ROWS = GIB // BLOB
SCOPE = dict(deployment=177, tenant=188, database=199, incarnation=1, generation=1)
PREFIX = '/scap-test/scap-object/v1/177/188/199/inc/1/gen/1/storage/1/objects/'
HEAD = '/scap-test/scap-object/v1/177/188/199/head'
NEGATIVES = {
    'missing_result': 'all-39-original-results',
    'recovered_result': 'recovered-original-result',
    'blob_hash': 'every-original-blob-hash',
    'missing_exit': 'all-owned-compute-exits',
    'unknown_relabelled': 'original-unknown-preserved',
}
FIXED_CALLS = Counter(create=1, activate_session=2, prepare_request=39, session_execute=39,
                      status=4, set_policy=3, session_open=1, session_query=262,
                      session_close=1, authority_info=1, takeover=1, lookup_identity=40)


class Rejected(ValueError):
    def __init__(self, guard, detail):
        super().__init__(f'{guard}: {detail}')
        self.guard = guard


def require(value, guard, detail):
    if not value:
        raise Rejected(guard, detail)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def parse(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, 'original-file-format', 'duplicate JSON key')
            value[key] = item
        return value

    def invalid(value):
        raise Rejected('original-file-format', 'nonfinite JSON number ' + value)

    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)


def lines(path):
    raw = Path(path).read_bytes()
    require(raw and raw.endswith(b'\n'), 'original-file-format', 'missing/truncated JSONL')
    return [parse(line) for line in raw.splitlines()]


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False)


def equal(left, right, guard, detail):
    require(canonical(left) == canonical(right), guard, detail)


def only(rows, guard, detail):
    require(len(rows) == 1, guard, detail)
    return rows[0]


def identity(row):
    return row['pid'], row['spawn_monotonic_ns']


def inventory(directory):
    found = {}
    for path in sorted(Path(directory).rglob('*')):
        info = path.lstat()
        require(not stat.S_ISLNK(info.st_mode), 'original-file-format', 'symlink in public evidence')
        if stat.S_ISREG(info.st_mode):
            found[path.relative_to(directory).as_posix()] = {'bytes': info.st_size, 'sha256': sha(path)}
        else:
            require(stat.S_ISDIR(info.st_mode), 'original-file-format', 'special file in public evidence')
    return found


def image_inventory(path):
    found = {}
    for suffix in ('', '-wal', '-shm', '-journal'):
        file = Path(str(path) + suffix)
        if not file.exists() and not file.is_symlink():
            found[suffix] = None
            continue
        info = file.lstat()
        require(stat.S_ISREG(info.st_mode), 'closed-native-image', 'image/sidecar is not a regular file')
        found[suffix] = {'bytes': info.st_size, 'sha256': sha(file)}
    require(found[''] is not None, 'closed-native-image', 'missing actual SQLite file')
    for suffix in ('-wal', '-journal'):
        require(found[suffix] is None or found[suffix]['bytes'] == 0,
                'closed-native-image', 'nonempty WAL/journal is not a standalone closed image')
    return found


def pairs(history):
    pending, complete = {}, []
    for row in history:
        if row['event'] == 'client_invoked':
            key = row['worker']
            require(key not in pending, 'client-call-denominator', 'overlapping calls for one worker')
            pending[key] = row
        elif row['event'] == 'client_observed':
            key = row['worker']
            require(key in pending, 'client-call-denominator', 'response without original invocation')
            call = pending.pop(key)
            for name in ('worker', 'pid', 'operation', 'request_id', 'request_epoch', 'budget_ms', 'key'):
                equal(row[name], call[name], 'client-call-denominator', 'response identity changed: ' + name)
            require(call['monotonic_ns'] < row['monotonic_ns'], 'client-call-denominator', 'response precedes invocation')
            complete.append((call, row))
    require(not pending, 'client-call-denominator', 'missing complete client observation')
    return complete


def original_mutations(calls):
    selected = [(a, b) for a, b in calls if a['operation'] == 'session_execute']
    require(len(selected) == 39 and sorted(a['request_id'] for a, _ in selected) == list(range(1, 40)),
            'all-39-original-results', 'execute attempts are missing, duplicated or outside the fixed denominator')
    return {a['request_id']: (a, b) for a, b in selected}


def fixed_call_inventory(calls, mutations):
    require(Counter(a['operation'] for a, _ in calls) == FIXED_CALLS,
            'fixed-client-operation-denominator', 'extra, missing or unknown original operation')
    prepared = [(a, b) for a, b in calls if a['operation'] == 'prepare_request']
    require(len(prepared) == 39 and sorted(a['request_id'] for a, _ in prepared) == list(range(1, 40)),
            'original-request-preparation', 'prepare_request identity denominator')
    for call, response in prepared:
        execute, _ = mutations[call['request_id']]
        require(call['worker'] == execute['worker'] == 1 and call['pid'] == execute['pid']
                and call['request_epoch'] == execute['request_epoch'] == 1 and call['budget_ms'] == 30_000
                and response['ok'] is True and response['error'] is None
                and response['monotonic_ns'] < execute['monotonic_ns'],
                'original-request-preparation', 'prepare_request is not the actual preceding preparation of its execute')


def original_unknown_lookup(calls, unknown, ack_event):
    invocation, response = unknown
    selected = [(a, b) for a, b in calls if a['operation'] == 'lookup_identity'
                and a['worker'] == invocation['worker'] and a['request_id'] == 39]
    call, observed = only(selected, 'original-unknown-preserved', 'missing/duplicate original warm lookup after UNKNOWN')
    require(call['pid'] == invocation['pid'] and call['request_epoch'] == 1
            and response['monotonic_ns'] < call['monotonic_ns'] < observed['monotonic_ns'] < ack_event['monotonic_ns']
            and observed['ok'] is True and observed['error'] is None and observed['resolution'] == 'committed',
            'original-unknown-preserved', 'warm lookup does not prove original UNKNOWN resolution before result recording')


def bind_calls_to_processes(calls, history):
    starts = {r['worker']: r for r in history if r['event'] == 'worker_started'}
    ends = {r['worker']: r for r in history if r['event'] == 'worker_stopped'}
    for call, response in calls:
        worker = call['worker']
        require(worker in starts and worker in ends, 'client-process-identity', 'call has no owned worker lifetime')
        start, end = starts[worker], ends[worker]
        require(call['pid'] == response['pid'] == start['pid'] == end['pid']
                and start['monotonic_ns'] <= call['monotonic_ns'] < response['monotonic_ns'] <= end['monotonic_ns'],
                'client-process-identity', 'call PID/time is outside its original owned worker')


def response_order(request, forwarded, response, delivered):
    require(forwarded['monotonic_ns'] >= request['monotonic_ns']
            and response['monotonic_ns'] >= forwarded['monotonic_ns'],
            'original-http-denominator', 'backend request/response order')
    if delivered is not None:
        require(delivered['monotonic_ns'] >= response['monotonic_ns'],
                'original-http-denominator', 'post-send delivery log precedes backend response')


def processes(history, build_binary):
    guard = 'all-owned-compute-exits'
    starts = [r for r in history if r['event'] == 'worker_started']
    stops = [r for r in history if r['event'] == 'worker_stopped']
    require(len(starts) == len(stops) == 3, guard, 'all three original compute incarnations must exit')
    require({r['worker'] for r in starts} == {1, 2, 3}, guard, 'worker denominator')
    require(len({identity(r) for r in starts}) == 3, guard, 'reused compute incarnation')
    life = defaultdict(list)

    def owned(start, end, end_ns):
        require(start['pid_source'] == end['pid_source'] == 'owned_Popen_child', guard, 'unowned process')
        require(identity(start) == identity(end), guard, 'exit does not match spawn')
        require(start['spawn_monotonic_ns'] < end_ns, guard, 'invalid lifetime')
        usage = end['kernel_usage']
        require(end['wait_status'] == -9 and usage['available'] is True
                and usage['source'] == 'kernel_wait4_owned_child', guard, 'missing SIGKILL/wait4 proof')
        pid, first = identity(start)
        require(all(end_ns <= a or b <= first for a, b in life[pid]), guard, 'overlapping independent PID lifetimes')
        life[pid].append((first, end_ns))

    for start in starts:
        end = only([r for r in stops if r['worker'] == start['worker']], guard, 'missing/duplicate compute exit')
        equal(start['binary'], build_binary, guard, 'executed binary differs from frozen build')
        owned(start, end, end['monotonic_ns'])
    loss = only([r for r in history if r['event'] == 'all_compute_and_local_cache_lost'], guard, 'cache loss missing')
    require(loss['local_cache_deleted'] is True and loss['process_signal'] == 'SIGKILL', guard, 'cache not deleted after SIGKILL')
    require({r['worker'] for r in loss['processes']} == {1, 2}, guard, 'warm compute loss denominator')
    for stopped in loss['processes']:
        original = only([r for r in stops if r['worker'] == stopped['worker']], guard, 'warm exit absent')
        equal({k: original[k] for k in stopped}, stopped, guard, 'cache-loss exit was rewritten')
        require(original['monotonic_ns'] < loss['monotonic_ns'] and original['fault'] is True, guard, 'cache loss precedes observed exit')
    begun = only([r for r in history if r['event'] == 'backend_started'], guard, 'initial backend start missing')
    killed = only([r for r in history if r['event'] == 'backend_processes_killed'], guard, 'backend loss missing')
    reopened = only([r for r in history if r['event'] == 'backend_restarted'], guard, 'backend restart missing')
    ended = only([r for r in history if r['event'] == 'backend_stopped'], guard, 'final backend exit missing')
    require(loss['monotonic_ns'] < killed['monotonic_ns'] < reopened['monotonic_ns'], guard, 'loss/restart order')
    require(begun['directory_identity'] == killed['directory_identity'] == reopened['directory_identity'], guard, 'backend persistence directory changed')
    require(killed['signal'] == 'SIGKILL', guard, 'backend fault changed')
    cold = only([r for r in starts if r['worker'] == 3], guard, 'cold worker missing')
    require(cold['spawn_monotonic_ns'] > reopened['monotonic_ns'], guard, 'cold process predates backend restart')
    roles = {'master', 'volume', 'filer', 's3'}
    backend_ids = []
    for first, last in ((begun, killed), (reopened, ended)):
        require(len(first['processes']) == len(last['processes']) == 4, guard, 'backend process denominator')
        require({r['role'] for r in first['processes']} == {r['role'] for r in last['processes']} == roles,
                guard, 'backend role denominator')
        for start in first['processes']:
            finish = only([r for r in last['processes'] if r['role'] == start['role']], guard, 'backend role exit')
            owned(start, finish, last['monotonic_ns'])
            backend_ids.append(identity(start))
    require(len(set(backend_ids)) == 8, guard, 'backend incarnation reused')
    return {'compute_incarnations': 3, 'backend_incarnations': 8, 'owned_wait4': 11,
            'last_exit_monotonic_ns': max(r['monotonic_ns'] for r in stops + [ended])}


def wire_history(history):
    guard = 'original-http-denominator'
    indexed = {name: {} for name in ('object_request', 'object_forwarded', 'object_response', 'object_response_delivered')}
    for row in history:
        if row['event'] in indexed:
            group = indexed[row['event']]
            serial = row['request_serial']
            require(serial not in group, guard, 'duplicate network event identity')
            group[serial] = row
    requests = indexed['object_request']
    require(sorted(requests) == list(range(1, len(requests) + 1)), guard, 'missing request serial')
    for name, group in indexed.items():
        require(set(group) <= set(requests), guard, name + ' has no original request')
    blackholes = []
    for serial, request in requests.items():
        path = request['path']
        require(path == HEAD or path.startswith(PREFIX) and re.fullmatch('[0-9a-f]{64}', path[len(PREFIX):]),
                guard, 'wrong complete physical namespace')
        require(request['method'] in ('GET', 'PUT'), guard, 'unplanned operation')
        if request['method'] == 'PUT':
            if path != HEAD:
                require(request['if_none_match'] == '*' and request['if_match'] is None, guard, 'immutable PUT is not Absent')
            else:
                require((request['if_none_match'] == '*') != bool(request['if_match']), guard, 'HEAD PUT lacks one original condition')
        for name in ('object_forwarded', 'object_response', 'object_response_delivered'):
            observed = indexed[name].get(serial)
            if observed is not None:
                for key in ('request_serial', 'phase', 'method', 'path', 'request_bytes', 'request_sha256', 'if_match', 'if_none_match'):
                    equal(observed[key], request[key], guard, 'original network request fields changed')
                require(observed['monotonic_ns'] >= request['monotonic_ns'], guard, 'network response before request')
        response = indexed['object_response'].get(serial)
        delivered = indexed['object_response_delivered'].get(serial)
        forwarded = indexed['object_forwarded'].get(serial)
        if response is None:
            require(forwarded is None and delivered is None and request['phase'] == 'hot_cache_head_blackhole'
                    and request['method'] == 'GET' and path == HEAD, guard, 'unexplained missing network response')
            blackholes.append(request)
            continue
        require(forwarded is not None and forwarded['monotonic_ns'] <= response['monotonic_ns'], guard, 'response without backend forward')
        response_order(request, forwarded, response, delivered)
        require(response['response_origin'] == 'backend', guard, 'injected response counted as real backend')
        if response['suppressed']:
            require(delivered is None and response['status'] == 200 and path == HEAD
                    and request['phase'] == 'lost_head_result', guard, 'wrong suppressed success')
        else:
            require(delivered is not None, guard, 'missing response delivery')
            for key in ('status', 'response_bytes', 'response_sha256', 'etag'):
                equal(delivered[key], response[key], guard, 'delivered response changed')
        if path.startswith(PREFIX) and request['method'] == 'GET' and response['status'] == 200:
            require(response['response_sha256'] == path[len(PREFIX):], guard, 'immutable response hash differs from key')
    require(len(blackholes) == 1, guard, 'original hot HEAD blackhole denominator')
    return indexed


def audit_data(data, wire_readers, build_binary):
    history, inputs, acks = data['history'], data['inputs'], data['acks']
    require(not any(r['event'] in ('capacity_verification_failed', 'transport_fixture_failed', 'resource_sampler_failed',
                                  'client_transport_failed', 'client_invocation_lost_with_process') for r in history),
            'actual-contract-complete', 'original run contains failure or missing invocation')
    require(len([r for r in history if r['event'] == 'capacity_verification_passed']) == 1,
            'actual-contract-complete', 'original contract did not reach completion')
    original = [r for r in inputs if r['event'] == 'input_prepared']
    prepared = [r['invocation'] for r in inputs if r['event'] == 'invocation_prepared']
    guard = 'all-39-original-results'
    require(len(inputs) == 78 and len(original) == len(prepared) == len(acks) == 39, guard, 'fixed 39 original inputs/results')
    require([r['id'] for r in original] == [r['id'] for r in prepared] == list(range(1, 40)), guard, 'original input identities')
    require([r['ordinal'] for r in acks] == list(range(1, 40)), guard, 'missing original result ordinal')
    require([r['event'] for r in inputs] == ['input_prepared', 'invocation_prepared'] * 39, guard, 'pre-invocation ledger order')
    calls = pairs(history)
    mutations = original_mutations(calls)
    fixed_call_inventory(calls, mutations)
    unknown = [r for r in acks if r['first_observed_via'] == 'lookup_after_unknown']
    require(len(unknown) == 1 and unknown[0]['invocation']['id'] == 39, 'original-unknown-preserved', 'original unknown identity/provenance changed')
    for ack in acks:
        rid = ack['invocation']['id']
        require(rid in mutations, guard, 'execute invocation omitted')
        call, response = mutations[rid]
        require(call['budget_ms'] == 30_000, guard, 'original SQL operation budget changed')
        if rid == 39:
            require(response['ok'] is False and response['error'] in ('Unknown', 'Store(Unknown)')
                    and ack['first_observed_via'] == 'lookup_after_unknown' and ack['observed_statements'] is None,
                    'original-unknown-preserved', 'original UNKNOWN was relabeled as an execute ACK')
        else:
            require(response['ok'] is True and response['error'] is None and ack['first_observed_via'] == 'execute',
                    guard, 'original execute success disappeared or changed')
    process_report = processes(history, build_binary)
    bind_calls_to_processes(calls, history)
    network = wire_history(history)
    receipts, expected, origins = {}, {}, {}
    input_shapes = Counter()
    for entry, invocation, ack in zip(original, prepared, acks):
        rid = entry['id']
        equal(invocation, ack['invocation'], guard, 'original invocation differs from ACK ledger')
        equal(invocation['scope'], SCOPE, guard, 'complete Scope changed')
        require(invocation['principal'] == invocation['request']['principal'] == 17
                and invocation['epoch'] == invocation['request']['epoch'] == 1
                and invocation['request']['id'] == rid, guard, 'full request identity changed')
        equal(ack['receipt']['scope'], SCOPE, guard, 'receipt Scope changed')
        equal(ack['receipt']['request'], invocation['request'], guard, 'receipt Request changed')
        require(ack['receipt']['sequence'] == rid, guard, 'result sequence changed')
        try:
            decoded = wire_readers.decoded_result(ack['encoded_result'])
            result_digest = wire_readers.result_hash(ack['receipt'], ack['encoded_result'])
        except (ValueError, KeyError, TypeError) as error:
            raise Rejected(guard, 'invalid complete original result: ' + str(error)) from error
        require(result_digest == ack['receipt']['result_hash'], guard, 'receipt does not bind full original result bytes')
        if ack['observed_statements'] is not None:
            equal(decoded, ack['observed_statements'], guard, 'typed original result differs from encoded bytes')
        require(len(decoded) == 2 and decoded[1]['columns'] == ['original_nonce']
                and len(decoded[1]['rows']) == 1 and len(decoded[1]['rows'][0]) == 1
                and type(decoded[1]['rows'][0][0]) is int, guard, 'complete original random nonce missing')
        require(entry['scope'] == SCOPE and entry['principal'] == 17 and entry['epoch'] == 1,
                guard, 'pre-invocation input identity changed')
        changes = entry['changes']
        operation = entry['operation']
        input_shapes[operation] += 1
        if operation == 'create_payloads':
            require(rid == 1 and changes == [] and entry['sql'][0] == 'CREATE TABLE payloads(id INTEGER PRIMARY KEY, payload BLOB NOT NULL)', guard, 'DDL original input changed')
        elif operation == 'insert':
            require(len(changes) == 512 and entry['sql'][0] == 'INSERT INTO payloads(id,payload) VALUES ' + ','.join(['(?,?)'] * 512), guard, 'bulk input shape changed')
            require([r['id'] for r in changes] == list(range(len(expected) + 1, len(expected) + 513)), guard, 'bulk row identity denominator')
        elif operation == 'update':
            require(len(changes) == 1 and changes[0]['id'] in expected
                    and entry['sql'][0] == 'UPDATE payloads SET payload=? WHERE id=?', guard, 'point input changed')
        else:
            raise Rejected(guard, 'unexpected fixed-contract SQL operation')
        require(entry['sql'][-1] == 'SELECT random() AS original_nonce', guard, 'original nonce SQL changed')
        require(entry['input_file_bytes'] == len(changes) * BLOB, guard, 'input bytes denominator')
        for change in changes:
            require(change['bytes'] == BLOB and re.fullmatch('[0-9a-f]{64}', change['sha256']),
                    'every-original-blob-hash', 'invalid pre-invocation BLOB witness')
            expected[change['id']] = {'blob_bytes': BLOB, 'sha256': change['sha256']}
            origins[change['id']] = rid
        receipts[rid] = ack
        call, response = mutations[rid]
        published = [r for r in network['object_response'].values() if r['method'] == 'PUT' and r['path'] == HEAD
                     and r['status'] == 200 and call['monotonic_ns'] < r['monotonic_ns'] < response['monotonic_ns']]
        publication = only(published, guard, 'execute lacks one real accepted HEAD')
        require(bool(publication['if_match']) and publication['if_none_match'] is None, guard, 'SQL publication changed original condition')
        require(publication['suppressed'] is (rid == 39), 'original-unknown-preserved', 'accepted HEAD response-loss boundary changed')
        result_gets = [r for r in network['object_response'].values() if r['method'] == 'GET'
                       and r['path'] == PREFIX + ack['receipt']['result_hash'] and r['status'] == 200
                       and call['monotonic_ns'] < r['monotonic_ns'] < network['object_request'][publication['request_serial']]['monotonic_ns']]
        require(result_gets, guard, 'original Result not read back before original HEAD publication')
    require(input_shapes == Counter(create_payloads=1, insert=32, update=6), guard, 'fixed operation denominator')
    require(set(expected) == set(range(1, ROWS + 1)), 'every-original-blob-hash', 'all 16384 independent rows required')
    recorded = [r for r in history if r['event'] == 'client_ack_recorded']
    require(len(recorded) == 39 and [r['ordinal'] for r in recorded] == list(range(1, 40)), guard, 'original result history denominator')
    for event, ack in zip(recorded, acks):
        equal(event['request'], ack['invocation']['request'], guard, 'result-recorded identity changed')
        require(event['result_sha256'] == hashlib.sha256(bytes(ack['encoded_result'])).hexdigest()
                and event['first_observed_via'] == ack['first_observed_via'], guard, 'original result-recorded provenance changed')
        require(event['monotonic_ns'] > mutations[ack['invocation']['id']][1]['monotonic_ns'],
                guard, 'result recorded before original execute observation')
    original_unknown_lookup(calls, mutations[39], recorded[-1])
    cold_calls = [(a, b) for a, b in calls if a['worker'] == 3 and a['operation'] == 'lookup_identity']
    recovered = [r for r in history if r['event'] == 'ack_audited']
    require(len(cold_calls) == len(recovered) == 39, 'recovered-original-result', 'all original cold lookups required')
    for event, ack, (call, response) in zip(recovered, acks, cold_calls):
        equal(event['request'], ack['invocation']['request'], 'recovered-original-result', 'cold request changed')
        require(event['ordinal'] == ack['ordinal'] and event['matches'] is True
                and call['request_id'] == ack['invocation']['id'] and response['ok'] is True
                and response['resolution'] == 'committed' and event['monotonic_ns'] > response['monotonic_ns'],
                'recovered-original-result', 'cold lookup identity/outcome changed')
        observed = event['observed']
        require(observed['ok'] is True, 'recovered-original-result', 'cold lookup failed')
        equal(observed['value'], {'state': 'committed', 'receipt': ack['receipt'], 'encoded': ack['encoded_result']},
              'recovered-original-result', 'cold receipt or full result differs from original')
    batches = [r for r in history if r['event'] == 'blob_batch_audited']
    require(len(batches) == 256, 'every-original-blob-hash', 'all 256 actual returned BLOB batches required')
    cold_queries = [(a, b) for a, b in calls if a['worker'] == 3 and a['operation'] == 'session_query']
    require(len(cold_queries) == 259 and all(b['ok'] is True for _, b in cold_queries[:258])
            and cold_queries[-1][0]['budget_ms'] == 200 and cold_queries[-1][1]['ok'] is False
            and cold_queries[-1][1]['error'] == 'Store(Unknown)',
            'every-original-blob-hash', 'cold query/batch/empty/tables/blackhole denominator')
    observed_ids = []
    for index, batch in enumerate(batches):
        call, response = cold_queries[index]
        require(call['budget_ms'] == 30_000
                and response['monotonic_ns'] < batch['monotonic_ns'] < cold_queries[index + 1][0]['monotonic_ns'],
                'every-original-blob-hash', 'BLOB batch not bound to its actual complete production query')
        rows = batch['rows']
        require(len(rows) == batch['count'] == 64 and batch['mismatch_count'] == 0,
                'every-original-blob-hash', 'full per-batch denominator')
        for rid, observed in rows:
            require(rid == len(observed_ids) + 1, 'every-original-blob-hash', 'missing/duplicate/reordered recovered row')
            equal(observed, expected[rid], 'every-original-blob-hash', 'recovered BLOB hash differs from original input')
            observed_ids.append(rid)
        require(batch['first_id'] == rows[0][0] and batch['last_id'] == rows[-1][0]
                and batch['cumulative_count'] == len(observed_ids), 'every-original-blob-hash', 'batch boundary changed')
    require(len(observed_ids) == ROWS, 'every-original-blob-hash', 'full recovered row denominator')
    cold = [r for r in network['object_response'].values() if r['phase'] == 'cold_recovery' and r['method'] == 'GET' and r['status'] == 200]
    cold_keys = {r['path'] for r in cold}
    require({PREFIX + ack['receipt']['result_hash'] for ack in acks} <= cold_keys
            and PREFIX + acks[-1]['receipt']['data_root'] in cold_keys,
            'cold-recovery-observations', 'current root or original retained Result not fetched during cold recovery')
    require(sum(r['response_bytes'] for r in cold) >= GIB, 'cold-recovery-observations', 'actual cold download smaller than complete payload')
    return {'status': 'PASSED', 'original_inputs': 39, 'execute_acks': 38, 'original_unknowns': 1,
            'unknown_lookup_results': 1, 'cold_original_lookups': 39, 'result_mismatches': 0,
            'blob_rows': ROWS, 'blob_bytes': GIB, 'blob_batches': 256, 'blob_mismatches': 0,
            'client_calls': len(calls), 'http_requests': len(network['object_request']),
            'cold_successful_gets': len(cold), 'cold_response_bytes': sum(r['response_bytes'] for r in cold),
            'processes': process_report, 'expected_blobs': expected, 'blob_origin_requests': origins}


def check_image(path, expected):
    before = image_inventory(path)
    result = {}
    try:
        connection = sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro&immutable=1', uri=True)
        try:
            connection.execute('PRAGMA query_only=ON')
            integrity = [r[0] for r in connection.execute('PRAGMA integrity_check')]
            require(integrity == ['ok'], 'native-integrity-check', 'full SQLite integrity_check failed')
            require([r[0] for r in connection.execute("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")] == ['payloads'],
                    'native-integrity-check', 'unexpected table inventory')
            count = total = 0
            for rid, payload in connection.execute('SELECT id,payload FROM payloads ORDER BY id'):
                require(type(rid) is int and rid == count + 1 and isinstance(payload, bytes),
                        'every-native-blob-byte', 'actual image row shape/identity differs')
                equal({'blob_bytes': len(payload), 'sha256': hashlib.sha256(payload).hexdigest()}, expected.get(rid),
                      'every-native-blob-byte', 'actual native bytes differ from independent original witness')
                count += 1
                total += len(payload)
            require(count == len(expected) and total == len(expected) * BLOB,
                    'every-native-blob-byte', 'actual image row/byte denominator')
            result = {'sqlite_version': sqlite3.sqlite_version, 'integrity_check': integrity,
                      'rows_rehashed': count, 'blob_bytes_rehashed': total, 'mode': 'ro&immutable=1',
                      'image_bytes': before['']['bytes'], 'image_sha256': before['']['sha256'], 'sidecars': before}
        finally:
            connection.close()
    except sqlite3.DatabaseError as error:
        raise Rejected('native-integrity-check', str(error)) from error
    finally:
        equal(image_inventory(path), before, 'original-files-unchanged', 'SQLite audit changed image or sidecars')
    return result


def changed_history(data, selector, mutate, *, remove=False):
    value = dict(data)
    value['history'] = list(data['history'])
    index = next(i for i, row in enumerate(value['history']) if selector(row))
    if remove:
        value['history'].pop(index)
    else:
        value['history'][index] = copy.deepcopy(value['history'][index])
        mutate(value['history'][index])
    return value


def negative_controls(data, readers, binary):
    outcomes = []
    for name, guard in NEGATIVES.items():
        if name == 'missing_result':
            altered = dict(data, acks=data['acks'][:-1])
        elif name == 'recovered_result':
            altered = changed_history(data, lambda r: r['event'] == 'ack_audited',
                lambda r: r['observed']['value']['encoded'].__setitem__(-1, r['observed']['value']['encoded'][-1] ^ 1))
        elif name == 'blob_hash':
            altered = changed_history(data, lambda r: r['event'] == 'blob_batch_audited',
                lambda r: r['rows'][0][1].__setitem__('sha256', '0' * 64))
        elif name == 'missing_exit':
            altered = changed_history(data, lambda r: r['event'] == 'worker_stopped' and r['worker'] == 3, None, remove=True)
        else:
            altered = changed_history(data,
                lambda r: r['event'] == 'client_observed' and r['operation'] == 'session_execute' and r['request_id'] == 39,
                lambda r: r.update(ok=True, error=None))
        try:
            audit_data(altered, readers, binary)
        except Rejected as error:
            require(error.guard == guard, 'negative-control-wrong-guard', name + ' rejected by ' + error.guard)
            outcomes.append({'case': name, 'status': 'REJECTED', 'expected_guard': guard, 'observed_guard': error.guard})
        else:
            raise Rejected('negative-control-accepted', name)
    return outcomes


def load_independent_readers(repo):
    directory = Path(repo).resolve() / 'experiments/object-network'
    sys.path.insert(0, str(directory))
    import lifecycle_oracle
    import audit_build
    expected = {'lifecycle_oracle': directory / 'lifecycle_oracle.py', 'audit_build': directory / 'audit_build.py'}
    for name, module in (('lifecycle_oracle', lifecycle_oracle), ('audit_build', audit_build)):
        require(Path(module.__file__).resolve() == expected[name], 'audit-source-identity', 'shadowed independent reader')
    return lifecycle_oracle, audit_build


def validate_manifest_destination(destination, directory, image, capture, repo):
    if destination is None:
        return
    resolved = Path(destination).resolve()
    reserved = {Path(str(image) + suffix).resolve() for suffix in ('', '-wal', '-shm', '-journal')}
    reserved.add(Path(capture).resolve())
    require(not resolved.is_relative_to(Path(directory).resolve())
            and not resolved.is_relative_to(Path(repo).resolve()) and resolved not in reserved,
            'read-only-output-boundary', 'manifest output would touch original evidence, frozen source, image/sidecar or capture proof')
    require(not Path(destination).is_symlink(), 'read-only-output-boundary', 'manifest output is a symlink')


def audit(arguments):
    directory = arguments.evidence.resolve()
    validate_manifest_destination(arguments.manifest_out, directory, arguments.image, arguments.capture, arguments.repo)
    original = inventory(directory)
    capture_bytes = arguments.capture.read_bytes()
    capture = parse(capture_bytes)
    image_before = image_inventory(arguments.image)
    readers, build_audit = load_independent_readers(arguments.repo)
    data = {'inputs': lines(directory / 'input-ledger.jsonl'), 'acks': lines(directory / 'ack-ledger.jsonl'),
            'history': lines(directory / 'history.jsonl')}
    build = build_audit.receipt(directory, profile='network', require_artifacts=True, source_root=arguments.repo)
    receipt = parse((directory / 'build-receipt.json').read_bytes())
    require(receipt['source_commit'] == arguments.expected_commit, 'build-source-identity', 'release source commit differs')
    require(capture['status'] == 'CAPTURED_CLOSED_IMAGE' and capture['source_unchanged'] is True
            and capture['image_sha256'] == image_before['']['sha256'], 'closed-native-image', 'capture proof differs')
    equal(capture['source_before'], capture['source_after'], 'closed-native-image', 'source changed across capture')
    equal(capture['source_before'], capture['copied'], 'closed-native-image', 'copy differs from source bytes')
    equal(capture['copied'], image_before, 'closed-native-image', 'captured image/sidecars differ from actual files')
    try:
        baseline = audit_data(data, readers, build['binary'])
        require(capture['started_monotonic_ns'] > baseline['processes']['last_exit_monotonic_ns'],
                'closed-native-image', 'image captured before all owned process exits')
        native = check_image(arguments.image, baseline['expected_blobs'])
        controls = negative_controls(data, readers, build['binary']) if arguments.controls else []
        positive = audit_data(data, readers, build['binary'])
        equal(positive, baseline, 'unchanged-positive', 'unchanged original history changed after controls')
        require(sha(arguments.image) == image_before['']['sha256'], 'original-files-unchanged', 'native image changed')
        manifest = [{'id': rid, **baseline['expected_blobs'][rid], 'last_original_request_id': baseline['blob_origin_requests'][rid]}
                    for rid in range(1, ROWS + 1)]
        if arguments.manifest_out is not None:
            with arguments.manifest_out.open('x') as stream:
                for row in manifest:
                    stream.write(canonical(row) + '\n')
                stream.flush(); os.fsync(stream.fileno())
        for field in ('expected_blobs', 'blob_origin_requests'):
            baseline.pop(field)
        helper_paths = [Path(__file__).resolve()] + [arguments.repo / 'experiments/object-network' / name
                       for name in ('lifecycle_oracle.py', 'head5_audit.py', 'audit_build.py')]
        report = {'schema': 1, 'status': 'PASS_NEW_INDEPENDENT_GIB1_RAW_AUDIT',
                  'auditor_identity': 'new fixed-gib1 independent verifier v2; historical external auditor not recovered',
                  'auditor_sha256': sha(__file__), 'source_sha256': {str(path.resolve()): sha(path) for path in helper_paths},
                  'runtime_source_commit': receipt['source_commit'], 'build': build, 'actual_history': baseline,
                  'independent_sqlite': native, 'negative_controls': controls, 'negative_control_count': len(controls),
                  'unchanged_positive': 'PASSED', 'original_files_unchanged': True,
                  'source_inventory_before': original, 'image_capture_sha256': hashlib.sha256(capture_bytes).hexdigest(),
                  'final_blob_manifest_sha256': sha(arguments.manifest_out) if arguments.manifest_out is not None else None,
                  'limitations': {'historical_external_auditor': 'NOT_RECOVERED_NOT_REUSED',
                    'deleted_bulk_sql_fingerprint_recomputation': 'NOT_CLAIMED; old random batch files were deleted by the unchanged original controller',
                    'six_overwritten_historical_blob_versions': 'NOT_REHASHABLE_FROM_FINAL_IMAGE',
                    'independent_full_s3_graph_reconstruction': 'NOT_CLAIMED; original proxy stores hashes and lengths, not every object body. The original native activation traverses and verifies the full closure; this auditor checks its original wire witnesses and the complete resulting native image.',
                    'sigv4_mac_recomputation': 'NOT_CLAIMED_BY_THIS_AUDITOR; private keys are not read',
                    'network_delivery_timing': 'object_response is the backend-response lower bound; object_response_delivered is a matching post-send log and may legally follow a client ACK or next request. No exact client-delivery timestamp is claimed.',
                    'aws_standard': 'NOT_RUN', 'production_slo': 'NOT_RUN', 'default_quota_10gib': 'NOT_RUN',
                    'unit_coverage_contribution': False}}
    finally:
        equal(inventory(directory), original, 'original-files-unchanged', 'original evidence changed')
        equal(image_inventory(arguments.image), image_before, 'original-files-unchanged', 'image or sidecars changed')
        require(arguments.capture.read_bytes() == capture_bytes, 'original-files-unchanged', 'image capture proof changed')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--capture', type=Path, required=True)
    parser.add_argument('--expected-commit', required=True)
    parser.add_argument('--manifest-out', type=Path)
    parser.add_argument('--controls', action='store_true')
    arguments = parser.parse_args()
    require(not sys.flags.optimize, 'auditor-runtime', 'Python optimization is prohibited')
    require(bool(re.fullmatch('[0-9a-f]{40}', arguments.expected_commit)), 'build-source-identity', 'invalid exact commit')
    print(json.dumps(audit(arguments), sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
