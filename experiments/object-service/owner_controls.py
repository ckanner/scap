#!/usr/bin/env python3
"""Mutate copies of real owner evidence; no synthetic trace is a passing run."""
from __future__ import annotations

import argparse
import base64
import copy
import json
import os
from pathlib import Path
import shutil
import struct

import owner_oracle as oracle


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False) + '\n').encode()


def save(path, raw):
    replacement = path.with_name(path.name + '.replacement')
    replacement.write_bytes(raw)
    replacement.replace(path)  # A control must never mutate its hard-linked original.


def document(path, change):
    value = oracle.parse(path.read_bytes()); change(value); save(path, encoded(value))


def reorder(values):
    values.sort(key=oracle.stamp)
    for number, row in enumerate(values, 1): row['sequence'] = number


def ledger(path, change, *, renumber=False):
    values = oracle.rows(path.parent, path.name); change(values)
    if renumber: reorder(values)
    save(path, b''.join(encoded(row) for row in values))


def select(values, **fields):
    return oracle.only([row for row in values if all(row.get(key) == value for key, value in fields.items())],
                       'control did not select one original witness: ' + str(fields))


def actual_request(values, command, operation, worker):
    return oracle.only([row for row in values if row['event'] == 'http_request' and row['command'] == command and
                        row['worker'] == worker and oracle.parse(oracle.b64(row['request_body']))['operation'] == operation],
                       'control did not select one original operation')


def edit_node(directory, node, change):
    path = directory / f'node-{node}.jsonl'
    values = oracle.rows(directory, path.name)
    change(values)
    lines = [encoded(row) for row in values]
    save(path, b''.join(lines))
    def mirror(events):
        observed = [row for row in events if row['event'] == 'node_event' and row['node'] == node]
        oracle.require(len(observed) == len(lines), 'control changed Node row denominator unexpectedly')
        for row, raw in zip(observed, lines): row.update(raw=base64.b64encode(raw).decode(), sha256=oracle.sha(raw))
        select(events, event='node_stopped', node=node)['ledger_sha256'] = oracle.sha(path.read_bytes())
    ledger(directory / 'events.jsonl', mirror)


def outcome(directory, name, change):
    node = 2 if name.startswith('bootstrap_') else 1
    edit_node(directory, node, lambda values: change(select(values, event='command_finished', command=name)))


def request_guard(directory):
    events = oracle.rows(directory, 'events.jsonl')
    target = select(events, event='http_request', command='guard_reconcile', worker='c')
    original = oracle.parse(oracle.b64(target['request_body']))
    original['expected_worker_instance'] = '7303'
    raw = json.dumps(original, separators=(',', ':')).encode()
    def relay(values):
        for row in values:
            if row.get('http_serial') == target['http_serial']:
                row.update(request_body=base64.b64encode(raw).decode(), request_sha256=oracle.sha(raw))
    ledger(directory / 'events.jsonl', relay)
    def node(values):
        row = oracle.only([item for item in values if item['event'] == 'http_request' and item['command'] == 'guard_reconcile'
                           and oracle.parse(oracle.b64(item['body']))['operation'] == 'takeover'], 'control guard Fetch')
        row.update(body=base64.b64encode(raw).decode(), body_sha256=oracle.sha(raw))
    edit_node(directory, 1, node)


def query_metadata(directory):
    events = oracle.rows(directory, 'events.jsonl')
    response = select(events, event='http_response', command='route_query', worker='b')
    payload = oracle.parse(oracle.b64(response['response_body']))
    result = bytearray(oracle.b64(payload['value']['result']))
    result[-8:] = struct.pack('<q', 77)  # Exact last_insert_rowid, not a guessed BLOB byte.
    payload['value']['result'] = base64.b64encode(result).decode()
    raw = json.dumps(payload, separators=(',', ':')).encode()
    def relay(values):
        for row in values:
            if row.get('http_serial') == response['http_serial'] and row['event'] in ('http_response', 'http_delivered'):
                row.update(response_body=base64.b64encode(raw).decode(), response_sha256=oracle.sha(raw))
    ledger(directory / 'events.jsonl', relay)
    def node(values):
        request = oracle.only([row for row in values if row['event'] == 'http_request' and row['command'] == 'route_query'
                               and oracle.parse(oracle.b64(row['body']))['operation'] == 'query'], 'control query Fetch')
        response = select(values, event='http_response', serial=request['serial'])
        response.update(body=base64.b64encode(raw).decode(), body_sha256=oracle.sha(raw))
        select(values, event='command_finished', command='route_query')['value']['statements'][0]['lastInsertRowid'] = {'integer': '77'}
    edit_node(directory, 1, node)


def restored_nonce(directory):
    def change(values):
        row = select(values, event='restored_intent', command='bootstrap_inspect')
        value = oracle.parse(oracle.b64(row['raw'])); value['activateNonce'] = '99999'
        raw = json.dumps(value, separators=(',', ':')).encode()
        row.update(raw=base64.b64encode(raw).decode(), sha256=oracle.sha(raw))
    edit_node(directory, 2, change)


def retry(directory):
    def change(values):
        source = actual_request(values, 'cold_write', 'execute', 'a')
        # Add a complete deliberate duplicate relay exchange. The actual SDK
        # ledger is unchanged; the fixed POST denominator must reject it.
        selected = [copy.deepcopy(row) for row in values if row.get('http_serial') == source['http_serial']]
        serial = max(row.get('http_serial', 0) for row in values) + 1
        for row in selected: row['http_serial'] = serial; row['monotonic_ns'] += 1
        values.extend(selected)
        select(values, event='proxy_stopped')['http_requests'] += 1
    ledger(directory / 'events.jsonl', change, renumber=True)


def wrong_status_principal(directory):
    configuration = oracle.parse((directory / 'owner-configuration.json').read_bytes())
    digest = configuration['credential_sha256']['manager']
    target = actual_request(oracle.rows(directory, 'events.jsonl'), 'route_query', 'status', 'a')['http_serial']
    ledger(directory / 'events.jsonl', lambda values: [row.update(credential_sha256=digest) for row in values if row.get('http_serial') == target])
    def change(values):
        request = oracle.only([row for row in values if row['event'] == 'http_request' and row['command'] == 'route_query'
                               and oracle.parse(oracle.b64(row['body']))['operation'] == 'status'], 'control original routed-query status')
        request['credential_sha256'] = digest
    edit_node(directory, 1, change)


def wrong_initial_quota(directory):
    scope = oracle.SCOPES['guard']
    def rewrite_http(raw):
        value = oracle.parse(raw)
        status = value.get('value')
        if isinstance(status, dict) and status.get('scope') == scope and 'max_bytes' in status:
            status['max_bytes'] = None
            return json.dumps(value, separators=(',', ':')).encode()
        return raw
    def relay(values):
        for row in values:
            if row['event'] in ('http_response', 'http_delivered') and row['origin'] == 'service':
                raw = rewrite_http(oracle.b64(row['response_body']))
                row.update(response_body=base64.b64encode(raw).decode(), response_sha256=oracle.sha(raw))
    ledger(directory / 'events.jsonl', relay)
    def statuses(value):
        if isinstance(value, dict):
            if value.get('scope') == scope and 'max_bytes' in value: value['max_bytes'] = None
            for child in value.values(): statuses(child)
        elif isinstance(value, list):
            for child in value: statuses(child)
    def node(values):
        for row in values:
            if row['event'] == 'http_response':
                raw = rewrite_http(oracle.b64(row['body']))
                row.update(body=base64.b64encode(raw).decode(), body_sha256=oracle.sha(raw))
            if row['event'] == 'command_finished': statuses(row)
    edit_node(directory, 1, node)
    def history(values):
        for row in values:
            if not row.get('path', '').endswith('/' + scope['database'] + '/head'): continue
            for suffix in ('request', 'response'):
                body_key = suffix + '_body'
                if body_key not in row: continue
                raw = oracle.b64(row[body_key])
                if not raw or raw[:1] != b'{': continue
                value = oracle.parse(raw)
                if value.get('format') != 6: continue
                value['quota'] = {'max_bytes': None}; raw = json.dumps(value, separators=(',', ':')).encode()
                row[body_key] = base64.b64encode(raw).decode(); row[suffix + '_bytes'] = len(raw)
                row[suffix + '_sha256'] = oracle.sha(raw); row['head_' + suffix + '_bytes'] = list(raw)
                if suffix == 'request': row['signing']['payload_sha256'] = oracle.sha(raw)
    ledger(directory / 'history.jsonl', history)


def etag_rebound(directory):
    values = oracle.rows(directory, 'history.jsonl')
    winner = oracle.only([row for row in values if row['event'] == 'object_response' and row['method'] == 'PUT'
                          and row['path'].endswith('/1004/head') and row['status'] == 200 and
                          oracle.parse(bytes(row['head_request_bytes']))['revision'] == 6], 'control late new version')
    victim = oracle.only([row for row in values if row['event'] == 'object_response' and row['method'] == 'PUT'
                          and row['path'].endswith('/1004/head') and row['status'] == 412], 'control old candidate')
    # Keep the forged replacement structurally valid so this control reaches
    # the original-observation rule, rather than a serial/revision schema check.
    # This is a mutation of an audit copy, never a product request or a retry.
    predecessor = oracle.parse(bytes(winner['head_request_bytes']))
    candidate = oracle.parse(bytes(victim['head_request_bytes']))
    candidate['head_serial'] = predecessor['head_serial'] + 1
    candidate['revision'] = predecessor['revision'] + 1
    candidate['transition']['revision'] = candidate['revision']
    raw = encoded(candidate)
    def change(rows):
        for row in rows:
            if row.get('request_serial') != victim['request_serial']: continue
            row.update(if_match=winner['etag'], request_body=base64.b64encode(raw).decode(),
                       request_bytes=len(raw), request_sha256=oracle.sha(raw), head_request_bytes=list(raw))
            row['signing']['payload_sha256'] = oracle.sha(raw)
    ledger(directory / 'history.jsonl', change)


def release_early(directory, fault, *, before_command=None):
    def change(values):
        release = select(values, event='fault_released', id=fault)
        if before_command is None:
            release['monotonic_ns'] = oracle.stamp(select(values, event='fault_entered', id=fault)) + 1
        else:
            node = oracle.rows(directory, 'node-1.jsonl')
            release['monotonic_ns'] = oracle.stamp(select(node, event='command_started', command=before_command)) - 1
    ledger(directory / 'events.jsonl', change, renumber=True)


def missing_cold_chunk(directory):
    history = oracle.rows(directory, 'history.jsonl')
    victims = {row['request_serial'] for row in history if row['event'] == 'object_response' and row['worker'] == 'd'
               and row['method'] == 'GET' and row['status'] == 200 and '/objects/' in row['path']
               and oracle.object_frame(oracle.b64(row['response_body']), row['path'])[0]['kind'] == 'chunk'}
    oracle.require(victims, 'control found no original cold chunk GET')
    serials = sorted({row['request_serial'] for row in history if 'request_serial' in row} - victims)
    mapping = {serial: index for index, serial in enumerate(serials, 1)}
    def change(rows):
        rows[:] = [row for row in rows if row.get('request_serial') not in victims]
        for row in rows:
            if 'request_serial' in row: row['request_serial'] = mapping[row['request_serial']]
    ledger(directory / 'history.jsonl', change, renumber=True)
    def events(rows):
        for row in rows:
            for key in ('request_serial', 'source_read_serial'):
                if row.get(key) is not None: row[key] = mapping[row[key]]
        select(rows, event='proxy_stopped')['s3_requests'] -= len(victims)
    ledger(directory / 'events.jsonl', events)


def guard_cache_changed(directory):
    ledger(directory / 'events.jsonl', lambda values: select(values, event='cache_observed', label='after_target_guard')['directories'].append(
        {'path': 'unexpected-empty-actor', 'device': 1, 'inode': 2}))


def aliased_process(directory):
    def change(values):
        borrowed = select(values, event='service_started', worker='a')['identity']
        for row in values:
            if row.get('worker') == 'b' and 'identity' in row: row['identity'] = copy.deepcopy(borrowed)
    ledger(directory / 'events.jsonl', change)


def cleanup_early(directory):
    def change(values):
        select(values, event='private_remove_started')['monotonic_ns'] = oracle.stamp(select(values, event='service_stop_requested', worker='b')) - 1
    ledger(directory / 'events.jsonl', change, renumber=True)


def private_cleanup_unrelated_to_cache(directory):
    def change(values):
        created = select(values, event='private_created')
        path = Path(created['path'])
        other = str(path.with_name(path.name + '-unrelated'))
        for row in values:
            if row['event'] in ('private_created', 'private_remove_started', 'private_removed'):
                row['path'] = other
    ledger(directory / 'events.jsonl', change)


def expired_gate(directory):
    def change(values):
        values.append({'schema': 1, 'sequence': len(values) + 1, 'event': 'fault_expired', 'id': 'late_put',
                       'monotonic_ns': oracle.stamp(values[-1]) + 1})
    ledger(directory / 'events.jsonl', change)


def cases():
    return {
        'widened_absolute_deadline': (lambda path: document(path / 'owner-plan.json', lambda value: next(
            item for item in value['commands'] if item['id'] == 'deadline_write').update(timeout_ms=5000)), 'absolute operation deadline changed'),
        'omitted_offered_failure': (lambda path: ledger(path / 'events.jsonl', lambda values: values.__setitem__(slice(None),
            [row for row in values if not (row['event'] == 'operator_command' and row['id'] == 'lifecycle_write')]), renumber=True), 'offered-operation order'),
        'wrong_actual_worker_guard': (request_guard, 'original phase body/identity/guard changed'),
        'routed_status_used_another_principal': (wrong_status_principal, 'Fetch used another authenticated principal'),
        'initial_quota_forged_in_all_mirrors': (wrong_initial_quota, 'initial persisted quota differs'),
        'hidden_original_sql_retry': (retry, 'actual relay POST denominator'),
        'unknown_claim_reported_not_sent': (lambda path: outcome(path, 'claim_lost', lambda value: value['error'].update(outcome='not_sent')), 'SDK outcome/retained original reference changed'),
        'unknown_activation_dropped_last_confirmed': (lambda path: outcome(path, 'activation_lost', lambda value: value['error'].update(lastConfirmed=None)), 'SDK outcome/retained original reference changed'),
        'restored_intent_regained_dispatch_rights': (lambda path: outcome(path, 'bootstrap_reuse', lambda value: value['error'].update(outcome='active')), 'SDK outcome/retained original reference changed'),
        'restored_intent_minted_new_nonce': (restored_nonce, 'restore regenerated original intent'),
        'persisted_intent_file_changed': (lambda path: save(path / 'intent-activation_prepare.json', b'{}'), 'saved original file bytes changed'),
        'typed_query_rowid_forged_in_all_mirrors': (query_metadata, 'complete SQLite result/metadata differs'),
        'old_candidate_rebound_to_new_etag': (etag_rebound, 'preceding same-call exact GET'),
        'old_writer_released_before_takeover': (lambda path: release_early(path, 'late_put'), 'old writer was not resumed after complete'),
        'acl_observation_released_before_revoke': (lambda path: release_early(path, 'acl_status_received'), 'ADMIN revocation did not race'),
        'recovery_released_before_hot_probe': (lambda path: release_early(path, 'recovery_read', before_command='recovery_hot'), 'hot/control probe did not finish during'),
        'cold_activation_skipped_complete_chunk': (missing_cold_chunk, 'complete current data closure'),
        'guard_created_empty_cache_directory': (guard_cache_changed, 'misbound target altered local cache'),
        'backend_accepted_unsigned_request': (lambda path: ledger(path / 'events.jsonl', lambda values: select(values, event='backend_unsigned_probe').update(status=200)), 'backend accepted an unsigned'),
        'two_workers_alias_one_child': (aliased_process, 'one child impersonates overlapping'),
        'missing_original_wait4': (lambda path: ledger(path / 'events.jsonl', lambda values: select(values, event='service_stopped', worker='a')['kernel_usage'].update(available=False)), 'original kernel wait4'),
        'private_removed_before_owned_exit': (cleanup_early, 'private cleanup preceded'),
        'private_cleanup_unrelated_to_cache': (private_cleanup_unrelated_to_cache, 'daemon cache escaped original private runtime'),
        'unobserved_fault_expiry_hidden': (expired_gate, 'unplanned/failed/expired/forced'),
        'actual_daemon_binary_substituted': (lambda path: ledger(path / 'events.jsonl', lambda values: select(values, event='service_started', worker='b')['binary'].update(sha256='0' * 64)), 'another actual release executable'),
    }


def main(args):
    evidence, output = args.evidence.resolve(), args.output.resolve()
    baseline = oracle.audit(evidence)
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    report = {'schema': 1, 'status': 'failed', 'profile': 'independent-real-owner-evidence-mutations',
              'baseline_evidence': str(evidence), 'baseline_sha256': baseline['evidence_sha256'],
              'denominator': len(cases()) + 1, 'negative_controls': [], 'positive_controls': []}
    try:
        for name, (mutate, expected) in cases().items():
            directory = output / name
            shutil.copytree(evidence, directory, copy_function=os.link)
            mutate(directory)
            inputs = {path.name: oracle.sha(path.read_bytes()) for path in sorted(directory.iterdir()) if path.is_file()}
            try: oracle.audit(directory)
            except ValueError as error:
                oracle.require(expected in str(error), 'negative control rejected at the wrong boundary: ' + name + ': ' + str(error))
                report['negative_controls'].append({'case': name, 'outcome': 'rejected', 'reason': str(error), 'input_files': inputs})
            else: raise AssertionError('corrupted real evidence passed: ' + name)
        directory = output / 'controller_summary_is_not_authority'
        shutil.copytree(evidence, directory, copy_function=os.link)
        save(directory / 'owner-summary.json', b'{"status":"invented","private_deleted":false,"http_posts":0}\n')
        verified = oracle.audit(directory)
        oracle.equal(verified['evidence_sha256'], baseline['evidence_sha256'], 'convenience summary changed original audit authority')
        report['positive_controls'].append({'case': directory.name, 'outcome': 'passed_without_controller_summary',
                                            'evidence_sha256': verified['evidence_sha256']})
        oracle.require(len(report['negative_controls']) + len(report['positive_controls']) == report['denominator'], 'control denominator incomplete')
        report['status'] = 'passed'
    except BaseException as error:
        report['error'] = repr(error)
        raise
    finally:
        save(output / 'controls.json', encoded(report))
        print(json.dumps({key: report.get(key) for key in ('status', 'denominator', 'error')}), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True, help='new directory for independently mutated evidence copies and controls.json')
    main(parser.parse_args())
