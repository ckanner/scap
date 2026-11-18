"""Adversarial self-checks for the independent auditor, not product evidence."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

import oracle as audit


SCOPE = {'deployment': '1', 'tenant': '7', 'database': '8701', 'incarnation': '1', 'generation': '1'}


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


class Bytes:
    def __init__(self):
        self.values = {}

    def add(self, raw):
        digest = audit.sha(raw)
        ref = {'file': 'raw/' + digest, 'sha256': digest, 'bytes': len(raw)}
        self.values[ref['file']] = raw
        return ref

    def read(self, ref):
        return self.values[ref['file']]


def head(database='8701'):
    return {'scope': {key: int(database if key == 'database' else value) for key, value in SCOPE.items()},
        'revision': 6, 'head_serial': 7, 'sequence': 3, 'owner_epoch': 1, 'owner_instance': 9601,
        'auth_epoch': 2, 'request_epoch': 1, 'active': True, 'lifecycle': 'ready', 'owner_plan': None,
        'transition': {'revision': 6, 'nonce': 3}, 'quota': {'max_bytes': 67108864},
        'retention': {'max_entries': 129, 'max_result_bytes': 268435456}, 'windows': [{'epoch': 1}],
        'storage': {'active_generation': 1, 'allocated_through': 1, 'plan': None, 'sweep': None, 'terminal': None},
        'data_root': 'a' * 64, 'snapshots': [], 'restore_origin': None}


def original_get():
    value = head()
    return {'request': {'method': 'GET', 'role': 'B', 'sequence': 10},
        'response': {'sequence': 12, 'status': 200}, 'head': value,
        'raw': encoded(value), 'etag': 'original-etag'}


def candidate():
    value = head()
    value['head_serial'] = 8
    return {'request': {'method': 'PUT', 'role': 'B', 'sequence': 20,
                       'headers': {'if-match': 'original-etag'}},
            'head': value, 'raw': encoded(value), 'response': {'status': 412, 'sequence': 22}}


def failed_reads(seconds):
    return [{'body': {'operation': 'status'},
             'request': {'role': 'B', 'sequence': index + 1, 'monotonic_ns': round(value * 1_000_000_000)},
             'failure': {'failure': 'ConnectionRefusedError'}, 'cut': None}
            for index, value in enumerate(seconds)]


def prepared_inspect():
    current = head()
    fixed = {'creator': 12, 'operation': 7, 'expected_revision': 6, 'expected_head_serial': 7,
        'mode': 'takeover', 'target_worker': 9602,
        'nonces': {'claim': 101, 'cancel': 102, 'activate': 103, 'abort': 104}}
    record = {'version': 1, 'scope': current['scope'], 'input': fixed}
    raw = encoded(record)
    reference = {'creator': '12', 'operation': '7', 'descriptor_hash': audit.sha(raw)}
    path = '/scap-test/scap-object/v1/1/7/8701/inc/1/gen/1/owner/v1/descriptor/12/7'
    descriptors = {path: {'record': record, 'raw': raw, 'hash': audit.sha(raw), 'occurrences': [
        {'request': {'method': 'PUT', 'role': 'M', 'sequence': 1}, 'response': {'sequence': 2}},
        {'request': {'method': 'GET', 'role': 'M', 'sequence': 12}, 'response': {'sequence': 13}}]}}
    observed = {'request': {'method': 'GET', 'role': 'M', 'sequence': 14},
        'response': {'sequence': 15}, 'head': current, 'raw': encoded(current), 'etag': 'original-etag'}
    call = {'request': {'role': 'M', 'sequence': 10}, 'response': {'status': 200, 'sequence': 20},
        'body': {'operation': 'owner_inspect', 'identity': {'creator': '12', 'operation': '7'}},
        'value': {'ok': True, 'value': {'state': 'prepared', 'accepted': None,
            'status': audit.projection(current),
            'prepared': {'scope': SCOPE, 'input': audit.public(fixed), 'reference': reference}}}}
    return call, descriptors, [observed]


def fixed_policy():
    endpoints = {role: f'http://127.0.0.1:{port}/v1' for role, port in
                 (('A', 13001), ('B', 13002), ('C', 13003), ('M', 13005))}
    workers = {'A': 9601, 'B': 9602, 'C': 9603, 'M': 9605}
    scope = dict(SCOPE, database='8702')
    return {'scope': scope, 'authorityId': 'controller-matrix-private-s3', 'principal': '12',
        'metadataEndpoints': [endpoints['M']],
        'workers': [{'workerInstance': str(workers[role]), 'endpoint': endpoints[role], 'rank': rank}
                    for rank, role in enumerate(('A', 'C', 'B'))],
        'modes': {'takeover': True, 'activate': True, 'cancel': True},
        'allowInsecureHttp': True, 'recoveryTimeoutMs': 60000}, endpoints, workers


def node_binding(identifier):
    inputs = {'source_root': '/bound/controller-source', 'source_sha256': 'd' * 64,
        'javascript_inputs': {'sdk/node/bin/owner-controller.mjs': 'a' * 64,
            'sdk/node/src/controller.js': 'b' * 64,
            'experiments/object-controller-matrix/client.mjs': 'c' * 64}}
    relative = ('sdk/node/bin/owner-controller.mjs' if identifier.startswith('controller-')
                else 'experiments/object-controller-matrix/client.mjs')
    entrypoint = inputs['source_root'] + '/' + relative
    start = {'event': 'child_started', 'id': identifier, 'sequence': 10,
             'command': ['/tools/node', entrypoint, '/private/config.json']}
    bound = {'event': 'node_source_bound', 'id': identifier, 'sequence': 9,
        'source_root': inputs['source_root'], 'entrypoint': entrypoint,
        'entrypoint_sha256': inputs['javascript_inputs'][relative],
        'javascript_inputs': deepcopy(inputs['javascript_inputs']),
        'source_sha256': inputs['source_sha256'], 'runtime_options_absent': True}
    return start, [bound], inputs


class OracleTests(unittest.TestCase):
    def reject(self, guard):
        return self.assertRaisesRegex(audit.Rejected, '^' + guard + '$')

    def release_inputs(self):
        eligible = (
            'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml',
            'crates/scap-service/Cargo.toml', 'crates/scap-service/build.rs',
            'crates/scap-service/src/lib.rs', 'sdk/node/package.json',
            'sdk/node/src/client.js', 'sdk/node/src/types.ts',
            'sdk/node-codec/src/codec.mjs', 'experiments/object-service/build.py',
            'experiments/object-network/Cargo.lock',
        )
        ignored = (
            'README.md', 'docs/example.rs', 'Cargo.toml.backup',
            'crates/scap-service/README.md', 'sdk/node/fixture.json',
            'sdk/node-extra/src/unrelated.js', 'experiments/object-service-extra/run.py',
        )
        files = {name: {'sha256': audit.sha(name.encode())} for name in (*eligible, *ignored)}
        return files, {name: files[name]['sha256'] for name in eligible}

    def test_release_inputs_follow_complete_fixed_build_rules_without_a_file_count(self):
        files, receipt = self.release_inputs()
        self.assertEqual(audit.release_source_inputs(files), receipt)
        audit.release_source_equivalence(files, receipt)
        name = 'crates/scap-object/src/catalogue/new_restore_consumer.rs'
        files[name] = {'sha256': audit.sha(b'new legitimate production source')}
        with self.reject('release-source-equivalence'):
            audit.release_source_equivalence(files, receipt)
        receipt[name] = files[name]['sha256']
        audit.release_source_equivalence(files, receipt)

    def test_release_receipt_rejects_missing_extra_out_of_rule_and_wrong_hash_inputs(self):
        for change in ('missing', 'extra', 'ignored', 'wrong_hash'):
            files, receipt = self.release_inputs()
            if change == 'missing':
                del receipt['crates/scap-service/src/lib.rs']
            elif change == 'extra':
                receipt['crates/scap-service/src/not_captured.rs'] = 'a' * 64
            elif change == 'ignored':
                # Even a real captured file cannot be added unless the fixed
                # builder includes it; subset matching would accept this.
                receipt['docs/example.rs'] = files['docs/example.rs']['sha256']
            else:
                receipt['sdk/node/src/client.js'] = 'a' * 64
            with self.subTest(change=change), self.reject('release-source-equivalence'):
                audit.release_source_equivalence(files, receipt)

    def test_release_requires_all_root_build_inputs_even_when_both_manifests_omit_one(self):
        for root in ('Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml'):
            files, receipt = self.release_inputs()
            del receipt[root]
            with self.subTest(root=root), self.reject('release-source-equivalence'):
                audit.release_source_equivalence(files, receipt)
            del files[root]
            with self.subTest(root=root), self.reject('release-required-root-inputs'):
                audit.release_source_equivalence(files, receipt)

    def test_release_source_paths_cannot_alias_or_escape_the_captured_root(self):
        for path in ('.', '/crates/foreign.rs', 'crates/../foreign.rs', './Cargo.toml', 'crates//alias.rs'):
            files, receipt = self.release_inputs()
            files[path] = {'sha256': 'a' * 64}
            with self.subTest(path=path), self.reject('release-source-path'):
                audit.release_source_equivalence(files, receipt)

    def test_rejected_412_candidate_is_checked_by_full_s3_audit(self):
        store, events = Bytes(), [{'event': 'backend_started', 'normal_access_sha256': 'test-normal-authority'}]
        path = '/scap-test/scap-object/v1/1/7/8701/head'
        original, proposed = original_get(), candidate()
        for serial, method, body, status, response, headers in (
            (1, 'GET', b'', 200, original['raw'], {}),
            (2, 'PUT', proposed['raw'], 412, b'', {'if-match': 'original-etag'}),
        ):
            fields = {'role': 'B', 'serial': serial}
            start = 1 + (serial - 1) * 5
            events.extend([
                {'event': 's3_handler_started', 'sequence': start, **fields},
                {'event': 's3_request', 'sequence': start + 1, 'method': method, 'path': path,
                 'signature_valid': True, 'headers': headers, 'request': store.add(body), **fields},
                {'event': 's3_backend_response', 'sequence': start + 2, 'status': status,
                 'headers': {'etag': 'original-etag'} if method == 'GET' else {},
                 'response': store.add(response), **fields},
                {'event': 's3_delivery_finished', 'sequence': start + 3, **fields},
                {'event': 's3_handler_finished', 'sequence': start + 4, **fields},
            ])
        events.append({'event': 's3_proxy_stopped', 'role': 'B', 'joined': True, 'errors': [], 'request_count': 2})
        exchanges, heads, _ = audit.s3_exchanges(events, store.read, SCOPE)
        self.assertEqual(len(exchanges), 2)
        self.assertEqual([item['request']['method'] for item in heads], ['GET'])
        broken = deepcopy(events)
        next(row for row in broken if row['event'] == 's3_request' and row['method'] == 'PUT')['headers']['if-match'] = 'unseen'
        with self.reject('head-original-exact-get'):
            audit.s3_exchanges(broken, store.read, SCOPE)
        changed = deepcopy(proposed['head'])
        changed['head_serial'] += 1
        broken = deepcopy(events)
        next(row for row in broken if row['event'] == 's3_request' and row['method'] == 'PUT')['request'] = store.add(encoded(changed))
        with self.reject('head-original-next-serial'):
            audit.s3_exchanges(broken, store.read, SCOPE)

    def test_original_get_must_precede_candidate_on_same_actual_role(self):
        audit.original_head_candidate(candidate(), [original_get()])
        for change in ('role', 'method', 'order'):
            with self.subTest(change=change):
                original = original_get()
                if change == 'order':
                    original['response']['sequence'] = 21
                else:
                    original['request'][change] = 'M' if change == 'role' else 'PUT'
                with self.reject('head-original-exact-get'):
                    audit.original_head_candidate(candidate(), [original])

    def test_same_etag_cannot_name_two_original_bodies(self):
        first, second = original_get(), original_get()
        second['raw'] = first['raw'] + b' '
        with self.reject('etag-no-aba'):
            audit.original_head_candidate(candidate(), [first, second])

    def test_initial_candidate_requires_absence_and_first_serial(self):
        item = candidate()
        item['request']['headers'] = {'if-none-match': '*'}
        item['head']['head_serial'] = 1
        audit.original_head_candidate(item, [])
        item['head']['head_serial'] = 2
        with self.reject('head-initial-absent'):
            audit.original_head_candidate(item, [])

    def test_late_candidate_keeps_both_original_body_and_etag(self):
        store = Bytes()
        request = {'headers': {'if-match': 'original-etag'}, 'request': store.add(candidate()['raw'])}
        winner = {'request': deepcopy(request)}
        audit.late_same_candidate(request, winner)
        for change in ('etag', 'body'):
            with self.subTest(change=change):
                late = deepcopy(request)
                if change == 'etag':
                    late['headers']['if-match'] = 'rebased-etag'
                else:
                    late['request'] = store.add(candidate()['raw'] + b' ')
                with self.reject('late-original-candidate-unchanged'):
                    audit.late_same_candidate(late, winner)

    def test_failure_window_accepts_valid_subsequence_with_intervening_bursts(self):
        for times in ([0, 1, 5], [0, 1, 4.1, 5], [0, 1, 4.5, 5.1]):
            with self.subTest(times=times):
                audit.fixed_failure_window([], failed_reads(times), 'B', 99, 'unit-failure-window')

    def test_failure_window_rejects_burst_count_short_span_or_wrong_boundary(self):
        for times in ([0, .1, 5.1], [0, 1, 2], [0, 5]):
            with self.subTest(times=times), self.reject('unit-failure-window'):
                audit.fixed_failure_window([], failed_reads(times), 'B', 99, 'unit-failure-window')
        with self.reject('unit-failure-window'):
            audit.fixed_failure_window([], failed_reads([0, 1, 5]), 'B', 3, 'unit-failure-window')
        with self.reject('unit-failure-window'):
            audit.fixed_failure_window([], failed_reads([0, 1, 5]), 'M', 99, 'unit-failure-window')

    def test_fresh_blocked_reports_require_two_distinct_indices_after_cut(self):
        report = {'state': 'blocked', 'reason': 'POLICY'}
        reports = {'controller-two': [deepcopy(report) for _ in range(4)]}
        events = [{'event': 'scenario_phase', 'label': 'after-winner', 'sequence': 10},
            {'event': 'controller_report_cut', 'id': 'controller-two', 'line_count': 2, 'sequence': 11}]
        observed = [{'event': 'controller_report_observed', 'id': 'controller-two',
                     'line_index': index, 'sequence': 12 + index, 'report': report} for index in (2, 3)]
        audit.fresh_blocked_reports(events + observed, reports, 'after-winner', 'POLICY', 'unit-fresh-reports')
        for indices in ((0, 1), (2, 2)):
            rows = deepcopy(observed)
            for row, index in zip(rows, indices):
                row['line_index'] = index
            with self.subTest(indices=indices), self.reject('unit-fresh-reports'):
                audit.fresh_blocked_reports(events + rows, reports, 'after-winner', 'POLICY', 'unit-fresh-reports')

    def test_raw_file_rejects_changed_bytes_invalid_extent_and_path_escape(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / 'raw').mkdir()
            raw = b'original witness'
            ref = Bytes().add(raw)
            path = directory / ref['file']
            path.write_bytes(raw)
            self.assertEqual(audit.raw_file(directory, ref), raw)
            changed = dict(ref, bytes=ref['bytes'] + 1)
            with self.reject('raw-hash'):
                audit.raw_file(directory, changed)
            with self.reject('raw-path'):
                audit.raw_file(directory, dict(ref, file='../outside'))
            path.write_bytes(b'changed! witness')
            with self.reject('raw-hash'):
                audit.raw_file(directory, ref)

    def test_raw_file_does_not_follow_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / 'raw').mkdir()
            raw = b'original'
            ref = Bytes().add(raw)
            target = directory / 'outside-raw'
            target.write_bytes(raw)
            (directory / ref['file']).symlink_to(target)
            with self.reject('raw-file'):
                audit.raw_file(directory, ref)

    def test_complete_json_lines_reject_duplicate_keys_and_truncation(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'events.jsonl'
            path.write_bytes(b'{"sequence":1}\n')
            self.assertEqual(audit.read_rows(path), [{'sequence': 1}])
            path.write_bytes(b'{"sequence":1,"sequence":2}\n')
            with self.assertRaisesRegex(ValueError, 'duplicate JSON key'):
                audit.read_rows(path)
            path.write_bytes(b'{"sequence":1}')
            with self.reject('complete-ledger'):
                audit.read_rows(path)
            path.write_bytes(b'{"nested":{"x":1,"x":2}}\n')
            with self.assertRaisesRegex(ValueError, 'duplicate JSON key'):
                audit.read_rows(path)

    def test_partial_or_reordered_inventory_cannot_get_complete_verdict(self):
        cases = list(audit.CASES)
        variants = [
            {'version': 1, 'expected': cases, 'selected': cases[:1], 'complete': False},
            {'version': 1, 'expected': cases[:1], 'selected': cases[:1], 'complete': True},
            {'version': 1, 'expected': cases, 'selected': list(reversed(cases)), 'complete': True},
        ]
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for value in variants:
                (directory / 'cases.json').write_bytes(encoded(value))
                with self.subTest(inventory=value), self.reject('complete-fixed-matrix'):
                    audit.audit(directory)

    def test_prepared_inspect_requires_real_status_and_no_accepted_marker(self):
        call, descriptors, heads = prepared_inspect()
        audit.owner_observation(call, descriptors, heads, SCOPE)
        for change, guard in (('missing', 'actual-http-status-shape'),
                              ('wrong', 'http-status-from-original-s3'),
                              ('accepted', 'unaccepted-prepared-observation')):
            broken = deepcopy(call)
            value = broken['value']['value']
            if change == 'missing':
                del value['status']
            elif change == 'wrong':
                value['status']['owner_instance'] = '9602'
            else:
                value['accepted'] = {'reference': value['prepared']['reference']}
            with self.subTest(change=change), self.reject(guard):
                audit.owner_observation(broken, descriptors, heads, SCOPE)

    def test_prepare_response_has_no_status_but_cannot_smuggle_one(self):
        call, descriptors, heads = prepared_inspect()
        value = call['value']['value']
        call['body'] = {'operation': 'owner_prepare', 'input': value['prepared']['input']}
        call['value']['value'] = {'state': 'prepared', 'prepared': value['prepared']}
        audit.owner_observation(call, descriptors, heads, SCOPE)
        call['value']['value']['status'] = value['status']
        with self.reject('prepared-response-fields'):
            audit.owner_observation(call, descriptors, heads, SCOPE)

    def test_observation_rejects_report_only_state_and_descriptor_read_from_future(self):
        call, descriptors, heads = prepared_inspect()
        call['value']['value']['state'] = 'active_observed'
        with self.reject('known-owner-observation'):
            audit.owner_observation(call, descriptors, heads, SCOPE)
        call, descriptors, heads = prepared_inspect()
        next(iter(descriptors.values()))['occurrences'][1]['response']['sequence'] = 21
        with self.reject('descriptor-persisted-and-read-before-http'):
            audit.owner_observation(call, descriptors, heads, SCOPE)

    def test_error_code_must_match_original_http_status(self):
        store = Bytes()
        fields = {'role': 'M', 'serial': 1}
        events = [
            {'event': 'http_proxy_request', 'sequence': 1, 'operation': 'status', 'principal': '12',
             'request': store.add(encoded({'operation': 'status'})), **fields},
            {'event': 'http_proxy_backend_response', 'sequence': 2, 'status': 403,
             'response': store.add(encoded({'ok': False, 'error': {'code': 'DENIED', 'message': 'DENIED'}})), **fields},
            {'event': 'http_proxy_delivery_finished', 'sequence': 3, 'complete': True, **fields},
            {'event': 'http_proxy_handler_finished', 'sequence': 4, **fields},
            {'event': 'http_proxy_closed', 'sequence': 5, 'role': 'M', 'joined': True, 'errors': [], 'request_count': 1},
        ]
        self.assertEqual(audit.error_code(audit.http_exchanges(events, store.read)[0]), 'DENIED')
        events[1]['status'] = 503
        with self.reject('original-http-error-status'):
            audit.http_exchanges(events, store.read)

    def test_policy_digest_matches_fixed_full_four_word_vector(self):
        policy, _, _ = fixed_policy()
        # Vector cross-checked once against the production SDK; this test imports no SDK.
        self.assertEqual(audit.policy_digest(policy), (
            'ebd2e1528b4538aa062c19d3e3f13f72530584c0d06546857a087a394545b781',
            {'claim': '16992892088662440106', 'cancel': '444758861055868786',
             'activate': '5982333643696457349', 'abort': '8793412658834814849'}))

    def test_fixed_policy_cannot_change_authority_rank_or_metadata_route(self):
        policy, endpoints, workers = fixed_policy()
        inputs = {'scope': policy['scope'], 'workers': workers, 'three_rank_workers': True,
                  'metadata_routes': 1, 'case_id': 'C2_same_creator_policy'}
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for change in (None, 'authority', 'rank', 'metadata'):
                store = Bytes()
                raw = deepcopy(policy)
                if change == 'authority':
                    raw['authorityId'] = 'different-authority'
                elif change == 'rank':
                    raw['workers'][1]['rank'], raw['workers'][2]['rank'] = 2, 1
                elif change == 'metadata':
                    raw['metadataEndpoints'] = [endpoints['C']]
                config = {'version': 1, 'scopes': [{'policy': raw, 'tokenEnv': 'SCAP_CONTROLLER_MATRIX_TOKEN'}]}
                payload = encoded(config)
                (directory / 'controller-two.json').write_bytes(payload)
                empty = store.add(b'')
                events = [{'event': 'http_proxy_started', 'role': role, 'endpoint': value[:-3]}
                          for role, value in endpoints.items()]
                events += [
                    {'event': 'controller_configuration', 'id': 'controller-two', 'principal': '12',
                     'file': 'controller-two.json', 'config': store.add(payload)},
                    {'event': 'child_started', 'id': 'controller-two', 'sequence': 2},
                    {'event': 'child_stopped', 'id': 'controller-two', 'sequence': 30, 'stderr': empty},
                    {'event': 'controller_reports', 'id': 'controller-two', 'raw': empty},
                ]
                calls = [{'request': {'principal': '12', 'role': 'M', 'sequence': 10},
                          'body': {'operation': 'status'}, 'response': None, 'value': None}]
                arguments = (directory, events, calls, [{'head': head('8702')}], {}, store.read, inputs)
                if change is None:
                    audit.controllers(*arguments)
                else:
                    with self.subTest(change=change), self.reject('fixed-controller-policy'):
                        audit.controllers(*arguments)

    def test_node_source_binding_accepts_both_fixed_entrypoints(self):
        for identifier in ('controller-one', 'business-initialize'):
            with self.subTest(identifier=identifier):
                audit.node_source_binding(*node_binding(identifier))

    def test_node_source_binding_rejects_suffix_only_path_and_changed_sdk_bytes(self):
        for identifier in ('controller-one', 'business-verify'):
            start, events, inputs = node_binding(identifier)
            start['command'][1] = start['command'][1].replace('/bound/controller-source', '/tmp/unbound-source')
            with self.subTest(identifier=identifier), self.reject('production-node-entrypoint'):
                audit.node_source_binding(start, events, inputs)
        start, events, inputs = node_binding('controller-one')
        events[0]['javascript_inputs']['sdk/node/src/controller.js'] = 'e' * 64
        with self.reject('actual-node-source-inputs'):
            audit.node_source_binding(start, events, inputs)

    def test_node_source_binding_rejects_runtime_injection_or_late_binding(self):
        start, events, inputs = node_binding('controller-one')
        events[0]['runtime_options_absent'] = False
        with self.reject('bound-node-runtime-options'):
            audit.node_source_binding(start, events, inputs)
        for sequence in (10, 11):
            start, events, inputs = node_binding('business-verify')
            events[0]['sequence'] = sequence
            with self.subTest(sequence=sequence), self.reject('node-source-before-spawn'):
                audit.node_source_binding(start, events, inputs)


if __name__ == '__main__':
    unittest.main()
