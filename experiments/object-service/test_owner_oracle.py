"""Synthetic verifier/control tests; never evidence that native/HTTP/S3 ran."""
from __future__ import annotations

import base64
import copy
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest

import owner_controls as controls
import owner_oracle as oracle


def encoded(value):
    return json.dumps(value, separators=(',', ':')).encode()


def wire_result(*, inserted=0, affected=0, values=(1, 2), ddl=False):
    raw = bytearray(b'SCAPRES1' + struct.pack('<I', 2 if ddl else 1))
    if ddl: raw.extend(struct.pack('<IIQq', 0, 0, 0, 0))
    raw.extend(struct.pack('<II', 1, 1) + b'n' + struct.pack('<I', len(values)))
    for value in values: raw.extend(b'\x01' + struct.pack('<q', value))
    raw.extend(struct.pack('<Qq', affected, inserted))
    return bytes(raw)


def frame(kind, value, raw=b'', database=1001):
    scope = {'deployment': 1, 'tenant': 7, 'database': database, 'incarnation': 1, 'generation': 1}
    metadata = encoded({'format': 2, 'scope': scope, 'payload': {'kind': kind, 'value': value}})
    body = b'SCAPOBJ2' + struct.pack('<IQ', len(metadata), len(raw)) + metadata + raw
    path = f'/scap-test/scap-object/v1/1/7/{database}/inc/1/gen/1/storage/1/objects/' + oracle.sha(body)
    return path, body


def data_tree():
    image = bytearray(8192); image[:18] = b'SQLite format 3\0\x10\0'
    chunk, raw = frame('chunk', {'first_page': 1, 'bytes': []}, bytes(image))
    objects = {chunk: raw}
    node, raw = frame('node', {'level': 0, 'first_chunk': 0, 'children': [chunk.rsplit('/', 1)[1]]})
    objects[node] = raw
    manifest, raw = frame('manifest', {'page_count': 2, 'root': node.rsplit('/', 1)[1]})
    objects[manifest] = raw
    return objects, manifest.rsplit('/', 1)[1], chunk


def corruption():
    path = '/scap-test/scap-object/v1/1/7/1007/inc/1/gen/1/storage/1/objects/' + 'a' * 64
    original = b'original immutable bytes'
    changed = bytes([original[0] ^ 128]) + original[1:]
    requests, responses = {}, {}
    for serial, method, worker, timestamp, body, etag, condition in (
            (1, 'PUT', 'a', 10, original, 'original-etag', '*'),
            (2, 'GET', 'b', 12, original, 'original-etag', None),
            (3, 'PUT', 'fixture', 20, changed, 'corrupt-etag', 'original-etag'),
            (4, 'GET', 'b', 22, changed, 'corrupt-etag', None),
            (5, 'PUT', 'fixture', 30, original, 'original-etag', 'corrupt-etag'),
            (6, 'GET', 'b', 32, original, 'original-etag', None)):
        requests[serial] = {'path': path, 'method': method, 'worker': worker, 'monotonic_ns': timestamp,
                            'request_body': base64.b64encode(body if method == 'PUT' else b'').decode(),
                            'if_match': condition if method == 'PUT' and condition != '*' else None,
                            'if_none_match': '*' if condition == '*' else None}
        responses[serial] = {'status': 200, 'etag': etag, 'monotonic_ns': timestamp + 1,
                             'response_body': base64.b64encode(body if method == 'GET' else b'').decode()}
    return path, requests, responses, original, changed


def signed_exchange_fixture(workers=None):
    workers = workers or {'a': '7101', 'b': '7202'}
    endpoints = {role: 'http://127.0.0.1:' + str(10001 + i) for i, role in enumerate(workers)}
    startups = [{'role': role, 'worker': worker, 'start': 1, 'ready': 200} for role, worker in workers.items()]
    history = []
    def exchange(worker, method, path, payload, body, status, when):
        serial = len(history) // 4 + 1
        signing = {'algorithm': 'AWS4-HMAC-SHA256', 'access_key_sha256': 'a' * 64,
            'credential_scope': '20261118/us-east-1/s3/aws4_request', 'date': '20261118T000000Z',
            'signature_sha256': 'b' * 64, 'host': endpoints[worker].split('://', 1)[1],
            'signed_headers': ['host', 'x-amz-content-sha256', 'x-amz-date'], 'payload_sha256': oracle.sha(payload)}
        common = {'request_serial': serial, 'worker': worker, 'phase': 'setup', 'method': method, 'path': path,
            'request_bytes': len(payload), 'request_sha256': oracle.sha(payload),
            'request_body': base64.b64encode(payload).decode(), 'signing': signing,
            'if_match': None, 'if_none_match': '*' if method == 'PUT' else None}
        response = {'status': status, 'response_bytes': len(body), 'response_sha256': oracle.sha(body),
                    'response_body': base64.b64encode(body).decode(), 'etag': '"worker-' + worker + '"' if status == 200 else None}
        if path.endswith('/head'):
            common['head_request_bytes'], response['head_response_bytes'] = list(payload), list(body)
        for offset, event in enumerate(('object_request', 'object_forwarded', 'object_response', 'object_response_delivered')):
            row = {**copy.deepcopy(common), 'event': event, 'monotonic_ns': when + offset,
                   'schema': 1, 'sequence': len(history) + 1}
            if offset >= 2:
                row.update(response)
            if event == 'object_response':
                row.update(response_origin='backend', suppressed=False)
            history.append(row)
    for i, (role, worker) in enumerate(workers.items()):
        value = b'SCAP-WORKER-INSTANCE-v1\0' + int(worker).to_bytes(8, 'big')
        path = '/scap-test/scap-worker/v1/instances/' + worker
        exchange(role, 'PUT', path, value, b'', 200, 20 + i * 20)
        exchange(role, 'GET', path, b'', value, 200, 30 + i * 20)
    exchange(next(iter(workers)), 'GET', '/scap-test/scap-object/v1/1/7/1001/head', b'', b'', 404, 220)
    return {'history': history, 'startups': startups, 'endpoints': endpoints, 'access_key_sha256': 'a' * 64,
            'phases': {'setup'}, 'blackhole_phases': ()}


class StartupPhysicalInventoryTests(unittest.TestCase):
    def test_only_verified_claims_are_separate_from_the_full_physical_inventory(self):
        net = oracle.original_s3_exchanges(**signed_exchange_fixture())
        self.assertEqual(set(net['physical_requests']), {1, 2, 3, 4, 5})
        self.assertEqual(set(net['startup_requests']), {1, 2, 3, 4})
        self.assertEqual(set(net['requests']), {5})
        self.assertEqual(set(net['startup_requests']) | set(net['requests']), set(net['physical_requests']))
        self.assertFalse(set(net['startup_requests']) & set(net['requests']))

    def test_startup_raw_bytes_cannot_disagree_with_the_exact_digest(self):
        for event, field in (('object_request', 'request_body'), ('object_response', 'response_body'),
                             ('object_response_delivered', 'response_body')):
            data = signed_exchange_fixture()
            serial = 1 if field == 'request_body' else 2
            row = next(row for row in data['history'] if row['request_serial'] == serial and row['event'] == event)
            row[field] = base64.b64encode(b'contradictory original capture').decode()
            with self.subTest(event=event), self.assertRaises(ValueError):
                oracle.original_s3_exchanges(**data)

    def test_startup_signature_is_not_hidden_by_business_filtering(self):
        for field, value, message in (
            ('access_key_sha256', 'c' * 64, 'S3 request signing principal changed'),
            ('host', 'unrelated.example:1234', 'S3 signed another endpoint'),
            ('payload_sha256', 'd' * 64, 'S3 signature omitted original request bytes'),
            ('credential_scope', '20261117/us-east-1/s3/aws4_request', 'S3 signing date/scope changed'),
        ):
            data = signed_exchange_fixture()
            for row in data['history']:
                if row['request_serial'] == 1:
                    row['signing'][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, message):
                oracle.original_s3_exchanges(**data)

    def test_forwarded_startup_cannot_rebind_its_original_signature(self):
        data = signed_exchange_fixture()
        row = next(row for row in data['history'] if row['request_serial'] == 1 and row['event'] == 'object_forwarded')
        row['signing']['signature_sha256'] = 'c' * 64
        with self.assertRaisesRegex(ValueError, 'original S3 request changed across relay stages'):
            oracle.original_s3_exchanges(**data)

    def test_missing_claim_is_not_replaced_with_a_fixed_count_allowance(self):
        data = signed_exchange_fixture()
        data['history'] = [row for row in data['history'] if row['request_serial'] != 2]
        for row in data['history']:
            if row['request_serial'] > 2:
                row['request_serial'] -= 1
        with self.assertRaisesRegex(ValueError, 'worker-identity-request-denominator'):
            oracle.original_s3_exchanges(**data)

    def test_unknown_instance_and_changed_etag_are_not_startup(self):
        for changed in ('path', 'etag'):
            data = signed_exchange_fixture()
            for row in data['history']:
                if row['request_serial'] == 2:
                    if changed == 'path':
                        row['path'] = '/scap-test/scap-worker/v1/instances/9999'
                    elif row['event'] in ('object_response', 'object_response_delivered'):
                        row['etag'] = '"another-get"'
            rule = 'worker-identity-exact-key' if changed == 'path' else 'worker-identity-same-etag'
            with self.subTest(changed=changed), self.assertRaisesRegex(ValueError, rule):
                oracle.original_s3_exchanges(**data)


class OriginalTraceTests(unittest.TestCase):
    def test_routed_query_status_preserves_writer_identity_while_owner_uses_manager(self):
        for command in ('route_query', 'late_query', 'corrupt_query', 'recovery_warm', 'recovery_hot', 'cold_query'):
            with self.subTest(command=command):
                self.assertEqual(oracle.caller(command, 'status'), 'writer')
                self.assertEqual(oracle.caller(command, 'query'), 'writer')
        self.assertEqual(oracle.caller('route_prepare', 'status'), 'manager')
        self.assertEqual(oracle.caller('reject_read', 'status'), 'blind_admin')
        self.assertEqual(oracle.caller('acl_revoke', 'policy'), 'rescue')

    def test_explicit_seed_array_survives_sorted_configuration_serialization(self):
        value = {'seed_scopes': list(oracle.NAMES), 'scopes': oracle.SCOPES}
        roundtrip = json.loads(json.dumps(value, sort_keys=True))
        self.assertEqual(roundtrip['seed_scopes'], list(oracle.NAMES))
        self.assertNotEqual(list(roundtrip['scopes']), list(oracle.NAMES))

    def test_numbered_integer_and_node_decimal_clocks(self):
        oracle.numbered([{'schema': 1, 'sequence': 1, 'monotonic_ns': 10}, {'schema': 1, 'sequence': 2, 'monotonic_ns': 11}])
        oracle.numbered([{'schema': 1, 'sequence': 1, 'monotonic_ns': '10'}, {'schema': 1, 'sequence': 2, 'monotonic_ns': '11'}], node=True)

    def test_trace_rejects_boolean_types_gaps_duplicates_and_reordered_clock(self):
        changes = ({'schema': True}, {'sequence': True}, {'sequence': 3}, {'monotonic_ns': True},
                   {'monotonic_ns': 10}, {'monotonic_ns': '11'})
        for change in changes:
            rows = [{'schema': 1, 'sequence': 1, 'monotonic_ns': 10}, {'schema': 1, 'sequence': 2, 'monotonic_ns': 11, **change}]
            with self.subTest(change=change), self.assertRaises(ValueError): oracle.numbered(rows)

    def test_noncanonical_or_empty_monotonic_clock_rejected(self):
        for value in ('01', '0', '-1', '1.0', '', 0, True, 1.0):
            with self.subTest(value=value), self.assertRaises(ValueError): oracle.stamp({'monotonic_ns': value})

    def test_digest_covers_complete_canonical_base64(self):
        row = {'body': 'YWJj', 'sha256': oracle.sha(b'abc')}
        self.assertEqual(oracle.bounded_bytes(row, 'body', 'sha256'), b'abc')
        for change in ({'body': 'YWJj\n'}, {'sha256': '0' * 64}, {'body': 'YWJjZA=='}):
            with self.subTest(change=change), self.assertRaises(ValueError): oracle.bounded_bytes({**row, **change}, 'body', 'sha256')
        with self.assertRaises(ValueError): oracle.bounded_bytes(row, 'body', 'sha256', 2)

    def test_envelope_rejects_ambiguous_or_duplicate_outcomes(self):
        for value in (b'{"ok":1,"value":{}}', b'{"ok":true,"value":{},"error":{}}',
                      b'{"ok":true,"ok":false,"value":{}}', b'{"ok":false,"error":{"code":"DENIED","message":"invented"}}'):
            with self.subTest(value=value), self.assertRaises(ValueError): oracle.envelope(value)
        self.assertEqual(oracle.envelope(b'{"ok":true,"value":{}}'), {'ok': True, 'value': {}})

    def test_registry_reordering_preserves_binding_but_changed_endpoint_does_not(self):
        routes = [['7202', 'http://127.0.0.1:2/v1'], ['7101', 'http://127.0.0.1:1/v1']]
        self.assertEqual(oracle.registry_digest(routes), oracle.registry_digest(list(reversed(routes))))
        self.assertNotEqual(oracle.registry_digest(routes), oracle.registry_digest([routes[0], ['7101', 'http://127.0.0.1:3/v1']]))


class CompleteResultTests(unittest.TestCase):
    def test_read_query_complete_metadata_and_sdk_projection(self):
        value = oracle.result_expected(wire_result(), values=[1, 2])
        self.assertEqual(oracle.sdk_result(value), {'statements': [{'columns': ['n'], 'rows': [[{'integer': '1'}], [{'integer': '2'}]],
                                                                 'affectedRows': {'integer': '0'}, 'lastInsertRowid': {'integer': '0'}}]})

    def test_original_seed_and_second_insert_metadata(self):
        oracle.result_expected(wire_result(inserted=1, affected=1, values=(1,), ddl=True), seed=True)
        oracle.result_expected(wire_result(inserted=2, affected=1, values=(2,)), inserted=2)

    def test_rowid_affected_rows_cells_and_complete_extent_are_all_checked(self):
        for raw in (wire_result(inserted=77), wire_result(affected=1), wire_result(values=(1, 99)), wire_result() + b'x', wire_result()[:-1]):
            with self.subTest(raw=raw[-16:]), self.assertRaises(ValueError): oracle.result_expected(raw, values=[1, 2])

    def test_wrong_seed_statement_metadata_is_rejected(self):
        raw = bytearray(wire_result(inserted=1, affected=1, values=(1,), ddl=True))
        raw[28:36] = struct.pack('<q', 1)
        with self.assertRaises(ValueError): oracle.result_expected(bytes(raw), seed=True)


class CompleteDependencyTests(unittest.TestCase):
    def test_actual_initial_quota_and_retention_are_explicit_and_not_observed_defaults(self):
        head = {'quota': {'max_bytes': 10737418240}, 'retention': {'max_entries': 4096, 'max_result_bytes': 268435456}}
        oracle.initial_limits(head)
        for key, value in (('quota', {'max_bytes': None}), ('quota', {'max_bytes': 4096}),
                           ('retention', {'max_entries': 4095, 'max_result_bytes': 268435456}),
                           ('retention', {'max_entries': 4096, 'max_result_bytes': 536870912})):
            with self.subTest(value=value), self.assertRaises(ValueError): oracle.initial_limits({**head, key: value})

    def test_complete_small_image_and_empty_manifest(self):
        objects, root, _ = data_tree()
        self.assertEqual(oracle.data_closure(objects, 'route', root), set(objects))
        path, raw = frame('manifest', {'page_count': 0, 'root': None})
        self.assertEqual(oracle.data_closure({path: raw}, 'route', path.rsplit('/', 1)[1]), {path})

    def test_missing_chunk_cannot_be_substituted_by_manifest(self):
        objects, root, chunk = data_tree(); del objects[chunk]
        with self.assertRaisesRegex(ValueError, 'missing complete data dependency'): oracle.data_closure(objects, 'route', root)

    def test_scope_hash_and_complete_frame_extent_are_independent(self):
        path, raw = frame('manifest', {'page_count': 0, 'root': None})
        wrong = raw[:12] + struct.pack('<Q', 5) + raw[20:]
        for body, key in ((raw[:-1] + b'x', path), (raw, path.replace('/1001/', '/1002/')),
                          (wrong, path.rsplit('/', 1)[0] + '/' + oracle.sha(wrong))):
            with self.subTest(key=key), self.assertRaises(ValueError): oracle.object_frame(body, key)

    def test_wrong_typed_root_cannot_reuse_valid_content_hash(self):
        objects, _, chunk = data_tree()
        with self.assertRaisesRegex(ValueError, 'wrong typed'): oracle.data_closure(objects, 'route', chunk.rsplit('/', 1)[1])

    def test_declared_image_extent_cannot_drop_trailing_pages(self):
        objects, root, _ = data_tree()
        prefix = next(iter(objects)).rsplit('/', 1)[0] + '/'
        payload, _ = oracle.object_frame(objects[prefix + root], prefix + root)
        path, raw = frame('manifest', {'page_count': 1, 'root': payload['value']['root']}); objects[path] = raw
        with self.assertRaisesRegex(ValueError, 'complete SQLite image extent'): oracle.data_closure(objects, 'route', path.rsplit('/', 1)[1])


class DeliberateCorruptionTests(unittest.TestCase):
    def test_exact_repair_may_reuse_original_content_etag(self):
        path, requests, responses, original, changed = corruption()
        self.assertEqual(oracle.corruption_versions(path, requests, responses), (original, changed, (1, 3, 5)))

    def test_repair_requires_exact_original_bytes_and_observed_bad_etag(self):
        for field, value in (('request_body', base64.b64encode(b'replacement').decode()), ('if_match', 'original-etag')):
            path, requests, responses, _, _ = corruption(); requests[5][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): oracle.corruption_versions(path, requests, responses)

    def test_extra_operator_put_is_not_hidden_by_restore(self):
        path, requests, responses, _, _ = corruption()
        requests[7], responses[7] = copy.deepcopy(requests[5]), copy.deepcopy(responses[5])
        with self.assertRaisesRegex(ValueError, 'exactly three'): oracle.corruption_versions(path, requests, responses)

    def test_only_fixed_first_byte_may_be_corrupted(self):
        path, requests, responses, original, _ = corruption()
        requests[3]['request_body'] = base64.b64encode(original[:-1] + b'x').decode()
        with self.assertRaisesRegex(ValueError, 'fixed first byte'): oracle.corruption_versions(path, requests, responses)

    def test_changed_bytes_cannot_reuse_original_etag(self):
        path, requests, responses, _, _ = corruption()
        responses[3]['etag'] = 'original-etag'; requests[5]['if_match'] = 'original-etag'
        with self.assertRaisesRegex(ValueError, 'incompatible ETag'): oracle.corruption_versions(path, requests, responses)

    def test_original_get_may_overlap_corruption_but_cannot_start_after_it(self):
        path, requests, responses, _, _ = corruption()
        requests[2]['monotonic_ns'], responses[2]['monotonic_ns'] = 19, 22
        oracle.corruption_versions(path, requests, responses)
        requests[2]['monotonic_ns'], responses[2]['monotonic_ns'] = 24, 25
        with self.assertRaisesRegex(ValueError, 'possible original version interval'): oracle.corruption_versions(path, requests, responses)

    def test_unknown_bytes_cannot_borrow_an_observed_etag(self):
        path, requests, responses, _, _ = corruption()
        responses[4]['response_body'] = base64.b64encode(b'invented').decode()
        with self.assertRaisesRegex(ValueError, 'possible original version interval'): oracle.corruption_versions(path, requests, responses)


class OwnedProcessTests(unittest.TestCase):
    def test_private_runtime_may_live_beside_ci_evidence(self):
        for parent in ('/tmp', '/home/runner/work/_temp', '/workspace/evidence'):
            oracle.private_runtime_identity({'path': parent + '/scap-owner-private-original_123', 'device': 27, 'inode': 88})

    def test_private_runtime_cannot_alias_or_change_owned_directory_shape(self):
        valid = {'path': '/workspace/scap-owner-private-original', 'device': 27, 'inode': 88}
        changed = [dict(valid, path=value) for value in ('scap-owner-private-original',
            '/workspace/../scap-owner-private-original', '/workspace/./scap-owner-private-original',
            '/workspace//scap-owner-private-original', '/workspace/unowned', '/workspace/scap-owner-private-')]
        changed += [dict(valid, device=True), dict(valid, inode=0), dict(valid, extra=1)]
        for value in changed:
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'private runtime identity changed'):
                oracle.private_runtime_identity(value)

    def test_all_original_worker_caches_belong_to_the_recorded_private_directory(self):
        private = {'path': '/workspace/scap-owner-private-original', 'device': 27, 'inode': 88}
        caches = {worker: private['path'] + '/cache-' + worker for worker in oracle.WORKERS}
        oracle.private_cache_directories(private, caches)
        for cache in ('/elsewhere/cache-b', private['path'] + '/cache-c', private['path'] + '/../cache-b'):
            with self.subTest(cache=cache), self.assertRaisesRegex(ValueError, 'daemon cache escaped original private runtime'):
                oracle.private_cache_directories(private, {**caches, 'b': cache})
        with self.assertRaisesRegex(ValueError, 'private cache worker denominator changed'):
            oracle.private_cache_directories(private, {})

    def test_node_shutdown_requires_same_owned_child_and_original_graceful_order(self):
        ident = {'pid': 123, 'spawn_monotonic_ns': 2, 'pid_source': 'owned_Popen_child'}
        start = {'identity': ident, 'monotonic_ns': 3}
        requested = {'identity': ident, 'monotonic_ns': 10, 'forced': False}
        marker = {'monotonic_ns': '15'}
        stop = {'identity': ident, 'monotonic_ns': 20, 'forced': False}
        oracle.node_shutdown(start, requested, stop, marker)
        for change in ({'forced': True}, {'monotonic_ns': 15}, {'identity': {**ident, 'pid': 456}}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                oracle.node_shutdown(start, {**requested, **change}, stop, marker)

    def test_wait4_requires_exact_exit_and_kernel_owned_usage(self):
        value = {'wait_status': 0, 'kernel_usage': {'available': True, 'source': 'kernel_wait4_owned_child',
                 'maxrss_bytes': 100, 'user_seconds': .2, 'system_seconds': .1}}
        oracle.wait4(value, 0)
        for change in ({'available': False}, {'source': 'estimated'}, {'maxrss_bytes': True}, {'user_seconds': -1}):
            bad = copy.deepcopy(value); bad['kernel_usage'].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError): oracle.wait4(bad, 0)
        for status in (True, 1, -9):
            with self.subTest(status=status), self.assertRaises(ValueError): oracle.wait4({**value, 'wait_status': status}, 0)

    def test_process_identity_rejects_role_only_or_nonowned_pid(self):
        value = {'pid': 123, 'spawn_monotonic_ns': 456, 'pid_source': 'owned_Popen_child'}
        self.assertEqual(oracle.identity(value), value)
        for change in ({'pid': True}, {'spawn_monotonic_ns': '456'}, {'pid_source': '/proc/guessed'}, {'pid': 0}):
            with self.subTest(change=change), self.assertRaises(ValueError): oracle.identity({**value, **change})


class MutationMechanismTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.directory = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def test_mutation_never_truncates_hardlinked_original(self):
        source, destination = self.directory / 'original', self.directory / 'copy'
        source.write_bytes(b'original'); os.link(source, destination)
        controls.save(destination, b'changed')
        self.assertEqual(source.read_bytes(), b'original'); self.assertEqual(destination.read_bytes(), b'changed')

    def test_private_cleanup_control_keeps_identity_mirrors_but_breaks_cache_ownership(self):
        private = {'path': '/workspace/scap-owner-private-original', 'device': 27, 'inode': 88}
        events = [{'event': event, **private} for event in ('private_created', 'private_remove_started', 'private_removed')]
        (self.directory / 'events.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in events))
        controls.private_cleanup_unrelated_to_cache(self.directory)
        changed = oracle.rows(self.directory, 'events.jsonl')
        values = [{key: row[key] for key in private} for row in changed]
        self.assertEqual(values, [values[0]] * 3)
        oracle.private_runtime_identity(values[0])
        with self.assertRaisesRegex(ValueError, 'daemon cache escaped original private runtime'):
            oracle.private_cache_directories(values[0], {worker: private['path'] + '/cache-' + worker for worker in oracle.WORKERS})

    def test_etag_rebound_passes_head_schema_but_lacks_original_exact_get(self):
        from test_object_wire import Trace, body
        trace = Trace()
        path = '/scap-test/scap-object/v1/1/7/1004/head'
        def head(revision):
            value = json.loads(body(revision)); value['scope']['database'] = 1004
            return encoded(value)
        trace.exchange('PUT', begin=10, end=15, path=path, request=head(1), etag='"v1"', create='*')
        for revision in range(2, 7):
            trace.exchange('GET', begin=revision*20, end=revision*20+3, path=path,
                           response=head(revision-1), etag=f'"v{revision-1}"')
            trace.exchange('PUT', begin=revision*20+5, end=revision*20+8, path=path,
                           request=head(revision), etag=f'"v{revision}"', match=f'"v{revision-1}"')
        victim = trace.exchange('PUT', begin=200, end=210, status=412, path=path,
                                request=head(5), match='"v4"')
        for row in trace.history:
            raw = bytes(row['head_request_bytes'])
            row['request_body'] = base64.b64encode(raw).decode()
            row['signing'] = {'payload_sha256': oracle.sha(raw)}
        trace.audit()
        source = self.directory / 'original-history.jsonl'
        original = b''.join(controls.encoded(row) for row in trace.history)
        source.write_bytes(original); os.link(source, self.directory / 'history.jsonl')
        controls.etag_rebound(self.directory)
        self.assertEqual(source.read_bytes(), original)
        changed = oracle.rows(self.directory, 'history.jsonl')
        for before, after in zip(trace.history, changed):
            if after['request_serial'] != victim:
                self.assertEqual(after, before); continue
            raw = oracle.b64(after['request_body']); value = oracle.parse(raw)
            self.assertEqual((value['head_serial'], value['revision'], value['transition']['revision']), (7, 7, 7))
            self.assertEqual(value['transition']['nonce'], 5)
            self.assertEqual(after['head_request_bytes'], list(raw))
            self.assertEqual(after['request_bytes'], len(raw))
            self.assertEqual(after['request_sha256'], oracle.sha(raw))
            self.assertEqual(after['signing']['payload_sha256'], oracle.sha(raw))
            self.assertEqual(after['if_match'], '"v6"')
        trace.history = changed
        with self.assertRaisesRegex(ValueError, 'preceding same-call exact GET'):
            trace.audit()

    def test_node_edit_updates_original_stdout_mirror_and_final_ledger_hash(self):
        row = {'schema': 1, 'sequence': 1, 'monotonic_ns': '10', 'event': 'command_finished', 'command': 'claim_lost',
               'ok': False, 'error': {'outcome': 'unknown'}}
        raw = controls.encoded(row); (self.directory / 'node-1.jsonl').write_bytes(raw)
        events = [{'schema': 1, 'sequence': 1, 'monotonic_ns': 11, 'event': 'node_event', 'node': 1,
                   'raw': base64.b64encode(raw).decode(), 'sha256': oracle.sha(raw)},
                  {'schema': 1, 'sequence': 2, 'monotonic_ns': 12, 'event': 'node_stopped', 'node': 1, 'ledger_sha256': oracle.sha(raw)}]
        (self.directory / 'events.jsonl').write_bytes(b''.join(controls.encoded(item) for item in events))
        controls.outcome(self.directory, 'claim_lost', lambda value: value['error'].update(outcome='not_sent'))
        changed = (self.directory / 'node-1.jsonl').read_bytes(); events = oracle.rows(self.directory, 'events.jsonl')
        self.assertEqual(oracle.b64(events[0]['raw']), changed)
        self.assertEqual(events[0]['sha256'], oracle.sha(changed))
        self.assertEqual(events[1]['ledger_sha256'], oracle.sha(changed))
        self.assertEqual(oracle.parse(changed)['error']['outcome'], 'not_sent')

    def test_mutation_suite_has_exact_named_semantic_rejection_boundaries(self):
        cases = controls.cases()
        self.assertEqual(len(cases), 25)
        self.assertTrue(all(callable(change) and isinstance(reason, str) and reason for change, reason in cases.values()))
        self.assertEqual(len(set(cases)), len(cases))

    def test_retry_control_selects_execute_when_status_uses_same_worker(self):
        values = [{'event': 'http_request', 'command': 'cold_write', 'worker': 'a', 'http_serial': index,
                   'request_body': base64.b64encode(encoded({'operation': operation})).decode()}
                  for index, operation in enumerate(('status', 'execute'), 1)]
        self.assertIs(controls.actual_request(values, 'cold_write', 'execute', 'a'), values[1])
        with self.assertRaises(ValueError): controls.actual_request(values + [copy.deepcopy(values[1])], 'cold_write', 'execute', 'a')


if __name__ == '__main__':
    unittest.main()
