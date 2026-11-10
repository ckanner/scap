"""Raw-ledger omissions, independent format rules and concurrent real SDK I/O.

Loopback replies below are explicit fixture units, never product acceptance.
The formal runner always uses the separately built scapd and native worker.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
import http.server
import json
import os
from pathlib import Path
import queue
import shutil
import subprocess
import tempfile
import threading
from types import SimpleNamespace
import unittest

import audit_evidence as e
import audit_model as m
import controls
import oracle
import spec
import support
from test_oracle import base_head, marked_head, original_descriptor, KNOWN, ROOT, HERE


class EvidenceBoundary(unittest.TestCase):
    def rejected(self, rule, function, *args):
        with self.assertRaises(m.Rejected) as caught:
            function(*args)
        self.assertEqual(caught.exception.rule, rule)

    def test_all_faults_independently_bound(self):
        self.assertEqual(tuple(row[:4] for row in oracle.FAULT_BINDINGS), spec.FAULTS)
        self.assertEqual(len(oracle.UNKNOWN_CALLS), 12)
        self.assertEqual(len(controls.cases()), 40)
        self.assertEqual(len({row[0] for row in controls.cases()}), 40)

    def test_numeric_hash_is_not_converted_to_u64(self):
        self.assertEqual(e.native({'hash': '1' * 64, 'revision': '23'}), {'hash': '1' * 64, 'revision': 23})

    def test_missing_whole_s3_exchange_rejected_by_closed_count(self):
        self.rejected('s3-closed-denominator', e.s3_exchanges, Path('/unused'),
                      [{'event': 's3_proxy_stopped', 'role': 'seed', 'request_count': 1}], {})

    def test_original_unknown_set_cannot_lose_one_call(self):
        values = {name: {'result': {'ok': False, 'error': {'code': code}},
                         'product_body': {'ok': False, 'error': {'code': code}}}
                  for name, code in oracle.ERROR_CALLS.items()}
        self.assertEqual(oracle.original_errors(values), Counter(oracle.ERROR_CALLS.values()))
        values.pop('bulk-p1-prepare')
        self.rejected('all-original-error-and-unknown-results', oracle.original_errors, values)

    def test_backend_error_must_match_original_client_error(self):
        values = {name: {'result': {'ok': False, 'error': {'code': code}},
                         'product_body': {'ok': False, 'error': {'code': code}}}
                  for name, code in oracle.ERROR_CALLS.items()}
        values['budget_gets-limited-resume']['product_body']['error']['code'] = 'CORRUPT'
        self.rejected('actual-product-error-not-runner-label', oracle.original_errors, values)

    def test_cancelling_cannot_take_over_tuple(self):
        value = marked_head('cancelling')
        value['owner_instance'] = value['owner_plan']['phase']['owner_instance'] = 9999
        m.head(m.encoded(value), KNOWN)
        self.rejected('owner-cancelling-keeps-original-tuple', m.advance, base_head(), value)

    def test_named_provisioning_requires_own_origin(self):
        value = base_head()
        value['lifecycle'] = 'provisioning'
        self.rejected('named-provisioning-has-no-business', m.head, m.encoded(value), KNOWN)

    def test_named_deleted_requires_original_barrier(self):
        value = base_head()
        value.update(lifecycle='deleted', creation={'creator': 11, 'operation': 7601,
                    'name_hash': '1' * 64, 'descriptor_hash': '2' * 64})
        self.rejected('named-deletion-current-authority', m.head, m.encoded(value), KNOWN)

    def test_proof_must_precede_admission_not_latest_head(self):
        original = original_descriptor()
        proof = {'version': 1, 'scope': original['scope'], 'marker': marked_head('active')['owner_plan']}
        current = marked_head('active')
        current['revision'] = current['head_serial'] = 20
        current['owner_plan']['reference'] = {'creator': 12, 'operation': 800102, 'descriptor_hash': 'f' * 64}
        current['owner_plan']['admission']['revision'] = current['owner_plan']['admission']['head_serial'] = 3
        self.rejected('owner-proof-before-current-admission', m.proof_before, proof, original, current)

    def test_raw_reference_size_and_digest_both_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'raw').mkdir()
            ref = controls.put_raw(root, b'original')
            self.assertEqual(e.raw(root, ref), b'original')
            ref['bytes'] += 1
            self.rejected('raw-integrity', e.raw, root, ref)

    def test_trace_watch_requires_exact_existing_observer_event(self):
        with tempfile.TemporaryDirectory() as directory:
            trace = support.Trace(Path(directory))
            observed = trace.watch('http_proxy_forward_finished', role='G-9105', operation='query')
            trace.emit('http_proxy_forward_finished', role='G-9105', operation='owner_resume')
            self.assertFalse(observed.is_set())
            row = trace.emit('http_proxy_forward_finished', role='G-9105', operation='query')
            self.assertTrue(observed.is_set())
            self.assertEqual(e.rows(Path(directory) / 'events.jsonl')[-1], row)
            self.assertEqual(trace.watches, [])

    def test_hash_fault_changes_only_reference_and_is_repeatable(self):
        head = marked_head('active')
        reference = head['owner_plan']['reference']
        gate = support.Gate('hash', 'GET', '/head', 'replace_body', 'after_response', uses=2,
            mutation={'kind': 'same_id_hash', 'creator': reference['creator'], 'operation': reference['operation'],
                      'descriptor_hash': 'f' * 64})
        original = m.encoded(head)
        first = support.Proxy.mutate(gate, original)
        self.assertEqual(first, support.Proxy.mutate(gate, original))
        expected = deepcopy(head)
        expected['owner_plan']['reference']['descriptor_hash'] = 'f' * 64
        self.assertEqual(m.wire.parse(first), expected)
        self.assertEqual(m.wire.parse(original), head)

    def test_proof_delivery_fault_preserves_identity_and_nonce(self):
        proof = {'version': 1, 'scope': base_head()['scope'], 'marker': marked_head('active')['owner_plan']}
        gate = support.Gate('proof', 'GET', '/proof', 'replace_body', 'after_response',
                            mutation={'kind': 'proof_at_admission', 'revision': 9, 'head_serial': 9})
        value = m.wire.parse(support.Proxy.mutate(gate, m.encoded(proof)))
        expected = deepcopy(proof)
        expected['marker']['phase'].update(revision=9, head_serial=9)
        self.assertEqual(value, expected)

    def test_hardlink_control_never_changes_original(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original, changed = root / 'original', root / 'changed'
            original.write_bytes(b'actual-original\n')
            os.link(original, changed)
            controls.replace(changed, b'explicit-counterfactual\n')
            self.assertEqual(original.read_bytes(), b'actual-original\n')
            self.assertEqual(changed.read_bytes(), b'explicit-counterfactual\n')
            self.assertNotEqual(original.stat().st_ino, changed.stat().st_ino)

    def test_control_mirrors_request_hash_and_exact_get_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'raw').mkdir()
            before = m.encoded(original_descriptor())
            old = controls.put_raw(root, before)
            rows = [
                {'event': 's3_request', 'role': 'C', 'serial': 1, 'method': 'PUT', 'request': old,
                 'headers': {'content-length': str(len(before)), 'x-amz-content-sha256': old['sha256']}, 'monotonic_ns': 1},
                {'event': 's3_backend_response', 'role': 'C', 'serial': 2, 'method': 'GET', 'response': old,
                 'headers': {'content-length': str(len(before))}, 'monotonic_ns': 2}]
            controls.save_rows(root / 'events.jsonl', rows)
            after = m.encoded({'unit': 'changed'})
            controls.replace_blob(root, old, after)
            first, second = e.rows(root / 'events.jsonl')
            self.assertEqual(first['request'], second['response'])
            self.assertEqual(first['headers']['x-amz-content-sha256'], m.sha(after))
            self.assertEqual(first['headers']['content-length'], str(len(after)))
            self.assertEqual(e.raw(root, second['response']), after)
            self.assertEqual(e.raw(root, old), before)

    def test_premature_effect_control_keeps_owned_exit_and_request(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rows = [
                {'event': 'fault_arrived', 'id': 'late-descriptor-put', 'role': 'A', 'serial': 3, 'monotonic_ns': 10},
                {'event': 'child_stop_requested', 'id': 'service-A-1', 'monotonic_ns': 1000},
                {'event': 'child_stopped', 'id': 'service-A-1', 'monotonic_ns': 2000},
                {'event': 'fault_release_requested', 'id': 'late-descriptor-put', 'role': 'A', 'monotonic_ns': 3000},
                {'event': 'fault_forward_resumed', 'id': 'late-descriptor-put', 'role': 'A', 'serial': 3, 'monotonic_ns': 4000},
                {'event': 's3_forward_started', 'role': 'A', 'serial': 3, 'monotonic_ns': 5000},
                {'event': 's3_backend_response', 'role': 'A', 'serial': 3, 'monotonic_ns': 6000},
                {'event': 's3_handler_finished', 'role': 'A', 'serial': 3, 'monotonic_ns': 7000}]
            controls.save_rows(root / 'events.jsonl', rows)
            controls.premature_effect(root, 'late-descriptor-put', 'service-A-1')
            altered = e.rows(root / 'events.jsonl')
            self.assertEqual(len(altered), len(rows))
            self.assertEqual(e.moment(e.one(altered, 'child_stopped', id='service-A-1')), 2000)
            self.assertLess(e.moment(e.one(altered, 's3_backend_response')), 2000)
            self.assertLess(1000, e.moment(e.one(altered, 's3_forward_started')))


class SignedS3Observer(unittest.TestCase):
    def test_two_head_mutations_and_one_missing_have_closed_real_loopback_ledgers(self):
        original, received, failures = m.encoded(marked_head('active')), [], []
        access, secret = 'owner-unit-access', 'owner-unit-secret'

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def log_message(self, *_args):
                pass

            def do_GET(self):
                try:
                    received.append(self.path)
                    assert support.signing.verify_signature('GET', self.path, dict(self.headers.items()), b'', access, secret)
                    self.send_response(200)
                    self.send_header('Content-Length', str(len(original)))
                    self.send_header('ETag', '"original-unit-etag"')
                    self.send_header('Connection', 'close')
                    self.end_headers()
                    self.wfile.write(original)
                except BaseException as error:
                    failures.append(repr(error))

        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        server.daemon_threads = False
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        proxy = None
        try:
            with tempfile.TemporaryDirectory(prefix='scap-owner-signed-unit-') as directory:
                root = Path(directory)
                trace = support.Trace(root)
                proxy = support.Proxy(SimpleNamespace(port=server.server_port), 'B', trace, {access: secret})
                endpoint = SimpleNamespace(port=proxy.server.server_port, access=access, secret=secret)
                path = '/scap-test/scap-object/v1/1/7/7201/head'
                reference = marked_head('active')['owner_plan']['reference']
                gate = proxy.arm('same-id-different-hash', 'GET', path, 'replace_body', stage='after_response', uses=2,
                    mutation={'kind': 'same_id_hash', 'creator': reference['creator'], 'operation': reference['operation'],
                              'descriptor_hash': 'f' * 64})
                for _ in range(2):
                    response = support.signing.signed_request(endpoint, 'GET', path)
                    body = support.signing.body_value(response['body'])
                    self.assertEqual(response['status'], 200)
                    self.assertEqual(m.wire.parse(body)['owner_plan']['reference']['descriptor_hash'], 'f' * 64)
                self.assertTrue(gate.finished.wait(5))
                self.assertEqual(gate.used, 2)
                missing = '/scap-test/scap-object/v1/1/7/7201/inc/1/gen/1/owner/v1/descriptor/11/800101'
                proxy.arm('current-descriptor-missing', 'GET', missing, 'no_such_key')
                response = support.signing.signed_request(endpoint, 'GET', missing)
                self.assertEqual(response['status'], 404)
                self.assertIn(b'NoSuchKey', support.signing.body_value(response['body']))
                proxy.close()
                proxy = None
                self.assertEqual(received, [path, path])
                self.assertFalse(failures)
                values = e.s3_exchanges(root, e.rows(root / 'events.jsonl'),
                    {'normal_access_sha256': m.sha(access.encode()), 'gc_access_sha256': m.sha(b'unused-gc')})
                self.assertEqual(len(values), 3)
                self.assertTrue(all(value['delivery_complete'] for value in values))
                self.assertEqual(values[0]['bytes'], original)
                self.assertEqual(values[0]['delivery_bytes'], values[1]['delivery_bytes'])
                self.assertIsNone(values[2]['backend'])
        finally:
            if proxy is not None:
                proxy.close()
            server.shutdown()
            server.server_close()
            thread.join(5)


class ConcurrentPublicSDK(unittest.TestCase):
    def test_two_resume_and_abort_keep_each_original_fetch_context(self):
        # The driver runs the real public SDK against an explicit local fixture
        # HTTP server. No native database or product process is started here.
        requests, release, failures = [], threading.Event(), []
        original = original_descriptor()
        saved = {'scope': oracle.public(original['scope']), 'input': oracle.public(original['input']),
                 'reference': oracle.public(m.reference(original))}
        active = marked_head('active')
        observation = {'state': 'active', 'status': oracle.projection(active), 'prepared': saved,
                       'accepted': oracle.public(active['owner_plan'])}

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def log_message(self, *_args):
                pass

            def do_POST(self):
                try:
                    body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                    requests.append(body)
                    operation = body['operation']
                    if operation == 'owner_prepare':
                        value = {'state': 'prepared', 'prepared': saved}
                    else:
                        if operation == 'owner_abort':
                            release.set()
                        else:
                            assert operation == 'owner_resume' and release.wait(5)
                        value = observation
                    payload = m.encoded({'ok': True, 'value': value})
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Content-Length', str(len(payload)))
                    self.send_header('Connection', 'close')
                    self.end_headers()
                    self.wfile.write(payload)
                except BaseException as error:
                    failures.append(repr(error))

        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        server.daemon_threads = False
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        child, reader = None, None
        try:
            with tempfile.TemporaryDirectory(prefix='scap-owner-sdk-loopback-') as directory:
                root = Path(directory)
                (root / 'raw').mkdir()
                endpoint = f'http://127.0.0.1:{server.server_port}'
                config = {'source_root': str(ROOT), 'endpoint': endpoint, 'scopes': {'bulk': spec.SCOPES['bulk']},
                    'tokens': {'11': 'a' * 64}, 'timeouts': {'sdk_ms': 5000, 'recovery_ms': 5000},
                    'workerEndpoints': {'9102': endpoint}, 'routes': [{'workerInstance': '9102', 'endpoint': endpoint + '/v1'}]}
                path = root / 'configuration.json'
                path.write_text(json.dumps(config))
                child = subprocess.Popen([shutil.which('node') or 'node', str(HERE / 'client.mjs'), str(path), str(root), 'loopback'],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                output = queue.Queue()

                def read():
                    for line in child.stdout:
                        output.put(json.loads(line))

                reader = threading.Thread(target=read)
                reader.start()
                self.assertEqual(output.get(timeout=5), {'ready': True})

                def send(name, operation, **fields):
                    child.stdin.write(json.dumps({'id': name, 'operation': operation, 'scope_name': 'bulk',
                                                  'intent': 'original', **fields}) + '\n')
                    child.stdin.flush()

                send('save', 'owner_save', input=saved['input'])
                self.assertTrue(output.get(timeout=5)['ok'])
                send('prepare', 'owner_prepare')
                self.assertTrue(output.get(timeout=5)['ok'])
                send('first-resume', 'owner_resume')
                send('second-resume', 'owner_resume')
                send('abort-observation', 'owner_abort')
                answers = [output.get(timeout=5) for _ in range(3)]
                self.assertEqual({row['id'] for row in answers}, {'first-resume', 'second-resume', 'abort-observation'})
                self.assertTrue(all(row['ok'] and row['value'] == observation for row in answers), answers)
                child.stdin.close()
                self.assertEqual(child.wait(timeout=5), 0, child.stderr.read())
                reader.join(5)
                self.assertFalse(reader.is_alive())
                ledger = e.rows(root / 'sdk-loopback.jsonl')
                for name in ('prepare', 'first-resume', 'second-resume', 'abort-observation'):
                    request = e.one(ledger, 'http_request', command=name)
                    response = e.one(ledger, 'http_response', command=name)
                    ending = e.one(ledger, 'command_finished', command=name)
                    self.assertEqual(ending['attempts'], 1)
                    self.assertEqual(request['ordinal'], 1)
                    self.assertLess(e.moment(request), e.moment(response))
                self.assertEqual(Counter(row['operation'] for row in requests),
                                 {'owner_prepare': 1, 'owner_resume': 2, 'owner_abort': 1})
                self.assertFalse(failures)
        finally:
            release.set()
            if child is not None:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=5)
                for stream in (child.stdin, child.stdout, child.stderr):
                    if stream is not None and not stream.closed:
                        stream.close()
            if reader is not None:
                reader.join(5)
            server.shutdown()
            server.server_close()
            thread.join(5)


if __name__ == '__main__':
    unittest.main()
