"""Observer boundaries only; these tests do not certify a product output pool."""
import hashlib
import importlib.util
import json
from copy import deepcopy
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


io = load('scap_output_test_io', 'io.py')
oracle = load('scap_output_test_oracle', 'oracle.py')
controls = load('scap_output_test_controls', 'controls.py')


def startup_fixture():
    binary = {'path': '/frozen/scapd', 'sha256': 'a' * 64}
    child = {'pid': 101, 'pid_source': 'owned_Popen_child', 'spawn_monotonic_ns': 50}
    events = [
        {'event': 'service_started', 'monotonic_ns': 60, 'spawn_requested_ns': 10,
         'identity': child, 'binary': binary, 'configuration_sha256': 'b' * 64, 'worker_instance': '5001'},
        {'event': 'service_ready', 'monotonic_ns': 80, 'identity': child, 'worker_instance': '5001'},
        {'event': 'service_stop_requested', 'monotonic_ns': 110, 'identity': child},
        {'event': 'service_stopped', 'monotonic_ns': 120, 'identity': child},
    ]
    value = b'SCAP-WORKER-INSTANCE-v1\0' + (5001).to_bytes(8, 'big')
    history = []
    for serial, method, path, when, payload, received, status in (
        (1, 'PUT', '/scap-test/scap-worker/v1/instances/5001', 20, value, b'', 200),
        (2, 'GET', '/scap-test/scap-worker/v1/instances/5001', 30, b'', value, 200),
        (3, 'GET', '/scap-test/scap-object/v1/1/7/101/inc/1/gen/1/head', 100, b'', b'', 404),
    ):
        common = {'request_serial': serial, 'phase': 'setup', 'method': method, 'path': path,
                  'request_bytes': len(payload), 'request_sha256': oracle.digest(payload),
                  'if_match': None, 'if_none_match': '*' if method == 'PUT' else None}
        response = {'status': status, 'response_bytes': len(received), 'response_sha256': oracle.digest(received),
                    'etag': '"original-claim"' if status == 200 else None}
        if path.endswith('/head'):
            common['head_request_bytes'] = list(payload)
            response['head_response_bytes'] = list(received)
        for offset, event in enumerate(('object_request', 'object_forwarded', 'object_response', 'object_response_delivered')):
            row = {**deepcopy(common), 'event': event, 'monotonic_ns': when + offset}
            if offset >= 2:
                row.update(response)
            if event == 'object_response':
                row.update(response_origin='backend', suppressed=False)
            history.append(row)
    return {'worker_instance': '5001'}, events, history, binary


class StartupOracleTests(unittest.TestCase):
    def check(self, data):
        config, events, history, binary = data
        return oracle.startup_objects(config, events, history, phases=('setup',), binary=binary,
                                      configuration_sha256='b' * 64)

    def test_accepts_exact_claim_before_post_popen_observation(self):
        self.assertEqual(self.check(startup_fixture()), {'instances': ['5001'], 'requests': 2,
            'business_requests': 1, 'physical_requests': 3})

    def test_delivery_callback_may_follow_readiness(self):
        data = startup_fixture()
        next(row for row in data[2] if row['request_serial'] == 2 and row['event'] == 'object_response_delivered')['monotonic_ns'] = 90
        self.check(data)

    def test_six_full_exchange_controls_hit_the_exact_startup_rules(self):
        for case, rule in controls.STARTUP_CASES.items():
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                config, events, history, binary = startup_fixture()
                root = Path(directory)
                for name, values in (('events.jsonl', events), ('history.jsonl', history)):
                    (root / name).write_text(''.join(json.dumps(row) + '\n' for row in values))
                controls.startup_mutation(root, case)
                with self.assertRaisesRegex(oracle.Rejected, '^' + rule + '$'):
                    self.check((config, oracle.rows(root / 'events.jsonl'), oracle.rows(root / 'history.jsonl'), binary))

    def test_claim_requires_full_delivery(self):
        data = startup_fixture()
        data[2][:] = [row for row in data[2] if not (row['request_serial'] == 2 and row['event'] == 'object_response_delivered')]
        with self.assertRaisesRegex(oracle.Rejected, 'missing/early original response delivery'):
            self.check(data)

    def test_unknown_role_and_prefix_cannot_be_filtered(self):
        for field, value, rule in (('worker', 'other', 'worker-identity-exact-key'),
                                   ('path', '/scap-test/unplanned/5001', 'object path escaped exact authority')):
            data = startup_fixture()
            for row in data[2]:
                if row['request_serial'] <= 2:
                    row[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(oracle.Rejected, rule):
                self.check(data)

    def test_duplicate_start_and_mismatched_process_are_not_readiness(self):
        data = startup_fixture()
        data[1].append(deepcopy(data[1][0]))
        with self.assertRaisesRegex(oracle.Rejected, 'worker-identity-lifecycle-denominator'):
            self.check(data)
        data = startup_fixture()
        data[1][1]['identity'] = {**data[1][1]['identity'], 'pid': 102}
        with self.assertRaisesRegex(oracle.Rejected, 'worker-identity-owned-ready'):
            self.check(data)

    def test_config_binary_and_spawn_are_original(self):
        for field, value, rule in (('configuration_sha256', 'c' * 64, 'worker-identity-source-binding'),
                                  ('binary', {}, 'worker-identity-source-binding'),
                                  ('worker_instance', '5002', 'worker-identity-config'),
                                  ('spawn_requested_ns', 51, 'worker-identity-startup-interval')):
            data = startup_fixture()
            data[1][0][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(oracle.Rejected, rule):
                self.check(data)

    def test_database_io_must_follow_the_proven_ready(self):
        data = startup_fixture()
        for row in data[2]:
            if row['request_serial'] == 3:
                row['monotonic_ns'] -= 30
        with self.assertRaisesRegex(oracle.Rejected, 'worker-identity-business-lifetime'):
            self.check(data)


class ObserverTests(unittest.TestCase):
    def peer(self, raw):
        server = socket.socket()
        server.bind(('127.0.0.1', 0))
        server.listen()
        self.addCleanup(server.close)
        def serve():
            connection, _ = server.accept()
            with connection:
                data = b''
                while not data.endswith(b'\r\n\r\n'):
                    data += connection.recv(1)
                connection.sendall(raw)
        thread = threading.Thread(target=serve)
        thread.start()
        self.addCleanup(thread.join, 3)
        return 'http://127.0.0.1:' + str(server.getsockname()[1])

    def test_headers_do_not_consume_body_and_peer_eof_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            rows = []
            endpoint = self.peer(b'HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nabc')
            response = io.SlowResponse(endpoint, 'test', b'', Path(directory), 'x',
                                       lambda event, **fields: rows.append({'event': event, **fields}))
            self.assertEqual(response.body_prefix, b'')
            self.assertEqual(rows[-1]['body_bytes_read'], 0)
            response.drain(allow_truncated=True)
            self.assertEqual((Path(directory) / 'x.response.json').read_bytes(), b'abc')
            self.assertTrue(rows[-1]['peer_eof'])
            self.assertFalse(rows[-1]['complete'])
            self.assertNotIn('slow_disconnected', [r['event'] for r in rows])

    def test_duplicate_length_is_rejected_before_body(self):
        with tempfile.TemporaryDirectory() as directory:
            endpoint = self.peer(b'HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nxx')
            with self.assertRaisesRegex(ValueError, 'duplicate response header'):
                io.SlowResponse(endpoint, 'test', b'', Path(directory), 'x', lambda *a, **kw: None)

    def test_remaining_uses_original_deadline(self):
        with patch.object(io.time, 'monotonic', side_effect=[10.2, 10.7, 11.0]):
            self.assertAlmostEqual(io.remaining(11), .8)
            self.assertAlmostEqual(io.remaining(11), .3)
            with self.assertRaisesRegex(TimeoutError, 'original slow-response deadline'):
                io.remaining(11)

    def test_raw_rejects_tampering_and_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            description = io.save(root / 'raw', b'abc')
            self.assertEqual(oracle.raw(root, description), b'abc')
            (root / 'raw').write_bytes(b'abd')
            with self.assertRaisesRegex(oracle.Rejected, 'raw-integrity'):
                oracle.raw(root, description)
            with self.assertRaisesRegex(oracle.Rejected, 'raw-path'):
                oracle.raw(root, dict(description, file='../raw'))

    def test_line_cap_is_applied_before_unbounded_read(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'oversize'
            path.write_bytes(b'x' * (1024 * 1024 + 1))
            with self.assertRaisesRegex(oracle.Rejected, 'ledger-framing'):
                oracle.rows(path)


if __name__ == '__main__':
    unittest.main()
