"""Observer boundaries only; these tests do not certify a product output pool."""
import hashlib
import importlib.util
import json
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
