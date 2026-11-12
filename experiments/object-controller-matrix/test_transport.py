"""Loopback checks of the new transport faults, not a database-policy oracle."""
import concurrent.futures
import http.client
import http.server
import json
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.parse import urlparse

import support as io


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.evidence = Path(self.directory.name)
        self.trace = io.Trace(self.evidence)
        self.received = []
        received = self.received

        class Backend(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def log_message(self, *_args):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers['Content-Length']))
                received.append(body)
                self.send_response_only(200)
                self.send_header('Content-Length', str(len(body)))
                self.send_header('Connection', 'close')
                self.end_headers()
                self.wfile.write(body)

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Backend)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=False)
        self.thread.start()
        self.proxy = io.HTTPProxy('test', self.server.server_port, self.trace, {'12': 'test-token'})

    def tearDown(self):
        try:
            self.proxy.close()
            self.assertFalse(self.proxy.errors)
        finally:
            self.server.shutdown()
            self.server.server_close()
            self.thread.join(3)
            self.assertFalse(self.thread.is_alive())
            self.directory.cleanup()

    def post(self, operation, label):
        body = json.dumps({'operation': operation, 'label': label}).encode()
        connection = http.client.HTTPConnection('127.0.0.1', urlparse(self.proxy.endpoint).port, timeout=3)
        try:
            connection.request('POST', '/v1', body, {'Authorization': 'Bearer test-token',
                'Content-Type': 'application/json'})
            response = connection.getresponse()
            return response.status, response.read()
        except (OSError, http.client.HTTPException):
            return 'closed', None
        finally:
            connection.close()

    def events(self):
        return [json.loads(line) for line in (self.evidence / 'events.jsonl').read_text().splitlines()]

    def test_concurrent_pair_keeps_both_originals_and_loses_only_one_real_response(self):
        first, second = self.proxy.hold_pair('first', 'second', 'owner_prepare')
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            calls = [pool.submit(self.post, 'owner_prepare', label) for label in ('a', 'b')]
            self.assertTrue(first.arrived.wait(2))
            self.assertTrue(second.arrived.wait(2))
            self.assertEqual(self.received, [])
            self.proxy.release_lost(first)
            self.assertTrue(first.finished.wait(2))
            self.proxy.release(second)
            self.assertTrue(second.finished.wait(2))
            outcomes = [call.result(3) for call in calls]
        self.assertEqual(sorted(str(status) for status, _ in outcomes), ['200', 'closed'])
        self.assertEqual(len(self.received), 2)
        rows = self.events()
        responses = [row for row in rows if row['event'] == 'http_proxy_backend_response']
        self.assertEqual(len(responses), 2)
        self.assertEqual({(self.evidence / row['response']['file']).read_bytes() for row in responses},
                         set(self.received))
        losses = [row for row in rows if row['event'] == 'http_proxy_delivery_suppressed']
        self.assertEqual([(row['id'], row['stage']) for row in losses], [('first', 'after_response')])
        forwarded = [row for row in rows if row['event'] == 'http_proxy_forward_started']
        self.assertEqual(len(forwarded), 2)

    def test_one_status_cut_closes_socket_without_forwarding_or_fabricating_response(self):
        self.proxy.cut_status('single-status', 1)
        self.assertEqual(self.post('status', 'cut'), ('closed', None))
        status, body = self.post('status', 'healthy')
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {'operation': 'status', 'label': 'healthy'})
        self.assertEqual(len(self.received), 1)
        rows = self.events()
        requests = [row for row in rows if row['event'] == 'http_proxy_request']
        forwarded = [row for row in rows if row['event'] == 'http_proxy_forward_started']
        responses = [row for row in rows if row['event'] == 'http_proxy_backend_response']
        self.assertEqual(len(requests), 2)
        self.assertEqual([row['serial'] for row in forwarded], [requests[1]['serial']])
        self.assertEqual([row['serial'] for row in responses], [requests[1]['serial']])


if __name__ == '__main__':
    unittest.main()
