"""Real loopback tests of observation/ownership; no product or S3 runtime."""
from __future__ import annotations

import hashlib
import http.client
import http.server
import json
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import http_proxy as proxy_module
from http_proxy import HTTPProxy


TOKENS = {'11': 'fixture-owner-secret-one', '12': 'fixture-owner-secret-two'}


class Trace:
    def __init__(self, path):
        self.path, self.rows = Path(path), []
        self.condition = threading.Condition()
        (self.path / 'raw').mkdir()
        self.fail_event = None

    def raw(self, data):
        digest = hashlib.sha256(data).hexdigest()
        with self.condition:
            path = self.path / 'raw' / digest
            if path.exists():
                assert path.read_bytes() == data
            else:
                path.write_bytes(data)
        return {'file': 'raw/' + digest, 'bytes': len(data), 'sha256': digest}

    def emit(self, event, **fields):
        with self.condition:
            if event == self.fail_event:
                self.fail_event = None
                raise OSError('injected evidence failure')
            row = {'sequence': len(self.rows) + 1, 'monotonic_ns': time.monotonic_ns(),
                   'event': event, **fields}
            self.rows.append(row)
            with (self.path / 'events.jsonl').open('ab') as stream:
                stream.write(json.dumps(row, sort_keys=True).encode() + b'\n')
            self.condition.notify_all()
            return row

    def matching(self, name):
        with self.condition:
            return [row for row in self.rows if row['event'] == 'http_proxy_' + name]

    def wait(self, name, count=1, seconds=2):
        with self.condition:
            return self.condition.wait_for(lambda: len(self.matching(name)) >= count, seconds)

    def body(self, reference):
        data = (self.path / reference['file']).read_bytes()
        assert len(data) == reference['bytes'] and hashlib.sha256(data).hexdigest() == reference['sha256']
        return data


class Backend:
    def __init__(self):
        self.requests, self.sockets = [], set()
        self.lock = threading.Lock()
        self.arrived, self.release = threading.Event(), threading.Event()
        self.respond = self.normal
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def log_message(self, *_args):
                pass

            def do_POST(self):
                self.close_connection = True
                self.connection.settimeout(2)
                with owner.lock:
                    owner.sockets.add(self.connection)
                try:
                    body = self.rfile.read(int(self.headers['Content-Length']))
                    request = {'path': self.path, 'body': body, 'headers': dict(self.headers)}
                    with owner.lock:
                        owner.requests.append(request)
                    owner.arrived.set()
                    owner.respond(self, request)
                except OSError:
                    pass
                finally:
                    with owner.lock:
                        owner.sockets.remove(self.connection)

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.daemon_threads = False
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever,
            kwargs={'poll_interval': 0.01}, daemon=False)
        self.thread.start()

    @staticmethod
    def normal(handler, request):
        body = b'{"actual":' + request['body'] + b'}'
        handler.send_response_only(200)
        handler.send_header('Content-Length', str(len(body)))
        handler.send_header('Content-Type', 'application/json')
        handler.send_header('Connection', 'close')
        handler.end_headers()
        handler.wfile.write(body)

    def close(self):
        self.release.set()
        with self.lock:
            for sock in self.sockets:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)
        assert not self.thread.is_alive()


class Call:
    def __init__(self, function):
        self.value = self.error = None
        self.done = threading.Event()

        def run():
            try:
                self.value = function()
            except BaseException as error:
                self.error = error
            finally:
                self.done.set()

        self.thread = threading.Thread(target=run, daemon=False)
        self.thread.start()

    def join(self, seconds=2):
        assert self.done.wait(seconds), 'owned client did not finish'
        self.thread.join(seconds)
        assert not self.thread.is_alive()
        return self


class HTTPProxyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.trace = Trace(self.directory.name)
        self.backend = Backend()
        self.proxies = []

    def tearDown(self):
        try:
            for value in self.proxies:
                value.close()
        finally:
            self.backend.close()
            self.directory.cleanup()

    def make(self, port=None, role=None):
        value = HTTPProxy(role or 'B-9102', port or self.backend.port, self.trace, TOKENS)
        self.proxies.append(value)
        return value

    @staticmethod
    def body(operation='owner_prepare'):
        return json.dumps({'version': 1, 'operation': operation}, separators=(',', ':')).encode()

    def request(self, proxy, operation='owner_prepare', path='/v1', principal='11', timeout=2):
        connection = http.client.HTTPConnection('127.0.0.1', int(proxy.endpoint.rsplit(':', 1)[1]), timeout=timeout)
        try:
            connection.request('POST', path, body=self.body(operation), headers={
                'Authorization': 'Bearer ' + TOKENS[principal], 'Content-Type': 'application/json'})
            response = connection.getresponse()
            return response.status, response.read(), dict(response.getheaders())
        finally:
            connection.close()

    def socket(self, proxy):
        sock = socket.create_connection(('127.0.0.1', int(proxy.endpoint.rsplit(':', 1)[1])), timeout=2)
        self.addCleanup(sock.close)
        return sock

    def raw_request(self, proxy, request):
        sock = self.socket(proxy)
        sock.sendall(request)
        try:
            return sock.recv(4096)
        except ConnectionResetError:
            return b''

    def wire(self, operation='owner_prepare'):
        body = self.body(operation)
        return (b'POST /v1 HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer '
                + TOKENS['11'].encode() + b'\r\nContent-Length: ' + str(len(body)).encode()
                + b'\r\n\r\n' + body)

    def test_full_request_response_and_independent_closed_denominator(self):
        proxy = self.make()
        proxy.phase_to('direct')
        first = self.request(proxy)
        proxy.phase_to('catalogue')
        second = self.request(proxy, 'status', '/v1/catalogue', '12')
        proxy.close()
        self.assertEqual((first[0], second[0]), (200, 200))
        self.assertEqual(first[1], b'{"actual":' + self.body() + b'}')
        self.assertEqual([r['path'] for r in self.backend.requests], ['/v1', '/v1/catalogue'])
        requests = self.trace.matching('request')
        self.assertEqual([r['serial'] for r in requests], [1, 2])
        self.assertEqual([r['principal'] for r in requests], ['11', '12'])
        self.assertEqual([r['phase'] for r in requests], ['direct', 'catalogue'])
        self.assertEqual(self.trace.body(requests[0]['request']), self.body())
        self.assertEqual(requests[0]['token_sha256'], hashlib.sha256(TOKENS['11'].encode()).hexdigest())
        for serial in (1, 2):
            names = [r['event'].removeprefix('http_proxy_') for r in self.trace.rows if r.get('serial') == serial]
            expected = ['handler_started', 'request', 'forward_started', 'forward_finished',
                        'backend_response', 'delivery_started', 'delivery_finished',
                        'handler_finished', 'connection_finished']
            self.assertEqual(names, expected)
        closed = self.trace.matching('closed')
        self.assertEqual(len(closed), 1)
        self.assertEqual((closed[0]['request_count'], closed[0]['connection_count']), (2, 2))
        self.assertTrue(closed[0]['joined'])
        self.assertEqual(closed[0]['errors'], [])
        public = (self.trace.path / 'events.jsonl').read_text()
        self.assertTrue(all(token not in public for token in TOKENS.values()))
        self.assertNotIn('authorization', public.lower())
        self.assertFalse(proxy.thread.is_alive())
        self.assertEqual(proxy.connections, {})

    def test_drop_records_complete_actual_response_but_no_delivery(self):
        proxy = self.make()
        gate = proxy.arm('prepare-ack', 'owner_prepare')
        call = Call(lambda: self.request(proxy)).join()
        self.assertIsInstance(call.error, (http.client.RemoteDisconnected, ConnectionResetError))
        self.assertTrue(gate.arrived.wait(1) and gate.finished.wait(1))
        self.assertEqual((gate.seen, gate.used), (1, 1))
        self.assertEqual({k: gate.observed[k] for k in ('role', 'serial', 'operation', 'method', 'path')},
            {'role': 'B-9102', 'serial': 1, 'operation': 'owner_prepare', 'method': 'POST', 'path': '/v1'})
        self.assertEqual(len(self.backend.requests), 1)
        response = self.trace.matching('backend_response')[0]
        self.assertEqual(self.trace.body(response['response']), b'{"actual":' + self.body() + b'}')
        self.assertEqual(self.trace.matching('delivery_started'), [])
        self.assertFalse(self.trace.matching('delivery_suppressed')[0]['aborted'])
        self.assertEqual(proxy.errors, [])

    def test_hold_after_response_does_not_prevent_backend_effect(self):
        proxy = self.make()
        gate = proxy.arm('resume-ack', 'owner_resume', 'hold')
        call = Call(lambda: self.request(proxy, 'owner_resume'))
        self.assertTrue(gate.arrived.wait(1))
        self.assertFalse(call.done.is_set())
        self.assertEqual(len(self.trace.matching('backend_response')), 1)
        self.assertEqual(self.trace.matching('delivery_started'), [])
        proxy.release(gate)
        self.assertIsNone(call.join().error)
        self.assertTrue(gate.finished.wait(1))
        self.assertTrue(self.trace.matching('delivery_finished')[0]['complete'])
        with self.assertRaises(ValueError):
            proxy.release(gate)

    def test_caller_timeout_before_forward_does_not_cancel_original(self):
        proxy = self.make()
        gate = proxy.arm('late', 'activate', 'hold', 'before_forward')
        call = Call(lambda: self.request(proxy, 'activate', timeout=0.08))
        self.assertTrue(gate.arrived.wait(1))
        self.assertIsInstance(call.join().error, TimeoutError)
        self.assertEqual(self.backend.requests, [])
        self.assertEqual(self.trace.matching('forward_started'), [])
        proxy.release(gate)
        self.assertTrue(gate.finished.wait(2))
        self.assertEqual(len(self.backend.requests), 1)
        self.assertEqual(len(self.trace.matching('request')), 1)
        self.assertEqual(len(self.trace.matching('backend_response')), 1)
        self.assertEqual(len(self.trace.matching('delivery_finished')), 1)
        self.assertIsInstance(call.error, TimeoutError)
        self.assertEqual(proxy.errors, [])

    def test_occurrence_counts_only_matching_operation_and_is_one_shot(self):
        proxy = self.make()
        gate = proxy.arm('second', 'owner_claim', occurrence=2)
        self.assertEqual(self.request(proxy, 'query')[0], 200)
        self.assertEqual(gate.seen, 0)
        self.assertEqual(self.request(proxy, 'owner_claim')[0], 200)
        self.assertEqual(gate.seen, 1)
        self.assertIsNotNone(Call(lambda: self.request(proxy, 'owner_claim')).join().error)
        self.assertEqual(self.request(proxy, 'owner_claim')[0], 200)
        proxy.close()
        self.assertEqual((gate.seen, gate.used, gate.observed['serial']), (2, 1, 3))
        self.assertEqual(self.trace.matching('closed')[0]['request_count'], 4)
        self.assertEqual(len(self.backend.requests), 4)

    def test_close_aborts_before_forward_hold_without_synthetic_response(self):
        proxy = self.make()
        gate = proxy.arm('shutdown', 'owner_abort', 'hold', 'before_forward')
        call = Call(lambda: self.request(proxy, 'owner_abort'))
        self.assertTrue(gate.arrived.wait(1))
        started = time.monotonic()
        proxy.close()
        self.assertLess(time.monotonic() - started, 2)
        self.assertIsNotNone(call.join().error)
        self.assertTrue(gate.aborted and gate.finished.is_set())
        self.assertEqual(self.backend.requests, [])
        self.assertEqual(proxy.errors, [])
        proxy.close()
        self.assertEqual(len(self.trace.matching('closed')), 1)

    def test_close_aborts_after_response_hold_and_preserves_actual_response(self):
        proxy = self.make()
        gate = proxy.arm('shutdown-after', 'owner_resume', 'hold')
        call = Call(lambda: self.request(proxy, 'owner_resume'))
        self.assertTrue(gate.arrived.wait(1))
        proxy.close()
        self.assertIsNotNone(call.join().error)
        self.assertTrue(gate.aborted and gate.finished.is_set())
        self.assertEqual(len(self.trace.matching('backend_response')), 1)
        self.assertEqual(self.trace.matching('delivery_started'), [])
        self.assertTrue(self.trace.matching('delivery_suppressed')[0]['aborted'])

    def test_close_unused_gate_and_partial_header_connection(self):
        proxy = self.make()
        gate = proxy.arm('unused', 'owner_claim')
        sock = self.socket(proxy)
        sock.sendall(b'POST /v1 HTTP/1.1\r\n')
        self.assertTrue(self.trace.wait('connection_started'))
        proxy.close()
        self.assertTrue(gate.aborted and gate.finished.is_set())
        self.assertFalse(gate.arrived.is_set())
        self.assertTrue(self.trace.matching('closed')[0]['joined'])
        self.assertEqual(proxy.errors, [])

    def test_unreleased_gate_expires_without_forwarding(self):
        with patch.object(proxy_module, 'HOLD_SECONDS', 0.08):
            proxy = self.make()
            gate = proxy.arm('expired', 'owner_claim', 'hold', 'before_forward')
            call = Call(lambda: self.request(proxy, 'owner_claim'))
            self.assertTrue(gate.arrived.wait(1))
            self.assertIsNotNone(call.join().error)
            self.assertTrue(gate.finished.wait(1))
            proxy.close()
        self.assertTrue(gate.aborted)
        self.assertEqual(self.backend.requests, [])
        self.assertIn('gate_deadline', [row['code'] for row in proxy.errors])

    def test_backend_connection_failure_is_observed_without_retry(self):
        reserved = socket.socket()
        self.addCleanup(reserved.close)
        reserved.bind(('127.0.0.1', 0))
        proxy = self.make(port=reserved.getsockname()[1])
        call = Call(lambda: self.request(proxy)).join()
        self.assertIsNotNone(call.error)
        self.assertEqual(len(self.trace.matching('forward_started')), 1)
        self.assertEqual(len(self.trace.matching('backend_failure')), 1)
        self.assertEqual(self.trace.matching('backend_response'), [])
        self.assertEqual(self.trace.matching('delivery_started'), [])
        self.assertEqual(proxy.errors, [])

    def test_backend_truncated_body_is_not_a_complete_product_response(self):
        def truncated(handler, _request):
            handler.send_response_only(200)
            handler.send_header('Content-Length', '100')
            handler.send_header('Connection', 'close')
            handler.end_headers()
            handler.wfile.write(b'partial')

        self.backend.respond = truncated
        proxy = self.make()
        self.assertIsNotNone(Call(lambda: self.request(proxy)).join().error)
        failure = self.trace.matching('backend_failure')[0]
        self.assertEqual(failure['failure'], 'IncompleteBody')
        self.assertEqual(self.trace.body(failure['response']), b'partial')
        self.assertEqual(self.trace.matching('backend_response'), [])
        self.assertEqual(proxy.errors, [])

    def test_complete_chunked_backend_is_reframed_without_changing_body(self):
        def chunked(handler, _request):
            handler.send_response_only(200)
            handler.send_header('Transfer-Encoding', 'chunked')
            handler.send_header('Connection', 'close')
            handler.end_headers()
            handler.wfile.write(b'3\r\none\r\n3\r\ntwo\r\n0\r\n\r\n')

        self.backend.respond = chunked
        proxy = self.make()
        status, body, headers = self.request(proxy)
        self.assertEqual((status, body), (200, b'onetwo'))
        self.assertEqual(headers['Content-Length'], '6')
        self.assertNotIn('Transfer-Encoding', headers)
        self.assertEqual(self.trace.matching('backend_response')[0]['headers']['transfer-encoding'], 'chunked')

    def test_invalid_method_path_framing_auth_and_json_never_forward(self):
        variants = [
            (self.wire().replace(b'POST ', b'GET ', 1), 'request_target'),
            (self.wire().replace(b'/v1 ', b'/v1?other=1 ', 1), 'request_target'),
            (self.wire().replace(b'Host: localhost\r\n', b'Host: localhost\r\nhost: duplicate\r\n'), 'request_headers'),
            (self.wire().replace(b'Content-Length:', b'Transfer-Encoding: chunked\r\nContent-Length:'), 'request_framing'),
            (self.wire().replace(TOKENS['11'].encode(), b'wrong-secret'), 'request_authorization'),
            (self.wire().replace(self.body(), b'x' * len(self.body())), 'handler_error'),
            (self.wire().replace(b'Content-Length: ' + str(len(self.body())).encode(),
                                 b'Content-Length: ' + str(proxy_module.MAX_REQUEST + 1).encode()), 'request_size'),
        ]
        for index, (raw, code) in enumerate(variants):
            with self.subTest(code=code):
                proxy = self.make(role=f'bad-{index}')
                self.assertEqual(self.raw_request(proxy, raw), b'')
                proxy.close()
                self.assertIn(code, [r['code'] for r in proxy.errors])
        self.assertEqual(self.backend.requests, [])
        public = (self.trace.path / 'events.jsonl').read_text()
        self.assertNotIn('wrong-secret', public)
        self.assertTrue(all(token not in public for token in TOKENS.values()))

    def test_header_cap_and_incomplete_request_are_closed(self):
        proxy = self.make()
        raw = self.wire().replace(b'Host: localhost\r\n', b'Host: localhost\r\nX-Large: ' + b'a' * 16384 + b'\r\n')
        self.assertEqual(self.raw_request(proxy, raw), b'')
        sock = self.socket(proxy)
        sock.sendall(self.wire()[:-1])
        sock.shutdown(socket.SHUT_WR)
        self.assertEqual(sock.recv(4096), b'')
        proxy.close()
        self.assertEqual([r['code'] for r in proxy.errors], ['request_headers', 'request_incomplete'])
        self.assertEqual(self.backend.requests, [])

    def test_oversize_backend_declaration_is_not_forwarded_as_success(self):
        def oversize(handler, _request):
            handler.send_response_only(200)
            handler.send_header('Content-Length', str(proxy_module.MAX_RESPONSE + 1))
            handler.end_headers()

        self.backend.respond = oversize
        proxy = self.make()
        self.assertIsNotNone(Call(lambda: self.request(proxy)).join().error)
        self.assertEqual([r['code'] for r in proxy.errors], ['backend_framing'])
        self.assertEqual(self.trace.matching('backend_response'), [])

    def test_unknown_length_response_still_has_hard_capture_cap(self):
        def oversize(handler, _request):
            handler.send_response_only(200)
            handler.send_header('Connection', 'close')
            handler.end_headers()
            handler.wfile.write(b'x' * 65)

        self.backend.respond = oversize
        with patch.object(proxy_module, 'MAX_RESPONSE', 64):
            proxy = self.make()
            self.assertIsNotNone(Call(lambda: self.request(proxy)).join().error)
            proxy.close()
        self.assertEqual([r['code'] for r in proxy.errors], ['backend_size'])
        self.assertEqual(self.trace.matching('backend_response'), [])

    def test_input_drip_cannot_renew_absolute_deadline(self):
        with patch.object(proxy_module, 'INPUT_SECONDS', 0.12):
            proxy = self.make()
            sock = self.socket(proxy)
            sock.sendall(b'POST /v1 HTTP/1.1\r\nX-Drip: ')
            started = time.monotonic()
            for _ in range(10):
                if self.trace.wait('deadline', seconds=0.035):
                    break
                try:
                    sock.sendall(b'a')
                except OSError:
                    break
            self.assertTrue(self.trace.wait('deadline'))
            self.assertLess(time.monotonic() - started, 1)
            proxy.close()
        self.assertEqual(self.trace.matching('deadline')[0]['stage'], 'input')
        self.assertEqual(self.backend.requests, [])

    def test_backend_drip_cannot_renew_absolute_deadline(self):
        def drip(handler, _request):
            handler.send_response_only(200)
            handler.send_header('Content-Length', '100')
            handler.end_headers()
            for _ in range(100):
                handler.wfile.write(b'x')
                if self.backend.release.wait(0.03):
                    return

        self.backend.respond = drip
        with patch.object(proxy_module, 'BACKEND_SECONDS', 0.12):
            proxy = self.make()
            call = Call(lambda: self.request(proxy)).join()
            self.assertIsNotNone(call.error)
            self.assertTrue(self.trace.wait('deadline'))
            proxy.close()
        self.assertEqual(self.trace.matching('deadline')[0]['stage'], 'backend')
        self.assertEqual(self.trace.matching('backend_response'), [])
        self.assertEqual(len(self.trace.matching('backend_failure')), 1)
        self.assertEqual(len(self.backend.requests), 1)

    def test_stalled_output_has_real_socket_deadline(self):
        body = b'x' * (8 * 1024 * 1024)

        def large(handler, _request):
            handler.send_response_only(200)
            handler.send_header('Content-Length', str(len(body)))
            handler.end_headers()
            handler.wfile.write(body)

        self.backend.respond = large
        with patch.object(proxy_module, 'OUTPUT_SECONDS', 0.12):
            proxy = self.make()
            sock = self.socket(proxy)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
            sock.sendall(self.wire())
            self.assertTrue(self.trace.wait('delivery_started'))
            self.assertTrue(self.trace.wait('delivery_finished'))
            self.assertFalse(self.trace.matching('delivery_finished')[0]['complete'])
            self.assertEqual(len(self.trace.matching('backend_response')), 1)
            proxy.close()
        self.assertEqual(proxy.errors, [])

    def test_close_interrupts_backend_wait_and_joins_handler(self):
        def blocked(_handler, _request):
            self.backend.release.wait(2)

        self.backend.respond = blocked
        proxy = self.make()
        call = Call(lambda: self.request(proxy))
        self.assertTrue(self.backend.arrived.wait(1))
        started = time.monotonic()
        proxy.close()
        self.assertLess(time.monotonic() - started, 1)
        self.assertIsNotNone(call.join().error)
        self.assertEqual(len(self.trace.matching('backend_failure')), 1)
        self.assertEqual(proxy.connections, {})
        self.assertEqual(proxy.errors, [])

    def test_capacity_is_checked_before_spawning_another_owned_handler(self):
        with patch.object(proxy_module, 'MAX_HANDLERS', 2):
            proxy = self.make()
            self.socket(proxy)
            self.socket(proxy)
            self.assertTrue(self.trace.wait('connection_started', 2))
            third = self.socket(proxy)
            self.assertEqual(third.recv(4096), b'')
            proxy.close()
        self.assertEqual(len(self.trace.matching('connection_started')), 2)
        self.assertEqual(len(self.trace.matching('connection_rejected')), 1)
        closed = self.trace.matching('closed')[0]
        self.assertEqual((closed['connection_count'], closed['request_count']), (3, 0))
        self.assertTrue(closed['joined'])

    def test_evidence_failure_after_start_still_reaps_handler(self):
        proxy = self.make()
        self.trace.fail_event = 'http_proxy_request'
        self.assertIsNotNone(Call(lambda: self.request(proxy)).join().error)
        proxy.close()
        self.assertEqual(self.backend.requests, [])
        self.assertEqual(proxy.connections, {})
        self.assertIn('handler_error', [r['code'] for r in proxy.errors])

    def test_started_trace_failure_does_not_leak_listener(self):
        before = {t.ident for t in threading.enumerate() if t.name.startswith('owner-http-')}
        self.trace.fail_event = 'http_proxy_started'
        with self.assertRaises(OSError):
            HTTPProxy('startup-failure', self.backend.port, self.trace, TOKENS)
        after = {t.ident for t in threading.enumerate() if t.name.startswith('owner-http-')}
        self.assertEqual(before, after)
        self.assertTrue(self.trace.matching('closed')[0]['joined'])

    def test_listener_thread_start_failure_closes_bound_socket(self):
        servers = []
        original = proxy_module.Server

        def remember(*args, **kwargs):
            server = original(*args, **kwargs)
            servers.append(server)
            return server

        with patch.object(proxy_module, 'Server', side_effect=remember), \
                patch.object(threading.Thread, 'start', side_effect=RuntimeError('start failure')):
            with self.assertRaises(RuntimeError):
                HTTPProxy('no-thread', self.backend.port, self.trace, TOKENS)
        self.assertEqual(len(servers), 1)
        self.assertEqual(servers[0].socket.fileno(), -1)

    def test_configuration_and_gate_validation_are_explicit(self):
        for args in [('', self.backend.port, TOKENS), ('role', 0, TOKENS),
                     ('role', self.backend.port, {}), ('role', self.backend.port, {'0': 'x'}),
                     ('role', self.backend.port, {'11': 'x', '12': 'x'}),
                     ('role', self.backend.port, {'11': 'bad\nsecret'})]:
            with self.subTest(args=args[:2]), self.assertRaises(ValueError):
                HTTPProxy(args[0], args[1], self.trace, args[2])
        proxy = self.make()
        for kwargs in ({'mode': 'invented'}, {'stage': 'before_forward'},
                       {'occurrence': True}, {'occurrence': 0}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                proxy.arm('bad', 'owner_prepare', **kwargs)
        gate = proxy.arm('held', 'owner_claim', 'hold')
        with self.assertRaises(ValueError):
            proxy.arm('second', 'owner_abort')
        with self.assertRaises(ValueError):
            proxy.release(gate)
        proxy.close()
        with self.assertRaises(ValueError):
            proxy.phase_to('too-late')
        with self.assertRaises(ValueError):
            proxy.arm('late', 'owner_abort')


if __name__ == '__main__':
    unittest.main()
