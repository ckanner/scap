"""Pure oracle counterexamples and explicitly synthetic signed loopback I/O."""
from copy import deepcopy
import http.server
import json
from pathlib import Path
import queue
import tempfile
import threading
from types import SimpleNamespace
import unittest

import absence_spec as spec
from absence_audit import fixed_inputs, race_barriers, o, m, e
from absence_controls import cases
from absence_support import io
from test_oracle import original_descriptor


class AbsenceOracle(unittest.TestCase):
    def rejected(self, rule, function, *args):
        with self.assertRaises(m.Rejected) as caught:
            function(*args)
        self.assertEqual(caught.exception.rule, rule)

    def test_independent_fixed_profile_and_controls(self):
        spec.validate()
        inputs = {'scopes': spec.SCOPES, 'workers': {k: list(v) for k, v in spec.WORKERS.items()},
                  'named': {}, 'native_worker': spec.NATIVE_WORKER, 'exceptional_plans': [],
                  'faults': [list(row) for row in spec.FAULTS], 'owner_rpc': {k: list(v) for k, v in spec.OWNER_RPC.items()},
                  'timeouts': spec.TIMEOUTS, 'limits': spec.LIMITS, 'expected': spec.EXPECTED}
        fixed_inputs(inputs)
        self.assertEqual(len(cases()), 13)
        self.assertEqual(len({name for name, _, _ in cases()}), 13)
        changed = deepcopy(inputs)
        changed['timeouts']['http_ms'] += 1
        self.rejected('absence-original-limits', fixed_inputs, changed)

    def fixture(self, proof=False):
        descriptor = {'value': original_descriptor(), 'exchange': {'request': {'path': '/descriptor'}}}
        current, previous, permanent = {}, {}, {}
        def read(path, start, status, body=b'', etag='"unit-head"', **fields):
            return {'request': {'method': 'GET', 'path': path, 'monotonic_ns': start},
                    'backend': {'status': status, 'headers': {'etag': etag}}, 'bytes': body, 'delivered': True,
                    'group': {'s3_delivery_finished': {'monotonic_ns': start + 1}}, **fields}
        values = [read('/descriptor', 1, 404),
                  read('/head', 3, 200, b'old' if proof else b'current', read_head=previous if proof else current),
                  read('/descriptor', 5, 404 if proof else 200, read_owner=None if proof else descriptor),
                  read('/head', 7, 200, b'old' if proof else b'current', read_head=previous if proof else current)]
        if proof:
            values += [read('/proof', 9, 200, read_owner=permanent),
                       read('/head', 11, 200, b'new', '"unit-new"', read_head=current)]
            call = {'product_body': {'ok': False, 'error': {'code': 'CONFLICT'}},
                    'result': {'error': {'code': 'CONFLICT'}}}
        else:
            call = {'product_body': {'ok': True, 'value': {'state': 'prepared', 'prepared': {
                'scope': o.public(descriptor['value']['scope']), 'input': o.public(descriptor['value']['input']),
                'reference': o.public(m.reference(descriptor['value']))}}}}
        return call, values, descriptor, permanent, current

    def test_real_first_absence_can_return_exact_first_winner(self):
        for name in ('current', 'superseded'):
            race_barriers(name, *self.fixture())

    def test_only_first_missing_is_not_a_corruption_certificate(self):
        call, values, descriptor, proof, current = self.fixture()
        values.pop(2)
        self.rejected('absence-original-two-descriptor-reads', race_barriers,
                      'current', call, values, descriptor, proof, current)

    def test_unstable_head_cannot_certify_original_descriptor_reread(self):
        call, values, descriptor, proof, current = self.fixture()
        values[-1]['read_head'] = {}
        self.rejected('absence-reread-original-winner-stable-head', race_barriers,
                      'superseded', call, values, descriptor, proof, current)

    def test_two_real_absences_then_new_proof_require_third_head(self):
        race_barriers('proof', *self.fixture(True))
        call, values, descriptor, proof, current = self.fixture(True)
        values.pop()
        self.rejected('proof-after-absence-fresh-head-conflict', race_barriers,
                      'proof', call, values, descriptor, proof, current)

    def test_missing_late_proof_cannot_be_called_proof_race(self):
        call, values, descriptor, proof, current = self.fixture(True)
        values.pop(4)
        self.rejected('proof-after-absence-fresh-head-conflict', race_barriers,
                      'proof', call, values, descriptor, proof, current)

    def test_corrupt_or_unknown_is_not_the_expected_conflict(self):
        for code in ('CORRUPT', 'UNKNOWN'):
            call, values, descriptor, proof, current = self.fixture(True)
            call['product_body']['error']['code'] = call['result']['error']['code'] = code
            self.rejected('proof-race-not-corrupt-or-unknown', race_barriers,
                          'proof', call, values, descriptor, proof, current)

    def test_original_cannot_publish_after_race(self):
        call, values, descriptor, proof, current = self.fixture(True)
        values.append({'request': {'method': 'PUT', 'path': '/new'}})
        self.rejected('absence-original-does-not-rebuild-or-publish', race_barriers,
                      'proof', call, values, descriptor, proof, current)


class RealResponseHold(unittest.TestCase):
    def test_signed_real_404_is_kept_after_concurrent_conditional_create(self):
        # A transport unit, not scapd or SeaweedFS acceptance. The actual runner
        # never uses this backend and the oracle requires native build receipts.
        access, secret, stored = 'absence-unit-access', 'absence-unit-secret', {}
        failures, first = [], queue.Queue()
        lock = threading.Lock()
        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'
            def log_message(self, *_):
                pass
            def dispatch(self):
                try:
                    body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
                    assert io.signing.verify_signature(self.command, self.path, dict(self.headers.items()), body, access, secret)
                    with lock:
                        if self.command == 'PUT':
                            assert self.headers.get('If-None-Match') == '*' and self.path not in stored
                            stored[self.path] = body
                            status, response = 200, b''
                        else:
                            status = 200 if self.path in stored else 404
                            response = stored.get(self.path, b'<Error><Code>NoSuchKey</Code></Error>')
                    self.send_response(status)
                    self.send_header('ETag', '"unit-object"')
                    self.send_header('Content-Length', str(len(response)))
                    self.send_header('Connection', 'close')
                    self.end_headers()
                    self.wfile.write(response)
                except BaseException as error:
                    failures.append(repr(error))
            do_GET = dispatch
            do_PUT = dispatch
        backend = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        backend.daemon_threads = False
        server = threading.Thread(target=backend.serve_forever)
        server.start()
        proxies, caller = [], None
        temporary = tempfile.TemporaryDirectory(prefix='scap-absence-transport-unit-')
        try:
            root, path = Path(temporary.name), '/scap-test/unit-descriptor'
            trace = io.Trace(root)
            for role in ('C', 'B'):
                proxies.append(io.Proxy(SimpleNamespace(port=backend.server_port), role, trace, {access: secret}))
            original, competitor = [SimpleNamespace(port=proxy.server.server_port, access=access, secret=secret) for proxy in proxies]
            gate = proxies[0].arm('unit-real-404', 'GET', path, 'hold', stage='after_response')
            def read():
                try:
                    first.put(io.signing.signed_request(original, 'GET', path))
                except BaseException as error:
                    first.put(error)
            caller = threading.Thread(target=read)
            caller.start()
            self.assertTrue(gate.arrived.wait(5))
            self.assertTrue(first.empty())
            rows = e.rows(root / 'events.jsonl')
            response = e.one(rows, 's3_backend_response', role='C', serial=1)
            self.assertEqual(response['status'], 404)
            self.assertLess(e.moment(response), e.moment(e.one(rows, 'fault_arrived')))
            published = io.signing.signed_request(competitor, 'PUT', path, b'actual-unit-winner', {'if-none-match': '*'})
            self.assertEqual(published['status'], 200)
            proxies[0].release(gate)
            answer = first.get(timeout=5)
            self.assertNotIsInstance(answer, BaseException)
            self.assertEqual(answer['status'], 404)
            next_read = io.signing.signed_request(original, 'GET', path)
            self.assertEqual(next_read['status'], 200)
            self.assertEqual(io.signing.body_value(next_read['body']), b'actual-unit-winner')
            caller.join(5)
            self.assertFalse(caller.is_alive())
            for proxy in proxies:
                proxy.close()
            proxies = []
            values = e.s3_exchanges(root, e.rows(root / 'events.jsonl'),
                {'normal_access_sha256': m.sha(access.encode()), 'gc_access_sha256': m.sha(b'unused-unit-gc')})
            self.assertEqual(len(values), 3)
            self.assertTrue(all(row['delivered'] and row['backend'] is not None for row in values))
            self.assertFalse(failures)
        finally:
            for proxy in proxies:
                proxy.close()
            if caller is not None:
                caller.join(5)
            backend.shutdown()
            backend.server_close()
            server.join(5)
            temporary.cleanup()


if __name__ == '__main__':
    unittest.main()
