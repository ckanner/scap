"""Adversarial observer-boundary tests, separate from the fixed actual contract."""
from __future__ import annotations
import io
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest

from run import Suite
from support import BoundedTrace, DeadlineSocket, Node, ObservedHub, PLAN, Service


class ObserverBoundaries(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='scap-guarded-observer-unit-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.evidence, self.private = self.root / 'evidence', self.root / 'private'
        self.evidence.mkdir()
        self.private.mkdir()
        self.child = self.root / 'owned-child.py'
        self.child.write_text(f'#!{sys.executable}\nimport time\ntime.sleep(60)\n')
        self.child.chmod(0o700)
        self.suite = Suite(SimpleNamespace(server=self.child), self.evidence, self.private,
                           {'node': {'path': str(self.child)}})

    def fail_recording(self):
        # A real failed write, injected after Suite registration and before Popen.
        self.suite.events.path = self.evidence

    def assert_reaped(self, process):
        self.assertEqual(process.returncode, -9)
        with self.assertRaises(ChildProcessError):
            os.waitpid(process.pid, os.WNOHANG)

    def test_service_start_observation_failure_still_reaps_registered_child(self):
        self.suite.s3_endpoints = {'s': 'http://127.0.0.1:1'}
        self.suite.backend = SimpleNamespace(access='fixture-access', secret='fixture-secret', stop=lambda: None)
        self.fail_recording()
        try:
            with self.assertRaises(IsADirectoryError):
                Service(self.suite, 's', 1)
        finally:
            errors = self.suite.cleanup()
        self.assertTrue(errors)
        service = self.suite.services['s']
        self.assertTrue(service.stopped)
        self.assert_reaped(service.process)
        self.assertIsNotNone(self.suite.events.failure)

    def test_node_start_observation_failure_still_reaps_before_reader_exists(self):
        self.suite.endpoints = {name: 'http://127.0.0.1:1/v1' for name in ('s', 'p', 'q')}
        self.suite.hub = SimpleNamespace(sink_url='http://127.0.0.1:2/v1', rules={}, errors=[],
            history=BoundedTrace(self.evidence / 'unused-history.jsonl'), close=lambda: None)
        self.fail_recording()
        try:
            with self.assertRaises(IsADirectoryError):
                Node(self.suite, 1)
        finally:
            errors = self.suite.cleanup()
        self.assertTrue(errors)
        self.assertEqual(len(self.suite.nodes), 1)
        node = self.suite.nodes[0]
        self.assertIsNone(node.reader)
        self.assertTrue(node.stopped)
        self.assert_reaped(node.process)
        self.assertTrue(node.process.stdin.closed and node.process.stdout.closed)

    def test_listener_start_observation_failure_still_closes_and_joins(self):
        self.fail_recording()
        try:
            with self.assertRaises(IsADirectoryError):
                ObservedHub(1, self.evidence, self.suite.events, self.suite)
        finally:
            errors = self.suite.cleanup()
        self.assertTrue(errors)
        self.assertEqual(len(self.suite.hub.servers), 1)
        server, thread = self.suite.hub.servers[0]
        self.assertEqual(server.fileno(), -1)
        self.assertFalse(thread.is_alive())

    def test_node_reader_bounds_an_unterminated_oversized_line_before_decoding(self):
        observed_sizes = []
        class HostileOutput(io.BytesIO):
            def readline(self, size=-1):
                observed_sizes.append(size)
                return super().readline(size)
        stream = HostileOutput(b'x' * (PLAN['bounds']['node_response_bytes'] + 32))
        node = Node.__new__(Node)
        node.suite, node.ordinal = self.suite, 1
        node.process = SimpleNamespace(stdout=stream)
        node.condition, node.rows, node.errors = threading.Condition(), [], []
        node.read()
        self.assertEqual(observed_sizes, [PLAN['bounds']['node_response_bytes'] + 1])
        self.assertEqual(stream.tell(), PLAN['bounds']['node_response_bytes'] + 1)
        self.assertEqual(node.rows, [])
        self.assertEqual(len(node.errors), 1)

    def test_slow_bytes_cannot_refresh_the_original_buffered_read_deadline(self):
        left, right = socket.socketpair()
        stop, errors = threading.Event(), []
        deadline = time.monotonic() + .08
        bounded = DeadlineSocket(left, deadline)
        def trickle():
            try:
                for _ in range(100):
                    if stop.wait(.02):
                        break
                    right.sendall(b'x')
            except OSError as error:
                if not stop.is_set():
                    errors.append(repr(error))
            finally:
                right.close()
        thread = threading.Thread(target=trickle)
        thread.start()
        started = time.monotonic()
        try:
            with bounded.makefile('rb') as stream:
                with self.assertRaises(TimeoutError):
                    stream.read(100)
            # A per-read reset would consume the complete two-second trickle.
            self.assertLess(time.monotonic() - started, 1)
        finally:
            stop.set()
            thread.join(timeout=2)
            bounded.close()
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])


if __name__ == '__main__':
    unittest.main()
