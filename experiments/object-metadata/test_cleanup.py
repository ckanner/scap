"""Fixture fault tests: no daemon, SDK, socket or object-store workload.

The child-cleanup checks own harmless Python processes and use the real kernel
wait4 helper. Failing evidence sinks must never prevent their termination.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
specification = importlib.util.spec_from_file_location("metadata_cleanup_runner", HERE / "run.py")
RUN = importlib.util.module_from_spec(specification)
specification.loader.exec_module(RUN)
PROXY = sys.modules["proxy"]


class Sink:
    def __init__(self, fail=None):
        self.fail, self.rows, self.errors = fail, [], []

    def emit(self, event, **fields):
        self.rows.append({"event": event, **fields})
        if self.fail == "all" or event == self.fail:
            raise OSError("untrusted sink detail must not escape into safe error receipts")


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="scap-metadata-cleanup-unit-")
        self.root = Path(self.temporary.name)
        self.private, self.evidence = self.root / "private", self.root / "evidence"
        self.private.mkdir()
        self.evidence.mkdir()
        self.children, self.threads = [], []

    def tearDown(self):
        # A regression must not leave the test's own harmless child behind.
        # This emergency path is deliberately separate from the assertions
        # that require the code under test to have already performed wait4.
        for child in self.children:
            if child.returncode is None:
                try:
                    child.kill()
                except ProcessLookupError:
                    pass
                RUN.network.wait_child(child, 3)
            for stream in (child.stdin, child.stdout, child.stderr):
                if stream is not None and not stream.closed:
                    stream.close()
        for thread in self.threads:
            thread.join(timeout=3)
        self.temporary.cleanup()

    def child(self):
        code = ("import signal,sys,time\n"
                "signal.signal(signal.SIGINT,lambda *_:sys.exit(0))\n"
                "print('ready',flush=True)\n"
                "while True: time.sleep(60)\n")
        child = subprocess.Popen([sys.executable, "-c", code], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        self.children.append(child)
        identity = RUN.network.process_identity(child)
        self.assertTrue(select.select([child.stdout], [], [], 3)[0], "controlled child did not become ready")
        self.assertEqual(child.stdout.readline(), b"ready\n")
        return child, identity

    def reaped(self, child, code):
        self.assertEqual(child.returncode, code)
        with self.assertRaises(ChildProcessError):
            os.waitpid(child.pid, os.WNOHANG)

    def suite(self, events):
        return SimpleNamespace(private=self.private, evidence=self.evidence, events=events, cleanup_errors=[],
                               ports={"S": 1}, tools={}, endpoints={"S": "http://127.0.0.1:1/v1"},
                               tokens={name: "unit-" + name for name in RUN.PRINCIPALS})

    def test_fsync_failure_is_latched_even_when_the_json_line_exists(self):
        trace = PROXY.Trace(self.evidence / "trace.jsonl")
        with mock.patch.object(PROXY.os, "fsync", side_effect=OSError("private sink detail")):
            with self.assertRaises(OSError):
                trace.emit("first")
        trace.emit("later")
        self.assertEqual([json.loads(line)["event"] for line in trace.path.read_text().splitlines()], ["first", "later"])
        self.assertEqual(trace.errors, [{"trace": "trace.jsonl", "event": "first", "sequence": 1, "error_name": "OSError"}])
        self.assertNotIn("private sink detail", json.dumps(trace.errors))

    def test_service_signal_and_wait4_survive_every_stop_record_failure(self):
        sink = Sink("all")
        suite = self.suite(sink)
        service = RUN.Service(suite, "S")
        service.process, service.identity = self.child()
        service.log.write_bytes(b"controlled unit child; no daemon\n")
        service.stop("controlled_unit_shutdown")
        self.reaped(service.process, 0)
        self.assertTrue(service.stopped)
        stopped = [row for row in sink.rows if row["event"] == "service_stopped"]
        self.assertEqual(len(stopped), 1)
        self.assertEqual(stopped[0]["kernel_usage"]["source"], "kernel_wait4_owned_child")
        self.assertTrue(stopped[0]["kernel_usage"]["available"])
        self.assertEqual([row["event"] for row in suite.cleanup_errors], ["service_stop_requested", "service_stopped"])

    def test_partial_node_start_without_reader_still_reaps_original_child(self):
        sink = Sink("all")
        suite = self.suite(sink)
        suite.tools["node"] = {"path": sys.executable, "sha256": "0" * 64}
        node = RUN.Node(suite)
        original_popen = subprocess.Popen

        def launch(_command, **options):
            child = original_popen([sys.executable, "-c", "import time; time.sleep(60)"], **options)
            self.children.append(child)
            return child

        with mock.patch.object(RUN.subprocess, "Popen", side_effect=launch):
            with self.assertRaises(OSError):
                node.start()
        self.assertIsNotNone(node.process)
        self.assertIsNone(node.reader)
        with self.assertRaises(AssertionError):
            node.stop(force=True)
        self.reaped(node.process, -signal.SIGKILL)
        stopped = [row for row in sink.rows if row["event"] == "node_stopped"]
        self.assertEqual(len(stopped), 1)
        self.assertTrue(stopped[0]["kernel_usage"]["available"])
        self.assertTrue(stopped[0]["forced"])
        self.assertTrue(suite.cleanup_errors)

    def test_suite_continues_through_prior_failures_and_reaps_all_backend_children(self):
        suite = RUN.Suite(SimpleNamespace(), self.evidence, self.private, {})
        suite.events = Sink("all")
        calls = []

        def fail(name):
            def effect(*_args, **_kwargs):
                calls.append(name)
                raise OSError("unrecordable cleanup")
            return effect

        suite.node = SimpleNamespace(stopped=False, stop=fail("node"))
        suite.services = {worker: SimpleNamespace(stop=fail(worker)) for worker in ("M", "S")}
        suite.hub = SimpleNamespace(release_for_cleanup=fail("release"), close=fail("listeners"))
        backend = object.__new__(RUN.network.Backend)
        backend.directory = self.private / "backend"
        backend.directory.mkdir()
        backend.access, backend.secret = "unit-access", "unit-secret"
        backend.processes, backend.process_metadata, backend.commands = [], {}, []
        for role in ("master", "volume", "filer", "s3"):
            child, identity = self.child()
            backend.processes.append(child)
            backend.process_metadata[child.pid] = identity
            backend.commands.append((role, []))
            (backend.directory / (role + ".private.log")).write_bytes(b"unit-only controlled child\n")
        owned = list(backend.processes)
        suite.backend = backend
        errors = suite.cleanup()
        self.assertEqual(calls, ["release", "node", "M", "S", "listeners"])
        self.assertTrue(errors)
        for child in owned:
            self.reaped(child, -signal.SIGKILL)
        stopped = [row for row in suite.events.rows if row["event"] == "backend_stopped"]
        self.assertEqual(len(stopped), 1)
        self.assertEqual(len(stopped[0]["processes"]), 4)
        self.assertTrue(all(row["kernel_usage"]["available"] for row in stopped[0]["processes"]))
        self.assertTrue(self.private.exists())

    def test_failed_cleanup_release_does_not_skip_other_listener_joins(self):
        hub = object.__new__(PROXY.Hub)
        hub.events, hub.errors = Sink("all"), []
        hub.http_trace = hub.s3_trace = SimpleNamespace(errors=[])
        rule = PROXY.Rule("held", {"kind": "hold"})
        rule.used, rule.request_serial = True, 17
        rule.entered.set()
        hub.rules = {"held": rule}
        joined = []
        hub.listeners = []
        for index in range(2):
            thread = threading.Thread(target=lambda: rule.released.wait(2), daemon=False)
            self.threads.append(thread)
            thread.start()

            def stop(errors, ordinal=index, owned_thread=thread):
                owned_thread.join(timeout=2)
                self.assertFalse(owned_thread.is_alive())
                joined.append(ordinal)
                PROXY.cleanup_event(hub.events, errors, "proxy_listener_stopped", listener_id=str(ordinal))
                if ordinal == 0:
                    raise RuntimeError("completed first listener; still visit the second")

            hub.listeners.append(SimpleNamespace(stop=stop))
        errors = []
        with self.assertRaises(AssertionError):
            hub.close(errors)
        self.assertTrue(rule.released.is_set())
        self.assertEqual(joined, [0, 1])
        self.assertIn("unreleased_fault", errors)
        self.assertIn("RuntimeError", errors)
        self.assertEqual(sum(isinstance(row, dict) and row["event"] == "fault_cleanup_release" for row in errors), 1)

    def test_listener_joins_every_owned_thread_before_a_failed_terminal_record(self):
        listener = object.__new__(PROXY.Listener)
        listener.hub = SimpleNamespace(events=Sink("all"))
        listener.listener_id, listener.channel, listener.worker = "s3-M", "s3", "M"
        listener.lock = threading.RLock()
        listener.accepted, listener.finished, listener.active = 2, 2, {}
        release, actions = threading.Event(), []

        def shutdown():
            actions.append("shutdown")
            release.set()

        listener.shutdown = shutdown
        listener.server_close = lambda: actions.append("close")
        listener.serve_thread = threading.Thread(target=lambda: release.wait(2), daemon=False)
        listener.threads = [threading.Thread(target=lambda: release.wait(2), daemon=False) for _ in range(2)]
        for thread in [listener.serve_thread, *listener.threads]:
            self.threads.append(thread)
            thread.start()
        errors = []
        listener.stop(errors)
        self.assertEqual(actions, ["shutdown", "close"])
        self.assertTrue(all(not thread.is_alive() for thread in [listener.serve_thread, *listener.threads]))
        self.assertEqual(errors, [{"event": "proxy_listener_stopped", "error_name": "OSError"}])

    def seal(self, sink, errors=None):
        (self.private / "preserve.bin").write_bytes(b"private runtime sentinel")
        info = self.private.stat()
        suite = SimpleNamespace(events=sink, private_identity={"path": str(self.private), "device": info.st_dev, "inode": info.st_ino})
        summary = {"status": "failed", "contract_finished": True, "source_unchanged": True,
                   "private_deleted": False, "cleanup_errors": [] if errors is None else errors}
        RUN.seal_observed(suite, self.private, summary)
        return summary

    def test_known_cleanup_failure_prevents_any_private_removal(self):
        sink = Sink()
        summary = self.seal(sink, ["earlier_evidence_failure"])
        self.assertEqual(summary["status"], "failed")
        self.assertFalse(summary["private_deleted"])
        self.assertEqual((self.private / "preserve.bin").read_bytes(), b"private runtime sentinel")
        self.assertEqual(sink.rows, [])

    def test_remove_started_write_failure_preserves_private_bytes(self):
        summary = self.seal(Sink("private_remove_started"))
        self.assertEqual(summary["status"], "failed")
        self.assertFalse(summary["private_deleted"])
        self.assertTrue((self.private / "preserve.bin").exists())
        self.assertEqual(summary["cleanup_errors"], [{"event": "private_remove_started", "error_name": "OSError"}])

    def test_remove_finished_write_failure_never_fakes_restoration_or_pass(self):
        summary = self.seal(Sink("private_remove_finished"))
        self.assertEqual(summary["status"], "failed")
        self.assertTrue(summary["private_deleted"])
        self.assertFalse(self.private.exists())
        self.assertEqual(summary["cleanup_errors"], [{"event": "private_remove_finished", "error_name": "OSError"}])

    def test_only_complete_cleanup_and_both_observations_can_seal_observed(self):
        sink = Sink()
        summary = self.seal(sink)
        self.assertEqual(summary["status"], "observed")
        self.assertEqual(summary["cleanup_errors"], [])
        self.assertTrue(summary["private_deleted"])
        self.assertEqual([row["event"] for row in sink.rows], ["private_remove_started", "private_remove_finished"])


if __name__ == "__main__":
    unittest.main()
