"""Actual tiny owned-child cleanup controls; not SCAP/native/S3 acceptance."""
from pathlib import Path
import os
import signal
import sys
import tempfile
from types import SimpleNamespace
import unittest

from deployment_recovery_imports import local

controller = local("discovery_contract")
Ledger, Worker = controller.Ledger, controller.Worker


class ShortWorker(Worker):
    def read(self, seconds):
        return super().read(min(seconds, 0.1))


class FaultLedger(Ledger):
    def __init__(self, path, fail):
        super().__init__(path); self.fail = fail

    def add(self, event, **values):
        if event == self.fail:
            raise OSError("unit simulated log write failure")
        return super().add(event, **values)


class OwnedChildCleanup(unittest.TestCase):
    def owner(self, root, code, *, fail=None):
        binary = root / "owned-test-child"
        binary.write_text("#!" + sys.executable + "\nimport json,os,sys,time\n" + code + "\n")
        binary.chmod(0o700)
        return SimpleNamespace(private=root, args=SimpleNamespace(seed_worker=binary, worker=binary),
                               facts=FaultLedger(root / "facts.jsonl", fail), workers=[])

    def assert_reaped(self, worker):
        self.assertTrue(worker.stopped)
        self.assertEqual(worker.process.returncode, -signal.SIGKILL)
        with self.assertRaises(ChildProcessError): os.waitpid(worker.process.pid, os.WNOHANG)

    def test_partial_ready_line_keeps_deadline_and_reaps_actual_child(self):
        with tempfile.TemporaryDirectory() as directory:
            owner = self.owner(Path(directory), "sys.stdout.write('{');sys.stdout.flush();time.sleep(30)")
            with self.assertRaisesRegex(AssertionError, "response deadline"):
                ShortWorker(owner, "recovery", {"worker": 1})
            self.assertEqual(len(owner.workers), 1); self.assert_reaped(owner.workers[0])

    def test_invalid_ready_and_failed_spawn_log_never_leave_unowned_process(self):
        for fail in (None, "worker_spawned"):
            with self.subTest(fail=fail), tempfile.TemporaryDirectory() as directory:
                owner = self.owner(Path(directory), "print(json.dumps({'ready':False}),flush=True);time.sleep(30)", fail=fail)
                with self.assertRaises((AssertionError, OSError)):
                    ShortWorker(owner, "seed", {"worker": 1})
                self.assertEqual(len(owner.workers), 1); self.assert_reaped(owner.workers[0])

    def test_failed_stop_log_still_kills_waits_and_closes_owned_child(self):
        with tempfile.TemporaryDirectory() as directory:
            owner = self.owner(Path(directory), "print(json.dumps({'ready':True,'resources':{'namespace_pid':os.getpid()}}),flush=True);time.sleep(30)")
            worker = ShortWorker(owner, "seed", {"worker": 1})
            owner.facts.fail = "worker_stop_requested"
            with self.assertRaisesRegex(OSError, "log write failure"):
                worker.stop("unit_failure")
            self.assert_reaped(worker)
            self.assertTrue(worker.process.stdin.closed and worker.process.stdout.closed)


if __name__ == "__main__": unittest.main()
