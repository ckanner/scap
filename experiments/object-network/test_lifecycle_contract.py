"""Controller doubles only. These tests never count as real worker/S3 execution."""

import contextlib
import copy
import io
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

import build
import lifecycle_contract as contract
import lifecycle_oracle
import run as support


class WorkerDouble:
    def __init__(self, config, responses):
        self.config, self.responses = config, list(responses)
        self.pending, self.invocations = None, []
        self.identity = {"pid": config["worker"]}
        self.binary={"path":"/synthetic/scap-object-network","sha256":"a"*64}

    def begin(self, operation, **values):
        if self.pending is not None:
            raise AssertionError("one outstanding fixture invocation")
        self.invocations.append({"op": operation, **values})
        self.pending = {"ordinal": len(self.invocations)}
        return self.pending

    def finish(self, pending):
        if pending is not self.pending:
            raise AssertionError("wrong pending invocation")
        self.pending = None
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response

    def kill(self, verify=False):
        if not verify:
            raise AssertionError("recovery needs verified SIGKILL")
        return {"worker": self.config["worker"], "pid": self.config["worker"], "wait_status": -9,
                "kernel_usage": {"available": True, "source": "kernel_wait4_owned_child"}}


def jsonlines(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


class LedgerAndControllerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        evidence, private, compute = [self.root / name for name in ("evidence", "private", "compute")]
        for path in (evidence, private, compute): path.mkdir()
        self.proxy = types.SimpleNamespace(set_phase=mock.Mock())
        self.suite = contract.LifecycleSuite(support, types.SimpleNamespace(worker=self.root / "worker"),
                                             evidence, private, compute, mock.Mock(), self.proxy, [], {},
                                             {"binary": {"sha256": "a" * 64}, "input_sha256": "b" * 64})
        self.case = self.suite.cases[0]
        self.config = {"scope": self.case["scope"], "worker": 123, "principal": 17}
        self.identity = {"epoch": 1, "id": 2, "principal": 17, "fingerprint": "c" * 64}
        self.observed = {"ok": True, "value": {"receipt": {"scope": self.case["scope"], "request": self.identity},
                                                "result": {"encoded": [1, 2], "statements": [{"rows": [[7]]}]}},
                         "resources": {"namespace_pid": 123}, "elapsed_ms": 2.5}

    def prepared(self, worker):
        return self.suite.prepare(self.case, worker, "seed", 1, 2, contract.rows_sql("LC-01", 1))

    def test_fact_metadata_can_contain_kind_without_changing_ledger(self):
        self.suite.fact(self.case, "case_started", kind="pilot", profile="prepare")
        observed = jsonlines(self.suite.paths["facts"])[-1]
        self.assertEqual(observed["event"], "case_started")
        self.assertEqual(observed["case"], self.case["id"])
        self.assertEqual(observed["kind"], "pilot")
        self.assertEqual(observed["profile"], "prepare")
        self.assertEqual(jsonlines(self.suite.paths["client"]), [])

    def test_fixed_twelve_case_profile_is_durable_before_first_worker_command(self):
        plan = json.loads((self.suite.evidence / "lifecycle-plan.json").read_text())
        self.assertEqual(plan["case_ids"], [f"LC-{number:02d}" for number in range(1, 13)])
        self.assertEqual(plan["fixture_limits"], {"quota_bytes": 4194304, "retention_entries": 4,
                                                  "retention_result_bytes": 134217728})
        self.assertEqual(len({json.dumps(case["scope"], sort_keys=True) for case in plan["cases"]}), 12)
        self.assertEqual(plan["aws_endpoint_gate"], "NOT_RUN")
        self.assertFalse(plan["unit_coverage_contribution"])
        self.assertEqual(jsonlines(self.suite.paths["client"]), [])

    def test_inputs_precede_invocation_and_every_success_duplicate_has_its_own_ack(self):
        worker = WorkerDouble(self.config, [{"ok": True, "value": self.identity}, self.observed, self.observed])
        original_begin = worker.begin
        def check_input(operation, **values):
            inputs = jsonlines(self.suite.paths["input"])
            self.assertTrue(inputs)
            self.assertEqual(inputs[0]["statements"], contract.rows_sql("LC-01", 1))
            if operation == "execute":
                self.assertEqual(inputs[-1]["identity"], self.identity)
            return original_begin(operation, **values)
        worker.begin = check_input
        intent = self.prepared(worker)
        self.suite.execute(self.case, worker, "seed", intent)
        self.suite.execute(self.case, worker, "replay", intent)
        acks = jsonlines(self.suite.paths["ack"])
        self.assertEqual(len(acks), 2)
        self.assertNotEqual(acks[0]["call_id"], acks[1]["call_id"])
        self.assertEqual(acks[0]["intent_id"], acks[1]["intent_id"])
        self.assertEqual(acks[0]["response"], self.observed)
        calls = [row for row in jsonlines(self.suite.paths["client"]) if row["event"] == "call"]
        self.assertEqual([call["call_id"] for call in calls], [1, 2, 3])
        self.assertEqual([item["op"] for item in worker.invocations], ["prepare_request", "execute", "execute"])
        self.assertTrue(all("intent" not in item and "principal" not in item for item in worker.invocations))

    def test_failure_and_unknown_are_kept_without_retry_or_execute_ack(self):
        for error in ("Store(Unknown)", "Conflict", "Closed", "Retired", "Fenced"):
            with self.subTest(error=error):
                worker = WorkerDouble(self.config, [{"ok": False, "error": error}])
                intent = {"intent_id": "synthetic", "epoch": 1, "id": 3, "statements": [{"sql": "SELECT 1"}]}
                response = self.suite.execute(self.case, worker, error, intent)
                self.assertFalse(response["ok"])
                self.assertEqual(len(worker.invocations), 1)
        self.assertEqual(jsonlines(self.suite.paths["ack"]), [])
        responses = [row for row in jsonlines(self.suite.paths["client"]) if row["event"] == "response"]
        self.assertEqual(len(responses), 5)

    def test_input_or_ack_sync_failure_cannot_be_hidden_by_reexecution(self):
        worker = WorkerDouble(self.config, [{"ok": True, "value": self.identity}, self.observed])
        with mock.patch.object(self.suite.support, "append_synced", side_effect=OSError("input sync failed")):
            with self.assertRaises(OSError): self.prepared(worker)
        self.assertEqual(worker.invocations, [])
        self.suite.intents.clear()
        intent = self.prepared(worker)
        real_append = self.suite.support.append_synced
        def fail_ack(path, row):
            if path == self.suite.paths["ack"]: raise OSError("ACK sync failed")
            return real_append(path, row)
        with mock.patch.object(self.suite.support, "append_synced", side_effect=fail_ack):
            with self.assertRaises(OSError): self.suite.execute(self.case, worker, "seed", intent)
        self.assertEqual(len(worker.invocations), 2)
        self.assertEqual(jsonlines(self.suite.paths["ack"]), [])
        self.assertTrue(jsonlines(self.suite.paths["client"])[-1]["response"]["ok"])

    def test_transport_failure_is_recorded_and_not_turned_into_rejection(self):
        worker = WorkerDouble(self.config, [TimeoutError("no reply")])
        with self.assertRaises(TimeoutError): self.suite.call(self.case, worker, "uncertain", "status")
        rows = jsonlines(self.suite.paths["client"])
        self.assertEqual(rows[-1]["event"], "transport_failure")
        self.assertEqual(rows[-1]["error_type"], "TimeoutError")
        self.assertEqual(len(worker.invocations), 1)

    def test_duplicate_call_label_is_rejected_before_phase_change_or_transport(self):
        worker = WorkerDouble(self.config, [{"ok": True, "value": {}}])
        self.suite.call(self.case, worker, "snapshot", "status")
        with self.assertRaisesRegex(ValueError, "duplicate invocation label before transport"):
            self.suite.call(self.case, worker, "snapshot", "status")
        self.assertEqual(len(worker.invocations), 1)
        self.assertEqual(self.suite.counter, 1)
        self.proxy.set_phase.assert_called_once_with("LC-01/snapshot")

    def test_deleted_recovery_inner_and_outer_snapshots_have_distinct_call_bindings(self):
        # Regression for the real 135ef89 run: eight before/after label pairs
        # were duplicated although every call ID and actual HTTP call existed.
        for case_number in (3, 6):
            for stage in ("compute_recovery", "backend_recovery"):
                case = self.suite.cases[case_number - 1]
                case["seed"] = {"intent_id": case["id"] + "/seed", "identity": self.identity}
                snapshot = {"ok": True, "value": {"etag": "same", "bytes": list(b'{"revision":9}')}}
                lifecycle = {"ok": False, "error": "Lifecycle"}
                responses = [snapshot, snapshot, lifecycle, lifecycle, lifecycle, lifecycle, lifecycle,
                             {"ok": False, "error": "Store(Conflict)"}, snapshot, snapshot]
                worker = WorkerDouble({**self.config, "scope": case["scope"]}, responses)
                with mock.patch.object(self.suite, "spawn", return_value=worker):
                    self.suite.audit(case, stage)
                case["directory"].rmdir()
                self.assertEqual(worker.responses, [])
        calls = [row for row in jsonlines(self.suite.paths["client"]) if row["event"] == "call"]
        self.assertEqual(len(calls), 40)
        self.assertEqual(len({row["call_id"] for row in calls}), 40)
        self.assertEqual(len({row["phase"] for row in calls}), 40)
        for case_number in (3, 6):
            for stage in ("compute_recovery", "backend_recovery"):
                labels = {row["label"] for row in calls if row["case"] == f"LC-{case_number:02d}"}
                self.assertTrue({stage + ".head_before", stage + ".deleted.head_before",
                                 stage + ".deleted.head_after", stage + ".head_after"} <= labels)

    def test_compute_loss_kills_all_owned_instances_and_removes_whole_case_directory(self):
        directory = self.case["directory"]
        (directory / "nested").mkdir(parents=True)
        (directory / "nested" / "cache.db").write_bytes(b"discardable")
        workers = [WorkerDouble({**self.config, "worker": number}, []) for number in (123, 124)]
        self.case["workers"] = workers.copy()
        self.suite.workers = workers.copy()
        self.suite.lose_compute(self.case, "compute_recovery")
        self.assertFalse(directory.exists())
        self.assertEqual(self.suite.workers, [])
        row = jsonlines(self.suite.paths["facts"])[-1]
        self.assertEqual([item["worker"] for item in row["stopped"]], [123, 124])
        self.assertEqual([item["wait_status"] for item in row["stopped"]], [-9, -9])
        self.assertFalse(row["exists_after"])

    def test_compute_kill_failure_preserves_failure_and_cache_evidence(self):
        directory = self.case["directory"]
        directory.mkdir()
        worker = WorkerDouble(self.config, [])
        worker.kill = mock.Mock(side_effect=TimeoutError("wait4 failed"))
        self.case["workers"] = [worker]; self.suite.workers = [worker]
        with self.assertRaises(TimeoutError): self.suite.lose_compute(self.case, "compute_recovery")
        self.assertTrue(directory.exists())
        self.assertFalse(any(row["event"] == "compute_lost" for row in jsonlines(self.suite.paths["facts"])))

    def test_original_principal_and_distinct_instances_are_fixed_at_spawn(self):
        created = []
        def fake_worker(binary, config, private, number, evidence):
            worker = WorkerDouble(config, [])
            created.append(worker)
            return worker
        with mock.patch.object(self.suite.support, "Worker", side_effect=fake_worker):
            self.suite.spawn(self.case, 17); self.suite.spawn(self.case, 17); self.suite.spawn(self.case, 18)
        self.assertEqual(len({item.config["worker"] for item in created}), 3)
        self.assertEqual([item.config["principal"] for item in created], [17, 17, 18])
        self.assertTrue(all(item.config["fixture_limits"] == contract.PROFILE for item in created))


class EntrypointTests(unittest.TestCase):
    def arguments(self, root):
        return ["--worker", str(root / "worker"), "--weed", str(root / "weed"),
                "--build-record", str(root / "build.json"), "--evidence", str(root / "evidence")]

    def test_missing_native_prerequisite_is_blocked_and_evidence_is_exclusive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(contract.main(self.arguments(root)), 1)
            summary = json.loads((root / "evidence" / "summary.json").read_text())
            self.assertEqual(summary["status"], "blocked")
            self.assertFalse(summary["real_worker_started"])
            self.assertFalse(summary["build_record_verified"])
            self.assertEqual(summary["aws_endpoint_gate"], "NOT_RUN")
            with self.assertRaises(FileExistsError): contract.main(self.arguments(root))

    def test_instrumentation_never_counts_as_integration_evidence(self):
        for environment in ({"LLVM_PROFILE_FILE": "unit.profraw"}, {"RUSTFLAGS": "-C instrument-coverage"},
                            {"CARGO_ENCODED_RUSTFLAGS": "-Cinstrument-coverage"}):
            with self.subTest(environment=environment), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                with mock.patch.dict(os.environ, environment), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(contract.main(self.arguments(root)), 1)
                self.assertEqual(json.loads((root / "evidence" / "summary.json").read_text())["status"], "blocked")

    def test_final_source_drift_or_cleanup_failure_cannot_report_success(self):
        for problem in ("source_drift", "backend_cleanup", "proxy_error", "oracle_failure"):
            with self.subTest(problem=problem), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for name in ("worker", "weed", "build.json"): (root / name).write_text("{}\n")
                compiled = {"binary": {"sha256": "a" * 64}, "input_sha256": "b" * 64}
                backend = mock.Mock(port=1, access="private", secret="private")
                proxy = mock.Mock(endpoint="http://127.0.0.1:1", errors=[])
                proxy.metrics.return_value = {}
                suite = mock.Mock(started_worker_count=1, cases=[])
                audit = {"status": "failed" if problem == "oracle_failure" else "passed"}
                verify = [compiled, ValueError("source drift")] if problem == "source_drift" else [compiled, compiled]
                if problem == "backend_cleanup": backend.stop.side_effect = OSError("cleanup failed")
                if problem == "proxy_error": proxy.errors = ["real proxy failure"]
                with mock.patch.object(build, "verify", side_effect=verify), \
                     mock.patch.object(build, "capture_receipt", side_effect=lambda record,worker,evidence:build.verify(record,worker)), \
                     mock.patch.object(support, "Backend", return_value=backend), \
                     mock.patch.object(support, "Proxy", return_value=proxy), \
                     mock.patch.object(contract, "LifecycleSuite", return_value=suite), \
                     mock.patch.object(lifecycle_oracle, "audit", return_value=audit), \
                     mock.patch.object(contract.tempfile, "mkdtemp", return_value=str(root / "private")), \
                     contextlib.redirect_stdout(io.StringIO()):
                    (root / "private").mkdir()
                    self.assertEqual(contract.main(self.arguments(root)), 1)
                summary = json.loads((root / "evidence" / "summary.json").read_text())
                self.assertEqual(summary["status"], "failed")
                self.assertFalse(summary["build_record_verified"])
                self.assertTrue(summary["private_diagnostics"]["retained"])


if __name__ == "__main__":
    unittest.main()
