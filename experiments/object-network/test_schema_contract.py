"""Independent oracle/controller checks, separate from real native/S3 evidence."""

import copy
import contextlib
import io
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

import schema_contract as contract


def ledger():
    rows = [{"invocation": {"id": number}, "observed_statements": [{"rows": []}]}
            for number in range(1, 7)]
    rows[1]["observed_statements"][0]["rows"] = [[1, "first", -(2 ** 63)]]
    rows[5]["observed_statements"][0]["rows"] = [[2, "second", 2 ** 63 - 1]]
    return rows


class SchemaOracleTests(unittest.TestCase):
    def test_plan_preserves_statement_and_request_boundaries(self):
        plan = contract.plan("first", "second")
        self.assertEqual([len(transaction) for transaction in plan], [6, 2, 1, 1, 1, 2])
        self.assertEqual(plan[2], [{"sql": "ALTER TABLE items RENAME TO renamed_items"}])
        self.assertEqual(plan[3], [{"sql": "ALTER TABLE renamed_items RENAME COLUMN payload TO body"}])
        self.assertEqual(plan[4], [{"sql": "ALTER TABLE renamed_items DROP COLUMN obsolete"}])
        self.assertEqual(plan[1][0]["parameters"], [{"type": "text", "value": "first"}])
        self.assertEqual(plan[5][0]["parameters"], [{"type": "text", "value": "second"}])
        self.assertIn("random()", plan[1][0]["sql"])
        self.assertIn("random()", plan[5][0]["sql"])

    def test_oracle_uses_original_random_values_and_checks_schema_dependencies(self):
        entries = ledger()
        original = copy.deepcopy(entries)
        cases = contract.expected_state(entries, ["first", "second"])
        self.assertEqual([case[0] for case in cases], ["table", "view", "trigger", "foreign_key", "schema"])
        self.assertEqual(cases[0][2], ["id", "body", "nonce"])
        self.assertEqual(cases[0][3], [[1, "first", -(2 ** 63)], [2, "second", 2 ** 63 - 1]])
        self.assertEqual(cases[1][3], cases[0][3])
        self.assertEqual(cases[2][3], [[1, "first"], [2, "second"]])
        self.assertEqual(cases[3][3], cases[2][3])
        self.assertIn(["index", "items_payload", "renamed_items"], cases[4][3])
        self.assertIn(["trigger", "item_insert", "renamed_items"], cases[4][3])
        self.assertEqual(entries, original)

    def test_missing_late_ack_identity_or_input_changes_cannot_pass(self):
        cases = []
        entries = ledger(); entries.pop(); cases.append(entries)
        entries = ledger(); entries[3]["invocation"]["id"] = 3; cases.append(entries)
        entries = ledger(); entries[1]["observed_statements"][0]["rows"] = []; cases.append(entries)
        entries = ledger(); entries[1]["observed_statements"][0]["rows"][0].append(1); cases.append(entries)
        for value in ([999, "first", 42], [1, "changed", 42], [1, "first", True]):
            entries = ledger(); entries[1]["observed_statements"][0]["rows"] = [value]; cases.append(entries)
        for entries in cases:
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                contract.expected_state(entries, ["first", "second"])

    def test_original_lookup_compares_full_receipt_and_encoded_bytes(self):
        entry = {"receipt": {"data_root": "root", "request": {"id": 3}, "sequence": 3},
                 "encoded_result": [0, 1, 255], "observed_statements": [{"rows": []}]}
        observed = {"state": "committed", "receipt": copy.deepcopy(entry["receipt"]), "encoded": [0, 1, 255]}
        self.assertTrue(contract.original_matches(entry, observed))
        for change in ({"state": "unknown"}, {"receipt": {**entry["receipt"], "sequence": 4}}, {"encoded": [0, 1]}):
            self.assertFalse(contract.original_matches(entry, {**observed, **change}))
        replay = {"receipt": entry["receipt"], "result": {"encoded": entry["encoded_result"],
                                                          "statements": entry["observed_statements"]}}
        self.assertTrue(contract.original_matches(entry, replay, replay=True))
        for changed in ({}, {**replay, "receipt": {}}, {**replay, "result": {}},
                        {**replay, "result": {**replay["result"], "statements": []}}):
            self.assertFalse(contract.original_matches(entry, changed, replay=True))

    def test_readback_rejects_changed_head_or_any_object_publication(self):
        head = {"etag": "same", "bytes": [1, 2]}
        trace = [{"event": "object_request", "method": "GET", "path": "/scap-test/head"}]
        contract.unchanged(head, dict(head), trace)
        for after in ({**head, "etag": "changed"}, {**head, "bytes": [1]}):
            with self.assertRaises(ValueError): contract.unchanged(head, after, trace)
        for path in ("/scap-test/head", "/scap-test/objects/new"):
            with self.assertRaises(ValueError):
                contract.unchanged(head, head, trace + [{"event": "object_request", "method": "PUT", "path": path}])


def success(response):
    if response.get("ok") is not True:
        raise ValueError("worker refused " + str(response.get("error")))
    return response.get("value")


class StoppedSessionControllerTests(unittest.TestCase):
    """Controller doubles; the native stopped-writer behavior is tested separately."""

    def fixture(self):
        suite = contract.SchemaSuite.__new__(contract.SchemaSuite)
        suite.support = types.SimpleNamespace(success=success)
        suite.phase = mock.Mock(side_effect=lambda case, label: label)
        suite.snapshot = mock.Mock(return_value={"bytes": [1, 2], "etag": "same"})
        suite.trace = mock.Mock(return_value=[{"event": "object_request", "method": "GET"}])
        suite.event = mock.Mock()
        worker = mock.Mock()
        worker.call.side_effect = [{"ok": False, "error": "StaleSnapshot"},
                                   {"ok": True, "value": {"opened": True}}]
        return suite, worker

    def test_stopped_session_is_observed_and_only_the_cache_is_reopened(self):
        suite, worker = self.fixture()
        suite.reopen_after_refusal({}, worker)
        self.assertEqual(worker.call.call_args_list, [
            mock.call("session_query", sql="SELECT 1"),
            mock.call("session_open", directory="schema-after-refusal"),
        ])
        self.assertEqual(suite.event.call_args_list[-1].kwargs["failed_sql_replayed"], False)
        self.assertEqual(suite.event.call_args_list[-1].kwargs["object_puts"], 0)

    def test_success_transport_or_other_error_does_not_satisfy_native_stop(self):
        for response in ({"ok": True}, {"ok": False, "error": "Store(Unknown)"},
                         {"ok": False, "error": "Corrupt"}):
            suite, worker = self.fixture()
            worker.call.side_effect = [response]
            with self.subTest(response=response), self.assertRaises(ValueError):
                suite.reopen_after_refusal({}, worker)
            self.assertEqual(worker.call.call_count, 1)

    def test_reopen_never_masks_publication_head_change_or_open_failure(self):
        for fault in ("stopped_put", "reopen_put", "changed_head", "open_failure"):
            suite, worker = self.fixture()
            if fault == "stopped_put":
                suite.trace.return_value = [{"event": "object_request", "method": "PUT"}]
            elif fault == "reopen_put":
                suite.trace.side_effect = [[], [{"event": "object_request", "method": "PUT"}]]
            elif fault == "changed_head":
                suite.snapshot.side_effect = [{"bytes": [1], "etag": "old"},
                                              {"bytes": [1], "etag": "old"},
                                              {"bytes": [2], "etag": "new"}]
            else:
                worker.call.side_effect = [{"ok": False, "error": "StaleSnapshot"},
                                           {"ok": False, "error": "Corrupt"}]
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                suite.reopen_after_refusal({}, worker)
            self.assertFalse(any(call.args[1] == "schema_failed_session_reopened"
                                 for call in suite.event.call_args_list))


class EntrypointTests(unittest.TestCase):
    """Entrypoint controls use doubles and do not represent S3 acceptance."""

    def arguments(self, directory):
        return ["--worker", str(directory / "worker"), "--weed", str(directory / "weed"),
                "--build-record", str(directory / "build.json"), "--evidence", str(directory / "evidence")]

    def test_missing_native_prerequisite_is_blocked_and_evidence_is_exclusive(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(contract.main(self.arguments(directory)), 1)
            summary = json.loads((directory / "evidence/summary.json").read_text())
            self.assertEqual(summary["status"], "blocked")
            self.assertFalse(summary["real_worker_started"])
            self.assertFalse(summary["build_record_verified"])
            with self.assertRaises(FileExistsError):
                contract.main(self.arguments(directory))

    def test_instrumented_process_is_never_used_as_integration_evidence(self):
        for name, value in (("LLVM_PROFILE_FILE", "/tmp/profile"),
                            ("RUSTFLAGS", "-C instrument-coverage"),
                            ("CARGO_ENCODED_RUSTFLAGS", "-Cinstrument-coverage")):
            with self.subTest(variable=name), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                with mock.patch.dict(contract.os.environ, {name: value}, clear=True), \
                        contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(contract.main(self.arguments(directory)), 1)
                summary = json.loads((directory / "evidence/summary.json").read_text())
                self.assertEqual(summary["status"], "blocked")
                self.assertIn("integration", summary["error"])

    def test_final_source_drift_and_cleanup_failure_cannot_report_success(self):
        for fault in (None, "source_drift", "suite_failed", "cleanup_failed", "proxy_failed"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                for filename in ("worker", "weed", "build.json"):
                    (directory / filename).write_bytes(b"test double, not an executable or build receipt")
                backend = mock.Mock(port=1, access="test-access", secret="test-secret")
                proxy = mock.Mock(endpoint="http://127.0.0.1:1", errors=[])
                proxy.metrics.return_value = {"requests": 0}
                suite = mock.Mock(summary={"status": "running"}, started_worker_count=1)
                support = types.SimpleNamespace(Backend=mock.Mock(return_value=backend),
                                                Proxy=mock.Mock(return_value=proxy))
                receipt = {"binary": {"sha256": "a" * 64}, "input_sha256": "b" * 64,
                           "source_commit": "c" * 40}
                verifier = mock.Mock(return_value=receipt)
                if fault == "source_drift":
                    verifier.side_effect = [receipt, ValueError("source changed")]
                elif fault == "suite_failed":
                    suite.run.side_effect = ValueError("schema mismatch")
                elif fault == "cleanup_failed":
                    backend.stop.side_effect = OSError("cleanup failure")
                elif fault == "proxy_failed":
                    proxy.errors.append("broken proxy")
                private = directory / "private"
                private.mkdir()
                with mock.patch.dict("sys.modules", {"build": types.SimpleNamespace(verify=verifier,capture_receipt=lambda record,worker,evidence:verifier(record,worker)),
                                                     "run": support}), \
                        mock.patch.object(contract, "SchemaSuite", return_value=suite), \
                        mock.patch.object(contract.tempfile, "mkdtemp", return_value=str(private)), \
                        contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(contract.main(self.arguments(directory)), int(fault is not None))
                summary = json.loads((directory / "evidence/summary.json").read_text())
                self.assertEqual(summary["status"], "passed" if fault is None else "failed")
                self.assertTrue(summary["real_worker_started"])
                backend.stop.assert_called_once()
                proxy.close.assert_called_once()
                self.assertNotIn("test-secret", json.dumps(summary))


if __name__ == "__main__":
    unittest.main()
