"""Harness self-tests ONLY: these do not execute Rust, SQLite or a real S3."""
from __future__ import annotations

import contextlib
import copy
import io
import json
import runpy
from pathlib import Path
import struct
import sys
import tempfile
import types
import unittest
from unittest import mock

import retained_result_contract as contract

SCOPE = {"deployment": 78, "tenant": 88, "database": 1001, "incarnation": 1, "generation": 1}
VALID = b"SCAPRES1" + struct.pack("<III", 1, 1, 1) + b"x" + struct.pack("<I", 1) + b"\x01" + struct.pack("<qQq", 42, 1, 7)


def fixture(epoch=1):
    request = {"epoch": epoch, "id": 2, "principal": 17, "fingerprint": "a" * 64}
    metadata = {"format": 2, "scope": dict(SCOPE), "payload": {"kind": "result", "value": {
        "request": request, "sequence": 2, "transition": {"revision": 6, "nonce": 2},
        "data_root": "b" * 64, "bytes": []}}}
    result = contract.pack(metadata, VALID)
    entries = [{"request": request, "outcome": {"state": "committed", "result": contract.sha(result)}}]
    index = contract.pack({"format": 2, "scope": dict(SCOPE), "payload": {"kind": "index", "value": entries}}, b"")
    head = {"format": 2, "scope": dict(SCOPE), "revision": 7, "sequence": 2, "data_root": "b" * 64,
            "owner_instance": 101, "active": False, "retention": {"max_result_bytes": 128 * 1024 * 1024},
            "windows": [{"epoch": epoch, "root": contract.sha(index), "count": 1, "result_bytes": len(VALID)}]}
    return head, index, result


def inputs(epoch=1):
    head, index, result = fixture(epoch)
    return contract.json_bytes(head), index, result


class PureFixtureTests(unittest.TestCase):
    def test_every_mutation_rehashes_all_links_and_preserves_semantic_metadata(self):
        for epoch in (1, 2):
            for damage in contract.MUTATIONS:
                with self.subTest(epoch=epoch, damage=damage):
                    head, index, result = inputs(epoch)
                    plan = contract.rewrite(head, index, result, epoch, damage)
                    changed = json.loads(plan["head"])
                    old = json.loads(head)
                    root = changed["windows"][0]["root"]
                    self.assertEqual(root, contract.sha(plan["index"]))
                    new_index, raw_index = contract.unpack(plan["index"])
                    self.assertFalse(raw_index)
                    link = new_index["payload"]["value"][0]["outcome"]["result"]
                    self.assertEqual(link, contract.sha(plan["result"]))
                    new_result, new_raw = contract.unpack(plan["result"])
                    old_result, old_raw = contract.unpack(result)
                    self.assertEqual(new_result, old_result)
                    self.assertNotEqual(new_raw, old_raw)
                    self.assertEqual(changed["windows"][0]["result_bytes"], len(new_raw))
                    old["windows"] = changed["windows"]
                    self.assertEqual(changed, old)
                    self.assertEqual(contract.unpack(index)[0]["payload"]["value"][0]["outcome"]["result"], contract.sha(result))
                    self.assertEqual(plan["request"], old_result["payload"]["value"]["request"])

    def test_mutation_vectors_are_independent_and_have_targeted_invalid_bytes(self):
        self.assertEqual(contract.mutate(VALID, "bad_magic")[1:], VALID[1:])
        self.assertEqual(contract.mutate(VALID, "truncated_footer"), VALID[:-1])
        self.assertEqual(contract.mutate(VALID, "trailing_byte"), VALID + b"\0")
        self.assertEqual(contract.mutate(VALID, "unknown_tag")[25], 255)
        self.assertEqual(contract.mutate(VALID, "nonfinite_real")[25:34], b"\x02" + struct.pack("<d", float("inf")))
        self.assertEqual(contract.mutate(VALID, "invalid_utf8")[25:31], b"\x03\x01\0\0\0\xff")
        for raw, name in ((b"bad", "bad_magic"), (VALID, "not-a-case")):
            with self.assertRaises(ValueError): contract.mutate(raw, name)

    def test_strict_json_rejects_duplicate_and_nonfinite_metadata(self):
        for data in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}'):
            with self.assertRaises(ValueError): contract.load_json(data)
        self.assertEqual(contract.load_json(b'{"x":1}'), {"x": 1})

    def test_frame_version_bounds_and_metadata(self):
        _, _, result = fixture()
        cases = [b"", b"x" * 20, result[:-1], result + b"x",
                 contract.pack({"format": 1}, b""),
                 contract.pack([2], b"")]
        for case in cases:
            with self.subTest(case=case[:20]), self.assertRaises(ValueError): contract.unpack(case)
        with mock.patch.object(contract, "MAX_BYTES", 20):
            with self.assertRaises(ValueError): contract.pack({"format": 2}, b"x")
            with self.assertRaises(ValueError): contract.unpack(result)

    def test_content_address_and_scope_cannot_be_inferred_from_untrusted_mismatch(self):
        for root in ("F" * 64, "a" * 63, "x" * 64):
            with self.assertRaises(ValueError): contract.object_key(SCOPE, root)
        self.assertEqual(contract.object_key(SCOPE, "a" * 64),
                         "scap-object/v1/78/88/1001/inc/1/gen/1/objects/" + "a" * 64)
        head, index, result = fixture()
        with self.assertRaises(ValueError): contract.rewrite(contract.json_bytes(head), index, result, 9, "bad_magic")
        head["format"] = 1
        with self.assertRaises(ValueError): contract.rewrite(contract.json_bytes(head), index, result, 1, "bad_magic")

    def test_rewrite_rejects_all_reference_and_counter_precondition_failures(self):
        variants = ("hash", "raw_index", "index_kind", "result_kind", "scope", "embedded_bytes",
                    "epoch", "count", "request_missing", "outcome", "negative_counter", "overflow", "format_overflow")
        for change in variants:
            with self.subTest(change=change):
                head, index, result = fixture()
                im, ir = contract.unpack(index); rm, rr = contract.unpack(result)
                if change == "hash": head["windows"][0]["root"] = "0" * 64
                if change == "raw_index": ir = b"x"
                if change == "index_kind": im["payload"]["kind"] = "chunk"
                if change == "result_kind": rm["payload"]["kind"] = "chunk"
                if change == "scope": rm["scope"]["tenant"] += 1
                if change == "embedded_bytes": rm["payload"]["value"]["bytes"] = [0]
                if change == "epoch": rm["payload"]["value"]["request"]["epoch"] += 1
                if change == "count": head["windows"][0]["count"] = 2
                if change == "request_missing": im["payload"]["value"][0]["request"]["id"] += 1
                if change == "outcome": im["payload"]["value"][0]["outcome"]["result"] = "0" * 64
                if change == "negative_counter": head["windows"][0]["result_bytes"] = 0
                if change == "overflow": head["retention"]["max_result_bytes"] = 0
                if change == "format_overflow": head["windows"][0]["result_bytes"] = 64 * 1024 * 1024
                # Recompute unrelated links so each test reaches its intended guard.
                result = contract.pack(rm, rr)
                if change != "outcome": im["payload"]["value"][0]["outcome"]["result"] = contract.sha(result)
                index = contract.pack(im, ir)
                if change != "hash": head["windows"][0]["root"] = contract.sha(index)
                with self.assertRaises(ValueError):
                    contract.rewrite(contract.json_bytes(head), index, result, 1, "trailing_byte")

    def test_refusal_requires_actual_semantic_error_and_real_expected_get(self):
        old = {"bytes": [1], "etag": "one"}
        response = {"ok": False, "error": "Corrupt"}
        trace = [{"event": "object_response", "method": "GET", "path": "/scap-test/r", "status": 200, "response_sha256": "digest"}]
        contract.require_refusal(response, old, dict(old), trace, "r", "digest")
        for bad in ({"ok": True}, {"ok": False, "error": "Format(Corrupt)"}, {"ok": False, "error": "Store(Unknown)"}):
            with self.assertRaises(ValueError): contract.require_refusal(bad, old, old, trace, "r", "digest")
        with self.assertRaises(ValueError): contract.require_refusal(response, old, {**old, "etag": "new"}, trace, "r", "digest")
        for changed in ([], [{**trace[0], "status": 404}], [{**trace[0], "response_sha256": "other"}]):
            with self.assertRaises(ValueError): contract.require_refusal(response, old, old, changed, "r", "digest")
        with self.assertRaises(ValueError):
            contract.require_refusal(response, old, old, trace + [{"event": "object_request", "method": "PUT", "path": "/db/head"}], "r", "digest")

    def test_success_wrapper_and_exclusive_summary(self):
        self.assertEqual(contract.value({"ok": True, "value": 4}), 4)
        with self.assertRaises(ValueError): contract.value({"ok": False, "error": "Unknown"})
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "summary.json"
            contract.finish_json(path, {"status": "blocked"})
            with self.assertRaises(FileExistsError): contract.finish_json(path, {"status": "passed"})
            self.assertEqual(json.loads(path.read_text()), {"status": "blocked"})


class FakeWorker:
    """A scenario-controller double, not a model of SCAP or an S3 server."""
    def __init__(self, suite, case, worker):
        self.suite, self.case = suite, case
        self.config = {"worker": worker}
        self.stopped = False

    def call(self, operation, **values):
        s, case = self.suite, self.case
        def done(value): return {"ok": True, "value": value}
        if operation == "store_get":
            stored = copy.deepcopy(case["objects"][values["key"]])
            s.traces.append({"event": "object_response", "method": "GET", "path": "/scap-test/" + values["key"],
                             "phase": s.current_phase, "status": 200, "response_sha256": contract.sha(bytes(stored["bytes"]))})
            return done(stored)
        if operation == "store_put":
            key = values["key"]
            if "etag" in values:
                if values["etag"] != case["objects"][key]["etag"]: return {"ok": False, "error": "Conflict"}
            elif key in case["objects"]: return {"ok": False, "error": "Conflict"}
            s.serial += 1
            stored = {"bytes": list(values["bytes"]), "etag": str(s.serial)}
            case["objects"][key] = stored
            s.traces.append({"event": "object_request", "method": "PUT", "path": "/scap-test/" + key, "phase": s.current_phase})
            return done({"etag": stored["etag"]})
        if operation == "inspect_object":
            meta, _ = contract.unpack(bytes(values["bytes"]))
            return done({"role": meta["payload"]["kind"], "sha256": contract.sha(bytes(values["bytes"]))})
        if operation == "decode_result":
            return done({}) if bytes(values["encoded"]) == VALID else {"ok": False, "error": "Malformed"}
        head = json.loads(bytes(case["objects"][case["head_key"]]["bytes"]))
        if operation == "status": return done(head)
        if operation == "takeover":
            head["revision"] += 1; head["active"] = False
            case["objects"][case["head_key"]] = {"bytes": list(contract.json_bytes(head)), "etag": f"takeover-{s.serial}"}
            return done(head)
        if operation in contract.PROBES:
            corrupt = None
            for window in head["windows"]:
                im, _ = contract.unpack(bytes(case["objects"][contract.object_key(head["scope"], window["root"])]["bytes"]))
                for entry in im["payload"]["value"]:
                    key = contract.object_key(head["scope"], entry["outcome"]["result"])
                    rm, raw = contract.unpack(bytes(case["objects"][key]["bytes"]))
                    if raw != VALID: corrupt = key
            if corrupt:
                if s.fault != "no_actual_get": self.call("store_get", key=corrupt)
                if s.fault == "old_behavior": return done({"state": "committed"})
                if s.fault == "outer_error": return {"ok": False, "error": "Format(Corrupt)"}
                if s.fault == "head_write":
                    self.call("store_put", key=case["head_key"], bytes=case["objects"][case["head_key"]]["bytes"],
                              etag=case["objects"][case["head_key"]]["etag"])
                if s.fault == "cache_leak" and operation in ("activate_session", "session_open"):
                    (case["directory"] / values["directory"]).mkdir()
                return {"ok": False, "error": "Corrupt"}
            return done(head)
        raise AssertionError(operation)

    def finish(self, pending):
        self.suite.commit_candidate(self.case)
        return {"ok": True, "value": {}}

    def kill(self):
        if self.suite.kill_error: raise OSError("injected cleanup")
        self.stopped = True


class FakeSuite:
    fault = None
    kill_error = False
    def __init__(self, arguments, evidence, private, compute, backend, proxy, workers, config):
        self.evidence, self.compute, self.proxy, self.workers = evidence, compute, proxy, workers
        self.number = 100; self.serial = 0; self.case_number = 0; self.ack_number = 0
        self.current_phase = ""; self.traces = []; self.audited = set()
        self.acks = evidence / "fault-ack-ledger.jsonl"; self.acks.touch()
        self.summary = {"case_results": [], "ack_mismatch_count": 0, "outcome_mismatch_count": 0}
        self.events = []

    def store(self, case, key, data):
        self.serial += 1
        case["objects"][key] = {"bytes": list(data), "etag": str(self.serial)}

    def ack(self, case, invocation, response):
        self.ack_number += 1
        with self.acks.open("a") as f: f.write(json.dumps({"ordinal": self.ack_number, "scope": case["scope"]}) + "\n")

    def commit_candidate(self, case):
        head = json.loads(bytes(case["objects"][case["head_key"]]["bytes"]))
        _, index, result = fixture(2)
        im, _ = contract.unpack(index); rm, _ = contract.unpack(result)
        im["scope"] = rm["scope"] = case["scope"]
        result = contract.pack(rm, VALID)
        im["payload"]["value"][0]["outcome"]["result"] = contract.sha(result)
        index = contract.pack(im, b"")
        self.store(case, contract.object_key(case["scope"], contract.sha(result)), result)
        self.store(case, contract.object_key(case["scope"], contract.sha(index)), index)
        head["windows"][0].update(root=contract.sha(index), count=1, result_bytes=len(VALID))
        self.store(case, case["head_key"], contract.json_bytes(head))

    def fixture(self, name):
        self.case_number += 1
        head, index, result = fixture(1)
        directory = self.compute / str(self.case_number); directory.mkdir()
        head["scope"]["database"] += self.case_number
        scope = head["scope"]
        im, _ = contract.unpack(index); rm, _ = contract.unpack(result)
        im["scope"] = rm["scope"] = dict(scope)
        result = contract.pack(rm, VALID)
        im["payload"]["value"][0]["outcome"]["result"] = contract.sha(result)
        index = contract.pack(im, b"")
        head["windows"][0]["root"] = contract.sha(index)
        empty = contract.pack({"format": 2, "scope": scope, "payload": {"kind": "index", "value": []}}, b"")
        head["windows"].insert(0, {"epoch": 2, "root": contract.sha(empty), "count": 0, "result_bytes": 0})
        case = {"name": name, "scope": scope, "directory": directory, "workers": [], "objects": {}, "invocation": {}}
        case["head_key"] = f"scap-object/v1/{scope['deployment']}/{scope['tenant']}/{scope['database']}/head"
        for data in (index, result, empty): self.store(case, contract.object_key(scope, contract.sha(data)), data)
        self.store(case, case["head_key"], contract.json_bytes(head))
        case["owner"] = self.spawn(case)
        self.ack(case, {}, {}); self.ack(case, {}, {})
        return case

    def spawn(self, case, logical_worker=None):
        self.number += 1
        worker = FakeWorker(self, case, logical_worker or self.number)
        self.workers.append(worker); case["workers"].append(worker)
        return worker

    def snapshot(self, case, worker, label): return contract.value(worker.call("store_get", key=case["head_key"]))
    def begin(self, case): return object()
    def event(self, case, event, **values): self.events.append({"case": case["name"], "event": event, **values})
    def phase(self, case, label):
        self.current_phase = case["name"] + "/" + label
        return self.current_phase
    def trace(self, phase): return [v for v in self.traces if v["phase"] == phase]
    def stop(self, case, worker):
        worker.kill(); self.workers.remove(worker); case["workers"].remove(worker)
    def lose_compute(self, case):
        for worker in list(case["workers"]): self.stop(case, worker)
        for p in case["directory"].iterdir(): self.assert_no_cache(p)
    def assert_no_cache(self, path): raise AssertionError("unexpected fixture cache")
    def audit(self, case, worker, committed, session_open=False):
        for line in self.acks.read_text().splitlines():
            item = json.loads(line)
            if item["scope"] == case["scope"]: self.audited.add(item["ordinal"])
        self.event(case, "audit_called", committed=committed)
    def passed(self, case, **facts):
        self.summary["case_results"].append({"case": case["name"], "status": "passed", **facts})
        for worker in list(case["workers"]): self.stop(case, worker)


class ScenarioTests(unittest.TestCase):
    def make_suite(self, root):
        compute = root / "compute"; compute.mkdir()
        return FakeSuite(None, root, root, compute, None, types.SimpleNamespace(errors=[]), [], {})

    def test_all_twelve_scenarios_use_separate_entrypoint_workers_and_audit(self):
        with tempfile.TemporaryDirectory() as tmp:
            suite = self.make_suite(Path(tmp))
            for epoch in ("current", "closed"):
                for damage in contract.MUTATIONS: contract.run_case(suite, epoch, damage)
            contract.check_final(suite)
            self.assertEqual(len([event for event in suite.events if event["event"] == "semantic_result_refused"]), 60)
            self.assertEqual(len([event for event in suite.events if event["event"] == "audit_called"]), 12)
            self.assertFalse(suite.workers)

    def test_wrong_implementation_transport_hash_or_incomplete_checks_do_not_pass(self):
        for fault in ("old_behavior", "outer_error", "no_actual_get", "head_write", "cache_leak"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as tmp:
                suite = self.make_suite(Path(tmp)); suite.fault = fault
                with self.assertRaises(ValueError): contract.run_case(suite, "closed", "bad_magic")
                self.assertFalse(suite.summary["case_results"])

    def test_completion_guard_rejects_missing_duplicate_probe_ack_or_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            suite = self.make_suite(Path(tmp))
            for epoch in ("current", "closed"):
                for damage in contract.MUTATIONS: contract.run_case(suite, epoch, damage)
            original = copy.deepcopy(suite.summary)
            cases = [lambda: suite.summary["case_results"].pop(),
                     lambda: suite.summary["case_results"][0].update(entrypoints=[]),
                     lambda: suite.audited.remove(1),
                     lambda: suite.summary.update(ack_mismatch_count=1),
                     lambda: suite.proxy.errors.append("error")]
            for mutate in cases:
                suite.summary = copy.deepcopy(original); suite.audited = set(range(1, 31)); suite.proxy.errors = []
                mutate()
                with self.assertRaises(ValueError): contract.check_final(suite)
            suite.summary = original; suite.audited = set(range(1, 31)); suite.proxy.errors = []
            suite.acks.write_text('{"ordinal":1}\n' * 30)
            with self.assertRaises(ValueError): contract.check_final(suite)

    def test_command_line_returns_nonzero_and_preserves_blocked_report(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            root = Path(tmp)
            argv = ["retained_result_contract.py", "--worker", str(root / "missing-worker"),
                    "--weed", str(root / "missing-weed"), "--build-record", str(root / "missing-build"),
                    "--evidence", str(root / "evidence")]
            with mock.patch.object(sys, "argv", argv), self.assertRaises(SystemExit) as exit_status:
                runpy.run_module("retained_result_contract", run_name="__main__")
            self.assertEqual(exit_status.exception.code, 1)
            self.assertEqual(json.loads((root / "evidence/summary.json").read_text())["status"], "blocked")

    def test_missing_binary_is_recorded_as_blocked_never_as_completed(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            root = Path(tmp); evidence = root / "output"
            code = contract.main(["--worker", str(root / "missing"), "--weed", str(root / "weed"),
                                  "--build-record", str(root / "build.json"), "--evidence", str(evidence)])
            report = json.loads((evidence / "summary.json").read_text())
            self.assertEqual(code, 1); self.assertEqual(report["status"], "blocked")
            self.assertFalse(report["real_worker_started"])
            self.assertEqual(report["aws_standard"], "NOT_RUN")
            with self.assertRaises(FileExistsError):
                contract.main(["--worker", "x", "--weed", "x", "--build-record", "x", "--evidence", str(evidence)])


class FakeBackend:
    fail_start = False
    fail_stop = False
    created = []
    def __init__(self, binary, directory):
        self.access, self.secret, self.port = "private-test-access", "private-test-secret", 1
        self.stopped = False
        self.created.append(self)
    def start(self):
        if self.fail_start: raise TimeoutError("startup failed")
    def stop(self):
        self.stopped = True
        if self.fail_stop: raise OSError("stop failure")


class FakeProxy:
    fail_clear = False
    fail_close = False
    reported_error = False
    created = []
    def __init__(self, port, evidence):
        self.errors = ["proxy failure"] if self.reported_error else []
        self.endpoint = "http://127.0.0.1:1"
        self.closed = False
        self.created.append(self)
    def clear(self):
        if self.fail_clear: raise OSError("release failure")
    def close(self):
        self.closed = True
        if self.fail_close: raise OSError("close failure")


class RunnerTests(unittest.TestCase):
    def setUp(self):
        FakeBackend.created = []; FakeProxy.created = []

    def run_main(self, overrides=None, verify_failure=False):
        with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
            root = Path(tmp)
            for name in ("worker", "weed", "build.json"):
                (root / name).write_text("fixture test only")
            private = root / "private"; private.mkdir()
            stack.enter_context(mock.patch.object(contract.tempfile, "mkdtemp", return_value=str(private)))
            builder = types.SimpleNamespace(verify=mock.Mock(return_value={
                "binary": {"sha256": "fake-worker-hash"}, "input_sha256": "fake-source-hash", "source_commit": "fake-test"}))
            if verify_failure: builder.verify.side_effect = ValueError("mismatched build inputs")
            support = types.SimpleNamespace(Backend=FakeBackend, Proxy=FakeProxy, FaultSuite=FakeSuite)
            stack.enter_context(mock.patch.dict(sys.modules, {"build": builder, "run": support}))
            for (owner, name), value in (overrides or {}).items():
                stack.enter_context(mock.patch.object(owner, name, value))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            code = contract.main(["--worker", str(root / "worker"), "--weed", str(root / "weed"),
                                  "--build-record", str(root / "build.json"), "--evidence", str(root / "out")])
            report = json.loads((root / "out/summary.json").read_text())
            return code, report, builder.verify.call_count

    def test_runner_requires_build_identity_before_and_after_all_scenarios(self):
        code, report, calls = self.run_main()
        self.assertEqual(code, 0); self.assertEqual(report["status"], "passed")
        self.assertEqual(report["verified_entrypoint_checks"], 60)
        self.assertEqual(report["ack_audited_count"], 30); self.assertEqual(calls, 2)
        self.assertEqual(report["cleanup_errors"], [])
        self.assertTrue(FakeBackend.created[0].stopped)
        self.assertTrue(FakeProxy.created[0].closed)
        self.assertNotIn("private-test-secret", json.dumps(report))
        self.assertNotIn("private-test-access", json.dumps(report))
        self.assertIn("fault-ack-ledger.jsonl", report["artifacts"])

    def test_build_mismatch_is_blocked_before_launch(self):
        code, report, calls = self.run_main(verify_failure=True)
        self.assertEqual(code, 1); self.assertEqual(report["status"], "blocked")
        self.assertFalse(FakeBackend.created); self.assertFalse(FakeProxy.created)
        self.assertFalse(report["real_worker_started"]); self.assertEqual(calls, 1)

    def test_backend_start_failure_is_blocked_and_resources_are_closed(self):
        code, report, _ = self.run_main({(FakeBackend, "fail_start"): True})
        self.assertEqual(code, 1); self.assertEqual(report["status"], "blocked")
        self.assertTrue(FakeBackend.created[0].stopped); self.assertTrue(FakeProxy.created[0].closed)

    def test_negative_control_and_cleanup_failures_cannot_return_success(self):
        variants = (
            {(FakeSuite, "fault"): "old_behavior"},
            {(FakeSuite, "kill_error"): True},
            {(FakeProxy, "fail_clear"): True},
            {(FakeProxy, "fail_close"): True},
            {(FakeProxy, "reported_error"): True},
            {(FakeBackend, "fail_stop"): True},
        )
        for changes in variants:
            with self.subTest(changes=changes):
                code, report, _ = self.run_main(changes)
                self.assertEqual(code, 1); self.assertEqual(report["status"], "failed")
                self.assertFalse(report["production_slo_passed"])

    def test_instrumentation_and_disabled_assertions_cannot_certify_integration(self):
        cases = ({"LLVM_PROFILE_FILE": "x"}, {"RUSTFLAGS": "-C instrument-coverage"},
                 {"CARGO_ENCODED_RUSTFLAGS": "-C\x1finstrument-coverage"})
        for environment in cases:
            with mock.patch.dict(contract.os.environ, environment, clear=True):
                code, report, _ = self.run_main()
            self.assertEqual(code, 1); self.assertEqual(report["status"], "blocked")
        with mock.patch.object(contract.sys, "flags", types.SimpleNamespace(optimize=1)):
            code, report, _ = self.run_main()
        self.assertEqual(code, 1); self.assertEqual(report["status"], "blocked")


if __name__ == "__main__":
    unittest.main()
