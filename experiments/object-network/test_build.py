"""Build-evidence controls with synthetic Cargo events, never native acceptance.

The compiler and version commands are mocked. Real temporary files and fsync
calls exercise publication and failure handling, not Rust, SQLite or S3.
The service build controls reuse this test-only case matrix.
"""
from __future__ import annotations

import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent


def load_module(name, path):
    specification = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


class BuildEvidenceCases:
    """Mixin: every inherited case invokes the real selected build controller."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="scap-build-evidence-control-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.source = self.directory / "source"
        for relative in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml",
                         "crates/scap-service/Cargo.toml", "crates/scap-service/src/main.rs", "crates/scap-sql/src/lib.rs",
                         "experiments/object-network/Cargo.toml", "experiments/object-network/Cargo.lock",
                         "experiments/object-network/src/main.rs", "experiments/object-capacity/run.py",
                         "experiments/object-service/build.py", "sdk/node/src/client.js"):
            path = self.source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("synthetic source fixture, not executable product code\n")
        patch = mock.patch.object(self.builder, "ROOT", self.source)
        patch.start()
        self.addCleanup(patch.stop)
        self.target = self.directory / "isolated-target"
        self.binary = self.target / "release" / self.target_name
        self.binary.parent.mkdir(parents=True)
        self.binary.write_bytes(b"synthetic compiler output, not an executable")
        self.native = self.target / "release" / "build" / "libsql-ffi-fixture" / "out"
        self.native.mkdir(parents=True)
        self.archive = self.native / "liblibsql.a"
        self.archive.write_bytes(b"synthetic native archive, not SQLite")
        self.events = [
            {"reason": "build-script-executed", "package_id": "git+https://example.invalid/libsql#libsql-ffi@0.10.0",
             "out_dir": str(self.native), "linked_libs":["static=libsql"], "linked_paths":["native="+str(self.native)]},
            {"reason": "compiler-artifact", "target": {"name": self.target_name, "kind": ["bin"],
             "src_path":str(self.source/("crates/scap-service/src/main.rs" if self.target_name=="scapd" else "experiments/object-network/src/main.rs"))},
             "manifest_path":str(self.source/("crates/scap-service/Cargo.toml" if self.target_name=="scapd" else "experiments/object-network/Cargo.toml")),
             "profile":{"opt_level":"3","debuginfo":0,"debug_assertions":False,"overflow_checks":False,"test":False},
             "filenames":[str(self.binary)], "executable": str(self.binary)},
            {"reason": "build-finished", "success": True},
        ]
        self.stdout = self.encode(self.events)
        self.stderr = b"synthetic compiler stderr, not a build result\n"
        self.returncode = 0
        self.on_run = lambda: None
        self.tool_error = None
        self.run_error = None
        self.fail_sync = {}
        self.invocations = 0
        self.real_fsync = os.fsync

    @staticmethod
    def encode(events):
        return b"".join(json.dumps(event).encode() + b"\n" for event in events)

    def compiler(self, command, *, cwd, env, stdout, stderr):
        self.assertEqual(command[:4], ["cargo", "+1.90.0", "build", "--release"])
        self.assertIn("--locked", command)
        self.assertIn("--message-format=json-render-diagnostics", command)
        self.assertEqual(cwd, self.source)
        self.assertEqual(env["CARGO_TARGET_DIR"], str(self.target))
        # Deliberately leave Python buffering to the controller. Its explicit
        # flush must precede fsync and the first read of Cargo's output.
        stdout.write(self.stdout)
        stderr.write(self.stderr)
        self.on_run()
        if self.run_error:
            raise self.run_error
        return SimpleNamespace(returncode=self.returncode)

    def version(self, command, **kwargs):
        if self.tool_error:
            raise self.tool_error
        return {"git":"f"*40+"\n","rustc":"rustc 1.90.0 (1159e78c4 2025-09-14)\nrelease: 1.90.0\n",
                "cargo":"cargo 1.90.0 (synthetic version witness)\n","node":"v22.16.0\n","cc":"synthetic native compiler identity\n"}[command[0]]

    def synced(self, descriptor):
        opened = os.fstat(descriptor)
        paths = [self.evidence / name for name in ("cargo.stdout.jsonl", "cargo.stderr.log", "build.json")]
        path = next(path for path in paths if path.exists()
                    and (path.stat().st_dev, path.stat().st_ino) == (opened.st_dev, opened.st_ino))
        self.syncs.append((path.name, path.read_bytes()))
        remaining = self.fail_sync.get(path.name, 0)
        if remaining:
            self.fail_sync[path.name] = remaining - 1 if remaining > 0 else remaining
            raise OSError("injected fsync failure: " + path.name)
        self.real_fsync(descriptor)

    def invoke(self):
        self.invocations += 1
        self.evidence = self.directory / f"evidence-{self.invocations}"
        self.syncs = []
        captured = io.StringIO()
        try:
            with mock.patch.dict(self.builder.os.environ, {}, clear=True), \
                    mock.patch.object(self.builder.subprocess, "run", side_effect=self.compiler), \
                    mock.patch.object(self.builder.subprocess, "check_output", side_effect=self.version), \
                    mock.patch.object(self.builder.os, "fsync", side_effect=self.synced), \
                    contextlib.redirect_stdout(captured):
                getattr(self.builder, self.entry)(SimpleNamespace(
                    evidence=self.evidence, target_dir=self.target))
        finally:
            self.printed = captured.getvalue()
        return json.loads((self.evidence / "build.json").read_text())

    def failed(self, message, exception=AssertionError):
        with self.assertRaisesRegex(exception, message):
            self.invoke()
        record = json.loads((self.evidence / "build.json").read_text())
        self.assertEqual(record["status"], "failed")
        self.assertIn(message, record.get("error", "") + record.get("receipt_error", ""))
        self.assertEqual(self.printed, "")
        with self.assertRaises(AssertionError):
            self.builder.verify(self.evidence / "build.json", self.binary)
        return record

    def test_complete_build_syncs_both_logs_before_reading_and_syncs_the_receipt(self):
        record = self.invoke()
        self.assertEqual(record["status"], "passed")
        self.assertEqual(record["exit_code"], 0)
        self.assertEqual(record["binary"], {"path": str(self.binary), "sha256": self.builder.digest(self.binary)})
        self.assertEqual(record["native_archives"], {str(self.archive): self.builder.digest(self.archive)})
        self.assertEqual([name for name, _ in self.syncs], ["cargo.stdout.jsonl", "cargo.stderr.log", "build.json"])
        self.assertEqual(self.syncs[0][1], self.stdout)
        self.assertEqual(self.syncs[1][1], self.stderr)
        self.assertEqual(json.loads(self.syncs[2][1]), record)
        self.assertEqual(record[self.stdout_hash], self.builder.digest(self.evidence / "cargo.stdout.jsonl"))
        self.assertEqual(record[self.stderr_hash], self.builder.digest(self.evidence / "cargo.stderr.log"))
        self.assertEqual(self.builder.verify(self.evidence / "build.json", self.binary), record)

    def test_successful_process_exit_cannot_certify_incomplete_or_ambiguous_event_logs(self):
        cases = [
            (self.encode(self.events[:-1]), "missing final successful"),
            (self.stdout[:-1], "incomplete Cargo"),
            (self.stdout[:-3], "incomplete Cargo"),
            (self.encode(self.events + [self.events[-1]]), "missing final successful"),
            (self.encode(self.events + [{"reason": "compiler-artifact", "executable": None}]), "missing final successful"),
            (self.encode(self.events[:-1] + [{"reason": "build-finished", "success": False}]), "missing final successful"),
            (self.encode(self.events[:-1] + [{"reason": "build-finished", "success": 1}]), "missing final successful"),
            (self.encode([[]] + self.events), "invalid Cargo event"),
            (b"", "incomplete Cargo"),
        ]
        for raw, message in cases:
            with self.subTest(raw=raw, message=message):
                self.stdout = raw
                record = self.failed(message)
                self.assertEqual(record["exit_code"], 0)
                self.assertEqual((self.evidence / "cargo.stdout.jsonl").read_bytes(), raw)

    def test_executable_and_native_artifacts_must_each_be_unique_and_exact(self):
        cases = []
        cases.append(([self.events[0], self.events[2]], "missing or ambiguous"))
        cases.append((self.events[:2] + [self.events[1], self.events[2]], "missing or ambiguous"))
        for field, value, message in (
                ("name", "different-binary", "unexpected executable target"),
                ("kind", ["example"], "unexpected executable target")):
            events = copy.deepcopy(self.events)
            events[1]["target"][field] = value
            cases.append((events, message))
        events = copy.deepcopy(self.events)
        events[1]["executable"] = str(self.target / "debug" / self.target_name)
        cases.append((events, "executable outside"))
        cases.append((self.events[1:], "missing or duplicate native"))
        cases.append(([self.events[0]] + self.events, "missing or duplicate native"))
        events = copy.deepcopy(self.events)
        events[0]["package_id"] = "git+https://example.invalid/libsql#another-libsql-ffi@0.10.0"
        cases.append((events, "missing or duplicate native"))
        events = copy.deepcopy(self.events)
        events[0]["out_dir"] = str(self.directory / "different-target" / "out")
        cases.append((events, "native output outside"))
        for events, message in cases:
            with self.subTest(events=events, message=message):
                self.stdout = self.encode(events)
                self.failed(message)

    def test_nonzero_compiler_exit_preserves_a_failed_receipt_even_with_a_success_event(self):
        self.returncode = 17
        record = self.failed("build")
        self.assertEqual(record["exit_code"], 17)
        self.assertEqual((self.evidence / "cargo.stderr.log").read_bytes(), self.stderr)

    def test_source_drift_during_compilation_is_preserved_as_failure(self):
        self.on_run = lambda: (self.source / "Cargo.lock").write_text("changed during fake build\n")
        self.failed("source changed")

    def test_missing_executable_and_native_archive_are_not_certified(self):
        self.binary.unlink()
        self.failed("No such file", FileNotFoundError)
        self.binary.write_bytes(b"synthetic compiler output, not an executable")
        self.archive.unlink()
        self.failed(self.missing_archive)

    def test_native_archive_cannot_escape_the_recorded_build_directory(self):
        outside = self.directory / "unrelated.a"
        outside.write_bytes(b"unrelated synthetic archive")
        (self.native / "escaped.a").symlink_to(outside)
        self.failed("native archive escaped")

    def test_stdout_and_stderr_sync_failure_precede_event_parsing_and_keep_failed_receipts(self):
        for name in ("cargo.stdout.jsonl", "cargo.stderr.log"):
            with self.subTest(log=name), mock.patch.object(self.builder, "cargo_events", wraps=self.builder.cargo_events) as parse:
                self.fail_sync = {name: 1}
                self.failed("injected fsync failure", OSError)
                self.assertEqual(parse.call_count, 0)
                self.assertEqual([item for item, _ in self.syncs[:2]], ["cargo.stdout.jsonl", "cargo.stderr.log"])

    def test_receipt_sync_errors_never_leave_readable_success_even_when_sync_keeps_failing(self):
        for attempts in (1, -1):
            with self.subTest(failures=attempts):
                self.fail_sync = {"build.json": attempts}
                record = self.failed("injected fsync failure", OSError)
                self.assertEqual(record["exit_code"], 0)
                statuses = [json.loads(raw)["status"] for name, raw in self.syncs if name == "build.json"]
                self.assertEqual(statuses, ["passed", "failed"])

    def test_subprocess_start_failure_still_syncs_logs_and_preserves_the_original_failure(self):
        self.run_error = OSError("injected compiler invocation failure")
        record = self.failed("injected compiler invocation failure", OSError)
        self.assertNotIn("exit_code", record)
        self.assertEqual([name for name, _ in self.syncs], ["cargo.stdout.jsonl", "cargo.stderr.log", "build.json"])

    def test_version_probe_failure_has_a_synced_failed_receipt_without_a_compile_claim(self):
        self.tool_error = OSError("injected version invocation failure")
        record = self.failed("injected version invocation failure", OSError)
        self.assertNotIn("exit_code", record)
        self.assertFalse((self.evidence / "cargo.stdout.jsonl").exists())
        self.assertEqual([name for name, _ in self.syncs], ["build.json"])

    def test_optimized_python_refuses_the_controller_before_tools_or_argument_handling(self):
        for arguments, environment in ((["-O"], {}), ([], {"PYTHONOPTIMIZE": "1"})):
            with self.subTest(arguments=arguments, environment=environment):
                completed = subprocess.run([sys.executable, *arguments, str(Path(self.builder.__file__)), "--help"],
                                           env=environment, capture_output=True, text=True, timeout=10)
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn("validation requires Python assertions", completed.stderr)
                self.assertNotIn("usage:", completed.stdout)


class NetworkBuildEvidenceTests(BuildEvidenceCases, unittest.TestCase):
    builder = load_module("scap_network_build_sync_controls", HERE / "build.py")
    entry = "run"
    target_name = "scap-object-network"
    stdout_hash = "build_stdout_sha256"
    stderr_hash = "build_stderr_sha256"
    missing_archive = "no actual native libSQL archive"


if __name__ == "__main__":
    unittest.main()
