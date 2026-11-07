"""Lightweight negative controls for acceptance bookkeeping and provenance.

These tests call the real build verifier, audit function and CLI preflight.
Synthetic ledgers exercise bookkeeping only: no daemon, S3 backend, SQL engine,
or SDK transport is started, and these results are not integration evidence.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent


def load_module(name, path):
    specification = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


BUILD = load_module("scap_service_build_controls", HERE / "build.py")
NETWORK = load_module("scap_network_controls_support", HERE.parent / "object-network" / "run.py")
# run.py imports its sibling build and the object-network controller named run.
# Bind their actual files explicitly so unittest discovery order cannot select
# an unrelated module with either short name.
with mock.patch.dict(sys.modules, {"build": BUILD, "run": NETWORK}), \
        mock.patch.object(sys, "path", list(sys.path)):
    RUN = load_module("scap_service_run_controls", HERE / "run.py")


def clean_environment():
    environment = dict(os.environ)
    for key in ("PYTHONOPTIMIZE", "LLVM_PROFILE_FILE", "NODE_V8_COVERAGE",
                "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"):
        environment.pop(key, None)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return environment


class CliPreflightControls(unittest.TestCase):
    def test_optimized_python_is_refused_before_argument_handling(self):
        for script in ("build.py", "run.py"):
            for flags, optimize in ((["-O"], None), ([], "1")):
                with self.subTest(script=script, flags=flags, environment=optimize):
                    environment = clean_environment()
                    if optimize is not None:
                        environment["PYTHONOPTIMIZE"] = optimize
                    completed = subprocess.run(
                        [sys.executable, *flags, str(HERE / script), "--help"],
                        env=environment, capture_output=True, text=True, timeout=10,
                    )
                    self.assertNotEqual(completed.returncode, 0)
                    self.assertIn("validation requires Python assertions", completed.stderr)
                    self.assertNotIn("usage:", completed.stdout)

    def poison_case(self, script, variable, value):
        with tempfile.TemporaryDirectory(prefix="scap-controller-preflight-") as temporary:
            directory = Path(temporary)
            executable_directory = directory / "bin"
            executable_directory.mkdir()
            marker = directory / "unexpected-child"
            # Even a regressed guard cannot start a real tool or backend. Any
            # invocation is observable and makes the negative control fail.
            for name in ("cargo", "rustc", "git", "node", "weed", "scapd"):
                executable = executable_directory / name
                executable.write_text(
                    '#!/bin/sh\nprintf "unexpected child\\n" >> "$SCAP_CONTROL_MARKER"\nexit 97\n'
                )
                executable.chmod(0o700)
            environment = clean_environment()
            environment.update(PATH=str(executable_directory), SCAP_CONTROL_MARKER=str(marker))
            environment[variable] = value
            evidence = directory / "evidence"
            arguments = ["--evidence", str(evidence)]
            if script == "build.py":
                arguments += ["--target-dir", str(directory / "target")]
            else:
                arguments += ["--server", str(executable_directory / "scapd"),
                              "--weed", str(executable_directory / "weed"),
                              "--node", str(executable_directory / "node")]
                if script == "catalogue_contract.py":
                    arguments += ["--build-record", str(directory / "missing-build.json")]
                else:
                    arguments += ["--diagnostic"]
            completed = subprocess.run(
                [sys.executable, str(HERE / script), *arguments], env=environment,
                capture_output=True, text=True, timeout=10,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertFalse(marker.exists(), "preflight invoked a build or runtime tool")
            if script == "build.py":
                self.assertIn("AssertionError", completed.stderr)
                self.assertFalse(evidence.exists())
            else:
                summary = json.loads((evidence / "summary.json").read_text())
                self.assertEqual(summary["status"], "blocked")
                self.assertIn("AssertionError", summary["error"])
                self.assertEqual(summary["cleanup_errors"], [])
                self.assertNotIn("tools", summary)
                self.assertNotIn("compute_loss", summary)

    def test_build_refuses_instrumented_rust_before_any_tool_is_started(self):
        for variable, value in (("LLVM_PROFILE_FILE", "forbidden-%p.profraw"),
                                ("RUSTFLAGS", "-C instrument-coverage"),
                                ("CARGO_ENCODED_RUSTFLAGS", "-C\x1finstrument-coverage")):
            with self.subTest(variable=variable):
                self.poison_case("build.py", variable, value)

    def test_run_refuses_all_unit_profiles_before_any_tool_is_started(self):
        for variable, value in (("LLVM_PROFILE_FILE", "forbidden-%p.profraw"),
                                ("NODE_V8_COVERAGE", "forbidden-v8-profiles"),
                                ("RUSTFLAGS", "-Cinstrument-coverage"),
                                ("CARGO_ENCODED_RUSTFLAGS", "-C\x1finstrument-coverage")):
            with self.subTest(variable=variable):
                self.poison_case("run.py", variable, value)


class BuildReceiptControls(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="scap-build-receipt-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.source = self.directory / "source"
        self.source.mkdir()
        self.paths = ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml",
                      "crates/scap-service/src/main.rs", "crates/scap-sqlite/src/lib.rs",
                      "sdk/node/src/client.js", "sdk/node/src/client.d.ts", "sdk/node/package.json",
                      "sdk/node-codec/src/codec.js", "experiments/object-service/probe.mjs",
                      "experiments/object-service/run.py", "experiments/object-network/run.py")
        for relative in self.paths:
            path = self.source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("original source bytes\n")
        self.binary = self.directory / "scapd"
        self.binary.write_bytes(b"original executable bytes")
        archive = self.directory / "libsql.a"
        archive.write_bytes(b"native archive fixture")
        self.root_patch = mock.patch.object(BUILD, "ROOT", self.source)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)
        self.value = {"schema": 1, "status": "passed", "profile": "release",
                      "inputs": BUILD.inputs(), "node": "v22.16.0",
                      "binary": {"path": str(self.binary), "sha256": BUILD.digest(self.binary)},
                      "native_archives": {str(archive): BUILD.digest(archive)}}
        self.record = self.directory / "build.json"
        self.record.write_text(json.dumps(self.value))

    def test_matching_receipt_is_accepted_with_complete_source_inventory(self):
        self.assertEqual(set(BUILD.inputs()), set(self.paths))
        self.assertEqual(BUILD.verify(self.record, self.binary), self.value)

    def test_failed_debug_or_unbound_receipts_are_refused(self):
        for changes in ({"status": "failed"}, {"profile": "debug"}, {"inputs": {}},
                        {"binary": {"sha256": "0" * 64}}, {"native_archives": {}}):
            with self.subTest(changes=changes):
                self.record.write_text(json.dumps({**self.value, **changes}))
                with self.assertRaises(AssertionError):
                    BUILD.verify(self.record, self.binary)

    def test_modifying_any_bound_source_is_refused(self):
        for relative in self.paths:
            with self.subTest(path=relative):
                path = self.source / relative
                path.write_text("changed after build\n")
                with self.assertRaisesRegex(AssertionError, "source changed"):
                    BUILD.verify(self.record, self.binary)
                path.write_text("original source bytes\n")

    def test_adding_or_removing_source_is_refused(self):
        path = self.source / "sdk/node/src/added.js"
        path.write_text("new executable input\n")
        with self.assertRaisesRegex(AssertionError, "source changed"):
            BUILD.verify(self.record, self.binary)
        path.unlink()
        (self.source / "crates/scap-service/src/main.rs").unlink()
        with self.assertRaisesRegex(AssertionError, "source changed"):
            BUILD.verify(self.record, self.binary)

    def test_changed_or_missing_executable_is_refused(self):
        self.binary.write_bytes(b"changed executable bytes")
        with self.assertRaisesRegex(AssertionError, "binary changed"):
            BUILD.verify(self.record, self.binary)
        self.binary.unlink()
        with self.assertRaises(FileNotFoundError):
            BUILD.verify(self.record, self.binary)


def ledger():
    """Minimal synthetic records for audit's bookkeeping, not protocol proofs."""
    raw = bytes.fromhex("534341505245533100000000")
    acks = []
    for number in range(10):
        other_tenant = number == 9
        scope = {"deployment": "1", "tenant": "8" if other_tenant else "7",
                 "database": "202" if other_tenant else "101", "incarnation": "1", "generation": "1"}
        request = {"epoch": "1", "id": "1" if other_tenant else str(number + 1),
                   "principal": "22" if other_tenant else "11", "fingerprint": "0" * 64}
        acks.append({"request": json.dumps({"scope": scope, "request": request}),
                     "receipt": {"scope": scope, "request": request},
                     "raw": base64.b64encode(raw).decode(), "raw_sha256": hashlib.sha256(raw).hexdigest()})
    phases = [{"phase": phase} for phase in
              ("initialize", "concurrent_create", "unknown_write", "resolve_unknown",
               "blackhole", "takeover", "recover")]
    phases[2]["sdk_http_attempts"] = 1
    phases[-1].update(acknowledgements_audited=18, rows_verified=9, mismatch_count=0,
                      other_tenant_rows_verified=1, recovered_data_databases=2,
                      uncertain_original_result_preserved=True)
    return {"acks.jsonl": acks, "duplicate-acks.jsonl": copy.deepcopy(acks[1:9]),
            "inputs.jsonl": [{"request": ack["request"]} for ack in acks],
            "client-phases.jsonl": phases}


class AcknowledgementAuditControls(unittest.TestCase):
    def audit(self, entries):
        with tempfile.TemporaryDirectory(prefix="scap-ack-audit-") as temporary:
            evidence = Path(temporary)
            for name, rows in entries.items():
                (evidence / name).write_text("".join(json.dumps(row) + "\n" for row in rows))
            return RUN.audit(evidence)

    def test_complete_denominator_and_both_recovered_tenants_are_reported(self):
        result = self.audit(ledger())
        self.assertEqual(result["unique_acknowledged_requests"], 10)
        self.assertEqual(result["duplicate_execute_responses"], 8)
        self.assertEqual(result["successful_execute_responses"], 18)
        self.assertEqual(result["rows_by_tenant"], {"7": 9, "8": 1})
        self.assertEqual(result["business_rows"], 10)
        self.assertEqual(result["recovered_data_databases"], 2)
        self.assertIs(result["outcome_unknown_kept_separate"], True)

    def test_omitted_or_extra_successful_responses_cannot_shrink_the_denominator(self):
        for name, extra in (("acks.jsonl", False), ("acks.jsonl", True),
                            ("duplicate-acks.jsonl", False), ("duplicate-acks.jsonl", True)):
            with self.subTest(ledger=name, extra=extra):
                entries = ledger()
                if extra:
                    entries[name].append(copy.deepcopy(entries[name][0]))
                else:
                    entries[name].pop()
                entries["client-phases.jsonl"][-1]["acknowledgements_audited"] = (
                    len(entries["acks.jsonl"]) + len(entries["duplicate-acks.jsonl"]))
                with self.assertRaises(AssertionError):
                    self.audit(entries)

    def test_duplicate_execution_must_retain_the_complete_original_ack(self):
        for field, value in (("raw", "changed"), ("raw_sha256", "0" * 64),
                             ("request", "changed"), ("receipt", {})):
            with self.subTest(field=field):
                entries = ledger()
                entries["duplicate-acks.jsonl"][0][field] = value
                with self.assertRaisesRegex(AssertionError, "exact original ACK"):
                    self.audit(entries)

    def test_duplicate_primary_identity_and_ack_without_input_are_refused(self):
        entries = ledger()
        entries["acks.jsonl"][1] = copy.deepcopy(entries["acks.jsonl"][0])
        with self.assertRaisesRegex(AssertionError, "duplicate ACK ledger entry"):
            self.audit(entries)
        entries = ledger()
        entries["inputs.jsonl"].pop()
        with self.assertRaisesRegex(AssertionError, "ACK without prior recorded input"):
            self.audit(entries)

    def test_changed_scope_request_or_result_bytes_are_refused(self):
        for fault in ("scope", "request", "raw_hash", "raw_magic", "base64"):
            with self.subTest(fault=fault):
                entries = ledger()
                ack = entries["acks.jsonl"][0]
                if fault in ("scope", "request"):
                    ack["receipt"] = {**ack["receipt"], fault: {}}
                elif fault == "raw_hash":
                    ack["raw_sha256"] = "0" * 64
                elif fault == "raw_magic":
                    raw = b"incorrect frame"
                    ack.update(raw=base64.b64encode(raw).decode(), raw_sha256=hashlib.sha256(raw).hexdigest())
                else:
                    ack["raw"] = "%%%"
                with self.assertRaises((AssertionError, ValueError)):
                    self.audit(entries)

    def test_missing_or_reordered_phase_is_refused(self):
        for fault in ("missing", "reordered"):
            with self.subTest(fault=fault):
                entries = ledger()
                phases = entries["client-phases.jsonl"]
                if fault == "missing":
                    phases.pop(3)
                else:
                    phases[0], phases[1] = phases[1], phases[0]
                with self.assertRaises(AssertionError):
                    self.audit(entries)

    def test_false_recovery_counts_or_unknown_replay_cannot_pass(self):
        cases = ((2, "sdk_http_attempts", 2), (-1, "acknowledgements_audited", 10),
                 (-1, "rows_verified", 8), (-1, "mismatch_count", 1),
                 (-1, "other_tenant_rows_verified", 0), (-1, "recovered_data_databases", 1),
                 (-1, "uncertain_original_result_preserved", False))
        for phase, field, value in cases:
            with self.subTest(field=field, value=value):
                entries = ledger()
                entries["client-phases.jsonl"][phase][field] = value
                with self.assertRaises(AssertionError):
                    self.audit(entries)


if __name__ == "__main__":
    unittest.main()
