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

import service_oracle


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
                      "crates/scap-service/Cargo.toml", "crates/scap-service/src/main.rs", "crates/scap-sqlite/src/lib.rs",
                      "sdk/node/src/client.js", "sdk/node/src/client.d.ts", "sdk/node/package.json",
                      "sdk/node-codec/src/codec.js", "experiments/object-service/probe.mjs",
                      "experiments/object-service/run.py", "experiments/object-network/run.py")
        for relative in self.paths:
            path = self.source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("original source bytes\n")
        self.target = self.directory / "target"
        self.binary = self.target / "release" / "scapd"
        self.binary.parent.mkdir(parents=True)
        self.binary.write_bytes(b"original executable bytes")
        self.native = self.target / "release" / "build" / "libsql-ffi-fixture" / "out"
        self.native.mkdir(parents=True)
        self.archive = self.native / "liblibsql.a"
        self.archive.write_bytes(b"native archive fixture")
        self.root_patch = mock.patch.object(BUILD, "ROOT", self.source)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)
        self.value = {"schema": 1, "status": "passed", "profile": "release",
                      "inputs": BUILD.inputs(), "node": "v22.16.0",
                      "command":["cargo","+1.90.0","build","--release","--locked","-p","scap-service",
                                 "--bin","scapd","--message-format=json-render-diagnostics"],
                      "source_commit":"f"*40,"exit_code":0,
                      "source_root":str(self.source),
                      "rustc":"rustc 1.90.0 (1159e78c4 2025-09-14)\nrelease: 1.90.0\n",
                      "binary": {"path": str(self.binary), "sha256": BUILD.digest(self.binary)},
                      "native_archives": {str(self.archive): BUILD.digest(self.archive)}}
        self.events=[{"reason":"build-script-executed","package_id":"registry+fixture#libsql-ffi@0.10.0","out_dir":str(self.native),
                      "linked_libs":["static=libsql"],"linked_paths":["native="+str(self.native)]},
                     {"reason":"compiler-artifact","target":{"name":"scapd","kind":["bin"],"src_path":str(self.source/"crates/scap-service/src/main.rs")},
                      "manifest_path":str(self.source/"crates/scap-service/Cargo.toml"),"executable":str(self.binary),"filenames":[str(self.binary)],
                      "profile":{"opt_level":"3","debuginfo":0,"debug_assertions":False,"overflow_checks":False,"test":False}},
                     {"reason":"build-finished","success":True}]
        (self.directory/"cargo.stdout.jsonl").write_text("".join(json.dumps(event)+"\n" for event in self.events))
        (self.directory/"cargo.stderr.log").write_text("synthetic original compiler stderr\n")
        for name in ("cargo.stdout.jsonl","cargo.stderr.log"):
            self.value[name+"_sha256"]=BUILD.digest(self.directory/name)
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

    def capture(self):
        directory=Path(tempfile.mkdtemp(prefix="run-",dir=self.directory))
        BUILD.capture_receipt(self.record,self.binary,directory)
        return directory

    def check(self,directory,**options):
        return service_oracle.build_receipt(directory,True,source_root=self.source,**options)

    def test_archived_original_source_and_raw_cargo_are_independently_recomputed(self):
        directory=self.capture()
        result=self.check(directory)
        self.assertEqual(result["verification_scope"],"full")
        self.assertEqual(result["source_files_verified"],len(self.paths))
        self.assertEqual(result["retrieved_artifacts"],[str(self.binary),str(self.archive)])
        facts=[{"event":"service_started","binary":copy.deepcopy(self.value["binary"])} for _ in range(3)]
        self.assertEqual(service_oracle.process_build_binding(facts,result)["services_bound_to_original_executable"],3)
        facts[-1]["binary"]["sha256"]="a"*64
        with self.assertRaisesRegex(ValueError,"another release binary"):
            service_oracle.process_build_binding(facts,result)

    def test_status_passed_cannot_replace_original_successful_cargo_and_artifact_evidence(self):
        for fault in ("exit101","exit_bool","node","rustc","command","hash","missing_archive",
                      "stdout","stderr","failed_event","missing_event","after_finished","wrong_binary","wrong_native",
                      "source_manifest","source_archive","source_omission"):
            directory=self.capture();path=directory/"build-receipt.json";value=json.loads(path.read_text())
            if fault=="exit101":value["exit_code"]=101
            elif fault=="exit_bool":value["exit_code"]=False
            elif fault=="node":value["node"]="v24.22.1"
            elif fault=="rustc":value["rustc"]="fixture status passed"
            elif fault=="command":value["command"].remove("--release")
            elif fault=="hash":value["binary"]["sha256"]="not-hex-"*8
            elif fault=="missing_archive":del value["archived_evidence"]
            elif fault in ("stdout","stderr"):(directory/("build-cargo.stdout.jsonl" if fault=="stdout" else "build-cargo.stderr.log")).write_bytes(b"changed\n")
            elif fault in ("failed_event","missing_event","after_finished","wrong_binary","wrong_native"):
                events=copy.deepcopy(self.events)
                if fault=="failed_event":events[-1]["success"]=False
                elif fault=="missing_event":events.pop()
                elif fault=="after_finished":events.append({"reason":"compiler-artifact","executable":None})
                elif fault=="wrong_binary":events[1]["executable"]=str(self.binary)+"-other"
                else:events[0]["out_dir"]=str(self.directory/"unrelated"/"out")
                output=directory/"build-cargo.stdout.jsonl";output.write_text("".join(json.dumps(event)+"\n" for event in events))
                value["cargo.stdout.jsonl_sha256"]=BUILD.digest(output)
            elif fault=="source_manifest":(directory/"build-source-manifest.json").write_text("{}\n")
            elif fault=="source_archive":
                archive=directory/"build-source.tar";raw=bytearray(archive.read_bytes());raw[512]^=1;archive.write_bytes(raw)
                value["archived_evidence"]["source_archive_sha256"]=BUILD.digest(archive)
            else:
                del value["inputs"]["sdk/node/src/client.js"]
                manifest=directory/"build-source-manifest.json"
                manifest.write_text(json.dumps({"schema":1,"source_commit":value["source_commit"],"inputs":value["inputs"]}))
                value["archived_evidence"]["source_manifest_sha256"]=BUILD.digest(manifest)
            path.write_text(json.dumps(value))
            with self.subTest(fault=fault),self.assertRaises((ValueError,KeyError)):
                self.check(directory)

    def test_native_and_binary_changes_fail_even_with_unchanged_passed_receipt(self):
        directory=self.capture()
        for artifact in (self.binary,self.archive):
            original=artifact.read_bytes();artifact.write_bytes(original+b"changed")
            with self.subTest(path=artifact),self.assertRaisesRegex(ValueError,"bytes differ"):
                self.check(directory)
            artifact.write_bytes(original)
        extra=self.native/"unrecorded.a";extra.write_bytes(b"unrecorded native archive")
        with self.assertRaisesRegex(ValueError,"inventory differs"):self.check(directory)

    def test_offline_missing_artifacts_are_explicit_partial_and_never_full_acceptance(self):
        directory=self.capture()
        self.target.rename(self.directory/"relocated-target")
        with self.assertRaisesRegex(ValueError,"unavailable"):self.check(directory)
        result=self.check(directory,require_artifacts=False)
        self.assertEqual(result["verification_scope"],"archived_source_and_cargo_only")
        self.assertEqual(result["executable_native_bytes"],"NOT_AVAILABLE")
        self.assertEqual(set(result["unavailable_artifacts"]),{str(self.binary),str(self.archive)})
        (self.source/"Cargo.lock").write_text("a later checkout\n")
        result=self.check(directory,require_artifacts=False)
        self.assertFalse(result["local_source_manifest_matches"])


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
