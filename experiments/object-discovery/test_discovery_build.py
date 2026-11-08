"""Synthetic raw Cargo/source/native receipt controls; no real build claim."""
from __future__ import annotations

import copy
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from deployment_recovery_imports import local

audit = local("discovery_build_audit")


class BuildIdentityControls(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source, self.evidence, self.target = (self.root / name for name in ("source", "evidence", "target"))
        self.source.mkdir(); self.evidence.mkdir()
        for name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "crates/scap-object/src/lib.rs",
                     "experiments/object-discovery/Cargo.toml", "experiments/object-discovery/Cargo.lock",
                     "experiments/object-discovery/src/main.rs", "experiments/object-discovery/discovery_oracle.py"):
            path = self.source / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text("unit source " + name)
        self.binary = self.target / "release/scap-object-discovery"
        self.native = self.target / "release/build/libsql-ffi-unit/out/liblibsql.a"
        for path in (self.binary, self.native):
            path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(b"unit artifact " + path.name.encode())
        tools = {}
        for name in ("rustc", "cargo"):
            path = self.root / name; path.write_bytes(b"unit compiler " + name.encode())
            tools[name] = {"path": str(path), "sha256": audit.file_digest(path)}
        inputs = audit.source_inventory(self.source, "discovery")
        commit = "a" * 40
        manifest = self.evidence / "build-source-manifest.json"
        manifest.write_text(json.dumps({"schema": 1, "source_commit": commit, "inputs": inputs}) + "\n")
        source_archive = self.evidence / "build-source.tar"
        with tarfile.open(source_archive, "w") as archive:
            for name in inputs:
                encoded = (self.source / name).read_bytes(); member = tarfile.TarInfo(name); member.size = len(encoded)
                archive.addfile(member, io.BytesIO(encoded))
        self.events = [
            {"reason": "build-script-executed", "package_id": "registry+unit#libsql-ffi@0.9.29", "out_dir": str(self.native.parent),
             "linked_libs": ["static=libsql"], "linked_paths": ["native=" + str(self.native.parent)]},
            {"reason": "compiler-artifact", "executable": str(self.binary), "filenames": [str(self.binary)],
             "manifest_path": str(self.source / "experiments/object-discovery/Cargo.toml"),
             "target": {"name": "scap-object-discovery", "kind": ["bin"], "src_path": str(self.source / "experiments/object-discovery/src/main.rs")},
             "profile": {"opt_level": "3", "debuginfo": 0, "debug_assertions": False, "overflow_checks": False, "test": False}},
            {"reason": "build-finished", "success": True}]
        self.value = {"schema": 1, "status": "passed", "profile": "release", "exit_code": 0, "source_root": str(self.source),
                      "source_commit": commit, "source_dirty": False, "incremental": "0", "inputs": inputs,
                      "input_sha256": audit.hashlib.sha256(json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
                      "versions": {"rustc": "rustc 1.90.0 (1159e78c4 2025-09-14)\nrelease: 1.90.0", "cargo": "cargo 1.90.0 unit", "cc": "unit cc"},
                      "command": ["cargo", "+1.90.0", "build", "--release", "--frozen", "--manifest-path", "experiments/object-discovery/Cargo.toml", "--message-format=json-render-diagnostics"],
                      "binary": {"path": str(self.binary), "sha256": audit.file_digest(self.binary)},
                      "native_archives": {str(self.native): audit.file_digest(self.native)}, "tool_identity": tools,
                      "archived_evidence": {"schema": 1, "source_manifest": manifest.name, "source_archive": source_archive.name,
                                            "cargo_stdout": "build-cargo.stdout.jsonl", "cargo_stderr": "build-cargo.stderr.log",
                                            "source_manifest_sha256": audit.file_digest(manifest), "source_archive_sha256": audit.file_digest(source_archive)}}
        (self.evidence / "build-cargo.stderr.log").write_bytes(b"unit original stderr\n")
        self.save()

    def save(self):
        stdout = self.evidence / "build-cargo.stdout.jsonl"
        stdout.write_text("".join(json.dumps(event) + "\n" for event in self.events))
        self.value["build_stdout_sha256"] = audit.file_digest(stdout)
        self.value["build_stderr_sha256"] = audit.file_digest(self.evidence / "build-cargo.stderr.log")
        (self.evidence / "build-receipt.json").write_text(json.dumps(self.value) + "\n")

    def check(self, **options):
        return audit.receipt(self.evidence, profile="discovery", **options)

    def test_full_requires_original_source_compiler_raw_cargo_native_link_and_binary(self):
        value = self.check()
        self.assertEqual(value["verification_scope"], "full")
        self.assertEqual(value["sha256"], audit.file_digest(self.evidence / "build-receipt.json"))
        self.assertEqual(value["source_files_verified"], len(self.value["inputs"]))

    def test_passed_summary_cannot_hide_failure_or_another_native_source_or_executable(self):
        original_value, original_events = copy.deepcopy((self.value, self.events))
        for fault in ("exit", "boolean", "wrong_target", "wrong_source", "native_dynamic", "native_path", "debug", "finished", "tail", "command"):
            self.value, self.events = copy.deepcopy((original_value, original_events))
            if fault == "exit": self.value["exit_code"] = 101
            elif fault == "boolean": self.value["exit_code"] = False
            elif fault == "wrong_target": self.events[1]["target"]["name"] = "scap-object-network"
            elif fault == "wrong_source": self.events[1]["target"]["src_path"] = "/another/main.rs"
            elif fault == "native_dynamic": self.events[0]["linked_libs"] = ["dylib=sqlite3"]
            elif fault == "native_path": self.events[0]["linked_paths"] = ["native=/another/out"]
            elif fault == "debug": self.events[1]["profile"]["debug_assertions"] = True
            elif fault == "finished": self.events[-1]["success"] = False
            elif fault == "tail": self.events.append({"reason": "compiler-artifact"})
            else: self.value["command"][3] = "--debug"
            self.save()
            with self.subTest(fault=fault), self.assertRaises(ValueError): self.check()

    def test_modified_native_binary_source_compiler_or_raw_log_is_rejected(self):
        for path in (self.native, self.binary, self.source / "crates/scap-object/src/lib.rs", self.root / "rustc",
                     self.evidence / "build-cargo.stdout.jsonl"):
            previous = path.read_bytes(); path.write_bytes(previous + b"changed")
            with self.subTest(path=path.name), self.assertRaises(ValueError): self.check()
            path.write_bytes(previous)

    def test_missing_compiler_or_native_requires_explicit_non_gate_partial_scope(self):
        for path in (self.root / "rustc", self.native):
            previous = path.read_bytes(); path.unlink()
            with self.subTest(path=path.name), self.assertRaisesRegex(ValueError, "unavailable"): self.check()
            value = self.check(require_artifacts=False)
            self.assertNotEqual(value["verification_scope"], "full")
            self.assertIn(str(path), value["unavailable_artifacts"])
            path.write_bytes(previous)
        self.assertNotEqual(self.check(require_artifacts=False)["verification_scope"], "full")


if __name__ == "__main__": unittest.main()
