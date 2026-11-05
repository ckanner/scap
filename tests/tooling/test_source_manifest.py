"""Deterministic source identity checks; these do not test the database."""
from contextlib import redirect_stdout
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import source_manifest as gate


class SourceManifestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.root = self.home / "repo"
        self.root.mkdir()
        self.git("init", "--quiet")
        self.git("config", "user.name", "Test fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        self.git("config", "core.autocrlf", "false")
        self.write(".gitignore", "target/\n")
        self.write("src/a.rs", "pub fn a() -> u8 { 1 }\n")
        self.write("empty.txt", "")
        self.commit()
        self.output = self.home / "before.json"

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.root), *args], check=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def commit(self):
        self.git("add", "--all")
        self.git("commit", "--quiet", "--allow-empty", "-m", "fixture")

    def cli(self, action, path=None):
        with redirect_stdout(io.StringIO()) as output:
            code = gate.main([action, str(path or self.output), "--root", str(self.root)])
        return code, output.getvalue()

    def test_capture_is_sorted_complete_and_bound_to_committed_bytes(self):
        snapshot = gate.capture(self.root)
        self.assertEqual(snapshot["schema_version"], 1)
        self.assertEqual(snapshot["scope"], "git-tracked-source-only")
        self.assertEqual(snapshot["commit"], self.git("rev-parse", "HEAD").decode().strip())
        self.assertEqual(snapshot["tree"], self.git("rev-parse", "HEAD^{tree}").decode().strip())
        self.assertEqual([f["path"] for f in snapshot["files"]], [".gitignore", "empty.txt", "src/a.rs"])
        for entry in snapshot["files"]:
            raw = (self.root / entry["path"]).read_bytes()
            self.assertEqual(entry["bytes"], len(raw))
            self.assertEqual(entry["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(gate.validate(snapshot), snapshot)

    def test_capture_and_verify_do_not_mutate_repo_and_never_overwrite(self):
        before = self.git("status", "--porcelain")
        self.assertEqual(self.cli("capture")[0], 0)
        retained = self.output.read_bytes()
        self.assertEqual(self.cli("verify")[0], 0)
        code, text = self.cli("capture")
        self.assertEqual(code, 1)
        self.assertIn("FAIL", text)
        self.assertEqual(self.output.read_bytes(), retained)
        self.assertEqual(self.git("status", "--porcelain"), before)

    def test_missing_manifest_and_git_errors_fail_closed(self):
        self.assertEqual(self.cli("verify")[0], 1)
        for failure in [OSError("cannot spawn"), subprocess.CalledProcessError(2, "git"),
                        subprocess.TimeoutExpired("git", 30)]:
            with self.subTest(failure=type(failure)), patch.object(gate, "capture", side_effect=failure):
                self.assertEqual(self.cli("capture")[0], 1)
        with patch.object(gate, "capture", side_effect=ValueError("invalid repository")):
            self.assertEqual(self.cli("capture")[0], 1)

    def test_dirty_staged_untracked_deleted_and_conflicted_sources_are_rejected(self):
        for mode in ["modified", "staged", "untracked", "deleted"]:
            with self.subTest(mode=mode):
                if mode == "untracked":
                    self.write("new.rs", "fn new() {}\n")
                elif mode == "deleted":
                    (self.root / "src/a.rs").unlink()
                else:
                    self.write("src/a.rs", "changed\n")
                    if mode == "staged":
                        self.git("add", "src/a.rs")
                with self.assertRaises(ValueError):
                    gate.capture(self.root)
                self.git("reset", "--hard", "--quiet")
                self.git("clean", "-fdq")
        with self.assertRaises(ValueError):
            gate.parse_index(b"100644 " + b"a" * 40 + b" 1\tconflict.rs\0")

    def test_ignored_build_outputs_do_not_change_source_scope(self):
        before = gate.capture(self.root)
        self.write("target/build/output.rs", "generated\n")
        self.assertEqual(gate.capture(self.root), before)

    def test_same_tree_but_new_commit_does_not_reuse_old_receipt(self):
        self.assertEqual(self.cli("capture")[0], 0)
        old = gate.load(self.output)
        self.git("commit", "--quiet", "--allow-empty", "-m", "new candidate")
        current = gate.capture(self.root)
        self.assertEqual(old["tree"], current["tree"])
        self.assertNotEqual(old["commit"], current["commit"])
        self.assertEqual(self.cli("verify")[0], 1)

    def test_new_tracked_file_and_changed_bytes_invalidate_snapshot(self):
        self.cli("capture")
        self.write("src/a.rs", "pub fn a() -> u8 { 2 }\n")
        self.write("src/extra.rs", "pub fn extra() {}\n")
        self.commit()
        self.assertEqual(self.cli("verify")[0], 1)

    def test_clean_status_is_not_enough_assume_unchanged_is_verified(self):
        self.git("update-index", "--assume-unchanged", "src/a.rs")
        self.write("src/a.rs", "not the committed source\n")
        self.assertEqual(self.git("status", "--porcelain"), b"")
        with self.assertRaisesRegex(ValueError, "committed bytes"):
            gate.capture(self.root)

    def test_permission_bits_are_verified_even_when_core_filemode_is_false(self):
        self.git("config", "core.filemode", "false")
        path = self.root / "src/a.rs"
        path.chmod(0o755)
        self.assertEqual(self.git("status", "--porcelain"), b"")
        with self.assertRaisesRegex(ValueError, "mode"):
            gate.capture(self.root)
        self.git("update-index", "--chmod=+x", "src/a.rs")
        self.git("commit", "-qm", "executable")
        entries = gate.capture(self.root)["files"]
        self.assertEqual(next(e for e in entries if e["path"] == "src/a.rs")["mode"], "100755")

    def test_missing_tracked_file_is_rejected_even_with_assume_unchanged(self):
        self.git("update-index", "--assume-unchanged", "src/a.rs")
        (self.root / "src/a.rs").unlink()
        with self.assertRaises(OSError):
            gate.capture(self.root)

    def test_symlink_blob_submodule_and_symlink_parent_are_rejected(self):
        (self.root / "link").symlink_to("src/a.rs")
        self.commit()
        with self.assertRaisesRegex(ValueError, "mode"):
            gate.capture(self.root)
        for mode in ["120000", "160000"]:
            with self.assertRaises(ValueError):
                gate.parse_index(f"{mode} {'a' * 40} 0\titem\0".encode())
        directory = self.root / "redirect"
        directory.symlink_to(self.root / "src", target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            gate.file_record(self.root, {"path": "redirect/a.rs", "mode": "100644", "git_blob": "a" * 40})

    def test_non_regular_file_fails_before_read(self):
        with self.assertRaisesRegex(ValueError, "regular"):
            gate.file_record(self.root, {"path": "src", "mode": "100644", "git_blob": "a" * 40})

    def test_nested_root_empty_inventory_and_non_sha1_repo_rejected(self):
        with self.assertRaisesRegex(ValueError, "top-level"):
            gate.capture(self.root / "src")
        with self.assertRaises(ValueError):
            gate.parse_index(b"")
        original = gate.git
        def different_format(root, *args):
            if args == ("rev-parse", "--show-object-format"):
                return b"sha256\n"
            return original(root, *args)
        with patch.object(gate, "git", side_effect=different_format):
            with self.assertRaisesRegex(ValueError, "SHA-1"):
                gate.capture(self.root)

    def test_parse_index_validates_shape_oids_paths_and_duplicates(self):
        prefix = b"100644 " + b"a" * 40 + b" 0\t"
        for raw in [b"bad", prefix + b"a", prefix + b"a\0" + prefix + b"a\0",
                    prefix + b"\0", prefix + b"../a\0", prefix + b"/a\0",
                    prefix + b"a/./b\0", prefix + b"a//b\0", prefix + b"a\\b\0",
                    prefix + b"a\nb\0", prefix + b"\xff\0",
                    b"100644 z 0\ta\0", b"100644 " + b"a" * 40 + b" 0 a\0"]:
            with self.subTest(raw=raw), self.assertRaises((ValueError, UnicodeError)):
                gate.parse_index(raw)
        entries = gate.parse_index(prefix + "目录/a b.rs".encode() + b"\0")
        self.assertEqual(entries[0]["path"], "目录/a b.rs")

    def test_repository_changed_during_capture_is_rejected(self):
        original = gate.state
        count = 0
        def state(root):
            nonlocal count
            value = original(root)
            count += 1
            if count == 2:
                value = {**value, "commit": "b" * 40}
            return value
        with patch.object(gate, "state", side_effect=state):
            with self.assertRaisesRegex(ValueError, "during"):
                gate.capture(self.root)

    def test_file_changed_during_read_is_rejected(self):
        entry = next(e for e in gate.parse_index(self.git("ls-files", "--stage", "-z")) if e["path"] == "src/a.rs")
        original = gate.read_bytes
        def changing(path):
            raw = original(path)
            path.write_bytes(raw + b" ")
            return raw
        with patch.object(gate, "read_bytes", side_effect=changing):
            with self.assertRaisesRegex(ValueError, "during"):
                gate.file_record(self.root, entry)

    def test_capture_forbids_manifest_inside_repo_including_symlink_parent(self):
        for path in [self.root / "before.json", self.root / "target/before.json"]:
            self.assertEqual(self.cli("capture", path)[0], 1)
        link = self.home / "points-to-repo"
        link.symlink_to(self.root, target_is_directory=True)
        self.assertEqual(self.cli("capture", link / "before.json")[0], 1)

    def test_manifest_size_utf8_duplicate_keys_and_json_are_validated(self):
        for raw in [b"{bad", b"\xff", b'{"a":1,"a":2}', b"x" * (gate.MAX_MANIFEST_BYTES + 1)]:
            self.output.write_bytes(raw)
            self.assertEqual(self.cli("verify")[0], 1)

    def test_manifest_schema_fields_exact_types_and_digests(self):
        good = gate.capture(self.root)
        for value in [None, [], {}, {**good, "extra": 1}, {**good, "schema_version": True},
                      {**good, "schema_version": 2}, {**good, "scope": "all-tests-passed"},
                      {**good, "commit": "x"}, {**good, "tree": None},
                      {**good, "source_sha256": "f" * 64}, {**good, "files": []},
                      {**good, "files": None}, {**good, "files": list(reversed(good["files"]))}]:
            with self.subTest(value=str(value)[:50]), self.assertRaises(ValueError):
                gate.validate(value)
        for change in [{"bytes": True}, {"bytes": -1}, {"bytes": 1.5}, {"sha256": "bad"},
                       {"git_blob": "bad"}, {"mode": "160000"}, {"mode": []}, {"path": "."}, {"path": "../escape"},
                       {"path": ""}, {"path": None}, {"extra": "field"}]:
            bad = deepcopy(good)
            bad["files"][0].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                gate.validate(bad)
        for record in [None, [], {}]:
            bad = deepcopy(good)
            bad["files"][0] = record
            with self.assertRaises(ValueError):
                gate.validate(bad)
        bad = deepcopy(good)
        bad["files"].append(bad["files"][-1])
        with self.assertRaises(ValueError):
            gate.validate(bad)

    def test_valid_json_roundtrip_and_canonical_fingerprint(self):
        snapshot = gate.capture(self.root)
        self.output.write_text(json.dumps(snapshot, ensure_ascii=False), encoding="utf-8")
        self.assertEqual(gate.load(self.output), snapshot)
        self.assertEqual(gate.fingerprint(snapshot["files"]), snapshot["source_sha256"])
        self.assertNotEqual(gate.fingerprint([]), snapshot["source_sha256"])

    def test_real_entrypoint_calls_main(self):
        args = [str(gate.__file__), "capture", str(self.output), "--root", str(self.root)]
        with patch.object(sys, "argv", args), redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                runpy.run_path(str(gate.__file__), run_name="__main__")
        self.assertEqual(raised.exception.code, 0)

    def test_oversized_capture_does_not_create_a_receipt(self):
        with patch.object(gate, "MAX_MANIFEST_BYTES", 1):
            self.assertEqual(self.cli("capture")[0], 1)
        self.assertFalse(self.output.exists())

    def test_file_replaced_by_symlink_during_read_is_rejected(self):
        entry = next(e for e in gate.parse_index(self.git("ls-files", "--stage", "-z")) if e["path"] == "src/a.rs")
        original = gate.read_bytes
        def replaced(path):
            raw = original(path)
            destination = self.home / "relocated"
            path.rename(destination)
            path.symlink_to(destination)
            return raw
        with patch.object(gate, "read_bytes", side_effect=replaced):
            with self.assertRaisesRegex(ValueError, "during"):
                gate.file_record(self.root, entry)

    def test_invalid_record_mode_is_a_clean_cli_failure(self):
        value = gate.capture(self.root)
        value["files"][0]["mode"] = []
        self.output.write_text(json.dumps(value))
        self.assertEqual(self.cli("verify")[0], 1)

    def test_non_repository_error_has_no_success_marker(self):
        outside = self.home / "not-a-repository"
        outside.mkdir()
        with redirect_stdout(io.StringIO()) as output:
            result = gate.main(["capture", str(self.output), "--root", str(outside)])
        self.assertEqual(result, 1)
        self.assertNotIn("CAPTURED", output.getvalue())
        self.assertFalse(self.output.exists())

    def test_verify_success_is_explicitly_source_only(self):
        self.assertEqual(self.cli("capture")[0], 0)
        code, text = self.cli("verify")
        self.assertEqual(code, 0)
        self.assertIn("test verdicts are separate", text)
        self.assertNotIn("tests passed", text)

    def test_output_symlink_never_overwrites_prior_evidence(self):
        original = self.home / "original.json"
        original.write_text("prior evidence")
        self.output.symlink_to(original)
        self.assertEqual(self.cli("capture")[0], 1)
        self.assertEqual(original.read_text(), "prior evidence")
