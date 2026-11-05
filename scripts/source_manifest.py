#!/usr/bin/env python3
"""Bind local validation to an exact, clean Git source candidate.

Capture before building and verify after the independent test gates. This is a
source-identity check, NOT a test runner, coverage verdict, or merge approval.
Ignored build outputs, external dependencies and transient changes restored
between observations require separate trusted build/provenance controls.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from os import stat_result
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
FIELDS = {"schema_version", "scope", "commit", "tree", "files", "source_sha256"}
RECORD_FIELDS = {"path", "mode", "git_blob", "bytes", "sha256"}
MODES = {"100644", "100755"}
SCOPE = "git-tracked-source-only"


def git(root: Path, *arguments: str) -> bytes:
    """Read local metadata without a shell or explicit write/remote command."""
    return subprocess.run(
        ["git", "--no-optional-locks", "-C", str(root), *arguments],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
    ).stdout


def digest(value: object, width: int) -> None:
    if not isinstance(value, str) or re.fullmatch(rf"[0-9a-f]{{{width}}}", value) is None:
        raise ValueError("invalid lowercase hexadecimal digest")


def source_path(value: object) -> str:
    """Accept canonical relative paths, including spaces and Unicode."""
    if not isinstance(value, str) or not value:
        raise ValueError("invalid source path")
    path = PurePosixPath(value)
    if (path.is_absolute() or path.as_posix() != value or ".." in path.parts
            or value == "." or "\\" in value or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise ValueError("source path must be canonical and repository-relative")
    return value


def parse_index(raw: bytes) -> list[dict]:
    """Parse NUL-delimited stage records; never rely on Git's quoted text paths."""
    if not raw or not raw.endswith(b"\0"):
        raise ValueError("empty or truncated Git index inventory")
    entries = []
    seen = set()
    for line in raw[:-1].split(b"\0"):
        header, path = line.decode("utf-8").split("\t", 1)
        mode, oid, stage = header.split(" ")
        if mode not in MODES or stage != "0":
            raise ValueError("unsupported source mode or conflicted index")
        digest(oid, 40)
        name = source_path(path)
        if name in seen:
            raise ValueError("duplicate source path")
        seen.add(name)
        entries.append({"path": name, "mode": mode, "git_blob": oid})
    return sorted(entries, key=lambda entry: entry["path"])


def state(root: Path) -> dict:
    """A clean index alone is insufficient: capture also hashes working bytes."""
    if git(root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise ValueError("source candidate is dirty or has untracked files")
    commit = git(root, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()
    tree = git(root, "rev-parse", "--verify", "HEAD^{tree}").decode().strip()
    digest(commit, 40)
    digest(tree, 40)
    return {"commit": commit, "tree": tree,
            "entries": parse_index(git(root, "ls-files", "--stage", "-z"))}


def read_bytes(path: Path) -> bytes:
    """Narrow filesystem port; byte identity includes empty files and line endings."""
    return path.read_bytes()


def stamp(value: stat_result) -> tuple:
    return (value.st_dev, value.st_ino, value.st_mode, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


def file_record(root: Path, entry: dict) -> dict:
    name = source_path(entry["path"])
    path = root
    for part in PurePosixPath(name).parts:
        path = path / part
        if path.is_symlink():
            raise ValueError(f"symlink source is not supported: {name!r}")
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError(f"source is not a regular file: {name!r}")
    mode = "100755" if before.st_mode & 0o111 else "100644"
    if mode != entry["mode"]:
        raise ValueError(f"source mode differs from index: {name!r}")
    raw = read_bytes(path)
    if stamp(before) != stamp(path.lstat()):
        raise ValueError(f"source changed during read: {name!r}")
    oid = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    if oid != entry["git_blob"]:
        raise ValueError(f"working source differs from committed bytes: {name!r}")
    return {**entry, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def fingerprint(entries: list[dict]) -> str:
    raw = json.dumps(entries, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def capture(root: Path) -> dict:
    root = root.resolve()
    actual = Path(git(root, "rev-parse", "--show-toplevel").decode().strip()).resolve()
    if actual != root:
        raise ValueError("--root must name the repository top-level")
    if git(root, "rev-parse", "--show-object-format").strip() != b"sha1":
        raise ValueError("this manifest version requires a SHA-1 Git repository")
    before = state(root)
    entries = [file_record(root, entry) for entry in before["entries"]]
    if state(root) != before:
        raise ValueError("Git identity changed during source capture")
    return {"schema_version": 1, "scope": SCOPE, "commit": before["commit"],
            "tree": before["tree"], "files": entries, "source_sha256": fingerprint(entries)}


def validate(value: object) -> dict:
    """Do not accept missing fields, boolean counters, or reordered/duplicate files."""
    if not isinstance(value, dict) or set(value) != FIELDS:
        raise ValueError("invalid source manifest fields")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1 or value["scope"] != SCOPE:
        raise ValueError("unsupported source manifest version or scope")
    digest(value["commit"], 40)
    digest(value["tree"], 40)
    digest(value["source_sha256"], 64)
    entries = value["files"]
    if not isinstance(entries, list) or not entries:
        raise ValueError("source inventory must be a nonempty list")
    paths = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != RECORD_FIELDS:
            raise ValueError("invalid source record fields")
        paths.append(source_path(entry["path"]))
        if not isinstance(entry["mode"], str) or entry["mode"] not in MODES:
            raise ValueError("unsupported source record mode")
        if type(entry["bytes"]) is not int or entry["bytes"] < 0:
            raise ValueError("invalid source byte count")
        digest(entry["git_blob"], 40)
        digest(entry["sha256"], 64)
    if paths != sorted(set(paths)):
        raise ValueError("source inventory is unordered or has duplicate paths")
    if fingerprint(entries) != value["source_sha256"]:
        raise ValueError("source manifest fingerprint mismatch")
    return value


def unique_object(pairs: list[tuple]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def load(path: Path) -> dict:
    with path.open("rb") as stream:
        raw = stream.read(MAX_MANIFEST_BYTES + 1)
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError("source manifest exceeds byte limit")
    return validate(json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("capture", "verify"))
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    try:
        root = args.root.resolve()
        if args.action == "capture":
            if args.manifest.resolve().is_relative_to(root):
                raise ValueError("write source manifests outside the repository")
            snapshot = capture(root)
            encoded = json.dumps(snapshot, indent=2, ensure_ascii=True) + "\n"
            if len(encoded.encode("utf-8")) > MAX_MANIFEST_BYTES:
                raise ValueError("source manifest exceeds byte limit")
            # Exclusive creation preserves old failure/success evidence; never truncate it.
            with args.manifest.open("x", encoding="utf-8") as stream:
                stream.write(encoded)
            print(f"CAPTURED: {snapshot['commit']} tree={snapshot['tree']}; {len(snapshot['files'])} files")
        else:
            expected = load(args.manifest)
            if capture(root) != expected:
                raise ValueError("source snapshot differs from the captured candidate")
            print(f"PASS: source identity matches {expected['commit']}; test verdicts are separate")
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"FAIL: source identity not verified: {error}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
