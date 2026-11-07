#!/usr/bin/env python3
"""Bind an actual stable release build to its inputs and native artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

if not __debug__:
    raise RuntimeError("validation requires Python assertions; disable -O/PYTHONOPTIMIZE")


ROOT = Path(__file__).resolve().parents[2]


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def sync(stream):
    stream.flush()
    os.fsync(stream.fileno())


def save_receipt(path, record):
    def persist():
        with path.open("w", encoding="utf-8") as stream:
            stream.write(json.dumps(record, indent=2, sort_keys=True) + "\n")
            sync(stream)

    try:
        persist()
    except BaseException as error:
        # A failed receipt sync cannot leave a readable success record. The
        # failure rewrite is also synced; persistent I/O failure still raises.
        record["status"] = "failed"
        record["receipt_error"] = repr(error)
        persist()
        raise


def cargo_events(path):
    raw = path.read_bytes()
    assert raw and raw.endswith(b"\n"), "incomplete Cargo JSONL output"
    events = [json.loads(line) for line in raw.splitlines()]
    assert all(isinstance(event, dict) for event in events), "invalid Cargo event"
    finished = [event for event in events if event.get("reason") == "build-finished"]
    assert (len(finished) == 1 and finished[0] is events[-1]
            and finished[0].get("success") is True), "missing final successful Cargo build-finished"
    return events


def release_artifacts(events, target):
    executable = [event for event in events if event.get("reason") == "compiler-artifact"
                  and event.get("executable") is not None]
    assert len(executable) == 1, "missing or ambiguous release executable artifact"
    artifact = executable[0]
    assert (artifact.get("target", {}).get("name") == "scap-object-network"
            and artifact["target"].get("kind") == ["bin"]), "unexpected executable target"
    binary = Path(artifact["executable"]).resolve()
    assert binary == target / "release" / "scap-object-network", "executable outside the isolated release target"
    native = [event for event in events if event.get("reason") == "build-script-executed"
              and event.get("package_id", "").rsplit("#", 1)[-1].split("@", 1)[0] == "libsql-ffi"]
    assert len(native) == 1, "missing or duplicate native libSQL build record"
    directory = Path(native[0]["out_dir"]).resolve()
    assert (directory.name == "out" and directory.parent.name.startswith("libsql-ffi-")
            and directory.parent.parent == target / "release" / "build"), "native output outside the isolated release target"
    archives = {}
    for path in sorted(directory.rglob("*.a")):
        path = path.resolve()
        assert path.is_relative_to(directory), "native archive escaped its build directory"
        archives[str(path)] = digest(path)
    assert archives, "no actual native libSQL archive observed"
    return binary, archives


def inputs():
    names = {"Cargo.toml", "Cargo.lock", "rust-toolchain.toml"}
    for path in (ROOT / "crates").rglob("*"):
        if path.is_file() and (path.suffix == ".rs" or path.name == "Cargo.toml"):
            names.add(path.relative_to(ROOT).as_posix())
    for directory in ("object-network", "object-capacity"):
        for path in (ROOT / "experiments" / directory).rglob("*"):
            if path.is_file() and (path.suffix in (".rs", ".py") or path.name in ("Cargo.toml", "Cargo.lock")):
                names.add(path.relative_to(ROOT).as_posix())
    return {name: digest(ROOT / name) for name in sorted(names)}


def input_digest(manifest):
    return hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def verify(record_path, worker):
    value = json.loads(record_path.read_text())
    assert value["status"] == "passed" and value["profile"] == "release"
    assert value["binary"]["sha256"] == digest(worker.resolve()), "worker is not the recorded build"
    assert value["inputs"] == inputs(), "build inputs changed after compilation"
    assert value["input_sha256"] == input_digest(value["inputs"])
    assert value["native_archives"], "missing native compilation evidence"
    return value


def run(arguments):
    assert "LLVM_PROFILE_FILE" not in os.environ
    for name in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"):
        assert "instrument-coverage" not in os.environ.get(name, ""), "release must not inherit unit instrumentation"
    evidence = arguments.evidence.resolve()
    evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    target = arguments.target_dir.resolve()
    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = str(target)
    command = ["cargo", "+1.90.0", "build", "--release", "--locked", "--manifest-path",
               "experiments/object-network/Cargo.toml", "--message-format=json-render-diagnostics"]
    receipt = {"schema": 1, "status": "failed", "profile": "release", "command": command}
    output = evidence / "cargo.stdout.jsonl"
    errors = evidence / "cargo.stderr.log"
    try:
        before = inputs()
        receipt["inputs"] = before
        receipt["input_sha256"] = input_digest(before)
        receipt["versions"] = {}
        for name, version_command in [("rustc", ["rustc", "+1.90.0", "-Vv"]),
                                      ("cargo", ["cargo", "+1.90.0", "-V"]), ("cc", ["cc", "--version"])]:
            receipt["versions"][name] = subprocess.check_output(
                version_command, cwd=ROOT, env=environment, text=True).strip()
        receipt["source_commit"] = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        with output.open("wb") as stdout, errors.open("wb") as stderr:
            try:
                process = subprocess.run(command, cwd=ROOT, env=environment, stdout=stdout, stderr=stderr)
                receipt["exit_code"] = process.returncode
            finally:
                try:
                    sync(stdout)
                finally:
                    sync(stderr)
        receipt["build_stdout_sha256"] = digest(output)
        receipt["build_stderr_sha256"] = digest(errors)
        assert process.returncode == 0, f"release build exited {process.returncode}"
        assert before == inputs(), "source changed during build"
        artifacts = cargo_events(output)
        binary, native = release_artifacts(artifacts, target)
        receipt["binary"] = {"path": str(binary), "sha256": digest(binary)}
        receipt["native_archives"] = native
        receipt["status"] = "passed"
    except BaseException as error:
        receipt["error"] = repr(error)
        raise
    finally:
        save_receipt(evidence / "build.json", receipt)
    print(json.dumps({"status": receipt["status"], "binary": receipt["binary"],
                      "input_sha256": receipt["input_sha256"]}, sort_keys=True), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-dir", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    run(parser.parse_args())
