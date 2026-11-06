#!/usr/bin/env python3
"""Bind an actual stable release build to its inputs and native artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[2]


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


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
    before = inputs()
    versions = {}
    for name, command in [("rustc", ["rustc", "+1.90.0", "-Vv"]), ("cargo", ["cargo", "+1.90.0", "-V"]),
                          ("cc", ["cc", "--version"])]:
        versions[name] = subprocess.check_output(command, cwd=ROOT, env=environment, text=True).strip()
    command = ["cargo", "+1.90.0", "build", "--release", "--locked", "--manifest-path",
               "experiments/object-network/Cargo.toml", "--message-format=json-render-diagnostics"]
    receipt = {"schema": 1, "status": "failed", "profile": "release", "inputs": before,
               "input_sha256": input_digest(before), "versions": versions, "command": command,
               "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()}
    output = evidence / "cargo.stdout.jsonl"
    errors = evidence / "cargo.stderr.log"
    with output.open("wb") as stdout, errors.open("wb") as stderr:
        process = subprocess.run(command, cwd=ROOT, env=environment, stdout=stdout, stderr=stderr)
    receipt["exit_code"] = process.returncode
    receipt["build_stdout_sha256"] = digest(output)
    receipt["build_stderr_sha256"] = digest(errors)
    try:
        assert process.returncode == 0, f"release build exited {process.returncode}"
        assert before == inputs(), "source changed during build"
        artifacts = [json.loads(line) for line in output.read_text().splitlines()]
        executable = [item for item in artifacts if item.get("reason") == "compiler-artifact"
                      and item.get("target", {}).get("name") == "scap-object-network" and item.get("executable")]
        assert len(executable) == 1, "missing exact worker compiler artifact"
        binary = Path(executable[0]["executable"]).resolve()
        assert binary == target / "release" / "scap-object-network"
        receipt["binary"] = {"path": str(binary), "sha256": digest(binary)}
        native = {}
        for item in artifacts:
            if item.get("reason") == "build-script-executed" and "libsql-ffi" in item.get("package_id", ""):
                for path in Path(item["out_dir"]).rglob("*.a"):
                    native[str(path)] = digest(path)
        assert native, "no actual native libSQL archive observed"
        receipt["native_archives"] = native
        receipt["status"] = "passed"
    except BaseException as error:
        receipt["error"] = repr(error)
        raise
    finally:
        (evidence / "build.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": receipt["status"], "binary": receipt["binary"],
                      "input_sha256": receipt["input_sha256"]}, sort_keys=True), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-dir", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    run(parser.parse_args())
