#!/usr/bin/env python3
"""Capture a real pinned release of the deployment-root recovery assembler."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
TARGET = "scap-object-discovery"
MANIFEST = "experiments/object-discovery/Cargo.toml"
COMMAND = ["cargo", "+1.90.0", "build", "--release", "--frozen", "--manifest-path",
           MANIFEST, "--message-format=json-render-diagnostics"]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


shared = module("discovery_shared_build", ROOT / "experiments/object-network/build.py")
capture = module("discovery_build_capture", ROOT / "experiments/object-network/build_evidence.py")


def inputs():
    names = {"Cargo.toml", "Cargo.lock", "rust-toolchain.toml"}
    for directory in ("crates", "experiments/object-network", "experiments/object-capacity",
                      "experiments/object-service", "experiments/object-discovery"):
        for path in (ROOT / directory).rglob("*"):
            if path.is_file() and (path.suffix in (".rs", ".py", ".mjs") or
                                   path.name in ("Cargo.toml", "Cargo.lock")):
                names.add(path.relative_to(ROOT).as_posix())
    return {name: shared.digest(ROOT / name) for name in sorted(names)}


def artifacts(events, target):
    binaries = [row for row in events if row.get("reason") == "compiler-artifact"
                and row.get("executable") is not None]
    assert len(binaries) == 1
    event = binaries[0]
    binary = target / "release" / TARGET
    assert event["target"]["name"] == TARGET and event["target"]["kind"] == ["bin"]
    assert Path(event["executable"]).resolve() == binary
    assert event["profile"] == {"opt_level": "3", "debuginfo": 0,
                                "debug_assertions": False, "overflow_checks": False, "test": False}
    native = [row for row in events if row.get("reason") == "build-script-executed"
              and row.get("package_id", "").rsplit("#", 1)[-1].split("@", 1)[0] == "libsql-ffi"]
    assert len(native) == 1
    directory = Path(native[0]["out_dir"]).resolve()
    assert directory.name == "out" and directory.parent.name.startswith("libsql-ffi-")
    assert directory.parent.parent == target / "release" / "build"
    assert native[0]["linked_libs"] == ["static=libsql"]
    assert native[0]["linked_paths"] == ["native=" + str(directory)]
    archives = {}
    for path in sorted(directory.rglob("*.a")):
        assert path.resolve().is_relative_to(directory)
        archives[str(path.resolve())] = shared.digest(path)
    assert str(directory / "liblibsql.a") in archives
    return binary, archives


def verify(path, worker):
    value = json.loads(Path(path).read_text())
    assert value["status"] == "passed" and value["profile"] == "release"
    assert type(value["exit_code"]) is int and value["exit_code"] == 0
    assert value["command"] == COMMAND
    assert value["inputs"] == inputs()
    assert value["input_sha256"] == shared.input_digest(value["inputs"])
    for name, field in (("cargo.stdout.jsonl", "build_stdout_sha256"),
                        ("cargo.stderr.log", "build_stderr_sha256")):
        assert shared.digest(Path(path).parent / name) == value[field]
    binary, native = artifacts(shared.cargo_events(Path(path).parent / "cargo.stdout.jsonl"),
                               Path(value["target_dir"]))
    assert binary == Path(worker).resolve() == Path(value["binary"]["path"])
    assert shared.digest(binary) == value["binary"]["sha256"]
    assert native == value["native_archives"]
    for tool in value["tool_identity"].values():
        assert shared.digest(Path(tool["path"])) == tool["sha256"]
    return value


def capture_receipt(path, worker, evidence):
    return capture.capture(Path(path), Path(evidence), value=verify(path, worker),
                           root=ROOT, inputs=inputs, save_receipt=shared.save_receipt,
                           sync=shared.sync, log_keys=("build_stdout_sha256", "build_stderr_sha256"))


def run(args):
    assert __debug__ and "LLVM_PROFILE_FILE" not in os.environ
    assert all("instrument-coverage" not in os.environ.get(name, "")
               for name in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"))
    evidence, target = args.evidence.resolve(), args.target_dir.resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    environment = dict(os.environ, CARGO_TARGET_DIR=str(target), CARGO_INCREMENTAL="0")
    value = {"schema": 1, "status": "failed", "profile": "release", "command": COMMAND,
             "target_dir": str(target), "source_root": str(ROOT), "incremental": "0"}
    try:
        value["inputs"] = inputs()
        value["input_sha256"] = shared.input_digest(value["inputs"])
        value["source_commit"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        value["source_dirty"] = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT))
        assert not value["source_dirty"], "freeze the recovery candidate before release build"
        value["versions"] = {name: subprocess.check_output(command, cwd=ROOT, text=True).strip()
                             for name, command in (("rustc", ["rustc", "+1.90.0", "-Vv"]),
                                                   ("cargo", ["cargo", "+1.90.0", "-V"]),
                                                   ("cc", ["cc", "--version"]))}
        value["tool_identity"] = {}
        for tool in ("rustc", "cargo"):
            path = Path(subprocess.check_output(["rustup", "which", "--toolchain", "1.90.0", tool], text=True).strip()).resolve()
            value["tool_identity"][tool] = {"path": str(path), "sha256": shared.digest(path)}
        with (evidence / "cargo.stdout.jsonl").open("wb") as stdout, (evidence / "cargo.stderr.log").open("wb") as stderr:
            process = subprocess.run(COMMAND, cwd=ROOT, env=environment, stdout=stdout, stderr=stderr)
            value["exit_code"] = process.returncode
            shared.sync(stdout); shared.sync(stderr)
        value["build_stdout_sha256"] = shared.digest(evidence / "cargo.stdout.jsonl")
        value["build_stderr_sha256"] = shared.digest(evidence / "cargo.stderr.log")
        assert process.returncode == 0
        assert value["inputs"] == inputs(), "source changed during recovery build"
        binary, native = artifacts(shared.cargo_events(evidence / "cargo.stdout.jsonl"), target)
        value.update(binary={"path": str(binary), "sha256": shared.digest(binary)}, native_archives=native, status="passed")
    except BaseException as error:
        value["error"] = repr(error)
        raise
    finally:
        shared.save_receipt(evidence / "build.json", value)
    print(json.dumps({"status": value["status"], "binary": value["binary"],
                      "input_sha256": value["input_sha256"]}, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-dir", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    run(parser.parse_args())
