#!/usr/bin/env python3
"""Build the dedicated LIST example and bind its actual bytes to current inputs.

This is a storage-port development receipt. It does not claim SQLite execution,
whole-workspace acceptance, AWS cloud validation, or a clean frozen candidate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

import build

ROOT = Path(__file__).resolve().parents[2]
TARGET = "scap-object-listing"


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def identify(command):
    path = Path(subprocess.check_output(command, cwd=ROOT, text=True).strip()).resolve()
    return {"path": str(path), "sha256": digest(path)}


def artifact(events, directory, profile):
    executables = [event for event in events if event.get("reason") == "compiler-artifact"
                   and event.get("executable") is not None]
    assert len(executables) == 1, "missing or ambiguous LIST executable"
    event = executables[0]
    assert event["target"]["name"] == TARGET and event["target"]["kind"] == ["example"]
    expected = directory / ("release" if profile == "release" else "debug") / "examples" / TARGET
    path = Path(event["executable"]).resolve()
    assert path == expected.resolve(), "unexpected LIST executable location"
    assert event["profile"]["test"] is False
    assert event["profile"]["debug_assertions"] is (profile == "dev")
    return path, event


def verify(path, worker):
    receipt = json.loads(Path(path).read_text())
    assert receipt["status"] == "passed" and receipt["scope"] == "N2-A-storage-port-only"
    assert receipt["profile"] in ("dev", "release") and receipt["exit_code"] == 0
    assert receipt["inputs"] == build.inputs(), "LIST source changed since build"
    assert receipt["input_sha256"] == build.input_digest(receipt["inputs"])
    for name, field in (("cargo.stdout.jsonl", "build_stdout_sha256"),
                        ("cargo.stderr.log", "build_stderr_sha256")):
        assert digest(Path(path).parent / name) == receipt[field], "LIST build log changed"
    binary, event = artifact(build.cargo_events(Path(path).parent / "cargo.stdout.jsonl"),
                             Path(receipt["target_dir"]), receipt["profile"])
    assert binary == Path(worker).resolve() == Path(receipt["binary"]["path"])
    assert digest(binary) == receipt["binary"]["sha256"], "LIST executable bytes changed"
    assert event["fresh"] == receipt["cargo_artifact_fresh"]
    for tool in receipt["tool_identity"].values():
        assert digest(tool["path"]) == tool["sha256"], "build tool identity changed"
    return receipt


def run(args):
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    directory = args.target_dir.resolve()
    profile = "release" if args.release else "dev"
    command = ["cargo", "+1.90.0", "build", "--frozen", "--manifest-path",
               "experiments/object-network/Cargo.toml", "--example", TARGET,
               "--message-format=json-render-diagnostics"]
    if args.release:
        command.append("--release")
    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = str(directory)
    environment["CARGO_INCREMENTAL"] = "0"
    record = {"schema": 1, "scope": "N2-A-storage-port-only", "status": "failed",
              "profile": profile, "command": command, "target_dir": str(directory),
              "incremental": "0", "source_root": str(ROOT)}
    try:
        record["inputs"] = build.inputs()
        record["input_sha256"] = build.input_digest(record["inputs"])
        record["source_commit"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        record["source_dirty"] = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT))
        record["tool_identity"] = {
            name: identify(["rustup", "which", "--toolchain", "1.90.0", name])
            for name in ("rustc", "cargo")
        }
        record["rustc_version"] = subprocess.check_output(["rustc", "+1.90.0", "-Vv"], text=True)
        record["cargo_version"] = subprocess.check_output(["cargo", "+1.90.0", "-V"], text=True)
        with (evidence / "cargo.stdout.jsonl").open("wb") as stdout, (evidence / "cargo.stderr.log").open("wb") as stderr:
            process = subprocess.run(command, cwd=ROOT, env=environment, stdout=stdout, stderr=stderr)
            record["exit_code"] = process.returncode
            build.sync(stdout)
            build.sync(stderr)
        record["build_stdout_sha256"] = digest(evidence / "cargo.stdout.jsonl")
        record["build_stderr_sha256"] = digest(evidence / "cargo.stderr.log")
        assert record["exit_code"] == 0, "LIST build failed"
        assert record["inputs"] == build.inputs(), "LIST inputs changed during build"
        binary, event = artifact(build.cargo_events(evidence / "cargo.stdout.jsonl"), directory, profile)
        record["binary"] = {"path": str(binary), "sha256": digest(binary)}
        record["cargo_artifact_fresh"] = event["fresh"]
        record["status"] = "passed"
    except BaseException as error:
        record["error"] = repr(error)
        raise
    finally:
        build.save_receipt(evidence / "build.json", record)
    print(json.dumps({"status": record["status"], "profile": profile,
                      "binary": record["binary"], "input_sha256": record["input_sha256"]}, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-dir", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--release", action="store_true")
    run(parser.parse_args())
