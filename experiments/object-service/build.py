#!/usr/bin/env python3
"""Bind the actual service release executable, SDK and fault fixture to source."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess

if not __debug__:
    raise RuntimeError("validation requires Python assertions; disable -O/PYTHONOPTIMIZE")

ROOT = Path(__file__).resolve().parents[2]


def digest(path):
    with Path(path).open("rb") as stream:
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
    binaries = [event for event in events if event.get("reason") == "compiler-artifact"
                and event.get("executable") is not None]
    assert len(binaries) == 1, "missing or ambiguous release executable artifact"
    artifact = binaries[0]
    assert (artifact.get("target", {}).get("name") == "scapd"
            and artifact["target"].get("kind") == ["bin"]), "unexpected executable target"
    binary = Path(artifact["executable"]).resolve()
    assert binary == target / "release" / "scapd", "executable outside the isolated release target"
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
    assert archives, "missing native SQLite build provenance"
    return binary, archives


def inputs():
    paths = {ROOT / name for name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml")}
    for directory in ("crates", "sdk/node", "sdk/node-codec", "experiments/object-service",
                      "experiments/object-network"):
        for path in (ROOT / directory).rglob("*"):
            if path.is_file() and (path.suffix in (".rs", ".py", ".js", ".mjs", ".ts")
                                   or path.name in ("Cargo.toml", "Cargo.lock", "package.json")):
                paths.add(path)
    return {path.relative_to(ROOT).as_posix(): digest(path) for path in sorted(paths)}


def verify(record, binary):
    record = Path(record)
    value = json.loads(record.read_text())
    assert value["status"] == "passed" and value["profile"] == "release"
    assert type(value.get("exit_code")) is int and value["exit_code"] == 0, "Cargo did not exit successfully"
    assert value["inputs"] == inputs(), "service/SDK/fixture source changed after build"
    assert isinstance(value.get("binary"), dict) and set(value["binary"]) == {"path", "sha256"}, "missing service binary provenance"
    assert Path(value["binary"]["path"]).resolve() == Path(binary).resolve(), "service executable path differs"
    assert value["binary"]["sha256"] == digest(binary), "service binary changed"
    assert value["native_archives"], "missing native SQLite build provenance"
    for name in ("cargo.stdout.jsonl", "cargo.stderr.log"):
        assert value[name + "_sha256"] == digest(record.parent / name), "original Cargo log changed"
    compiled, native = release_artifacts(cargo_events(record.parent / "cargo.stdout.jsonl"),
                                         Path(binary).resolve().parents[1])
    assert compiled == Path(binary).resolve(), "Cargo executable differs from supplied binary"
    assert native == value["native_archives"], "native SQLite archives changed after build"
    return value


def capture_receipt(record, binary, evidence):
    specification=importlib.util.spec_from_file_location("scap_build_evidence_capture",
        Path(__file__).resolve().parent.parent/"object-network"/"build_evidence.py")
    module=importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module.capture(record,evidence,value=verify(record,binary),root=ROOT,inputs=inputs,
                          save_receipt=save_receipt,sync=sync,
                          log_keys=("cargo.stdout.jsonl_sha256","cargo.stderr.log_sha256"))


def main(args):
    assert "LLVM_PROFILE_FILE" not in os.environ
    assert not any("instrument-coverage" in os.environ.get(key, "")
                   for key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"))
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=False, mode=0o700)
    target = args.target_dir.resolve()
    environment = dict(os.environ, CARGO_TARGET_DIR=str(target))
    command = ["cargo", "+1.90.0", "build", "--release", "--locked", "-p", "scap-service",
               "--bin", "scapd", "--message-format=json-render-diagnostics"]
    record = {"schema": 1, "status": "failed", "profile": "release", "command": command}
    output = evidence / "cargo.stdout.jsonl"
    errors = evidence / "cargo.stderr.log"
    try:
        record["inputs"] = inputs()
        record["source_root"] = str(ROOT.resolve())
        record["source_commit"] = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        record["rustc"] = subprocess.check_output(["rustc", "+1.90.0", "-Vv"], text=True)
        record["node"] = subprocess.check_output(["node", "--version"], text=True).strip()
        with output.open("wb") as out, errors.open("wb") as err:
            try:
                process = subprocess.run(command, cwd=ROOT, env=environment, stdout=out, stderr=err)
                record["exit_code"] = process.returncode
            finally:
                try:
                    sync(out)
                finally:
                    sync(err)
        record["cargo.stdout.jsonl_sha256"] = digest(output)
        record["cargo.stderr.log_sha256"] = digest(errors)
        assert process.returncode == 0, "service build failed"
        assert record["inputs"] == inputs(), "source changed during service build"
        events = cargo_events(output)
        binary, native = release_artifacts(events, target)
        record["binary"] = {"path": str(binary), "sha256": digest(binary)}
        record["native_archives"] = native
        record["status"] = "passed"
    except BaseException as error:
        record["error"] = repr(error)
        raise
    finally:
        save_receipt(evidence / "build.json", record)
    print(json.dumps({"status": record["status"], "binary": record["binary"]}), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-dir", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    main(parser.parse_args())
