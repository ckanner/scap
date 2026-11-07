#!/usr/bin/env python3
"""Bind the actual service release executable, SDK and fault fixture to source."""
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
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


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
    value = json.loads(Path(record).read_text())
    assert value["status"] == "passed" and value["profile"] == "release"
    assert value["inputs"] == inputs(), "service/SDK/fixture source changed after build"
    assert value["binary"]["sha256"] == digest(binary), "service binary changed"
    assert value["native_archives"], "missing native SQLite build provenance"
    return value


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
    record = {"schema": 1, "status": "failed", "profile": "release", "command": command,
              "inputs": inputs(), "source_commit": subprocess.check_output(
                  ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "rustc": subprocess.check_output(["rustc", "+1.90.0", "-Vv"], text=True),
              "node": subprocess.check_output(["node", "--version"], text=True).strip()}
    try:
        with (evidence / "cargo.stdout.jsonl").open("wb") as out, (evidence / "cargo.stderr.log").open("wb") as err:
            process = subprocess.run(command, cwd=ROOT, env=environment, stdout=out, stderr=err)
        record["exit_code"] = process.returncode
        assert process.returncode == 0, "service build failed"
        assert record["inputs"] == inputs(), "source changed during service build"
        events = [json.loads(line) for line in (evidence / "cargo.stdout.jsonl").read_text().splitlines()]
        binaries = [event["executable"] for event in events if event.get("reason") == "compiler-artifact"
                    and event.get("target", {}).get("name") == "scapd" and event.get("executable")]
        assert len(binaries) == 1
        binary = Path(binaries[0]).resolve()
        assert binary == target / "release" / "scapd"
        record["binary"] = {"path": str(binary), "sha256": digest(binary)}
        native = {}
        for event in events:
            if event.get("reason") == "build-script-executed" and "libsql-ffi" in event.get("package_id", ""):
                native.update({str(path): digest(path) for path in Path(event["out_dir"]).rglob("*.a")})
        assert native
        record["native_archives"] = native
        record["status"] = "passed"
    except BaseException as error:
        record["error"] = repr(error)
        raise
    finally:
        for name in ("cargo.stdout.jsonl", "cargo.stderr.log"):
            if (evidence / name).is_file():
                record[name + "_sha256"] = digest(evidence / name)
        (evidence / "build.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": record["status"], "binary": record["binary"]}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-dir", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    main(parser.parse_args())
