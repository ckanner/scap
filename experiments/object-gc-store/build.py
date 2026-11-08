#!/usr/bin/env python3
"""Freeze an actual uninstrumented GC adapter executable, without SQLite."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess

from support import ROOT, digest


def inputs():
    names = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).split(b"\0")
    return {name.decode(): digest(ROOT / name.decode()) for name in names if name}


def artifact(events, target):
    exes = [event for event in events if event.get("reason") == "compiler-artifact"
            and event.get("executable") is not None]
    assert len(exes) == 1
    event = exes[0]
    assert event["target"]["name"] == "scap-object-gc-store" and event["target"]["kind"] == ["bin"]
    assert event["profile"]["test"] is False and event["profile"]["debug_assertions"] is False
    binary = Path(event["executable"]).resolve()
    assert binary == target / "release" / "scap-object-gc-store"
    archives = {str(path): digest(path) for path in sorted((target / "release").rglob("*.a"))}
    assert archives, "native dependency archives missing"
    return {"path": str(binary), "sha256": digest(binary)}, archives


def verify(receipt_path, binary):
    path = Path(receipt_path)
    record = json.loads(path.read_text())
    assert record["status"] == "passed" and record["source_dirty"] is False
    assert record["scope"] == "GC-transport-only" and record["exit_code"] == 0
    assert record["inputs"] == inputs(), "source inputs changed"
    assert record["binary"] == {"path": str(Path(binary).resolve()), "sha256": digest(binary)}
    for name in ("cargo.stdout.jsonl", "cargo.stderr.log"):
        assert digest(path.parent / name) == record["logs"][name]
    events = [json.loads(line) for line in (path.parent / "cargo.stdout.jsonl").read_text().splitlines()]
    assert events[-1] == {"reason": "build-finished", "success": True}
    exe, archives = artifact(events, Path(record["target"]))
    assert exe == record["binary"] and archives == record["native_archives"]
    for tool in record["tools"].values():
        assert digest(tool["path"]) == tool["sha256"]
    return record


def run(args):
    evidence, target = args.evidence.resolve(), args.target.resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    assert not target.exists(), "new isolated target required"
    assert not os.environ.get("LLVM_PROFILE_FILE")
    assert all("instrument-coverage" not in os.environ.get(name, "")
               for name in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"))
    command = ["cargo", "+1.90.0", "build", "--release", "--frozen", "--manifest-path",
               "experiments/object-gc-store/Cargo.toml", "--message-format=json-render-diagnostics"]
    record = {"schema": 1, "status": "failed", "scope": "GC-transport-only", "target": str(target),
              "command": command, "source_root": str(ROOT), "inputs": inputs()}
    try:
        record["source_commit"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        record["source_dirty"] = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT))
        assert record["source_dirty"] is False, "freeze candidate first"
        record["tools"] = {}
        for name in ("cargo", "rustc"):
            path = Path(subprocess.check_output(["rustup", "which", "--toolchain", "1.90.0", name], text=True).strip())
            record["tools"][name] = {"path": str(path), "sha256": digest(path)}
        record["versions"] = {name: subprocess.check_output([name, "+1.90.0", "-Vv"], text=True)
                              for name in ("cargo", "rustc")}
        env = dict(os.environ, CARGO_TARGET_DIR=str(target), CARGO_INCREMENTAL="0", CARGO_BUILD_JOBS="1")
        with (evidence / "cargo.stdout.jsonl").open("wb") as out, (evidence / "cargo.stderr.log").open("wb") as err:
            result = subprocess.run(command, cwd=ROOT, env=env, stdout=out, stderr=err, check=False)
            for stream in (out, err):
                stream.flush()
                os.fsync(stream.fileno())
        record["exit_code"] = result.returncode
        record["logs"] = {name: digest(evidence / name) for name in ("cargo.stdout.jsonl", "cargo.stderr.log")}
        assert result.returncode == 0, "GC worker build failed"
        assert record["inputs"] == inputs(), "source changed during compilation"
        events = [json.loads(line) for line in (evidence / "cargo.stdout.jsonl").read_text().splitlines()]
        assert events[-1] == {"reason": "build-finished", "success": True}
        record["binary"], record["native_archives"] = artifact(events, target)
        record["status"] = "passed"
    except BaseException as error:
        record["error"] = repr(error)
        raise
    finally:
        (evidence / "build.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    verify(evidence / "build.json", Path(record["binary"]["path"]))
    print(json.dumps({"status": record["status"], "binary": record["binary"]}), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    run(parser.parse_args())
