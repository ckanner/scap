#!/usr/bin/env python3
"""Provision the existing pinned S3 fixture, then run the actual Node/Rust S2 API.

Only orchestration lives here. Production restore logic remains in Rust and the
public client. Private credentials/backend files never enter the report.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("restore_network", ROOT / "experiments/object-network/run.py")
NET = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NET)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inputs():
    fixture = Path(__file__).resolve().parent
    paths = set(fixture.glob("*.mjs")) | {fixture / "run.py", fixture / "README.md",
        ROOT / "experiments/object-network/run.py", ROOT / "sdk/node/package.json",
        ROOT / "sdk/node-codec/package.json"}
    for directory in [ROOT / "sdk/node/src", ROOT / "sdk/node-codec/src"]:
        paths.update(directory.rglob("*.js"))
    return {str(path.relative_to(ROOT)): digest(path) for path in sorted(paths)}


def node_gate(node, arguments, evidence, label):
    with (evidence / f"{label}.stdout.log").open("wb") as output, (evidence / f"{label}.stderr.log").open("wb") as error:
        result = subprocess.run([str(node), *arguments], stdout=output, stderr=error, timeout=60, check=False)
    assert result.returncode == 0, f"{label} failed; retain original evidence"
    return {"status": "PASS", "exit_status": result.returncode}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--weed", type=Path, required=True)
    parser.add_argument("--node", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    started = time.time_ns()
    result = {"schema_version": 2, "started_unix_ns": started, "status": "FAILED",
        "backend": "SeaweedFS 4.51 (local compatibility endpoint, not AWS)",
        "scope": "actual daemon/HTTP/Node/native/S3 restore witnesses; separate from unit coverage",
        "gates": {name: {"status": "NOT_RUN"} for name in ["auditor_unit", "probe", "independent_audit", "negative_controls", "input_freeze", "backend_cleanup"]}}
    stage = "input_freeze"
    try:
        assert "LLVM_PROFILE_FILE" not in os.environ, "runtime must not contribute to unit coverage"
        tools = {key: {"path": str(path.resolve()), "sha256": digest(path)}
                 for key, path in [("server", args.server), ("weed", args.weed), ("node", args.node)]}
        before = inputs()
        source = {"commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                  "tree": subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT, text=True).strip(),
                  "tracked_changes": subprocess.check_output(["git", "diff", "--name-only", "HEAD"], cwd=ROOT, text=True).splitlines()}
        manifest = {"schema_version": 1, "harness_source": source, "inputs_before": before, "tools_before": tools,
                    "server_source_binding": "binary SHA-256 only; pair with the independently frozen build manifest"}
        (evidence / "input-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        result["tools"] = tools
        stage = "auditor_unit"
        result["gates"][stage] = node_gate(args.node.resolve(), ["--test", str(Path(__file__).with_name("audit.test.mjs"))], evidence, stage)
        with tempfile.TemporaryDirectory(prefix="scap-s2-private-") as temporary:
            private = Path(temporary)
            backend = NET.Backend(args.weed.resolve(), private / "backend", max_volumes=4)
            try:
                stage = "backend_start"
                backend.start()
                environment = dict(os.environ, SCAP_RESTORE_ACCESS=backend.access,
                                   SCAP_RESTORE_SECRET=backend.secret)
                stage = "probe"
                with (evidence / "probe.stdout.log").open("wb") as output, (evidence / "probe.stderr.log").open("wb") as error:
                    process = subprocess.Popen([str(args.node.resolve()), str(Path(__file__).with_name("probe.mjs")),
                        str(args.server.resolve()), backend.endpoint, str(private), str(evidence)],
                        env=environment, stdout=output, stderr=error, start_new_session=True)
                    try:
                        process.wait(timeout=240)
                    except subprocess.TimeoutExpired:
                        # Reap the entire owned Node/daemon process group on timeout.
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=10)
                result["gates"][stage] = {"status": "PASS" if process.returncode == 0 else "FAILED", "exit_status": process.returncode}
                assert process.returncode == 0, "S2 probe failed; retain original logs"
                stage = "independent_audit"
                result["gates"][stage] = node_gate(args.node.resolve(), [str(Path(__file__).with_name("audit.mjs")), str(evidence)], evidence, stage)
                stage = "negative_controls"
                result["gates"][stage] = node_gate(args.node.resolve(), [str(Path(__file__).with_name("negative-controls.mjs")), str(evidence)], evidence, stage)
            finally:
                cleanup = backend.stop()
                result["backend_cleanup"] = cleanup
                valid = len(cleanup) == 4 and all(item["wait_status"] == -signal.SIGKILL for item in cleanup)
                result["gates"]["backend_cleanup"] = {"status": "PASS" if valid else "FAILED"}
                assert valid, "backend cleanup was not confirmed"
        stage = "input_freeze"
        after = inputs()
        after_tools = {key: {"path": item["path"], "sha256": digest(Path(item["path"]))} for key, item in tools.items()}
        manifest.update(inputs_after=after, tools_after=after_tools)
        (evidence / "input-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        assert before == after and tools == after_tools, "input changed during runtime"
        result["gates"][stage] = {"status": "PASS"}
        result["input_manifest_sha256"] = digest(evidence / "input-manifest.json")
        result["audit_sha256"] = digest(evidence / "audit.jsonl")
        result["status"] = "PASS"
    except Exception as failure:
        result["failure"] = {"stage": stage, "type": type(failure).__name__}
        if stage in result["gates"] and result["gates"][stage]["status"] == "NOT_RUN":
            result["gates"][stage] = {"status": "FAILED"}
    finally:
        result["finished_unix_ns"] = time.time_ns()
        (evidence / "run.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
