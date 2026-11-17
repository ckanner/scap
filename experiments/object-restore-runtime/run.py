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
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("restore_network", ROOT / "experiments/object-network/run.py")
NET = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NET)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--weed", type=Path, required=True)
    parser.add_argument("--node", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    tools = {key: {"path": str(path.resolve()), "sha256": digest(path)}
             for key, path in [("server", args.server), ("weed", args.weed), ("node", args.node)]}
    started = time.time_ns()
    with tempfile.TemporaryDirectory(prefix="scap-s2-private-") as temporary:
        private = Path(temporary)
        backend = NET.Backend(args.weed.resolve(), private / "backend", max_volumes=4)
        try:
            backend.start()
            environment = dict(os.environ, SCAP_RESTORE_ACCESS=backend.access,
                               SCAP_RESTORE_SECRET=backend.secret)
            with (evidence / "probe.stdout.log").open("wb") as output, (evidence / "probe.stderr.log").open("wb") as error:
                process = subprocess.Popen([str(args.node.resolve()), str(Path(__file__).with_name("probe.mjs")),
                    str(args.server.resolve()), backend.endpoint, str(private), str(evidence)],
                    env=environment, stdout=output, stderr=error, start_new_session=True)
                try:
                    process.wait(timeout=240)
                except subprocess.TimeoutExpired:
                    # The Node probe owns actual daemon children. Reap its
                    # entire owned group on fixture timeout, not only Node.
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=10)
            result = {"schema_version": 1, "started_unix_ns": started, "finished_unix_ns": time.time_ns(),
                "backend": "SeaweedFS 4.51 (local compatibility endpoint, not AWS)",
                "tools": tools, "status": "PASS" if process.returncode == 0 else "FAILED",
                "exit_status": process.returncode,
                "scope": "actual daemon/HTTP/Node/native/S3 restore cases; separate from unit coverage"}
            (evidence / "run.json").write_text(json.dumps(result, indent=2) + "\n")
            assert process.returncode == 0, "S2 probe failed; retain original logs"
            assert all(digest(Path(item["path"])) == item["sha256"] for item in tools.values())
        finally:
            backend.stop()
    print(json.dumps(result))


if __name__ == "__main__":
    main()
