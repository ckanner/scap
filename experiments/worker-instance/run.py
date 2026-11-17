#!/usr/bin/env python3
"""Actual scapd startup claims on pinned local S3, outside unit coverage.

No product behavior is implemented here: the fixture provisions SeaweedFS,
relays signed requests, controls process loss/transport faults, and checks the
observable startup results. It does not qualify AWS or an IAM policy.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("instance_network", ROOT / "experiments/object-network/run.py")
NET = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NET)
PREFIX = "scap-worker/v1/instances/"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def configuration(port, cache, endpoint, worker):
    return {
        "version": 1, "listen": f"127.0.0.1:{port}", "worker_instance": str(worker),
        "cache_directory": str(cache),
        "s3": {"endpoint": endpoint, "region": "us-east-1", "bucket": "scap-test",
               "access_key_env": "SCAP_INSTANCE_ACCESS", "secret_key_env": "SCAP_INSTANCE_SECRET",
               "session_token_env": None, "allow_http": True, "timeout_ms": 10000},
        "admission": {"active_database_actors": 1, "active_database_actors_per_tenant": 1,
                      "actor_idle_timeout_ms": 1000, "control_workers": 1,
                      "queued_total": 4, "queued_per_tenant": 2, "queued_per_database": 2,
                      "reserved_controls": 1, "data_intake": 2, "control_intake": 2,
                      "recovery_intake": 2, "max_body_bytes": 4096,
                      "timeout_ms": 1000, "recovery_timeout_ms": 1000},
        "cache": {"pages_per_actor": 1024, "parallel_recoveries": 1},
        "credentials": [{"sha256": hashlib.sha256(b"startup-test-token-0123456789abcdef").hexdigest(),
                         "deployment": "1", "tenant": "1", "principal": "1", "provision": False}],
    }


class Service:
    def __init__(self, suite, label, worker, endpoint=None):
        self.suite, self.label, self.worker = suite, label, worker
        self.port = NET.free_port(suite.ports)
        self.cache = suite.private / (label + "-cache")
        self.cache.mkdir()
        config = suite.evidence / (label + "-config.json")
        config.write_text(json.dumps(configuration(self.port, self.cache,
            endpoint or suite.proxy.endpoint, worker), indent=2) + "\n")
        self.stderr = suite.evidence / (label + ".stderr.log")
        with (suite.evidence / (label + ".stdout.log")).open("wb") as output, self.stderr.open("wb") as error:
            self.child = subprocess.Popen([str(suite.binary), str(config)], stdin=subprocess.DEVNULL,
                stdout=output, stderr=error, env=dict(os.environ,
                    SCAP_INSTANCE_ACCESS=suite.backend.access, SCAP_INSTANCE_SECRET=suite.backend.secret))
        self.identity = NET.process_identity(self.child)
        suite.services.append(self)
        NET.record(suite.evidence, "service_spawned", label=label, worker=worker, identity=self.identity)

    def ready(self):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=.3)
        try:
            connection.request("GET", "/healthz")
            response = connection.getresponse()
            return response.status == 200 and json.loads(response.read(4096)) == {"status": "alive", "protocol": 1}
        except (OSError, ValueError, http.client.HTTPException):
            return False
        finally:
            connection.close()

    def wait_ready(self):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            assert self.child.poll() is None, self.stderr.read_text()
            if self.ready():
                NET.record(self.suite.evidence, "service_ready", label=self.label, worker=self.worker)
                return
            time.sleep(.02)
        raise TimeoutError("startup readiness deadline")

    def expect_failure(self, code):
        status, usage = NET.wait_child(self.child, 15)
        assert status == 1, (self.label, status, self.stderr.read_text())
        assert self.stderr.read_text() == f"scapd: {code}\n", self.stderr.read_text()
        assert not self.ready(), "failed startup exposed a listener"
        assert not list(self.cache.iterdir()), "failed claim created service worker files"
        NET.record(self.suite.evidence, "startup_rejected", label=self.label, worker=self.worker,
                   code=code, status=status, usage=usage)

    def stop(self, crash=False):
        if self.child.poll() is None:
            self.child.send_signal(signal.SIGKILL if crash else signal.SIGINT)
            status, usage = NET.wait_child(self.child, 8)
            assert status == (-signal.SIGKILL if crash else 0), (self.label, status)
            NET.record(self.suite.evidence, "service_stopped", label=self.label, crash=crash,
                       status=status, usage=usage)


class Suite:
    def __init__(self, binary, weed, evidence, private):
        self.binary, self.evidence, self.private = binary, evidence, private
        self.ports, self.services, self.cases = set(), [], []
        self.backend = NET.Backend(weed, private / "backend")
        self.proxy = None

    def phase(self, name):
        self.proxy.set_phase(name)

    def verified(self, name, puts, gets):
        rows = [r for r in self.proxy.observations if r.get("phase") == name and r["event"] == "object_request"]
        assert sum(r["method"] == "PUT" for r in rows) == puts, rows
        assert sum(r["method"] == "GET" for r in rows) == gets, rows
        assert all(r["if_none_match"] == "*" and r["if_match"] is None for r in rows if r["method"] == "PUT")
        assert all(r["path"].startswith("/scap-test/" + PREFIX) for r in rows)
        self.cases.append({"name": name, "put_count": puts, "get_count": gets})
        NET.record(self.evidence, "case_verified", **self.cases[-1])

    def run(self):
        self.backend.start()
        self.proxy = NET.Proxy(self.backend.port, self.evidence)
        self.proxy.capture = True
        self.phase("first-start")
        first = Service(self, "first", 100)
        first.wait_ready()
        self.verified("first-start", 1, 1)

        self.phase("duplicate-live")
        Service(self, "duplicate-live", 100).expect_failure("INSTANCE_REUSED")
        self.verified("duplicate-live", 1, 0)
        first.stop()
        self.phase("duplicate-clean-exit")
        Service(self, "duplicate-clean-exit", 100).expect_failure("INSTANCE_REUSED")
        self.verified("duplicate-clean-exit", 1, 0)

        self.phase("new-id")
        fresh = Service(self, "fresh", 101)
        fresh.wait_ready()
        self.verified("new-id", 1, 1)
        fresh.stop(crash=True)
        self.phase("duplicate-crash")
        Service(self, "duplicate-crash", 101).expect_failure("INSTANCE_REUSED")
        self.verified("duplicate-crash", 1, 0)

        self.phase("competing-processes")
        pair = self.proxy.arm("pair", method="PUT", key=PREFIX + "102")
        contenders = [Service(self, f"racer-{i}", 102) for i in range(2)]
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            ready = [service for service in contenders if service.ready()]
            if ready:
                assert len(ready) == 1
                winner = ready[0]
                loser = next(service for service in contenders if service is not winner)
                loser.expect_failure("INSTANCE_REUSED")
                assert winner.ready()
                winner.stop()
                break
            time.sleep(.02)
        else:
            raise TimeoutError("competing startup deadline")
        assert pair.used == 2
        self.verified("competing-processes", 2, 1)

        self.phase("lost-create-ack")
        lost = self.proxy.arm("drop", method="PUT", key=PREFIX + "103",
                              stage="after_upstream_response", expected_status=200)
        ambiguous = Service(self, "lost-create-ack", 103)
        assert lost.arrived.wait(12)
        lost.release.set()
        ambiguous.expect_failure("INSTANCE_UNKNOWN")
        self.verified("lost-create-ack", 1, 0)
        self.phase("unknown-id-remains-consumed")
        Service(self, "unknown-id-remains-consumed", 103).expect_failure("INSTANCE_REUSED")
        self.verified("unknown-id-remains-consumed", 1, 0)

        self.phase("corrupt-readback")
        held = self.proxy.arm("hold", method="GET", key=PREFIX + "104")
        corrupt = Service(self, "corrupt-readback", 104)
        assert held.arrived.wait(12)
        # Privileged fault injection only: replace the real backend record
        # after creation, before its exact readback. Product never overwrites.
        assert self.backend.signed("PUT", "/scap-test/" + PREFIX + "104", "corrupt")
        NET.record(self.evidence, "fixture_marker_replaced", worker=104)
        held.release.set()
        corrupt.expect_failure("INSTANCE_CORRUPT")
        self.verified("corrupt-readback", 1, 1)

        self.phase("unreachable-backend")
        # Keep the bound socket open without listening: nothing else can claim
        # the endpoint between choosing it and the daemon's connection attempt.
        with socket.socket() as unavailable:
            unavailable.bind(("127.0.0.1", 0))
            endpoint = f"http://127.0.0.1:{unavailable.getsockname()[1]}"
            Service(self, "unreachable-backend", 105, endpoint).expect_failure("INSTANCE_UNKNOWN")
        self.verified("unreachable-backend", 0, 0)
        assert not self.proxy.errors, self.proxy.errors
        return self.cases

    def close(self):
        if self.proxy is not None:
            self.proxy.clear()
        for service in self.services:
            service.stop(crash=True)
        if self.proxy is not None:
            self.proxy.close()
        self.backend.stop()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--weed", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    assert not os.environ.get("LLVM_PROFILE_FILE"), "runtime cannot contribute unit coverage"
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    result = {"schema": 1, "scope": "actual daemon and pinned local S3; AWS/IAM NOT_RUN",
              "binary": {"path": str(args.binary.resolve()), "sha256": sha(args.binary)},
              "backend": {"path": str(args.weed.resolve()), "sha256": sha(args.weed)},
              "sources": {str(path.relative_to(ROOT)): sha(path) for path in (ROOT / "crates").rglob("*.rs")},
              "status": "FAILED"}
    try:
        with tempfile.TemporaryDirectory(prefix="scap-instance-") as directory:
            suite = Suite(args.binary.resolve(), args.weed.resolve(), evidence, Path(directory))
            try:
                cases = suite.run()
            finally:
                suite.close()
            result["cases"] = cases
            result["status"] = "PASSED"
    finally:
        (evidence / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": result["status"], "cases": len(result["cases"]), "evidence": str(evidence)}))


if __name__ == "__main__":
    main()
