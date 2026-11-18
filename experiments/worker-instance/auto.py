#!/usr/bin/env python3
"""Actual automatic worker allocation: daemon, local S3, native SQLite, faults.

This only provisions and observes production code. It does not allocate IDs in
the fixture, repair missing counters, or qualify AWS/IAM. Raw private backend
credentials and data remain in a temporary directory outside public evidence.
"""
from __future__ import annotations

import argparse
import base64
import http.client
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("explicit_instance_fixture", Path(__file__).with_name("run.py"))
BASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASE)
NET = BASE.NET
COUNTER = "scap-worker/v1/allocator"
TOKEN = "startup-test-token-0123456789abcdef"


class Deployment:
    def __init__(self, suite, label, worker="auto", bucket="scap-test", port=None):
        self.cache = suite.private / (label + "-cache")
        self.cache.mkdir()
        self.port = port or NET.free_port(suite.ports)
        self.path = suite.evidence / (label + "-config.json")
        config = BASE.configuration(self.port, self.cache, suite.proxy.endpoint, worker)
        config["s3"]["bucket"] = bucket
        config["credentials"][0]["provision"] = True
        config["admission"]["timeout_ms"] = 5000
        config["admission"]["recovery_timeout_ms"] = 10000
        self.path.write_text(json.dumps(config, indent=2) + "\n")
        self.sha256 = BASE.sha(self.path)


class Service(BASE.Service):
    def __init__(self, suite, label, deployment):
        self.suite, self.label, self.deployment = suite, label, deployment
        self.port, self.cache, self.worker = deployment.port, deployment.cache, "auto"
        self.cache_before = self.cache_snapshot()
        assert BASE.sha(deployment.path) == deployment.sha256, "restart configuration changed"
        self.stderr = suite.evidence / (label + ".stderr.log")
        with (suite.evidence / (label + ".stdout.log")).open("wb") as output, self.stderr.open("wb") as error:
            self.child = subprocess.Popen([str(suite.binary), str(deployment.path)],
                stdin=subprocess.DEVNULL, stdout=output, stderr=error, env=suite.environment())
        self.identity = NET.process_identity(self.child)
        suite.services.append(self)
        NET.record(suite.evidence, "service_spawned", label=label, identity=self.identity,
                   configuration_sha256=deployment.sha256)

    def cache_snapshot(self):
        return {str(path.relative_to(self.cache)): "directory" if path.is_dir() else BASE.sha(path)
                for path in self.cache.rglob("*")}

    def records(self):
        return [json.loads(line) for line in self.stderr.read_text().splitlines() if line.startswith("{")]

    def wait_ready(self):
        super().wait_ready()
        records = self.records()
        assert [row["event"] for row in records] == ["worker_identity_claimed", "worker_identity_ready"], records
        assigned = records[0]["worker_instance"]
        assert records[1]["worker_instance"] == assigned
        self.worker = int(assigned)
        assert str(self.worker) == assigned and 0 < self.worker < 2**64
        NET.record(self.suite.evidence, "assigned_identity", label=self.label, worker=assigned)
        return self.worker

    def expect_failure(self, code, claimed=False):
        status, usage = NET.wait_child(self.child, 15)
        assert status == 1, (self.label, status, self.stderr.read_text())
        lines = self.stderr.read_text().splitlines()
        assert [line for line in lines if not line.startswith("{")] == [f"scapd: {code}"], lines
        records = self.records()
        assert [row["event"] for row in records] == (["worker_identity_claimed"] if claimed else []), records
        assert not self.ready(), "failed startup exposed a listener"
        assert self.cache_snapshot() == self.cache_before, "failed startup modified or leaked worker cache"
        NET.record(self.suite.evidence, "startup_rejected", label=self.label, code=code,
                   identity_records=records, status=status, usage=usage)
        return int(records[0]["worker_instance"]) if claimed else None

    def api(self, operation, **fields):
        body = {"version": 1, "scope": {"deployment": "1", "tenant": "1", "database": "1",
                "incarnation": "1", "generation": "1"}, "operation": operation, **fields}
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=12)
        try:
            connection.request("POST", "/v1", json.dumps(body),
                {"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json",
                 "x-scap-admission": {"status": "control", "activate": "recovery"}.get(operation, "data")})
            response = connection.getresponse()
            value = json.loads(response.read(65536))
            NET.record(self.suite.evidence, "native_api_response", operation=operation,
                       status=response.status, value=value)
            return value
        finally:
            connection.close()


class Suite(BASE.Suite):
    def __init__(self, binary, weed, evidence, private):
        self.binary, self.evidence, self.private = binary, evidence, private
        self.ports, self.services, self.cases = set(), [], []
        # Seaweed allocates volumes per bucket collection. Reserve a bounded
        # fixture capacity for three buckets; the inherited single-bucket
        # fixture's two volume slots cannot provision this suite. The pinned
        # master scaffold grows seven volumes for each unreplicated bucket.
        self.backend = NET.Backend(weed, private / "backend", max_volumes=24)
        self.proxy = None

    def environment(self):
        return dict(os.environ, SCAP_INSTANCE_ACCESS=self.backend.access,
                    SCAP_INSTANCE_SECRET=self.backend.secret)

    def prepare_bucket(self, bucket):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self.backend.signed("PUT", "/" + bucket) and self.backend.signed("PUT", "/" + bucket + "/fixture-ready", "ready"):
                NET.record(self.evidence, "fixture_bucket_ready", bucket=bucket)
                return
            time.sleep(.1)
        raise TimeoutError("additional fixture bucket readiness")

    def initialize(self, label, deployment, floor, error=None):
        path = self.evidence / (label + ".stderr.log")
        with (self.evidence / (label + ".stdout.log")).open("wb") as output, path.open("wb") as stderr:
            child = subprocess.Popen([str(self.binary), "--init-worker-allocator", str(deployment.path), str(floor)],
                stdin=subprocess.DEVNULL, stdout=output, stderr=stderr, env=self.environment())
        try:
            status, usage = NET.wait_child(child, 15)
        finally:
            if child.poll() is None:
                child.kill()
                NET.wait_child(child, 8)
        assert status == (1 if error else 0), path.read_text()
        if error:
            assert path.read_text() == f"scapd: {error}\n"
        else:
            assert json.loads(path.read_text()) == {"event": "worker_allocator_initialized", "high_water": str(floor)}
        assert not list(deployment.cache.iterdir())
        NET.record(self.evidence, "allocator_initialized" if not error else "initialization_rejected",
                   label=label, floor=str(floor), code=error, status=status, usage=usage)

    def verified(self, name, expected, **detail):
        # The persisted proxy ledger is complete even when full HEAD byte
        # capture is disabled; no database contents are needed for this oracle.
        observed = [json.loads(line) for line in (self.evidence / "history.jsonl").read_text().splitlines()]
        rows = [row for row in observed if row.get("phase") == name and row["event"] == "object_request"]
        counter = [row for row in rows if row["path"].endswith("/" + COUNTER)]
        marker = [row for row in rows if "/" + BASE.PREFIX in row["path"]]
        actual = {
            "counter_get": sum(row["method"] == "GET" for row in counter),
            "counter_create": sum(row["method"] == "PUT" and row["if_none_match"] == "*" for row in counter),
            "counter_cas": sum(row["method"] == "PUT" and row["if_match"] is not None for row in counter),
            "marker_put": sum(row["method"] == "PUT" for row in marker),
            "marker_get": sum(row["method"] == "GET" for row in marker),
        }
        assert actual == dict(zip(actual, expected)), (name, actual, expected)
        for row in counter:
            if row["method"] == "PUT":
                assert (row["if_none_match"] == "*") != (row["if_match"] is not None)
        assert all(row["if_none_match"] == "*" and row["if_match"] is None
                   for row in marker if row["method"] == "PUT")
        case = {"name": name, **actual, **detail}
        self.cases.append(case)
        NET.record(self.evidence, "case_verified", **case)

    def run(self):
        self.backend.start()
        self.proxy = NET.Proxy(self.backend.port, self.evidence)
        deployment = Deployment(self, "unchanged-auto")
        self.phase("missing-counter")
        Service(self, "missing-counter", deployment).expect_failure("INSTANCE_ALLOCATOR_MISSING")
        self.verified("missing-counter", (1, 0, 0, 0, 0))

        self.phase("explicit-initialization")
        self.initialize("initialize", deployment, 100)
        self.verified("explicit-initialization", (1, 1, 0, 0, 0))
        self.phase("initialization-cannot-reset")
        self.initialize("initialize-again", deployment, 0, "INSTANCE_ALLOCATOR_EXISTS")
        self.verified("initialization-cannot-reset", (0, 1, 0, 0, 0))

        self.phase("automatic-first-start")
        first = Service(self, "first", deployment)
        assert first.wait_ready() == 101
        self.verified("automatic-first-start", (1, 0, 1, 1, 1), assigned="101")
        self.phase("assigned-id-reaches-native-sqlite")
        created = first.api("create", nonce="1")
        assert created["ok"] and created["value"]["owner_instance"] == "101", created
        guarded = first.api("status", expected_worker_instance="100")
        assert guarded["error"]["code"] == "TARGET_MISMATCH", guarded
        activated = first.api("activate", expected_revision="1", nonce="2", expected_worker_instance="101")
        assert activated["ok"] and activated["value"]["active"], activated
        queried = first.api("query", statements=[{"sql": "SELECT 42 AS x", "params": []}])
        expected = b"SCAPRES1" + struct.pack("<III", 1, 1, 1) + b"x" + struct.pack("<I", 1) + b"\x01" + struct.pack("<qQq", 42, 0, 0)
        assert queried["ok"] and base64.b64decode(queried["value"]["result"], validate=True) == expected, queried
        self.verified("assigned-id-reaches-native-sqlite", (0, 0, 0, 0, 0), integer_result=42)
        first.stop()

        self.phase("same-config-clean-restart")
        restarted = Service(self, "clean-restart", deployment)
        assert restarted.wait_ready() == 102
        self.verified("same-config-clean-restart", (1, 0, 1, 1, 1), configuration_sha256=deployment.sha256, assigned="102")
        restarted.stop(crash=True)
        shutil.rmtree(deployment.cache)
        deployment.cache.mkdir()
        NET.record(self.evidence, "fixture_all_compute_cache_lost", configuration_sha256=deployment.sha256)
        self.phase("same-config-crash-restart")
        restarted = Service(self, "crash-restart", deployment)
        assert restarted.wait_ready() == 103
        stale = restarted.api("status", expected_worker_instance="101")
        assert not stale["ok"] and stale["error"]["code"] == "TARGET_MISMATCH", stale
        observed = restarted.api("status", expected_worker_instance="103")
        assert observed["ok"] and observed["value"]["owner_instance"] == "101", observed
        self.verified("same-config-crash-restart", (1, 0, 1, 1, 1), configuration_sha256=deployment.sha256,
                      assigned="103", all_compute_cache_lost=True, stale_route_rejected=True,
                      prior_database_owner_unchanged="101")
        restarted.stop()

        self.phase("concurrent-auto-startups")
        pair = self.proxy.arm("pair", method="PUT", key=COUNTER)
        contenders = [Service(self, f"auto-racer-{i}", Deployment(self, f"racer-{i}")) for i in range(2)]
        assigned = sorted(service.wait_ready() for service in contenders)
        assert assigned == [104, 105] and pair.used == 2
        self.verified("concurrent-auto-startups", (3, 0, 3, 2, 2), assigned=[str(value) for value in assigned])
        for service in contenders:
            service.stop()

        self.phase("explicit-claim-wins-auto-reservation")
        held = self.proxy.arm("hold", method="PUT", key=BASE.PREFIX + "106")
        automatic = Service(self, "collision-auto", Deployment(self, "collision-auto"))
        assert held.arrived.wait(12)
        explicit = Service(self, "collision-explicit", Deployment(self, "collision-explicit", worker=106))
        assert explicit.wait_ready() == 106
        held.release.set()
        assert automatic.wait_ready() == 107
        self.verified("explicit-claim-wins-auto-reservation", (2, 0, 2, 3, 2), assigned=["106", "107"])
        explicit.stop()
        automatic.stop()

        self.phase("lost-counter-cas-ack")
        lost = self.proxy.arm("drop", method="PUT", key=COUNTER,
                              stage="after_upstream_response", expected_status=200)
        ambiguous = Service(self, "lost-counter-cas-ack", deployment)
        assert lost.arrived.wait(12)
        lost.release.set()
        ambiguous.expect_failure("INSTANCE_UNKNOWN")
        self.verified("lost-counter-cas-ack", (1, 0, 1, 0, 0), burned="108")
        self.phase("restart-skips-lost-counter-ack")
        restarted = Service(self, "after-counter-loss", deployment)
        assert restarted.wait_ready() == 109
        self.verified("restart-skips-lost-counter-ack", (1, 0, 1, 1, 1), assigned="109")
        restarted.stop()

        self.phase("lost-marker-create-ack")
        lost = self.proxy.arm("drop", method="PUT", key=BASE.PREFIX + "110",
                              stage="after_upstream_response", expected_status=200)
        ambiguous = Service(self, "lost-marker-create-ack", deployment)
        assert lost.arrived.wait(12)
        lost.release.set()
        ambiguous.expect_failure("INSTANCE_UNKNOWN")
        self.verified("lost-marker-create-ack", (1, 0, 1, 1, 0), burned="110")
        self.phase("restart-skips-lost-marker-ack")
        restarted = Service(self, "after-marker-loss", deployment)
        assert restarted.wait_ready() == 111
        self.verified("restart-skips-lost-marker-ack", (1, 0, 1, 1, 1), assigned="111")
        restarted.stop()

        with socket.socket() as occupied:
            occupied.bind(("127.0.0.1", 0))
            occupied.listen()
            blocked = Deployment(self, "bind-failure", port=occupied.getsockname()[1])
            self.phase("claimed-is-not-ready")
            failed = Service(self, "bind-failure", blocked)
            assert failed.expect_failure("LISTEN", claimed=True) == 112
            self.verified("claimed-is-not-ready", (1, 0, 1, 1, 1), burned="112", ready_record=False)
        self.phase("restart-after-listener-failure")
        restarted = Service(self, "after-bind-failure", blocked)
        assert restarted.wait_ready() == 113
        self.verified("restart-after-listener-failure", (1, 0, 1, 1, 1), assigned="113", configuration_sha256=blocked.sha256)
        restarted.stop()

        self.prepare_bucket("scap-overflow-test")
        overflow = Deployment(self, "overflow", bucket="scap-overflow-test")
        self.phase("last-u64-in-independent-bucket")
        self.initialize("overflow-initialize", overflow, 2**64 - 2)
        last = Service(self, "last-u64", overflow)
        assert last.wait_ready() == 2**64 - 1
        self.verified("last-u64-in-independent-bucket", (2, 1, 1, 1, 1), assigned=str(2**64 - 1))
        last.stop()
        self.phase("allocator-exhausted-without-wrap")
        Service(self, "exhausted", overflow).expect_failure("INSTANCE_EXHAUSTED")
        self.verified("allocator-exhausted-without-wrap", (1, 0, 0, 0, 0))

        self.prepare_bucket("scap-corrupt-test")
        corrupt = Deployment(self, "corrupt", bucket="scap-corrupt-test")
        self.phase("corrupt-counter")
        self.initialize("corrupt-initialize", corrupt, 0)
        assert self.backend.signed("PUT", "/scap-corrupt-test/" + COUNTER, "corrupt")
        NET.record(self.evidence, "fixture_counter_corrupted", bucket="scap-corrupt-test")
        Service(self, "corrupt-counter", corrupt).expect_failure("INSTANCE_CORRUPT")
        self.verified("corrupt-counter", (2, 1, 0, 0, 0))
        assert not self.proxy.errors, self.proxy.errors
        return self.cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--weed", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    assert not os.environ.get("LLVM_PROFILE_FILE"), "runtime cannot contribute unit coverage"
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    result = {"schema": 1, "status": "FAILED", "scope": "actual daemon, native SQLite and pinned local S3; AWS/IAM NOT_RUN",
        "binary_sha256": BASE.sha(args.binary), "backend_sha256": BASE.sha(args.weed),
        "source_sha256": {str(path.relative_to(ROOT)): BASE.sha(path) for path in (ROOT / "crates").rglob("*.rs")}}
    try:
        with tempfile.TemporaryDirectory(prefix="scap-auto-instance-") as temporary:
            suite = Suite(args.binary.resolve(), args.weed.resolve(), evidence, Path(temporary))
            result["backend_capacity"] = suite.backend.capacity
            try:
                cases = suite.run()
            finally:
                suite.close()
            result.update(status="PASSED", cases=cases)
    finally:
        (evidence / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": result["status"], "cases": len(result["cases"]), "evidence": str(evidence)}))


if __name__ == "__main__":
    main()
