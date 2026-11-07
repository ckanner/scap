#!/usr/bin/env python3
"""Real daemon + Node SDK + signed local S3 fault and recovery contracts.

Only private fixture resources are created. No AWS resources or credentials are
discovered. Independent input/ACK ledgers survive all compute/cache destruction.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time

if not __debug__:
    raise RuntimeError("validation requires Python assertions; disable -O/PYTHONOPTIMIZE")

import build

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "experiments" / "object-network"))
from run import Backend, Proxy, free_port, process_identity, wait_child  # noqa: E402


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def config(port, owner, cache, endpoint, tokens):
    credentials = [
        {"sha256": sha(tokens["admin"]), "deployment": "1", "tenant": "7", "principal": "11", "provision": True},
        {"sha256": sha(tokens["reader"]), "deployment": "1", "tenant": "7", "principal": "12", "provision": False},
        {"sha256": sha(tokens["other"]), "deployment": "1", "tenant": "8", "principal": "22", "provision": True},
    ]
    return {"version": 1, "listen": f"127.0.0.1:{port}", "worker_instance": str(owner),
            "cache_directory": str(cache), "s3": {"endpoint": endpoint,
            "region": "us-east-1", "bucket": "scap-test", "access_key_env": "SCAP_TEST_ACCESS",
            "secret_key_env": "SCAP_TEST_SECRET", "session_token_env": None,
            "allow_http": True, "timeout_ms": 2000}, "admission": {
            "workers": 4, "control_workers": 2, "queued_per_worker": 32, "queued_per_tenant": 16,
            "queued_per_database": 8, "reserved_controls": 2, "data_intake": 8, "control_intake": 4,
            "recovery_intake": 2, "max_body_bytes": 100663296, "timeout_ms": 5000,
            "recovery_timeout_ms": 30000}, "cache": {"sessions_per_worker": 4,
            "pages_per_worker": 5242880, "parallel_recoveries": 2}, "credentials": credentials}


class Service:
    def __init__(self, binary, private, owner, endpoint, tokens, backend):
        self.owner = owner
        self.port = free_port(set())
        self.cache = private / f"compute-{owner}"
        self.cache.mkdir(mode=0o700)
        self.configuration = private / f"service-{owner}.private.json"
        self.configuration.write_text(json.dumps(config(self.port, owner, self.cache, endpoint, tokens)))
        self.configuration.chmod(0o600)
        environment = dict(os.environ, SCAP_TEST_ACCESS=backend.access, SCAP_TEST_SECRET=backend.secret)
        self.log = private / f"service-{owner}.private.log"
        with self.log.open("wb") as stream:
            self.process = subprocess.Popen([str(binary), str(self.configuration)], env=environment,
                                            stdout=stream, stderr=stream)
        self.identity = process_identity(self.process)
        self.endpoint = f"http://127.0.0.1:{self.port}"
        try:
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                assert self.process.poll() is None, "daemon exited before liveness probe"
                connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=0.5)
                try:
                    connection.request("GET", "/healthz")
                    response = connection.getresponse()
                    body = json.loads(response.read(4096))
                    if response.status == 200 and body == {"status": "alive", "protocol": 1}:
                        return
                except (OSError, ValueError, http.client.HTTPException):
                    pass
                finally:
                    connection.close()
                time.sleep(0.05)
            raise RuntimeError("daemon liveness probe deadline")
        except BaseException:
            self.stop()
            raise

    def stop(self):
        if self.process.poll() is None:
            self.process.kill()
        status, usage = wait_child(self.process, 10)
        return {"owner_instance": self.owner, **self.identity, "wait_status": status, "kernel_usage": usage}


def audit(evidence):
    acks = [json.loads(line) for line in (evidence / "acks.jsonl").read_text().splitlines()]
    duplicates = [json.loads(line) for line in (evidence / "duplicate-acks.jsonl").read_text().splitlines()]
    inputs = [json.loads(line)["request"] for line in (evidence / "inputs.jsonl").read_text().splitlines()]
    identities = set()
    for ack in acks:
        import base64
        raw = base64.b64decode(ack["raw"], validate=True)
        assert raw.startswith(b"SCAPRES1")
        assert hashlib.sha256(raw).hexdigest() == ack["raw_sha256"]
        assert ack["request"] in inputs, "ACK without prior recorded input"
        original = json.loads(ack["request"])
        assert ack["receipt"]["scope"] == original["scope"]
        assert ack["receipt"]["request"] == original["request"]
        key = json.dumps([original["scope"], original["request"]], sort_keys=True)
        assert key not in identities, "duplicate ACK ledger entry"
        identities.add(key)
    for duplicate in duplicates:
        assert duplicate in acks, "duplicate execute did not return an exact original ACK"
    assert len(duplicates) == 8
    phases = [json.loads(line) for line in (evidence / "client-phases.jsonl").read_text().splitlines()]
    expected = ["initialize", "concurrent_create", "unknown_write", "resolve_unknown", "blackhole", "takeover", "recover"]
    assert [phase["phase"] for phase in phases] == expected
    assert len(acks) == 10
    assert phases[-1]["acknowledgements_audited"] == len(acks) + len(duplicates) == 18
    assert phases[2]["sdk_http_attempts"] == 1
    assert phases[-1]["rows_verified"] == 9 and phases[-1]["mismatch_count"] == 0
    assert phases[-1]["other_tenant_rows_verified"] == 1 and phases[-1]["recovered_data_databases"] == 2
    assert phases[-1]["uncertain_original_result_preserved"] is True
    return {"unique_acknowledged_requests": len(acks), "successful_execute_responses": len(acks) + len(duplicates),
            "duplicate_execute_responses": len(duplicates), "business_rows": 10,
            "rows_by_tenant": {"7": 9, "8": 1}, "recovered_data_databases": 2, "mismatch_count": 0,
            "phases": phases, "outcome_unknown_kept_separate": True}


def main(args):
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=False, mode=0o700)
    summary = {"schema": 1, "status": "blocked", "diagnostic": args.diagnostic,
               "aws_standard": "NOT_RUN", "production_slo_passed": False}
    private = Path(tempfile.mkdtemp(prefix="scap-service-private-", dir=evidence.parent))
    backend = proxy = None
    services = []
    before = build.inputs()
    try:
        assert args.server.is_file() and args.weed.is_file(), "missing actual daemon or pinned S3 binary"
        assert "LLVM_PROFILE_FILE" not in os.environ, "unit instrumentation is forbidden"
        assert "NODE_V8_COVERAGE" not in os.environ, "real HTTP runs must not write unit profiles"
        assert not any("instrument-coverage" in os.environ.get(key, "")
                       for key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"))
        node = Path(shutil.which(args.node) or args.node).resolve()
        tools_before = {
            "node": {"path": str(node), "sha256": build.digest(node),
                     "version": subprocess.check_output([str(node), "--version"], text=True).strip()},
            "weed": {"path": str(args.weed.resolve()), "sha256": build.digest(args.weed),
                     "version": subprocess.check_output([str(args.weed), "version"], text=True).strip()},
        }
        assert tools_before["node"]["version"] == "v22.16.0", "the acceptance profile pins Node 22.16.0"
        summary["tools"] = tools_before
        if not args.diagnostic:
            assert args.build_record, "a final run requires the service build receipt"
            receipt = build.verify(args.build_record, args.server)
            assert receipt["node"] == tools_before["node"]["version"], "Node differs from build receipt"
            (evidence / "build-receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
        summary.update(status="running", binary_sha256=build.digest(args.server), inputs=before)
        backend = Backend(args.weed.resolve(), private / "backend")
        backend.start()
        proxy = Proxy(backend.port, evidence)
        proxy.capture = True
        tokens = {key: secrets.token_hex(32) for key in ("admin", "reader", "other")}
        first = Service(args.server.resolve(), private, 5001, proxy.endpoint, tokens, backend)
        services.append(first)
        second = Service(args.server.resolve(), private, 5002, proxy.endpoint, tokens, backend)
        services.append(second)
        probe_config = private / "client.private.json"

        def phase(name, primary=first, secondary=second):
            proxy.set_phase(name)
            probe_config.write_text(json.dumps({"endpoint": primary.endpoint,
                                               "secondary": secondary.endpoint, "tokens": tokens}))
            probe_config.chmod(0o600)
            command = [str(node), str(Path(__file__).with_name("probe.mjs")), name, str(probe_config), str(evidence)]
            with (evidence / (name + ".stdout.log")).open("wb") as out, (evidence / (name + ".stderr.log")).open("wb") as err:
                completed = subprocess.run(command, cwd=ROOT, stdout=out, stderr=err, timeout=90)
            assert completed.returncode == 0, f"real SDK phase failed: {name}; inspect its stderr"

        phase("initialize")
        phase("concurrent_create")
        loss = proxy.arm("drop", suffix="/head")
        phase("unknown_write")
        assert loss.arrived.is_set() and loss.used == 1
        accepted = [item for item in proxy.observations if item.get("phase") == "unknown_write"
                    and item.get("event") == "object_response" and item.get("method") == "PUT"
                    and item.get("path", "").endswith("/head") and item.get("status") == 200]
        assert len(accepted) == 1 and accepted[0]["suppressed"] is True
        proxy.clear()
        phase("resolve_unknown")
        blackhole = proxy.arm("blackhole", method="GET", key="scap-object/v1/1/7/101/head")
        phase("blackhole")
        assert blackhole.arrived.is_set()
        proxy.clear()
        phase("takeover")
        summary["compute_loss"] = [service.stop() for service in services]
        assert all(item["wait_status"] == -signal.SIGKILL for item in summary["compute_loss"])
        for service in services:
            shutil.rmtree(service.cache)
            assert not service.cache.exists()
        services.clear()
        summary["all_cache_directories_removed"] = True
        summary["backend_loss"] = backend.stop(verify=True)
        backend.start()
        recovered = Service(args.server.resolve(), private, 5003, proxy.endpoint, tokens, backend)
        services.append(recovered)
        phase("recover", recovered, recovered)
        summary["audit"] = audit(evidence)
        assert not proxy.errors, proxy.errors
        summary["object_metrics"] = proxy.metrics()
        if not args.diagnostic:
            build.verify(args.build_record, args.server)
            assert build.inputs() == before
        assert build.digest(node) == tools_before["node"]["sha256"], "Node executable changed during run"
        assert build.digest(args.weed) == tools_before["weed"]["sha256"], "S3 backend executable changed during run"
        summary["status"] = "passed"
    except BaseException as error:
        if summary["status"] == "running":
            summary["status"] = "failed"
        summary["error"] = repr(error)
    finally:
        cleanup = []
        for service in services:
            try:
                service.stop()
            except BaseException as error:
                cleanup.append(repr(error))
        if proxy is not None:
            try:
                proxy.close()
            except BaseException as error:
                cleanup.append(repr(error))
        if backend is not None:
            try:
                backend.stop()
            except BaseException as error:
                cleanup.append(repr(error))
        summary["cleanup_errors"] = cleanup
        if cleanup:
            summary["status"] = "failed"
        # Keep the private tree for failure diagnosis; it is NEVER an artifact
        # upload target and contains fixture credentials and database files.
        summary["private_fixture_removed"] = False
        if summary["status"] == "passed":
            shutil.rmtree(private)
            summary["private_fixture_removed"] = True
        (evidence / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps({key: summary.get(key) for key in ("status", "diagnostic", "error", "audit", "cleanup_errors")}))
    return 0 if summary["status"] == "passed" else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--weed", type=Path, required=True)
    parser.add_argument("--node", default="node")
    parser.add_argument("--build-record", type=Path)
    parser.add_argument("--diagnostic", action="store_true")
    parser.add_argument("--evidence", type=Path, required=True)
    raise SystemExit(main(parser.parse_args()))
