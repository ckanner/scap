#!/usr/bin/env python3
"""Raw TCP contract against the real scapd binary, without LLVM unit profiles.

Only /healthz is queried after startup. A real pinned local S3 backend is needed
for the permanent instance claim; this experiment does not prove database,
cloud S3, TLS or total RSS contracts.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time

from oracle import H2, PROFILE, healthy, verify


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("transport_process_helpers", ROOT / "experiments/object-network/run.py")
NETWORK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NETWORK)
HEALTH = b"GET /healthz HTTP/1.1\r\nHost: unit\r\n\r\n"


def encoded(raw):
    return base64.b64encode(raw).decode("ascii")


class Trace:
    def __init__(self, path):
        self.path, self.sequence = path, 0

    def emit(self, event, **fields):
        self.sequence += 1
        row = {"sequence": self.sequence, "monotonic_ns": time.monotonic_ns(), "event": event, **fields}
        with self.path.open("a") as stream:
            stream.write(json.dumps(row, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())


class Client:
    def __init__(self, port):
        self.socket = socket.create_connection(("127.0.0.1", port), timeout=1)
        self.socket.settimeout(5)

    def send(self, raw):
        self.socket.sendall(raw)

    def response(self):
        result = bytearray()
        while b"\r\n\r\n" not in result:
            part = self.socket.recv(1)
            if not part:
                raise ValueError("EOF before response headers")
            result.extend(part)
            assert len(result) <= 8192
        head = bytes(result)
        lengths = [int(line.split(b":", 1)[1]) for line in head.split(b"\r\n")
                   if line.lower().startswith(b"content-length:")]
        assert len(lengths) == 1 and 0 <= lengths[0] <= 1024
        remaining = lengths[0]
        while remaining:
            part = self.socket.recv(remaining)
            if not part:
                raise ValueError("EOF before response body")
            result.extend(part)
            remaining -= len(part)
        return bytes(result)

    def quiet(self, seconds):
        self.socket.settimeout(seconds)
        try:
            response = self.socket.recv(1)
            return "received", response
        except TimeoutError:
            return "timeout", b""
        finally:
            self.socket.settimeout(5)

    def closed(self, timeout=5):
        deadline = time.monotonic() + timeout
        result = bytearray()
        while True:
            self.socket.settimeout(max(0.001, deadline - time.monotonic()))
            try:
                part = self.socket.recv(4096)
            except ConnectionResetError:
                return bytes(result), time.monotonic_ns()
            if not part:
                return bytes(result), time.monotonic_ns()
            result.extend(part)
            assert len(result) <= 16384

    def close(self):
        self.socket.close()


def configuration(port, cache, endpoint):
    return {
        "version": 1, "listen": f"127.0.0.1:{port}", "transport": PROFILE,
        "worker_instance": "7001", "cache_directory": str(cache),
        "s3": {"endpoint": endpoint, "region": "us-east-1", "bucket": "scap-test",
               "access_key_env": "SCAP_TCP_ACCESS", "secret_key_env": "SCAP_TCP_SECRET",
               "session_token_env": None, "allow_http": True, "timeout_ms": 1000},
        "admission": {"active_database_actors": 1, "active_database_actors_per_tenant": 1,
                      "actor_idle_timeout_ms": 1000, "control_workers": 1,
                      "queued_total": 4, "queued_per_tenant": 2, "queued_per_database": 2,
                      "reserved_controls": 1, "data_intake": 2, "control_intake": 2,
                      "recovery_intake": 2, "max_body_bytes": 4096,
                      "timeout_ms": 1000, "recovery_timeout_ms": 1000},
        "cache": {"pages_per_actor": 1024, "parallel_recoveries": 1},
        "credentials": [{"sha256": hashlib.sha256(b"unused-transport-token-0123456789abcdef").hexdigest(),
                         "deployment": "1", "tenant": "1", "principal": "1", "provision": False}],
    }


def exercise(binary, evidence, weed):
    if os.environ.get("LLVM_PROFILE_FILE"):
        raise ValueError("real TCP execution must not write unit profiles")
    evidence.mkdir(parents=True, exist_ok=False)
    trace = Trace(evidence / "events.jsonl")
    observations = {"schema": 1, "profile": PROFILE, "cases": [],
                    "binary": {"path": str(binary), "sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}}
    (evidence / "plan.json").write_text(json.dumps({"schema": 1, "profile": PROFILE,
        "cases": ["capacity", "first_header_deadline", "keepalive_header_deadline",
                  "header_bytes_at", "header_bytes_over", "header_count_at", "header_count_over", "h2"],
        "scope": "real scapd TCP, healthz only after local S3 identity claim, no cloud S3 or RSS verdict"}, indent=2) + "\n")
    clients, process, backend = [], None, None
    try:
        with tempfile.TemporaryDirectory(prefix="scap-tcp-") as temporary, contextlib.ExitStack() as teardown:
            backend = NETWORK.Backend(weed, Path(temporary) / "backend")
            teardown.callback(backend.stop)
            backend.start()
            cache = Path(temporary) / "cache"
            cache.mkdir()
            with socket.socket() as available:
                available.bind(("127.0.0.1", 0))
                port = available.getsockname()[1]
            config = evidence / "config.json"
            config.write_text(json.dumps(configuration(port, cache, backend.endpoint), indent=2) + "\n")
            with (evidence / "daemon.stdout.log").open("wb") as output, (evidence / "daemon.stderr.log").open("wb") as errors:
                process = subprocess.Popen([str(binary), str(config)], stdin=subprocess.DEVNULL,
                    stdout=output, stderr=errors, env=dict(os.environ,
                        SCAP_TCP_ACCESS=backend.access, SCAP_TCP_SECRET=backend.secret))
            identity = NETWORK.process_identity(process)
            trace.emit("started", identity=identity, binary=observations["binary"])

            def connect():
                client = Client(port)
                clients.append(client)
                return client

            deadline = time.monotonic() + 10
            while True:
                try:
                    ready = connect()
                    ready.send(HEALTH)
                    healthy(ready.response())
                    ready.close()
                    break
                except (OSError, ValueError):
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.05)

            def record(row):
                observations["cases"].append(row)
                trace.emit("observation", **row)

            occupied, receipts = [], []
            for _ in range(PROFILE["max_connections"]):
                client = connect()
                client.send(HEALTH)
                response = client.response()
                partial = b"GET /healthz HTTP/1.1\r\nHost:"
                receipts.append({"request": encoded(HEALTH), "response": encoded(response),
                    "partial_request": encoded(partial), "hold_ns": time.monotonic_ns()})
                client.send(partial)
                occupied.append(client)
            waiting = connect()
            candidate = HEALTH.replace(b"\r\n\r\n", b"\r\nConnection: close\r\n\r\n")
            waiting.send(candidate)
            row = {"case": "capacity", "occupied": receipts, "request": encoded(candidate),
                   "probe_start_ns": time.monotonic_ns()}
            outcome, response = waiting.quiet(0.2)
            row.update(probe_outcome=outcome, probe_response=encoded(response), probe_end_ns=time.monotonic_ns())
            row["release_ns"] = time.monotonic_ns()
            occupied[0].close()
            response, finished = waiting.closed()
            row.update(response=encoded(response), response_ns=finished)
            occupied[1].close()
            record(row)

            for name in ("first_header_deadline", "keepalive_header_deadline"):
                client = connect()
                row = {"case": name}
                if name.startswith("keepalive"):
                    client.send(HEALTH)
                    row["first_response"] = encoded(client.response())
                request = b"GET /healthz HTTP/1.1\r\nHost:"
                row.update(start_ns=time.monotonic_ns(), request=encoded(request))
                client.send(request)
                outcome, response = client.quiet(2)
                row.update(probe_outcome=outcome, probe_response=encoded(response),
                           drip_ns=time.monotonic_ns(), drip=encoded(b" unit"))
                client.send(b" unit")
                response, finished = client.closed(2.25)
                row.update(response=encoded(response), close_ns=finished, closed=True)
                record(row)

            prefix = b"GET /healthz HTTP/1.1\r\nHost: unit\r\nConnection: close\r\nX-Pad: "
            requests = []
            for name, length in (("header_bytes_at", 512), ("header_bytes_over", 513)):
                requests.append((name, prefix + b"x" * (length - len(prefix) - 4) + b"\r\n\r\n"))
            for name, count in (("header_count_at", 4), ("header_count_over", 5)):
                request = b"GET /healthz HTTP/1.1\r\nHost: unit\r\nConnection: close\r\n"
                request += b"".join(f"X-{index}: y\r\n".encode() for index in range(count - 2)) + b"\r\n"
                requests.append((name, request))
            requests.append(("h2", H2))
            for name, request in requests:
                client = connect()
                client.send(request)
                response, finished = client.closed()
                record({"case": name, "request": encoded(request), "response": encoded(response),
                        "closed": True, "close_ns": finished})

            idle = connect()
            idle.send(HEALTH)
            healthy(idle.response())
            sent = time.monotonic_ns()
            os.kill(process.pid, signal.SIGINT)
            response, _ = idle.closed()
            assert response == b""
            code, usage = NETWORK.wait_child(process, 6)
            observations["cleanup"] = {"identity": identity, "signal_ns": sent,
                "reaped_ns": time.monotonic_ns(), "returncode": code, "usage": usage, "idle_closed": True}
            trace.emit("reaped", **observations["cleanup"])
            verify(observations)
            return observations
    except BaseException as error:
        trace.emit("failure", error_type=type(error).__name__, message=str(error))
        raise
    finally:
        for client in clients:
            client.close()
        if process is not None and process.returncode is None:
            try:
                os.kill(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            code, usage = NETWORK.wait_child(process, 6)
            trace.emit("failure_cleanup_reaped", returncode=code, usage=usage)
        if backend is not None:
            backend.stop()
        (evidence / "observations.json").write_text(json.dumps(observations, indent=2, sort_keys=True) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--weed", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    observations = exercise(args.binary.resolve(strict=True), args.evidence.resolve(), args.weed.resolve(strict=True))
    print(json.dumps({"verified": verify(observations), "evidence": str(args.evidence)}, sort_keys=True))


if __name__ == "__main__":
    main()
