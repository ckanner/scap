#!/usr/bin/env python3
"""Real signed S3 auxiliary response bounds, including accepted-PUT ambiguity."""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import tempfile
import threading
import time

if not __debug__:
    raise RuntimeError("validation requires Python assertions; disable -O/PYTHONOPTIMIZE")

import listing_build
import response_oracle
from listing_contract import Worker, body_record, verify_signature
import run as fixture

LIMIT = 64 * 1024
LARGE = 4 * 1024 * 1024
STREAM_LIMIT = 16 * 1024 * 1024
CASES = (
    ("get_small_404", "get", 404, LIMIT, False, False),
    ("get_large_404", "get", 404, LARGE, False, False),
    ("get_stream_500", "get", 500, STREAM_LIMIT, True, False),
    ("put_small_412", "put", 412, LIMIT, False, True),
    ("put_large_412", "put", 412, LARGE, False, True),
    ("put_accepted_500", "put", 500, LARGE, False, False),
    ("get_success_large", "get", 200, LARGE, False, True),
    ("put_success_large", "put", 200, LARGE, False, False),
)


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


class Log:
    def __init__(self, path):
        self.path, self.lock, self.sequence = path, threading.Lock(), 0
        self.rows = []

    def emit(self, event, **fields):
        with self.lock:
            self.sequence += 1
            value = {"schema": 1, "sequence": self.sequence, "event": event, "monotonic_ns": time.monotonic_ns(), **fields}
            with self.path.open("a") as stream:
                stream.write(json.dumps(value, sort_keys=True) + "\n")
                stream.flush(); os.fsync(stream.fileno())
            self.rows.append(value)
            return value


class Proxy:
    def __init__(self, backend, log, case):
        self.backend, self.log, self.case = backend, log, case
        self.lock, self.serial, self.errors = threading.Lock(), 0, []
        self.done = threading.Event()
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args):
                pass

            def do_GET(self):
                self.dispatch()

            def do_PUT(self):
                self.dispatch()

            def dispatch(self):
                try:
                    self.forward()
                except BaseException as error:
                    owner.errors.append(repr(error))
                    owner.log.emit("fixture_failure", case=owner.case[0], error=repr(error))
                finally:
                    self.close_connection = True

            def forward(self):
                self.connection.settimeout(5)
                length = int(self.headers.get("Content-Length", "0"))
                assert 0 <= length <= 1024
                payload = self.rfile.read(length)
                assert len(payload) == length
                verified = verify_signature(self.command, self.path, self.headers, payload, owner.backend.access, owner.backend.secret)
                assert verified
                with owner.lock:
                    owner.serial += 1
                    serial = owner.serial
                label, operation, status, size, streaming, _seed = owner.case
                owner.log.emit("request", case=label, serial=serial, method=self.command, path=self.path,
                               body=body_record(payload), if_match=self.headers.get("If-Match"),
                               if_none_match=self.headers.get("If-None-Match"), sigv4_verified=verified)
                connection = http.client.HTTPConnection("127.0.0.1", owner.backend.port, timeout=5)
                try:
                    connection.putrequest(self.command, self.path, skip_host=True, skip_accept_encoding=True)
                    for name, value in self.headers.items():
                        connection.putheader(name, value)
                    connection.endheaders(payload)
                    response = connection.getresponse()
                    original = response.read(64 * 1024 + 1)
                    assert len(original) <= 64 * 1024
                    owner.log.emit("backend_response", case=label, serial=serial, status=response.status,
                                   body=body_record(original), etag=response.getheader("ETag"))
                    # A second explicit GET proves a conditional PUT accepted
                    # before its error response still wrote exactly one value.
                    if serial > 1:
                        outgoing = original
                        status, size, streaming = response.status, len(original), False
                    else:
                        outgoing = None
                    self.send_response_only(status)
                    for name, value in response.getheaders():
                        if name.lower() not in ("transfer-encoding", "connection", "content-length"):
                            self.send_header(name, value)
                    self.send_header("Transfer-Encoding" if streaming else "Content-Length", "chunked" if streaming else str(size))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    sent, closed = 0, False
                    owner.log.emit("send_started", case=label, serial=serial, status=status,
                                   declared_length=None if streaming else size, maximum_fixture_bytes=size, chunked=streaming)
                    try:
                        while sent < size:
                            chunk = outgoing[sent:sent + 4096] if outgoing is not None else b"e" * min(4096, size - sent)
                            if streaming:
                                self.wfile.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
                            else:
                                self.wfile.write(chunk)
                            self.wfile.flush()
                            sent += len(chunk)
                            if outgoing is None:
                                time.sleep(0.001)
                        if streaming:
                            self.wfile.write(b"0\r\n\r\n")
                            self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError, TimeoutError):
                        closed = True
                    owner.log.emit("send_finished", case=label, serial=serial, sent_bytes=sent,
                                   eof_sent=not closed and sent == size, peer_closed=closed)
                    if serial == 1:
                        owner.done.set()
                finally:
                    connection.close()

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = False
        self.endpoint = f"http://127.0.0.1:{self.server.server_port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(3)
        assert not self.thread.is_alive() and not self.errors, self.errors



def run(args):
    evidence = args.evidence.resolve(); evidence.mkdir(parents=True, exist_ok=False)
    log = Log(evidence / "response-history.jsonl")
    binary = args.worker.resolve()
    if args.bounded:
        assert args.build_receipt
        receipt = listing_build.verify(args.build_receipt, binary)
        provenance = {"kind": "current-development-build", "receipt": str(args.build_receipt.resolve()), "sha256": sha(args.build_receipt)}
    else:
        assert args.original_preservation
        receipt = json.loads(args.original_preservation.read_text())
        assert receipt["binary_sha256"] == sha(binary) and receipt["original_commit"] == "927e2e6845010abbfe193b8c632ae0ad2f3ae98d"
        provenance = {"kind": "preserved-original-a927", "receipt": str(args.original_preservation.resolve()), "sha256": sha(args.original_preservation)}
    assert "LLVM_PROFILE_FILE" not in os.environ
    log.emit("inputs", binary={"path": str(binary), "sha256": sha(binary)}, provenance=provenance,
             fixture={"path": str(Path(__file__).resolve()), "sha256": sha(__file__)},
             weed={"path": str(args.weed.resolve()), "sha256": sha(args.weed)})
    report = {"status": "failed"}
    with tempfile.TemporaryDirectory(prefix="scap-response-private-", dir=evidence.parent) as temporary:
        private = Path(temporary)
        backend = fixture.Backend(args.weed.resolve(), private / "backend")
        proxy = worker = None
        try:
            backend.start(); log.emit("backend_started", processes=backend.identities())
            for case in CASES:
                label, operation, _status, _size, _streaming, seed = case
                key = "response-contract/" + label
                if seed:
                    assert backend.signed("PUT", "/scap-test/" + key, "fixture-seed")
                proxy = Proxy(backend, log, case)
                worker = Worker(binary, private, label, backend, proxy.endpoint)
                log.emit("worker_started", case=label, identity=worker.identity)
                command = {"id": 1, "op": operation, "key": key}
                if operation == "put":
                    command["value"] = "accepted-value-" + label
                log.emit("call", case=label, command=command)
                worker.process.stdin.write(json.dumps(command) + "\n"); worker.process.stdin.flush()
                value = worker.read(); log.emit("reply", case=label, value=value)
                assert proxy.done.wait(5), "response stream did not close within owned bound"
                if label == "put_accepted_500":
                    command = {"id": 2, "op": "get", "key": key}
                    log.emit("call", case=label + "_readback", command=command)
                    worker.process.stdin.write(json.dumps(command) + "\n"); worker.process.stdin.flush()
                    log.emit("reply", case=label + "_readback", value=worker.read())
                log.emit("worker_stopped", case=label, **worker.close()); worker = None
                proxy.close(); proxy = None
            report = {"status": "observations_complete"}
        except BaseException as error:
            report["error"] = repr(error)
        finally:
            if worker:
                log.emit("worker_cleanup", **worker.close())
            if proxy:
                proxy.close()
            log.emit("backend_stopped", processes=backend.stop())
    if report["status"] == "observations_complete":
        try:
            report = response_oracle.inspect(evidence, args.bounded, negative=args.bounded)
        except BaseException as error:
            report = {"status": "failed", "error": repr(error)}
    (evidence / "response-oracle.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] in ("passed", "original_gap_reproduced") else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker", type=Path, required=True)
    parser.add_argument("--weed", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--bounded", action="store_true")
    parser.add_argument("--build-receipt", type=Path)
    parser.add_argument("--original-preservation", type=Path)
    raise SystemExit(run(parser.parse_args()))
