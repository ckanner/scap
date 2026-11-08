"""Fixture-only forwarding proxy with complete S3 byte evidence and one GET gate."""
from __future__ import annotations

import base64
import hashlib
import http.client
import http.server
import json
import os
import re
import threading
import time

from isolation_spec import DEADLINES


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class Trace:
    def __init__(self, path):
        self.path, self.lock, self.sequence = path, threading.Lock(), 0

    def emit(self, event, **fields):
        with self.lock:
            self.sequence += 1
            row = {"schema": 1, "sequence": self.sequence, "event": event,
                   "monotonic_ns": time.monotonic_ns(), **fields}
            with self.path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(row, sort_keys=True) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            return row


def signing(headers):
    """Record nonsecret SigV4 structure, never credentials or authorization bytes."""
    value = headers.get("Authorization", "")
    match = re.fullmatch(r"AWS4-HMAC-SHA256 Credential=([^/]+)/([^,]+), SignedHeaders=([^,]+), Signature=([0-9a-f]{64})", value)
    if match is None:
        raise ValueError("product request lacks an exact SigV4 Authorization header")
    access, scope, names, signature = match.groups()
    names = names.split(";")
    if names != sorted(set(names)) or not {"host", "x-amz-date", "x-amz-content-sha256"} <= set(names):
        raise ValueError("incomplete SigV4 signed header set")
    return {"algorithm": "AWS4-HMAC-SHA256", "access_key_sha256": sha(access.encode()),
            "credential_scope": scope, "signed_headers": names,
            "signature_sha256": sha(signature.encode()), "host": headers["Host"],
            "date": headers["X-Amz-Date"], "payload_sha256": headers["X-Amz-Content-Sha256"]}


class Proxy:
    def __init__(self, backend_port, evidence):
        self.backend_port = backend_port
        self.trace = Trace(evidence / "history.jsonl")
        self.lock, self.serial = threading.Lock(), 0
        self.phase, self.gate_path, self.gated_serial = "setup", None, None
        self.arrived, self.release = threading.Event(), threading.Event()
        self.errors, self.objects = [], {}
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
                    with owner.lock:
                        owner.errors.append(repr(error))
                    owner.trace.emit("transport_fixture_failed", error=repr(error))
                finally:
                    self.close_connection = True

            def forward(self):
                self.connection.settimeout(DEADLINES["s3_request_ms"] / 1000)
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 <= length <= 4 * 1024 * 1024:
                    raise ValueError("fixture body bound")
                payload = self.rfile.read(length)
                if len(payload) != length:
                    raise ValueError("truncated incoming body")
                with owner.lock:
                    owner.serial += 1
                    fields = {"request_serial": owner.serial, "phase": owner.phase, "method": self.command,
                              "path": self.path, "request_bytes": len(payload), "request_sha256": sha(payload),
                              "request_body": base64.b64encode(payload).decode(),
                              "if_match": self.headers.get("If-Match"), "if_none_match": self.headers.get("If-None-Match"),
                              "signing": signing(self.headers)}
                    if self.path.endswith("/head"):
                        fields["head_request_bytes"] = list(payload)
                    gated = self.command == "GET" and self.path == owner.gate_path and owner.gated_serial is None
                    if gated:
                        owner.gated_serial = owner.serial
                owner.trace.emit("object_request", **fields)
                if gated:
                    owner.trace.emit("transport_fault_observed", mode="hold", stage="before_forward", **fields)
                    owner.arrived.set()
                    if not owner.release.wait(DEADLINES["gate_hold_ms"] / 1000):
                        raise TimeoutError("original frozen GET hold deadline")
                connection = http.client.HTTPConnection("127.0.0.1", owner.backend_port, timeout=8)
                try:
                    connection.putrequest(self.command, self.path, skip_host=True, skip_accept_encoding=True)
                    for name, value in self.headers.items():
                        connection.putheader(name, value)
                    connection.endheaders(payload)
                    owner.trace.emit("object_forwarded", **fields)
                    response = connection.getresponse()
                    body = response.read(4 * 1024 * 1024 + 1)
                    if len(body) > 4 * 1024 * 1024:
                        raise ValueError("fixture response bound")
                    received = {"status": response.status, "response_bytes": len(body), "response_sha256": sha(body),
                                "response_body": base64.b64encode(body).decode(), "etag": response.getheader("ETag")}
                    if self.path.endswith("/head"):
                        received["head_response_bytes"] = list(body)
                    owner.trace.emit("object_response", response_origin="backend", suppressed=False, **fields, **received)
                    if response.status == 200 and "/objects/" in self.path:
                        original = payload if self.command == "PUT" else body
                        with owner.lock:
                            owner.objects[self.path] = original
                    self.send_response_only(response.status)
                    for name, value in response.getheaders():
                        if name.lower() not in ("connection", "transfer-encoding", "content-length"):
                            self.send_header(name, value)
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(body)
                    owner.trace.emit("object_response_delivered", **fields, **received)
                finally:
                    connection.close()

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = False
        self.endpoint = f"http://127.0.0.1:{self.server.server_port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def set_phase(self, phase):
        with self.lock:
            self.phase = phase
            self.trace.emit("phase_started", phase=phase)

    def arm(self, path):
        with self.lock:
            if self.gate_path is not None:
                raise ValueError("duplicate gate")
            self.gate_path = path
            self.trace.emit("transport_fault_armed", mode="hold", method="GET", path=path,
                            stage="before_forward", deadline_ms=DEADLINES["gate_hold_ms"])

    def release_gate(self):
        self.trace.emit("gate_released", request_serial=self.gated_serial, path=self.gate_path)
        self.release.set()

    def close(self):
        self.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        if self.thread.is_alive():
            raise TimeoutError("proxy did not stop")
