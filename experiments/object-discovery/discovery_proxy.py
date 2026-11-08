"""Fixture relay: complete original bytes, signed S3 and explicit fault gates."""
from __future__ import annotations

import hashlib
import hmac
import http.client
import http.server
import json
import os
import re
import threading
import time
from urllib.parse import parse_qsl, quote, urlsplit


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def signature(method, target, headers, payload, access, secret):
    match = re.fullmatch(r"AWS4-HMAC-SHA256 Credential=([^/]+)/([^,]+),\s*SignedHeaders=([^,]+),\s*Signature=([0-9a-f]{64})",
                         headers.get("Authorization", ""))
    if match is None:
        raise ValueError("missing exact SigV4 request")
    actual, scope, signed, observed = match.groups()
    date, region, service, suffix = scope.split("/")
    if actual != access or (region, service, suffix) != ("us-east-1", "s3", "aws4_request"):
        raise ValueError("wrong SigV4 identity/scope")
    names = signed.split(";")
    if names != sorted(set(names)) or not {"host", "x-amz-date", "x-amz-content-sha256"} <= set(names):
        raise ValueError("incomplete signed headers")
    if any(name in {"authorization", "cookie", "x-amz-security-token"} for name in names):
        raise ValueError("fixture does not archive secret signed headers")
    values = {name: ' '.join(headers[name].split()) for name in names}
    canonical_headers = "".join(f"{name}:{values[name]}\n" for name in names)
    parsed = urlsplit(target)
    query = "&".join(f"{quote(key, safe='-_.~')}={quote(value, safe='-_.~')}"
                     for key, value in sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    body_hash = headers["X-Amz-Content-Sha256"]
    if body_hash not in (sha(payload), "UNSIGNED-PAYLOAD"):
        raise ValueError("signed body hash differs")
    canonical = "\n".join((method, parsed.path, query, canonical_headers, signed, body_hash)).encode()
    message = "\n".join(("AWS4-HMAC-SHA256", headers["X-Amz-Date"], scope, sha(canonical))).encode()
    key = ("AWS4" + secret).encode()
    for component in (date, region, service, suffix):
        key = hmac.new(key, component.encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(hmac.new(key, message, hashlib.sha256).hexdigest(), observed):
        raise ValueError("actual SigV4 signature did not verify")
    return {"algorithm": "AWS4-HMAC-SHA256", "access_key_sha256": sha(access.encode()),
            "credential_scope": scope, "signed_headers": names, "signature_sha256": sha(observed.encode()),
            "signed_header_values": values,
            "payload_sha256": body_hash, "host": headers["Host"], "date": headers["X-Amz-Date"],
            "verified_at_relay": True}


class Gate:
    def __init__(self, mode, method, path, occurrence, stage):
        self.mode, self.method, self.path = mode, method, path
        self.occurrence, self.stage, self.seen = occurrence, stage, 0
        self.arrived, self.release, self.finished = threading.Event(), threading.Event(), threading.Event()
        self.abort, self.observation = False, None


class Proxy:
    def __init__(self, backend, evidence):
        self.backend, self.evidence = backend, evidence
        self.blobs = evidence / "s3-bodies"; self.blobs.mkdir()
        self.lock = threading.RLock()
        self.serial = self.sequence = 0
        self.phase, self.call_id, self.gate = "setup", None, None
        self.gates, self.errors, self.objects = [], [], {}
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            def log_message(self, *_args): pass
            def do_GET(self): self.dispatch()
            def do_PUT(self): self.dispatch()
            def do_DELETE(self): self.dispatch()

            def dispatch(self):
                self.close_connection = True
                try:
                    self.forward()
                except BaseException as error:
                    with owner.lock: owner.errors.append(repr(error))
                    owner.emit("transport_fixture_failed", error=repr(error))

            def pause(self, gate, fields, response=None):
                observation = {**fields, **(response or {})}
                owner.emit("transport_fault_observed", mode=gate.mode, stage=gate.stage, **observation)
                gate.observation = observation
                gate.arrived.set()
                if not gate.release.wait(90):
                    raise TimeoutError("fixture gate release deadline")
                return gate.abort

            def forward(self):
                self.connection.settimeout(10)
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 <= length <= 4 * 1024 * 1024:
                    raise ValueError("fixture request body bound")
                body = self.rfile.read(length)
                if len(body) != length: raise ValueError("truncated fixture request")
                signed = signature(self.command, self.path, self.headers, body,
                                   owner.backend.access, owner.backend.secret)
                with owner.lock:
                    owner.serial += 1
                    fields = {"request_serial": owner.serial, "call_id": owner.call_id, "phase": owner.phase,
                              "method": self.command, "path": self.path, "request_bytes": length,
                              "request_sha256": owner.store(body), "if_match": self.headers.get("If-Match"),
                              "if_none_match": self.headers.get("If-None-Match"), "signing": signed}
                    gate = owner.gate
                    if gate is not None and (gate.method != self.command or gate.path != self.path): gate = None
                    if gate is not None:
                        gate.seen += 1
                        if gate.seen != gate.occurrence: gate = None
                    if gate is not None: owner.gate = None
                owner.emit("object_request", **fields)
                if gate is not None and gate.stage == "before_forward":
                    if self.pause(gate, fields):
                        owner.emit("object_cut_before_forward", **fields)
                        gate.finished.set()
                        return
                connection = http.client.HTTPConnection("127.0.0.1", owner.backend.port, timeout=8)
                try:
                    connection.putrequest(self.command, self.path, skip_host=True, skip_accept_encoding=True)
                    for name, value in self.headers.items(): connection.putheader(name, value)
                    connection.endheaders(body)
                    owner.emit("object_forwarded", **fields)
                    response = connection.getresponse(); raw = response.read(4 * 1024 * 1024 + 1)
                    if len(raw) > 4 * 1024 * 1024: raise ValueError("fixture response body bound")
                    received = {"status": response.status, "response_bytes": len(raw),
                                "response_sha256": owner.store(raw), "etag": response.getheader("ETag")}
                    owner.emit("object_response", response_origin="backend", **fields, **received)
                    with owner.lock:
                        if response.status == 200 and "?" not in self.path:
                            owner.objects[self.path] = body if self.command == "PUT" else raw
                        if self.command == "DELETE" and response.status in (200, 204): owner.objects.pop(self.path, None)
                    if gate is not None and gate.stage == "after_response":
                        if self.pause(gate, fields, received):
                            owner.emit("object_cut_after_response", **fields, **received)
                            gate.finished.set()
                            return
                    try:
                        owner.emit("object_delivery_started", **fields, **received)
                        self.send_response_only(response.status)
                        for name, value in response.getheaders():
                            if name.lower() not in ("connection", "transfer-encoding", "content-length"):
                                self.send_header(name, value)
                        self.send_header("Content-Length", str(len(raw))); self.send_header("Connection", "close")
                        self.end_headers(); self.wfile.write(raw)
                        owner.emit("object_response_delivered", **fields, **received)
                    except (BrokenPipeError, ConnectionResetError):
                        owner.emit("object_caller_disconnected", **fields, **received)
                    if gate is not None: gate.finished.set()
                finally: connection.close()

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = False
        self.endpoint = f"http://127.0.0.1:{self.server.server_port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()

    def store(self, raw):
        digest = sha(raw); path = self.blobs / digest
        with self.lock:
            if path.exists():
                if path.read_bytes() != raw: raise ValueError("body hash collision")
            else:
                with path.open("xb") as stream:
                    stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        return digest

    def emit(self, event, **fields):
        with self.lock:
            self.sequence += 1
            row = {"schema": 1, "sequence": self.sequence, "event": event,
                   "monotonic_ns": time.monotonic_ns(), **fields}
            with (self.evidence / "history.jsonl").open("a") as stream:
                stream.write(json.dumps(row, sort_keys=True) + "\n"); stream.flush(); os.fsync(stream.fileno())
            return row

    def select(self, phase, call_id):
        with self.lock: self.phase, self.call_id = phase, call_id

    def arm(self, method, path, *, occurrence=1, stage="before_forward", mode="hold"):
        with self.lock:
            if self.gate is not None: raise ValueError("fixture already has an armed gate")
            gate = Gate(mode, method, path, occurrence, stage); self.gates.append(gate); self.gate = gate
            self.emit("transport_fault_armed", method=method, path=path, occurrence=occurrence, stage=stage, mode=mode)
            return gate

    def release(self, gate, *, abort=False):
        gate.abort = abort
        self.emit("gate_released", request_serial=gate.observation["request_serial"], abort=abort)
        gate.release.set()

    def close(self):
        for gate in self.gates:
            if not gate.release.is_set(): gate.abort = True; gate.release.set()
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=3)
        if self.thread.is_alive(): raise TimeoutError("proxy did not stop")
