"""Fixture-only signed S3 forwarding, bounded LIST faults, and two independent holds."""
from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import http.server
import json
import os
import re
import threading
import time
from urllib.parse import parse_qsl, quote, unquote, urlsplit


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def body(raw):
    return {"bytes": len(raw), "sha256": sha(raw), "base64": base64.b64encode(raw).decode()}


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


def signing(method, target, headers, payload, access, secret):
    """Verify SigV4 using private fixture keys; publish only nonsecret witnesses."""
    match = re.fullmatch(r"AWS4-HMAC-SHA256 Credential=([^/]+)/([^,]+),\s*SignedHeaders=([^,]+),\s*Signature=([0-9a-f]{64})",
                         headers.get("Authorization", ""))
    if match is None:
        raise ValueError("missing product SigV4 Authorization")
    actual_access, scope, signed, signature = match.groups()
    date, region, service, suffix = scope.split("/")
    if actual_access != access or (region, service, suffix) != ("us-east-1", "s3", "aws4_request"):
        raise ValueError("wrong private S3 identity or credential scope")
    names = signed.split(";")
    if names != sorted(set(names)) or not {"host", "x-amz-date", "x-amz-content-sha256"} <= set(names):
        raise ValueError("incomplete signed headers")
    parsed = urlsplit(target)
    query = "&".join(f"{quote(key, safe='-_.~')}={quote(value, safe='-_.~')}"
                     for key, value in sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    canonical_headers = "".join(f"{name}:{' '.join(headers[name].split())}\n" for name in names)
    payload_hash = headers["x-amz-content-sha256"]
    if payload_hash not in ("UNSIGNED-PAYLOAD", sha(payload)):
        raise ValueError("signed payload differs")
    canonical = "\n".join((method, parsed.path, query, canonical_headers, signed, payload_hash)).encode()
    signed_value = "\n".join(("AWS4-HMAC-SHA256", headers["x-amz-date"], scope, sha(canonical))).encode()
    key = ("AWS4" + secret).encode()
    for component in (date, region, service, suffix):
        key = hmac.new(key, component.encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(hmac.new(key, signed_value, hashlib.sha256).hexdigest(), signature):
        raise ValueError("product SigV4 mismatch")
    return {"algorithm": "AWS4-HMAC-SHA256", "access_key_sha256": sha(access.encode()),
            "credential_scope": scope, "signed_headers": names, "signature_sha256": sha(signature.encode()),
            "host": headers["Host"], "date": headers["x-amz-date"], "payload_sha256": payload_hash,
            "verified": True}


class Rule:
    def __init__(self, label, mode, *, prefix=None, key=None):
        if (prefix is None) == (key is None):
            raise ValueError("a fault has exactly one LIST prefix or exact key")
        self.label, self.mode, self.prefix, self.key = label, mode, prefix, key
        self.used, self.serial = 0, None
        self.arrived, self.release, self.finished = threading.Event(), threading.Event(), threading.Event()

    def matches(self, method, key, query):
        return self.used == 0 and method == "GET" and (
            query.get("prefix") == self.prefix and query.get("list-type") == "2"
            if self.prefix is not None else not query and key == self.key)


def fault_response(raw, status, mode):
    if mode in (None, "hold"):
        return status, raw
    if status != 200:
        raise ValueError("fault did not observe the original successful backend response")
    if mode in ("denied", "missing"):
        return (403 if mode == "denied" else 404), b"<Error><Code>InjectedFixtureFailure</Code></Error>"
    if mode == "corrupt_head":
        return 200, b"{}"
    if mode == "missing_truncation":
        changed, count = re.subn(rb"<IsTruncated>.*?</IsTruncated>", b"", raw, count=1, flags=re.DOTALL)
        if count != 1:
            raise ValueError("truncation field not observed")
        return 200, changed
    if mode == "no_progress":
        if b"<IsTruncated>true</IsTruncated>" not in raw:
            raise ValueError("zero-progress fault requires a real truncated page")
        changed = re.sub(rb"<(Contents|CommonPrefixes)>.*?</\1>", b"", raw, flags=re.DOTALL)
        changed, count = re.subn(rb"<KeyCount>.*?</KeyCount>", b"<KeyCount>0</KeyCount>", changed, count=1)
        if count != 1:
            raise ValueError("KeyCount field not observed")
        return 200, changed
    raise ValueError("unknown discovery transport fault: " + mode)


class Proxy:
    def __init__(self, backend, evidence):
        self.backend = backend
        self.trace = Trace(evidence / "discovery-s3.jsonl")
        self.lock, self.serial = threading.Lock(), 0
        self.rules, self.errors = [], []
        self.latency = None
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
                # BaseHTTPRequestHandler has parsed the request headers. Take
                # this handler-entry witness before authentication, locks or
                # trace I/O; it is not the sender's dispatch or body-read time.
                request_received_monotonic_ns = time.monotonic_ns()
                selected = None
                try:
                    self.connection.settimeout(12)
                    length = int(self.headers.get("Content-Length", "0"))
                    if not 0 <= length <= 4 * 1024 * 1024:
                        raise ValueError("fixture request bound")
                    payload = self.rfile.read(length)
                    if len(payload) != length:
                        raise ValueError("incomplete incoming object request")
                    parsed = urlsplit(self.path)
                    pairs = parse_qsl(parsed.query, keep_blank_values=True)
                    query = dict(pairs)
                    if len(query) != len(pairs):
                        raise ValueError("duplicate S3 query parameter")
                    object_key = unquote(parsed.path).removeprefix("/scap-test/")
                    signed = signing(self.command, self.path, self.headers, payload, owner.backend.access, owner.backend.secret)
                    with owner.lock:
                        owner.serial += 1
                        serial = owner.serial
                        latency = owner.latency if self.command == "GET" and not query else None
                        for rule in owner.rules:
                            if rule.matches(self.command, object_key, query):
                                selected = rule
                                rule.used, rule.serial = 1, serial
                                break
                    fields = {"request_serial": serial, "method": self.command, "path": self.path,
                              "request_received_monotonic_ns": request_received_monotonic_ns,
                              "key": object_key, "query": query, "request": body(payload),
                              "if_match": self.headers.get("If-Match"), "if_none_match": self.headers.get("If-None-Match"),
                              "signing": signed, "fault": selected.label if selected else None,
                              "latency": latency[0] if latency else None}
                    owner.trace.emit("request", **fields)
                    if selected:
                        owner.trace.emit("fault_observed", request_serial=serial, label=selected.label, mode=selected.mode)
                        selected.arrived.set()
                    if selected and selected.mode == "hold" and not selected.release.wait(12):
                        raise TimeoutError("discovery hold fixture deadline")
                    connection = http.client.HTTPConnection("127.0.0.1", owner.backend.port, timeout=10)
                    try:
                        connection.putrequest(self.command, self.path, skip_host=True, skip_accept_encoding=True)
                        for name, value in self.headers.items():
                            connection.putheader(name, value)
                        connection.endheaders(payload)
                        owner.trace.emit("forwarded", request_serial=serial)
                        response = connection.getresponse()
                        raw = response.read(4 * 1024 * 1024 + 1)
                        if len(raw) > 4 * 1024 * 1024:
                            raise ValueError("fixture response bound")
                        original = {"status": response.status, "body": body(raw), "etag": response.getheader("ETag")}
                        owner.trace.emit("backend_response", request_serial=serial, **original)
                        if latency:
                            owner.trace.emit("delay_started", request_serial=serial, label=latency[0], seconds=latency[1])
                            time.sleep(latency[1])
                            owner.trace.emit("delay_finished", request_serial=serial, label=latency[0])
                        status, delivered = fault_response(raw, response.status, selected.mode if selected else None)
                        outgoing = {"status": status, "body": body(delivered), "etag": response.getheader("ETag")}
                        # The pre-send event bounds the actual returned body. A
                        # post-send logger can run after the client receives it.
                        owner.trace.emit("delivery_started", request_serial=serial, **outgoing)
                        try:
                            self.send_response_only(status)
                            for name, value in response.getheaders():
                                if name.lower() not in ("connection", "transfer-encoding", "content-length"):
                                    self.send_header(name, value)
                            self.send_header("Content-Length", str(len(delivered)))
                            self.send_header("Connection", "close")
                            self.end_headers()
                            self.wfile.write(delivered)
                            self.wfile.flush()
                            owner.trace.emit("delivery_finished", request_serial=serial)
                        except (BrokenPipeError, ConnectionResetError):
                            owner.trace.emit("delivery_disconnected", request_serial=serial)
                    finally:
                        connection.close()
                except BaseException as error:
                    with owner.lock:
                        owner.errors.append(repr(error))
                    owner.trace.emit("fixture_failed", error=repr(error))
                finally:
                    if selected:
                        selected.finished.set()
                    self.close_connection = True

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = False
        self.endpoint = f"http://127.0.0.1:{self.server.server_port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def arm(self, label, mode, **selector):
        rule = Rule(label, mode, **selector)
        with self.lock:
            if any(old.label == label for old in self.rules):
                raise ValueError("fault label reused")
            self.rules.append(rule)
        self.trace.emit("fault_armed", label=label, mode=mode, **selector)
        return rule

    def release(self, rule):
        self.trace.emit("hold_released", label=rule.label, request_serial=rule.serial)
        rule.release.set()

    def delay_exact_gets(self, label, seconds):
        if not 0 < seconds <= 0.1:
            raise ValueError("fixture exact-GET delay bound")
        with self.lock:
            if self.latency is not None:
                raise ValueError("fixture exact-GET latency already active")
            self.latency = (label, seconds)
        self.trace.emit("latency_armed", label=label, seconds=seconds)

    def clear_latency(self):
        with self.lock:
            if self.latency is None:
                raise ValueError("fixture exact-GET latency not active")
            label, _ = self.latency
            self.latency = None
        self.trace.emit("latency_disabled", label=label)

    def close(self):
        for rule in self.rules:
            rule.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        if self.thread.is_alive():
            raise TimeoutError("discovery proxy did not stop")
