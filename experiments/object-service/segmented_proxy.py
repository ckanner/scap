"""Raw signed-S3 relay; deduplicated body files keep the fixed large trace small."""
from __future__ import annotations

import http.client
import http.server
import json
import os
import threading
import time

from isolation_proxy import sha, signing
from segmented_spec import DEADLINES


class Proxy:
    def __init__(self, backend_port, evidence):
        self.backend_port, self.evidence = backend_port, evidence
        self.blobs = evidence / "s3-bodies"
        self.blobs.mkdir()
        self.lock, self.serial, self.sequence = threading.RLock(), 0, 0
        self.phase, self.errors, self.objects = "setup", [], {}
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            def log_message(self, *_args): pass
            def do_GET(self): self.dispatch()
            def do_PUT(self): self.dispatch()
            def do_DELETE(self): self.dispatch()

            def dispatch(self):
                try:
                    self.forward()
                except BaseException as error:
                    owner.errors.append(repr(error))
                    owner.emit("transport_fixture_failed", error=repr(error))
                finally:
                    self.close_connection = True

            def forward(self):
                self.connection.settimeout(DEADLINES["s3_request_ms"] / 1000)
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 <= length <= 4 * 1024 * 1024: raise ValueError("request byte bound")
                body = self.rfile.read(length)
                if len(body) != length: raise ValueError("truncated S3 request")
                with owner.lock:
                    owner.serial += 1
                    fields = {"request_serial": owner.serial, "phase": owner.phase, "method": self.command,
                              "path": self.path, "request_bytes": len(body), "request_sha256": owner.store(body),
                              "if_match": self.headers.get("If-Match"), "if_none_match": self.headers.get("If-None-Match"),
                              "signing": signing(self.headers)}
                owner.emit("object_request", **fields)
                connection = http.client.HTTPConnection("127.0.0.1", owner.backend_port,
                                                        timeout=DEADLINES["s3_request_ms"] / 1000)
                try:
                    connection.putrequest(self.command, self.path, skip_host=True, skip_accept_encoding=True)
                    for name, value in self.headers.items(): connection.putheader(name, value)
                    connection.endheaders(body)
                    owner.emit("object_forwarded", **fields)
                    response = connection.getresponse()
                    raw = response.read(4 * 1024 * 1024 + 1)
                    if len(raw) > 4 * 1024 * 1024: raise ValueError("response byte bound")
                    received = {"status": response.status, "response_bytes": len(raw),
                                "response_sha256": owner.store(raw), "etag": response.getheader("ETag")}
                    owner.emit("object_response", response_origin="backend", **fields, **received)
                    with owner.lock:
                        if response.status == 200:
                            owner.objects[self.path] = body if self.command == "PUT" else raw
                        if self.command == "DELETE" and response.status in (200, 204):
                            owner.objects.pop(self.path, None)
                    self.send_response_only(response.status)
                    for name, value in response.getheaders():
                        if name.lower() not in ("connection", "transfer-encoding", "content-length"):
                            self.send_header(name, value)
                    self.send_header("Content-Length", str(len(raw))); self.send_header("Connection", "close")
                    self.end_headers(); self.wfile.write(raw)
                    owner.emit("object_response_delivered", **fields, **received)
                finally: connection.close()

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = False
        self.endpoint = f"http://127.0.0.1:{self.server.server_port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

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
            row = {"schema": 1, "sequence": self.sequence, "event": event, "monotonic_ns": time.monotonic_ns(), **fields}
            with (self.evidence / "history.jsonl").open("a") as stream:
                stream.write(json.dumps(row, sort_keys=True) + "\n"); stream.flush(); os.fsync(stream.fileno())

    def set_phase(self, phase):
        with self.lock: self.phase = phase; self.emit("phase_started", phase=phase)

    def close(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=3)
        if self.thread.is_alive(): raise TimeoutError("proxy did not stop")
