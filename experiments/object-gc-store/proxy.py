"""Observe actual signed S3 traffic and pause a single original request."""
from __future__ import annotations

import http.client
import http.server
import threading
import time

from support import body_record, verify_signature

NS = b' xmlns="http://s3.amazonaws.com/doc/2006-03-01/"'
VERSIONING = b"<VersioningConfiguration" + NS + b"/>"


def error(code):
    return b"<Error><Code>" + code.encode() + b"</Code></Error>"


def mutation(mode, original):
    status, headers, body, extra = original["status"], dict(original["headers"]), original["bytes"], 0
    if mode == "malformed":
        body = b"<VersioningConfiguration"
    elif mode == "unknown_versioning":
        body = b"<VersioningConfiguration" + NS + b"><Status>Future</Status></VersioningConfiguration>"
    elif mode == "oversize":
        body = b" " * 32769
        if status == 204:
            status = 500
    elif mode == "short":
        extra = 13
    elif mode == "version_header":
        headers["x-amz-version-id"] = "unexpected-version"
    elif mode == "object_lock":
        status, body = 200, b"<ObjectLockConfiguration" + NS + b"><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>"
    elif mode in ("no_such_key", "no_such_bucket", "bad_404"):
        status = 404
        body = {"no_such_key": error("NoSuchKey"), "no_such_bucket": error("NoSuchBucket"),
                "bad_404": b"not XML"}[mode]
    elif mode in ("status_401", "status_403", "status_409", "status_500", "status_200"):
        status, body = int(mode[-3:]), b""
    elif mode == "redirect":
        status, body = 307, b""
        headers["Location"] = "/must-not-follow"
    elif mode not in (None, "drop_before", "drop_after", "late_before", "config_race"):
        raise AssertionError("unknown proxy mode " + str(mode))
    return status, headers, body, extra


class Call:
    def __init__(self, name, stage=None, mode=None):
        self.name, self.stage, self.mode = name, stage, mode
        self.arrived, self.release = threading.Event(), threading.Event()
        self.condition = threading.Condition()
        self.active, self.requests, self.used = 0, 0, 0

    def idle(self):
        with self.condition:
            assert self.condition.wait_for(lambda: self.active == 0, 8), "proxy handlers still active"


class Proxy:
    def __init__(self, backend, log):
        self.backend, self.log, self.current, self.errors = backend, log, None, []
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args):
                pass

            def do_GET(self):
                self.forward()

            def do_DELETE(self):
                self.forward()

            def __getattr__(self, name):
                # BaseHTTPRequestHandler otherwise returns an unrecorded 501
                # for unexpected verbs, hiding them from the HTTP denominator.
                if name.startswith("do_"):
                    return self.unexpected_method
                raise AttributeError(name)

            def unexpected_method(self):
                call = owner.current
                self.close_connection = True
                message = "unplanned product method: " + self.command
                owner.errors.append(message)
                if call is not None:
                    with call.condition:
                        call.requests += 1
                owner.log.write("unexpected_http", case=call.name if call else None,
                                method=self.command, target=self.path, headers=dict(self.headers.items()),
                                body_observed=False, forwarded=False)
                owner.log.write("fixture_error", case=call.name if call else None, error=message)
                try:
                    self.send_response_only(501)
                    self.send_header("Content-Length", "0")
                    self.send_header("Connection", "close")
                    self.end_headers()
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def forward(self):
                call, connection = owner.current, None
                assert call is not None
                with call.condition:
                    call.active += 1
                    call.requests += 1
                    sequence = call.requests
                self.close_connection = True
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    assert length == 0, "GC requests must have empty bodies"
                    payload, started = b"", time.monotonic_ns()
                    headers = dict(self.headers.items())
                    auth = verify_signature(self.command, self.path, headers, payload, backend.access, backend.secret)
                    assert auth, "independent signature check rejected product request"
                    stage = "delete" if self.command == "DELETE" else self.path.rsplit("?", 1)[-1]
                    mode = None
                    with call.condition:
                        if stage == call.stage and call.used == 0:
                            mode, call.used = call.mode, 1
                    owner.log.write("request", case=call.name, sequence=sequence, method=self.command,
                                    target=self.path, headers=headers, body=body_record(payload),
                                    signature_valid=auth, fault=mode, request_started_ns=started)
                    if mode in ("drop_before", "late_before"):
                        call.arrived.set()
                        assert call.release.wait(8), "original request release deadline"
                        if mode == "drop_before":
                            owner.log.write("transport_end", case=call.name, sequence=sequence,
                                            forwarded=False, response_attempted=False)
                            return
                    connection = http.client.HTTPConnection("127.0.0.1", backend.port, timeout=5)
                    connection.putrequest(self.command, self.path, skip_host=True, skip_accept_encoding=True)
                    for name, value in headers.items():
                        connection.putheader(name, value)
                    # HTTPConnection buffers request headers until endheaders.
                    # Record the lower bound before the first upstream send,
                    # independently of how long its response later takes.
                    owner.log.write("backend_forward_started", case=call.name, sequence=sequence,
                                    forward_started_ns=time.monotonic_ns())
                    connection.endheaders()
                    response = connection.getresponse()
                    body = response.read(65537)
                    assert len(body) <= 65536
                    original = {"status": response.status, "headers": dict(response.getheaders()), "bytes": body}
                    owner.log.write("backend_response", case=call.name, sequence=sequence,
                                    status=original["status"], headers=original["headers"], body=body_record(body))
                    if mode in ("drop_after", "config_race"):
                        call.arrived.set()
                        assert call.release.wait(8), "backend response release deadline"
                        if mode == "drop_after":
                            owner.log.write("transport_end", case=call.name, sequence=sequence,
                                            forwarded=True, response_attempted=False)
                            return
                    status, delivered_headers, delivered, extra = mutation(mode, original)
                    sent = False
                    attempted = time.monotonic_ns()
                    try:
                        self.send_response_only(status)
                        for name, value in delivered_headers.items():
                            if name.lower() not in ("content-length", "connection", "transfer-encoding"):
                                self.send_header(name, value)
                        self.send_header("Content-Length", str(len(delivered) + extra))
                        self.send_header("Connection", "close")
                        self.end_headers()
                        self.wfile.write(delivered)
                        self.wfile.flush()
                        sent = True
                    except (BrokenPipeError, ConnectionResetError):
                        pass
                    owner.log.write("delivery", case=call.name, sequence=sequence, status=status,
                                    headers=delivered_headers, body=body_record(delivered),
                                    declared_length=len(delivered) + extra, write_completed=sent,
                                    delivery_attempt_ns=attempted)
                except BaseException as exception:
                    owner.errors.append(repr(exception))
                    owner.log.write("fixture_error", case=call.name, sequence=sequence, error=repr(exception))
                finally:
                    if connection is not None:
                        connection.close()
                    with call.condition:
                        call.active -= 1
                        call.condition.notify_all()

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.endpoint = f"http://127.0.0.1:{self.server.server_port}"

    def close(self):
        if self.current is not None:
            self.current.release.set()
            self.current.idle()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(3)
        assert not self.thread.is_alive()
