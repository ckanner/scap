"""Real forwarding only; complete per-listener histories and owned handler joins."""
from __future__ import annotations

import base64
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import sys
import threading
import time

from fixture_spec import DEADLINES, LIMITS

# Reuse only the nonsecret SigV4 header projection. No owner fixture globals or
# producer-side service assertions are imported or replaced.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "object-service"))
from isolation_proxy import signing


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def payload(prefix, raw):
    return {prefix + "_base64": base64.b64encode(raw).decode("ascii"),
            prefix + "_bytes": len(raw), prefix + "_sha256": sha(raw)}


def error_name(error):
    allowed = {"AssertionError", "BrokenPipeError", "ConnectionAbortedError", "ConnectionResetError",
               "EOFError", "HTTPException", "IncompleteRead", "JSONDecodeError", "OSError",
               "RemoteDisconnected", "RuntimeError", "TimeoutError", "ValueError"}
    name = type(error).__name__
    return name if name in allowed else "UNKNOWN"


def cleanup_event(trace, failures, event, **fields):
    """A failed evidence sink cannot prevent a previously owned effect closing."""
    try:
        trace.emit(event, **fields)
    except BaseException as error:
        failures.append({"event": event, "error_name": error_name(error)})


class Trace:
    def __init__(self, path):
        self.path, self.sequence, self.lock = path, 0, threading.RLock()
        self.errors = []
        with path.open("xb"):
            pass
        path.chmod(0o600)

    def emit(self, event, **fields):
        with self.lock:
            self.sequence += 1
            row = {"schema": 1, "sequence": self.sequence, "monotonic_ns": time.monotonic_ns(),
                   "event": event, **fields}
            try:
                with self.path.open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(row, sort_keys=True) + "\n")
                    stream.flush()
                    os.fsync(stream.fileno())
            except BaseException as error:
                # In particular, a failed fsync can leave an apparently
                # complete line. Keep that durability failure independently;
                # later successful writes cannot turn this run into a PASS.
                self.errors.append({"trace": self.path.name, "event": event,
                                    "sequence": self.sequence, "error_name": error_name(error)})
                raise
            return row


class Rule:
    def __init__(self, identifier, fields):
        self.id, self.fields, self.used = identifier, fields, False
        self.entered, self.released = threading.Event(), threading.Event()
        self.request_serial = None

    def matches(self, fields, raw):
        if any(self.fields[key] != fields[key] for key in ("worker", "method", "path")):
            return False
        return "nonce" not in self.fields or str(json.loads(raw)["transition"]["nonce"]) == self.fields["nonce"]


class Listener(http.server.ThreadingHTTPServer):
    """Own every accepted socket thread, including malformed/empty requests."""
    daemon_threads = False
    block_on_close = True

    def __init__(self, hub, channel, worker, handler):
        self.hub, self.channel, self.worker = hub, channel, worker
        self.listener_id = channel + "-" + worker
        self.trace = hub.http_trace if channel == "http" else hub.s3_trace
        self.lock, self.local = threading.RLock(), threading.local()
        self.accepted, self.finished = 0, 0
        self.active, self.threads = {}, []
        super().__init__(("127.0.0.1", 0), handler)
        self.serve_thread = threading.Thread(target=self.serve_forever, daemon=False)
        self.serve_thread.start()

    def process_request(self, request, client_address):
        with self.lock:
            self.accepted += 1
            identifier = self.listener_id + ":" + str(self.accepted)
            state = {"handler_id": identifier, "failed": False, "dispatches": 0}
            self.active[identifier] = state
            thread = threading.Thread(target=self.owned_request, args=(request, client_address, state), daemon=False)
            self.threads.append(thread)
            thread.start()

    def owned_request(self, request, client_address, state):
        self.local.state = state
        common = {"listener_id": self.listener_id, "handler_id": state["handler_id"],
                  "worker": self.worker, "channel": self.channel}
        try:
            self.trace.emit("handler_started", **common)
            self.finish_request(request, client_address)
        except BaseException as error:
            self.failed(error)
        finally:
            try:
                self.shutdown_request(request)
            finally:
                with self.lock:
                    state["failed"] |= state["dispatches"] != 1
                    try:
                        self.trace.emit("handler_finished", **common, failed=state["failed"])
                    finally:
                        self.finished += 1
                        del self.active[state["handler_id"]]

    def failed(self, error):
        state = self.local.state
        state["failed"] = True
        row = {"listener_id": self.listener_id, "handler_id": state["handler_id"],
               "worker": self.worker, "error_name": error_name(error)}
        with self.hub.lock:
            self.hub.errors.append(row)
        self.trace.emit("http_fixture_failed" if self.channel == "http" else "object_fixture_failed", **row)

    def stop(self, errors):
        self.shutdown()
        self.server_close()
        self.serve_thread.join(timeout=3)
        assert not self.serve_thread.is_alive(), "proxy serve thread did not join"
        # All accepted requests have a socket timeout. A join failure is raw
        # fixture failure, never an excuse to seal an incomplete lifecycle.
        bound = time.monotonic() + DEADLINES["child_seconds"]
        for thread in self.threads:
            thread.join(timeout=max(0, bound - time.monotonic()))
        assert all(not thread.is_alive() for thread in self.threads), "proxy handler did not join"
        with self.lock:
            assert not self.active and self.accepted == self.finished
            cleanup_event(self.hub.events, errors, "proxy_listener_stopped", listener_id=self.listener_id,
                channel=self.channel, worker=self.worker, accepted_handlers=self.accepted,
                finished_handlers=self.finished, active_handlers=0, serve_thread_joined=True, handlers_joined=True)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        self.connection.settimeout(DEADLINES["child_seconds"] if self.server.channel == "http"
                                   else DEADLINES["s3_ms"] / 1000)

    def log_message(self, *_args):
        pass

    def __getattr__(self, name):
        # BaseHTTPRequestHandler's default 501 would otherwise omit unexpected
        # methods from the raw object-request denominator.
        if name.startswith("do_"):
            return self.dispatch
        raise AttributeError(name)

    def send_error(self, code, message=None, explain=None):
        self.server.failed(ValueError("invalid raw HTTP framing"))
        super().send_error(code, message, explain)

    def dispatch(self):
        self.server.local.state["dispatches"] += 1
        try:
            self.forward()
        except BaseException as error:
            self.server.failed(error)
        finally:
            self.close_connection = True

    def incoming(self):
        assert self.headers.get("Transfer-Encoding") is None, "fixture requires a fixed request body"
        length = int(self.headers.get("Content-Length", "0"))
        limit = LIMITS["http_request_bytes"] if self.server.channel == "http" else LIMITS["proxy_body_bytes"]
        assert 0 <= length <= limit
        raw = self.rfile.read(length)
        assert len(raw) == length, "truncated incoming body"
        return raw

    def deliver(self, status, headers, raw):
        self.send_response_only(status)
        for name, value in headers:
            if name.lower() not in ("connection", "transfer-encoding", "content-length"):
                self.send_header(name, value)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(raw)
        self.wfile.flush()

    def forward(self):
        owner, worker = self.server.hub, self.server.worker
        raw = self.incoming()
        common = {"listener_id": self.server.listener_id,
                  "handler_id": self.server.local.state["handler_id"],
                  "worker": worker, "method": self.command, "path": self.path,
                  **payload("request_body", raw)}
        if self.server.channel == "http":
            token = self.headers.get("Authorization", "").removeprefix("Bearer ")
            with owner.lock:
                owner.http_serial += 1
                common.update(http_serial=owner.http_serial, command=self.headers.get("X-SCAP-Fixture-Command"),
                              credential_sha256=sha(token.encode()))
                owner.http_trace.emit("http_request", **common)
            return self.forward_http(common, raw)
        with owner.lock:
            owner.s3_serial += 1
            common.update(request_serial=owner.s3_serial, if_match=self.headers.get("If-Match"),
                          if_none_match=self.headers.get("If-None-Match"), signing=signing(self.headers))
            owner.s3_trace.emit("object_request", **common)
        self.forward_s3(common, raw)

    def forward_http(self, common, raw):
        owner = self.server.hub
        connection = http.client.HTTPConnection("127.0.0.1", owner.http_ports[self.server.worker],
                                                timeout=DEADLINES["child_seconds"])
        try:
            connection.putrequest(self.command, self.path, skip_accept_encoding=True)
            for name, value in self.headers.items():
                if name.lower() not in ("host", "connection"):
                    connection.putheader(name, value)
            connection.putheader("Connection", "close")
            connection.endheaders(raw)
            owner.http_trace.emit("http_forwarded", **common)
            response = connection.getresponse()
            body = response.read(LIMITS["proxy_body_bytes"] + 1)
            assert len(body) <= LIMITS["proxy_body_bytes"]
            received = {"status": response.status, **payload("response_body", body),
                        "response_headers": response.getheaders(), "response_origin": "service"}
            owner.http_trace.emit("http_response", **common, **received)
            self.deliver(response.status, received["response_headers"], body)
            owner.http_trace.emit("http_delivered", **common, **received)
        finally:
            connection.close()

    def forward_s3(self, common, raw):
        owner = self.server.hub
        rule = owner.select(common, raw)
        if rule and rule.fields["kind"] == "hold":
            owner.enter(rule, common["request_serial"])
            if not rule.released.wait(DEADLINES["gate_seconds"]):
                owner.events.emit("fault_expired", id=rule.id, request_serial=rule.request_serial)
                raise TimeoutError("original metadata gate expired")
        connection = http.client.HTTPConnection("127.0.0.1", owner.backend_port, timeout=DEADLINES["s3_ms"] / 1000)
        try:
            # The original signed Host and conditional headers remain intact.
            connection.putrequest(self.command, self.path, skip_host=True, skip_accept_encoding=True)
            for name, value in self.headers.items():
                connection.putheader(name, value)
            connection.endheaders(raw)
            owner.s3_trace.emit("object_forwarded", **common)
            response = connection.getresponse()
            body = response.read(LIMITS["proxy_body_bytes"] + 1)
            assert len(body) <= LIMITS["proxy_body_bytes"]
            received = {"status": response.status, **payload("response_body", body),
                        "etag": response.getheader("ETag"), "response_origin": "backend"}
            owner.s3_trace.emit("object_response", **common, **received)
            if self.server.worker == "F" and self.command == "GET" and response.status == 200:
                with owner.lock:
                    assert self.path not in owner.fixture_reads, "repeated fixture read"
                    owner.fixture_reads[self.path] = {"request_serial": common["request_serial"],
                                                     "body": body, "etag": received["etag"]}
            if rule and rule.fields["kind"] == "drop":
                assert response.status == 200, "response loss requires an actual accepted backend response"
                owner.enter(rule, common["request_serial"])
                owner.s3_trace.emit("object_response_suppressed", **common, **received,
                    fault_id=rule.id, reason="explicit_response_loss")
                return
            self.deliver(response.status, response.getheaders(), body)
            owner.s3_trace.emit("object_response_delivered", **common, **received)
        finally:
            connection.close()


class Hub:
    def __init__(self, backend_port, evidence, events):
        self.backend_port, self.events = backend_port, events
        self.http_trace, self.s3_trace = Trace(evidence / "http-proxy.jsonl"), Trace(evidence / "s3.jsonl")
        self.lock, self.http_serial, self.s3_serial = threading.RLock(), 0, 0
        self.rules, self.listeners, self.errors, self.fixture_reads, self.http_ports = {}, [], [], {}, {}

    def start(self, channel, worker, backend_port=None):
        assert all(listener.listener_id != channel + "-" + worker for listener in self.listeners)
        if channel == "http":
            self.http_ports[worker] = backend_port
        else:
            assert channel == "s3" and backend_port is None
        listener = Listener(self, channel, worker, Handler)
        self.listeners.append(listener)
        endpoint = "http://127.0.0.1:" + str(listener.server_port)
        self.events.emit("proxy_listener_started", listener_id=listener.listener_id,
                         channel=channel, worker=worker, endpoint=endpoint)
        return endpoint + "/v1" if channel == "http" else endpoint

    def arm(self, identifier, **fields):
        with self.lock:
            assert identifier not in self.rules
            assert ((fields["kind"], fields["stage"]) in
                    (("hold", "before_forward"), ("drop", "after_backend_response")))
            self.rules[identifier] = Rule(identifier, fields)
            self.events.emit("fault_armed", id=identifier, **fields)

    def select(self, fields, raw):
        with self.lock:
            matches = [rule for rule in self.rules.values() if rule.matches(fields, raw)]
            assert len(matches) <= 1, "ambiguous fault"
            if not matches:
                return None
            rule = matches[0]
            assert not rule.used, "repeated fault request"
            rule.used = True
            return rule

    def enter(self, rule, request_serial):
        assert not rule.entered.is_set()
        rule.request_serial = request_serial
        self.events.emit("fault_entered", id=rule.id, request_serial=request_serial)
        rule.entered.set()

    def wait(self, identifier):
        rule = self.rules[identifier]
        assert rule.entered.wait(DEADLINES["gate_seconds"]), "fault did not enter"
        return rule.request_serial

    def release(self, identifier):
        rule = self.rules[identifier]
        assert rule.fields["kind"] == "hold" and rule.entered.is_set() and not rule.released.is_set()
        self.events.emit("fault_released", id=identifier, request_serial=rule.request_serial)
        rule.released.set()

    def complete(self):
        assert not self.errors and not any(trace.errors for trace in (self.events, self.http_trace, self.s3_trace))
        assert len(self.rules) == 3
        assert all(rule.used and rule.entered.is_set() and
                   (rule.fields["kind"] != "hold" or rule.released.is_set()) for rule in self.rules.values())

    def release_for_cleanup(self, errors):
        for rule in self.rules.values():
            if rule.fields["kind"] == "hold" and rule.entered.is_set() and not rule.released.is_set():
                try:
                    cleanup_event(self.events, errors, "fault_cleanup_release", id=rule.id, request_serial=rule.request_serial)
                finally:
                    rule.released.set()
                errors.append("unreleased_fault")

    def close(self, errors):
        self.release_for_cleanup(errors)
        for listener in self.listeners:
            try:
                listener.stop(errors)
            except BaseException as error:
                errors.append(error_name(error))
        errors.extend(self.errors)
        errors.extend(self.http_trace.errors)
        errors.extend(self.s3_trace.errors)
        assert not self.errors and not errors, {"proxy_errors": self.errors, "shutdown_errors": errors}
