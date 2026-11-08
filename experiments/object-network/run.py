#!/usr/bin/env python3
"""Real object/SQLite/process contracts; never contributes to unit coverage.

The Rust worker calls production code. This file only provisions a pinned S3
compatibility backend, controls transport/process faults and checks observations.
Private fixture credentials and backend data stay outside the public evidence.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import resource
import secrets
import select
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time


VERSION = "4.51 153ab668c99731a6d29492bf6c61d0b4fa701101"
RECORD_LOCK = threading.Lock()
FIXTURE_BODY_LIMIT = 64 * 1024 * 1024
CONTRACTS = [
    "signed_exact_key_conditional_objects",
    "same_etag_two_process_competition",
    "original_result_and_all_compute_loss",
    "lost_head_response_keeps_original_result",
    "takeover_fences_inflight_old_writer",
    "commit_cancel_both_orders",
    "lost_cancel_response_preserves_fence",
    "corrupt_dependency_fails_closed_without_head_change",
    "object_blackhole_fails_closed",
    "backend_process_restart_retains_acknowledged_state",
]
FAULT_CONTRACTS = [
    "each_observed_dependency_upload_cut_retains_previous_authority",
    "accepted_head_survives_process_loss_and_native_publication_failure",
    "missing_and_corrupt_typed_dependencies_refuse_cold_activation",
    "changed_head_during_recovery_refuses_old_activation",
]


def append_synced(path, message):
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(message, sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def record(evidence, event, **values):
    message = {"event": event, "monotonic_ns": time.monotonic_ns(), "wall_time_ns": time.time_ns(), **values}
    with RECORD_LOCK:
        with (evidence / "history.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(message, sort_keys=True) + "\n")
        print(json.dumps(message, sort_keys=True), flush=True)


def process_identity(process):
    # The Popen child handle and its wait status are authoritative. In this
    # sandbox, /proc/self can report a host PID whose /proc/<PID> is unavailable;
    # reading /proc/Popen.pid would instead measure an unrelated process.
    return {"pid": process.pid, "spawn_monotonic_ns": time.monotonic_ns(),
            "pid_source": "owned_Popen_child"}


def wait_child(process, timeout):
    deadline = time.monotonic() + timeout
    if process.returncode is not None:
        return process.returncode, {"available": False, "reason": "already_reaped"}
    while time.monotonic() < deadline:
        pid, status, usage = os.wait4(process.pid, os.WNOHANG)
        if pid:
            assert pid == process.pid
            process.returncode = os.waitstatus_to_exitcode(status)
            return process.returncode, {"available": True, "source": "kernel_wait4_owned_child",
                "maxrss_bytes": usage.ru_maxrss * 1024,
                "user_seconds": usage.ru_utime, "system_seconds": usage.ru_stime}
        time.sleep(0.01)
    raise TimeoutError("owned child termination deadline")


def free_port(used):
    while True:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        if port not in used:
            used.add(port)
            return port


class Backend:
    def __init__(self, binary, directory, volume_size_mib=64, max_volumes=2):
        version = subprocess.check_output([str(binary), "version"], text=True).strip()
        assert VERSION in version, version
        self.binary = binary
        self.directory = directory
        self.directory.mkdir(mode=0o700)
        self.access = secrets.token_hex(16)
        self.secret = secrets.token_hex(32)
        self.identity = self.directory / "identity.private.json"
        self.identity.write_text(json.dumps({"identities": [{
            "name": "object-contract", "credentials": [{"accessKey": self.access, "secretKey": self.secret}],
            "actions": ["Admin", "Read", "Write", "List", "Tagging"],
        }]}))
        self.identity.chmod(0o600)
        used = set()
        ports = {name: (free_port(used), free_port(used)) for name in ("master", "volume", "filer", "s3")}
        self.port = ports["s3"][0]
        self.endpoint = f"http://127.0.0.1:{self.port}"
        master = "127.0.0.1:%d.%d" % ports["master"]
        filer = "127.0.0.1:%d.%d" % ports["filer"]
        for name in ("master", "volume", "filer"):
            (directory / name).mkdir(mode=0o700)
        def listen(name):
            return ["-ip=127.0.0.1", "-ip.bind=127.0.0.1", f"-port={ports[name][0]}", f"-port.grpc={ports[name][1]}"]
        self.commands = [
            ("master", ["master", *listen("master"), f"-mdir={directory / 'master'}", "-peers=none", "-telemetry=false", f"-volumeSizeLimitMB={volume_size_mib}", "-volumePreallocate=false"]),
            ("volume", ["volume", *listen("volume"), f"-dir={directory / 'volume'}", f"-master={master}", f"-max={max_volumes}"]),
            ("filer", ["filer", *listen("filer"), f"-defaultStoreDir={directory / 'filer'}", f"-master={master}"]),
            ("s3", ["s3", *listen("s3"), f"-filer={filer}", f"-config={self.identity}", "-port.iceberg=0", "-port.lance=0"]),
        ]
        self.processes = []
        self.process_metadata = {}
        self.capacity = {"volume_size_mib": volume_size_mib, "max_volumes": max_volumes, "preallocate": False}

    def signed(self, method, path, body=""):
        # Only fixture provisioning uses curl. Product object operations use the
        # production S3 adapter with independently checked SigV4 responses.
        command = ["curl", "--silent", "--show-error", "--fail", "--max-time", "1", "--noproxy", "*",
                   "--aws-sigv4", "aws:amz:us-east-1:s3", "--config", "-", "-X", method]
        if method == "HEAD":
            command.append("--head")
        else:
            command.extend(["--data-binary", body])
        command.append(self.endpoint + path)
        return subprocess.run(command, input=f'user = "{self.access}:{self.secret}"\n', text=True,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False).returncode == 0

    def start(self):
        assert not self.processes
        for name, arguments in self.commands:
            with (self.directory / f"{name}.private.log").open("ab") as log:
                process = subprocess.Popen([str(self.binary), *arguments], stdout=log, stderr=log, cwd=self.directory)
                self.processes.append(process)
                self.process_metadata[process.pid] = process_identity(process)
        bound = time.monotonic() + 40
        while time.monotonic() < bound:
            assert all(process.poll() is None for process in self.processes), "backend exited before readiness"
            if self.signed("HEAD", "/scap-test") or self.signed("PUT", "/scap-test"):
                if self.signed("PUT", "/scap-test/fixture-ready", "ready"):
                    return
            time.sleep(0.15)
        raise AssertionError("signed backend readiness deadline")

    def stop(self, verify=False):
        if verify:
            assert len(self.processes) == 4
            assert all(process.poll() is None for process in self.processes)
        for process in reversed(self.processes):
            if process.poll() is None:
                process.kill()
        observed = []
        for (name, _), process in zip(self.commands, self.processes):
            code, usage = wait_child(process, 8)
            if verify:
                assert code == -signal.SIGKILL, code
            observed.append({"role": name, **self.process_metadata.get(process.pid, {"pid": process.pid}),
                             "wait_status": code, "kernel_usage": usage})
        self.processes = []
        return observed

    def identities(self):
        return [{"role": name, **self.process_metadata[process.pid]} for (name, _), process in zip(self.commands, self.processes)]


class Rule:
    def __init__(self, mode, suffix=None, *, method=None, key=None, immutable=False,
                 occurrence=1, stage="before_forward", expected_status=None):
        assert stage in ("before_forward", "after_upstream_response")
        assert occurrence > 0
        self.mode = mode
        self.suffix = suffix
        self.method = method
        self.key = key
        self.immutable = immutable
        self.occurrence = occurrence
        self.stage = stage
        self.expected_status = expected_status
        self.arrived = threading.Event()
        self.release = threading.Event()
        self.finished = threading.Event()
        self.barrier = threading.Barrier(2, timeout=8) if mode == "pair" else None
        self.used = 0
        self.seen = 0
        self.aborted = False
        self.observation = None
        self.payload = None

    def matches(self, method, path):
        if self.method is not None and method != self.method:
            return False
        if self.suffix is not None and not (method == "PUT" and path.endswith(self.suffix)):
            return False
        if self.key is not None and path != "/scap-test/" + self.key:
            return False
        if self.immutable and (method != "PUT" or "/objects/" not in path):
            return False
        return True

    def abort(self):
        self.aborted = True
        self.release.set()


class Proxy:
    def __init__(self, backend_port, evidence):
        self.backend_port = backend_port
        self.evidence = evidence
        self.lock = threading.Lock()
        self.rule = None
        self.rules = []
        self.phase = "setup"
        self.request_serial = 0
        self.stats = {}
        self.successful_keys = {}
        self.errors = []
        # Capacity experiments import this fixture. Never accumulate their
        # large HTTP histories in memory; only the small fault suite opts in.
        self.capture = False
        # Catalogue authority JSON is bounded separately from binary objects.
        # Opt-in only: existing HEAD/capacity evidence remains byte-for-byte shaped as before.
        self.capture_catalogue = False
        self.observations = []
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
                    owner.event("transport_fixture_failed", error=repr(error))

            def forward(self):
                started = time.monotonic_ns()
                self.close_connection = True
                self.connection.settimeout(10)
                length = int(self.headers.get("Content-Length", "0"))
                assert 0 <= length <= FIXTURE_BODY_LIMIT
                payload = self.rfile.read(length)
                assert len(payload) == length
                with owner.lock:
                    owner.request_serial += 1
                    fields = {"request_serial": owner.request_serial, "phase": owner.phase,
                              "method": self.command, "path": self.path, "request_bytes": length,
                              "request_sha256": hashlib.sha256(payload).hexdigest(),
                              "if_match": self.headers.get("If-Match"), "if_none_match": self.headers.get("If-None-Match")}
                    if owner.capture and self.path.endswith("/head"):
                        fields["head_request_bytes"] = list(payload)
                    if owner.capture_catalogue and "/catalogue/v1/" in self.path:
                        assert len(payload) <= 64 * 1024, "catalogue request capture exceeds 64 KiB"
                        fields["catalogue_request_bytes"] = list(payload)
                    rule = owner.rule
                    if rule and not rule.matches(self.command, self.path):
                        rule = None
                    if rule:
                        rule.seen += 1
                        if rule.seen < rule.occurrence:
                            rule = None
                    if rule:
                        rule.used += 1
                        rule.payload = payload
                        if rule.mode in ("hold", "cut", "drop", "inject409", "inject412") or rule.mode == "pair" and rule.used == 2:
                            owner.rule = None
                owner.event("object_request", **fields)
                if rule and rule.stage == "before_forward":
                    owner.reached(rule, fields)
                    if rule.mode == "blackhole":
                        rule.release.wait(10)
                        return
                    if rule.mode in ("hold", "cut"):
                        assert rule.release.wait(12), "held operation release deadline"
                        if rule.aborted or rule.mode == "cut":
                            owner.event("request_aborted_before_forward", **fields)
                            rule.finished.set()
                            return
                    if rule.mode == "pair":
                        rule.barrier.wait()
                    if rule.mode in ("inject409", "inject412"):
                        status = int(rule.mode[-3:])
                        owner.event("injected_response", status=status, **fields)
                        self.send_response_only(status)
                        self.send_header("Content-Length", "0")
                        self.send_header("Connection", "close")
                        self.end_headers()
                        return
                upstream = http.client.HTTPConnection("127.0.0.1", owner.backend_port, timeout=8)
                try:
                    upstream.putrequest(self.command, self.path, skip_host=True, skip_accept_encoding=True)
                    for name, value in self.headers.items():
                        upstream.putheader(name, value)
                    upstream.endheaders(payload)
                    owner.event("object_forwarded", **fields)
                    response = upstream.getresponse()
                    body = response.read(FIXTURE_BODY_LIMIT + 1)
                    assert len(body) <= FIXTURE_BODY_LIMIT
                    received = {"status": response.status, "response_bytes": len(body),
                                "response_sha256": hashlib.sha256(body).hexdigest(),
                                "etag": response.getheader("ETag")}
                    if owner.capture and self.path.endswith("/head"):
                        received["head_response_bytes"] = list(body)
                    if owner.capture_catalogue and "/catalogue/v1/" in self.path:
                        assert len(body) <= 64 * 1024, "catalogue response capture exceeds 64 KiB"
                        received["catalogue_response_bytes"] = list(body)
                    owner.event("object_response", status=response.status,
                                **{key: value for key, value in received.items() if key != "status"},
                                suppressed=bool(rule and rule.mode in ("drop", "cut")),
                                response_origin="backend", elapsed_ns=time.monotonic_ns() - started, **fields)
                    if rule and rule.stage == "after_upstream_response":
                        if rule.expected_status is not None:
                            assert response.status == rule.expected_status, received
                        owner.reached(rule, {**fields, **received})
                        assert rule.release.wait(12), "accepted response release deadline"
                        if rule.aborted or rule.mode == "cut":
                            owner.event("response_suppressed_after_backend", **fields, **received)
                            rule.finished.set()
                            return
                    if rule and rule.mode == "drop":
                        assert response.status == 200, "response-loss boundary must follow actual acceptance"
                        return
                    self.send_response_only(response.status)
                    for name, value in response.getheaders():
                        if name.lower() not in ("connection", "transfer-encoding", "content-length"):
                            self.send_header(name, value)
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(body)
                    owner.event("object_response_delivered", **fields, **received)
                    if rule:
                        rule.finished.set()
                except (BrokenPipeError, ConnectionResetError):
                    owner.event("caller_disconnected", method=self.command, path=self.path)
                finally:
                    upstream.close()

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = False
        self.endpoint = f"http://127.0.0.1:{self.server.server_port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def event(self, event, **fields):
        with self.lock:
            if self.capture:
                self.observations.append({"event": event, **fields})
            phase = fields.get("phase", self.phase)
            counts = self.stats.setdefault(phase, {"get_requests": 0, "put_requests": 0,
                "get_response_bytes": 0, "put_request_bytes": 0, "put_success_bytes": 0,
                "put_successes": 0, "head_puts": 0, "http_statuses": {}})
            if event == "object_request":
                if fields["method"] == "GET":
                    counts["get_requests"] += 1
                if fields["method"] == "PUT":
                    counts["put_requests"] += 1
                    counts["put_request_bytes"] += fields["request_bytes"]
                    counts["head_puts"] += fields["path"].endswith("/head")
            if event == "object_response":
                status = str(fields["status"])
                counts["http_statuses"][status] = counts["http_statuses"].get(status, 0) + 1
                if fields["method"] == "GET":
                    counts["get_response_bytes"] += fields["response_bytes"]
                if fields["method"] == "PUT" and 200 <= fields["status"] < 300:
                    counts["put_successes"] += 1
                    counts["put_success_bytes"] += fields["request_bytes"]
                    self.successful_keys.setdefault(phase, set()).add(fields["path"])
            record(self.evidence, event, **fields)

    def reached(self, rule, fields):
        rule.observation = {"mode": rule.mode, "stage": rule.stage,
                            "matched_ordinal": rule.seen, **fields}
        self.event("transport_fault_observed", **rule.observation)
        # The controller only kills after this exact cut has a durable record.
        if rule.mode == "cut" or rule.stage == "after_upstream_response":
            with (self.evidence / "history.jsonl").open("rb") as stream:
                os.fsync(stream.fileno())
        rule.arrived.set()

    def set_phase(self, phase):
        with self.lock:
            self.phase = phase
            record(self.evidence, "phase_started", phase=phase)

    def metrics(self):
        with self.lock:
            return {name: {**json.loads(json.dumps(counts)),
                           "unique_successful_put_keys": len(self.successful_keys.get(name, set()))}
                    for name, counts in self.stats.items()}

    def arm(self, mode, suffix=None, **selector):
        with self.lock:
            assert self.rule is None
            rule = Rule(mode, suffix, **selector)
            self.rules.append(rule)
            self.rule = rule
            record(self.evidence, "transport_fault_armed", mode=mode, suffix=suffix, **selector)
            return rule

    def clear(self):
        with self.lock:
            self.rule = None
            for rule in self.rules:
                if rule.mode == "cut":
                    rule.abort()
                else:
                    rule.release.set()

    def close(self):
        self.clear()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)


class Worker:
    def __init__(self, binary, config, private, number, evidence, *, ignore_file_size_signal=False):
        def binary_digest():
            with binary.open("rb") as stream:return hashlib.file_digest(stream,"sha256").hexdigest()
        self.binary={"path":str(binary.resolve()),"sha256":binary_digest()}
        self.config = config
        self.evidence = evidence
        self.path = private / f"worker-{number}.private.json"
        self.path.write_text(json.dumps(config))
        self.path.chmod(0o600)
        previous = signal.getsignal(signal.SIGXFSZ)
        try:
            if ignore_file_size_signal:
                # This optional fault worker is spawned on the controller's
                # main thread. No product signal handler or Rust hook changes.
                signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
            with (private / f"worker-{number}.private.log").open("ab") as log:
                self.process = subprocess.Popen([str(binary), str(self.path)], stdin=subprocess.PIPE,
                                                stdout=subprocess.PIPE, stderr=log, text=True, bufsize=1,
                                                restore_signals=not ignore_file_size_signal)
        finally:
            if ignore_file_size_signal:
                signal.signal(signal.SIGXFSZ, previous)
        try:
            ready = self.read(10)
            assert ready["ready"] is True
            self.ready_resources = ready["resources"]
            if ignore_file_size_signal:
                assert int(ready["resources"]["signal_ignored_hex"], 16) & (1 << (signal.SIGXFSZ - 1))
            self.pending = None
            self.identity = process_identity(self.process)
            assert ready["resources"]["namespace_pid"] == self.process.pid
            self.identity.update(self_proc_pid=ready["resources"]["proc_pid"],
                                 self_start_ticks=ready["resources"]["start_ticks"])
            assert binary_digest()==self.binary["sha256"],"worker binary changed across Popen"
            record(evidence, "worker_started", worker=config["worker"], resources=ready["resources"], binary=self.binary, **self.identity)
        except BaseException:
            # Construction has not yet transferred ownership to the suite.
            if self.process.poll() is None:self.process.kill()
            wait_child(self.process,5)
            self.process.stdin.close();self.process.stdout.close()
            raise

    def read(self, timeout):
        assert select.select([self.process.stdout], [], [], timeout)[0], "worker response deadline"
        line = self.process.stdout.readline()
        assert line, f"worker exited {self.process.poll()}"
        return json.loads(line)

    def begin(self, op, **values):
        assert self.pending is None, "one outstanding command per process"
        started = time.monotonic_ns()
        request = {"op": op, **values}
        fields = {"worker": self.config["worker"], "pid": self.process.pid, "operation": op,
                  "request_id": values.get("id", values.get("identity", {}).get("id")),
                  "request_epoch": values.get("epoch", values.get("identity", {}).get("epoch")),
                  "key": values.get("key"), "budget_ms": values.get("budget_ms", 8000)}
        record(self.evidence, "client_invoked", **fields)
        self.process.stdin.write(json.dumps(request) + "\n")
        self.process.stdin.flush()
        self.pending = {"started": started, "fields": fields,
                        "timeout": values.get("budget_ms", 8000) / 1000 + 4}
        return self.pending

    def finish(self, pending):
        assert self.pending is pending
        fields = pending["fields"]
        try:
            response = self.read(pending["timeout"])
        except BaseException as error:
            record(self.evidence, "client_transport_failed", error=repr(error), **fields)
            raise
        finally:
            self.pending = None
        record(self.evidence, "client_observed", ok=response["ok"], error=response.get("error"),
               resolution=response.get("value", {}).get("state"), resources=response.get("resources"),
               error_details=response.get("error_details"),
               elapsed_ns=time.monotonic_ns() - pending["started"], worker_elapsed_ms=response.get("elapsed_ms"), **fields)
        return response

    def call(self, op, **values):
        return self.finish(self.begin(op, **values))

    def kill(self, verify=False):
        if verify:
            assert self.process.poll() is None
        if self.process.poll() is None:
            self.process.kill()
        code, usage = wait_child(self.process, 5)
        if verify:
            assert code == -signal.SIGKILL, code
        observed = {"worker": self.config["worker"], **self.identity, "wait_status": code, "kernel_usage": usage}
        record(self.evidence, "worker_stopped", fault=verify, **observed)
        if self.pending is not None:
            record(self.evidence, "client_invocation_lost_with_process", **self.pending["fields"],
                   wait_status=code, client_response_observed=False, fault_requested=verify,
                   cleanup_aborted=not verify)
            self.pending = None
        if not self.process.stdin.closed:
            self.process.stdin.close()
        if not self.process.stdout.closed:
            self.process.stdout.close()
        return observed


def success(value):
    assert value["ok"], value
    return value["value"]


def failure(value, *expected):
    assert not value["ok"], value
    assert value["error"] in expected, value
    return value["error"]


class FaultSuite:
    """Small, isolated process/transport observations of production APIs."""

    def __init__(self, arguments, evidence, private, compute, backend, proxy, workers, config):
        self.arguments, self.evidence, self.private = arguments, evidence, private
        self.compute, self.backend, self.proxy, self.workers, self.config = compute, backend, proxy, workers, config
        self.number = 100
        self.case_number = 0
        self.call_number = 0
        self.ack_number = 0
        self.audited = set()
        self.children = []
        self.inputs = evidence / "fault-input-ledger.jsonl"
        self.acks = evidence / "fault-ack-ledger.jsonl"
        self.outcomes = evidence / "fault-outcome-ledger.jsonl"
        self.cases = evidence / "fault-cases.jsonl"
        for path in (self.inputs, self.acks, self.outcomes, self.cases):
            path.touch(mode=0o600, exist_ok=False)
        self.summary = {"status": "running", "planned_case_count": 0, "passed_case_count": 0,
                        "case_results": [], "ack_audited_count": 0, "ack_mismatch_count": 0,
                        "outcome_mismatch_count": 0, "backend_missing_cases": 0, "backend_corrupt_cases": 0,
                        "coverage_scope": {
                            "dependency_cuts": "before forwarding and after backend 200, before client response",
                            "late_forward_after_process_death": "NOT_RUN; pre-forward cuts explicitly abort",
                            "warm_quarantine": "existing_unit_only; not measured by these cold cases",
                            "full_ot_01_08_matrix": "NOT_RUN",
                            "additional_http_error_matrix": "NOT_RUN",
                            "aws_endpoint_gate": "NOT_RUN"}}

    def event(self, case, event, **values):
        entry = {"case": case["name"], "scope": case["scope"], "event": event,
                 "wall_time_ns": time.time_ns(), "monotonic_ns": time.monotonic_ns(), **values}
        append_synced(self.cases, entry)
        record(self.evidence, event, case=case["name"], **values)

    def spawn(self, case, *, logical_worker=None, ignore_file_size_signal=False):
        self.number += 1
        config = {**self.config, "scope": case["scope"], "worker": logical_worker or self.number,
                  "cache_root": str(case["directory"]), "resource_log": None,
                  "fixture_limits": {"quota_bytes": 2 * 1024 * 1024, "retention_entries": 2,
                                     "retention_result_bytes": 128 * 1024 * 1024}}
        entry = Worker(self.arguments.worker.resolve(), config, self.private, self.number, self.evidence,
                       ignore_file_size_signal=ignore_file_size_signal)
        self.workers.append(entry)
        case["workers"].append(entry)
        return entry

    def stop(self, case, worker, *, fault=False):
        observed = worker.kill(verify=fault)
        self.workers.remove(worker)
        case["workers"].remove(worker)
        return observed

    def phase(self, case, suffix):
        phase = case["name"] + "/" + suffix
        self.proxy.set_phase(phase)
        return phase

    def trace(self, phase, event=None):
        with self.proxy.lock:
            return [dict(entry) for entry in self.proxy.observations
                    if entry.get("phase") == phase and (event is None or entry["event"] == event)]

    def prepare(self, case, worker, epoch, identity, statements):
        self.call_number += 1
        invocation = {"serial": self.call_number, "case": case["name"], "scope": case["scope"],
                      "principal": worker.config["principal"], "epoch": epoch, "id": identity,
                      "statements": statements}
        append_synced(self.inputs, {"event": "input_prepared", **invocation})
        identity = success(worker.call("prepare_request", epoch=epoch, id=identity, statements=statements))
        assert all(identity[key] == invocation[key] for key in ("epoch", "id", "principal"))
        invocation["request"] = identity
        append_synced(self.inputs, {"event": "invocation_prepared", **invocation})
        return invocation

    def ack(self, case, invocation, response):
        value = success(response)
        assert value["receipt"]["scope"] == invocation["scope"]
        assert value["receipt"]["request"] == invocation["request"]
        self.ack_number += 1
        append_synced(self.acks, {"ordinal": self.ack_number, "invocation": invocation,
                                 "receipt": value["receipt"], "encoded_result": value["result"]["encoded"],
                                 "observed_statements": value["result"]["statements"],
                                 "first_observed_via": "execute_success"})
        self.event(case, "fault_client_ack_recorded", ordinal=self.ack_number,
                   invocation_serial=invocation["serial"], receipt=value["receipt"],
                   encoded_result_sha256=hashlib.sha256(bytes(value["result"]["encoded"])).hexdigest())
        return value

    def execute(self, case, worker, epoch, identity, statements):
        invocation = self.prepare(case, worker, epoch, identity, statements)
        value = self.ack(case, invocation, worker.call("execute", epoch=epoch, id=identity,
                        statements=statements, directory=f"execute-{invocation['serial']}"))
        return invocation, value

    def blob(self, case, name, size):
        data = secrets.token_bytes(size)
        path = self.private / f"fault-input-{self.case_number}-{name}.private.bin"
        with path.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        digest = hashlib.sha256(data).hexdigest()
        append_synced(self.inputs, {"event": "payload_prepared", "case": case["name"],
                                   "scope": case["scope"], "name": name, "bytes": size,
                                   "sha256": digest, "source": "independent_os_random_bytes"})
        return {"type": "blob_file", "path": str(path), "offset": 0, "length": size, "sha256": digest}

    def snapshot(self, case, worker, label):
        observed = success(worker.call("store_get", key=case["head_key"]))
        self.event(case, "head_observed", label=label, etag=observed["etag"],
                   bytes=observed["bytes"], sha256=hashlib.sha256(bytes(observed["bytes"])).hexdigest(),
                   source="one_exact_get_body_and_etag")
        return observed

    def fixture(self, name, *, ignore_file_size_signal=False):
        self.case_number += 1
        directory = self.compute / f"fault-{self.case_number}"
        directory.mkdir(mode=0o700)
        case = {"name": name, "scope": {"deployment": 78, "tenant": 88, "database": 1000 + self.case_number,
                                        "incarnation": 1, "generation": 1},
                "directory": directory, "workers": []}
        self.event(case, "fault_case_started", fixture_quota_bytes=2 * 1024 * 1024, retention_entries=2)
        self.phase(case, "setup")
        owner = self.spawn(case, ignore_file_size_signal=ignore_file_size_signal)
        case["owner"] = owner
        head = success(owner.call("create", nonce=1))
        success(owner.call("activate", revision=head["revision"], nonce=2))
        self.execute(case, owner, 1, 1, [{"sql": "CREATE TABLE witness(id INTEGER PRIMARY KEY, payload BLOB NOT NULL, nonce INTEGER NOT NULL)"}])
        case["seed_blob"] = self.blob(case, "seed", 32 * 1024)
        _, seed = self.execute(case, owner, 1, 2, [{"sql": "INSERT INTO witness VALUES(1,?,random()) RETURNING id,nonce,length(payload)",
                                                  "parameters": [case["seed_blob"]]}])
        case["seed_rows"] = seed["result"]["statements"][0]["rows"]
        head = success(owner.call("status"))
        closed = success(owner.call("close_full", revision=head["revision"], nonce=3))
        assert closed["request_epoch"] == 2 and len(closed["windows"]) == 2
        case["head_key"] = success(owner.call("authority_keys"))["head"]
        case["before"] = self.snapshot(case, owner, "before_candidate")
        success(owner.call("session_open", directory="warm"))
        case["candidate_blob"] = self.blob(case, "candidate", 256 * 1024)
        candidate = [{"sql": "INSERT INTO witness VALUES(2,?,random()) RETURNING id,nonce,length(payload)",
                      "parameters": [case["candidate_blob"]]}]
        case["invocation"] = self.prepare(case, owner, 2, 1, candidate)
        return case

    def begin(self, case):
        invocation = case["invocation"]
        return case["owner"].begin("session_execute", epoch=2, id=1,
                                  statements=invocation["statements"], budget_ms=8000)

    def no_reply(self, case):
        owner = case["owner"]
        assert owner.pending is not None and owner.process.poll() is None
        ready = bool(select.select([owner.process.stdout], [], [], 0)[0])
        self.event(case, "pending_execute_pipe_observed", response_bytes_ready=ready,
                   pid=owner.process.pid, invocation_serial=case["invocation"]["serial"])
        assert not ready, "candidate replied before its selected publication boundary"

    def lose_compute(self, case):
        killed = [self.stop(case, entry, fault=True) for entry in list(case["workers"])]
        shutil.rmtree(case["directory"])
        assert not case["directory"].exists()
        self.event(case, "fault_scope_all_compute_lost", processes=killed, signal="SIGKILL",
                   complete_cache_directory_deleted=True)
        case["directory"].mkdir(mode=0o700)

    def outcome(self, case, worker, committed, receipt=None, *, expected=None, source="fresh_authoritative_lookup"):
        invocation = case["invocation"]
        value = success(worker.call("lookup_identity", identity=invocation["request"]))
        prior_ack = any(entry["invocation"]["serial"] == invocation["serial"]
                        for entry in (json.loads(line) for line in self.acks.read_text().splitlines()))
        append_synced(self.outcomes, {"case": case["name"], "invocation": invocation, "observed": value,
                                     "execute_ack": prior_ack, "source": source,
                                     "wall_time_ns": time.time_ns()})
        matches = value["state"] == ("committed" if committed else "unknown")
        if committed:
            matches = (matches and value["receipt"]["scope"] == invocation["scope"]
                       and value["receipt"]["request"] == invocation["request"]
                       and (receipt is None or receipt == value["receipt"]))
        if expected is not None:
            matches = matches and value == expected
        self.summary["outcome_mismatch_count"] += not matches
        self.event(case, "fault_outcome_audited", matches=matches, observed=value, execute_ack=prior_ack,
                   expected=expected, source=source)
        assert matches, value
        return value

    def before_loss_outcome(self, case, receipt=None):
        observer = self.spawn(case)
        self.phase(case, "preloss_resolution")
        return self.outcome(case, observer, True, receipt, source="post_head_lookup_not_execute_ack")

    def audit(self, case, worker, committed, *, receipt=None, session_open=False, expected_resolution=None):
        phase = self.phase(case, "cold_oracle")
        if not session_open:
            success(worker.call("session_open", directory="cold-oracle"))
        # The fsynced client ledger, not recovered data, supplies every ACK.
        entries = [json.loads(line) for line in self.acks.read_text().splitlines()]
        entries = [entry for entry in entries if entry["invocation"]["scope"] == case["scope"]]
        assert len(entries) >= 2
        for entry in entries:
            observed = success(worker.call("lookup_identity", identity=entry["invocation"]["request"]))
            matches = (observed["state"] == "committed" and observed["receipt"] == entry["receipt"]
                       and observed["encoded"] == entry["encoded_result"])
            self.summary["ack_mismatch_count"] += not matches
            self.event(case, "fault_ack_audited", ordinal=entry["ordinal"], matches=matches, observed=observed)
            assert matches, observed
            self.audited.add(entry["ordinal"])
        original = self.outcome(case, worker, committed, receipt, expected=expected_resolution)
        seed = case["seed_rows"][0]
        assert seed[0] == 1 and seed[2] == case["seed_blob"]["length"]
        expected = [[1, {"blob_bytes": case["seed_blob"]["length"], "sha256": case["seed_blob"]["sha256"]}, seed[1]]]
        if committed:
            decoded = success(worker.call("decode_result", encoded=original["encoded"]))
            row = decoded["statements"][0]["rows"][0]
            assert row[0] == 2 and row[2] == case["candidate_blob"]["length"]
            expected.append([2, {"blob_bytes": case["candidate_blob"]["length"], "sha256": case["candidate_blob"]["sha256"]}, row[1]])
        observed = success(worker.call("session_query", sql="SELECT id,payload,nonce FROM witness ORDER BY id", hash_blobs=True))
        rows = observed["statements"][0]["rows"]
        self.event(case, "fault_effects_audited", expected_rows=expected, observed_rows=rows, matches=rows == expected)
        assert rows == expected
        if committed:
            assert success(worker.call("lookup_identity", identity=case["invocation"]["request"])) == original
        assert not [entry for entry in self.trace(phase, "object_request")
                    if entry["method"] == "PUT" and entry["path"].endswith("/head")]

    def passed(self, case, **facts):
        self.event(case, "fault_case_passed", **facts)
        self.summary["case_results"].append({"case": case["name"], "scope": case["scope"], "status": "passed", **facts})
        self.summary["passed_case_count"] += 1
        for entry in list(case["workers"]):
            self.stop(case, entry)

    def pilot(self):
        case = self.fixture("dependency_upload_pilot")
        phase = self.phase(case, "candidate")
        self.ack(case, case["invocation"], case["owner"].finish(self.begin(case)))
        uploads = [entry for entry in self.trace(phase, "object_request")
                   if entry["method"] == "PUT" and "/objects/" in entry["path"]]
        inventory = success(case["owner"].call("authority_inventory"))
        by_key = {"/scap-test/" + obj["key"]: obj for obj in inventory["objects"]}
        plan = []
        for ordinal, request in enumerate(uploads, 1):
            obj = by_key[request["path"]]
            responses = [entry for entry in self.trace(phase, "object_response")
                         if entry["request_serial"] == request["request_serial"]]
            assert len(responses) == 1 and responses[0]["status"] == 200
            assert obj["sha256"] == request["request_sha256"]
            plan.append({"ordinal": ordinal, "role": obj["role"], "bytes": request["request_bytes"],
                         "pilot_key": obj["key"], "pilot_sha256": obj["sha256"],
                         "pilot_request_serial": request["request_serial"]})
        assert len(plan) >= 6 and {entry["role"] for entry in plan} >= {"chunk", "tree_node", "manifest", "index", "result"}
        self.audit(case, case["owner"], True)
        self.passed(case, observed_dependency_put_count=len(plan))
        return plan

    def cut(self, spec, stage, *, head=False):
        name = ("head_before_forward" if head else f"dependency_{spec['ordinal']:02}_{stage}")
        case = self.fixture(name)
        phase = self.phase(case, "cut")
        selector = {"method": "PUT", "stage": stage}
        if head:
            selector["key"] = case["head_key"]
        else:
            selector.update(immutable=True, occurrence=spec["ordinal"])
        if stage == "after_upstream_response":
            selector["expected_status"] = 200
        rule = self.proxy.arm("cut", **selector)
        self.begin(case)
        assert rule.arrived.wait(5), {"case": name, "selector": selector}
        assert rule.used == 1
        self.event(case, "exact_cut_reached", selector=selector, observation=rule.observation,
                   pilot_role=None if head else spec["role"])
        self.no_reply(case)
        self.lose_compute(case)
        rule.abort()
        assert rule.finished.wait(3), "cut request did not terminate without late forwarding"
        trace = self.trace(phase)
        request = rule.observation
        forwarded = [entry for entry in trace if entry["event"] == "object_forwarded"
                     and entry["request_serial"] == request["request_serial"]]
        assert bool(forwarded) == (stage == "after_upstream_response")
        assert not [entry for entry in trace if entry["event"] == "object_forwarded"
                    and entry["method"] == "PUT" and entry["path"].endswith("/head")]
        previous = [entry for entry in trace if entry["event"] == "object_response"
                    and entry["method"] == "PUT" and "/objects/" in entry["path"] and entry["status"] == 200]
        expected = spec["ordinal"] if stage == "after_upstream_response" else spec["ordinal"] - 1
        if head:
            expected = spec["dependency_count"]
        assert len(previous) == expected, {"expected": expected, "actual": len(previous)}
        # Every earlier completed upload was read back before the next upload.
        for entry in previous:
            if entry["request_serial"] == request["request_serial"]:
                continue
            assert any(observed["event"] == "object_response" and observed["method"] == "GET"
                       and observed["path"] == entry["path"] and observed["status"] == 200
                       and observed["response_sha256"] == entry["request_sha256"]
                       and trace.index(entry) < position
                       and observed["request_serial"] < request["request_serial"]
                       for position, observed in enumerate(trace)), entry
        reader = self.spawn(case)
        if not head:
            inspected = success(reader.call("inspect_object", bytes=list(rule.payload)))
            assert inspected["role"] == spec["role"]
            assert inspected["sha256"] == request["request_sha256"]
            assert inspected["bytes_len"] == request["request_bytes"]
            self.event(case, "cut_payload_officially_decoded", actual=inspected,
                       pilot_ordinal=spec["ordinal"], pilot_role=spec["role"])
        assert self.snapshot(case, reader, "after_cut") == case["before"]
        self.audit(case, reader, False)
        self.passed(case, cut_stage=stage, cut_observation=rule.observation,
                    immutable_backend_acceptances=len(previous), head_forwarded=False,
                    held_request_terminal="aborted_without_forward" if stage == "before_forward" else "suppressed_after_backend")

    def accepted_head(self, native_failure=False):
        case = self.fixture("native_file_size_failure_after_head" if native_failure else "accepted_head_then_sigkill",
                            ignore_file_size_signal=native_failure)
        if native_failure:
            wal = case["directory"] / "warm" / "database.sqlite-wal"
            wal_bytes = wal.stat().st_size if wal.exists() else 0
            assert wal_bytes == 0
            self.event(case, "native_baseline_wal_observed", exists=wal.exists(), bytes=wal_bytes)
        phase = self.phase(case, "accepted_head")
        rule = self.proxy.arm("hold" if native_failure else "cut", method="PUT", key=case["head_key"],
                              stage="after_upstream_response", expected_status=200)
        pending = self.begin(case)
        assert rule.arrived.wait(5) and rule.used == 1
        self.event(case, "accepted_head_response_held", observation=rule.observation)
        self.no_reply(case)
        receipt = None
        if native_failure:
            owner = case["owner"]
            original_limit = resource.prlimit(owner.process.pid, resource.RLIMIT_FSIZE)
            initial = owner.ready_resources["file_size_soft_limit_bytes"]
            assert original_limit[0] == (resource.RLIM_INFINITY if initial is None else initial)
            left_ms = 8000 - (time.monotonic_ns() - pending["started"]) / 1_000_000
            assert left_ms > 2000, "fault must be armed well before the request deadline"
            try:
                changed = resource.prlimit(owner.process.pid, resource.RLIMIT_FSIZE, (0, original_limit[1]))
                assert changed == original_limit
                assert resource.prlimit(owner.process.pid, resource.RLIMIT_FSIZE)[0] == 0
                self.event(case, "file_size_limit_armed_after_head", pid=owner.process.pid,
                           original_limit=list(original_limit), soft_limit_bytes=0, remaining_budget_ms=left_ms)
                rule.release.set()
                response = owner.finish(pending)
                remaining = 8000 - (time.monotonic_ns() - pending["started"]) / 1_000_000
                assert not response["ok"] and remaining > 1000, response
                details = response["error_details"]
                assert details["kind"] == "committed_but_unavailable", response
                assert response["resources"]["file_size_soft_limit_bytes"] == 0
                receipt = details["receipt"]
                append_synced(self.outcomes, {"case": case["name"], "invocation": case["invocation"],
                                             "source": "native_failure_response", "execute_ack": False,
                                             "response": response, "remaining_budget_ms": remaining})
                self.event(case, "native_failure_after_accepted_head", response=response, remaining_budget_ms=remaining)
            finally:
                if owner.process.poll() is None:
                    resource.prlimit(owner.process.pid, resource.RLIMIT_FSIZE, original_limit)
                    self.event(case, "file_size_limit_restored", pid=owner.process.pid,
                               restored_limit=list(original_limit))
                rule.release.set()
            failure(owner.call("session_execute", epoch=2, id=2, sql="INSERT INTO witness VALUES(3,x'01',3)"), "StaleSnapshot")
            failure(owner.call("session_query", sql="SELECT id FROM witness"), "StaleSnapshot")
        before_loss = self.before_loss_outcome(case, receipt)
        if not native_failure:
            self.no_reply(case)
        self.lose_compute(case)
        rule.abort()
        assert rule.finished.wait(3)
        reader = self.spawn(case)
        after = self.snapshot(case, reader, "accepted_head_after_compute_loss")
        assert after != case["before"]
        assert hashlib.sha256(bytes(after["bytes"])).hexdigest() == rule.observation["request_sha256"]
        assert len([entry for entry in self.trace(phase, "object_response")
                    if entry["method"] == "PUT" and entry["path"].endswith("/head") and entry["status"] == 200]) == 1
        self.audit(case, reader, True, receipt=receipt, expected_resolution=before_loss)
        self.passed(case, accepted_head=rule.observation, native_failure=native_failure,
                    native_failure_mechanism="Linux RLIMIT_FSIZE; exact errno not traced" if native_failure else None,
                    execute_ack=False)

    def checkpoint_failure(self):
        case = self.fixture("native_checkpoint_reader_blocks_truncate")
        owner = case["owner"]
        database = case["directory"] / "warm" / "database.sqlite"
        wal = Path(str(database) + "-wal")
        assert not wal.exists() or wal.stat().st_size == 0
        program = """import json, os, sqlite3, sys
connection = sqlite3.connect('file:' + sys.argv[1] + '?mode=ro', uri=True, isolation_level=None, timeout=0)
connection.execute('BEGIN DEFERRED')
def rows():
    return [list(row) for row in connection.execute('SELECT id,nonce,length(payload) FROM witness ORDER BY id')]
print(json.dumps({'ready': True, 'pid': os.getpid(), 'rows': rows()}), flush=True)
for command in sys.stdin:
    assert command.strip() == 'observe'
    print(json.dumps({'pid': os.getpid(), 'rows': rows()}), flush=True)
"""
        with (self.private / f"reader-{self.case_number}.private.log").open("ab") as log:
            helper = subprocess.Popen([sys.executable, "-u", "-c", program, str(database)],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log,
                                      text=True, bufsize=1)
        self.children.append(helper)
        assert select.select([helper.stdout], [], [], 5)[0]
        initial = json.loads(helper.stdout.readline())
        assert initial["ready"] and initial["pid"] == helper.pid and initial["rows"] == case["seed_rows"]
        identity = process_identity(helper)
        self.event(case, "native_old_read_transaction_started", process=identity, observed=initial,
                   connection_mode="read_only", sqlite_version=sqlite3.sqlite_version)
        phase = self.phase(case, "checkpoint_failure")
        pending = self.begin(case)
        response = owner.finish(pending)
        remaining = 8000 - (time.monotonic_ns() - pending["started"]) / 1_000_000
        assert not response["ok"] and remaining > 1000, response
        assert response["error_details"]["kind"] == "committed_but_unavailable", response
        receipt = response["error_details"]["receipt"]
        heads = [entry for entry in self.trace(phase, "object_response")
                 if entry["method"] == "PUT" and entry["path"].endswith("/head") and entry["status"] == 200]
        assert len(heads) == 1 and wal.stat().st_size > 0
        append_synced(self.outcomes, {"case": case["name"], "invocation": case["invocation"],
                                     "source": "native_failure_response", "execute_ack": False,
                                     "response": response, "remaining_budget_ms": remaining})
        before_loss = self.before_loss_outcome(case, receipt)
        decoded = success(owner.call("decode_result", encoded=before_loss["encoded"]))
        expected = case["seed_rows"] + decoded["statements"][0]["rows"]
        fresh = sqlite3.connect("file:" + str(database) + "?mode=ro", uri=True, timeout=0)
        try:
            visible = [list(row) for row in fresh.execute("SELECT id,nonce,length(payload) FROM witness ORDER BY id")]
        finally:
            fresh.close()
        helper.stdin.write("observe\n")
        helper.stdin.flush()
        assert select.select([helper.stdout], [], [], 5)[0]
        retained = json.loads(helper.stdout.readline())
        assert retained["pid"] == helper.pid and retained["rows"] == case["seed_rows"]
        assert visible == expected
        self.event(case, "native_published_wal_with_retained_old_reader", old_reader=retained,
                   fresh_local_rows=visible, expected_local_rows=expected, wal_bytes=wal.stat().st_size,
                   remaining_budget_ms=remaining, native_failure=response)
        failure(owner.call("session_query", sql="SELECT id FROM witness"), "StaleSnapshot")
        failure(owner.call("session_execute", epoch=2, id=2, sql="INSERT INTO witness VALUES(3,x'01',3)"), "StaleSnapshot")
        helper.kill()
        code, usage = wait_child(helper, 5)
        assert code == -signal.SIGKILL
        helper.stdin.close()
        helper.stdout.close()
        self.children.remove(helper)
        self.event(case, "native_old_reader_killed", process=identity, wait_status=code, kernel_usage=usage)
        self.lose_compute(case)
        reader = self.spawn(case)
        self.audit(case, reader, True, receipt=receipt, expected_resolution=before_loss)
        self.passed(case, backend_head_status=200, native_publication_visible=True, wal_retained=True,
                    old_reader_retained_original_snapshot=True, execute_ack=False,
                    native_failure_mechanism="TRUNCATE checkpoint blocked by an independent real read transaction")

    def delete_fixture_object(self, case, key):
        expected = "/".join(case["head_key"].split("/")[:-1]) + "/inc/"
        assert key.startswith(expected) and "/objects/" in key
        command = ["curl", "--silent", "--show-error", "--max-time", "3", "--noproxy", "*",
                   "--aws-sigv4", "aws:amz:us-east-1:s3", "--config", "-", "-X", "DELETE",
                   "--output", os.devnull, "--write-out", "%{http_code}", self.backend.endpoint + "/scap-test/" + key]
        result = subprocess.run(command, input=f'user = "{self.backend.access}:{self.backend.secret}"\n',
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
        assert result.returncode == 0 and result.stdout in ("200", "204"), {"code": result.returncode, "status": result.stdout}
        self.event(case, "trusted_fixture_object_deleted", key=key, http_status=int(result.stdout),
                   response_origin="backend", trusted_admin_operation=True)

    def dependency_failure(self, role, damage):
        case = self.fixture(f"cold_{role}_{damage}")
        owner = case["owner"]
        inventory = success(owner.call("authority_inventory"))
        candidates = [obj for obj in inventory["objects"] if obj["role"] == role
                      and (role not in ("index", "result") or obj["epoch"] == 1)]
        assert candidates, {"role": role, "inventory": inventory}
        target = candidates[0]
        original = success(owner.call("store_get", key=target["key"]))
        assert hashlib.sha256(bytes(original["bytes"])).hexdigest() == target["sha256"]
        head = success(owner.call("status"))
        taken = success(owner.call("takeover", revision=head["revision"], nonce=4))
        before = self.snapshot(case, owner, "recovering_before_damage")
        if damage == "missing":
            self.delete_fixture_object(case, target["key"])
            failure(owner.call("store_get", key=target["key"]), "Missing")
            replacement_etag = None
        else:
            replacement = bytes(original["bytes"])
            replacement = bytes([replacement[0] ^ 0x80]) + replacement[1:]
            changed = success(owner.call("store_put", key=target["key"], bytes=list(replacement), etag=original["etag"]))
            replacement_etag = changed["etag"]
            assert success(owner.call("store_get", key=target["key"]))["bytes"] == list(replacement)
            self.event(case, "trusted_fixture_object_corrupted", target=target,
                       original_sha256=target["sha256"], replacement_sha256=hashlib.sha256(replacement).hexdigest(),
                       condition_etag=original["etag"], replacement_etag=replacement_etag)
        logical_owner = owner.config["worker"]
        self.lose_compute(case)
        reader = self.spawn(case, logical_worker=logical_owner)
        phase = self.phase(case, "cold_rejection")
        response = reader.call("activate_session", revision=taken["revision"], nonce=5, directory="failed-cold")
        failure(response, "Store(Missing)" if damage == "missing" else "Format(Corrupt)")
        bad_gets = [entry for entry in self.trace(phase, "object_response")
                    if entry["method"] == "GET" and entry["path"] == "/scap-test/" + target["key"]]
        assert bad_gets and bad_gets[-1]["status"] == (404 if damage == "missing" else 200)
        if damage == "corrupt":
            assert bad_gets[-1]["response_sha256"] == hashlib.sha256(replacement).hexdigest()
        assert not (case["directory"] / "failed-cold").exists()
        assert self.snapshot(case, reader, "after_rejected_activation") == before
        assert not [entry for entry in self.trace(phase, "object_request")
                    if entry["method"] == "PUT" and entry["path"].endswith("/head")]
        self.event(case, "cold_activation_refused", target=target, damage=damage, response=response,
                   head_unchanged=True, failed_cache_removed=True)
        values = {"key": target["key"], "bytes": original["bytes"]}
        if replacement_etag is not None:
            values["etag"] = replacement_etag
        success(reader.call("store_put", **values))
        assert success(reader.call("store_get", key=target["key"]))["bytes"] == original["bytes"]
        self.event(case, "trusted_fixture_original_object_restored", target=target)
        # A known-corrupt Database handle must not publish even after fixture
        # repair. A fresh process performs the successful full cold activation.
        self.stop(case, reader)
        recovered = self.spawn(case, logical_worker=logical_owner)
        success(recovered.call("activate_session", revision=taken["revision"], nonce=6, directory="repaired-cold"))
        self.audit(case, recovered, False, session_open=True)
        self.summary["backend_missing_cases" if damage == "missing" else "backend_corrupt_cases"] += 1
        self.passed(case, dependency=target, damage=damage, cold_rejection=response["error"],
                    retained_closed_epoch=1 if role in ("index", "result") else None)

    def recovery_head_change(self):
        case = self.fixture("head_changes_during_cold_activation")
        owner = case["owner"]
        inventory = success(owner.call("authority_inventory"))
        target = next(obj for obj in inventory["objects"] if obj["role"] == "chunk")
        head = success(owner.call("status"))
        taken = success(owner.call("takeover", revision=head["revision"], nonce=4))
        before = self.snapshot(case, owner, "recovery_selected_head")
        other = self.spawn(case)
        self.phase(case, "recovery_blocked")
        rule = self.proxy.arm("hold", method="GET", key=target["key"])
        pending = owner.begin("activate_session", revision=taken["revision"], nonce=5, directory="stale-recovery")
        assert rule.arrived.wait(5) and rule.used == 1
        self.event(case, "cold_recovery_dependency_held", target=target, observation=rule.observation)
        self.phase(case, "replacement_head")
        changed = success(other.call("takeover", revision=taken["revision"], nonce=6))
        after = self.snapshot(case, other, "replacement_during_recovery")
        assert after["bytes"] != before["bytes"] and after["etag"] != before["etag"]
        phase = self.phase(case, "stale_activation_resumes")
        rule.release.set()
        response = owner.finish(pending)
        failure(response, "Conflict")
        assert not (case["directory"] / "stale-recovery").exists()
        assert self.snapshot(case, other, "after_stale_activation_refused") == after
        assert not [entry for entry in self.trace(phase, "object_request")
                    if entry["method"] == "PUT" and entry["path"].endswith("/head")]
        self.stop(case, owner)
        success(other.call("activate_session", revision=changed["revision"], nonce=7, directory="current-recovery"))
        self.audit(case, other, False, session_open=True)
        self.passed(case, held_dependency=target, stale_activation=response["error"],
                    stale_activation_head_puts=0, failed_cache_removed=True,
                    selected_head_etag=before["etag"], replacement_head_etag=after["etag"])

    def run(self):
        self.proxy.capture = True
        try:
            plan = self.pilot()
            planned = ([{"case": f"dependency_{entry['ordinal']:02}_{stage}", "ordinal": entry["ordinal"],
                         "pilot_role": entry["role"], "stage": stage}
                        for entry in plan for stage in ("before_forward", "after_upstream_response")]
                       + [{"case": "head_before_forward"}, {"case": "accepted_head_then_sigkill"},
                          {"case": "native_file_size_failure_after_head"},
                          {"case": "native_checkpoint_reader_blocks_truncate"}]
                       + [{"case": f"cold_{role}_{damage}"} for role in ("chunk", "tree_node", "manifest", "index", "result")
                          for damage in ("missing", "corrupt")]
                       + [{"case": "head_changes_during_cold_activation"}])
            self.summary["planned_case_count"] = 1 + len(planned)
            path = self.evidence / "fault-plan.json"
            with path.open("x", encoding="utf-8") as stream:
                json.dump({"schema": 1, "observed_uploads": plan, "cases": planned,
                           "pilot_is_additional_case": True}, stream, indent=2, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            for entry in plan:
                for stage in ("before_forward", "after_upstream_response"):
                    self.cut(entry, stage)
            self.cut({"ordinal": len(plan) + 1, "dependency_count": len(plan)}, "before_forward", head=True)
            self.accepted_head()
            self.accepted_head(native_failure=True)
            self.checkpoint_failure()
            for role in ("chunk", "tree_node", "manifest", "index", "result"):
                for damage in ("missing", "corrupt"):
                    self.dependency_failure(role, damage)
            self.recovery_head_change()
            acknowledged = [json.loads(line) for line in self.acks.read_text().splitlines()]
            assert [entry["ordinal"] for entry in acknowledged] == list(range(1, self.ack_number + 1))
            assert self.audited == {entry["ordinal"] for entry in acknowledged}
            self.summary["ack_audited_count"] = len(self.audited)
            assert self.summary["passed_case_count"] == self.summary["planned_case_count"]
            assert not self.proxy.errors, self.proxy.errors
            self.summary["status"] = "passed"
        except BaseException as error:
            self.summary.update(status="failed", error=repr(error))
            raise
        finally:
            cleanup_errors = []
            for child in self.children:
                try:
                    if child.poll() is None:
                        child.kill()
                    code, usage = wait_child(child, 5)
                    record(self.evidence, "native_reader_cleanup", pid=child.pid, wait_status=code, kernel_usage=usage)
                except BaseException as error:
                    cleanup_errors.append({"step": "reader_process", "pid": child.pid, "error": repr(error)})
                for name, stream in (("stdin", child.stdin), ("stdout", child.stdout)):
                    try:
                        if not stream.closed:
                            stream.close()
                    except BaseException as error:
                        cleanup_errors.append({"step": "reader_" + name, "pid": child.pid, "error": repr(error)})
            self.proxy.capture = False
            self.summary["ack_audited_count"] = len(self.audited)
            self.summary["ack_recorded_count"] = self.ack_number
            self.summary["ledger_sha256"] = {}
            for path in (self.inputs, self.acks, self.outcomes, self.cases):
                try:
                    with path.open("rb") as stream:
                        self.summary["ledger_sha256"][path.name] = hashlib.file_digest(stream, "sha256").hexdigest()
                except BaseException as error:
                    cleanup_errors.append({"step": "ledger_hash", "path": path.name, "error": repr(error)})
            self.summary["cleanup_errors"] = cleanup_errors
            if cleanup_errors:
                self.summary["status"] = "failed"
                self.summary.setdefault("error", "fault fixture cleanup failed")
        assert self.summary["status"] == "passed", self.summary.get("error")
        return self.summary


def run(arguments):
    assert "LLVM_PROFILE_FILE" not in os.environ
    evidence = arguments.evidence.resolve()
    evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    build = None
    if arguments.build_record:
        from build import capture_receipt
        build = capture_receipt(arguments.build_record, arguments.worker, evidence)
    private = Path(tempfile.mkdtemp(prefix="scap-object-network-private-"))
    compute = private / "compute"
    compute.mkdir(mode=0o700)
    backend = Backend(arguments.weed.resolve(), private / "backend")
    proxy = Proxy(backend.port, evidence)
    workers = []
    completed = []
    scope = {"deployment": 77, "tenant": 88, "database": 99, "incarnation": 1, "generation": 1}
    config = {"endpoint": proxy.endpoint, "region": "us-east-1", "bucket": "scap-test",
              "access_key": backend.access, "secret_key": backend.secret, "scope": scope,
              "worker": 1, "principal": 17, "cache_root": str(compute),
              "fixture_limits": {"quota_bytes": 256 * 1024, "retention_entries": 16,
                                 "retention_result_bytes": 128 * 1024 * 1024}}
    serial = 0
    ledger = evidence / "ack-ledger.jsonl"
    ledger.touch(mode=0o600, exist_ok=False)
    ledger_lock = threading.Lock()
    acknowledgements = 0
    def worker(number, **changes):
        entry = Worker(arguments.worker.resolve(), {**config, "worker": number, **changes}, private, number, evidence)
        workers.append(entry)
        return entry
    def execute(entry, identity, sql, **changes):
        nonlocal serial, acknowledgements
        serial += 1
        response = entry.call("execute", epoch=1, id=identity, sql=sql, directory=f"execute-{serial}", **changes)
        if response["ok"]:
            value = response["value"]
            invocation = {"scope": entry.config["scope"], "principal": entry.config["principal"],
                          "epoch": 1, "id": identity}
            assert value["receipt"]["scope"] == invocation["scope"]
            assert all(value["receipt"]["request"][field] == invocation[field] for field in ("principal", "epoch", "id"))
            with ledger_lock:
                acknowledgements += 1
                ack = {"ordinal": acknowledgements, "invocation": invocation, "scope": invocation["scope"],
                       "request": value["receipt"]["request"], "sql": sql, "receipt": value["receipt"],
                       "encoded_result": value["result"]["encoded"], "observed_result": value["result"]["statements"]}
                with ledger.open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(ack, sort_keys=True) + "\n")
                    stream.flush()
                    os.fsync(stream.fileno())
                record(evidence, "client_ack_recorded", ordinal=ack["ordinal"], request=ack["request"],
                       result_sha256=hashlib.sha256(bytes(ack["encoded_result"])).hexdigest())
        return response
    def query(entry, sql, **changes):
        nonlocal serial
        serial += 1
        return entry.call("query", sql=sql, directory=f"query-{serial}", **changes)
    def done(name):
        completed.append(name)
        record(evidence, "contract_passed", name=name)
    summary = {"schema": 1, "aws_endpoint_gate": "NOT_RUN", "production_slo_passed": False,
               "unit_coverage_contribution": False, "backend_version": VERSION,
               "diagnostic": arguments.diagnostic, "build_record_verified": build is not None,
               "build_input_sha256": build["input_sha256"] if build else None,
               "backend_binary_sha256": hashlib.file_digest(arguments.weed.open("rb"), "sha256").hexdigest(),
               "worker_binary_sha256": hashlib.file_digest(arguments.worker.open("rb"), "sha256").hexdigest(),
               "private_fixture": str(private), "completed_contracts": completed, "ack_audit_complete": False}
    try:
        record(evidence, "run_started", backend=VERSION, aws_endpoint_gate="NOT_RUN")
        backend.start()
        backend_identity = hashlib.sha256(str(backend.directory.resolve()).encode()).hexdigest()
        record(evidence, "backend_started", processes=backend.identities(), directory_identity=backend_identity)
        first, second = worker(1), worker(2)
        wrong = worker(90, secret_key="intentionally-wrong-fixture-secret")

        original = success(first.call("store_put", key="contracts/immutable", bytes=[1, 2, 3]))
        failure(second.call("store_put", key="contracts/immutable", bytes=[4, 5, 6]), "Conflict")
        fetched = success(first.call("store_get", key="contracts/immutable"))
        assert fetched == {"bytes": [1, 2, 3], "etag": original["etag"]}
        failure(wrong.call("store_get", key="contracts/immutable"), "Unknown")
        failure(first.call("store_put", key="contracts/immutable", bytes=[9], etag='"wrong-version"'), "Conflict")
        for status, expected in [(409, "Unknown"), (412, "Conflict")]:
            rule = proxy.arm(f"inject{status}", "/contracts/immutable")
            failure(first.call("store_put", key="contracts/immutable", bytes=[7], etag=original["etag"]), expected)
            assert rule.used == 1
        assert success(first.call("store_get", key="contracts/immutable"))["bytes"] == [1, 2, 3]
        done(CONTRACTS[0])

        for case in range(8):
            key = f"contracts/cas-{case}"
            token = success(first.call("store_put", key=key, bytes=[0]))["etag"]
            rule = proxy.arm("pair", "/" + key)
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                calls = [pool.submit(entry.call, "store_put", key=key, bytes=[index], etag=token)
                         for index, entry in [(1, first), (2, second)]]
                results = [call.result(timeout=12) for call in calls]
            assert rule.used == 2
            winners = [index + 1 for index, response in enumerate(results) if response["ok"]]
            assert len(winners) == 1, {"case": case, "results": results}
            for response in results:
                if not response["ok"]:
                    failure(response, "Conflict", "Unknown")
            assert success(first.call("store_get", key=key))["bytes"] == winners
            record(evidence, "cas_race_checked", case=case, results=results)
        done(CONTRACTS[1])

        created = success(first.call("create", nonce=1))
        success(first.call("activate", revision=created["revision"], nonce=2))
        success(execute(first, 1, "CREATE TABLE items(id INTEGER PRIMARY KEY, value INTEGER NOT NULL)"))
        random_sql = "INSERT INTO items(value) VALUES(random()) RETURNING id, value"
        ack = success(execute(first, 2, random_sql))
        original_rows = ack["result"]["statements"][0]["rows"]
        killed = [entry.kill(verify=True) for entry in list(workers)]
        workers.clear()
        shutil.rmtree(compute)
        compute.mkdir(mode=0o700)
        record(evidence, "all_compute_and_local_cache_lost", processes=killed,
               process_signal="SIGKILL", local_cache_deleted=True)
        first, second = worker(3), worker(4)
        resolved = success(first.call("lookup", epoch=1, id=2, sql=random_sql))
        assert resolved["state"] == "committed" and resolved["encoded"] == ack["result"]["encoded"]
        assert resolved["receipt"] == ack["receipt"]
        recovered = success(query(first, "SELECT id, value FROM items ORDER BY id"))
        assert recovered["statements"][0]["rows"] == original_rows
        current = success(first.call("status"))
        taken = success(first.call("takeover", revision=current["revision"], nonce=3))
        success(first.call("activate", revision=taken["revision"], nonce=4))
        done(CONTRACTS[2])

        lost_sql = "INSERT INTO items(value) VALUES(random()) RETURNING id, value"
        rule = proxy.arm("drop", "/head")
        failure(execute(first, 3, lost_sql), "Store(Unknown)", "Unknown")
        assert rule.used == 1
        resolved_lost = success(second.call("lookup", epoch=1, id=3, sql=lost_sql))
        assert resolved_lost["state"] == "committed"
        # A repeat of the same identity must return the stored original result.
        replay = success(execute(first, 3, lost_sql))
        assert replay["result"]["encoded"] == resolved_lost["encoded"]
        assert replay["receipt"] == resolved_lost["receipt"]
        assert success(query(second, "SELECT count(*) FROM items"))["statements"][0]["rows"] == [[2]]
        done(CONTRACTS[3])

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            rule = proxy.arm("hold", "/head")
            pending = pool.submit(execute, first, 4, "INSERT INTO items(value) VALUES(400) RETURNING id")
            assert rule.arrived.wait(5)
            current = success(second.call("status"))
            taken = success(second.call("takeover", revision=current["revision"], nonce=5))
            success(second.call("activate", revision=taken["revision"], nonce=6))
            rule.release.set()
            failure(pending.result(timeout=8), "Conflict")
        assert success(query(second, "SELECT count(*) FROM items"))["statements"][0]["rows"] == [[2]]
        failure(execute(first, 5, "INSERT INTO items(value) VALUES(500)"), "Fenced")
        done(CONTRACTS[4])

        cancelled_sql = "INSERT INTO items(value) VALUES(600) RETURNING id"
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            rule = proxy.arm("hold", "/head")
            pending = pool.submit(execute, second, 6, cancelled_sql)
            assert rule.arrived.wait(5)
            cancelled = success(first.call("cancel", epoch=1, id=6, sql=cancelled_sql))
            assert cancelled["state"] == "cancelled"
            rule.release.set()
            failure(pending.result(timeout=8), "Conflict")
        assert success(second.call("lookup", epoch=1, id=6, sql=cancelled_sql))["state"] == "cancelled"
        failure(execute(second, 6, cancelled_sql), "Closed")
        commit_sql = "INSERT INTO items(value) VALUES(700) RETURNING id"
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            rule = proxy.arm("hold", "/head")
            pending = pool.submit(first.call, "cancel", epoch=1, id=7, sql=commit_sql)
            assert rule.arrived.wait(5)
            committed = success(execute(second, 7, commit_sql))
            rule.release.set()
            failure(pending.result(timeout=8), "Conflict")
        after = success(first.call("cancel", epoch=1, id=7, sql=commit_sql))
        assert after["state"] == "committed" and after["encoded"] == committed["result"]["encoded"]
        assert success(query(first, "SELECT count(*) FROM items"))["statements"][0]["rows"] == [[3]]
        done(CONTRACTS[5])

        lost_cancel_sql = "INSERT INTO items(value) VALUES(900) RETURNING id"
        rule = proxy.arm("drop", "/head")
        failure(first.call("cancel", epoch=1, id=9, sql=lost_cancel_sql), "Store(Unknown)")
        assert rule.used == 1
        lost_cancel_resolution = success(second.call("lookup", epoch=1, id=9, sql=lost_cancel_sql))
        assert lost_cancel_resolution["state"] == "cancelled"
        failure(execute(second, 9, lost_cancel_sql), "Closed")
        record(evidence, "lost_cancel_resolved", request_id=9, resolution=lost_cancel_resolution)
        done(CONTRACTS[6])

        keys = success(first.call("authority_keys"))
        original_head = success(first.call("store_get", key=keys["head"]))
        original_dependency = success(first.call("store_get", key=keys["data_root"]))
        corrupted = success(first.call("store_put", key=keys["data_root"], bytes=[0, 1, 2], etag=original_dependency["etag"]))
        record(evidence, "trusted_fixture_dependency_corrupted", key=keys["data_root"],
               original_sha256=hashlib.sha256(bytes(original_dependency["bytes"])).hexdigest())
        failure(query(first, "SELECT id, value FROM items ORDER BY id"), "Format(Corrupt)")
        failure(execute(second, 10, "INSERT INTO items(value) VALUES(1000)"), "Format(Corrupt)")
        assert success(first.call("store_get", key=keys["head"])) == original_head
        success(first.call("store_put", key=keys["data_root"], bytes=original_dependency["bytes"], etag=corrupted["etag"]))
        assert success(first.call("store_get", key=keys["data_root"]))["bytes"] == original_dependency["bytes"]
        assert success(query(first, "SELECT count(*) FROM items"))["statements"][0]["rows"] == [[3]]
        record(evidence, "corrupt_dependency_rejected_and_restored", head_unchanged=True)
        done(CONTRACTS[7])

        rule = proxy.arm("blackhole")
        failure(query(first, "SELECT count(*) FROM items", budget_ms=200), "Store(Unknown)")
        failure(execute(second, 8, "INSERT INTO items(value) VALUES(800)", budget_ms=200), "Store(Unknown)")
        assert rule.used == 2
        proxy.clear()
        assert success(query(first, "SELECT count(*) FROM items"))["statements"][0]["rows"] == [[3]]
        done(CONTRACTS[8])

        killed = backend.stop(verify=True)
        record(evidence, "backend_processes_killed", processes=killed, signal="SIGKILL", directory_identity=backend_identity)
        backend.start()
        record(evidence, "backend_restarted", processes=backend.identities(), directory_identity=backend_identity)

        # The independent client ledger is the denominator. Do not build the
        # expected set from the final database or silently omit DDL/late ACKs.
        acknowledged = [json.loads(line) for line in ledger.read_text().splitlines()]
        assert len(acknowledged) == acknowledgements and acknowledgements > 0
        assert [entry["ordinal"] for entry in acknowledged] == list(range(1, acknowledgements + 1))
        mismatches = []
        for entry in acknowledged:
            identity = entry["request"]
            invocation = entry["invocation"]
            assert invocation["scope"] == first.config["scope"] and invocation["principal"] == first.config["principal"]
            observed = first.call("lookup", epoch=invocation["epoch"], id=invocation["id"], sql=entry["sql"])
            observed_value = observed.get("value", {})
            matches = (observed["ok"] and observed_value.get("state") == "committed"
                       and observed_value.get("receipt") == entry["receipt"]
                       and observed_value.get("encoded") == entry["encoded_result"])
            record(evidence, "ack_audited", ordinal=entry["ordinal"], request=identity, matches=matches,
                   observed=observed)
            if not matches:
                mismatches.append({"ordinal": entry["ordinal"], "request": identity, "observed": observed})
        summary["ack_audited_count"] = len(acknowledged)
        summary["ack_mismatch_count"] = len(mismatches)
        summary["ack_mismatches"] = mismatches
        summary["ack_ledger_sha256"] = hashlib.file_digest(ledger.open("rb"), "sha256").hexdigest()
        summary["ack_audit_complete"] = True
        assert not mismatches, mismatches

        # Original random values come from client-observed RETURNING rows.
        # The third committed insert has independently known constant 700.
        by_id = {entry["request"]["id"]: entry for entry in acknowledged}
        assert set(by_id) == {1, 2, 3, 7}
        expected_rows = (by_id[2]["observed_result"][0]["rows"] + by_id[3]["observed_result"][0]["rows"]
                         + [[by_id[7]["observed_result"][0]["rows"][0][0], 700]])
        expected_rows.sort(key=lambda row: row[0])
        observed_rows = success(query(first, "SELECT id, value FROM items ORDER BY id"))["statements"][0]["rows"]
        record(evidence, "acknowledged_effects_audited", expected_rows=expected_rows, observed_rows=observed_rows)
        assert observed_rows == expected_rows
        summary["acknowledged_effect_rows"] = len(expected_rows)
        assert success(first.call("lookup", epoch=1, id=9, sql=lost_cancel_sql)) == lost_cancel_resolution
        done(CONTRACTS[9])
        assert completed == CONTRACTS
        faults = FaultSuite(arguments, evidence, private, compute, backend, proxy, workers, config)
        summary["fault_contracts"] = faults.summary
        faults.run()
        for name in FAULT_CONTRACTS:
            done(name)
        assert completed == CONTRACTS + FAULT_CONTRACTS
        from schema_contract import CONTRACT as SCHEMA_CONTRACT, SchemaSuite
        schema = SchemaSuite(sys.modules[__name__], arguments, evidence, private, compute,
                             proxy, workers, config)
        summary["schema_contracts"] = schema.summary
        schema.run()
        done(SCHEMA_CONTRACT)
        assert completed == CONTRACTS + FAULT_CONTRACTS + [SCHEMA_CONTRACT]
        assert not proxy.errors, proxy.errors
        summary["status"] = "passed"
    except BaseException as error:
        summary["status"] = "failed"
        summary["error"] = repr(error)
        record(evidence, "verification_failed", error=repr(error), completed_contracts=completed)
        raise
    finally:
        cleanup_errors = []
        proxy.clear()
        for entry in workers:
            try:
                entry.kill()
            except BaseException as error:
                cleanup_errors.append({"step": "worker", "pid": entry.process.pid, "error": repr(error)})
        for name, operation in (("proxy", proxy.close), ("backend", backend.stop)):
            try:
                operation()
            except BaseException as error:
                cleanup_errors.append({"step": name, "error": repr(error)})
        summary["object_metrics"] = proxy.metrics()
        summary["proxy_errors"] = proxy.errors
        summary["cleanup_errors"] = cleanup_errors
        if proxy.errors or cleanup_errors:
            summary["status"] = "failed"
        if summary["status"] == "passed":
            record(evidence, "verification_passed", contracts=len(completed))
        (evidence / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    assert summary["status"] == "passed", summary.get("error", "transport fixture failure")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker", type=Path, required=True)
    parser.add_argument("--weed", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    build_mode = parser.add_mutually_exclusive_group(required=True)
    build_mode.add_argument("--build-record", type=Path)
    build_mode.add_argument("--diagnostic", action="store_true")
    run(parser.parse_args())
