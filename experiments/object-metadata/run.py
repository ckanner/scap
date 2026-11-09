#!/usr/bin/env python3
"""Finite metadata-only contracts on real daemon, SDK, TCP and signed S3."""
from __future__ import annotations

import argparse
import http.client
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

from fixture_spec import COMMANDS, DEADLINES, FAILURES, LIMITS, NAMES, PLAN, PRINCIPALS, SCOPES, WORKERS, head_path
from proxy import Hub, Trace, cleanup_event, error_name, payload, sha

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def load(name, path):
    specification = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


build = load("metadata_service_build", ROOT / "experiments/object-service/build.py")
network = load("metadata_network_backend", ROOT / "experiments/object-network/run.py")


def encoded(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()


def binary_identity(tool):
    return {key: tool[key] for key in ("path", "sha256")}


def persist_bytes(path, raw):
    with path.open("xb") as stream:
        stream.write(raw)
        build.sync(stream)
    path.chmod(0o600)


def configuration(port, worker, cache, endpoint, tokens):
    body = LIMITS["http_request_bytes"]
    admission = {"active_database_actors": 20, "active_database_actors_per_tenant": 16,
        "actor_idle_timeout_ms": DEADLINES["actor_idle_ms"], "control_workers": 1,
        "queued_total": 64, "queued_per_tenant": 32, "queued_per_database": 8, "reserved_controls": 2,
        "data_intake": 8, "control_intake": 4, "recovery_intake": 2, "max_body_bytes": body,
        "timeout_ms": DEADLINES["ordinary_ms"], "recovery_timeout_ms": DEADLINES["recovery_ms"]}
    for name, count, tenant in (("data", 8, 4), ("control", 4, 1), ("recovery", 2, 1)):
        admission[name + "_profile"] = {"version": 1, "requests_per_tenant": tenant,
            "body_bytes": count * body, "body_bytes_per_tenant": tenant * body}
    return {"version": 1, "listen": f"127.0.0.1:{port}", "worker_instance": WORKERS[worker],
        "cache_directory": str(cache), "admission": admission,
        "cache": {"pages_per_actor": 65536, "parallel_recoveries": 1},
        "execution": {"result_memory_bytes": 134217728},
        "credentials": [{"sha256": sha(tokens[role].encode()), "deployment": "1", "tenant": "7",
            "principal": principal, "provision": role == "writer"} for role, principal in PRINCIPALS.items()],
        "s3": {"endpoint": endpoint, "region": "us-east-1", "bucket": "scap-test",
            "access_key_env": "SCAP_TEST_ACCESS", "secret_key_env": "SCAP_TEST_SECRET",
            "session_token_env": None, "allow_http": True, "timeout_ms": DEADLINES["s3_ms"]}}


class Service:
    def __init__(self, suite, worker):
        self.suite, self.worker, self.port = suite, worker, suite.ports[worker]
        self.cache = suite.private / ("cache-" + worker)
        self.process, self.stopped = None, False
        self.log = suite.evidence / ("service-" + worker + ".log")

    def start(self):
        self.cache.mkdir(mode=0o700)
        value = configuration(self.port, self.worker, self.cache,
                              self.suite.s3_endpoints[self.worker], self.suite.tokens)
        path = self.suite.private / ("service-" + self.worker + ".private.json")
        build.save_receipt(path, value)
        path.chmod(0o600)
        persist_bytes(self.suite.evidence / ("service-" + self.worker + ".json"), path.read_bytes())
        executable = self.suite.args.server.resolve()
        self.binary = {"path": str(executable), "sha256": build.digest(executable)}
        with self.log.open("xb") as output:
            spawn_requested_ns = time.monotonic_ns()
            self.process = subprocess.Popen([str(executable), str(path)], cwd=ROOT, stdout=output, stderr=output,
                env=dict(os.environ, SCAP_TEST_ACCESS=self.suite.backend.access, SCAP_TEST_SECRET=self.suite.backend.secret))
        self.identity = network.process_identity(self.process)
        self.suite.events.emit("service_started", worker=self.worker, identity=self.identity, binary=self.binary,
            configuration_file="service-" + self.worker + ".json", configuration_sha256=build.digest(path),
            cache_directory=str(self.cache), backend_endpoint=f"http://127.0.0.1:{self.port}",
            spawn_requested_ns=spawn_requested_ns)
        assert build.digest(executable) == self.binary["sha256"]
        bound = time.monotonic() + DEADLINES["ready_seconds"]
        while time.monotonic() < bound:
            connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=.5)
            try:
                connection.request("GET", "/healthz")
                response = connection.getresponse()
                raw = response.read(4097)
                if response.status == 200 and json.loads(raw) == {"status": "alive", "protocol": 1}:
                    self.suite.events.emit("service_ready", worker=self.worker, identity=self.identity,
                                           status=200, **payload("body", raw))
                    return
            except (OSError, ValueError, http.client.HTTPException):
                pass
            finally:
                connection.close()
            time.sleep(.02)
        raise TimeoutError("original daemon readiness deadline")

    def stop(self, reason):
        if self.stopped or self.process is None:
            return
        cleanup_event(self.suite.events, self.suite.cleanup_errors, "service_stop_requested",
                      worker=self.worker, identity=self.identity, reason=reason, signal="SIGINT")
        try:
            os.kill(self.process.pid, signal.SIGINT)
        except ProcessLookupError:
            pass
        termination_error = None
        try:
            code, usage = network.wait_child(self.process, 10)
        except TimeoutError as error:
            termination_error = error_name(error)
            cleanup_event(self.suite.events, self.suite.cleanup_errors, "service_forced_cleanup",
                          worker=self.worker, identity=self.identity, error_name=termination_error)
            try:
                os.kill(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            code, usage = network.wait_child(self.process, 10)
        self.stopped = True
        cleanup_event(self.suite.events, self.suite.cleanup_errors, "service_stopped", worker=self.worker, identity=self.identity,
            wait_status=code, kernel_usage=usage, termination_error=termination_error,
            stdout_sha256=build.digest(self.log))
        assert termination_error is None and code == 0 and usage.get("available") is True


class Node:
    def __init__(self, suite):
        self.suite, self.condition = suite, threading.Condition()
        self.rows, self.errors, self.stopped, self.process = [], [], False, None
        self.eof = False
        self.reader = None
        self.stderr = suite.evidence / "node.stderr.log"

    def start(self):
        config = {"plan": PLAN, "endpoints": self.suite.endpoints, "tokens": self.suite.tokens,
                  "evidence": str(self.suite.evidence)}
        path = self.suite.private / "node.private.json"
        build.save_receipt(path, config)
        path.chmod(0o600)
        with self.stderr.open("xb") as errors:
            spawn_requested_ns = time.monotonic_ns()
            self.process = subprocess.Popen([self.suite.tools["node"]["path"], str(HERE / "probe.mjs"), str(path)],
                cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors)
        self.identity = network.process_identity(self.process)
        self.suite.events.emit("node_started", identity=self.identity, binary=binary_identity(self.suite.tools["node"]),
            configuration_sha256=build.digest(path), spawn_requested_ns=spawn_requested_ns)
        self.reader = threading.Thread(target=self.read, daemon=False)
        self.reader.start()
        self.wait("hello")

    def read(self):
        try:
            while True:
                raw = self.process.stdout.readline(LIMITS["node_line_bytes"] + 1)
                if not raw:
                    break
                assert len(raw) <= LIMITS["node_line_bytes"] and raw.endswith(b"\n"), "incomplete Node line"
                row = json.loads(raw)
                self.suite.events.emit("node_event", **payload("raw", raw))
                with self.condition:
                    self.rows.append(row)
                    self.condition.notify_all()
        except BaseException as error:
            with self.condition:
                self.errors.append(error_name(error))
                self.condition.notify_all()
        finally:
            with self.condition:
                self.eof = True
                self.condition.notify_all()

    def wait(self, event, command=None):
        bound = time.monotonic() + DEADLINES["child_seconds"]
        with self.condition:
            while True:
                assert not self.errors, self.errors
                found = [row for row in self.rows if row["event"] == event
                         and (command is None or row.get("command") == command)]
                if found:
                    assert len(found) == 1, "duplicate Node observation"
                    return found[0]
                assert not self.eof, "Node closed stdout before the expected original observation"
                remaining = bound - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("original SDK observation deadline")
                self.condition.wait(remaining)

    def offer(self, identifier):
        raw = encoded({"id": identifier}) + b"\n"
        self.suite.events.emit("operator_command", id=identifier, **payload("raw", raw))
        self.process.stdin.write(raw)
        self.process.stdin.flush()

    def finish(self, identifier):
        row = self.wait("command_finished", identifier)
        if identifier in FAILURES:
            assert row["ok"] is False and row["error"]["code"] == FAILURES[identifier], row
        else:
            assert row["ok"] is True, row
        assert isinstance(row["call_id"], str), "operation did not issue its original Fetch"
        return row

    def stop(self, force=False):
        if self.stopped or self.process is None:
            return
        cleanup_event(self.suite.events, self.suite.cleanup_errors, "node_stop_requested", identity=self.identity, forced=force)
        termination_error = None
        if not force:
            try:
                self.offer("shutdown")
                finished = self.wait("finished")
                assert finished["commands"] == finished["http_attempts"] == len(COMMANDS)
                self.process.stdin.close()
            except BaseException as error:
                termination_error, force = error_name(error), True
        if force:
            cleanup_event(self.suite.events, self.suite.cleanup_errors, "node_forced_cleanup", identity=self.identity,
                          error_name=termination_error)
            try:
                os.kill(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            code, usage = network.wait_child(self.process, 10)
        except TimeoutError as error:
            termination_error, force = error_name(error), True
            cleanup_event(self.suite.events, self.suite.cleanup_errors, "node_forced_cleanup", identity=self.identity,
                          error_name=termination_error)
            try:
                os.kill(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            code, usage = network.wait_child(self.process, 10)
        if self.reader is not None:
            self.reader.join(timeout=3)
        self.stopped = True
        ledger = self.suite.evidence / "metadata-node.jsonl"
        try:
            cleanup_event(self.suite.events, self.suite.cleanup_errors, "node_stopped", identity=self.identity,
                wait_status=code, kernel_usage=usage, forced=force, termination_error=termination_error,
                stderr_sha256=build.digest(self.stderr), ledger_sha256=build.digest(ledger) if ledger.exists() else None)
        finally:
            self.process.stdout.close()
            if not self.process.stdin.closed:
                self.process.stdin.close()
        assert not force and termination_error is None and code == 0 and usage.get("available") is True
        assert self.reader is not None and not self.reader.is_alive() and not self.errors


class Suite:
    def __init__(self, args, evidence, private, tools):
        self.args, self.evidence, self.private, self.tools = args, evidence, private, tools
        self.events = Trace(evidence / "events.jsonl")
        info = private.stat()
        self.private_identity = {"path": str(private), "device": info.st_dev, "inode": info.st_ino}
        self.events.emit("private_created", **self.private_identity)
        self.backend = self.hub = self.node = None
        self.services, self.reservations, self.curls, self.offered = {}, {}, [], []
        self.cleanup_errors = []
        self.tokens = {role: secrets.token_hex(32) for role in PRINCIPALS}

    def start_service(self, worker):
        assert worker not in self.services
        self.reservations.pop(worker).close()
        service = Service(self, worker)
        self.services[worker] = service
        service.start()

    def setup(self):
        self.backend = network.Backend(Path(self.tools["weed"]["path"]), self.private / "backend")
        self.backend.start()
        self.events.emit("backend_started", processes=self.backend.identities(),
            binary=binary_identity(self.tools["weed"]), access_key_sha256=sha(self.backend.access.encode()))
        connection = http.client.HTTPConnection("127.0.0.1", self.backend.port, timeout=3)
        try:
            connection.request("GET", "/scap-test/fixture-ready")
            response = connection.getresponse()
            raw = response.read(65537)
            self.events.emit("backend_unsigned_probe", endpoint=self.backend.endpoint, method="GET",
                path="/scap-test/fixture-ready", authorization=None, **payload("request_body", b""),
                status=response.status, **payload("response_body", raw))
            assert response.status == 403 and len(raw) <= 65536, "backend must enforce signing"
        finally:
            connection.close()
        self.hub = Hub(self.backend.port, self.evidence, self.events)
        self.s3_endpoints = {worker: self.hub.start("s3", worker) for worker in (*WORKERS, "F")}
        self.ports = {}
        for worker in WORKERS:
            reserved = socket.socket()
            reserved.bind(("127.0.0.1", 0))
            self.reservations[worker] = reserved
            self.ports[worker] = reserved.getsockname()[1]
        self.endpoints = {worker: self.hub.start("http", worker, self.ports[worker]) for worker in WORKERS}
        self.start_service("S")
        public = {"schema": 1, "workers": WORKERS, "scopes": SCOPES, "endpoints": self.endpoints,
            "s3_endpoints": self.s3_endpoints,
            "credential_sha256": {role: sha(token.encode()) for role, token in self.tokens.items()},
            "backend": {"endpoint": self.backend.endpoint, "access_key_sha256": sha(self.backend.access.encode())},
            "services": {worker: {"configuration_file": "service-" + worker + ".json",
                "backend_endpoint": f"http://127.0.0.1:{self.ports[worker]}", "worker_instance": WORKERS[worker],
                "cache_directory": str(self.private / ("cache-" + worker))} for worker in WORKERS},
            "private": self.private_identity}
        build.save_receipt(self.evidence / "metadata-configuration.json", public)
        self.node = Node(self)
        self.node.start()

    def begin(self, identifier):
        assert identifier not in self.offered and identifier in COMMANDS
        assert identifier == list(COMMANDS)[len(self.offered)], "offered command order differs"
        self.offered.append(identifier)
        self.node.offer(identifier)

    def call(self, identifier):
        self.begin(identifier)
        return self.node.finish(identifier)

    def snapshot(self, label):
        cache = self.services["M"].cache
        files, directories = [], []
        for path in sorted(cache.rglob("*")):
            assert not path.is_symlink(), "cache witness contains a symlink"
            if path.is_file():
                files.append({"path": str(path.relative_to(cache)), "bytes": path.stat().st_size,
                              "sha256": build.digest(path)})
            elif path.is_dir():
                info = path.stat()
                directories.append({"path": str(path.relative_to(cache)), "device": info.st_dev, "inode": info.st_ino})
            else:
                raise AssertionError("unexpected cache entry")
        self.events.emit("cache_observed", worker="M", label=label, path=str(cache), files=files, directories=directories)
        assert not files, "metadata-only worker materialized a cache file"

    def fixture(self, identifier, method, body=b"", if_match=None, source_read_serial=None):
        path = head_path("known_quarantine")
        self.events.emit("fixture_started", id=identifier, method=method, path=path,
            **payload("body", body), if_match=if_match, source_read_serial=source_read_serial)
        headers = self.evidence / (identifier + ".headers")
        result = self.evidence / (identifier + ".body")
        stdout_path, stderr_path = (self.evidence / (identifier + ".stdout"), self.evidence / (identifier + ".stderr"))
        command = [self.tools["curl"]["path"], "--silent", "--show-error", "--noproxy", "*",
            "--max-time", str(DEADLINES["curl_seconds"]), "--aws-sigv4", "aws:amz:us-east-1:s3", "--config", "-",
            "--request", method, "--header", "x-amz-content-sha256: " + sha(body),
            "--dump-header", str(headers), "--output", str(result), "--write-out", "%{http_code}"]
        if method == "PUT":
            assert if_match and source_read_serial is not None
            request_file = self.private / (identifier + ".payload")
            persist_bytes(request_file, body)
            command.extend(["--header", "If-Match: " + if_match, "--data-binary", "@" + str(request_file)])
        else:
            assert method == "GET" and not body and if_match is source_read_serial is None
        command.append(self.s3_endpoints["F"] + path)
        with stdout_path.open("xb") as output, stderr_path.open("xb") as errors:
            spawn_requested_ns = time.monotonic_ns()
            child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=output, stderr=errors)
        identity = network.process_identity(child)
        owned = {"id": identifier, "process": child, "identity": identity}
        self.curls.append(owned)
        self.events.emit("fixture_process_started", id=identifier, identity=identity,
            binary=binary_identity(self.tools["curl"]), spawn_requested_ns=spawn_requested_ns)
        child.stdin.write(f'user = "{self.backend.access}:{self.backend.secret}"\n'.encode())
        child.stdin.close()
        code, usage = network.wait_child(child, DEADLINES["curl_seconds"] + 2)
        self.curls.remove(owned)
        stdout, stderr = stdout_path.read_bytes(), stderr_path.read_bytes()
        raw_headers = headers.read_bytes() if headers.exists() else b""
        response = result.read_bytes() if result.exists() else b""
        etags = [line.split(b":", 1)[1].strip().decode("ascii") for line in raw_headers.splitlines()
                 if line.lower().startswith(b"etag:")]
        status = int(stdout) if len(stdout) == 3 and stdout.isdigit() else None
        self.events.emit("fixture_process_stopped", id=identifier, identity=identity, wait_status=code,
            kernel_usage=usage, status=status, **payload("body", response), etag=etags[-1] if etags else None,
            headers_sha256=sha(raw_headers), stdout_sha256=sha(stdout), stderr_sha256=sha(stderr))
        assert code == 0 and usage.get("available") is True and stdout == b"200" and not stderr and len(etags) == 1
        return response, etags[0]

    def run(self):
        self.setup()
        for name in NAMES:
            for operation in ("create", "activate", "execute", "policy"):
                self.call("s_" + name + "_" + operation)
        # M did not exist while S constructed any immutable data/result objects.
        self.start_service("M")
        self.snapshot("before_metadata")
        for identifier in ("m_success_status_before", "m_success_takeover", "m_success_policy", "m_success_status_after"):
            self.call(identifier)
        self.hub.arm("drop_get_unknown", worker="M", method="GET", path=head_path("get_unknown"),
                     stage="after_backend_response", kind="drop")
        self.call("m_get_unknown_takeover")
        self.call("o_get_unknown_status")
        self.hub.arm("drop_put_unknown", worker="M", method="PUT", path=head_path("put_unknown"), nonce="22001",
                     stage="after_backend_response", kind="drop")
        self.call("m_put_unknown_policy")
        self.call("o_put_unknown_status")
        self.hub.arm("hold_stale_put", worker="M", method="PUT", path=head_path("stale_412"), nonce="23001",
                     stage="before_forward", kind="hold")
        self.begin("m_stale_takeover")
        self.hub.wait("hold_stale_put")
        self.call("o_stale_policy")
        self.hub.release("hold_stale_put")
        self.node.finish("m_stale_takeover")
        for identifier in ("m_permission_takeover", "m_permission_policy", "o_permission_status"):
            self.call(identifier)
        original, original_etag = self.fixture("f_quarantine_get", "GET")
        read = self.hub.fixture_reads[head_path("known_quarantine")]
        assert read["body"] == original and read["etag"] == original_etag
        _, corrupt_etag = self.fixture("f_quarantine_corrupt", "PUT", b"{}", original_etag, read["request_serial"])
        self.call("m_quarantine_bad_status")
        self.fixture("f_quarantine_restore", "PUT", original, corrupt_etag, read["request_serial"])
        for identifier in ("m_quarantine_repaired_status", "m_quarantine_takeover", "m_quarantine_policy"):
            self.call(identifier)
        self.snapshot("after_metadata")
        self.node.stop()
        assert self.offered == list(COMMANDS)
        self.hub.complete()

    def cleanup(self):
        errors = self.cleanup_errors
        # A failed workload may have left the original PUT held. Releasing
        # this only as explicit failed-run cleanup prevents worker shutdown
        # from waiting on its own fixture gate. The failure remains recorded.
        if self.hub:
            try:
                self.hub.release_for_cleanup(errors)
            except BaseException as error:
                errors.append(error_name(error))
        if self.node and not self.node.stopped:
            try:
                self.node.stop(force=True)
            except BaseException as error:
                errors.append(error_name(error))
        for owned in self.curls:
            try:
                child = owned["process"]
                try:
                    os.kill(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                code, usage = network.wait_child(child, 5)
                if child.stdin is not None and not child.stdin.closed:
                    child.stdin.close()
                cleanup_event(self.events, errors, "fixture_forced_cleanup", id=owned["id"], identity=owned["identity"],
                              wait_status=code, kernel_usage=usage)
                errors.append("unfinished_fixture")
            except BaseException as error:
                errors.append(error_name(error))
        for worker in ("M", "S"):
            if worker in self.services:
                try:
                    self.services[worker].stop("planned_fixture_shutdown")
                except BaseException as error:
                    errors.append(error_name(error))
        for reserved in self.reservations.values():
            try:
                reserved.close()
            except BaseException as error:
                errors.append(error_name(error))
        if self.hub:
            try:
                self.hub.close(errors)
            except BaseException as error:
                errors.append(error_name(error))
        if self.backend:
            cleanup_event(self.events, errors, "backend_stop_requested", processes=self.backend.identities(),
                          signal="SIGKILL", reason="planned_fixture_shutdown")
            try:
                stopped = self.backend.stop(verify=True)
                cleanup_event(self.events, errors, "backend_stopped", processes=stopped)
                for role in ("master", "volume", "filer", "s3"):
                    raw = (self.backend.directory / (role + ".private.log")).read_bytes()
                    assert self.backend.access.encode() not in raw and self.backend.secret.encode() not in raw
                    persist_bytes(self.evidence / ("backend-" + role + ".log"), raw)
            except BaseException as error:
                errors.append(error_name(error))
                # Preserve the normal shutdown failure and still reap any
                # remaining owned child; this path can never produce a PASS.
                try:
                    stopped = self.backend.stop()
                    cleanup_event(self.events, errors, "backend_forced_cleanup", processes=stopped)
                except BaseException as cleanup_error:
                    errors.append(error_name(cleanup_error))
        # Include earlier fsync failures even when the complete-looking line
        # survived. Do not rewrite or fabricate the missing original event.
        errors.extend(self.events.errors)
        cleanup_event(self.events, errors, "cleanup_finished", errors=list(errors))
        return errors


def source_capture(evidence):
    command = [sys.executable, str(ROOT / "scripts/source_manifest.py"), "capture",
               str(evidence / "metadata-source-before.json"), "--root", str(ROOT)]
    with (evidence / "metadata-source-before.log").open("xb") as output:
        process = subprocess.run(command, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT, timeout=60)
        build.sync(output)
    assert process.returncode == 0, "fixture source capture failed"
    manifest = json.loads((evidence / "metadata-source-before.json").read_bytes())
    archive = evidence / "metadata-source.tar"
    with archive.open("xb") as output, (evidence / "metadata-source-archive.stderr.log").open("xb") as errors:
        process = subprocess.run(["git", "archive", "--format=tar", manifest["commit"]], cwd=ROOT,
                                 stdout=output, stderr=errors, timeout=60)
        build.sync(output)
        build.sync(errors)
    assert process.returncode == 0, "fixture source archive failed"
    build.save_receipt(evidence / "metadata-source-archive.json", {"schema": 1, "commit": manifest["commit"],
        "tree": manifest["tree"], "sha256": build.digest(archive), "bytes": archive.stat().st_size})


def source_verify(evidence):
    with (evidence / "metadata-source-after.log").open("xb") as output:
        process = subprocess.run([sys.executable, str(ROOT / "scripts/source_manifest.py"), "verify",
            str(evidence / "metadata-source-before.json"), "--root", str(ROOT)], cwd=ROOT,
            stdout=output, stderr=subprocess.STDOUT, timeout=60)
        build.sync(output)
    assert process.returncode == 0, "fixture source changed"


def seal_observed(suite, private, summary):
    """Delete only after all already-known evidence/owner failures are absent.

    A terminal write can fail after a real deletion. That cannot be rolled
    back: retain the true private_deleted observation and a failed result.
    """
    errors = summary["cleanup_errors"]
    if not (summary.get("contract_finished") and not errors and summary["source_unchanged"]):
        return
    cleanup_event(suite.events, errors, "private_remove_started", **suite.private_identity)
    if errors:
        return
    try:
        shutil.rmtree(private)
    except BaseException as error:
        errors.append({"event": "private_remove", "error_name": error_name(error)})
    summary["private_deleted"] = not private.exists()
    if errors:
        return
    cleanup_event(suite.events, errors, "private_remove_finished", **suite.private_identity,
                  observed_absence=summary["private_deleted"])
    if not summary["private_deleted"]:
        errors.append("private_removal_incomplete")
    if not errors:
        summary["status"] = "observed"


def main(args):
    evidence = args.evidence.resolve()
    assert not evidence.is_relative_to(ROOT)
    evidence.mkdir(parents=True, exist_ok=False, mode=0o700)
    private = Path(tempfile.mkdtemp(prefix="scap-metadata-private-", dir=evidence.parent))
    suite = None
    tools = {}
    summary = {"schema": 1, "status": "failed", "private_directory": str(private), "private_deleted": False,
               "aws_standard": "NOT_RUN", "production_slo": "NOT_RUN"}
    try:
        assert not any(os.environ.get(name) for name in ("LLVM_PROFILE_FILE", "NODE_V8_COVERAGE", "NODE_OPTIONS"))
        source_capture(evidence)
        build_evidence = evidence / "daemon-build-evidence"
        build_evidence.mkdir(mode=0o700)
        build.capture_receipt(args.build_record, args.server, build_evidence)
        for name, path in (("node", Path(shutil.which("node")).resolve()), ("weed", args.weed.resolve()),
                           ("curl", Path(shutil.which("curl")).resolve())):
            version = subprocess.check_output([str(path), "version" if name == "weed" else "--version"], text=True).strip()
            tools[name] = {"path": str(path), "sha256": build.digest(path), "version": version}
        assert tools["node"]["version"] == "v22.16.0" and network.VERSION in tools["weed"]["version"]
        build.save_receipt(evidence / "metadata-plan.json", PLAN)
        build.save_receipt(evidence / "metadata-tools.json", tools)
        suite = Suite(args, evidence, private, tools)
        suite.run()
        summary["contract_finished"] = True
    except BaseException as error:
        summary["error_name"] = error_name(error)
        if suite:
            cleanup_event(suite.events, suite.cleanup_errors, "fixture_failed", error_name=summary["error_name"])
    finally:
        summary["cleanup_errors"] = suite.cleanup() if suite else []
        try:
            build.verify(args.build_record, args.server)
            source_verify(evidence)
            assert all(build.digest(Path(tool["path"])) == tool["sha256"] for tool in tools.values()), "runtime tool changed"
            summary["source_unchanged"] = True
        except BaseException as error:
            summary["source_unchanged"] = False
            summary["source_error_name"] = error_name(error)
        if suite:
            seal_observed(suite, private, summary)
        build.save_receipt(evidence / "summary.json", summary)
    assert summary["status"] == "observed", summary
    oracle = load("metadata_independent_oracle", HERE / "oracle.py")
    try:
        result = oracle.audit(evidence)
        assert not private.exists(), "current-run private cleanup check failed"
        build.save_receipt(evidence / "oracle.json", result)
    except BaseException as error:
        summary["status"], summary["audit_error_name"] = "failed", error_name(error)
        build.save_receipt(evidence / "summary.json", summary)
        raise
    summary["status"] = "passed"
    build.save_receipt(evidence / "summary.json", summary)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    if not __debug__:
        raise RuntimeError("metadata acceptance requires Python assertions")
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--weed", type=Path, required=True)
    parser.add_argument("--build-record", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    main(parser.parse_args())
