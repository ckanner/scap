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
import secrets
import select
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time


VERSION = "4.51 153ab668c99731a6d29492bf6c61d0b4fa701101"
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


def record(evidence, event, **values):
    message = {"event": event, "monotonic_ns": time.monotonic_ns(), **values}
    with (evidence / "history.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(message, sort_keys=True) + "\n")
    print(json.dumps(message, sort_keys=True), flush=True)


def free_port(used):
    while True:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        if port not in used:
            used.add(port)
            return port


class Backend:
    def __init__(self, binary, directory):
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
            ("master", ["master", *listen("master"), f"-mdir={directory / 'master'}", "-peers=none", "-telemetry=false", "-volumeSizeLimitMB=64"]),
            ("volume", ["volume", *listen("volume"), f"-dir={directory / 'volume'}", f"-master={master}", "-max=2"]),
            ("filer", ["filer", *listen("filer"), f"-defaultStoreDir={directory / 'filer'}", f"-master={master}"]),
            ("s3", ["s3", *listen("s3"), f"-filer={filer}", f"-config={self.identity}", "-port.iceberg=0", "-port.lance=0"]),
        ]
        self.processes = []

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
                self.processes.append(subprocess.Popen([str(self.binary), *arguments], stdout=log, stderr=log,
                                                       cwd=self.directory))
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
            code = process.wait(timeout=8)
            if verify:
                assert code == -signal.SIGKILL, code
            observed.append({"role": name, "pid": process.pid, "wait_status": code})
        self.processes = []
        return observed

    def identities(self):
        return [{"role": name, "pid": process.pid} for (name, _), process in zip(self.commands, self.processes)]


class Rule:
    def __init__(self, mode, suffix=None):
        self.mode = mode
        self.suffix = suffix
        self.arrived = threading.Event()
        self.release = threading.Event()
        self.barrier = threading.Barrier(2, timeout=8) if mode == "pair" else None
        self.used = 0


class Proxy:
    def __init__(self, backend_port, evidence):
        self.backend_port = backend_port
        self.evidence = evidence
        self.lock = threading.Lock()
        self.rule = None
        self.rules = []
        self.events = []
        self.errors = []
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
                self.close_connection = True
                self.connection.settimeout(10)
                length = int(self.headers.get("Content-Length", "0"))
                assert 0 <= length <= 2 * 1024 * 1024
                payload = self.rfile.read(length)
                assert len(payload) == length
                with owner.lock:
                    rule = owner.rule
                    if rule and rule.suffix is not None and not (self.command == "PUT" and self.path.endswith(rule.suffix)):
                        rule = None
                    if rule:
                        rule.used += 1
                        if rule.mode in ("hold", "drop", "inject409", "inject412") or rule.mode == "pair" and rule.used == 2:
                            owner.rule = None
                if rule:
                    rule.arrived.set()
                    owner.event("transport_fault_observed", mode=rule.mode, method=self.command, path=self.path,
                                if_match=self.headers.get("If-Match"), if_none_match=self.headers.get("If-None-Match"))
                    if rule.mode == "blackhole":
                        rule.release.wait(10)
                        return
                    if rule.mode == "hold":
                        assert rule.release.wait(8), "held operation release deadline"
                    if rule.mode == "pair":
                        rule.barrier.wait()
                    if rule.mode in ("inject409", "inject412"):
                        status = int(rule.mode[-3:])
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
                    response = upstream.getresponse()
                    body = response.read(2 * 1024 * 1024 + 1)
                    assert len(body) <= 2 * 1024 * 1024
                    owner.event("object_response", method=self.command, path=self.path, status=response.status,
                                response_bytes=len(body), suppressed=bool(rule and rule.mode == "drop"),
                                if_match=self.headers.get("If-Match"), if_none_match=self.headers.get("If-None-Match"),
                                etag=response.getheader("ETag"))
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
            self.events.append({"event": event, **fields})
            record(self.evidence, event, **fields)

    def arm(self, mode, suffix=None):
        with self.lock:
            assert self.rule is None
            rule = Rule(mode, suffix)
            self.rules.append(rule)
            self.rule = rule
            return rule

    def clear(self):
        with self.lock:
            self.rule = None
            for rule in self.rules:
                rule.release.set()

    def close(self):
        self.clear()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)


class Worker:
    def __init__(self, binary, config, private, number, evidence):
        self.config = config
        self.evidence = evidence
        self.path = private / f"worker-{number}.private.json"
        self.path.write_text(json.dumps(config))
        self.path.chmod(0o600)
        with (private / f"worker-{number}.private.log").open("ab") as log:
            self.process = subprocess.Popen([str(binary), str(self.path)], stdin=subprocess.PIPE,
                                            stdout=subprocess.PIPE, stderr=log, text=True, bufsize=1)
        assert self.read(10) == {"ready": True}
        record(evidence, "worker_started", worker=config["worker"], pid=self.process.pid)

    def read(self, timeout):
        assert select.select([self.process.stdout], [], [], timeout)[0], "worker response deadline"
        line = self.process.stdout.readline()
        assert line, f"worker exited {self.process.poll()}"
        return json.loads(line)

    def call(self, op, **values):
        request = {"op": op, **values}
        fields = {"worker": self.config["worker"], "pid": self.process.pid, "operation": op,
                  "request_id": values.get("id"), "request_epoch": values.get("epoch"),
                  "key": values.get("key"), "budget_ms": values.get("budget_ms", 8000)}
        record(self.evidence, "client_invoked", **fields)
        self.process.stdin.write(json.dumps(request) + "\n")
        self.process.stdin.flush()
        try:
            response = self.read(values.get("budget_ms", 8000) / 1000 + 4)
        except BaseException as error:
            record(self.evidence, "client_transport_failed", error=repr(error), **fields)
            raise
        record(self.evidence, "client_observed", ok=response["ok"], error=response.get("error"),
               resolution=response.get("value", {}).get("state"), **fields)
        return response

    def kill(self, verify=False):
        if verify:
            assert self.process.poll() is None
        if self.process.poll() is None:
            self.process.kill()
        code = self.process.wait(timeout=5)
        if verify:
            assert code == -signal.SIGKILL, code
        observed = {"worker": self.config["worker"], "pid": self.process.pid, "wait_status": code}
        record(self.evidence, "worker_stopped", fault=verify, **observed)
        self.process.stdin.close()
        self.process.stdout.close()
        return observed


def success(value):
    assert value["ok"], value
    return value["value"]


def failure(value, *expected):
    assert not value["ok"], value
    assert value["error"] in expected, value
    return value["error"]


def run(arguments):
    assert "LLVM_PROFILE_FILE" not in os.environ
    evidence = arguments.evidence.resolve()
    evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    build = None
    if arguments.build_record:
        from build import verify
        build = verify(arguments.build_record, arguments.worker)
        shutil.copyfile(arguments.build_record, evidence / "build-receipt.json")
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
              "worker": 1, "principal": 17, "cache_root": str(compute)}
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
        assert not proxy.errors, proxy.errors
        summary["status"] = "passed"
        record(evidence, "verification_passed", contracts=len(completed))
    except BaseException as error:
        summary["status"] = "failed"
        summary["error"] = repr(error)
        record(evidence, "verification_failed", error=repr(error), completed_contracts=completed)
        raise
    finally:
        proxy.clear()
        for entry in workers:
            entry.kill()
        proxy.close()
        backend.stop()
        (evidence / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker", type=Path, required=True)
    parser.add_argument("--weed", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    build_mode = parser.add_mutually_exclusive_group(required=True)
    build_mode.add_argument("--build-record", type=Path)
    build_mode.add_argument("--diagnostic", action="store_true")
    run(parser.parse_args())
