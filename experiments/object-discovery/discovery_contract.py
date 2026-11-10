#!/usr/bin/env python3
"""Real signed S3, complete compute loss, root-only production RecoveryJob.

This controller records inputs, calls and effects. The independent oracle is
responsible for determining whether the resulting original evidence passes.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import hmac
import http.client
import importlib.util
import json
import os
from pathlib import Path
import resource
import secrets
import select
import shutil
import signal
import subprocess
import sys
import time
from urllib.parse import urlsplit

from deployment_recovery_imports import local

proxy_source, specification = local("discovery_proxy"), local("discovery_spec")
Proxy, sha = proxy_source.Proxy, proxy_source.sha
DATA_CASES, DESCRIPTOR_TENANTS = specification.DATA_CASES, specification.DESCRIPTOR_TENANTS
HEAD_FORMAT, IMMUTABLE_FORMAT = specification.HEAD_FORMAT, specification.IMMUTABLE_FORMAT
INTERMEDIATE_CASES, JOB_MS, MAX_STEPS = specification.INTERMEDIATE_CASES, specification.JOB_MS, specification.MAX_STEPS
QUERY, RECOVERY_PROFILES, STEP_MS = specification.QUERY, specification.RECOVERY_PROFILES, specification.STEP_MS
discovery_build = local("discovery_build")

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


fixture = load("discovery_network_fixture", ROOT / "experiments/object-network/run.py")
seed_build = load("discovery_network_build", ROOT / "experiments/object-network/build.py")


def save(path, value):
    with path.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(value, sort_keys=True, indent=2) + "\n")
        stream.flush(); os.fsync(stream.fileno())


class Ledger:
    def __init__(self, path):
        self.path, self.sequence = path, 0
        path.touch(exist_ok=False)

    def add(self, event, **fields):
        self.sequence += 1
        row = {"schema": 1, "sequence": self.sequence, "monotonic_ns": time.monotonic_ns(),
               "event": event, **fields}
        fixture.append_synced(self.path, row)
        return row


class Worker:
    def __init__(self, owner, mode, config, *, ignore_fsize=False):
        self.owner, self.mode, self.config = owner, mode, config
        self.worker = config["worker"]; self.pending = None; self.stopped = False
        binary = owner.args.seed_worker if mode == "seed" else owner.args.worker
        self.binary = {"path": str(binary.resolve()), "sha256": discovery_build.shared.digest(binary)}
        path = owner.private / f"worker-{self.worker}.private.json"
        path.write_text(json.dumps(config)); path.chmod(0o600)
        previous = signal.getsignal(signal.SIGXFSZ)
        before = time.monotonic_ns()
        try:
            if ignore_fsize: signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
            with (owner.private / f"worker-{self.worker}.private.log").open("ab") as log:
                self.process = subprocess.Popen([str(binary), str(path)], stdin=subprocess.PIPE,
                                                stdout=subprocess.PIPE, stderr=log, text=True, bufsize=1,
                                                restore_signals=not ignore_fsize)
        finally: signal.signal(signal.SIGXFSZ, previous)
        self.identity = {"pid": self.process.pid, "pid_source": "owned_Popen_child", "spawn_monotonic_ns": before}
        self.output = b""
        # Transfer the owned child before any fallible handshake or logging.
        owner.workers.append(self)
        public = {key: value for key, value in config.items() if key not in ("access_key", "secret_key")}
        try:
            owner.facts.add("worker_spawned", worker=self.worker, mode=mode, config=public,
                            config_path=str(path), config_sha256=sha(path.read_bytes()), identity=self.identity, binary=self.binary)
            self.ready = self.read(12)
            assert self.ready["ready"] is True and self.ready["resources"]["namespace_pid"] == self.process.pid
            assert discovery_build.shared.digest(binary) == self.binary["sha256"]
            owner.facts.add("worker_started", worker=self.worker, mode=mode, config=public,
                            config_path=str(path), config_sha256=sha(path.read_bytes()), identity=self.identity,
                            binary=self.binary, ready=self.ready)
        except BaseException:
            self.stop("worker_construction_failed", expected_kill=False)
            raise

    def read(self, seconds):
        deadline = time.monotonic() + seconds
        while b"\n" not in self.output:
            remaining = deadline - time.monotonic()
            assert remaining > 0 and select.select([self.process.stdout], [], [], remaining)[0], "worker response deadline"
            raw = os.read(self.process.stdout.fileno(), 65536)
            assert raw, "worker exited without a complete reply"
            self.output += raw
            assert len(self.output) <= 8 * 1024 * 1024, "fixture response exceeds complete-byte bound"
        line, self.output = self.output.split(b"\n", 1)
        return json.loads(line)

    def begin(self, label, operation, *, intent_id=None, **values):
        assert self.pending is None and label not in self.owner.labels
        self.owner.labels.add(label); self.owner.call_number += 1
        command = {"op": operation, **values}
        row = self.owner.calls.add("invoked", call_id=self.owner.call_number, label=label,
                                   worker=self.worker, mode=self.mode, identity=self.identity,
                                   request=command, intent_id=intent_id)
        self.owner.proxy.select(label, row["call_id"])
        self.process.stdin.write(json.dumps(command) + "\n"); self.process.stdin.flush()
        self.pending = row
        return row

    def finish(self):
        call = self.pending; assert call is not None
        response = self.read(call["request"].get("budget_ms", 8000) / 1000 + 5)
        observed = self.owner.calls.add("observed", call_id=call["call_id"], response=response)
        self.pending = None
        if call["request"]["op"] in ("execute", "session_execute") and response.get("ok") is True:
            assert call["intent_id"] is not None
            self.owner.acks.add("ack", call_id=call["call_id"], intent_id=call["intent_id"],
                                observed_ns=observed["monotonic_ns"], response=response)
        return response

    def call(self, label, operation, **values):
        self.begin(label, operation, **values)
        return self.finish()

    def stop(self, reason, *, expected_kill=True):
        if self.stopped: return
        try:
            self.owner.facts.add("worker_stop_requested", worker=self.worker, identity=self.identity, reason=reason)
        finally:
            # A failed log write (including ENOSPC) must not retain a child.
            try: os.kill(self.process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            code, usage = fixture.wait_child(self.process, 8)
            self.process.stdin.close(); self.process.stdout.close(); self.stopped = True
        self.owner.facts.add("worker_stopped", worker=self.worker, identity=self.identity,
                             wait_status=code, kernel_usage=usage, reason=reason)
        if self.pending is not None:
            self.owner.calls.add("lost_with_process", call_id=self.pending["call_id"], identity=self.identity)
            self.pending = None
        if expected_kill: assert code == -signal.SIGKILL


def accepted(response):
    assert response.get("ok") is True, response
    return response["value"]


def head_key(scope):
    return "scap-object/v1/{deployment}/{tenant}/{database}/head".format(**scope)


def object_base(scope, storage_generation):
    assert type(storage_generation) is int and storage_generation == 1
    return ("/scap-test/scap-object/v1/{deployment}/{tenant}/{database}/inc/{incarnation}/gen/{generation}/storage/".format(**scope)
            + str(storage_generation) + "/objects/")


def name_key(creation):
    scope = creation["scope"]
    return f"scap-object/v1/{scope['deployment']}/{scope['tenant']}/catalogue/v1/name/" + sha(creation["name"].encode())


class Suite:
    def __init__(self, args):
        self.args, self.evidence = args, args.evidence.resolve()
        self.evidence.mkdir(parents=True, exist_ok=False)
        self.private = self.evidence.with_name(self.evidence.name + ".private")
        self.private.mkdir(mode=0o700)
        self.compute = self.private / "compute"; self.compute.mkdir(mode=0o700)
        (self.evidence / "native").mkdir(); (self.evidence / "input-bodies").mkdir()
        self.facts, self.calls = Ledger(self.evidence / "facts.jsonl"), Ledger(self.evidence / "calls.jsonl")
        self.inputs, self.acks = Ledger(self.evidence / "inputs.jsonl"), Ledger(self.evidence / "acks.jsonl")
        self.workers, self.labels = [], set()
        self.call_number = self.worker_number = self.input_number = 0
        self.deployment = secrets.randbits(62) + 1
        self.backend = fixture.Backend(args.weed, self.private / "backend", volume_size_mib=64, max_volumes=2)
        self.proxy = None
        self.config = {}
        save(self.evidence / "plan.json", {"schema": 1, "deployment": self.deployment,
             "descriptor_tenants": DESCRIPTOR_TENANTS, "data_cases": DATA_CASES,
             "intermediate_cases": INTERMEDIATE_CASES, "recovery_profiles": RECOVERY_PROFILES,
             "head_format": HEAD_FORMAT, "immutable_format": IMMUTABLE_FORMAT,
             "query": QUERY, "job_ms": JOB_MS, "step_ms": STEP_MS, "maximum_steps": MAX_STEPS,
             "aws_standard_contract": "NOT_RUN", "unit_coverage_contribution": False})
        self.builds = {}
        for label, builder, receipt, worker in (("seed", seed_build, args.seed_build, args.seed_worker),
                                                ("recovery", discovery_build, args.build, args.worker)):
            directory = self.evidence / (label + "-build"); directory.mkdir()
            self.builds[label] = builder.capture_receipt(receipt, worker, directory)
        self.facts.add("builds_verified", stage="before", binaries={key: value["binary"] for key, value in self.builds.items()})

    def backend_start(self, stage):
        self.backend.start()
        self.facts.add("backend_started", stage=stage, identities=self.backend.identities(),
                       binary={"path": str(self.args.weed.resolve()), "sha256": discovery_build.shared.digest(self.args.weed)},
                       version=subprocess.check_output([str(self.args.weed), "version"], text=True).strip(),
                       access_key_sha256=sha(self.backend.access.encode()))

    def backend_stop(self, stage):
        self.facts.add("backend_stop_requested", stage=stage, identities=self.backend.identities())
        stopped = self.backend.stop(verify=True)
        self.facts.add("backend_stopped", stage=stage, identities=stopped)

    def spawn(self, *, scope=None, mode="seed", readers=None, retention=4, ignore_fsize=False):
        self.worker_number += 1; number = 70000 + self.worker_number
        cache = self.compute / str(number); cache.mkdir(mode=0o700)
        common = {**self.config, "worker": number, "cache_root": str(cache)}
        if mode == "seed":
            common.update(scope=scope, principal=17, provision=True, resource_log=None,
                          fixture_limits={"quota_bytes": 8 * 1024 * 1024, "retention_entries": retention,
                                          "retention_result_bytes": 128 * 1024 * 1024})
        else:
            common.update(deployment=self.deployment, readers={str(key): value for key, value in readers.items()},
                          artifact_root=str(self.evidence / "native" / str(number)), job_budget_ms=JOB_MS)
        return Worker(self, mode, common, ignore_fsize=ignore_fsize)

    def scope(self, tenant, database):
        return {"deployment": self.deployment, "tenant": tenant, "database": database, "incarnation": 1, "generation": 1}

    def control(self, worker, label, operation, **values):
        current = accepted(worker.call(label + ".status", "status"))
        return accepted(worker.call(label, operation, revision=current["revision"],
                                    nonce=1_000_000 + self.call_number, **values))

    def input(self, worker, label, row, *, epoch=1, identity=1, schema=False):
        self.input_number += 1
        raw = os.urandom(4096); digest = sha(raw); path = self.evidence / "input-bodies" / digest
        with path.open("xb") as stream: stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        statements = []
        if schema: statements.append({"sql": "CREATE TABLE data(id INTEGER PRIMARY KEY,value BLOB NOT NULL,token BLOB NOT NULL)"})
        statements.append({"sql": f"INSERT INTO data VALUES({row},?,randomblob(16)) RETURNING id,value,token",
                           "parameters": [{"type": "blob_file", "path": str(path), "offset": 0,
                                           "length": len(raw), "sha256": digest}]})
        value = {"intent_id": self.input_number, "label": label, "scope": worker.config["scope"],
                 "principal": 17, "epoch": epoch, "id": identity, "row": row,
                 "statements": statements, "input_body": {"file": digest, "bytes": len(raw), "sha256": digest}}
        self.inputs.add("input", **value)
        request = accepted(worker.call(label + ".prepare", "prepare_request", epoch=epoch, id=identity, statements=statements))
        self.facts.add("request_prepared", intent_id=value["intent_id"], identity=request)
        return value

    def execute(self, worker, intent, *, begin=False, session=False):
        operation = "session_execute" if session else "execute"
        values = dict(epoch=intent["epoch"], id=intent["id"], statements=intent["statements"],
                      directory=f"sql-{intent['intent_id']}", intent_id=intent["intent_id"])
        if begin: return worker.begin(intent["label"] + ".execute", operation, **values)
        return worker.call(intent["label"] + ".execute", operation, **values)

    def activate(self, worker, label):
        head = accepted(worker.call(label + ".status", "status"))
        if head["owner_instance"] != worker.worker: self.control(worker, label + ".takeover", "takeover")
        self.control(worker, label + ".activate", "activate")

    def direct(self, label, tenant, database, *, retention=4, ignore_fsize=False):
        worker = self.spawn(scope=self.scope(tenant, database), retention=retention, ignore_fsize=ignore_fsize)
        accepted(worker.call(label + ".create", "create", nonce=1))
        self.activate(worker, label)
        original = self.input(worker, label + ".base", 1, schema=True)
        accepted(self.execute(worker, original))
        self.facts.add("data_case_seeded", case=label, scope=worker.config["scope"], intent_id=original["intent_id"])
        return worker, original

    def prepare(self, label, tenant, operation, *, name=None, expected=None):
        worker = self.spawn(scope=self.scope(tenant, 999999))
        request = {"name": name or ("未知目录-" + label), "operation": operation,
                   "expected_name_revision": expected, "options": {"quota": {"kind": "default"}}}
        creation = accepted(worker.call(label + ".prepare", "catalogue_prepare", input=request))["creation"]
        self.facts.add("creation_prepared", case=label, creation=creation)
        return worker, creation

    def stopped_creation(self, label, state, operation):
        worker, creation = self.prepare(label, 2, operation)
        key, occurrence = name_key(creation), (1 if state == "reserved" else 2)
        if state == "provisioning": key, occurrence = head_key(creation["scope"]), 1
        gate = self.proxy.arm("PUT", "/scap-test/" + key, occurrence=occurrence, stage="after_response")
        worker.begin(label + ".resume_cut", "catalogue_resume", creation=creation)
        assert gate.arrived.wait(6)
        worker.stop("intermediate_" + state); self.proxy.release(gate, abort=True)
        assert gate.finished.wait(4)
        inspector = self.spawn(scope=creation["scope"])
        observed = accepted(inspector.call(label + ".inspect", "catalogue_inspect", create_operation=operation))
        assert observed["phase"] == state, observed
        self.facts.add("intermediate_state", case=label, phase=state, creation=creation)
        return inspector, creation

    def seed(self):
        for tenant in DESCRIPTOR_TENANTS:
            worker, creation = self.prepare(f"descriptor-{tenant}", tenant, 1)
            worker.stop("descriptor_only_seed_complete")
        orphan = self.spawn(scope=self.scope(2, 444))
        orphan_bytes = b"explicit unreachable fixture orphan"
        accepted(orphan.call("orphan.put", "store_put", key=(object_base(orphan.config["scope"], 1) + sha(orphan_bytes)).removeprefix("/scap-test/"), bytes=list(orphan_bytes)))
        native, original = self.direct("native", 2, 101, ignore_fsize=True)
        maintenance, _ = self.direct("maintenance", 10, 202)
        self.control(maintenance, "maintenance.enter", "set_lifecycle", lifecycle="maintenance")
        acl, _ = self.direct("acl", 99, 303)
        self.control(acl, "acl.readers", "set_policy", policy=[
            {"principal": 17, "read": False, "write": False, "admin": True},
            {"principal": 18, "read": True, "write": False, "admin": False}])
        retired, _ = self.direct("retired", 10, 204, retention=1)
        for epoch in range(1, 5):
            self.control(retired, f"retired.close-{epoch}", "close_full")
            if epoch < 4:
                intent = self.input(retired, f"retired.epoch-{epoch+1}", epoch + 1, epoch=epoch + 1)
                accepted(self.execute(retired, intent))
        owner, creation = self.prepare("reuse_old", 2, 501, name="同名不复用旧身份")
        accepted(owner.call("reuse_old.resume", "catalogue_resume", creation=creation))
        old = self.spawn(scope=creation["scope"]); self.activate(old, "reuse_old")
        old_input = self.input(old, "reuse_old.base", 1, schema=True); accepted(self.execute(old, old_input))
        self.facts.add("data_case_seeded", case="reuse_old", scope=creation["scope"], intent_id=old_input["intent_id"])
        status = accepted(old.call("reuse_old.delete_status", "status"))
        deletion = {"creation": creation, "operation": 801, "expected_name_revision": 2,
                    "expected_head_revision": status["revision"], "nonce": 901}
        deleted = accepted(old.call("reuse_old.delete", "catalogue_delete", input=deletion))
        successor, next_creation = self.prepare("reuse_new", 2, 502, name=creation["name"], expected=deleted["binding_revision"])
        accepted(successor.call("reuse_new.resume", "catalogue_resume", creation=next_creation))
        new = self.spawn(scope=next_creation["scope"]); self.activate(new, "reuse_new")
        new_input = self.input(new, "reuse_new.base", 1, schema=True); accepted(self.execute(new, new_input))
        self.facts.add("data_case_seeded", case="reuse_new", scope=next_creation["scope"], intent_id=new_input["intent_id"])
        for offset, state in enumerate(("reserved", "provisioning", "bound"), 601):
            self.stopped_creation(state, state, offset)
        for offset, label in enumerate(("control_admitted", "aborting", "aborted"), 611):
            worker, c = self.stopped_creation(label, "reserved", offset)
            command = {"creation": c, "operation": offset + 200, "expected_name_revision": 1, "nonce": offset + 300}
            if label == "aborted":
                accepted(worker.call(label + ".abort", "catalogue_abort", input=command))
            else:
                stage = "before_forward" if label == "control_admitted" else "after_response"
                gate = self.proxy.arm("PUT", "/scap-test/" + name_key(c), stage=stage)
                worker.begin(label + ".abort_cut", "catalogue_abort", input=command)
                assert gate.arrived.wait(6)
                worker.stop(label); self.proxy.release(gate, abort=True); assert gate.finished.wait(4)
            self.facts.add("abort_fixture", case=label, creation=c, control=command)
        # One old SQL candidate is held before HEAD, then explicitly cancelled.
        late = self.input(native, "native.late", 2, identity=20)
        gate = self.proxy.arm("PUT", "/scap-test/" + head_key(native.config["scope"]))
        self.execute(native, late, begin=True)
        assert gate.arrived.wait(6)
        native.stop("late_candidate_process_lost")
        fence = self.spawn(scope=native.config["scope"], ignore_fsize=True)
        cancelled = accepted(fence.call("native.cancel_late", "cancel", epoch=late["epoch"], id=late["id"], statements=late["statements"]))
        assert cancelled["state"] == "cancelled"
        self.facts.add("late_candidate_barrier", intent_id=late["intent_id"], response=cancelled,
                       request_serial=gate.observation["request_serial"])
        self.proxy.release(gate); assert gate.finished.wait(5)
        self.activate(fence, "native.restart")
        accepted(fence.call("native.session", "session_open", directory="warm"))
        wal = Path(fence.config["cache_root"]) / "warm/database.sqlite-wal"
        assert not wal.exists() or wal.stat().st_size == 0
        failure = self.input(fence, "native.accepted_without_native_ack", 3, identity=30)
        hold = self.proxy.arm("PUT", "/scap-test/" + head_key(fence.config["scope"]), stage="after_response")
        self.execute(fence, failure, begin=True, session=True); assert hold.arrived.wait(6)
        original_limit = resource.prlimit(fence.process.pid, resource.RLIMIT_FSIZE)
        try:
            resource.prlimit(fence.process.pid, resource.RLIMIT_FSIZE, (0, original_limit[1]))
            assert resource.prlimit(fence.process.pid, resource.RLIMIT_FSIZE)[0] == 0
            self.facts.add("native_file_limit_armed", worker=fence.worker, identity=fence.identity,
                           old=list(original_limit), soft_limit=0, request_serial=hold.observation["request_serial"],
                           intent_id=failure["intent_id"], wal_bytes=0)
            self.proxy.release(hold)
            response = fence.finish()
            assert response["ok"] is False and response["error_details"]["kind"] == "committed_but_unavailable", response
            self.facts.add("native_failed_after_s3_accept", intent_id=failure["intent_id"], response=response)
        finally:
            resource.prlimit(fence.process.pid, resource.RLIMIT_FSIZE, original_limit)
            self.facts.add("native_file_limit_restored", worker=fence.worker, identity=fence.identity, restored=list(original_limit))
            hold.release.set()
        accepted(fence.call("native.close_stale", "session_close"))
        extra = self.input(fence, "native.fill_window", 4, identity=40)
        accepted(self.execute(fence, extra))
        self.control(fence, "native.close_window", "close_full")
        next_input = self.input(fence, "native.new_window", 5, epoch=2, identity=50)
        accepted(self.execute(fence, next_input))
        self.original_result = original

    def lose_compute(self, stage):
        self.facts.add("compute_loss_started", stage=stage,
                       live_workers=[worker.worker for worker in self.workers if not worker.stopped])
        for worker in self.workers:
            if not worker.stopped: worker.stop("full_compute_loss_" + stage)
        shutil.rmtree(self.compute); assert not self.compute.exists()
        self.facts.add("compute_removed", stage=stage, path=str(self.compute), exists=False)
        self.backend_stop(stage); self.backend_start("after_" + stage)
        self.compute.mkdir(mode=0o700)
        self.facts.add("compute_loss_completed", stage=stage, root_only_restart=True)

    def recovery(self, profile, readers, *, stop_after=None, expected_stop=None):
        worker = self.spawn(mode="recovery", readers=readers)
        self.facts.add("recovery_profile_started", profile=profile, worker=worker.worker)
        last = None
        for step in range(1, MAX_STEPS + 1):
            last = accepted(worker.call(f"{profile}.step-{step}", "step", budget_ms=STEP_MS))
            if last["recovered_head"] is not None:
                accepted(worker.call(f"{profile}.query-{step}", "query", budget_ms=STEP_MS, sql=QUERY))
                accepted(worker.call(f"{profile}.drop-{step}", "drop_image"))
            if last["stopped"] is not None:
                assert last["stopped"] == expected_stop and not last["completion"]["recovery_complete"], last
                break
            if last["completion"]["recovery_complete"]:
                assert expected_stop is None and stop_after is None
                # Include a final image's fresh query in the cumulative public
                # budget observation; the finished job does not rescan storage.
                if last["recovered_head"] is not None: continue
                break
            if stop_after is not None and step >= stop_after and last["recovered_head"] is None:
                assert not last["completion"]["recovery_complete"]
                break
        else: raise AssertionError("root recovery exceeded experiment step bound")
        self.facts.add("recovery_profile_finished", profile=profile, worker=worker.worker, last=last)
        worker.stop("profile_" + profile)
        return last

    def fixture_http(self, label, method, path, body=b"", *, absent=False):
        self.call_number += 1
        call = self.calls.add("invoked", call_id=self.call_number, label=label, worker=None, mode="fixture",
                              identity=None, request={"op": "fixture_http", "method": method, "path": path,
                                                      "body_sha256": sha(body), "body_bytes": len(body), "absent": absent}, intent_id=None)
        self.proxy.select(label, call["call_id"])
        parsed = urlsplit(self.proxy.endpoint); host = parsed.netloc
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        scope = stamp[:8] + "/us-east-1/s3/aws4_request"
        headers = {"host": host, "x-amz-date": stamp, "x-amz-content-sha256": sha(body)}
        if absent: headers["if-none-match"] = "*"
        signed = ";".join(sorted(headers)); canonical_headers = "".join(f"{key}:{headers[key]}\n" for key in sorted(headers))
        canonical = "\n".join((method, path, "", canonical_headers, signed, sha(body))).encode()
        message = "\n".join(("AWS4-HMAC-SHA256", stamp, scope, sha(canonical))).encode()
        key = ("AWS4" + self.backend.secret).encode()
        for part in scope.split("/"): key = hmac.new(key, part.encode(), hashlib.sha256).digest()
        signature_value = hmac.new(key, message, hashlib.sha256).hexdigest()
        headers["Authorization"] = f"AWS4-HMAC-SHA256 Credential={self.backend.access}/{scope}, SignedHeaders={signed}, Signature={signature_value}"
        connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=8)
        try:
            connection.request(method, path, body, headers)
            response = connection.getresponse(); raw = response.read()
            result = {"status": response.status, "bytes": len(raw), "sha256": sha(raw), "etag": response.getheader("ETag")}
        finally: connection.close()
        self.calls.add("observed", call_id=call["call_id"], response=result)
        return result

    def run(self):
        self.backend_start("initial")
        self.proxy = Proxy(self.backend, self.evidence)
        self.config = {"endpoint": self.proxy.endpoint, "region": "us-east-1", "bucket": "scap-test",
                       "access_key": self.backend.access, "secret_key": self.backend.secret}
        self.seed(); self.lose_compute("seed")
        readers = {2: 17, 10: 17, 99: 18}
        self.recovery("interrupted", readers, stop_after=12)
        self.lose_compute("interrupted")
        self.recovery("missing_reader", {2: 17, 10: 17}, expected_stop="PermissionBlocked")
        self.recovery("admin_without_read", {2: 17, 10: 17, 99: 17}, expected_stop="PermissionBlocked")
        # Delete one actual closed-window Result, then restore those exact bytes.
        scope = self.original_result["scope"]
        captured_head = json.loads(self.proxy.objects["/scap-test/" + head_key(scope)])
        base = object_base(scope, captured_head["storage"]["active_generation"])
        original_ack = next(json.loads(line) for line in (self.evidence / "acks.jsonl").read_text().splitlines()
                            if json.loads(line)["intent_id"] == self.original_result["intent_id"])
        key = base + original_ack["response"]["value"]["receipt"]["result_hash"]
        raw = self.proxy.objects[key]
        assert self.fixture_http("damage.delete_retained_result", "DELETE", key)["status"] in (200, 204)
        self.facts.add("retained_result_removed", key=key, original_sha256=sha(raw), bytes=len(raw), intent_id=self.original_result["intent_id"])
        self.recovery("missing_retained_result", readers, expected_stop="Corrupt")
        assert self.fixture_http("damage.restore_retained_result", "PUT", key, raw, absent=True)["status"] == 200
        self.facts.add("retained_result_restored", key=key, sha256=sha(raw), bytes=len(raw))
        self.recovery("complete", readers)
        self.backend_stop("finished")
        self.proxy.close(); assert not self.proxy.errors, self.proxy.errors
        self.proxy = None
        seed_build.verify(self.args.seed_build, self.args.seed_worker)
        discovery_build.verify(self.args.build, self.args.worker)
        self.facts.add("builds_verified", stage="after", binaries={key: value["binary"] for key, value in self.builds.items()})

    def close(self):
        errors = []
        for worker in self.workers:
            if not worker.stopped:
                try: worker.stop("failed_run_cleanup")
                except BaseException as error: errors.append(error)
        if self.proxy is not None:
            try: self.proxy.close()
            except BaseException as error: errors.append(error)
        if self.backend.processes:
            stopped = self.backend.stop()
            self.facts.add("backend_failed_cleanup", identities=stopped)
        if errors: raise errors[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("worker", "build", "seed-worker", "seed-build", "weed", "evidence"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    suite = None; report = {"status": "failed", "aws_standard_contract": "NOT_RUN"}
    try:
        suite = Suite(args); suite.run()
        report = local("discovery_oracle").audit(suite.evidence)
    except BaseException as error:
        report["error"] = repr(error)
        raise
    finally:
        if suite is not None:
            suite.close()
            save(suite.evidence / "controller-result.json", report)
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
