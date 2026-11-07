#!/usr/bin/env python3
"""Twelve real lifecycle races; lifecycle_oracle audits the durable observations."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import sys
import tempfile
import time


PROFILE = {"quota_bytes": 4 * 1024 * 1024, "retention_entries": 4,
           "retention_result_bytes": 128 * 1024 * 1024}
CASES = [f"LC-{number:02d}" for number in range(1, 13)]
SCHEMA = [{"sql": "CREATE TABLE events(id INTEGER PRIMARY KEY, label TEXT NOT NULL, token INTEGER NOT NULL)"}]
QUERY = "SELECT id,label,token FROM events ORDER BY id"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def accepted(response):
    require(response.get("ok") is True, "worker operation failed: " + repr(response))
    return response["value"]


def refused(response, error):
    require(response.get("ok") is False and response.get("error") == error,
            "wrong refusal; expected " + error + ": " + repr(response))


def save_json(path, value):
    with path.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(value, sort_keys=True, indent=2) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def rows_sql(case, row=2):
    label = case + ("-seed" if row == 1 else "-candidate")
    return [{"sql": f"INSERT INTO events VALUES({row},?,random()) RETURNING id,label,token",
             "parameters": [{"type": "text", "value": label}]}]


def policy(revoked=False):
    return [{"principal": principal, "read": True, "write": True, "admin": True}
            for principal in ([18] if revoked else [17, 18])]


class LifecycleSuite:
    """Only orchestration lives here; no database state transition is reproduced."""

    def __init__(self, support, arguments, evidence, private, compute, backend, proxy,
                 workers, config, compiled):
        self.support, self.arguments, self.evidence = support, arguments, evidence
        self.private, self.compute, self.backend, self.proxy = private, compute, backend, proxy
        self.workers, self.config = workers, config
        self.counter = self.worker_number = self.nonce = 0
        self.call_labels = set()
        self.intents, self.acks, self.cases, self.cancellations = {}, [], [], {}
        self.started_worker_count = 0
        self.paths = {kind: evidence / f"lifecycle-{kind}-ledger.jsonl"
                      for kind in ("input", "client", "ack")}
        self.paths["facts"] = evidence / "lifecycle-facts.jsonl"
        for path in self.paths.values():
            path.touch(mode=0o600, exist_ok=False)
        deployment = secrets.randbits(62) + 1
        plan = {"version": 1, "case_ids": CASES, "fixture_limits": PROFILE,
                "s3_timeout_ms": 8000, "aws_endpoint_gate": "NOT_RUN",
                "production_slo_passed": False, "unit_coverage_contribution": False,
                "binary_sha256": compiled["binary"]["sha256"],
                "input_sha256": compiled["input_sha256"], "cases": []}
        for number, case_id in enumerate(CASES, 1):
            scope = {"deployment": deployment, "tenant": 1, "database": number,
                     "incarnation": 1, "generation": 1}
            case = {"id": case_id, "scope": scope, "directory": compute / case_id,
                    "workers": [], "deleted": case_id in ("LC-03", "LC-06"),
                    "retired": case_id == "LC-11", "cancelled": case_id in ("LC-07", "LC-09")}
            case["head_key"] = f"scap-object/v1/{deployment}/1/{number}/head"
            self.cases.append(case)
            plan["cases"].append({"id": case_id, "scope": scope, "head_key": case["head_key"]})
        save_json(evidence / "lifecycle-plan.json", plan)
        self.fact(None, "build_verified", stage="before", binary_sha256=plan["binary_sha256"],
                  input_sha256=plan["input_sha256"])

    def append(self, kind, event, **values):
        row = {"event": event, "monotonic_ns": time.monotonic_ns(), **values}
        self.support.append_synced(self.paths[kind], row)
        return row

    def fact(self, case, event, **values):
        return self.append("facts", event, case=None if case is None else case["id"], **values)

    def spawn(self, case, principal=17, scope=None):
        self.worker_number += 1
        number = 30000 + self.worker_number
        config = {**self.config, "scope": scope or case["scope"], "principal": principal,
                  "worker": number, "cache_root": str(case["directory"]),
                  "fixture_limits": PROFILE, "resource_log": None}
        worker = self.support.Worker(self.arguments.worker.resolve(), config, self.private,
                                     number, self.evidence)
        self.workers.append(worker)
        case["workers"].append(worker)
        self.started_worker_count += 1
        self.fact(case, "worker_started", worker=number, principal=principal,
                  scope=config["scope"], identity=worker.identity)
        return worker

    def begin(self, case, worker, label, operation, *, intent=None, **values):
        phase = case["id"] + "/" + label
        require(phase not in self.call_labels, "duplicate invocation label before transport: " + phase)
        self.call_labels.add(phase)
        self.counter += 1
        command = {"op": operation, **values}
        self.proxy.set_phase(phase)
        row = self.append("client", "call", call_id=self.counter, case=case["id"],
                          label=label, phase=phase, worker=worker.config["worker"],
                          principal=worker.config["principal"], scope=worker.config["scope"],
                          intent_id=None if intent is None else intent["intent_id"], command=command)
        pending = worker.begin(operation, **values)
        return {"worker": worker, "pending": pending, "call": row}

    def finish(self, pending):
        call = pending["call"]
        try:
            response = pending["worker"].finish(pending["pending"])
        except BaseException as error:
            self.append("client", "transport_failure", call_id=call["call_id"],
                        error_type=type(error).__name__, error=str(error))
            raise
        row = self.append("client", "response", call_id=call["call_id"], response=response)
        if (call["intent_id"] is not None and response.get("ok") is True
                and response.get("value", {}).get("state") == "cancelled"):
            self.cancellations.setdefault(call["intent_id"], response["value"])
        if call["command"]["op"] in ("execute", "session_execute") and response.get("ok") is True:
            require(call["intent_id"] in self.intents, "successful execute lacks an independent input")
            ack = self.append("ack", "ack", call_id=call["call_id"], case=call["case"],
                              intent_id=call["intent_id"], response=response,
                              observed_ns=row["monotonic_ns"])
            self.acks.append(ack)
        return response

    def call(self, case, worker, label, operation, **values):
        return self.finish(self.begin(case, worker, label, operation, **values))

    def prepare(self, case, worker, name, epoch, request_id, statements):
        intent_id = case["id"] + "/" + name
        require(intent_id not in self.intents, "duplicate intent")
        intent = {"intent_id": intent_id, "case": case["id"], "name": name,
                  "scope": worker.config["scope"], "principal": worker.config["principal"],
                  "epoch": epoch, "id": request_id, "statements": copy.deepcopy(statements)}
        self.append("input", "input", **intent)
        self.intents[intent_id] = intent
        identity = accepted(self.call(case, worker, "prepare." + name, "prepare_request", intent=intent,
                                      epoch=epoch, id=request_id, statements=statements))
        intent["identity"] = identity
        self.append("input", "prepared", intent_id=intent_id, identity=identity)
        return intent

    def execute(self, case, worker, label, intent, *, begin=False):
        values = {"intent": intent, "epoch": intent["epoch"], "id": intent["id"],
                  "statements": intent["statements"], "directory": "execute-" + str(self.counter + 1)}
        method = self.begin if begin else self.call
        return method(case, worker, label, "execute", **values)

    def resolution(self, case, worker, label, intent, operation="lookup_identity"):
        return self.call(case, worker, label, operation, intent=intent, identity=intent["identity"])

    def control(self, case, worker, label, operation, **values):
        head = accepted(self.call(case, worker, label + ".status", "status"))
        self.nonce += 1
        return self.call(case, worker, label, operation, revision=head["revision"],
                         nonce=1000000 + self.nonce, **values)

    def snapshot(self, case, worker, label):
        return accepted(self.call(case, worker, label, "store_get", key=case["head_key"]))

    def query(self, case, worker, label, *, session=False):
        return self.call(case, worker, label, "session_query" if session else "query", sql=QUERY,
                         directory="query-" + str(self.counter + 1))

    def fixture(self, case):
        case["directory"].mkdir(mode=0o700)
        owner, admin = self.spawn(case), self.spawn(case, 18)
        case.update(owner=owner, admin=admin)
        accepted(self.call(case, owner, "create", "create", nonce=1))
        accepted(self.control(case, owner, "grant_admin", "set_policy", policy=policy()))
        accepted(self.control(case, owner, "activate", "activate"))
        for name, request_id, statements in (("schema", 1, SCHEMA), ("seed", 2, rows_sql(case["id"], 1))):
            intent = self.prepare(case, owner, name, 1, request_id, statements)
            case[name] = intent
            accepted(self.execute(case, owner, name, intent))
        case["candidate"] = self.prepare(case, owner, "candidate", 1, 3, rows_sql(case["id"]))
        case["initial"] = self.snapshot(case, owner, "initial_head")
        self.fact(case, "fixture_ready")

    def held(self, case, stage):
        rule = self.proxy.arm("hold", method="PUT", key=case["head_key"], stage=stage,
                              expected_status=200 if stage == "after_upstream_response" else None)
        pending = self.execute(case, case["owner"], "candidate", case["candidate"], begin=True)
        require(rule.arrived.wait(8), "candidate did not reach its real HEAD boundary")
        self.fact(case, "boundary", call_id=pending["call"]["call_id"],
                  observation=rule.observation, payload=list(rule.payload))
        return rule, pending

    def release(self, case, rule, pending, barrier_label):
        self.fact(case, "release", call_id=pending["call"]["call_id"],
                  request_serial=rule.observation["request_serial"], barrier_label=barrier_label)
        rule.release.set()
        return self.finish(pending)

    def lifecycle_race(self, case, number):
        first = number <= 3
        kind = (number - 1) % 3
        rule, pending = self.held(case, "before_forward" if first else "after_upstream_response")
        try:
            if kind == 0:
                barrier = self.control(case, case["admin"], "barrier", "set_policy", policy=policy(True))
            else:
                barrier = self.control(case, case["admin"], "barrier", "set_lifecycle",
                                       lifecycle="maintenance" if kind == 1 else "deleted")
            accepted(barrier)
            response = self.release(case, rule, pending, "barrier")
        finally:
            rule.release.set()
        refused(response, "Conflict") if first else accepted(response)
        owner = case["owner"]
        if kind == 0:
            refused(self.query(case, owner, "revoked.query"), "Denied")
            refused(self.resolution(case, owner, "revoked.lookup", case["seed"]), "Denied")
            accepted(self.control(case, case["admin"], "restore_policy", "set_policy", policy=policy()))
        elif kind == 1:
            accepted(self.query(case, owner, "maintenance.query"))
            fresh = self.prepare(case, owner, "maintenance_write", 1, 4, rows_sql(case["id"]))
            refused(self.execute(case, owner, "maintenance.write", fresh), "Lifecycle")
            refused(self.control(case, case["admin"], "maintenance.takeover", "takeover"), "Lifecycle")
            accepted(self.control(case, case["admin"], "restore_ready", "set_lifecycle", lifecycle="ready"))
        else:
            self.deleted_checks(case, owner, "deleted", variant_creates=True)
        if first and not case["deleted"]:
            observed = accepted(self.resolution(case, owner, "candidate.unknown", case["candidate"]))
            require(observed == {"state": "unknown"}, "lost CAS was not separately resolved")

    def deleted_checks(self, case, worker, prefix, *, variant_creates=False):
        before = self.snapshot(case, worker, prefix + ".head_before")
        head = json.loads(bytes(before["bytes"]))
        refused(self.query(case, worker, prefix + ".query"), "Lifecycle")
        refused(self.resolution(case, worker, prefix + ".lookup", case["seed"]), "Lifecycle")
        for op in ("activate", "takeover", "set_lifecycle"):
            values = {"lifecycle": "ready"} if op == "set_lifecycle" else {}
            self.nonce += 1
            refused(self.call(case, worker, prefix + "." + op, op, revision=head["revision"],
                              nonce=1000000 + self.nonce, **values), "Lifecycle")
        refused(self.call(case, worker, prefix + ".create", "create", nonce=2000000 + self.nonce),
                "Store(Conflict)")
        if variant_creates:
            for name in ("incarnation", "generation"):
                changed = {**case["scope"], name: 2}
                alternate = self.spawn(case, scope=changed)
                refused(self.call(case, alternate, prefix + ".create." + name, "create", nonce=3000000),
                        "Store(Conflict)")
                refused(self.call(case, alternate, prefix + ".status." + name, "status"), "Format(Corrupt)")
        after = self.snapshot(case, worker, prefix + ".head_after")
        require(before == after, "deleted checks changed the tombstone")

    def cancellation_race(self, case, number):
        observer = self.spawn(case)
        case["observer"] = observer
        if number == 9:
            rule = self.proxy.arm("drop", method="PUT", key=case["head_key"],
                                  stage="after_upstream_response", expected_status=200)
            pending = self.begin(case, observer, "cancel_lost", "cancel_identity", intent=case["candidate"],
                                 identity=case["candidate"]["identity"])
            require(rule.arrived.wait(8), "cancellation did not reach accepted response boundary")
            self.fact(case, "boundary", call_id=pending["call"]["call_id"],
                      observation=rule.observation, payload=list(rule.payload))
            response = self.release(case, rule, pending, "cancel_lost")
            refused(response, "Store(Unknown)")
            result = accepted(self.resolution(case, observer, "cancel.confirmed", case["candidate"]))
            require(result["state"] == "cancelled", "ambiguous cancellation was not proved")
            case["cancellation"] = result
        else:
            rule, pending = self.held(case, "before_forward" if number == 7 else "after_upstream_response")
            try:
                result = accepted(self.resolution(case, observer, "barrier", case["candidate"], "cancel_identity"))
                response = self.release(case, rule, pending, "barrier")
            finally:
                rule.release.set()
            if number == 7:
                require(result["state"] == "cancelled", "cancel did not win")
                case["cancellation"] = result
                refused(response, "Conflict")
            else:
                committed = accepted(response)
                require(result == {"state": "committed", "receipt": committed["receipt"],
                                   "encoded": committed["result"]["encoded"]}, "cancel did not return original commit")
        if number in (7, 9):
            refused(self.execute(case, case["owner"], "cancelled.execute", case["candidate"]), "Closed")
            require(accepted(self.resolution(case, observer, "cancelled.lookup", case["candidate"]))
                    == case["cancellation"], "cancellation transition changed")

    def identities(self, case):
        owner, admin = case["owner"], case["admin"]
        accepted(self.execute(case, owner, "duplicate_seed", case["seed"]))
        for name, worker, epoch, statements in (
            ("changed_sql", owner, 1, [{**case["seed"]["statements"][0],
                                       "sql": case["seed"]["statements"][0]["sql"] + " /* changed */"}]),
            ("changed_parameter", owner, 1, [{**case["seed"]["statements"][0],
                                             "parameters": [{"type": "text", "value": "changed"}]}]),
            ("changed_principal", admin, 1, case["seed"]["statements"]),
            ("future_epoch", owner, 2, case["seed"]["statements"]),
        ):
            intent = self.prepare(case, worker, name, epoch, 2, statements)
            refused(self.execute(case, worker, name, intent), "RequestConflict")
        for name, request_id, sql in (("read_execute", 3, "SELECT random() AS token"),
                                     ("zero_execute", 4, "UPDATE events SET label=label WHERE id=-1")):
            intent = self.prepare(case, owner, name, 1, request_id, [{"sql": sql}])
            case[name] = intent
            accepted(self.execute(case, owner, name, intent))
        full = self.prepare(case, owner, "full_window", 1, 5, rows_sql(case["id"]))
        refused(self.execute(case, owner, "full_window", full), "WindowFull")
        accepted(self.control(case, admin, "close_full", "close_full"))
        accepted(self.execute(case, owner, "closed_duplicate", case["seed"]))

    def fill(self, case, epoch, count):
        for index in range(count):
            name = f"fill_{epoch}_{index}"
            intent = self.prepare(case, case["admin"], name, epoch, 90 + index, [{"sql": "SELECT 1"}])
            result = accepted(self.resolution(case, case["admin"], name, intent, "cancel_identity"))
            require(result["state"] == "cancelled", "window filler must be a real cancellation")

    def retirement(self, case):
        rule, pending = self.held(case, "before_forward")
        try:
            self.fill(case, 1, 2)
            accepted(self.control(case, case["admin"], "barrier", "close_full"))
            response = self.release(case, rule, pending, "barrier")
        finally:
            rule.release.set()
        refused(response, "Conflict")
        accepted(self.resolution(case, case["owner"], "closed.seed", case["seed"]))
        require(accepted(self.resolution(case, case["owner"], "closed.absent", case["candidate"]))
                == {"state": "closed"}, "closed absent request must be Closed")
        for epoch in (2, 3):
            self.fill(case, epoch, 4)
            accepted(self.control(case, case["admin"], f"close_{epoch}", "close_full"))
        require(accepted(self.resolution(case, case["owner"], "retired.seed", case["seed"]))
                == {"state": "retired"}, "old committed identity must be Retired")
        refused(self.call(case, case["admin"], "retired.raw_candidate", "store_put", key=case["head_key"],
                          bytes=list(rule.payload), etag=rule.observation["if_match"]), "Conflict")

    def owners(self, case):
        owner = case["owner"]
        rule, pending = self.held(case, "before_forward")
        try:
            for name in ("owner_b", "owner_a2"):
                successor = self.spawn(case)
                accepted(self.control(case, successor, name + ".takeover", "takeover"))
                accepted(self.control(case, successor, name + ".activate", "activate"))
            response = self.release(case, rule, pending, "owner_a2.activate")
        finally:
            rule.release.set()
        refused(response, "Conflict")
        fresh = self.prepare(case, owner, "old_owner", 1, 4, rows_sql(case["id"]))
        refused(self.execute(case, owner, "old_owner", fresh), "Fenced")
        case["owner"] = successor
        before = self.snapshot(case, successor, "aba.before")
        accepted(self.control(case, successor, "aba.maintenance", "set_lifecycle", lifecycle="maintenance"))
        accepted(self.control(case, successor, "aba.ready", "set_lifecycle", lifecycle="ready"))
        self.nonce += 1
        refused(self.call(case, successor, "aba.stale_revision", "set_lifecycle",
                          revision=json.loads(bytes(before["bytes"]))["revision"], nonce=1000000 + self.nonce,
                          lifecycle="ready"), "Conflict")
        refused(self.call(case, successor, "aba.raw_candidate", "store_put", key=case["head_key"],
                          bytes=list(rule.payload), etag=rule.observation["if_match"]), "Conflict")
        refused(self.call(case, successor, "aba.raw_snapshot", "store_put", key=case["head_key"],
                          bytes=before["bytes"], etag=before["etag"]), "Conflict")
        self.snapshot(case, successor, "aba.after")
        require(accepted(self.resolution(case, successor, "candidate.unknown", case["candidate"]))
                == {"state": "unknown"}, "fenced candidate outcome was not checked")

    def lose_compute(self, case, stage):
        identities = []
        for worker in list(case["workers"]):
            identities.append(worker.kill(verify=True))
            case["workers"].remove(worker)
            self.workers.remove(worker)
        directory = case["directory"]
        require(directory.is_dir() and not directory.is_symlink(), "owned compute directory missing")
        shutil.rmtree(directory)
        require(not directory.exists(), "compute directory was not removed")
        self.fact(case, "compute_lost", stage=stage, stopped=identities,
                  directory=str(directory), existed_before=True, exists_after=directory.exists())

    def audit(self, case, stage):
        case["directory"].mkdir(mode=0o700)
        worker = self.spawn(case)
        self.fact(case, "recovery_started", stage=stage, worker=worker.config["worker"])
        self.snapshot(case, worker, stage + ".head_before")
        if case["deleted"]:
            self.deleted_checks(case, worker, stage + ".deleted", variant_creates=False)
        else:
            accepted(self.control(case, worker, stage + ".takeover", "takeover"))
            accepted(self.control(case, worker, stage + ".activate_session", "activate_session",
                                  directory=stage + "-session"))
            accepted(self.query(case, worker, stage + ".rows", session=True))
        # Audit identities once per stage. Every original or repeated ACK remains
        # in the ACK ledger and is classified separately by the offline oracle.
        known = sorted({ack["intent_id"] for ack in self.acks if ack["case"] == case["id"]})
        for intent_id in known:
            intent = self.intents[intent_id]
            label = stage + ".ack." + intent["name"]
            lookup = self.resolution(case, worker, label + ".lookup", intent)
            if case["deleted"]:
                refused(lookup, "Lifecycle")
            elif case["retired"]:
                require(accepted(lookup) == {"state": "retired"}, "retired ACK was relabelled")
                refused(self.execute(case, worker, label + ".replay", intent), "Retired")
            else:
                require(accepted(lookup)["state"] == "committed", "retained ACK result unavailable")
                accepted(self.execute(case, worker, label + ".replay", intent))
        if not case["deleted"] and case["id"] != "LC-10":
            lookup = accepted(self.resolution(case, worker, stage + ".candidate.lookup", case["candidate"]))
            if case["cancelled"]:
                require(lookup == case["cancellation"], "recovery lost cancellation barrier")
                refused(self.execute(case, worker, stage + ".candidate.execute", case["candidate"]), "Closed")
            elif case["retired"]:
                require(lookup == {"state": "retired"}, "retired absent identity changed")
            elif case["id"] in ("LC-01", "LC-02", "LC-12"):
                require(lookup == {"state": "unknown"}, "recovery changed rejected candidate outcome")
            else:
                require(lookup["state"] == "committed", "recovery lost commit-first candidate")
        cancellation_inputs = [self.intents[key] for key in sorted(self.cancellations)
                               if self.intents[key]["case"] == case["id"]
                               and self.intents[key]["name"] != "candidate"]
        observers = {17: worker}
        for intent in cancellation_inputs:
            principal = intent["principal"]
            if principal not in observers:
                observers[principal] = self.spawn(case, principal)
            observer = observers[principal]
            prefix = stage + ".cancel." + intent["name"]
            found = accepted(self.resolution(case, observer, prefix + ".lookup", intent))
            if case["retired"] and intent["epoch"] == 1:
                require(found == {"state": "retired"}, "retired cancellation was relabelled")
                refused(self.execute(case, observer, prefix + ".execute", intent), "Retired")
            else:
                require(found == self.cancellations[intent["intent_id"]], "retained cancellation changed")
                refused(self.execute(case, observer, prefix + ".execute", intent), "Closed")
        self.snapshot(case, worker, stage + ".head_after")
        self.fact(case, "recovery_observed", stage=stage)

    def run(self):
        self.fact(None, "backend_started", identities=self.backend.identities())
        for number, case in enumerate(self.cases, 1):
            self.fixture(case)
            if number <= 6:
                self.lifecycle_race(case, number)
            elif number <= 9:
                self.cancellation_race(case, number)
            elif number == 10:
                self.identities(case)
            elif number == 11:
                self.retirement(case)
            else:
                self.owners(case)
            self.snapshot(case, case["owner"], "pre_loss")
            self.lose_compute(case, "compute_recovery")
            self.audit(case, "compute_recovery")
            self.lose_compute(case, "before_backend")
        require(not self.workers, "backend restart requires every computation process stopped")
        self.fact(None, "backend_stopping", live_compute_workers=len(self.workers))
        stopped = self.backend.stop(verify=True)
        self.fact(None, "backend_stopped", identities=stopped, live_compute_workers=len(self.workers))
        self.backend.start()
        self.fact(None, "backend_restarted", identities=self.backend.identities())
        for case in self.cases:
            self.audit(case, "backend_recovery")
            self.lose_compute(case, "final_cleanup")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("worker", "weed", "build-record", "evidence"):
        parser.add_argument("--" + name, type=Path, required=True)
    arguments = parser.parse_args(argv)
    evidence = arguments.evidence.resolve()
    evidence.mkdir(parents=True, mode=0o700, exist_ok=False)
    summary = {"status": "blocked", "case_ids": CASES, "real_worker_started": False,
               "scope": "private-loopback-real-S3-and-Rust-worker", "fixture_limits": PROFILE,
               "aws_endpoint_gate": "NOT_RUN", "production_slo_passed": False,
               "unit_coverage_contribution": False, "build_record_verified": False}
    backend = proxy = suite = private = None
    workers, cleanup = [], []
    try:
        require(not sys.flags.optimize, "fixture assertions must be enabled")
        require("LLVM_PROFILE_FILE" not in os.environ, "integration cannot contribute unit coverage")
        for name in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"):
            require("instrument-coverage" not in os.environ.get(name, ""), "integration cannot inherit instrumentation")
        for path in (arguments.worker, arguments.weed, arguments.build_record):
            require(path.is_file(), "missing prerequisite: " + str(path))
        import build
        import run as support
        compiled = build.verify(arguments.build_record, arguments.worker)
        shutil.copyfile(arguments.build_record, evidence / "build-receipt.json")
        private = Path(tempfile.mkdtemp(prefix="scap-lifecycle-private-"))
        compute = private / "compute"
        compute.mkdir(mode=0o700)
        backend = support.Backend(arguments.weed.resolve(), private / "backend")
        proxy = support.Proxy(backend.port, evidence)
        proxy.capture = True
        config = {"endpoint": proxy.endpoint, "region": "us-east-1", "bucket": "scap-test",
                  "access_key": backend.access, "secret_key": backend.secret}
        suite = LifecycleSuite(support, arguments, evidence, private, compute, backend, proxy,
                               workers, config, compiled)
        backend.start()
        summary["status"] = "running"
        suite.run()
    except BaseException as error:
        summary.update(status="blocked" if summary["status"] == "blocked" else "failed",
                       error_type=type(error).__name__, error=str(error))
    finally:
        if proxy is not None:
            try:
                proxy.clear()
            except BaseException as error:
                cleanup.append({"phase": "release_proxy", "error": repr(error)})
        for worker in list(workers):
            try:
                worker.kill()
            except BaseException as error:
                cleanup.append({"phase": "stop_worker", "error": repr(error)})
        for phase, item, method in (("close_proxy", proxy, "close"), ("stop_backend", backend, "stop")):
            if item is not None:
                try:
                    observed = getattr(item, method)()
                    if phase == "stop_backend" and suite is not None:
                        suite.fact(None, "backend_cleanup", identities=observed)
                except BaseException as error:
                    cleanup.append({"phase": phase, "error": repr(error)})
        if proxy is not None:
            summary["object_metrics"] = proxy.metrics()
            summary["proxy_errors"] = proxy.errors
            if proxy.errors:
                cleanup.append({"phase": "proxy_errors", "count": len(proxy.errors)})
        summary["cleanup_errors"] = cleanup
        if private is not None:
            summary["private_diagnostics"] = {"directory": str(private), "retained": private.exists(),
                                               "contains_worker_configuration_and_credentials": True,
                                               "backend_files_retained": (private / "backend").exists()}
        if suite is not None:
            summary["real_worker_started"] = suite.started_worker_count > 0
            summary["remaining_case_compute_directories"] = [str(case["directory"]) for case in suite.cases
                                                              if case["directory"].exists()]
        if cleanup:
            summary["status"] = "failed"
        if summary["status"] == "running":
            try:
                compiled = build.verify(arguments.build_record, arguments.worker)
                suite.fact(None, "build_verified", stage="after", binary_sha256=compiled["binary"]["sha256"],
                           input_sha256=compiled["input_sha256"])
                suite.fact(None, "cleanup_observed", proxy_errors=[], cleanup_errors=[])
                import lifecycle_oracle
                audit = lifecycle_oracle.audit(evidence)
                save_json(evidence / "lifecycle-oracle.json", audit)
                require(audit["status"] == "passed", "independent lifecycle oracle failed: " + repr(audit))
                summary.update(status="passed", build_record_verified=True, oracle=audit)
            except BaseException as error:
                summary.update(status="failed", error_type=type(error).__name__, error=str(error))
        summary["artifacts"] = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                                for path in sorted(evidence.iterdir()) if path.is_file()}
        save_json(evidence / "summary.json", summary)
    print(json.dumps({"status": summary["status"], "evidence": str(evidence)}))
    return 0 if summary["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
