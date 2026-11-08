#!/usr/bin/env python3
"""Real catalogue PUT boundaries and fixed-intent recovery, using production APIs."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import select
import shutil
import sys
import tempfile
import time

from lifecycle_contract import LifecycleSuite, accepted, refused, require, save_json


PROFILE = {"quota_bytes": 4 * 1024 * 1024, "retention_entries": 32,
           "retention_result_bytes": 128 * 1024 * 1024}
PILOTS = ("prepare", "resume", "abort_missing", "abort_provisioning", "abort_foreign", "delete")
CUTS = ("before_forward", "after_backend", "after_consumed")
CATALOGUE_MUTATIONS = {"catalogue_prepare", "catalogue_resume", "catalogue_abort", "catalogue_delete"}
QUERY = "SELECT id,label,token FROM events ORDER BY id"
SCHEMA = [{"sql": "CREATE TABLE events(id INTEGER PRIMARY KEY,label TEXT NOT NULL,token INTEGER NOT NULL)"}]


def name_key(deployment, tenant, name):
    suffix = hashlib.sha256(name.encode("utf-8")).hexdigest()
    return f"scap-object/v1/{deployment}/{tenant}/catalogue/v1/name/{suffix}"


def head_key(scope):
    return "scap-object/v1/{deployment}/{tenant}/{database}/head".format(**scope)


class CatalogueSuite(LifecycleSuite):
    """Reuse process/ledger mechanics, never lifecycle scenario expectations."""
    def __init__(self, support, arguments, evidence, private, compute, backend, proxy,
                 workers, config, compiled):
        self.support, self.arguments, self.evidence = support, arguments, evidence
        self.private, self.compute, self.backend, self.proxy = private, compute, backend, proxy
        self.workers, self.config = workers, config
        self.counter = self.worker_number = self.nonce = 0
        self.call_labels, self.pending_calls = set(), {}
        self.intents, self.catalogue_intents, self.acks, self.cases, self.cancellations = {}, {}, [], [], {}
        self.descriptor_acks = {}
        self.started_worker_count = 0
        self.deployment = secrets.randbits(62) + 1
        self.paths = {kind: evidence / f"catalogue-{kind}-ledger.jsonl" for kind in ("input", "client", "ack")}
        self.paths["facts"] = evidence / "catalogue-facts.jsonl"
        for path in self.paths.values(): path.touch(mode=0o600, exist_ok=False)
        save_json(evidence / "catalogue-plan.json", {"version": 1, "deployment": self.deployment,
            "pilot_profiles": list(PILOTS), "cut_stages": list(CUTS), "fixture_limits": PROFILE,
            "head_format": 4, "immutable_format": 2, "catalogue_record_bytes": 65536,
            "binary_sha256": compiled["binary"]["sha256"], "input_sha256": compiled["input_sha256"],
            "aws_endpoint_gate": "NOT_RUN", "unit_coverage_contribution": False})
        self.fact(None, "build_verified", stage="before", binary_sha256=compiled["binary"]["sha256"],
                  input_sha256=compiled["input_sha256"])

    def new_case(self, case_id, profile, **metadata):
        require(all(case["id"] != case_id for case in self.cases), "duplicate case identity")
        number = len(self.cases) + 1
        scope = {"deployment": self.deployment, "tenant": 1, "database": number,
                 "incarnation": 1, "generation": 1}
        case = {"id": case_id, "profile": profile, "scope": scope,
                "directory": self.compute / case_id, "workers": [], "ordinal": number,
                "creation": None, "sql": [], "terminal": None, **metadata}
        case["directory"].mkdir(mode=0o700)
        case["create_input"] = {"name": "目录-" + case_id, "operation": 100000 + number,
                                "expected_name_revision": None, "options": {"quota": {"kind": "default"}}}
        case["name_key"] = name_key(self.deployment, 1, case["create_input"]["name"])
        self.cases.append(case)
        self.fact(case, "case_started", profile=profile, input=case["create_input"], **metadata)
        case["owner"] = self.spawn(case)
        return case

    def spawn(self, case, principal=17, scope=None, provision=True):
        self.worker_number += 1
        number = 50000 + self.worker_number
        config = {**self.config, "scope": scope or case["scope"], "principal": principal,
                  "provision": provision, "worker": number, "cache_root": str(case["directory"]),
                  "fixture_limits": PROFILE, "resource_log": None}
        worker = self.support.Worker(self.arguments.worker.resolve(), config, self.private, number, self.evidence)
        self.workers.append(worker); case["workers"].append(worker)
        self.started_worker_count += 1
        self.fact(case, "worker_started", worker=number, principal=principal, provision=provision,
                  scope=config["scope"], identity=worker.identity, binary=worker.binary)
        return worker

    def begin(self, *args, **kwargs):
        pending = super().begin(*args, **kwargs)
        self.pending_calls[pending["worker"].config["worker"]] = pending
        return pending

    def finish(self, pending):
        response = super().finish(pending)
        call = pending["call"]
        del self.pending_calls[call["worker"]]
        if call["command"]["op"] in CATALOGUE_MUTATIONS and response["ok"] is True:
            self.append("ack", "catalogue_ack", call_id=call["call_id"], case=call["case"],
                        intent_id=call["intent_id"], response=response)
            if call["command"]["op"] == "catalogue_prepare":
                previous = self.descriptor_acks.setdefault(call["intent_id"], {"case": call["case"], "value": response["value"]})
                require(previous["value"] == response["value"], "same prepare changed its complete immutable descriptor result")
        return response

    def lose_compute(self, case, stage):
        lost = [self.pending_calls[worker.config["worker"]] for worker in case["workers"]
                if worker.config["worker"] in self.pending_calls]
        super().lose_compute(case, stage)
        for pending in lost:
            call = pending["call"]
            self.append("client", "lost", call_id=call["call_id"], outcome="unknown",
                        worker=call["worker"], reason="verified_compute_sigkill", response_observed=False)
            del self.pending_calls[call["worker"]]

    def cat(self, case, worker, label, operation, *, key=None, begin=False, **values):
        command = {"op": operation, **values}
        context = {"deployment": worker.config["scope"]["deployment"],
                   "tenant": worker.config["scope"]["tenant"], "principal": worker.config["principal"]}
        intent_id = case["id"] + "/" + (key or label)
        record = {"intent_id": intent_id, "case": case["id"], "context": context, "command": command}
        if intent_id in self.catalogue_intents:
            require(self.catalogue_intents[intent_id] == record, "explicit reentry changed its saved input")
        else:
            self.append("input", "catalogue_input", **copy.deepcopy(record))
            self.catalogue_intents[intent_id] = copy.deepcopy(record)
        method = self.begin if begin else self.call
        return method(case, worker, label, operation, intent=record, **values)

    def prepared(self, case, worker, label="prepare"):
        value = accepted(self.cat(case, worker, label, "catalogue_prepare", key="create", input=case["create_input"]))
        creation = value["creation"]
        require(case["creation"] is None or creation == case["creation"], "create operation allocated another identity")
        case["creation"] = creation
        case["scope"] = creation["scope"]
        case["head_key"] = head_key(creation["scope"])
        self.fact(case, "creation_observed", call_label=label, creation=creation)
        return value

    def inspect(self, case, worker, label):
        return self.cat(case, worker, label, "catalogue_inspect",
                        create_operation=case["create_input"]["operation"])

    def resume(self, case, worker, label, *, begin=False):
        return self.cat(case, worker, label, "catalogue_resume", key="resume", creation=case["creation"], begin=begin)

    def held_call(self, case, worker, label, operation, *, selector, stage="before_forward", key=None, **values):
        rule = self.proxy.arm("hold", method="PUT", stage=stage,
                              expected_status=200 if stage == "after_upstream_response" else None, **selector)
        pending = self.cat(case, worker, label, operation, key=key, begin=True, **values)
        require(rule.arrived.wait(8), "catalogue candidate did not reach selected PUT")
        self.fact(case, "boundary", label=label, call_id=pending["call"]["call_id"],
                  observation=rule.observation, payload=list(rule.payload))
        return rule, pending

    def release_call(self, case, rule, pending):
        self.proxy.set_phase(pending["call"]["phase"])
        self.fact(case, "release", call_id=pending["call"]["call_id"], request_serial=rule.observation["request_serial"])
        rule.release.set()
        return self.finish(pending)

    def stopped_at(self, case, state):
        """Obtain an actual intermediate state by losing a production resume call."""
        selector = {"key": case["name_key"], "occurrence": 1 if state == "reserved" else 2} if state != "provisioning" else {"key": case["head_key"]}
        rule, pending = self.held_call(case, case["owner"], "setup." + state, "catalogue_resume",
                                       key="resume", creation=case["creation"], selector=selector,
                                       stage="after_upstream_response")
        self.lose_compute(case, "setup." + state)
        rule.abort(); require(rule.finished.wait(5), "setup cut did not finish suppressing response")
        case["directory"].mkdir(mode=0o700)
        case["owner"] = self.spawn(case)
        found = accepted(self.cat(case, case["owner"], "setup.inspect." + state, "catalogue_inspect",
                                  create_operation=case["create_input"]["operation"]))
        require(found["phase"] == state, "actual setup phase differs from the requested intermediate state")
        self.fact(case, "intermediate_verified", phase=state, creation=case["creation"])

    def setup_profile(self, case):
        profile = case["profile"]
        if profile == "prepare": return
        self.prepared(case, case["owner"])
        if profile == "resume": return
        if profile.startswith("abort_"):
            self.stopped_at(case, "provisioning" if profile == "abort_provisioning" else "reserved")
            if profile == "abort_foreign": self.foreign(case, "incarnation", "ready")
            case["control"] = {"creation": case["creation"], "operation": 200000 + case["ordinal"],
                               "expected_name_revision": 1, "nonce": 300000 + case["ordinal"]}
        elif profile == "delete":
            require(accepted(self.resume(case, case["owner"], "setup.ready"))["phase"] == "ready", "create did not become Ready")
            self.seed(case)
            current = accepted(self.call(case, case["owner"], "setup.delete_status", "status"))
            case["control"] = {"creation": case["creation"], "operation": 200000 + case["ordinal"],
                               "expected_name_revision": 2, "expected_head_revision": current["revision"],
                               "nonce": 300000 + case["ordinal"]}
        else: raise ValueError("unknown pilot profile")

    def target(self, case, label, *, begin=False):
        worker, profile = case["owner"], case["profile"]
        if profile == "prepare":
            return self.cat(case, worker, label, "catalogue_prepare", key="create", input=case["create_input"], begin=begin)
        if profile == "resume": return self.resume(case, worker, label, begin=begin)
        operation = "catalogue_abort" if profile.startswith("abort_") else "catalogue_delete"
        return self.cat(case, worker, label, operation, key="control", input=case["control"], begin=begin)

    def seed(self, case, creation=None, prefix="sql"):
        target = creation or case["creation"]
        owner = self.spawn(case, scope=target["scope"])
        case["owner"] = owner
        accepted(self.control(case, owner, prefix + ".takeover", "takeover"))
        accepted(self.control(case, owner, prefix + ".activate", "activate"))
        sql = [{"sql": "INSERT INTO events VALUES(1,?,random()) RETURNING id,label,token",
                "parameters": [{"type": "text", "value": case["id"] + ":" + prefix}]}]
        for name, number, statements in (("schema", 1, SCHEMA), ("seed", 2, sql)):
            intent = self.prepare(case, owner, prefix + "." + name, 1, number, statements)
            case["sql"].append(intent["intent_id"])
            accepted(self.execute(case, owner, prefix + "." + name, intent))

    def foreign(self, case, variant, lifecycle):
        scope = dict(case["creation"]["scope"])
        if variant in ("incarnation", "generation"):
            scope[variant] = 2 if scope[variant] != 2 else 3
        worker = self.spawn(case, scope=scope)
        accepted(self.call(case, worker, "foreign.create", "create", nonce=91))
        if lifecycle != "ready": accepted(self.control(case, worker, "foreign.lifecycle", "set_lifecycle", lifecycle=lifecycle))
        raw = accepted(self.call(case, worker, "foreign.before", "store_get", key=case["head_key"]))
        case["foreign"] = {"scope": scope, "snapshot": raw, "lifecycle": lifecycle, "variant": variant}
        self.fact(case, "foreign_occupied", scope=scope, snapshot=raw, lifecycle=lifecycle, variant=variant)

    def finish_profile(self, case, label="converge"):
        if case["profile"] == "prepare":
            self.prepared(case, case["owner"], label + ".prepare")
            value = accepted(self.resume(case, case["owner"], label + ".resume"))
            terminal = "ready"
        else:
            value = accepted(self.target(case, label + ".original"))
            terminal = "aborted" if case["profile"].startswith("abort_") else "deleted" if case["profile"] == "delete" else "ready"
        require(value["phase"] == terminal, "explicit original-intent convergence did not reach its expected terminal")
        case["terminal"] = terminal
        if terminal == "ready" and not case["sql"]: self.seed(case)
        self.fact(case, "case_terminal", phase=terminal)

    def pilot(self, profile):
        case = self.new_case("PILOT-" + profile, profile, kind="pilot")
        self.setup_profile(case)
        call = self.counter + 1
        accepted(self.target(case, "pilot"))
        phase = case["id"] + "/pilot"
        puts = [e for e in self.proxy.observations if e["event"] == "object_request" and e["method"] == "PUT" and e["phase"] == phase]
        require(0 < len(puts) <= 32, "pilot PUT denominator is empty or unbounded")
        selected = [{"ordinal": n, "path": e["path"], "request_serial": e["request_serial"],
                     "request_sha256": e["request_sha256"], "if_match": e["if_match"], "if_none_match": e["if_none_match"]}
                    for n, e in enumerate(puts, 1)]
        self.finish_profile(case)
        self.recover_then_stop(case)
        return {"profile": profile, "case": case["id"], "call_id": call, "puts": selected}

    def cut(self, profile, ordinal, stage):
        case = self.new_case(f"CUT-{profile}-{ordinal:02d}-{stage}", profile,
                             kind="cut", put_ordinal=ordinal, cut_stage=stage)
        self.setup_profile(case)
        rule = self.proxy.arm("cut" if stage != "after_consumed" else "hold", method="PUT", occurrence=ordinal,
                              stage="before_forward" if stage == "before_forward" else "after_upstream_response",
                              expected_status=None if stage == "before_forward" else 200)
        pending = self.target(case, "cut", begin=True)
        require(rule.arrived.wait(8), "target ordinal did not reach a real backend boundary")
        self.fact(case, "cut_observed", call_id=pending["call"]["call_id"], stage=stage,
                  observation=rule.observation, payload=list(rule.payload))
        next_rule = None
        if stage == "after_consumed":
            next_rule = self.proxy.arm("cut", method="GET", stage="before_forward")
            rule.release.set()
            bound = time.monotonic() + 8
            while not next_rule.arrived.is_set() and not select.select([pending["worker"].process.stdout], [], [], 0)[0]:
                require(time.monotonic() < bound, "no proof of consumed PUT response")
                time.sleep(0.002)
            require(rule.finished.wait(5), "delivered PUT observation did not finish before consumption witness")
            if next_rule.arrived.is_set():
                self.fact(case, "response_consumed", call_id=pending["call"]["call_id"],
                          proof="subsequent_get", request_serial=rule.observation["request_serial"],
                          subsequent=next_rule.observation)
            else:
                response = self.finish(pending)
                self.fact(case, "response_consumed", call_id=pending["call"]["call_id"],
                          proof="complete_worker_response", request_serial=rule.observation["request_serial"], response=response)
        self.lose_compute(case, "fault")
        if stage != "after_consumed": rule.abort()
        if next_rule is not None:
            next_rule.abort()
            if next_rule.arrived.is_set(): require(next_rule.finished.wait(5), "post-consumption GET cut did not finish")
        require(rule.finished.wait(5), "target cut did not finish")
        self.proxy.clear()
        case["directory"].mkdir(mode=0o700)
        case["owner"] = self.spawn(case)
        self.fact(case, "explicit_reentry", stage="after_fault", worker=case["owner"].config["worker"])
        self.finish_profile(case)
        self.recover_then_stop(case)

    def recover(self, case, stage):
        case["directory"].mkdir(mode=0o700)
        worker = self.spawn(case)
        case["owner"] = worker
        self.fact(case, "recovery_started", stage=stage, worker=worker.config["worker"])
        for ordinal, (identity, descriptor) in enumerate(list(self.descriptor_acks.items())):
            if descriptor["case"] != case["id"]: continue
            original = self.catalogue_intents[identity]
            caller = original["context"]
            observer = worker if caller["principal"] == worker.config["principal"] and caller["tenant"] == worker.config["scope"]["tenant"] else self.spawn(case, principal=caller["principal"], scope=descriptor["value"]["creation"]["scope"])
            verified = accepted(self.cat(case, observer, f"{stage}.descriptor.{ordinal}", "catalogue_prepare",
                                         key=identity.split("/", 1)[1], input=original["command"]["input"]))
            require(verified == descriptor["value"], "cold prepare changed a previously acknowledged descriptor")
        inspected = self.cat(case, worker, stage + ".inspect", "catalogue_inspect",
                             create_operation=case["create_input"]["operation"])
        resolved = self.cat(case, worker, stage + ".resolve", "catalogue_resolve", name=case["creation"]["name"])
        if case.get("corrupt"):
            refused(inspected, "Corrupt"); refused(resolved, "Corrupt")
            refused(self.resume(case, worker, stage + ".resume_corrupt"), "Corrupt")
            if "corrupt_control" in case:
                operation = "catalogue_delete" if "expected_head_revision" in case["corrupt_control"] else "catalogue_abort"
                refused(self.cat(case, worker, stage + ".control_corrupt", operation,
                                 key="corrupt.control", input=case["corrupt_control"]), "Corrupt")
            self.fact(case, "recovery_observed", stage=stage)
            return
        observed = accepted(inspected)
        require(observed["creation"] == case["creation"] and observed["phase"] == case["terminal"], "cold creation progress changed identity/terminal")
        live = []
        if case.get("successor"):
            require(accepted(resolved)["creation"] == case["successor"], "resolve redirected to old identity")
            live.append(case["successor"])
        elif case["terminal"] == "ready":
            require(accepted(resolved)["creation"] == case["creation"], "resolved another creation")
            live.append(case["creation"])
        else:
            refused(resolved, "NotFound")
        if "control" in case:
            operation = "catalogue_delete" if "expected_head_revision" in case["control"] else "catalogue_abort"
            actor = case.get("control_principal", 17)
            controller = worker if actor == 17 else self.spawn(case, principal=actor, provision=case.get("control_provision", True))
            result = self.cat(case, controller, stage + ".control", operation, key="control", input=case["control"])
            if case.get("control_error"): refused(result, case["control_error"])
            else:
                value = accepted(result)
                require(value["phase"] == case.get("control_phase", case["terminal"]), "original control did not survive compute loss")
        verified_scopes = set()
        for ordinal, creation in enumerate(live):
            reader = worker if worker.config["scope"] == creation["scope"] else self.spawn(case, scope=creation["scope"])
            prefix = f"{stage}.live.{ordinal}"
            accepted(self.control(case, reader, prefix + ".takeover", "takeover"))
            accepted(self.control(case, reader, prefix + ".activate", "activate_session", directory=prefix + "-session"))
            accepted(self.call(case, reader, prefix + ".rows", "session_query", sql=QUERY))
            verified_scopes.add(json.dumps(creation["scope"], sort_keys=True))
            for intent_id in case["sql"]:
                intent = self.intents[intent_id]
                if intent["scope"] != creation["scope"]: continue
                accepted(self.resolution(case, reader, stage + ".lookup." + intent["name"], intent))
                accepted(self.execute(case, reader, stage + ".replay." + intent["name"], intent))
        for intent_id in case["sql"]:
            intent = self.intents[intent_id]
            if json.dumps(intent["scope"], sort_keys=True) in verified_scopes: continue
            old = worker if worker.config["scope"] == intent["scope"] else self.spawn(case, scope=intent["scope"])
            refused(self.resolution(case, old, stage + ".deleted." + intent["name"], intent), "Lifecycle")
        if "foreign" in case:
            after = accepted(self.call(case, worker, stage + ".foreign", "store_get", key=case["head_key"]))
            require(after == case["foreign"]["snapshot"], "foreign HEAD bytes or ETag changed")
        self.fact(case, "recovery_observed", stage=stage)

    def recover_then_stop(self, case):
        self.lose_compute(case, "compute_recovery")
        self.recover(case, "compute_recovery")
        self.lose_compute(case, "before_backend")

    def run(self):
        self.fact(None, "backend_started", identities=self.backend.identities())
        pilots = [self.pilot(profile) for profile in PILOTS]
        save_json(self.evidence / "catalogue-cut-plan.json", {"pilots": pilots, "cut_stages": list(CUTS)})
        for pilot in pilots:
            for put in pilot["puts"]:
                for stage in CUTS: self.cut(pilot["profile"], put["ordinal"], stage)
        self.structural_cases()
        require(not self.workers, "backend restart requires zero actual compute workers")
        self.fact(None, "backend_stopping", live_compute_workers=0)
        stopped = self.backend.stop(verify=True)
        self.fact(None, "backend_stopped", identities=stopped, live_compute_workers=0)
        self.backend.start()
        self.fact(None, "backend_restarted", identities=self.backend.identities())
        for case in self.cases:
            self.recover(case, "backend_recovery")
            self.lose_compute(case, "final_cleanup")

    def structural_cases(self):
        for same in (False, True): self.creation_race(same)
        for winner in ("bind", "abort"): self.binding_race(winner)
        for winner in ("provision", "tombstone"): self.absent_head_race(winner)
        for operation in ("abort", "delete"):
            for outcome in ("conflict", "unknown"): self.control_admission(operation, outcome)
        for variant in ("incarnation", "generation", "direct"):
            for lifecycle in ("ready", "maintenance", "deleted"): self.foreign_case(variant, lifecycle)
        for damage in ("missing_descriptor", "descriptor_hash", "descriptor_scope"):
            self.foreign_provenance(damage)
        for damage in ("missing", "malformed", "format", "physical_key"): self.corruption_case(damage)
        self.abort_boundaries()
        self.authorization_case()
        self.reuse_case()
        self.ready_reentry()
        self.provisioning_case()
        self.invalid_case()

    def terminal(self, case, phase):
        case["terminal"] = phase
        if phase == "ready" and not case["sql"]: self.seed(case)
        self.fact(case, "case_terminal", phase=phase)
        self.recover_then_stop(case)

    def creation_race(self, same):
        case = self.new_case("CAT-01-" + ("same" if same else "different"), "resume", kind="creation_race", same_intent=same)
        self.setup_profile(case)
        left = case["owner"]
        right = self.spawn(case, principal=17 if same else 18)
        if same: other = case["creation"]
        else:
            value = {**case["create_input"], "operation": case["create_input"]["operation"] + 1000000}
            other = accepted(self.cat(case, right, "other.prepare", "catalogue_prepare", key="other.create", input=value))["creation"]
        first, pending = self.held_call(case, left, "left.reserve", "catalogue_resume", key="resume", creation=case["creation"], selector={"key": case["name_key"]})
        second, competing = self.held_call(case, right, "right.reserve", "catalogue_resume", key="resume" if same else "other.resume", creation=other, selector={"key": case["name_key"]})
        require(accepted(self.release_call(case, first, pending))["phase"] == "ready", "first reservation failed")
        refused(self.release_call(case, second, competing), "Conflict")
        value = accepted(self.cat(case, right, "right.explicit_reentry", "catalogue_resume", key="resume" if same else "other.resume", creation=other))
        require(value["phase"] == ("ready" if same else "name_conflict"), "reservation loser was misclassified")
        case["owner"] = left
        self.terminal(case, "ready")

    def binding_race(self, winner):
        case = self.new_case("CAT-02-" + winner, "abort_provisioning", kind="binding_race", winner=winner)
        self.setup_profile(case)
        resumer, aborter = case["owner"], self.spawn(case)
        binding, pending = self.held_call(case, resumer, "bind.candidate", "catalogue_resume", key="resume", creation=case["creation"], selector={"key": case["name_key"]})
        aborting, competing = self.held_call(case, aborter, "abort.candidate", "catalogue_abort", key="control", input=case["control"], selector={"key": case["name_key"]})
        require(binding.observation["if_match"] == aborting.observation["if_match"], "bind/abort did not use the same Reserved ETag")
        if winner == "bind":
            require(accepted(self.release_call(case, binding, pending))["phase"] == "ready", "bind did not win")
            refused(self.release_call(case, aborting, competing), "Conflict")
            value = accepted(self.cat(case, aborter, "abort.after_bound", "catalogue_abort", key="control", input=case["control"]))
            require(value["phase"] == "cannot_abort_bound", "Bound was cancelled")
            case["control_phase"] = "cannot_abort_bound"
            self.terminal(case, "ready")
        else:
            require(accepted(self.release_call(case, aborting, competing))["phase"] == "aborted", "abort did not win")
            refused(self.release_call(case, binding, pending), "Conflict")
            require(accepted(self.resume(case, resumer, "resume.after_abort"))["phase"] == "aborted", "cancelled creation became ready")
            self.terminal(case, "aborted")

    def absent_head_race(self, winner):
        case = self.new_case("CAT-03-" + winner, "abort_missing", kind="absent_head_race", winner=winner)
        self.setup_profile(case)
        resumer, aborter = case["owner"], self.spawn(case)
        provision, pending = self.held_call(case, resumer, "provision.candidate", "catalogue_resume", key="resume", creation=case["creation"], selector={"key": case["head_key"]})
        if winner == "tombstone":
            require(accepted(self.cat(case, aborter, "abort.wins", "catalogue_abort", key="control", input=case["control"]))["phase"] == "aborted", "absent tombstone did not win")
            refused(self.release_call(case, provision, pending), "Conflict")
        else:
            tombstone, competing = self.held_call(case, aborter, "tombstone.candidate", "catalogue_abort", key="control", input=case["control"], selector={"key": case["head_key"]})
            require(provision.observation["if_none_match"] == tombstone.observation["if_none_match"] == "*", "absent HEAD race changed its condition")
            result = self.release_call(case, provision, pending)
            require((result["ok"] and result["value"]["phase"] == "aborting") or
                    (not result["ok"] and result["error"] == "Conflict"), "late provision escaped Aborting")
            refused(self.release_call(case, tombstone, competing), "Conflict")
            require(accepted(self.cat(case, aborter, "abort.explicit_reentry", "catalogue_abort", key="control", input=case["control"]))["phase"] == "aborted", "own Provisioning was not fenced")
        self.terminal(case, "aborted")

    def changed_control(self, case, worker):
        original = case["control"]
        fields = ["nonce", "expected_name_revision"] + (["expected_head_revision"] if "expected_head_revision" in original else [])
        operation = "catalogue_delete" if "expected_head_revision" in original else "catalogue_abort"
        for field in fields:
            changed = {**original, field: original[field] + 1}
            refused(self.cat(case, worker, "changed." + field, operation, input=changed), "Conflict")
        auxiliary = {**case["create_input"], "name": case["create_input"]["name"] + "-other", "operation": case["create_input"]["operation"] + 1000000}
        creation = accepted(self.cat(case, worker, "changed.target.prepare", "catalogue_prepare", input=auxiliary))["creation"]
        refused(self.cat(case, worker, "changed.creation", operation, input={**original, "creation": creation}), "Conflict")

    def control_admission(self, operation, outcome):
        profile = "abort_provisioning" if operation == "abort" else "delete"
        case = self.new_case(f"CAT-04-{operation}-{outcome}", profile, kind="control_admission", control_kind=operation, outcome=outcome)
        self.setup_profile(case)
        owner = case["owner"]
        key = case["name_key"] if operation == "abort" else case["head_key"]
        command = "catalogue_" + operation
        if outcome == "unknown":
            self.proxy.arm("drop", method="PUT", key=key)
            refused(self.cat(case, owner, "control.lost", command, key="control", input=case["control"]), "Unknown")
        else:
            rule, pending = self.held_call(case, owner, "control.candidate", command, key="control", input=case["control"], selector={"key": key})
            competitor = self.spawn(case)
            if operation == "abort":
                require(accepted(self.resume(case, competitor, "control.conflicting_bind"))["phase"] == "ready", "competing bind failed")
            else:
                accepted(self.control(case, competitor, "control.conflicting_quota", "set_quota", quota={"max_bytes": 8 * 1024 * 1024}))
            refused(self.release_call(case, rule, pending), "Conflict")
        self.changed_control(case, owner)
        if operation == "abort" and outcome == "conflict":
            value = accepted(self.cat(case, owner, "control.fixed_reentry", command, key="control", input=case["control"]))
            require(value["phase"] == "cannot_abort_bound", "fixed abort acquired new bound condition")
            case["control_phase"] = "cannot_abort_bound"
            self.terminal(case, "ready")
        elif operation == "delete" and outcome == "conflict":
            refused(self.cat(case, owner, "control.fixed_reentry", command, key="control", input=case["control"]), "Conflict")
            # Keep the original immutable rejection for recovery; no new control is inferred.
            case["control_error"] = "Conflict"
            self.terminal(case, "ready")
        else:
            expected = "aborted" if operation == "abort" else "deleted"
            require(accepted(self.cat(case, owner, "control.fixed_reentry", command, key="control", input=case["control"]))["phase"] == expected, "fixed UNKNOWN control did not converge")
            self.terminal(case, expected)

    def reuse(self, case):
        worker = case["owner"]
        old = accepted(self.call(case, worker, "reuse.tombstone", "store_get", key=case["name_key"]))
        binding = json.loads(bytes(old["bytes"]))
        require(binding["state"] == "tombstone", "name reuse requires an actual tombstone")
        input = {**case["create_input"], "operation": case["create_input"]["operation"] + 1000000,
                 "expected_name_revision": binding["revision"]}
        successor = accepted(self.cat(case, worker, "successor.prepare", "catalogue_prepare", key="successor.create", input=input))["creation"]
        require(accepted(self.cat(case, worker, "successor.resume", "catalogue_resume", key="successor.resume", creation=successor))["phase"] == "ready", "new name identity did not become Ready")
        case["successor"] = successor
        self.seed(case, successor, "successor.sql")
        return successor

    def foreign_case(self, variant, lifecycle):
        case = self.new_case(f"CAT-05-{variant}-{lifecycle}", "abort_missing", kind="foreign", variant=variant, foreign_lifecycle=lifecycle)
        self.setup_profile(case)
        self.foreign(case, variant, lifecycle)
        conflict = accepted(self.resume(case, case["owner"], "foreign.resume"))
        require(conflict["phase"] == "identity_conflict" and conflict["head_revision"] is None,
                "foreign occupancy was mistaken for this creation's HEAD")
        require(accepted(self.target(case, "foreign.abort"))["phase"] == "aborted", "foreign occupation was not permanently proven")
        self.reuse(case)
        before = accepted(self.call(case, case["owner"], "successor.before_old", "store_get", key=head_key(case["successor"]["scope"])))
        require(accepted(self.target(case, "foreign.old_abort"))["phase"] == "aborted", "old foreign abort lost its permanent proof")
        # A rejected new control can still durably reserve its operation ID.
        # Keep this alternate in a disjoint fixture namespace: +1 would alias
        # the primary control of the next case under the same caller/kind.
        changed = {**case["control"], "operation": case["control"]["operation"] + 1000000,
                   "nonce": case["control"]["nonce"] + 1000000}
        refused(self.cat(case, case["owner"], "foreign.other_abort", "catalogue_abort", input=changed), "Conflict")
        after = accepted(self.call(case, case["owner"], "successor.after_old", "store_get", key=head_key(case["successor"]["scope"])))
        require(before == after, "old abort modified successor HEAD")
        self.terminal(case, "aborted")

    def foreign_provenance(self, damage):
        """Deliberate invalid provenance, never a claimed valid named collision."""
        case = self.new_case("CAT-05-provenance-" + damage, "abort_missing",
                             kind="foreign_provenance", damage=damage)
        self.setup_profile(case)
        self.foreign(case, "incarnation", "ready")
        worker = case["owner"]
        original = case["foreign"]["snapshot"]
        alternate = {**case["create_input"], "name": case["create_input"]["name"] + "-origin",
                     "operation": case["create_input"]["operation"] + 1000000}
        descriptor_key = (f"scap-object/v1/{self.deployment}/1/catalogue/v1/create/17/"
                          + str(alternate["operation"]))
        if damage == "missing_descriptor":
            refused(self.call(case, worker, "provenance.missing_descriptor", "store_get", key=descriptor_key), "Missing")
            descriptor_hash = "0" * 64
        else:
            accepted(self.cat(case, worker, "provenance.real_prepare", "catalogue_prepare", input=alternate))
            descriptor = accepted(self.call(case, worker, "provenance.real_descriptor", "store_get", key=descriptor_key))
            descriptor_hash = hashlib.sha256(bytes(descriptor["bytes"])).hexdigest()
            if damage == "descriptor_hash":
                descriptor_hash = ("0" if descriptor_hash[0] != "0" else "1") + descriptor_hash[1:]
        damaged = json.loads(bytes(original["bytes"]))
        damaged["creation"] = {"creator": 17, "operation": alternate["operation"],
                               "name_hash": hashlib.sha256(alternate["name"].encode()).hexdigest(),
                               "descriptor_hash": descriptor_hash}
        payload = json.dumps(damaged, ensure_ascii=False, separators=(",", ":")).encode()
        self.fact(case, "damage_invoked", kind=damage, key=case["head_key"], payload=list(payload))
        accepted(self.call(case, worker, "provenance.damage", "store_put", key=case["head_key"],
                           bytes=list(payload), etag=original["etag"]))
        refused(self.inspect(case, worker, "provenance.inspect"), "Corrupt")
        refused(self.resume(case, worker, "provenance.resume"), "Corrupt")
        case["corrupt_control"] = case.pop("control")
        refused(self.cat(case, worker, "provenance.abort", "catalogue_abort",
                         key="corrupt.control", input=case["corrupt_control"]), "Corrupt")
        refused(self.cat(case, worker, "provenance.resolve", "catalogue_resolve", name=case["creation"]["name"]), "Corrupt")
        case["corrupt"] = True
        self.terminal(case, "corrupt")

    def corruption_case(self, damage):
        case = self.new_case("CAT-06-" + damage, "resume", kind="corruption", damage=damage)
        self.setup_profile(case); self.stopped_at(case, "bound")
        worker = case["owner"]
        original = accepted(self.call(case, worker, "damage.before", "store_get", key=case["head_key"]))
        if damage == "missing":
            self.fact(case, "damage_invoked", kind="delete", key=case["head_key"])
            require(self.backend.signed("DELETE", "/scap-test/" + case["head_key"]), "fixture HEAD deletion failed")
            self.fact(case, "damage_observed", kind="delete", key=case["head_key"])
            refused(self.call(case, worker, "damage.missing_get", "store_get", key=case["head_key"]), "Missing")
        else:
            if damage == "malformed": payload = b"not-a-valid-head"
            elif damage == "format":
                value = json.loads(bytes(original["bytes"])); value["format"] = 999
                payload = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
            else:
                scope = dict(case["scope"]); scope["database"] = 1 if scope["database"] != 1 else 2
                other = self.spawn(case, scope=scope)
                accepted(self.call(case, other, "damage.other_create", "create", nonce=92))
                payload = bytes(accepted(self.call(case, other, "damage.other_head", "store_get", key=head_key(scope)))["bytes"])
            self.fact(case, "damage_invoked", kind=damage, key=case["head_key"], payload=list(payload))
            accepted(self.call(case, worker, "damage.put", "store_put", key=case["head_key"], bytes=list(payload), etag=original["etag"]))
        refused(self.inspect(case, worker, "damage.inspect"), "Corrupt")
        refused(self.resume(case, worker, "damage.resume"), "Corrupt")
        refused(self.cat(case, worker, "damage.resolve", "catalogue_resolve", name=case["creation"]["name"]), "Corrupt")
        case["corrupt_control"] = {"creation": case["creation"], "operation": 200000 + case["ordinal"],
                                   "expected_name_revision": 2, "expected_head_revision": json.loads(bytes(original["bytes"]))["revision"],
                                   "nonce": 300000 + case["ordinal"]}
        refused(self.cat(case, worker, "damage.delete", "catalogue_delete",
                         key="corrupt.control", input=case["corrupt_control"]), "Corrupt")
        case["corrupt"] = True
        self.terminal(case, "corrupt")

    def abort_boundaries(self):
        case = self.new_case("CAT-07-boundaries", "resume", kind="abort_boundaries")
        self.setup_profile(case)
        case["control"] = {"creation": case["creation"], "operation": 200000 + case["ordinal"], "expected_name_revision": 1, "nonce": 300000 + case["ordinal"]}
        value = accepted(self.cat(case, case["owner"], "abort.not_reserved", "catalogue_abort", key="control", input=case["control"]))
        require(value["phase"] == "not_reserved", "descriptor-only abort became Aborted")
        self.stopped_at(case, "bound")
        value = accepted(self.cat(case, case["owner"], "abort.bound", "catalogue_abort", key="control", input=case["control"]))
        require(value["phase"] == "cannot_abort_bound", "Bound creation was cancelled")
        case["control_phase"] = "cannot_abort_bound"
        require(accepted(self.resume(case, case["owner"], "bound.complete"))["phase"] == "ready", "Bound completion failed")
        self.terminal(case, "ready")

    def authorization_case(self):
        case = self.new_case("CAT-08-authorization", "delete", kind="authorization")
        self.setup_profile(case)
        owner = case["owner"]
        admin = self.spawn(case, principal=18, provision=False)
        outsider = self.spawn(case, principal=19, provision=False)
        permissions = [{"principal": 17, "read": True, "write": True, "admin": False},
                       {"principal": 18, "read": True, "write": True, "admin": True}]
        head = accepted(self.control(case, owner, "grant.other_admin", "set_policy", policy=permissions))
        case["control"]["expected_head_revision"] = head["revision"]
        refused(self.cat(case, outsider, "delete.denied", "catalogue_delete", input=case["control"]), "Denied")
        refused(self.cat(case, admin, "resume.no_provision", "catalogue_resume", creation=case["creation"]), "Denied")
        creator_other = self.spawn(case, principal=18, provision=True)
        abort = {"creation": case["creation"], "operation": 400000 + case["ordinal"], "expected_name_revision": 1, "nonce": 500000 + case["ordinal"]}
        refused(self.cat(case, creator_other, "abort.non_creator", "catalogue_abort", input=abort), "Denied")
        case["control_principal"] = 18
        case["control_provision"] = False
        require(accepted(self.cat(case, admin, "delete.other_admin", "catalogue_delete", key="control", input=case["control"]))["phase"] == "deleted", "non-creator ADMIN could not delete")
        self.terminal(case, "deleted")

    def named_candidates(self, case):
        candidates = {}
        for event in self.proxy.observations:
            if event["event"] != "object_request" or event["method"] != "PUT" or not event["phase"].startswith(case["id"] + "/"): continue
            raw = event.get("catalogue_request_bytes", event.get("head_request_bytes"))
            if not raw: continue
            value = json.loads(bytes(raw))
            if event["path"] == "/scap-test/" + case["name_key"] and value.get("creation") == case["creation"] and value.get("state") in ("reserved", "bound"):
                candidates.setdefault(value["state"], event)
            elif event["path"] == "/scap-test/" + case["head_key"] and value.get("lifecycle") == "ready" and (value.get("creation") or {}).get("operation") == case["creation"]["operation"]:
                candidates.setdefault("complete", event)
        require(set(candidates) == {"reserved", "bound", "complete"}, "missing original authority candidates before reuse")
        return candidates

    def reuse_case(self):
        case = self.new_case("CAT-09-reuse", "delete", kind="reuse")
        self.setup_profile(case)
        candidates = self.named_candidates(case)
        require(accepted(self.target(case, "delete.original"))["phase"] == "deleted", "original deletion failed")
        self.reuse(case)
        current = head_key(case["successor"]["scope"])
        before = accepted(self.call(case, case["owner"], "reuse.before_old", "store_get", key=current))
        for name, request in candidates.items():
            raw = request.get("catalogue_request_bytes", request.get("head_request_bytes"))
            refused(self.call(case, case["owner"], "old." + name, "store_put", key=request["path"][len("/scap-test/"):], bytes=raw, etag=request["if_match"]), "Conflict")
        require(accepted(self.resume(case, case["owner"], "old.resume"))["phase"] == "deleted", "old resume redirected to new identity")
        require(accepted(self.target(case, "old.delete"))["phase"] == "deleted", "original delete lost proof")
        old = self.spawn(case, scope=case["creation"]["scope"])
        for intent_id in case["sql"]:
            intent = self.intents[intent_id]
            if intent["scope"] == case["creation"]["scope"]: refused(self.execute(case, old, "old.sql." + intent["name"], intent), "Lifecycle")
        after = accepted(self.call(case, case["owner"], "reuse.after_old", "store_get", key=current))
        require(before == after, "old identity modified successor authority")
        self.terminal(case, "deleted")

    def ready_reentry(self):
        case = self.new_case("CAT-10-ready-reentry", "resume", kind="ready_reentry")
        self.setup_profile(case)
        require(accepted(self.resume(case, case["owner"], "create.ready"))["phase"] == "ready", "create did not become Ready")
        self.seed(case)
        worker = case["owner"]
        accepted(self.control(case, worker, "change.quota", "set_quota", quota={"max_bytes": 8 * 1024 * 1024}))
        permissions = [{"principal": principal, "read": True, "write": True, "admin": True} for principal in (17, 18)]
        accepted(self.control(case, worker, "change.policy", "set_policy", policy=permissions))
        before = accepted(self.call(case, worker, "reentry.before", "store_get", key=case["head_key"]))
        require(accepted(self.resume(case, worker, "reentry.original"))["phase"] == "ready", "Ready reentry failed")
        after = accepted(self.call(case, worker, "reentry.after", "store_get", key=case["head_key"]))
        require(before == after, "Ready reentry reset current data/policy/quota")
        for label, changed in (("name", {**case["create_input"], "name": "another-name"}),
                               ("quota", {**case["create_input"], "options": {"quota": {"kind": "unlimited"}}})):
            refused(self.cat(case, worker, "identity.changed_" + label, "catalogue_prepare", input=changed), "Conflict")
        wrong = copy.deepcopy(case["creation"]); wrong["scope"]["generation"] += 1
        refused(self.cat(case, worker, "identity.changed_scope", "catalogue_resume", creation=wrong), "Invalid")
        other = self.spawn(case, principal=18)
        refused(self.cat(case, other, "identity.other_principal", "catalogue_resume", creation=case["creation"]), "Denied")
        scope = dict(case["scope"]); scope["tenant"] = 2
        other_tenant = self.spawn(case, scope=scope)
        result = self.cat(case, other_tenant, "identity.other_tenant", "catalogue_resume", creation=case["creation"])
        refused(result, "Invalid")
        self.terminal(case, "ready")

    def provisioning_case(self):
        case = self.new_case("CAT-11-provisioning", "abort_provisioning", kind="provisioning")
        self.setup_profile(case)
        worker = case["owner"]
        intent = self.prepare(case, worker, "blocked.sql", 1, 1, [{"sql": "SELECT 1"}])
        denied = [("status", {}), ("query", {"sql": "SELECT 1", "directory": "denied-query"}),
                  ("session_open", {"directory": "denied-session"}),
                  ("takeover", {"revision": 1, "nonce": 41}), ("activate", {"revision": 1, "nonce": 42}),
                  ("activate_session", {"revision": 1, "nonce": 43, "directory": "denied-activate"}),
                  ("set_policy", {"revision": 1, "nonce": 44, "policy": [{"principal": 17, "read": True, "write": True, "admin": True}]}),
                  ("set_quota", {"revision": 1, "nonce": 45, "quota": {"max_bytes": None}}),
                  ("set_lifecycle", {"revision": 1, "nonce": 46, "lifecycle": "ready"}),
                  ("close_full", {"revision": 1, "nonce": 47})]
        for operation, values in denied: refused(self.call(case, worker, "blocked." + operation, operation, **values), "Lifecycle")
        refused(self.execute(case, worker, "blocked.execute", intent), "Lifecycle")
        for operation in ("lookup_identity", "cancel_identity"): refused(self.resolution(case, worker, "blocked." + operation, intent, operation), "Lifecycle")
        refused(self.call(case, worker, "blocked.create", "create", nonce=48), "Store(Conflict)")
        require(accepted(self.target(case, "provisioning.abort"))["phase"] == "aborted", "Provisioning abort did not fence")
        self.terminal(case, "aborted")

    def invalid_case(self):
        case = self.new_case("CAT-12-invalid", "resume", kind="invalid")
        self.setup_profile(case)
        for label, fields, expected in (("empty", {"name": ""}, "Invalid"), ("control_char", {"name": "bad\0name"}, "Invalid"),
                                        ("long", {"name": "x" * 129}, "Limit"), ("zero", {"operation": 0}, "Invalid"),
                                        ("overflow", {"expected_name_revision": 2 ** 64 - 1}, "Limit")):
            input = {**case["create_input"], "operation": case["create_input"]["operation"] + 1000000, **fields}
            refused(self.cat(case, case["owner"], "invalid." + label, "catalogue_prepare", input=input), expected)
        input = {**case["create_input"], "name": "deadline", "operation": case["create_input"]["operation"] + 2000000}
        result = self.cat(case, case["owner"], "invalid.deadline", "catalogue_prepare", input=input, budget_ms=0)
        require(not result["ok"] and result["error"] == "Unknown", "expired call returned a completed creation")
        require(accepted(self.resume(case, case["owner"], "valid.resume"))["phase"] == "ready", "valid identity could not proceed after refused inputs")
        self.terminal(case, "ready")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("worker", "weed", "build-record", "evidence"): parser.add_argument("--" + name, type=Path, required=True)
    arguments = parser.parse_args(argv)
    evidence = arguments.evidence.resolve()
    evidence.mkdir(parents=True, mode=0o700, exist_ok=False)
    summary = {"status": "blocked", "scope": "private-loopback-real-S3-and-Rust-catalogue",
               "aws_endpoint_gate": "NOT_RUN", "unit_coverage_contribution": False}
    backend = proxy = suite = private = None
    workers, cleanup = [], []
    try:
        require(not sys.flags.optimize and "LLVM_PROFILE_FILE" not in os.environ, "integration must run assertions without unit instrumentation")
        for name in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"):
            require("instrument-coverage" not in os.environ.get(name, ""), "integration cannot inherit instrumentation")
        import build
        import run as support
        compiled = build.capture_receipt(arguments.build_record, arguments.worker, evidence)
        private = Path(tempfile.mkdtemp(prefix="scap-catalogue-private-"))
        compute = private / "compute"; compute.mkdir(mode=0o700)
        backend = support.Backend(arguments.weed.resolve(), private / "backend")
        proxy = support.Proxy(backend.port, evidence); proxy.capture = proxy.capture_catalogue = True
        config = {"endpoint": proxy.endpoint, "region": "us-east-1", "bucket": "scap-test",
                  "access_key": backend.access, "secret_key": backend.secret}
        suite = CatalogueSuite(support, arguments, evidence, private, compute, backend, proxy, workers, config, compiled)
        backend.start(); summary["status"] = "running"
        suite.run()
    except BaseException as error:
        summary.update(status="blocked" if summary["status"] == "blocked" else "failed",
                       error_type=type(error).__name__, error=str(error))
    finally:
        if proxy is not None:
            try: proxy.clear()
            except BaseException as error: cleanup.append({"phase": "release_proxy", "error": repr(error)})
        for worker in list(workers):
            try: worker.kill()
            except BaseException as error: cleanup.append({"phase": "stop_worker", "error": repr(error)})
        for phase, item, method in (("close_proxy", proxy, "close"), ("stop_backend", backend, "stop")):
            if item is not None:
                try:
                    observed = getattr(item, method)()
                    if phase == "stop_backend" and suite is not None: suite.fact(None, "backend_cleanup", identities=observed)
                except BaseException as error: cleanup.append({"phase": phase, "error": repr(error)})
        if proxy is not None:
            summary["object_metrics"] = proxy.metrics(); summary["proxy_errors"] = proxy.errors
            if proxy.errors: cleanup.append({"phase": "proxy_errors", "count": len(proxy.errors)})
        if private is not None: summary["private_diagnostics"] = {"directory": str(private), "contains_worker_configuration_and_credentials": True}
        summary["cleanup_errors"] = cleanup
        if cleanup: summary["status"] = "failed"
        if summary["status"] == "running":
            try:
                compiled = build.verify(arguments.build_record, arguments.worker)
                suite.fact(None, "build_verified", stage="after", binary_sha256=compiled["binary"]["sha256"], input_sha256=compiled["input_sha256"])
                suite.fact(None, "cleanup_observed", proxy_errors=[], cleanup_errors=[])
                import catalogue_oracle
                audit = catalogue_oracle.audit(evidence)
                save_json(evidence / "catalogue-oracle.json", audit)
                require(audit["status"] == "passed", "independent catalogue oracle failed")
                summary.update(status="passed", oracle=audit)
            except BaseException as error: summary.update(status="failed", error_type=type(error).__name__, error=str(error))
        summary["artifacts"] = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(evidence.iterdir()) if path.is_file()}
        save_json(evidence / "summary.json", summary)
    print(json.dumps({"status": summary["status"], "evidence": str(evidence)}))
    return 0 if summary["status"] == "passed" else 1


if __name__ == "__main__": sys.exit(main())
