"""Independent verifier of named-catalogue raw histories and their prefixes.

This module imports no model, scheduler, candidate builder or transition helper.
It reconstructs the object service from invoke/effect/receive events, checks
candidate deltas against recorded exact GETs, and separately checks observations.
No S3, SQLite, production ID encoding, authentication or unbounded liveness is
proved by accepting one of these finite histories.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any


class OracleError(AssertionError):
    def __init__(self, code: str, message: str, step: int):
        self.code, self.detail, self.step = code, message, step
        super().__init__(f"{code} at event {step}: {message}")


def _encoded(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _hash(value: Any) -> str:
    return hashlib.sha256(_encoded(value).encode()).hexdigest()


class CatalogueOracle:
    ACTIONS = {"descriptor", "root", "reserve", "provision", "bind", "complete",
               "accept_abort", "fence_abort", "prove_abort", "release_abort",
               "delete_head", "release_delete", "abort_descriptor", "delete_descriptor", "grant_admin"}
    NEGATIVE_STATES = {"invalid", "denied", "invalid_control", "control_identity",
                       "intent_conflict", "corrupt", "missing_barrier", "missing_authority",
                       "name_conflict", "identity_conflict", "conflict", "not_prepared",
                       "not_reserved", "reserved", "aborting", "cannot_abort_bound",
                       "bound", "unavailable", "not_deleted", "deleting", "not_admitted"}

    def __init__(self):
        self.step = -1
        self.limits: dict = {}
        self.objects: dict[str, dict] = {}
        self.reads: dict[str, dict] = {}
        self.claimed_reads: set[str] = set()
        self.attempts: dict[str, dict] = {}
        self.etags: dict[str, str] = {}
        self.generation = 0
        self.accepted: dict[str, set[str]] = {}
        self.counts: Counter = Counter()

    def need(self, condition, code, message):
        if not condition:
            raise OracleError(code, message, self.step)

    def scope(self, value):
        self.need(isinstance(value, list) and len(value) == 5 and
                  all(type(v) is int and 1 <= v <= 255 for v in value),
                  "SCOPE", "invalid finite authority scope")

    def create(self, value):
        self.need(isinstance(value, dict) and set(value) == {
            "operation", "principal", "name", "scope", "previous", "quota", "retention"},
            "IDENTITY", "incomplete or extended creation identity")
        self.scope(value["scope"])
        self.need(all(type(value[k]) is int and 1 <= value[k] <= 255 for k in ("operation", "principal")),
                  "IDENTITY", "invalid operation/principal")
        self.need(value["previous"] is None or (type(value["previous"]) is int and
                  1 <= value["previous"] <= self.limits["max_revision"]), "IDENTITY", "invalid predecessor")
        self.need(isinstance(value["name"], str) and 1 <= len(value["name"].encode()) <= 128,
                  "IDENTITY", "invalid name")
        self.need(all(ord(c) >= 32 and not 127 <= ord(c) <= 159 for c in value["name"]),
                  "IDENTITY", "control character in name")
        self.need(type(value["quota"]) is int and value["quota"] > 0 and value["retention"] == 2,
                  "BUDGET", "creation budget changed or invalid")

    @staticmethod
    def descriptor_key(create):
        s = create["scope"]
        return f"descriptor/{s[0]}/{s[1]}/{create['principal']}/{create['operation']}"

    @staticmethod
    def head_key(scope):
        return f"head/{scope[0]}/{scope[1]}/{scope[2]}"

    @staticmethod
    def name_key(create):
        return f"name/{create['scope'][0]}/{create['scope'][1]}/{create['name']}"

    def source(self, create):
        return {"key": self.descriptor_key(create),
                "digest": _hash({"kind": "descriptor", "intent": create})}

    def proof_key(self, create):
        s = create["scope"]
        return f"abort-proof/{s[0]}/{s[1]}/{create['principal']}/{create['operation']}"

    @staticmethod
    def control_key(create, control):
        s = create["scope"]
        return f"control/{s[0]}/{s[1]}/{control['principal']}/{control['kind']}/{control['operation']}"

    def own(self, record, create):
        return record is not None and record.get("scope") == create["scope"] and record.get("origin") == self.source(create)

    def control(self, create, control, kind):
        self.need(isinstance(control, dict) and set(control) == {
            "kind", "principal", "operation", "create", "scope", "name",
            "expected_name_revision", "expected_head_revision", "nonce"},
            "CONTROL_ID", "incomplete control identity")
        self.need(control["kind"] == kind and (kind == "delete" or control["principal"] == create["principal"])
                  and control["create"] == self.source(create) and control["scope"] == create["scope"]
                  and control["name"] == create["name"], "CONTROL_ID", "control changed its creation/principal")
        self.need(all(type(control[k]) is int and 1 <= control[k] <= 255
                      for k in ("principal", "operation", "nonce", "expected_name_revision")),
                  "CONTROL_ID", "invalid fixed control token")
        self.need((kind == "abort" and control["expected_head_revision"] is None) or
                  (kind == "delete" and type(control["expected_head_revision"]) is int
                   and control["expected_head_revision"] > 0), "CONTROL_ID", "invalid original HEAD revision")

    def validate_record(self, key, body):
        self.need(isinstance(body, dict), "FORMAT", "non-record body")
        kind = body.get("kind")
        if kind == "descriptor":
            self.need(set(body) == {"kind", "intent"}, "FORMAT", "descriptor fields changed")
            self.create(body["intent"])
            self.need(key == self.descriptor_key(body["intent"]), "IDENTITY", "misaddressed descriptor")
        elif kind == "control_descriptor":
            self.need(set(body) == {"kind", "intent"}, "FORMAT", "control descriptor fields changed")
            control = body["intent"]
            s = control["scope"]
            self.scope(s)
            self.need(key == f"control/{s[0]}/{s[1]}/{control['principal']}/{control['kind']}/{control['operation']}",
                      "CONTROL_DESCRIPTOR", "control is not indexed by caller/kind/operation")
        elif kind == "root":
            self.need(set(body) == {"kind", "scope", "empty"} and body["empty"] is True,
                      "CLOSURE", "invalid symbolic empty dependency")
            self.scope(body["scope"])
            self.need(key == "root/" + _hash(body), "CLOSURE", "wrong dependency identity")
        elif kind == "head":
            self.need(set(body) == {"kind", "scope", "origin", "revision", "state", "active",
                      "owner_epoch", "data", "abort", "delete", "quota", "retention", "admins"},
                      "FORMAT", "HEAD fields changed")
            self.scope(body["scope"])
            self.need(key == self.head_key(body["scope"]), "SCOPE", "physical HEAD slot disagrees with body")
            self.need(body["state"] in {"provisioning", "ready", "maintenance", "deleted"},
                      "LIFECYCLE", "unknown lifecycle")
            self.need(isinstance(body["origin"], dict) and
                      (set(body["origin"]) == {"key", "digest"} or set(body["origin"]) == {"direct"}),
                      "ORIGIN", "unrecognized creation source")
            self.need(body["active"] is False, "LIFECYCLE", "this model never activates a writer")
            self.need(type(body["quota"]) is int and body["quota"] > 0 and body["retention"] == 2,
                      "BUDGET", "invalid creation policy")
            self.need(isinstance(body["admins"], list) and body["admins"] == sorted(set(body["admins"]))
                      and all(type(p) is int and 1 <= p <= 255 for p in body["admins"]),
                      "AUTH", "invalid current administrator policy")
        elif kind == "binding":
            self.need(set(body) == {"kind", "name", "scope", "origin", "revision", "state",
                      "abort", "delete", "proof"}, "FORMAT", "binding fields changed")
            self.scope(body["scope"])
            self.need(key == f"name/{body['scope'][0]}/{body['scope'][1]}/{body['name']}",
                      "IDENTITY", "misaddressed binding")
            self.need(body["state"] in {"reserved", "bound", "aborting", "tombstone"},
                      "LIFECYCLE", "unknown name state")
        elif kind == "abort_proof":
            self.need(set(body) == {"kind", "create", "scope", "control", "barrier"},
                      "ABORT_PROOF", "proof fields changed")
            self.scope(body["scope"])
            self.need(key == body["create"]["key"].replace("descriptor/", "abort-proof/", 1),
                      "ABORT_PROOF", "proof is not indexed by original create operation")
        else:
            self.need(False, "FORMAT", "unknown record type")
        for field in ("revision", "owner_epoch"):
            if field in body:
                self.need(type(body[field]) is int and 1 <= body[field] <= self.limits["max_revision"],
                          "BUDGET", "revision/fence wrapped or exceeded model bound")

    def record_etag(self, etag, body):
        self.need(isinstance(etag, str) and bool(etag), "ETAG", "missing opaque ETag")
        previous = self.etags.setdefault(etag, _encoded(body))
        self.need(previous == _encoded(body), "ETAG", "same opaque version identifies different bytes")

    def observations(self, event):
        ids = event["reads"]
        self.need(isinstance(ids, list) and len(ids) == len(set(ids)), "READ_SET", "duplicate GET reference")
        result = {}
        for read_id in ids:
            self.need(read_id in self.reads and read_id not in self.claimed_reads,
                      "READ_SET", "missing or reused operation observation")
            item = self.reads[read_id]
            self.need(item["generation"] == self.generation, "READ_GENERATION",
                      "new computation reused an observation lost with an old process")
            self.need(item["key"] not in result, "READ_SET", "multiple snapshots substituted for one key")
            result[item["key"]] = item
            self.claimed_reads.add(read_id)
        return result

    def read(self, observed, key):
        self.need(key in observed, "READ_SET", f"no exact GET of {key}")
        return observed[key]["body"]

    def unchanged(self, old, new, allowed):
        self.need(set(old) == set(new) and all(new[k] == v for k, v in old.items() if k not in allowed),
                  "PRESERVATION", "candidate reset fields outside its declared transition")

    def binding(self, binding, create, state):
        self.need(self.own(binding, create) and binding.get("name") == create["name"],
                  "ORIGIN", "name is owned by another creation")
        self.need(binding["state"] == state, "LIFECYCLE", f"name is not {state}")

    def dependency(self, observed, head, create):
        root = self.read(observed, head["data"])
        self.need(root is not None and root.get("kind") == "root" and root.get("scope") == create["scope"]
                  and root.get("empty") is True and head["data"] == "root/" + _hash(root),
                  "CLOSURE", "initial dependency not observed durable and exact")

    def barrier(self, proof, head, create, control):
        self.need(proof is not None and proof.get("kind") == "abort_proof"
                  and proof.get("create") == self.source(create) and proof.get("scope") == create["scope"]
                  and proof.get("control") == control, "ABORT_PROOF", "missing or different permanent cancel proof")
        self.need(head is not None, "BARRIER", "name released before its permanent physical-slot barrier")
        self.validate_record(self.head_key(create["scope"]), head)
        evidence = proof["barrier"]
        if evidence.get("kind") == "own_deleted":
            self.need(self.own(head, create) and head["state"] == "deleted" and head["abort"] == control,
                      "BARRIER", "own identity was not irreversibly cancelled")
            self.need(set(evidence) == {"kind", "scope", "origin", "revision", "abort"}
                      and all(evidence[k] == head[k] for k in ("scope", "origin", "revision", "abort")),
                      "BARRIER", "proof does not identify the exact cancellation transition")
        elif evidence.get("kind") == "foreign_occupied":
            self.need(not self.own(head, create), "BARRIER", "foreign occupancy claimed for own live identity")
            self.need(set(evidence) == {"kind", "scope", "origin"} and evidence["scope"] == head["scope"]
                      and evidence["origin"] == head["origin"],
                      "BARRIER", "foreign proof changed the occupant or depends on mutable revision/ETag")
        else:
            self.need(False, "BARRIER", "unknown or absent identity barrier")

    def check_candidate(self, event, observed):
        action, create, control, wire = (event[k] for k in ("action", "create", "control", "wire"))
        self.need(action in self.ACTIONS, "ACTION", "unmodeled candidate action")
        self.create(create)
        if action not in {"delete_descriptor", "delete_head", "release_delete", "grant_admin"}:
            self.need(event["actor"] == create["principal"], "AUTH", "another actor borrowed the creation identity")
        descriptor = self.read(observed, self.descriptor_key(create))
        new = wire["body"]
        self.validate_record(wire["key"], new)
        old_target = self.read(observed, wire["key"])
        self.need(wire["expected"] == observed[wire["key"]]["etag"],
                  "CAS_BASE", "conditional write did not keep its exact observed ETag")
        if action == "descriptor":
            self.need(descriptor is None and wire["expected"] is None and new.get("kind") == "descriptor"
                      and new["intent"] == create and wire["key"] == self.descriptor_key(create),
                      "IDENTITY", "descriptor was reassigned or accepted a changed fixed intent")
            return
        self.need(descriptor == {"kind": "descriptor", "intent": create},
                  "IDENTITY", "candidate's original descriptor is not durable/exact")
        if action in {"abort_descriptor", "delete_descriptor"}:
            kind = action.split("_")[0]
            self.control(create, control, kind)
            self.need(event["actor"] == control["principal"], "AUTH", "control caller differs from its authenticated actor")
            if kind == "delete":
                selected = self.read(observed, self.head_key(create["scope"]))
                self.need(self.own(selected, create) and event["actor"] in selected["admins"],
                          "AUTH", "delete control admitted without fresh HEAD administrator permission")
            self.need(wire["key"] == self.control_key(create, control) and old_target is None
                      and wire["expected"] is None and new == {"kind": "control_descriptor", "intent": control},
                      "CONTROL_DESCRIPTOR", "control conditions were reassigned or not immutably admitted")
            return
        if action == "root":
            self.need(new["kind"] == "root" and new["scope"] == create["scope"] and old_target is None
                      and wire["expected"] is None, "CLOSURE", "immutable root was overwritten or borrowed")
            return
        binding = self.read(observed, self.name_key(create))
        source = self.source(create)
        if action in {"accept_abort", "fence_abort", "prove_abort", "release_abort", "delete_head", "release_delete"}:
            self.control(create, control, "delete" if action in {"delete_head", "release_delete"} else "abort")
            self.need(event["actor"] == control["principal"], "AUTH", "control invocation changed its actor")
            frozen = self.read(observed, self.control_key(create, control))
            self.need(frozen == {"kind": "control_descriptor", "intent": control},
                      "CONTROL_DESCRIPTOR", "changed/unadmitted control conditions reached a mutable authority")
        if action == "reserve":
            self.need(new["kind"] == "binding" and wire["key"] == self.name_key(create)
                      and new["state"] == "reserved" and self.own(new, create)
                      and new["name"] == create["name"] and new["abort"] is None
                      and new["delete"] is None and new["proof"] is None,
                      "IDENTITY", "reservation lost its immutable creation identity")
            if binding is None:
                self.need(create["previous"] is None and new["revision"] == 1,
                          "NAME_ORDER", "missing predecessor treated as a new name")
            else:
                self.need(binding["state"] == "tombstone" and binding["revision"] == create["previous"]
                          and new["revision"] == binding["revision"] + 1,
                          "NAME_ORDER", "old intent rebound to a newer tombstone")
                self.need(new["scope"][2] != binding["scope"][2], "ID_REUSE", "physical HEAD ID reused")
            return
        if action == "accept_abort":
            self.binding(binding, create, "reserved")
            self.control(create, control, "abort")
            self.need(binding["revision"] == control["expected_name_revision"], "CONTROL_REBASE", "abort changed original name revision")
            self.unchanged(binding, new, {"state", "revision", "abort"})
            self.need(wire["key"] == self.name_key(create) and new["state"] == "aborting"
                      and new["revision"] == binding["revision"] + 1 and new["abort"] == control,
                      "ABORT_ACCEPT", "abort did not compete on the Reserved name slot")
            return
        head = self.read(observed, self.head_key(create["scope"]))
        if head is not None:
            self.validate_record(self.head_key(create["scope"]), head)
        if action == "grant_admin":
            self.binding(binding, create, "bound")
            self.need(self.own(head, create) and head["state"] == "ready" and event["actor"] in head["admins"],
                      "AUTH", "policy grant bypassed the current HEAD administrator")
            self.need(isinstance(control, dict) and set(control) == {"grant"}
                      and type(control["grant"]) is int and 1 <= control["grant"] <= 255,
                      "AUTH", "invalid symbolic grant")
            self.unchanged(head, new, {"revision", "admins"})
            self.need(wire["key"] == self.head_key(create["scope"]) and new["revision"] == head["revision"] + 1
                      and new["admins"] == sorted(set(head["admins"]) | {control["grant"]}),
                      "AUTH", "grant changed authority/data or added unintended administrators")
            return
        if action in {"provision", "bind", "complete"}:
            self.binding(binding, create, "bound" if action == "complete" else "reserved")
            if action == "provision":
                self.need(head is None and wire["expected"] is None, "ID_REUSE", "occupied HEAD overwritten/adopted")
                self.need(wire["key"] == self.head_key(create["scope"]) and new["kind"] == "head"
                          and new["scope"] == create["scope"], "SCOPE", "creation silently selected another Scope")
                self.need(new["origin"] == source, "ORIGIN", "provisioning borrowed another source")
                self.need(new["state"] == "provisioning" and new["revision"] == 1 and new["owner_epoch"] == 1
                          and new["abort"] is None and new["delete"] is None
                          and new["quota"] == create["quota"] and new["retention"] == create["retention"]
                          and new["admins"] == [create["principal"]],
                          "PROVISIONING", "creation skipped provisioning or changed initial contract")
                self.dependency(observed, new, create)
            else:
                self.need(self.own(head, create) and head["state"] == "provisioning", "ORIGIN", "bind/complete adopted another or already live HEAD")
                if action == "bind":
                    self.unchanged(binding, new, {"state", "revision"})
                    self.need(wire["key"] == self.name_key(create) and new["state"] == "bound"
                              and new["revision"] == binding["revision"] + 1,
                              "NAME_ORDER", "binding did not advance the original reservation")
                else:
                    self.unchanged(head, new, {"state", "revision"})
                    self.need(wire["key"] == self.head_key(create["scope"]) and new["state"] == "ready"
                              and new["revision"] == head["revision"] + 1,
                              "PROVISIONING", "Ready did not extend the precise provisioning revision")
                    self.dependency(observed, head, create)
            return
        if action in {"fence_abort", "prove_abort", "release_abort"}:
            self.control(create, control, "abort")
            self.binding(binding, create, "aborting")
            self.need(binding["abort"] == control and binding["revision"] == control["expected_name_revision"] + 1,
                      "CONTROL_ID", "a different abort adopted the accepted name transition")
            if action == "fence_abort":
                self.need(wire["key"] == self.head_key(create["scope"]) and new["kind"] == "head"
                          and new["scope"] == create["scope"] and new["origin"] == source
                          and new["state"] == "deleted" and new["abort"] == control and new["delete"] is None,
                          "BARRIER", "cancel fence does not identify its immutable creation and abort")
                if head is None:
                    self.need(new["revision"] == 1 and new["owner_epoch"] == 1
                              and new["quota"] == create["quota"] and new["retention"] == create["retention"]
                              and new["admins"] == [create["principal"]],
                              "BARRIER", "absent-HEAD tombstone changed creation contract")
                    self.dependency(observed, new, create)
                else:
                    self.need(self.own(head, create) and head["state"] == "provisioning",
                              "FOREIGN_HEAD", "abort changed a foreign or already serviceable HEAD")
                    self.unchanged(head, new, {"state", "revision", "active", "owner_epoch", "abort"})
                    self.need(new["revision"] == head["revision"] + 1 and new["owner_epoch"] == head["owner_epoch"] + 1,
                              "BARRIER", "cancel did not advance HEAD ordering/fence")
            else:
                if action == "prove_abort":
                    self.need(wire["key"] == self.proof_key(create) and old_target is None and wire["expected"] is None,
                              "ABORT_PROOF", "cancel proof overwritten or addressed by the wrong operation")
                    self.barrier(new, head, create, control)
                else:
                    proof = self.read(observed, self.proof_key(create))
                    self.barrier(proof, head, create, control)
                    self.unchanged(binding, new, {"state", "revision", "proof"})
                    self.need(wire["key"] == self.name_key(create) and new["state"] == "tombstone"
                              and new["revision"] == binding["revision"] + 1
                              and new["proof"] == {"key": self.proof_key(create), "digest": _hash(proof)},
                              "ABORT_PROOF", "name released without observing its permanent exact AbortProof")
            return
        self.control(create, control, "delete")
        self.binding(binding, create, "bound")
        self.need(binding["revision"] == control["expected_name_revision"], "CONTROL_REBASE", "delete changed original binding revision")
        self.need(self.own(head, create), "ORIGIN", "deletion borrowed a different HEAD")
        self.need(event["actor"] in head["admins"], "AUTH", "delete lacks fresh HEAD administrator permission")
        if action == "delete_head":
            self.need(head["state"] in {"ready", "maintenance"}, "LIFECYCLE", "normal delete bypassed complete")
            self.need(head["revision"] == control["expected_head_revision"], "CONTROL_REBASE", "delete rebound to a new HEAD revision")
            self.unchanged(head, new, {"state", "revision", "active", "owner_epoch", "delete"})
            self.need(wire["key"] == self.head_key(create["scope"]) and new["state"] == "deleted"
                      and new["revision"] == head["revision"] + 1 and new["owner_epoch"] == head["owner_epoch"] + 1
                      and new["delete"] == control, "DELETE", "wrong terminal deletion transition")
        else:
            self.need(head["state"] == "deleted" and head["delete"] == control
                      and head["revision"] == control["expected_head_revision"] + 1,
                      "DELETE", "another operation's deletion treated as the original result")
            self.unchanged(binding, new, {"state", "revision", "delete"})
            self.need(wire["key"] == self.name_key(create) and new["state"] == "tombstone"
                      and new["revision"] == binding["revision"] + 1 and new["delete"] == control,
                      "DELETE", "name released without the exact HEAD deletion")

    def invariants(self):
        """State predicates, independent of the model's candidate construction."""
        self.need(len(self.objects) <= self.limits["max_records"], "BUDGET", "record budget exceeded")
        for key, item in self.objects.items():
            body = item["body"]
            if body["kind"] not in {"binding", "head", "abort_proof"}:
                continue
            source = body.get("origin", body.get("create"))
            if "direct" in source:
                continue
            descriptor = self.objects.get(source["key"], {}).get("body")
            self.need(descriptor is not None and source["digest"] == _hash(descriptor),
                      "ORIGIN", "record's creation descriptor is absent or mismatched")
            create = descriptor["intent"]
            self.need(body["scope"] == create["scope"], "SCOPE", "one creation operation acquired another Scope")
            binding = self.objects.get(self.name_key(create), {}).get("body")
            head = self.objects.get(self.head_key(create["scope"]), {}).get("body")
            if body["kind"] == "head" and body["state"] in {"ready", "maintenance"}:
                self.need(self.own(binding, create) and binding["state"] == "bound", "READY_BINDING", "serviceable HEAD lacks its current Bound name")
            if body["kind"] == "binding":
                if body["abort"] is not None or body["delete"] is not None:
                    control = body["abort"] or body["delete"]
                    self.need(self.objects.get(self.control_key(create, control), {}).get("body") ==
                              {"kind": "control_descriptor", "intent": control},
                              "CONTROL_DESCRIPTOR", "name transition lost fixed control admission")
                if body["state"] in {"bound", "aborting"}:
                    choices = self.accepted.setdefault(_encoded(source), set())
                    choices.add(body["state"])
                    self.need(len(choices) == 1, "ABORT_BOUND", "same reservation accepted both bind and abort")
                if body["state"] == "aborting" and self.own(head, create):
                    self.need(head["state"] not in {"ready", "maintenance"}, "ABORT_BOUND", "accepted abort became serviceable")
                if body["state"] == "tombstone":
                    if body["abort"] is not None:
                        proof = self.objects.get(self.proof_key(create), {}).get("body")
                        self.barrier(proof, head, create, body["abort"])
                        self.need(body["proof"] == {"key": self.proof_key(create), "digest": _hash(proof)},
                                  "ABORT_PROOF", "released name lost permanent proof")
                    else:
                        self.need(self.own(head, create) and head["state"] == "deleted"
                                  and body["delete"] is not None and head["delete"] == body["delete"],
                                  "BARRIER", "name released without a permanent delete")
            elif body["kind"] == "abort_proof":
                self.barrier(body, head, create, body["control"])
            elif body["kind"] == "head" and (body["abort"] is not None or body["delete"] is not None):
                control = body["abort"] or body["delete"]
                self.need(self.objects.get(self.control_key(create, control), {}).get("body") ==
                          {"kind": "control_descriptor", "intent": control},
                          "CONTROL_DESCRIPTOR", "terminal HEAD lost fixed control admission")

    def check_observation(self, event, observed):
        result, delivered = event["result"], event["delivered"]
        self.need(type(delivered) is bool and event["observed"] == (result if delivered else {"state": "unknown"}),
                  "RECEIPT", "lost reply reported as an observed completion")
        state = result["state"]
        if event["type"] == "resolve":
            binding = self.read(observed, event["name_key"])
            head = None
            if binding is not None and binding["state"] == "bound":
                head = self.read(observed, self.head_key(binding["scope"]))
            ready = (head is not None and head["state"] == "ready" and head["scope"] == binding["scope"]
                     and head["origin"] == binding["origin"])
            self.need(state == ("ready" if ready else "unavailable"), "RESOLVE", "name served an incomplete/deleted authority")
            if ready:
                self.need(result["scope"] == head["scope"] and result["origin"] == head["origin"],
                          "RESOLVE", "name returned a cached/wrong authority")
        else:
            create, kind, control = event["create"], event["kind"], event["control"]
            # A rejected invalid/unauthorized input never confers completion.
            if state in {"invalid", "denied", "invalid_control", "control_identity"}:
                self.need(state in self.NEGATIVE_STATES, "OBSERVATION", "unrecognized rejection")
                return
            self.create(create)
            self.need(event["actor"] == (control["principal"] if kind == "delete" else create["principal"]),
                      "AUTH", "progress borrowed another caller/creator")
            if kind in {"abort", "delete"}:
                self.control(create, control, kind)
            self.need(kind in {"create", "abort", "delete"}, "OBSERVATION", "ambiguous operation addressing")
            descriptor = self.read(observed, self.descriptor_key(create))
            if state == "not_prepared":
                self.need(descriptor is None, "OBSERVATION", "durable original operation reported absent")
                return
            if state == "intent_conflict":
                self.need(descriptor != {"kind": "descriptor", "intent": create}, "OBSERVATION", "invented intent conflict")
                return
            self.need(descriptor == {"kind": "descriptor", "intent": create}, "IDENTITY", "progress changed original operation identity")
            binding = self.read(observed, self.name_key(create))
            head = self.read(observed, self.head_key(create["scope"]))
            proof = self.read(observed, self.proof_key(create))
            if kind in {"abort", "delete"}:
                if kind == "delete":
                    self.need(self.own(head, create) and event["actor"] in head["admins"],
                              "AUTH", "delete progress ignored current/frozen administrator policy")
                frozen = self.read(observed, self.control_key(create, control))
                if state == "not_admitted":
                    self.need(frozen is None, "CONTROL_DESCRIPTOR", "admitted control reported unsubmitted")
                    return
                if state == "conflict" and frozen != {"kind": "control_descriptor", "intent": control}:
                    self.need(frozen is not None, "CONTROL_DESCRIPTOR", "unsubmitted control called an admitted conflict")
                    return
                self.need(frozen == {"kind": "control_descriptor", "intent": control},
                          "CONTROL_DESCRIPTOR", "control success/progress changed admitted conditions")
            if state == "ready":
                self.need(kind == "create" and self.own(binding, create) and binding["state"] == "bound"
                          and self.own(head, create) and head["state"] == "ready"
                          and result["scope"] == create["scope"] and result["origin"] == self.source(create),
                          "OBSERVATION", "creation ACK lacks observed Bound + Ready of original Scope")
            elif state == "aborted":
                self.need(kind in {"create", "abort"} and proof is not None, "ABORT_PROOF", "cancel ACK has no observed permanent proof")
                accepted = proof["control"]
                self.control(create, accepted, "abort")
                self.need(kind != "abort" or accepted == control, "CONTROL_ID", "another abort's proof used as success")
                self.barrier(proof, head, create, accepted)
                same_terminal = (self.own(binding, create) and binding["state"] == "tombstone"
                                 and binding["abort"] == accepted and binding["revision"] == accepted["expected_name_revision"] + 2
                                 and binding["proof"] == {"key": self.proof_key(create), "digest": _hash(proof)})
                successor = (binding is not None and not self.own(binding, create)
                             and binding["revision"] > accepted["expected_name_revision"] + 2)
                self.need(same_terminal or successor, "ABORT_ACK", "proof exists but name release has not been observed")
                self.need(result["scope"] == create["scope"] and result["control"] == accepted,
                          "CONTROL_ID", "cancel receipt changed original identity")
            elif state == "deleted":
                self.need(kind in {"create", "delete"} and self.own(head, create) and head["state"] == "deleted"
                          and head["delete"] is not None, "DELETE", "delete ACK has no original terminal HEAD")
                deletion = head["delete"]
                self.control(create, deletion, "delete")
                self.need(kind != "delete" or deletion == control, "CONTROL_ID", "another delete was claimed as success")
                same_terminal = (self.own(binding, create) and binding["state"] == "tombstone" and binding["delete"] == deletion
                                 and binding["revision"] == deletion["expected_name_revision"] + 1)
                successor = (binding is not None and not self.own(binding, create)
                             and binding["revision"] > deletion["expected_name_revision"] + 1)
                self.need(same_terminal or successor, "DELETE_ACK", "HEAD deleted but name release not observed")
                self.need(result["scope"] == create["scope"] and result["control"] == deletion,
                          "CONTROL_ID", "delete receipt changed original identity")
            else:
                self.need(state in self.NEGATIVE_STATES, "OBSERVATION", "unrecognized progress outcome")
                if state == "cannot_abort_bound":
                    self.need(kind == "abort" and self.own(binding, create) and binding["state"] == "bound",
                              "OBSERVATION", "wrong cancellation boundary")
                elif state == "aborting":
                    self.need(self.own(binding, create) and binding["state"] == "aborting",
                              "OBSERVATION", "cancel acceptance was not durable")
                elif state == "not_reserved":
                    self.need(binding is None and proof is None, "OBSERVATION", "lost name authority called unreserved")
                elif state == "identity_conflict":
                    self.need(head is not None and not self.own(head, create), "OBSERVATION", "absent/own slot called foreign")
        if delivered:
            self.counts[f"observed_{state}"] += 1
        else:
            self.counts["lost_observations"] += 1

    def accept(self, event):
        kind = event["type"]
        self.counts[kind] += 1
        if kind == "genesis":
            self.need(self.step == 0, "ORDER", "genesis is not the unique first event")
            self.limits = copy.deepcopy(event["limits"])
            self.need(set(self.limits) == {"max_records", "max_revision", "max_attempts", "max_pending", "max_events"}
                      and all(type(v) is int and v > 0 for v in self.limits.values()), "BUDGET", "invalid declared bounds")
            self.objects = copy.deepcopy(event["objects"])
            for key, item in self.objects.items():
                self.need(item["body"]["kind"] in {"root", "head"}, "GENESIS", "preseeded directory/proof hides its provenance")
                if item["body"]["kind"] == "head":
                    self.need(set(item["body"]["origin"]) == {"direct"}, "GENESIS", "seed HEAD impersonates a modeled creation")
                self.validate_record(key, item["body"])
                self.record_etag(item["etag"], item["body"])
            self.invariants()
        elif kind == "get":
            self.need(event["read_id"] not in self.reads, "READ_SET", "GET identity reused")
            self.need(event.get("generation") == self.generation, "READ_GENERATION",
                      "GET does not belong to the current computation generation")
            current = self.objects.get(event["key"])
            self.need(event["body"] == (None if current is None else current["body"])
                      and event["etag"] == (None if current is None else current["etag"]),
                      "FRESH_GET", "GET body/ETag are not one current exact response")
            self.reads[event["read_id"]] = copy.deepcopy(event)
        elif kind == "prepare":
            name = event["attempt"]
            self.need(name not in self.attempts and len(self.attempts) < self.limits["max_attempts"],
                      "ORDER", "attempt reused or declared budget exceeded")
            self.need(event["generation"] == self.generation, "CRASH", "candidate resurrected an old process")
            self.check_candidate(event, self.observations(event))
            self.attempts[name] = dict(event=copy.deepcopy(event), phase="prepared", outcome=None)
        elif kind == "invoke":
            self.need(event["attempt"] in self.attempts, "ORDER", "invoke lacks candidate")
            attempt = self.attempts[event["attempt"]]
            self.need(attempt["phase"] == "prepared" and event["generation"] == self.generation
                      and attempt["event"]["generation"] == self.generation, "CRASH", "unsent candidate survived compute loss")
            self.need(event["wire"] == attempt["event"]["wire"], "SEALED_CANDIDATE", "candidate changed ETag/body after preparation")
            self.need(sum(a["phase"] in {"invoked", "effected"} for a in self.attempts.values()) < self.limits["max_pending"],
                      "BUDGET", "inflight request bound exceeded")
            attempt["phase"] = "invoked"
        elif kind == "effect":
            self.need(event["attempt"] in self.attempts, "ORDER", "storage effect without a prepared/invoked request")
            attempt = self.attempts[event["attempt"]]
            self.need(attempt["phase"] == "invoked", "ORDER", "storage effect without exactly one invocation")
            wire = attempt["event"]["wire"]
            self.need(event["wire"] == wire, "SEALED_CANDIDATE", "network changed a sealed request")
            old = self.objects.get(wire["key"])
            etag = None if old is None else old["etag"]
            outcome = "conflict" if etag != wire["expected"] else (
                "limit" if old is None and len(self.objects) >= self.limits["max_records"] else "applied")
            self.need(event["before"] == etag and event["outcome"] == outcome,
                      "CONDITIONAL_RESULT", "object service did not apply the original condition/budget")
            if outcome == "applied":
                if old is not None and old["body"]["kind"] == "head":
                    previous, new = old["body"], wire["body"]
                    self.need(previous["scope"] == new["scope"] and previous["origin"] == new["origin"],
                              "ID_REUSE", "physical HEAD slot changed immutable identity")
                    self.need(previous["state"] != "deleted", "RESURRECTION", "terminal HEAD was overwritten")
                if old is not None:
                    self.need(old["body"]["kind"] in {"head", "binding"}, "IMMUTABLE", "immutable record overwritten")
                self.record_etag(event["after"], wire["body"])
                self.objects[wire["key"]] = dict(body=copy.deepcopy(wire["body"]), etag=event["after"])
                self.invariants()
            else:
                self.need(event["after"] == etag, "CONDITIONAL_RESULT", "failed condition changed object version")
            attempt.update(phase="effected", outcome=outcome)
            self.counts[f"effect_{outcome}"] += 1
        elif kind == "receive":
            self.need(event["attempt"] in self.attempts, "ORDER", "response without invocation")
            attempt = self.attempts[event["attempt"]]
            self.need(attempt["phase"] == "effected" and event["generation"] == self.generation, "ORDER", "response before effect or twice")
            self.need(type(event["lost"]) is bool and (event["lost"] or attempt["event"]["generation"] == self.generation),
                      "CRASH", "old process received a response after compute loss")
            self.need(event["outcome"] == ("unknown" if event["lost"] else attempt["outcome"]),
                      "RESPONSE", "lost/known conditional response was misreported")
            attempt["phase"] = "received"
            self.counts[f"response_{event['outcome']}"] += 1
        elif kind == "crash":
            self.need(event["generation"] == self.generation + 1, "CRASH", "compute generation did not advance once")
            self.generation = event["generation"]
        elif kind in {"observe", "resolve"}:
            self.check_observation(event, self.observations(event))
        elif kind == "rejected":
            self.need(isinstance(event["code"], str) and event["code"], "REJECTION", "unrecorded failure reason")
            self.observations(event)
        elif kind == "transport_rejected":
            self.need(event["attempt"] in self.attempts and event["generation"] == self.generation,
                      "REJECTION", "rejected transport has no known local attempt")
            self.need(event["action"] in {"invoke", "effect", "receive"} and event["code"] in {"phase", "limit"},
                      "REJECTION", "unrecognized transport rejection")
            attempt = self.attempts[event["attempt"]]
            expected_phase = {"invoke": "prepared", "effect": "invoked", "receive": "effected"}[event["action"]]
            if event["code"] == "phase":
                self.need(attempt["phase"] != expected_phase or
                          (event["action"] == "invoke" and attempt["event"]["generation"] != self.generation),
                          "REJECTION", "invented transport phase rejection")
            else:
                self.need(event["action"] == "invoke" and sum(a["phase"] in {"invoked", "effected"}
                          for a in self.attempts.values()) >= self.limits["max_pending"],
                          "REJECTION", "invented pending budget rejection")
        else:
            self.need(False, "EVENT", f"unknown event {kind}; no deletion/implicit write is allowed")

    def audit(self, events):
        self.need(isinstance(events, list) and bool(events), "HISTORY", "empty/non-list history")
        for self.step, event in enumerate(events):
            try:
                self.need(self.step == 0 or bool(self.limits), "ORDER", "history has no genesis")
                self.accept(event)
                self.need(self.step < self.limits["max_events"], "BUDGET", "history exceeds declared event bound")
            except OracleError:
                raise
            except (KeyError, TypeError, ValueError, IndexError, AttributeError) as error:
                raise OracleError("MALFORMED", str(error), self.step) from error
        return dict(events=len(events), records=len(self.objects), attempts=len(self.attempts),
                    counts=dict(sorted(self.counts.items())))


def audit(events: list[dict]) -> dict:
    return CatalogueOracle().audit(events)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("history", type=Path)
    args = parser.parse_args()
    data = json.loads(args.history.read_text())
    events = data["events"] if isinstance(data, dict) else data
    try:
        print(json.dumps(audit(events), indent=2, sort_keys=True))
    except OracleError as error:
        print(json.dumps(dict(accepted=False, code=error.code, step=error.step, detail=error.detail), indent=2))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
