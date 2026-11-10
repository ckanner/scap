"""Bounded terminal-retirement protocol simulator, never a product backend.

Frames and scopes are finite symbols. Calls have distinct preparation, network
invocation, storage effect and client observation. An unknown response and a
compute crash never retract an invoked call. The independent oracle imports
none of this module.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json


OLD = (1, 7, 11, 1, 1)
FOREIGN = (1, 7, 11, 2, 2)
SUCCESSOR = (1, 7, 12, 1, 1)
ADMIN = 7
MAX_CALLS = 48
MAX_EVENTS = 1024
MAX_SERIAL = 31


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def fingerprint(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def head_key(scope=OLD):
    return "head:" + "/".join(map(str, scope[:3]))


def payload_key(scope=OLD, generation=1):
    return "payload:" + "/".join(map(str, scope)) + f":{generation}:live"


def retired(head, generation):
    return 0 < generation <= head["allocated"] and (
        head["terminal"] is not None
        or generation != head["active_generation"]
        and generation != head["plan_target"]
    )


def valid_head(head):
    if not 1 <= head["active_generation"] <= head["allocated"] <= head["serial"] <= MAX_SERIAL:
        return False
    if head["format"] == 6:
        return head["terminal"] is None
    return head["format"] == 7 and head["terminal"] is not None and head["allocated"] < head["terminal"]["serial"] <= head["serial"] and head["revision"] < head["terminal"]["serial"] and head["lifecycle"] == "deleted" and not head["active"] and head["plan_target"] is None and (head["checkpoint"] is None or head["terminal"]["serial"] < head["checkpoint"]["serial"] <= head["serial"])


class Rejected(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


@dataclass
class Call:
    kind: str
    method: str
    key: str
    condition: str | None
    body: object
    observations: list[int]
    process: int
    phase: str = "prepared"
    result: str | None = None
    stored: object = None
    reply: str | None = None


class Model:
    def __init__(self, mode="direct", object_etags="fresh", fault=None, initial_serial=None):
        assert mode in ("direct", "delete", "abort", "abort_absent", "foreign")
        assert object_etags in ("fresh", "content")
        self.mode, self.object_etags, self.fault = mode, object_etags, fault
        self.process, self.clock, self.counter = 1, 0, 0
        self.store, self.calls, self.reads = {}, {}, {}
        self.events, self.reader = [], None
        self.incidents, self.semantic_latch = set(), False
        self.directory_replies = []
        named = mode != "direct"
        aborting = mode in ("abort", "abort_absent", "foreign")
        self.receipt = None if aborting else {"scope": list(OLD), "request": 41, "nonce": 41, "result": "original-random"}
        origin = {"creator": ADMIN, "operation": 31, "descriptor": "descriptor:31"} if named else None
        control = {
            "scope": list(OLD), "origin": origin, "principal": ADMIN,
            "kind": "abort" if aborting else "delete", "operation": 51,
            "expected_name_revision": 1 if aborting else 2,
            "expected_head_revision": None if aborting else 1, "nonce": 101,
        }
        head = {
            "format": 6, "scope": list(FOREIGN if mode == "foreign" else OLD),
            "serial": 1 if aborting else 2, "revision": 1, "nonce": 31, "owner_epoch": 1,
            "active": not aborting, "lifecycle": "provisioning" if aborting else "ready",
            "active_generation": 1, "allocated": 1 if aborting else 2,
            "plan_target": None, "terminal": None, "checkpoint": None,
            "admin": ADMIN, "request_epoch": 1, "data_root": "live", "result_root": "retained",
            "creation": origin, "deletion": None,
        }
        if mode == "foreign":
            head.update(lifecycle="ready", active=True, creation={"creator": 8, "operation": 32, "descriptor": "foreign-descriptor"})
        if initial_serial is not None:
            head["serial"] = initial_serial
        assert valid_head(head)
        if mode != "abort_absent":
            self._put(head_key(), head)
        self._put(payload_key(), {"scope": list(OLD), "hash": "live", "semantic": "valid"})
        self._put(payload_key(SUCCESSOR), {"scope": list(SUCCESSOR), "hash": "live", "semantic": "valid"})
        if mode == "foreign":
            self._put(payload_key(FOREIGN), {"scope": list(FOREIGN), "hash": "live", "semantic": "valid"})
        if named:
            self._put("descriptor:31", {"scope": list(OLD), "origin": origin, "name": "demo"})
            self._put("control:51", control)
            self._put("name:demo", {
                "scope": list(OLD), "stage": "aborting" if aborting else "bound",
                "revision": 2, "control": "control:51" if aborting else None, "proof": None,
            })
        self._emit("initial", mode=mode, object_etags=object_etags, store=deepcopy(self.store), receipt=self.receipt)
        # Held calls genuinely precede the Deleted barrier. The initial-create
        # request uses Absent; every other late HEAD request keeps its old ETag.
        live = deepcopy(head)
        live.update(scope=list(OLD), lifecycle="provisioning" if named else "ready", creation=origin, active=False)
        self._prepare("old-create", "initial_create", "PUT", head_key(), "absent", live, [])
        if mode != "abort_absent":
            observation = self.get(head_key())
            candidate = deepcopy(observation["body"])
            candidate["serial"] += 1
            candidate["revision"] += 1
            candidate["nonce"] = 41
            if aborting and mode != "foreign":
                candidate.update(lifecycle="deleted", active=False, deletion=control, nonce=101)
                candidate["owner_epoch"] += 1
            self._prepare("old-head", "old_head", "PUT", head_key(), observation["etag"], candidate, [observation["id"]])
            if not aborting:
                self.reader = {
                    "basis": deepcopy(observation), "generation": 1, "backend": "original",
                    "deadline": 10, "process": self.process, "failed": False, "probes": 0, "outcome": None,
                    "physical": False,
                }
                self._prepare("old-read", "read", "GET", payload_key(), None, None, [observation["id"]])
        self._prepare("old-put", "old_put", "PUT", payload_key(), "absent", self.store[payload_key()]["body"], [])
        if mode == "foreign":
            self._put("proof:31", {"control": "control:51", "kind": "foreign", "scope": list(FOREIGN), "creation": head["creation"]})
            self._emit("foreign_proof", stored=deepcopy(self.store["proof:31"]))
        else:
            self.logical_delete(control if named else None, live)

    def _emit(self, event, **fields):
        if len(self.events) >= MAX_EVENTS:
            raise Rejected("event_budget")
        row = {"sequence": len(self.events) + 1, "event": event, "process": self.process, **deepcopy(fields)}
        self.events.append(row)
        return row

    def _put(self, key, body):
        self.counter += 1
        etag = "v" + str(self.counter)
        if key.startswith("payload:") and self.object_etags == "content":
            etag = "content-" + fingerprint(body)
        self.store[key] = {"etag": etag, "body": deepcopy(body)}
        return self.store[key]

    def reject(self, reason):
        self._emit("rejected", reason=reason)
        raise Rejected(reason)

    def get(self, key, failure=None):
        row = self._emit("get", key=key, result=failure or ("present" if key in self.store else "missing"),
                         stored=None if failure else deepcopy(self.store.get(key)))
        result = {"id": row["sequence"], "key": key, "process": self.process, "result": row["result"]}
        if row["stored"] is not None:
            result.update(row["stored"])
        self.reads[result["id"]] = deepcopy(result)
        return result

    def _prepare(self, identifier, kind, method, key, condition, body, observations, principal=ADMIN):
        if identifier in self.calls or len(self.calls) == MAX_CALLS:
            self.reject("call_budget_or_identity_reuse")
        self.calls[identifier] = Call(kind, method, key, condition, deepcopy(body), list(observations), self.process)
        self._emit("prepare", id=identifier, kind=kind, method=method, key=key,
                   condition=condition, body=body, observations=observations, principal=principal)
        return identifier

    def invoke(self, identifier):
        call = self.calls[identifier]
        if call.phase != "prepared" or call.process != self.process:
            self.reject("stale_or_already_invoked")
        call.phase = "invoked"
        self._emit("invoke", id=identifier)

    def effect(self, identifier):
        call = self.calls[identifier]
        if call.phase != "invoked":
            self.reject("not_in_flight")
        current = self.store.get(call.key)
        if call.method == "GET":
            result = "present" if current else "missing"
            stored = deepcopy(current)
        elif call.condition == "absent" and current is not None:
            result, stored = "conflict", deepcopy(current)
        elif call.condition != "absent" and (current is None or current["etag"] != call.condition):
            result, stored = ("missing" if current is None and call.method == "DELETE" else "conflict"), deepcopy(current)
        elif call.method == "DELETE":
            del self.store[call.key]
            result, stored = "applied", None
        else:
            stored = deepcopy(self._put(call.key, call.body))
            result = "applied"
        call.phase, call.result, call.stored = "effected", result, deepcopy(stored)
        self._emit("effect", id=identifier, result=result, stored=stored)

    def respond(self, identifier, lost=False):
        call = self.calls[identifier]
        if call.phase != "effected" or call.reply is not None:
            self.reject("no_new_response")
        reply = "unknown" if lost or call.process != self.process else call.result
        call.reply = reply
        self._emit("response", id=identifier, result=reply)
        return reply

    def timeout(self, identifier):
        call = self.calls[identifier]
        if call.phase not in ("invoked", "effected") or call.reply is not None:
            self.reject("not_unresolved")
        call.reply = "unknown"
        self._emit("response", id=identifier, result="unknown")

    def run(self, identifier, lost=False):
        self.invoke(identifier)
        self.effect(identifier)
        return self.respond(identifier, lost)

    def crash(self):
        old = self.process
        self.process += 1
        # An independent post-crash Database starts a new knowledge lineage;
        # old in-flight network effects survive, but old handles do not.
        self.incidents, self.semantic_latch = set(), False
        self._emit("crash", previous=old)

    def tick(self, amount=1):
        if amount <= 0 or self.clock + amount > 32:
            self.reject("clock_budget")
        self.clock += amount
        self._emit("tick", clock=self.clock)

    def logical_delete(self, control, absent_head):
        base = self.get(head_key())
        head = deepcopy(base.get("body", absent_head))
        head.update(lifecycle="deleted", active=False, deletion=deepcopy(control))
        head["serial"] = base["body"]["serial"] + 1 if base["result"] == "present" else 1
        head["revision"] = base["body"]["revision"] + 1 if base["result"] == "present" else 1
        head["nonce"] = 101
        if base["result"] == "present":
            head["owner_epoch"] += 1
        self._prepare("logical-delete", "logical_delete", "PUT", head_key(), base.get("etag", "absent"), head, [base["id"]])
        self.run("logical-delete")

    def authority(self, principal=ADMIN, maintenance_clear=False):
        head = self.get(head_key())
        observations = [head["id"]]
        if head["result"] != "present":
            self.reject("missing_head")
        body = head["body"]
        if not valid_head(body):
            self.semantic_latch = True
            self._emit("authority_invalid", observation=head["id"])
            self.reject("invalid_head")
        if body["scope"] != list(OLD):
            self.reject("foreign_scope")
        if body["admin"] != principal:
            self.reject("denied")
        if body["lifecycle"] != "deleted":
            self.reject("not_deleted")
        if maintenance_clear and (body["plan_target"] is not None or body["checkpoint"] is not None):
            self.reject("maintenance_busy")
        if body["creation"] is not None:
            # Catalogue::view ordering: stable name, proof before the HEAD it
            # certifies, then a second exact name observation. These reads are
            # one synchronous model action; inter-read races are not explored.
            descriptor = self.get("descriptor:31")
            control = self.get("control:51")
            previous_name = self.get("name:demo")
            proof = self.get("proof:31")
            head = self.get(head_key())
            binding = self.get("name:demo")
            observations.extend(value["id"] for value in (descriptor, control, previous_name, proof, head, binding))
            if {k: v for k, v in previous_name.items() if k != "id"} != {k: v for k, v in binding.items() if k != "id"}:
                self.reject("changing_name")
            body = head["body"]
            if descriptor["result"] != "present" or control["result"] != "present" or binding["result"] != "present":
                if self.fault != "ignore_missing_intent":
                    self.reject("missing_intent")
            elif descriptor["body"]["scope"] != list(OLD) or descriptor["body"]["origin"] != body["creation"] or control["body"] != body["deletion"]:
                self.reject("intent_mismatch")
            elif body["nonce"] != control["body"]["nonce"]:
                self.reject("changed_business_barrier")
            elif control["body"]["kind"] == "delete":
                if body["revision"] != control["body"]["expected_head_revision"] + 1 or proof["result"] != "missing":
                    self.reject("delete_barrier_mismatch")
                if binding["body"]["stage"] not in ("bound", "tombstone", "successor"):
                    self.reject("delete_not_accepted")
            else:
                if binding["body"]["stage"] not in ("aborting", "tombstone", "successor"):
                    self.reject("abort_not_accepted")
                if binding["body"]["stage"] != "aborting" and proof["result"] != "present":
                    self.reject("missing_abort_proof")
                if proof["result"] == "present" and proof["body"] != {"control": "control:51", "kind": "own", "revision": body["revision"], "nonce": body["nonce"]}:
                    self.reject("abort_barrier_mismatch")
        return head, observations

    def technical(self, head):
        if head["serial"] >= MAX_SERIAL:
            self.reject("serial_budget")
        body = deepcopy(head)
        body["serial"] += 1
        return body

    def prepare_terminal(self, identifier, principal=ADMIN, expected_serial=None):
        base, observations = self.authority(principal, maintenance_clear=True)
        if expected_serial is not None and expected_serial != base["body"]["serial"]:
            self.reject("head_serial_conflict")
        if base["body"]["terminal"] is not None:
            self.reject("already_terminal")
        if self.semantic_latch or base["body"]["active_generation"] in self.incidents:
            self.reject("known_lineage_incident")
        body = self.technical(base["body"])
        body.update(format=7, active=False)
        body["terminal"] = {"serial": body["serial"]}
        if self.fault == "change_business_barrier":
            body["revision"] += 1
            body["nonce"] += 1
        return self._prepare(identifier, "terminal", "PUT", head_key(), base["etag"], body, observations, principal)

    def terminal_status(self):
        observed = self.get(head_key())
        state = "terminal_observed" if observed["result"] == "present" and observed["body"]["terminal"] else "unsealed"
        self._emit("terminal_status", observation=observed["id"], state=state)
        return state

    def prepare_checkpoint(self, identifier):
        base = self.get(head_key())
        body = base.get("body")
        if body is None or body["scope"] != list(OLD) or body["checkpoint"] is not None:
            self.reject("checkpoint_conflict")
        if body["terminal"] is None and self.fault != "deleted_is_retired":
            self.reject("protected_generation")
        if self.semantic_latch:
            self.reject("semantic_latch")
        candidate = self.get(payload_key())
        if candidate["result"] != "present":
            self.reject("empty_page")
        next_head = self.technical(body)
        next_head["checkpoint"] = {
            "serial": next_head["serial"], "scope": list(OLD), "generation": 1,
            "key": payload_key(), "etag": candidate["etag"], "disposition": "pending",
        }
        return self._prepare(identifier, "checkpoint", "PUT", head_key(), base["etag"], next_head, [base["id"], candidate["id"]])

    def prepare_delete(self, identifier, inspect_failure=None):
        base = self.get(head_key())
        if base["result"] != "present" or base["body"]["checkpoint"] is None:
            self.reject("batch_conflict")
        checkpoint = base["body"]["checkpoint"]
        present = self.get(checkpoint["key"], inspect_failure)
        if present["result"] in ("unknown", "budget"):
            self.reject("inspect_" + present["result"])
        if present["result"] == "missing":
            self._emit("absence_observed", head=base["id"], observation=present["id"], batch=checkpoint["serial"])
            return present["id"]
        condition = present["etag"] if self.fault == "refresh_delete_etag" else checkpoint["etag"]
        return self._prepare(identifier, "delete", "DELETE", checkpoint["key"], condition, None, [base["id"], present["id"]])

    def prepare_settle(self, identifier, delete_call=None, absent=None):
        base = self.get(head_key())
        checkpoint = base.get("body", {}).get("checkpoint")
        if checkpoint is None:
            self.reject("batch_conflict")
        if self.semantic_latch:
            self.reject("semantic_latch")
        observations = [base["id"]]
        if absent is not None:
            read = self.reads[absent]
            if read["process"] != self.process or read["key"] != checkpoint["key"] or read["result"] != "missing":
                self.reject("no_typed_absence")
            disposition = "observed_absent"
            observations.append(absent)
        else:
            call = self.calls[delete_call]
            if call.reply not in ("applied", "missing", "conflict") and self.fault != "unknown_is_applied":
                self.reject("unresolved_delete")
            disposition = {"missing": "observed_absent", "conflict": "condition_mismatch"}.get(call.reply, "applied")
        body = self.technical(base["body"])
        body["checkpoint"]["disposition"] = disposition
        self._prepare(identifier, "settle", "PUT", head_key(), base["etag"], body, observations)
        self._emit("settlement_source", id=identifier, delete_call=delete_call, absent=absent)
        return identifier

    def prepare_clear(self, identifier):
        base = self.get(head_key())
        checkpoint = base.get("body", {}).get("checkpoint")
        if checkpoint is None or checkpoint["disposition"] == "pending":
            self.reject("unsettled_batch")
        if self.semantic_latch:
            self.reject("semantic_latch")
        body = self.technical(base["body"])
        body["checkpoint"] = None
        return self._prepare(identifier, "clear", "PUT", head_key(), base["etag"], body, [base["id"]])

    def prove_abort(self, identifier="prove"):
        head, observations = self.authority()
        if self.mode not in ("abort", "abort_absent"):
            self.reject("not_abort")
        body = {"control": "control:51", "kind": "own", "revision": head["body"]["revision"], "nonce": head["body"]["nonce"]}
        return self._prepare(identifier, "prove", "PUT", "proof:31", "absent", body, observations)

    def release_name(self, identifier="release"):
        head, observations = self.authority()
        binding = self.get("name:demo")
        observations.append(binding["id"])
        proof = self.get("proof:31")
        observations.append(proof["id"])
        if self.mode.startswith("abort") and proof["result"] != "present":
            self.reject("proof_before_release")
        if binding["body"]["stage"] not in ("bound", "aborting"):
            self.reject("name_already_released")
        body = deepcopy(binding["body"])
        body.update(stage="tombstone", revision=body["revision"] + 1, control="control:51", proof="proof:31" if self.mode.startswith("abort") else None)
        return self._prepare(identifier, "release", "PUT", "name:demo", binding["etag"], body, observations)

    def reuse_name(self):
        head, observations = self.authority()
        binding = self.get("name:demo")
        if binding["body"]["stage"] != "tombstone":
            self.reject("name_not_released")
        next_name = {"scope": list(SUCCESSOR), "stage": "successor", "revision": 4, "control": None, "proof": None}
        self._put("name:demo", next_name)
        successor = deepcopy(head["body"])
        successor.update(format=6, scope=list(SUCCESSOR), serial=1, revision=1, nonce=1, lifecycle="ready", terminal=None, checkpoint=None, deletion=None, active=True, active_generation=1, allocated=1,
                         creation={"creator": ADMIN, "operation": 32, "descriptor": "descriptor:32"})
        self._put(head_key(SUCCESSOR), successor)
        self._emit("name_reuse", observations=observations + [binding["id"]], binding=deepcopy(self.store["name:demo"]), head=deepcopy(self.store[head_key(SUCCESSOR)]))

    def recover_intent(self, nonce=101):
        head, observations = self.authority()
        control = self.store["control:51"]["body"]
        if nonce != control["nonce"]:
            self.reject("same_operation_different_intent")
        binding = self.store["name:demo"]["body"]
        state = "aborted" if self.mode.startswith("abort") else "deleted"
        if binding["stage"] not in ("tombstone", "successor"):
            state = "aborting" if self.mode.startswith("abort") else "deleting"
        self.directory_replies.append(state)
        self._emit("directory_reply", observations=observations, state=state, original_control=deepcopy(control))
        return state

    def foreign_abort_view(self):
        # This grants only the old creator's metadata cancellation progress.
        # It is deliberately not an own-HEAD or payload retirement authority.
        descriptor = self.get("descriptor:31")
        control = self.get("control:51")
        previous = self.get("name:demo")
        proof = self.get("proof:31")
        head = self.get(head_key())
        binding = self.get("name:demo")
        values = (descriptor, control, previous, proof, head, binding)
        if any(value["result"] != "present" for value in values):
            self.reject("missing_foreign_abort_authority")
        if previous["body"] != binding["body"] or previous["etag"] != binding["etag"]:
            self.reject("changing_name")
        original = control["body"]
        if descriptor["body"]["scope"] != list(OLD) or original["scope"] != list(OLD) or descriptor["body"]["origin"] != original["origin"] or original["principal"] != ADMIN or original["kind"] != "abort":
            self.reject("intent_mismatch")
        expected = {"control": "control:51", "kind": "foreign", "scope": head["body"]["scope"], "creation": head["body"]["creation"]}
        if head["body"]["scope"] == list(OLD) or proof["body"] != expected or binding["body"]["scope"] != list(OLD) or binding["body"]["stage"] not in ("aborting", "tombstone"):
            self.reject("foreign_barrier_mismatch")
        return binding, original, [value["id"] for value in values]

    def release_foreign_abort(self, identifier="foreign-release"):
        binding, _, observations = self.foreign_abort_view()
        if binding["body"]["stage"] != "aborting":
            self.reject("name_already_released")
        body = deepcopy(binding["body"])
        body.update(stage="tombstone", revision=body["revision"] + 1, control="control:51", proof="proof:31")
        return self._prepare(identifier, "foreign_release", "PUT", "name:demo", binding["etag"], body, observations)

    def recover_foreign_abort(self, nonce=101):
        binding, control, observations = self.foreign_abort_view()
        if nonce != control["nonce"]:
            self.reject("same_operation_different_intent")
        state = "aborted" if binding["body"]["stage"] == "tombstone" else "aborting"
        self._emit("foreign_directory_reply", observations=observations, state=state, original_control=control)
        return state

    def reader_reply(self):
        call = self.calls["old-read"]
        if self.reader["process"] != self.process:
            self.reject("stale_reader")
        if call.reply not in ("present", "missing"):
            self.reject("reader_no_response")
        if self.reader["failed"]:
            self.reject("closed_prefix")
        if call.reply == "present" and call.stored["body"].get("semantic") == "valid":
            self.reader["outcome"] = "value"
        elif call.reply == "present" and call.stored["body"].get("semantic") == "bad":
            self.reader.update(failed=True, outcome="corrupt")
            self.semantic_latch = True
        else:
            self.reader.update(failed=True, physical=True, outcome="missing")
            self.incidents.add(self.reader["generation"])
        self._emit("reader_reply", state=deepcopy(self.reader), semantic=self.semantic_latch, incidents=sorted(self.incidents))
        return self.reader["outcome"]

    def reader_budget(self):
        if self.reader is None or self.reader["process"] != self.process or self.reader["failed"]:
            self.reject("closed_or_stale_prefix")
        # Local admission/aggregate allowance is not evidence about storage.
        self.reader.update(failed=True, outcome="budget")
        self._emit("reader_budget", state=deepcopy(self.reader), semantic=self.semantic_latch, incidents=sorted(self.incidents))
        return "budget"

    def diagnose(self, failure=None):
        reader = self.reader
        if reader is None or reader["process"] != self.process:
            self.reject("stale_reader")
        if not reader["failed"] or not reader["physical"] or reader["probes"] != 0:
            self.reject("no_diagnostic_prefix")
        if self.clock >= reader["deadline"]:
            self._emit("diagnostic_expired", state=deepcopy(reader))
            return reader["outcome"]
        reader["probes"] += 1
        observed = self.get(head_key(), failure)
        if observed["result"] == "present":
            old, head = reader["basis"], observed["body"]
            contradiction = not valid_head(head) or head["scope"] != old["body"]["scope"] or head["serial"] < old["body"]["serial"] or head["active_generation"] < old["body"]["active_generation"] or head["allocated"] < old["body"]["allocated"]
            contradiction |= head["serial"] == old["body"]["serial"] and (head != old["body"] or observed["etag"] != old["etag"])
            contradiction |= head["serial"] > old["body"]["serial"] and observed["etag"] == old["etag"]
            contradiction |= self.fault != "ignore_terminal_era" and head["terminal"] is not None and head["terminal"]["serial"] <= old["body"]["serial"]
            if contradiction:
                self.semantic_latch = True
            elif retired(head, reader["generation"]):
                reader["outcome"] = "snapshot_expired"
        self._emit("diagnostic", observation=observed["id"], state=deepcopy(reader), semantic=self.semantic_latch, incidents=sorted(self.incidents))
        return reader["outcome"]

    def fresh_lookup(self):
        head = self.get(head_key())
        result = "lifecycle" if head["result"] == "present" and head["body"]["lifecycle"] == "deleted" else "missing"
        self._emit("fresh_lookup", observation=head["id"], result=result)
        return result

    def late_receipt(self, native_failure=False):
        if self.receipt is None:
            self.reject("no_known_receipt")
        outcome = "committed_unavailable" if native_failure else "committed"
        self._emit("receipt_reply", receipt=self.receipt, outcome=outcome, replayed=False)

    def destroy_metadata(self, key):
        observed = self.get(key)
        return self._prepare("metadata-delete", "unsafe_metadata_delete", "DELETE", key, observed["etag"], None, [observed["id"]])

    def corrupt_authority(self, key, body=None):
        # Explicit fault injection, not a protocol action; permanent metadata
        # loss cannot be healed by replaying caller-supplied control fields.
        if body is None:
            self.store.pop(key, None)
        else:
            self._put(key, body)
        self._emit("fault_injection", key=key, stored=deepcopy(self.store.get(key)))

    def snapshot(self):
        return {"store": deepcopy(self.store), "process": self.process, "clock": self.clock,
                "calls": {key: deepcopy(vars(value)) for key, value in sorted(self.calls.items())},
                "reader": deepcopy(self.reader), "incidents": sorted(self.incidents), "semantic": self.semantic_latch}

    def history(self):
        return {"schema": 1, "events": deepcopy(self.events), "final": self.snapshot()}
