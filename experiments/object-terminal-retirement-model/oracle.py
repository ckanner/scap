"""Independent trace checker for the finite terminal-retirement experiment.

Only JSON-like records enter this module. It never imports the simulator,
scheduler, a candidate constructor, or production SCAP code.
"""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys


SCOPE = [1, 7, 11, 1, 1]
NEXT_SCOPE = [1, 7, 12, 1, 1]
HEAD = "head:1/7/11"
DATA = "payload:1/7/11/1/1:1:live"


class Violation(Exception):
    def __init__(self, rule, sequence):
        self.rule, self.sequence = rule, sequence
        super().__init__(f"{rule} at event {sequence}")


def require(condition, rule, sequence):
    if not condition:
        raise Violation(rule, sequence)


def unchanged(before, after, exceptions):
    return {k: v for k, v in before.items() if k not in exceptions} == {
        k: v for k, v in after.items() if k not in exceptions
    }


def state_retired(head, generation):
    if generation < 1 or generation > head["allocated"]:
        return False
    if head["terminal"] is not None:
        return head["format"] == 7 and head["lifecycle"] == "deleted" and not head["active"]
    return generation not in (head["active_generation"], head["plan_target"])


def head_shape(head):
    counters = 1 <= head["active_generation"] <= head["allocated"] <= head["serial"] <= 31
    if head["format"] == 6:
        return counters and head["terminal"] is None
    terminal = head["terminal"]
    return counters and head["format"] == 7 and terminal is not None and head["allocated"] < terminal["serial"] <= head["serial"] and head["revision"] < terminal["serial"] and head["lifecycle"] == "deleted" and head["active"] is False and head["plan_target"] is None and (head["checkpoint"] is None or terminal["serial"] < head["checkpoint"]["serial"] <= head["serial"])


def reader_state(actual, expected, sequence):
    for name in ("process", "generation", "deadline", "backend", "failed", "physical", "probes", "outcome"):
        require(actual[name] == expected[name], "captured_reader_context", sequence)
    basis = expected["basis"]
    require(actual["basis"] == {"id": basis["sequence"], "key": basis["key"], "process": basis["process"], "result": basis["result"], **basis["stored"]}, "captured_reader_context", sequence)


def catalogue(head, observations, sequence):
    if head["creation"] is None:
        require(head["deletion"] is None, "direct_identity", sequence)
        return
    by_key = {value["key"]: value for value in observations}
    for key in ("descriptor:31", "control:51", "name:demo"):
        require(key in by_key and by_key[key]["result"] == "present", "catalogue_authority", sequence)
    require("proof:31" in by_key, "catalogue_authority", sequence)
    descriptor = by_key["descriptor:31"]["stored"]["body"]
    control = by_key["control:51"]["stored"]["body"]
    name = by_key["name:demo"]["stored"]["body"]
    proof = by_key["proof:31"]
    view_proof = next(value for value in observations if value["key"] == "proof:31")
    names = [value for value in observations if value["key"] == "name:demo"]
    heads = [value for value in observations if value["key"] == HEAD]
    require(len(names) >= 2 and heads and names[0]["stored"] == names[1]["stored"], "stable_catalogue_view", sequence)
    require(names[0]["sequence"] < view_proof["sequence"] < heads[-1]["sequence"] < names[1]["sequence"], "proof_before_head_view", sequence)
    require(descriptor["scope"] == SCOPE and descriptor["origin"] == head["creation"], "catalogue_authority", sequence)
    require(control == head["deletion"] and control["scope"] == SCOPE and control["origin"] == head["creation"], "catalogue_authority", sequence)
    require(head["nonce"] == control["nonce"], "business_barrier", sequence)
    require(name["scope"] == SCOPE or name["stage"] == "successor" and name["scope"] == NEXT_SCOPE and name["revision"] > 3, "name_identity", sequence)
    if control["kind"] == "delete":
        require(control["expected_name_revision"] == 2 and head["revision"] == control["expected_head_revision"] + 1, "business_barrier", sequence)
        require(name["stage"] in ("bound", "tombstone", "successor") and proof["result"] == "missing", "catalogue_authority", sequence)
    else:
        require(control["expected_name_revision"] == 1 and control["expected_head_revision"] is None and head["revision"] in (1, 2), "business_barrier", sequence)
        require(name["stage"] in ("aborting", "tombstone", "successor"), "catalogue_authority", sequence)
        if name["stage"] != "aborting":
            require(proof["result"] == "present", "catalogue_authority", sequence)
        if proof["result"] == "present":
            expected = {"control": "control:51", "kind": "own", "revision": head["revision"], "nonce": head["nonce"]}
            require(proof["stored"]["body"] == expected, "business_barrier", sequence)


def foreign_catalogue(observations, sequence):
    by_key = {value["key"]: value for value in observations}
    for key in (HEAD, "descriptor:31", "control:51", "name:demo", "proof:31"):
        require(key in by_key and by_key[key]["result"] == "present", "foreign_catalogue_authority", sequence)
    names = [value for value in observations if value["key"] == "name:demo"]
    require(len(names) == 2 and names[0]["stored"] == names[1]["stored"], "stable_catalogue_view", sequence)
    require(names[0]["sequence"] < by_key["proof:31"]["sequence"] < by_key[HEAD]["sequence"] < names[1]["sequence"], "proof_before_head_view", sequence)
    head = by_key[HEAD]["stored"]["body"]
    descriptor = by_key["descriptor:31"]["stored"]["body"]
    control = by_key["control:51"]["stored"]["body"]
    proof = by_key["proof:31"]["stored"]["body"]
    name = names[1]["stored"]["body"]
    require(descriptor["scope"] == SCOPE and control["scope"] == SCOPE and descriptor["origin"] == control["origin"] and control["principal"] == control["origin"]["creator"] == 7 and control["kind"] == "abort", "foreign_catalogue_authority", sequence)
    require(head["scope"] != SCOPE and proof == {"control": "control:51", "kind": "foreign", "scope": head["scope"], "creation": head["creation"]}, "foreign_proof_not_owned", sequence)
    require(name["scope"] == SCOPE and name["stage"] in ("aborting", "tombstone"), "foreign_catalogue_authority", sequence)
    return names[1], control


def audit(history, check_final=True):
    require(history.get("schema") == 1, "schema", 0)
    events = history["events"]
    require(0 < len(events) <= 1024 and events[0]["event"] == "initial", "initial", 0)
    store = deepcopy(events[0]["store"])
    original_receipt = deepcopy(events[0]["receipt"])
    if events[0]["mode"] in ("abort", "abort_absent", "foreign"):
        require(original_receipt is None, "initial_receipt", 0)
    else:
        require(original_receipt["scope"] == SCOPE and original_receipt["request"] == original_receipt["nonce"], "initial_receipt", 0)
    require(all(head_shape(value["body"]) for key, value in store.items() if key.startswith("head:")), "initial_head", 0)
    process, clock = 1, 0
    observations, calls = {}, {}
    semantic, incidents = False, set()
    reader = None
    retired_scopes = set()
    count = {"events": 0, "terminal_applied": 0, "payload_delete": 0, "unknown": 0,
             "expired": 0, "directory_replies": 0, "late_effects": 0}

    for index, event in enumerate(events, 1):
        require(event["sequence"] == index, "event_order", index)
        kind = event["event"]
        count["events"] += 1
        if kind == "initial":
            require(index == 1, "initial", index)
            continue
        if kind == "crash":
            require(event["previous"] == process and event["process"] == process + 1, "process_identity", index)
            process += 1
            semantic, incidents = False, set()
            continue
        require(event["process"] == process, "process_identity", index)
        if kind == "get":
            require(event["result"] in ("present", "missing", "unknown", "budget"), "typed_get", index)
            if event["result"] in ("unknown", "budget"):
                require(event["stored"] is None, "typed_get", index)
            else:
                require(event["stored"] == store.get(event["key"]), "exact_get", index)
                require((event["result"] == "present") == (event["key"] in store), "exact_get", index)
            observations[index] = deepcopy(event)
        elif kind == "tick":
            require(clock < event["clock"] <= 32, "original_deadline", index)
            clock = event["clock"]
        elif kind == "prepare":
            identifier = event["id"]
            require(identifier not in calls and len(calls) < 48, "call_identity", index)
            obs = []
            for token in event["observations"]:
                require(token in observations and observations[token]["process"] == process, "fresh_process_observation", index)
                obs.append(observations[token])
            head_obs = next((value for value in reversed(obs) if value["key"] == HEAD), None)
            base = head_obs["stored"]["body"] if head_obs and head_obs["result"] == "present" else None
            body, operation = event["body"], event["kind"]
            if operation == "terminal":
                require(base is not None and base["scope"] == SCOPE, "scope_binding", index)
                require(head_shape(base), "head_shape", index)
                require(base["lifecycle"] == "deleted" and base["terminal"] is None, "explicit_terminal_transition", index)
                require(base["admin"] == event["principal"] and event["principal"] == 7, "current_admin", index)
                require(base["plan_target"] is None and base["checkpoint"] is None, "no_protected_maintenance", index)
                require(not semantic and base["active_generation"] not in incidents, "lineage_publication_gate", index)
                catalogue(base, obs, index)
                require(event["condition"] == head_obs["stored"]["etag"], "original_condition", index)
                require(unchanged(base, body, {"format", "serial", "active", "terminal"}), "business_barrier", index)
                require(body["format"] == 7 and body["serial"] == base["serial"] + 1 and not body["active"] and body["terminal"] == {"serial": body["serial"]}, "terminal_shape", index)
            elif operation in ("checkpoint", "settle", "clear"):
                require(base is not None and base["scope"] == SCOPE and base["terminal"] is not None and base["format"] == 7, "explicit_retirement_before_gc", index)
                require(head_shape(base) and base["admin"] == event["principal"] == 7, "current_admin", index)
                require(not semantic, "lineage_publication_gate", index)
                require(event["condition"] == head_obs["stored"]["etag"], "original_condition", index)
                require(body["serial"] == base["serial"] + 1 and unchanged(base, body, {"serial", "checkpoint"}), "terminal_monotonicity", index)
                if operation == "checkpoint":
                    cp = body["checkpoint"]
                    require(base["checkpoint"] is None and cp["serial"] == body["serial"], "batch_identity", index)
                    require(cp["scope"] == SCOPE and cp["generation"] == 1 and cp["key"] == DATA and state_retired(base, 1), "scope_binding", index)
                    actual = next((value for value in obs if value["key"] == DATA and value["result"] == "present"), None)
                    require(actual is not None and cp["etag"] == actual["stored"]["etag"] and cp["disposition"] == "pending", "exact_candidate_etag", index)
                elif operation == "settle":
                    require(base["checkpoint"] is not None and body["checkpoint"] is not None and unchanged(base["checkpoint"], body["checkpoint"], {"disposition"}), "batch_identity", index)
                    require(body["checkpoint"]["disposition"] in ("applied", "observed_absent", "condition_mismatch"), "settled_disposition", index)
                else:
                    require(base["checkpoint"] is not None and base["checkpoint"]["disposition"] != "pending" and body["checkpoint"] is None, "observed_settlement_before_clear", index)
            elif operation == "delete":
                require(base is not None and base["terminal"] is not None and base["checkpoint"] is not None, "fresh_batch_authorization", index)
                require(head_shape(base) and base["admin"] == event["principal"] == 7, "current_admin", index)
                cp = base["checkpoint"]
                require(event["key"] == cp["key"] == DATA and cp["scope"] == SCOPE and state_retired(base, cp["generation"]), "scope_binding", index)
                require(event["condition"] == cp["etag"], "original_delete_etag", index)
                require(any(value["key"] == DATA and value["result"] == "present" for value in obs), "exact_candidate_get", index)
            elif operation == "unsafe_metadata_delete":
                require(False, "permanent_metadata", index)
            elif operation in ("prove", "release"):
                require(base is not None and base["scope"] == SCOPE and base["lifecycle"] == "deleted", "catalogue_authority", index)
                catalogue(base, obs, index)
                if operation == "prove":
                    require(event["key"] == "proof:31" and event["condition"] == "absent" and body == {"control": "control:51", "kind": "own", "revision": base["revision"], "nonce": base["nonce"]}, "business_barrier", index)
                else:
                    name_obs = [value for value in obs if value["key"] == "name:demo"][-1]
                    name = name_obs["stored"]["body"]
                    require(event["condition"] == name_obs["stored"]["etag"] and body["scope"] == SCOPE and body["revision"] == name["revision"] + 1 and body["stage"] == "tombstone", "original_name_condition", index)
                    if base["deletion"]["kind"] == "abort":
                        require(any(value["key"] == "proof:31" and value["result"] == "present" for value in obs), "proof_before_release", index)
            elif operation == "foreign_release":
                name, _ = foreign_catalogue(obs, index)
                require(event["key"] == "name:demo" and event["condition"] == name["stored"]["etag"] and event["principal"] == 7, "original_name_condition", index)
                expected = deepcopy(name["stored"]["body"])
                require(expected["stage"] == "aborting", "foreign_catalogue_authority", index)
                expected.update(stage="tombstone", revision=expected["revision"] + 1, control="control:51", proof="proof:31")
                require(body == expected, "foreign_metadata_only", index)
            elif operation == "old_put":
                require(event["key"] == DATA and event["condition"] == "absent" and body["scope"] == SCOPE, "immutable_namespace", index)
            elif operation == "old_head":
                require(base is not None and event["condition"] == head_obs["stored"]["etag"] and body["scope"] == base["scope"], "original_condition", index)
            elif operation == "read":
                require(base is not None and base["scope"] == SCOPE and event["key"] == DATA, "captured_reader_namespace", index)
                require(base["lifecycle"] == "ready", "reader_admission", index)
                reader = {"basis": deepcopy(head_obs), "process": process, "generation": 1, "deadline": 10, "backend": "original", "failed": False, "physical": False, "probes": 0, "outcome": None}
            elif operation == "initial_create":
                require(event["condition"] == "absent" and event["key"] == HEAD and body["scope"] == SCOPE, "permanent_slot_condition", index)
            elif operation == "logical_delete":
                require(body["lifecycle"] == "deleted" and body["terminal"] is None and body["format"] == 6, "logical_delete_is_not_retirement", index)
                require(event["condition"] == (head_obs["stored"]["etag"] if base else "absent"), "original_condition", index)
            else:
                require(False, "unknown_operation", index)
            calls[identifier] = {"request": deepcopy(event), "phase": "prepared", "result": None, "stored": None, "reply": None, "settlement": operation != "settle"}
        elif kind == "settlement_source":
            call = calls[event["id"]]
            cp = call["request"]["body"]["checkpoint"]
            if event["absent"] is not None:
                read = observations[event["absent"]]
                require(read["process"] == process and read["key"] == cp["key"] and read["result"] == "missing" and cp["disposition"] == "observed_absent", "typed_absence", index)
            else:
                original = calls[event["delete_call"]]
                require(original["request"]["kind"] == "delete" and original["reply"] in ("applied", "missing", "conflict"), "unknown_not_disposition", index)
                expected = {"applied": "applied", "missing": "observed_absent", "conflict": "condition_mismatch"}[original["reply"]]
                require(cp["disposition"] == expected and original["request"]["condition"] == cp["etag"], "original_delete_etag", index)
            call["settlement"] = True
        elif kind == "invoke":
            call = calls[event["id"]]
            require(call["phase"] == "prepared" and call["request"]["process"] == process and call["settlement"], "fresh_process_invocation", index)
            call["phase"] = "invoked"
        elif kind == "effect":
            call = calls[event["id"]]
            require(call["phase"] == "invoked", "effect_after_invocation", index)
            request = call["request"]
            current = store.get(request["key"])
            method, condition = request["method"], request["condition"]
            if method == "GET":
                expected = "present" if current else "missing"
                require(event["stored"] == current, "linearized_get", index)
            elif condition == "absent" and current is not None:
                expected = "conflict"
            elif condition != "absent" and (current is None or current["etag"] != condition):
                expected = "missing" if current is None and method == "DELETE" else "conflict"
            else:
                expected = "applied"
                if method == "DELETE":
                    require(request["kind"] == "delete" and request["key"] == DATA, "permanent_metadata", index)
                    require(tuple(SCOPE) in retired_scopes, "permanent_retirement", index)
                    del store[request["key"]]
                    count["payload_delete"] += 1
                else:
                    require(event["stored"] is not None and event["stored"]["body"] == request["body"] and bool(event["stored"]["etag"]), "sealed_request_bytes", index)
                    if request["key"] == HEAD:
                        require(head_shape(request["body"]), "head_shape", index)
                        if current is not None:
                            require(request["body"]["serial"] > current["body"]["serial"] and event["stored"]["etag"] != current["etag"], "head_serial_and_etag", index)
                    if request["key"] == HEAD and current is not None and current["body"]["terminal"] is not None:
                        require(request["body"]["terminal"] == current["body"]["terminal"] and unchanged(current["body"], request["body"], {"serial", "checkpoint"}), "terminal_monotonicity", index)
                    store[request["key"]] = deepcopy(event["stored"])
                    if request["kind"] == "terminal":
                        retired_scopes.add(tuple(SCOPE))
                        count["terminal_applied"] += 1
            require(event["result"] == expected, "conditional_store", index)
            call.update(phase="effected", result=expected, stored=deepcopy(event["stored"]))
            if call["reply"] == "unknown" or request["process"] != process:
                count["late_effects"] += 1
        elif kind == "response":
            call = calls[event["id"]]
            require(call["reply"] is None and call["phase"] in ("invoked", "effected"), "single_original_response", index)
            result = event["result"]
            if result != "unknown":
                require(call["phase"] == "effected" and call["result"] == result and call["request"]["process"] == process, "known_response", index)
            else:
                count["unknown"] += 1
            call["reply"] = result
        elif kind == "terminal_status":
            value = observations[event["observation"]]
            expected = "terminal_observed" if value["result"] == "present" and value["stored"]["body"]["terminal"] else "unsealed"
            require(event["state"] == expected, "state_observation_not_call_outcome", index)
        elif kind == "absence_observed":
            require(observations[event["observation"]]["result"] == "missing", "typed_absence", index)
        elif kind == "name_reuse":
            obs = [observations[token] for token in event["observations"]]
            base = next(value["stored"]["body"] for value in obs if value["key"] == HEAD)
            catalogue(base, obs, index)
            require(event["binding"]["body"]["scope"] == NEXT_SCOPE and event["head"]["body"]["scope"] == NEXT_SCOPE and head_shape(event["head"]["body"]), "new_name_new_slot", index)
            require("head:1/7/12" not in store and event["head"]["body"]["terminal"] is None and event["head"]["body"]["deletion"] is None, "new_name_new_slot", index)
            store["name:demo"] = deepcopy(event["binding"])
            store["head:1/7/12"] = deepcopy(event["head"])
        elif kind == "directory_reply":
            obs = [observations[token] for token in event["observations"]]
            base = next(value["stored"]["body"] for value in obs if value["key"] == HEAD)
            catalogue(base, obs, index)
            require(event["original_control"] == base["deletion"], "original_intent_recovery", index)
            name = [value for value in obs if value["key"] == "name:demo"][-1]["stored"]["body"]
            completed = name["stage"] in ("tombstone", "successor")
            aborting = base["deletion"]["kind"] == "abort"
            expected = ("aborted" if aborting else "deleted") if completed else ("aborting" if aborting else "deleting")
            require(event["state"] == expected, "directory_completion", index)
            count["directory_replies"] += 1
        elif kind == "foreign_directory_reply":
            name, control = foreign_catalogue([observations[token] for token in event["observations"]], index)
            require(event["original_control"] == control, "original_intent_recovery", index)
            expected = "aborted" if name["stored"]["body"]["stage"] == "tombstone" else "aborting"
            require(event["state"] == expected, "directory_completion", index)
            count["directory_replies"] += 1
        elif kind == "reader_reply":
            call = calls["old-read"]
            require(reader is not None and reader["process"] == process and not reader["failed"] and call["reply"] in ("present", "missing"), "reader_prefix", index)
            if call["reply"] == "present" and call["stored"]["body"].get("semantic") == "valid":
                reader["outcome"] = "value"
            elif call["reply"] == "present" and call["stored"]["body"].get("semantic") == "bad":
                reader.update(failed=True, outcome="corrupt")
                semantic = True
            else:
                reader.update(failed=True, physical=True, outcome="missing")
                incidents.add(1)
            require(event["state"]["outcome"] == reader["outcome"] and event["semantic"] == semantic and set(event["incidents"]) == incidents, "failure_provenance", index)
            reader_state(event["state"], reader, index)
        elif kind == "reader_budget":
            require(reader is not None and reader["process"] == process and not reader["failed"], "reader_prefix", index)
            reader.update(failed=True, outcome="budget")
            require(event["semantic"] == semantic and set(event["incidents"]) == incidents, "local_budget_not_storage_fault", index)
            reader_state(event["state"], reader, index)
        elif kind == "diagnostic":
            require(reader is not None and reader["process"] == process and reader["failed"] and reader["physical"] and reader["probes"] == 0, "single_diagnostic", index)
            require(clock < reader["deadline"], "original_deadline", index)
            reader["probes"] += 1
            value = observations[event["observation"]]
            if value["result"] == "present":
                old = reader["basis"]["stored"]
                fresh = value["stored"]
                a, b = old["body"], fresh["body"]
                contradiction = not head_shape(b) or b["scope"] != a["scope"] or b["serial"] < a["serial"] or b["active_generation"] < a["active_generation"] or b["allocated"] < a["allocated"]
                contradiction |= b["serial"] == a["serial"] and fresh != old
                contradiction |= b["serial"] > a["serial"] and fresh["etag"] == old["etag"]
                contradiction |= b["terminal"] is not None and b["terminal"]["serial"] <= a["serial"]
                if contradiction:
                    semantic = True
                elif state_retired(b, 1):
                    reader["outcome"] = "snapshot_expired"
                    count["expired"] += 1
            require(event["state"]["outcome"] == reader["outcome"] and event["state"]["probes"] == 1 and event["semantic"] == semantic and set(event["incidents"]) == incidents, "strict_expiry_proof", index)
            reader_state(event["state"], reader, index)
        elif kind == "diagnostic_expired":
            require(reader is not None and reader["process"] == process and reader["probes"] == 0 and reader["failed"] and reader["physical"] and clock >= reader["deadline"], "original_deadline", index)
            reader_state(event["state"], reader, index)
        elif kind == "fresh_lookup":
            value = observations[event["observation"]]
            expected = "lifecycle" if value["result"] == "present" and value["stored"]["body"]["lifecycle"] == "deleted" else "missing"
            require(event["result"] == expected, "deleted_lookup_contract", index)
        elif kind == "receipt_reply":
            require(original_receipt is not None and event["receipt"] == original_receipt and event["outcome"] in ("committed", "committed_unavailable") and event["replayed"] is False, "known_receipt_preserved", index)
        elif kind == "foreign_proof":
            foreign = store[HEAD]["body"]
            require(foreign["scope"] != SCOPE and event["stored"]["body"] == {"control": "control:51", "kind": "foreign", "scope": foreign["scope"], "creation": foreign["creation"]}, "foreign_proof_not_owned", index)
            store["proof:31"] = deepcopy(event["stored"])
        elif kind == "authority_invalid":
            observed = observations[event["observation"]]
            require(observed["result"] == "present" and not head_shape(observed["stored"]["body"]), "invalid_authority_source", index)
            semantic = True
        elif kind == "fault_injection":
            if event["stored"] is None:
                store.pop(event["key"], None)
            else:
                store[event["key"]] = deepcopy(event["stored"])
        elif kind == "rejected":
            require(isinstance(event["reason"], str) and bool(event["reason"]), "typed_rejection", index)
        else:
            require(False, "unknown_event", index)
    if not check_final:
        return count
    require(history["final"]["store"] == store and history["final"]["process"] == process and history["final"]["clock"] == clock, "complete_final_state", len(events))
    require(history["final"]["semantic"] == semantic and set(history["final"]["incidents"]) == incidents, "complete_final_knowledge", len(events))
    if reader is not None:
        reader_state(history["final"]["reader"], reader, len(events))
    for identifier, call in calls.items():
        final = history["final"]["calls"][identifier]
        require(all(final[key] == call[key] for key in ("phase", "result", "stored", "reply")), "complete_final_calls", len(events))
    return count


def main():
    history = json.loads(Path(sys.argv[1]).read_text())
    try:
        print(json.dumps({"ok": True, "counts": audit(history)}, sort_keys=True))
    except (Violation, KeyError, TypeError, ValueError) as error:
        print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
