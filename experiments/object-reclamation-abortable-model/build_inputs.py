"""Expand the reviewed inventory into finite programs, before any exploration.

This file builds fixtures only. It imports neither reducer nor acceptance oracle.
All pause barriers, initial-state assumptions and network bounds are serialized.
"""

import copy
import hashlib
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
SCOPE = {"deployment": 1, "tenant": 7, "database": 9, "incarnation": 13, "generation": 17}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def step(op, **values):
    return {"op": op, **values}


def mark(name):
    return step("mark", name=name)


def wait(actor, marker):
    return step("await", condition={"mark": actor + "/" + marker})


def until(condition):
    return step("await", condition=condition)


def observe(**values):
    return step("observe", **values)


def head(**values):
    observation = {key: values.pop(key) for key in tuple(values) if key in ("allow_failure", "allow_unknown")}
    return [step("head_get", **values), observe(**observation)]


def publish(op, *, uncertain=False, label=None, allow_unknown=False, allow_failure=False, **values):
    send = step("send_head", uncertain=uncertain)
    if label is not None:
        send["label"] = label
    return [step("prepare_" + op, **values), send,
            observe(allow_unknown=allow_unknown, allow_failure=allow_failure)]


def change(op, **values):
    return [*head(), *publish(op, **values)]


def load(name, **values):
    observation = {key: values.pop(key) for key in tuple(values) if key in ("allow_failure", "allow_unknown")}
    return [step("object_get", name=name, **values), observe(**observation)]


def enter(mode="read"):
    return [*head(), step("admit", mode=mode)]


def read_end():
    return [step("materialize"), step("return_read")]


def investigate():
    return [*head(purpose="failure", allow_failure=True, allow_unknown=True), step("classify_failure")]


def capture(nonce=None):
    return [*head(), step("capture_plan", **({"nonce": nonce} if nonce else {}))]


def copies(count):
    return [part for index in range(count) for op in ("copy_source", "copy_put", "copy_verify")
            for part in (step(op, index=index), observe())]


def migration(nonce="copy2", count=2):
    return [*change("freeze", nonce=nonce), *capture(nonce), *copies(count),
            *change("seal"), *change("promote")]


def candidate(name, generation=1, reset=False):
    return [step("candidate_get", name=name, generation=generation), observe(), step("capture_candidate", reset=reset)]


def install(names, *, generation=1, batch="batch1", plan="sweep1", uncertain=False):
    return [*head(), *(part for index, name in enumerate(names) for part in candidate(name, generation, reset=index == 0)),
            *head(), *publish("checkpoint", batch=batch, plan=plan, uncertain=uncertain,
                              label=batch, allow_unknown=uncertain),
            *head(), step("observe_checkpoint")]


def persist_and_clear():
    return [*change("dispositions"), *head(), step("observe_checkpoint"),
            *change("clear"), *head(), step("confirm_clear")]


def sweep(names, *, generation=1, batch="batch1"):
    return [*install(names, generation=generation, batch=batch),
            *(part for index in range(len(names)) for part in
              (step("delete", index=index), observe(), step("record_disposition", index=index))),
            *persist_and_clear()]


def writer_prepare():
    values = [*enter("write"), step("native_execute")]
    for name in ("D", "E", "F"):
        values.extend([step("object_put", name=name), observe(), *load(name, purpose="readback")])
    values.append(step("prepare_write", data="D", result="F", dependencies=["D", "E", "F"], request="req-original"))
    return values


def writer_finish(*, uncertain=False):
    return [step("send_head", label="write", uncertain=uncertain), observe(allow_unknown=uncertain),
            step("native_publish"), step("ack_write")]


def bootstrap():
    return [step("bootstrap"), *(part for name in ("A", "B", "C") for part in load(name, purpose="readback"))]


def actor(program, principal=1, role="client", worker=11):
    return {"principal": principal, "worker": worker, "role": role, "program": program}


def main():
    frames = {}

    def frame(name, kind, refs=(), receipt=None, unusual=False):
        body = {"scope": SCOPE, "kind": kind, "references": [frames[key]["hash"] for key in refs]}
        if receipt:
            body["receipt_data_root"] = frames[receipt]["hash"]
        body["value"] = name
        raw = b"MODELFRAME1\n" + (json.dumps(body, indent=1).encode() if unusual else canonical(body))
        frames[name] = {"hash": hashlib.sha256(raw).hexdigest(), "raw": raw.hex(),
                        "references": body["references"], "kind": kind}

    frame("B", "data")
    frame("A", "data", ("B",))
    frame("C", "result", receipt="A", unusual=True)
    frame("E", "data")
    frame("D", "data", ("E",))
    frame("F", "result", receipt="D")
    acl = {str(value): {"read": True, "write": value == 1, "admin": value == 1} for value in (1, 2, 3)}
    initial = {"scope": SCOPE, "serial": 1, "revision": 1, "sequence": 0, "A": 1, "M": 1,
               "life": "ready", "owner": 11, "owner_epoch": 1, "active": True, "acl": acl,
               "creation": "creator1-operation7-descriptor", "data": frames["A"]["hash"],
               "results": [frames["C"]["hash"]], "plan": None, "hold": None, "checkpoint": None}
    spec = {"schema": "scap-abortable-generation-model-input-v1", "scope": SCOPE, "creator": 1,
            "creation": initial["creation"], "initial_head": initial,
            "initial_roots": [initial["data"], *initial["results"]], "frames": frames,
            "inventory_sha256": hashlib.sha256((HERE / "SCENARIOS.md").read_bytes()).hexdigest(),
            "bounds": {"actors": 4, "generations": 3, "frames": 6, "references_per_frame": 2,
                       "graph_depth": 2, "holds": 1, "plans_or_checkpoints": 1, "ordinary_pins": 0,
                       "candidates": 2, "steps_per_actor": 128, "tokens": 96,
                       "states_per_profile": 50000, "edges_per_profile": 150000, "seconds_per_profile": 120},
            "claims": {"production_protocol_enabled": False, "absolute_deadline_timing": "NOT_MODELED",
                       "sql_native_semantics": "ABSTRACT_OUTCOME_ONLY", "frame_format": "MODELFRAME1_NOT_SCAPOBJ2",
                       "list_inventory": "EXPLICIT_FINITE_CANDIDATES", "durable_checkpoint_transport": "MODELED",
                       "caller_detach": "NOT_WORKER_DEADLINE", "whole_system_fairness_or_liveness": "NOT_MODELED"},
            "required_current_rights": {
                "ordinary_read_admit": "read; lifecycle Ready",
                "ordinary_write_admit": "read+write; lifecycle Ready; active owner worker; no copy plan",
                "provisioning_complete_abort": "exact immutable creator/operation identity; lifecycle Provisioning",
                "copy_freeze_capture_seal_promote_abort": "admin; lifecycle Ready; full current plan identity where applicable; owner worker is not required",
                "new_sweep_candidate_checkpoint_delete": "admin; lifecycle Ready; permanent retirement and exact original checkpoint; owner worker is not required",
                "checkpoint_disposition_clear": "admin; exact original batch; retirement; may close existing batch in Deleted without admitting new DELETE",
                "acl_owner_delete_hold": "admin; operation-specific lifecycle/identity; owner worker is not required",
                "scoped_failure_investigation": "no new READ grant; exact Scope and retirement only",
                "retained_read_return": "original authorized complete materialization, not a new authority grant"},
            "profiles": []}

    def key(generation, name):
        s = SCOPE
        return (f"scap-object/v1/{s['deployment']}/{s['tenant']}/{s['database']}/inc/{s['incarnation']}"
                f"/gen/{s['generation']}/storage/{generation}/objects/{frames[name]['hash']}")

    def add(identifier, actors, witnesses, *, result=False, head_changes=None, objects=None, absent=False,
            initial_plan=False, initial_hold=False, note=""):
        h = copy.deepcopy(initial)
        if not result:
            h["results"] = []
        if head_changes:
            h.update(copy.deepcopy(head_changes))
        if initial_plan:
            h.update(serial=2, M=2, active=False)
            h["plan"] = {"identity": {"scope": SCOPE, "source": 1, "target": 2, "nonce": "old2",
                                      "roots": [h["data"], *h["results"]], "started_serial": 2}, "phase": "copying"}
        if initial_hold:
            h["hold"] = {"id": "retained", "generation": h["A"], "roots": [h["data"], *h["results"]]}
            h["serial"] += 1
            if h["plan"] is not None:
                h["plan"]["identity"]["started_serial"] = h["serial"]
        storage = {}
        inventory = objects or {1: ["A", "B", *(["C"] if result else [])]}
        for generation, names in inventory.items():
            for name in names:
                physical = key(generation, name)
                storage[physical] = {"raw": frames[name]["raw"],
                                     "etag": '"initial:' + hashlib.sha256(physical.encode()).hexdigest() + '"'}
        locals_ = {}
        for name in actors:
            locals_[name] = {"pc": 0, "stopped": None, "labels": {}, "last": None, "last_result": None,
                             "no_work": False, "view": None, "view_token": None, "context": None, "plan": None,
                             "sources": {}, "verified": {}, "frames": {}, "readbacks": {}, "failure": None,
                             "materialized": None, "candidate": None, "native": None, "commit_known": False,
                             "receipt": None, "outcome": None, "detached": False, "local_stop": False, "marks": {},
                             "candidates": [], "intent": None, "intent_base_serial": None, "checkpoint": None,
                             "checkpoint_knowledge": None, "dispositions": {}, "clear_serial": None}
        assert len(actors) <= spec["bounds"]["actors"]
        assert max(len(value["program"]) for value in actors.values()) <= spec["bounds"]["steps_per_actor"], identifier
        profile = {"id": identifier, "actors": actors, "required_witnesses": witnesses,
                   "fixture_assumptions": note or "Initial objects/HEAD are a declared validated cut, not an inferred network history; barriers are explicit fixture scheduling.",
                   "initial": {"head": None if absent else h, "objects": storage, "tokens": {}, "actors": locals_,
                               "health": {}, "authority_corrupt": False, "authority_fault": None, "candidate_fault": None}}
        spec["profiles"].append(profile)

    add("A01", {"r": actor([*enter(), *load("A"), mark("paused"), wait("m", "fenced"),
                             *load("B"), *read_end()], 2),
                "m": actor([wait("r", "paused"), *change("freeze", nonce="copy2"), mark("fenced")])},
        ["last_get_after_fence", "read_success_after_fence", "ordinary_no_head_write"])
    add("A02", {"r": actor([*enter(), *load("A"), *load("B"), step("materialize"), mark("materialized"),
                             wait("m", "swept"), step("return_read")], 2),
                "m": actor([wait("r", "materialized"), *migration(), *sweep(["A", "B"]), mark("swept")])},
        ["return_after_complete_old_sweep", "materialized_before_fence"])
    add("A03", {"r": actor([*enter(), *load("A"), step("object_get", name="B", label="tail"),
                             wait("m", "swept"), observe(label="tail"), *read_end()], 2),
                "m": actor([until({"token": "r/tail", "fields": {"stage": "applied"}}),
                             *migration(), *sweep(["A", "B"]), mark("swept")])},
        ["found_delivery_observed_after_sweep"])
    for identifier, fault, unavailable in (("A04", "missing", False), ("A05", "corrupt", False), ("A09", "missing", True)):
        mover = [wait("r", "paused"), *migration()]
        mover += sweep(["B"]) if fault == "missing" else [step("fault_object", generation=1, name="B", mode="corrupt")]
        if unavailable:
            mover += [step("fault_authority", mode="unavailable")]
        mover += [mark("changed"), wait("r", "classified")]
        if unavailable:
            mover += [step("fault_authority", mode=None)]
        mover += [mark("healthy2")]
        add(identifier, {"r": actor([*enter(), *load("A"), mark("paused"), wait("m", "changed"),
                                      *load("B", allow_failure=True), *investigate(), mark("classified")], 2),
                         "m": actor(mover, role="fixture"),
                         "n": actor([wait("m", "healthy2"), *enter(), *load("A"), *load("B"), *read_end()], 2)},
            ["retired_authority_unknown" if unavailable else "retired_corruption_expired" if fault == "corrupt" else "retired_missing_expired",
             "new_active_remains_healthy"])
    for identifier, fault, unavailable in (("A06", "missing", False), ("A07", "corrupt", False), ("A08", "missing", True)):
        f = [wait("r", "paused")]
        if identifier == "A07":
            f += change("acl", principal=3, read=False)
        f += [step("fault_object", generation=1, name="B", mode=fault)]
        if unavailable:
            f += [step("fault_authority", mode="unavailable")]
        f += [mark("faulted"), wait("r", "classified")]
        if unavailable:
            f += [step("fault_authority", mode=None)]
        f += [mark("investigated")]
        add(identifier, {"r": actor([*enter(), *load("A"), mark("paused"), wait("f", "faulted"),
                                      *load("B", allow_failure=True), *investigate(), mark("classified")], 2),
                         "f": actor(f, role="fixture"), "n": actor([wait("f", "investigated"), *enter()], 2)},
            ["active_authority_unknown" if unavailable else "active_corruption_rejected", "same_active_readmission_blocked"])
    for identifier, op in (("A10", "acl"), ("A11", "delete")):
        extra = {"principal": 2, "read": False} if op == "acl" else {}
        actors = {"r": actor([*enter(), *load("A"), mark("paused"), wait("m", "changed"), *load("B"), *read_end()], 2),
                  "m": actor([wait("r", "paused"), *change(op, **extra), mark("changed")]),
                  "n": actor([wait("m", "changed"), *enter()], 2)}
        if identifier == "A11":
            actors["g"] = actor([wait("m", "changed"), *head(), step("candidate_get", generation=1, name="A")])
        add(identifier, actors, ["original_authorized_read_success", "new_admission_denied",
                                 *( ["deleted_active_gc_rejected"] if identifier == "A11" else [])])

    add("W01", {"w": actor([*writer_prepare(), *writer_finish(), mark("done")]),
                "m": actor([until({"token": "w/write", "fields": {"stage": "applied"}}),
                             *change("freeze", nonce="copy2")])},
        ["write_wins_then_freeze_new_roots", "native_commit_before_ack"], result=True)
    add("W02", {"w": actor([*writer_prepare(), mark("prepared"), wait("m", "fenced"), *writer_finish()]),
                "m": actor([wait("w", "prepared"), *change("freeze", nonce="copy2"), mark("fenced")])},
        ["fence_wins_original_write_conflict", "no_sql_replay"], result=True)
    add("W03", {"w": actor([*writer_prepare(), *writer_finish(uncertain=True)]),
                "m": actor([until({"all": [{"outcome": {"actor": "w", "kind": "unknown"}},
                                             {"token": "w/write", "fields": {"stage": "applied"}}]}),
                             *change("freeze", nonce="copy2")])},
        ["unknown_write_late_applied_before_freeze", "unknown_not_retroactive_ack"], result=True)
    add("W04", {"w": actor([*writer_prepare(), *writer_finish(uncertain=True)]),
                "m": actor([until({"outcome": {"actor": "w", "kind": "unknown"}}),
                             *change("freeze", nonce="copy2")])},
        ["unknown_write_late_conflict_after_fence"], result=True)
    add("W05", {"w": actor([*writer_prepare(), *writer_finish(), mark("done")]),
                "m": actor([wait("w", "done"), *migration(count=4)])},
        ["native_failure_withholds_ack", "committed_result_survives_migration"], result=True)
    add("W06", {"w": actor([*enter("write"), step("object_put", name="A", label="old_put", uncertain=True),
                             observe(allow_unknown=True), mark("sent")]),
                "m": actor([wait("w", "sent"), *migration(), *sweep(["A"], batch="old"), mark("first_sweep"),
                             until({"token": "w/old_put", "fields": {"stage": "applied"}}),
                             *sweep(["A"], batch="orphan"), mark("second_sweep")])},
        ["late_absent_put_recreates_retired_orphan", "second_sweep_preserves_active_same_hash"])
    add("F01", {"m": actor([*change("freeze", nonce="own2", uncertain=True, allow_unknown=True, label="freeze"),
                             *capture("own2"), step("copy_source", name="A"), observe()])},
        ["unknown_freeze_without_plan_rejected", "unknown_freeze_exact_own_plan_allows_copy"])

    add("P01", {"old": actor([*enter("complete"), *load("A"), mark("paused"), wait("new", "swept"),
                               *load("B", allow_failure=True), *investigate(), mark("classified")]),
                "new": actor([wait("old", "paused"), *enter("complete"), *load("A"), *load("B"), *load("C"),
                               *publish("complete"), step("ack_transition"), *migration(count=3), *sweep(["B"]), mark("swept")]),
                "meta": actor([wait("old", "classified"), *head(), step("metadata_ready")])},
        ["paused_provisioning_reader_expires", "ready_metadata_is_distinct_from_immutable_success"], result=True,
        head_changes={"life": "provisioning", "active": False})
    add("P02", {"c": actor([*enter("complete"), *load("A"), *load("B"), *load("C"), mark("admitted"),
                             wait("a", "admitted"), *publish("complete"), step("ack_transition")]),
                "a": actor([*enter("abort"), *load("A"), *load("B"), *load("C"), mark("admitted"),
                             wait("c", "admitted"), *publish("abort"), step("ack_transition")])},
        ["complete_wins_original_abort_conflict", "abort_wins_original_complete_conflict"], result=True,
        head_changes={"life": "provisioning", "active": False})
    add("P03", {"old": actor([step("bootstrap"), *load("A", purpose="readback"), mark("paused"),
                               wait("new", "swept"), *load("B", purpose="readback", allow_failure=True),
                               *investigate(), mark("classified"), *publish("create")]),
                "new": actor([wait("old", "paused"), *bootstrap(), *publish("create"), step("ack_transition"),
                               *migration(count=3), *sweep(["B"]), mark("swept")])},
        ["prehead_bootstrap_retired_failure", "old_absent_create_cannot_win"], absent=True, result=True)
    add("P04", {"c": actor([*bootstrap(), mark("prepared"), wait("a", "prepared"), *publish("create"), step("ack_transition")]),
                "a": actor([*bootstrap(), mark("prepared"), wait("c", "prepared"), *publish("absent_abort"), step("ack_transition")])},
        ["absent_abort_wins_permanent_head", "absent_create_wins_permanent_head"], absent=True, result=True)

    add("C01", {"old": actor([*capture("old2"), step("copy_verify", name="B", label="old_verify"),
                               mark("captured"), wait("m", "new3"),
                               observe(label="old_verify", allow_failure=True), *investigate()]),
                "m": actor([wait("old", "captured"), *capture("old2"), *change("abort_plan"),
                             *sweep(["B"], generation=2), *change("freeze", nonce="new3"), mark("new3")])},
        ["retired_target_above_active_expires", "current_source_and_new_target_not_poisoned"],
        initial_plan=True, objects={1: ["A", "B"], 2: ["B"]})
    add("C02", {"old": actor([*capture("old2"), step("copy_source", name="B", label="old_source"),
                               mark("captured"), wait("m", "new3"),
                               observe(label="old_source", allow_failure=True), *investigate()]),
                "m": actor([wait("old", "captured"), *capture("old2"), *change("abort_plan"),
                             step("fault_object", generation=1, name="B", mode="missing"),
                             *change("freeze", nonce="new3"), mark("new3")], role="fixture")},
        ["expired_plan_active_source_corruption_not_expiry"], initial_plan=True)
    add("C03", {"old": actor([*capture("old2"), step("copy_verify", name="B", label="old_verify"), mark("pending"),
                               wait("m", "new3"), *capture("new3"), observe(label="old_verify")]),
                "m": actor([wait("old", "pending"), *capture("old2"), *change("abort_plan"),
                             *change("freeze", nonce="new3"), mark("new3")])},
        ["old_target_success_rejected_by_new_plan_identity", "new_plan_has_no_adopted_copy_evidence"],
        initial_plan=True, objects={1: ["A", "B"], 2: ["B"]})
    add("H01", {"m": actor([*change("hold_add", id="retained"), *migration(), mark("promoted"),
                             wait("p", "attempted"), *change("hold_release", id="retained"), *sweep(["A", "B"])]),
                "p": actor([wait("m", "promoted"), *head(), mark("attempted"),
                             step("candidate_get", generation=1, name="A")])},
        ["retained_generation_blocks_sweep", "explicit_hold_release_allows_sweep"])
    add("D01", {"p": actor([*capture("old2"), *copies(2), *change("seal"), *head(),
                             step("prepare_promote"), mark("prepared"), wait("d", "deleted"),
                             step("send_head"), observe()]),
                "d": actor([wait("p", "prepared"), *change("delete"), mark("deleted")])},
        ["delete_preserves_active_allocated_acl_owner_hold", "late_promote_cannot_revive_deleted"],
        initial_plan=True, initial_hold=True)
    add("X01", {"r": actor([*enter(), *load("A"), step("detach"),
                             step("object_get", name="B", label="pending", uncertain=True),
                             step("stop_local"), step("object_get", name="A")], 2)},
        ["detached_caller_may_still_dispatch_before_local_stop", "closed_gate_rejects_new_dispatch", "pending_request_delivers_after_local_stop"])
    add("X02", {"m": actor([*migration(count=3)])},
        ["noncanonical_frame_copied_verbatim", "receipt_data_root_not_reference_edge"], result=True,
        head_changes={"data": frames["D"]["hash"]}, objects={1: ["D", "E", "C"]})
    add("X03", {"r": actor([*enter(), *load("A"), mark("paused"), wait("f", "faulted"),
                             *load("B", allow_failure=True), *investigate()], 2),
                "f": actor([wait("r", "paused"), step("fault_object", generation=1, name="B", mode="missing"),
                             step("fault_authority", choices=["wrong_scope", "malformed"]), mark("faulted")], role="fixture")},
        ["wrong_scope_authority_is_not_retirement", "malformed_authority_is_not_retirement"])

    retired = {"A": 2, "M": 2, "serial": 4}
    retired_objects = {1: ["A", "B"], 2: ["A", "B"]}
    cp_prefix = [*head(), *candidate("A"), *head(),
                 *publish("checkpoint", plan="sweep1", batch="intent", label="intent", uncertain=True, allow_unknown=True)]
    add("CP01", {"g": actor([*cp_prefix, *head(), step("observe_checkpoint"), step("delete"), observe()])},
        ["intent_unknown_applied_fresh_own_batch_allows_delete", "delete_without_fresh_own_batch_rejected"],
        head_changes=retired, objects=retired_objects)
    add("CP02", {"g": actor([*cp_prefix, *head(), step("observe_checkpoint"), mark("first_observation"),
                              *head(), step("observe_checkpoint"), step("delete"), observe()])},
        ["same_serial_absence_is_pending", "late_original_intent_cas_after_absent_observation"],
        head_changes=retired, objects=retired_objects)
    add("CP03", {"g": actor([*cp_prefix, *head(), step("observe_checkpoint"), mark("observed"),
                              wait("f", "fenced"), *head(), step("observe_checkpoint"), step("delete")]),
                 "f": actor([wait("g", "observed"), *change("fence"), mark("fenced")])},
        ["higher_serial_fences_original_intent", "fenced_intent_is_not_fabricated_applied"],
        head_changes=retired, objects=retired_objects)
    cp04 = [*install(["A"]), step("delete", label="original_delete", uncertain=True), observe(allow_unknown=True), mark("unknown"),
            wait("f", "fault_chosen"), step("delete", label="retry_delete"), observe(),
            *head(), step("candidate_get"), observe(), step("record_disposition"), *persist_and_clear(), mark("cleared"),
            *sweep(["B"], batch="new_batch"), *change("freeze", nonce="new3"), mark("new_plan")]
    add("CP04", {"g": actor(cp04), "f": actor([wait("g", "unknown"),
                                                step("fault_candidate", choices=[None, "NO_SUCH_BUCKET", "UNAVAILABLE"]), mark("fault_chosen")], role="fixture")},
        ["unknown_delete_observed_absent_persisted", "no_such_bucket_not_absence", "unavailable_not_absence",
         "old_delete_after_clear_new_batch_new_plan", "original_delete_knowledge_stays_unknown"],
        head_changes=retired, objects=retired_objects)
    cp05 = [*install(["A"]), step("delete", label="original_delete", uncertain=True), observe(allow_unknown=True),
            step("delete", label="remove"), observe(), mark("removed"), wait("u", "recreated"),
            *head(), step("candidate_get"), observe(), step("capture_candidate", reset=True),
            step("delete", label="settle_old"), observe(), step("record_disposition"), *persist_and_clear(),
            *head(), *publish("checkpoint", plan="sweep1", batch="version2", sequence=2),
            *head(), step("observe_checkpoint"), step("delete", label="new_version"), observe(), step("record_disposition")]
    add("CP05", {"g": actor(cp05), "u": actor([step("bootstrap"), wait("g", "removed"),
                                                step("object_put", name="A"), observe(), mark("recreated")])},
        ["same_bytes_recreated_with_new_opaque_etag", "old_condition_settled_by_distinct_attempt",
         "new_etag_requires_distinct_persisted_candidate", "old_unknown_not_rewritten_by_retry"],
        head_changes=retired, objects=retired_objects)

    two_admins = copy.deepcopy(acl)
    two_admins["3"]["admin"] = True
    add("T01", {"g": actor([*install(["A"]), step("delete", label="old_delete", uncertain=True), mark("sent"),
                              wait("a", "revoked"), observe(label="old_delete", allow_unknown=True),
                              *head(), step("observe_checkpoint")]),
                 "a": actor([wait("g", "sent"), *change("acl", principal=1, admin=False), mark("revoked")], 3),
                 "m": actor([wait("a", "revoked"), *head(), step("prepare_freeze", nonce="forbidden")])},
        ["fresh_checkpoint_after_admin_revoke_denied", "fresh_maintenance_after_admin_revoke_denied",
         "original_delete_delivers_after_admin_revoke"], head_changes={**retired, "acl": two_admins}, objects=retired_objects)
    add("T02", {"g": actor([*head(), step("prepare_freeze", nonce="old_plan"), step("send_head", label="old_freeze"),
                              mark("sent"), wait("a", "changed"), observe(label="old_freeze", allow_failure=True),
                              *change("freeze", nonce="fresh_admin_plan")]),
                 "a": actor([wait("g", "sent"), *change("owner", worker=22), mark("changed")], 3, worker=22),
                 "w": actor([wait("a", "changed"), *enter("write")])},
        ["owner_change_fences_original_maintenance_cas", "retained_admin_can_start_fresh_maintenance",
         "old_worker_cannot_admit_new_business_write"], head_changes={"acl": two_admins})

    add("S01", {"w": actor([*writer_prepare(), step("send_head", label="write"), step("stop_local"),
                              observe(label="write"), step("native_publish"), step("ack_write")])},
        ["business_cas_applies_after_local_stop", "known_native_commit_withheld_after_stop",
         "known_native_failure_withheld_after_stop", "original_write_condition_survives_stop"], result=True)
    add("S02", {"w": actor([*writer_prepare(), step("send_head", label="write", uncertain=True), step("detach"),
                              observe(label="write", allow_unknown=True), step("native_publish"), step("ack_write")])},
        ["detach_withholds_known_native_success", "withheld_durable_is_not_rollback",
         "detached_unknown_is_not_retroactive_ack"], result=True)
    add("S03", {"c": actor([*enter("complete"), *load("A"), *load("B"), *load("C"),
                              step("prepare_complete"), step("send_head", label="control"), step("stop_local"),
                              observe(label="control"), step("ack_transition")])},
        ["complete_cas_applies_after_local_stop", "known_complete_public_success_withheld"], result=True,
        head_changes={"life": "provisioning", "active": False})
    add("S04", {"r": actor([step("head_get", label="ready"), step("stop_local"), observe(label="ready"), step("metadata_ready")]),
                 "h": actor([*head(), step("metadata_ready"), step("detach"), step("stop_local")])},
        ["ready_metadata_success_blocked_by_stop", "past_success_not_revoked_by_later_detach_stop"])

    spec["profiles"].sort(key=lambda item: item["id"])
    assert len(spec["profiles"]) == 41
    assert len({profile["id"] for profile in spec["profiles"]}) == 41
    path = HERE / "inputs.json"
    path.write_text(json.dumps(spec, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"output": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                      "profiles": len(spec["profiles"]), "expanded_steps": sum(len(actor_["program"]) for profile in spec["profiles"] for actor_ in profile["actors"].values()),
                      "max_actor_steps": max(len(actor_["program"]) for profile in spec["profiles"] for actor_ in profile["actors"].values()),
                      "exploration": "NOT_RUN"}, sort_keys=True))


if __name__ == "__main__":
    main()
