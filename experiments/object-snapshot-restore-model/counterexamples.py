"""Named unsafe protocol variants and separately labeled observation mutations."""
from copy import deepcopy
from dataclasses import dataclass

from cases import setup, full_copy_without_record, rejected, special
from model import Model, digest, key


@dataclass
class Negative:
    name: str
    rule: str
    category: str
    build: object


def alter_candidate(model, identifier, change):
    change(model.calls[identifier])
    event = next(event for event in model.events if event["event"] == "candidate" and event["id"] == identifier)
    for field in ("body", "condition", "evidence", "inputs"):
        event[field] = deepcopy(model.calls[identifier][field])


def bad(name):
    if name == "omit_snapshot_on_copy":
        model = Model(); model.capture(1); model.run(model.source_update("sql", ["new-only"]))
        model.run(model.begin()); model.copy_generation(omit_snapshot=True); model.seal(unsafe=True)
    elif name == "inconsistent_copy_basis":
        model = Model(); model.capture(1); call = model.begin()
        alter_candidate(model, call, lambda value: value["body"]["plan"]["basis"].update(snapshots=[]))
    elif name == "release_without_proof":
        model = Model(); entry = model.capture(1); model.snapshot_release(entry, unsafe=True)
    elif name == "reused_snapshot_id":
        model = Model(); entry = model.capture(1); descriptor = model.store["snapshot/source/1/1"]["body"]
        model.run(model.snapshot_release(entry)); model.snapshot_capture(descriptor, unsafe=True)
    elif name == "cross_scope_raw_page":
        model, entry, desc = setup()
        page = next(value["body"] for path, value in model.store.items() if path.startswith("data/source/1/") and value["body"]["kind"] == "page")
        model.candidate("payload", key("target", 1, digest(page)), page, "absent", "a", inputs={"scope": "target", "generation": 1})
    elif name == "generic_bind_before_copy":
        model, entry, desc = setup(); model.bind(desc, unsafe=True)
    elif name == "generic_ready_before_copy":
        model, entry, desc = setup()
        name_body = deepcopy(model.store["name/backup"]["body"]); name_body.update(state="bound", revision=2)
        model.operator("name/backup", name_body); model.ready(desc, unsafe=True)
    elif name == "partial_copy_capability":
        model, entry, desc = setup(); attempt = model.start_copy(desc); model.copy_page(attempt, 1)
        model.validate_copy(attempt, unsafe=True)
    elif name == "stale_acl_completion":
        model, entry, desc = setup(); attempt = full_copy_without_record(model, desc)
        model.run(model.source_update("revoke")); model.completion(attempt, unsafe=True)
    elif name == "changed_head2_ignored":
        model, entry, desc = setup(); attempt = full_copy_without_record(model, desc)
        call = model.completion(attempt)
        candidate = model.calls[call]
        model.run(model.source_update("revoke")); new_read, _ = model.present("head/source", "a")
        wrong_evidence = deepcopy(candidate["evidence"]); wrong_evidence["head2"] = new_read
        model.candidate("completion", candidate["key"], candidate["body"], "absent", "a", wrong_evidence)
    elif name in ("target_error_expired", "semantic_error_expired", "protected_source_missing_expired"):
        model, entry, desc = setup(); attempt = model.start_copy(desc)
        if name == "semantic_error_expired":
            rejected(lambda: model.project_failure(attempt, "source", "semantic", unsafe="SnapshotExpired"))
        else:
            domain = "target" if name == "target_error_expired" else "source"
            read, _ = model.get(f"data/{domain}/1/definitely-absent", "a")
            rejected(lambda: model.project_failure(attempt, domain, "physical", read, unsafe="SnapshotExpired"))
    elif name == "budget_quarantined":
        model, entry, desc = setup(); attempt = model.start_copy(desc, budget=0)
        rejected(lambda: model.copy_page(attempt, 1))
        next(event for event in reversed(model.events) if event["event"] == "copy_failure")["result"] = "Corrupt"
    elif name == "unknown_probe_expired":
        model, entry, desc = setup(); attempt = model.start_copy(desc)
        model.run(model.begin()); model.copy_generation(); model.run(model.seal()); model.run(model.promote()); model.sweep("source", 1)
        rejected(lambda: model.copy_page(attempt, 1))
        failure = next(event for event in reversed(model.events) if event["event"] == "copy_failure")
        for event in model.events:
            if event["event"] in ("get_effect", "get_response") and event["id"] == failure["probe"]:
                event["result"] = {"status": "unknown"}
    elif name == "original_target_etag_rebound":
        model, entry, desc = setup(); model.copy_all(desc); call = model.install_copied(desc)
        model.run(model.abort_accept(desc)); model.run(model.abort_fence(desc))
        alter_candidate(model, call, lambda value: value.update(condition=model.store["head/target"]["etag"]))
    elif name == "active_generation_deleted":
        model = Model(); head_read, _ = model.present("head/source")
        object_key = next(path for path in model.store if path.startswith("data/source/1/"))
        read, value = model.present(object_key)
        model.candidate("gc_delete", object_key, None, value["etag"],
                        evidence={"head": head_read, "object": read}, inputs={"scope": "source", "generation": 1})
    elif name == "terminal_drops_snapshot":
        model = Model(); model.capture(1); model.run(model.source_update("delete")); model.terminal(unsafe=True)
    elif name == "business_rewrites_point":
        model = Model(); model.capture(1); call = model.source_update("sql", ["new"])
        alter_candidate(model, call, lambda value: value["body"]["snapshots"][0]["point"].update(root=value["body"]["root"]))
    elif name == "missing_descriptor_recreated":
        model = Model(); entry = model.capture(1); model.run(model.snapshot_release(entry)); model.operator("snapshot/source/1/1", None)
        prior, _ = model.get("snapshot/source/1/1")
        head_read, head = model.fresh_head(); proof_read, _ = model.present("accepted/source/1/1")
        root_read, _ = model.present(key("source", head["body"]["A"], head["body"]["root"]))
        descriptor = {"kind": "snapshot_descriptor", "scope": "source", "creator": 1, "operation": 1,
                      "label": "point", "base": head["body"], "etag": head["etag"], "capture_serial": head["body"]["serial"] + 1,
                      "point": {"root": head["body"]["root"], "pages": head["body"]["pages"],
                                "sequence": head["body"]["sequence"], "revision": head["body"]["revision"]}}
        model.candidate("snapshot_descriptor", "snapshot/source/1/1", descriptor, "absent",
                        evidence={"head": head_read, "proof": proof_read, "prior": prior, "root": root_read})
    elif name == "released_new_attempt":
        model, entry, desc = setup(); attempt = model.start_copy(desc)
        old_start = deepcopy(next(event for event in model.events if event["event"] == "copy_start"))
        model.run(model.snapshot_release(entry)); source, _ = model.present("head/source", "a")
        evidence, _, _ = model.view(desc)
        old_start.update(id="unsafe-new-attempt", source=source, index=len(model.events), **evidence)
        model.events.append(old_start)
    elif name == "crashed_prefix_reused":
        model, entry, desc = setup(); attempt = full_copy_without_record(model, desc)
        old = deepcopy(next(event for event in reversed(model.events) if event["event"] == "copy_validated"))
        model.crash("a"); old["index"] = len(model.events); model.events.append(old)
    elif name == "crashed_unsent_invoked":
        model = Model(); descriptor = model.snapshot_prepare(1); call = model.snapshot_capture(descriptor)
        model.crash("admin"); model.event("put_invoke", id=call)
    elif name == "historical_observation_ack":
        model = special("snapshot_observation_is_not_release_ack")
        next(event for event in reversed(model.events) if event["event"] == "snapshot_observation")["historical_ack"] = True
    elif name == "absence_as_not_applied":
        model = Model(); descriptor = model.snapshot_prepare(1); entry = model.entry(descriptor)
        model.run(model.source_update("revoke")); model.snapshot_observe(entry)
        next(event for event in reversed(model.events) if event["event"] == "snapshot_observation")["result"] = "not_applied"
    elif name == "limits_below_live":
        model = Model(); model.capture(1); call = model.source_update("limits", {"max_points": 2, "max_pages": 6})
        alter_candidate(model, call, lambda value: value["body"]["limits"].update(max_points=0, max_pages=0))
    elif name == "spent_cleanup_reserve":
        model = Model(maximum=8); model.capture(1)
        for operation in ("revoke", "grant", "revoke"):
            model.run(model.source_update(operation))
        model.source_update("grant", unsafe=True)
    elif name == "source_requests_imported":
        model, entry, desc = setup(); model.copy_all(desc); call = model.install_copied(desc)
        alter_candidate(model, call, lambda value: value["body"].update(requests=[9001]))
    elif name == "completion_wrong_target_root":
        model, entry, desc = setup(); call = model.completion(full_copy_without_record(model, desc))
        alter_candidate(model, call, lambda value: value["body"].update(root="f" * 64))
    elif name == "snapshot_proof_is_release_while_live":
        model = Model(); entry = model.capture(1); model.snapshot_release(entry)
        model.snapshot_observe(entry)
        next(event for event in reversed(model.events) if event["event"] == "snapshot_observation")["result"] = "released_observed"
    elif name == "same_identity_wrong_hash_accepted":
        model, entry, desc = setup(); model.run(model.source_update("sql", ["changed"]))
        model.snapshot_release(entry)  # Durable proof; remove candidate remains unsent.
        attempt = full_copy_without_record(model, desc)
        good = model.completion(attempt); candidate = model.calls[good]
        malformed = deepcopy(model.store["head/source"]["body"])
        malformed["snapshots"][0]["ref"]["descriptor_hash"] = "f" * 64
        model.operator("head/source", malformed)
        first, _ = model.present("head/source", "a")
        desc_read, _ = model.present("snapshot/source/1/1", "a")
        proof_read, _ = model.present("accepted/source/1/1", "a")
        second, _ = model.present("head/source", "a")
        evidence = {**candidate["evidence"], "head1": first, "head2": second, "descriptor": desc_read, "proof": proof_read}
        model.candidate("completion", candidate["key"], candidate["body"], "absent", "a", evidence)
    elif name == "raw_present_forged_missing":
        model = Model(); model.present("head/source")
        event = next(event for event in model.events if event["event"] == "get_effect")
        event["result"] = {"status": "missing"}
    elif name == "aggregate_count_masks_root_geometry":
        model, entry, desc = setup(); full_copy_without_record(model, desc)
        event = next(event for event in model.events if event["event"] == "copy_validated")
        event["pages"] = 1
    elif name == "terminal_gc_drops_checkpoint_reserve":
        model = Model(maximum=5); model.run(model.source_update("delete")); model.run(model.terminal())
        model.checkpoint("source", 1, unsafe=True)
    elif name == "target_admission_ignores_revocation":
        model, entry, desc = setup(); model.copy_all(desc)
        model.provision_right(2, False)
        rejected(lambda: model.install_copied(desc), "Denied")
        next(event for event in reversed(model.events) if event["event"] == "target_admission")["allowed"] = True
    elif name == "missing_referenced_completion_still_binds":
        model, entry, desc = setup(copied=True)
        model.operator(f"completion/target/{digest(desc)}", None)
        model.bind(desc, unsafe=True)
    elif name == "original_name_revision_rebased":
        model, entry, desc = setup()
        model.run(model.abort_accept(desc)); model.run(model.abort_fence(desc)); model.run(model.abort_release(desc))
        admission = model.target_gate(2, "target", "a", "unsafe_reserve")
        descriptor_read, _ = model.present("creation/2/100", "a")
        name_read, previous = model.present("name/backup", "a")
        value = {"kind": "name", "name": "backup", "scope": "target", "descriptor": digest(desc),
                 "state": "reserved", "revision": previous["body"]["revision"] + 1}
        model.candidate("reserve", "name/backup", value, previous["etag"], "a",
                        {"descriptor": descriptor_read, "name": name_read, "target_admission": admission})
    elif name == "creator_gate_borrowed_for_foreign_plan":
        model = Model(); entry = model.capture(1)
        descriptor = model.restore_prepare(entry, operation=101, actor="c", scope="target-c")
        admission = model.target_gate(2, "target-c", "a", "unsafe_reserve")
        descriptor_read, _ = model.present("creation/3/101", "a")
        name_read, _ = model.get("name/backup", "a")
        value = {"kind": "name", "name": "backup", "scope": "target-c", "descriptor": digest(descriptor),
                 "state": "reserved", "revision": 1}
        model.candidate("reserve", "name/backup", value, "absent", "a",
                        {"descriptor": descriptor_read, "name": name_read, "target_admission": admission})
    else:
        raise ValueError(name)
    return model.trace(name)


MATRIX = (
    ("omit_snapshot_on_copy", "complete_tree", "protocol"),
    ("inconsistent_copy_basis", "copy_basis", "protocol"),
    ("release_without_proof", "release_proof_before_remove", "protocol"),
    ("reused_snapshot_id", "snapshot_original_basis", "protocol"),
    ("cross_scope_raw_page", "payload_scope", "protocol"),
    ("generic_bind_before_copy", "restore_recipe_before_bind", "protocol"),
    ("generic_ready_before_copy", "restore_recipe_before_ready", "metadata_and_protocol"),
    ("partial_copy_capability", "complete_tree", "protocol"),
    ("stale_acl_completion", "current_permission", "protocol"),
    ("changed_head2_ignored", "stable_source_barrier", "protocol"),
    ("target_error_expired", "failure_provenance", "protocol"),
    ("semantic_error_expired", "semantic_not_expired", "protocol"),
    ("budget_quarantined", "budget_not_corruption", "observer"),
    ("protected_source_missing_expired", "fresh_retirement_proof", "protocol"),
    ("unknown_probe_expired", "exact_dependency", "observer"),
    ("original_target_etag_rebound", "original_head_etag", "protocol"),
    ("active_generation_deleted", "permanent_retirement", "protocol"),
    ("terminal_drops_snapshot", "terminal_retained_roots", "protocol"),
    ("business_rewrites_point", "preserved_authority_fields", "protocol"),
    ("missing_descriptor_recreated", "missing_is_not_rebuild", "metadata_and_protocol"),
    ("released_new_attempt", "restore_source_admission", "protocol"),
    ("crashed_prefix_reused", "fresh_copy_prefix", "protocol"),
    ("crashed_unsent_invoked", "fresh_process_invocation", "protocol"),
    ("historical_observation_ack", "historical_observation_not_ack", "observer"),
    ("absence_as_not_applied", "historical_observation_not_ack", "observer"),
    ("limits_below_live", "persisted_snapshot_limits", "protocol"),
    ("spent_cleanup_reserve", "cleanup_reserve", "protocol"),
    ("source_requests_imported", "new_identity", "protocol"),
    ("completion_wrong_target_root", "completion_binding", "protocol"),
    ("snapshot_proof_is_release_while_live", "historical_observation_not_ack", "observer"),
    ("same_identity_wrong_hash_accepted", "snapshot_descriptor_binding", "metadata_and_protocol"),
    ("raw_present_forged_missing", "exact_get", "observer"),
    ("aggregate_count_masks_root_geometry", "per_root_geometry", "observer"),
    ("terminal_gc_drops_checkpoint_reserve", "cleanup_reserve", "protocol"),
    ("target_admission_ignores_revocation", "fresh_target_permission", "observer"),
    ("missing_referenced_completion_still_binds", "referenced_completion", "metadata_and_protocol"),
    ("original_name_revision_rebased", "original_name_revision", "protocol"),
    ("creator_gate_borrowed_for_foreign_plan", "fresh_target_permission", "protocol"),
)


def negatives():
    return [Negative(name, rule, category, lambda name=name: bad(name)) for name, rule, category in MATRIX]
