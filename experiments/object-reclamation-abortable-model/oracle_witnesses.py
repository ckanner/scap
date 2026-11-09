"""Independent, concrete existential witnesses over actual graph states/edges."""


def response(token, outcome):
    return token is not None and token["stage"] == "applied" and token["response"]["outcome"] == outcome


def label(state, owner, name):
    local = state["actors"].get(owner, {})
    return state["tokens"].get(local.get("labels", {}).get(name))


def outcome(state, owner, kind):
    value = state["actors"].get(owner, {}).get("outcome")
    return value is not None and value["kind"] == kind


def stopped(state, owner, code):
    return state["actors"].get(owner, {}).get("stopped") == code


def transition(state, owner, name, result):
    return any(token["owner"] == owner and token["kind"] == "head_cas"
               and token["request"]["transition"] == name and response(token, result)
               for token in state["tokens"].values())


def state_markers(rules, state):
    markers = set()
    if rules.profile["id"] == "CP02":
        local, token = state["actors"]["g"], label(state, "g", "intent")
        if local["checkpoint_knowledge"] == "pending_absent" and token is not None and token["stage"] == "pending" and token["observed"] == "unknown":
            markers.add("pending_intent_absent_observed")
    return markers


def edge_markers(rules, before, after, action):
    markers = set()
    if "network" in action and action["choice"] == "apply":
        token = before["tokens"][action["network"]]
        if token["kind"] == "head_cas" and token["request"]["transition"] == "write" and token["observed"] == "unknown" and response(after["tokens"][action["network"]], "APPLIED"):
            markers.add("write_applied_after_original_unknown")
    return markers


def state_facts(rules, state, histories=()):
    name, head, actors = rules.profile["id"], state["head"], state["actors"]
    facts = set()
    add = facts.add
    active = None if head is None else head["A"]
    old_a = rules.key(1, rules.names["A"])
    old_b = rules.key(1, rules.names["B"])
    if name == "A01" and outcome(state, "r", "read_success") and head["plan"] is not None:
        facts.update(("last_get_after_fence", "read_success_after_fence", "ordinary_no_head_write"))
    if name == "A02" and outcome(state, "r", "read_success") and active == 2 and old_a not in state["objects"] and old_b not in state["objects"]:
        facts.update(("return_after_complete_old_sweep", "materialized_before_fence"))
    if name == "A03" and outcome(state, "r", "read_success") and old_b not in state["objects"] and response(label(state, "r", "tail"), "FOUND"):
        add("found_delivery_observed_after_sweep")
    if name in ("A04", "A05", "A09"):
        if outcome(state, "r", "expired"):
            add("retired_corruption_expired" if name == "A05" else "retired_missing_expired")
        if outcome(state, "r", "unknown") and actors["r"]["failure"] is not None:
            add("retired_authority_unknown")
        if outcome(state, "n", "read_success") and active == 2 and "2" not in state["health"]:
            add("new_active_remains_healthy")
    if name in ("A06", "A07", "A08"):
        failure = actors["r"]["failure"]
        if failure is not None and outcome(state, "r", "error") and actors["r"]["outcome"]["code"] == "CORRUPT":
            add("active_corruption_rejected")
        if failure is not None and outcome(state, "r", "unknown") and active == 1:
            add("active_authority_unknown")
        if stopped(state, "n", "CORRUPT"):
            add("same_active_readmission_blocked")
    if name in ("A10", "A11"):
        if outcome(state, "r", "read_success") and (head["life"] == "deleted" or not head["acl"]["2"]["read"]):
            add("original_authorized_read_success")
        if stopped(state, "n", "DENIED") or stopped(state, "n", "LIFECYCLE"):
            add("new_admission_denied")
        if name == "A11" and stopped(state, "g", "LIFECYCLE"):
            add("deleted_active_gc_rejected")
    if name.startswith("W") and name != "W06":
        original = label(state, "w", "write")
        if name == "W01":
            if response(original, "APPLIED") and head["plan"] is not None and rules.names["D"] in head["plan"]["identity"]["roots"] and rules.names["F"] in head["plan"]["identity"]["roots"]:
                add("write_wins_then_freeze_new_roots")
            if outcome(state, "w", "write_ack"):
                add("native_commit_before_ack")
        if name == "W02" and response(original, "CONFLICT"):
            facts.update(("fence_wins_original_write_conflict", "no_sql_replay"))
        if name == "W03" and response(original, "APPLIED") and original["observed"] == "unknown" and head["plan"] is not None:
            add("unknown_not_retroactive_ack")
            if "write_applied_after_original_unknown" in histories:
                add("unknown_write_late_applied_before_freeze")
        if name == "W05":
            if outcome(state, "w", "committed_unavailable"):
                add("native_failure_withholds_ack")
                if active == 2 and rules.key(2, rules.names["F"]) in state["objects"] and rules.key(2, rules.names["C"]) in state["objects"]:
                    add("committed_result_survives_migration")
    if name == "W06" and actors["m"]["marks"].get("second_sweep") and old_a not in state["objects"] and rules.key(2, rules.names["A"]) in state["objects"]:
        add("second_sweep_preserves_active_same_hash")
    if name == "F01":
        original = label(state, "m", "freeze")
        if original is not None and original["observed"] == "unknown":
            if stopped(state, "m", "NO_COPY_PLAN"):
                add("unknown_freeze_without_plan_rejected")
            if response(original, "APPLIED") and any(token["kind"] == "object_get" and token["request"]["purpose"] == "copy_source"
                                                     for token in state["tokens"].values()):
                add("unknown_freeze_exact_own_plan_allows_copy")
    if name == "P01":
        if outcome(state, "old", "expired") and active == 2 and head["life"] == "ready":
            add("paused_provisioning_reader_expires")
        if outcome(state, "meta", "metadata_ready") and actors["meta"]["materialized"] is None:
            add("ready_metadata_is_distinct_from_immutable_success")
    if name == "P02":
        if transition(state, "c", "complete", "APPLIED") and transition(state, "a", "abort", "CONFLICT"):
            add("complete_wins_original_abort_conflict")
        if transition(state, "a", "abort", "APPLIED") and transition(state, "c", "complete", "CONFLICT"):
            add("abort_wins_original_complete_conflict")
    if name == "P03":
        if outcome(state, "old", "expired"):
            add("prehead_bootstrap_retired_failure")
        if stopped(state, "old", "NO_BOOTSTRAP") and head is not None and not any(token["owner"] == "old" and token["kind"] == "head_cas" for token in state["tokens"].values()):
            add("old_absent_create_cannot_win")
    if name == "P04":
        if transition(state, "a", "absent_abort", "APPLIED") and transition(state, "c", "create", "CONFLICT"):
            add("absent_abort_wins_permanent_head")
        if transition(state, "c", "create", "APPLIED") and transition(state, "a", "absent_abort", "CONFLICT"):
            add("absent_create_wins_permanent_head")
    if name == "C01" and outcome(state, "old", "expired") and active == 1 and head["M"] == 3 and head["plan"] is not None and actors["old"]["failure"]["generation"] == 2:
        facts.update(("retired_target_above_active_expires", "current_source_and_new_target_not_poisoned"))
    if name == "C02" and outcome(state, "old", "error") and actors["old"]["outcome"]["code"] == "CORRUPT" and active == 1 and head["M"] == 3:
        add("expired_plan_active_source_corruption_not_expiry")
    if name == "C03" and stopped(state, "old", "OLD_PLAN_RESPONSE") and response(label(state, "old", "old_verify"), "FOUND") and actors["old"]["plan"]["target"] == 3 and not actors["old"]["verified"]:
        facts.update(("old_target_success_rejected_by_new_plan_identity", "new_plan_has_no_adopted_copy_evidence"))
    if name == "H01":
        if stopped(state, "p", "GENERATION_PROTECTED"):
            add("retained_generation_blocks_sweep")
        if active == 2 and head["hold"] is None and old_a not in state["objects"] and old_b not in state["objects"]:
            add("explicit_hold_release_allows_sweep")
    if name == "D01" and head["life"] == "deleted":
        original = rules.profile["initial"]["head"]
        if all(head[key] == original[key] for key in ("A", "M", "acl", "owner", "hold")) and head["plan"] is None:
            add("delete_preserves_active_allocated_acl_owner_hold")
        if transition(state, "p", "promote", "CONFLICT"):
            add("late_promote_cannot_revive_deleted")
    if name == "X01":
        if actors["r"]["detached"] and label(state, "r", "pending") is not None:
            add("detached_caller_may_still_dispatch_before_local_stop")
        if stopped(state, "r", "LOCAL_GATE_CLOSED"):
            add("closed_gate_rejects_new_dispatch")
    if name == "X02" and active == 2 and head["plan"] is None:
        copied = state["objects"].get(rules.key(2, rules.names["C"]))
        if copied is not None and copied["raw"] == rules.frames[rules.names["C"]]["raw"]:
            add("noncanonical_frame_copied_verbatim")
            if all(token["request"].get("hash") not in (rules.names["A"], rules.names["B"]) for token in state["tokens"].values()):
                add("receipt_data_root_not_reference_edge")
    if name == "X03" and stopped(state, "r", "AUTHORITY_CORRUPT"):
        add("wrong_scope_authority_is_not_retirement" if state["authority_fault"] == "wrong_scope" else "malformed_authority_is_not_retirement")
    if name == "CP01":
        original = label(state, "g", "intent")
        if original is not None and original["observed"] == "unknown" and response(original, "APPLIED") and any(token["kind"] == "delete" for token in state["tokens"].values()):
            add("intent_unknown_applied_fresh_own_batch_allows_delete")
        if stopped(state, "g", "NO_OBSERVED_CHECKPOINT"):
            add("delete_without_fresh_own_batch_rejected")
    if name == "CP02":
        if "pending_intent_absent_observed" in state_markers(rules, state):
            add("same_serial_absence_is_pending")
        if "pending_intent_absent_observed" in histories and response(label(state, "g", "intent"), "APPLIED"):
            add("late_original_intent_cas_after_absent_observation")
    if name == "CP03":
        original = label(state, "g", "intent")
        if original is not None and original["observed"] == "unknown" and response(original, "CONFLICT") and actors["g"]["checkpoint_knowledge"] == "higher_fence":
            facts.update(("higher_serial_fences_original_intent", "fenced_intent_is_not_fabricated_applied"))
    if name == "CP04":
        original = label(state, "g", "original_delete")
        if original is not None and original["observed"] == "unknown":
            add("original_delete_knowledge_stays_unknown")
            cp = head["checkpoint"]
            if cp is not None and any(entry["disposition"] == "observed_absent" and state["tokens"][entry["evidence"]]["kind"] == "candidate_get" for entry in cp["entries"]):
                add("unknown_delete_observed_absent_persisted")
        if stopped(state, "g", "NOT_TYPED_EXACT_ABSENCE"):
            if state["candidate_fault"] == "NO_SUCH_BUCKET":
                add("no_such_bucket_not_absence")
            if state["candidate_fault"] == "UNAVAILABLE":
                add("unavailable_not_absence")
    if name == "CP05":
        original = label(state, "g", "original_delete")
        recreated = any(token["owner"] == "u" and token["kind"] == "object_put" and response(token, "APPLIED")
                        for token in state["tokens"].values())
        if recreated:
            add("same_bytes_recreated_with_new_opaque_etag")
        if response(label(state, "g", "settle_old"), "CONFLICT"):
            add("old_condition_settled_by_distinct_attempt")
            if original is not None and original["observed"] == "unknown":
                add("old_unknown_not_rewritten_by_retry")
        newer = label(state, "g", "new_version")
        if newer is not None and original is not None and newer["request"]["key"] == original["request"]["key"] and newer["request"]["etag"] != original["request"]["etag"]:
            add("new_etag_requires_distinct_persisted_candidate")
    if name == "T01":
        if stopped(state, "g", "DENIED"):
            add("fresh_checkpoint_after_admin_revoke_denied")
        if stopped(state, "m", "DENIED"):
            add("fresh_maintenance_after_admin_revoke_denied")
    if name == "T02":
        if response(label(state, "g", "old_freeze"), "CONFLICT") and head["owner"] == 22:
            add("owner_change_fences_original_maintenance_cas")
        if head["owner"] == 22 and head["plan"] is not None and head["plan"]["identity"]["nonce"] == "fresh_admin_plan":
            add("retained_admin_can_start_fresh_maintenance")
        if stopped(state, "w", "FENCED"):
            add("old_worker_cannot_admit_new_business_write")
    if name == "S01":
        original = label(state, "w", "write")
        local = actors["w"]
        if local["local_stop"] and original is not None and original["request"]["base"] == local["context"]["base"]:
            add("original_write_condition_survives_stop")
        if stopped(state, "w", "LOCAL_GATE_CLOSED") and local["commit_known"] and response(original, "APPLIED"):
            if local["native"] == "commit":
                add("known_native_commit_withheld_after_stop")
            if local["native"] == "fail":
                add("known_native_failure_withheld_after_stop")
    if name == "S02":
        local, original = actors["w"], label(state, "w", "write")
        if outcome(state, "w", "withheld") and local["native"] == "commit" and local["commit_known"]:
            add("detach_withholds_known_native_success")
            if head["data"] == rules.names["D"] and response(original, "APPLIED"):
                add("withheld_durable_is_not_rollback")
        if outcome(state, "w", "unknown") and original is not None and original["observed"] == "unknown" and response(original, "APPLIED"):
            add("detached_unknown_is_not_retroactive_ack")
    if name == "S03" and stopped(state, "c", "LOCAL_GATE_CLOSED") and response(label(state, "c", "control"), "APPLIED") and head["life"] == "ready":
        add("known_complete_public_success_withheld")
    if name == "S04":
        if stopped(state, "r", "LOCAL_GATE_CLOSED") and response(label(state, "r", "ready"), "FOUND"):
            add("ready_metadata_success_blocked_by_stop")
        if outcome(state, "h", "metadata_ready") and actors["h"]["detached"] and actors["h"]["local_stop"]:
            add("past_success_not_revoked_by_later_detach_stop")
    return facts


def edge_facts(rules, before, after, action):
    facts = set()
    if "network" not in action or action["choice"] != "apply":
        return facts
    name = rules.profile["id"]
    identifier = action["network"]
    token, result = before["tokens"][identifier], after["tokens"][identifier]
    if name == "W04" and token["kind"] == "head_cas" and token["request"]["transition"] == "write" and token["observed"] == "unknown" and response(result, "CONFLICT"):
        facts.add("unknown_write_late_conflict_after_fence")
    if name == "W06" and token["kind"] == "object_put" and token["request"]["generation"] == 1 and before["actors"]["m"]["marks"].get("first_sweep") and response(result, "APPLIED"):
        facts.add("late_absent_put_recreates_retired_orphan")
    if name == "X01" and token["kind"] == "object_get" and before["actors"]["r"]["local_stop"]:
        facts.add("pending_request_delivers_after_local_stop")
    if name == "CP04" and token == label(before, "g", "original_delete") and token["observed"] == "unknown" and before["actors"]["g"]["marks"].get("new_plan") and before["head"]["plan"] is not None:
        facts.add("old_delete_after_clear_new_batch_new_plan")
    if name == "T01" and token == label(before, "g", "old_delete") and not before["head"]["acl"]["1"]["admin"]:
        facts.add("original_delete_delivers_after_admin_revoke")
    if name == "S01" and token == label(before, "w", "write") and before["actors"]["w"]["local_stop"] and response(result, "APPLIED"):
        facts.add("business_cas_applies_after_local_stop")
    if name == "S03" and token == label(before, "c", "control") and before["actors"]["c"]["local_stop"] and response(result, "APPLIED"):
        facts.add("complete_cas_applies_after_local_stop")
    return facts
