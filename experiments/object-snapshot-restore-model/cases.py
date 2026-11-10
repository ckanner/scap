"""Declared finite schedule matrix; all prefixes remain in the raw history."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from itertools import product

from model import Model, Rejected, digest, key


@dataclass
class Case:
    name: str
    family: str
    build: object


def interleave(left, right):
    if not left:
        yield tuple(right)
    elif not right:
        yield tuple(left)
    else:
        for tail in interleave(left[1:], right):
            yield (left[0],) + tail
        for tail in interleave(left, right[1:]):
            yield (right[0],) + tail


def rejected(action, expected=None):
    try:
        action()
    except Rejected as error:
        if expected is not None:
            assert error.code == expected, (error.code, expected)
        return error.code
    if expected is not None:
        raise AssertionError(f"expected {expected}")
    return None


def network(model, call, step, lost=False):
    if step == "invoke":
        model.invoke(call)
    elif step == "effect":
        model.effect(call)
    elif step == "response":
        model.respond(call, lost)
    else:
        raise ValueError(step)


def setup(provision=True, copied=False):
    model = Model()
    entry = model.capture(1)
    descriptor = model.restore_prepare(entry)
    model.run(model.reserve(descriptor))
    if provision:
        model.run(model.provision(descriptor))
    if copied:
        model.copy_all(descriptor)
        model.run(model.install_copied(descriptor))
    return model, entry, descriptor


def full_copy_without_record(model, descriptor, actor="a"):
    attempt = model.start_copy(descriptor, actor)
    for number in range(1, descriptor["input"]["source"]["point"]["pages"] + 1):
        model.copy_page(attempt, number)
    model.validate_copy(attempt)
    return attempt


def finish(model, descriptor, actor="b"):
    """Scheduler observes effects to choose fresh public operations, never a CAS ETag."""
    name = f"name/{descriptor['input']['name']}"
    scope = descriptor["input"]["scope"]
    for _ in range(8):
        binding = model.store.get(name)
        if binding is None or (binding["body"]["state"] == "tombstone" and binding["body"]["descriptor"] != digest(descriptor)):
            model.run(model.reserve(descriptor, actor))
            continue
        state = binding["body"]["state"]
        target = model.store.get(f"head/{scope}")
        if state == "reserved":
            if target is None:
                model.run(model.provision(descriptor, actor))
            elif target["body"]["origin"]["phase"] == "copying":
                if f"completion/{scope}/{digest(descriptor)}" not in model.store:
                    model.copy_all(descriptor, actor)
                model.run(model.install_copied(descriptor, actor))
            else:
                model.run(model.bind(descriptor, actor))
        elif state == "bound":
            if target["body"]["lifecycle"] == "provisioning":
                model.run(model.ready(descriptor, actor))
            else:
                model.cold_target(descriptor, actor)
                return "ready"
        elif state == "aborting":
            if target is None or target["body"]["lifecycle"] == "provisioning":
                model.run(model.abort_fence(descriptor, actor))
            model.run(model.abort_release(descriptor, actor))
        else:
            assert state == "tombstone"
            return "aborted"
    raise AssertionError("finite restore did not settle")


def remove_source(model, entry):
    if entry in model.store["head/source"]["body"]["snapshots"]:
        model.run(model.snapshot_release(entry))
    if model.store["head/source"]["body"]["lifecycle"] != "deleted":
        model.run(model.source_update("delete"))
    if model.store["head/source"]["body"]["terminal"] is None:
        model.run(model.terminal())
    for generation in range(1, model.store["head/source"]["body"]["M"] + 1):
        model.sweep("source", generation)


def paired(kind, order, loss):
    if kind == "capture":
        model = Model()
        one = model.snapshot_prepare(1, "first")
        two = model.snapshot_prepare(2, "second")
        calls = {"a": model.snapshot_capture(one), "b": model.snapshot_capture(two)}
    elif kind == "release_sql":
        model = Model()
        entry = model.capture(1)
        calls = {"a": model.snapshot_release(entry), "b": model.source_update("sql", ["changed", "later"])}
    elif kind == "bind_abort":
        model, entry, descriptor = setup(copied=True)
        calls = {"a": model.bind(descriptor), "b": model.abort_accept(descriptor)}
    elif kind == "provision_abort":
        model, entry, descriptor = setup(provision=False)
        provision = model.provision(descriptor)
        model.run(model.abort_accept(descriptor))
        calls = {"a": provision, "b": model.abort_fence(descriptor)}
    elif kind == "two_completion":
        model, entry, descriptor = setup()
        one = full_copy_without_record(model, descriptor, "a")
        two = full_copy_without_record(model, descriptor, "b")
        calls = {"a": model.completion(one), "b": model.completion(two)}
    elif kind == "different_creator_name":
        model = Model(); entry = model.capture(1)
        one = model.restore_prepare(entry, operation=100, actor="a", scope="target-a")
        two = model.restore_prepare(entry, operation=101, actor="c", scope="target-c")
        calls = {"a": model.reserve(one, "a"), "b": model.reserve(two, "c")}
    else:
        raise ValueError(kind)
    for label in order:
        actor, step = label.split(".")
        network(model, calls[actor], step, loss[0 if actor == "a" else 1])
    if kind in ("capture", "release_sql", "bind_abort", "provision_abort", "different_creator_name"):
        assert sum(model.calls[call]["effect"]["status"] == "applied" for call in calls.values()) == 1
    if kind == "release_sql":
        model.snapshot_observe(entry)
    if kind in ("bind_abort", "provision_abort", "two_completion"):
        state = finish(model, descriptor)
        if state == "ready":
            remove_source(model, entry)
            model.cold_target(descriptor)
        else:
            model.run(model.terminal("target"))
            model.sweep("target", 1)
    if kind == "different_creator_name":
        if model.store["name/backup"]["body"]["descriptor"] == digest(one):
            winner, winner_actor, loser, loser_actor = one, "a", two, "c"
        else:
            winner, winner_actor, loser, loser_actor = two, "c", one, "a"
        assert finish(model, winner, winner_actor) == "ready"
        rejected(lambda: model.abort_accept(loser, loser_actor), "Conflict")
        rejected(lambda: model.cold_target(loser, loser_actor), "Lifecycle")
        rejected(lambda: model.abort_accept(winner, loser_actor), "Denied")
        rejected(lambda: model.cold_target(winner, loser_actor), "Denied")
        model.cold_target(winner, winner_actor)
    return model


def migration(order):
    model, entry, descriptor = setup()
    attempt = model.start_copy(descriptor)
    for step in order:
        if step == "begin":
            model.run(model.begin())
        elif step == "copy":
            model.copy_generation()
        elif step == "seal":
            model.run(model.seal())
        elif step == "promote":
            model.run(model.promote())
        elif step == "gc":
            model.sweep("source", 1)
        elif step in ("page1", "page2"):
            rejected(lambda: model.copy_page(attempt, int(step[-1])))
        elif step == "validate":
            rejected(lambda: model.validate_copy(attempt))
        elif step == "complete":
            rejected(lambda: model.run(model.completion(attempt)))
        else:
            raise ValueError(step)
    finish(model, descriptor)
    remove_source(model, entry)
    model.cold_target(descriptor)
    return model


def late_completion(order, lost):
    model, entry, descriptor = setup()
    attempt = full_copy_without_record(model, descriptor)
    call = model.completion(attempt)
    for step in order:
        if step == "release":
            model.run(model.snapshot_release(entry))
        elif step == "delete":
            model.run(model.source_update("delete"))
        elif step == "terminal":
            model.run(model.terminal())
        elif step == "gc":
            model.sweep("source", 1)
        else:
            network(model, call, step, lost)
    model.crash("a")
    assert finish(model, descriptor) == "ready"
    return model


def copied_abort(order, lost):
    model, entry, descriptor = setup()
    model.copy_all(descriptor)
    copied = model.install_copied(descriptor)
    for step in order:
        if step == "accept":
            model.run(model.abort_accept(descriptor))
        elif step == "fence":
            model.run(model.abort_fence(descriptor))
        elif step == "release":
            model.run(model.abort_release(descriptor))
        else:
            network(model, copied, step, lost)
    assert finish(model, descriptor) == "aborted"
    model.run(model.terminal("target"))
    model.sweep("target", 1)
    return model


def restart(operation, cut):
    model, entry, descriptor = setup(provision=operation not in ("provision",))
    if operation == "capture":
        model = Model()
        snapshot_descriptor = model.snapshot_prepare(1)
        entry = model.entry(snapshot_descriptor)
        call = model.snapshot_capture(snapshot_descriptor)
    elif operation == "release":
        call = model.snapshot_release(entry)
    elif operation == "provision":
        call = model.provision(descriptor)
    elif operation == "completion":
        call = model.completion(full_copy_without_record(model, descriptor))
    elif operation in ("copied", "bind", "ready"):
        model.copy_all(descriptor)
        if operation == "copied":
            call = model.install_copied(descriptor)
        else:
            model.run(model.install_copied(descriptor))
            if operation == "bind":
                call = model.bind(descriptor)
            else:
                model.run(model.bind(descriptor))
                call = model.ready(descriptor)
    elif operation == "abort":
        call = model.abort_accept(descriptor)
    else:
        raise ValueError(operation)
    actor = model.calls[call]["actor"]
    if cut >= 1:
        model.invoke(call)
    if cut >= 2:
        model.effect(call)
    if cut == 3:
        model.respond(call)
    elif cut >= 1:
        model.respond(call, lost=True)
    model.crash(actor)
    if cut == 1:
        # Already invoked remote work survives the compute process.
        model.effect(call)
    if cut == 0:
        rejected(lambda: model.invoke(call), "StaleProcess")
    if operation == "capture":
        if cut == 0:
            model.run(model.snapshot_capture(snapshot_descriptor))
        assert model.snapshot_observe(entry) == "retained"
    elif operation == "release":
        if cut == 0:
            model.run(model.snapshot_release(entry))
        assert model.snapshot_observe(entry) == "released_observed"
    else:
        finish(model, descriptor)
    return model


def special(name):
    if name == "multi_root_lower_current_quota":
        model = Model()
        first = model.capture(1, "two-pages")
        model.run(model.source_update("sql", ["new-one-page"]))
        model.run(model.source_update("quota", 1))
        second = model.capture(2, "one-page")
        model.run(model.begin()); model.copy_generation(); model.run(model.seal()); model.run(model.promote())
        model.sweep("source", 1)
        for operation, entry in ((100, first), (101, second)):
            desc = model.restore_prepare(entry, operation, name=f"backup-{operation}", scope=f"target-{operation}")
            finish(model, desc)
        return model
    if name == "copy_freezes_table_and_limits":
        model = Model(); entry = model.capture(1)
        model.run(model.begin())
        rejected(lambda: model.snapshot_prepare(2, "other"), "Fenced")
        rejected(lambda: model.snapshot_release(entry), "Fenced")
        rejected(lambda: model.source_update("limits", {"max_points": 2, "max_pages": 6}), "Fenced")
        model.run(model.source_update("revoke")); model.copy_generation(); model.run(model.seal()); model.run(model.promote())
        return model
    if name == "released_label_is_new_identity":
        model = Model(); old = model.capture(1)
        descriptor = model.store["snapshot/source/1/1"]["body"]
        model.run(model.snapshot_release(old)); new = model.capture(2)
        rejected(lambda: model.snapshot_capture(descriptor), "Fenced")
        assert model.snapshot_observe(old) == "released_observed"
        assert model.snapshot_observe(new) == "retained"
        rejected(lambda: model.restore_prepare(old), "Released")
        return model
    if name == "deleted_retains_until_explicit_release":
        model = Model(); entry = model.capture(1)
        model.run(model.source_update("delete"))
        rejected(lambda: model.terminal(), "Fenced")
        desc = model.restore_prepare(entry); finish(model, desc)
        remove_source(model, entry); model.cold_target(desc)
        return model
    if name in ("zero_budget_fresh_retry", "partial_budget_fresh_retry"):
        model, entry, desc = setup()
        attempt = model.start_copy(desc, budget=0 if name.startswith("zero") else 1)
        rejected(lambda: model.copy_page(attempt, 1), "Budget")
        assert finish(model, desc) == "ready"
        return model
    if name == "target_error_not_source_expiry":
        model, entry, desc = setup(); attempt = model.start_copy(desc)
        read, _ = model.get("data/target/1/definitely-absent", "a")
        rejected(lambda: model.project_failure(attempt, "target", "physical", read), "Missing")
        finish(model, desc)
        return model
    if name == "semantic_error_not_source_expiry":
        model, entry, desc = setup(); attempt = model.start_copy(desc)
        rejected(lambda: model.project_failure(attempt, "source", "semantic"), "Corrupt")
        return model
    if name in ("release_during_old_prefix", "release_after_full_prefix"):
        model, entry, desc = setup(); attempt = model.start_copy(desc)
        if name == "release_after_full_prefix":
            for number in (1, 2): model.copy_page(attempt, number)
            model.validate_copy(attempt)
        model.run(model.snapshot_release(entry))
        rejected(lambda: model.start_copy(desc, "b"), "Released")
        if name == "release_during_old_prefix":
            for number in (1, 2): model.copy_page(attempt, number)
            model.validate_copy(attempt)
        model.run(model.completion(attempt)); finish(model, desc)
        return model
    if name == "released_failed_prefix_cannot_restart":
        model, entry, desc = setup(); attempt = model.start_copy(desc)
        model.copy_page(attempt, 1); model.run(model.snapshot_release(entry))
        model.run(model.begin()); model.copy_generation(); model.run(model.seal()); model.run(model.promote()); model.sweep("source", 1)
        # The current root still shares this page; the old physical namespace is gone.
        rejected(lambda: model.copy_page(attempt, 2), "SnapshotExpired")
        rejected(lambda: model.start_copy(desc, "b"), "Released")
        model.run(model.abort_accept(desc)); finish(model, desc)
        return model
    if name in ("revoke_before_start", "revoke_before_completion", "revoke_inside_final_barrier",
                "revoke_after_candidate", "revoke_after_record"):
        model, entry, desc = setup()
        if name == "revoke_before_start":
            model.run(model.source_update("revoke")); rejected(lambda: model.start_copy(desc), "Denied")
        else:
            attempt = full_copy_without_record(model, desc)
            if name == "revoke_before_completion":
                model.run(model.source_update("revoke")); rejected(lambda: model.completion(attempt), "Denied")
            elif name == "revoke_inside_final_barrier":
                rejected(lambda: model.completion(attempt, hook=lambda: model.run(model.source_update("revoke"))), "Conflict")
            else:
                call = model.completion(attempt)
                if name == "revoke_after_record": model.run(call)
                model.run(model.source_update("revoke"))
                if name == "revoke_after_candidate": model.run(call)
                finish(model, desc)
                return model
        model.run(model.source_update("grant")); finish(model, desc)
        return model
    if name == "proof_conflict_stable_is_corrupt":
        model, entry, desc = setup(); attempt = full_copy_without_record(model, desc)
        model.run(model.snapshot_release(entry))
        bad = deepcopy(model.store["accepted/source/1/1"]["body"])
        bad["entry"]["point"]["sequence"] += 1
        model.operator("accepted/source/1/1", bad)
        rejected(lambda: model.completion(attempt), "Corrupt")
        return model
    if name == "proof_conflict_changed_head_is_conflict":
        model, entry, desc = setup(); attempt = full_copy_without_record(model, desc)
        model.run(model.snapshot_release(entry))
        bad = deepcopy(model.store["accepted/source/1/1"]["body"])
        bad["entry"]["point"]["sequence"] += 1
        model.operator("accepted/source/1/1", bad)
        rejected(lambda: model.completion(attempt, hook=lambda: model.run(model.source_update("revoke"))), "Conflict")
        return model
    if name == "descriptor_missing_after_acceptance":
        model = Model(); entry = model.capture(1)
        model.operator("snapshot/source/1/1", None)
        rejected(lambda: model.snapshot_prepare(1), "Corrupt")
        return model
    if name == "descriptor_missing_after_release":
        model = Model(); entry = model.capture(1); model.run(model.snapshot_release(entry))
        model.operator("snapshot/source/1/1", None)
        rejected(lambda: model.snapshot_prepare(1), "Corrupt")
        return model
    if name == "existing_prepare_permission_after_delayed_descriptor":
        model = Model(); entry = model.capture(1)
        # Both actors use principal2; a fresh descriptor read must not carry an old grant.
        descriptor = model.snapshot_prepare(2, "second", actor="a")
        rejected(lambda: model.snapshot_prepare(2, "conflicting-label", actor="a",
                 hook=lambda: model.run(model.source_update("revoke"))), "Denied")
        return model
    if name == "snapshot_policy_cannot_drop_below_live":
        model = Model(); entry = model.capture(1)
        rejected(lambda: model.source_update("limits", {"max_points": 0, "max_pages": 0}), "Budget")
        model.run(model.snapshot_release(entry)); model.run(model.source_update("limits", {"max_points": 0, "max_pages": 0}))
        rejected(lambda: model.snapshot_prepare(2), "Budget")
        return model
    if name == "target_quota_is_independent":
        model = Model(); entry = model.capture(1)
        rejected(lambda: model.restore_prepare(entry, quota=1), "Budget")
        return model
    if name == "same_operation_first_recipe_wins":
        model = Model(); entry = model.capture(1); desc = model.restore_prepare(entry)
        rejected(lambda: model.restore_prepare(entry, scope="different-target"), "Conflict")
        assert model.restore_prepare(entry) == desc
        return model
    if name == "name_collision_does_not_allocate_loser_payload":
        model, entry, desc = setup(provision=False)
        other = model.restore_prepare(entry, operation=101, scope="target-other")
        rejected(lambda: model.reserve(other), "Conflict")
        assert not any(path.startswith("data/target-other/") for path in model.store)
        return model
    if name == "foreign_slot_preserves_foreign_and_releases_name":
        model, entry, desc = setup(provision=False)
        old = {"kind": "target_head", "format": 9, "scope": "foreign", "serial": 1, "revision": 1,
               "sequence": 0, "request_epoch": 1, "requests": [], "owner": 0, "active": False, "creator": 3,
               "A": 1, "M": 1, "terminal": None, "lifecycle": "provisioning", "root": "f" * 64, "pages": 0,
               "origin": {"descriptor": "f" * 64, "phase": "copying", "completion": None}}
        model.operator("head/target", old)
        rejected(lambda: model.provision(desc), "Conflict")
        model.run(model.abort_accept(desc)); rejected(lambda: model.abort_fence(desc), "ForeignOccupied")
        model.run(model.abort_release(desc))
        assert model.store["head/target"]["body"] == old
        return model
    if name == "completion_missing_is_not_rebuilt":
        model, entry, desc = setup(); model.copy_all(desc)
        model.operator(f"completion/target/{digest(desc)}", None)
        rejected(lambda: model.install_copied(desc), "Missing")
        return model
    if name == "snapshot_observation_is_not_release_ack":
        model = Model(); entry = model.capture(1); call = model.snapshot_release(entry)
        # Proof accepted, but the remove CAS has not even been invoked.
        assert model.snapshot_observe(entry) == "retained"
        model.invoke(call); model.respond(call, lost=True); model.effect(call)
        assert model.snapshot_observe(entry) == "released_observed"
        return model
    if name == "cleanup_counter_reserve_exhaustion":
        model = Model(maximum=8); entry = model.capture(1)
        for action in ("revoke", "grant", "revoke"):
            model.run(model.source_update(action))
        assert model.store["head/source"]["body"]["serial"] == 5
        rejected(lambda: model.source_update("grant"), "Limit")
        model.run(model.snapshot_release(entry)); model.run(model.source_update("delete")); model.run(model.terminal())
        assert model.store["head/source"]["body"]["serial"] == 8
        return model
    if name == "late_payload_after_retirement_repeat_sweep":
        model, entry, desc = setup(); attempt = full_copy_without_record(model, desc)
        candidate = model.completion(attempt); model.run(model.abort_accept(desc)); finish(model, desc)
        page = next(value["body"] for path, value in model.store.items() if path.startswith("data/target/1/") and value["body"]["kind"] == "page")
        late = model.candidate("payload", key("target", 1, digest(page)), page, "absent", "a", inputs={"scope": "target", "generation": 1})
        model.invoke(late); model.respond(late, lost=True)
        model.run(model.terminal("target")); model.sweep("target", 1)
        model.effect(late); model.run(candidate)
        model.sweep("target", 1)
        rejected(lambda: model.install_copied(desc), "Fenced")
        return model
    if name == "three_generations_late_delete":
        model = Model(); entry = model.capture(1)
        model.run(model.begin()); model.copy_generation(); model.run(model.seal()); model.run(model.promote())
        old_key = next(path for path in model.store if path.startswith("data/source/1/"))
        old_delete = model.deletion("source", 1, old_key); model.invoke(old_delete)
        model.run(model.begin()); model.copy_generation(); model.run(model.seal()); model.run(model.promote())
        model.effect(old_delete); model.respond(old_delete)
        model.sweep("source", 1); model.sweep("source", 2)
        desc = model.restore_prepare(entry); finish(model, desc)
        assert model.store["head/source"]["body"]["A"] == 3
        return model
    if name == "completion_missing_after_copied":
        model, entry, desc = setup(copied=True)
        model.operator(f"completion/target/{digest(desc)}", None)
        rejected(lambda: model.bind(desc), "Corrupt")
        return model
    if name in ("same_identity_wrong_hash_stable", "same_identity_wrong_hash_changed"):
        model, entry, desc = setup(); model.run(model.source_update("sql", ["later"]))
        model.snapshot_release(entry)
        attempt = full_copy_without_record(model, desc)
        malformed = deepcopy(model.store["head/source"]["body"])
        malformed["snapshots"][0]["ref"]["descriptor_hash"] = "f" * 64
        model.operator("head/source", malformed)
        if name.endswith("stable"):
            rejected(lambda: model.completion(attempt), "Corrupt")
        else:
            # Change only the observed authority pair; metadata was already bad.
            def change():
                changed = deepcopy(model.store["head/source"]["body"]); changed["serial"] += 1
                model.operator("head/source", changed)
            rejected(lambda: model.completion(attempt, hook=change), "Conflict")
        return model
    if name == "protected_source_missing_is_corrupt_class":
        model, entry, desc = setup(); attempt = model.start_copy(desc)
        model.operator(key("source", 1, entry["point"]["root"]), None)
        rejected(lambda: model.copy_page(attempt, 1), "Corrupt")
        return model
    if name in ("terminal_checkpoint_reserves_clear", "terminal_checkpoint_unknown_keeps_q"):
        model = Model(maximum=6); model.run(model.source_update("delete")); model.run(model.terminal())
        model.run(model.checkpoint("source", 1))
        if name.endswith("keeps_q"):
            rejected(lambda: model.settle_checkpoint("source", unknown_first=True), "Unknown")
            assert model.store["head/source"]["body"]["serial"] == 4
            model.crash("admin")
        model.run(model.settle_checkpoint("source")); model.run(model.clear_checkpoint("source"))
        assert model.store["head/source"]["body"]["serial"] == 6
        # A finite cleanup reserve is not an infinite-collector counter promise.
        assert any(path.startswith("data/source/1/") for path in model.store)
        rejected(lambda: model.checkpoint("source", 1), "Limit")
        return model
    if name == "terminal_checkpoint_refuses_insufficient_room":
        model = Model(maximum=5); model.run(model.source_update("delete")); model.run(model.terminal())
        rejected(lambda: model.checkpoint("source", 1), "Limit")
        return model
    if name == "target_revocation_after_record_blocks_new_resume":
        model, entry, desc = setup(); model.copy_all(desc)
        model.provision_right(2, False)
        rejected(lambda: model.install_copied(desc), "Denied")
        model.provision_right(2, True); remove_source(model, entry); finish(model, desc)
        return model
    if name == "target_abort_does_not_need_source_permission":
        model, entry, desc = setup(); model.run(model.source_update("revoke"))
        model.run(model.abort_accept(desc)); assert finish(model, desc) == "aborted"
        return model
    if name == "name_reuse_keeps_original_target_fenced":
        model, entry, desc = setup(copied=True)
        old_bind = model.bind(desc)
        model.run(model.abort_accept(desc)); assert finish(model, desc) == "aborted"
        tombstone_revision = model.store["name/backup"]["body"]["revision"]
        successor = model.restore_prepare(entry, operation=101, actor="c", scope="successor",
                                          expected_name_revision=tombstone_revision)
        assert finish(model, successor, "c") == "ready"
        model.run(old_bind)
        assert model.calls[old_bind]["effect"]["status"] == "conflict"
        rejected(lambda: model.reserve(desc), "Conflict")
        rejected(lambda: model.cold_target(desc), "Lifecycle")
        model.cold_target(successor, "c")
        return model
    raise ValueError(name)


SPECIALS = (
    "multi_root_lower_current_quota", "copy_freezes_table_and_limits", "released_label_is_new_identity",
    "deleted_retains_until_explicit_release", "zero_budget_fresh_retry", "partial_budget_fresh_retry",
    "target_error_not_source_expiry", "semantic_error_not_source_expiry", "release_during_old_prefix",
    "release_after_full_prefix", "released_failed_prefix_cannot_restart", "revoke_before_start",
    "revoke_before_completion", "revoke_inside_final_barrier", "revoke_after_candidate", "revoke_after_record",
    "proof_conflict_stable_is_corrupt", "proof_conflict_changed_head_is_conflict",
    "descriptor_missing_after_acceptance", "descriptor_missing_after_release",
    "existing_prepare_permission_after_delayed_descriptor", "snapshot_policy_cannot_drop_below_live",
    "target_quota_is_independent", "same_operation_first_recipe_wins", "name_collision_does_not_allocate_loser_payload",
    "foreign_slot_preserves_foreign_and_releases_name", "completion_missing_is_not_rebuilt",
    "snapshot_observation_is_not_release_ack", "cleanup_counter_reserve_exhaustion",
    "late_payload_after_retirement_repeat_sweep",
    "three_generations_late_delete", "completion_missing_after_copied", "same_identity_wrong_hash_stable",
    "same_identity_wrong_hash_changed", "protected_source_missing_is_corrupt_class",
    "terminal_checkpoint_reserves_clear", "terminal_checkpoint_unknown_keeps_q",
    "terminal_checkpoint_refuses_insufficient_room", "target_revocation_after_record_blocks_new_resume",
    "target_abort_does_not_need_source_permission",
    "name_reuse_keeps_original_target_fenced",
)


def cases():
    result = []
    pair_orders = list(interleave(tuple(f"a.{part}" for part in ("invoke", "effect", "response")),
                                  tuple(f"b.{part}" for part in ("invoke", "effect", "response"))))
    assert len(pair_orders) == 20
    for family in ("capture", "release_sql", "bind_abort", "provision_abort", "two_completion", "different_creator_name"):
        for loss, order_no in product(product((False, True), repeat=2), range(len(pair_orders))):
            order = pair_orders[order_no]
            result.append(Case(f"{family}-{int(loss[0])}{int(loss[1])}-{order_no:02d}", family,
                               lambda family=family, order=order, loss=loss: paired(family, order, loss)))
    migration_orders = list(interleave(("begin", "copy", "seal", "promote", "gc"),
                                       ("page1", "page2", "validate", "complete")))
    assert len(migration_orders) == 126
    for number, order in enumerate(migration_orders):
        result.append(Case(f"migration-{number:03d}", "migration", lambda order=order: migration(order)))
    for family, left, right, builder in (
            ("late_completion", ("release", "delete", "terminal", "gc"), ("invoke", "effect", "response"), late_completion),
            ("copied_abort", ("accept", "fence", "release"), ("invoke", "effect", "response"), copied_abort)):
        for number, order in enumerate(interleave(left, right)):
            for lost in (False, True):
                result.append(Case(f"{family}-{number:02d}-{int(lost)}", family,
                                   lambda order=order, lost=lost, builder=builder: builder(order, lost)))
    for operation, cut in product(("capture", "release", "provision", "completion", "copied", "bind", "ready", "abort"), range(4)):
        result.append(Case(f"restart-{operation}-{cut}", "restart", lambda operation=operation, cut=cut: restart(operation, cut)))
    for name in SPECIALS:
        result.append(Case(name, "boundary", lambda name=name: special(name)))
    return result
