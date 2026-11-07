"""Protocol, scheduler and explicit recovery checks for the directory experiment."""
import copy
import itertools
import unittest

from named_catalogue_model import (
    CatalogueModel, Limits, ModelError, RACES, RESPONSE_MODES, Trace,
    control_intent, control_key, create_intent, descriptor_key, directed, foreign_seed,
    head_key, name_key, origin, proof_key, race, schedules,
)
from named_catalogue_oracle import audit


class NamedCatalogueModelTests(unittest.TestCase):
    def setUp(self):
        self.create = create_intent()
        self.abort = control_intent(self.create)
        self.trace = Trace("unit")

    def test_race_matrix_enumerates_every_network_order_and_response_pair(self):
        orders = tuple(schedules())
        self.assertEqual(len(orders), 20)
        self.assertEqual(len(set(orders)), 20)
        self.assertTrue(all(order.count("left") == order.count("right") == 3 for order in orders))
        histories = 0
        for kind in RACES:
            winners = set()
            for index, order in enumerate(orders):
                for modes in RESPONSE_MODES:
                    with self.subTest(kind=kind, order=index, modes=modes):
                        run = race(kind, order, modes, index=index)
                        result = audit(run.history())
                        self.assertLessEqual(result["records"], 32)
                        self.assertEqual(run.notes["network_steps"], 6)
                        winners.add(run.notes["winner"])
                        network_responses = [e for e in run.history() if e["type"] == "receive"
                                             and e["attempt"] in {"left", "right"}]
                        self.assertEqual(sum(e["outcome"] == "unknown" for e in network_responses), sum(modes))
                        histories += 1
            self.assertEqual(winners, {"left", "right"})
        self.assertEqual(histories, 10 * 20 * 4)

    def test_directed_cuts_are_independently_audited_and_explicitly_bounded(self):
        runs = list(directed())
        self.assertEqual(len({r.name for r in runs}), len(runs))
        creation = [r for r in runs if r.name.startswith("direct_create_")]
        cancellation = [r for r in runs if r.name.startswith("direct_abort_") and "crash" in r.name]
        self.assertEqual(len(creation), 6 * 4)
        self.assertEqual(len(cancellation), 5 * 3)
        for run in runs:
            with self.subTest(name=run.name):
                outcome = audit(run.history())
                self.assertLessEqual(outcome["events"], run.model.limits.max_events)
                self.assertLessEqual(outcome["attempts"], run.model.limits.max_attempts)
                self.assertLessEqual(outcome["records"], run.model.limits.max_records)

    def test_one_operation_cannot_change_scope_name_or_creation_budget(self):
        r, create = self.trace, self.create
        r.perform("descriptor", create)
        for field, replacement in (("scope", [1, 1, 2, 1, 1]), ("name", "other"),
                                   ("quota", 11), ("previous", 3)):
            changed = dict(create, **{field: replacement})
            r.reject("intent_conflict", "prepare", f"changed-{field}", "descriptor", changed)
            self.assertEqual(r.call("observe", changed)["state"], "intent_conflict")
        self.assertEqual(r.model.current(descriptor_key(create))["intent"], create)
        audit(r.history())

    def test_binding_is_not_ready_and_normal_delete_cannot_bypass_complete(self):
        r, create = self.trace, self.create
        r.setup(create, "bound")
        self.assertEqual(r.call("observe", create)["state"], "bound")
        self.assertEqual(r.call("resolve", create)["state"], "unavailable")
        deletion = control_intent(create, "delete", name_revision=2, head_revision=1)
        r.reject("phase", "prepare", "early-delete", "delete_head", create, deletion)
        r.reject("cannot_abort_bound", "prepare", "late-abort", "accept_abort", create, self.abort)
        r.perform("complete", create)
        self.assertEqual(r.call("resolve", create)["state"], "ready")
        audit(r.history())

    def test_abort_needs_both_permanent_barrier_and_durable_proof(self):
        r, create, abort = self.trace, self.create, self.abort
        r.setup(create)
        r.perform("accept_abort", create, abort)
        r.reject("missing_barrier", "prepare", "proof-too-soon", "prove_abort", create, abort)
        r.perform("fence_abort", create, abort)
        r.reject("missing_proof", "prepare", "release-too-soon", "release_abort", create, abort)
        r.perform("prove_abort", create, abort)
        self.assertEqual(r.call("observe", create, kind="abort", control=abort)["state"], "aborting")
        r.perform("release_abort", create, abort)
        self.assertEqual(r.call("observe", create, kind="abort", control=abort)["state"], "aborted")
        audit(r.history())

    def test_foreign_occupancy_includes_same_scope_but_other_creation_source(self):
        for same_scope, state in itertools.product((False, True), ("provisioning", "ready", "maintenance", "deleted")):
            with self.subTest(same_scope=same_scope, state=state):
                r = Trace("foreign", seed=foreign_seed(same_scope=same_scope, state=state))
                before = r.model.current(head_key(self.create["scope"]))
                r.setup(self.create)
                r.reject("identity_conflict", "prepare", "collision", "provision", self.create)
                r.resume_abort(self.create, self.abort)
                proof = r.model.current(proof_key(self.create))
                self.assertEqual(proof["barrier"]["kind"], "foreign_occupied")
                self.assertEqual(set(proof["barrier"]), {"kind", "scope", "origin"})
                self.assertEqual(r.model.current(head_key(self.create["scope"])), before)
                audit(r.history())

    def test_old_abort_does_not_mutate_reused_name_and_different_nonce_is_not_success(self):
        r = Trace("reuse", seed=foreign_seed())
        r.setup(self.create)
        r.resume_abort(self.create, self.abort)
        next_create = create_intent(3, 2, previous=3)
        r.resume_create(next_create)
        before = r.model.snapshot()["objects"]
        self.assertEqual(r.call("observe", self.create, kind="abort", control=self.abort)["state"], "aborted")
        changed = dict(self.abort, nonce=22)
        self.assertEqual(r.call("observe", self.create, kind="abort", control=changed)["state"], "conflict")
        r.reject("name_conflict", "prepare", "old-create", "reserve", self.create)
        r.reject("name_conflict", "prepare", "old-complete", "complete", self.create)
        self.assertEqual(r.model.snapshot()["objects"], before)
        self.assertEqual(r.call("resolve", self.create)["scope"], next_create["scope"])
        self.assertEqual(self.create["scope"], [1, 1, 1, 1, 1])
        audit(r.history())

    def test_a_new_incarnation_cannot_reuse_the_same_physical_head_slot(self):
        self.trace.setup(self.create)
        self.trace.resume_abort(self.create, self.abort)
        changed = create_intent(3, 1, incarnation=2, generation=2, previous=3)
        self.assertEqual(head_key(changed["scope"]), head_key(self.create["scope"]))
        self.trace.perform("descriptor", changed)
        self.trace.reject("identity_reuse", "prepare", "reuse", "reserve", changed)
        audit(self.trace.history())

    def test_tombstone_predecessor_is_fixed_and_a_missing_record_is_not_a_new_name(self):
        create = create_intent(previous=3)
        self.trace.perform("descriptor", create)
        self.trace.reject("missing_authority", "prepare", "missing", "reserve", create)
        self.assertIsNone(self.trace.model.current(name_key(create)))
        audit(self.trace.history())

    def test_delete_keeps_both_original_expected_revisions(self):
        r, create = self.trace, self.create
        r.setup(create, "ready")
        for revision in (1, 3):
            wrong = control_intent(create, "delete", operation=20 + revision, name_revision=2, head_revision=revision)
            r.reject("conflict", "prepare", f"head-{revision}", "delete_head", create, wrong)
        wrong_name = control_intent(create, "delete", operation=24, name_revision=1, head_revision=2)
        r.reject("conflict", "prepare", "name-old", "delete_head", create, wrong_name)
        original = control_intent(create, "delete", operation=25, name_revision=2, head_revision=2)
        r.perform("delete_head", create, original)
        self.assertEqual(r.call("observe", create, kind="delete", control=original)["state"], "deleting")
        self.assertEqual(r.call("resolve", create)["state"], "unavailable")
        r.perform("release_delete", create, original)
        self.assertEqual(r.call("observe", create, kind="delete", control=original)["state"], "deleted")
        audit(r.history())

    def test_compute_loss_discards_unsent_candidate_but_not_invoked_request(self):
        r, create = self.trace, self.create
        r.call("prepare", "unsent", "descriptor", create)
        r.call("crash")
        r.reject("phase", "invoke", "unsent")
        r.call("prepare", "sent", "descriptor", create)
        r.call("invoke", "sent")
        r.call("crash")
        self.assertEqual(r.call("effect", "sent"), "applied")
        self.assertEqual(r.call("receive", "sent"), "unknown")
        self.assertEqual(r.call("observe", create)["state"], "not_reserved")
        audit(r.history())

    def test_public_candidate_copy_cannot_change_inflight_scope_or_condition(self):
        r, create = self.trace, self.create
        wire = r.call("prepare", "descriptor", "descriptor", create)
        wire["body"]["intent"]["scope"][2] = 2
        wire["expected"] = "invented"
        r.call("invoke", "descriptor")
        r.call("effect", "descriptor")
        r.call("receive", "descriptor")
        record = r.model.current(descriptor_key(create))
        self.assertEqual(record["intent"]["scope"], create["scope"])
        record["intent"]["scope"][2] = 3
        self.assertEqual(r.model.current(descriptor_key(create))["intent"]["scope"], create["scope"])
        audit(r.history())

    def test_limits_are_real_backpressure_and_do_not_evict_barriers(self):
        r = Trace("records", limits=Limits(max_records=3))
        r.setup(self.create)
        before = copy.deepcopy(r.model.snapshot()["objects"])
        r.call("prepare", "full", "provision", self.create)
        r.call("invoke", "full")
        self.assertEqual(r.call("effect", "full"), "limit")
        self.assertEqual(r.call("receive", "full"), "limit")
        self.assertEqual(r.model.snapshot()["objects"], before)
        audit(r.history())
        tiny = Trace("attempts", limits=Limits(max_attempts=1))
        tiny.perform("descriptor", self.create)
        tiny.reject("limit", "prepare", "more", "reserve", self.create)
        audit(tiny.history())
        pending = Trace("pending", limits=Limits(max_pending=1))
        pending.call("prepare", "one", "descriptor", self.create)
        pending.call("prepare", "two", "descriptor", self.create)
        pending.call("invoke", "one")
        pending.reject("limit", "invoke", "two")
        audit(pending.history())

    def test_changed_control_or_other_principal_cannot_continue_accepted_abort(self):
        r, create, abort = self.trace, self.create, self.abort
        r.setup(create)
        r.perform("accept_abort", create, abort)
        changed = dict(abort, operation=12)
        r.reject("control_identity", "prepare", "other-abort", "fence_abort", create, changed)
        r.reject("denied", "prepare", "other-principal", "fence_abort", create, abort, actor=2)
        r.resume_abort(create, abort)
        self.assertEqual(r.model.current(head_key(create["scope"]))["abort"], abort)
        audit(r.history())

    def test_unknown_reply_does_not_erase_durable_result_or_change_original_scope(self):
        self.trace.setup(self.create, "ready")
        self.assertEqual(self.trace.call("observe", self.create, lost=True), {"state": "unknown"})
        self.trace.call("crash")
        result = self.trace.call("observe", self.create)
        self.assertEqual(result, {"state": "ready", "scope": self.create["scope"], "origin": origin(self.create)})
        audit(self.trace.history())

    def test_unadmitted_control_is_not_a_durable_cancellation(self):
        self.trace.setup(self.create)
        self.assertEqual(self.trace.call("observe", self.create, kind="abort", control=self.abort)["state"], "not_admitted")
        # Direct use of the modeled protocol, without Trace's explicit admission helper.
        with self.assertRaises(ModelError) as failure:
            self.trace.model.prepare("unadmitted", "accept_abort", self.create, self.abort)
        self.assertEqual(failure.exception.code, "control_not_prepared")
        self.assertEqual(self.trace.model.current(name_key(self.create))["state"], "reserved")
        audit(self.trace.history())

    def test_control_descriptor_freezes_conditions_before_a_failed_target_cas(self):
        r = self.trace
        r.setup(self.create, "ready")
        original = control_intent(self.create, "delete", name_revision=2, head_revision=2)
        r.call("prepare", "old-delete", "delete_head", self.create, original)
        r.call("invoke", "old-delete")
        r.perform("grant_admin", self.create, {"grant": 2})
        self.assertEqual(r.call("effect", "old-delete"), "conflict")
        r.call("receive", "old-delete", lost=True)
        changed = dict(original, expected_head_revision=3)
        r.reject("control_conflict", "prepare", "rebased-control", "delete_head", self.create, changed)
        self.assertEqual(r.model.current(control_key(self.create, original))["intent"], original)
        audit(r.history())

    def test_noncreator_current_admin_can_delete_but_cannot_abort_creation(self):
        r = self.trace
        r.setup(self.create, "ready")
        deletion = control_intent(self.create, "delete", name_revision=2, head_revision=3, caller=2)
        r.reject("denied", "prepare", "nonadmin", "delete_descriptor", self.create, deletion)
        r.perform("grant_admin", self.create, {"grant": 2})
        r.resume_delete(self.create, deletion)
        self.assertEqual(r.model.current(head_key(self.create["scope"]))["delete"]["principal"], 2)
        r.reject("denied", "prepare", "not-creator", "abort_descriptor", self.create, control_intent(self.create, caller=2))
        audit(r.history())

    def test_invalid_creation_input_never_writes_any_authority(self):
        for change in ({"name": ""}, {"name": "bad\x00name"}, {"scope": [1, 1, 0, 1, 1]},
                       {"operation": True}, {"retention": 1}):
            with self.subTest(change=change):
                r = Trace("invalid")
                create = dict(self.create, **change)
                r.reject("invalid", "prepare", "invalid", "descriptor", create)
                self.assertEqual(r.model.snapshot()["objects"], {})
                audit(r.history())
        with self.assertRaises(ModelError):
            CatalogueModel(limits=Limits(max_pending=0))


if __name__ == "__main__":
    unittest.main()
