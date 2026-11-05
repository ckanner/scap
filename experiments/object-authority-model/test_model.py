"""Protocol regression cases; these are not cloud or SQLite acceptance tests."""

import copy
import json
import unittest
from dataclasses import replace

from model import ControlIntent, Model, ModelError, Request, Store


class ModelTests(unittest.TestCase):
    def request(self, model, name="r", epoch=None, principal="alice", fingerprint="sql"):
        return Request(model.scope, model.head["request_epoch"] if epoch is None else epoch,
                       name, principal, fingerprint)

    def rejects(self, code, action, *args, **kwargs):
        with self.assertRaises(ModelError) as caught:
            action(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def commit(self, model, op_id, request=None, **kwargs):
        head = model.head
        return model.prepare(op_id, "commit", request=request or self.request(model, op_id),
                             base_seq=head["db_seq"], base_root=head["data_root"], **kwargs)

    def control(self, model, op_id, kind, *, actor="alice", auth_epoch=1, **params):
        intent = ControlIntent.make(model.scope, model.head["revision"], op_id, kind, actor, **params)
        model.prepare(op_id, kind, control=intent, actor=actor, auth_epoch=auth_epoch)
        return intent

    def seal(self, model, op_id, **stage):
        model.stage(op_id, **stage)
        for index in range(len(model.attempts[op_id].objects)):
            model.upload(op_id, index)
        model.verify(op_id)

    def finish(self, model, op_id, *, forget=True, **stage):
        if model.attempts[op_id].phase != "resolved":
            self.seal(model, op_id, **stage)
            model.invoke_cas(op_id)
            self.assertTrue(model.deliver_cas(op_id))
            self.assertEqual(model.receive_cas(op_id), "applied")
            if model.attempts[op_id].kind == "commit":
                model.publish(op_id)
        reply = model.reply(op_id)
        if forget:
            model.forget(op_id)
        return reply

    def close(self, model, op_id):
        self.control(model, op_id, "close", actor="coordinator",
                     expected_epoch=model.head["request_epoch"])
        return self.finish(model, op_id)

    def test_store_only_compares_tokens_and_identical_bytes_can_aba(self):
        store = Store(2)
        ok, original = store.put("HEAD", {"revision": 0}, None)
        self.assertTrue(ok)
        self.assertFalse(store.put("HEAD", {"revision": 1}, "invented")[0])
        ok, other = store.put("HEAD", {"arbitrary": "no owner or auth"}, original)
        self.assertTrue(ok)  # The object service is not a business state machine.
        ok, restored = store.put("HEAD", {"revision": 0}, other)
        self.assertTrue(ok)
        self.assertEqual(restored, original)
        self.assertTrue(store.put("HEAD", {"revision": 1}, original)[0])

    def test_dependencies_cas_native_publish_and_reply_are_separate(self):
        model = Model()
        request = self.request(model)
        self.commit(model, "write", request)
        model.stage("write", delta=3, result="original rows")
        self.rejects("phase", model.reply, "write")
        model.upload("write", 0)
        self.rejects("missing_object", model.verify, "write")
        self.assertEqual(model.head["db_seq"], 0)
        model.upload("write", 1)
        model.upload("write", 2)
        model.verify("write")
        model.invoke_cas("write")
        self.assertEqual(model.lookup(request)["state"], "unknown")
        model.deliver_cas("write")
        self.assertEqual(model.head["db_seq"], 1)
        self.assertEqual(model.lookup(request)["result"], "original rows")
        self.rejects("phase", model.publish, "write")
        model.receive_cas("write")
        self.rejects("not_materialized", model.reply, "write")
        model.publish("write")
        self.assertEqual(model.reply("write")["state"], "committed")

    def test_commit_cancel_competitors_have_only_one_head_successor(self):
        for first in ("write", "cancel"):
            with self.subTest(first=first):
                model = Model()
                request = self.request(model)
                self.commit(model, "write", request)
                model.prepare("cancel", "cancel", request=request)
                for op in ("write", "cancel"):
                    self.seal(model, op)
                    model.invoke_cas(op)
                second = "cancel" if first == "write" else "write"
                self.assertTrue(model.deliver_cas(first))
                self.assertFalse(model.deliver_cas(second))
                self.assertEqual(model.receive_cas(first), "applied")
                self.assertEqual(model.receive_cas(second), "conflict")
                if first == "write":
                    model.publish(first)
                self.assertEqual(model.reply(second)["state"], "conflict")
                self.assertEqual(model.reply(first)["state"],
                                 "committed" if first == "write" else "cancelled")
                self.assertEqual(model.lookup(request)["state"],
                                 "committed" if first == "write" else "cancelled")
                self.assertEqual(model.head["db_seq"], int(first == "write"))

    def test_absence_and_compute_loss_do_not_cancel_an_inflight_cas(self):
        model = Model()
        request = self.request(model)
        self.commit(model, "late", request)
        self.seal(model, "late", delta=5)
        model.invoke_cas("late")
        self.assertEqual(model.lookup(request)["state"], "unknown")
        model.restart()
        self.assertTrue(model.deliver_cas("late"))
        self.assertEqual(model.receive_cas("late"), "unknown")
        self.assertEqual(model.lookup(request)["state"], "committed")
        model.begin_read("after-restart")
        self.assertEqual(model.finish_read("after-restart"), 5)
        self.assertFalse(any(event["type"] == "reply" for event in model.events))

    def test_cancel_fences_a_previously_sent_write_even_after_restart(self):
        model = Model()
        request = self.request(model)
        self.commit(model, "late", request)
        self.seal(model, "late")
        model.invoke_cas("late")
        model.restart()
        model.prepare("cancel", "cancel", request=request)
        self.finish(model, "cancel")
        self.assertFalse(model.deliver_cas("late"))
        self.assertEqual(model.receive_cas("late"), "unknown")
        self.assertEqual(model.lookup(request)["state"], "cancelled")
        self.assertEqual(model.head["db_seq"], 0)

    def test_lost_cas_response_and_exact_retry_do_not_rebase_or_clear_unknown(self):
        model = Model()
        request = self.request(model)
        self.commit(model, "lost", request)
        self.seal(model, "lost")
        model.invoke_cas("lost")
        original = copy.deepcopy(model.pending["lost"])
        model.deliver_cas("lost")
        self.assertEqual(model.receive_cas("lost", lost=True), "unknown")
        model.invoke_cas("lost")
        self.assertEqual(model.pending["lost"], original)
        self.assertFalse(model.deliver_cas("lost"))
        self.assertEqual(model.receive_cas("lost"), "unknown")
        self.assertEqual(model.reply("lost")["state"], "unknown")
        self.rejects("phase", model.forget, "lost")
        self.assertEqual(model.lookup(request)["state"], "committed")
        self.assertEqual(model.head["db_seq"], 1)

    def test_native_failure_or_lost_reply_preserves_committed_data_and_result(self):
        for native_failure in (True, False):
            with self.subTest(native_failure=native_failure):
                model = Model()
                request = self.request(model)
                self.commit(model, "write", request)
                self.seal(model, "write", delta=7, result="saved")
                model.invoke_cas("write")
                model.deliver_cas("write")
                model.receive_cas("write")
                model.publish("write", fail=native_failure)
                result = model.reply("write", lost=not native_failure)
                self.assertEqual(result["state"], "committed_unavailable" if native_failure else "unknown")
                self.assertEqual(model.lookup(request)["result"], "saved")
                model.begin_read("verified")
                self.assertEqual(model.finish_read("verified"), 7)

    def test_takeover_fences_old_pages_and_activation_needs_actual_recovery(self):
        model = Model()
        self.commit(model, "old")
        self.seal(model, "old")
        model.invoke_cas("old")
        self.control(model, "take", "takeover", new_owner="writer-2")
        self.finish(model, "take")
        self.assertFalse(model.deliver_cas("old"))
        self.rejects("owner_fenced", self.commit, model, "old-again")
        self.rejects("owner_fenced", self.commit, model, "before-active",
                     owner="writer-2", owner_epoch=2)
        fake = model.recovery_identity(model.head)
        self.rejects("recovery_fenced", self.control, model, "fake-active", "activate", recovery=fake)
        proof = model.recover(owner="writer-2", owner_epoch=2)
        self.control(model, "active", "activate", recovery=proof)
        self.finish(model, "active")
        self.commit(model, "new", owner="writer-2", owner_epoch=2)
        self.finish(model, "new", delta=4)
        model.begin_read("value")
        self.assertEqual(model.finish_read("value"), 4)

    def test_recovery_proof_is_not_reusable_after_compute_loss_or_new_owner(self):
        model = Model()
        self.control(model, "take", "takeover", new_owner="writer-2")
        self.finish(model, "take")
        old = model.recover(owner="writer-2", owner_epoch=2)
        model.restart()
        self.rejects("recovery_fenced", self.control, model, "stale", "activate", recovery=old)
        proof = model.recover(owner="writer-2", owner_epoch=2)
        self.control(model, "take3", "takeover", new_owner="writer-3")
        self.finish(model, "take3")
        self.rejects("recovery_fenced", self.control, model, "wrong-owner", "activate", recovery=proof)

    def test_scope_actor_fingerprint_and_current_permissions_guard_results(self):
        model = Model()
        request = self.request(model)
        self.commit(model, "write", request)
        self.finish(model, "write")
        self.rejects("principal_mismatch", model.lookup, request, actor="bob")
        self.rejects("principal_mismatch", model.prepare, "impersonate", "cancel", request=request, actor="bob")
        other_principal = replace(request, principal="bob")
        self.assertEqual(model.lookup(other_principal, actor="bob")["state"], "conflict")
        self.assertEqual(model.lookup(replace(request, fingerprint="different"))["state"], "conflict")
        self.rejects("scope", model.lookup, replace(request, scope="another/database"))
        self.rejects("future_epoch", model.lookup, replace(request, epoch=2))
        self.control(model, "revoke", "auth", grants={"alice": ["admin"], "bob": ["read", "write"]})
        self.finish(model, "revoke")
        self.rejects("auth_fenced", model.lookup, request)
        self.rejects("forbidden", model.lookup, request, auth_epoch=2)
        self.rejects("forbidden", self.commit, model, "duplicate", request, auth_epoch=2)

    def test_permission_delete_and_maintenance_changes_fence_prepared_writes(self):
        for kind, params, rejection in (
            ("auth", {"grants": {"alice": ["admin", "read"]}}, "auth_fenced"),
            ("delete", {}, "deleted"),
            ("maintenance", {"enabled": True}, "maintenance"),
        ):
            with self.subTest(kind=kind):
                model = Model()
                self.commit(model, "old")
                self.seal(model, "old")
                model.invoke_cas("old")
                original_roots = (model.head["data_root"], model.head["request_root"])
                self.control(model, "fence", kind, **params)
                self.finish(model, "fence")
                self.assertFalse(model.deliver_cas("old"))
                self.rejects(rejection, self.commit, model, "new")
                self.assertEqual((model.head["data_root"], model.head["request_root"]), original_roots)
                if kind == "delete":
                    self.rejects("deleted", model.lookup, self.request(model, epoch=1))

    def test_strong_reads_choose_fresh_roots_and_keep_authorized_snapshot(self):
        model = Model()
        model.begin_read("before")
        self.commit(model, "change")
        self.finish(model, "change", delta=2)
        self.assertEqual(model.finish_read("before"), 0)
        model.begin_read("authorized")
        self.control(model, "revoke", "auth", grants={"alice": ["admin"], "bob": ["read", "write"]})
        self.finish(model, "revoke")
        self.assertEqual(model.finish_read("authorized"), 2)
        self.rejects("forbidden", model.begin_read, "new", auth_epoch=2)
        self.control(model, "maintenance", "maintenance", enabled=True, auth_epoch=2)
        self.finish(model, "maintenance")
        model.begin_read("independent-reader", actor="bob", auth_epoch=2)
        self.assertEqual(model.finish_read("independent-reader"), 2)

    def test_two_closed_generations_are_preserved_before_atomic_retirement(self):
        model = Model()
        original = self.request(model, "first")
        self.commit(model, "first", original)
        self.finish(model, "first", result="must survive two closes")
        original_result = model.lookup(original)["result_root"]
        for epoch in range(1, 4):
            count = 1 if epoch == 1 else 0
            while count < 2:
                op_id = f"cancel-{epoch}-{count}"
                model.prepare(op_id, "cancel", request=self.request(model, op_id))
                self.finish(model, op_id)
                count += 1
            self.close(model, f"close-{epoch}")
            if epoch < 3:
                self.assertEqual(model.lookup(original)["result"], "must survive two closes")
                self.assertEqual(model.head["retired_floor"], 0)
            else:
                self.assertEqual(model.lookup(original)["state"], "retired")
                self.assertEqual(model.head["retired_floor"], 1)
        self.assertEqual(model.head["request_epoch"], 4)
        self.assertIn(original_result, model.store.objects)  # Logical retirement is not GC.
        self.rejects("retired", self.commit, model, "old-replay", original)
        self.assertEqual(original.epoch, 1)
        model.begin_read("data-survives")
        self.assertEqual(model.finish_read("data-survives"), 1)

    def test_full_window_cancel_and_closed_absence_never_forge_cancelled(self):
        model = Model()
        for name in ("a", "b"):
            model.prepare(name, "cancel", request=self.request(model, name))
            self.finish(model, name)
        absent = self.request(model, "not-recorded")
        self.assertEqual(model.lookup(absent)["state"], "unknown")
        before = model.head
        self.rejects("resource_exhausted", model.prepare, "cannot-cancel", "cancel", request=absent)
        self.assertEqual(model.head, before)
        self.close(model, "full-close")
        self.assertEqual(model.lookup(absent)["state"], "epoch_closed")
        self.rejects("epoch_closed", model.prepare, "old-cancel", "cancel", request=absent)
        self.rejects("epoch_closed", self.commit, model, "old-write", absent)
        self.assertEqual(absent.epoch, 1)

    def test_close_requires_full_window_coordinator_and_original_control(self):
        model = Model(window_limit=1)
        self.rejects("window_not_full", self.control, model, "empty", "close",
                     actor="coordinator", expected_epoch=1)
        model.prepare("cancel", "cancel", request=self.request(model))
        self.finish(model, "cancel")
        self.rejects("forbidden", self.control, model, "tenant", "close", expected_epoch=1)
        self.rejects("epoch_fenced", self.control, model, "wrong", "close",
                     actor="coordinator", expected_epoch=2)
        intent = self.control(model, "close", "close", actor="coordinator", expected_epoch=1)
        self.finish(model, "close")
        model.restart()
        self.rejects("control_fenced", model.prepare, "close", "close", actor="coordinator", control=intent)
        self.assertEqual(model.head["request_epoch"], 2)

    def test_retention_contract_cannot_be_changed_on_restart_or_reopen(self):
        model = Model()
        before = model.head
        self.rejects("contract_mismatch", model.restart, window_limit=1)
        self.rejects("contract_mismatch", Model, store=model.store, window_limit=1)
        self.rejects("invalid_contract", Model, store=model.store, keep_closed=1)
        model.restart(window_limit=2, keep_closed=2)
        reopened = Model(store=model.store)
        self.assertEqual(reopened.head, before)
        self.assertEqual(model.head, before)

    def test_corrupt_dependencies_and_head_fail_closed(self):
        for target in ("staged", "data", "index", "head"):
            with self.subTest(target=target):
                model = Model()
                request = self.request(model)
                self.commit(model, "write", request)
                if target == "staged":
                    model.stage("write")
                    for i in range(3):
                        model.upload("write", i)
                    model.corrupt(model.attempts["write"].objects[0][0])
                    self.rejects("corrupt", model.verify, "write")
                    self.assertEqual(model.head["db_seq"], 0)
                else:
                    self.finish(model, "write")
                    key = (model.head_key if target == "head" else
                           model.head["data_root" if target == "data" else "request_root"])
                    model.corrupt(key)
                    self.rejects("corrupt", model.lookup, request)
                    self.rejects("corrupt", model.begin_read, "unavailable")

    def test_object_budget_counts_orphans_and_counter_exhaustion_is_atomic(self):
        model = Model(max_objects=5)
        self.commit(model, "write")
        model.stage("write")
        model.upload("write", 0)
        model.upload("write", 1)
        self.rejects("resource_exhausted", model.upload, "write", 2)
        self.assertEqual(len(model.store.objects), 5)
        self.assertEqual(model.head["db_seq"], 0)
        tiny = Model(max_counter=2)
        self.control(tiny, "take", "takeover", new_owner="writer-2")
        self.finish(tiny, "take")
        proof = tiny.recover(owner="writer-2", owner_epoch=2)
        self.control(tiny, "active", "activate", recovery=proof)
        self.finish(tiny, "active")
        before = tiny.head
        self.commit(tiny, "overflow", owner="writer-2", owner_epoch=2)
        self.rejects("exhausted", tiny.stage, "overflow")
        self.assertEqual(tiny.head, before)

    def test_completed_handles_are_reclaimable_but_inflight_and_unknown_are_not(self):
        model = Model(max_attempts=1)
        self.commit(model, "first")
        self.finish(model, "first", forget=False)
        self.rejects("resource_exhausted", self.commit, model, "second")
        model.forget("first")
        self.commit(model, "second")
        self.finish(model, "second")
        self.close(model, "close")
        self.commit(model, "lost")
        self.seal(model, "lost")
        model.invoke_cas("lost")
        self.rejects("phase", model.forget, "lost")
        model.deliver_cas("lost")
        model.receive_cas("lost", lost=True)
        model.reply("lost")
        self.rejects("phase", model.forget, "lost")
        self.rejects("resource_exhausted", self.commit, model, "extra")

    def test_unknown_control_preserves_original_identity_and_exact_intent_proof(self):
        model = Model()
        intent = self.control(model, "take", "takeover", new_owner="writer-2")
        self.seal(model, "take")
        model.invoke_cas("take")
        model.deliver_cas("take")
        model.receive_cas("take", lost=True)
        self.assertEqual(model.lookup_control(intent)["state"], "applied")
        different = ControlIntent.make(model.scope, 0, "take", "takeover", new_owner="writer-3")
        self.assertEqual(model.lookup_control(different)["state"], "conflict")
        other_kind = ControlIntent.make(model.scope, 0, "take", "delete")
        self.assertEqual(model.lookup_control(other_kind)["state"], "conflict")
        model.restart()
        self.rejects("control_fenced", model.prepare, "take", "takeover", control=intent)
        self.assertEqual(model.lookup_control(intent)["state"], "applied")
        self.control(model, "maintain", "maintenance", enabled=True)
        self.finish(model, "maintain")
        self.assertEqual(model.lookup_control(intent)["state"], "superseded")
        unsent = ControlIntent.make(model.scope, model.head["revision"], "unsent", "delete")
        self.assertEqual(model.lookup_control(unsent)["state"], "unknown")

    def test_known_results_are_returned_without_restaging_or_new_cas(self):
        model = Model()
        request = self.request(model)
        self.commit(model, "first", request)
        self.finish(model, "first", result="original")
        before, object_count = model.head, len(model.store.objects)
        resolved = model.prepare("same-request", "cancel", request=request)
        self.assertEqual(resolved.phase, "resolved")
        self.rejects("phase", model.stage, "same-request", result="different")
        reply = model.reply("same-request")
        self.assertEqual(reply["state"], "committed")
        self.assertEqual(reply["result"]["result"], "original")
        self.assertEqual(model.head, before)
        self.assertEqual(len(model.store.objects), object_count)

    def test_reused_handle_nonce_has_new_complete_transition_identity(self):
        model = Model(max_attempts=1)
        first = self.request(model, "first")
        second = self.request(model, "second")
        self.commit(model, "same", first)
        self.finish(model, "same")
        self.assertEqual(model.head["transition_id"], "1:same")
        self.commit(model, "same", second)
        self.finish(model, "same")
        self.assertEqual(model.head["transition_id"], "2:same")
        self.assertEqual(model.lookup(first)["transition_id"], "1:same")
        self.assertEqual(model.lookup(second)["transition_id"], "2:same")
        self.assertEqual(model.head["db_seq"], 2)

    def test_public_observations_cannot_mutate_prepared_work_or_read_snapshots(self):
        model = Model()
        prepared = self.commit(model, "write")
        prepared.snapshot.head["grants"]["bob"].append("admin")
        prepared.intent["actor"] = "bob"
        staged = model.stage("write", result="original")
        staged.candidate["grants"]["bob"].append("admin")
        staged.objects[1][1]["result"] = "tampered"
        model.attempts["write"].candidate["db_seq"] = 100
        for index in range(3):
            model.upload("write", index)
        model.verify("write")
        model.invoke_cas("write")
        model.pending["write"]["candidate"]["db_seq"] = 101
        model.deliver_cas("write")
        model.receive_cas("write")
        model.publish("write")
        self.assertEqual(model.reply("write")["result"]["result"], "original")
        self.assertNotIn("admin", model.head["grants"]["bob"])
        snapshot = model.begin_read("safe")
        snapshot.head["data_root"] = "invented"
        model.readers["safe"]["snapshot"].head["data_root"] = "also-invented"
        self.assertEqual(model.finish_read("safe"), 1)

    def test_seal_rejects_accidental_internal_candidate_or_base_mutation(self):
        for field in ("candidate", "base"):
            with self.subTest(field=field):
                model = Model()
                self.commit(model, "write")
                model.stage("write")
                if field == "candidate":
                    model._attempts["write"].candidate["grants"]["bob"].append("admin")
                    self.rejects("unsealed", model.upload, "write", 0)
                else:
                    model._attempts["write"].snapshot.head["db_seq"] = 22
                    self.rejects("unsealed", model.verify, "write")
                self.assertEqual(model.head["revision"], 0)

    def test_unavailable_store_does_not_allow_cached_read_or_successful_write(self):
        model = Model()
        self.commit(model, "write")
        self.seal(model, "write")
        model.store.available = False
        self.rejects("unavailable", model.invoke_cas, "write")
        self.rejects("unavailable", model.lookup, self.request(Model()))
        self.rejects("unavailable", model.begin_read, "cached")
        model.store.available = True
        self.assertEqual(model.head["revision"], 0)
        self.assertEqual(model.events[-1]["type"], "rejected")
        json.dumps(model.events, allow_nan=False)
        json.dumps(model.snapshot_state(), allow_nan=False)


if __name__ == "__main__":
    unittest.main()
