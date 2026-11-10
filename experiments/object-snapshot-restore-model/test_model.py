from copy import deepcopy
import unittest

from cases import finish, full_copy_without_record, rejected, setup, special
from codec_budget import build, report
from model import Model
from oracle import audit


class ModelTests(unittest.TestCase):
    def check(self, name):
        model = special(name)
        audit(model.trace(name))
        return model

    def test_source_can_be_entirely_absent_after_ready(self):
        model = self.check("deleted_retains_until_explicit_release")
        self.assertFalse(any(key.startswith("data/source/") for key in model.store))
        self.assertEqual(model.store["head/target"]["body"]["requests"], [])

    def test_snapshot_release_proof_precedes_remove(self):
        model = Model(); entry = model.capture(1)
        call = model.snapshot_release(entry)
        self.assertEqual(model.snapshot_observe(entry), "retained")
        model.run(call, lost=True)
        self.assertEqual(model.snapshot_observe(entry), "released_observed")
        self.assertEqual(model.calls[call]["response"], {"status": "unknown"})
        audit(model.trace("proof-does-not-ack"))

    def test_label_reuse_does_not_change_identity(self):
        self.check("released_label_is_new_identity")

    def test_copy_does_not_use_lowered_current_quota_for_historical_tree(self):
        self.check("multi_root_lower_current_quota")

    def test_budget_has_no_diagnostic_head_or_partial_completion(self):
        model, entry, desc = setup(); attempt = model.start_copy(desc, budget=0)
        begin = len(model.events)
        rejected(lambda: model.copy_page(attempt, 1), "Budget")
        self.assertFalse(any(event["event"] == "get_invoke" for event in model.events[begin:]))
        self.assertFalse(any(path.startswith("completion/") for path in model.store))
        finish(model, desc); audit(model.trace("budget-new-attempt"))

    def test_failed_final_authorization_consumes_old_prefix(self):
        model, entry, desc = setup(); attempt = full_copy_without_record(model, desc)
        model.run(model.source_update("revoke"))
        rejected(lambda: model.completion(attempt), "Denied")
        model.run(model.source_update("grant"))
        rejected(lambda: model.completion(attempt), "ExpiredAttempt")
        finish(model, desc); audit(model.trace("authorization-prefix-consumed"))

    def test_completed_context_cannot_add_payload_after_final_barrier(self):
        model, entry, desc = setup(); attempt = full_copy_without_record(model, desc)
        call = model.completion(attempt)
        rejected(lambda: model.copy_page(attempt, 1), "ExpiredAttempt")
        model.run(call); finish(model, desc); audit(model.trace("closed-copy-capability"))

    def test_current_missing_is_not_expiry(self):
        self.check("protected_source_missing_is_corrupt_class")

    def test_target_missing_is_not_source_expiry(self):
        self.check("target_error_not_source_expiry")

    def test_release_does_not_revoke_old_admitted_gets(self):
        self.check("release_during_old_prefix")

    def test_failed_released_point_cannot_gain_fresh_context(self):
        self.check("released_failed_prefix_cannot_restart")

    def test_foreign_slot_is_preserved_and_name_released(self):
        self.check("foreign_slot_preserves_foreign_and_releases_name")

    def test_terminal_checkpoint_unknown_still_has_settle_and_clear(self):
        model = self.check("terminal_checkpoint_unknown_keeps_q")
        self.assertEqual(model.store["head/source"]["body"]["serial"], 6)
        self.assertIsNone(model.store["head/source"]["body"]["sweep"])
        self.assertTrue(any(path.startswith("data/source/1/") for path in model.store))

    def test_terminal_cannot_spend_checkpoint_clear_reserve(self):
        self.check("terminal_checkpoint_refuses_insufficient_room")

    def test_all_bounded_cleanup_paths_keep_reserved_room(self):
        model = Model(maximum=8)
        checked = 0
        for revision in range(1, 9):
            for serial in range(revision, 9):
                for points in range(3):
                    for mode in ("idle", "owner", "copy", "pending_sweep", "settled_sweep"):
                        for deleted in (False, True):
                            if deleted and mode in ("owner", "copy"):
                                continue
                            for terminal in (False, True):
                                if terminal and (not deleted or points or mode in ("owner", "copy")):
                                    continue
                                head = {"revision": revision, "serial": serial,
                                        "lifecycle": "deleted" if deleted else "ready",
                                        "terminal": 1 if terminal else None, "snapshots": list(range(points)),
                                        "owner_pending": mode == "owner", "plan": {} if mode == "copy" else None,
                                        "sweep": None if "sweep" not in mode else {"entries": [{"disposition":
                                            "pending" if mode == "pending_sweep" else "applied"}]}}
                                if not model.room(head):
                                    continue
                                # Execute one finite cleanup route, not a duplicate
                                # arithmetic formula for the original admission.
                                next_head = deepcopy(head)
                                if next_head["owner_pending"]:
                                    next_head["owner_pending"] = False
                                    next_head["revision"] += 1; next_head["serial"] += 1
                                    self.assertTrue(model.room(next_head))
                                if next_head["plan"] is not None:
                                    next_head["plan"] = None; next_head["serial"] += 1
                                    self.assertTrue(model.room(next_head))
                                if next_head["sweep"] is not None:
                                    if next_head["sweep"]["entries"][0]["disposition"] == "pending":
                                        next_head["sweep"]["entries"][0]["disposition"] = "applied"
                                        next_head["serial"] += 1
                                        self.assertTrue(model.room(next_head))
                                    next_head["sweep"] = None; next_head["serial"] += 1
                                    self.assertTrue(model.room(next_head))
                                while next_head["snapshots"]:
                                    next_head["snapshots"].pop(); next_head["serial"] += 1
                                    self.assertTrue(model.room(next_head))
                                if next_head["lifecycle"] != "deleted":
                                    next_head["lifecycle"] = "deleted"
                                    next_head["serial"] += 1; next_head["revision"] += 1
                                    self.assertTrue(model.room(next_head))
                                if next_head["terminal"] is None:
                                    next_head["terminal"] = 1; next_head["serial"] += 1
                                self.assertTrue(model.room(next_head))
                                self.assertLessEqual(next_head["serial"], 8)
                                checked += 1
        self.assertGreater(checked, 200)

    def test_head_encoded_upper_bound_includes_escaped_fields(self):
        value = report()
        self.assertEqual(value["bytes"]["live_copy"], 164934)
        self.assertEqual(value["bytes"]["live_sweep"], 199324)
        self.assertEqual(value["bytes"]["terminal_sweep"], 157799)
        self.assertEqual(value["bytes"]["all_optional_upper_bound_not_valid_head"], 242467)
        self.assertEqual(value["minimum_margin"], 19677)
        shapes = build()
        self.assertEqual(len(shapes["live_copy"]["policy"]), 1024)
        self.assertEqual(len(shapes["live_copy"]["storage"]["plan"]["basis"]["snapshots"]), 64)
        self.assertEqual(len(shapes["live_sweep"]["storage"]["sweep"]["entries"][0]["etag"]), 1024)


if __name__ == "__main__":
    unittest.main()
