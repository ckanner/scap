"""Finite protocol examples; these are model tests, not product unit coverage."""
from copy import deepcopy
import unittest

from model import Model, Rejected, OLD, FOREIGN, SUCCESSOR, head_key, payload_key, retired
from oracle import audit, state_retired


def seal(model):
    model.run(model.prepare_terminal("seal"))


def batch(model):
    model.run(model.prepare_checkpoint("batch"))


def sweep(model):
    batch(model)
    model.run(model.prepare_delete("delete"))
    model.run(model.prepare_settle("settle", delete_call="delete"))
    model.run(model.prepare_clear("clear"))


class Protocol(unittest.TestCase):
    def rejected(self, model, reason, action):
        with self.assertRaises(Rejected) as result:
            action()
        self.assertEqual(result.exception.reason, reason)
        audit(model.history())

    def test_owned_modes_preserve_business_identity(self):
        for mode in ("direct", "delete", "abort", "abort_absent"):
            with self.subTest(mode=mode):
                m = Model(mode)
                original = deepcopy(m.store[head_key()]["body"])
                seal(m)
                sweep(m)
                final = m.store[head_key()]["body"]
                for field in ("scope", "revision", "nonce", "owner_epoch", "creation", "deletion", "request_epoch", "data_root", "result_root", "active_generation", "allocated"):
                    self.assertEqual(final[field], original[field])
                self.assertNotIn(payload_key(), m.store)
                self.assertIn(payload_key(SUCCESSOR), m.store)
                self.assertEqual(m.fresh_lookup(), "lifecycle")
                audit(m.history())

    def test_last_generation_requires_explicit_seal(self):
        m = Model()
        self.rejected(m, "protected_generation", lambda: m.prepare_checkpoint("batch"))
        self.assertIn(payload_key(), m.store)

    def test_provisioning_sources_have_no_ordinary_read_or_known_sql_receipt(self):
        for mode in ("abort", "abort_absent", "foreign"):
            m = Model(mode)
            self.assertNotIn("old-read", m.calls)
            self.assertIsNone(m.reader)
            self.rejected(m, "no_known_receipt", m.late_receipt)

    def test_fixed_candidates_conflict_without_rebase(self):
        m = Model()
        first = m.prepare_terminal("first")
        second = m.prepare_terminal("second")
        self.assertEqual(m.calls[first].condition, m.calls[second].condition)
        self.assertEqual(m.run(first), "applied")
        self.assertEqual(m.run(second), "conflict")
        self.assertEqual(audit(m.history())["terminal_applied"], 1)

    def test_expected_serial_and_current_admin(self):
        m = Model("delete")
        self.rejected(m, "head_serial_conflict", lambda: m.prepare_terminal("wrong-serial", expected_serial=1))
        self.rejected(m, "denied", lambda: m.prepare_terminal("wrong-principal", principal=8))
        seal(m)
        self.rejected(m, "already_terminal", lambda: m.prepare_terminal("again"))

    def test_unknown_terminal_may_effect_after_unsealed_observation(self):
        m = Model()
        m.invoke(m.prepare_terminal("seal"))
        m.timeout("seal")
        self.assertEqual(m.terminal_status(), "unsealed")
        m.crash()
        m.effect("seal")
        self.assertEqual(m.terminal_status(), "terminal_observed")
        self.assertEqual(m.calls["seal"].reply, "unknown")
        self.assertEqual(audit(m.history())["late_effects"], 1)

    def test_crash_discards_unsent_candidate_but_not_invoked_effect(self):
        m = Model()
        m.prepare_terminal("unsent")
        m.crash()
        self.rejected(m, "stale_or_already_invoked", lambda: m.invoke("unsent"))
        m.run(m.prepare_terminal("fresh"))
        audit(m.history())

    def test_permanent_head_fences_old_cas_and_absent_create(self):
        for mode in ("direct", "delete", "abort", "abort_absent"):
            m = Model(mode)
            seal(m)
            sweep(m)
            if "old-head" in m.calls:
                self.assertEqual(m.run("old-head"), "conflict")
            self.assertEqual(m.run("old-create"), "conflict")
            self.assertIsNotNone(m.store[head_key()]["body"]["terminal"])
            audit(m.history())

    def test_late_put_recreates_orphan_and_new_round_cleans_it(self):
        for etags in ("fresh", "content"):
            m = Model(object_etags=etags)
            seal(m)
            sweep(m)
            self.assertEqual(m.run("old-put"), "applied")
            m.run(m.prepare_checkpoint("batch-2"))
            m.run(m.prepare_delete("delete-2"))
            m.run(m.prepare_settle("settle-2", delete_call="delete-2"))
            m.run(m.prepare_clear("clear-2"))
            self.assertNotIn(payload_key(), m.store)
            self.assertEqual(audit(m.history())["payload_delete"], 2)

    def test_late_delete_after_clear_is_safe_even_with_repeating_etag(self):
        for etags in ("fresh", "content"):
            m = Model(object_etags=etags)
            seal(m)
            batch(m)
            m.invoke(m.prepare_delete("held"))
            m.run(m.prepare_delete("delete"))
            m.run(m.prepare_settle("settle", delete_call="delete"))
            m.run(m.prepare_clear("clear"))
            m.run("old-put")
            m.effect("held")
            self.assertEqual(m.respond("held"), "applied" if etags == "content" else "conflict")
            self.assertIn(payload_key(SUCCESSOR), m.store)
            audit(m.history())

    def test_unknown_delete_is_pending_until_restart_typed_absence(self):
        m = Model()
        seal(m)
        batch(m)
        m.run(m.prepare_delete("delete"), lost=True)
        self.rejected(m, "unresolved_delete", lambda: m.prepare_settle("bad", delete_call="delete"))
        self.assertEqual(m.store[head_key()]["body"]["checkpoint"]["disposition"], "pending")
        m.crash()
        missing = m.prepare_delete("probe")
        m.run(m.prepare_settle("settle", absent=missing))
        m.run(m.prepare_clear("clear"))
        self.assertEqual(m.calls["delete"].reply, "unknown")
        audit(m.history())

    def test_replacement_etag_does_not_refresh_old_delete_condition(self):
        m = Model()
        seal(m)
        batch(m)
        original = m.store[head_key()]["body"]["checkpoint"]["etag"]
        m.run(m.prepare_delete("lost"), lost=True)
        m.run("old-put")
        self.assertNotEqual(m.store[payload_key()]["etag"], original)
        m.run(m.prepare_delete("retry"))
        self.assertEqual(m.calls["retry"].condition, original)
        self.assertEqual(m.calls["retry"].reply, "conflict")
        m.run(m.prepare_settle("settle", delete_call="retry"))
        self.assertEqual(m.store[head_key()]["body"]["checkpoint"]["disposition"], "condition_mismatch")
        self.assertIn(payload_key(), m.store)
        audit(m.history())

    def test_no_such_bucket_and_local_budget_cannot_close_pending(self):
        for failure in ("unknown", "budget"):
            m = Model()
            seal(m)
            batch(m)
            self.rejected(m, "inspect_" + failure, lambda: m.prepare_delete("delete", inspect_failure=failure))
            self.assertEqual(m.store[head_key()]["body"]["checkpoint"]["disposition"], "pending")
            self.assertFalse(m.semantic_latch)

    def test_complete_old_get_can_finish_after_terminal_collection(self):
        m = Model()
        m.invoke("old-read")
        m.effect("old-read")
        seal(m)
        sweep(m)
        m.respond("old-read")
        self.assertEqual(m.reader_reply(), "value")
        audit(m.history())

    def test_missing_old_get_requires_exact_terminal_proof(self):
        m = Model()
        m.invoke("old-read")
        seal(m)
        sweep(m)
        m.effect("old-read")
        m.respond("old-read")
        self.assertEqual(m.reader_reply(), "missing")
        self.assertEqual(m.diagnose(), "snapshot_expired")
        self.assertEqual(m.incidents, {1})
        self.assertFalse(m.semantic_latch)
        self.rejected(m, "no_diagnostic_prefix", m.diagnose)

    def test_unknown_probe_stays_local_and_does_not_poison_terminal_gc(self):
        m = Model()
        seal(m)
        batch(m)
        m.run(m.prepare_delete("delete"))
        m.run("old-read")
        m.reader_reply()
        self.assertEqual(m.diagnose("unknown"), "missing")
        self.assertEqual(m.incidents, {1})
        self.assertFalse(m.semantic_latch)
        m.run(m.prepare_settle("settle", delete_call="delete"))
        m.run(m.prepare_clear("clear"))
        audit(m.history())

    def test_hash_valid_semantic_failure_never_becomes_expired(self):
        m = Model()
        seal(m)
        bad = deepcopy(m.store[payload_key()]["body"])
        bad["semantic"] = "bad"
        m.corrupt_authority(payload_key(), bad)
        m.run("old-read")
        self.assertEqual(m.reader_reply(), "corrupt")
        self.rejected(m, "no_diagnostic_prefix", m.diagnose)
        self.rejected(m, "semantic_latch", lambda: m.prepare_checkpoint("blocked"))
        self.assertTrue(m.semantic_latch)

    def test_terminal_settle_and_clear_keep_semantic_publication_gate(self):
        for stage in ("settle", "clear"):
            m = Model()
            seal(m)
            bad = deepcopy(m.store[payload_key()]["body"])
            bad["semantic"] = "bad"
            m.corrupt_authority(payload_key(), bad)
            m.run("old-read")
            batch(m)
            m.run(m.prepare_delete("delete"))
            if stage == "clear":
                m.run(m.prepare_settle("settle", delete_call="delete"))
            m.reader_reply()
            action = (lambda: m.prepare_settle("settle", delete_call="delete")) if stage == "settle" else (lambda: m.prepare_clear("clear"))
            self.rejected(m, "semantic_latch", action)

    def test_local_budget_has_no_probe_or_corruption_latch(self):
        m = Model()
        before = len([event for event in m.events if event["event"] == "get"])
        self.assertEqual(m.reader_budget(), "budget")
        self.rejected(m, "no_diagnostic_prefix", m.diagnose)
        self.assertEqual(before, len([event for event in m.events if event["event"] == "get"]))
        self.assertFalse(m.semantic_latch or m.incidents)
        seal(m)
        audit(m.history())

    def test_original_deadline_and_crash_cannot_extend_old_prefix(self):
        m = Model()
        seal(m)
        sweep(m)
        m.run("old-read")
        m.reader_reply()
        m.tick(10)
        before = len([event for event in m.events if event["event"] == "get"])
        self.assertEqual(m.diagnose(), "missing")
        self.assertEqual(before, len([event for event in m.events if event["event"] == "get"]))
        m.crash()
        self.rejected(m, "stale_reader", m.diagnose)
        self.rejected(m, "stale_reader", m.reader_reply)

    def test_unsealed_physical_incident_blocks_old_lineage_only(self):
        m = Model()
        m.corrupt_authority(payload_key())
        m.run("old-read")
        m.reader_reply()
        self.assertEqual(m.diagnose(), "missing")
        self.rejected(m, "known_lineage_incident", lambda: m.prepare_terminal("old-handle"))
        m.crash()
        seal(m)
        audit(m.history())

    def test_fresh_authority_counter_contradictions_never_expire(self):
        for field, value in (("allocated", 1), ("active_generation", 0), ("serial", 1), ("scope", list(FOREIGN))):
            m = Model()
            seal(m)
            sweep(m)
            m.run("old-read")
            m.reader_reply()
            invalid = deepcopy(m.store[head_key()]["body"])
            invalid[field] = value
            m.corrupt_authority(head_key(), invalid)
            self.assertEqual(m.diagnose(), "missing")
            self.assertTrue(m.semantic_latch)
            audit(m.history())

    def test_terminal_seal_must_follow_original_live_context(self):
        m = Model(initial_serial=10)
        seal(m)
        sweep(m)
        m.run("old-read")
        m.reader_reply()
        impossible = deepcopy(m.store[head_key()]["body"])
        impossible["terminal"]["serial"] = 3
        m.corrupt_authority(head_key(), impossible)
        self.assertEqual(m.diagnose(), "missing")
        self.assertTrue(m.semantic_latch)
        audit(m.history())

    def test_terminal_serial_must_exceed_allocated_highwater(self):
        m = Model()
        seal(m)
        malformed = deepcopy(m.store[head_key()]["body"])
        malformed["terminal"]["serial"] = malformed["allocated"]
        m.corrupt_authority(head_key(), malformed)
        self.rejected(m, "invalid_head", lambda: m.prepare_terminal("again"))
        self.assertTrue(m.semantic_latch)

    def test_terminal_checkpoint_must_be_allocated_after_seal(self):
        m = Model()
        seal(m)
        batch(m)
        malformed = deepcopy(m.store[head_key()]["body"])
        malformed["checkpoint"]["serial"] = malformed["terminal"]["serial"]
        m.corrupt_authority(head_key(), malformed)
        self.rejected(m, "invalid_head", lambda: m.prepare_terminal("again"))
        self.assertTrue(m.semantic_latch)

    def test_abort_proof_before_or_after_seal_survives_gc(self):
        for mode in ("abort", "abort_absent"):
            for before in (True, False):
                m = Model(mode)
                if before:
                    m.run(m.prove_abort())
                seal(m)
                batch(m)
                if not before:
                    m.run(m.prove_abort())
                proof = deepcopy(m.store["proof:31"])
                m.run(m.release_name())
                self.assertEqual(m.recover_intent(), "aborted")
                m.run(m.prepare_delete("delete"))
                m.run(m.prepare_settle("settle", delete_call="delete"))
                m.run(m.prepare_clear("clear"))
                self.assertEqual(proof, m.store["proof:31"])
                audit(m.history())

    def test_metadata_only_delete_recovery_and_name_reuse(self):
        m = Model("delete")
        seal(m)
        batch(m)
        self.assertEqual(m.recover_intent(), "deleting")
        m.run(m.release_name())
        m.reuse_name()
        self.assertEqual(m.recover_intent(), "deleted")
        self.rejected(m, "same_operation_different_intent", lambda: m.recover_intent(nonce=102))
        m.run(m.prepare_delete("delete"))
        self.assertEqual(m.store[head_key(SUCCESSOR)]["body"]["lifecycle"], "ready")
        audit(m.history())

    def test_missing_actual_intent_is_not_recreated(self):
        for key in ("descriptor:31", "control:51", "name:demo"):
            m = Model("delete")
            m.corrupt_authority(key)
            self.rejected(m, "missing_intent", lambda: m.prepare_terminal("seal"))
            self.assertNotIn(key, m.store)
        m = Model("abort")
        m.run(m.prove_abort())
        m.run(m.release_name())
        m.corrupt_authority("proof:31")
        self.rejected(m, "missing_abort_proof", lambda: m.prepare_terminal("seal"))

    def test_foreign_occupied_proof_cannot_retire_foreign_database(self):
        m = Model("foreign")
        original = deepcopy(m.store[head_key()])
        self.rejected(m, "foreign_scope", lambda: m.prepare_terminal("seal"))
        self.assertEqual(m.store[head_key()], original)
        self.assertIn(payload_key(FOREIGN), m.store)

    def test_foreign_proof_still_completes_old_cancellation_without_owning_head(self):
        m = Model("foreign")
        foreign_head = deepcopy(m.store[head_key()])
        foreign_data = deepcopy(m.store[payload_key(FOREIGN)])
        proof = deepcopy(m.store["proof:31"])
        self.assertEqual(m.recover_foreign_abort(), "aborting")
        m.run(m.release_foreign_abort(), lost=True)
        m.crash()
        self.assertEqual(m.recover_foreign_abort(), "aborted")
        self.rejected(m, "same_operation_different_intent", lambda: m.recover_foreign_abort(nonce=102))
        self.rejected(m, "foreign_scope", lambda: m.prepare_terminal("seal"))
        self.assertEqual(m.store[head_key()], foreign_head)
        self.assertEqual(m.store[payload_key(FOREIGN)], foreign_data)
        self.assertEqual(m.store["proof:31"], proof)
        audit(m.history())

    def test_known_receipt_never_converts_to_expiry(self):
        m = Model()
        seal(m)
        sweep(m)
        m.late_receipt()
        m.late_receipt(native_failure=True)
        audit(m.history())

    def test_head6_retirement_predicate_is_an_explicit_inherited_boundary(self):
        head = deepcopy(Model().store[head_key()]["body"])
        head.update(active_generation=2, allocated=4, serial=4, plan_target=4)
        for generation, expected in ((0, False), (1, True), (2, False), (3, True), (4, False), (5, False)):
            self.assertEqual(retired(head, generation), expected)
            self.assertEqual(state_retired(head, generation), expected)
        head["plan_target"] = None
        self.assertTrue(retired(head, 4))
        head.update(format=7, serial=5, active=False, terminal={"serial": 5})
        self.assertTrue(all(retired(head, generation) and state_retired(head, generation) for generation in range(1, 5)))

    def test_serial_exhaustion_fails_before_preparing_seal(self):
        m = Model()
        full = deepcopy(m.store[head_key()]["body"])
        full["serial"] = 31
        m.corrupt_authority(head_key(), full)
        self.rejected(m, "serial_budget", lambda: m.prepare_terminal("seal"))
        self.assertNotIn("seal", m.calls)


if __name__ == "__main__":
    unittest.main()
