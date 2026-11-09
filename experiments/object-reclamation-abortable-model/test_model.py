"""Small independent boundary tests; full graph/negative controls are separate."""

import copy
import json
from pathlib import Path
import unittest

from model import Model
from oracle import check_edge, enabled
from oracle_protocol import Rules, etag


INPUTS = json.loads(Path(__file__).with_name("inputs.json").read_text())


def profile(name):
    return next(value for value in INPUTS["profiles"] if value["id"] == name)


def original_path(name):
    fixture = profile(name)
    producer, rules = Model(INPUTS, fixture), Rules(INPUTS, fixture)
    state, path = copy.deepcopy(fixture["initial"]), []
    for _ in range(512):
        choices = producer.actions(state)
        if not choices:
            return rules, path, state
        def order(action):
            if "network" in action:
                return (0 if action["choice"] == "apply" else 5, action["network"])
            return (1 if action["choice"] in ("step", "known", "commit", None) else 4, action["actor"])
        action = min(choices, key=order)
        after = producer.successor(state, action)
        check_edge(rules, state, after, action)
        path.append((state, after, action))
        state = after
    raise AssertionError("deterministic unit fixture exceeded its fixed bound")


class ContractBoundaries(unittest.TestCase):
    def test_frozen_original_profiles_and_new_technical_profiles_are_distinct(self):
        self.assertEqual(len(INPUTS["profiles"]), 41)
        self.assertEqual(set(value["id"] for value in INPUTS["profiles"] if value["id"].startswith("T")), {"T01", "T02"})
        self.assertEqual(INPUTS["bounds"]["ordinary_pins"], 0)

    def test_original_authorized_read_finishes_after_freeze_without_closing_get(self):
        _, _, final = original_path("A01")
        self.assertEqual(final["actors"]["r"]["outcome"]["kind"], "read_success")
        self.assertIsNotNone(final["head"]["plan"])
        tokens = [value for value in final["tokens"].values() if value["owner"] == "r"]
        self.assertEqual(sum(value["kind"] == "head_get" for value in tokens), 1)
        self.assertFalse(any(value["kind"] == "head_cas" for value in tokens))

    def test_incomplete_public_result_is_rejected(self):
        rules, path, _ = original_path("A01")
        before, after, action = path[-1]
        altered = copy.deepcopy(after)
        local = altered["actors"]["r"]
        local["outcome"]["result"] = copy.deepcopy(local["materialized"])
        local["outcome"]["result"]["frames"].pop(next(iter(local["outcome"]["result"]["frames"])))
        with self.assertRaisesRegex(ValueError, "original complete materialization"):
            check_edge(rules, before, altered, action)

    def test_retired_failure_does_not_poison_new_active(self):
        _, _, final = original_path("A04")
        self.assertEqual(final["actors"]["r"]["outcome"]["kind"], "expired")
        self.assertEqual(final["actors"]["n"]["outcome"]["kind"], "read_success")
        self.assertNotIn("2", final["health"])

    def test_active_failure_stays_corrupt(self):
        _, _, final = original_path("A06")
        self.assertEqual(final["actors"]["r"]["outcome"]["code"], "CORRUPT")
        self.assertEqual(final["actors"]["n"]["stopped"], "CORRUPT")

    def test_failed_authority_does_not_prove_retirement(self):
        _, _, final = original_path("A08")
        self.assertEqual(final["actors"]["r"]["outcome"]["kind"], "unknown")
        self.assertEqual(final["actors"]["n"]["stopped"], "CORRUPT")

    def test_aborted_target_can_retire_above_active(self):
        rules = Rules(INPUTS, profile("C01"))
        head = copy.deepcopy(profile("C01")["initial"]["head"])
        head["M"], head["plan"]["identity"]["target"] = 3, 3
        self.assertTrue(rules.retired(head, 2))
        self.assertFalse(rules.retired(head, 1))
        self.assertFalse(rules.retired(head, 3))

    def test_retained_hold_blocks_namespace_retirement(self):
        rules = Rules(INPUTS, profile("CP01"))
        head = copy.deepcopy(profile("CP01")["initial"]["head"])
        self.assertTrue(rules.retired(head, 1))
        head["hold"] = {"id": "keep", "generation": 1, "roots": [rules.names["A"]]}
        self.assertFalse(rules.retired(head, 1))

    def test_receipt_root_identity_is_not_a_reference(self):
        rules = Rules(INPUTS, profile("X02"))
        closure = rules.closure(rules.roots(profile("X02")["initial"]["head"]))
        self.assertEqual(closure, {rules.names[name] for name in ("D", "E", "C")})
        self.assertNotIn(rules.names["A"], closure)

    def test_raw_noncanonical_bytes_are_preserved(self):
        rules, _, final = original_path("X02")
        result = final["objects"][rules.key(2, rules.names["C"])]["raw"]
        self.assertEqual(result, rules.frames[rules.names["C"]]["raw"])
        self.assertIn(b"\n ", bytes.fromhex(result))

    def test_body_derived_head_etag_cannot_aba_with_new_serial(self):
        body = copy.deepcopy(profile("A01")["initial"]["head"])
        original = etag(body)
        body["serial"] += 2
        self.assertNotEqual(original, etag(body))

    def test_same_hash_has_distinct_physical_generation_keys(self):
        rules = Rules(INPUTS, profile("A01"))
        self.assertNotEqual(rules.key(1, rules.names["A"]), rules.key(2, rules.names["A"]))
        self.assertIn("/inc/13/gen/17/storage/2/objects/", rules.key(2, rules.names["A"]))

    def test_unknown_pending_network_remains_enabled_after_local_exit(self):
        fixture = profile("X01")
        rules = Rules(INPUTS, fixture)
        state = copy.deepcopy(fixture["initial"])
        state["actors"]["r"].update(stopped="LOCAL_GATE_CLOSED", local_stop=True)
        state["tokens"]["old"] = {"stage": "pending", "observed": "unknown"}
        self.assertEqual({json.loads(value)["choice"] for value in enabled(rules, state)}, {"apply", "discard"})

    def test_typed_absence_is_distinct_from_bucket_missing_and_unknown(self):
        rules = Rules(INPUTS, profile("CP04"))
        entry = {"key": rules.key(1, rules.names["A"]), "etag": '"old"'}
        state = {"tokens": {"get": {"kind": "candidate_get", "stage": "applied", "observed": "known",
                                     "request": {"key": entry["key"]}, "response": {"outcome": "NO_SUCH_KEY"}}}}
        rules.disposition(state, entry, "observed_absent", "get")
        for invalid in ("NO_SUCH_BUCKET", "UNAVAILABLE", "UNKNOWN"):
            state["tokens"]["get"]["response"]["outcome"] = invalid
            with self.assertRaisesRegex(ValueError, "not exact-key absence"):
                rules.disposition(state, entry, "observed_absent", "get")

    def test_new_delete_attempt_does_not_rewrite_original_unknown(self):
        rules = Rules(INPUTS, profile("CP05"))
        entry = {"key": rules.key(1, rules.names["A"]), "etag": '"old"'}
        state = {"tokens": {
            "original": {"kind": "delete", "stage": "pending", "observed": "unknown", "request": entry},
            "retry": {"kind": "delete", "stage": "applied", "observed": "known", "request": entry, "response": {"outcome": "CONFLICT"}}}}
        rules.disposition(state, entry, "condition_mismatch", "retry")
        self.assertEqual(state["tokens"]["original"]["observed"], "unknown")
        with self.assertRaisesRegex(ValueError, "exact known original key evidence"):
            rules.disposition(state, entry, "condition_mismatch", "original")

    def test_replacement_etag_is_not_original_condition(self):
        rules = Rules(INPUTS, profile("CP05"))
        entry = {"key": rules.key(1, rules.names["A"]), "etag": '"old"'}
        state = {"tokens": {"retry": {"kind": "delete", "stage": "applied", "observed": "known",
                                       "request": {"key": entry["key"], "etag": '"replacement"'}, "response": {"outcome": "CONFLICT"}}}}
        with self.assertRaisesRegex(ValueError, "replaced original DELETE condition"):
            rules.disposition(state, entry, "condition_mismatch", "retry")

    def test_stop_withholds_ack_but_preserves_known_remote_and_native_commit(self):
        _, _, final = original_path("S01")
        actor = final["actors"]["w"]
        self.assertEqual(actor["stopped"], "LOCAL_GATE_CLOSED")
        self.assertTrue(actor["commit_known"])
        self.assertEqual(actor["native"], "commit")
        self.assertEqual(actor["receipt"]["head"]["data"], final["head"]["data"])

    def test_detach_is_not_native_or_remote_rollback(self):
        _, _, final = original_path("S02")
        actor = final["actors"]["w"]
        self.assertTrue(actor["detached"])
        self.assertEqual(actor["outcome"]["kind"], "withheld")
        self.assertEqual(actor["native"], "commit")
        self.assertTrue(actor["commit_known"])

    def test_stopped_complete_can_be_durable_without_public_success(self):
        _, _, final = original_path("S03")
        self.assertEqual(final["head"]["life"], "ready")
        self.assertEqual(final["actors"]["c"]["stopped"], "LOCAL_GATE_CLOSED")

    def test_stop_metadata_and_later_stop_historical_success_are_different(self):
        _, _, final = original_path("S04")
        self.assertEqual(final["actors"]["r"]["stopped"], "LOCAL_GATE_CLOSED")
        self.assertEqual(final["actors"]["h"]["outcome"]["kind"], "metadata_ready")
        self.assertTrue(final["actors"]["h"]["detached"])
        self.assertTrue(final["actors"]["h"]["local_stop"])

    def test_normal_instruction_cannot_modify_fixture_fault_state(self):
        rules, path, _ = original_path("A01")
        before, after, action = next(item for item in path if item[2].get("actor") == "r")
        altered = copy.deepcopy(after)
        altered["authority_fault"] = "unavailable"
        with self.assertRaisesRegex(ValueError, "nonfixture instruction modified"):
            check_edge(rules, before, altered, action)

    def test_normal_instruction_cannot_forge_pause_marks(self):
        rules, path, _ = original_path("A01")
        before, after, action = next(item for item in path if item[2].get("actor") == "r")
        altered = copy.deepcopy(after)
        altered["actors"]["r"]["marks"]["paused"] = True
        with self.assertRaisesRegex(ValueError, "fact owned by another operation: marks"):
            check_edge(rules, before, altered, action)


if __name__ == "__main__":
    unittest.main()
