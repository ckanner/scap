"""Independent-oracle self-tests, including deliberately self-consistent faults."""
import ast
import copy
import unittest
from pathlib import Path

from named_catalogue_model import directed, negatives
from named_catalogue_oracle import OracleError, audit


class NamedCatalogueOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.histories = {run.name: run.history() for run in directed()}

    def test_all_directed_raw_histories_are_accepted(self):
        for name, history in self.histories.items():
            with self.subTest(name=name):
                result = audit(history)
                self.assertEqual(result["events"], len(history))

    def test_every_declared_negative_control_is_rejected_with_its_invariant(self):
        cases = list(negatives(self.histories))
        self.assertEqual(len(cases), 25)
        self.assertEqual(len({name for name, _, _ in cases}), len(cases))
        for name, expected, history in cases:
            with self.subTest(name=name):
                with self.assertRaises(OracleError) as failure:
                    audit(history)
                self.assertEqual(failure.exception.code, expected)

    def test_every_prefix_is_valid_without_inventing_a_completion(self):
        name = "direct_foreign_reuse_ready_other_incarnation"
        history = self.histories[name]
        for end in range(1, len(history) + 1):
            with self.subTest(prefix=end):
                result = audit(history[:end])
                self.assertEqual(result["events"], end)
        before_release = self.histories["direct_abort_proof_before_name_release"]
        result = audit(before_release)
        self.assertEqual(result["counts"].get("observed_aborted", 0), 0)
        self.assertEqual(result["counts"].get("observed_aborting", 0), 1)

    def test_oracle_does_not_import_model_or_any_shared_transition_helpers(self):
        path = Path(__file__).with_name("named_catalogue_oracle.py")
        module = ast.parse(path.read_text())
        imports = []
        for node in ast.walk(module):
            if isinstance(node, ast.Import):
                imports.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.append(node.module)
        allowed = {"__future__", "argparse", "copy", "hashlib", "json", "collections", "pathlib", "typing"}
        self.assertTrue(set(imports) <= allowed, imports)

    def test_unknown_event_or_physical_delete_cannot_silently_change_state(self):
        history = copy.deepcopy(self.histories["direct_abort_fence_before_proof"])
        for event_type in ("delete_object", "unconditional_put", "ttl_expired", "invented"):
            with self.subTest(event_type=event_type):
                with self.assertRaises(OracleError) as failure:
                    audit(history + [{"type": event_type, "key": "head/1/1/1"}])
                self.assertEqual(failure.exception.code, "EVENT")

    def test_duplicate_storage_effect_or_response_is_not_an_additional_success(self):
        for kind in ("effect", "receive"):
            history = copy.deepcopy(self.histories["direct_create_complete_lost_response"])
            index = next(i for i, e in enumerate(history) if e["type"] == kind)
            history.insert(index + 1, copy.deepcopy(history[index]))
            with self.subTest(kind=kind), self.assertRaises(OracleError) as failure:
                audit(history)
            self.assertEqual(failure.exception.code, "ORDER")

    def test_unconditional_overwrite_is_rejected_even_if_current_body_looks_valid(self):
        history = copy.deepcopy(self.histories["direct_create_complete_lost_response"])
        candidate = next(e for e in history if e["type"] == "prepare" and e["action"] == "complete")
        candidate["wire"]["expected"] = None
        with self.assertRaises(OracleError) as failure:
            audit(history)
        self.assertEqual(failure.exception.code, "CAS_BASE")

    def test_earlier_read_cannot_be_reused_as_a_new_progress_observation(self):
        history = copy.deepcopy(self.histories["direct_lost_business_reply_create"])
        observes = [e for e in history if e["type"] == "observe"]
        observes[-1]["reads"] = copy.deepcopy(observes[-2]["reads"])
        with self.assertRaises(OracleError) as failure:
            audit(history)
        self.assertEqual(failure.exception.code, "READ_SET")

    def test_known_conflict_cannot_be_relabelled_applied(self):
        history = copy.deepcopy(self.histories["direct_own_reuse_late_if_none"])
        response = next(e for e in history if e["type"] == "receive" and e["attempt"] == "late-provision")
        response["lost"] = False
        response["outcome"] = "applied"
        with self.assertRaises(OracleError) as failure:
            audit(history)
        # This reply targets a crashed generation as well as inventing success.
        self.assertEqual(failure.exception.code, "CRASH")

    def test_record_budget_failure_cannot_be_turned_into_a_commit(self):
        history = copy.deepcopy(self.histories["direct_record_budget"])
        effect = next(e for e in history if e["type"] == "effect" and e["outcome"] == "limit")
        effect["outcome"] = "applied"
        effect["after"] = "made-up-token"
        with self.assertRaises(OracleError) as failure:
            audit(history)
        self.assertEqual(failure.exception.code, "CONDITIONAL_RESULT")

    def test_malformed_or_empty_histories_are_rejected(self):
        with self.assertRaises(OracleError) as failure:
            audit([])
        self.assertEqual(failure.exception.code, "HISTORY")
        with self.assertRaises(OracleError) as failure:
            audit([{"type": "genesis"}])
        self.assertEqual(failure.exception.code, "MALFORMED")

    def test_crash_discards_unclaimed_gets_as_well_as_prepared_candidates(self):
        cases = {name: (code, history) for name, code, history in negatives(self.histories)}
        for name in ("old_ready_observations_survive_compute_loss", "old_absent_get_relabelled_as_new_process"):
            with self.subTest(name=name), self.assertRaises(OracleError) as failure:
                audit(cases[name][1])
            self.assertEqual(failure.exception.code, "READ_GENERATION")

    def test_invoked_write_still_effects_after_crash_with_new_observations(self):
        history = self.histories["direct_create_provision_before_effect_crash"]
        result = audit(history)
        self.assertEqual(result["counts"]["response_unknown"], 1)
        self.assertGreaterEqual(result["counts"]["observed_ready"], 1)


if __name__ == "__main__":
    unittest.main()
