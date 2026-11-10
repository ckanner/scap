import ast
from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from cases import special
from counterexamples import negatives
from oracle import audit, Violation


class OracleTests(unittest.TestCase):
    def test_all_declared_negatives_reject_their_exact_rule(self):
        for case in negatives():
            with self.subTest(name=case.name, category=case.category):
                with self.assertRaises(Violation) as caught:
                    audit(case.build())
                self.assertEqual(caught.exception.rule, case.rule)

    def test_positive_summary_is_irrelevant(self):
        value = special("deleted_retains_until_explicit_release").trace("summary")
        original = audit(value)
        altered = deepcopy(value); altered["summary"] = {"all_data_lost": True, "ready": False}
        self.assertEqual(audit(altered), original)
        del altered["summary"]
        self.assertEqual(audit(altered), original)

    def test_oracle_isolated_with_only_its_file_and_history(self):
        value = special("three_generations_late_delete").trace("isolated")
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            shutil.copy(Path(__file__).with_name("oracle.py"), target / "oracle.py")
            (target / "history.json").write_text(json.dumps(value))
            result = subprocess.run([sys.executable, "-I", str(target / "oracle.py"), str(target / "history.json")],
                                    cwd=target, text=True, capture_output=True, check=True, timeout=15)
            self.assertEqual(json.loads(result.stdout), audit(value))

    def test_observer_has_no_model_or_case_import(self):
        tree = ast.parse(Path(__file__).with_name("oracle.py").read_text())
        imported = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.append((node.module or "").split(".")[0])
        self.assertFalse(set(imported) & {"model", "cases", "counterexamples", "explore", "codec_budget"})

    def test_raw_conditional_result_cannot_be_overridden_by_summary(self):
        value = special("snapshot_observation_is_not_release_ack").trace("bad-effect")
        effect = next(event for event in value["events"] if event["event"] == "put_effect")
        effect["result"] = {"status": "conflict"}
        value["summary"] = {"ok": True}
        with self.assertRaises(Violation) as caught:
            audit(value)
        self.assertEqual(caught.exception.rule, "conditional_effect")

    def test_real_tree_bytes_bound_the_cold_result(self):
        value = special("deleted_retains_until_explicit_release").trace("bad-cold")
        event = next(event for event in reversed(value["events"]) if event["event"] == "cold_target")
        event["values"][0] = "forged"
        with self.assertRaises(Violation) as caught:
            audit(value)
        self.assertEqual(caught.exception.rule, "cold_independent_target")


if __name__ == "__main__":
    unittest.main()
