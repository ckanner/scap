import ast
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from counterexamples import examples
from model import Model, payload_key
from oracle import audit, Violation


class IndependentObserver(unittest.TestCase):
    def test_all_concrete_counterexamples_fail_expected_rule(self):
        count = 0
        for case in examples():
            with self.subTest(case=case["name"]):
                with self.assertRaises(Violation) as result:
                    audit(case["history"])
                self.assertEqual(result.exception.rule, case["expected_rule"])
                self.assertLessEqual(result.exception.sequence, len(case["history"]["events"]))
                count += 1
        self.assertEqual(count, 20)

    def test_provisioning_observation_cannot_admit_ordinary_read(self):
        m = Model("abort")
        observation = next(value for value in m.reads.values() if value.get("body", {}).get("lifecycle") == "provisioning")
        m._prepare("unreachable-read", "read", "GET", payload_key(), None, None, [observation["id"]])
        with self.assertRaises(Violation) as result:
            audit(m.history())
        self.assertEqual(result.exception.rule, "reader_admission")

    def test_oracle_has_no_simulator_or_production_import(self):
        tree = ast.parse(Path(__file__).with_name("oracle.py").read_text())
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.append(node.module)
        self.assertEqual(set(imports), {"__future__", "copy", "json", "pathlib", "sys"})

    def test_every_prefix_can_end_with_inflight_requests(self):
        m = Model("abort")
        m.invoke(m.prepare_terminal("seal"))
        m.timeout("seal")
        m.crash()
        m.effect("seal")
        m.run(m.prove_abort())
        m.run(m.release_name())
        m.recover_intent()
        history = m.history()
        for length in range(1, len(history["events"]) + 1):
            prefix = {"schema": 1, "events": history["events"][:length]}
            audit(prefix, check_final=False)
        audit(history)

    def test_changed_actual_condition_is_not_a_summary_only_check(self):
        m = Model()
        m.run(m.prepare_terminal("seal"))
        history = m.history()
        request = next(event for event in history["events"] if event["event"] == "prepare" and event["kind"] == "terminal")
        request["condition"] = "fresh-but-unobserved-etag"
        with self.assertRaises(Violation) as result:
            audit(history)
        self.assertEqual(result.exception.rule, "original_condition")

    def test_final_state_must_be_complete(self):
        m = Model()
        history = m.history()
        history["final"]["store"].clear()
        with self.assertRaises(Violation) as result:
            audit(history)
        self.assertEqual(result.exception.rule, "complete_final_state")

    def test_cli_runs_with_only_oracle_and_json_history(self):
        m = Model()
        m.run(m.prepare_terminal("seal"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "oracle.py").write_text(Path(__file__).with_name("oracle.py").read_text())
            (root / "history.json").write_text(json.dumps(m.history()))
            result = subprocess.run([sys.executable, "-I", str(root / "oracle.py"), str(root / "history.json")], cwd=root, check=True, capture_output=True, text=True)
            self.assertTrue(json.loads(result.stdout)["ok"])

    def test_old_read_context_cannot_swap_backend_or_basis(self):
        m = Model()
        m.run("old-read")
        m.reader_reply()
        original = m.history()
        for field, value in (("backend", "replacement"), ("generation", 2), ("deadline", 11)):
            with self.subTest(field=field):
                history = deepcopy(original)
                next(event for event in history["events"] if event["event"] == "reader_reply")["state"][field] = value
                with self.assertRaises(Violation) as result:
                    audit(history)
                self.assertEqual(result.exception.rule, "captured_reader_context")


if __name__ == "__main__":
    unittest.main()
