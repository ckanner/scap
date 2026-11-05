"""Positive histories, explicit fault mutants, and evidence-boundary regressions."""

from __future__ import annotations

import ast
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from explore import examples, interleavings, negative_controls
from oracle import OracleError, audit


# Generation is deterministic and independent of the oracle's implementation.
# The negative controls mutate only copies of the real model's raw histories.
SAMPLES = examples()
NEGATIVES = list(negative_controls(SAMPLES))


class PositiveHistoryTests(unittest.TestCase):
    pass


class NegativeHistoryTests(unittest.TestCase):
    pass


for _name, _history in SAMPLES.items():
    def positive(self, history=_history):
        result = audit(copy.deepcopy(history))
        self.assertTrue(result["passed"])
        self.assertEqual(result["events"], len(history))
        self.assertFalse(result["production_slo_passed"])
    setattr(PositiveHistoryTests, f"test_{_name}", positive)


for _control in NEGATIVES:
    def negative(self, control=_control):
        with self.assertRaises(OracleError) as caught:
            audit(copy.deepcopy(control["events"]))
        self.assertEqual(caught.exception.code, control["expected_invariant"])
        self.assertGreater(caught.exception.step, 0)
    setattr(NegativeHistoryTests, f"test_{_control['name']}", negative)


class EvidenceBoundaryTests(unittest.TestCase):
    def test_oracle_imports_no_model_or_explorer(self):
        tree = ast.parse(Path(__file__).with_name("oracle.py").read_text())
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.add((node.module or "").split(".")[0])
        self.assertFalse({"model", "explore"} & imports)
        self.assertLessEqual(imports, {"__future__", "argparse", "copy", "hashlib", "json", "collections", "pathlib", "typing"})

    def test_raw_json_roundtrip_keeps_every_observation(self):
        for name, history in SAMPLES.items():
            with self.subTest(name=name):
                serialized = json.loads(json.dumps(history, allow_nan=False))
                self.assertEqual(audit(history), audit(serialized))

    def test_event_ordinal_gaps_are_rejected(self):
        history = copy.deepcopy(SAMPLES["single_commit"])
        history[1]["seq"] += 1
        with self.assertRaises(OracleError) as caught:
            audit(history)
        self.assertEqual(caught.exception.code, "SCHEMA")

    def test_unknown_event_cannot_hide_an_ack(self):
        history = copy.deepcopy(SAMPLES["single_commit"])
        history.append({"seq": len(history) + 1, "type": "unrecognized_ack", "outcome": "success"})
        with self.assertRaises(OracleError) as caught:
            audit(history)
        self.assertEqual(caught.exception.code, "SCHEMA")

    def test_exact_twenty_linear_extensions(self):
        schedules = list(interleavings())
        self.assertEqual(len(schedules), 20)
        self.assertEqual(len(set(schedules)), 20)
        self.assertEqual(schedules[0], ("left",) * 3 + ("right",) * 3)
        self.assertEqual(schedules[-1], ("right",) * 3 + ("left",) * 3)
        for schedule in schedules:
            self.assertEqual(schedule.count("left"), 3)
            self.assertEqual(schedule.count("right"), 3)

    def test_existing_output_directory_is_never_overwritten(self):
        with tempfile.TemporaryDirectory(prefix="scap-n0-no-overwrite-") as directory:
            marker = Path(directory) / "prior-failure.txt"
            marker.write_text("retain the failed attempt\n")
            result = subprocess.run([sys.executable, str(Path(__file__).with_name("explore.py")),
                                     "--output", directory], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("does not exist", result.stderr)
            self.assertEqual(marker.read_text(), "retain the failed attempt\n")
            self.assertEqual([p.name for p in Path(directory).iterdir()], [marker.name])

    def test_pending_cas_prefix_does_not_prove_cancellation(self):
        history = SAMPLES["absent_inflight_then_lost_response"]
        effect = next(i for i, e in enumerate(history) if e["type"] == "cas_effect")
        prefix = history[:effect]
        result = audit(prefix)
        self.assertTrue(result["passed"])
        self.assertEqual(result["pending_cas"], 1)
        self.assertEqual(result["publications"], 0)
        self.assertEqual(result["sql_success_replies"], 0)
        self.assertEqual(prefix[-1]["outcome"], {"state": "unknown"})

    def test_audit_and_counterexamples_do_not_rewrite_originals(self):
        before = json.dumps(SAMPLES, sort_keys=True)
        for history in SAMPLES.values():
            audit(history)
        list(negative_controls(SAMPLES))
        self.assertEqual(json.dumps(SAMPLES, sort_keys=True), before)


if __name__ == "__main__":
    unittest.main()
