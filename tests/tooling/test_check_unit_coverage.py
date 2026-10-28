"""Adversarial unit fixtures for the coverage gate, not database tests."""

import copy
from contextlib import redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import runpy
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[2] / "scripts/check_unit_coverage.py"
SPEC = importlib.util.spec_from_file_location("check_unit_coverage", SCRIPT)
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class CoverageGateTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.source = "crates/example/src/lib.rs"
        self.write(self.source, "pub fn answer() -> u8 { 42 }\n")
        self.write("crates/example/src/tests.rs", "// unit fixture\n")
        self.write("experiments/probe/probe.rs", "// research fixture\n")
        self.write("target/generated.rs", "// build output\n")
        self.policy = {
            "required_percent": 100,
            "test_tier": "unit",
            "rust_metrics": list(gate.METRICS),
            "rust_test_sources": ["crates/example/src/tests.rs"],
            "research_harness_roots": ["experiments/probe"],
        }
        self.file = {
            "filename": str(self.root / self.source),
            "summary": {metric: {"count": 2, "covered": 2} for metric in gate.METRICS},
        }
        self.report = {"type": "llvm.coverage.json.export", "data": [{"files": [self.file]}]}

    def write(self, path, text):
        destination = self.root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text)

    def inspect(self):
        return gate.inspect(self.report, self.policy, self.root)

    def test_exact_counters_pass_and_nonproduction_files_do_not_inflate_them(self):
        for filename in ["crates/example/src/tests.rs", "/outside/dependency.rs"]:
            self.report["data"][0]["files"].append({"filename": filename, "summary": {}})
        errors, rows = self.inspect()
        self.assertEqual(errors, [])
        self.assertEqual(len(rows), 1)
        self.assertIn("branches=2/2", rows[0])

    def test_relative_report_paths_are_resolved(self):
        self.file["filename"] = self.source
        self.assertEqual(self.inspect()[0], [])

    def test_policy_cannot_lower_threshold_change_tier_or_omit_metrics(self):
        for field, value in [("required_percent", 99), ("test_tier", "integration"), ("rust_metrics", ["lines"])]:
            with self.subTest(field=field):
                policy = copy.deepcopy(self.policy)
                policy[field] = value
                self.assertTrue(gate.inspect(self.report, policy, self.root)[0])

    def test_unknown_production_file_is_not_silently_excluded(self):
        self.write("bin/new.rs", "fn main() {}\n")
        self.write("crates/example/src/target/helper.rs", "pub fn f() {}\n")
        self.assertIn("production source missing", " ".join(self.inspect()[0]))
        self.assertIn("src/target/helper.rs", " ".join(self.inspect()[0]))

    def test_research_or_build_files_compiled_into_unit_target_are_rejected(self):
        for filename in ["experiments/probe/probe.rs", "target/generated.rs"]:
            with self.subTest(filename=filename):
                report = copy.deepcopy(self.report)
                report["data"][0]["files"].append({"filename": filename, "summary": {}})
                self.assertIn("compiled into unit target", " ".join(gate.inspect(report, self.policy, self.root)[0]))

    def test_stale_test_classification_fails(self):
        self.policy["rust_test_sources"].append("missing.rs")
        self.assertIn("stale test-source", " ".join(self.inspect()[0]))

    def test_no_production_sources_is_not_a_pass(self):
        (self.root / self.source).unlink()
        self.assertIn("zero denominator", " ".join(self.inspect()[0]))

    def test_source_cannot_turn_off_coverage(self):
        for annotation in ["#[coverage(off)]", "#[cfg(coverage)]", "#[cfg(not(coverage))]", "#[cfg(not(coverage_nightly))]", "#[cfg_attr(coverage,\n allow(dead_code))]"]:
            self.write(self.source, annotation + "\npub fn f() {}\n")
            self.assertIn("exclusion is forbidden", " ".join(self.inspect()[0]))

    def test_wrong_format_is_rejected(self):
        self.report["type"] = "invented"
        self.assertIn("expected LLVM", " ".join(self.inspect()[0]))

    def test_duplicate_files_cannot_hide_a_failed_counter(self):
        self.report["data"][0]["files"].append(copy.deepcopy(self.file))
        self.assertIn("duplicate production", " ".join(self.inspect()[0]))

    def test_missing_metric_is_rejected(self):
        del self.file["summary"]["branches"]
        self.assertIn("missing metric branches", " ".join(self.inspect()[0]))

    def test_noninteger_counters_are_rejected(self):
        for count, covered in [(2.0, 2), (2, "2"), (True, 1)]:
            self.file["summary"]["lines"] = {"count": count, "covered": covered}
            self.assertIn("non-integer lines", " ".join(self.inspect()[0]))

    def test_negative_or_impossible_counters_are_rejected(self):
        for count, covered in [(-1, 0), (2, -1), (2, 3)]:
            self.file["summary"]["functions"] = {"count": count, "covered": covered}
            self.assertIn("invalid functions", " ".join(self.inspect()[0]))

    def test_zero_executable_denominator_and_unmeasured_branches_fail(self):
        for metric in gate.METRICS:
            self.file["summary"][metric] = {"count": 0, "covered": 0}
        errors = " ".join(self.inspect()[0])
        self.assertIn("empty executable", errors)
        self.assertIn("branch measurement is absent", errors)

    def test_near_100_is_not_rounded_to_a_pass(self):
        self.file["summary"]["lines"] = {"count": 1000000, "covered": 999999, "percent": 100.0}
        self.assertIn("999999/1000000", " ".join(self.inspect()[0]))

    def save(self):
        self.write("contracts/coverage-policy.json", json.dumps(self.policy))
        self.write("report.json", json.dumps(self.report))
        return [str(self.root / "report.json"), "--root", str(self.root)]

    def test_command_success_with_default_and_explicit_policy(self):
        args = self.save()
        for extra in [[], ["--policy", str(self.root / "contracts/coverage-policy.json")]]:
            with redirect_stdout(io.StringIO()) as output:
                self.assertEqual(gate.main(args + extra), 0)
            self.assertIn("PASS", output.getvalue())

    def test_command_rejects_uncovered_code(self):
        self.file["summary"]["regions"]["covered"] = 1
        with redirect_stdout(io.StringIO()) as output:
            self.assertEqual(gate.main(self.save()), 1)
        self.assertIn("FAIL", output.getvalue())

    def test_command_handles_missing_or_malformed_input(self):
        args = self.save()
        for contents in ["not json", "{}", "[]", '{"data":null}']:
            self.write("report.json", contents)
            with redirect_stdout(io.StringIO()) as output:
                self.assertEqual(gate.main(args), 1)
            self.assertIn("Invalid coverage input", output.getvalue())
        (self.root / "report.json").unlink()
        with redirect_stdout(io.StringIO()):
            self.assertEqual(gate.main(args), 1)

    def test_cli_entry_uses_the_same_gate(self):
        with patch.object(sys, "argv", [str(SCRIPT)] + self.save()), redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as result:
                runpy.run_path(str(SCRIPT), run_name="__main__")
        self.assertEqual(result.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
