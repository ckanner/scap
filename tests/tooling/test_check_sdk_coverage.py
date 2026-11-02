"""Adversarial SDK coverage reports, independent from SDK or integration tests."""

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


SCRIPT = Path(__file__).resolve().parents[2] / "scripts/check_sdk_coverage.py"
SPEC = importlib.util.spec_from_file_location("check_sdk_coverage", SCRIPT)
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class SdkCoverageTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        (self.root / "src").mkdir()
        self.source = self.root / "src/client.ts"
        self.source.write_text("export function f(v: boolean) { return v ? 1 : 0; }\n")
        (self.root / "src/README.md").write_text("not executable\n")
        (self.root / "src/nested").mkdir()
        self.summary = {"path": "src/client.ts", "s": {"0": 1}, "f": {"0": 1}, "b": {"0": [1, 2]}, "statementMap": {"0": {}}, "fnMap": {"0": {}}, "branchMap": {"0": {"locations": [{}, {}]}}}
        self.report = {"src/client.ts": self.summary}

    def errors(self):
        return " ".join(gate.inspect(self.report, self.root)[0])

    def test_complete_raw_counts_pass_for_relative_and_absolute_paths(self):
        errors, rows = gate.inspect(self.report, self.root)
        self.assertEqual(errors, [])
        self.assertEqual(rows, ["src/client.ts: s=1, f=1, b=2"])
        self.report = {str(self.source): self.summary}
        self.summary["path"] = str(self.source)
        self.assertEqual(self.errors(), "")

    def test_every_source_is_required_and_non_sources_cannot_fill_the_denominator(self):
        for suffix in [".ts", ".mts", ".cts", ".tsx", ".js", ".mjs", ".cjs", ".jsx"]:
            with self.subTest(suffix=suffix):
                missing = self.root / f"src/nested/missing{suffix}"
                missing.write_text("export const n = 1;\n")
                self.assertIn("missing from unit coverage", self.errors())
                missing.unlink()
        self.report["test-fixture.ts"] = copy.deepcopy(self.summary)
        self.assertIn("unexpected SDK coverage source", self.errors())
        self.assertIn("path mismatch", self.errors())

    def test_duplicate_path_aliases_do_not_hide_a_report(self):
        self.report[str(self.source)] = copy.deepcopy(self.summary)
        self.assertIn("duplicate SDK source", self.errors())

    def test_empty_source_inventory_and_missing_report_are_not_success(self):
        self.source.unlink()
        self.assertIn("zero denominator", self.errors())
        self.assertIn("branch measurement is absent", self.errors())

    def test_coverage_exclusion_markers_are_rejected(self):
        for marker in ["c8 ignore next", "istanbul ignore file", "v8 ignore start"]:
            with self.subTest(marker=marker):
                self.source.write_text("/* " + marker + " */\n")
                self.assertIn("exclusion is forbidden", self.errors())

    def test_missing_map_keys_and_changed_branch_arity_fail(self):
        del self.summary["statementMap"]["0"]
        self.assertIn("counter/map keys differ", self.errors())
        self.summary["branchMap"]["0"]["locations"] = [{}]
        self.assertIn("branch arity mismatch", self.errors())
        self.summary["branchMap"] = {}
        self.assertIn("branch arity mismatch", self.errors())

    def test_branch_vectors_must_be_nonempty_arrays(self):
        for value in [[], 1, None, "1"]:
            with self.subTest(value=value):
                self.summary["b"]["0"] = value
                self.assertIn("invalid branch vector", self.errors())

    def test_no_rounding_of_missing_or_noninteger_hits(self):
        for metric in ["s", "f", "b"]:
            for value in [0, -1, True, 1.0, "1", None]:
                with self.subTest(metric=metric, value=value):
                    report = copy.deepcopy(self.report)
                    report["src/client.ts"][metric]["0"] = [value, 1] if metric == "b" else value
                    self.assertIn("invalid or uncovered", " ".join(gate.inspect(report, self.root)[0]))

    def test_empty_executable_maps_are_not_one_hundred_percent(self):
        for metric, mapping in gate.METRICS:
            self.summary[metric] = {}
            self.summary[mapping] = {}
        self.assertIn("empty executable denominator", self.errors())
        self.assertIn("branch measurement is absent", self.errors())

    def arguments(self):
        path = self.root / "report.json"
        path.write_text(json.dumps(self.report))
        return [str(path), "--root", str(self.root)]

    def test_cli_pass_failure_and_malformed_reports(self):
        args = self.arguments()
        with redirect_stdout(io.StringIO()) as output:
            self.assertEqual(gate.main(args), 0)
        self.assertIn("PASS", output.getvalue())
        self.summary["s"]["0"] = 0
        with redirect_stdout(io.StringIO()) as output:
            self.assertEqual(gate.main(self.arguments()), 1)
        self.assertIn("FAIL", output.getvalue())
        for content in ["invalid-json", "[]", '{"src/client.ts":{}}']:
            Path(args[0]).write_text(content)
            with redirect_stdout(io.StringIO()) as output:
                self.assertEqual(gate.main(args), 1)
            self.assertIn("Invalid SDK coverage input", output.getvalue())
        Path(args[0]).unlink()
        with redirect_stdout(io.StringIO()):
            self.assertEqual(gate.main(args), 1)

    def test_entrypoint_calls_the_same_gate(self):
        with patch.object(sys, "argv", [str(SCRIPT)] + self.arguments()), redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as result:
                runpy.run_path(str(SCRIPT), run_name="__main__")
        self.assertEqual(result.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
