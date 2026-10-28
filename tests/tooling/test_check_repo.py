"""Unit tests for the repository text and design-contract checker."""

from __future__ import annotations

from contextlib import redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest import mock

from scripts import check_repo


SCRIPT_PATH = Path(check_repo.__file__).resolve()


def valid_contract() -> dict:
    return {
        "status": "design-only",
        "implementation_complete": False,
        "replication": {"voters": 3, "quorum": 2},
        "consistency": {
            "partition_policy": "CP",
            "automatic_local_write_fallback": False,
        },
        "storage": {"worker_suspend_requires_full_s3_archive": False},
        "targets": {"single_az_rpo_validated": False},
        "scope": {"postgresql_in_initial_scope": False},
        "gates": ["G0", "G1", "G2", "G3", "G4"],
    }


class MarkdownTargetTests(unittest.TestCase):
    def test_extracts_inline_titles_and_reference_definitions(self):
        text = (
            '[named](guide.md "A descriptive title")\n'
            "![image](assets/image.png)\n"
            "[reference]: <another.md>\n"
            "[named-ref][reference]\n"
        )
        self.assertEqual(
            check_repo.markdown_targets(text),
            ["guide.md", "assets/image.png", "<another.md>"],
        )

    def test_ignores_fenced_links_and_accepts_links_after_the_fence(self):
        text = (
            "  ```markdown\n[hidden](missing.md)\n[hidden-ref]: missing.md\n"
            "  ```\n[visible](present.md)\n"
        )
        self.assertEqual(check_repo.markdown_targets(text), ["present.md"])
        self.assertEqual(check_repo.markdown_targets(""), [])

    def test_unclosed_fence_does_not_expose_its_contents(self):
        self.assertEqual(check_repo.markdown_targets("```\n[x](hidden.md)\n"), [])


class TextValidationTests(unittest.TestCase):
    def test_accepts_empty_and_utf8_text(self):
        for raw in (b"", b"valid\n", "有效文本\n".encode()):
            with self.subTest(raw=raw):
                text, errors = check_repo.validate_text(Path("note.md"), raw)
                self.assertEqual(text, raw.decode())
                self.assertEqual(errors, [])

    def test_reports_invalid_utf8_without_attempting_other_parsers(self):
        text, errors = check_repo.validate_text(Path("bad.json"), b"\xff\r ")
        self.assertIsNone(text)
        self.assertEqual(errors, ["not UTF-8: bad.json"])

    def test_reports_newline_line_ending_and_whitespace_independently(self):
        text, errors = check_repo.validate_text(Path("bad.rs"), b"first \r\nsecond\t")
        self.assertEqual(text, "first \r\nsecond\t")
        self.assertEqual(
            errors,
            [
                "missing final newline: bad.rs",
                "non-LF line endings: bad.rs",
                "trailing whitespace: bad.rs:1",
                "trailing whitespace: bad.rs:2",
            ],
        )

    def test_validates_json_but_does_not_parse_other_text_as_json(self):
        text, errors = check_repo.validate_text(Path("data.json"), b'{"value": 1}\n')
        self.assertEqual(text, '{"value": 1}\n')
        self.assertEqual(errors, [])
        _, errors = check_repo.validate_text(Path("data.json"), b"{broken}\n")
        self.assertEqual(len(errors), 1)
        self.assertTrue(errors[0].startswith("invalid JSON: data.json:"))
        self.assertEqual(check_repo.validate_text(Path("code.rs"), b"{broken}\n")[1], [])


class ContractTests(unittest.TestCase):
    def test_accepts_only_design_and_g0_statuses_without_claiming_ha(self):
        for status in ("design-only", "g0-prototype"):
            with self.subTest(status=status):
                contract = valid_contract()
                contract["status"] = status
                self.assertEqual(check_repo.check_contract(json.dumps(contract)), [])

    def test_each_contract_invariant_is_enforced(self):
        cases = (
            (("status",), "production", "allowed repository status"),
            (("implementation_complete",), True, "no implemented HA claim"),
            (("implementation_complete",), 0, "no implemented HA claim"),
            (("replication", "voters"), 5, "3-voter, 2-quorum baseline"),
            (("replication", "quorum"), 1, "3-voter, 2-quorum baseline"),
            (("consistency", "partition_policy"), "AP", "CP partition policy"),
            (
                ("consistency", "automatic_local_write_fallback"),
                True,
                "no local-write fallback",
            ),
            (
                ("storage", "worker_suspend_requires_full_s3_archive"),
                True,
                "S3-independent worker suspend",
            ),
            (("targets", "single_az_rpo_validated"), True, "RPO not yet validated"),
            (("scope", "postgresql_in_initial_scope"), True, "no PostgreSQL initial scope"),
            (("gates",), ["G0", "G1", "G2", "G3"], "complete gate sequence"),
        )
        for keys, value, invariant in cases:
            with self.subTest(keys=keys, value=value):
                contract = deepcopy(valid_contract())
                destination = contract
                for key in keys[:-1]:
                    destination = destination[key]
                destination[keys[-1]] = value
                self.assertEqual(
                    check_repo.check_contract(json.dumps(contract)),
                    [f"design contract mismatch: {invariant}"],
                )

    def test_malformed_json_and_missing_or_incompatible_structure_fail(self):
        for text in ("{", "{}", "[]", "null", '{"status": []}'):
            with self.subTest(text=text):
                errors = check_repo.check_contract(text)
                self.assertEqual(len(errors), 1)
                self.assertTrue(errors[0].startswith("invalid design contract structure:"))


class RepositoryFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        for relative in check_repo.REQUIRED:
            self.write(relative, "fixture\n")
        self.write("contracts/design-contract.json", json.dumps(valid_contract()) + "\n")

    def write(self, relative: str, content: str | bytes) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content.encode() if isinstance(content, str) else content)
        return path

    def run_main(self) -> tuple[int, str]:
        output = io.StringIO()
        with redirect_stdout(output):
            status = check_repo.main(self.root)
        return status, output.getvalue()


class RepositoryTests(RepositoryFixture):
    def test_complete_repository_passes_and_reports_counts(self):
        result = check_repo.check_repository(self.root)
        self.assertEqual(result.failures, ())
        self.assertEqual(result.checked, len(check_repo.REQUIRED))
        self.assertEqual(result.local_links, 0)
        status, output = self.run_main()
        self.assertEqual(status, 0)
        self.assertIn(f"OK: {len(check_repo.REQUIRED)} text files, 0 local links", output)
        self.assertIn("no database or fault-injection tests were run", output)

    def test_new_engineering_documents_are_required(self):
        for relative in (
            "docs/engineering/performance-slo.md",
            "docs/engineering/testability-and-coverage.md",
        ):
            with self.subTest(relative=relative):
                self.assertIn(relative, check_repo.REQUIRED)
                (self.root / relative).unlink()
        status, output = self.run_main()
        self.assertEqual(status, 1)
        self.assertIn("Repository checks failed:", output)
        self.assertIn("- missing required file: docs/engineering/performance-slo.md", output)
        self.assertIn("- missing required file: docs/engineering/testability-and-coverage.md", output)
        self.assertNotIn("OK:", output)

    def test_missing_manifest_fails_without_trying_to_parse_it(self):
        (self.root / "contracts/design-contract.json").unlink()
        self.assertEqual(
            check_repo.check_repository(self.root).failures,
            ("missing required file: contracts/design-contract.json",),
        )

    def test_missing_repository_reports_required_files(self):
        result = check_repo.check_repository(self.root / "does-not-exist")
        self.assertEqual(result.checked, 0)
        self.assertEqual(len(result.failures), len(check_repo.REQUIRED))

    def test_rust_toml_and_named_text_files_are_checked(self):
        self.write("crates/example/src/lib.rs", b"fn example() {} ")
        self.write("Cargo.toml", b'[workspace]\r\n')
        self.write(".gitignore", b"target ")
        result = check_repo.check_repository(self.root)
        self.assertEqual(result.checked, len(check_repo.REQUIRED) + 3)
        self.assertIn("missing final newline: crates/example/src/lib.rs", result.failures)
        self.assertIn("trailing whitespace: crates/example/src/lib.rs:1", result.failures)
        self.assertIn("non-LF line endings: Cargo.toml", result.failures)
        self.assertIn("missing final newline: .gitignore", result.failures)

    def test_excludes_outputs_dependencies_and_unrecognized_files(self):
        for directory in (".git", "node_modules", "target", "__pycache__", ".venv", "coverage", "vendor"):
            self.write(f"nested/{directory}/bad.md", b"\xff")
        self.write(".coverage", b"\xff")
        self.write(".coverage.machine.123.json", b"\xff")
        self.write("unknown.bin", b"\xff")
        (self.root / "dangling.md").symlink_to(self.root / "missing-target")
        result = check_repo.check_repository(self.root)
        self.assertEqual(result.failures, ())
        self.assertEqual(result.checked, len(check_repo.REQUIRED))

    def test_invalid_utf8_is_a_reported_failure(self):
        self.write("invalid.md", b"\xff")
        result = check_repo.check_repository(self.root)
        self.assertEqual(result.failures, ("not UTF-8: invalid.md",))

    def test_unreadable_text_file_is_reported(self):
        bad_path = self.write("unreadable.md", "valid\n")
        original = Path.read_bytes

        def read_bytes(path):
            if path == bad_path:
                raise OSError("simulated read failure")
            return original(path)

        with mock.patch.object(Path, "read_bytes", read_bytes):
            result = check_repo.check_repository(self.root)
        self.assertIn("cannot read file: unreadable.md: simulated read failure", result.failures)

    def test_manifest_read_errors_are_reported_without_crashing(self):
        manifest_path = self.root / "contracts/design-contract.json"
        original = Path.read_text

        def read_text(path, *args, **kwargs):
            if path == manifest_path:
                raise OSError("manifest is unreadable")
            return original(path, *args, **kwargs)

        with mock.patch.object(Path, "read_text", read_text):
            result = check_repo.check_repository(self.root)
        self.assertIn("cannot read design contract: manifest is unreadable", result.failures)

    def test_invalid_utf8_manifest_does_not_crash_contract_check(self):
        self.write("contracts/design-contract.json", b"\xff")
        result = check_repo.check_repository(self.root)
        self.assertIn("not UTF-8: contracts/design-contract.json", result.failures)
        self.assertTrue(any(item.startswith("cannot read design contract:") for item in result.failures))

    def test_malformed_manifest_reports_json_and_contract_errors(self):
        self.write("contracts/design-contract.json", "{broken}\n")
        result = check_repo.check_repository(self.root)
        self.assertTrue(any(item.startswith("invalid JSON: contracts/design-contract.json:") for item in result.failures))
        self.assertTrue(any(item.startswith("invalid design contract structure:") for item in result.failures))


class MarkdownValidationTests(RepositoryFixture):
    def test_accepts_external_anchor_and_valid_local_targets(self):
        self.write("docs/page one.md", "# Target\n")
        self.write("docs/source.md", (
            "[https](https://example.test/path)\n"
            "[network](//example.test/path)\n"
            "[anchor](#heading)\n"
            "[query](?view=1)\n"
            "[local](page%20one.md#heading)\n"
            "[reference]: <page%20one.md>\n"
        ))
        result = check_repo.check_repository(self.root)
        self.assertEqual(result.failures, ())
        self.assertEqual(result.local_links, 2)

    def test_reports_missing_and_escaping_links(self):
        path = self.write("docs/source.md", "[missing](missing.md)\n[escape](../../outside.md)\n")
        errors, count = check_repo.check_markdown(path.read_text(), path, self.root)
        self.assertEqual(count, 2)
        self.assertEqual(errors, [
            "broken local link: docs/source.md: missing.md",
            "local link escapes repository: docs/source.md: ../../outside.md",
        ])

    def test_symlink_does_not_allow_a_link_to_escape_the_repository(self):
        with tempfile.TemporaryDirectory() as outside:
            destination = Path(outside) / "outside.md"
            destination.write_text("outside\n")
            (self.root / "shortcut.md").symlink_to(destination)
            path = self.root / "README.md"
            errors, count = check_repo.check_markdown("[shortcut](shortcut.md)\n", path, self.root)
        self.assertEqual(count, 1)
        self.assertEqual(errors, ["local link escapes repository: README.md: shortcut.md"])

    def test_reports_chat_only_markers(self):
        path = self.root / "README.md"
        for marker in ("genui", "sandbox:", "/workspace/scratch/"):
            with self.subTest(marker=marker):
                errors, count = check_repo.check_markdown(marker + "\n", path, self.root)
                self.assertEqual(errors, ["chat-only reference in repository Markdown: README.md"])
                self.assertEqual(count, 0)

    def test_checks_unbalanced_fences_without_parsing_hidden_links(self):
        path = self.root / "README.md"
        errors, count = check_repo.check_markdown("```\n[x](missing.md)\n", path, self.root)
        self.assertEqual(errors, ["unbalanced code fence: README.md"])
        self.assertEqual(count, 0)
        self.assertEqual(check_repo.check_markdown("```\n[x](missing.md)\n```\n", path, self.root), ([], 0))

    def test_malformed_url_is_reported_and_does_not_abort_other_links(self):
        path = self.root / "README.md"
        errors, count = check_repo.check_markdown("[bad](https://[invalid)\n[ok](AGENTS.md)\n", path, self.root)
        self.assertEqual(count, 1)
        self.assertEqual(len(errors), 1)
        self.assertTrue(errors[0].startswith("invalid Markdown link: README.md: https://[invalid:"))


class EntrypointTests(RepositoryFixture):
    def test_real_main_guard_exits_with_the_check_result(self):
        original_resolve = Path.resolve
        synthetic_script = self.root / "scripts/check_repo.py"

        def resolve(path, *args, **kwargs):
            if path == SCRIPT_PATH:
                return synthetic_script
            return original_resolve(path, *args, **kwargs)

        for expected_status in (0, 1):
            with self.subTest(expected_status=expected_status):
                if expected_status:
                    (self.root / "README.md").unlink()
                output = io.StringIO()
                with mock.patch.object(Path, "resolve", resolve), redirect_stdout(output):
                    with self.assertRaises(SystemExit) as raised:
                        runpy.run_path(str(SCRIPT_PATH), run_name="__main__")
                self.assertEqual(raised.exception.code, expected_status)
                self.assertIn("OK:" if expected_status == 0 else "Repository checks failed:", output.getvalue())
