#!/usr/bin/env python3
"""Check repository text and design contracts, without running database tests."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
EXCLUDED = {
    ".git", "node_modules", "target", "__pycache__", ".venv",
    "coverage", ".coverage", "vendor", "dist",
}
TEXT_SUFFIXES = {".md", ".json", ".py", ".yaml", ".yml", ".rs", ".toml", ".ts", ".mjs", ".sh"}
TEXT_NAMES = {".gitignore", ".gitattributes", ".editorconfig"}
REQUIRED = (
    "README.md",
    "AGENTS.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "docs/README.md",
    "docs/architecture/object-storage-native-proposal.md",
    "docs/operations/failure-matrix.md",
    "docs/operations/runbooks.md",
    "docs/engineering/validation.md",
    "docs/engineering/roadmap.md",
    "docs/engineering/object-runtime.md",
    "docs/engineering/object-authority-n0.md",
    "docs/engineering/testability-and-coverage.md",
    "docs/engineering/local-validation.md",
    "docs/adr/README.md",
    "docs/adr/0020-object-storage-native-authority.md",
    "docs/adr/0021-object-native-runtime.md",
    "docs/adr/0022-production-capacity.md",
    "experiments/object-capacity/README.md",
    "contracts/design-contract.json",
    ".github/workflows/docs.yml",
    ".github/workflows/quality.yml",
)


def markdown_targets(text: str) -> list[str]:
    """Extract link targets outside fenced code; support inline and definitions."""
    lines = []
    fenced = False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            fenced = not fenced
            continue
        if not fenced:
            lines.append(line)
    prose = "\n".join(lines)
    inline = re.findall(r"\[[^\]\n]*\]\(([^\s)]+)(?:\s+\"[^\"]*\")?\)", prose)
    references = re.findall(r"^\[[^\]]+\]:\s+(\S+)", prose, re.MULTILINE)
    return inline + references


@dataclass(frozen=True)
class CheckResult:
    failures: tuple[str, ...]
    checked: int
    local_links: int


def excluded_name(name: str) -> bool:
    """Ignore generated outputs and dependencies, including parallel profiles."""
    return name in EXCLUDED or name.startswith(".coverage.")


def text_files(root: Path) -> Iterator[Path]:
    """Prune excluded trees before walking rather than traversing build outputs."""
    for directory, directories, filenames in os.walk(root):
        directories[:] = sorted(name for name in directories if not excluded_name(name))
        for filename in sorted(filenames):
            if excluded_name(filename):
                continue
            path = Path(directory) / filename
            if path.is_file() and (path.suffix in TEXT_SUFFIXES or path.name in TEXT_NAMES):
                yield path


def validate_text(relative: Path, raw: bytes) -> tuple[str | None, list[str]]:
    """Validate bytes independently of filesystem traversal and reporting."""
    failures: list[str] = []
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None, [f"not UTF-8: {relative}"]
    if raw and not raw.endswith(b"\n"):
        failures.append(f"missing final newline: {relative}")
    if b"\r" in raw:
        failures.append(f"non-LF line endings: {relative}")
    for number, line in enumerate(text.splitlines(), start=1):
        if line.rstrip() != line:
            failures.append(f"trailing whitespace: {relative}:{number}")
    if relative.suffix == ".json":
        try:
            json.loads(text)
        except json.JSONDecodeError as error:
            failures.append(f"invalid JSON: {relative}: {error}")
    return text, failures


def check_markdown(text: str, path: Path, root: Path) -> tuple[list[str], int]:
    """Check Markdown-only contracts and count local link candidates."""
    failures: list[str] = []
    local_links = 0
    relative = path.relative_to(root)
    if "genui" in text or "sandbox:" in text or "/workspace/scratch/" in text:
        failures.append(f"chat-only reference in repository Markdown: {relative}")
    if sum(line.lstrip().startswith("```") for line in text.splitlines()) % 2:
        failures.append(f"unbalanced code fence: {relative}")
    for target in markdown_targets(text):
        try:
            parsed = urlsplit(target.strip("<>"))
        except ValueError as error:
            failures.append(f"invalid Markdown link: {relative}: {target}: {error}")
            continue
        if parsed.scheme or parsed.netloc or not parsed.path:
            continue
        resolved = (path.parent / unquote(parsed.path)).resolve()
        if not resolved.is_relative_to(root):
            failures.append(f"local link escapes repository: {relative}: {target}")
        elif not resolved.exists():
            failures.append(f"broken local link: {relative}: {target}")
        local_links += 1
    return failures, local_links


def check_contract(text: str) -> list[str]:
    """Validate the design contract without consulting mutable repository state."""
    try:
        contract = json.loads(text)
        checks = {
            "object-native contract version": (
                type(contract["schema_version"]) is int and contract["schema_version"] == 2
            ),
            "object-native prototype status": contract["status"] == "object-native-prototype",
            "implementation remains incomplete": contract["implementation_complete"] is False,
            "S3 HEAD conditional authority": contract["authority"] == "s3-head-conditional-put",
            "no local-write fallback": (
                contract["consistency"]["automatic_local_write_fallback"] is False
            ),
            "no SQL replay after unknown": contract["consistency"]["unknown_sql_replay"] is False,
            "ACK requires durable objects, conditional HEAD, and native publication": (
                contract["consistency"]["ack_requires"] == [
                    "verified-immutable-dependencies",
                    "conditional-head-publication",
                    "native-publication",
                ]
            ),
            "local disk is not authoritative": contract["storage"]["local_disk_authoritative"] is False,
            "immutable objects are create-only": contract["storage"]["immutable_create_only"] is True,
            "physical GC remains unimplemented": contract["storage"]["physical_gc_implemented"] is False,
            "AWS Standard remains unvalidated": contract["targets"]["aws_standard_validated"] is False,
            "production SLO remains unvalidated": contract["targets"]["production_slo_validated"] is False,
            "no PostgreSQL initial scope": (
                contract["scope"]["postgresql_in_initial_scope"] is False
            ),
            "complete gate sequence": contract["gates"] == ["N0", "N1", "N2", "N3", "N4"],
            "100 percent unit coverage": (
                type(contract["quality"]["unit_coverage_percent"]) is int
                and contract["quality"]["unit_coverage_percent"] == 100
            ),
            "integration profiles cannot count as unit": (
                contract["quality"]["integration_profiles_count_as_unit"] is False
            ),
            "no legacy runtime": contract["compatibility"]["legacy_runtime"] is False,
            "no legacy SDK": contract["compatibility"]["legacy_sdk"] is False,
            "no dual backend": contract["compatibility"]["dual_backend"] is False,
            "configurable production capacity profile": contract["profile"] == {
                "head_format": 5,
                "object_format": 2,
                "catalogue_format": 1,
                "page_size": 4096,
                "native_max_pages": 4294967294,
                "default_database_bytes": 10737418240,
                "database_quota_optional": True,
                "chunk_pages": 32,
                "tree_fanout": 256,
                "tree_max_level": 3,
                "head_bytes": 262144,
                "object_bytes": 67174400,
                "result_bytes_default": 52428800,
                "result_bytes_format": 67108864,
                "input_bytes": 67108864,
                "changed_bytes_default": 67108864,
                "cache_bytes_default": 67108864,
                "operation_timeout_seconds": 30,
                "recovery_timeout_seconds": 1800,
                "request_window_default": 4096,
                "request_window_result_bytes_default": 268435456,
                "request_window_format": 65536,
                "closed_windows_retained": 2,
            },
        }
    except (json.JSONDecodeError, KeyError, TypeError) as error:
        return [f"invalid design contract structure: {error}"]
    return [f"design contract mismatch: {name}" for name, ok in checks.items() if not ok]


def check_repository(root: Path) -> CheckResult:
    """Collect repository failures with an explicit root for deterministic fixtures."""
    root = root.resolve()
    failures: list[str] = []
    checked = 0
    local_links = 0
    for required in REQUIRED:
        if not (root / required).is_file():
            failures.append(f"missing required file: {required}")

    for path in text_files(root):
        relative = path.relative_to(root)
        checked += 1
        try:
            raw = path.read_bytes()
        except OSError as error:
            failures.append(f"cannot read file: {relative}: {error}")
            continue
        text, text_failures = validate_text(relative, raw)
        failures.extend(text_failures)
        if text is not None and path.suffix == ".md":
            markdown_failures, link_count = check_markdown(text, path, root)
            failures.extend(markdown_failures)
            local_links += link_count

    manifest_path = root / "contracts/design-contract.json"
    if manifest_path.is_file():
        try:
            failures.extend(check_contract(manifest_path.read_text(encoding="utf-8")))
        except (OSError, UnicodeError) as error:
            failures.append(f"cannot read design contract: {error}")
    return CheckResult(tuple(failures), checked, local_links)


def main(root: Path = ROOT) -> int:
    result = check_repository(root)
    if result.failures:
        print("Repository checks failed:")
        for failure in result.failures:
            print(f"- {failure}")
        return 1
    print(f"OK: {result.checked} text files, {result.local_links} local links, design contract checked.")
    print("Documentation checks only; no database or fault-injection tests were run.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
