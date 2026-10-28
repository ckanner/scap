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
    "coverage", ".coverage", "vendor",
}
TEXT_SUFFIXES = {".md", ".json", ".py", ".yaml", ".yml", ".rs", ".toml"}
TEXT_NAMES = {".gitignore", ".gitattributes", ".editorconfig"}
REQUIRED = (
    "README.md",
    "AGENTS.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "docs/README.md",
    "docs/architecture/requirements.md",
    "docs/architecture/overview.md",
    "docs/architecture/consistency.md",
    "docs/architecture/storage-lifecycle.md",
    "docs/architecture/api-contracts.md",
    "docs/architecture/tenancy-security.md",
    "docs/architecture/technology-stack.md",
    "docs/operations/failure-matrix.md",
    "docs/operations/runbooks.md",
    "docs/engineering/validation.md",
    "docs/engineering/roadmap.md",
    "docs/engineering/capacity-cost.md",
    "docs/engineering/performance-slo.md",
    "docs/engineering/repository-layout.md",
    "docs/engineering/testability-and-coverage.md",
    "docs/research/components.md",
    "docs/adr/README.md",
    "contracts/design-contract.json",
    ".github/workflows/docs.yml",
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
            "allowed repository status": contract["status"] in {"design-only", "g0-prototype"},
            "no implemented HA claim": contract["implementation_complete"] is False,
            "3-voter, 2-quorum baseline": (
                contract["replication"]["voters"] == 3
                and contract["replication"]["quorum"] == 2
            ),
            "CP partition policy": contract["consistency"]["partition_policy"] == "CP",
            "no local-write fallback": (
                contract["consistency"]["automatic_local_write_fallback"] is False
            ),
            "S3-independent worker suspend": (
                contract["storage"]["worker_suspend_requires_full_s3_archive"] is False
            ),
            "RPO not yet validated": contract["targets"]["single_az_rpo_validated"] is False,
            "no PostgreSQL initial scope": (
                contract["scope"]["postgresql_in_initial_scope"] is False
            ),
            "complete gate sequence": set(contract["gates"]) == {"G0", "G1", "G2", "G3", "G4"},
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
