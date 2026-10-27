#!/usr/bin/env python3
"""Check the design repository. This does not test a database implementation."""

from __future__ import annotations

import json
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
EXCLUDED = {".git", "node_modules", "target", "__pycache__", ".venv"}
TEXT_SUFFIXES = {".md", ".json", ".py", ".yaml", ".yml"}
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
    "docs/engineering/repository-layout.md",
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


def main() -> int:
    failures: list[str] = []
    checked = 0
    local_links = 0
    for required in REQUIRED:
        if not (ROOT / required).is_file():
            failures.append(f"missing required file: {required}")

    for path in sorted(ROOT.rglob("*")):
        relative = path.relative_to(ROOT)
        if any(part in EXCLUDED for part in relative.parts) or not path.is_file():
            continue
        if path.suffix not in TEXT_SUFFIXES and path.name not in TEXT_NAMES:
            continue
        checked += 1
        raw = path.read_bytes()
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            failures.append(f"not UTF-8: {relative}")
            continue
        if raw and not raw.endswith(b"\n"):
            failures.append(f"missing final newline: {relative}")
        if b"\r" in raw:
            failures.append(f"non-LF line endings: {relative}")
        for number, line in enumerate(text.splitlines(), start=1):
            if line.rstrip() != line:
                failures.append(f"trailing whitespace: {relative}:{number}")

        if path.suffix == ".json":
            try:
                json.loads(text)
            except json.JSONDecodeError as error:
                failures.append(f"invalid JSON: {relative}: {error}")

        if path.suffix != ".md":
            continue
        if "genui" in text or "sandbox:" in text or "/workspace/scratch/" in text:
            failures.append(f"chat-only reference in repository Markdown: {relative}")
        if sum(line.lstrip().startswith("```") for line in text.splitlines()) % 2:
            failures.append(f"unbalanced code fence: {relative}")
        for target in markdown_targets(text):
            parsed = urlsplit(target.strip("<>"))
            if parsed.scheme or parsed.netloc or not parsed.path:
                continue
            resolved = (path.parent / unquote(parsed.path)).resolve()
            if not resolved.is_relative_to(ROOT):
                failures.append(f"local link escapes repository: {relative}: {target}")
            elif not resolved.exists():
                failures.append(f"broken local link: {relative}: {target}")
            local_links += 1

    manifest_path = ROOT / "contracts/design-contract.json"
    if manifest_path.is_file():
        try:
            contract = json.loads(manifest_path.read_text(encoding="utf-8"))
            checks = {
                "design-only status": contract["status"] == "design-only",
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
            failures.extend(f"design contract mismatch: {name}" for name, ok in checks.items() if not ok)
        except (json.JSONDecodeError, KeyError, TypeError) as error:
            failures.append(f"invalid design contract structure: {error}")

    if failures:
        print("Repository checks failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1
    print(f"OK: {checked} text files, {local_links} local links, design contract checked.")
    print("Documentation checks only; no database or fault-injection tests were run.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
