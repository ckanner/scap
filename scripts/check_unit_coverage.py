#!/usr/bin/env python3
"""Fail closed on missing source files, missing counters, or uncovered code.

This consumes a fresh, unit-only LLVM report. It does not generate coverage or
prove the report's provenance; the fixed CI command owns collection and cleanup.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
METRICS = ("lines", "functions", "regions", "branches")
IGNORED_ROOTS = {".git", "target", "node_modules", ".venv", "__pycache__"}


def inspect(report: dict, policy: dict, root: Path) -> tuple[list[str], list[str]]:
    """Return failures and exact per-file counters; never round a near-100 value."""
    errors: list[str] = []
    rows: list[str] = []
    if policy.get("required_percent") != 100 or policy.get("test_tier") != "unit":
        errors.append("policy must require 100% from unit tests")
    if policy.get("rust_metrics") != list(METRICS):
        errors.append("all Rust metrics must be measured")
    tests = set(policy["rust_test_sources"])
    research = tuple(root / path for path in policy["research_harness_roots"])
    sources: set[str] = set()
    for path in root.rglob("*.rs"):
        relative = path.relative_to(root)
        if relative.parts[0] in IGNORED_ROOTS:
            continue
        if relative.as_posix() in tests:
            continue
        if any(path.is_relative_to(directory) for directory in research):
            continue
        sources.add(relative.as_posix())
        if re.search(
            r"coverage\s*\(\s*off\s*\)|\b(?:cfg|cfg_attr)\s*\([^]]*\bcoverage(?:_nightly)?\b",
            path.read_text(),
        ):
            errors.append(f"source coverage exclusion is forbidden: {relative}")
    if not sources:
        errors.append("no production Rust source files; zero denominator is not 100%")
    for test in tests:
        if not (root / test).is_file():
            errors.append(f"stale test-source classification: {test}")

    if report.get("type") != "llvm.coverage.json.export":
        errors.append("expected LLVM coverage JSON export")
    summaries: dict[str, dict] = {}
    for data in report["data"]:
        for file in data["files"]:
            path = Path(file["filename"])
            if not path.is_absolute():
                path = root / path
            path = path.resolve()
            if not path.is_relative_to(root):
                continue
            name = path.relative_to(root).as_posix()
            if name not in sources:
                if name not in tests:
                    errors.append(f"unclassified or research source compiled into unit target: {name}")
                continue
            if name in summaries:
                errors.append(f"duplicate production file in report: {name}")
            summaries[name] = file["summary"]

    total_branches = 0
    for name in sorted(sources):
        if name not in summaries:
            errors.append(f"production source missing from coverage map: {name}")
            continue
        counters = []
        for metric in METRICS:
            counter = summaries[name].get(metric)
            if not isinstance(counter, dict):
                errors.append(f"missing metric {metric}: {name}")
                continue
            count, covered = counter.get("count"), counter.get("covered")
            if type(count) is not int or type(covered) is not int:
                errors.append(f"non-integer {metric} counters: {name}")
                continue
            if count < 0 or covered < 0 or covered > count:
                errors.append(f"invalid {metric} counters: {name}")
                continue
            if metric == "branches":
                total_branches += count
            if count == 0 and metric != "branches":
                errors.append(f"empty executable {metric} denominator: {name}")
            if covered != count:
                errors.append(f"uncovered {metric}: {name}: {covered}/{count}")
            counters.append(f"{metric}={covered}/{count}")
        rows.append(f"{name}: " + ", ".join(counters))
    if total_branches == 0:
        errors.append("branch measurement is absent; do not label 0/0 as 100%")
    return errors, rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--policy", type=Path)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    policy_path = args.policy or root / "contracts/coverage-policy.json"
    try:
        report = json.loads(args.report.read_text())
        policy = json.loads(policy_path.read_text())
        errors, rows = inspect(report, policy, root)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        print(f"Invalid coverage input: {error}")
        return 1
    for row in rows:
        print(row)
    if errors:
        for error in errors:
            print(f"FAIL: {error}")
        return 1
    print("PASS: every production Rust source is present; unit counters are 100%.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
