#!/usr/bin/env python3
"""Check the complete SDK source inventory and exact Istanbul unit counters.

The fixed npm unit command owns fresh collection and the executable-line gate.
This extra gate rejects rounded percentages, omitted sources, skipped counters
and source-level coverage exclusions. Integration profiles cannot fill gaps.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1] / "sdk/node"
METRICS = (("s", "statementMap"), ("f", "fnMap"), ("b", "branchMap"))


def inspect(report: dict, root: Path) -> tuple[list[str], list[str]]:
    """Validate raw hit counts for every first-party executable SDK source."""
    root = root.resolve()
    sources = {
        path.resolve() for path in (root / "src").rglob("*")
        if path.is_file() and path.suffix in {".ts", ".mts", ".cts", ".tsx", ".js", ".mjs", ".cjs", ".jsx"}
    }
    errors: list[str] = []
    rows: list[str] = []
    if not sources:
        errors.append("no SDK production sources; zero denominator is not 100%")
    summaries: dict[Path, dict] = {}
    for name, value in report.items():
        path = (root / name).resolve()
        if path not in sources:
            errors.append(f"unexpected SDK coverage source: {name}")
        if path in summaries:
            errors.append(f"duplicate SDK source: {name}")
        if (root / value["path"]).resolve() != path:
            errors.append(f"coverage path mismatch: {name}")
        summaries[path] = value
    total_branches = 0
    for path in sorted(sources):
        name = path.relative_to(root).as_posix()
        if re.search(r"\b(?:c8|istanbul|v8)\s+ignore\b", path.read_text()):
            errors.append(f"source coverage exclusion is forbidden: {name}")
        if path not in summaries:
            errors.append(f"SDK source missing from unit coverage map: {name}")
            continue
        summary = summaries[path]
        counters = []
        for metric, mapping in METRICS:
            counts, locations = summary[metric], summary[mapping]
            if set(counts) != set(locations):
                errors.append(f"counter/map keys differ for {metric}: {name}")
            hits = []
            for key, value in counts.items():
                if metric == "b":
                    if not isinstance(value, list) or not value:
                        errors.append(f"invalid branch vector: {name}:{key}")
                        continue
                    if len(value) != len(locations.get(key, {}).get("locations", [])):
                        errors.append(f"branch arity mismatch: {name}:{key}")
                    hits.extend(value)
                else:
                    hits.append(value)
            if not hits and metric != "b":
                errors.append(f"empty executable denominator for {metric}: {name}")
            if any(type(hit) is not int or hit <= 0 for hit in hits):
                errors.append(f"invalid or uncovered {metric} counter: {name}")
            if metric == "b":
                total_branches += len(hits)
            counters.append(f"{metric}={len(hits)}")
        rows.append(f"{name}: " + ", ".join(counters))
    if total_branches == 0:
        errors.append("branch measurement is absent")
    return errors, rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    try:
        errors, rows = inspect(json.loads(args.report.read_text()), args.root)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        print(f"Invalid SDK coverage input: {error}")
        return 1
    for row in rows:
        print(row)
    if errors:
        for error in errors:
            print(f"FAIL: {error}")
        return 1
    print("PASS: every SDK source and every statement/function/branch counter is covered.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
