"""Run the entire declared finite matrix, retaining every raw history."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import platform
import signal
import subprocess
import sys
import time
import traceback

from cases import cases
from codec_budget import report as codec_report
from counterexamples import negatives
from oracle import audit, canonical, Violation


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PRODUCT_BASE = "e3bdf7b6a3e5ee2bf9114e8e571f0b8a64e53492"
MAX_SECONDS = 120
MAX_BYTES = 256 * 1024 * 1024
POSITIVE_COUNT = 804
NEGATIVE_COUNT = 47
FAMILIES = {"capture": 80, "release_sql": 80, "bind_abort": 80, "provision_abort": 80,
            "two_completion": 80, "different_creator_name": 80, "migration": 126,
            "late_completion": 70, "copied_abort": 40, "restart": 32, "boundary": 41, "refinement": 15}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def source():
    files = [*sorted(HERE.glob("*.py")), HERE / "README.md", HERE / "PLAN.md",
             ROOT / "docs/architecture/retained-snapshot-restore.md", ROOT / "AGENTS.md"]
    rows = {str(path.relative_to(ROOT)): digest(path.read_bytes()) for path in files}
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
                          text=True, check=True, timeout=10).stdout.strip()
    status = subprocess.run(["git", "status", "--porcelain", "--", *rows], cwd=ROOT,
                            capture_output=True, text=True, check=True, timeout=10).stdout
    return {"git_head": head, "declared_inputs_status": status, "files": rows,
            "sha256": digest(canonical(rows).encode())}


class Output:
    def __init__(self, directory):
        self.directory = directory
        directory.mkdir(parents=True, exist_ok=False)
        self.bytes = 0

    def save(self, name, value):
        data = (canonical(value) + "\n").encode()
        if self.bytes + len(data) > MAX_BYTES:
            raise RuntimeError("fixed evidence byte limit")
        path = self.directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(data)
        self.bytes += len(data)
        return {"path": name, "sha256": digest(data), "bytes": len(data)}


def inventory(positive, negative):
    assert len(positive) == POSITIVE_COUNT
    assert len(negative) == NEGATIVE_COUNT
    assert len({case.name for case in positive}) == POSITIVE_COUNT
    assert len({case.name for case in negative}) == NEGATIVE_COUNT
    assert dict(Counter(case.family for case in positive)) == FAMILIES
    return {"positive": [{"name": case.name, "family": case.family} for case in positive],
            "negative": [{"name": case.name, "expected_rule": case.rule, "category": case.category} for case in negative],
            "families": FAMILIES}


def run(directory, diagnostic=False):
    output = Output(directory)
    started = time.monotonic()
    result = {"status": "FAILED", "diagnostic": diagnostic, "product_base": PRODUCT_BASE,
              "product_implementation": "NOT_RUN", "native_http_s3": "NOT_RUN", "aws": "NOT_RUN",
              "limits": {"seconds": MAX_SECONDS, "bytes": MAX_BYTES, "processes": 1}}
    records, totals, states, edges = [], Counter(), set(), set()
    active_case, active_history = None, None

    def expired(_signum, _frame):
        raise TimeoutError("fixed exploration deadline")

    previous = signal.signal(signal.SIGALRM, expired)
    signal.alarm(MAX_SECONDS)
    try:
        before = source()
        if not diagnostic:
            assert not before["declared_inputs_status"], "formal mode requires committed declared inputs"
        executable = Path(sys.executable).resolve()
        output.save("inputs.json", {"source": before, "python": platform.python_version(),
                                   "python_executable_sha256": digest(executable.read_bytes()),
                                   "product_base": PRODUCT_BASE, "diagnostic": diagnostic})
        positive, negative = cases(), negatives()
        output.save("inventory.json", inventory(positive, negative))
        output.save("codec-budget.json", codec_report())
        designated = None
        for case in positive:
            active_case, active_history = case.name, None
            model = case.build()
            active_history = model.trace(case.name)
            location = output.save("positive/" + case.name + ".json", active_history)
            observed = audit(active_history)
            totals.update(observed)
            records.append({"kind": "positive", "name": case.name, "family": case.family,
                            **location, "audit": observed})
            candidates = {event["id"]: event for event in active_history["events"] if event["event"] == "candidate"}
            prior = {}
            for event in active_history["events"]:
                if event["event"] == "initial":
                    for object_key, item in event["objects"].items():
                        if object_key.startswith("head/"):
                            prior[object_key] = digest(canonical(item["body"]).encode())
                            states.add(prior[object_key])
                elif event["event"] == "put_effect" and event["result"]["status"] == "applied":
                    call = candidates[event["id"]]
                    if call["key"].startswith("head/"):
                        state = digest(canonical(call["body"]).encode())
                        states.add(state)
                        if call["key"] in prior:
                            edges.add((prior[call["key"]], call["kind"], state))
                        prior[call["key"]] = state
            if case.name == "deleted_retains_until_explicit_release":
                designated = active_history, observed
        assert designated is not None
        controls = []
        original, original_result = designated
        roundtrip = json.loads(canonical(original))
        roundtrip_location = output.save("positive-controls/json-roundtrip.json", roundtrip)
        controls.append({"name": "json-roundtrip", "passed": audit(roundtrip) == original_result, **roundtrip_location})
        roundtrip["summary"] = {"status": "invented", "data": "wrong", "known_ack": True}
        summary_location = output.save("positive-controls/summary-ignored.json", roundtrip)
        controls.append({"name": "summary-ignored", "passed": audit(roundtrip) == original_result, **summary_location})
        del roundtrip["summary"]
        absent_location = output.save("positive-controls/no-summary.json", roundtrip)
        controls.append({"name": "no-summary", "passed": audit(roundtrip) == original_result, **absent_location})
        assert all(control["passed"] for control in controls)
        for case in negative:
            active_case, active_history = case.name, None
            active_history = case.build()
            location = output.save("negative/" + case.name + ".json", active_history)
            try:
                audit(active_history)
            except Violation as error:
                rejection = {"rule": error.rule, "event": error.index, "message": str(error)}
                assert error.rule == case.rule, (case.name, case.rule, rejection)
            else:
                raise AssertionError("negative accepted: " + case.name)
            records.append({"kind": "negative", "name": case.name, "category": case.category,
                            "expected_rule": case.rule, "rejection": rejection, **location})
        after = source()
        output.save("source-after.json", after)
        assert after == before, "declared input source changed during run"
        result.update(status="PASS", positives=POSITIVE_COUNT, negatives=NEGATIVE_COUNT,
                      positive_controls=controls, source=before, totals=dict(totals),
                      distinct_head_states=len(states), distinct_head_edges=len(edges),
                      records=records)
    except Exception as error:
        result.update(error=repr(error), traceback=traceback.format_exc(), active_case=active_case, records=records)
        if active_history is not None:
            result["failed_history"] = output.save("failed-history.json", active_history)
        try:
            result["source_after_failure"] = source()
        except Exception as source_error:
            result["source_after_failure_error"] = repr(source_error)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
        result.update(seconds=time.monotonic() - started, evidence_bytes_before_manifest=output.bytes)
        output.save("manifest.json", result)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--diagnostic", action="store_true")
    args = parser.parse_args()
    result = run(args.out.resolve(), args.diagnostic)
    print(json.dumps({key: result.get(key) for key in
                      ("status", "diagnostic", "positives", "negatives", "seconds", "error", "active_case")}, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
