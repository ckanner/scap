#!/usr/bin/env python3
"""Directed raw-evidence and interval-projection counterexamples, no new actuals."""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path

from oracle import HEAD, one, parse, read, verify_intervals, verify_refresh, verify_rows


def check(evidence):
    evidence = Path(evidence)
    original = [parse((evidence / "plan.json").read_bytes()), read(evidence / "events.jsonl"),
        read(evidence / "history.jsonl"), read(evidence / "http-client-ledger.jsonl"),
        read(evidence / "probe.jsonl"), read(evidence / "original-results.jsonl"),
        read(evidence / "original-lookups.jsonl")]
    positive = verify_rows(*original)
    results = []

    def rejected(name, mutation, message):
        values = copy.deepcopy(original)
        mutation(values)
        try:
            verify_rows(*values)
        except ValueError as error:
            assert message in str(error), (name, "wrong rejection", str(error))
            results.append({"name": name, "tier": "raw", "rejected_by": str(error)})
        else:
            raise AssertionError("counterexample accepted: " + name)

    rejected("changed_resource_profile", lambda v: v[0]["profile"].update(workers=4), "frozen plan changed")
    rejected("missing_original_response", lambda v: v[1].remove(one(v[1], "http_response", command="first")),
             "missing/duplicate http_response")
    rejected("duplicate_sdk_post", lambda v: v[3].append(copy.deepcopy(one(v[3], "http_request", phase="first"))),
             "missing exact SDK request")

    def corrupt_response(values):
        for event in ("http_response", "http_delivered"):
            one(values[1], event, command="first")["response_body"] = "e30="
    rejected("changed_original_response_bytes", corrupt_response, "original HTTP bytes changed")

    def wrong_signer(values):
        serial = next(row["request_serial"] for row in values[2] if row["event"] == "object_request")
        for row in values[2]:
            if row.get("request_serial") == serial:
                row["signing"]["access_key_sha256"] = "0" * 64
    rejected("unbound_s3_principal", wrong_signer, "S3 request signing principal changed")
    rejected("replaced_original_lookup", lambda v: v[6][0].update(raw="AA=="), "lookup replayed non-deterministic SQL")

    def alias_image(values):
        images = one(values[1], "private_images")["images"]
        assert len(images) >= 2
        images[1].update(device=images[0]["device"], inode=images[0]["inode"])
    rejected("aliased_private_native_file", alias_image, "private reader images alias")
    rejected("unobserved_clean_exit", lambda v: one(v[1], "service_stopped").update(status=1),
             "owned worker cleanup not observed")

    # Full original byte/identity validation above precedes these narrow causal
    # projections. Mutating timing in a projection cannot be called a new S3
    # execution or a full raw-history certificate.
    events, history = original[1:3]
    requests = [row for row in events if row["event"] == "http_request"]
    calls = {row["http_serial"]: {"request": row,
        "response": one(events, "http_response", http_serial=row["http_serial"])} for row in requests}
    by_command = {}
    for row in requests:
        by_command.setdefault(row["command"], []).append(row["http_serial"])
    projection = [events, history, calls, by_command]
    verify_intervals(*projection)

    def reject_interval(name, mutation, message, verifier=verify_intervals):
        values = copy.deepcopy(projection)
        mutation(values)
        try:
            verifier(*values)
        except ValueError as error:
            assert message in str(error), (name, "wrong rejection", str(error))
            results.append({"name": name, "tier": "interval_projection", "rejected_by": str(error)})
        else:
            raise AssertionError("interval counterexample accepted: " + name)

    reject_interval("serial_reads", lambda v: one(v[0], "fault_released", id="first").update(
        monotonic_ns=one(v[0], "fault_entered", id="second")["monotonic_ns"] - 1), "did not overlap")

    def another_head(values):
        gate = one(values[0], "fault_entered", id="first")
        one(values[1], "object_request", request_serial=gate["request_serial"])["path"] += "-other"
    reject_interval("unrelated_get_overlap", another_head, "held another operation")

    def reused_get(values):
        first = one(values[0], "fault_entered", id="first")
        second = one(values[0], "fault_entered", id="second")
        request = one(values[1], "object_request", request_serial=second["request_serial"])
        first.update(request_serial=second["request_serial"],
            monotonic_ns=(request["monotonic_ns"] + second["monotonic_ns"]) // 2)
    reject_interval("one_get_as_two_readers", reused_get, "one GET counted twice")
    for name in ("other", "write", "control"):
        def delayed(values, command=name):
            values[2][values[3][command][0]]["response"]["monotonic_ns"] = one(values[0], "fault_released", id="first")["monotonic_ns"] + 1
        reject_interval("blocked_" + name, delayed, "blocked another tenant")
    reject_interval("active_quota_bypassed", lambda v: v[2][v[3]["queued"][0]]["response"].update(
        monotonic_ns=one(v[0], "fault_released", id="first")["monotonic_ns"] - 1), "escaped active quota")
    verify_refresh(*projection)
    for name in ("warm", "write_again", "refresh"):
        def escaped(values, command=name):
            values[2][values[3][command][0]]["response"]["monotonic_ns"] = one(values[0], "fault_released", id="park_first")["monotonic_ns"] + 1
        reject_interval("unbound_refresh_worker_" + name, escaped, "escaped the single remaining reader", verify_refresh)

    def cold_worker(values):
        call = values[2][values[3]["refresh"][0]]
        found = [row for row in values[1] if row["event"] == "object_request" and row["path"] == HEAD
                 and call["request"]["monotonic_ns"] < row["monotonic_ns"] < call["response"]["monotonic_ns"]]
        assert len(found) == 3
        for row in found[1:]:
            values[1].remove(row)
    reject_interval("cold_reader_substituted_for_stale_image", cold_worker, "exactly one pre-SQL refresh", verify_refresh)
    assert verify_rows(*original) == positive, "original positive evidence changed"
    return {"status": "passed", "negative_controls": len(results), "positive_controls": 1, "controls": results}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path)
    print(json.dumps(check(parser.parse_args().evidence), sort_keys=True))
