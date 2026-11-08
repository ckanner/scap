#!/usr/bin/env python3
"""Independent original S3/stream/worker evidence; imports no runner or SDK."""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path

if not __debug__:
    raise RuntimeError("validation requires Python assertions; disable -O/PYTHONOPTIMIZE")

LIMIT = 64 * 1024
LARGE = 4 * 1024 * 1024
STREAM_LIMIT = 16 * 1024 * 1024
CASES = (
    ("get_small_404", "get", 404, LIMIT, False, False),
    ("get_large_404", "get", 404, LARGE, False, False),
    ("get_stream_500", "get", 500, STREAM_LIMIT, True, False),
    ("put_small_412", "put", 412, LIMIT, False, True),
    ("put_large_412", "put", 412, LARGE, False, True),
    ("put_accepted_500", "put", 500, LARGE, False, False),
    ("get_success_large", "get", 200, LARGE, False, True),
    ("put_success_large", "put", 200, LARGE, False, False),
)


def payload(value):
    assert set(value) == {"bytes", "sha256", "base64"}
    raw = base64.b64decode(value["base64"], validate=True)
    assert len(raw) == value["bytes"] and hashlib.sha256(raw).hexdigest() == value["sha256"]
    return raw


def audit(rows, bounded):
    assert [row["sequence"] for row in rows] == list(range(1, len(rows) + 1))
    assert all(left["monotonic_ns"] < right["monotonic_ns"] for left, right in zip(rows, rows[1:]))
    assert not any(row["event"] == "fixture_failure" for row in rows)
    cases = {}
    def one(event, label, serial=None):
        found = [row for row in rows if row["event"] == event and row.get("case") == label and (serial is None or row.get("serial") == serial)]
        assert len(found) == 1, (event, label, serial)
        return found[0]
    for label, operation, status, size, streaming, seed in CASES:
        start, reply = one("call", label), one("reply", label)
        request, response, sent = one("request", label, 1), one("backend_response", label, 1), one("send_finished", label, 1)
        stopped = one("worker_stopped", label)
        assert stopped["wait_status"] == 0 and stopped["kernel_usage"]["source"] == "kernel_wait4_owned_child"
        started = one("worker_started", label)["identity"]
        for key in ("pid", "spawn_monotonic_ns", "pid_source"):
            assert stopped[key] == started[key]
        assert stopped["pid_source"] == "owned_Popen_child" and stopped["kernel_usage"]["available"] is True
        assert stopped["kernel_usage"]["maxrss_bytes"] > 0
        assert request["sigv4_verified"] and request["method"] == operation.upper()
        assert request["path"] == "/scap-test/" + start["command"]["key"]
        incoming = payload(request["body"])
        payload(response["body"])
        if operation == "get":
            assert incoming == b"" and request["if_match"] is None and request["if_none_match"] is None
        else:
            assert incoming == start["command"]["value"].encode() and request["if_none_match"] == "*" and request["if_match"] is None
        assert response["status"] == (412 if operation == "put" and seed else 200 if operation == "put" or seed else 404)
        assert start["monotonic_ns"] < request["monotonic_ns"] < response["monotonic_ns"] < reply["monotonic_ns"]
        value = reply["value"]
        expected = ("Missing" if status == 404 else "Conflict" if status == 412 else "Unknown")
        if status == 200:
            if operation == "put":
                assert value["ok"] is True
            else:
                assert value == {"id": 1, "ok": False, "error": "Limit"}
            assert sent["sent_bytes"] < size and sent["peer_closed"]
        else:
            if bounded and size > LIMIT:
                expected = "Unknown"
            assert value == {"id": 1, "ok": False, "error": expected}, (label, value, expected)
            if size == LIMIT or not bounded and not streaming:
                assert sent["sent_bytes"] == size and sent["eof_sent"], (label, sent)
            elif bounded:
                assert sent["sent_bytes"] < 1024 * 1024 and sent["peer_closed"] and not sent["eof_sent"], (label, sent)
            else:
                assert sent["sent_bytes"] > 1024 * 1024 and sent["peer_closed"]
                assert reply["monotonic_ns"] - start["monotonic_ns"] > 2_500_000_000
        expected_calls = 2 if label == "put_accepted_500" else 1
        actual = [row for row in rows if row["event"] == "request" and row.get("case") == label]
        assert len(actual) == expected_calls, "SDK retried an operation"
        if label == "put_accepted_500":
            assert request["if_none_match"] == "*" and response["status"] == 200 and value["error"] == "Unknown"
            recovered = one("reply", label + "_readback")["value"]
            original = base64.b64decode(request["body"]["base64"], validate=True)
            assert recovered["ok"] is True and bytes(recovered["bytes"]) == original and recovered["etag"] == response["etag"]
            assert actual[1]["method"] == "GET" and actual[1]["path"] == request["path"]
            exact = one("backend_response", label, 2)
            assert exact["status"] == 200 and payload(exact["body"]) == original and exact["etag"] == response["etag"]
        cases[label] = {"result": value, "actual_backend_requests": len(actual), "sent_response_bytes": sent["sent_bytes"],
                        "elapsed_ms": (reply["monotonic_ns"] - start["monotonic_ns"]) / 1_000_000,
                        "kernel_maxrss_bytes": stopped["kernel_usage"]["maxrss_bytes"]}
    starts = [row for row in rows if row["event"] == "backend_started"]
    ends = [row for row in rows if row["event"] == "backend_stopped"]
    assert len(starts) == len(ends) == 1
    assert {row["role"] for row in starts[0]["processes"]} == {"master", "volume", "filer", "s3"}
    identities = set()
    for original in starts[0]["processes"]:
        final = [row for row in ends[0]["processes"] if row["role"] == original["role"]]
        assert len(final) == 1
        for key in ("pid", "spawn_monotonic_ns", "pid_source"):
            assert final[0][key] == original[key]
        assert final[0]["kernel_usage"]["available"] is True and final[0]["kernel_usage"]["source"] == "kernel_wait4_owned_child"
        assert final[0]["wait_status"] == -9
        identities.add((original["pid"], original["spawn_monotonic_ns"]))
    for row in rows:
        if row["event"] == "worker_started":
            identity = (row["identity"]["pid"], row["identity"]["spawn_monotonic_ns"])
            assert identity not in identities
            identities.add(identity)
    assert len(identities) == 12
    return {"status": "passed" if bounded else "original_gap_reproduced", "cases": cases,
            "max_successful_get_bytes": 1024, "auxiliary_response_limit": LIMIT if bounded else "NOT_PRESENT",
            "scope": "storage-port-development-contract", "aws_standard": "NOT_RUN"}


def controls(rows):
    def alter_reply(data, label, **fields):
        value = next(row for row in data if row["event"] == "reply" and row["case"] == label)["value"]
        value.update(fields)
    def consume_all(data):
        row = next(row for row in data if row["event"] == "send_finished" and row["case"] == "get_large_404")
        row.update(sent_bytes=LARGE, eof_sent=True, peer_closed=False)
    def readback_changed(data):
        row = next(row for row in data if row["event"] == "reply" and row["case"] == "put_accepted_500_readback")
        row["value"]["bytes"] = list(b"a different accepted value")
    def wait_missing(data):
        row = next(row for row in data if row["event"] == "worker_stopped")
        row["kernel_usage"]["available"] = False
    reports = []
    for name, mutate in (("unbounded_error_was_consumed", consume_all),
                         ("accepted_put_misreported_local_limit", lambda data: alter_reply(data, "put_accepted_500", error="Limit")),
                         ("accepted_put_misreported_conflict", lambda data: alter_reply(data, "put_accepted_500", error="Conflict")),
                         ("exact_readback_changed", readback_changed), ("missing_kernel_wait4", wait_missing)):
        data = copy.deepcopy(rows)
        mutate(data)
        try:
            audit(data, True)
        except (AssertionError, KeyError, ValueError):
            reports.append({"name": name, "rejected": True})
        else:
            raise AssertionError("actual-history control passed: " + name)
    return reports


def inspect(directory, bounded, negative=False):
    path = Path(directory) / "response-history.jsonl"
    original = path.read_bytes()
    assert original.endswith(b"\n")
    rows = [json.loads(line) for line in original.splitlines()]
    report = audit(rows, bounded)
    if negative:
        assert bounded
        report["negative_controls"] = controls(rows)
    assert path.read_bytes() == original
    report["original_history_sha256"] = hashlib.sha256(original).hexdigest()
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--bounded", action="store_true")
    parser.add_argument("--controls", action="store_true")
    args = parser.parse_args()
    print(json.dumps(inspect(args.evidence, args.bounded, args.controls), indent=2, sort_keys=True))
