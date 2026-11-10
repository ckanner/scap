#!/usr/bin/env python3
"""Independent raw-input, signature, response and object-state auditor."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

from plan import BUCKET, PREFIX, cases
from support import body_value, digest, header, rows, verify_signature

NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"


def exactly(values, reason):
    assert len(values) == 1, reason
    return values[0]


def code(response):
    root = ET.fromstring(body_value(response["body"]))
    assert root.tag in ("Error", NS + "Error")
    names = [child for child in root if child.tag in ("Code", NS + "Code")]
    return exactly(names, "ambiguous error code").text


def deletion(response):
    if any(header(response, name) is not None for name in ("x-amz-version-id", "x-amz-delete-marker")):
        return "Unknown"
    body = body_value(response["body"])
    if len(body) > 32768 or len(body) != response["declared_length"]:
        return "Unknown"
    status = response["status"]
    if status == 204 and not body:
        return "Applied"
    if status == 412:
        return "Conflict"
    if status == 403:
        return "Denied"
    if status == 404:
        try:
            return "Missing" if code(response) == "NoSuchKey" else "Unknown"
        except (ET.ParseError, AssertionError):
            return "Unknown"
    return "Unknown"


def fault_delivery(mode, stage, response, delivery):
    """Check observed fault bytes, independently of the proxy mutator."""
    body = body_value(delivery["body"])
    if mode == "malformed":
        assert delivery["status"] == 200 and body == b"<VersioningConfiguration"
    elif mode == "unknown_versioning":
        assert delivery["status"] == 200
        root = ET.fromstring(body)
        assert root.tag == NS + "VersioningConfiguration" and root.findtext(NS + "Status") == "Future"
    elif mode == "oversize":
        assert body == b" " * 32769 and delivery["status"] == (500 if stage == "delete" else 200)
    elif mode == "short":
        assert delivery["status"] == response["status"] and body == body_value(response["body"])
        assert delivery["declared_length"] == len(body) + 13
    elif mode == "version_header":
        assert delivery["status"] == response["status"] and header(delivery, "x-amz-version-id") == "unexpected-version"
    elif mode == "object_lock":
        assert delivery["status"] == 200
        root = ET.fromstring(body)
        assert root.tag == NS + "ObjectLockConfiguration" and root.findtext(NS + "ObjectLockEnabled") == "Enabled"
    elif mode == "no_such_bucket":
        assert delivery["status"] == 404 and code(delivery) == "NoSuchBucket"
    elif mode == "bad_404":
        assert delivery["status"] == 404 and body == b"not XML"
    elif mode.startswith("status_"):
        assert delivery["status"] == int(mode[-3:]) and not body
    elif mode == "redirect":
        assert delivery["status"] == 307 and not body and header(delivery, "Location") == "/must-not-follow"
    else:
        raise AssertionError("unclassified delivered fault " + mode)
    if mode != "short":
        assert delivery["declared_length"] == len(body)


def audit(history, inputs, outputs, credential, binary_sha256):
    plan = cases()
    names = {item["name"] for item in plan}
    assert all(item.get("case") is None or item["case"] in names for item in history), "unplanned case"
    assert all(left["at_ns"] <= right["at_ns"] for left, right in zip(history, history[1:])), "history clock reordered"
    invocations = [item for item in history if item["event"] == "invoke"]
    returns = [item for item in history if item["event"] == "return"]
    assert [item["case"] for item in invocations] == [item["name"] for item in plan], "planned invocation omitted/reordered"
    assert [item["case"] for item in returns] == [item["name"] for item in plan], "return omitted/reordered"
    assert not any(item["event"] == "fixture_error" for item in history)
    expected_workers = {BUCKET, "scap-gc-versioned", "scap-gc-absent", "scap-gc-race"}
    assert set(inputs) == set(outputs) == expected_workers
    for bucket in expected_workers:
        assert inputs[bucket] == [item["command"] for item in invocations if item["bucket"] == bucket], "raw stdin differs"
        assert outputs[bucket][0] == {"ready": True, "max_delete_batch": 32, "max_gc_response_bytes": 32768}
        assert outputs[bucket][1:] == [item["result"] for item in returns if item["bucket"] == bucket], "raw stdout differs"
    request_count, observations = 0, 0
    previous = None
    for number, spec in enumerate(plan, 1):
        name, kind, bucket = spec["name"], spec["kind"], spec.get("bucket", BUCKET)
        events = [item for item in history if item.get("case") == name]
        def one(event):
            return exactly([item for item in events if item["event"] == event], name + " " + event)
        invoked, returned, closed = one("invoke"), one("return"), one("case_transport_closed")
        command, result = invoked["command"], returned["result"]
        assert invoked["bucket"] == returned["bucket"] == bucket
        assert set(command) == {"id", "prefix", "deadline_ms", "candidates"}
        assert command["id"] == result["id"] == number
        assert command["prefix"] == spec.get("prefix", PREFIX)
        deadline = 0 if kind == "expired" else 750 if spec.get("mode") in ("drop_before", "drop_after", "late_before") else 5000
        assert command["deadline_ms"] == deadline
        assert invoked["at_ns"] < returned["at_ns"] <= closed["at_ns"]
        requests = [item for item in events if item["event"] == "request"]
        assert len(requests) == closed["requests"] == spec["requests"], name + " unexpected request count/retry"
        assert closed["injected"] == (1 if "mode" in spec else 0)
        assert [item["sequence"] for item in requests] == list(range(1, len(requests) + 1))
        assert all(1 <= item["sequence"] <= len(requests) for item in events
                   if item["event"] in ("backend_forward_started", "backend_response", "delivery", "transport_end")), "orphan wire observation"
        request_count += len(requests)
        original = []
        creations = [item for item in events if item["event"] == "fixture_create"]
        expected_count = (33 if kind == "budget" else 2 if kind in ("delete_fault", "race") else 1
                          if kind in ("wrong", "exact", "bad_hash", "bad_etag") else 0)
        assert len(creations) == expected_count
        object_events = [item for item in events if item["event"] == "object_observation"]
        expected_object_count = 2 * len(creations) + (2 if kind == "repeat" else 0)
        assert len(object_events) == expected_object_count
        observations += len(object_events)
        for index, created in enumerate(creations):
            payload = ("GC transport fixture\n" + name + "\n" + str(index) + "\n").encode()
            key = PREFIX + hashlib.sha256(payload).hexdigest()
            assert created["key"] == key and created["bucket"] == bucket and created["status"] == 200
            assert body_value(created["payload"]) == payload
            before = exactly([item for item in object_events if item["key"] == key and item["label"] == "before"], name + " original GET")
            assert before["bucket"] == bucket and before["status"] == 200
            assert body_value(before["body"]) == payload
            tag = header(before, "ETag")
            assert tag and tag == header(created, "ETag"), "candidate not bound to exact original GET"
            original.append({"hash": key[len(PREFIX):], "etag": tag})
        wanted = copy.deepcopy(original)
        if kind == "repeat":
            assert previous is not None
            wanted = [previous]
            before = exactly([item for item in object_events if item["label"] == "before"], "repeat before")
            assert before["key"] == PREFIX + previous["hash"] and before["status"] == 404 and code(before) == "NoSuchKey"
        elif kind == "wrong":
            wanted[0]["etag"] = '"wrong-original-etag"'
        elif kind == "bad_hash":
            wanted.insert(0, {"hash": "HEAD", "etag": wanted[0]["etag"]})
        elif kind == "bad_etag":
            wanted.insert(0, {"hash": wanted[0]["hash"], "etag": "*"})
        assert command["candidates"] == wanted, "unrecorded/rebound candidate"
        if kind == "exact":
            previous = dict(original[0])
        delete_candidates = [item for item in wanted if len(item["hash"]) == 64 and item["etag"] != "*"]
        for request in requests:
            sequence = request["sequence"]
            assert body_value(request["body"]) == b""
            assert request["signature_valid"] is True
            assert verify_signature(request["method"], request["target"], request["headers"], b"",
                                    credential["access"], credential["secret"]), "raw signature invalid"
            assert invoked["at_ns"] <= request["at_ns"]
            if sequence <= 2:
                stage = "versioning" if sequence == 1 else "object-lock"
                assert request["method"] == "GET" and request["target"] == f"/{bucket}?{stage}"
                assert header(request, "If-Match") is None
            else:
                stage = "delete"
                candidate = delete_candidates[sequence - 3]
                assert request["method"] == "DELETE" and request["target"] == f"/{bucket}/{PREFIX}{candidate['hash']}"
                assert header(request, "If-Match") == candidate["etag"], "original ETag changed"
            fault = spec.get("mode") if stage == spec.get("stage") and (stage != "delete" or sequence == 3) else None
            assert request["fault"] == fault
            backend = [item for item in events if item["event"] == "backend_response" and item["sequence"] == sequence]
            forwards = [item for item in events if item["event"] == "backend_forward_started" and item["sequence"] == sequence]
            delivered = [item for item in events if item["event"] == "delivery" and item["sequence"] == sequence]
            ended = [item for item in events if item["event"] == "transport_end" and item["sequence"] == sequence]
            if fault == "drop_before":
                assert not forwards and not backend and not delivered
                end = exactly(ended, "missing drop-before observation")
                assert end["forwarded"] is False and end["response_attempted"] is False
                continue
            forward = exactly(forwards, "missing original backend forward observation")
            response = exactly(backend, "missing actual backend response")
            assert request["at_ns"] <= forward["forward_started_ns"] <= forward["at_ns"] < response["at_ns"]
            if stage == "versioning":
                if kind == "missing_bucket":
                    assert response["status"] == 404 and code(response) == "NoSuchBucket"
                else:
                    assert response["status"] == 200
                    root = ET.fromstring(body_value(response["body"]))
                    assert root.tag == NS + "VersioningConfiguration"
                    if kind in ("enabled", "suspended"):
                        assert root.findtext(NS + "Status") == kind.capitalize()
                    else:
                        assert len(root) == 0
            elif stage == "object-lock":
                assert response["status"] == 404 and code(response) == "ObjectLockConfigurationNotFoundError"
            elif kind == "wrong":
                assert response["status"] == 412
            elif kind != "repeat":
                assert response["status"] == 204
            if fault == "drop_after":
                assert not delivered
                end = exactly(ended, "missing drop-after observation")
                assert end["forwarded"] is True and end["response_attempted"] is False
                assert response["at_ns"] < returned["at_ns"] < end["at_ns"]
                continue
            assert not ended
            delivery = exactly(delivered, "missing delivered response")
            assert response["at_ns"] <= delivery["delivery_attempt_ns"] <= delivery["at_ns"]
            if fault in (None, "late_before", "config_race"):
                assert delivery["status"] == response["status"] and delivery["headers"] == response["headers"]
                assert body_value(delivery["body"]) == body_value(response["body"])
            if fault == "late_before":
                assert returned["at_ns"] < forward["forward_started_ns"], "original DELETE was forwarded before timeout"
            else:
                assert delivery["delivery_attempt_ns"] < returned["at_ns"], "result predates response delivery"
            if fault not in (None, "late_before", "config_race"):
                fault_delivery(fault, stage, response, delivery)
            if stage == "delete" and kind != "delete_fault":
                actual = deletion(delivery)
                entry = result["outcomes"][sequence - 3 + (1 if kind in ("bad_hash", "bad_etag") else 0)]
                assert entry == ({"ok": True, "outcome": actual} if actual in ("Applied", "Missing", "Conflict")
                                 else {"ok": False, "error": actual})
        if "error" in spec:
            assert result == {"id": number, "ok": False, "error": spec["error"]}, name
        else:
            assert set(result) == {"id", "ok", "outcomes"} and result["ok"] is True
            expected = spec.get("outcomes", [] if kind == "probe" else None)
            if expected is not None:
                assert len(result["outcomes"]) == len(expected)
                for entry, outcome in zip(result["outcomes"], expected):
                    assert entry == ({"ok": True, "outcome": outcome} if outcome in ("Applied", "Missing", "Conflict")
                                     else {"ok": False, "error": outcome}), name
            else:
                assert kind == "repeat" and len(result["outcomes"]) == 1
        for index, choice in enumerate(original if kind != "repeat" else [previous]):
            key = PREFIX + choice["hash"]
            after = exactly([item for item in object_events if item["key"] == key and item["label"] == "after"], name + " after GET")
            assert after["bucket"] == bucket
            survives = (kind == "wrong" or (kind == "budget" and index == 32)
                        or (kind in ("delete_fault", "race") and index == 1)
                        or spec.get("mode") == "drop_before")
            if survives:
                before = exactly([item for item in object_events if item["key"] == key and item["label"] == "before"], "survivor before")
                assert after["status"] == 200 and header(after, "ETag") == choice["etag"]
                assert body_value(after["body"]) == body_value(before["body"]), "wrong or unattempted object changed"
            else:
                assert after["status"] == 404 and code(after) == "NoSuchKey", "deleted key remains or bucket disappeared"
        if kind in ("enabled", "suspended", "race"):
            change = one("configuration_change")
            assert change["status"] == 200 and change["value"] == ("Enabled" if kind == "race" else kind.capitalize())
        if kind == "race":
            change = one("configuration_change")
            lock_response = exactly([item for item in events if item["event"] == "backend_response" and item["sequence"] == 2], "race lock")
            lock_delivery = exactly([item for item in events if item["event"] == "delivery" and item["sequence"] == 2], "race release")
            assert lock_response["at_ns"] < change["at_ns"] < lock_delivery["delivery_attempt_ns"]
            versions = one("versions_observation")
            assert versions["status"] == 200
            root = ET.fromstring(body_value(versions["body"]))
            assert root.tag == NS + "ListVersionsResult" and root.findtext(NS + "IsTruncated") == "false"
            records, markers = root.findall(NS + "Version"), root.findall(NS + "DeleteMarker")
            assert len(records) == 2 and len(markers) == 1, "versioned DELETE did not preserve original versions"
            assert markers[0].findtext(NS + "Key") == PREFIX + original[0]["hash"]
            for choice in original:
                version = exactly([item for item in records if item.findtext(NS + "Key") == PREFIX + choice["hash"]], "retained version")
                assert version.findtext(NS + "ETag") == choice["etag"]
    started = [item for item in history if item["event"] == "worker_started"]
    stopped = [item for item in history if item["event"] == "worker_stopped"]
    assert len(started) == len(stopped) == len(expected_workers)
    assert {item["bucket"] for item in started} == {item["bucket"] for item in stopped} == expected_workers
    assert len({(item["pid"], item["spawn_monotonic_ns"]) for item in started}) == len(expected_workers)
    assert all(item["binary_sha256"] == binary_sha256 for item in started)
    for start in started:
        stop = exactly([item for item in stopped if item["bucket"] == start["bucket"]], "owned worker stop")
        assert stop["pid"] == start["pid"] and stop["spawn_monotonic_ns"] == start["spawn_monotonic_ns"]
        assert stop["wait_status"] == 0 and stop["kernel_usage"]["source"] == "kernel_wait4_owned_child"
    start = exactly([item for item in history if item["event"] == "backend_started"], "owned backend start")
    stop = exactly([item for item in history if item["event"] == "backend_stopped"], "owned backend stop")
    assert len(start["children"]) == len(stop["children"]) == 4
    assert {item["role"] for item in start["children"]} == {"master", "volume", "filer", "s3"}
    assert {item["role"] for item in stop["children"]} == {"master", "volume", "filer", "s3"}
    all_starts = started + start["children"]
    assert len({item["pid"] for item in all_starts}) == 8, "simultaneous child PID reused"
    assert len({(item["pid"], item["spawn_monotonic_ns"]) for item in all_starts}) == 8
    assert all(type(item["pid"]) is int and item["pid"] > 0 and item["pid_source"] == "owned_Popen_child"
               for item in all_starts)
    for before, after in zip(start["children"], stop["children"]):
        assert all(before[name] == after[name] for name in ("role", "pid", "spawn_monotonic_ns"))
        assert after["wait_status"] == -9 and after["kernel_usage"]["source"] == "kernel_wait4_owned_child"
    return {"cases": len(plan), "signed_product_requests": request_count,
            "independent_object_gets": observations, "owned_children_reaped": 8}


def controls(history, inputs, outputs, credential, binary_sha256):
    names = []
    for name in ("omit_invocation", "omit_delete", "change_original_etag", "change_signature",
                 "unknown_as_applied", "late_as_early", "unreaped_worker", "missing_raw_input",
                 "duplicate_worker", "duplicate_backend", "config_after_delivery", "result_before_delivery",
                 "declared_fault_not_delivered"):
        altered, changed_inputs, changed_outputs = copy.deepcopy((history, inputs, outputs))
        if name == "omit_invocation":
            altered.remove(next(item for item in altered if item["event"] == "invoke"))
        elif name == "omit_delete":
            altered.remove(next(item for item in altered if item["event"] == "request" and item["method"] == "DELETE"))
        elif name in ("change_original_etag", "change_signature"):
            request = next(item for item in altered if item["event"] == "request" and item["method"] == "DELETE")
            target = "if-match" if name == "change_original_etag" else "authorization"
            key = next(key for key in request["headers"] if key.lower() == target)
            request["headers"][key] = '"rebound"' if target == "if-match" else "invalid-signature"
        elif name == "unknown_as_applied":
            ret = next(item for item in altered if item["event"] == "return" and item["case"] == "delete_drop_after")
            ret["result"]["outcomes"][0] = {"ok": True, "outcome": "Applied"}
            output = next(item for item in changed_outputs[ret["bucket"]] if item.get("id") == ret["result"]["id"])
            output["outcomes"][0] = {"ok": True, "outcome": "Applied"}
        elif name == "late_as_early":
            forward = next(item for item in altered if item["event"] == "backend_forward_started" and item["case"] == "delete_late_before" and item["sequence"] == 3)
            returned = next(item for item in altered if item["event"] == "return" and item["case"] == "delete_late_before")
            forward["forward_started_ns"] = returned["at_ns"] - 1
        elif name == "unreaped_worker":
            next(item for item in altered if item["event"] == "worker_stopped")["wait_status"] = None
        elif name == "missing_raw_input":
            changed_inputs[BUCKET].pop()
        elif name == "duplicate_worker":
            starts = [item for item in altered if item["event"] == "worker_started"]
            for key in ("bucket", "pid", "spawn_monotonic_ns"):
                starts[1][key] = starts[0][key]
        elif name == "duplicate_backend":
            for event in ("backend_started", "backend_stopped"):
                children = next(item for item in altered if item["event"] == event)["children"]
                children[1] = dict(children[0])
        elif name == "config_after_delivery":
            changed = next(item for item in altered if item["event"] == "configuration_change" and item["case"] == "configuration_changes_after_preflight")
            delivery = next(item for item in altered if item["event"] == "delivery" and item["case"] == "configuration_changes_after_preflight" and item["sequence"] == 2)
            delivery["delivery_attempt_ns"] = changed["at_ns"] - 1
        elif name == "result_before_delivery":
            returned = next(item for item in altered if item["event"] == "return" and item["case"] == "matching_original_etag")
            delivery = next(item for item in altered if item["event"] == "delivery" and item["case"] == "matching_original_etag" and item["sequence"] == 3)
            delivery["delivery_attempt_ns"] = returned["at_ns"] + 1
        else:
            delivery = next(item for item in altered if item["event"] == "delivery" and item["case"] == "delete_status_200" and item["sequence"] == 3)
            delivery["status"] = 204
        try:
            audit(altered, changed_inputs, changed_outputs, credential, binary_sha256)
        except (AssertionError, KeyError, ValueError, IndexError):
            names.append(name)
        else:
            raise AssertionError("negative control unexpectedly passed: " + name)
    assert audit(copy.deepcopy(history), copy.deepcopy(inputs), copy.deepcopy(outputs), credential, binary_sha256)
    return names


def audit_directory(directory, private_credential):
    directory = Path(directory)
    report = json.loads((directory / "run.json").read_text())
    assert report["workload_completed"] is True and report["source_and_binary_unchanged"] is True
    assert report["cleanup_errors"] == [] and report["product_gc"] == "OFF" and report["aws"] == "NOT_RUN"
    assert json.loads((directory / "plan.json").read_text()) == cases()
    for name, expected in report["raw_files"].items():
        assert digest(directory / name) == expected, "raw file changed: " + name
    credential = json.loads(Path(private_credential).read_text())
    history = rows(directory / "history.jsonl")
    buckets = (BUCKET, "scap-gc-versioned", "scap-gc-absent", "scap-gc-race")
    inputs = {bucket: rows(directory / (bucket + ".stdin.jsonl")) for bucket in buckets}
    outputs = {bucket: rows(directory / (bucket + ".stdout.jsonl")) for bucket in buckets}
    assert digest(report["binary"]["path"]) == report["binary"]["sha256"]
    result = audit(history, inputs, outputs, credential, report["binary"]["sha256"])
    result.update(status="passed", negative_controls=controls(history, inputs, outputs, credential, report["binary"]["sha256"]),
                  positive_controls=1, original_history_sha256=digest(directory / "history.jsonl"))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--private-credential", type=Path, required=True)
    arguments = parser.parse_args()
    print(json.dumps(audit_directory(arguments.evidence, arguments.private_credential), indent=2, sort_keys=True))
