#!/usr/bin/env python3
"""Independent original-wire/process/build audit for the HEAD5 index contract."""
from __future__ import annotations

import argparse
from bisect import bisect_right
from collections import Counter, defaultdict
import copy
import json
from pathlib import Path
import re
import signal
from urllib.parse import urlparse

from audit_wire import b64, committed, equal, fingerprint, head5_publication, parse, require, result
from service_oracle import build_receipt, exchanges, exited, identity, only, rows, stamp, value_of
from segmented_spec import BACKEND_VERSION, CALLS, DEADLINES, LAST_ID, PHASES, PLAN, SCOPE
from segmented_tree_audit import HEAD, PREFIX, SCOPE as NATIVE_SCOPE, Trees, digest, envelope, head, sha

FILES = ("segmented-plan.json", "segmented-tools.json", "history.jsonl", "process-ledger.jsonl",
         "http-client-ledger.jsonl", "segmented-calls.jsonl", "segmented-inputs.jsonl", "segmented-acks.jsonl",
         "segmented-lookups.jsonl", "segmented-phases.jsonl")
QUERY = [{"sql": "SELECT id,payload,nonce FROM witness ORDER BY id", "params": []}]


def numbered(ledger):
    require([row["sequence"] for row in ledger] == list(range(1, len(ledger) + 1)), "missing original trace row")
    require(all(type(row.get("schema")) is int and row["schema"] == 1 for row in ledger), "trace schema changed")
    require(all(stamp(left) < stamp(right) for left, right in zip(ledger, ledger[1:])), "trace clock order")


def labeled(directory, calls):
    ledger = rows(directory, "segmented-calls.jsonl"); observed = {}
    require(len(ledger) == 2 * PLAN["http_invocations"] and len(calls) == PLAN["http_invocations"], "HTTP input denominator changed")
    for phase in PHASES:
        starts = [r for r in ledger if r["phase"] == phase and r["event"] == "call_started"]
        ends = [r for r in ledger if r["phase"] == phase and r["event"] == "call_finished"]
        equal([(r["label"], r["operation"]) for r in starts], CALLS[phase], "planned call input inventory")
        equal([r["label"] for r in ends], [r[0] for r in CALLS[phase]], "planned terminal inventory")
        previous = 0
        for begin, end in zip(starts, ends):
            label = begin["label"]; call = calls[end["call_id"]]
            require(label not in observed and call["request"]["phase"] == phase and call["request"]["client"] == "index", "call belongs to another original client")
            equal(call["body"]["scope"], SCOPE, "HTTP scope changed")
            require(call["body"]["operation"] == begin["operation"], "HTTP operation changed")
            require(previous < stamp(begin) < stamp(call["request"]) < stamp(call["response"]) < stamp(end), "original call time order")
            require(stamp(call["response"]) - stamp(call["request"]) <= DEADLINES["client_request_ms"] * 1_000_000,
                    "original HTTP deadline exceeded")
            expected = "ok"
            if label == "conflict": expected = "REQUEST_CONFLICT"
            if phase in PLAN["damage_cases"] and begin["operation"] in ("open", "query"):
                expected = "MISSING" if phase == "missing" else "CORRUPT"
            require(end["outcome"] == expected, "planned outcome changed")
            if expected == "ok": value_of(call)
            else:
                require(call["response"]["status"] == 409 and call["value"] == {"ok": False, "error": {"code": expected, "message": expected}},
                        "typed HTTP rejection changed")
            observed[label] = call; previous = stamp(end)
    require({r["call_id"] for r in ledger if r["event"] == "call_finished"} == set(calls), "unaccounted HTTP retry")
    phase_rows = rows(directory, "segmented-phases.jsonl")
    require(Counter(r["phase"] for r in phase_rows) == Counter(PHASES), "phase denominator changed")
    for row in phase_rows:
        require(row["calls"] == row["sdk_http_attempts"] == len(CALLS[row["phase"]]), "SDK omitted/retried a call")
    return observed


def sql(directory, observed):
    inputs = rows(directory, "segmented-inputs.jsonl"); acks = rows(directory, "segmented-acks.jsonl")
    require(len(inputs) == PLAN["tracked_inputs"] and Counter(r["name"] for r in acks) == Counter(("first", "last")), "input/original ACK denominator changed")
    by_label = {r["label"]: r for r in inputs}; expected = {}; originals = {}
    require(len(by_label) == len(inputs), "duplicate original input")
    expected_labels = {"execute_first", "execute_last", "unknown", "conflict"} | {f"cancel_{i}" for i in range(2, LAST_ID)}
    require(set(by_label) == expected_labels, "tracked input labels changed")
    for label, source in by_label.items():
        saved = parse(source["request"])
        require(set(saved) == {"scope", "request", "statements"}, "original saved input fields")
        equal(saved["scope"], SCOPE, "original input scope")
        statement_list = saved["statements"]
        if label.startswith("cancel_"):
            identifier = int(label.split("_")[1])
            equal(statement_list, [{"sql": "INSERT INTO witness VALUES(?1,x'00',-1)", "params": [{"type": "integer", "value": str(identifier)}]}], "cancel input changed")
        elif label in ("unknown", "conflict"):
            identifier = 9000 if label == "unknown" else 1
            equal(statement_list, [{"sql": "SELECT 9000" if label == "unknown" else "SELECT 999", "params": []}], "probe input changed")
        else:
            identifier = 1 if label == "execute_first" else LAST_ID
            require(len(statement_list) == (2 if identifier == 1 else 1), "original SQL statement count")
            if identifier == 1:
                equal(statement_list[0], {"sql": "CREATE TABLE witness(id INTEGER PRIMARY KEY,payload BLOB,nonce INTEGER)", "params": []}, "original schema changed")
            insert = statement_list[-1]; payload = b64(insert["params"][1]["base64"])
            require(len(payload) == PLAN["original_blob_bytes"], "original BLOB length changed")
            equal(insert, {"sql": "INSERT INTO witness VALUES(?1,?2,random()) RETURNING id,payload,nonce",
                           "params": [{"type": "integer", "value": "1" if identifier == 1 else "2"},
                                      {"type": "blob", "base64": insert["params"][1]["base64"]}]}, "original INSERT changed")
        request = {"epoch": "1", "id": str(identifier), "principal": "11", "fingerprint": fingerprint(statement_list)}
        equal(saved["request"], request, "full request identity/fingerprint changed")
        call = observed[label]; operation = call["body"]["operation"]
        wire = {"version": 1, "scope": SCOPE, "operation": operation, "request": request}
        if operation == "execute": wire["statements"] = statement_list
        equal(call["body"], wire, "HTTP input differs from durable original input")
        require(stamp(source) < stamp(call["request"]), "original input was not saved before invocation")
        native = {**request, "epoch": 1, "id": identifier, "principal": 11}
        if label.startswith("cancel_"):
            value = value_of(call)
            equal(value, {"state": "cancelled", "transition": {"revision": str(identifier + 2), "nonce": str(identifier)}}, "original cancellation changed")
            expected[identifier] = {"request": native, "outcome": {"state": "cancelled", "transition": {"revision": identifier + 2, "nonce": identifier}}, "result_bytes": 0}
        elif operation == "execute":
            name = "first" if identifier == 1 else "last"; ack = only([r for r in acks if r["name"] == name], "original ACK inventory")
            raw, decoded = committed(value_of(call))
            require(ack["call_id"] == call["request"]["call_id"] and ack["request"] == source["request"] and
                    stamp(call["response"]) < stamp(ack) and b64(ack["raw"]) == raw and ack["raw_sha256"] == sha(raw), "ACK provenance/bytes changed")
            equal(ack["receipt"], value_of(call)["receipt"], "original ACK receipt changed")
            receipt = ack["receipt"]
            equal(receipt["scope"], SCOPE, "receipt scope"); equal(receipt["request"], request, "receipt identity")
            require(receipt["sequence"] == ("1" if identifier == 1 else "2") and receipt["transition"] == {"revision": str(identifier + 2), "nonce": str(identifier)}, "original receipt transition")
            require(len(decoded) == len(statement_list) and decoded[-1]["columns"] == ["id", "payload", "nonce"] and len(decoded[-1]["rows"]) == 1,
                    "original native result shape")
            row = decoded[-1]["rows"][0]
            require(row[:2] == [1 if identifier == 1 else 2, payload] and type(row[2]) is int and -(2**63) <= row[2] < 2**63,
                    "original SQLite random/BLOB result changed")
            if identifier == 1:
                require(decoded[0]["columns"] == [] and decoded[0]["rows"] == [], "CREATE produced unexpected result")
            expected[identifier] = {"request": native, "outcome": {"state": "committed", "result": receipt["result_hash"]}, "result_bytes": len(raw)}
            originals[name] = {"ack": ack, "input": saved, "raw": raw, "row": row, "value": value_of(call)}
    require(value_of(observed["unknown"]) == {"state": "unknown"}, "unknown ID changed resolution")
    for operation, nonce, revision, active in (("create", 701, 1, False), ("activate", 702, 2, True)):
        wire = {"version": 1, "scope": SCOPE, "operation": operation, "nonce": str(nonce)}
        if operation == "activate": wire["expected_revision"] = "1"
        equal(observed[operation]["body"], wire, "administrative input changed")
        value = value_of(observed[operation])
        require(value["revision"] == str(revision) and value["sequence"] == "0" and value["active"] is active and value["owner_instance"] == str(PLAN["owner_instance"]), "administrative result changed")
    lookup_rows = rows(directory, "segmented-lookups.jsonl")
    expected_lookup_labels = {f"{phase}_{name}" for phase in ("warm", "cold", "repaired") for name in ("first", "last")} | {phase + "_first" for phase in PLAN["damage_cases"]}
    require(Counter(r["label"] for r in lookup_rows) == Counter(expected_lookup_labels), "original lookup denominator")
    for label, call in observed.items():
        operation = call["body"]["operation"]
        if label in expected_lookup_labels:
            original = originals["first" if label.endswith("first") else "last"]
            equal(call["body"], {"version": 1, "scope": SCOPE, "operation": "lookup", "request": original["input"]["request"]}, "original lookup identity")
            equal(value_of(call), original["value"], "lookup regenerated original result")
            row = only([r for r in lookup_rows if r["label"] == label], "lookup saved witness")
            require(row["call_id"] == call["request"]["call_id"] and row["original_call_id"] == original["ack"]["call_id"] and
                    b64(row["raw"]) == original["raw"] and stamp(call["response"]) < stamp(row), "lookup provenance changed")
            equal(row["receipt"], original["ack"]["receipt"], "lookup receipt changed")
        elif label.endswith("_cancelled"):
            saved = parse(by_label["cancel_2"]["request"])
            equal(call["body"], {"version": 1, "scope": SCOPE, "operation": "lookup", "request": saved["request"]}, "cancelled lookup identity")
            equal(value_of(call), value_of(observed["cancel_2"]), "cancel resolution changed after recovery")
        elif operation == "query":
            equal(call["body"], {"version": 1, "scope": SCOPE, "operation": "query", "statements": QUERY}, "query input changed")
            if call["value"]["ok"]:
                decoded = result(b64(value_of(call)["result"]))
                require(len(decoded) == 1 and decoded[0]["columns"] == ["id", "payload", "nonce"] and
                        decoded[0]["rows"] == [originals["first"]["row"], originals["last"]["row"]] and decoded[0]["affected_rows"] == 0,
                        "query differs from original two results / cancelled SQL ran")
        elif operation in ("open", "status"):
            equal(call["body"], {"version": 1, "scope": SCOPE, "operation": operation}, "Open/status input changed")
            if call["value"]["ok"]:
                value = value_of(call)
                require(value["revision"] == str(LAST_ID + 2) and value["sequence"] == "2" and value["active"] is True and
                        value["owner_instance"] == str(PLAN["owner_instance"]), "current authority response changed")
                equal(value["scope"], SCOPE, "current authority scope")
    return expected, originals


def body_file(directory, digest_value, length):
    digest(digest_value)
    raw = (directory / "s3-bodies" / digest_value).read_bytes()
    require(type(length) is int and len(raw) == length and sha(raw) == digest_value, "raw S3 body hash/length changed")
    return raw


def original_network(directory, history, observed, facts, configuration):
    numbered(history)
    require(all(r["event"] in {"phase_started", "object_request", "object_forwarded", "object_response", "object_response_delivered"} for r in history), "failed/unplanned S3 event")
    expected_phases = ["seed", "warm", "inspection", "cold"]
    for damage in PLAN["damage_cases"]: expected_phases += ["damage_" + damage, damage, "repair_" + damage]
    expected_phases += ["repaired"]
    equal([r["phase"] for r in history if r["event"] == "phase_started"], expected_phases, "S3 phase order")
    wire = defaultdict(dict)
    for row in history:
        if row["event"] == "phase_started": continue
        serial = row["request_serial"]; event = row["event"]
        require(type(serial) is int and serial > 0 and event not in wire[serial], "duplicate S3 event")
        wire[serial][event] = row
    require(sorted(wire) == list(range(1, len(wire) + 1)), "missing S3 request serial")
    fixture_inputs = [r for r in facts if r["event"] == "fixture_request"]
    fixture_outputs = {r["ordinal"]: r for r in facts if r["event"] == "fixture_response"}
    require([r["ordinal"] for r in fixture_inputs] == list(range(1, len(fixture_inputs) + 1)) and len(fixture_outputs) == len(fixture_inputs), "fixture invocation denominator")
    backend = only([r for r in facts if r["event"] == "backend_started"], "backend signing identity")
    call_intervals = {}
    for phase in PHASES:
        intervals = sorted((stamp(call["request"]), stamp(call["response"]), label)
                           for label, call in observed.items() if call["request"]["phase"] == phase)
        call_intervals[phase] = ([entry[0] for entry in intervals], intervals)
    by_call, fixture, all_objects, state = defaultdict(list), {}, {}, {}
    common = ("request_serial", "phase", "method", "path", "request_bytes", "request_sha256", "if_match", "if_none_match", "signing")
    parsed = {}
    for serial, events in wire.items():
        require(set(events) == {"object_request", "object_forwarded", "object_response", "object_response_delivered"}, "incomplete original S3 exchange")
        request, forwarded, response, delivered = [events[e] for e in ("object_request", "object_forwarded", "object_response", "object_response_delivered")]
        require(stamp(request) < stamp(forwarded) < stamp(response) <= stamp(delivered) and response["response_origin"] == "backend", "S3 forwarding/response order")
        for event in (forwarded, response, delivered):
            equal({k: event[k] for k in common}, {k: request[k] for k in common}, "original signed request mutated in relay")
        equal({k: delivered[k] for k in ("status", "response_bytes", "response_sha256", "etag")},
              {k: response[k] for k in ("status", "response_bytes", "response_sha256", "etag")}, "S3 delivery changed backend bytes")
        sent = body_file(directory, request["request_sha256"], request["request_bytes"])
        received = body_file(directory, response["response_sha256"], response["response_bytes"])
        require(request["path"] == HEAD or request["path"].startswith(PREFIX) and len(request["path"]) == len(PREFIX) + 64, "S3 request escaped fixed database")
        signature = request["signing"]
        require(signature["algorithm"] == "AWS4-HMAC-SHA256" and signature["access_key_sha256"] == backend["access_key_sha256"] and
                re.fullmatch(r"[0-9]{8}/us-east-1/s3/aws4_request", signature["credential_scope"]) is not None and
                re.fullmatch(r"[0-9]{8}T[0-9]{6}Z", signature["date"]) is not None and
                signature["credential_scope"].startswith(signature["date"][:8]) and digest(signature["signature_sha256"]), "original SigV4 identity/scope")
        require(signature["signed_headers"] == sorted(set(signature["signed_headers"])) and {"host", "x-amz-content-sha256", "x-amz-date"} <= set(signature["signed_headers"]) and
                signature["host"] == urlparse(configuration["s3"]["endpoint"]).netloc and signature["payload_sha256"] == sha(sent), "signed host/payload binding")
        matches = []
        if request["phase"] in call_intervals:
            beginnings, intervals = call_intervals[request["phase"]]
            position = bisect_right(beginnings, stamp(request)) - 1
            if position >= 0:
                first, last, label = intervals[position]
                if first < stamp(request) < stamp(response) < last: matches = [label]
        controls = [r for r in fixture_inputs if r["phase"] == request["phase"] and
                    stamp(r) < stamp(request) < stamp(response) < stamp(fixture_outputs[r["ordinal"]])]
        require(len(matches) + len(controls) == 1, "S3 request lacks unique actual HTTP/fixture invocation")
        item = {"serial": serial, "request": request, "response": response, "sent": sent, "received": received,
                "fixture": bool(controls), "label": matches[0] if matches else controls[0]["label"]}
        if matches:
            require(request["method"] in ("GET", "PUT"), "runtime attempted physical DELETE")
            by_call[matches[0]].append(item)
        else:
            control = controls[0]; output = fixture_outputs[control["ordinal"]]
            require(control["label"] not in fixture, "fixture issued repeated S3 request")
            for name in ("method", "path", "request_sha256", "request_bytes", "if_match", "if_none_match"):
                equal(control[name], request[name], "fixture wire input changed: " + name)
            for name in ("status", "response_sha256", "response_bytes", "etag"):
                equal(output[name], response[name], "fixture wire response changed: " + name)
            fixture[control["label"]] = item
        parsed[serial] = item
    # All operations are sequential in this fixture. Version truth comes from
    # the backend response interval, not the later delivery logger timestamp.
    ordered = sorted(parsed.values(), key=lambda item: stamp(item["response"]))
    require(all(stamp(a["response"]) < stamp(b["request"]) for a, b in zip(ordered, ordered[1:])), "fixture unexpectedly overlapped S3 requests")
    for item in ordered:
        request, response = item["request"], item["response"]; key = request["path"]; method = request["method"]
        current = state.get(key); status = response["status"]
        if method == "GET":
            require(not item["sent"] and request["if_match"] is None and request["if_none_match"] is None, "GET had mutation input")
            if current is None: require(status == 404, "GET invented a missing object")
            else:
                require(status == 200 and (item["received"], response["etag"]) == current, "GET bytes/ETag differ from original accepted version")
        elif method == "PUT":
            require((request["if_match"] is None) != (request["if_none_match"] is None), "PUT has no unique condition")
            if request["if_none_match"] is not None:
                require(request["if_none_match"] == "*", "create-only condition changed")
                require(status == (200 if current is None else 412), "create-only status differs from original version")
                if current is not None: require(current[0] == item["sent"], "different candidate reused immutable key")
            else:
                require(current is not None and request["if_match"] == current[1] and status == 200, "conditional PUT rebound/wrong ETag")
            if not item["fixture"] and key != HEAD:
                require(request["if_none_match"] == "*", "runtime overwrote immutable object")
                envelope(item["sent"], key)
            if status == 200:
                require(isinstance(response["etag"], str) and bool(response["etag"]), "accepted PUT lacks ETag")
                state[key] = item["sent"], response["etag"]
                if key != HEAD: all_objects[key] = item["sent"]
        else:
            require(item["fixture"] and item["label"] == "missing_delete" and method == "DELETE" and current is not None and status in (200, 204), "unplanned deletion")
            require(not item["sent"] and request["if_match"] is None and request["if_none_match"] is None, "DELETE fixture conditions changed")
            del state[key]
    require(len(fixture) == len(fixture_inputs), "fixture invocation omitted its real S3 exchange")
    return ordered, by_call, fixture, all_objects


def semantic_network(ordered, by_call, fixture, expected, originals, observed):
    objects, heads, levels = {}, {}, {}
    validator = Trees(objects)
    publications = []
    seed_labels = {entry[0] for entry in CALLS["seed"]}
    for item in ordered:
        request, response = item["request"], item["response"]
        if request["method"] != "PUT" or response["status"] != 200: continue
        key = request["path"]
        if key != HEAD:
            objects[key] = item["sent"]
            if item["fixture"]: validator.nodes.clear()
            continue
        if item["fixture"]: continue
        label = item["label"]; candidate = head(item["sent"])
        head5_publication(candidate, publications[-1]["head"] if publications else None)
        require(label in seed_labels and label not in heads, "extra runtime HEAD publication")
        if label == "create": count, revision, nonce, sequence, active = 0, 1, 701, 0, False
        elif label == "activate": count, revision, nonce, sequence, active = 0, 2, 702, 0, True
        else:
            count = 1 if label == "execute_first" else LAST_ID if label == "execute_last" else int(label.split("_")[1])
            revision, nonce, sequence, active = count + 2, count, 2 if count == LAST_ID else 1, True
        require(candidate["revision"] == revision and candidate["transition"] == {"revision": revision, "nonce": nonce} and
                candidate["sequence"] == sequence and candidate["active"] is active and candidate["owner_epoch"] == 1 and
                candidate["owner_instance"] == PLAN["owner_instance"] and candidate["auth_epoch"] == 1 and candidate["request_epoch"] == 1,
                "accepted HEAD authority/sequence changed")
        equal(candidate["policy"], [{"principal": 11, "read": True, "write": True, "admin": True}], "original authorization policy changed")
        require(len(candidate["windows"]) == 1 and candidate["windows"][0]["count"] == count, "retained window omitted a request")
        proof = validator.index(candidate["windows"][0], candidate)
        # Every scalar/variant has already passed strict typed validation. This
        # comparison avoids repeatedly serializing the entire historical prefix.
        require(proof["entries"] == tuple(expected[i] for i in range(1, count + 1)), "retained index differs from all original outcomes")
        data_dependencies, _ = validator.data(candidate["data_root"])
        for dependency in proof["dependencies"] | data_dependencies:
            require(dependency in objects, "HEAD acknowledged before full closure publication")
        if sequence:
            root = originals["first" if sequence == 1 else "last"]["ack"]["receipt"]["data_root"]
            require(candidate["data_root"] == root, "HEAD lost original SQL data root")
        if publications:
            previous = publications[-1]["head"]
            excluded = {"head_serial", "revision", "transition", "sequence", "active", "data_root", "windows"}
            equal({k: v for k, v in candidate.items() if k not in excluded}, {k: v for k, v in previous.items() if k not in excluded},
                  "publication silently changed unrelated authority fields")
        heads[label] = (candidate, item["sent"]); levels[count] = proof["level"]
        publications.append({"label": label, "head": candidate, "request": request, "response": response})
    equal([p["label"] for p in publications], [item[0] for item in CALLS["seed"]], "successful HEAD denominator/order changed")
    require(levels[128] == 0 and levels[129] == 1 and levels[2112] == 1 and levels[2113] == levels[LAST_ID] == 2,
            "actual index did not execute both planned root splits")
    final, final_bytes = heads["execute_last"]
    final_validator = Trees(objects)
    proof = final_validator.index(final["windows"][0], final)
    data_dependencies, _ = final_validator.data(final["data_root"])
    complete = proof["dependencies"] | data_dependencies | {HEAD}
    require(proof["summary"]["result_bytes"] == sum(len(value["raw"]) for value in originals.values()), "cancellation/result aggregate changed")
    right = []; key = PREFIX + final["windows"][0]["root"]
    while True:
        kind, node, raw = envelope(objects[key], key)
        require(kind == "index" and not raw, "rightmost dependency type")
        right.append((key, objects[key], node))
        if node["kind"] == "leaf": break
        key = PREFIX + node["children"][-1]["hash"]
    target, leaf_bytes, leaf = right[-1]
    require(leaf["entries"][-1]["request"]["id"] == LAST_ID and leaf["entries"][0]["request"]["id"] > 1, "damage was not a non-target original leaf")

    fixed = {"original_head", "corrupt_before", "corrupt_put", "corrupt_observed", "corrupt_restore_before", "corrupt_restore_put", "corrupt_restored",
             "missing_delete", "missing_observed", "missing_restore_put", "missing_restored", "summary_head_before", "summary_head_put", "summary_head_observed",
             "summary_restore_before", "summary_restore_put", "summary_restored"}
    fixed |= {f"summary_node_{i}_{operation}" for i in range(len(right)) for operation in ("put", "get")}
    require(set(fixture) == fixed, "damage/repair original call inventory changed")
    require(fixture["original_head"]["received"] == final_bytes, "inspection used another HEAD")
    bad_magic = bytes([leaf_bytes[0] ^ 128]) + leaf_bytes[1:]
    for label in fixed:
        item = fixture[label]
        if label.startswith("summary_node_"): continue
        expected_key = HEAD if "head" in label or label.startswith("summary_restore") or label == "summary_restored" else target
        require(item["request"]["path"] == expected_key, "fixture damaged another authority/dependency")
    require(fixture["corrupt_before"]["received"] == fixture["corrupt_restore_put"]["sent"] == fixture["corrupt_restored"]["received"] == leaf_bytes,
            "corrupt case did not restore exact original leaf")
    require(fixture["corrupt_put"]["sent"] == fixture["corrupt_observed"]["received"] == fixture["corrupt_restore_before"]["received"] == bad_magic,
            "corrupt case did not observe actual overwritten backend bytes")
    require(fixture["missing_observed"]["response"]["status"] == 404 and fixture["missing_restore_put"]["sent"] ==
            fixture["missing_restored"]["received"] == leaf_bytes and fixture["missing_restore_put"]["request"]["if_none_match"] == "*",
            "missing case lacks actual DELETE/404/exact recreation")
    modified = None; damaged_leaf = None
    for depth, (_, _, original_node) in enumerate(reversed(right)):
        put = fixture[f"summary_node_{depth}_put"]; get = fixture[f"summary_node_{depth}_get"]
        expected_node = copy.deepcopy(original_node)
        if depth == 0: expected_node["entries"][-1]["result_bytes"] += 1
        else: expected_node["children"][-1]["hash"] = modified
        modified = sha(put["sent"]); key = PREFIX + modified
        kind, actual_node, trailing = envelope(put["sent"], key)
        require(kind == "index" and not trailing, "summary mutant type changed")
        equal(actual_node, expected_node, "summary mutation changed more than planned result-byte claim/hash path")
        require(put["request"]["path"] == get["request"]["path"] == key and get["received"] == put["sent"] and
                put["request"]["if_none_match"] == "*", "summary candidate not durably stored/read back")
        if depth == 0: damaged_leaf = key
    altered_head = copy.deepcopy(final); altered_head["windows"][0]["root"] = modified
    equal(head(fixture["summary_head_put"]["sent"]), altered_head, "fixture changed more than new typed root")
    require(fixture["summary_head_observed"]["received"] == fixture["summary_head_put"]["sent"] == fixture["summary_restore_before"]["received"],
            "summary mutant HEAD not actually observed")
    require(fixture["summary_head_before"]["received"] == fixture["summary_restore_put"]["sent"] == fixture["summary_restored"]["received"] == final_bytes,
            "summary repair did not restore original HEAD bytes")
    try: Trees(objects).index(altered_head["windows"][0], altered_head)
    except ValueError: pass
    else: raise AssertionError("independent complete-tree audit accepted summary mutant")

    for label, items in by_call.items():
        if label not in seed_labels:
            require(all(item["request"]["method"] == "GET" for item in items), "read/rejected recovery wrote object authority")
        if label in ("warm_query", "cold_query", "repaired_query") or label.endswith("_status"):
            item = only(items, "resident query/control downloaded data or skipped fresh HEAD")
            expected_bytes = fixture["summary_head_put"]["sent"] if label == "summary_status" else final_bytes
            require(item["request"]["method"] == "GET" and item["request"]["path"] == HEAD and item["received"] == expected_bytes,
                    "resident query/control did not perform one fresh HEAD GET")
    for phase in ("cold", "repaired"):
        items = by_call[phase + "_open"]
        loaded = {item["request"]["path"] for item in items if item["response"]["status"] == 200}
        require(complete <= loaded, "cold Open skipped an entire retained index/data/result dependency")
        require(all(item["request"]["method"] == "GET" for item in items), "Open changed publication")
    for phase in PLAN["damage_cases"]:
        key = damaged_leaf if phase == "summary" else target
        require(all(item["request"]["path"] != key for item in by_call[phase + "_first"]), "non-target lookup touched damaged leaf")
        for operation in ("open", "query"):
            attempts = [item for item in by_call[phase + "_" + operation] if item["request"]["path"] == key]
            item = only(attempts, "cold entrypoint skipped bad non-target leaf")
            if phase == "missing": require(item["response"]["status"] == 404, "missing rejection lacks original backend 404")
            elif phase == "corrupt": require(item["received"] == bad_magic, "corrupt rejection did not read actual corrupted bytes")
            else: require(item["received"] == fixture["summary_node_0_put"]["sent"], "summary rejection did not read rehashed typed leaf")
    for phase in ("warm", "cold", "repaired"):
        for name in ("first", "last", "cancelled"):
            items = by_call[phase + "_" + name]
            expected_count = 4 if name == "cancelled" else 5
            require(len(items) == expected_count and all(item["request"]["method"] == "GET" for item in items),
                    "three-level point lookup did not stay on one bounded path")
    return {"accepted_runtime_HEADs": len(publications), "head_format": 5, "observed_split_counts": [129, 2113],
            "retained_entries": len(proof["entries"]), "current_index_nodes": len(proof["dependencies"]) - 2,
            "current_complete_dependencies": len(complete), "original_result_bytes": proof["summary"]["result_bytes"],
            "cold_complete_graph_checks": 2, "rejected_non_target_checks": 6, "resident_HEAD_only_queries": 3,
            "fixture_only_delete_calls": 1, "damage_target": target, "typed_summary_damage_target": damaged_leaf}


def processes(directory, facts, http, build, fixture, damage_target):
    numbered(facts); events = defaultdict(list)
    for row in facts: events[row["event"]].append(row)
    require(set(events) == {"plan_frozen", "backend_started", "service_started", "service_ready", "service_stop_requested",
            "service_stopped", "cache_removed", "client_phase_started", "client_process_started", "client_phase_finished",
            "fixture_request", "fixture_process_started", "fixture_response", "unsigned_backend_request", "unsigned_backend_response",
            "proxy_stopped", "backend_stopped", "cleanup_finished"}, "missing/unplanned process event")
    plan = only(events["plan_frozen"], "plan witness inventory")
    require(plan is facts[0] and plan["sha256"] == sha((directory / "segmented-plan.json").read_bytes()), "plan was not frozen before actual execution")
    tools = parse((directory / "segmented-tools.json").read_bytes())
    require(set(tools) == {"node", "weed", "curl"} and tools["node"]["version"] == "v22.16.0" and
            BACKEND_VERSION in tools["weed"]["version"] and tools["curl"]["version"].startswith("curl "), "actual tool versions changed")
    for tool in tools.values(): require(sha(Path(tool["path"]).read_bytes()) == tool["sha256"], "actual tool executable changed")
    incarnations, pid_intervals = set(), defaultdict(list)
    def register(value, first, last):
        ident = identity(value); pair = ident["pid"], ident["spawn_monotonic_ns"]
        require(pair not in incarnations and first <= ident["spawn_monotonic_ns"] < last, "duplicate/invalid child incarnation")
        require(all(last <= a or b <= first for a, b in pid_intervals[ident["pid"]]), "same PID claims overlapping child processes")
        incarnations.add(pair); pid_intervals[ident["pid"]].append((first, last))
        return ident
    starts, lifetimes, configurations = events["service_started"], {}, {}
    require([r["ordinal"] for r in starts] == list(range(1, PLAN["service_processes"] + 1)), "six fresh service processes missing")
    previous_removed = 0; caches = set()
    for start in starts:
        ordinal = start["ordinal"]
        ready, requested, stopped, removed = [only([r for r in events[event] if r["ordinal"] == ordinal], "service lifecycle inventory")
                                             for event in ("service_ready", "service_stop_requested", "service_stopped", "cache_removed")]
        ident = register(start["identity"], start["spawn_requested_ns"], stamp(stopped))
        require(previous_removed < start["spawn_requested_ns"] <= ident["spawn_monotonic_ns"] <= stamp(start) < stamp(ready) < stamp(requested) < stamp(stopped) < stamp(removed),
                "new compute existed before old process/cache loss")
        for row in (ready, requested): equal(identity(row["identity"]), ident, "service lifecycle process changed")
        equal(identity(stopped), ident, "service wait4 process changed"); exited(stopped, -signal.SIGKILL)
        require(stopped["stdout_sha256"] == sha((directory / f"service-{ordinal}.stdout.log").read_bytes()), "original daemon output changed")
        require(removed["path"] == start["cache_directory"] and removed["exists"] is False and removed["path"] not in caches, "cache loss missing/reused path")
        caches.add(removed["path"]); previous_removed = stamp(removed)
        raw = (directory / f"service-config-{ordinal}.json").read_bytes(); config = parse(raw)
        require(sha(raw) == start["configuration_sha256"] and start["endpoint"] == "http://" + config["listen"] and
                start["cache_directory"] == config["cache_directory"], "actual daemon config binding changed")
        require(config["worker_instance"] == str(PLAN["owner_instance"]) and config["version"] == 1 and
                config["s3"]["timeout_ms"] == DEADLINES["s3_request_ms"] and config["admission"]["timeout_ms"] == DEADLINES["ordinary_service_ms"] and
                config["admission"]["recovery_timeout_ms"] == DEADLINES["recovery_service_ms"] and config["admission"]["actor_idle_timeout_ms"] == 60000,
                "frozen service timeout/owner configuration changed")
        require(config["s3"]["region"] == "us-east-1" and config["s3"]["bucket"] == "scap-test" and config["s3"]["allow_http"] is True,
                "actual S3 fixture configuration changed")
        if configurations:
            first = configurations[1]
            equal({k: v for k, v in config.items() if k not in ("listen", "cache_directory", "credentials")},
                  {k: v for k, v in first.items() if k not in ("listen", "cache_directory", "credentials")}, "fresh service changed runtime settings")
        require(len(config["credentials"]) == 3 and config["credentials"][0]["principal"] == "11" and config["credentials"][0]["provision"] is True,
                "actual credential policy changed")
        for credential in config["credentials"]: digest(credential["sha256"])
        require(start["command"][0] == start["binary"]["path"] and len(start["command"]) == 2, "daemon command did not execute recorded binary/config")
        if build["status"] != "NOT_PROVIDED": equal(start["binary"], build["binary"], "daemon executed another release artifact")
        require(ready["response_status"] == 200 and parse(b64(ready["response_body"])) == {"status": "alive", "protocol": 1}, "actual health response changed")
        require(stamp(ready) - start["spawn_requested_ns"] <= DEADLINES["service_ready_ms"] * 1_000_000, "original daemon readiness deadline exceeded")
        lifetimes[ordinal] = (start, ready, requested, stopped, removed); configurations[ordinal] = config
    old, gone = [only(events[event], "backend process inventory") for event in ("backend_started", "backend_stopped")]
    equal(old["binary"], tools["weed"], "backend binary binding changed")
    for inventory in (old, gone):
        require(Counter(r["role"] for r in inventory["processes"]) == Counter(("master", "volume", "filer", "s3")), "backend role inventory changed")
    for initial in old["processes"]:
        final = only([r for r in gone["processes"] if r["role"] == initial["role"]], "backend role disappeared")
        register(initial, initial["spawn_monotonic_ns"], stamp(gone))
        equal(identity(initial), identity(final), "backend wait4 incarnation changed"); exited(final, -signal.SIGKILL)
        require(initial["spawn_monotonic_ns"] < stamp(old) < starts[0]["spawn_requested_ns"] and stamp(gone) > stamp(lifetimes[6][3]), "backend/compute lifetime order")
        require((directory / ("backend-" + initial["role"] + ".log")).is_file(), "backend original log missing")
    equal([r["phase"] for r in events["client_phase_started"]], list(PHASES), "client phase start order")
    equal([r["phase"] for r in events["client_phase_finished"]], list(PHASES), "client phase completion order")
    require(Counter(r["phase"] for r in events["client_process_started"]) == Counter(PHASES) and
            Counter(r["phase"] for r in http if r["event"] == "client_process_hello") == Counter(PHASES), "actual client denominator")
    phase_services = {"seed": 1, "warm": 1, "cold": 2, "corrupt": 3, "missing": 4, "summary": 5, "repaired": 6}
    for phase in PHASES:
        begin, child, finish = [only([r for r in events[event] if r["phase"] == phase], "actual SDK child inventory")
                                for event in ("client_phase_started", "client_process_started", "client_phase_finished")]
        ident = register(child["identity"], child["spawn_requested_ns"], stamp(finish))
        equal(identity(finish["identity"]), ident, "SDK wait4 identity changed"); exited(finish, 0)
        start, ready, requested, _, _ = lifetimes[phase_services[phase]]
        require(begin["service_ordinal"] == phase_services[phase] and stamp(ready) < stamp(begin) <= child["spawn_requested_ns"] <=
                ident["spawn_monotonic_ns"] <= stamp(child) < stamp(finish) < stamp(requested), "SDK phase escaped exact compute incarnation")
        budget = DEADLINES["seed_phase_ms"] if phase == "seed" else DEADLINES["other_phase_ms"]
        require(begin["deadline_ms"] == budget and stamp(finish) - stamp(begin) <= budget * 1_000_000, "original SDK phase deadline exceeded")
        equal(child["binary"], tools["node"], "SDK used another Node executable")
        require(child["command"][0] == tools["node"]["path"] and len(child["command"]) == 5 and
                Path(child["command"][1]).name == "segmented_probe.mjs" and child["command"][2] == phase, "original SDK process command changed")
        hello = only([r for r in http if r["phase"] == phase and r["event"] == "client_process_hello"], "SDK self-observation")
        require(hello["pid_source"] == "node_process.pid" and hello["self_pid"] == ident["pid"] and
                child["spawn_requested_ns"] < stamp(hello) < stamp(finish), "SDK hello escaped pre-Popen/finish interval")
        for row in [r for r in http if r["phase"] == phase and r["event"] != "client_process_hello"]:
            require(stamp(hello) < stamp(row) < stamp(finish) and row["call_id"].startswith(f"{phase}:{ident['pid']}:"), "HTTP event outside actual SDK child")
            if row["event"] == "http_request": require(row["url"] == start["endpoint"] + "/v1", "HTTP used wrong daemon")
        for suffix in ("stdout", "stderr"):
            require(finish[suffix + "_sha256"] == sha((directory / (phase + "." + suffix + ".log")).read_bytes()), "original SDK log changed")
        require(not (directory / (phase + ".stderr.log")).read_bytes(), "successful SDK phase had stderr")
    require(len(events["fixture_process_started"]) == len(fixture) == len(events["fixture_response"]), "actual signed curl child denominator")
    for original in events["fixture_request"]:
        ordinal = original["ordinal"]
        child, finish = [only([r for r in events[event] if r["ordinal"] == ordinal], "signed fixture child inventory")
                          for event in ("fixture_process_started", "fixture_response")]
        ident = register(child["identity"], child["spawn_requested_ns"], stamp(finish))
        equal(identity(finish["identity"]), ident, "curl wait4 incarnation changed"); exited(finish, 0)
        require(stamp(original) < child["spawn_requested_ns"] <= ident["spawn_monotonic_ns"] <= stamp(child) < stamp(finish) and
                stamp(finish) - child["spawn_requested_ns"] <= (DEADLINES["curl_ms"] + 2000) * 1_000_000, "original signed fixture deadline/order")
        equal(child["binary"], tools["curl"], "fixture used another curl executable")
        command = child["command"]
        require(command[0] == tools["curl"]["path"] and command[-1] == configurations[1]["s3"]["endpoint"] + original["path"] and
                command[command.index("--max-time") + 1] == str(DEADLINES["curl_ms"] / 1000) and
                command[command.index("--request") + 1] == original["method"] and
                command[command.index("--aws-sigv4") + 1] == "aws:amz:us-east-1:s3" and command[command.index("--config") + 1] == "-",
                "actual signed fixture command changed")
        raw = (directory / "curl" / f"{ordinal}.body").read_bytes()
        headers = (directory / "curl" / f"{ordinal}.headers").read_bytes()
        stdout = (directory / "curl" / f"{ordinal}.stdout").read_bytes(); stderr = (directory / "curl" / f"{ordinal}.stderr").read_bytes()
        require(len(raw) == finish["response_bytes"] and sha(raw) == finish["response_sha256"] and
                sha(headers) == finish["headers_sha256"] and sha(stdout) == finish["stdout_sha256"] and sha(stderr) == finish["stderr_sha256"] and
                stdout == str(finish["status"]).encode() and not stderr, "raw curl output changed")
        statuses = [int(line.split()[1]) for line in headers.splitlines() if line.startswith(b"HTTP/")]
        require(statuses and statuses[-1] == finish["status"], "raw curl HTTP status differs")
        etags = [line.split(b":", 1)[1].strip().decode() for line in headers.splitlines() if line.lower().startswith(b"etag:")]
        require((etags[-1] if etags else None) == finish["etag"], "raw curl ETag differs")
        item = fixture[original["label"]]
        require(child["spawn_requested_ns"] < stamp(item["request"]) < stamp(item["response"]) < stamp(finish), "curl did not make recorded actual exchange")
    unsigned, denied = [only(events[event], "unsigned backend auth control inventory") for event in ("unsigned_backend_request", "unsigned_backend_response")]
    require(unsigned["method"] == "GET" and unsigned["path"] == damage_target and unsigned["authorization_present"] is False and
            stamp(unsigned) < stamp(denied) < stamp(lifetimes[1][2]) and denied["status"] == 403 and
            sha(b64(denied["response_body"])) == denied["response_sha256"] and b"AccessDenied" in b64(denied["response_body"]),
            "backend did not actually reject unsigned request to same existing key")
    proxy, cleanup = [only(events[event], "cleanup inventory") for event in ("proxy_stopped", "cleanup_finished")]
    require(proxy["errors"] == cleanup["errors"] == [] and stamp(lifetimes[6][4]) < stamp(proxy) < stamp(gone) < stamp(cleanup), "cleanup left original children/cache/proxy")
    return {"actual_service_children": 6, "actual_sdk_children": len(PHASES), "actual_fixture_children": len(fixture),
            "actual_backend_children": 4, "unique_kernel_child_incarnations": len(incarnations),
            "complete_compute_cache_losses": 6, "kernel_wait4_verified": True, "backend_authentication_enforced": True}


def audit(directory, *, require_build=True):
    directory = Path(directory)
    equal(parse((directory / "segmented-plan.json").read_bytes()), PLAN, "fixed pre-run input/deadline plan changed")
    http = rows(directory, "http-client-ledger.jsonl"); calls = exchanges(http)
    observed = labeled(directory, calls); expected, originals = sql(directory, observed)
    facts = rows(directory, "process-ledger.jsonl"); history = rows(directory, "history.jsonl")
    configuration = parse((directory / "service-config-1.json").read_bytes())
    ordered, by_call, fixture, _ = original_network(directory, history, observed, facts, configuration)
    network = semantic_network(ordered, by_call, fixture, expected, originals, observed)
    build_report = build_receipt(directory, require_build)
    process_report = processes(directory, facts, http, build_report, fixture, network["damage_target"])
    output = {"schema": 1, "status": "passed", "http_calls": len(calls), "tracked_inputs": len(expected) + 2,
              "original_sql_acks": len(originals), "cancelled_requests": LAST_ID - 2, "original_s3_requests": len(ordered),
              "build": build_report, "processes": process_report, "network": network,
              "aws_standard": "NOT_RUN", "production_tps": "NOT_MEASURED", "physical_gc": "DISABLED"}
    output["source_sha256"] = {name: sha((directory / name).read_bytes()) for name in FILES}
    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser(); parser.add_argument("evidence", type=Path)
    arguments = parser.parse_args()
    print(json.dumps(audit(arguments.evidence), indent=2, sort_keys=True))
