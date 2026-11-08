#!/usr/bin/env python3
"""Independent original HTTP/S3/process audit; imports no discovery implementation."""
from __future__ import annotations

import argparse
import base64
from collections import Counter, defaultdict
import copy
import hashlib
import json
from pathlib import Path
import re
import signal
from urllib.parse import parse_qsl, unquote, urlsplit
import xml.etree.ElementTree as ET

from audit_wire import b64, committed, equal, fingerprint, object_versions, parse, require, result
from service_oracle import build_receipt, exited, identity, only, rows, stamp, value_of

FILES = ("discovery-tools.json", "discovery-source-before.json", "discovery-source-after.json",
         "process-ledger.jsonl", "http-client-ledger.jsonl", "discovery-auth.jsonl", "discovery-calls.jsonl",
         "discovery-phases.jsonl", "discovery-s3.jsonl", "discovery-sql-inputs.jsonl", "discovery-sql-results.jsonl")
FAULTS = {"denied": "DENIED", "missing": "UNKNOWN", "missing_truncation": "CORRUPT", "no_progress": "CORRUPT",
          "head_missing": "CORRUPT", "head_corrupt_head": "CORRUPT"}
PHASES = ("setup", "reader_first", "revoke_continue", "capabilities", "cursor_bindings",
          *(item for name in FAULTS for item in ("fault_" + name, "after_fault_" + name)),
          "hold_timeout", "one_held_probe", "hold_abort", "held_probes", "release_recovered", "cursor_before_loss", "restart")
ROLE_SCOPE = {"admin": ("1", "7", "11", True, False), "reader": ("1", "7", "12", False, False),
              "operator": ("1", "7", "13", False, True), "other": ("1", "8", "22", True, False),
              "third": ("1", "9", "33", False, False), "foreign": ("2", "7", "44", True, True)}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def raw(value):
    require(set(value) == {"bytes", "sha256", "base64"}, "raw object witness shape")
    decoded = b64(value["base64"])
    require(type(value["bytes"]) is int and value["bytes"] == len(decoded) and value["sha256"] == sha(decoded),
            "raw object bytes/hash differ")
    return decoded


def numbered(ledger):
    require([row["sequence"] for row in ledger] == list(range(1, len(ledger) + 1)), "missing/reordered numbered trace")
    require(all(row.get("schema") == 1 for row in ledger), "trace schema changed")
    require(all(stamp(left) < stamp(right) for left, right in zip(ledger, ledger[1:])), "trace clock order")


def window(call, time):
    return stamp(call["request"]) < time < stamp(call["response"])


def numeric_wire(value):
    if isinstance(value, dict):
        return {key: numeric_wire(item) for key, item in value.items()}
    if isinstance(value, list):
        return [numeric_wire(item) for item in value]
    return str(value) if type(value) is int else value


def read_sources(directory):
    return {name: rows(directory, name) if name.endswith(".jsonl") else parse((directory / name).read_bytes()) for name in FILES}


def http_calls(data):
    http = data["http-client-ledger.jsonl"]
    calls, counts = {}, Counter()
    for row in http:
        if row["event"] == "client_process_hello":
            continue
        call_id = row["call_id"]
        if row["event"] == "http_request":
            counts[row["phase"]] += 1
            require(call_id not in calls and call_id.rsplit(":", 1)[1] == str(counts[row["phase"]]), "HTTP invocation gap/duplicate")
            require(row["method"] == "POST" and row["headers"]["content-type"] == "application/json", "wrong SDK HTTP method/type")
            original = b64(row["body"])
            require(sha(original) == row["body_sha256"], "original request hash differs")
            body = parse(original)
            url = urlsplit(row["url"])
            require(url.hostname == "127.0.0.1" and url.path in ("/v1", "/v1/catalogue", "/v1/discovery")
                    and not url.query and not url.fragment and url.username is None and url.password is None, "HTTP route escaped private fixture")
            require(type(body["version"]) is int and body["version"] == 1, "wrong protocol version")
            expected = ("discovery" if url.path == "/v1/discovery" else "catalogue" if url.path == "/v1/catalogue"
                        else "recovery" if body["operation"] in ("open", "activate")
                        else "data" if body["operation"] in ("create", "query", "execute") else "control")
            require(row["headers"]["x-scap-admission"] == expected, "SDK used the wrong admission pool")
            if expected == "discovery":
                require(set(body) == {"version", "operation", "cursor"} and body["operation"] in ("list_names", "deployment_inventory"),
                        "discovery input introduced identity/routing fields")
            calls[call_id] = {"request": row, "body": body, "route": url.path}
        else:
            require(row["event"] in ("http_response", "http_transport_error") and call_id in calls and "response" not in calls[call_id],
                    "HTTP response is missing, duplicated or unsolicited")
            call = calls[call_id]
            require(row["phase"] == call["request"]["phase"] and row["client"] == call["request"]["client"]
                    and stamp(call["request"]) < stamp(row), "HTTP response binding/order")
            call["response"] = row
            if row["event"] == "http_response":
                original = b64(row["body"])
                require(sha(original) == row["body_sha256"], "original response hash differs")
                value = parse(original)
                require(type(value.get("ok")) is bool and (row["status"] == 200) == value["ok"], "HTTP status/envelope disagree")
                require(set(value) == ({"ok", "value"} if value["ok"] else {"ok", "error"}), "HTTP envelope fields changed")
                require(row["headers"]["content-type"].split(";")[0] == "application/json", "non-JSON discovery response")
                call["value"] = value
    require(all("response" in value for value in calls.values()), "HTTP invocation lacks terminal outcome")
    auth = data["discovery-auth.jsonl"]
    require(Counter(row["call_id"] for row in auth) == Counter(calls.keys()), "authorization witness denominator differs")
    roles = only([row for row in data["process-ledger.jsonl"] if row["event"] == "fixture_roles"], "trusted credential inventory")["roles"]
    require(set(roles) == set(ROLE_SCOPE), "role denominator changed")
    for role, expected in ROLE_SCOPE.items():
        equal(tuple(roles[role][key] for key in ("deployment", "tenant", "principal", "provision", "deployment_inventory")), expected,
              "trusted role capability changed")
    for row in auth:
        call = calls[row["call_id"]]
        require(row["role"] in roles and row["credential_sha256"] == roles[row["role"]]["sha256"]
                and row["endpoint"] == call["request"]["url"], "actual HTTP bearer differs from trusted role")
        call["role"], call["identity"] = row["role"], roles[row["role"]]
    outcomes, observed = data["discovery-calls.jsonl"], {}
    beginnings = [row for row in outcomes if row["event"] == "call_started"]
    finishes = [row for row in outcomes if row["event"] == "call_finished"]
    require(len(beginnings) == len(finishes) == len(calls), "SDK invocation/HTTP denominator differs")
    for first in beginnings:
        label = first["label"]
        require(label not in observed, "SDK label repeated")
        last = only([row for row in finishes if row["label"] == label], "SDK outcome inventory")
        call = calls[last["call_id"]]
        require(call["request"]["phase"] == first["phase"] == last["phase"] and first["client"] == call["request"]["client"]
                and first["operation"] == call["body"]["operation"] and first["role"] == call["role"], "SDK result binds another original call")
        require(stamp(first) < stamp(call["request"]) < stamp(call["response"]) < stamp(last) and last["attempts"] == 1,
                "SDK silently retried or changed original call interval")
        if "error" in last:
            code = last["error"]["code"]
            if call["response"]["event"] == "http_response":
                require(call["value"]["ok"] is False and call["value"]["error"]["code"] == code, "SDK error differs from raw HTTP")
            else:
                require(code in ("DEADLINE", "ABORTED"), "unexpected read transport classification")
        else:
            value = value_of(call)
            if call["route"] == "/v1/discovery":
                equal(last["value"], value, "SDK discovery page differs from full raw response")
        call["label"], call["outcome"] = label, last
        observed[label] = call
    require({row["call_id"] for row in finishes} == set(calls), "two SDK results reused one HTTP call")
    require(Counter(row["phase"] for row in data["discovery-phases.jsonl"]) == Counter(PHASES), "phase completion inventory changed")
    for phase in data["discovery-phases.jsonl"]:
        require(phase["attempts"] == counts[phase["phase"]], "phase omitted an HTTP attempt")
    return calls, observed, roles


def network(data, calls):
    history = data["discovery-s3.jsonl"]
    numbered(history)
    require(not any(row["event"] == "fixture_failed" for row in history), "original S3 fixture failure")
    grouped = defaultdict(list)
    for row in history:
        if "request_serial" in row:
            grouped[row["request_serial"]].append(row)
    require(sorted(grouped) == list(range(1, len(grouped) + 1)), "S3 invocation denominator has gaps")
    objects, version_requests, version_responses = {}, {}, {}
    allowed = {"request", "forwarded", "backend_response", "delivery_started", "delivery_finished", "delivery_disconnected",
               "fault_armed", "fault_observed", "hold_released"}
    require(all(row["event"] in allowed for row in history), "unplanned S3 event")
    for serial, events in grouped.items():
        by = defaultdict(list)
        for row in events:
            by[row["event"]].append(row)
        request, forwarded, backend, delivery = [only(by[kind], "missing/duplicate original S3 " + kind)
                                                 for kind in ("request", "forwarded", "backend_response", "delivery_started")]
        terminal = only(by["delivery_finished"] + by["delivery_disconnected"], "S3 delivery terminal inventory")
        require(stamp(request) < stamp(forwarded) < stamp(backend) < stamp(delivery) < stamp(terminal), "S3 original interval order")
        require(request["method"] in ("GET", "PUT") and request["signing"]["verified"] is True
                and request["signing"]["algorithm"] == "AWS4-HMAC-SHA256", "missing verified actual product SigV4")
        parsed = urlsplit(request["path"])
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        require(dict(pairs) == request["query"] and len(pairs) == len(request["query"]), "raw S3 query differs")
        require(unquote(parsed.path).removeprefix("/scap-test/") == request["key"], "raw S3 key differs")
        incoming, upstream, outgoing = raw(request["request"]), raw(backend["body"]), raw(delivery["body"])
        if request["method"] == "GET":
            require(incoming == b"" and request["if_match"] is None and request["if_none_match"] is None, "GET body/conditions changed")
        else:
            require(not request["query"] and ((request["if_none_match"] == "*" and request["if_match"] is None)
                    or (request["if_none_match"] is None and isinstance(request["if_match"], str))), "unconditional/ambiguous PUT")
        if request["fault"] is None:
            require(not by["fault_observed"] and backend["status"] == delivery["status"] and backend["etag"] == delivery["etag"],
                    "unexplained S3 response mutation")
            equal(upstream, outgoing, "unfaulted response bytes changed")
        else:
            fault = only(by["fault_observed"], "missing actual fault observation")
            armed = only([row for row in history if row["event"] == "fault_armed" and row["label"] == fault["label"]], "fault arm inventory")
            require(fault["label"] == request["fault"] and fault["mode"] == armed["mode"] and stamp(armed) < stamp(request) < stamp(fault),
                    "fault selection changed")
            if fault["mode"] == "hold":
                release = only(by["hold_released"], "held S3 was not explicitly released")
                require(release["label"] == fault["label"] and stamp(fault) < stamp(release) < stamp(forwarded), "hold released before observation or after forward")
                equal(upstream, outgoing, "hold rewrote S3 bytes")
                require(backend["status"] == delivery["status"], "hold rewrote status")
            else:
                require(backend["status"] == 200, "fault lacks actual successful backend witness")
                expected = 403 if fault["mode"] == "denied" else 404 if fault["mode"] == "missing" else 200
                require(delivery["status"] == expected and upstream != outgoing, "fault did not alter original response")
        objects[serial] = {"request": request, "backend": backend, "delivery": delivery, "terminal": terminal,
                           "incoming": incoming, "upstream": upstream, "outgoing": outgoing}
        if not request["query"]:
            row = {"monotonic_ns": stamp(request), "path": unquote(parsed.path), "method": request["method"],
                   "request_bytes": len(incoming), "request_sha256": sha(incoming),
                   "if_match": request["if_match"], "if_none_match": request["if_none_match"]}
            response = {**row, "monotonic_ns": stamp(backend), "status": backend["status"],
                        "response_bytes": len(upstream), "response_sha256": sha(upstream), "etag": backend["etag"]}
            prefix = "head" if request["key"].endswith("/head") else "catalogue" if "/catalogue/v1/" in request["key"] else None
            if prefix:
                row[prefix + "_request_bytes"] = list(incoming)
                response[prefix + "_request_bytes"] = list(incoming)
                response[prefix + "_response_bytes"] = list(upstream)
            version_requests[serial], version_responses[serial] = row, response
    versions = object_versions(version_requests, version_responses)
    # Exact reads can outlive a disconnected HTTP client, but only the two
    # observed held requests receive this bounded original 5-second window.
    held = [call for call in calls.values() if call.get("label") in ("held_client_timeout", "held_client_abort")]
    for obj in objects.values():
        request = obj["request"]
        compatible = []
        for call in calls.values():
            identity_value = call["identity"]
            prefix = f"scap-object/v1/{identity_value['deployment']}/{identity_value['tenant']}/"
            if call["body"]["operation"] == "deployment_inventory" and identity_value["deployment_inventory"]:
                prefix = f"scap-object/v1/{identity_value['deployment']}/"
            target = request["query"].get("prefix", request["key"])
            if not target.startswith(prefix):
                continue
            ordinary = window(call, stamp(request))
            continuing = call in held and stamp(call["request"]) < stamp(request) < stamp(call["request"]) + 5_000_000_000
            if ordinary or continuing:
                compatible.append(call["label"])
        require(compatible, "S3 request has no authenticated invocation or bounded still-running worker")
    publications = [obj for obj in objects.values() if obj["request"]["method"] == "PUT" and obj["backend"]["status"] == 200]
    listing_count = 0
    for obj in objects.values():
        request = obj["request"]
        if not request["query"]:
            continue
        listing_count += 1
        query = request["query"]
        require(query.get("list-type") == "2" and query.get("max-keys") == "32" and set(query) <=
                {"list-type", "max-keys", "prefix", "delimiter", "start-after"}, "unbounded/unsupported original LIST request")
        require(query.get("delimiter") in (None, "/") and obj["backend"]["status"] == 200, "unexpected successful backend LIST contract")
        root = ET.fromstring(obj["upstream"])
        def field(name):
            found = [item for item in root if item.tag.rsplit("}", 1)[-1] == name]
            return only(found, "LIST field inventory: " + name).text or ""
        prefix, after = query["prefix"], query.get("start-after", "")
        require(field("Prefix") == prefix and field("MaxKeys") == "32", "LIST scope/bound echo differs")
        if after:
            require(field("StartAfter") == after, "LIST lower-bound echo differs")
        entries = []
        for kind, child_name in (("Contents", "Key"), ("CommonPrefixes", "Prefix")):
            group = []
            for node in root:
                if node.tag.rsplit("}", 1)[-1] == kind:
                    entry = only([child for child in node if child.tag.rsplit("}", 1)[-1] == child_name], "LIST entry field")
                    group.append(entry.text or "")
            require(group == sorted(set(group), key=lambda item: item.encode()), "LIST sequence duplicates/order")
            entries.extend(group)
        entries.sort(key=lambda item: item.encode())
        keys = {put["request"]["key"] for put in publications if stamp(put["backend"]) < stamp(request)}
        expected = set()
        for key in keys:
            if not key.startswith(prefix):
                continue
            suffix = key[len(prefix):]
            candidate = prefix + suffix.split("/", 1)[0] + "/" if query.get("delimiter") == "/" and "/" in suffix else key
            if candidate.encode() > after.encode():
                expected.add(candidate)
        expected = sorted(expected, key=lambda item: item.encode())
        equal(entries, expected[:32], "actual backend LIST omitted/added a candidate from prior accepted writes")
        require(field("KeyCount") == str(len(entries)) and field("IsTruncated") == str(len(expected) > 32).lower(),
                "LIST completeness/count differs from observed permanent inventory")
    return objects, {"signed_backend_requests": len(objects), "list_requests": listing_count, "versions": versions,
                     "original_backend_response_body_bytes": sum(len(obj["upstream"]) for obj in objects.values()),
                     "delivered_response_body_bytes": sum(len(obj["outgoing"]) for obj in objects.values())}


def within(objects, call, *, key=None, listing=None):
    return [obj for obj in objects.values() if window(call, stamp(obj["request"])) and stamp(obj["delivery"]) < stamp(call["response"])
            and (key is None or obj["request"]["key"] == key)
            and (listing is None or bool(obj["request"]["query"]) == listing)]


def successful_gets(objects, call, key):
    return [obj for obj in within(objects, call, key=key, listing=False) if obj["request"]["method"] == "GET"
            and obj["delivery"]["status"] == 200 and obj["upstream"] == obj["outgoing"]]


def metadata_reservations(gets):
    """Independent reconstruction of the port budget, not HTTP body byte totals."""
    used, maximum = 0, 16 * 1024 * 1024
    for obj in sorted(gets, key=lambda value: stamp(value["request"])):
        key = obj["request"]["key"]
        require(key.endswith("/head") or "/catalogue/v1/" in key, "metadata scan downloaded data objects")
        bound = 256 * 1024 if key.endswith("/head") else 64 * 1024
        allowance = min(bound, maximum - used)
        require(allowance > 0, "GET dispatched after metadata budget exhausted")
        used += allowance
        if obj["delivery"]["status"] == 200 and len(obj["outgoing"]) <= allowance:
            # This fixture's successful exact GETs have complete declared
            # lengths, full ranges and valid ETags. Only these earn a refund.
            require(obj["delivery"]["etag"] is not None and obj["upstream"] == obj["outgoing"],
                    "unverified successful metadata body")
            used -= allowance - len(obj["outgoing"])
        # Missing/denied/failed GET retains its entire reservation, including
        # normal absent abort proofs. Its HTTP error text is a separate bound.
    return used


def visible_witness(objects, call, value):
    creation = value["creation"]
    who = call["identity"]
    scope = creation["scope"]
    require(scope["deployment"] == who["deployment"] and scope["tenant"] == who["tenant"], "ordinary names disclosed a foreign tenant")
    prefix = f"scap-object/v1/{scope['deployment']}/{scope['tenant']}/"
    name = prefix + "catalogue/v1/name/" + sha(creation["name"].encode())
    descriptor = prefix + f"catalogue/v1/create/{creation['creator']}/{creation['operation']}"
    proof = prefix + f"catalogue/v1/abort-proof/{creation['creator']}/{creation['operation']}"
    head = prefix + scope["database"] + "/head"
    names = [obj for obj in successful_gets(objects, call, name) if
             numeric_wire(parse(obj["outgoing"])["creation"]) == creation and
             str(parse(obj["outgoing"])["revision"]) == value["binding_revision"]]
    heads = [obj for obj in successful_gets(objects, call, head) if str(parse(obj["outgoing"])["revision"]) == value["head_revision"]]
    witnesses = []
    for authority in heads:
        parsed = parse(authority["outgoing"])
        if not any(str(permission["principal"]) == who["principal"] and permission["read"] is True for permission in parsed["policy"]):
            continue
        require(parsed["lifecycle"] == "ready" and numeric_wire(parsed["scope"]) == scope, "visible HEAD state/scope differs")
        source = [obj for obj in successful_gets(objects, call, descriptor) if sha(obj["outgoing"]) == parsed["creation"]["descriptor_hash"]
                  and numeric_wire(parse(obj["outgoing"])["creation"]) == creation and stamp(obj["delivery"]) < stamp(authority["request"])]
        before = [obj for obj in names if stamp(obj["delivery"]) < stamp(authority["request"])]
        after = [obj for obj in names if stamp(authority["delivery"]) < stamp(obj["request"])]
        barriers = [obj for obj in within(objects, call, key=proof, listing=False) if obj["delivery"]["status"] == 404
                    and stamp(obj["delivery"]) < stamp(authority["request"])
                    and any(stamp(prior["delivery"]) < stamp(obj["request"]) for prior in before)]
        if source and before and after and barriers:
            witnesses.append(authority)
    require(witnesses, "visible name lacks same-call source + Name/Proof/HEAD/Name and fresh READ permission")


def pages(data, observed, objects):
    names_seen, inventory_groups = 0, defaultdict(list)
    for label, call in observed.items():
        if call["route"] != "/v1/discovery" or call.get("value", {}).get("ok") is not True:
            continue
        value = value_of(call)
        inventory = call["body"]["operation"] == "deployment_inventory"
        require(set(value) == ({"records", "cursor", "completion", "usage", "stopped"} if inventory else
                              {"names", "cursor", "traversal_exhausted", "stopped"}), "discovery response leaked/omitted fields")
        exhausted = value["completion"]["traversal_exhausted"] if inventory else value["traversal_exhausted"]
        require(type(exhausted) is bool and (value["cursor"] is None) == exhausted and (not exhausted or value["stopped"] is None),
                "failure/unknown page was reported as a complete empty traversal")
        require(value["stopped"] in (None, "INVALID", "DENIED", "LIMIT", "CONFLICT", "UNKNOWN", "CORRUPT"), "unknown page stop reason")
        if value["cursor"] is not None:
            require(isinstance(value["cursor"], str) and re.fullmatch(r"[A-Za-z0-9_-]{1,16384}", value["cursor"]), "cursor is not bounded opaque URL text")
        entries = value["records"] if inventory else value["names"]
        require(isinstance(entries, list) and len(entries) <= 128, "discovery candidate response exceeds fixed bound")
        if inventory:
            require(call["identity"]["deployment_inventory"] is True, "inventory accepted without actual operator capability")
            completion = value["completion"]
            require(completion["preexisting_slots_covered"] == exhausted and completion["data_recovery"] == "not_run"
                    and completion["recovery_complete"] is False, "metadata traversal falsely claimed data recovery/snapshot")
            limits = {"list_pages": 4, "candidates": 128, "exact_gets": 512, "list_bytes": 4 * 1024 * 1024, "metadata_bytes": 16 * 1024 * 1024}
            require(set(value["usage"]) == set(limits) and all(type(value["usage"][key]) is int and 0 <= value["usage"][key] <= limit for key, limit in limits.items()), "inventory cost budget differs")
            real = within(objects, call)
            lists = [obj for obj in real if obj["request"]["query"]]
            gets = [obj for obj in real if not obj["request"]["query"] and obj["request"]["method"] == "GET"]
            require(value["usage"]["list_pages"] == len(lists) and value["usage"]["exact_gets"] == len(gets), "reported HTTP budget differs from actual S3")
            require(value["usage"]["list_bytes"] == sum(len(obj["outgoing"]) for obj in lists),
                    "reported LIST bytes differ from actual complete pages")
            require(value["usage"]["metadata_bytes"] == metadata_reservations(gets),
                    "reported metadata reservation/refund budget differs from original calls")
            for entry in entries:
                require(entry["key"].startswith("scap-object/v1/1/"), "operator escaped trusted deployment")
                authority = successful_gets(objects, call, entry["key"])
                require(authority, "inventory record lacks actual same-page exact GET")
                if entry["kind"] == "control":
                    require(entry["control"] is not None, "control inventory discarded immutable intent")
                    projections = [{key: numeric_wire(parse(obj["outgoing"])[key]) for key in
                                    ("kind", "principal", "operation", "expected_name_revision", "expected_head_revision", "nonce")}
                                   for obj in authority]
                    require(entry["control"] in projections, "observed control differs from immutable original control")
                else:
                    require(entry["control"] is None, "non-control fabricated control authority")
            if label.startswith("operator_inventory_"):
                inventory_groups["initial"].append(call)
            if label.startswith("restart_inventory_"):
                inventory_groups["restart"].append(call)
        else:
            require("scap-object/v1/" not in b64(call["response"]["body"]).decode(), "ordinary names exposed physical frontier")
            for entry in entries:
                require(set(entry) == {"creation", "binding_revision", "head_revision"}, "ordinary name fields differ")
                visible_witness(objects, call, entry)
                names_seen += 1
    published = {obj["request"]["key"] for obj in objects.values() if obj["request"]["method"] == "PUT" and obj["backend"]["status"] == 200
                 and obj["request"]["key"].startswith("scap-object/v1/1/") and
                 ("/catalogue/v1/" in obj["request"]["key"] or obj["request"]["key"].endswith("/head"))}
    require(len(published) >= 392, "fixture omitted permanent metadata inventory")
    for group in ("initial", "restart"):
        scan = inventory_groups[group]
        require(len(scan) > 1 and scan[0]["body"]["cursor"] is None, "inventory did not perform real explicit pagination")
        collected = []
        for index, call in enumerate(scan):
            value = value_of(call)
            if index:
                require(call["body"]["cursor"] == value_of(scan[index - 1])["cursor"], "inventory reset/skipped original continuation")
            require(value["stopped"] in (None, "LIMIT"), "complete inventory hid an incomplete error")
            collected.extend(entry["key"] for entry in value["records"])
            require(value["completion"]["metadata_classified"] == str(len(collected)), "cumulative classification count differs")
        require(value_of(scan[-1])["cursor"] is None and len(collected) == len(set(collected)) and set(collected) == published,
                "completed deployment inventory omitted/repeated a prior permanent slot")
    return {"fresh_read_visible_names": names_seen, "permanent_metadata_keys": len(published),
            "inventory_scans": 2, "data_recovery": "not_run"}


def cases(observed, objects, history):
    setup = {f"prepare_{index}" for index in range(129)} | {f"ready_{index}" for index in range(129)} | {
        "prepare_other", "ready_other", "prepare_foreign", "ready_foreign", "prepare_dormant", "control_dormant",
        "grant_first_status", "grant_first", "grant_last_status", "grant_last", "seed_status", "seed_activate", "seed_execute"}
    require({label for label, call in observed.items() if call["request"]["phase"] == "setup"} == setup, "setup input denominator changed")
    for index in range(129):
        call = observed[f"prepare_{index}"]
        require(call["body"]["name"] == f"discovery-{index:03}" and call["body"]["create_operation"] == str(10000 + index), "seed names/identities changed")
        require(value_of(observed[f"ready_{index}"])["phase"] == "ready", "seed did not durably reach Ready")
    first = value_of(observed["reader_first"])
    require(isinstance(first["cursor"], str) and len(first["names"]) == 1, "reader did not receive a genuine partial first page")
    ordered = sorted((value_of(observed[f"prepare_{index}"])["creation"] for index in range(129)), key=lambda row: sha(row["name"].encode()))
    require(first["names"][0]["creation"] == ordered[0], "first visible item differs from actual byte-ordered candidate")
    revoked = ordered[-1]
    revocation = observed["revoke_last"]
    require(any(row["principal"] == "12" and row["read"] is False and row["admin"] is True for row in revocation["body"]["permissions"]), "revocation did not remove READ while preserving ADMIN")
    resumed = [call for label, call in observed.items() if label.startswith("reader_resume_")]
    require(resumed and resumed[0]["body"]["cursor"] == first["cursor"] and value_of(resumed[-1])["cursor"] is None,
            "reader continuation reset or never completed")
    for call in resumed:
        require(stamp(revocation["response"]) < stamp(call["request"]), "resume preceded actual permission revocation")
        require(not value_of(call)["names"], "revoked or already-consumed name leaked into continuation")
    head = f"scap-object/v1/1/7/{revoked['scope']['database']}/head"
    require(any(successful_gets(objects, call, head) for call in resumed), "continuation omitted fresh authority for revoked candidate")
    denied = {"revoked_resolve", "provision_is_not_inventory", "inventory_is_not_sql", "operator_cannot_cross_tenant_sql"}
    cursors = {"tampered_cursor", "principal_cursor", "tenant_cursor", "deployment_cursor", "names_as_inventory",
               "inventory_as_names", "other_daemon_cursor", "restart_cursor"}
    for label in denied | cursors:
        call = observed[label]
        expected = "CURSOR_INVALID" if label in cursors else "DENIED"
        require(call.get("value", {}).get("error", {}).get("code") == expected, "permission/cursor negative falsely succeeded")
        if label in cursors | {"provision_is_not_inventory", "operator_cannot_cross_tenant_sql"}:
            require(not within(objects, call), "rejected capability/cursor performed S3 I/O")
    positive = observed["original_cursor_positive"]
    require(positive["body"]["cursor"] == first["cursor"] and value_of(positive)["stopped"] in (None, "LIMIT"),
            "invalid-binding cases lack a same-daemon valid-cursor positive control")
    fresh, restarted = observed["fresh_cursor_before_loss"], observed["restart_cursor"]
    require(restarted["body"]["cursor"] == value_of(fresh)["cursor"] and
            stamp(restarted["request"]) - stamp(fresh["response"]) < 600_000_000_000,
            "restart rejection could be ordinary cursor expiry or a different token")
    for label, stopped in FAULTS.items():
        call = observed["fault_" + label]
        page = value_of(call)
        require(page["stopped"] == stopped and page["cursor"] is not None and page["traversal_exhausted"] is False,
                "S3 failure was turned into successful empty discovery")
        target = only([obj for obj in objects.values() if obj["request"]["fault"] == label], "actual original fault denominator")
        require(window(call, stamp(target["request"])) and stamp(target["delivery"]) < stamp(call["response"]), "fault has no matching API invocation")
        recovery = [value for name, value in observed.items() if name.startswith("after_fault_" + label + "_")]
        require(recovery and recovery[0]["body"]["cursor"] == page["cursor"] and value_of(recovery[-1])["cursor"] is None,
                "fault recovery silently restarted or omitted the explicit cursor")
        all_names = page["names"] + [item for value in recovery for item in value_of(value)["names"]]
        require([item["creation"] for item in all_names] == [ordered[0]], "fault continuation skipped/repeated an authorized name")
        if label.startswith("head_"):
            require([item["creation"] for item in page["names"]] == [ordered[0]], "HEAD fault did not occur after a classified candidate")
            lists = within(objects, recovery[0], listing=True)
            require(lists and lists[0]["request"]["query"].get("start-after") == "scap-object/v1/1/7/catalogue/v1/name/" + sha(ordered[0]["name"].encode()),
                    "continuation advanced to unclassified LIST page tail")
    held = {}
    for label, call_label, code in (("slot_timeout", "held_client_timeout", "DEADLINE"), ("slot_abort", "held_client_abort", "ABORTED")):
        observed_fault = only([row for row in history if row["event"] == "fault_observed" and row["label"] == label], "held LIST observation")
        release = only([row for row in history if row["event"] == "hold_released" and row["label"] == label], "held LIST release")
        call = observed[call_label]
        require(call["outcome"]["error"]["code"] == code and call["response"]["event"] == "http_transport_error", "client did not actually timeout/drop")
        require(stamp(call["request"]) < stamp(observed_fault) < stamp(call["response"]) < stamp(release)
                and stamp(release) < stamp(call["request"]) + 5_000_000_000, "held job escaped the original fixed server deadline")
        held[label] = (observed_fault, release)
    probes = {"same_tenant_still_busy", "aborted_tenant_still_busy", "global_two_still_busy"}
    singleton, spare = observed["tenant_one_still_busy"], observed["spare_global_slot_empty_success"]
    require(singleton["value"].get("error", {}).get("code") == "BACKPRESSURE" and not within(objects, singleton),
            "per-tenant admission released a still-running worker")
    equal(value_of(spare), {"names": [], "cursor": None, "traversal_exhausted": True, "stopped": None},
          "unused global slot did not prove a complete authorized empty prefix")
    require(len(within(objects, spare, listing=True)) == 1, "complete empty result did not read a real LIST page")
    require(stamp(held["slot_timeout"][0]) < stamp(singleton["request"]) < stamp(singleton["response"])
            < stamp(spare["request"]) < stamp(spare["response"]) < stamp(held["slot_abort"][0]),
            "per-tenant limit was not isolated from the global-two limit")
    for label in probes | {"while_held_query", "while_held_lookup", "while_held_cancel"}:
        call = observed[label]
        for fault, release in held.values():
            require(stamp(fault) < stamp(call["request"]) < stamp(call["response"]) < stamp(release),
                    "hot/control/capacity probe did not complete while both LIST workers remained blocked")
        if label in probes:
            require(call["value"].get("error", {}).get("code") == "BACKPRESSURE", "client disconnect released a running slot early")
            require(not within(objects, call), "capacity rejection dispatched new object work")
        else:
            value_of(call)
    require(any(name.startswith("after_release_") and call.get("value", {}).get("ok") is True for name, call in observed.items()),
            "released workers never made admission available again")
    return {"seed_ready_names": 131, "observed_response_faults": 6, "invalid_cursor_bindings": len(cursors),
            "held_running_workers": 2, "hot_and_control_successes_while_blocked": 3}


def sql(data, observed, objects):
    input_row = only(data["discovery-sql-inputs.jsonl"], "native SQL input inventory")
    saved = parse(input_row["request"])
    require(fingerprint(saved["statements"]) == saved["request"]["fingerprint"], "native original SQL fingerprint changed")
    outcomes = data["discovery-sql-results.jsonl"]
    expected = {"seed_execute", "while_held_lookup", "while_held_cancel", "after_restart_lookup", "after_restart_cancel"}
    require({row["label"] for row in outcomes} == expected and len(outcomes) == len(expected), "native original result denominator changed")
    original = only([row for row in outcomes if row["label"] == "seed_execute"], "original execute ACK missing")
    for row in outcomes:
        call = observed[row["label"]]
        require(call["outcome"]["call_id"] == row["call_id"] and row["request"] == input_row["request"], "lookup/cancel retargeted original request")
        value = value_of(call)
        equal(value, {"state": "committed", "receipt": original["receipt"], "result": original["raw"]}, "full raw original result changed")
        decoded_raw, _ = committed(value)
        require(sha(decoded_raw) == row["raw_sha256"] == original["raw_sha256"] and row["raw"] == original["raw"], "native original raw ACK bytes changed")
        require(stamp(input_row) < stamp(call["request"]) < stamp(call["response"]) < stamp(row), "SQL input/ACK order")
        if row["kind"] == "execute":
            equal(call["body"], {"version": 1, "operation": "execute", **saved}, "execute input changed")
        else:
            equal(call["body"], {"version": 1, "operation": row["kind"], "scope": saved["scope"], "request": saved["request"]}, "recovery reference changed")
    execute = observed["seed_execute"]
    receipt = original["receipt"]
    witnesses = []
    for obj in within(objects, execute, listing=False):
        if obj["request"]["method"] == "PUT" and obj["request"]["key"].endswith("/head") and obj["backend"]["status"] == 200:
            head = parse(obj["incoming"])
            if head["revision"] == int(receipt["transition"]["revision"]):
                require(head["data_root"] == receipt["data_root"] and numeric_wire(head["scope"]) == saved["scope"], "ACK durable HEAD differs")
                witnesses.append(obj)
    require(len(witnesses) == 1, "native execute ACK lacks its accepted conditional HEAD")
    for label in ("while_held_query", "after_restart_query"):
        call = observed[label]
        equal(call["body"]["statements"], [{"sql": "SELECT id, label FROM witness ORDER BY id", "params": []}], "native witness query changed")
        decoded = result(b64(value_of(call)["result"]))
        require(len(decoded) == 1 and decoded[0]["rows"] == [[1, "discovery-native-witness"]], "actual SQLite business row differs")
    return {"original_execute_ack": 1, "identical_lookup_cancel_results": 4, "native_business_readbacks": 2}


def processes(data, calls, build):
    facts, http = data["process-ledger.jsonl"], data["http-client-ledger.jsonl"]
    numbered(facts)
    by = defaultdict(list)
    for row in facts:
        by[row["event"]].append(row)
    seen, lifetimes = set(), defaultdict(list)
    def register(value, end):
        ident = identity(value)
        key = (ident["pid"], ident["spawn_monotonic_ns"])
        require(key not in seen and key[1] < end and all(end <= lower or upper <= key[1] for lower, upper in lifetimes[key[0]]),
                "one owned child impersonates multiple overlapping processes")
        seen.add(key)
        lifetimes[key[0]].append((key[1], end))
    require(Counter(row["owner_instance"] for row in by["service_started"]) == Counter((7001, 7002, 7003)), "daemon inventory changed")
    for start in by["service_started"]:
        owner = start["owner_instance"]
        ready, requested, stopped, configuration = [only([row for row in by[event] if row["owner_instance"] == owner], "daemon lifetime/configuration inventory")
                                                   for event in ("service_ready", "service_stop_requested", "service_stopped", "service_configuration")]
        for row in (ready, requested):
            equal(identity(row["identity"]), identity(start["identity"]), "daemon incarnation changed")
        equal(identity(stopped), identity(start["identity"]), "daemon wait4 belongs to another child")
        register(start["identity"], stamp(stopped)); exited(stopped, -signal.SIGKILL)
        require(stamp(start) < stamp(ready) < stamp(requested) < stamp(stopped), "daemon lifetime order")
        equal(start["binary"], data["discovery-tools.json"]["server"], "actual daemon binary identity differs")
        if build["status"] != "NOT_PROVIDED":
            equal(start["binary"], build["binary"], "daemon did not execute frozen native release artifact")
        require(start["command"][0] == start["binary"]["path"] and len(start["command"]) == 2, "recorded child command differs")
        conf = configuration["configuration"]
        expected = only(by["fixture_roles"], "role fixture")["roles"]
        equal(sorted(conf["credentials"], key=lambda value: value["sha256"]),
              sorted(expected.values(), key=lambda value: value["sha256"]), "actual daemon credentials differ from observed HTTP roles")
        require(conf["worker_instance"] == str(owner) and conf["discovery"] == {"cursor_key_env": "SCAP_TEST_CURSOR_KEY"}, "actual discovery configuration differs")
    lost = only(by["all_compute_lost"], "complete compute/cache loss missing")
    require(lost["live_service_processes"] == 0 and lost["all_cache_directories_removed"] is True, "false complete compute loss")
    for owner in (7001, 7002):
        stopped = only([row for row in by["service_stopped"] if row["owner_instance"] == owner], "original daemon loss")
        removed = only([row for row in by["cache_directory_removed"] if row["owner_instance"] == owner], "original cache loss")
        start = only([row for row in by["service_started"] if row["owner_instance"] == owner], "original daemon")
        require(stopped["reason"] == "compute_loss" and stamp(stopped) < stamp(removed) < stamp(lost) and removed["exists"] is False
                and removed["cache_directory"] == start["cache_directory"], "cache loss is not real and owned")
    replacement = only([row for row in by["service_started"] if row["owner_instance"] == 7003], "replacement daemon")
    require(stamp(lost) < replacement["spawn_requested_ns"], "replacement existed before complete compute loss")
    backend, cleaned = only(by["backend_started"], "backend start"), only(by["backend_cleanup"], "backend wait4")
    require(Counter(row["role"] for row in backend["processes"]) == Counter(("master", "volume", "filer", "s3")), "backend process denominator")
    for start in backend["processes"]:
        stopped = only([row for row in cleaned["processes"] if row["role"] == start["role"]], "backend owned wait4")
        equal(identity(start), identity(stopped), "backend child identity changed")
        register(start, stamp(cleaned)); exited(stopped, -signal.SIGKILL)
    require([row["phase"] for row in by["client_phase_started"]] == list(PHASES), "required original phase order/set changed")
    require(Counter(row["phase"] for row in by["client_phase_finished"]) == Counter(PHASES), "SDK owned child completion inventory")
    for phase in PHASES:
        first, child, last = [only([row for row in by[event] if row["phase"] == phase], "SDK process lifecycle inventory")
                             for event in ("client_phase_started", "client_process_started", "client_phase_finished")]
        equal(identity(child["identity"]), identity(last["identity"]), "SDK wait4 incarnation changed")
        register(child["identity"], stamp(last)); exited(last, 0)
        hello = only([row for row in http if row["event"] == "client_process_hello" and row["phase"] == phase], "SDK self-observation")
        require(stamp(first) < stamp(hello) < stamp(last) and hello["pid_source"] == "node_process.pid", "SDK hello outside pre-Popen phase boundary")
        for call in calls.values():
            if call["request"]["phase"] == phase:
                require(stamp(hello) < stamp(call["request"]) < stamp(call["response"]) < stamp(last), "HTTP escaped its owned client")
                require(call["request"]["call_id"].startswith(f"{phase}:{hello['self_pid']}:"), "HTTP self-PID differs")
    return {"service_children": 3, "backend_children": 4, "sdk_children": len(PHASES), "all_owned_wait4": True}


def audit_data(data, build):
    equal(data["discovery-source-before.json"], data["discovery-source-after.json"], "source changed during real contract")
    calls, observed, _ = http_calls(data)
    objects, network_report = network(data, calls)
    return {"http_invocations": len(calls), "network": network_report, "pages": pages(data, observed, objects),
            "cases": cases(observed, objects, data["discovery-s3.jsonl"]), "sql": sql(data, observed, objects),
            "processes": processes(data, calls, build)}


def audit(directory, *, require_build=True):
    directory = Path(directory)
    data = read_sources(directory)
    build = build_receipt(directory, require_build)
    report = audit_data(data, build)
    for value in data["discovery-tools.json"].values():
        require(sha(Path(value["path"]).read_bytes()) == value["sha256"], "actual runtime executable changed")
    if require_build:
        manifest = parse((directory / "build-source-manifest.json").read_bytes())
        equal(data["discovery-source-before.json"], manifest["inputs"], "runtime SDK/fixture not from frozen source inventory")
    return {"schema": 1, "status": "passed" if require_build else "diagnostic", **report, "build": build,
            "source_sha256": {name: sha((directory / name).read_bytes()) for name in FILES}, "aws_standard": "NOT_RUN"}


def controls(directory):
    """Reject altered copies of actual observations; never rewrite original evidence."""
    directory = Path(directory)
    baseline = read_sources(directory)
    before = {name: sha((directory / name).read_bytes()) for name in FILES}
    def mutate_response(data, label, change):
        terminal = only([row for row in data["discovery-calls.jsonl"] if row["event"] == "call_finished" and row["label"] == label], "control label")
        response = only([row for row in data["http-client-ledger.jsonl"] if row.get("call_id") == terminal["call_id"] and row["event"] == "http_response"], "control raw response")
        parsed = parse(b64(response["body"]))
        change(parsed)
        encoded = json.dumps(parsed, separators=(",", ":")).encode()
        response["body"], response["body_sha256"] = base64.b64encode(encoded).decode(), sha(encoded)
        response["status"] = 200 if parsed["ok"] else 403
        terminal.pop("error", None)
        terminal["value"] = parsed.get("value")
    def false_empty(data):
        mutate_response(data, "fault_missing", lambda value: value.update(ok=True, value={"names": [], "cursor": None, "traversal_exhausted": True, "stopped": None}))
    def cursor_success(data):
        def replace(value):
            value.clear(); value.update(ok=True, value={"names": [], "cursor": None, "traversal_exhausted": True, "stopped": None})
        mutate_response(data, "tampered_cursor", replace)
    def omitted_inventory(data):
        mutate_response(data, "operator_inventory_first", lambda value: value["value"]["records"].pop())
    def early_release(data):
        trace = data["discovery-s3.jsonl"]
        release = only([row for row in trace if row["event"] == "hold_released" and row["label"] == "slot_timeout"], "control release")
        start = only([row for row in data["discovery-calls.jsonl"] if row["event"] == "call_started" and row["label"] == "while_held_query"], "control hot query")
        release["monotonic_ns"] = stamp(start) - 1
        trace.sort(key=stamp)
        for index, row in enumerate(trace, 1):
            row["sequence"] = index
    def missing_wait(data):
        row = only([row for row in data["process-ledger.jsonl"] if row["event"] == "service_stopped" and row["owner_instance"] == 7001], "control wait")
        row["kernel_usage"] = {"available": False, "reason": "fabricated"}
    def missing_ack(data):
        data["discovery-sql-results.jsonl"] = [row for row in data["discovery-sql-results.jsonl"] if row["label"] != "after_restart_cancel"]
    def replaced_cas(data):
        row = next(row for row in data["discovery-s3.jsonl"] if row["event"] == "request" and row["if_match"] is not None)
        row["if_match"] = '"not-the-original-exact-get"'
    def fake_cache_loss(data):
        row = only([row for row in data["process-ledger.jsonl"] if row["event"] == "cache_directory_removed" and row["owner_instance"] == 7001], "control cache")
        row["exists"] = True
    reports = []
    for name, alter in (("false_complete_empty_404", false_empty), ("tampered_cursor_false_success", cursor_success),
                        ("completed_inventory_omitted_slot", omitted_inventory), ("release_before_hot_delivery", early_release),
                        ("missing_owned_wait4", missing_wait), ("missing_original_result_recovery", missing_ack),
                        ("replaced_original_cas_condition", replaced_cas), ("false_complete_cache_loss", fake_cache_loss)):
        data = copy.deepcopy(baseline)
        alter(data)
        try:
            audit_data(data, {"status": "NOT_PROVIDED"})
        except (ValueError, KeyError, AssertionError) as error:
            reports.append({"name": name, "rejected": True, "reason": str(error)})
        else:
            raise ValueError("actual-history negative control was accepted: " + name)
    require(before == {name: sha((directory / name).read_bytes()) for name in FILES}, "negative controls changed original evidence")
    return {"status": "passed", "actual_history_mutations_rejected": reports, "original_source_sha256": before}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--diagnostic", action="store_true")
    parser.add_argument("--controls", action="store_true")
    args = parser.parse_args()
    print(json.dumps(controls(args.evidence) if args.controls else audit(args.evidence, require_build=not args.diagnostic), indent=2, sort_keys=True))
