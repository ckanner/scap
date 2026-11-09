#!/usr/bin/env python3
"""Independent original HTTP/S3/process audit; imports no discovery implementation."""
from __future__ import annotations

import argparse
import base64
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
import copy
import hashlib
import json
from pathlib import Path
import re
import signal
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit
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
          "slow_progress", "prime_hot", "hold_timeout", "one_held_probe", "hold_abort", "held_probes",
          "release_recovered", "cursor_before_loss", "restart")
ROLE_SCOPE = {"admin": ("1", "7", "11", True, False), "reader": ("1", "7", "12", False, False),
              "operator": ("1", "7", "13", False, True), "other": ("1", "8", "22", True, False),
              "third": ("1", "9", "33", False, False), "foreign": ("2", "7", "44", True, True)}
MAX_SCAN_PAGES = 128
READ_NANOSECONDS = 4_000_000_000
HTTP_NANOSECONDS = 5_000_000_000


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


class ObjectHistory(dict):
    """Index an already verified immutable history without changing witnesses."""
    def __init__(self, objects):
        super().__init__(objects)
        self.observed = sorted(objects.values(), key=lambda obj: stamp(obj["request"]))
        self.times = [stamp(obj["request"]) for obj in self.observed]

    def invocation(self, call):
        lower = bisect_right(self.times, stamp(call["request"]))
        upper = bisect_left(self.times, stamp(call["response"]))
        return self.observed[lower:upper]


def observed_requests(objects, call):
    if isinstance(objects, ObjectHistory):
        return objects.invocation(call)
    return [obj for obj in objects.values() if window(call, stamp(obj["request"]))]


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
    starts = sorted(stamp(call["request"]) for call in calls.values())
    for call in calls.values():
        call["next_invocation_ns"] = next((time for time in starts if time > stamp(call["response"])), None)
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
               "fault_armed", "fault_observed", "hold_released", "latency_armed", "latency_disabled",
               "delay_started", "delay_finished"}
    require(all(row["event"] in allowed for row in history), "unplanned S3 event")
    latency = only([row for row in history if row["event"] == "latency_armed"], "steady latency arm")
    latency_end = only([row for row in history if row["event"] == "latency_disabled"], "steady latency end")
    require(latency["label"] == latency_end["label"] == "slow_progress" and latency["seconds"] == 0.03
            and stamp(latency) < stamp(latency_end), "steady exact-GET latency contract changed")
    delayed = 0
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
        slow = request["method"] == "GET" and not request["query"] and stamp(latency) < stamp(request) < stamp(latency_end)
        require(request["latency"] == ("slow_progress" if slow else None), "steady latency selected another request")
        if slow:
            start = only(by["delay_started"], "missing exact-GET delay start")
            end = only(by["delay_finished"], "missing exact-GET delay end")
            require(start["label"] == end["label"] == "slow_progress" and start["seconds"] == 0.03
                    and stamp(backend) < stamp(start) < stamp(end) < stamp(delivery)
                    and stamp(end) - stamp(start) >= 30_000_000, "actual exact-GET delay was shorter than specified")
            delayed += 1
        else:
            require(not by["delay_started"] and not by["delay_finished"], "unplanned delayed request")
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
    return ObjectHistory(objects), {"signed_backend_requests": len(objects), "list_requests": listing_count, "versions": versions,
                     "exact_gets_with_observed_30ms_latency": delayed,
                     "original_backend_response_body_bytes": sum(len(obj["upstream"]) for obj in objects.values()),
                     "delivered_response_body_bytes": sum(len(obj["outgoing"]) for obj in objects.values())}


def within(objects, call, *, key=None, listing=None):
    return [obj for obj in observed_requests(objects, call) if stamp(obj["delivery"]) < stamp(call["response"])
            and (key is None or obj["request"]["key"] == key)
            and (listing is None or bool(obj["request"]["query"]) == listing)]


def successful_gets(objects, call, key):
    return [obj for obj in within(objects, call, key=key, listing=False) if obj["request"]["method"] == "GET"
            and obj["delivery"]["status"] == 200 and obj["upstream"] == obj["outgoing"]]


def metadata_reservation_options(gets, uncertain=None, *, declared_corruption=False, unconsumed=None):
    """Independent reconstruction of the port budget, not HTTP body byte totals."""
    used, maximum = 0, 16 * 1024 * 1024
    ordered = sorted(gets, key=lambda value: stamp(value["request"]))
    require(uncertain is None or ordered and uncertain == ordered[-1]["request"]["request_serial"],
            "metadata refund ambiguity escaped the single final GET")
    require(unconsumed is None or (uncertain is None and ordered and
            unconsumed == ordered[-1]["request"]["request_serial"]),
            "unconsumed reservation escaped the single final GET")
    choices = None
    for obj in ordered:
        key = obj["request"]["key"]
        require(key.endswith("/head") or "/catalogue/v1/" in key, "metadata scan downloaded data objects")
        bound = 256 * 1024 if key.endswith("/head") else 64 * 1024
        allowance = min(bound, maximum - used)
        require(allowance > 0, "GET dispatched after metadata budget exhausted")
        used += allowance
        if obj["request"]["request_serial"] == unconsumed:
            continue
        if obj["delivery"]["status"] == 200 and len(obj["outgoing"]) <= allowance:
            # This fixture's successful exact GETs have complete declared
            # lengths, full ranges and valid ETags. Only these earn a refund.
            corrupt_head = (declared_corruption and obj["request"]["fault"] == "head_corrupt_head"
                            and key.endswith("/head") and obj["outgoing"] == b"{}")
            require(obj["delivery"]["etag"] is not None and (obj["upstream"] == obj["outgoing"] or corrupt_head),
                    "unverified successful metadata body")
            refunded = used - allowance + len(obj["outgoing"])
            if obj["request"]["request_serial"] == uncertain:
                choices = {used, refunded}
            used = refunded
        # Missing/denied/failed GET retains its entire reservation, including
        # normal absent abort proofs. Its HTTP error text is a separate bound.
    return choices if choices is not None else {used}


def page_requests(objects, call):
    identity_value = call["identity"]
    prefix = f"scap-object/v1/{identity_value['deployment']}/"
    if call["body"]["operation"] == "list_names":
        prefix += identity_value["tenant"] + "/"
    return sorted((obj for obj in observed_requests(objects, call)
                   if obj["request"]["query"].get("prefix", obj["request"]["key"]).startswith(prefix)),
                  key=lambda obj: stamp(obj["request"]))


def list_reservation_options(lists, uncertain=None, unconsumed=None):
    """Each LIST reserves 1 MiB; only a complete successful return refunds it."""
    ordered = sorted(lists, key=lambda value: stamp(value["request"]))
    tail = uncertain if uncertain is not None else unconsumed
    require(tail is None or ordered and tail == ordered[-1]["request"]["request_serial"],
            "LIST accounting ambiguity escaped the single final operation")
    require(uncertain is None or unconsumed is None, "LIST tail has conflicting consumption proofs")
    used, choices = 0, None
    for obj in ordered:
        require(used <= 3 * 1024 * 1024, "LIST dispatched after its original byte budget exhausted")
        used += 1024 * 1024
        if obj["request"]["request_serial"] == unconsumed:
            continue
        if obj["delivery"]["status"] == 200 and obj["outgoing"] == obj["upstream"]:
            require(len(obj["outgoing"]) <= 1024 * 1024, "successful LIST exceeds its original reservation")
            refunded = used - 1024 * 1024 + len(obj["outgoing"])
            if obj["request"]["request_serial"] == uncertain:
                choices = {used, refunded}
            used = refunded
    return choices if choices is not None else {used}


def page_budget(objects, call, classified_through=0, *, natural=True):
    """Check external timing bounds and every fixed per-invocation cost limit."""
    value = value_of(call)
    real = page_requests(objects, call)
    lists = [obj for obj in real if obj["request"]["query"]]
    gets = [obj for obj in real if not obj["request"]["query"]]
    require(real and all(obj["request"]["method"] == "GET" for obj in real),
            "discovery page lacks actual read-only metadata work")
    require(len(lists) <= 4 and len(gets) <= 512,
            "discovery renewed its original LIST/exact-GET budget")
    # These are observation clocks, not dispatch clocks. A final abandoned
    # request may have been sent before its deadline and logged after it.
    cutoff = stamp(real[0]["request"]) + READ_NANOSECONDS
    require(all(stamp(obj["request"]) < cutoff for obj in real[:-1]),
            "discovery issued non-final work beyond the external four-second read bound")
    require(all(stamp(obj["delivery"]) < cutoff for obj in real[:-1]),
            "causally enabling response exceeded the external four-second read bound")
    require(all(stamp(left["delivery"]) < stamp(right["request"])
                for left, right in zip(real, real[1:])),
            "discovery metadata requests lack their synchronous response dependency")
    late = stamp(real[-1]["request"]) >= cutoff
    abandoned = None
    if late:
        final = real[-1]
        require(natural and value["stopped"] == "UNKNOWN" and value["cursor"] is not None,
                "final work exceeded the external four-second read bound without an UNKNOWN tail")
        require(final["terminal"]["event"] == "delivery_disconnected",
                "late final operation lacks explicit disconnected delivery")
        require(stamp(final["request"]) > classified_through,
                "late final operation already contributed to classified progress")
        abandoned = final["request"]["request_serial"]
    elif stamp(real[-1]["request"]) <= classified_through or not natural or value["stopped"] != "UNKNOWN":
        require(stamp(real[-1]["delivery"]) < cutoff,
                "classified response exceeded the external four-second read bound")
    uncertain, unconsumed, list_uncertain, list_unconsumed, unresolved_list = None, None, None, None, None
    if natural:
        elapsed = stamp(call["response"]) - stamp(call["request"])
        require(elapsed < HTTP_NANOSECONDS, "natural discovery page renewed its original five-second deadline")
        require(value["stopped"] in (None, "LIMIT", "UNKNOWN"), "natural continuation hid a non-deadline error")
        require(all(obj["request"]["fault"] is None for obj in real), "natural page contains an injected fault")
        if value["stopped"] == "UNKNOWN":
            require(3_500_000_000 <= elapsed and value["cursor"] is not None,
                    "natural UNKNOWN lacks its original deadline and continuation")
            final = real[-1]
            # External TCP completion cannot reveal whether the store client
            # accepted the final body before its fixed deadline. Only this last
            # unresolved GET may retain its reservation or earn its exact refund.
            if final["request"]["query"] and stamp(final["request"]) > classified_through:
                require(final["terminal"]["event"] == "delivery_disconnected",
                        "unresolved final LIST lacks disconnected delivery without classified progress")
                unresolved_list = final["request"]["request_serial"]
                if stamp(final["delivery"]) >= cutoff:
                    list_unconsumed = unresolved_list
                else:
                    list_uncertain = unresolved_list
            elif not final["request"]["query"] and stamp(final["request"]) > classified_through:
                if stamp(final["delivery"]) >= cutoff:
                    # The body was not even sent by the external upper bound;
                    # the store's original-deadline postcheck cannot refund it.
                    unconsumed = final["request"]["request_serial"]
                else:
                    uncertain = final["request"]["request_serial"]
    # The declared successful HEAD-body corruption is decoded above the store
    # port. Meter refunds its exact delivered length before the format error.
    options = metadata_reservation_options(gets, uncertain, declared_corruption=not natural, unconsumed=unconsumed)
    list_options = list_reservation_options(lists, list_uncertain, list_unconsumed)
    return {"list_pages": len(lists), "exact_gets": len(gets), "list_byte_options": list_options,
            "metadata_options": options, "uncertain_final_get": uncertain,
            "unconsumed_final_get": unconsumed, "late_final_request": abandoned,
            "unresolved_final_list": unresolved_list, "uncertain_final_list": list_uncertain,
            "unconsumed_final_list": list_unconsumed}


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


def pages(data, observed, objects, inventory_budgets=None):
    names_seen, inventory_groups, inventory_tails = 0, defaultdict(list), []
    inventory_budgets = {} if inventory_budgets is None else inventory_budgets
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
            require(value["stopped"] in (None, "LIMIT", "UNKNOWN"), "complete inventory hid an incomplete error")
            collected.extend(entry["key"] for entry in value["records"])
            require(value["completion"]["metadata_classified"] == str(len(collected)), "cumulative classification count differs")
        require(value_of(scan[-1])["cursor"] is None and len(collected) == len(set(collected)) and set(collected) == published,
                "completed deployment inventory omitted/repeated a prior permanent slot")
        inventory_tails.extend(inventory_progress(scan, objects, published, inventory_budgets))
    for call in observed.values():
        if call["body"]["operation"] != "deployment_inventory" or call.get("value", {}).get("ok") is not True:
            continue
        budget, value = inventory_budgets[call["label"]], value_of(call)
        require(value["usage"]["list_pages"] == budget["list_pages"]
                and value["usage"]["exact_gets"] == budget["exact_gets"], "reported HTTP budget differs from actual S3")
        require(value["usage"]["list_bytes"] in budget["list_byte_options"],
                "reported LIST budget differs from exact completed pages and the single original-deadline tail")
        require(value["usage"]["metadata_bytes"] in budget["metadata_options"],
                "reported metadata budget differs from exact completed GETs and the single original-deadline tail")
    return {"fresh_read_visible_names": names_seen, "permanent_metadata_keys": len(published),
            "inventory_scans": 2, "data_recovery": "not_run", "abandoned_final_operations": inventory_tails}


def classified_name_evidence(reads, creation, *, admitted_after=None):
    """Prove a stable Ready metadata view, including READ-denied candidates."""
    scope = creation["scope"]
    prefix = f"scap-object/v1/{scope['deployment']}/{scope['tenant']}/"
    def candidates(key):
        return reads[key] if admitted_after is None else [obj for obj in reads[key] if stamp(obj["request"]) > admitted_after]
    key = prefix + "catalogue/v1/name/" + sha(creation["name"].encode())
    names = [obj for obj in candidates(key) if obj["delivery"]["status"] == 200
             and numeric_wire(parse(obj["outgoing"])["creation"]) == creation
             and parse(obj["outgoing"])["state"] == "bound"]
    descriptors = [obj for obj in candidates(prefix + f"catalogue/v1/create/{creation['creator']}/{creation['operation']}")
                   if obj["delivery"]["status"] == 200 and numeric_wire(parse(obj["outgoing"])["creation"]) == creation]
    proofs = [obj for obj in candidates(prefix + f"catalogue/v1/abort-proof/{creation['creator']}/{creation['operation']}")
              if obj["delivery"]["status"] == 404]
    for head in candidates(prefix + scope["database"] + "/head"):
        if head["delivery"]["status"] != 200:
            continue
        body = parse(head["outgoing"])
        if body["lifecycle"] != "ready" or numeric_wire(body["scope"]) != scope:
            continue
        source = any(sha(obj["outgoing"]) == body["creation"]["descriptor_hash"]
                     and stamp(obj["delivery"]) < stamp(head["request"]) for obj in descriptors)
        for after in names:
            if stamp(after["request"]) <= stamp(head["delivery"]):
                continue
            before = [obj for obj in names if obj["outgoing"] == after["outgoing"]
                      and obj["delivery"]["etag"] == after["delivery"]["etag"]
                      and stamp(obj["delivery"]) < stamp(head["request"])]
            barrier = any(stamp(proof["delivery"]) < stamp(head["request"])
                          and any(stamp(prior["delivery"]) < stamp(proof["request"]) for prior in before) for proof in proofs)
            if source and before and barrier and parse(after["outgoing"])["origin"] == body["creation"]:
                return {"binding": parse(after["outgoing"]), "head": body, "through": stamp(after["delivery"])}
    return None


def classified_name(reads, creation):
    return classified_name_evidence(reads, creation) is not None


def read_map(objects, call):
    reads = defaultdict(list)
    for obj in within(objects, call, listing=False):
        reads[obj["request"]["key"]].append(obj)
    return reads


def listed(obj):
    require(obj["delivery"]["status"] == 200 and obj["outgoing"] == obj["upstream"],
            "continuation relied on a failed or altered LIST")
    root = ET.fromstring(obj["outgoing"])
    entries = []
    for node in root:
        if node.tag.rsplit("}", 1)[-1] in ("Contents", "CommonPrefixes"):
            entries.append(only([child for child in node if child.tag.rsplit("}", 1)[-1] in ("Key", "Prefix")],
                                "continuation LIST entry").text or "")
    flag = only([node for node in root if node.tag.rsplit("}", 1)[-1] == "IsTruncated"],
                "continuation LIST completeness").text
    require(flag in ("true", "false"), "continuation LIST completeness is not boolean")
    return sorted(entries), flag == "true"


def no_post_return_work(objects, call, following):
    # Intervening explicit HTTP operations (e.g. READ revocation) have their
    # own authorization and are not attributed to the earlier finished scan.
    next_invocation = call.get("next_invocation_ns") or stamp(following["request"])
    target = f"scap-object/v1/{call['identity']['deployment']}/"
    if call["body"]["operation"] == "list_names":
        target += call["identity"]["tenant"] + "/"
    require(not any(stamp(call["response"]) <= stamp(obj["request"]) < next_invocation
                    and obj["request"]["query"].get("prefix", obj["request"]["key"]).startswith(target)
                    for obj in objects.values()),
            "abandoned tail was followed by work after its original HTTP response")


def abandoned_list(objects, call, following, serial):
    final = objects[serial]
    require(final is page_requests(objects, call)[-1] and final["request"]["query"]
            and final["terminal"]["event"] == "delivery_disconnected",
            "abandoned LIST was not the one disconnected final operation")
    resumed = [obj for obj in page_requests(objects, following) if obj["request"]["query"]]
    require(resumed, "abandoned LIST has no explicit following LIST")
    equal(final["request"]["query"], resumed[0]["request"]["query"],
          "unconsumed LIST changed its original scope/phase/physical frontier")
    require(value_of(call)["cursor"] is not None and following["body"]["cursor"] == value_of(call)["cursor"],
            "unconsumed LIST did not retain its original authenticated cursor")
    no_post_return_work(objects, call, following)
    return {"call": call["label"], "operation": "LIST", "request_serial": serial,
            "resumed_request_serial": resumed[0]["request"]["request_serial"],
            "original_query": final["request"]["query"], "dispatch_time": "NOT_OBSERVED",
            "classification_from_tail": False}


def unchanged_frontier(objects, call, following, budget):
    """A finite retry may repeat a physical frontier only at a proved cutoff."""
    require(value_of(call)["stopped"] == "UNKNOWN", "unchanged frontier lacks a natural deadline cutoff")
    final = page_requests(objects, call)[-1]
    serial = final["request"]["request_serial"]
    require(serial in (budget["uncertain_final_get"], budget["unconsumed_final_get"],
                       budget["unresolved_final_list"])
            and final["terminal"]["event"] == "delivery_disconnected",
            "unchanged frontier lacks one unclassified disconnected tail")
    require(stamp(final["terminal"]) >= stamp(call["request"]) + 3_500_000_000,
            "unchanged frontier lacks tail evidence at its original cutoff")
    original = [obj for obj in page_requests(objects, call) if obj["request"]["query"]]
    resumed = [obj for obj in page_requests(objects, following) if obj["request"]["query"]]
    require(original and resumed, "unchanged frontier omitted its original or resumed LIST")
    equal(original[0]["request"]["query"], resumed[0]["request"]["query"],
          "unchanged frontier changed the exact original LIST query")
    require(following["body"]["cursor"] == value_of(call)["cursor"],
            "unchanged frontier replaced its original authenticated cursor")
    return serial


def abandoned_candidate(objects, call, following, serial, creation, *, authority, physical, prefix, delimiter=None):
    """A late observation may only belong to the exact unclassified frontier.

    This does not recover the product's dispatch timestamp. It proves a single
    admitted candidate, a disconnected final GET, and no causally later work.
    """
    final = objects[serial]
    require(final is page_requests(objects, call)[-1] and final["terminal"]["event"] == "delivery_disconnected",
            "abandoned candidate was not the one disconnected final GET")
    admitting = only([obj for obj in within(objects, call, listing=True)
                      if obj["request"]["query"]["prefix"] == prefix
                      and obj["request"]["query"].get("delimiter") == delimiter
                      and physical in listed(obj)[0]],
                     "late tail lacks its original unclassified-candidate LIST")
    scope = creation["scope"]
    tenant = f"scap-object/v1/{scope['deployment']}/{scope['tenant']}/"
    keys = {authority, tenant + "catalogue/v1/name/" + sha(creation["name"].encode()),
            tenant + f"catalogue/v1/create/{creation['creator']}/{creation['operation']}",
            tenant + f"catalogue/v1/abort-proof/{creation['creator']}/{creation['operation']}",
            tenant + scope["database"] + "/head"}
    require(final["request"]["key"] in keys,
            "late final GET belongs to an already classified or unrelated candidate")
    reads = [obj for obj in page_requests(objects, call) if not obj["request"]["query"]
             and stamp(admitting["delivery"]) < stamp(obj["request"]) <= stamp(final["request"])]
    first = next((obj for obj in reads if obj["request"]["key"] == authority), None)
    require(first is not None, "late tail lacks the unclassified candidate's original authority GET")
    require(all(obj["request"]["key"] in keys for obj in reads
                if stamp(obj["request"]) >= stamp(first["request"])),
            "late tail crossed another candidate after its unclassified authority")
    no_post_return_work(objects, call, following)
    return {"call": call["label"], "operation": "GET", "request_serial": serial, "candidate": authority,
            "admitting_list_serial": admitting["request"]["request_serial"],
            "candidate_authority_serial": first["request"]["request_serial"],
            "dispatch_time": "NOT_OBSERVED", "classification_from_tail": False}


def scan_sequence(scan, *, initial=None, bound=MAX_SCAN_PAGES):
    require(1 <= len(scan) <= bound, "explicit discovery continuation exceeded its fixed total page bound")
    for index, call in enumerate(scan):
        expected = initial if index == 0 else value_of(scan[index - 1])["cursor"]
        require(call["body"]["cursor"] == expected, "continuation reset or replaced its original authenticated cursor")
        if index:
            require(expected is not None and stamp(scan[index - 1]["response"]) < stamp(call["request"]),
                    "continuation dispatched before its original page finished")
    require(value_of(scan[-1])["cursor"] is None, "bounded explicit continuation never completed")


def name_progress(scan, objects, ordered, *, initial=None, start_after="", fault_first=False, bound=MAX_SCAN_PAGES):
    """Audit every crossed physical candidate, not changing encrypted tokens."""
    scan_sequence(scan, initial=initial, bound=bound)
    who = scan[0]["identity"]
    prefix = f"scap-object/v1/{who['deployment']}/{who['tenant']}/catalogue/v1/name/"
    expected = {prefix + sha(creation["name"].encode()): creation for creation in ordered}
    queries, frontiers = [], []
    for call in scan:
        require(call["identity"] == who, "one continuation changed its authenticated scope/principal")
        lists = [obj for obj in page_requests(objects, call) if obj["request"]["query"]]
        require(lists and all(obj["request"]["query"]["prefix"] == prefix for obj in lists),
                "name continuation lacks its actual tenant LIST")
        queries.append(within(objects, call, listing=True))
        frontiers.append(lists[0]["request"]["query"].get("start-after", ""))
    require(frontiers[0] == start_after and (not start_after or start_after in expected),
            "name continuation changed its original physical lower bound")
    covered, unknown, tails, stationary = [], 0, [], 0
    for index, call in enumerate(scan):
        lower = frontiers[index]
        upper = frontiers[index + 1] if index + 1 < len(scan) else max(expected, default="")
        natural = not (index == 0 and fault_first)
        require((upper in expected or upper == "") and lower <= upper,
                "name continuation lower bound escaped or reset its fixed candidate set")
        zero = natural and index + 1 < len(scan) and lower == upper
        if index + 1 == len(scan):
            require(queries[index], "complete names lack an actual consumed final LIST")
            entries, truncated = listed(queries[index][-1])
            require(not truncated and (not entries or entries[-1] == max(expected, default="")),
                    "complete names lack an actual exhausted final LIST")
        reads = read_map(objects, call)
        visible, through = [], 0
        page_keys = [key for key in expected if lower < key <= upper]
        require(len(page_keys) <= 128, "name continuation renewed its candidate budget")
        for key in page_keys:
            admitted = [obj for obj in queries[index] if obj["request"]["fault"] is None and key in listed(obj)[0]]
            require(admitted,
                    "name classification was not in an original successful LIST")
            witnesses = [classified_name_evidence(reads, expected[key], admitted_after=stamp(obj["delivery"])) for obj in admitted]
            witness = next((value for value in witnesses if value is not None), None)
            require(witness is not None, "natural continuation advanced past an unclassified name after its original LIST admission")
            through = max(through, witness["through"])
            if any(str(permission["principal"]) == who["principal"] and permission["read"] is True
                   for permission in witness["head"]["policy"]):
                visible.append({"creation": expected[key], "binding_revision": str(witness["binding"]["revision"]),
                                "head_revision": str(witness["head"]["revision"])})
            covered.append(key)
        equal(value_of(call)["names"], visible, "classified prefix omitted/repeated a visible name or disclosed a READ-denied name")
        budget = page_budget(objects, call, through, natural=natural)
        tail = budget["late_final_request"]
        if zero:
            tail = unchanged_frontier(objects, call, scan[index + 1], budget)
            stationary += 1
        if budget["unresolved_final_list"] is not None:
            require(index + 1 < len(scan), "unconsumed LIST falsely completed the name traversal")
            tails.append(abandoned_list(objects, call, scan[index + 1], budget["unresolved_final_list"]))
        elif tail is not None:
            pending = sorted(key for key in expected if key > upper)
            require(index + 1 < len(scan) and pending,
                    "late tail has no original cursor before an unclassified name")
            key = pending[0]
            tails.append(abandoned_candidate(objects, call, scan[index + 1], tail,
                                             expected[key], authority=key, physical=key, prefix=prefix))
        unknown += int(natural and value_of(call)["stopped"] == "UNKNOWN")
    equal(covered, [key for key in expected if key > start_after], "completed names omitted/repeated a classified candidate")
    return {"pages": len(scan), "natural_unknown_pages": unknown, "classified_candidates": len(covered),
            "complete": True, "abandoned_final_operations": tails, "unchanged_frontier_pages": stationary}


def inventory_candidate(objects, call, entry):
    """Bind a record to the LIST and exact candidate interval that admitted it."""
    scope = entry["creation"]["scope"]
    tenant = f"scap-object/v1/{scope['deployment']}/{scope['tenant']}/"
    kind = entry["kind"]
    require(kind in ("name", "create", "control", "head"), "inventory candidate kind is outside the fixed fixture")
    prefix = tenant if kind == "head" else tenant + "catalogue/v1/" + kind + "/"
    physical = entry["key"][:-4] if kind == "head" else entry["key"]
    lists = within(objects, call, listing=True)
    admitted = only([obj for obj in lists if obj["request"]["query"]["prefix"] == prefix
                     and obj["request"]["query"].get("delimiter") == ("/" if kind == "head" else None)
                     and physical in listed(obj)[0]], "inventory record lacks its unique original admitting LIST")
    lower = stamp(admitted["delivery"])
    upper = min((stamp(obj["request"]) for obj in lists if stamp(obj["request"]) > lower),
                default=stamp(call["response"]))
    phase = {serial: obj for serial, obj in objects.items() if lower < stamp(obj["request"]) < upper
             and stamp(obj["delivery"]) < upper and not obj["request"]["query"]}
    authority = successful_gets(phase, call, entry["key"])
    require(authority, "admitted inventory candidate lacks its own exact authority GET")
    lower = min(stamp(obj["request"]) for obj in authority)
    entries = listed(admitted)[0]
    following = entries[entries.index(physical) + 1:]
    # Different immutable control records may name the same creation. A later
    # record must not borrow the earlier record's Name/Proof/HEAD/Name witness.
    next_keys = {key + "head" if kind == "head" else key for key in following
                 if kind != "head" or key != tenant + "catalogue/"}
    upper = min((stamp(obj["request"]) for obj in phase.values() if obj["request"]["key"] in next_keys
                 and stamp(obj["request"]) > lower), default=upper)
    return {serial: obj for serial, obj in phase.items() if lower <= stamp(obj["request"]) < upper
            and stamp(obj["delivery"]) < upper}


def inventory_record(objects, call, entry):
    require(set(entry) == {"key", "kind", "state", "creation", "scope", "binding_revision", "head_revision", "control"},
            "inventory projection fields differ")
    creation = entry["creation"]
    require(isinstance(creation, dict) and entry["scope"] == creation["scope"], "fixture inventory lost its original creation")
    scope = creation["scope"]
    prefix = f"scap-object/v1/{scope['deployment']}/{scope['tenant']}/"
    key_by_kind = {"name": prefix + "catalogue/v1/name/" + sha(creation["name"].encode()),
                   "create": prefix + f"catalogue/v1/create/{creation['creator']}/{creation['operation']}",
                   "head": prefix + scope["database"] + "/head"}
    candidate = inventory_candidate(objects, call, entry)
    reads = read_map(candidate, call)
    if entry["kind"] in key_by_kind:
        require(entry["key"] == key_by_kind[entry["kind"]], "inventory kind/key changed")
    else:
        require(entry["kind"] == "control" and entry["key"].startswith(prefix + "catalogue/v1/control/"),
                "inventory introduced an unseeded record kind")
    require(successful_gets(candidate, call, entry["key"]), "inventory crossed a record without an exact original GET")
    witness = classified_name_evidence(reads, creation)
    if witness is not None:
        require(entry["state"] == "ready" and entry["binding_revision"] == str(witness["binding"]["revision"])
                and entry["head_revision"] == str(witness["head"]["revision"]) and entry["control"] is None,
                "inventory Ready projection differs from its stable exact view")
        return witness["through"]
    # The only non-Ready source in this fixed fixture is the unreserved dormant
    # descriptor and its immutable admitted control. Absence needs the same
    # original Name/Proof/HEAD/Name order, not a successful empty inventory.
    require(creation["name"] == "discovery-descriptor-only" and entry["kind"] in ("create", "control")
            and entry["binding_revision"] is None and entry["head_revision"] is None
            and entry["state"] == ("descriptor_only" if entry["kind"] == "create" else "control_admitted"),
            "inventory classified an unsupported or unproved metadata state")
    descriptor = key_by_kind["create"]
    sources = [obj for obj in reads[descriptor] if obj["delivery"]["status"] == 200
               and numeric_wire(parse(obj["outgoing"])["creation"]) == creation]
    names = [obj for obj in reads[key_by_kind["name"]] if obj["delivery"]["status"] == 404]
    proofs = [obj for obj in reads[prefix + f"catalogue/v1/abort-proof/{creation['creator']}/{creation['operation']}"]
              if obj["delivery"]["status"] == 404]
    heads = [obj for obj in reads[key_by_kind["head"]] if obj["delivery"]["status"] == 404]
    for after in names:
        for head in heads:
            if stamp(head["delivery"]) >= stamp(after["request"]):
                continue
            if any(stamp(source["delivery"]) < stamp(head["request"]) for source in sources) and any(
                    stamp(proof["delivery"]) < stamp(head["request"]) and any(
                        stamp(before["delivery"]) < stamp(proof["request"]) for before in names) for proof in proofs):
                return stamp(after["delivery"])
    raise ValueError("dormant inventory lacks its original stable absent view")


def inventory_layout(published):
    """The public traversal order, including empty phases and ignored prefixes."""
    root = "scap-object/v1/1/"
    tenants = sorted({root + key[len(root):].split("/", 1)[0] + "/" for key in published})
    steps, positions = [], {(root, "/", ""): 0}
    def append(kind, prefix, delimiter, key=None, record=None):
        steps.append({"kind": kind, "prefix": prefix, "delimiter": delimiter, "key": key, "record": record})
    for tenant in tenants:
        append("tenant", root, "/", tenant)
        for suffix in ("catalogue/v1/name/", "catalogue/v1/create/", "catalogue/v1/control/", "catalogue/v1/abort-proof/", ""):
            prefix, delimiter = tenant + suffix, None if suffix else "/"
            positions[(prefix, delimiter, "")] = len(steps)
            if suffix:
                entries = [(key, key) for key in sorted(published) if key.startswith(prefix)]
            else:
                entries = [(key[:-4], key) for key in sorted(published) if key.startswith(tenant) and key.endswith("/head")]
                if any(key.startswith(tenant + "catalogue/") for key in published):
                    entries.append((tenant + "catalogue/", None))
                entries.sort()
            for key, record in entries:
                append("record" if record else "ignored", prefix, delimiter, key, record)
                positions[(prefix, delimiter, key)] = len(steps)
            append("phase_end", prefix, delimiter)
        positions[(root, "/", tenant)] = len(steps)
    append("deployment_end", root, "/")
    return steps, positions


def inventory_progress(scan, objects, published, budgets=None):
    scan_sequence(scan)
    steps, positions = inventory_layout(published)
    queries, lower = [], []
    for call in scan:
        lists = [obj for obj in page_requests(objects, call) if obj["request"]["query"]]
        require(lists, "inventory continuation lacks its actual LIST")
        query = lists[0]["request"]["query"]
        checkpoint = (query["prefix"], query.get("delimiter"), query.get("start-after", ""))
        require(checkpoint in positions, "inventory continuation escaped its original physical candidates")
        lower.append(positions[checkpoint]); queries.append(within(objects, call, listing=True))
    require(lower[0] == 0, "inventory did not start at its original deployment prefix")
    classified, tails = [], []
    all_records = {entry["key"]: entry for call in scan for entry in value_of(call)["records"]}
    for index, call in enumerate(scan):
        upper = lower[index + 1] if index + 1 < len(scan) else len(steps)
        require(lower[index] <= upper, "inventory physical frontier moved backwards")
        zero = lower[index] == upper
        crossed = steps[lower[index]:upper]
        expected_records = [step["record"] for step in crossed if step["record"] is not None]
        equal([entry["key"] for entry in value_of(call)["records"]], expected_records,
              "inventory continuation skipped/repeated an unclassified physical record")
        classified.extend(expected_records)
        through = max((inventory_record(objects, call, entry) for entry in value_of(call)["records"]), default=0)
        for step in crossed:
            candidates = [obj for obj in queries[index] if obj["request"]["query"]["prefix"] == step["prefix"]
                          and obj["request"]["query"].get("delimiter") == step["delimiter"]]
            require(candidates, "inventory advanced past an unobserved traversal phase")
            if step["kind"] in ("phase_end", "deployment_end"):
                witnesses = [obj for obj in candidates if not listed(obj)[1] and (step["kind"] != "deployment_end" or not listed(obj)[0])]
                require(witnesses,
                        "inventory advanced without an actual exhausted LIST")
            else:
                witnesses = [obj for obj in candidates if step["key"] in listed(obj)[0]
                             and (step["kind"] != "tenant" or listed(obj)[0][0] == step["key"])]
                require(witnesses, "inventory classified a candidate absent from its actual LIST")
            if step["kind"] != "record":
                consumed = only(witnesses, "inventory progress lacks its one original phase LIST")
                through = max(through, stamp(consumed["delivery"]))
        minimum = sum(step["kind"] in ("record", "tenant", "ignored") for step in crossed)
        require(minimum <= value_of(call)["usage"]["candidates"] <= min(128, minimum + 1),
                "inventory candidate budget differs from its completed prefix and one possible unfinished candidate")
        budget = page_budget(objects, call, through)
        if budgets is not None:
            budgets[call["label"]] = budget
        tail = budget["late_final_request"]
        if zero:
            require(index + 1 < len(scan), "stationary inventory falsely completed the traversal")
            tail = unchanged_frontier(objects, call, scan[index + 1], budget)
        if budget["unresolved_final_list"] is not None:
            require(index + 1 < len(scan), "unconsumed LIST falsely completed the inventory traversal")
            tails.append(abandoned_list(objects, call, scan[index + 1], budget["unresolved_final_list"]))
        elif tail is not None:
            require(index + 1 < len(scan) and upper < len(steps) and steps[upper]["kind"] == "record",
                    "late inventory tail has no cursor before its unclassified record")
            pending = steps[upper]
            entry = all_records[pending["record"]]
            tails.append(abandoned_candidate(objects, call, scan[index + 1], tail, entry["creation"],
                                             authority=pending["record"], physical=pending["key"],
                                             prefix=pending["prefix"], delimiter=pending["delimiter"]))
    require(len(classified) == len(set(classified)) and set(classified) == published,
            "complete inventory did not classify its exact permanent set")
    return tails


def numbered_pages(observed, prefix):
    # "missing" and "missing_truncation" are different intentional faults.
    # Prefix-only matching would accidentally combine their recovery scans.
    values = [call for label, call in observed.items() if re.fullmatch(re.escape(prefix) + r"[0-9]+", label)]
    require([call["label"] for call in values] == [prefix + str(index) for index in range(len(values))],
            "explicit continuation page indices have a gap or reorder")
    return values


def natural_progress(observed, objects, ordered):
    def suffix(prefix):
        return numbered_pages(observed, prefix)
    resumed = suffix("reader_resume_")
    require(resumed, "reader continuation was omitted")
    original_lower = next(obj for obj in page_requests(objects, resumed[0]) if obj["request"]["query"])["request"]["query"].get("start-after", "")
    release = [call for label, call in observed.items() if re.fullmatch(r"after_release_[0-9]+", label)
               and call.get("value", {}).get("ok") is True]
    require(len(release) == 1, "admission recovery omitted or duplicated its one successful starting page")
    scans = {
        "reader_revocation": ([observed["reader_first"], *resumed], None, "", False),
        "operator_no_read": ([observed["operator_names_first"], *suffix("operator_names_resume_")], None, "", False),
        "original_cursor_positive": ([observed["original_cursor_positive"], *suffix("original_cursor_resume_")],
                                      value_of(observed["reader_first"])["cursor"], original_lower, False),
        "released_admission": ([*release, *suffix("after_release_resume_")], None, "", False),
        "fresh_before_restart": ([observed["fresh_cursor_before_loss"], *suffix("fresh_cursor_resume_")], None, "", False),
        "restart": (suffix("restart_names_"), None, "", False),
    }
    for fault in FAULTS:
        scans["fault_" + fault] = ([observed["fault_" + fault], *suffix("after_fault_" + fault + "_")], None, "", True)
    reports, covered = {}, set()
    for label, (scan, token, lower, fault) in scans.items():
        reports[label] = name_progress(scan, objects, ordered, initial=token, start_after=lower, fault_first=fault)
        covered.update(call["label"] for call in scan)
    slow = suffix("slow_progress_")
    name_progress(slow, objects, ordered, bound=16)
    covered.update(call["label"] for call in slow)
    spare = observed["spare_global_slot_empty_success"]
    name_progress([spare], objects, [])
    covered.add(spare["label"])
    expected = {label for label, call in observed.items() if call["body"]["operation"] == "list_names"
                and call.get("value", {}).get("ok") is True}
    equal(sorted(covered), sorted(expected), "successful name pages escaped independent continuation auditing")
    return reports


def slow_progress(observed, objects, history, ordered):
    scan = [call for call in observed.values() if call["request"]["phase"] == "slow_progress"]
    require(3 <= len(scan) <= 16 and [call["label"] for call in scan] == [f"slow_progress_{index}" for index in range(len(scan))],
            "steady-latency scan omitted/reordered explicit pages")
    armed = only([row for row in history if row["event"] == "latency_armed"], "steady latency arm")
    disabled = only([row for row in history if row["event"] == "latency_disabled"], "steady latency end")
    prefix = "scap-object/v1/1/7/catalogue/v1/name/"
    expected = {prefix + sha(creation["name"].encode()): creation for creation in ordered}
    frontiers, values = [], []
    for index, call in enumerate(scan):
        require(stamp(armed) < stamp(call["request"]) < stamp(call["response"]) < stamp(disabled),
                "slow scan was not covered by actual sustained latency")
        value = value_of(call)
        values.append(value)
        require(call["body"]["cursor"] == (None if index == 0 else values[index - 1]["cursor"]),
                "steady-latency continuation reset or replaced its original cursor")
        lists = [obj for obj in page_requests(objects, call) if obj["request"]["query"]]
        require(lists and all(obj["request"]["query"]["prefix"] == prefix for obj in lists),
                "steady-latency scan lacks the actual tenant LIST")
        frontiers.append(lists[0]["request"]["query"].get("start-after", ""))
        if index < len(scan) - 1:
            elapsed = stamp(call["response"]) - stamp(call["request"])
            require(value["stopped"] == "UNKNOWN" and isinstance(value["cursor"], str)
                    and value["traversal_exhausted"] is False and 3_500_000_000 <= elapsed < 5_000_000_000,
                    "scan deadline discarded a partial cursor or extended the original HTTP deadline")
        else:
            require(value["cursor"] is None and value["traversal_exhausted"] is True and value["stopped"] is None,
                    "steady-latency explicit continuation never finished")
    require(frontiers[0] == "" and all(left <= right for left, right in zip(frontiers, frontiers[1:]))
            and all(not key or key in expected for key in frontiers[1:]), "steady-latency lower bound reset/escaped its candidates")
    covered = []
    for index, call in enumerate(scan):
        upper = frontiers[index + 1] if index + 1 < len(scan) else max(expected)
        reads = defaultdict(list)
        for obj in within(objects, call, listing=False):
            reads[obj["request"]["key"]].append(obj)
        for key, creation in expected.items():
            if frontiers[index] < key <= upper:
                require(classified_name(reads, creation), "steady-latency continuation advanced past an unclassified name")
                covered.append(key)
    require(covered == list(expected), "steady-latency scan omitted/repeated a preexisting name")
    require([item["creation"] for value in values for item in value["names"]] == [ordered[0]],
            "steady-latency pagination lost/repeated an authorized name")
    return {"pages": len(scan), "unknown_pages_with_continuation": len(scan) - 1,
            "classified_preexisting_names": len(covered), "completed": True}


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
    require(isinstance(first["cursor"], str), "reader did not receive a genuine partial first page")
    ordered = sorted((value_of(observed[f"prepare_{index}"])["creation"] for index in range(129)), key=lambda row: sha(row["name"].encode()))
    revoked = ordered[-1]
    revocation = observed["revoke_last"]
    require(any(row["principal"] == "12" and row["read"] is False and row["admin"] is True for row in revocation["body"]["permissions"]), "revocation did not remove READ while preserving ADMIN")
    resumed = [call for label, call in observed.items() if label.startswith("reader_resume_")]
    require(resumed and resumed[0]["body"]["cursor"] == first["cursor"] and value_of(resumed[-1])["cursor"] is None,
            "reader continuation reset or never completed")
    for call in resumed:
        require(stamp(revocation["response"]) < stamp(call["request"]), "resume preceded actual permission revocation")
    visible = first["names"] + [item for call in resumed for item in value_of(call)["names"]]
    equal([item["creation"] for item in visible], [ordered[0]],
          "reader continuation lost/repeated its authorized name or disclosed the revoked name")
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
    require(positive["body"]["cursor"] == first["cursor"] and value_of(positive)["stopped"] in (None, "LIMIT", "UNKNOWN"),
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
        phase = "after_fault_" + label
        recovery = [value for value in observed.values() if value["request"]["phase"] == phase]
        require([value["label"] for value in recovery] == [f"{phase}_{index}" for index in range(len(recovery))],
                "fault recovery page suffixes are not contiguous canonical decimal indices")
        require(recovery and recovery[0]["body"]["cursor"] == page["cursor"] and value_of(recovery[-1])["cursor"] is None,
                "fault recovery silently restarted or omitted the explicit cursor")
        all_names = page["names"] + [item for value in recovery for item in value_of(value)["names"]]
        require([item["creation"] for item in all_names] == [ordered[0]], "fault continuation skipped/repeated an authorized name")
        if label.startswith("head_"):
            require([item["creation"] for item in page["names"]] == [ordered[0]], "HEAD fault did not occur after a classified candidate")
            lists = [obj for obj in page_requests(objects, recovery[0]) if obj["request"]["query"]]
            require(lists and lists[0]["request"]["query"].get("start-after") == "scap-object/v1/1/7/catalogue/v1/name/" + sha(ordered[0]["name"].encode()),
                    "continuation advanced to unclassified LIST page tail")
    progress = slow_progress(observed, objects, history, ordered)
    natural = natural_progress(observed, objects, ordered)
    hot = observed["while_held_query"]
    resident = only(within(objects, hot), "resident hot query performed extra object I/O")
    require(resident["request"]["method"] == "GET" and not resident["request"]["query"]
            and resident["request"]["key"] == f"scap-object/v1/1/7/{ordered[0]['scope']['database']}/head"
            and resident["delivery"]["status"] == 200, "resident hot query was not a fresh exact HEAD-only read")
    prime = observed["prime_hot_query"]
    require(prime["request"]["phase"] == "prime_hot" and stamp(prime["response"]) < stamp(hot["request"]),
            "resident probe was not explicitly primed before the holds")
    held = {}
    for label, call_label, code in (("slot_timeout", "held_client_timeout", "DEADLINE"), ("slot_abort", "held_client_abort", "ABORTED")):
        observed_fault = only([row for row in history if row["event"] == "fault_observed" and row["label"] == label], "held LIST observation")
        release = only([row for row in history if row["event"] == "hold_released" and row["label"] == label], "held LIST release")
        call = observed[call_label]
        require(call["outcome"]["error"]["code"] == code and call["response"]["event"] == "http_transport_error", "client did not actually timeout/drop")
        require(stamp(prime["response"]) < stamp(observed_fault)
                and stamp(call["request"]) < stamp(observed_fault) < stamp(call["response"]) < stamp(release)
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
            "held_running_workers": 2, "hot_and_control_successes_while_blocked": 3,
            "resident_hot_query_head_only": True, "steady_latency_progress": progress,
            "bounded_natural_continuations": natural,
            "deadline_evidence": {"external_read_bound": "causally_enabling_requests_and_delivery_starts_before_first_S3_plus_4_seconds",
                                  "exact_internal_origin": "frozen_production_received_HTTP_plus_5_seconds_minus_1_second",
                                  "internal_receive_timestamp_observed": False, "internal_dispatch_timestamp_observed": False,
                                  "late_request_exception": "one_disconnected_unclassified_final_GET_or_LIST_before_HTTP_reply",
                                  "observed_HTTP_roundtrip_under_seconds": 5}}


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
    for label in ("prime_hot_query", "while_held_query", "after_restart_query"):
        call = observed[label]
        equal(call["body"]["statements"], [{"sql": "SELECT id, label FROM witness ORDER BY id", "params": []}], "native witness query changed")
        decoded = result(b64(value_of(call)["result"]))
        require(len(decoded) == 1 and decoded[0]["rows"] == [[1, "discovery-native-witness"]], "actual SQLite business row differs")
    return {"original_execute_ack": 1, "identical_lookup_cancel_results": 4, "native_business_readbacks": 3}


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


def control_list_frontier(data, serial, after):
    """Coherent false LIST evidence reaches the semantic frontier assertion."""
    trace = data["discovery-s3.jsonl"]
    group = [row for row in trace if row.get("request_serial") == serial]
    request = only([row for row in group if row["event"] == "request"], "frontier control request")
    prefix = request["query"]["prefix"]
    require("delimiter" not in request["query"], "frontier control is for ordinary names")
    starts = {row["request_serial"]: row for row in trace if row["event"] == "request"}
    keys = {starts[row["request_serial"]]["key"] for row in trace if row["event"] == "backend_response"
            and row["status"] == 200 and stamp(row) < stamp(request)
            and starts[row["request_serial"]]["method"] == "PUT"
            and starts[row["request_serial"]]["key"].startswith(prefix)
            and starts[row["request_serial"]]["key"] > after}
    keys = sorted(keys)
    if after:
        request["query"]["start-after"] = after
    else:
        request["query"].pop("start-after", None)
    parsed = urlsplit(request["path"])
    request["path"] = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(request["query"]), parsed.fragment))
    original = only([row for row in group if row["event"] == "backend_response"], "frontier control backend")
    root = ET.fromstring(raw(original["body"]))
    namespace = root.tag.rsplit("}", 1)[0] + "}" if "}" in root.tag else ""
    for child in list(root):
        if child.tag.rsplit("}", 1)[-1] in ("Contents", "CommonPrefixes", "StartAfter", "KeyCount", "IsTruncated"):
            root.remove(child)
    if after:
        ET.SubElement(root, namespace + "StartAfter").text = after
    ET.SubElement(root, namespace + "KeyCount").text = str(min(32, len(keys)))
    ET.SubElement(root, namespace + "IsTruncated").text = str(len(keys) > 32).lower()
    for key in keys[:32]:
        node = ET.SubElement(root, namespace + "Contents")
        ET.SubElement(node, namespace + "Key").text = key
    changed = ET.tostring(root)
    for row in group:
        if row["event"] in ("backend_response", "delivery_started"):
            row["body"] = {"bytes": len(changed), "sha256": sha(changed), "base64": base64.b64encode(changed).decode()}


def control_shift_after(data, cutoff, delta):
    for values in data.values():
        if not isinstance(values, list):
            continue
        for row in values:
            if "monotonic_ns" in row and stamp(row) >= cutoff:
                value = stamp(row) + delta
                row["monotonic_ns"] = str(value) if isinstance(row["monotonic_ns"], str) else value


def control_renumber(trace):
    trace.sort(key=stamp)
    ids = {}
    for index, row in enumerate(trace, 1):
        row["sequence"] = index
        if "request_serial" in row:
            old = row["request_serial"]
            if row["event"] == "request":
                ids[old] = len(ids) + 1
            row["request_serial"] = ids[old]


def control_tail_history(data, call, originals, replacements, removed=()):
    """Build an explicitly false deadline history from complete original rows.

    A valid run need not contain a naturally late request. Counterfactual time
    compression of this one unfaulted page leaves deterministic space below
    its unchanged five-second outer bound; body/ETag/input bytes stay original.
    """
    start = stamp(call["request"])
    replacement_rows = [copy.deepcopy(row) for group in replacements.values() for row in group]
    final_time = max((stamp(row) for row in replacement_rows), default=start)
    finished = max(stamp(call["response"]), final_time + 20_000_000)
    require(finished - start < HTTP_NANOSECONDS, "negative construction escaped its original outer deadline")
    control_shift_after(data, stamp(call["response"]), finished - stamp(call["response"]))
    excluded = set(removed) | set(replacements)
    kept = sorted((copy.deepcopy(row) for serial, group in originals.items() if serial not in excluded for row in group), key=stamp)
    for index, row in enumerate(kept):
        row["monotonic_ns"] = start + 10_000_000 + index * 1000
    trace = data["discovery-s3.jsonl"]
    trace[:] = [row for row in trace if row.get("request_serial") not in set(originals) | set(replacements)]
    trace.extend(kept); trace.extend(replacement_rows)
    control_renumber(trace)


def metadata_control_counts(options, early):
    require(len(early) == 2 and len({obj["request"]["request_serial"] for obj in early}) == 2,
            "refund controls reused one earlier GET as two observations")
    refunds = [(256 * 1024 if obj["request"]["key"].endswith("/head") else 64 * 1024) - len(obj["outgoing"])
               for obj in early]
    middle = (min(options) + max(options)) // 2 if len(options) == 2 else min(options) + refunds[0] // 2
    changed = (min(options) + refunds[0], max(options) + sum(refunds), middle)
    require(len(set(changed)) == 3 and all(value not in options for value in changed),
            "refund negative controls are identical or equal a legal final-tail outcome")
    return changed


def controls(directory):
    """Reject altered copies of actual observations; never rewrite original evidence."""
    directory = Path(directory)
    baseline = read_sources(directory)
    before = {name: sha((directory / name).read_bytes()) for name in FILES}
    # A positive copy must still pass; no negative can rely on an unrelated
    # baseline failure to make this suite green.
    positive = audit_data(copy.deepcopy(baseline), {"status": "NOT_PROVIDED"})
    base_calls, base_observed, _ = http_calls(baseline)
    base_objects, _ = network(baseline, base_calls)
    base_inventory_budgets = {}
    pages(baseline, base_observed, base_objects, base_inventory_budgets)
    inventory_record_call = next(call for call in base_observed.values()
                                 if call["body"]["operation"] == "deployment_inventory"
                                 and call.get("value", {}).get("ok") is True and value_of(call)["records"])
    def mutate_response(data, label, change):
        terminal = only([row for row in data["discovery-calls.jsonl"] if row["event"] == "call_finished" and row["label"] == label], "control label")
        response = only([row for row in data["http-client-ledger.jsonl"] if row.get("call_id") == terminal["call_id"] and row["event"] == "http_response"], "control raw response")
        parsed = parse(b64(response["body"]))
        change(parsed)
        encoded = json.dumps(parsed, separators=(",", ":")).encode()
        response["body"], response["body_sha256"] = base64.b64encode(encoded).decode(), sha(encoded)
        if "content-length" in response.get("headers", {}):
            response["headers"]["content-length"] = str(len(encoded))
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
        mutate_response(data, inventory_record_call["label"], lambda value: value["value"]["records"].pop())
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
    def lost_slow_checkpoint(data):
        def replace(value):
            value.clear(); value.update(ok=False, error={"code": "DEADLINE", "message": "DEADLINE"})
        mutate_response(data, "slow_progress_0", replace)
        terminal = only([row for row in data["discovery-calls.jsonl"] if row["event"] == "call_finished"
                         and row["label"] == "slow_progress_0"], "slow checkpoint control")
        terminal.pop("value")
        terminal["error"] = {"code": "DEADLINE", "name": "ScapError"}
        response = only([row for row in data["http-client-ledger.jsonl"] if row.get("call_id") == terminal["call_id"]
                         and row["event"] == "http_response"], "slow checkpoint response")
        response["status"] = 503
    def reset_slow_cursor(data):
        terminal = only([row for row in data["discovery-calls.jsonl"] if row["event"] == "call_finished"
                         and row["label"] == "slow_progress_1"], "slow cursor control")
        request = only([row for row in data["http-client-ledger.jsonl"] if row.get("call_id") == terminal["call_id"]
                        and row["event"] == "http_request"], "slow cursor request")
        value = parse(b64(request["body"]))
        value["cursor"] = None
        encoded = json.dumps(value, separators=(",", ":")).encode()
        request["body"], request["body_sha256"] = base64.b64encode(encoded).decode(), sha(encoded)
    def nonresident_hot(data):
        _, observed, _ = http_calls(data)
        prime, hot = observed["prime_hot_query"], observed["while_held_query"]
        trace = data["discovery-s3.jsonl"]
        cold = next(row for row in trace if row["event"] == "request" and window(prime, stamp(row))
                    and row["method"] == "GET" and "/objects/" in row["key"])
        moved = [row for row in trace if row.get("request_serial") == cold["request_serial"]]
        for index, row in enumerate(moved):
            row["monotonic_ns"] = stamp(hot["request"]) + 10_000 + index
        trace.sort(key=stamp)
        for index, row in enumerate(trace, 1):
            row["sequence"] = index
    resumed = [call for label, call in base_observed.items() if label.startswith("reader_resume_")]
    ordered = sorted((value_of(base_observed[f"prepare_{index}"])["creation"] for index in range(129)),
                     key=lambda creation: sha(creation["name"].encode()))
    prefix = "scap-object/v1/1/7/catalogue/v1/name/"
    keys = [prefix + sha(creation["name"].encode()) for creation in ordered]
    reader_scan = [base_observed["reader_first"], *resumed]
    advancing = []
    for current, following in zip(reader_scan, reader_scan[1:]):
        first_list = next(obj for obj in page_requests(base_objects, current) if obj["request"]["query"])
        next_list = next(obj for obj in page_requests(base_objects, following) if obj["request"]["query"])
        lower = first_list["request"]["query"].get("start-after", "")
        upper = next_list["request"]["query"].get("start-after", "")
        if lower < upper < max(keys):
            advancing.append((current, following, first_list, next_list, lower, upper))
    require(advancing, "natural controls lack an original advancing partial page before the finite suffix")
    first, following, first_list, following_list, original_lower, lower = advancing[0]
    partial = first
    first_reads = read_map(base_objects, first)
    skipped = next(prefix + sha(creation["name"].encode()) for creation in ordered
                   if prefix + sha(creation["name"].encode()) > lower and not classified_name(first_reads, creation))

    def false_natural_completion(data):
        mutate_response(data, partial["label"], lambda value: value["value"].update(cursor=None, stopped=None, traversal_exhausted=True))

    def skipped_natural_candidate(data):
        control_list_frontier(data, following_list["request"]["request_serial"], skipped)

    def no_natural_progress(data):
        control_list_frontier(data, following_list["request"]["request_serial"], original_lower)

    def renewed_http_deadline(data):
        control_shift_after(data, stamp(first["response"]),
                            stamp(first["request"]) + 5_100_000_000 - stamp(first["response"]))

    def renewed_read_deadline(data):
        causal_tail_change(data, "non_final")

    original_objects = page_requests(base_objects, first)
    through = max(classified_name_evidence(first_reads, creation)["through"] for key, creation in zip(keys, ordered)
                  if original_lower < key <= lower)
    completed = only([obj for obj in original_objects if stamp(obj["delivery"]) == through], "control completed classification GET")
    completed_id = completed["request"]["request_serial"]
    original_ids = {obj["request"]["request_serial"] for obj in original_objects}
    original_rows = {serial: [row for row in baseline["discovery-s3.jsonl"] if row.get("request_serial") == serial]
                     for serial in original_ids}
    removed_ids = {obj["request"]["request_serial"] for obj in original_objects
                   if stamp(obj["request"]) > stamp(completed["request"])}
    extra_id = max(base_objects) + 1

    def copied_group(serial, started, *, disconnected=True, delivered=None):
        group = copy.deepcopy(original_rows[completed_id])
        require([row["event"] for row in group[:-1]] == ["request", "forwarded", "backend_response", "delivery_started"]
                and group[-1]["event"] in ("delivery_finished", "delivery_disconnected"),
                "causal negative lacks an original complete unfaulted GET")
        for index, row in enumerate(group):
            row["request_serial"], row["monotonic_ns"] = serial, started + index * 1000
        if delivered is not None:
            for row, offset in zip(group[2:], (-1000, 0, 1000)):
                row["monotonic_ns"] = delivered + offset
        group[-1]["event"] = "delivery_disconnected" if disconnected else "delivery_finished"
        return group

    def causal_tail_change(data, kind):
        # Every valid completed scan provides this earlier classification GET;
        # none of these mutations depends on naturally observing a late tail.
        start = stamp(first["request"])
        if kind in ("classified", "missing_disconnect"):
            replacements = {completed_id: copied_group(completed_id, start + 4_110_000_000,
                                                       disconnected=kind != "missing_disconnect")}
        elif kind == "non_final":
            replacements = {completed_id: copied_group(completed_id, start + 4_110_000_000),
                            extra_id: copied_group(extra_id, start + 4_120_000_000)}
        elif kind == "multiple":
            replacements = {extra_id: copied_group(extra_id, start + 4_110_000_000),
                            extra_id + 1: copied_group(extra_id + 1, start + 4_120_000_000)}
        else:
            require(kind == "prior_response", "unknown causal negative construction")
            replacements = {completed_id: copied_group(completed_id, start + 100_000_000,
                                                       delivered=start + 4_110_000_000),
                            extra_id: copied_group(extra_id, start + 4_120_000_000)}
        mutate_response(data, first["label"], lambda value: value["value"].update(stopped="UNKNOWN"))
        control_tail_history(data, first, original_rows, replacements, removed_ids)

    def post_return_work(data):
        source_id = first_list["request"]["request_serial"]
        events = copy.deepcopy(original_rows[source_id])
        started = stamp(first["response"]) + 1
        occupied = {stamp(row) for row in data["discovery-s3.jsonl"]}
        while any(started + index in occupied for index in range(len(events))):
            started += len(events)
        require(started + len(events) < first["next_invocation_ns"], "post-return negative lacks the actual inter-invocation interval")
        for index, row in enumerate(events):
            row["request_serial"], row["monotonic_ns"] = extra_id, started + index
        data["discovery-s3.jsonl"].extend(events)
        control_renumber(data["discovery-s3.jsonl"])

    def renewed_get_budget(data):
        trace = data["discovery-s3.jsonl"]
        source = next(obj for obj in page_requests(base_objects, first)
                      if not obj["request"]["query"] and obj["delivery"]["status"] == 200)
        events = [row for row in trace if row.get("request_serial") == source["request"]["request_serial"]]
        base = max(row.get("request_serial", 0) for row in trace)
        # Add actual-shaped successful GET histories inside the original call;
        # all event and invocation identities are renumbered coherently.
        for copy_index in range(513):
            for event_index, row in enumerate(events):
                added = copy.deepcopy(row)
                added["request_serial"] = base + copy_index + 1
                added["monotonic_ns"] = stamp(source["terminal"]) + 1000 + copy_index * len(events) + event_index
                trace.append(added)
        control_renumber(trace)

    inventory_options = []
    for call in base_observed.values():
        if call["body"]["operation"] != "deployment_inventory" or call.get("value", {}).get("ok") is not True:
            continue
        budget = base_inventory_budgets[call["label"]]
        early = [obj for obj in page_requests(base_objects, call)[:-1] if not obj["request"]["query"]
                 and obj["delivery"]["status"] == 200
                 and min(budget["metadata_options"]) + (256 * 1024 if obj["request"]["key"].endswith("/head") else 64 * 1024)
                 - len(obj["outgoing"]) not in budget["metadata_options"]]
        if len(early) >= 2:
            inventory_options.append((len(budget["metadata_options"]), call, budget, early))
    require(inventory_options, "metadata controls lack two distinct original causally completed GET refunds")
    _, budget_call, budget, early = max(inventory_options, key=lambda item: item[0])
    options = budget["metadata_options"]
    early_count, multiple_count, middle = metadata_control_counts(options, early[:2])

    def metadata_change(data, count):
        mutate_response(data, budget_call["label"], lambda value: value["value"]["usage"].update(metadata_bytes=count))

    completed_list = next(obj for obj in page_requests(base_objects, budget_call)[:-1]
                          if obj["request"]["query"] and obj["delivery"]["status"] == 200 and obj["upstream"] == obj["outgoing"])
    require(0 not in budget["list_byte_options"], "LIST refund control lacks positive original reservation accounting")

    def fabricated_list_refund(data):
        mutate_response(data, budget_call["label"], lambda value: value["value"]["usage"].update(list_bytes=0))

    new_controls = (
        ("natural_partial_false_complete", false_natural_completion,
         "original authenticated cursor|continuation dispatched|genuine partial first page"),
        ("natural_frontier_skipped_unclassified_key", skipped_natural_candidate,
         "advanced past an unclassified name|name classification was not in an original successful LIST"),
        ("natural_opaque_token_without_progress", no_natural_progress,
         "classified prefix omitted/repeated|unclassified disconnected tail|already classified or unrelated candidate|natural deadline cutoff|scope/phase/physical frontier"),
        ("natural_http_deadline_renewed", renewed_http_deadline, "five-second deadline"),
        ("natural_read_cutoff_renewed", renewed_read_deadline, "external four-second read bound"),
        ("natural_exact_get_budget_renewed", renewed_get_budget, "LIST/exact-GET budget"),
        ("metadata_early_get_not_refunded", lambda data: metadata_change(data, early_count), "metadata budget differs"),
        ("metadata_multiple_ambiguous_refunds", lambda data: metadata_change(data, multiple_count), "metadata budget differs"),
        ("metadata_arbitrary_intermediate_count", lambda data: metadata_change(data, middle), "metadata budget differs"),
        ("late_final_already_classified_get", lambda data: causal_tail_change(data, "classified"), "already contributed to classified progress"),
        ("late_final_missing_disconnect", lambda data: causal_tail_change(data, "missing_disconnect"), "lacks explicit disconnected delivery"),
        ("multiple_late_unconsumed_tails", lambda data: causal_tail_change(data, "multiple"), "non-final work beyond"),
        ("late_response_enabled_another_request", lambda data: causal_tail_change(data, "prior_response"), "causally enabling response exceeded"),
        ("new_work_after_original_http_return", post_return_work, "no authenticated invocation"),
        ("completed_list_fabricated_full_refund", fabricated_list_refund, "reported LIST budget differs"),
    )
    reports = []
    original_controls = (("false_complete_empty_404", false_empty), ("tampered_cursor_false_success", cursor_success),
                        ("completed_inventory_omitted_slot", omitted_inventory), ("release_before_hot_delivery", early_release),
                        ("missing_owned_wait4", missing_wait), ("missing_original_result_recovery", missing_ack),
                        ("replaced_original_cas_condition", replaced_cas), ("false_complete_cache_loss", fake_cache_loss),
                        ("slow_deadline_discarded_checkpoint", lost_slow_checkpoint), ("slow_cursor_reset", reset_slow_cursor),
                         ("nonresident_hot_query", nonresident_hot))
    for name, alter, boundary in (*((name, alter, None) for name, alter in original_controls), *new_controls):
        data = copy.deepcopy(baseline)
        alter(data)
        try:
            audit_data(data, {"status": "NOT_PROVIDED"})
        except (ValueError, KeyError, AssertionError) as error:
            require(boundary is None or re.search(boundary, str(error)) is not None,
                    "negative control rejected at an unrelated boundary: " + name + ": " + str(error))
            reports.append({"name": name, "rejected": True, "reason": str(error)})
        else:
            raise ValueError("actual-history negative control was accepted: " + name)
    require(before == {name: sha((directory / name).read_bytes()) for name in FILES}, "negative controls changed original evidence")
    return {"status": "passed", "actual_history_mutations_rejected": reports, "original_source_sha256": before,
            "positive_original_copy": {"passed": True, "http_invocations": positive["http_invocations"]},
            "natural_partial_control": {"label": partial["label"], "original_stop": value_of(partial)["stopped"]},
            "causal_tail_control": {"label": first["label"], "classified_get_serial": completed_id,
                                    "original_following_list_serial": following_list["request"]["request_serial"],
                                    "naturally_late_tail_required": False},
            "list_refund_control": {"label": budget_call["label"], "completed_list_serial": completed_list["request"]["request_serial"],
                                    "exact_legal_counts": sorted(budget["list_byte_options"]), "fabricated_count": 0},
            "metadata_tail_control": {"label": budget_call["label"], "exact_legal_counts": sorted(options),
                                      "uncertain_final_get": budget["uncertain_final_get"],
                                      "earlier_gets": [obj["request"]["request_serial"] for obj in early[:2]]}}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--diagnostic", action="store_true")
    parser.add_argument("--controls", action="store_true")
    args = parser.parse_args()
    print(json.dumps(controls(args.evidence) if args.controls else audit(args.evidence, require_build=not args.diagnostic), indent=2, sort_keys=True))
