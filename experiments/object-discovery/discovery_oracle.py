#!/usr/bin/env python3
"""Independent original-input/ACK/LIST/object/native/process/build audit.

Never reads a controller result or imports a controller/product implementation.
The complete denominator comes from original intent records and accepted S3
history; a supplied recovered Scope list is never an audit input.
"""
from __future__ import annotations

import argparse
import base64
from collections import Counter, defaultdict
import copy
import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
import re
import signal
import sqlite3
import sys
from urllib.parse import parse_qsl, quote, urlsplit
import xml.etree.ElementTree as ET

from deployment_recovery_imports import local

readers, tree, specification = local("discovery_audit_sources"), local("discovery_tree_audit"), local("discovery_spec")
seed_build_audit, catalogue_audit, wire_audit = readers.build, readers.catalogue, readers.wire
Metadata = local("discovery_metadata_audit").Metadata
Trees, envelope, head, object_prefix = tree.Trees, tree.envelope, tree.head, tree.object_prefix
DATA_CASES, DESCRIPTOR_TENANTS = specification.DATA_CASES, specification.DESCRIPTOR_TENANTS
HEAD_FORMAT, IMMUTABLE_FORMAT = specification.HEAD_FORMAT, specification.IMMUTABLE_FORMAT
INTERMEDIATE_CASES, JOB_MS, MAX_STEPS = specification.INTERMEDIATE_CASES, specification.JOB_MS, specification.MAX_STEPS
QUERY, RECOVERY_PROFILES, STEP_MS = specification.QUERY, specification.RECOVERY_PROFILES, specification.STEP_MS
discovery_build_audit = local("discovery_build_audit")

equal, fingerprint, parse, require, result = (wire_audit.equal, wire_audit.fingerprint, wire_audit.parse,
                                              wire_audit.require, wire_audit.result)
OwnedChildren, seed_receipt = seed_build_audit.OwnedChildren, seed_build_audit.receipt
head_path = catalogue_audit.head_path

FILES = ("plan.json", "facts.jsonl", "calls.jsonl", "inputs.jsonl", "acks.jsonl", "history.jsonl")
INPUT_LABELS = {case + ".base" for case in DATA_CASES} | {
    "retired.epoch-2", "retired.epoch-3", "retired.epoch-4", "native.late",
    "native.accepted_without_native_ack", "native.fill_window", "native.new_window"}
LIMITS = {"list_pages": 4096, "candidates": 65536, "exact_gets": 1_048_576,
          "list_bytes": 4 * 1024**3, "metadata_bytes": 512 * 1024**2, "data_bytes": 64 * 1024**3}


def sha(raw): return hashlib.sha256(raw).hexdigest()


def stamp(row):
    value = row["monotonic_ns"]
    require(type(value) is int and value > 0, "original monotonic clock type/range")
    return value


def one(values, message):
    require(len(values) == 1, message)
    return values[0]


def numbered(rows):
    equal([row["sequence"] for row in rows], list(range(1, len(rows) + 1)), "original ledger row missing/reordered")
    require(all(type(row["schema"]) is int and row["schema"] == 1 for row in rows), "ledger schema")
    require(all(stamp(left) < stamp(right) for left, right in zip(rows, rows[1:])), "original ledger clock order")


def byte_array(value):
    require(isinstance(value, list) and all(type(n) is int and 0 <= n <= 255 for n in value), "incomplete original byte array")
    return bytes(value)


def body(directory, row, prefix, overrides):
    length, digest = row[prefix + "_bytes"], row[prefix + "_sha256"]
    require(type(length) is int and 0 <= length <= 4 * 1024**2, "fixture body extent")
    require(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest), "original body digest shape")
    raw = overrides[digest] if digest in overrides else (directory / "s3-bodies" / digest).read_bytes()
    require(len(raw) == length and sha(raw) == digest, "original complete HTTP body changed or missing")
    return raw


def calls(ledger):
    numbered(ledger)
    starts, ends, labels = {}, {}, set()
    for row in ledger:
        number = row["call_id"]
        if row["event"] == "invoked":
            require(number not in starts and row["label"] not in labels, "duplicate original invocation")
            require(type(number) is int and number == len(starts) + 1, "call denominator gap")
            labels.add(row["label"]); starts[number] = row
        else:
            require(row["event"] in ("observed", "lost_with_process") and number in starts and number not in ends,
                    "unexpected/duplicate terminal call record")
            require(stamp(starts[number]) < stamp(row), "call terminal preceded invocation")
            ends[number] = row
    equal(sorted(starts), sorted(ends), "original invocation lacks observed or lost terminal")
    return starts, ends


def list_page(raw, request, keys):
    parsed = urlsplit(request["path"])
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    require(len(pairs) == len(dict(pairs)), "duplicate LIST query field")
    query = dict(pairs)
    require(parsed.path.rstrip("/") == "/scap-test" and
            set(query) <= {"list-type", "max-keys", "prefix", "delimiter", "start-after"} and
            query.get("list-type") == "2" and query.get("max-keys") == "32", "LIST request shape/limit")
    prefix, after, delimiter = query["prefix"], query.get("start-after"), query.get("delimiter")
    require(delimiter in (None, "/") and prefix.startswith("scap-object/v1/") and prefix.endswith("/"), "LIST prefix/mode")
    require(len(raw) <= 1024**2 and b"<!" not in raw and b"<?" not in raw[5:], "LIST XML unsafe syntax/bound")
    root = ET.fromstring(raw); ns = "{http://s3.amazonaws.com/doc/2006-03-01/}"
    require(root.tag == ns + "ListBucketResult" and not root.attrib, "LIST root")
    def scalar(name):
        values = root.findall(ns + name)
        require(len(values) <= 1, "duplicate LIST scalar")
        return None if not values else values[0].text or ""
    require(all(child.tag.removeprefix(ns) in {"Name", "Prefix", "MaxKeys", "KeyCount", "IsTruncated", "StartAfter", "Delimiter", "NextContinuationToken", "Contents", "CommonPrefixes"} for child in root), "unknown LIST structure")
    equal([scalar("Name"), scalar("Prefix"), scalar("MaxKeys"), scalar("StartAfter"), scalar("Delimiter")],
          ["scap-test", prefix, "32", after, delimiter], "LIST echoed request differs")
    observed = []
    for element, child, kind in (("Contents", "Key", "object"), ("CommonPrefixes", "Prefix", "prefix")):
        vector = []
        for value in root.findall(ns + element):
            found = value.findall(ns + child)
            require(len(found) == 1 and found[0].text, "LIST entry key missing")
            vector.append((found[0].text, kind))
        require([key for key, _ in vector] == sorted({key for key, _ in vector}, key=lambda text: text.encode()), "LIST vector duplicate/order")
        observed.extend(vector)
    observed.sort(key=lambda item: item[0].encode())
    expected = set()
    for path in keys:
        key = path.removeprefix("/scap-test/")
        if not key.startswith(prefix) or key == prefix: continue
        suffix = key[len(prefix):]
        item = (prefix + suffix.split("/", 1)[0] + "/", "prefix") if delimiter and "/" in suffix else (key, "object")
        if after is None or item[0].encode() > after.encode(): expected.add(item)
    expected = sorted(expected, key=lambda item: item[0].encode())
    equal(observed, expected[:32], "LIST omitted or invented an original accepted key/prefix")
    equal(scalar("KeyCount"), str(len(observed)), "LIST count denominator")
    more = len(expected) > 32
    equal(scalar("IsTruncated"), "true" if more else "false", "LIST falsely ended or invented continuation")
    token = scalar("NextContinuationToken")
    require(bool(observed) and isinstance(token, str) and 0 < len(token.encode()) <= 4096 if more else token is None,
            "LIST continuation token consistency")
    return {"prefix": prefix, "after": after, "entries": observed, "more": more}


def authenticated(request, payload, access, credentials, *, full):
    """Recompute the original SigV4 MAC, never trust a relay's boolean result."""
    signed = request["signing"]
    require(set(signed) == {"algorithm", "access_key_sha256", "credential_scope", "signed_headers",
                           "signature_sha256", "signed_header_values", "payload_sha256", "host", "date",
                           "verified_at_relay"}, "incomplete original signing evidence")
    names, values = signed["signed_headers"], signed["signed_header_values"]
    require(signed["verified_at_relay"] is True and signed["access_key_sha256"] in access and
            signed["algorithm"] == "AWS4-HMAC-SHA256", "actual SigV4/identity witness")
    require(isinstance(names, list) and names == sorted(set(names)) and set(values) == set(names) and
            {"host", "x-amz-date", "x-amz-content-sha256"} <= set(names) and
            not {"authorization", "cookie", "x-amz-security-token"}.intersection(names), "signed header inventory")
    require(all(isinstance(name, str) and re.fullmatch(r"[a-z0-9-]+", name) and
                isinstance(values[name], str) and values[name] == ' '.join(values[name].split()) for name in names),
            "signed header canonical spelling")
    require(values["host"] == signed["host"] and values["x-amz-date"] == signed["date"] and
            values["x-amz-content-sha256"] == signed["payload_sha256"] and
            signed["payload_sha256"] in (sha(payload), "UNSIGNED-PAYLOAD"), "signed original payload/header binding")
    for name, field in (("if-match", "if_match"), ("if-none-match", "if_none_match")):
        require(values.get(name) == request[field], "conditional request differs from authenticated headers")
    scope = signed["credential_scope"].split("/")
    require(len(scope) == 4 and scope[1:] == ["us-east-1", "s3", "aws4_request"] and
            re.fullmatch(r"[0-9]{8}", scope[0]) and re.fullmatch(r"[0-9]{8}T[0-9]{6}Z", signed["date"]) and
            signed["date"][:8] == scope[0], "SigV4 date/scope mismatch")
    require(re.fullmatch(r"[0-9a-f]{64}", signed["signature_sha256"]), "signature digest shape")
    credential = credentials.get(signed["access_key_sha256"])
    if credential is None:
        require(not full, "original signing credential bytes unavailable for full independent MAC check")
        return
    access_key, secret = credential
    require(sha(access_key.encode()) == signed["access_key_sha256"], "original credential identity changed")
    uri = urlsplit(request["path"])
    query = "&".join(quote(key, safe="-_.~") + "=" + quote(value, safe="-_.~")
                     for key, value in sorted(parse_qsl(uri.query, keep_blank_values=True)))
    canonical = "\n".join((request["method"], uri.path, query,
                           "".join(name + ":" + values[name] + "\n" for name in names),
                           ";".join(names), signed["payload_sha256"]))
    message = "\n".join((signed["algorithm"], signed["date"], signed["credential_scope"], sha(canonical.encode())))
    key = ("AWS4" + secret).encode()
    for part in scope:
        key = hmac.new(key, part.encode(), hashlib.sha256).digest()
    expected = hmac.new(key, message.encode(), hashlib.sha256).hexdigest()
    require(hmac.compare_digest(sha(expected.encode()), signed["signature_sha256"]),
            "original request method/path/headers failed independent SigV4 MAC")


def gates(history, requests, responses):
    """Each selected original request has one observed, released, bounded gate."""
    arms = [row for row in history if row["event"] == "transport_fault_armed"]
    observations = [row for row in history if row["event"] == "transport_fault_observed"]
    equal(len(arms), len(observations), "armed gate lacks its one actual observation")
    require(all("request_serial" in row or row["event"] == "transport_fault_armed" for row in history),
            "unowned original transport event")
    selected = set()
    starts = {serial: stamp(request) for serial, request in requests.items()}
    for index, armed in enumerate(arms):
        upper = stamp(arms[index + 1]) if index + 1 < len(arms) else float("inf")
        require(type(armed["occurrence"]) is int and armed["occurrence"] > 0 and
                armed["stage"] in ("before_forward", "after_response") and armed["mode"] == "hold",
                "gate selection contract changed")
        matching = sorted((request for request in requests.values() if stamp(armed) < stamp(request) < upper and
                           request["path"] == armed["path"] and request["method"] == armed["method"]), key=stamp)
        require(len(matching) >= armed["occurrence"], "gate did not select the declared original occurrence")
        request = matching[armed["occurrence"] - 1]; serial = request["request_serial"]
        require(serial not in selected, "one request impersonated two fault gates")
        selected.add(serial)
        observation = one([row for row in observations if row["request_serial"] == serial], "wrong gate request selected")
        require(observation["stage"] == armed["stage"] and observation["mode"] == armed["mode"], "gate stage changed")
        values = [row for row in history if row.get("request_serial") == serial]
        release = one([row for row in values if row["event"] == "gate_released"], "gate release missing/duplicated")
        require(type(release["abort"]) is bool and stamp(observation) < stamp(release) < upper,
                "gate release did not follow observation before next gate")
        response = responses.get(serial)
        if armed["stage"] == "before_forward":
            require(stamp(request) < stamp(observation), "pre-forward gate preceded request")
            starts[serial] = stamp(release)
        else:
            require(response is not None and stamp(response) < stamp(observation), "post-response gate preceded backend acceptance")
            equal([observation[key] for key in ("status", "response_bytes", "response_sha256", "etag")],
                  [response[key] for key in ("status", "response_bytes", "response_sha256", "etag")], "gate held another response")
        cuts = [row for row in values if row["event"] in ("object_cut_before_forward", "object_cut_after_response")]
        if release["abort"]:
            cut = one(cuts, "aborted gate did not cut exactly one request")
            require(cut["event"] == "object_cut_" + armed["stage"] and stamp(release) < stamp(cut), "wrong or early gate cut")
        else:
            require(not cuts, "nonaborted request was cut")
            continuation = one([row for row in values if row["event"] ==
                                ("object_forwarded" if armed["stage"] == "before_forward" else "object_delivery_started")],
                               "released gate did not continue")
            require(stamp(release) < stamp(continuation), "held request/response continued before release")
    require({row["request_serial"] for row in observations} == selected and
            {row["request_serial"] for row in history if row["event"] == "gate_released"} == selected,
            "unarmed fault/release event")
    # The assembler serializes all backend operations. A selected old PUT is
    # paused before forwarding, then released after a cancellation has returned.
    # Prove that fixture-specific condition from original pre-send boundaries;
    # a general concurrent history needs a graph of legal linearizations instead.
    previous = 0
    for serial in sorted(responses, key=lambda number: stamp(responses[number])):
        require(previous < starts[serial], "fixture backend intervals overlap; response-order audit is not applicable")
        previous = stamp(responses[serial])


def network(directory, history, invoked, ended, facts, overrides, credentials, deployment, *, full):
    numbered(history)
    require(not any(row["event"] == "transport_fixture_failed" for row in history), "unexplained fixture transport failure")
    serials = defaultdict(list)
    for row in history:
        if "request_serial" in row: serials[row["request_serial"]].append(row)
    equal(sorted(serials), list(range(1, len(serials) + 1)), "raw HTTP request denominator gap")
    require(serials, "no actual signed S3 requests")
    requests, responses, reads, by_call = {}, {}, defaultdict(list), defaultdict(list)
    common = ("request_serial", "call_id", "phase", "method", "path", "request_bytes", "request_sha256", "if_match", "if_none_match", "signing")
    late = one([row for row in facts if row["event"] == "late_candidate_barrier"], "late candidate barrier inventory")
    access = {row["access_key_sha256"] for row in facts if row["event"] == "backend_started"}
    require(len(access) == 1, "backend credential identity changed")
    for serial, values in serials.items():
        kinds = defaultdict(list)
        for row in values: kinds[row["event"]].append(row)
        require(set(kinds) <= {"object_request", "object_forwarded", "object_response", "object_delivery_started",
                               "object_response_delivered", "object_caller_disconnected", "object_cut_before_forward",
                               "object_cut_after_response", "transport_fault_observed", "gate_released"}, "unplanned transport event")
        request = one(kinds["object_request"], "missing/duplicate HTTP request")
        call_id = request["call_id"]; require(call_id in invoked, "S3 request lacks original caller")
        call, end = invoked[call_id], ended[call_id]
        require(request["phase"] == call["label"] and stamp(call) < stamp(request) < stamp(end), "S3 path/call interval mismatch")
        for row in values:
            if row["event"] != "gate_released":
                equal({key: row.get(key) for key in common}, {key: request.get(key) for key in common}, "wire event belongs to another original request")
        require(request["method"] in ("GET", "PUT", "DELETE"), "unplanned method")
        if "?" not in request["path"] and not request["path"].endswith("/head") and "/catalogue/v1/" not in request["path"]:
            catalogue_audit.immutable_address(request["path"])
        payload = body(directory, request, "request", overrides)
        authenticated(request, payload, access, credentials, full=full)
        if request["method"] == "PUT":
            require(request["if_none_match"] == "*" and request["if_match"] is None or
                    request["if_none_match"] is None and isinstance(request["if_match"], str) and request["if_match"], "unconditional/ambiguous PUT")
        else:
            require(not payload and request["if_match"] is None and request["if_none_match"] is None, "read/delete body or condition changed")
        if call["mode"] == "recovery": require(request["method"] == "GET", "read-only recovery wrote S3")
        if request["method"] == "DELETE": require(call["mode"] == "fixture" and call["label"] == "damage.delete_retained_result", "unexpected deletion")
        fault = one(kinds["transport_fault_observed"], "duplicate gate observation") if kinds["transport_fault_observed"] else None
        response = one(kinds["object_response"], "duplicate backend response") if kinds["object_response"] else None
        if response is None:
            require(fault is not None and fault["stage"] == "before_forward" and kinds["object_cut_before_forward"] and
                    not kinds["object_forwarded"] and not kinds["object_delivery_started"] and
                    not kinds["object_response_delivered"] and not kinds["object_caller_disconnected"] and
                    not kinds["object_cut_after_response"] and end["event"] == "lost_with_process",
                    "missing backend response without a killed pre-forward cut")
        else:
            forwarded = one(kinds["object_forwarded"], "backend response lacks one forward")
            require(stamp(request) < stamp(forwarded) < stamp(response) and response["response_origin"] == "backend", "backend interval/origin")
            require(stamp(response) < stamp(end) or serial == late["request_serial"] and end["event"] == "lost_with_process", "late unowned backend response")
            require(type(response["status"]) is int and response["status"] in (200, 204, 404, 412), "unplanned backend status")
            raw = body(directory, response, "response", overrides)
            require(not kinds["object_cut_before_forward"], "forwarded request also claims a pre-forward cut")
            exact = "?" not in request["path"]
            if response["status"] == 200 and exact: require(isinstance(response["etag"], str) and response["etag"], "success lacks same-response ETag")
            if kinds["object_cut_after_response"]:
                require(fault is not None and fault["stage"] == "after_response" and end["event"] == "lost_with_process" and
                        not kinds["object_delivery_started"] and not kinds["object_response_delivered"] and
                        not kinds["object_caller_disconnected"], "accepted cut was consumed or has no lost process")
            else:
                started = one(kinds["object_delivery_started"], "missing original delivery start")
                terminal = one(kinds["object_response_delivered"] + kinds["object_caller_disconnected"], "missing/duplicate delivery terminal")
                require(stamp(response) < stamp(started) < stamp(terminal), "delivery interval")
                for item in (started, terminal):
                    equal([item[k] for k in ("status", "response_bytes", "response_sha256", "etag")],
                          [response[k] for k in ("status", "response_bytes", "response_sha256", "etag")], "delivery changed body/ETag/status")
                if end["event"] == "observed":
                    require(stamp(started) < stamp(end) and terminal["event"] == "object_response_delivered", "observed caller never consumed its original response")
                else:
                    require(serial == late["request_serial"] or
                            stamp(started) < stamp(end) and terminal["event"] == "object_response_delivered",
                            "unexplained lost caller with delivered response")
            if fault is not None:
                released = one(kinds["gate_released"], "observed gate has no release")
                require(stamp(fault) < stamp(released), "gate released before original observation")
                if kinds["object_delivery_started"]: require(stamp(released) < stamp(kinds["object_delivery_started"][0]), "held response delivered before release")
            responses[serial] = response
        requests[serial] = request; by_call[call_id].append(serial)
    gates(history, requests, responses)
    # gates() proves the original backend intervals do not overlap. The order
    # below is therefore valid for this experiment, without rewriting clocks.
    state, births, accepted_heads, listings = {}, {}, [], {}
    for serial in sorted(responses, key=lambda value: stamp(responses[value])):
        request, response = requests[serial], responses[serial]
        path, status, method = request["path"], response["status"], request["method"]
        raw = body(directory, response if method == "GET" else request, "response" if method == "GET" else "request", overrides)
        if "?" in path:
            require(method == "GET" and status == 200, "LIST method/backend status")
            listings[serial] = list_page(raw, request, state)
            continue
        require(path.startswith("/scap-test/scap-object/v1/") and "#" not in path, "exact object outside authority")
        previous = state.get(path)
        if method == "GET":
            require(status in (200, 404), "exact GET status")
            if status == 404: require(previous is None, "false 404 for persistent accepted object")
            else:
                require(previous is not None, "GET version omitted from raw accepted history")
                require(response["etag"] == previous["etag"] and raw == previous["raw"], "GET body/ETag are not the same accepted version")
            reads[request["call_id"]].append((request, response))
        elif method == "DELETE":
            require(status in (200, 204) and previous is not None, "fixture deletion lacks an original dependency")
            del state[path]
        else:
            matches = previous is None if request["if_none_match"] == "*" else previous is not None and request["if_match"] == previous["etag"]
            require((status == 200 and matches) or (status == 412 and not matches), "S3 condition/status contradicts original version chain")
            if status == 200:
                if "/objects/" in path: require(request["if_none_match"] == "*" and path.rsplit("/", 1)[1] == sha(raw), "immutable path/body/condition")
                if path.endswith("/head"):
                    authority = head(raw, path)
                    old = head(previous["raw"], path) if previous is not None else None
                    catalogue_audit.head5_audit.advance(old, authority)
                    if previous is not None:
                        equal(authority["scope"], old["scope"], "permanent physical slot was reused")
                        require(authority["revision"] == old["revision"] + 1, "HEAD skipped/reused a revision")
                    accepted_heads.append((request, response, authority))
                state[path] = {"raw": raw, "etag": response["etag"], "serial": serial}
                births.setdefault(path, stamp(response))
    require(responses[late["request_serial"]]["status"] == 412, "late old candidate was not rejected by its saved condition")
    require(any(page["more"] and page["prefix"] == f"scap-object/v1/{deployment}/" for page in listings.values()), "real deployment-root pagination was not exercised")
    return {"requests": requests, "responses": responses, "reads": reads, "calls": by_call,
            "objects": {key: value["raw"] for key, value in state.items()}, "versions": state,
            "births": births, "heads": accepted_heads, "listings": listings}


def processes(directory, facts, invoked, ended, builds, *, full):
    numbered(facts)
    registry = OwnedChildren()
    credentials = {}
    spawned = {row["worker"]: row for row in facts if row["event"] == "worker_spawned"}
    starts = {row["worker"]: row for row in facts if row["event"] == "worker_started"}
    stops = {row["worker"]: row for row in facts if row["event"] == "worker_stopped"}
    require(len(spawned) == sum(row["event"] == "worker_spawned" for row in facts) and
            len(starts) == sum(row["event"] == "worker_started" for row in facts) and
            len(stops) == sum(row["event"] == "worker_stopped" for row in facts), "duplicate child lifecycle")
    equal(sorted(spawned), sorted(starts), "spawned child lacks ready handshake")
    equal(sorted(starts), sorted(stops), "original worker process not reaped")
    require({row["mode"] for row in starts.values()} == {"seed", "recovery"}, "missing seed/recovery process separation")
    for worker, start in starts.items():
        spawn, stop = spawned[worker], stops[worker]
        ident = start["identity"]
        equal(ident, spawn["identity"], "ready identity differs from Popen")
        equal(ident, stop["identity"], "wait4 belongs to another child")
        registry.register(ident, stamp(stop))
        require(ident["spawn_monotonic_ns"] <= stamp(spawn) < stamp(start) < stamp(stop), "worker lifecycle interval")
        ready = start["ready"]
        require(ready["ready"] is True and ready["resources"]["namespace_pid"] == ident["pid"] and
                type(ready["resources"]["start_ticks"]) is int and ready["resources"]["start_ticks"] > 0,
                "worker self identity differs from owned child")
        require(stop["wait_status"] == -signal.SIGKILL and stop["kernel_usage"].get("available") is True and
                stop["kernel_usage"].get("source") == "kernel_wait4_owned_child", "worker loss has no actual kernel wait4 proof")
        requested = one([row for row in facts if row["event"] == "worker_stop_requested" and row["worker"] == worker], "worker stop request inventory")
        equal(requested["identity"], ident, "stop requested for another child")
        require(stamp(start) < stamp(requested) < stamp(stop), "stop request interval")
        for key in ("mode", "config", "config_path", "config_sha256", "binary"):
            equal(start[key], spawn[key], "runtime identity changed during handshake")
        mode = start["mode"]; binary = builds["seed" if mode == "seed" else "recovery"]["binary"]
        equal(start["binary"], binary, "actual child did not execute the frozen release binary")
        config = start["config"]
        require(config["worker"] == worker and config["bucket"] == "scap-test" and config["region"] == "us-east-1", "runtime namespace/worker config")
        path = Path(start["config_path"])
        if path.exists():
            raw = path.read_bytes(); require(sha(raw) == start["config_sha256"], "original runtime configuration bytes changed")
            actual = parse(raw)
            require(isinstance(actual.get("access_key"), str) and isinstance(actual.get("secret_key"), str), "missing actual S3 runtime credentials")
            equal({key: value for key, value in actual.items() if key not in ("access_key", "secret_key")}, config, "recorded public config differs from executed config")
            key = sha(actual["access_key"].encode())
            pair = (actual["access_key"], actual["secret_key"])
            require(key not in credentials or credentials[key] == pair, "original signing credentials changed between compute incarnations")
            credentials[key] = pair
        else:
            require(not full, "original runtime configuration unavailable in full audit")
        if mode == "recovery":
            require(set(config) == {"endpoint", "region", "bucket", "worker", "cache_root", "artifact_root", "deployment", "readers", "job_budget_ms"},
                    "recovery config accepted a hidden Scope/name/input denominator")
            require(ready["configuration_schema"] == "deployment-root-only-v1", "recovery executable lacks root-only schema")
            equal(ready["configuration_sha256"], start["config_sha256"], "child did not load original config bytes")
            equal(ready["configuration"], config, "actual recovery configuration differs from recorded trusted configuration")
            require(config["job_budget_ms"] == JOB_MS, "whole-job deadline changed")
        else:
            require(config["principal"] == 17 and config["provision"] is True, "fixture caller changed")
        worker_calls = [call for call in invoked.values() if call["worker"] == worker]
        previous = stamp(start)
        for call in worker_calls:
            terminal = ended[call["call_id"]]
            require(previous < stamp(call) < stamp(terminal), "one worker has overlapping calls")
            if terminal["event"] == "lost_with_process":
                require(stamp(call) < stamp(requested) < stamp(stop) <= stamp(terminal), "lost call lacks actual process exit boundary")
            else:
                require(stamp(terminal) < stamp(requested), "observed call completed after worker stop")
            equal(call["identity"], ident, "call bound to another process")
            require(call["mode"] == mode, "call changed worker role")
            previous = stamp(ended[call["call_id"]])
    backend_starts = [row for row in facts if row["event"] == "backend_started"]
    backend_stops = [row for row in facts if row["event"] == "backend_stopped"]
    equal([row["stage"] for row in backend_starts], ["initial", "after_seed", "after_interrupted"], "backend reconstruction inventory")
    equal([row["stage"] for row in backend_stops], ["seed", "interrupted", "finished"], "backend loss inventory")
    for start, stop in zip(backend_starts, backend_stops):
        require("4.51" in start["version"], "unpinned actual S3 backend")
        binary = Path(start["binary"]["path"])
        if binary.is_file(): require(discovery_build_audit.file_digest(binary) == start["binary"]["sha256"], "actual backend binary changed")
        else: require(not full, "actual S3 backend bytes unavailable in full audit")
        begin, finish = start["identities"], stop["identities"]
        require(len(begin) == 4 and len(finish) == 4 and {value["role"] for value in begin} == {"master", "volume", "filer", "s3"}, "backend role denominator")
        for child in begin:
            terminal = one([value for value in finish if value["role"] == child["role"]], "backend role terminal")
            equal({key: terminal[key] for key in child}, child, "backend role changed process identity")
            require(terminal["wait_status"] == -signal.SIGKILL and terminal["kernel_usage"].get("available") is True and
                    terminal["kernel_usage"].get("source") == "kernel_wait4_owned_child", "backend process loss not witnessed")
            registry.register(child, stamp(stop))
            require(child["spawn_monotonic_ns"] < stamp(start) < stamp(stop), "backend incarnation interval")
    for stage in ("seed", "interrupted"):
        begin = one([row for row in facts if row["event"] == "compute_loss_started" and row["stage"] == stage], "full compute loss start")
        removed = one([row for row in facts if row["event"] == "compute_removed" and row["stage"] == stage], "complete local cache removal")
        complete = one([row for row in facts if row["event"] == "compute_loss_completed" and row["stage"] == stage], "full compute loss completion")
        require(stamp(begin) < stamp(removed) < stamp(complete) and removed["exists"] is False and complete["root_only_restart"] is True, "incomplete compute-loss chain")
        live = [worker for worker in starts if stamp(starts[worker]) < stamp(begin) < stamp(stops[worker])]
        equal(sorted(begin["live_workers"]), sorted(live), "full loss omitted an actual live compute process")
        require(all(stamp(stops[worker]) < stamp(removed) for worker in starts if stamp(starts[worker]) < stamp(begin)), "cache removed while old compute remained live")
        if full:
            require(all(not Path(starts[worker]["config"]["cache_root"]).exists() for worker in starts if stamp(starts[worker]) < stamp(begin)), "old compute cache survived global loss")
    seed_loss = one([row for row in facts if row["event"] == "compute_loss_completed" and row["stage"] == "seed"], "missing initial loss")
    require(all(stamp(start) > stamp(seed_loss) for start in starts.values() if start["mode"] == "recovery"), "recovery reused pre-loss compute")
    require(all(stamp(end) < stamp(seed_loss) for worker, end in stops.items() if starts[worker]["mode"] == "seed"), "seed compute survived into recovery")
    return starts, credentials


def durable_closure(paths, publication, call, wire):
    """ACK dependencies exist first; newly published bytes were actually reread."""
    for path in paths:
        born = wire["births"].get(path)
        require(born is not None and born < stamp(publication), "ACK preceded full durable dependency closure")
        if born > stamp(call):
            accepted = [(request, wire["responses"][serial]) for serial, request in wire["requests"].items()
                        if request["call_id"] == call["call_id"] and request["method"] == "PUT" and request["path"] == path and
                        serial in wire["responses"] and wire["responses"][serial]["status"] == 200]
            upload, response = one(accepted, "new ACK dependency lacks its own conditional durable upload")
            require(upload["if_none_match"] == "*" and stamp(response) == born, "new dependency was not immutable conditional create")
            require(any(request["path"] == path and received["status"] == 200 and
                        born < stamp(request) < stamp(received) < stamp(publication) and
                        received["response_sha256"] == upload["request_sha256"] and received["etag"] == response["etag"]
                        for request, received in wire["reads"][call["call_id"]]),
                    "new ACK dependency has no complete same-call readback before HEAD")


def current_entries(authority, objects):
    tree = Trees(objects, authority)
    return [entry for window in authority["windows"] for entry in tree.index(window, authority)["entries"]]


def originals(directory, inputs, acks, invoked, ended, starts, facts, wire, metadata):
    numbered(inputs); numbered(acks)
    require(all(row["event"] == "input" for row in inputs) and
            {row["label"] for row in inputs} == INPUT_LABELS and len(inputs) == len(INPUT_LABELS),
            "original SQL input denominator differs from the frozen experiment")
    equal([row["intent_id"] for row in inputs], list(range(1, len(inputs) + 1)), "original SQL intent identity gap")
    data_cases = [row for row in facts if row["event"] == "data_case_seeded"]
    equal(Counter(row["case"] for row in data_cases), Counter(DATA_CASES), "data fixture scope denominator")
    creation_cases = [row for row in facts if row["event"] == "creation_prepared"]
    expected_creations = {f"descriptor-{tenant}" for tenant in DESCRIPTOR_TENANTS} | set(INTERMEDIATE_CASES) | {"reuse_old", "reuse_new"}
    require(len(creation_cases) == len(expected_creations) and {row["case"] for row in creation_cases} == expected_creations,
            "deployment tenant/name source denominator")
    for created in creation_cases:
        call = one([call for call in invoked.values() if call["label"] == created["case"] + ".prepare"], "creation lacks original prepare invocation")
        require(call["request"]["op"] == "catalogue_prepare", "creation source not prepared by production")
        terminal = ended[call["call_id"]]
        require(terminal["event"] == "observed" and terminal["response"]["ok"] is True, "creation has no acknowledged immutable descriptor")
        equal(terminal["response"]["value"]["creation"], created["creation"], "creation fact differs from actual response")
        source = metadata.descriptor(created["creation"])["value"]
        equal(source["creation"], created["creation"], "accepted source differs from original prepare")
        require(created["creation"]["creator"] == 17 and created["creation"]["scope"]["tenant"] == starts[call["worker"]]["config"]["scope"]["tenant"], "creation escaped caller namespace")
        if created["case"].startswith("descriptor-"):
            tenant = int(created["case"].removeprefix("descriptor-"))
            require(created["creation"]["scope"]["tenant"] == tenant and created["creation"]["operation"] == 1,
                    "an unconfigured deployment tenant was omitted/substituted")
    execute_calls = [call for call in invoked.values() if call["request"]["op"] in ("execute", "session_execute")]
    require(len(execute_calls) == len(inputs) and {call["intent_id"] for call in execute_calls} == {row["intent_id"] for row in inputs}, "SQL execute/input one-to-one denominator")
    observed_acks = {call["call_id"] for call in execute_calls if ended[call["call_id"]]["event"] == "observed"
                     and ended[call["call_id"]]["response"].get("ok") is True}
    require(all(row["event"] == "ack" for row in acks) and len(acks) == len(observed_acks) and
            {row["call_id"] for row in acks} == observed_acks, "ACK ledger omitted/invented a successful original SQL response")
    for ack in acks:
        call, terminal = invoked[ack["call_id"]], ended[ack["call_id"]]
        equal(ack["intent_id"], call["intent_id"], "ACK belongs to another input")
        equal(ack["response"], terminal["response"], "ACK result differs from original client response")
        require(ack["observed_ns"] == stamp(terminal) < stamp(ack), "ACK predates actual observation")
    prepared = {row["intent_id"]: row for row in facts if row["event"] == "request_prepared"}
    require(len(prepared) == len(inputs), "prepared request identity denominator")
    expected_rows, outcomes, original_results, retained = defaultdict(dict), {}, {}, {}
    input_files = set()
    for intent in inputs:
        body_info = intent["input_body"]
        require(set(body_info) == {"file", "bytes", "sha256"} and body_info["file"] == body_info["sha256"], "original random input reference")
        original = (directory / "input-bodies" / body_info["file"]).read_bytes()
        require(len(original) == body_info["bytes"] == 4096 and sha(original) == body_info["sha256"], "full pre-invocation input BLOB missing/changed")
        input_files.add(body_info["file"])
        statements = intent["statements"]
        base = intent["label"].endswith(".base")
        require(len(statements) == (2 if base else 1), "fixture SQL statement denominator")
        if base: equal(statements[0], {"sql": "CREATE TABLE data(id INTEGER PRIMARY KEY,value BLOB NOT NULL,token BLOB NOT NULL)"}, "schema intent changed")
        insertion = statements[-1]
        require(insertion["sql"] == f"INSERT INTO data VALUES({intent['row']},?,randomblob(16)) RETURNING id,value,token", "original SQL effect changed")
        parameter = one(insertion["parameters"], "original BLOB parameter count")
        require(parameter["type"] == "blob_file" and parameter["offset"] == 0 and parameter["length"] == len(original) and parameter["sha256"] == sha(original), "original full input parameter changed")
        require(Path(parameter["path"]).name == body_info["file"], "original BLOB invocation selected another file")
        public = [{"sql": item["sql"], "params": [] if n < len(statements)-1 else [{"type": "blob", "base64": base64.b64encode(original).decode()}]} for n, item in enumerate(statements)]
        identity = {"epoch": intent["epoch"], "id": intent["id"], "principal": intent["principal"], "fingerprint": fingerprint(public)}
        equal(prepared[intent["intent_id"]]["identity"], identity, "prepared identity differs from independent complete SQL/input fingerprint")
        prep = one([call for call in invoked.values() if call["label"] == intent["label"] + ".prepare"], "missing original prepare-request call")
        call = one([call for call in execute_calls if call["intent_id"] == intent["intent_id"]], "input executed twice or lost")
        require(stamp(intent) < stamp(prep) < stamp(ended[prep["call_id"]]) < stamp(call), "input bytes were not recorded before preparation/execution")
        equal(ended[prep["call_id"]]["response"]["value"], identity, "worker prepare response differs from original fingerprint")
        for invocation in (prep, call):
            command = invocation["request"]
            equal(command["statements"], statements, "execution changed original SQL or BLOB binding")
            require(command["epoch"] == intent["epoch"] and command["id"] == intent["id"], "execution changed retry identity")
            equal(starts[invocation["worker"]]["config"]["scope"], intent["scope"], "input invoked under another complete Scope")
        terminal = ended[call["call_id"]]
        slot = head_path(intent["scope"])
        if intent["label"] == "native.late":
            require(terminal["event"] == "lost_with_process" and call["call_id"] not in observed_acks, "late cancelled candidate became an ACK")
            barrier = one([row for row in facts if row["event"] == "late_candidate_barrier"], "late input cancellation denominator")
            cancellation = one([candidate for candidate in invoked.values() if candidate["label"] == "native.cancel_late"],
                               "late input lost original cancel invocation")
            equal(cancellation["request"], {"op": "cancel", "epoch": intent["epoch"], "id": intent["id"],
                                            "statements": statements}, "cancel changed original retry identity/input")
            require(barrier["intent_id"] == intent["intent_id"], "cancellation attached to another original input")
            retained.setdefault(slot, current_entries(metadata.heads[slot], wire["objects"]))
            entry = one([entry for entry in retained[slot] if entry["request"] == identity], "current authority dropped a retained cancellation")
            equal(entry["outcome"], {"state": "cancelled", "transition": barrier["response"]["transition"]},
                  "current authority replaced original cancellation barrier")
            outcomes[intent["intent_id"]] = "cancelled"
            continue
        require(terminal["event"] == "observed", "original accepted input lost its terminal")
        response = terminal["response"]
        unavailable = intent["label"] == "native.accepted_without_native_ack"
        if unavailable:
            require(response["ok"] is False and response["error_details"]["kind"] == "committed_but_unavailable" and
                    call["call_id"] not in observed_acks, "native failure was counted as a successful ACK")
            receipt = response["error_details"]["receipt"]
        else:
            require(response["ok"] is True and call["call_id"] in observed_acks, "acknowledged fixture input has no ACK")
            receipt = response["value"]["receipt"]
        equal(receipt["scope"], intent["scope"], "receipt complete Scope differs")
        equal(receipt["request"], identity, "receipt lost original request identity")
        publication = one([(request, received, authority) for request, received, authority in wire["heads"]
                           if request["call_id"] == call["call_id"] and authority["scope"] == intent["scope"] and
                           authority["transition"] == receipt["transition"] and authority["sequence"] == receipt["sequence"] and
                           authority["data_root"] == receipt["data_root"]], "original result lacks its own accepted HEAD publication")
        request, received, authority = publication
        require(stamp(received) < stamp(terminal), "ACK/native response preceded S3 acceptance")
        tree = Trees(wire["objects"], authority)
        dependencies, _ = tree.data(authority["data_root"])
        entries = []
        for window in authority["windows"]:
            proof = tree.index(window, authority); dependencies |= proof["dependencies"]; entries.extend(proof["entries"])
        entry = one([entry for entry in entries if entry["request"] == identity], "accepted HEAD omitted its original request")
        require(entry["outcome"] == {"state": "committed", "result": receipt["result_hash"]}, "accepted HEAD bound another original result")
        durable_closure(dependencies, request, call, wire)
        result_path = object_prefix(authority) + receipt["result_hash"]
        kind, stored, encoded = envelope(wire["objects"][result_path], result_path, authority)
        require(kind == "result", "receipt points at another object type")
        equal({key: stored[key] for key in ("request", "sequence", "transition", "data_root")},
              {key: receipt[key] for key in ("request", "sequence", "transition", "data_root")}, "original stored result identity/transition differs")
        if not unavailable:
            equal(encoded, byte_array(response["value"]["result"]["encoded"]), "original ACK result bytes changed")
        decoded = result(encoded)
        require(len(decoded) == len(statements), "original result statement count changed")
        last = decoded[-1]
        equal(last["columns"], ["id", "value", "token"], "original returning columns")
        row = one(last["rows"], "original insert result row denominator")
        require(len(row) == 3 and type(row[0]) is int and row[0] == intent["row"] and row[1] == original and
                isinstance(row[2], bytes) and len(row[2]) == 16 and last["affected_rows"] == 1,
                "original result does not preserve complete input and nondeterministic output")
        require(row[0] not in expected_rows[slot], "original input reused one effect key")
        expected_rows[slot][row[0]] = row
        original_results[intent["intent_id"]] = {"receipt": receipt, "encoded": encoded, "row": row, "call_id": call["call_id"]}
        current = metadata.heads[slot]
        if current["lifecycle"] == "deleted":
            require(intent["label"] == "reuse_old.base", "unplanned historical ACK deleted")
            source = one([value["creation"] for value in creation_cases if value["case"] == "reuse_old"], "old name source")
            metadata.deleted(source, current); outcomes[intent["intent_id"]] = "deleted_barrier"
        elif identity["epoch"] < max(1, current["request_epoch"] - 2):
            outcomes[intent["intent_id"]] = "retired_barrier"
        else:
            retained.setdefault(slot, current_entries(current, wire["objects"]))
            current_entry = one([entry for entry in retained[slot] if entry["request"] == identity],
                                "current authority omitted a retained original ACK/UNKNOWN result")
            equal(current_entry, entry, "current retained result changed original identity/outcome/bytes")
            outcomes[intent["intent_id"]] = "retained_committed_without_native_ack" if unavailable else "retained_ack"
    equal(sorted(path.name for path in (directory / "input-bodies").iterdir()), sorted(input_files), "original input byte archive denominator")
    require(Counter(outcomes.values()) == Counter({"retained_ack": 8, "retired_barrier": 2, "deleted_barrier": 1,
                                                  "retained_committed_without_native_ack": 1, "cancelled": 1}),
            "input/ACK/UNKNOWN/barrier outcomes changed")
    return expected_rows, outcomes, original_results


def recovery_profiles(directory, invoked, ended, starts, facts, wire, metadata, expected_rows, overrides):
    begun = [row for row in facts if row["event"] == "recovery_profile_started"]
    finished = [row for row in facts if row["event"] == "recovery_profile_finished"]
    equal([row["profile"] for row in begun], list(RECOVERY_PROFILES), "recovery profile denominator/order")
    equal([row["profile"] for row in finished], list(RECOVERY_PROFILES), "recovery profile terminal denominator")
    require(len({row["worker"] for row in begun}) == len(begun), "recovery profiles reused one runtime job")
    expected = metadata.expected()
    expected_heads = metadata.heads
    needed = {key for key, value in expected_heads.items() if value["lifecycle"] in ("ready", "maintenance")}
    no_data = set(expected_heads) - needed
    require(len(needed) == 5 and len(no_data) >= 4, "actual ready/maintenance and permanent-barrier fixture denominator")
    require(any(value["kind"] == "OrphanPrefix" for value in expected.values()), "unreachable physical prefix was not classified")
    report = {}; native_files = set()
    for begin, finish in zip(begun, finished):
        profile, worker = begin["profile"], begin["worker"]
        require(worker == finish["worker"] and starts[worker]["mode"] == "recovery", "profile uses another worker")
        config = starts[worker]["config"]
        wanted_readers = {"2": 17, "10": 17, "99": 18}
        if profile == "missing_reader": wanted_readers.pop("99")
        if profile == "admin_without_read": wanted_readers["99"] = 17
        equal(config["readers"], wanted_readers, "trusted reader selection changed")
        require(config["deployment"] == int(metadata.root.split("/")[4]), "recovery deployment root changed")
        selected = [call for call in invoked.values() if call["worker"] == worker]
        steps = [call for call in selected if call["request"]["op"] == "step"]
        require(steps and len(steps) <= MAX_STEPS, "recovery step bound")
        equal([call["label"] for call in steps], [f"{profile}.step-{number}" for number in range(1, len(steps)+1)], "step input labels are not canonical contiguous indices")
        observed, recovered, nonrequired, previous_usage = {}, set(), set(), {key: 0 for key in LIMITS}
        expected_labels = set(); last = None
        dependency_count = native_bytes = row_count = 0
        for number, call in enumerate(steps, 1):
            require(call["mode"] == "recovery" and call["intent_id"] is None and
                    call["request"] == {"op": "step", "budget_ms": STEP_MS}, "recovery step accepted a hidden scope/frontier/denominator")
            terminal = ended[call["call_id"]]
            require(terminal["event"] == "observed" and terminal["response"]["ok"] is True, "recovery step lacked its actual production response")
            value = terminal["response"]["value"]
            require(set(value) == {"step", "metadata", "completion", "usage", "stopped", "recovered_head", "native"} and value["step"] == number, "recovery response shape/step")
            expected_labels.add(call["label"])
            usage, progress, observation = value["usage"], value["completion"], value["metadata"]
            require(set(usage) == set(LIMITS) and all(type(usage[key]) is int and previous_usage[key] <= usage[key] <= LIMITS[key] for key in LIMITS), "whole-job cost reset/exceeded/changed")
            previous_usage = usage
            reads = wire["reads"][call["call_id"]]
            if observation is not None:
                path = "/scap-test/" + observation["key"]
                require(path in expected and path not in observed, "metadata omitted frontier or repeated a classified record")
                equal(observation, expected[path], "reported typed metadata differs from actual complete authority")
                metadata.witnessed(observation, reads)
                observed[path] = observation
                if observation["kind"] == "Head" and path in no_data:
                    nonrequired.add(path)
            if value["recovered_head"] is not None:
                authority = value["recovered_head"]; slot = head_path(authority["scope"])
                require(slot in needed and slot not in recovered and observation is not None and observation["kind"] == "Head" and
                        observation["scope"] == authority["scope"] and value["stopped"] is None, "recovered image lacks one actual required permanent slot")
                equal(authority, expected_heads[slot], "recovered native image used another current HEAD")
                principal = wanted_readers.get(str(authority["scope"]["tenant"]))
                require(principal is not None and any(permission["principal"] == principal and permission["read"] is True for permission in authority["policy"]), "inventory/provision/ADMIN was used as READ")
                actual = {}
                for request, received in reads:
                    if received["status"] == 200:
                        actual[request["path"]] = body(directory, received, "response", overrides)
                require(slot in actual, "native restoration has no same-call exact HEAD")
                equal(head(actual[slot], slot), authority, "native HEAD body differs from the actual GET")
                tree = Trees(actual, authority)
                dependencies, image = tree.data(authority["data_root"])
                entries = []
                for window in authority["windows"]:
                    proof = tree.index(window, authority); dependencies |= proof["dependencies"]; entries.extend(proof["entries"])
                dependency_count += len(dependencies)
                head_reads = [(request, received) for request, received in reads if request["path"] == slot and received["status"] == 200]
                require(len(head_reads) >= 2, "native recovery omitted final exact HEAD validation")
                final_request, final_received = head_reads[-1]
                equal([head_reads[0][1][key] for key in ("etag", "response_sha256")],
                      [final_received[key] for key in ("etag", "response_sha256")], "native restore changed HEAD body/ETag")
                require(all(any(request["path"] == path and received["status"] == 200 and stamp(received) < stamp(final_request)
                                for request, received in reads) for path in dependencies), "final HEAD preceded full data/result GET closure")
                native = value["native"]
                require(set(native) == {"file", "bytes", "sha256"} and native["file"] == f"image-{number}.sqlite", "native evidence was not from this step")
                native_path = directory / "native" / str(worker) / native["file"]
                copied = native_path.read_bytes()
                require(len(copied) == native["bytes"] and sha(copied) == native["sha256"] and copied == image,
                        "actual native image differs from all authenticated physical pages")
                native_files.add(native_path.relative_to(directory).as_posix()); native_bytes += len(copied)
                wanted = [row for _, row in sorted(expected_rows[slot].items())]
                with sqlite3.connect(native_path.as_uri() + "?mode=ro&immutable=1", uri=True) as database:
                    require(database.execute("PRAGMA integrity_check").fetchall() == [("ok",)], "independent native integrity check failed")
                    rows = [list(row) for row in database.execute(QUERY)]
                require(rows == wanted, "native image omitted/invented/changed an original complete input effect")
                query = one([candidate for candidate in selected if candidate["label"] == f"{profile}.query-{number}"], "recovered image has no full production query")
                drop = one([candidate for candidate in selected if candidate["label"] == f"{profile}.drop-{number}"], "recovered image lease was not dropped")
                require(query["request"] == {"op": "query", "budget_ms": STEP_MS, "sql": QUERY} and drop["request"] == {"op": "drop_image"}, "query/drop acquired another scope or changed full query")
                require(stamp(terminal) < stamp(query) < stamp(ended[query["call_id"]]) < stamp(drop) < stamp(ended[drop["call_id"]]), "image query/drop lifetime order")
                reply = ended[query["call_id"]]["response"]
                require(reply["ok"] is True and ended[drop["call_id"]]["response"]["ok"] is True, "native query/drop failed")
                decoded = result(byte_array(reply["value"]["encoded"]))
                require(len(decoded) == 1 and decoded[0]["columns"] == ["id", "value", "token"] and decoded[0]["rows"] == wanted,
                        "full production query differs from independent input/ACK effects")
                require(ended[drop["call_id"]]["response"]["value"] == {"dropped": True}, "image lease was not released")
                query_heads = [(request, received) for request, received in wire["reads"][query["call_id"]] if request["path"] == slot and received["status"] == 200]
                require(len(query_heads) == 1 and head(body(directory, query_heads[0][1], "response", overrides), slot) == authority,
                        "returned handle query skipped current READ/HEAD validation")
                expected_labels.update((query["label"], drop["label"])); row_count += len(rows); recovered.add(slot)
            else:
                require(value["native"] is None, "unverified slot supplied a native image")
            require(set(progress) == {"traversal_exhausted", "preexisting_slots_covered", "metadata_classified", "heads_classified",
                                      "data_verified", "data_not_required", "pending_scope", "permission_blocked", "recovery_complete"}, "completion fields changed")
            head_count = sum(item["kind"] == "Head" for item in observed.values())
            equal([progress[key] for key in ("metadata_classified", "heads_classified", "data_verified", "data_not_required")],
                  [len(observed), head_count, len(recovered), len(nonrequired)], "completion counters exceed independently verified denominator")
            require(progress["preexisting_slots_covered"] is progress["traversal_exhausted"], "coverage/exhaustion fields differ")
            if value["stopped"] is None:
                require(progress["pending_scope"] is None and progress["permission_blocked"] is False, "successful step concealed a pending slot")
            else:
                require(number == len(steps) and progress["recovery_complete"] is False, "failed step skipped forward or declared recovery complete")
            if progress["recovery_complete"]:
                require(profile == "complete" and set(observed) == set(expected) and recovered == needed and nonrequired == no_data and
                        progress["traversal_exhausted"] is True and value["stopped"] is None, "strict complete omitted metadata/data/result/native verification")
            last = value
        equal({call["label"]: call["request"]["op"] for call in selected},
              {label: invoked[next(call["call_id"] for call in selected if call["label"] == label)]["request"]["op"] for label in expected_labels},
              "recovery worker performed unaccounted commands")
        equal(finish["last"], last, "profile terminal fact differs from actual final worker response")
        if profile == "interrupted":
            require(len(steps) >= 12 and last["recovered_head"] is None and last["stopped"] is None and
                    not last["completion"]["recovery_complete"], "interrupted traversal was called complete")
        elif profile in ("missing_reader", "admin_without_read"):
            require(last["stopped"] == "PermissionBlocked" and last["completion"]["permission_blocked"] is True and
                    last["completion"]["pending_scope"]["tenant"] == 99, "missing READ was filtered out or called healthy")
            pending_head = expected_heads[head_path(last["completion"]["pending_scope"])]
            require(not any(request["path"].startswith(object_prefix(pending_head)) for request, _ in wire["reads"][steps[-1]["call_id"]]),
                    "unauthorized data was downloaded before current READ")
        elif profile == "missing_retained_result":
            removed = one([row for row in facts if row["event"] == "retained_result_removed"], "missing retained result fault inventory")
            require(last["stopped"] == "Corrupt" and last["completion"]["pending_scope"] is not None and
                    any(request["path"] == removed["key"] and received["status"] == 404 for request, received in wire["reads"][steps[-1]["call_id"]]),
                    "cold recovery ignored a missing noncurrent retained Result")
        else:
            require(last["completion"]["recovery_complete"] is True and last["recovered_head"] is None, "whole-job completion/accounting missing")
        worker_ids = {call["call_id"] for call in selected}
        raw_requests = [request for request in wire["requests"].values() if request["call_id"] in worker_ids]
        lists = sum("?" in request["path"] for request in raw_requests)
        equal([last["usage"]["list_pages"], last["usage"]["exact_gets"]], [lists, len(raw_requests)-lists], "reported whole-job operation counts differ from original S3 requests")
        wire_bytes = sum(received["response_bytes"] for serial, received in wire["responses"].items() if wire["requests"][serial]["call_id"] in worker_ids)
        require(sum(last["usage"][key] for key in ("list_bytes", "metadata_bytes", "data_bytes")) >= wire_bytes,
                "conservative bounded-body usage omitted observed body bytes")
        report[profile] = {"steps": len(steps), "metadata_classified": len(observed), "data_verified": len(recovered),
                           "required_heads": len(needed), "data_not_required": len(nonrequired), "native_rows": row_count,
                           "native_bytes": native_bytes, "closure_objects": dependency_count, "usage": last["usage"],
                           "raw_http_body_bytes": wire_bytes, "stopped": last["stopped"],
                           "recovery_complete": last["completion"]["recovery_complete"]}
    equal(sorted(path.relative_to(directory).as_posix() for path in (directory/"native").rglob("*.sqlite")), sorted(native_files), "native image evidence denominator changed")
    return report


def fault_boundaries(facts, invoked, ended, starts, wire):
    late = one([row for row in facts if row["event"] == "late_candidate_barrier"], "late candidate cancellation witness")
    request = wire["requests"][late["request_serial"]]; response = wire["responses"][late["request_serial"]]
    original = invoked[request["call_id"]]
    require(original["label"] == "native.late.execute" and ended[original["call_id"]]["event"] == "lost_with_process", "late candidate bound to another invocation")
    cancellation = one([call for call in invoked.values() if call["label"] == "native.cancel_late"], "late candidate has no actual cancel")
    equal(ended[cancellation["call_id"]]["response"]["value"], late["response"], "cancellation response changed")
    require(late["response"]["state"] == "cancelled" and stamp(ended[original["call_id"]]) < stamp(cancellation) and
            stamp(ended[cancellation["call_id"]]) < stamp(late) < stamp(response) and response["status"] == 412,
            "old candidate was not fenced by an observed earlier cancellation")
    armed = one([row for row in facts if row["event"] == "native_file_limit_armed"], "native failure injection denominator")
    failed = one([row for row in facts if row["event"] == "native_failed_after_s3_accept"], "native failure result denominator")
    restored = one([row for row in facts if row["event"] == "native_file_limit_restored"], "native limit restoration")
    serial = armed["request_serial"]; request, response = wire["requests"][serial], wire["responses"][serial]
    call, terminal = invoked[request["call_id"]], ended[request["call_id"]]
    require(call["label"] == "native.accepted_without_native_ack.execute" and request["method"] == "PUT" and
            request["path"].endswith("/head") and response["status"] == 200, "native cut did not follow actual HEAD acceptance")
    require(stamp(response) < stamp(armed) < stamp(terminal) < stamp(failed) < stamp(restored), "native failure ordering")
    require(armed["soft_limit"] == 0 and armed["wal_bytes"] == 0 and terminal["response"]["resources"]["file_size_soft_limit_bytes"] == 0,
            "native file failure was not the actual RLIMIT_FSIZE boundary")
    require(int(starts[armed["worker"]]["ready"]["resources"]["signal_ignored_hex"], 16) & (1 << (signal.SIGXFSZ-1)), "native fault killed the worker instead of returning publication failure")
    equal(failed["response"], terminal["response"], "native failure fact differs from actual response")
    equal(restored["restored"], armed["old"], "native file-size limit not restored")
    removed = one([row for row in facts if row["event"] == "retained_result_removed"], "closed Result removal inventory")
    returned = one([row for row in facts if row["event"] == "retained_result_restored"], "closed Result restoration inventory")
    require(removed["key"] == returned["key"] and removed["original_sha256"] == returned["sha256"] and removed["bytes"] == returned["bytes"], "fixture restored fabricated replacement bytes")
    deletes = [request for request in wire["requests"].values() if request["method"] == "DELETE"]
    require(len(deletes) == 1 and deletes[0]["path"] == removed["key"] and
            stamp(wire["responses"][deletes[0]["request_serial"]]) < stamp(removed) < stamp(returned), "Result damage not recorded as actual S3 deletion")


def load_data(directory):
    data = {}
    for name in FILES:
        raw = (directory / name).read_bytes()
        require(raw and raw.endswith(b"\n"), name + ": original record incomplete")
        data[name] = [parse(line) for line in raw.splitlines()] if name.endswith(".jsonl") else parse(raw)
    return data


def audit_data(directory, data, *, require_build=True, overrides=None):
    directory = Path(directory); overrides = {} if overrides is None else overrides
    plan = data["plan.json"]
    equal({key: value for key, value in plan.items() if key != "deployment"},
          {"schema": 1, "descriptor_tenants": list(DESCRIPTOR_TENANTS), "data_cases": list(DATA_CASES),
           "intermediate_cases": list(INTERMEDIATE_CASES), "recovery_profiles": list(RECOVERY_PROFILES),
           "head_format": HEAD_FORMAT, "immutable_format": IMMUTABLE_FORMAT, "query": QUERY,
           "job_ms": JOB_MS, "step_ms": STEP_MS, "maximum_steps": MAX_STEPS,
           "aws_standard_contract": "NOT_RUN", "unit_coverage_contribution": False}, "frozen experiment coverage obligations changed")
    require(type(plan["deployment"]) is int and 0 < plan["deployment"] < 2**64, "deployment identity")
    builds = {"seed": seed_receipt(directory / "seed-build", profile="network", require_artifacts=require_build),
              "recovery": discovery_build_audit.receipt(directory / "recovery-build", profile="discovery", require_artifacts=require_build)}
    invoked, ended = calls(data["calls.jsonl"])
    facts = data["facts.jsonl"]
    starts, credentials = processes(directory, facts, invoked, ended, builds, full=require_build)
    wire = network(directory, data["history.jsonl"], invoked, ended, facts, overrides, credentials,
                   plan["deployment"], full=require_build)
    metadata = Metadata(wire["objects"], plan["deployment"])
    rows, outcomes, originals_by_id = originals(directory, data["inputs.jsonl"], data["acks.jsonl"], invoked, ended, starts, facts, wire, metadata)
    fault_boundaries(facts, invoked, ended, starts, wire)
    profiles = recovery_profiles(directory, invoked, ended, starts, facts, wire, metadata, rows, overrides)
    used_bodies = {row[field] for row in data["history.jsonl"] for field in ("request_sha256", "response_sha256") if field in row}
    equal(sorted(path.name for path in (directory/"s3-bodies").iterdir()), sorted(used_bodies), "complete HTTP body file denominator changed")
    require(all(value["verification_scope"] == "full" for value in builds.values()) or not require_build, "full build identity unavailable")
    return {"status": "passed" if require_build else "partial", "verification_scope": "full" if require_build else "offline_restricted_not_an_acceptance_gate",
            "deployment": plan["deployment"], "builds": builds, "original_inputs": len(data["inputs.jsonl"]),
            "original_ack_count": len(data["acks.jsonl"]), "input_outcomes": dict(Counter(outcomes.values())),
            "processes": len(starts), "signed_s3_requests": len(wire["requests"]), "list_pages": len(wire["listings"]),
            "full_byte_objects": len(wire["objects"]), "profiles": profiles,
            "aws_standard_contract": "NOT_RUN", "production_throughput_slo": "NOT_RUN",
            "completion_meaning": "per-slot verification points; not a simultaneous deployment snapshot"}


def audit(directory, *, require_build=True):
    directory = Path(directory)
    before = {name: sha((directory/name).read_bytes()) for name in FILES}
    value = audit_data(directory, load_data(directory), require_build=require_build)
    require(before == {name: sha((directory/name).read_bytes()) for name in FILES}, "original evidence changed during independent audit")
    return {**value, "source_sha256": before}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--offline", action="store_true")
    arguments = parser.parse_args()
    print(json.dumps(audit(arguments.evidence, require_build=not arguments.offline), sort_keys=True, indent=2))
    raise SystemExit(2 if arguments.offline else 0)
