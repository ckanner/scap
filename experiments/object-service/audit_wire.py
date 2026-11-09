"""Read-only independent public wire witnesses; never imports product/controller code."""
from __future__ import annotations

import base64
from collections import Counter, defaultdict
import hashlib
import heapq
import importlib.util
import json
import math
from pathlib import Path
import re
import struct


_HEAD5_SPEC = importlib.util.spec_from_file_location(
    "scap_independent_service_head5_schema",
    Path(__file__).resolve().parents[1] / "object-network" / "head5_audit.py")
_HEAD5 = importlib.util.module_from_spec(_HEAD5_SPEC)
_HEAD5_SPEC.loader.exec_module(_HEAD5)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def parse(raw):
    def invalid(value):
        raise ValueError("non-finite JSON constant: " + value)
    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)


def equal(left, right, message):
    if isinstance(left, bytes) or isinstance(right, bytes):
        require(type(left) is bytes and type(right) is bytes and left == right, message)
        return
    require(json.dumps(left, sort_keys=True, ensure_ascii=False, allow_nan=False) ==
            json.dumps(right, sort_keys=True, ensure_ascii=False, allow_nan=False), message)


def b64(value):
    require(isinstance(value, str), "base64 must be text")
    raw = base64.b64decode(value, validate=True)
    require(base64.b64encode(raw).decode() == value, "noncanonical base64")
    return raw


def decimal(value, *, zero=False):
    require(isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]*", value) is not None,
            "noncanonical decimal")
    number = int(value)
    require((0 if zero else 1) <= number < 2 ** 64, "u64 outside range")
    return number


def fingerprint(statements):
    require(isinstance(statements, list) and 0 < len(statements) <= 65536, "invalid statements")
    data = bytearray(b"SCAPSQL1" + struct.pack("<I", len(statements)))
    for statement in statements:
        require(set(statement) == {"sql", "params"}, "statement fields changed")
        sql = statement["sql"].encode("utf-8", errors="strict")
        require(sql and b"\0" not in sql, "invalid SQL")
        data.extend(struct.pack("<I", len(sql)) + sql)
        parameters = statement["params"]
        require(isinstance(parameters, list) and len(parameters) <= 32766, "invalid parameters")
        data.extend(struct.pack("<I", len(parameters)))
        for value in parameters:
            kind = value["type"]
            if kind == "null":
                require(set(value) == {"type"}, "null fields")
                data.append(0)
            elif kind == "integer":
                require(set(value) == {"type", "value"}, "integer fields")
                text = value["value"]
                require(isinstance(text, str) and re.fullmatch(r"0|-?[1-9][0-9]*", text) is not None,
                        "noncanonical i64")
                number = int(text)
                require(-(2 ** 63) <= number < 2 ** 63, "i64 outside range")
                data.extend(b"\1" + struct.pack("<q", number))
            elif kind == "real":
                require(set(value) == {"type", "bits"} and re.fullmatch(r"[0-9a-f]{16}", value["bits"]), "real fields")
                raw = bytes.fromhex(value["bits"])
                require(math.isfinite(struct.unpack(">d", raw)[0]), "nonfinite parameter")
                data.extend(b"\2" + raw[::-1])
            elif kind == "text":
                require(set(value) == {"type", "value"}, "text fields")
                raw = value["value"].encode("utf-8", errors="strict")
                data.extend(b"\3" + struct.pack("<I", len(raw)) + raw)
            elif kind == "blob":
                require(set(value) == {"type", "base64"}, "blob fields")
                raw = b64(value["base64"])
                data.extend(b"\4" + struct.pack("<I", len(raw)) + raw)
            else:
                raise ValueError("unknown parameter tag")
    return hashlib.sha256(data).hexdigest()


def result(raw):
    require(isinstance(raw, bytes) and len(raw) <= 64 * 1024 * 1024, "result bound")
    position = 0

    def take(count):
        nonlocal position
        require(0 <= count <= len(raw) - position, "truncated result")
        value = raw[position:position + count]
        position += count
        return value

    def number(code):
        return struct.unpack("<" + code, take(struct.calcsize("<" + code)))[0]

    def text():
        return take(number("I")).decode("utf-8", errors="strict")

    def scalar():
        kind = number("B")
        if kind == 0:
            return None
        if kind == 1:
            return number("q")
        if kind == 2:
            value = number("d")
            require(math.isfinite(value), "nonfinite result")
            return value
        if kind == 3:
            return text()
        if kind == 4:
            return take(number("I"))
        raise ValueError("unknown result tag")

    require(take(8) == b"SCAPRES1", "wrong result magic")
    count = number("I")
    require(count <= 65536 and count * 24 <= len(raw) - position, "impossible statement count")
    statements = []
    for _ in range(count):
        columns = number("I")
        require(columns <= 2000 and columns * 4 <= len(raw) - position, "impossible column count")
        names = [text() for _ in range(columns)]
        rows = number("I")
        require((columns != 0 or rows == 0) and rows * columns <= len(raw) - position - 16, "impossible rows")
        statements.append({"columns": names, "rows": [[scalar() for _ in names] for _ in range(rows)],
                           "affected_rows": number("Q"), "last_insert_rowid": number("q")})
    require(position == len(raw), "trailing result bytes")
    return statements


def receipt_hash(receipt, raw):
    require(set(receipt) == {"scope", "request", "sequence", "transition", "data_root", "result_hash"}, "receipt fields")
    scope = receipt["scope"]
    names = ("deployment", "tenant", "database", "incarnation", "generation")
    require(set(scope) == set(names), "scope fields")
    native_scope = {key: decimal(scope[key]) for key in names}
    request = receipt["request"]
    require(set(request) == {"epoch", "id", "principal", "fingerprint"}, "request fields")
    native_request = {key: decimal(request[key]) for key in ("epoch", "id", "principal")}
    native_request["fingerprint"] = request["fingerprint"]
    transition = receipt["transition"]
    require(set(transition) == {"revision", "nonce"}, "transition fields")
    native_transition = {key: decimal(transition[key]) for key in ("revision", "nonce")}
    require(native_transition["nonce"] == native_request["id"], "SQL nonce differs from identity")
    for digest in (request["fingerprint"], receipt["data_root"], receipt["result_hash"]):
        require(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) is not None, "hash fields")
    metadata = {"format": 2, "scope": native_scope, "payload": {"kind": "result", "value": {
        "request": native_request, "sequence": decimal(receipt["sequence"]), "transition": native_transition,
        "data_root": receipt["data_root"], "bytes": []}}}
    encoded = json.dumps(metadata, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
    return hashlib.sha256(b"SCAPOBJ2" + struct.pack("<IQ", len(encoded), len(raw)) + encoded + raw).hexdigest()


def committed(value):
    require(set(value) == {"state", "receipt", "result"} and value["state"] == "committed", "committed shape")
    raw = b64(value["result"])
    statements = result(raw)
    require(receipt_hash(value["receipt"], raw) == value["receipt"]["result_hash"], "result object digest differs")
    return raw, statements


def sha256_text(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None,
            "invalid SHA-256 digest")
    return value


def moment(row):
    value = row["monotonic_ns"]
    require(type(value) is int and value > 0, "invalid object monotonic timestamp")
    return value


def head5_profile(value):
    """Validate the complete independent HEAD5 schema from original HEAD bytes.

    The shared reader has no controller or production imports. Per-experiment
    lifecycle, predecessor and complete dependency-closure proofs remain here.
    """
    return _HEAD5.validate(value)


def head5_publication(candidate, predecessor=None):
    """Verify actual business publications in the foundation-only real profile."""
    head5_profile(candidate)
    if predecessor is None:
        require(candidate["head_serial"] == candidate["revision"] == 1,
                "HEAD5 initial authority must start at serial/revision one")
    else:
        head5_profile(predecessor)
        equal(candidate["scope"], predecessor["scope"], "HEAD5 CAS changed logical Scope")
        require(candidate["head_serial"] == predecessor["head_serial"] + 1,
                "HEAD5 CAS did not advance original head serial exactly once")
        require(candidate["revision"] == predecessor["revision"] + 1,
                "HEAD5 foundation business publication revision")


def capture(row, *, response=False):
    prefix = "head" if row["path"].endswith("/head") else (
        "catalogue" if "/catalogue/v1/" in row["path"] else None)
    suffix = "response" if response else "request"
    length = row[suffix + "_bytes"]
    require(type(length) is int and 0 <= length <= 64 * 1024 * 1024, "invalid object byte length")
    sha256_text(row[suffix + "_sha256"])
    if prefix is None:
        return None
    value = row[prefix + "_" + suffix + "_bytes"]
    require(isinstance(value, list) and all(type(n) is int and 0 <= n < 256 for n in value),
            "authority capture is not complete bytes")
    raw = bytes(value)
    require(len(raw) == length and hashlib.sha256(raw).hexdigest() == row[suffix + "_sha256"],
            "authority captured body differs from byte length/digest")
    if prefix == "catalogue":
        require(length <= 65536, "catalogue authority capture exceeds bound")
    if prefix == "head" and ((response and row["method"] == "GET" and row["status"] == 200)
                              or (not response and row["method"] == "PUT")):
        require(length <= 256 * 1024, "HEAD5 exceeds production byte bound")
        head5_profile(parse(raw))
    return raw


def object_exchanges(history, *, phases, blackhole_phases=()):
    """Verify complete original wire pairs; no summary or controller imports."""
    serials = defaultdict(list)
    require(not any(row["event"] in ("transport_fixture_failed", "caller_disconnected") for row in history),
            "unexplained object transport failure")
    for row in history:
        if row["event"].startswith("object_") or row["event"] == "transport_fault_observed":
            require("request_serial" in row, "object wire event has no request serial")
        if "request_serial" in row:
            serials[row["request_serial"]].append(row)
    require(serials and all(type(serial) is int and serial > 0 for serial in serials), "invalid object serial")
    require(sorted(serials) == list(range(1, len(serials) + 1)), "object request serial gap")
    requests, responses = {}, {}
    common = ("phase", "method", "path", "request_bytes", "request_sha256", "if_match", "if_none_match",
              "head_request_bytes", "catalogue_request_bytes")
    response_fields = ("status", "response_bytes", "response_sha256", "etag", "head_response_bytes", "catalogue_response_bytes")
    allowed = {"object_request", "object_forwarded", "object_response", "object_response_delivered", "transport_fault_observed"}
    for serial, events in serials.items():
        by_event = defaultdict(list)
        for row in events:
            require(row["event"] in allowed, "unplanned/injected object event")
            by_event[row["event"]].append(row)
        require(len(by_event["object_request"]) == 1, "missing/duplicate object request")
        request = by_event["object_request"][0]
        require(request["phase"] in phases and request["method"] in ("GET", "PUT"), "unplanned object method/phase")
        require(isinstance(request["path"], str) and request["path"].startswith("/scap-test/scap-object/v1/")
                and "?" not in request["path"] and "#" not in request["path"], "object path escaped exact authority")
        if "/objects/" in request["path"]:
            key = re.fullmatch(r"/scap-test/scap-object/v1/([1-9][0-9]*)/([1-9][0-9]*)/([1-9][0-9]*)"
                               r"/inc/([1-9][0-9]*)/gen/([1-9][0-9]*)/storage/1/objects/[0-9a-f]{64}",
                               request["path"])
            require(key is not None and all(int(value) < 2**64 for value in key.groups()),
                    "HEAD5 immutable path lacks exact supported physical namespace")
        capture(request)
        if request["method"] == "GET":
            require(request["request_bytes"] == 0 and request["request_sha256"] == hashlib.sha256(b"").hexdigest()
                    and request["if_match"] is None and request["if_none_match"] is None, "GET changed its body/conditions")
        else:
            require((request["if_none_match"] == "*" and request["if_match"] is None)
                    or (request["if_none_match"] is None and isinstance(request["if_match"], str) and request["if_match"]),
                    "unconditional or ambiguous object PUT")
        require(len(by_event["transport_fault_observed"]) <= 1, "duplicate object fault witness")
        fault = by_event["transport_fault_observed"][0] if by_event["transport_fault_observed"] else None
        if fault:
            require(fault["mode"] in ("hold", "drop", "blackhole") and fault["stage"] == "before_forward",
                    "unplanned service object fault")
            require(moment(request) < moment(fault), "object fault preceded invocation")
        require(len(by_event["object_response"]) <= 1 and len(by_event["object_forwarded"]) <= 1
                and len(by_event["object_response_delivered"]) <= 1, "duplicate object response/forward/delivery")
        response = by_event["object_response"][0] if by_event["object_response"] else None
        forwarded = by_event["object_forwarded"][0] if by_event["object_forwarded"] else None
        delivered = by_event["object_response_delivered"][0] if by_event["object_response_delivered"] else None
        for row in events:
            for key in common:
                equal(row.get(key), request.get(key), "S3 event binds another original request: " + key)
        requests[serial] = request
        if response is None:
            require(request["phase"] in blackhole_phases and request["method"] == "GET" and fault is not None
                    and fault["mode"] == "blackhole" and forwarded is None and delivered is None,
                    "missing backend response without explicit pre-forward blackhole")
            continue
        require(forwarded is not None and moment(request) < moment(forwarded) < moment(response)
                and response["response_origin"] == "backend", "invalid original backend exchange")
        require(type(response["status"]) is int and response["status"] in ((200, 404) if request["method"] == "GET" else (200, 412)),
                "unplanned actual backend status")
        require(type(response["suppressed"]) is bool, "missing delivery disposition")
        capture(response, response=True)
        if response["status"] == 200:
            require(isinstance(response["etag"], str) and response["etag"], "successful exact object response lacks ETag")
        if response["suppressed"]:
            require(fault is not None and fault["mode"] == "drop" and response["status"] == 200 and delivered is None,
                    "suppressed response lacks observed accepted-response loss")
        else:
            require(delivered is not None and moment(response) < moment(delivered), "missing/early original response delivery")
            require(fault is None or fault["mode"] == "hold", "delivered response contradicts observed fault")
            for key in response_fields:
                equal(delivered.get(key), response.get(key), "delivery changed original backend body/ETag/status")
        responses[serial] = response
    return requests, responses


def object_versions(requests, responses, *, calls=None, bindings=None):
    """Check per-key CAS version chains with legal overlapping read intervals.

    A response-receipt timestamp is not a linearization point. We reconstruct
    the unique accepted If-Match chain, then solve precedence constraints within
    every original invocation/response interval. Hashes bind complete bodies to
    opaque ETags; neither wall-clock leases nor final-state summaries are used.
    """
    candidates = {}
    if calls is not None:
        for serial, request in requests.items():
            matching = {number for number, call in calls.items()
                        if int(call["request"]["monotonic_ns"]) < moment(request)
                        < int(call["response"]["monotonic_ns"])}
            if bindings is not None:
                matching &= bindings[serial]
            require(matching, "object request has no invoking HTTP call interval")
            if serial in responses:
                matching = {number for number in matching
                            if moment(responses[serial]) < int(calls[number]["response"]["monotonic_ns"])}
                require(matching, "backend response has no original invoking HTTP call interval")
            candidates[serial] = matching
    accepted = defaultdict(dict)
    by_path = defaultdict(list)
    for serial, response in responses.items():
        request = requests[serial]
        by_path[request["path"]].append(serial)
        if request["method"] == "PUT" and response["status"] == 200:
            versions = accepted[request["path"]]
            require(response["etag"] not in versions, "accepted object ETag reused")
            versions[response["etag"]] = serial
            if "/objects/" in request["path"]:
                require(request["if_none_match"] == "*" and request["path"].rsplit("/", 1)[1] == request["request_sha256"],
                        "immutable object key/condition differs from actual bytes")
    total_edges = 0
    for path, serials in by_path.items():
        versions = accepted[path]
        successors, roots, edges = {}, [], set()
        for etag, serial in versions.items():
            request = requests[serial]
            if request["if_none_match"] == "*":
                if path.endswith("/head"):
                    head5_publication(parse(capture(request)))
                roots.append(serial)
            else:
                previous = versions.get(request["if_match"])
                require(previous is not None and previous != serial, "accepted CAS has no original predecessor version")
                require(previous not in successors, "two successful CAS writes consumed the same ETag")
                successors[previous] = serial
                edges.add((previous, serial))
        require(not versions or len(roots) == 1, "object history has missing/duplicate conditional root")
        if versions:
            visited, current = set(), roots[0]
            while current is not None and current not in visited:
                visited.add(current)
                current = successors.get(current)
            require(current is None and len(visited) == len(versions), "disconnected/cyclic object version chain")
        for serial in serials:
            request, response = requests[serial], responses[serial]
            if request["method"] == "GET":
                if response["status"] == 404:
                    if roots:
                        edges.add((serial, roots[0]))
                    continue
                previous = versions.get(response["etag"])
                require(previous is not None, "GET exposed a version omitted from accepted history")
                original = requests[previous]
                equal([response["response_bytes"], response["response_sha256"]],
                      [original["request_bytes"], original["request_sha256"]], "same exact GET ETag identifies different complete bytes")
                raw = capture(response, response=True)
                if raw is not None:
                    equal(raw, capture(original), "same exact GET body differs from original version")
                edges.add((previous, serial))
                if previous in successors:
                    edges.add((serial, successors[previous]))
            else:
                if path.endswith("/head") and request["if_none_match"] == "*":
                    head5_publication(parse(capture(request)))
                if request["if_match"] is not None:
                    previous = versions.get(request["if_match"])
                    require(previous is not None, "CAS condition has no observed original version")
                    if path.endswith("/head"):
                        head5_publication(parse(capture(request)), parse(capture(requests[previous])))
                    witnesses = [other for other in serials if requests[other]["method"] == "GET"
                                 and responses[other]["status"] == 200 and responses[other]["etag"] == request["if_match"]
                                 and moment(responses[other]) < moment(request)
                                 and (calls is None or candidates[other] & candidates[serial])]
                    require(witnesses, "CAS did not use a preceding same-call exact GET body/ETag")
                    if response["status"] == 412:
                        require(previous in successors, "backend 412 rejected the current original ETag")
                        edges.add((successors[previous], serial))
                elif response["status"] == 412:
                    require(roots, "conditional create 412 lacks permanent key occupancy")
                    edges.add((roots[0], serial))
        # Scale the recorded nanoseconds to allow strict logical order even
        # when several effects fall between two adjacent observation clocks.
        scale = len(serials) + 1
        earliest = {serial: moment(requests[serial]) * scale for serial in serials}
        following, indegree = defaultdict(set), Counter({serial: 0 for serial in serials})
        for before, after in edges:
            require(before != after, "self-referential object effect")
            following[before].add(after)
            indegree[after] += 1
        ready = [(earliest[serial], serial) for serial in serials if indegree[serial] == 0]
        heapq.heapify(ready)
        visited = 0
        while ready:
            _, serial = heapq.heappop(ready)
            require(earliest[serial] <= moment(responses[serial]) * scale,
                    "object versions violate original real-time invocation/response intervals")
            visited += 1
            for later in following[serial]:
                earliest[later] = max(earliest[later], earliest[serial] + 1)
                indegree[later] -= 1
                if indegree[later] == 0:
                    heapq.heappush(ready, (earliest[later], later))
        require(visited == len(serials), "object read/CAS history has no consistent linearization")
        total_edges += len(edges)
    return {"accepted_versions": sum(len(versions) for versions in accepted.values()),
            "exact_get_body_etag_pairs": sum(requests[serial]["method"] == "GET" and response["status"] == 200
                                              for serial, response in responses.items()),
            "conditional_put_responses": sum(requests[serial]["method"] == "PUT" for serial in responses),
            "causal_constraints": total_edges,
            "blackholed_before_forward": len(requests) - len(responses),
            "ambiguous_http_intervals": sum(len(value) > 1 for value in candidates.values()),
            "http_interval_binding": "checked" if calls is not None else "NOT_REQUESTED"}
