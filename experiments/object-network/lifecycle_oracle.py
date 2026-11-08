#!/usr/bin/env python3
"""Read-only lifecycle evidence audit. Does not import or execute the controller."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
import math
from pathlib import Path
import struct
import sys


CASE_IDS = [f"LC-{number:02d}" for number in range(1, 13)]
STAGES = ("compute_recovery", "backend_recovery")
SOURCE_FILES = ("lifecycle-plan.json", "lifecycle-input-ledger.jsonl", "lifecycle-client-ledger.jsonl",
                "lifecycle-ack-ledger.jsonl", "lifecycle-facts.jsonl", "history.jsonl", "build-receipt.json")
PROFILE = {"quota_bytes": 4194304, "retention_entries": 4, "retention_result_bytes": 134217728}
RECEIPT_FIELDS = {"scope", "request", "sequence", "transition", "data_root", "result_hash"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def equal(left, right, message):
    require(canonical(left) == canonical(right), message)


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "duplicate JSON key: " + key)
        value[key] = item
    return value


def invalid_constant(value):
    raise ValueError("non-finite JSON number: " + value)


def parse(raw):
    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid_constant)


def byte_string(value):
    require(isinstance(value, list) and all(type(item) is int and 0 <= item <= 255 for item in value),
            "full byte array required")
    return bytes(value)


def head(value):
    result = parse(byte_string(value))
    require(isinstance(result, dict) and result.get("format") == 3, "HEAD body is not format 3")
    # These twelve cases create direct, unnamed databases. HEAD v3 requires
    # explicit nullable origins; the separate catalogue oracle audits named
    # creation/deletion proofs. Immutable SCAPOBJ2 frames remain format 2.
    require("creation" in result and result["creation"] is None
            and "deletion" in result and result["deletion"] is None,
            "lifecycle fixture requires explicit unnamed HEAD origins")
    return result


def fingerprint(statements):
    """Independent SCAPSQL1 wire witness; no authority/state transition code."""
    require(isinstance(statements, list) and 0 < len(statements) <= 65536, "invalid statement inventory")
    encoded = bytearray(b"SCAPSQL1" + struct.pack("<I", len(statements)))
    for statement in statements:
        sql = statement["sql"].encode("utf-8")
        require(sql and b"\0" not in sql, "invalid SQL input")
        encoded.extend(struct.pack("<I", len(sql)) + sql)
        parameters = statement.get("parameters", [])
        require(len(parameters) <= 32766, "too many parameters")
        encoded.extend(struct.pack("<I", len(parameters)))
        for parameter in parameters:
            kind, value = parameter["type"], parameter.get("value")
            if kind == "null":
                encoded.append(0)
            elif kind == "integer":
                require(type(value) is int and -(2 ** 63) <= value < 2 ** 63, "invalid int64 parameter")
                encoded.extend(b"\1" + struct.pack("<q", value))
            elif kind == "real":
                require(type(value) in (int, float) and math.isfinite(value), "invalid finite real parameter")
                encoded.extend(b"\2" + struct.pack("<d", value))
            elif kind == "text":
                raw = value.encode("utf-8")
                encoded.extend(b"\3" + struct.pack("<I", len(raw)) + raw)
            else:
                raise ValueError("lifecycle profile requires self-contained scalar parameters")
    return hashlib.sha256(encoded).hexdigest()


def decoded_result(value):
    """Strict SCAPRES1 reader, preserving column order, int64 and BLOB bytes."""
    require(len(value) <= 64 * 1024 * 1024, "result exceeds durable format bound")
    raw = byte_string(value)
    offset = 0

    def take(count):
        nonlocal offset
        require(0 <= count <= len(raw) - offset, "truncated SCAPRES1 result")
        result = raw[offset:offset + count]
        offset += count
        return result

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
            result = number("d")
            require(math.isfinite(result), "non-finite SCAPRES1 real")
            return result
        if kind == 3:
            return text()
        if kind == 4:
            return {"blob": list(take(number("I")))}
        raise ValueError("unknown SCAPRES1 value tag")

    require(take(8) == b"SCAPRES1", "wrong result format")
    count = number("I")
    require(count <= 65536 and count * 24 <= len(raw) - offset, "impossible result statement count")
    statements = []
    for _ in range(count):
        column_count = number("I")
        require(column_count <= 2000 and column_count * 4 <= len(raw) - offset, "impossible result column count")
        columns = [text() for _ in range(column_count)]
        row_count = number("I")
        require((column_count != 0 or row_count == 0) and row_count * column_count <= len(raw) - offset - 16,
                "impossible result row count")
        rows = [[scalar() for _ in columns] for _ in range(row_count)]
        statements.append({"columns": columns, "rows": rows,
                           "affected_rows": number("Q"), "last_insert_rowid": number("q")})
    require(offset == len(raw), "trailing SCAPRES1 bytes")
    return statements


def validate_result(value):
    equal(decoded_result(value["encoded"]), value["statements"], "typed result differs from complete SCAPRES1 bytes")


def result_hash(receipt, encoded):
    """Hash the fixed SCAPOBJ2 Result frame, including every receipt binding."""
    require(set(receipt) == RECEIPT_FIELDS, "incomplete receipt")

    def ordered(value, names):
        require(set(value) == set(names), "incomplete nested receipt identity")
        return {name: value[name] for name in names}

    scope = ordered(receipt["scope"], ("deployment", "tenant", "database", "incarnation", "generation"))
    request = ordered(receipt["request"], ("epoch", "id", "principal", "fingerprint"))
    transition = ordered(receipt["transition"], ("revision", "nonce"))
    for value in [*scope.values(), request["epoch"], request["id"], request["principal"],
                  receipt["sequence"], *transition.values()]:
        require(type(value) is int and 0 < value < 2 ** 64, "invalid receipt u64")
    for value in (request["fingerprint"], receipt["data_root"], receipt["result_hash"]):
        require(isinstance(value, str) and len(value) == 64 and all(character in "0123456789abcdef" for character in value),
                "invalid receipt hash")
    require(transition["nonce"] == request["id"], "SQL transition nonce differs from request ID")
    metadata = {"format": 2, "scope": scope, "payload": {"kind": "result", "value": {
        "request": request, "sequence": receipt["sequence"], "transition": transition,
        "data_root": receipt["data_root"], "bytes": []}}}
    raw = byte_string(encoded)
    metadata_bytes = json.dumps(metadata, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    frame = b"SCAPOBJ2" + struct.pack("<IQ", len(metadata_bytes), len(raw)) + metadata_bytes + raw
    return hashlib.sha256(frame).hexdigest()


def validate_original(original):
    validate_result(original["result"])
    equal(result_hash(original["receipt"], original["result"]["encoded"]), original["receipt"]["result_hash"],
          "SCAPOBJ2 Result digest does not bind receipt to complete raw result")


def original_matches(original, observed, *, replay=False):
    validate_original(original)
    if replay:
        equal(original, observed, "replay changed full receipt, encoded result or typed statements")
    else:
        equal(observed, {"state": "committed", "receipt": original["receipt"],
                         "encoded": original["result"]["encoded"]}, "lookup changed original receipt/result")


def expected_rows(case_id, originals):
    """Only the independent INSERT inputs and first actual ACK witness supply random()."""
    rows = []
    for name, row_id, suffix in (("seed", 1, "seed"), ("candidate", 2, "candidate")):
        if name not in originals:
            continue
        statements = originals[name]["result"]["statements"]
        require(len(statements) == 1, "INSERT RETURNING statement count changed")
        statement = statements[0]
        equal(statement["columns"], ["id", "label", "token"], "RETURNING columns changed")
        require(len(statement["rows"]) == 1 and len(statement["rows"][0]) == 3, "RETURNING row shape changed")
        row = statement["rows"][0]
        equal(row[:2], [row_id, case_id + "-" + suffix], "RETURNING differs from pre-recorded input")
        require(type(row[2]) is int and -(2 ** 63) <= row[2] < 2 ** 63, "random() witness is not int64")
        require(statement["affected_rows"] == 1, "INSERT affected-row count changed")
        rows.append(row)
    require(rows and rows[0][0] == 1, "missing seed ACK witness")
    return rows


def zero_page_input(name, statements):
    expected = {"read_execute": "SELECT random() AS token",
                "zero_execute": "UPDATE events SET label=label WHERE id=-1"}
    require(name in expected, "unplanned zero-page execution")
    equal(statements, [{"sql": expected[name]}], "LC-10 read/zero-change input profile changed")


class Network:
    def __init__(self, history):
        self.history = history
        self.serials = defaultdict(list)
        self.phases = defaultdict(list)
        for position, row in enumerate(history):
            row = {**row, "position": position}
            if "request_serial" in row:
                self.serials[row["request_serial"]].append(row)
            if "phase" in row:
                self.phases[row["phase"]].append(row)

    def events(self, call, event=None, *, method=None, head_only=False):
        return [row for row in self.phases.get(call["phase"], [])
                if (event is None or row["event"] == event)
                and (method is None or row.get("method") == method)
                and (not head_only or row.get("path", "").endswith("/head"))]

    def only(self, serial, event):
        found = [row for row in self.serials[serial] if row["event"] == event]
        require(len(found) == 1, f"serial {serial}: missing/duplicate {event}")
        return found[0]

    def exchange(self, request, status):
        serial = request["request_serial"]
        equal(self.only(serial, "object_request"), request, "request serial aliases another request")
        forwarded = self.only(serial, "object_forwarded")
        response = self.only(serial, "object_response")
        require(response.get("response_origin") == "backend" and response.get("status") == status,
                f"serial {serial}: expected real backend {status}")
        require(request["position"] < forwarded["position"] < response["position"], "backend event order changed")
        for name in ("method", "path", "request_sha256", "if_match", "if_none_match", "head_request_bytes"):
            equal(request.get(name), response.get(name), "backend response no longer identifies original request")
        require(not any(row["event"] == "injected_response" for row in self.serials[serial]),
                "proxy-injected response cannot prove a backend condition")
        if request["path"].endswith("/head"):
            require(hashlib.sha256(byte_string(request["head_request_bytes"])).hexdigest()
                    == request["request_sha256"], "HEAD request bytes/hash mismatch")
        return response

    def put(self, call, status):
        requests = self.events(call, "object_request", method="PUT", head_only=True)
        require(len(requests) == 1, call["label"] + ": expected exactly one original HEAD PUT")
        request = requests[0]
        return request, self.exchange(request, status)

    def base(self, call, request):
        require(isinstance(request.get("if_match"), str) and request["if_match"], "missing original If-Match")
        require(request.get("if_none_match") is None, "replacement cannot also be an absent create")
        reads = [row for row in self.events(call, "object_response", method="GET", head_only=True)
                 if row.get("response_origin") == "backend" and row.get("status") == 200
                 and row.get("etag") == request["if_match"] and row["position"] < request["position"]]
        require(reads, call["label"] + ": no same-GET body/ETag for original candidate")
        read = reads[-1]
        require(hashlib.sha256(byte_string(read["head_response_bytes"])).hexdigest() == read["response_sha256"],
                "HEAD GET body/hash mismatch")
        return head(read["head_response_bytes"])

    def no_put(self, call):
        require(not self.events(call, "object_request", method="PUT"), call["label"] + ": unexpected object PUT")


def race_order(network, candidate, barrier, boundary, release, *, commit_first, cancel_observation=False):
    request, result = network.put(candidate, 200 if commit_first else 412)
    base = network.base(candidate, request)
    observation = network.only(request["request_serial"], "transport_fault_observed")
    stage = "after_upstream_response" if commit_first else "before_forward"
    require(observation["stage"] == stage and observation["mode"] == "hold", "wrong real fault boundary")
    equal(boundary["payload"], request["head_request_bytes"], "saved candidate bytes changed")
    equal(boundary["observation"]["request_serial"], request["request_serial"], "fault matched another request")
    equal(boundary["observation"]["if_match"], request["if_match"], "saved original condition changed")
    require(release["request_serial"] == request["request_serial"], "released a different candidate")
    require(boundary["monotonic_ns"] < barrier["monotonic_ns"] < release["monotonic_ns"], "barrier outside held interval")
    if cancel_observation:
        network.no_put(barrier)
        reads = network.events(barrier, "object_response", method="GET", head_only=True)
        require(any(row.get("status") == 200 and row["position"] > result["position"] for row in reads),
                "cancel did not freshly observe accepted commit")
    else:
        _, barrier_response = network.put(barrier, 200)
        if commit_first:
            require(result["position"] < barrier_response["position"], "control preceded supposedly accepted commit")
        else:
            forwarded = network.only(request["request_serial"], "object_forwarded")
            require(observation["position"] < barrier_response["position"] < forwarded["position"],
                    "old candidate reached backend before the control barrier")
    delivered = network.only(request["request_serial"], "object_response_delivered")
    require(delivered["monotonic_ns"] >= release["monotonic_ns"], "candidate response was delivered before release")
    return base, request, result


class Audit:
    def __init__(self, data):
        self.data = data
        self.plan, self.inputs, self.clients = data["plan"], data["inputs"], data["clients"]
        self.acks, self.facts, self.history = data["acks"], data["facts"], data["history"]
        self.network = Network(self.history)
        self.calls, self.responses, self.labels, self.intents, self.originals = {}, {}, {}, {}, {}
        self.case_results = []
        self.ack_classes = Counter()
        self.cancellations = {}

    def call(self, case, label):
        require((case, label) in self.labels, f"{case}/{label}: required call NOT_RUN")
        return self.labels[case, label]

    def response(self, call):
        return self.responses[call["call_id"]]["response"]

    def value(self, case, label):
        call = self.call(case, label)
        response = self.response(call)
        require(response.get("ok") is True, f"{case}/{label}: expected success, saw {response.get('error')}")
        return response["value"]

    def failure(self, case, label, error, *, no_put=True):
        call = self.call(case, label)
        response = self.response(call)
        require(response.get("ok") is False and response.get("error") == error,
                f"{case}/{label}: expected {error}, saw {response}")
        if no_put:
            self.network.no_put(call)
        return call

    def state(self, case, label, state):
        value = self.value(case, label)
        require(value.get("state") == state, f"{case}/{label}: expected {state}, saw {value}")
        if state in ("unknown", "closed", "retired"):
            equal(value, {"state": state}, "unexpected terminal-state payload")
        self.network.no_put(self.call(case, label))
        return value

    def fact(self, case, event, **values):
        rows = [row for row in self.facts if row["case"] == case and row["event"] == event
                and all(row.get(key) == value for key, value in values.items())]
        require(len(rows) == 1, f"{case}/{event}/{values}: missing or duplicate fact")
        return rows[0]

    def snapshot(self, case, label):
        call = self.call(case, label)
        value = self.value(case, label)
        reads = self.network.events(call, "object_response", method="GET", head_only=True)
        require(len(reads) == 1 and reads[0].get("status") == 200
                and reads[0].get("response_origin") == "backend", "snapshot lacks exact real GET")
        equal(value, {"bytes": reads[0]["head_response_bytes"], "etag": reads[0]["etag"]},
              "snapshot body/ETag split across observations")
        self.network.no_put(call)
        return value, head(value["bytes"])

    def inventory(self):
        equal(self.plan.get("case_ids"), CASE_IDS, "twelve-case denominator changed")
        require(self.plan.get("version") == 1, "unsupported evidence plan")
        equal(self.plan.get("fixture_limits"), PROFILE, "unannounced capacity profile")
        require(self.plan.get("s3_timeout_ms") == 8000, "fault timeout profile changed")
        require(self.plan.get("aws_endpoint_gate") == "NOT_RUN"
                and self.plan.get("production_slo_passed") is False
                and self.plan.get("unit_coverage_contribution") is False, "proof scope was overstated")
        equal([case["id"] for case in self.plan["cases"]], CASE_IDS, "case scope inventory changed")
        scopes = [canonical(case["scope"]) for case in self.plan["cases"]]
        require(len(set(scopes)) == 12, "cases share a durable identity")
        for case in self.plan["cases"]:
            scope = case["scope"]
            require(set(scope) == {"deployment", "tenant", "database", "incarnation", "generation"}
                    and all(type(item) is int and item > 0 for item in scope.values()), "invalid scope")
            expected = "scap-object/v1/{deployment}/{tenant}/{database}/head".format(**scope)
            equal(case["head_key"], expected, "scope mapped to wrong HEAD key")
        for row in self.clients:
            kind, call_id = row["event"], row["call_id"]
            require(type(call_id) is int and call_id > 0, "invalid call ID")
            if kind == "call":
                require(call_id not in self.calls, "duplicate call ID")
                require((row["case"], row["label"]) not in self.labels, "duplicate invocation label")
                require(row["case"] in CASE_IDS, "call for unplanned case")
                require(row["phase"] == row["case"] + "/" + row["label"], "phase/call binding changed")
                self.calls[call_id] = row
                self.labels[row["case"], row["label"]] = row
            elif kind == "response":
                require(call_id in self.calls and call_id not in self.responses, "orphan/duplicate response")
                require(row["monotonic_ns"] > self.calls[call_id]["monotonic_ns"], "response before invocation")
                require(type(row["response"].get("ok")) is bool, "untyped response status")
                self.responses[call_id] = row
            else:
                raise ValueError("incomplete call: " + kind)
        equal(sorted(self.calls), list(range(1, len(self.calls) + 1)), "call inventory has a gap")
        equal(sorted(self.calls), sorted(self.responses), "call missing a response")
        require(self.calls, "empty evidence cannot pass")
        started = [row for row in self.facts if row["event"] == "worker_started"]
        workers = {row["worker"]: row for row in started}
        require(len(workers) == len(started), "worker identity reused across processes")
        for call in self.calls.values():
            worker = workers.get(call["worker"])
            require(worker is not None, "call has no actual worker identity")
            for name in ("scope", "principal", "case"):
                equal(call[name], worker[name], "call differs from trusted worker configuration")
            require(call["command"].get("budget_ms", 8000) <= 8000, "fixture inflated command timeout")
            expected_scope = self.plan["cases"][CASE_IDS.index(call["case"])]["scope"]
            if call["case"] in ("LC-03", "LC-06"):
                for changed in ("incarnation", "generation"):
                    if call["label"] in ("deleted.create." + changed, "deleted.status." + changed):
                        expected_scope = {**expected_scope, changed: 2}
            equal(call["scope"], expected_scope, "call was moved outside its planned durable scope")
        # The original support history is a second inventory. Dropping client and
        # ACK entries together must not shrink the execution denominator.
        for worker_id in workers:
            calls = [call for call in self.calls.values() if call["worker"] == worker_id]
            invocations = [row for row in self.history if row["event"] == "client_invoked" and row["worker"] == worker_id]
            observed = [row for row in self.history if row["event"] == "client_observed" and row["worker"] == worker_id]
            require(len(calls) == len(invocations) == len(observed), "client/support-history denominator differs")
            for call, invocation, response in zip(calls, invocations, observed):
                command = call["command"]
                equal(command["op"], invocation["operation"], "support operation differs")
                equal(invocation["request_id"], command.get("id", command.get("identity", {}).get("id")), "request ID differs")
                equal(response["ok"], self.response(call)["ok"], "support success differs")
                equal(response.get("error"), self.response(call).get("error"), "support error differs")
                require(call["monotonic_ns"] <= invocation["monotonic_ns"] < response["monotonic_ns"]
                        <= self.responses[call["call_id"]]["monotonic_ns"], "client event interval differs")
        for row in self.inputs:
            identity = row["intent_id"]
            if row["event"] == "input":
                require(identity not in self.intents, "duplicate business intent")
                self.intents[identity] = {**row}
            elif row["event"] == "prepared":
                require(identity in self.intents and "identity" not in self.intents[identity], "orphan/duplicate prepared identity")
                intent = self.intents[identity]
                require(intent["monotonic_ns"] < row["monotonic_ns"], "identity recorded before independent input")
                prepared = self.value(intent["case"], "prepare." + intent["name"])
                equal(prepared, row["identity"], "prepared Request changed in ledger")
                for key in ("epoch", "id", "principal"):
                    equal(prepared[key], intent[key], "prepared identity aliases input")
                require(isinstance(prepared.get("fingerprint"), str) and len(prepared["fingerprint"]) == 64,
                        "missing exact statement fingerprint")
                equal(prepared["fingerprint"], fingerprint(intent["statements"]), "SCAPSQL1 input fingerprint differs")
                intent["identity"] = prepared
                intent["prepared_ns"] = row["monotonic_ns"]
            else:
                raise ValueError("unknown input record")
        for intent in self.intents.values():
            require("identity" in intent, "input not bound to a Request")
        for call in self.calls.values():
            if call["intent_id"] is None:
                continue
            require(call["intent_id"] in self.intents, "call lacks independent input")
            intent = self.intents[call["intent_id"]]
            equal(call["scope"], intent["scope"], "request scope changed")
            equal(call["principal"], intent["principal"], "request principal changed")
            command = call["command"]
            if command["op"] == "prepare_request":
                require(intent["monotonic_ns"] < call["monotonic_ns"], "input was not recorded before preparation")
            else:
                require(intent["prepared_ns"] < call["monotonic_ns"], "business command sent before identity was durable")
            if "identity" in command:
                equal(command["identity"], intent["identity"], "lookup/cancel changed original identity")
            else:
                for key in ("epoch", "id", "statements"):
                    equal(command[key], intent[key], "SQL/parameter/epoch identity changed on retransmission")
        successful = {call_id for call_id, call in self.calls.items()
                      if call["command"]["op"] in ("execute", "session_execute") and self.response(call)["ok"]}
        require(len({ack["call_id"] for ack in self.acks}) == len(self.acks), "duplicate ACK call ID")
        equal(sorted(successful), sorted(ack["call_id"] for ack in self.acks), "execute/ACK denominator differs")
        for ack in self.acks:
            call = self.calls[ack["call_id"]]
            equal(ack["response"], self.response(call), "ACK differs from actual client response")
            equal(ack["intent_id"], call["intent_id"], "ACK attributed to another input")
            equal(ack["case"], call["case"], "ACK attributed to another case")
            equal(ack["observed_ns"], self.responses[call["call_id"]]["monotonic_ns"], "ACK observation time changed")
            require(ack["monotonic_ns"] >= ack["observed_ns"], "ACK recorded before observed response")
            intent = self.intents[call["intent_id"]]
            value = ack["response"]["value"]
            require(set(value["receipt"]) == RECEIPT_FIELDS, "incomplete receipt")
            equal(value["receipt"]["scope"], intent["scope"], "receipt scope differs")
            equal(value["receipt"]["request"], intent["identity"], "receipt identity differs")
            validate_original(value)
            identity = canonical([intent["scope"], intent["identity"]])
            if identity in self.originals:
                original_matches(self.originals[identity], value, replay=True)
            else:
                self.originals[identity] = value
        self.workers = workers

    def network_bindings(self):
        phases = {call["phase"]: call for call in self.calls.values()}
        requests = [row for row in self.history if row["event"] == "object_request"]
        require(requests, "no real object transport evidence")
        for serial in self.network.serials:
            self.network.only(serial, "object_request")
        for raw_request in requests:
            require(raw_request.get("phase") in phases, "network request outside a recorded invocation")
            call = phases[raw_request["phase"]]
            request = self.network.only(raw_request["request_serial"], "object_request")
            response = self.network.only(request["request_serial"], "object_response")
            self.network.exchange(request, response["status"])
            start, end = call["monotonic_ns"], self.responses[call["call_id"]]["monotonic_ns"]
            require(start <= request["monotonic_ns"] < response["monotonic_ns"] <= end,
                    "network request/response outside original call interval")
            scope = call["scope"]
            base = "/scap-test/scap-object/v1/{deployment}/{tenant}/{database}".format(**scope)
            immutable = base + "/inc/{incarnation}/gen/{generation}/objects/".format(**scope)
            path = request["path"]
            if path.endswith("/head"):
                equal(path, base + "/head", "HEAD request mapped to another physical database")
                if request["method"] == "PUT":
                    equal(head(request["head_request_bytes"])["scope"], scope, "HEAD candidate scope differs from caller")
            else:
                require(path.startswith(immutable), "object request mapped to another scope")
                suffix = path[len(immutable):]
                require(len(suffix) == 64 and all(character in "0123456789abcdef" for character in suffix),
                        "invalid immutable object key")
                if request["method"] == "PUT":
                    require(request["if_none_match"] == "*" and request["if_match"] is None,
                            "immutable object write was not conditional create")
        for call in self.calls.values():
            if call["command"]["op"] not in ("prepare_request", "create", "store_put"):
                require(self.network.events(call, "object_response", method="GET", head_only=True),
                        call["label"] + ": missing fresh HEAD observation")
        # Every accepted revision must consume the immediately prior accepted
        # ETag. This detects a whole omitted control call, not just a missing ACK.
        latest, versions = {}, {}
        for row in self.history:
            if row["event"] != "object_response" or not row.get("path", "").endswith("/head") or row.get("status") != 200:
                continue
            path, etag = row["path"], row.get("etag")
            require(isinstance(etag, str) and etag, "successful HEAD observation lacks ETag")
            if row["method"] == "PUT":
                candidate = head(row["head_request_bytes"])
                if path in latest:
                    previous = latest[path]
                    equal(row["if_match"], previous["etag"], "accepted HEAD chain has a missing/refreshed predecessor")
                    require(candidate["revision"] == previous["head"]["revision"] + 1, "accepted revision chain has a gap")
                else:
                    require(row["if_none_match"] == "*" and candidate["revision"] == 1,
                            "authority history did not begin with explicit absent create")
                latest[path] = {"etag": etag, "head": candidate}
                require((path, etag) not in versions, "accepted HEAD ETag was reused")
                versions[path, etag] = row["head_request_bytes"]
            else:
                require((path, etag) in versions, "GET selected an unobserved authority revision")
                equal(row["head_response_bytes"], versions[path, etag], "same ETag returned different HEAD bytes")

    def transitions(self):
        controls = {"set_policy", "set_lifecycle", "takeover", "activate", "activate_session", "close_full"}
        published = {}
        for call in self.calls.values():
            command, response = call["command"], self.response(call)
            operation = command["op"]
            if operation == "store_get":
                self.snapshot(call["case"], call["label"])
            if operation in controls and response["ok"]:
                request, _ = self.network.put(call, 200)
                before, after = self.network.base(call, request), head(request["head_request_bytes"])
                equal(after, response["value"], "control returned a different HEAD")
                require(before["lifecycle"] != "deleted", "control reactivated a deleted identity")
                require(command["revision"] == before["revision"] and after["revision"] == before["revision"] + 1,
                        "control refreshed or ignored expected revision")
                equal(after["transition"], {"revision": after["revision"], "nonce": command["nonce"]}, "control nonce changed")
                for field in ("scope", "sequence", "data_root", "quota", "retention"):
                    equal(before[field], after[field], "control changed " + field)
                if operation == "set_policy":
                    equal(after["policy"], command["policy"], "policy not published")
                    require(after["auth_epoch"] == before["auth_epoch"] + 1, "policy did not advance auth epoch")
                elif operation == "set_lifecycle":
                    equal(after["lifecycle"], command["lifecycle"], "lifecycle not published")
                elif operation == "takeover":
                    require(after["owner_epoch"] == before["owner_epoch"] + 1 and not after["active"], "takeover did not fence")
                    equal(after["owner_instance"], call["worker"], "takeover installed another process")
                elif operation in ("activate", "activate_session"):
                    require(not before["active"] and after["active"], "activation state invalid")
                    equal(after["owner_instance"], call["worker"], "another owner was activated")
                    equal(after["owner_epoch"], before["owner_epoch"], "activation changed owner epoch")
                else:
                    require(before["windows"][0]["count"] == 4, "close_full did not close a full fixture window")
                    require(after["request_epoch"] == before["request_epoch"] + 1, "closed epoch not advanced")
                    equal([window["epoch"] for window in after["windows"]],
                          list(range(after["request_epoch"], max(0, after["request_epoch"] - 3), -1)), "retained epoch inventory changed")
                    require(after["windows"][0]["count"] == 0, "new epoch not empty")
            elif operation == "create":
                request, _ = self.network.put(call, 200 if response["ok"] else 412)
                require(request["if_none_match"] == "*" and request["if_match"] is None, "create was not conditional absent")
                if response["ok"]:
                    equal(head(request["head_request_bytes"]), response["value"], "created HEAD differs")
            elif operation in ("execute", "session_execute") and response["ok"]:
                identity = canonical([call["scope"], response["value"]["receipt"]["request"]])
                puts = self.network.events(call, "object_request", method="PUT", head_only=True)
                if not puts:
                    self.network.no_put(call)
                    require(identity in published, "first execute ACK lacks actual HEAD publication evidence")
                    original_matches(published[identity], response["value"], replay=True)
                    continue
                require(identity not in published, "same business identity published twice")
                request, _ = self.network.put(call, 200)
                before, after = self.network.base(call, request), head(request["head_request_bytes"])
                receipt = response["value"]["receipt"]
                require(after["sequence"] == before["sequence"] + 1 and after["revision"] == before["revision"] + 1,
                        "SQL publication did not advance exactly once")
                for field in ("scope", "sequence", "transition", "data_root"):
                    equal(receipt[field], after[field], "receipt differs from accepted HEAD")
                result_reads = [row for row in self.network.events(call, "object_response", method="GET")
                                if row["path"].endswith("/objects/" + receipt["result_hash"])
                                and row.get("status") == 200 and row.get("response_sha256") == receipt["result_hash"]
                                and row["position"] < request["position"]]
                require(result_reads, "ACK result object was not durably read back before HEAD publication")
                require(self.responses[call["call_id"]]["monotonic_ns"] > self.network.only(request["request_serial"], "object_response")["monotonic_ns"],
                        "execute ACK preceded HEAD acceptance")
                published[identity] = response["value"]
            if operation in ("lookup_identity", "cancel_identity") and response["ok"] and response["value"].get("state") == "cancelled":
                identity = call["intent_id"]
                puts = self.network.events(call, "object_request", method="PUT", head_only=True)
                if puts:
                    request, _ = self.network.put(call, 200)
                    before, after = self.network.base(call, request), head(request["head_request_bytes"])
                    equal(response["value"]["transition"], after["transition"], "cancel proof differs from published HEAD")
                    equal(before["data_root"], after["data_root"], "cancellation changed business data")
                    equal(before["sequence"], after["sequence"], "cancellation changed business sequence")
                else:
                    self.network.no_put(call)
                if identity in self.cancellations:
                    equal(self.cancellations[identity], response["value"], "cancellation proof changed")
                else:
                    self.cancellations[identity] = response["value"]

    def originals_for(self, case):
        result = {}
        for ack in self.acks:
            if ack["case"] == case:
                intent = self.intents[ack["intent_id"]]
                result.setdefault(intent["name"], ack["response"]["value"])
        return result

    def rows(self, case, label, originals):
        call = self.call(case, label)
        equal(call["command"]["sql"], "SELECT id,label,token FROM events ORDER BY id", "audit query changed")
        statements = self.value(case, label)["statements"]
        require(len(statements) == 1, "audit returned extra statements")
        equal(statements[0]["columns"], ["id", "label", "token"], "business columns changed")
        equal(statements[0]["rows"], expected_rows(case, originals), "recovered effects differ from independent input/ACK witnesses")
        self.network.no_put(call)

    def deleted(self, case, prefix, *, variants=False):
        before, before_head = self.snapshot(case, prefix + ".head_before")
        require(before_head["lifecycle"] == "deleted", "missing tombstone")
        for suffix in ("query", "lookup", "activate", "takeover", "set_lifecycle"):
            self.failure(case, prefix + "." + suffix, "Lifecycle")
        self.failure(case, prefix + ".create", "Store(Conflict)", no_put=False)
        if variants:
            for changed in ("incarnation", "generation"):
                call = self.failure(case, prefix + ".create." + changed, "Store(Conflict)", no_put=False)
                expected = {**before_head["scope"], changed: 2}
                equal(call["scope"], expected, "scope-reuse check changed the wrong identity")
                request, _ = self.network.put(call, 412)
                require(request["path"] == "/scap-test/" + self.plan["cases"][CASE_IDS.index(case)]["head_key"],
                        "scope-reuse create used another physical key")
                self.failure(case, prefix + ".status." + changed, "Format(Corrupt)")
        after, _ = self.snapshot(case, prefix + ".head_after")
        equal(before, after, "refused operations changed deleted HEAD")

    def race(self, case, *, commit_first, barrier="barrier", cancel_observation=False):
        candidate = self.call(case, "candidate")
        barrier_call = self.call(case, barrier)
        boundary = self.fact(case, "boundary", call_id=candidate["call_id"])
        release = self.fact(case, "release", call_id=candidate["call_id"])
        equal(release["barrier_label"], barrier, "release refers to wrong control")
        result = race_order(self.network, candidate, barrier_call, boundary, release,
                            commit_first=commit_first, cancel_observation=cancel_observation)
        require(self.responses[barrier_call["call_id"]]["monotonic_ns"] < release["monotonic_ns"],
                "barrier not observed before release")
        require(release["monotonic_ns"] < self.responses[candidate["call_id"]]["monotonic_ns"],
                "candidate result arrived before release")
        if commit_first:
            self.value(case, "candidate")
        else:
            self.failure(case, "candidate", "Conflict", no_put=False)
        return result

    def raw_rejection(self, case, label, old_bytes, old_etag):
        call = self.failure(case, label, "Conflict", no_put=False)
        equal(call["command"]["bytes"], old_bytes, "old candidate bytes were rewritten")
        equal(call["command"]["etag"], old_etag, "old candidate refreshed its ETag")
        request, _ = self.network.put(call, 412)
        equal(request["head_request_bytes"], old_bytes, "transport changed old candidate")
        equal(request["if_match"], old_etag, "transport refreshed old ETag")

    def scenario(self, case, number):
        originals = self.originals_for(case)
        required = {"schema", "seed"} | ({"candidate"} if number in (4, 5, 6, 8) else set())
        if number == 10:
            required |= {"read_execute", "zero_execute"}
        equal(sorted(originals), sorted(required), "successful identity/effect inventory changed")
        expected_rows(case, originals)
        schema = self.intents[case + "/schema"]
        equal(schema["statements"], [{"sql": "CREATE TABLE events(id INTEGER PRIMARY KEY, label TEXT NOT NULL, token INTEGER NOT NULL)"}],
              "schema input profile changed")
        require(schema["principal"] == self.intents[case + "/seed"]["principal"] == 17, "original principal changed")
        schema_result = originals["schema"]["result"]["statements"]
        require(len(schema_result) == 1 and schema_result[0]["columns"] == [] and schema_result[0]["rows"] == [],
                "schema ACK shape differs from its input")
        # The expected SQL/parameters are an independent contract, not values
        # inferred from whatever the recovered database happens to contain.
        for name, row_id in (("seed", 1), ("candidate", 2)):
            intent = self.intents[case + "/" + name]
            expected_sql = f"INSERT INTO events VALUES({row_id},?,random()) RETURNING id,label,token"
            equal(intent["statements"], [{"sql": expected_sql, "parameters": [{"type": "text", "value": case + "-" + name}]}],
                  "business input profile changed")
        if number <= 6:
            self.race(case, commit_first=number >= 4)
            kind = (number - 1) % 3
            barrier = self.value(case, "barrier")
            require(self.call(case, "barrier")["principal"] == 18, "revocation/lifecycle barrier did not use independent admin")
            if kind == 0:
                equal(barrier["policy"], [{"principal": 18, "read": True, "write": True, "admin": True}], "revocation did not remove original principal")
                for suffix in ("query", "lookup"):
                    self.failure(case, "revoked." + suffix, "Denied")
                self.value(case, "restore_policy")
            elif kind == 1:
                equal(barrier["lifecycle"], "maintenance", "maintenance barrier missing")
                self.rows(case, "maintenance.query", originals)
                self.failure(case, "maintenance.write", "Lifecycle")
                self.failure(case, "maintenance.takeover", "Lifecycle")
                equal(self.value(case, "restore_ready")["lifecycle"], "ready", "maintenance not explicitly ended")
            else:
                equal(barrier["lifecycle"], "deleted", "deleted barrier missing")
                self.deleted(case, "deleted", variants=True)
            if number in (1, 2):
                self.state(case, "candidate.unknown", "unknown")
        elif number in (7, 8):
            _, candidate, _ = self.race(case, commit_first=number == 8, cancel_observation=number == 8)
            result = self.value(case, "barrier")
            if number == 7:
                require(result["state"] == "cancelled", "cancel-first was not cancelled")
                request, _ = self.network.put(self.call(case, "barrier"), 200)
                equal(result["transition"], head(request["head_request_bytes"])["transition"], "cancel proof differs from published transition")
                self.failure(case, "cancelled.execute", "Closed")
                equal(self.state(case, "cancelled.lookup", "cancelled"), result, "cancelled lookup changed")
            else:
                original_matches(originals["candidate"], result)
        elif number == 9:
            call = self.failure(case, "cancel_lost", "Store(Unknown)", no_put=False)
            request, response = self.network.put(call, 200)
            self.network.base(call, request)
            boundary = self.fact(case, "boundary", call_id=call["call_id"])
            equal(boundary["payload"], request["head_request_bytes"], "lost cancellation bytes changed")
            observed = self.network.only(request["request_serial"], "transport_fault_observed")
            require(observed["mode"] == "drop" and observed["stage"] == "after_upstream_response", "UNKNOWN not after accepted cancellation")
            require(response["suppressed"] is True and not any(row["event"] == "object_response_delivered"
                                                               for row in self.network.serials[request["request_serial"]]),
                    "lost cancellation response was delivered")
            proof = self.state(case, "cancel.confirmed", "cancelled")
            equal(proof["transition"], head(request["head_request_bytes"])["transition"], "UNKNOWN resolved to another cancellation")
            self.failure(case, "cancelled.execute", "Closed")
            equal(self.state(case, "cancelled.lookup", "cancelled"), proof, "cancel proof changed")
        elif number == 10:
            original_matches(originals["seed"], self.value(case, "duplicate_seed"), replay=True)
            for label in ("changed_sql", "changed_parameter", "changed_principal", "future_epoch"):
                self.failure(case, label, "RequestConflict")
            seed = self.intents[case + "/seed"]
            for label in ("changed_sql", "changed_parameter"):
                altered = self.intents[case + "/" + label]
                require(altered["identity"]["fingerprint"] != seed["identity"]["fingerprint"], "changed statement used old fingerprint")
            require(self.intents[case + "/changed_principal"]["principal"] == 18, "changed principal check did not use another principal")
            require(self.intents[case + "/future_epoch"]["epoch"] == 2, "future epoch check did not use future epoch")
            for label in ("read_execute", "zero_execute"):
                zero_page_input(label, self.intents[case + "/" + label]["statements"])
                call = self.call(case, label)
                request, _ = self.network.put(call, 200)
                before = self.network.base(call, request)
                equal(before["data_root"], head(request["head_request_bytes"])["data_root"], "zero-page transaction changed data root")
            read_statements = self.value(case, "read_execute")["result"]["statements"]
            require(len(read_statements) == 1, "read execute statement count changed")
            equal(read_statements[0]["columns"], ["token"], "read execute result missing")
            read_rows = read_statements[0]["rows"]
            require(len(read_rows) == 1 and len(read_rows[0]) == 1 and type(read_rows[0][0]) is int
                    and -(2 ** 63) <= read_rows[0][0] < 2 ** 63, "read execute missing original random() witness")
            zero_statements = self.value(case, "zero_execute")["result"]["statements"]
            require(len(zero_statements) == 1 and zero_statements[0]["columns"] == []
                    and zero_statements[0]["rows"] == [] and zero_statements[0]["affected_rows"] == 0,
                    "zero-change UPDATE changed a row or result shape")
            self.failure(case, "full_window", "WindowFull")
            require(self.value(case, "close_full")["request_epoch"] == 2, "full window not closed")
            original_matches(originals["seed"], self.value(case, "closed_duplicate"), replay=True)
        elif number == 11:
            _, candidate, _ = self.race(case, commit_first=False)
            original_matches(originals["seed"], self.state(case, "closed.seed", "committed"))
            self.state(case, "closed.absent", "closed")
            for epoch, count in ((1, 2), (2, 4), (3, 4)):
                for index in range(count):
                    value = self.value(case, f"fill_{epoch}_{index}")
                    require(value["state"] == "cancelled", "epoch filled without real cancellations")
                closed = self.value(case, "barrier" if epoch == 1 else f"close_{epoch}")
                require(closed["request_epoch"] == epoch + 1, "retirement sequence skipped an epoch")
            self.state(case, "retired.seed", "retired")
            self.raw_rejection(case, "retired.raw_candidate", candidate["head_request_bytes"], candidate["if_match"])
        else:
            _, candidate, _ = self.race(case, commit_first=False, barrier="owner_a2.activate")
            owners = [self.call(case, label)["worker"] for label in ("candidate", "owner_b.takeover", "owner_a2.takeover")]
            require(len(set(owners)) == 3, "ABA reused a live process identity")
            b, a2 = self.value(case, "owner_b.activate"), self.value(case, "owner_a2.activate")
            require(a2["owner_epoch"] == b["owner_epoch"] + 1, "second takeover did not advance owner epoch")
            self.failure(case, "old_owner", "Fenced")
            before, old = self.snapshot(case, "aba.before")
            after, new = self.snapshot(case, "aba.after")
            require(old["lifecycle"] == new["lifecycle"] == "ready" and new["revision"] == old["revision"] + 2,
                    "ABA return did not advance authority")
            require(before["etag"] != after["etag"], "ABA retained old ETag")
            for field in ("scope", "data_root", "sequence", "owner_epoch", "owner_instance", "policy", "auth_epoch", "windows"):
                equal(old[field], new[field], "ABA changed unrelated " + field)
            self.failure(case, "aba.stale_revision", "Conflict")
            equal(self.call(case, "aba.stale_revision")["command"]["revision"], old["revision"], "stale-revision check used latest revision")
            self.raw_rejection(case, "aba.raw_candidate", candidate["head_request_bytes"], candidate["if_match"])
            self.raw_rejection(case, "aba.raw_snapshot", before["bytes"], before["etag"])
            self.state(case, "candidate.unknown", "unknown")
        return originals

    def recovery(self, case, originals, number):
        frozen, frozen_head = self.snapshot(case, "pre_loss")
        deleted, retired = number in (3, 6), number == 11
        class_name = "deleted_access" if deleted else "retired" if retired else "retained_original"
        case_acks = [ack for ack in self.acks if ack["case"] == case]
        require(case_acks, "no ACK denominator for case")
        for stage in STAGES:
            loss = self.fact(case, "compute_lost", stage="compute_recovery" if stage == "compute_recovery" else "before_backend")
            recovery = self.fact(case, "recovery_started", stage=stage)
            require(loss["monotonic_ns"] < recovery["monotonic_ns"], "recovery preceded confirmed compute loss")
            require(recovery["worker"] not in [row["worker"] for row in loss["stopped"]], "recovery reused old worker identity")
            before, before_head = self.snapshot(case, stage + ".head_before")
            for field in ("data_root", "sequence", "lifecycle", "request_epoch", "windows", "policy"):
                equal(before_head[field], frozen_head[field], "recovery selected another durable " + field)
            if deleted:
                equal(before, frozen, "tombstone changed across process/backend loss")
                self.deleted(case, stage + ".deleted")
            else:
                self.value(case, stage + ".takeover")
                self.value(case, stage + ".activate_session")
                self.rows(case, stage + ".rows", originals)
            for name, original in originals.items():
                prefix = stage + ".ack." + name
                if deleted:
                    self.failure(case, prefix + ".lookup", "Lifecycle")
                elif retired:
                    self.state(case, prefix + ".lookup", "retired")
                    self.failure(case, prefix + ".replay", "Retired")
                else:
                    original_matches(original, self.state(case, prefix + ".lookup", "committed"))
                    original_matches(original, self.value(case, prefix + ".replay"), replay=True)
                    self.network.no_put(self.call(case, prefix + ".replay"))
            if not deleted and number != 10:
                label = stage + ".candidate.lookup"
                expected = "cancelled" if number in (7, 9) else "retired" if retired else "committed" if number in (4, 5, 8) else "unknown"
                value = self.state(case, label, expected)
                if expected == "cancelled":
                    equal(value, self.cancellations[case + "/candidate"], "recovery changed cancellation")
                    self.failure(case, stage + ".candidate.execute", "Closed")
                elif expected == "committed":
                    original_matches(originals["candidate"], value)
            for intent_id, proof in self.cancellations.items():
                intent = self.intents[intent_id]
                if intent["case"] != case or intent["name"] == "candidate":
                    continue
                prefix = stage + ".cancel." + intent["name"]
                if retired and intent["epoch"] == 1:
                    self.state(case, prefix + ".lookup", "retired")
                    self.failure(case, prefix + ".execute", "Retired")
                else:
                    equal(self.state(case, prefix + ".lookup", "cancelled"), proof,
                          "recovery changed a retained cancellation proof")
                    self.failure(case, prefix + ".execute", "Closed")
            _, after_head = self.snapshot(case, stage + ".head_after")
            equal(after_head["data_root"], frozen_head["data_root"], "result audits changed business root")
            self.fact(case, "recovery_observed", stage=stage)
        self.ack_classes[class_name] += len(case_acks)
        self.case_results.append({"id": case, "status": "passed", "ack_responses": len(case_acks),
                                  "ack_identities": len(originals), "ack_classification": class_name,
                                  "recovery_stages": list(STAGES)})

    def process_and_build(self):
        from audit_build import OwnedChildren, receipt
        self.build_audit=receipt(self.data["_evidence_directory"],profile="network",
                                require_artifacts=self.data.get("_require_artifacts",True))
        equal(self.build_audit["binary"],self.data["build"]["binary"],"archived receipt differs from loaded original build")
        children=OwnedChildren()
        stopped = set()
        lifetimes = {}
        identity_fields = {"pid", "spawn_monotonic_ns", "pid_source", "self_proc_pid", "self_start_ticks"}
        for worker_id, started in self.workers.items():
            require(set(started["identity"]) == identity_fields, "worker lacks complete Popen/procfs identity")
            history = [row for row in self.history if row["event"] == "worker_started" and row["worker"] == worker_id]
            require(len(history) == 1, "worker start fact lacks unique original observation")
            equal(history[0]["binary"],self.build_audit["binary"],"actual owned worker used another release executable")
            equal(started["binary"],history[0]["binary"],"worker fact changed original executable identity")
            equal(started["identity"], {key: history[0][key] for key in identity_fields}, "worker start identities differ")
            require(history[0]["monotonic_ns"] <= started["monotonic_ns"], "worker fact precedes original start observation")
            lifetimes[worker_id] = [started["monotonic_ns"], None]
        for case in CASE_IDS:
            for stage in ("compute_recovery", "before_backend", "final_cleanup"):
                loss = self.fact(case, "compute_lost", stage=stage)
                require(loss["existed_before"] is True and loss["exists_after"] is False and loss["stopped"],
                        "compute directory deletion or process-loss denominator missing")
                require(Path(loss["directory"]).name==case,"compute deletion selected another case directory")
                equal(loss["directory"],self.fact(case,"compute_lost",stage="compute_recovery")["directory"],
                      "cache deletion changed the original per-case compute tree")
                for process in loss["stopped"]:
                    require(process["wait_status"] == -9 and process["kernel_usage"].get("available") is True
                            and process["kernel_usage"].get("source") == "kernel_wait4_owned_child",
                            "compute SIGKILL lacks actual wait4 evidence")
                    require(type(process["kernel_usage"].get("maxrss_bytes")) is int and process["kernel_usage"]["maxrss_bytes"]>0,
                            "compute wait4 lacks actual kernel resource witness")
                    worker_id = process["worker"]
                    require(worker_id not in stopped and worker_id in self.workers, "worker missing/double-counted in loss evidence")
                    require(self.workers[worker_id]["case"]==case,"cache loss counted another case's computation")
                    equal(process["pid"], self.workers[worker_id]["identity"]["pid"], "killed an unrelated process")
                    stopped.add(worker_id)
                    events = [row for row in self.history if row["event"] == "worker_stopped" and row["worker"] == worker_id]
                    require(len(events) == 1 and events[0]["fault"] is True and events[0]["wait_status"] == -9,
                            "process-loss fact does not match original process history")
                    equal(process, {key: events[0][key] for key in process}, "wait4/identity facts differ from original process history")
                    for key in identity_fields:
                        equal(process[key], self.workers[worker_id]["identity"][key], "stopped another process incarnation")
                    require(events[0]["monotonic_ns"] < loss["monotonic_ns"], "directory loss recorded before worker termination")
                    lifetimes[worker_id][1] = events[0]["monotonic_ns"]
                    children.register(self.workers[worker_id]["identity"],events[0]["monotonic_ns"])
        equal(sorted(stopped), sorted(self.workers), "some compute processes never lost their full cache")
        raw_started=[row["worker"] for row in self.history if row["event"]=="worker_started"]
        equal(sorted(raw_started),sorted(self.workers),"original process start denominator differs from worker facts")
        invoked=[row for row in self.history if row["event"]=="client_invoked"]
        observed=[row for row in self.history if row["event"]=="client_observed"]
        require(len(invoked)==len(self.calls) and len(observed)==len(self.responses),"original invocation/response denominator changed")
        for call in self.calls.values():
            start, end = lifetimes[call["worker"]]
            require(start <= call["monotonic_ns"] < self.responses[call["call_id"]]["monotonic_ns"] <= end,
                    "call outside verified worker lifetime")
            resources = self.response(call)["resources"]
            identity = self.workers[call["worker"]]["identity"]
            equal([resources["namespace_pid"], resources["proc_pid"], resources["start_ticks"]],
                  [identity["pid"], identity["self_proc_pid"], identity["self_start_ticks"]], "response came from another process")
            ending=self.responses[call["call_id"]]["monotonic_ns"]
            original=[row for row in invoked if row["worker"]==call["worker"] and call["monotonic_ns"]<=row["monotonic_ns"]<ending]
            require(len(original)==1 and original[0]["operation"]==call["command"]["op"] and original[0]["pid"]==identity["pid"],
                    "client ledger changed original stdin invocation/process")
            original=[row for row in observed if row["worker"]==call["worker"] and call["monotonic_ns"]<row["monotonic_ns"]<=ending]
            require(len(original)==1,"complete response lacks original owned process observation")
            response=self.response(call)
            equal([original[0]["ok"],original[0]["error"],original[0]["resources"]],
                  [response["ok"],response.get("error"),response["resources"]],"original owned process response changed")
        old = self.fact(None, "backend_started")["identities"]
        killed = self.fact(None, "backend_stopped")
        stopping = self.fact(None, "backend_stopping")
        restarted = self.fact(None, "backend_restarted")
        new = restarted["identities"]
        require(killed["live_compute_workers"] == 0, "backend restarted with old computation still live")
        require(stopping["live_compute_workers"] == 0 and stopping["monotonic_ns"] < killed["monotonic_ns"]
                < restarted["monotonic_ns"], "backend stop/restart order changed")
        require(not any(start <= stopping["monotonic_ns"] <= end for start, end in lifetimes.values()),
                "actual process history contradicts zero live compute workers at backend cut")
        for case in CASE_IDS:
            loss = self.fact(case, "compute_lost", stage="before_backend")
            require(loss["monotonic_ns"] < stopping["monotonic_ns"], "backend cut preceded complete compute loss")
            for stage in STAGES:
                recovery = self.fact(case, "recovery_started", stage=stage)
                loss = self.fact(case, "compute_lost", stage="compute_recovery" if stage == "compute_recovery" else "before_backend")
                if stage == "backend_recovery":
                    require(restarted["monotonic_ns"] < recovery["monotonic_ns"], "backend recovery preceded actual restart")
                for call in self.calls.values():
                    if call["case"] == case and call["label"].startswith(stage + "."):
                        require(self.workers[call["worker"]]["monotonic_ns"] > loss["monotonic_ns"], "recovery used computation from before cache loss")
                        require(call["monotonic_ns"] >= recovery["monotonic_ns"], "stage call preceded recorded recovery")
                        if not call["label"].startswith(stage + ".cancel."):
                            equal(call["worker"], recovery["worker"], "recovery fact names a different worker from actual calls")
        expected_roles = ["master", "volume", "filer", "s3"]
        for group in (old, killed["identities"], new):
            equal([row["role"] for row in group], expected_roles, "backend process denominator changed")
        for before, gone, after in zip(old, killed["identities"], new):
            for key in ("pid", "spawn_monotonic_ns", "pid_source", "role"):
                equal(before[key], gone[key], "backend killed wrong process incarnation")
            require(gone["wait_status"] == -9 and gone["kernel_usage"].get("available") is True,
                    "backend process loss not confirmed")
            require(gone["kernel_usage"].get("source") == "kernel_wait4_owned_child",
                    "backend process loss lacks kernel wait4 evidence")
            require(type(gone["kernel_usage"].get("maxrss_bytes")) is int and gone["kernel_usage"]["maxrss_bytes"]>0,
                    "backend wait4 lacks original kernel resource witness")
            require((before["pid"], before["spawn_monotonic_ns"]) != (after["pid"], after["spawn_monotonic_ns"]),
                    "backend was not restarted")
            require(killed["monotonic_ns"] < after["spawn_monotonic_ns"] < restarted["monotonic_ns"],
                    "replacement backend was not spawned after the confirmed cut")
            require(after["pid_source"] == "owned_Popen_child", "replacement backend identity is not an owned child")
            require(before["spawn_monotonic_ns"]<self.fact(None,"backend_started")["monotonic_ns"],"backend start preceded owned spawn")
            children.register(before,killed["monotonic_ns"])
        final = self.fact(None, "backend_cleanup")
        equal([row["role"] for row in final["identities"]], expected_roles, "final backend cleanup denominator changed")
        for born, gone in zip(new, final["identities"]):
            children.register(born,final["monotonic_ns"])
            for key in ("pid", "spawn_monotonic_ns", "pid_source", "role"):
                equal(born[key], gone[key], "final backend cleanup stopped another incarnation")
            require(gone["wait_status"] == -9 and gone["kernel_usage"].get("available") is True,
                    "final backend process exit was not observed")
            require(gone["kernel_usage"].get("source") == "kernel_wait4_owned_child",
                    "final backend process exit lacks kernel wait4 evidence")
            require(type(gone["kernel_usage"].get("maxrss_bytes")) is int and gone["kernel_usage"]["maxrss_bytes"]>0,
                    "backend cleanup lacks original kernel resource witness")
        require(all(self.fact(case, "compute_lost", stage="final_cleanup")["monotonic_ns"] < final["monotonic_ns"]
                    for case in CASE_IDS), "final backend stopped before final compute cleanup")
        build = self.data["build"]
        equal(build["binary"]["sha256"], self.plan["binary_sha256"], "wrong worker build")
        equal(build["input_sha256"], self.plan["input_sha256"], "wrong source inputs")
        for stage in ("before", "after"):
            checked = self.fact(None, "build_verified", stage=stage)
            for key in ("binary_sha256", "input_sha256"):
                equal(checked[key], self.plan[key], "frozen candidate identity changed")
        cleanup = self.fact(None, "cleanup_observed")
        require(cleanup["proxy_errors"] == [] and cleanup["cleanup_errors"] == [], "cleanup errors cannot pass")
        require(not any(row["event"] in ("transport_fixture_failed","client_transport_failed","client_invocation_lost_with_process")
                        for row in self.history), "original transport/process failure hidden")
        self.build_audit["unique_child_incarnations"]=len(children.incarnations)

    def run(self):
        self.inventory()
        self.network_bindings()
        self.transitions()
        for number, case in enumerate(CASE_IDS, 1):
            originals = self.scenario(case, number)
            self.recovery(case, originals, number)
        self.process_and_build()
        require(sum(self.ack_classes.values()) == len(self.acks), "ACK was omitted from final classification")
        execute = [call for call in self.calls.values() if call["command"]["op"] in ("execute", "session_execute")]
        committed_observations = [call for call in self.calls.values() if call["command"]["op"] in ("lookup_identity", "cancel_identity")
                                 and self.response(call)["ok"] and self.response(call)["value"].get("state") == "committed"]
        unresolved = [call for call in committed_observations
                      if not any(ack["intent_id"] == call["intent_id"] for ack in self.acks)]
        before_ack = [call for call in committed_observations
                      if not any(ack["intent_id"] == call["intent_id"] and ack["observed_ns"]
                                 <= self.responses[call["call_id"]]["monotonic_ns"] for ack in self.acks)]
        terminal_observations = Counter(self.response(call).get("value", {}).get("state")
                                        for call in self.calls.values() if self.response(call)["ok"])
        rejected_candidates = [call["call_id"] for call in execute if call["label"] == "candidate"
                               and self.response(call).get("error") == "Conflict"]
        deleted_checks = sum(call["case"] in ("LC-03", "LC-06") and self.response(call).get("error") == "Lifecycle"
                             for call in self.calls.values())
        revoked_checks = sum(call["case"] in ("LC-01", "LC-04") and self.response(call).get("error") == "Denied"
                             for call in self.calls.values())
        return {"status": "passed", "case_results": self.case_results, "planned_cases": len(CASE_IDS),
                "checked_cases": len(self.case_results), "inputs": len(self.intents),
                "execute_responses": len(execute), "ack_responses": len(self.acks), "ack_identities": len(self.originals),
                "ack_classifications": dict(self.ack_classes),
                "resolved_without_execute_ack_identities": len({call["intent_id"] for call in unresolved}),
                "resolved_without_execute_ack_observations": len(unresolved),
                "committed_observations_before_execute_ack": len(before_ack),
                "cancellation_identities": len(self.cancellations),
                "cancellation_proof_observations": terminal_observations["cancelled"],
                "rejected_candidate_calls": rejected_candidates, "retired_lookup_checks": terminal_observations["retired"],
                "closed_lookup_checks": terminal_observations["closed"],
                "deleted_access_checks": deleted_checks, "revoked_access_checks": revoked_checks,
                "ack_mismatches": 0,
                "aws_endpoint_gate": "NOT_RUN", "production_slo_passed": False, "unit_coverage_contribution": False}


def read_sources(evidence):
    names = {"plan": "lifecycle-plan.json", "inputs": "lifecycle-input-ledger.jsonl",
             "clients": "lifecycle-client-ledger.jsonl", "acks": "lifecycle-ack-ledger.jsonl",
             "facts": "lifecycle-facts.jsonl", "history": "history.jsonl", "build": "build-receipt.json"}
    data = {}
    for key, name in names.items():
        raw = (evidence / name).read_bytes()
        require(raw and raw.endswith(b"\n"), "missing/truncated evidence: " + name)
        data[key] = [parse(line) for line in raw.splitlines()] if name.endswith("jsonl") else parse(raw)
    data["_evidence_directory"]=Path(evidence)
    return data


def audit(evidence, *, require_artifacts=True):
    checker = None
    try:
        data=read_sources(evidence)
        data["_require_artifacts"]=require_artifacts
        checker = Audit(data)
        result = checker.run()
        result["build"]=checker.build_audit
        if checker.build_audit["verification_scope"]!="full":result["status"]="partial"
    except Exception as error:
        result = {"status": "failed", "planned_cases": 12,
                  "checked_cases": 0 if checker is None else len(checker.case_results),
                  "error_type": type(error).__name__, "error": str(error),
                  "aws_endpoint_gate": "NOT_RUN", "production_slo_passed": False,
                  "unit_coverage_contribution": False}
    result["source_sha256"] = {name: hashlib.sha256((evidence / name).read_bytes()).hexdigest()
                               for name in SOURCE_FILES if (evidence / name).is_file()}
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--allow-unavailable-artifacts",action="store_true",help="explicit partial offline audit; never a full release gate")
    arguments = parser.parse_args(argv)
    result = audit(arguments.evidence.resolve(),require_artifacts=not arguments.allow_unavailable_artifacts)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
