#!/usr/bin/env python3
"""Read-only original HTTP/S3/process isolation audit; never imports controllers."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
import signal
import struct
from urllib.parse import urlparse

from audit_wire import b64, committed, equal, fingerprint, object_exchanges, object_versions, parse, require, result
from isolation_spec import ADMISSION, BACKEND_VERSION, CACHE, CALLS, DEADLINES, PHASES, PLAN, SCOPES
from service_oracle import build_receipt, exchanges, exited, identity, only, rows, stamp, value_of

FILES = ("isolation-plan.json", "isolation-tools.json", "isolation-service-config.json", "history.jsonl",
         "process-ledger.jsonl", "http-client-ledger.jsonl", "isolation-calls.jsonl", "isolation-inputs.jsonl",
         "isolation-acks.jsonl", "isolation-lookups.jsonl", "isolation-phases.jsonl")
QUERY = [{"sql": "SELECT id,payload,label,nonce FROM witness ORDER BY id", "params": []}]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def window(call, moment):
    return stamp(call["request"]) < moment < stamp(call["response"])


def numbered(ledger):
    require([row["sequence"] for row in ledger] == list(range(1, len(ledger) + 1)), "missing original trace row")
    require(all(type(row.get("schema")) is int and row["schema"] == 1 for row in ledger), "trace schema changed")
    require(all(stamp(left) < stamp(right) for left, right in zip(ledger, ledger[1:])), "original trace clock order")


def client_hello(child, hello, finished):
    # The parent logs after Popen returns. A child can run before that log, or
    # even before the parent's post-Popen identity sample. Use the pre-Popen
    # launch witness as the lower bound; never reorder genuine child events.
    require(hello["pid_source"] == "node_process.pid" and type(hello["self_pid"]) is int and hello["self_pid"] > 0 and
            child["spawn_requested_ns"] < stamp(hello) < stamp(finished), "client self PID/lifetime witness changed")


def labeled_calls(directory, calls):
    ledger = rows(directory, "isolation-calls.jsonl")
    observed = {}
    for phase in PHASES:
        starts = [row for row in ledger if row["phase"] == phase and row["event"] == "call_started"]
        finished = [row for row in ledger if row["phase"] == phase and row["event"] == "call_finished"]
        equal([(row["label"], row["name"], row["operation"]) for row in starts], CALLS[phase], "all-call input denominator changed")
        equal([row["label"] for row in finished], [item[0] for item in CALLS[phase]], "call outcome inventory changed")
        previous = 0
        for first, last in zip(starts, finished):
            label, name, operation = first["label"], first["name"], first["operation"]
            call = calls[last["call_id"]]
            require(label not in observed and call["request"]["phase"] == phase and call["request"]["client"] == name,
                    "call result points to another original client")
            equal(call["body"]["scope"], SCOPES[name], "call entered another database")
            require(call["body"]["operation"] == operation, "call operation changed")
            require(previous < stamp(first) < stamp(call["request"]) < stamp(call["response"]) < stamp(last), "original call interval changed")
            require(stamp(call["response"]) - stamp(call["request"]) <= DEADLINES["client_request_ms"] * 1000000,
                    "original client request deadline exceeded")
            expected = "BACKPRESSURE" if label == "c_at_capacity" else "ok"
            require(last["outcome"] == expected, "unexpected call outcome")
            if expected == "ok":
                value_of(call)
            else:
                require(call["response"]["status"] == 429 and call["value"] == {"ok": False, "error": {"code": "BACKPRESSURE", "message": "BACKPRESSURE"}},
                        "capacity refusal did not preserve the typed HTTP outcome")
            observed[label] = call
            previous = stamp(last)
    require(len(ledger) == 2 * PLAN["http_invocations"] and len(calls) == PLAN["http_invocations"], "missing or extra actual HTTP invocation")
    require({row["call_id"] for row in ledger if row["event"] == "call_finished"} == set(calls), "unaccounted HTTP attempt/retry")
    phase_rows = rows(directory, "isolation-phases.jsonl")
    require(Counter(row["phase"] for row in phase_rows) == Counter(PHASES), "phase result denominator changed")
    for row in phase_rows:
        require(row["calls"] == row["sdk_http_attempts"] == len(CALLS[row["phase"]]), "SDK retried or omitted a planned call")
    return observed


def sql_results(directory, observed):
    inputs, acks, lookups = (rows(directory, name) for name in
                            ("isolation-inputs.jsonl", "isolation-acks.jsonl", "isolation-lookups.jsonl"))
    for ledger in (inputs, acks, lookups):
        require(Counter(row["name"] for row in ledger) == Counter(("a", "b")), "original SQL/result denominator changed")
    originals = {}
    for index, name in enumerate(("a", "b")):
        source = only([row for row in inputs if row["name"] == name], "SQL input inventory")
        ack = only([row for row in acks if row["name"] == name], "original commit response inventory")
        saved = parse(source["request"])
        require(set(saved) == {"scope", "request", "statements"}, "saved original request fields")
        equal(saved["scope"], SCOPES[name], "original input scope changed")
        statements = saved["statements"]
        payload = b64(statements[1]["params"][0]["base64"])
        label = "\ufeff隔离\0😀-" + name
        require(len(payload) == source["payload_bytes"] == PLAN["blob_bytes"][name] and
                sha(payload) == source["payload_sha256"] and source["label"] == label, "original BLOB input changed")
        equal(statements, [{"sql": "CREATE TABLE witness(id INTEGER PRIMARY KEY,payload BLOB,label TEXT,nonce INTEGER)", "params": []},
                          {"sql": "INSERT INTO witness VALUES(1,?1,?2,random()) RETURNING id,payload,label,nonce",
                           "params": [{"type": "blob", "base64": statements[1]["params"][0]["base64"]},
                                      {"type": "text", "value": label}]}], "SQL workload changed")
        equal(saved["request"], {"epoch": "1", "id": "1", "principal": "11", "fingerprint": fingerprint(statements)},
              "original SQL identity/fingerprint changed")
        call = observed[name + "_execute"]
        equal(call["body"], {"version": 1, "scope": SCOPES[name], "operation": "execute",
                             "request": saved["request"], "statements": statements}, "execute differs from original saved input")
        raw, decoded = committed(value_of(call))
        require(ack["call_id"] == call["request"]["call_id"] and ack["request"] == source["request"], "ACK bound another original input")
        require(stamp(source) < stamp(call["request"]) < stamp(call["response"]) < stamp(ack), "input was not durable before execution")
        equal(ack["receipt"], value_of(call)["receipt"], "ACK receipt differs from original HTTP bytes")
        require(b64(ack["raw"]) == raw and ack["raw_sha256"] == sha(raw), "ACK raw bytes/hash differ from original HTTP response")
        equal(ack["receipt"]["scope"], SCOPES[name], "receipt scope changed")
        equal(ack["receipt"]["request"], saved["request"], "receipt request identity changed")
        require(ack["receipt"]["sequence"] == "1" and ack["receipt"]["transition"] == {"revision": "3", "nonce": "1"}, "commit transition changed")
        require(len(decoded) == 2 and decoded[0]["columns"] == [] and decoded[0]["rows"] == [] and
                decoded[1]["columns"] == ["id", "payload", "label", "nonce"] and len(decoded[1]["rows"]) == 1,
                "original complete result shape changed")
        row = decoded[1]["rows"][0]
        require(row[:3] == [1, payload, label] and type(row[3]) is int and -(2**63) <= row[3] < 2**63,
                "original SQLite random/result values changed")
        original = only([row for row in lookups if row["name"] == name], "lookup inventory")
        lookup = observed[name + "_original_lookup"]
        equal(lookup["body"], {"version": 1, "scope": SCOPES[name], "operation": "lookup", "request": saved["request"]},
              "lookup changed its original request")
        equal(value_of(lookup), value_of(call), "original committed response was regenerated")
        require(original["original_call_id"] == ack["call_id"] and original["call_id"] == lookup["request"]["call_id"] and
                stamp(lookup["response"]) < stamp(original), "lookup lost original response provenance")
        for key in ("receipt", "raw", "raw_sha256"):
            equal(original[key], ack[key], "lookup original bytes changed: " + key)
        originals[name] = {"input": saved, "ack": ack, "raw": raw, "rows": decoded[1]["rows"], "columns": decoded[1]["columns"]}
        for operation, nonce, revision, active in (("create", 501 + index*10, "1", False), ("activate", 502 + index*10, "2", True)):
            target = observed[name + "_" + operation]
            expected = {"version": 1, "scope": SCOPES[name], "operation": operation, "nonce": str(nonce)}
            if operation == "activate":
                expected["expected_revision"] = "1"
            equal(target["body"], expected, "administrative original input changed")
            value = value_of(target)
            require(value["revision"] == revision and value["sequence"] == "0" and value["active"] is active and
                    value["owner_instance"] == str(PLAN["owner_instance"]), "seed administrative state changed")
            equal(value["scope"], SCOPES[name], "seed returned another scope")
    query_count = 0
    for label, call in observed.items():
        operation = call["body"]["operation"]
        if operation == "query":
            name = call["request"]["client"]
            expected = [{"sql": "SELECT 999", "params": []}] if name == "c" else QUERY
            equal(call["body"], {"version": 1, "scope": SCOPES[name], "operation": "query", "statements": expected}, "query input changed")
            if name == "c":
                continue
            decoded = result(b64(value_of(call)["result"]))
            require(len(decoded) == 1 and decoded[0]["columns"] == originals[name]["columns"] and
                    decoded[0]["rows"] == originals[name]["rows"] and decoded[0]["affected_rows"] == 0,
                    "query differs from exact original BLOB/random result")
            query_count += 1
        if operation in ("open", "status"):
            equal(call["body"], {"version": 1, "scope": SCOPES["a"], "operation": operation}, "control/open input changed")
            value = value_of(call)
            require(value["revision"] == "3" and value["sequence"] == "1" and value["active"] is True and
                    value["owner_instance"] == str(PLAN["owner_instance"]), "control/open lost current authority")
            equal(value["scope"], SCOPES["a"], "control/open returned another scope")
    require(query_count == PLAN["successful_queries"], "successful original data query denominator changed")
    return originals


def envelope(raw, path):
    require(len(raw) >= 20 and raw[:8] == b"SCAPOBJ2" and sha(raw) == path.rsplit("/", 1)[1], "immutable bytes/key mismatch")
    metadata_bytes, raw_bytes = struct.unpack_from("<IQ", raw, 8)
    require(20 + metadata_bytes + raw_bytes == len(raw), "immutable frame length mismatch")
    metadata = parse(raw[20:20 + metadata_bytes])
    require(set(metadata) == {"format", "scope", "payload"} and metadata["format"] == 2, "immutable metadata format changed")
    scope = metadata["scope"]
    expected = f"/scap-test/scap-object/v1/{scope['deployment']}/{scope['tenant']}/{scope['database']}/inc/{scope['incarnation']}/gen/{scope['generation']}/storage/1/objects/"
    require(path.startswith(expected), "immutable frame scope differs from exact key")
    return metadata["payload"], raw[20 + metadata_bytes:]


def tree(objects, prefix, root):
    selected = set()
    def load(digest, kind):
        key = prefix + digest
        selected.add(key)
        payload, raw = envelope(objects[key], key)
        require(payload["kind"] == kind, "typed page-tree dependency changed")
        return payload["value"], raw
    manifest, raw = load(root, "manifest")
    require(not raw and set(manifest) == {"page_count", "root"} and type(manifest["page_count"]) is int and
            0 < manifest["page_count"] <= 256 * 32, "test page-tree extent changed")
    node, raw = load(manifest["root"], "node")
    require(not raw and node["level"] == 0 and node["first_chunk"] == 0 and
            len(node["children"]) == (manifest["page_count"] + 31)//32, "test node extent changed")
    chunks = []
    for index, digest in enumerate(node["children"]):
        value, raw = load(digest, "chunk")
        require(value == {"first_page": index*32 + 1, "bytes": []} and
                len(raw) == min(32, manifest["page_count"] - index*32) * 4096, "page chunk position/extent changed")
        chunks.append(raw)
    image = b"".join(chunks)
    require(image[:16] == b"SQLite format 3\0" and image[16:18] == b"\x10\0", "restored bytes are not a 4096-byte SQLite image")
    return selected, prefix + node["children"][0], len(image), len(chunks)


def network(history, calls, observed, originals, facts, configuration):
    numbered(history)
    allowed = {"phase_started", "transport_fault_armed", "transport_fault_observed", "gate_released",
               "object_request", "object_forwarded", "object_response", "object_response_delivered"}
    require(all(row["event"] in allowed for row in history), "unplanned/failed S3 trace event")
    equal([row["phase"] for row in history if row["event"] == "phase_started"], list(PHASES), "S3 phase inventory changed")
    standard = [row for row in history if row["event"] != "gate_released"]
    from audit_wire import service_startups
    requests, responses = object_exchanges(standard, phases=PHASES, startups=service_startups(facts))
    require(len(requests) == len(responses), "incomplete original object exchange")
    held_marker = only([row for row in history if row["event"] == "transport_fault_observed"], "observed GET gate inventory")
    released_marker = only([row for row in history if row["event"] == "gate_released"], "GET gate release inventory")
    backend = only([row for row in facts if row["event"] == "backend_started"], "backend signing identity inventory")
    objects, by_call, bindings = {}, defaultdict(list), {}
    for serial, request in requests.items():
        response = responses[serial]
        wire = [row for row in history if row.get("request_serial") == serial and row["event"] != "gate_released"]
        signing = request["signing"]
        require(signing["algorithm"] == "AWS4-HMAC-SHA256" and signing["access_key_sha256"] == backend["access_key_sha256"], "request lacks original fixture signing identity")
        require(re.fullmatch(r"[0-9]{8}/us-east-1/s3/aws4_request", signing["credential_scope"]) is not None and
                re.fullmatch(r"[0-9]{8}T[0-9]{6}Z", signing["date"]) is not None and
                signing["credential_scope"].startswith(signing["date"][:8]) and
                re.fullmatch(r"[0-9a-f]{64}", signing["signature_sha256"]) is not None,
                "original SigV4 scope/date/signature witness changed")
        require(signing["signed_headers"] == sorted(set(signing["signed_headers"])) and
                {"host", "x-amz-content-sha256", "x-amz-date"} <= set(signing["signed_headers"]) and
                signing["host"] == urlparse(configuration["s3"]["endpoint"]).netloc and
                signing["payload_sha256"] == request["request_sha256"], "signed payload/host/header binding changed")
        sent, received = b64(request["request_body"]), b64(response["response_body"])
        require(len(sent) == request["request_bytes"] and sha(sent) == request["request_sha256"] and
                len(received) == response["response_bytes"] and sha(received) == response["response_sha256"], "original S3 complete bytes changed")
        for row in wire:
            equal(row["request_body"], request["request_body"], "forwarded request body differs")
            equal(row["signing"], signing, "forwarded signature witness differs")
            if row["event"] == "object_response_delivered":
                equal(row["response_body"], response["response_body"], "delivered object bytes differ")
        if request["path"].endswith("/head"):
            equal(list(sent), request["head_request_bytes"], "HEAD request capture differs")
            equal(list(received), response["head_response_bytes"], "HEAD response capture differs")
        if "/objects/" in request["path"] and response["status"] == 200:
            raw = sent if request["method"] == "PUT" else received
            envelope(raw, request["path"])
            if request["path"] in objects:
                require(objects[request["path"]] == raw, "immutable object changed bytes")
            objects[request["path"]] = raw
        held_interval = stamp(held_marker) < stamp(request) < stamp(released_marker)
        if held_interval and request["path"].startswith("/scap-test/scap-object/v1/1/7/101/"):
            require(request["method"] == "GET" and request["path"].endswith("/head"),
                    "A performed additional data I/O while its original data GET was held")
        matching = {label for label, call in observed.items() if
                    request["path"].startswith(f"/scap-test/scap-object/v1/1/7/{call['body']['scope']['database']}/") and
                    window(call, stamp(request)) and window(call, stamp(response)) and
                    (label != "a_cold_open" or not held_interval) and
                    (call["body"]["operation"] != "status" or request["path"].endswith("/head"))}
        require(matching, "S3 exchange has no invoking database HTTP call")
        require(len(matching) == 1, "ambiguous S3/HTTP operation binding")
        label = next(iter(matching))
        by_call[label].append(serial)
        bindings[serial] = {observed[label]["request"]["call_id"]}
    versions = object_versions(requests, responses, calls=calls, bindings=bindings)
    heads, trees = {}, {}
    for name in ("a", "b"):
        scope = SCOPES[name]
        prefix = f"/scap-test/scap-object/v1/1/7/{scope['database']}/inc/1/gen/1/storage/1/objects/"
        root = originals[name]["ack"]["receipt"]["data_root"]
        trees[name] = tree(objects, prefix, root)
        commits = [serial for serial in by_call[name + "_execute"] if requests[serial]["method"] == "PUT" and requests[serial]["path"].endswith("/head")]
        serial = only(commits, "execute did not publish one original HEAD candidate")
        require(responses[serial]["status"] == 200, "original HEAD was not accepted")
        head = parse(b64(requests[serial]["request_body"]))
        require(head["data_root"] == root and head["sequence"] == 1 and head["revision"] == 3 and
                head["transition"] == {"revision": 3, "nonce": 1} and head["owner_instance"] == PLAN["owner_instance"], "original committed HEAD differs from receipt")
        result_key = prefix + originals[name]["ack"]["receipt"]["result_hash"]
        payload, raw = envelope(objects[result_key], result_key)
        require(payload["kind"] == "result" and raw == originals[name]["raw"], "durable result differs from original ACK bytes")
        index_key = prefix + head["windows"][0]["root"]
        index, raw = envelope(objects[index_key], index_key)
        expected_index = {"kind": "leaf", "epoch": 1, "entries": [{
            "request": payload["value"]["request"],
            "outcome": {"state": "committed", "result": result_key.rsplit("/", 1)[1]},
            "result_bytes": len(originals[name]["raw"])}]}
        require(index["kind"] == "index" and not raw and index["value"] == expected_index,
                "committed index lost original request/result/length reference")
        require(head["windows"][0]["count"] == 1 and
                head["windows"][0]["result_bytes"] == len(originals[name]["raw"]),
                "committed leaf aggregate differs from HEAD")
        dependencies = trees[name][0] | {result_key, index_key}
        for key in dependencies:
            publications = [number for number, request in requests.items() if request["path"] == key and request["method"] == "PUT" and responses[number]["status"] == 200]
            published = only(publications, "durable dependency publication inventory")
            require(stamp(responses[published]) < stamp(requests[serial]), "HEAD published before an immutable dependency")
        heads[name] = (head, b64(requests[serial]["request_body"]))
    require(len([request for request in requests.values() if request["method"] == "PUT" and request["path"].endswith("/head")]) == 6,
            "unexpected additional HEAD publication")
    for label, call in observed.items():
        if call["body"]["operation"] == "query" and label != "c_at_capacity" or label == "a_control_while_blocked":
            name = call["request"]["client"]
            serial = only(by_call[label], "resident query/control performed extra S3 I/O")
            request, response = requests[serial], responses[serial]
            require(request["method"] == "GET" and request["path"] == f"/scap-test/scap-object/v1/1/7/{SCOPES[name]['database']}/head" and
                    response["status"] == 200 and b64(response["response_body"]) == heads[name][1],
                    "resident query/control was not an exact fresh HEAD-only read")
    require(not by_call["c_at_capacity"], "actor admission refused only after touching C's object store")
    cold_reads = {requests[serial]["path"] for serial in by_call["a_cold_open"] if requests[serial]["method"] == "GET" and responses[serial]["status"] == 200}
    require(trees["a"][0] <= cold_reads and trees["a"][3] >= 4, "cold Open did not fetch the entire original SQLite page tree")
    armed = only([row for row in history if row["event"] == "transport_fault_armed"], "GET gate arm inventory")
    held = only([row for row in history if row["event"] == "transport_fault_observed"], "observed GET gate inventory")
    released = only([row for row in history if row["event"] == "gate_released"], "GET gate release inventory")
    require(armed["path"] == held["path"] == released["path"] == trees["a"][1] and
            armed["method"] == held["method"] == "GET" and armed["mode"] == held["mode"] == "hold" and
            armed["deadline_ms"] == DEADLINES["gate_hold_ms"], "gate missed A's original first data chunk")
    serial = held["request_serial"]
    require(serial == released["request_serial"] and serial in by_call["a_cold_open"], "held object did not belong to A Open")
    forwarded = only([row for row in history if row["event"] == "object_forwarded" and row["request_serial"] == serial], "gated original forward inventory")
    require(stamp(armed) < stamp(observed["a_cold_open"]["request"]) < stamp(held) < stamp(released) < stamp(forwarded) <
            stamp(responses[serial]) < stamp(observed["a_cold_open"]["response"]), "A's original GET was not held until release")
    require(stamp(held) - stamp(observed["a_cold_open"]["request"]) <= DEADLINES["gate_arrival_ms"] * 1000000 and
            stamp(released) - stamp(held) <= DEADLINES["gate_hold_ms"] * 1000000, "original gate deadline exceeded")
    for label, _, _ in CALLS["during_cold"]:
        call = observed[label]
        require(stamp(held) < stamp(call["request"]) < stamp(call["response"]) < stamp(released), "hot/control response did not complete while A remained blocked")
    first, last = observed["b_while_a_blocked"], observed["b_after_backpressure"]
    require(stamp(last["response"]) - stamp(first["request"]) <= DEADLINES["hot_probe_ms"] * 1000000, "original complete isolation probe deadline exceeded")
    require(stamp(observed["a_cold_open"]["request"]) - stamp(observed["a_execute"]["response"]) > ADMISSION["actor_idle_timeout_ms"] * 1000000,
            "A was not idle beyond its configured lifetime")
    require(stamp(observed["a_resident_query"]["request"]) > stamp(observed["a_cold_open"]["response"]), "post-Open query preceded completed recovery")
    return {"s3_requests": len(requests), "original_version_audit": versions,
            "cold_image_bytes": trees["a"][2], "cold_image_chunks": trees["a"][3],
            "cold_page_tree_dependencies_downloaded": len(trees["a"][0]), "held_get_serial": serial,
            "hot_and_control_completed_before_release": 4, "resident_queries_head_only": 10,
            "capacity_refusal_s3_requests": 0, "original_results_preserved": 2}


def processes(directory, facts, http, history, configuration, build):
    numbered(facts)
    by_event = defaultdict(list)
    for row in facts:
        by_event[row["event"]].append(row)
    require(set(by_event) == {"plan_frozen", "backend_started", "service_started", "service_ready", "client_phase_started",
            "client_process_started", "client_phase_finished", "unsigned_backend_request", "unsigned_backend_response",
            "cold_gate_arrived", "service_stop_requested", "service_stopped", "proxy_stopped", "backend_stopped", "cleanup_finished"},
            "missing or unplanned process event")
    plan = only(by_event["plan_frozen"], "frozen plan inventory")
    require(plan is facts[0] and plan["sha256"] == sha((directory / "isolation-plan.json").read_bytes()), "plan was not frozen before execution")
    start, ready, requested, stopped = [only(by_event[event], "service process inventory") for event in
                                       ("service_started", "service_ready", "service_stop_requested", "service_stopped")]
    ident = identity(start["identity"])
    for row in (ready, requested):
        equal(identity(row["identity"]), ident, "service process incarnation changed")
    equal(identity(stopped), ident, "service wait4 belongs to another process")
    require(ident["spawn_monotonic_ns"] < stamp(start) < stamp(ready) < stamp(requested) < stamp(stopped), "service original lifetime order")
    exited(stopped, -signal.SIGKILL)
    require(stopped["stdout_sha256"] == sha((directory / "scapd.stdout.log").read_bytes()), "original service stdout changed")
    require(start["owner_instance"] == ready["owner_instance"] == PLAN["owner_instance"] and
            start["configuration_sha256"] == sha((directory / "isolation-service-config.json").read_bytes()), "actual daemon configuration changed")
    require(start["command"][0] == start["binary"]["path"] and len(start["command"]) == 2, "process command did not execute recorded binary")
    if build["status"] != "NOT_PROVIDED":
        equal(start["binary"], build["binary"], "actual daemon did not execute the original release artifact")
    require(start["endpoint"] == "http://" + configuration["listen"] and start["cache_directory"] == configuration["cache_directory"], "service endpoint/cache differs from actual configuration")
    require(ready["response_status"] == 200 and sha(b64(ready["response_body"])) == ready["response_sha256"] and
            parse(b64(ready["response_body"])) == {"status": "alive", "protocol": 1}, "raw liveness response changed")
    tools = parse((directory / "isolation-tools.json").read_bytes())
    require(set(tools) == {"node", "weed"} and tools["node"]["version"] == "v22.16.0" and
            BACKEND_VERSION in tools["weed"]["version"], "unpinned actual fixture binaries")
    for tool in tools.values():
        require(sha(Path(tool["path"]).read_bytes()) == tool["sha256"], "actual fixture executable bytes changed")
    old, gone = [only(by_event[event], "backend lifetime inventory") for event in ("backend_started", "backend_stopped")]
    equal(old["binary"], {key: tools["weed"][key] for key in ("path", "sha256")}, "backend used another executable")
    for inventory in (old, gone):
        require(Counter(row["role"] for row in inventory["processes"]) == Counter(("master", "volume", "filer", "s3")), "backend process inventory changed")
    for initial in old["processes"]:
        final = only([row for row in gone["processes"] if row["role"] == initial["role"]], "backend role missing")
        equal(identity(initial), identity(final), "backend wait4 belongs to another original process")
        exited(final, -signal.SIGKILL)
        require(initial["spawn_monotonic_ns"] < stamp(old) < stamp(start) < stamp(stopped) < stamp(gone), "backend/service lifetime order")
    equal([row["phase"] for row in by_event["client_phase_started"]], list(PHASES), "client start phase inventory changed")
    require(Counter(row["phase"] for row in by_event["client_phase_finished"]) == Counter(PHASES) and
            Counter(row["phase"] for row in by_event["client_process_started"]) == Counter(PHASES), "client process denominator changed")
    require(Counter(row["phase"] for row in http if row["event"] == "client_process_hello") == Counter(PHASES), "client self-observation denominator changed")
    for phase in PHASES:
        begun, child, finished = [only([row for row in by_event[event] if row["phase"] == phase], "phase process inventory")
                                  for event in ("client_phase_started", "client_process_started", "client_phase_finished")]
        equal(identity(begun["service"]), ident, "client used another daemon incarnation")
        equal(identity(child["identity"]), identity(finished["identity"]), "client wait4 belongs to another process")
        exited(finished, 0)
        require(stamp(ready) < stamp(begun) <= child["spawn_requested_ns"] <= child["identity"]["spawn_monotonic_ns"] < stamp(child) < stamp(finished) < stamp(requested), "client lifetime escaped original daemon")
        require(begun["deadline_ms"] == DEADLINES["client_phase_ms"] and stamp(finished) - stamp(begun) <= DEADLINES["client_phase_ms"] * 1000000,
                "original client process deadline exceeded")
        equal(child["binary"], {key: tools["node"][key] for key in ("path", "sha256")}, "client used another Node executable")
        require(child["command"][0] == child["binary"]["path"] and child["command"][2] == phase and
                Path(child["command"][1]).name == "isolation_probe.mjs" and len(child["command"]) == 5, "client command was not the actual probe")
        hello = only([row for row in http if row["event"] == "client_process_hello" and row["phase"] == phase], "client hello inventory")
        client_hello(child, hello, finished)
        for row in [item for item in http if item["phase"] == phase and item["event"] != "client_process_hello"]:
            require(stamp(hello) < stamp(row) < stamp(finished) and row["call_id"].startswith(f"{phase}:{hello['self_pid']}:"), "HTTP exchange escaped its original Node process")
            if row["event"] == "http_request":
                require(row["url"] == start["endpoint"] + "/v1", "HTTP request used another daemon")
        for suffix in ("stdout", "stderr"):
            require(finished[suffix + "_sha256"] == sha((directory / (phase + "." + suffix + ".log")).read_bytes()), "original client output changed")
    unsigned = only(by_event["unsigned_backend_request"], "unsigned auth-control input denominator")
    denied = only(by_event["unsigned_backend_response"], "unsigned auth-control response denominator")
    gate = only([row for row in history if row["event"] == "transport_fault_armed"], "auth-control exact object key")
    require(unsigned["method"] == "GET" and unsigned["authorization_present"] is False and unsigned["path"] == gate["path"] and
            stamp(unsigned) < stamp(denied) < stamp(gate) and denied["status"] == 403 and
            sha(b64(denied["response_body"])) == denied["response_sha256"] and b"AccessDenied" in b64(denied["response_body"]),
            "backend authentication was not independently rejected on the same existing key")
    controller = only(by_event["cold_gate_arrived"], "controller gate observation inventory")
    held = only([row for row in history if row["event"] == "transport_fault_observed"], "proxy gate observation inventory")
    released = only([row for row in history if row["event"] == "gate_released"], "proxy gate release inventory")
    require(controller["request_serial"] == held["request_serial"] and controller["path"] == held["path"] and
            stamp(held) < stamp(controller) < stamp(released), "controller did not observe the original blocked GET")
    during = only([row for row in by_event["client_phase_finished"] if row["phase"] == "during_cold"], "hot/control process completion")
    require(stamp(controller) < stamp(during) < stamp(released) and
            stamp(during) - stamp(controller) <= DEADLINES["hot_probe_ms"] * 1000000, "complete hot/control process exceeded the frozen gate budget")
    proxy = only(by_event["proxy_stopped"], "proxy cleanup inventory")
    cleanup = only(by_event["cleanup_finished"], "cleanup inventory")
    require(proxy["errors"] == cleanup["errors"] == [] and stamp(stopped) < stamp(proxy) < stamp(gone) < stamp(cleanup), "original child/proxy cleanup incomplete")
    return {"original_daemons": 1, "original_backend_processes": 4, "original_sdk_processes": 5,
            "owned_kernel_wait4_verified": True, "backend_authentication_enforced": True}


def audit(directory, *, require_build=True):
    directory = Path(directory)
    equal(parse((directory / "isolation-plan.json").read_bytes()), PLAN, "frozen workload/deadline plan changed")
    configuration = parse((directory / "isolation-service-config.json").read_bytes())
    equal(configuration["admission"], ADMISSION, "actual admission budget differs from frozen plan")
    equal(configuration["cache"], CACHE, "actual cache/recovery budget differs from frozen plan")
    require(configuration["s3"]["timeout_ms"] == DEADLINES["s3_request_ms"] and configuration["worker_instance"] == str(PLAN["owner_instance"]), "actual S3 deadline/owner differs from frozen plan")
    facts, http, history = (rows(directory, name) for name in ("process-ledger.jsonl", "http-client-ledger.jsonl", "history.jsonl"))
    calls = exchanges(http)
    observed = labeled_calls(directory, calls)
    originals = sql_results(directory, observed)
    network_report = network(history, calls, observed, originals, facts, configuration)
    build_report = build_receipt(directory, require_build)
    process_report = processes(directory, facts, http, history, configuration, build_report)
    return {"schema": 1, "status": "passed" if require_build else "diagnostic", "http_invocations": len(calls),
            "http_successes": 20, "backpressure_responses": 1, "unique_sql_inputs": 2,
            "original_commit_responses": 2, "original_result_lookups": 2, "successful_queries": 10,
            "network": network_report, "processes": process_report, "build": build_report,
            "aws_standard": "NOT_RUN", "production_tps": "NOT_MEASURED",
            "evidence_sha256": {name: sha((directory / name).read_bytes()) for name in FILES}}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path)
    arguments = parser.parse_args()
    print(json.dumps(audit(arguments.evidence), sort_keys=True))
