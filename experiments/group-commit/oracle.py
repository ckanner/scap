#!/usr/bin/env python3
"""Audit original service, SDK and S3 bytes; a logical jump alone proves nothing."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import heapq
import json
from pathlib import Path, PurePosixPath
import signal
import sqlite3
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "experiments/object-service"))
from audit_wire import (b64, committed, equal, fingerprint, head5_profile, moment,
                        object_versions, parse, require, result, service_startups)  # noqa: E402
from owner_oracle import numbered, original_s3_exchanges  # noqa: E402
from spec import (BASES, COMMANDS, EXPECTED_GROUP_SIZES, FINAL_ROWS, GROUPS, HEAD,
                  ORIGINALS, PHASES, PREFIX, PROFILE, SCOPE, SEED_SQL, WORKERS)  # noqa: E402
import protocol  # noqa: E402
sys.path.append(str(ROOT / "experiments/object-network"))
from audit_build import OwnedChildren, receipt as audit_build  # noqa: E402


def read(path):
    raw = path.read_bytes()
    require(raw.endswith(b"\n"), "incomplete original event stream")
    return [parse(line) for line in raw.splitlines()]


def one(rows, event, **fields):
    found = [row for row in rows if row["event"] == event and all(row.get(key) == value for key, value in fields.items())]
    require(len(found) == 1, "missing/duplicate " + event + " " + str(fields))
    return found[0]


def original_bytes(row, field, digest):
    raw = b64(row[field])
    require(hashlib.sha256(raw).hexdigest() == row[digest], "original bytes changed: " + field)
    return raw


def client_moment(row):
    value = row["monotonic_ns"]
    require(isinstance(value, str) and value.isascii() and value.isdecimal() and value[0] != "0",
            "invalid client monotonic clock")
    return int(value)


def inventory(events, history, ledger, probe):
    allowed = {
        "events": {"redirect_sink_started", "backend_started", "configuration", "empty_cache",
            "service_started", "service_ready", "probe_started", "command_sent", "fault_armed", "fault_entered",
            "fault_released", "http_request", "http_forwarded", "http_response", "http_delivered",
            "http_response_suppressed", "crash_requested", "service_stopped", "cache_discarded", "shutdown_requested",
            "probe_stopped", "cache_cleaned", "proxy_stopped", "backend_stopped"},
        "history": {"phase_started", "object_request", "object_forwarded", "object_response",
                    "object_response_delivered", "transport_fault_observed"},
        "ledger": {"client_process_hello", "http_request", "http_response", "http_transport_error"},
        "probe": {"command_started", "command_finished"},
    }
    for name, rows in (("events", events), ("history", history), ("ledger", ledger), ("probe", probe)):
        require(all(row["event"] in allowed[name] for row in rows), "unexpected event kind: " + name)
    commands = Counter(command["id"] for command in COMMANDS)
    require(Counter(row["command"] for row in events if row["event"] == "command_sent") == commands,
            "offered command inventory changed")
    for event in ("command_started", "command_finished"):
        require(Counter(row["command"] for row in probe if row["event"] == event) == commands,
                "SDK command inventory changed")
    require(Counter(row["phase"] for row in ledger if row["event"] == "client_process_hello") == commands,
            "SDK command inventory changed")
    rules = {phase + "_queue_gate": {"channel": "s3", "worker": "primary", "method": "GET", "path": HEAD, "kind": "hold"}
             for phase in PHASES}
    rules["group_candidate"] = {"channel": "s3", "worker": "primary", "method": "PUT", "path": HEAD, "nonce": "74", "kind": "hold"}
    rules["lost_member_reply"] = {"channel": "http", "worker": "primary", "command": "response_loss_b", "kind": "drop"}
    for event in ("fault_armed", "fault_entered", "fault_released"):
        expected = {name for name, rule in rules.items() if event != "fault_released" or rule["kind"] == "hold"}
        selected = [row for row in events if row["event"] == event]
        require(len(selected) == len(expected) and {row["id"] for row in selected} == expected, "fault inventory changed")
        if event != "fault_released":
            for row in selected:
                equal({key: row.get(key) for key in rules[row["id"]]}, rules[row["id"]], "fixed fault rule changed")
    phases = [row["phase"] for row in history if row["event"] == "phase_started"]
    equal(phases, ["seed", *PHASES, "restart", "lookup"], "phase inventory changed")
    current = "setup"
    for row in history:
        if row["event"] == "phase_started":
            current = row["phase"]
        elif row["event"] == "object_request":
            require(row["phase"] == current, "phase inventory changed")
    probe_start, probe_stop = one(events, "probe_started"), one(events, "probe_stopped")
    require(type(probe_start["spawn_requested_ns"]) is int
            and 0 < probe_start["spawn_requested_ns"] < moment(probe_start), "SDK spawn boundary changed")
    require(all(probe_start["spawn_requested_ns"] < client_moment(row) < moment(probe_stop) for row in [*probe, *ledger]),
            "SDK evidence escaped owned process lifetime")
    for worker in WORKERS:
        ready = one(events, "service_ready", worker=worker)
        stop = one(events, "service_stopped", worker=worker)
        for row in events:
            if row["event"] in ("http_request", "http_response") and row["worker"] == worker:
                require(moment(ready) < moment(row) < moment(stop), "HTTP escaped owned worker lifetime")


def lost_reply_fault(events, request, response, suppressed):
    """The named drop must bind the original handler before it selects rules.

    The relay selects at request entry and observes its successful service
    response before recording fault entry and suppressing client delivery.
    A late rule or a different handler is not evidence of that response loss.
    """
    armed = one(events, "fault_armed", id="lost_member_reply")
    entered = one(events, "fault_entered", id="lost_member_reply")
    require(moment(armed) < moment(request), "lost reply fault was not armed before original request")
    require(type(entered.get("http_serial")) is int and entered["http_serial"] == request["http_serial"],
            "lost reply fault bound another HTTP request")
    require(moment(response) < moment(entered) < moment(suppressed),
            "lost reply fault entry was not after response and before suppression")
    require(suppressed.get("id") == "lost_member_reply", "lost reply suppression fault identity changed")
    require(suppressed.get("reason") == "explicit_response_loss", "lost reply suppression reason changed")


def http(events, ledger, probe):
    configuration = one(events, "configuration")
    groups = defaultdict(list)
    for row in events:
        if "http_serial" in row and row["event"].startswith("http_"):
            groups[row["http_serial"]].append(row)
    count = sum(entry["http"] for entry in COMMANDS)
    require(sorted(groups) == list(range(1, count + 1)), "original HTTP denominator changed")
    calls, by_command = {}, defaultdict(list)
    sdk_ids = set()
    for serial, rows in groups.items():
        request = one(rows, "http_request")
        forward = one(rows, "http_forwarded")
        response = one(rows, "http_response")
        require(moment(request) < moment(forward) < moment(response), "HTTP lifecycle reordered")
        for row in rows:
            for key in ("worker", "command", "method", "path", "request_body", "request_sha256", "credential_sha256"):
                equal(row[key], request[key], "HTTP original identity changed")
        require(request["method"] == "POST" and request["path"] == "/v1"
                and request["credential_sha256"] == configuration["credential_sha256"]
                and response["origin"] == "service", "HTTP route/authentication/origin changed")
        raw = original_bytes(request, "request_body", "request_sha256")
        reply_raw = original_bytes(response, "response_body", "response_sha256")
        body, reply = parse(raw), parse(reply_raw)
        equal(body["scope"], SCOPE, "HTTP full scope changed")
        require(body["version"] == 1, "HTTP version changed")
        matching = [row for row in ledger if row["event"] == "http_request" and row["phase"] == request["command"]
                    and row["body_sha256"] == request["request_sha256"]]
        require(len(matching) == 1, "missing/duplicate exact SDK POST")
        sdk_request = matching[0]
        require(sdk_request["call_id"] not in sdk_ids, "one SDK POST counted twice")
        sdk_ids.add(sdk_request["call_id"])
        equal(original_bytes(sdk_request, "body", "body_sha256"), raw, "SDK request differs from HTTP")
        require(sdk_request["url"] == configuration["endpoints"][request["worker"]]
                and client_moment(sdk_request) < moment(request), "SDK dispatch route/clock changed")
        if request["command"] == "response_loss_b":
            suppressed = one(rows, "http_response_suppressed")
            terminal = one(ledger, "http_transport_error", call_id=sdk_request["call_id"])
            require(len(rows) == 4 and response["suppressed"] is True and response["status"] == 200
                    and moment(response) < moment(suppressed) < client_moment(terminal), "lost reply was not actual accepted-response loss")
            lost_reply_fault(events, request, response, suppressed)
        else:
            delivered = one(rows, "http_delivered")
            require(len(rows) == 4 and not response["suppressed"] and moment(response) < moment(delivered),
                    "HTTP delivery missing or fabricated")
            for key in ("status", "response_body", "response_sha256", "origin", "suppressed"):
                equal(delivered[key], response[key], "HTTP delivery changed")
            terminal = one(ledger, "http_response", call_id=sdk_request["call_id"])
            equal(original_bytes(terminal, "body", "body_sha256"), reply_raw, "SDK received another result")
            require(terminal["status"] == response["status"] and moment(response) < client_moment(terminal),
                    "SDK response preceded actual service reply")
        calls[serial] = {"request": request, "response": response, "body": body, "reply": reply}
        by_command[request["command"]].append(serial)
    require(len([row for row in ledger if row["event"] == "http_request"]) == count
            and len([row for row in ledger if row["event"] in ("http_response", "http_transport_error")]) == count,
            "extra SDK POST or terminal outcome")
    require(set(by_command) == {entry["id"] for entry in COMMANDS}, "HTTP command set changed")
    require(len([row for row in probe if row["event"] == "command_finished"]) == len(COMMANDS)
            and not any(row["event"] == "command_failed" for row in probe), "SDK command completion denominator")
    originals = {}
    for spec in COMMANDS:
        name, serials = spec["id"], by_command[spec["id"]]
        require(len(serials) == spec["http"], "SDK replayed or omitted an original request")
        start, finish = one(probe, "command_started", command=name), one(probe, "command_finished", command=name)
        require(finish["outcome"] == spec.get("error", "ok") and finish["attempts"] == spec["http"],
                "SDK outcome differs from fixed command")
        require(moment(one(events, "command_sent", command=name)) < client_moment(start), "SDK preceded offered input")
        operations = {"seed": ["create", "activate", "execute"], "resume": ["status", "takeover", "activate"],
                      "duplicate": ["execute"]}.get(spec["operation"], [spec["operation"]])
        require([calls[n]["body"]["operation"] for n in serials] == operations, "actual operation differs from fixed workload")
        for serial in serials:
            call = calls[serial]
            body, reply, response = call["body"], call["reply"], call["response"]
            require(call["request"]["worker"] == spec.get("worker", "primary")
                    and client_moment(start) < moment(call["request"]) < moment(response) < client_moment(finish),
                    "command route or original interval changed")
            if body["operation"] in ("execute", "lookup", "cancel"):
                reference = next(entry for entry in COMMANDS if entry["id"] == spec["original"]) if "original" in spec else spec
                sql = SEED_SQL if reference["operation"] == "seed" else reference["sql"]
                statements = [{"sql": text, "params": []} for text in sql]
                expected_id = "1" if reference["operation"] == "seed" else reference["request_id"]
                equal(body["request"], {"epoch": "1", "id": expected_id, "principal": "11",
                    "fingerprint": fingerprint(statements)}, "original full identity/fingerprint changed")
                if body["operation"] == "execute":
                    equal(body["statements"], statements, "original SQL changed")
            expected_error = spec.get("error")
            if expected_error and expected_error != "UNKNOWN":
                require(reply["ok"] is False and reply["error"]["code"] == expected_error and response["status"] != 200,
                        "failed independent request was acknowledged")
                continue
            require(reply["ok"] is True and response["status"] == 200, "successful original request rejected")
            if body["operation"] == "execute":
                raw_result, statements = committed(reply["value"])
                equal(reply["value"]["receipt"]["request"], body["request"], "receipt belongs to another request")
                if spec["operation"] == "duplicate":
                    equal(reply["value"], originals[spec["original"]]["value"], "duplicate SQL replayed its original result")
                else:
                    originals[name] = {"value": reply["value"], "raw": raw_result, "statements": statements, "call": serial}
            elif body["operation"] == "lookup":
                require(reply["value"]["state"] == spec["state"], "lookup outcome lost a group member/barrier")
                if spec["state"] == "committed":
                    equal(reply["value"], originals[spec["original"]]["value"], "lookup replayed non-deterministic SQL")
            elif body["operation"] == "cancel":
                require(reply["value"]["state"] == "cancelled", "cancel did not install a barrier")
    require(set(originals) == set(ORIGINALS), "original committed result denominator changed")
    return calls, by_command, originals


def intervals(events, history, calls, by_command):
    for phase in PHASES:
        gate = one(events, "fault_entered", id=phase + "_queue_gate")
        released = one(events, "fault_released", id=phase + "_queue_gate")
        request = one(history, "object_request", request_serial=gate["request_serial"])
        blocker = calls[by_command[phase + "_blocker"][0]]
        require(request["method"] == "GET" and request["path"] == HEAD and request["worker"] == "primary"
                and moment(blocker["request"]) < moment(request) <= moment(gate) < moment(released) < moment(blocker["response"]),
                "queue gate did not hold the original actor operation")
        for command in GROUPS[phase]:
            call = calls[by_command[command["id"]][0]]
            require(moment(gate) < moment(call["request"]) < moment(released) < moment(call["response"]),
                    "group member was not queued before original actor release")
        overflow = calls[by_command[phase + "_overflow"][0]]
        require(moment(gate) < moment(overflow["request"]) < moment(overflow["response"]) < moment(released),
                "queue-full refusal did not precede group execution")
    held = one(events, "fault_entered", id="group_candidate")
    release = one(events, "fault_released", id="group_candidate")
    cancel = calls[by_command["cancel_member"][0]]
    require(moment(held) < moment(cancel["request"]) < moment(cancel["response"]) < moment(release),
            "cancel did not win while original group CAS was held")


def linearize(requests, responses, serials, edges):
    scale = len(serials) + 1
    earliest = {serial: moment(requests[serial]) * scale for serial in serials}
    following, indegree = defaultdict(set), Counter({serial: 0 for serial in serials})
    for before, after in edges:
        require(before != after, "self-referential HEAD effect")
        following[before].add(after)
        indegree[after] += 1
    ready = [(earliest[serial], serial) for serial in serials if indegree[serial] == 0]
    heapq.heapify(ready)
    visited = 0
    while ready:
        _, serial = heapq.heappop(ready)
        require(earliest[serial] <= moment(responses[serial]) * scale, "HEAD has no legal real-time linearization")
        visited += 1
        for later in following[serial]:
            earliest[later] = max(earliest[later], earliest[serial] + 1)
            indegree[later] -= 1
            if indegree[later] == 0:
                heapq.heappush(ready, (earliest[later], later))
    require(visited == len(serials), "cyclic HEAD authority history")


def authority(events, history, calls, by_command, originals):
    configuration = one(events, "configuration")
    net = original_s3_exchanges(history, phases={"setup", "seed", "restart", "lookup", *PHASES},
        blackhole_phases=set(), startups=service_startups(events, workers=WORKERS),
        endpoints=configuration["s3_endpoints"], access_key_sha256=configuration["access_key_sha256"])
    requests, responses = net["requests"], net["responses"]
    require(set(requests) == set(responses), "incomplete original S3 exchange")
    objects, created, readbacks = {}, {}, defaultdict(list)
    immutable = {serial: row for serial, row in requests.items() if row["path"] != HEAD}
    immutable_report = object_versions(immutable, {serial: responses[serial] for serial in immutable})
    for serial, request in immutable.items():
        response = responses[serial]
        require(request["path"].startswith(PREFIX), "S3 escaped the fixed database")
        if request["method"] == "PUT" and response["status"] == 200:
            require(request["if_none_match"] == "*", "immutable object was overwritten")
            objects[request["path"]] = b64(request["request_body"])
            created[request["path"]] = serial
        if request["method"] == "GET" and response["status"] == 200:
            readbacks[request["path"]].append(serial)
    heads = {serial: request for serial, request in requests.items() if request["path"] == HEAD}
    versions, candidates, proofs = {}, {}, {}
    for serial, request in heads.items():
        if request["method"] == "PUT":
            candidate = head5_profile(parse(b64(request["request_body"])))
            candidates[serial] = candidate
            proofs[serial] = protocol.closure(objects, candidate)
            for key in proofs[serial]["dependencies"]:
                require(key in created and moment(responses[created[key]]) < moment(request)
                        and any(moment(responses[created[key]]) < moment(requests[read])
                                and moment(responses[read]) < moment(request) for read in readbacks[key]),
                        "HEAD preceded dependency persistence and exact readback")
            if responses[serial]["status"] == 200:
                require(responses[serial]["etag"] not in versions, "HEAD ETag reused")
                versions[responses[serial]["etag"]] = serial
    roots = [serial for serial in versions.values() if heads[serial]["if_none_match"] == "*"]
    require(len(roots) == 1, "HEAD conditional root denominator")
    root = roots[0]
    require(candidates[root]["revision"] == candidates[root]["head_serial"] == 1
            and candidates[root]["sequence"] == 0 and not proofs[root]["entries"], "initial authority changed")
    edges, successors, accepted_members, group_sizes = set(), {}, {}, defaultdict(list)
    rejected = []
    for serial, request in heads.items():
        response = responses[serial]
        if request["method"] == "GET":
            if response["status"] == 404:
                edges.add((serial, root))
            else:
                origin = versions.get(response["etag"])
                require(origin is not None, "HEAD GET omitted its original accepted version")
                equal(b64(response["response_body"]), b64(heads[origin]["request_body"]), "HEAD body/ETag pair changed")
                edges.add((origin, serial))
            continue
        if request["if_none_match"] == "*":
            require(serial == root and response["status"] == 200, "unplanned second HEAD creation")
            continue
        previous = versions.get(request["if_match"])
        require(previous is not None and previous != serial, "CAS has no original accepted predecessor")
        members = protocol.publication(candidates[previous], candidates[serial], proofs[previous], proofs[serial])
        active_calls = []
        if members:
            for member in members:
                intermediate, _ = protocol.data(objects, member["metadata"]["data_root"])
                for key in intermediate:
                    require(key in created and moment(responses[created[key]]) < moment(request)
                            and any(moment(responses[created[key]]) < moment(requests[read])
                                    and moment(responses[read]) < moment(request) for read in readbacks[key]),
                            "member root preceded dependency persistence and exact readback")
                native = member["metadata"]["request"]
                matches = [number for number, call in calls.items() if call["body"]["operation"] == "execute"
                    and call["request"]["command"] != "duplicate_a"
                    and call["body"]["request"] == {key: str(value) if key != "fingerprint" else value for key, value in native.items()}]
                require(len(matches) == 1, "group member has no unique original SQL request")
                active_calls += matches
        else:
            active_calls = [number for number, call in calls.items() if call["body"]["operation"] in ("activate", "takeover", "cancel")
                and moment(call["request"]) < moment(request) < moment(call["response"])]
            require(len(active_calls) == 1, "control CAS has no unique original request")
        lower = max(moment(calls[number]["request"]) for number in active_calls)
        upper = min(moment(calls[number]["response"]) for number in active_calls)
        require(lower < moment(request) < moment(response) < upper, "group CAS escaped a member's original interval")
        witnesses = [other for other, get in heads.items() if get["method"] == "GET" and get["worker"] == request["worker"]
            and responses[other]["status"] == 200 and responses[other]["etag"] == request["if_match"]
            and lower < moment(get) < moment(responses[other]) < moment(request)]
        require(witnesses, "group reused an ETag without its original in-attempt exact GET")
        if members:
            manifest = PREFIX + candidates[serial]["data_root"]
            require(any(lower < moment(requests[read]) < moment(responses[read]) < moment(request)
                        for read in readbacks[manifest]), "group omitted the final authoritative manifest GET")
        if response["status"] == 200:
            require(previous not in successors, "two accepted HEADs consumed one original ETag")
            successors[previous] = serial
            edges.add((previous, serial))
            for member in members:
                identifier = member["metadata"]["request"]["id"]
                require(identifier not in accepted_members, "SQL identity committed twice")
                accepted_members[identifier] = (serial, member)
            if members and request["phase"] in PHASES and members[0]["metadata"]["request"]["id"] != BASES[request["phase"]]:
                group_sizes[request["phase"]].append(len(members))
        else:
            require(request["phase"] == "cancel_race" and len(members) == 4, "unplanned rejected HEAD candidate")
            rejected.append((serial, previous))
    for serial, request in heads.items():
        if request["method"] == "GET" and responses[serial]["status"] == 200:
            previous = versions[responses[serial]["etag"]]
            if previous in successors:
                edges.add((serial, successors[previous]))
    require(len(rejected) == 1, "group conflict denominator changed")
    for serial, previous in rejected:
        require(previous in successors, "group conflict lacks a winning authority publication")
        winner = successors[previous]
        require(candidates[winner]["transition"]["nonce"] == 72, "another action replaced the cancellation winner")
        edges.add((winner, serial))
    current, visited = root, set()
    while current is not None and current not in visited:
        visited.add(current)
        last = current
        current = successors.get(current)
    require(current is None and visited == set(versions.values()), "disconnected/cyclic accepted HEAD chain")
    linearize(requests, responses, set(heads), edges)
    equal({phase: group_sizes[phase] for phase in PHASES}, EXPECTED_GROUP_SIZES, "actual independent group boundaries changed")
    for name, original in originals.items():
        receipt = original["value"]["receipt"]
        serial, stored = accepted_members[int(receipt["request"]["id"])]
        protocol.receipt_matches(receipt, original["raw"], stored)
        require(moment(responses[serial]) < moment(calls[original["call"]]["response"]), "ACK preceded accepted group CAS")
    final = proofs[last]
    require(set(accepted_members) == {int(item["value"]["receipt"]["request"]["id"]) for item in originals.values()},
            "accepted SQL has no original result witness")
    require(final["entries"][72]["outcome"]["state"] == "cancelled"
            and not {71, 73, 74}.intersection(final["entries"]), "lost group overwrote cancellation or replayed SQL")
    return {"net": net, "final": final, "accepted_heads": len(versions), "accepted_members": accepted_members,
            "group_sizes": dict(group_sizes), "immutable": immutable_report, "heads": heads, "candidates": candidates}


def verify_rows(plan, events, history, ledger, probe, inputs, originals, lookups):
    equal(plan, {"profile": PROFILE, "scope": SCOPE, "workers": WORKERS, "commands": COMMANDS,
                 "http_count": sum(command["http"] for command in COMMANDS)}, "frozen group plan changed")
    numbered(events)
    numbered(history)
    inventory(events, history, ledger, probe)
    require(not any(row["event"] in ("http_fixture_failed", "unexpected_sink_request", "fault_expired",
        "fault_cleanup_release") for row in events), "unplanned fixture failure")
    calls, by_command, acknowledgements = http(events, ledger, probe)
    intervals(events, history, calls, by_command)
    proof = authority(events, history, calls, by_command, acknowledgements)
    expected_inputs = {command["id"] for command in COMMANDS if command["operation"] in ("seed", "execute")}
    require({row["command"] for row in inputs} == expected_inputs and len(inputs) == len(expected_inputs),
            "saved original input denominator changed")
    for row in inputs:
        call = calls[by_command[row["command"]][-1]]
        tracked = row["input"]
        if isinstance(tracked, str):
            tracked = parse(tracked)
        equal(tracked["scope"], call["body"]["scope"], "saved request scope changed")
        equal(tracked["request"], call["body"]["request"], "saved original identity changed")
        equal(tracked["statements"], call["body"]["statements"], "saved original statements changed")
        require(client_moment(row) < moment(call["request"]), "input was not saved before dispatch")
    require(len(originals) == len(ORIGINALS) - 1 and {row["command"] for row in originals}
            == set(ORIGINALS) - {"response_loss_b"}, "SDK acknowledged a dropped response")
    for row in originals:
        original = acknowledgements[row["command"]]
        equal(row["receipt"], original["value"]["receipt"], "SDK stored another original receipt")
        equal(b64(row["raw"]), original["raw"], "SDK stored another original result")
    require(len(lookups) == len(ORIGINALS) and {row["original"] for row in lookups} == set(ORIGINALS),
            "cold original lookup denominator changed")
    for row in lookups:
        original = acknowledgements[row["original"]]
        equal(row["receipt"], original["value"]["receipt"], "cold lookup changed original receipt")
        equal(b64(row["raw"]), original["raw"], "cold lookup replayed non-deterministic SQL")
    for phase in PHASES:
        require(acknowledgements[phase + "_blocker"]["statements"][0]["rows"] == [[BASES[phase]]],
                "blocker SELECT returned another original value")
    require(acknowledgements["success_c"]["statements"][0]["rows"] == [[12]]
            and acknowledgements["last_failure_c"]["statements"][0]["rows"] == [[12]],
            "read-only member did not see its successful private prefix")
    final_call = calls[by_command["final"][0]]
    final = result(b64(final_call["reply"]["value"]["result"]))
    require([row[0] for row in final[0]["rows"]] == FINAL_ROWS and final[1]["rows"] == []
            and final[2]["rows"] == [[99], [199]] and final[3]["rows"] == [[12]], "final independent SQL state changed")
    random_rows = {}
    for original in acknowledgements.values():
        for statement in original["statements"]:
            if statement["columns"] == ["n", "nonce"]:
                for identifier, nonce in statement["rows"]:
                    require(identifier not in random_rows, "one original insertion appeared twice")
                    random_rows[identifier] = nonce
    equal(final[0]["rows"], [[identifier, random_rows[identifier]] for identifier in FINAL_ROWS],
          "cold image contains replayed random values")
    # The captured checkpoint image retains SQLite's WAL header. Open the
    # exact reconstructed bytes as an immutable readonly file; deserialize on
    # an in-memory connection cannot open that header's WAL mode. Do not patch
    # header bytes or combine this observer with a product/native unit profile.
    with tempfile.TemporaryDirectory(prefix="scap-group-oracle-") as directory:
        image_path = Path(directory) / "authoritative.sqlite"
        image_path.write_bytes(proof["final"]["image"])
        database = sqlite3.connect(image_path.as_uri() + "?mode=ro&immutable=1", uri=True)
        try:
            require(database.execute("PRAGMA integrity_check").fetchall() == [("ok",)], "authoritative reconstructed image is corrupt")
            equal([list(row) for row in database.execute("SELECT n,nonce FROM witness ORDER BY n")], final[0]["rows"],
                  "HTTP state differs from durable SQLite image")
            require(database.execute("SELECT * FROM child").fetchall() == [], "failed deferred transaction leaked into durable image")
        finally:
            database.close()
        require(image_path.read_bytes() == proof["final"]["image"], "observer changed authoritative SQLite bytes")
    owned = OwnedChildren()
    for worker in WORKERS:
        start = one(events, "service_started", worker=worker)
        stop = one(events, "service_stopped", worker=worker)
        require(start["identity"] == stop["identity"] and stop["usage"]["available"] is True
                and stop["usage"]["source"] == "kernel_wait4_owned_child"
                and stop["status"] == (-signal.SIGKILL if worker == "primary" else 0), "owned service exit was not observed")
        require(one(events, "empty_cache", worker=worker)["entries"] == [], "worker reused a private cache")
        owned.register(start["identity"], moment(stop))
    discarded = one(events, "cache_discarded", worker="primary")
    require(discarded["files"] and discarded["exists"] is False
            and moment(discarded) < moment(one(events, "service_started", worker="restarted")), "cold recovery reused crashed cache")
    require(one(events, "cache_cleaned", worker="restarted")["entries"] == []
            and one(events, "proxy_stopped")["errors"] == [], "owned service resources not cleaned")
    start, stop = one(events, "probe_started"), one(events, "probe_stopped")
    require(start["identity"] == stop["identity"] and stop["status"] == 0
            and stop["usage"]["available"] is True, "SDK process exit was not observed")
    owned.register(start["identity"], moment(stop))
    backend_start, backend_stop = one(events, "backend_started"), one(events, "backend_stopped")
    require(len(backend_start["identities"]) == len(backend_stop["processes"]) == 4, "backend process denominator changed")
    for identity in backend_start["identities"]:
        matches = [row for row in backend_stop["processes"] if row["role"] == identity["role"]]
        require(len(matches) == 1, "backend child exit missing")
        stop = matches[0]
        equal({key: stop[key] for key in identity}, identity, "backend identity changed")
        require(stop["wait_status"] == -signal.SIGKILL and stop["kernel_usage"]["available"] is True,
                "backend child was not reaped")
        owned.register(identity, moment(backend_stop))
    return {"status": "passed", "commands": len(COMMANDS), "http_requests": plan["http_count"],
            "accepted_heads": proof["accepted_heads"], "committed_independent_requests": len(acknowledgements),
            "group_sizes": {phase: proof["group_sizes"].get(phase, []) for phase in PHASES},
            "cold_original_lookups": len(lookups), "rejected_group_cas": 1,
            "business_s3_requests": len(proof["net"]["requests"]), "immutable": proof["immutable"],
            "observer_sqlite_version": sqlite3.sqlite_version, "aws": "NOT_RUN", "production_slo": "NOT_RUN"}


def verify_source(evidence, events):
    inputs = parse((evidence / "inputs.json").read_bytes())
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    require(digest(evidence / "source.json") == inputs["source_manifest_sha256"]
            and digest(evidence / "source.tar") == inputs["source_archive_sha256"], "source witness changed")
    manifest = parse((evidence / "source.json").read_bytes())
    equal(parse((evidence / "source-after.json").read_bytes()), manifest, "source changed during actual execution")
    with tarfile.open(evidence / "source.tar", mode="r:") as archive:
        members = archive.getmembers()
        require(len(members) == len(manifest) and {member.name for member in members} == set(manifest), "source inventory changed")
        for member in members:
            path = PurePosixPath(member.name)
            require(member.isfile() and not path.is_absolute() and ".." not in path.parts
                    and member.name == path.as_posix() and 0 <= member.size <= 16 * 1024 * 1024, "unsafe source archive")
            raw = archive.extractfile(member).read()
            require(len(raw) == member.size and hashlib.sha256(raw).hexdigest() == manifest[member.name], "source bytes changed")
    for path in Path(__file__).parent.iterdir():
        if path.is_file() and path.suffix in (".py", ".mjs", ".md"):
            require(manifest.get(path.relative_to(ROOT).as_posix()) == digest(path), "group fixture omitted or changed")
    value = parse((evidence / "build/build-receipt.json").read_bytes())
    require(digest(evidence / "build/build-receipt.json") == inputs["build_receipt_sha256"]
            and value["source_commit"] == inputs["build_source_commit"]
            and all(manifest.get(name) == expected for name, expected in value["inputs"].items()), "runtime build source changed")
    tools = inputs["tools"]
    require(set(tools) == {"scapd", "node", "weed"}, "actual executable inventory changed")
    equal(tools["scapd"], value["binary"], "invoked daemon differs from release build")
    for worker in WORKERS:
        config_path = evidence / (worker + "-config.json")
        config = parse(config_path.read_bytes())
        start = one(events, "service_started", worker=worker)
        require(digest(config_path) == start["configuration_sha256"]
                and config["worker_instance"] == WORKERS[worker]
                and config["cache"] == {"pages_per_actor": 8192, "parallel_recoveries": 4}, "actual service configuration changed")
        equal(config["admission"]["group_commit"], PROFILE, "actual group profile changed")
        require(start["binary_sha256"] == tools["scapd"]["sha256"] == digest(Path(tools["scapd"]["path"])), "daemon binary changed")
    for name, event, field in (("node", "probe_started", "node_sha256"), ("weed", "backend_started", "binary_sha256")):
        require(one(events, event)[field] == tools[name]["sha256"] == digest(Path(tools[name]["path"])), "tool executable bytes changed")
    return {"source_files_verified": len(manifest), "build": audit_build(evidence / "build", profile="service", source_root=ROOT)}


def evidence_rows(evidence):
    return [parse((evidence / "plan.json").read_bytes()), *[read(evidence / name) for name in
        ("events.jsonl", "history.jsonl", "http-client-ledger.jsonl", "probe.jsonl", "original-inputs.jsonl",
         "original-results.jsonl", "original-lookups.jsonl")]]


def verify(evidence):
    evidence = Path(evidence)
    values = evidence_rows(evidence)
    source = verify_source(evidence, values[1])
    return {**verify_rows(*values), "source": source}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path)
    print(json.dumps(verify(parser.parse_args().evidence), sort_keys=True))
