#!/usr/bin/env python3
"""Independent byte/interval audit; imports no service or SDK implementation."""
from __future__ import annotations

import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import signal
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "experiments/object-service"))
from audit_wire import (b64, committed, equal, fingerprint, moment, object_versions,
                        parse, require, result, service_startups)  # noqa: E402
from owner_oracle import original_s3_exchanges  # noqa: E402
from spec import COMMANDS, HEAD, OTHER_HEAD, PROFILE, SCOPES  # noqa: E402
sys.path.append(str(ROOT / "experiments/object-network"))
from audit_build import OwnedChildren, receipt as audit_build  # noqa: E402


def read(path):
    raw = path.read_bytes()
    require(raw.endswith(b"\n"), "incomplete original event stream")
    return [parse(line) for line in raw.splitlines()]


def one(rows, event, **fields):
    found = [row for row in rows if row["event"] == event and
             all(row.get(key) == value for key, value in fields.items())]
    require(len(found) == 1, "missing/duplicate " + event + " " + str(fields))
    return found[0]


def original_bytes(row, field, digest):
    raw = b64(row[field])
    require(hashlib.sha256(raw).hexdigest() == row[digest], "original HTTP bytes changed")
    return raw


def client_moment(row):
    value = row["monotonic_ns"]
    require(isinstance(value, str) and value.isascii() and value.isdecimal()
            and value[0] != "0", "invalid SDK monotonic timestamp")
    return int(value)


def verify_intervals(events, history, calls, by_command):
    """Check concurrency using original request intervals, not throughput."""
    first = one(events, "fault_entered", id="first")
    second = one(events, "fault_entered", id="second")
    released_first = one(events, "fault_released", id="first")
    released_second = one(events, "fault_released", id="second")
    require(moment(first) < moment(second) < moment(released_first) < moment(released_second),
            "same-database reads did not overlap before either gate released")
    for name, gate in (("first", first), ("second", second)):
        call = calls[by_command[name][0]]
        request = one(history, "object_request", request_serial=gate["request_serial"])
        require(moment(call["request"]) < moment(request) <= moment(gate) < moment(call["response"]),
                "read gate outside original query")
        require(request["method"] == "GET" and request["path"] == HEAD and request["worker"] == "pool",
                "query gate held another operation")
    require(first["request_serial"] != second["request_serial"], "one GET counted twice")
    for name in ("other", "write", "control"):
        call = calls[by_command[name][0]]
        require(moment(second) < moment(call["request"]) < moment(call["response"]) < moment(released_first),
                "readers blocked another tenant, writer or controls")
    queued = calls[by_command["queued"][0]]
    require(moment(second) < moment(queued["request"]) < moment(released_first) < moment(queued["response"]),
            "queued same-tenant query escaped active quota")


def verify_refresh(events, history, calls, by_command):
    """Two held readers force warm/refresh onto the same remaining worker."""
    gates, releases = [], []
    for name in ("park_first", "park_second"):
        gate = one(events, "fault_entered", id=name)
        release = one(events, "fault_released", id=name)
        call = calls[by_command[name][0]]
        request = one(history, "object_request", request_serial=gate["request_serial"])
        require(request["method"] == "GET" and request["path"] == OTHER_HEAD and request["worker"] == "pool"
                and moment(call["request"]) < moment(request) <= moment(gate) < moment(release) < moment(call["response"]),
                "refresh parking gate lacks its original other-tenant query")
        gates.append(gate)
        releases.append(release)
    require(gates[0]["request_serial"] != gates[1]["request_serial"], "refresh counted one parked worker twice")
    lower, upper = max(map(moment, gates)), min(map(moment, releases))
    for name in ("warm", "write_again", "refresh"):
        call = calls[by_command[name][0]]
        require(lower < moment(call["request"]) < moment(call["response"]) < upper,
                "warm/write/refresh escaped the single remaining reader interval")
        lower = moment(call["response"])
    refresh = calls[by_command["refresh"][0]]
    selected = [row for row in history if row["event"] == "object_request" and row["path"] == HEAD
                and moment(refresh["request"]) < moment(row) < moment(refresh["response"])]
    require(len(selected) == 3 and all(row["method"] == "GET" for row in selected),
            "stale reader did not perform exactly one pre-SQL refresh")


def verify_rows(plan, events, history, client, probe, originals, lookups):
    equal(plan, {"profile": PROFILE, "scopes": SCOPES, "commands": COMMANDS,
                 "http_count": sum(entry["http"] for entry in COMMANDS)}, "frozen plan changed")
    require(not any(row["event"] in ("http_fixture_failed", "unexpected_sink_request", "fault_expired",
        "fault_cleanup_release") for row in events), "unplanned fixture failure")
    configuration = one(events, "configuration")
    by_serial = defaultdict(list)
    for row in events:
        if "http_serial" in row:
            by_serial[row["http_serial"]].append(row)
    require(sorted(by_serial) == list(range(1, plan["http_count"] + 1)), "HTTP denominator changed")
    calls, by_command = {}, defaultdict(list)
    for serial, rows in by_serial.items():
        request = one(rows, "http_request")
        forwarded = one(rows, "http_forwarded")
        response = one(rows, "http_response")
        delivered = one(rows, "http_delivered")
        require(len(rows) == 4 and moment(request) < moment(forwarded) < moment(response) < moment(delivered),
                "HTTP lifecycle incomplete or reordered")
        require(request["worker"] == "pool" and request["method"] == "POST" and request["path"] == "/v1",
                "HTTP worker/route changed")
        require(response["origin"] == "service" and not response["suppressed"], "HTTP response fabricated")
        for row in rows:
            for key in ("worker", "command", "method", "path", "request_body", "request_sha256", "credential_sha256"):
                equal(row[key], request[key], "HTTP request identity changed")
        for key in ("status", "response_body", "response_sha256", "origin", "suppressed"):
            equal(delivered[key], response[key], "HTTP delivery changed")
        body = parse(original_bytes(request, "request_body", "request_sha256"))
        reply = parse(original_bytes(response, "response_body", "response_sha256"))
        calls[serial] = {"request": request, "response": response, "body": body, "reply": reply}
        by_command[request["command"]].append(serial)

    require(set(by_command) == {entry["id"] for entry in COMMANDS}, "HTTP command set changed")
    require(len([row for row in probe if row["event"] == "command_finished"]) == len(COMMANDS)
            and not any(row["event"] == "command_failed" for row in probe), "SDK completion denominator")
    successful_queries = 0
    for command in COMMANDS:
        name = command["id"]
        serials = by_command[name]
        require(len(serials) == command["http"], "SDK retry or missing original POST")
        finished = one(probe, "command_finished", command=name)
        require(finished["attempts"] == command["http"] and finished["outcome"] == command.get("error", "ok"),
                "SDK result does not match fixed command")
        submitted = one(events, "command_sent", command=name)
        started = one(probe, "command_started", command=name)
        require(moment(submitted) < client_moment(started), "SDK command preceded parent input")
        expected_operations = {"seed": ["create", "activate", "execute"] + (["policy"] if command["scope"] == "a" else []),
            "revoke": ["status", "policy"], "write": ["execute"], "query_write": ["query"]}.get(command["operation"], [command["operation"]])
        require([calls[serial]["body"]["operation"] for serial in serials] == expected_operations,
                "actual operation differs from offered work")
        caller = command.get("caller", "other" if command["scope"] == "b" else "admin")
        for serial in serials:
            call = calls[serial]
            request, response, body, reply = (call[key] for key in ("request", "response", "body", "reply"))
            equal(body["scope"], SCOPES[command["scope"]], "cross-scope query")
            require(body["version"] == 1 and request["credential_sha256"] == configuration["credential_hashes"][caller],
                    "HTTP authentication identity changed")
            if body["operation"] == "query":
                sql = "INSERT INTO witness VALUES(99,random())" if command["operation"] == "query_write" else "SELECT n FROM witness ORDER BY n"
                equal(body["statements"], [{"sql": sql, "params": []}], "query workload changed")
            if body["operation"] == "execute":
                sql = (["CREATE TABLE witness(n INTEGER PRIMARY KEY,nonce INTEGER)",
                        "INSERT INTO witness VALUES(1,random()) RETURNING n,nonce"]
                       if command["operation"] == "seed" else
                       [f"INSERT INTO witness VALUES({command['n']},random()) RETURNING n,nonce"])
                equal(body["statements"], [{"sql": text, "params": []} for text in sql], "write workload changed")
            if body["operation"] == "policy":
                equal(body["permissions"], [
                    {"principal": "11", "read": True, "write": True, "admin": True},
                    {"principal": "12", "read": command["operation"] == "seed", "write": False, "admin": False},
                ], "reader permission change differs from fixed command")
            require(client_moment(started) < moment(request) < moment(response) < client_moment(finished), "SDK/HTTP interval mismatch")
            matches = [row for row in client if row["event"] == "http_request" and row["phase"] == name
                       and row["body_sha256"] == request["request_sha256"]]
            require(len(matches) == 1, "missing exact SDK request")
            sdk_request = matches[0]
            sdk_response = one(client, "http_response", call_id=sdk_request["call_id"])
            equal(original_bytes(sdk_request, "body", "body_sha256"), b64(request["request_body"]), "SDK request differs from wire")
            equal(original_bytes(sdk_response, "body", "body_sha256"), b64(response["response_body"]), "SDK response differs from wire")
            require(sdk_response["status"] == response["status"] and client_moment(sdk_request) < moment(request)
                    and moment(response) < client_moment(sdk_response), "SDK response interval mismatch")
            if command.get("error"):
                require(reply["ok"] is False and reply["error"]["code"] == command["error"] and response["status"] != 200,
                        "failure acknowledged as success")
            else:
                require(reply["ok"] is True and response["status"] == 200, "successful request rejected")
                if body["operation"] == "query":
                    require(body["statements"] == [{"sql": "SELECT n FROM witness ORDER BY n", "params": []}], "query workload changed")
                    decoded = result(b64(reply["value"]["result"]))
                    require(len(decoded) == 1 and decoded[0]["columns"] == ["n"]
                            and decoded[0]["rows"] == [[int(value)] for value in command["rows"]]
                            and decoded[0]["affected_rows"] == decoded[0]["last_insert_rowid"] == 0,
                            "query returned stale or wrong rows")
                    successful_queries += 1
    require(len([row for row in client if row["event"] == "http_request"]) == plan["http_count"]
            and len([row for row in client if row["event"] == "http_response"]) == plan["http_count"], "SDK HTTP denominator")

    verify_intervals(events, history, calls, by_command)
    verify_refresh(events, history, calls, by_command)

    net = original_s3_exchanges(history, phases={"seed", "overlap", "refresh", "unknown", "read_only", "revoke", "receipts"},
        blackhole_phases={"unknown"}, startups=service_startups(events, workers={"pool": "9101"}),
        endpoints={"pool": configuration["s3_endpoint"]}, access_key_sha256=configuration["access_key_sha256"])
    proxy = one(events, "proxy_stopped")
    require(proxy["http_requests"] == len(calls) and proxy["s3_requests"] == len(net["physical_requests"]),
            "proxy final counters differ from complete raw inventory")
    bindings = {serial: {number for number, call in calls.items()
                         if request["path"].startswith("/scap-test/scap-object/v1/" + "/".join(
                             call["body"]["scope"][key] for key in ("deployment", "tenant", "database")) + "/")}
                for serial, request in net["requests"].items()}
    versions = object_versions(net["requests"], net["responses"], calls=calls, bindings=bindings)
    unknown = [row for row in net["requests"].values() if row["phase"] == "unknown"]
    require(len(unknown) == 1 and unknown[0]["method"] == "GET" and unknown[0]["path"] == HEAD,
            "failed strong read retried or wrote objects")
    require(all(row["method"] == "GET" for row in net["requests"].values() if row["phase"] == "read_only"),
            "query published mutable state")

    require(len(originals) == 4 and {row["command"] for row in originals} == {"seed_a", "seed_b", "write", "write_again"}
            and len(lookups) == 3 and {row["command"] for row in lookups}
            == {"lookup_seed_a", "lookup_write", "lookup_write_again"}, "retained result denominator")
    for saved in originals:
        command = saved["command"]
        input_value = parse(saved["input"])
        execute = next(calls[serial] for serial in by_command[command] if calls[serial]["body"]["operation"] == "execute")
        value = execute["reply"]["value"]
        raw, _ = committed(value)
        require(input_value["request"]["fingerprint"] == fingerprint(input_value["statements"]), "original request fingerprint")
        equal(input_value["request"], execute["body"]["request"], "saved identity differs from original SQL request")
        equal(input_value["scope"], execute["body"]["scope"], "saved scope differs from original SQL request")
        equal(input_value["statements"], execute["body"]["statements"], "saved SQL differs from original request")
        equal(value["receipt"]["request"], execute["body"]["request"], "original receipt acknowledged another request")
        equal(value["receipt"]["scope"], execute["body"]["scope"], "original receipt acknowledged another scope")
        equal(saved["receipt"], value["receipt"], "original receipt changed")
        equal(b64(saved["raw"]), raw, "original random result changed")
        digest = value["receipt"]["result_hash"]
        puts = [row for row in net["requests"].values() if row["method"] == "PUT" and row["path"].endswith("/" + digest)]
        require(puts and any(moment(net["responses"][row["request_serial"]]) < moment(execute["response"]) for row in puts),
                "ACK before result-object durability")
    for saved in lookups:
        command = next(row for row in COMMANDS if row["id"] == saved["command"])
        require(saved["original"] == command["original"], "lookup referred to another original command")
        original = next(row for row in originals if row["command"] == saved["original"])
        call = calls[by_command[saved["command"]][0]]
        equal(call["body"]["request"], parse(original["input"])["request"], "lookup sent another original identity")
        lookup = call["reply"]["value"]
        committed(lookup)
        equal(saved["receipt"], original["receipt"], "lookup changed receipt")
        equal(saved["receipt"], lookup["receipt"], "lookup receipt differs from HTTP")
        equal(saved["raw"], original["raw"], "lookup replayed non-deterministic SQL")
        equal(saved["raw"], lookup["result"], "lookup bytes differ from HTTP")

    images = one(events, "private_images")["images"]
    require(images and len(images) <= 6 and len({(row["device"], row["inode"]) for row in images}) == len(images),
            "private reader images alias or exceed worker count")
    require(len({Path(row["path"]).parts[0] for row in images}) == len(images)
            and all(Path(row["path"]).parts[0].startswith("scap-worker-") and not Path(row["path"]).is_absolute()
                    and ".." not in Path(row["path"]).parts for row in images), "reader worker directories alias")
    stopped = one(events, "service_stopped")
    require(stopped["status"] == 0 and stopped["usage"]["available"] is True
            and stopped["identity"] == one(events, "service_started")["identity"], "owned worker cleanup not observed")
    require(one(events, "cache_cleaned")["entries"] == [] and one(events, "probe_stopped")["status"] == 0
            and one(events, "proxy_stopped")["errors"] == [], "owned resources not cleaned")
    owned = OwnedChildren()
    for name in ("service", "probe"):
        start, stop = one(events, name + "_started"), one(events, name + "_stopped")
        require(start["identity"] == stop["identity"] and stop["usage"]["available"] is True
                and stop["usage"]["source"] == "kernel_wait4_owned_child", "owned child exit evidence changed")
        owned.register(start["identity"], moment(stop))
    backend_start, backend_stop = one(events, "backend_started"), one(events, "backend_stopped")
    identities, ended = backend_start["identities"], backend_stop["processes"]
    require(len(identities) == len(ended) == 4 and {row["role"] for row in identities}
            == {"master", "volume", "filer", "s3"}, "backend child denominator changed")
    for identity in identities:
        matches = [row for row in ended if row["role"] == identity["role"]]
        require(len(matches) == 1, "backend child has no unique exit")
        stop = matches[0]
        equal({key: stop[key] for key in identity}, identity, "backend process identity changed")
        require(stop["wait_status"] == -signal.SIGKILL and stop["kernel_usage"]["available"] is True
                and stop["kernel_usage"]["source"] == "kernel_wait4_owned_child", "backend child was not reaped")
        owned.register(identity, moment(backend_stop))
    return {"status": "passed", "commands": len(COMMANDS), "http_requests": plan["http_count"],
            "successful_queries": successful_queries, "business_s3_requests": len(net["requests"]),
            "startup_s3_requests": len(net["startup_requests"]), "versions": versions,
            "original_results": len(originals), "original_lookups": len(lookups), "private_images": len(images)}


def verify_source(evidence, events):
    inputs = parse((evidence / "inputs.json").read_bytes())
    require(re.fullmatch(r"[0-9a-f]{40}", inputs["source_commit"]) is not None, "source commit changed")
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    configuration = parse((evidence / "service-config.json").read_bytes())
    require(digest(evidence / "service-config.json") == one(events, "service_started")["configuration_sha256"],
            "actual service configuration changed")
    equal(configuration["admission"]["read_pool"], PROFILE, "actual service read pool differs from fixed profile")
    require(configuration["worker_instance"] == "9101"
            and configuration["cache"] == {"pages_per_actor": 8192, "parallel_recoveries": 4},
            "actual worker/cache profile changed")
    require(digest(evidence / "source.json") == inputs["source_manifest_sha256"]
            and digest(evidence / "source.tar") == inputs["source_archive_sha256"], "fixture source witness changed")
    manifest = parse((evidence / "source.json").read_bytes())
    equal(parse((evidence / "source-after.json").read_bytes()), manifest, "source changed during actual execution")
    with tarfile.open(evidence / "source.tar", mode="r:") as archive:
        members = archive.getmembers()
        require(len(members) == len(manifest) and {member.name for member in members} == set(manifest),
                "fixture source inventory changed")
        for member in members:
            path = PurePosixPath(member.name)
            require(member.isfile() and not path.is_absolute() and ".." not in path.parts
                    and member.name == path.as_posix() and 0 <= member.size <= 16 * 1024 * 1024,
                    "fixture archive contains unsafe or oversized member")
            raw = archive.extractfile(member).read()
            require(len(raw) == member.size and hashlib.sha256(raw).hexdigest() == manifest[member.name],
                    "fixture source bytes changed")
    for path in Path(__file__).parent.iterdir():
        if path.is_file() and path.suffix in (".py", ".mjs", ".md"):
            require(manifest.get(path.relative_to(ROOT).as_posix()) == digest(path), "read-pool fixture omitted or changed")
    value = parse((evidence / "build/build-receipt.json").read_bytes())
    require(digest(evidence / "build/build-receipt.json") == inputs["build_receipt_sha256"]
            and value["source_commit"] == inputs["build_source_commit"], "build receipt changed")
    require(all(manifest.get(name) == expected for name, expected in value["inputs"].items()),
            "runtime build inputs differ from actual fixture source")
    tools = inputs["tools"]
    require(set(tools) == {"scapd", "node", "weed"}, "actual tool inventory changed")
    equal(tools["scapd"], value["binary"], "invoked service differs from release build")
    for name, event in (("scapd", "service_started"), ("node", "probe_started"), ("weed", "backend_started")):
        field = "node_sha256" if name == "node" else "binary_sha256"
        require(one(events, event)[field] == tools[name]["sha256"] == digest(Path(tools[name]["path"])),
                "invoked executable bytes changed")
    return {"source_files_verified": len(manifest),
            "build": audit_build(evidence / "build", profile="service", source_root=ROOT)}


def verify(evidence):
    evidence = Path(evidence)
    events = read(evidence / "events.jsonl")
    identity = verify_source(evidence, events)
    return {**verify_rows(parse((evidence / "plan.json").read_bytes()), events,
        read(evidence / "history.jsonl"), read(evidence / "http-client-ledger.jsonl"),
        read(evidence / "probe.jsonl"), read(evidence / "original-results.jsonl"), read(evidence / "original-lookups.jsonl")),
        "source": identity}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path)
    print(json.dumps(verify(parser.parse_args().evidence), sort_keys=True))
