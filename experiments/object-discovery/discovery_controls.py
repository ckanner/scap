#!/usr/bin/env python3
"""Mutate copies of a completed real trace; never edit original evidence.

A full independent baseline must pass first. Synthetic/unit fixtures do not
qualify. Rebound raw-body mutations reach semantic checks, and complete HTTP
exchange omissions renumber the transcript to avoid merely testing row gaps.
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import xml.etree.ElementTree as ET

import discovery_oracle as oracle


def one(rows, message):
    if len(rows) != 1: raise ValueError("control selection: " + message)
    return rows[0]


def invocation(data, label):
    return one([row for row in data["calls.jsonl"] if row["event"] == "invoked" and row["label"] == label], label)


def terminal(data, call):
    return one([row for row in data["calls.jsonl"] if row["event"] != "invoked" and row["call_id"] == call["call_id"]], "terminal")


def step(data, profile, *, required=None):
    for call in data["calls.jsonl"]:
        if call["event"] == "invoked" and call["label"].startswith(profile + ".step-"):
            value = terminal(data, call)["response"]["value"]
            if required is None or required(value): return call, value
    raise ValueError("control selection: no matching step")


def last_step(data, profile):
    call = [row for row in data["calls.jsonl"] if row["event"] == "invoked" and row["label"].startswith(profile + ".step-")][-1]
    return call, terminal(data, call)["response"]["value"]


def rebind_finish(data, profile):
    _, last = last_step(data, profile)
    one([row for row in data["facts.jsonl"] if row["event"] == "recovery_profile_finished" and row["profile"] == profile], "profile finish")["last"] = copy.deepcopy(last)


def renumber(data, name):
    for n, row in enumerate(data[name], 1): row["sequence"] = n


def omit_exchanges(data, serials):
    history = [row for row in data["history.jsonl"] if row.get("request_serial") not in serials]
    remaining = sorted({row["request_serial"] for row in history if "request_serial" in row})
    remap = {old: new for new, old in enumerate(remaining, 1)}
    for row in history:
        if "request_serial" in row: row["request_serial"] = remap[row["request_serial"]]
    for row in data["facts.jsonl"]:
        if "request_serial" in row:
            if row["request_serial"] not in remap: raise ValueError("control accidentally removed its fault anchor")
            row["request_serial"] = remap[row["request_serial"]]
    data["history.jsonl"] = history; renumber(data, "history.jsonl")


def response_rows(data, serial):
    return [row for row in data["history.jsonl"] if row.get("request_serial") == serial and "response_sha256" in row]


def replace_body(data, serial, encoded, overrides):
    digest = oracle.sha(encoded); overrides[digest] = encoded
    for row in response_rows(data, serial):
        row["response_sha256"] = digest; row["response_bytes"] = len(encoded)


def snapshots(directory):
    paths = [directory / name for name in oracle.FILES]
    for name in ("s3-bodies", "input-bodies", "native", "seed-build", "recovery-build"):
        paths += [path for path in (directory / name).rglob("*") if path.is_file()]
    return {path.relative_to(directory).as_posix(): oracle.discovery_build_audit.file_digest(path) for path in sorted(paths)}


def run(directory):
    directory = Path(directory).resolve()
    before = snapshots(directory)
    original = oracle.load_data(directory)
    baseline = oracle.audit_data(directory, original)
    if baseline["status"] != "passed" or baseline["verification_scope"] != "full":
        raise ValueError("real complete baseline did not pass full audit")
    results = []

    def control(label, change, *, accepts=False):
        data, overrides = copy.deepcopy(original), {}
        change(data, overrides)
        try:
            oracle.audit_data(directory, data, overrides=overrides)
        except ValueError as error:
            if accepts: raise ValueError(label + ": legitimate trace was rejected: " + str(error)) from error
            results.append({"control": label, "expected": "reject", "observed": "rejected", "reason": str(error)})
        else:
            if not accepts: raise ValueError(label + ": mutated original trace falsely passed")
            results.append({"control": label, "expected": "accept", "observed": "accepted"})

    def omit_input(data, _):
        data["inputs.jsonl"].pop(); renumber(data, "inputs.jsonl")
    control("omitted-original-input-with-contiguous-ledger", omit_input)

    def omit_ack(data, _):
        data["acks.jsonl"].pop(); renumber(data, "acks.jsonl")
    control("omitted-original-ack-with-contiguous-ledger", omit_ack)

    def unknown_ack(data, _):
        call = invocation(data, "native.accepted_without_native_ack.execute")
        terminal(data, call)["response"]["ok"] = True
    control("committed-without-native-publication-relabelled-ack", unknown_ack)

    def wrong_pid(data, _):
        first = one([row for row in data["facts.jsonl"] if row["event"] == "worker_started" and row["mode"] == "seed" and
                     row["config"]["scope"]["tenant"] == 10 and row["config"]["scope"]["database"] == 202], "maintenance child")
        victim = one([row for row in data["facts.jsonl"] if row["event"] == "worker_started" and row["mode"] == "seed" and
                      row["config"]["scope"]["tenant"] == 99], "acl child")
        for name in ("facts.jsonl", "calls.jsonl"):
            for row in data[name]:
                if row.get("worker") == victim["worker"] and row.get("identity") is not None:
                    row["identity"]["pid"] = first["identity"]["pid"]
                if row.get("worker") == victim["worker"] and "ready" in row:
                    row["ready"]["resources"]["namespace_pid"] = first["identity"]["pid"]
    control("overlapping-workers-claim-one-owned-pid", wrong_pid)

    def hidden_scope(data, _):
        worker = one([row for row in data["facts.jsonl"] if row["event"] == "recovery_profile_started" and row["profile"] == "complete"], "complete profile")["worker"]
        for row in data["facts.jsonl"]:
            if row.get("worker") == worker and "config" in row:
                row["config"]["known_scopes"] = []
                if "ready" in row: row["ready"]["configuration"]["known_scopes"] = []
    control("recovery-configuration-adds-predetermined-scope-list", hidden_scope)

    def source_binary(data, _):
        worker = one([row for row in data["facts.jsonl"] if row["event"] == "recovery_profile_started" and row["profile"] == "complete"], "complete profile")["worker"]
        for row in data["facts.jsonl"]:
            if row.get("worker") == worker and "binary" in row: row["binary"]["sha256"] = "0" * 64
    control("process-not-bound-to-original-release-binary", source_binary)

    def late_accepted(data, _):
        serial = one([row for row in data["facts.jsonl"] if row["event"] == "late_candidate_barrier"], "late original candidate")["request_serial"]
        for row in response_rows(data, serial): row["status"] = 200
    control("late-old-condition-mislabeled-accepted", late_accepted)

    def get_response(data):
        call, _ = step(data, "complete", required=lambda value: value["recovered_head"] is not None)
        return next(row for row in data["history.jsonl"] if row["event"] == "object_response" and
                    row["call_id"] == call["call_id"] and row["method"] == "GET" and "/objects/" in row["path"] and row["status"] == 200)

    def bad_etag(data, _):
        for row in response_rows(data, get_response(data)["request_serial"]): row["etag"] = '"unrelated-response-etag"'
    control("get-body-etag-from-different-version", bad_etag)

    def wrong_get_body(data, overrides):
        response = get_response(data)
        encoded = (directory / "s3-bodies" / response["response_sha256"]).read_bytes()
        replace_body(data, response["request_serial"], encoded[:-1] + bytes([encoded[-1] ^ 1]), overrides)
    control("get-body-rehashed-with-original-etag", wrong_get_body)

    def false_missing(data, _):
        for row in response_rows(data, get_response(data)["request_serial"]): row["status"] = 404; row["etag"] = None
    control("false-404-for-persistent-accepted-dependency", false_missing)

    def missing_retained_read(data, _):
        removed = one([row for row in data["facts.jsonl"] if row["event"] == "retained_result_removed"], "retained original Result")
        call, _ = step(data, "complete", required=lambda value: value["recovered_head"] is not None and value["recovered_head"]["scope"]["database"] == 101)
        serials = {row["request_serial"] for row in data["history.jsonl"] if row["event"] == "object_request" and
                   row["call_id"] == call["call_id"] and row["path"] == removed["key"]}
        if not serials: raise ValueError("control has no noncurrent Result GET")
        omit_exchanges(data, serials)
    control("entire-closed-window-result-get-omitted-with-rebound-sequences", missing_retained_read)

    def missing_readback(data, _):
        call = invocation(data, "native.base.execute")
        upload = next(row for row in data["history.jsonl"] if row["event"] == "object_request" and row["call_id"] == call["call_id"] and
                      row["method"] == "PUT" and "/objects/" in row["path"])
        serials = {row["request_serial"] for row in data["history.jsonl"] if row["event"] == "object_request" and
                   row["call_id"] == call["call_id"] and row["method"] == "GET" and row["path"] == upload["path"]}
        if not serials: raise ValueError("control has no new immutable readback")
        omit_exchanges(data, serials)
    control("new-ack-dependency-upload-without-complete-readback", missing_readback)

    def omitted_metadata(data, _):
        call, value = step(data, "complete", required=lambda value: value["metadata"] is not None and value["metadata"]["state"] == "DescriptorOnly")
        value["metadata"] = None
        for candidate in data["calls.jsonl"]:
            if candidate["event"] == "invoked" and candidate["label"].startswith("complete.step-") and candidate["call_id"] >= call["call_id"]:
                terminal(data, candidate)["response"]["value"]["completion"]["metadata_classified"] -= 1
        rebind_finish(data, "complete")
    control("unknown-tenant-metadata-omitted-with-consistent-summary-counters", omitted_metadata)

    def blocked_complete(data, _):
        _, value = last_step(data, "admin_without_read")
        value["stopped"] = None
        value["completion"].update(recovery_complete=True, traversal_exhausted=True, preexisting_slots_covered=True,
                                   permission_blocked=False, pending_scope=None)
        rebind_finish(data, "admin_without_read")
    control("admin-without-read-falsely-declares-complete", blocked_complete)

    def list_response(data):
        return next(row for row in data["history.jsonl"] if row["event"] == "object_response" and "?" in row["path"] and
                    b"<IsTruncated>true</IsTruncated>" in (directory / "s3-bodies" / row["response_sha256"]).read_bytes())

    def false_end(data, overrides):
        response = list_response(data); encoded = (directory / "s3-bodies" / response["response_sha256"]).read_bytes()
        replace_body(data, response["request_serial"], encoded.replace(b"<IsTruncated>true</IsTruncated>", b"<IsTruncated>false</IsTruncated>"), overrides)
    control("root-list-false-end-hides-original-tail", false_end)

    def omitted_prefix(data, overrides):
        response = list_response(data); root = ET.fromstring((directory / "s3-bodies" / response["response_sha256"]).read_bytes())
        ns = "{http://s3.amazonaws.com/doc/2006-03-01/}"
        root.remove(root.findall(ns + "CommonPrefixes")[-1]); count = root.find(ns + "KeyCount"); count.text = str(int(count.text) - 1)
        replace_body(data, response["request_serial"], ET.tostring(root, encoding="utf-8"), overrides)
    control("root-list-omits-prefix-and-rebinds-key-count", omitted_prefix)

    def changed_native(data, _):
        _, value = step(data, "complete", required=lambda value: value["native"] is not None)
        value["native"]["sha256"] = "f" * 64
    control("native-copy-is-not-the-verified-full-page-image", changed_native)

    def changed_query(data, _):
        call = next(row for row in data["calls.jsonl"] if row["event"] == "invoked" and row["label"].startswith("complete.query-"))
        value = terminal(data, call)["response"]["value"]
        encoded = bytes(value["encoded"]); first_blob = oracle.result(encoded)[0]["rows"][0][1]
        position = encoded.index(first_blob); value["encoded"][position] ^= 1
    control("full-production-query-changes-original-input-byte", changed_query)

    def changed_ack(data, _):
        call = invocation(data, "native.base.execute"); value = terminal(data, call)["response"]
        encoded = value["value"]["result"]["encoded"]; token = oracle.result(bytes(encoded))[-1]["rows"][0][2]
        position = bytes(encoded).index(token); encoded[position] ^= 1
        one([row for row in data["acks.jsonl"] if row["call_id"] == call["call_id"]], "original ACK")["response"] = copy.deepcopy(value)
    control("original-ack-nondeterministic-result-rebound-in-both-ledgers", changed_ack)

    def compute_survives(data, _):
        one([row for row in data["facts.jsonl"] if row["event"] == "compute_removed" and row["stage"] == "seed"], "compute loss")["exists"] = True
    control("old-compute-cache-survives-global-loss", compute_survives)

    def false_exit(data, _):
        next(row for row in data["facts.jsonl"] if row["event"] == "worker_stopped")["wait_status"] = 0
    control("claimed-process-loss-has-no-sigkill-wait4", false_exit)

    def forged_path(data, _):
        serial = get_response(data)["request_serial"]
        for row in data["history.jsonl"]:
            if row.get("request_serial") == serial and "path" in row: row["path"] += "forged"
    control("signed-original-http-path-changed-with-relay-verified-true", forged_path)

    def counter_reset(data, _):
        _, value = last_step(data, "complete"); value["usage"]["exact_gets"] = 0
        rebind_finish(data, "complete")
    control("whole-job-budget-resets-at-final-page", counter_reset)

    def late_delivery_log(data, _):
        call = next(row for row in data["calls.jsonl"] if row["event"] == "invoked" and row["label"].startswith("complete.query-"))
        end = terminal(data, call)
        delivered = one([row for row in data["history.jsonl"] if row["event"] == "object_response_delivered" and row["call_id"] == call["call_id"]], "query terminal delivery")
        delivered["monotonic_ns"] = end["monotonic_ns"] + 1
        data["history.jsonl"].sort(key=lambda row: row["monotonic_ns"]); renumber(data, "history.jsonl")
    control("legal-post-send-log-after-caller-observed-response", late_delivery_log, accepts=True)

    if snapshots(directory) != before: raise ValueError("controls changed original evidence bytes")
    return {"status": "passed", "verification_scope": "full", "baseline": baseline,
            "negative_controls": sum(item["expected"] == "reject" for item in results),
            "positive_controls": sum(item["expected"] == "accept" for item in results),
            "original_source_sha256": before, "originals_unchanged": True, "controls": results}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(run(args.evidence), sort_keys=True, indent=2))
