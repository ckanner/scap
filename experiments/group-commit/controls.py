#!/usr/bin/env python3
"""Counterfactual observer controls after a full audit of original evidence.

Raw controls mutate copies of captured rows and rerun the complete row audit.
Projection controls mutate decoded facts from those same audited rows and call
the named semantic checker. Neither kind runs SQL, sends HTTP/S3 requests, or
counts as an additional actual execution. Original evidence is read-only.
"""
from __future__ import annotations

import argparse
import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import oracle
import protocol
from spec import HEAD, PREFIX


RAW_CASES = {
    "unknown_original_event": "unexpected event kind: events",
    "extra_offered_command": "offered command inventory changed",
    "extra_sdk_command": "SDK command inventory changed",
    "extra_armed_fault": "fault inventory changed",
    "changed_fixed_fault_rule": "fixed fault rule changed",
    "extra_s3_phase": "phase inventory changed",
    "changed_original_http_bytes": "original bytes changed: request_body",
    "failed_member_changed_sql": "original SQL changed",
    "extra_sdk_post": "missing/duplicate exact SDK POST",
    "lost_reply_claimed_ack": "SDK outcome differs from fixed command",
    "saved_result_substituted": "SDK stored another original result",
    "cold_result_regenerated": "cold lookup replayed non-deterministic SQL",
    "crashed_cache_reused": "cold recovery reused crashed cache",
    "unobserved_head_etag": "CAS has no original accepted predecessor",
    "immutable_replacement": "immutable object key/condition differs from actual bytes",
    "missing_dependency_readback": "HEAD preceded dependency persistence and exact readback",
}

PUBLICATION_CASES = {
    "shared_transaction_revision": "member sequence/revision is not its independent transaction",
    "missing_logical_member": "logical group width differs from fresh identities",
    "repeated_member_sequence": "member sequence/revision is not its independent transaction",
    "one_serial_for_many_members": "group changed protected authority or final member root",
    "retained_identity_removed": "group removed retained identities",
    "retained_identity_rewritten": "group rewrote a retained identity",
    "cancelled_member_published": "group replaced a cancellation barrier",
    "protected_owner_changed": "group changed protected authority or final member root",
    "protected_policy_changed": "group changed protected authority or final member root",
    "protected_storage_changed": "group changed protected authority or final member root",
    "final_root_is_not_last_member": "group changed protected authority or final member root",
}

RECEIPT_CASES = {
    "receipt_uses_final_instead_of_member_root": "receipt differs from original stored result",
    "receipt_changes_original_identity": "receipt changed original full identity",
    "receipt_regenerates_result_bytes": "receipt differs from original stored result",
}

INTERVAL_CASES = {
    "member_dispatched_after_actor_release": "group member was not queued before original actor release",
    "queue_refusal_after_actor_release": "queue-full refusal did not precede group execution",
    "cancel_finished_outside_group_hold": "cancel did not win while original group CAS was held",
}


def jsonable(value):
    if isinstance(value, bytes):
        return {"bytes_base64": base64.b64encode(value).decode()}
    if isinstance(value, set):
        return sorted(jsonable(item) for item in value)
    if isinstance(value, dict):
        return {str(key): jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [jsonable(item) for item in value]
    return value


def digest(value):
    raw = json.dumps(jsonable(value), sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False, allow_nan=False).encode()
    return hashlib.sha256(raw).hexdigest()


def reference(file, row):
    return {"file": file, **{key: row[key] for key in
        ("sequence", "event", "request_serial", "http_serial", "call_id", "command", "request_sha256")
        if key in row}, "original_row_sha256": digest(row)}


def inventory(evidence):
    files = {}
    for path in sorted(evidence.rglob("*")):
        oracle.require(not path.is_symlink(), "controls cannot follow evidence symlinks")
        if path.is_file():
            files[path.relative_to(evidence).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
        else:
            oracle.require(path.is_dir(), "controls encountered nonregular evidence")
    return files


def rejection(name, scope, expected, check, before, after, references):
    """A generic exception or another rejection reason is a failed control."""
    oracle.require(digest(before) != digest(after), "counterfactual did not change the audited facts")
    observed = None
    try:
        check()
    except Exception as error:
        observed = {"type": type(error).__name__, "message": str(error)}
    correct = observed == {"type": "ValueError", "message": expected}
    return {"name": name, "scope": scope, "status": "passed" if correct else "failed",
            "expected_rejection": expected, "observed_rejection": observed,
            "original_references": references, "before_sha256": digest(before), "after_sha256": digest(after),
            "additional_actual_executions": 0}


def projections(rows):
    _, events, history, ledger, probe, *_ = rows
    calls, by_command, originals = oracle.http(events, ledger, probe)
    authority = oracle.authority(events, history, calls, by_command, originals)
    requests, responses = authority["net"]["requests"], authority["net"]["responses"]
    versions = {responses[serial]["etag"]: serial for serial, request in authority["heads"].items()
                if request["method"] == "PUT" and responses[serial]["status"] == 200}
    selected = []
    for serial, request in authority["heads"].items():
        if request["method"] != "PUT" or request["phase"] != "success" or request["if_match"] not in versions:
            continue
        base = versions[request["if_match"]]
        if authority["candidates"][serial]["sequence"] - authority["candidates"][base]["sequence"] == 4:
            selected.append((base, serial))
    oracle.require(len(selected) == 1, "controls require one original four-member success group")
    base, serial = selected[0]
    objects = {request["path"]: oracle.b64(request["request_body"]) for number, request in requests.items()
               if request["path"].startswith(PREFIX) and request["method"] == "PUT"
               and responses[number]["status"] == 200}
    previous, candidate = authority["candidates"][base], authority["candidates"][serial]
    before, after = protocol.closure(objects, previous), protocol.closure(objects, candidate)
    publication = {"previous": previous, "candidate": candidate,
                   "before": {key: before[key] for key in ("entries", "stored")},
                   "after": {key: after[key] for key in ("entries", "stored")}}
    value = originals["success_a"]
    first = int(value["value"]["receipt"]["request"]["id"])
    receipt = {"receipt": value["value"]["receipt"], "raw": value["raw"], "stored": after["stored"][first]}
    references = [reference("history.jsonl", authority["heads"][number]) for number in (base, serial)]
    references.append(reference("events.jsonl", calls[value["call"]]["response"]))
    return {"publication": publication, "receipt": receipt, "intervals": (events, history, calls, by_command),
            "references": references, "group_serial": serial, "base_serial": base,
            "result_key": PREFIX + after["stored"][first]["hash"], "authority": authority}


def publication_mutation(original, name):
    changed = deepcopy(original)
    previous, candidate, before, after = (changed[key] for key in ("previous", "candidate", "before", "after"))
    added = sorted(set(after["entries"]) - set(before["entries"]),
                   key=lambda identifier: after["stored"][identifier]["metadata"]["sequence"])
    if name == "shared_transaction_revision":
        after["stored"][added[1]]["metadata"]["transition"]["revision"] = previous["revision"] + 1
    elif name == "missing_logical_member":
        after["entries"].pop(added[1])
    elif name == "repeated_member_sequence":
        after["stored"][added[1]]["metadata"]["sequence"] = previous["sequence"] + 1
    elif name == "one_serial_for_many_members":
        candidate["head_serial"] = previous["head_serial"] + 1
    elif name == "retained_identity_removed":
        after["entries"].pop(min(before["entries"]))
    elif name == "retained_identity_rewritten":
        after["entries"][min(before["entries"])]["request"]["fingerprint"] = "f" * 64
    elif name == "cancelled_member_published":
        value = after["stored"][added[1]]["metadata"]
        after["entries"][added[1]]["outcome"] = {"state": "cancelled", "transition": value["transition"]}
    elif name == "protected_owner_changed":
        candidate["owner_epoch"] += 1
    elif name == "protected_policy_changed":
        candidate["policy"][0]["write"] = not candidate["policy"][0]["write"]
    elif name == "protected_storage_changed":
        candidate["storage"]["allocated_through"] += 1
    elif name == "final_root_is_not_last_member":
        candidate["data_root"] = after["stored"][added[0]]["metadata"]["data_root"]
    else:
        raise ValueError("unknown publication control: " + name)
    return changed


def changed_bytes(value):
    oracle.require(value, "control requires nonempty original bytes")
    return value[:-1] + bytes([value[-1] ^ 1])


def renumber(history, events):
    serials = {old: new for new, old in enumerate(sorted({row["request_serial"] for row in history
                                                       if "request_serial" in row}), 1)}
    for sequence, row in enumerate(history, 1):
        row["sequence"] = sequence
        if "request_serial" in row:
            row["request_serial"] = serials[row["request_serial"]]
    for row in events:
        if "request_serial" in row:
            oracle.require(row["request_serial"] in serials, "control removed a named fault exchange")
            row["request_serial"] = serials[row["request_serial"]]


def raw_mutation(original, projection, name):
    rows = deepcopy(original)
    _, events, history, ledger, probe, _, saved, lookups = rows
    references = []

    def target(items, file, event=None, **fields):
        found = [row for row in items if (event is None or row.get("event") == event)
                 and all(row.get(key) == value for key, value in fields.items())]
        oracle.require(len(found) == 1, "control target is missing or repeated: " + name)
        references.append(reference(file, found[0]))
        return found[0]

    if name in ("unknown_original_event", "extra_offered_command", "extra_armed_fault", "extra_s3_phase"):
        items, file = (history, "history.jsonl") if name == "extra_s3_phase" else (events, "events.jsonl")
        references.append(reference(file, items[-1]))
        added = {"schema": 1, "sequence": len(items) + 1,
                 "monotonic_ns": oracle.moment(items[-1]) + 1}
        if name == "unknown_original_event":
            added["event"] = "synthetic_unplanned_observer_event"
        elif name == "extra_offered_command":
            added.update(event="command_sent", command="synthetic_extra_command")
        elif name == "extra_s3_phase":
            added.update(event="phase_started", phase="synthetic_extra_phase")
        else:
            source = target(events, "events.jsonl", "fault_armed", id="success_queue_gate")
            added = {**source, **added, "id": "synthetic_extra_fault"}
        items.append(added)
    elif name == "extra_sdk_command":
        source = target(probe, "probe.jsonl", "command_started", command="success_a")
        probe.append({**source, "command": "synthetic_extra_command",
                      "monotonic_ns": str(max(oracle.client_moment(row) for row in probe) + 1)})
    elif name == "changed_fixed_fault_rule":
        target(events, "events.jsonl", "fault_armed", id="success_queue_gate")["method"] = "PUT"
    elif name in ("changed_original_http_bytes", "failed_member_changed_sql"):
        command = "success_a" if name == "changed_original_http_bytes" else "first_failure_a"
        request = target(events, "events.jsonl", "http_request", command=command)
        raw = oracle.b64(request["request_body"])
        if name == "changed_original_http_bytes":
            replacement = base64.b64encode(changed_bytes(raw)).decode()
            for row in events:
                if row.get("http_serial") == request["http_serial"]:
                    row["request_body"] = replacement
        else:
            body = oracle.parse(raw)
            body["statements"][0]["sql"] = "SELECT * FROM synthetic_missing_table"
            replacement = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode()
            text, sha = base64.b64encode(replacement).decode(), hashlib.sha256(replacement).hexdigest()
            for row in events:
                if row.get("http_serial") == request["http_serial"]:
                    row.update(request_body=text, request_sha256=sha)
            sdk = target(ledger, "http-client-ledger.jsonl", "http_request", phase=command)
            sdk.update(body=text, body_sha256=sha)
    elif name == "extra_sdk_post":
        row = target(ledger, "http-client-ledger.jsonl", "http_request", phase="success_a")
        ledger.append(deepcopy(row))
    elif name == "lost_reply_claimed_ack":
        target(probe, "probe.jsonl", "command_finished", command="response_loss_b")["outcome"] = "ok"
    elif name in ("saved_result_substituted", "cold_result_regenerated"):
        items, file, fields = (saved, "original-results.jsonl", {"command": "success_a"}) if name == "saved_result_substituted" else (
            lookups, "original-lookups.jsonl", {"original": "success_a"})
        row = target(items, file, **fields)
        row["raw"] = base64.b64encode(changed_bytes(oracle.b64(row["raw"]))).decode()
    elif name == "crashed_cache_reused":
        target(events, "events.jsonl", "cache_discarded", worker="primary")["exists"] = True
    elif name == "unobserved_head_etag":
        serial = projection["group_serial"]
        target(history, "history.jsonl", "object_request", request_serial=serial)
        for row in history:
            if row.get("request_serial") == serial:
                row["if_match"] = '"synthetic-etag-not-observed-in-original-history"'
    elif name == "immutable_replacement":
        request = next(row for row in history if row["event"] == "object_request"
                       and row["path"].startswith(PREFIX) and row["method"] == "PUT")
        references.append(reference("history.jsonl", request))
        for row in history:
            if row.get("request_serial") == request["request_serial"]:
                row.update(if_none_match=None, if_match='"synthetic-immutable-replacement"')
    elif name == "missing_dependency_readback":
        net = projection["authority"]["net"]
        deadline = oracle.moment(net["requests"][projection["group_serial"]])
        serials = {serial for serial, request in net["requests"].items()
                   if request["method"] == "GET" and request["path"] == projection["result_key"]
                   and oracle.moment(net["responses"][serial]) < deadline}
        oracle.require(serials, "control needs the original group result readback")
        references.extend(reference("history.jsonl", net["requests"][serial]) for serial in sorted(serials))
        history[:] = [row for row in history if row.get("request_serial") not in serials]
        renumber(history, events)
    else:
        raise ValueError("unknown raw control: " + name)
    return rows, references


def interval_mutation(original, name):
    changed = deepcopy(original)
    events, _, calls, by_command = changed
    if name == "cancel_finished_outside_group_hold":
        release = oracle.one(events, "fault_released", id="group_candidate")
        calls[by_command["cancel_member"][0]]["response"]["monotonic_ns"] = oracle.moment(release) + 1
    else:
        release = oracle.one(events, "fault_released", id="success_queue_gate")
        command, stage = ("success_a", "request") if name == "member_dispatched_after_actor_release" else ("success_overflow", "response")
        oracle.require(name in INTERVAL_CASES, "unknown interval control")
        calls[by_command[command][0]][stage]["monotonic_ns"] = oracle.moment(release) + 1
    return changed


class ControlFailure(ValueError):
    def __init__(self, report):
        self.report = report
        failed = [row["name"] for row in report["controls"] if row["status"] != "passed"]
        super().__init__("controls did not reject for their intended reasons: " + ", ".join(failed))


def check(evidence):
    evidence = Path(evidence)
    original_inventory = inventory(evidence)
    baseline = oracle.verify(evidence)
    rows = oracle.evidence_rows(evidence)
    # This positive check covers all copied raw rows; it is not another actual
    # run, nor a claim to have forged a second valid source/build archive.
    positive = oracle.verify_rows(*deepcopy(rows))
    oracle.equal(positive, {key: value for key, value in baseline.items() if key != "source"},
                 "byte-identical row copy changed the observer verdict")
    projection = projections(rows)
    controls = []
    for name, expected in RAW_CASES.items():
        changed, references = raw_mutation(rows, projection, name)
        controls.append(rejection(name, "raw-ledger-counterfactual", expected,
            lambda: oracle.verify_rows(*changed), rows, changed, references))
    publication = projection["publication"]
    protocol.publication(**publication)
    for name, expected in PUBLICATION_CASES.items():
        changed = publication_mutation(publication, name)
        controls.append(rejection(name, "audited-publication-projection", expected,
            lambda: protocol.publication(**changed), publication, changed, projection["references"]))
    receipt = projection["receipt"]
    protocol.receipt_matches(**receipt)
    for name, expected in RECEIPT_CASES.items():
        changed = deepcopy(receipt)
        if name == "receipt_uses_final_instead_of_member_root":
            changed["receipt"]["data_root"] = publication["candidate"]["data_root"]
        elif name == "receipt_changes_original_identity":
            changed["receipt"]["request"]["principal"] = "12"
        else:
            changed["raw"] = changed_bytes(changed["raw"])
        controls.append(rejection(name, "audited-receipt-projection", expected,
            lambda: protocol.receipt_matches(**changed), receipt, changed, projection["references"]))
    intervals = projection["intervals"]
    oracle.intervals(*intervals)
    for name, expected in INTERVAL_CASES.items():
        changed = interval_mutation(intervals, name)
        controls.append(rejection(name, "audited-interval-projection", expected,
            lambda: oracle.intervals(*changed), intervals, changed, projection["references"]))
    net = projection["authority"]["net"]
    first, last = projection["base_serial"], projection["group_serial"]
    original_order = {(first, last)}
    oracle.linearize(net["requests"], net["responses"], {first, last}, original_order)
    for name, changed, expected in (
        ("head_order_reverses_real_time", {(last, first)}, "HEAD has no legal real-time linearization"),
        ("head_order_is_cyclic", {(first, last), (last, first)}, "cyclic HEAD authority history"),
    ):
        controls.append(rejection(name, "audited-head-order-projection", expected,
            lambda: oracle.linearize(net["requests"], net["responses"], {first, last}, changed),
            original_order, changed, projection["references"]))
    oracle.equal(inventory(evidence), original_inventory, "controls changed original evidence")
    report = {"schema": 1, "status": "passed" if all(row["status"] == "passed" for row in controls) else "failed",
        "profile": "independent-group-commit-observer-controls-v1", "original_full_audit": baseline,
        "positive_row_copy": {"status": "passed", "scope": "all copied original rows, after full source/build audit"},
        "original_inventory_sha256": digest(original_inventory), "original_files": len(original_inventory),
        "raw_counterfactuals": len(RAW_CASES), "projection_counterfactuals": len(controls) - len(RAW_CASES),
        "controls": controls, "additional_actual_executions": 0,
        "boundary": "Counterfactual copies test observer rejection only; original execution counts are unchanged"}
    if report["status"] != "passed":
        raise ControlFailure(report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--output", type=Path, help="new JSON report; default prints to stdout")
    args = parser.parse_args()
    try:
        report = check(args.evidence)
    except ControlFailure as error:
        report = error.report
    except Exception as error:
        report = {"schema": 1, "status": "failed", "error_type": type(error).__name__, "error": str(error),
                  "additional_actual_executions": 0}
    if args.output is not None:
        with args.output.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2, sort_keys=True, ensure_ascii=False)
            stream.write("\n")
    print(json.dumps(report, sort_keys=True, ensure_ascii=False))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
