#!/usr/bin/env python3
"""Mutate hard-linked copies of real evidence; originals remain byte-identical."""
from __future__ import annotations

import argparse
import base64
import copy
import json
import os
from pathlib import Path
import shutil

from isolation_controls import cargo_profile, document, ledger, save, select
import segmented_oracle as oracle


def call(directory, label):
    labels = oracle.rows(directory, "segmented-calls.jsonl")
    identity = select(labels, event="call_finished", label=label)["call_id"]
    wire = oracle.rows(directory, "http-client-ledger.jsonl")
    return select(wire, event="http_request", call_id=identity), select(wire, event="http_response", call_id=identity)


def renumber(values):
    values.sort(key=lambda row: int(row["monotonic_ns"]))
    mapping = {row["request_serial"]: number for number, row in enumerate(
        (r for r in values if r["event"] == "object_request"), 1)}
    for number, row in enumerate(values, 1):
        row["sequence"] = number
        if "request_serial" in row: row["request_serial"] = mapping[row["request_serial"]]


def omit_bad_leaf_get(directory):
    begin, end = call(directory, "corrupt_query")
    def change(values):
        number = next(row["request_serial"] for row in values if row["event"] == "object_response" and row["phase"] == "corrupt" and
                      row["method"] == "GET" and "/objects/" in row["path"] and int(begin["monotonic_ns"]) < row["monotonic_ns"] < int(end["monotonic_ns"]) and
                      oracle.body_file(directory, row["response_sha256"], row["response_bytes"])[:8] != b"SCAPOBJ2")
        values[:] = [row for row in values if row.get("request_serial") != number]
        renumber(values)
    ledger(directory / "history.jsonl", change)


def extra_resident_download(directory):
    begin, end = call(directory, "warm_query")
    def change(values):
        sample = next(row for row in values if row["event"] == "object_response" and row["phase"] == "cold" and
                      row["method"] == "GET" and "/objects/" in row["path"] and row["status"] == 200)
        existing = sample["request_serial"]; number = max(r.get("request_serial", 0) for r in values) + 1
        copied = [copy.deepcopy(select(values, event=event, request_serial=existing)) for event in
                  ("object_request", "object_forwarded", "object_response", "object_response_delivered")]
        # Place this deliberately forged exchange after the actual resident HEAD
        # response while remaining inside the original complete HTTP interval.
        lower = max(r["monotonic_ns"] for r in values if r["event"] == "object_response_delivered" and r["phase"] == "warm" and
                    int(begin["monotonic_ns"]) < r["monotonic_ns"] < int(end["monotonic_ns"])) + 1
        assert lower + 4 < int(end["monotonic_ns"])
        for index, row in enumerate(copied): row.update(request_serial=number, phase="warm", monotonic_ns=lower + index)
        values.extend(copied); renumber(values)
    ledger(directory / "history.jsonl", change)


def wrong_get_etag(directory):
    def change(values):
        sample = next(r for r in values if r["event"] == "object_response" and r["phase"] == "warm" and r["path"] == oracle.HEAD)
        for row in values:
            if row.get("request_serial") == sample["request_serial"] and row["event"] in ("object_response", "object_response_delivered"):
                row["etag"] = '"a-different-version"'
    ledger(directory / "history.jsonl", change)


def altered_http_result(directory):
    request, _ = call(directory, "repaired_query")
    def change(values):
        row = select(values, event="http_response", call_id=request["call_id"])
        value = json.loads(base64.b64decode(row["body"]))
        raw = bytearray(base64.b64decode(value["value"]["result"]))
        original = select(oracle.rows(directory, "segmented-inputs.jsonl"), label="execute_first")
        payload = base64.b64decode(json.loads(original["request"])["statements"][-1]["params"][1]["base64"])
        raw[raw.index(payload)] ^= 1
        value["value"]["result"] = base64.b64encode(raw).decode()
        encoded = json.dumps(value, separators=(",", ":")).encode()
        row.update(body=base64.b64encode(encoded).decode(), body_sha256=oracle.sha(encoded))
    ledger(directory / "http-client-ledger.jsonl", change)


def changed_body_file(directory):
    row = next(r for r in oracle.rows(directory, "history.jsonl") if r["event"] == "object_response" and r["phase"] == "cold" and
               "/objects/" in r["path"] and r["method"] == "GET" and r["status"] == 200)
    path = directory / "s3-bodies" / row["response_sha256"]
    raw = bytearray(path.read_bytes()); raw[-1] ^= 1; save(path, raw)


def cases():
    return {
        "widened_original_deadline": lambda p: document(p/"segmented-plan.json", lambda v: v["deadlines"].update(seed_phase_ms=3_600_000)),
        "lost_original_input": lambda p: ledger(p/"segmented-inputs.jsonl", lambda v: v.pop()),
        "lost_original_cancel_outcome": lambda p: ledger(p/"segmented-calls.jsonl", lambda v: v.__setitem__(slice(None), [r for r in v if r["label"] != "cancel_1000"])),
        "hidden_sdk_retry": lambda p: ledger(p/"segmented-phases.jsonl", lambda v: v[0].update(sdk_http_attempts=v[0]["sdk_http_attempts"] + 1)),
        "changed_original_ack": lambda p: ledger(p/"segmented-acks.jsonl", lambda v: v[0].update(raw_sha256="0"*64)),
        "changed_original_query_blob": altered_http_result,
        "missing_nontarget_leaf_read": omit_bad_leaf_get,
        "resident_query_downloaded_objects": extra_resident_download,
        "get_etag_from_another_version": wrong_get_etag,
        "original_s3_body_changed": changed_body_file,
        "unsigned_backend_accepted": lambda p: ledger(p/"process-ledger.jsonl", lambda v: select(v, event="unsigned_backend_response").update(status=200)),
        "compute_cache_not_removed": lambda p: ledger(p/"process-ledger.jsonl", lambda v: select(v, event="cache_removed", ordinal=1).update(exists=True)),
        "missing_kernel_wait4": lambda p: ledger(p/"process-ledger.jsonl", lambda v: select(v, event="service_stopped", ordinal=2)["kernel_usage"].update(available=False)),
        "different_actual_daemon": lambda p: ledger(p/"process-ledger.jsonl", lambda v: select(v, event="service_started", ordinal=6)["binary"].update(sha256="0"*64)),
        "different_actual_config": lambda p: ledger(p/"process-ledger.jsonl", lambda v: select(v, event="service_started", ordinal=3).update(configuration_sha256="0"*64)),
        "changed_actual_client_output": lambda p: save(p/"cold.stdout.log", b"forged output\n"),
        "original_release_profile_changed": cargo_profile,
        "original_native_archive_changed": lambda p: document(p/"build-receipt.json", lambda v: v["native_archives"].update({next(iter(v["native_archives"])): "0"*64})),
        "truncated_original_source_archive": lambda p: save(p/"build-source.tar", (p/"build-source.tar").read_bytes()[:-512]),
    }


def main(args):
    evidence, output = args.evidence.resolve(), args.output.resolve()
    baseline = oracle.audit(evidence)
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    report = {"schema": 1, "status": "failed", "profile": "segmented-real-evidence-corruption-controls", "baseline_evidence": str(evidence),
              "baseline_source_sha256": baseline["source_sha256"], "denominator": len(cases()) + 1, "negative_controls": [], "positive_controls": []}
    try:
        for name, mutate in cases().items():
            path = output / name; shutil.copytree(evidence, path, copy_function=os.link); mutate(path)
            try: oracle.audit(path)
            except (ValueError, KeyError, TypeError, AssertionError) as error:
                report["negative_controls"].append({"case": name, "outcome": "rejected", "reason": str(error)})
            else: raise AssertionError("corrupted real evidence incorrectly passed: " + name)
            print(json.dumps({"control": name, "status": "rejected"}), flush=True)
        path = output / "controller_summary_is_not_authority"
        shutil.copytree(evidence, path, copy_function=os.link)
        save(path / "summary.json", b'{"status":"invented","http_invocations":0}\n')
        oracle.audit(path)
        report["positive_controls"].append({"case": path.name, "outcome": "passed_without_controller_summary"})
        assert len(report["negative_controls"]) + len(report["positive_controls"]) == report["denominator"]
        report["status"] = "passed"
    except BaseException as error:
        report["error"] = repr(error); raise
    finally:
        save(output / "controls.json", (json.dumps(report, indent=2, sort_keys=True) + "\n").encode())
        print(json.dumps({key: report.get(key) for key in ("status", "denominator", "error")}), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(); parser.add_argument("--evidence", type=Path, required=True); parser.add_argument("--output", type=Path, required=True)
    main(parser.parse_args())
