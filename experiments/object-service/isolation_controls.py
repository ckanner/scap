#!/usr/bin/env python3
"""Corrupt independent copies of real evidence; no workload reruns or fake S3 pass."""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil

import isolation_oracle as oracle


def save(path, raw):
    temporary = path.with_name(path.name + ".replacement")
    temporary.write_bytes(raw)
    temporary.replace(path)  # Never truncate a hard-linked original evidence file.


def document(path, transform):
    value = json.loads(path.read_bytes())
    transform(value)
    save(path, (json.dumps(value, sort_keys=True) + "\n").encode())


def ledger(path, transform):
    value = [json.loads(line) for line in path.read_bytes().splitlines()]
    transform(value)
    save(path, b"".join((json.dumps(row, sort_keys=True)+"\n").encode() for row in value))


def select(values, **fields):
    return next(row for row in values if all(row.get(key) == value for key, value in fields.items()))


def http_call(directory, label):
    calls = oracle.rows(directory, "isolation-calls.jsonl")
    call_id = select(calls, event="call_finished", label=label)["call_id"]
    wire = oracle.rows(directory, "http-client-ledger.jsonl")
    return select(wire, event="http_request", call_id=call_id), select(wire, event="http_response", call_id=call_id)


def reorder_trace(values):
    values.sort(key=lambda row: int(row["monotonic_ns"]))
    for index, row in enumerate(values, 1):
        row["sequence"] = index


def move_event(directory, event, timestamp):
    def change(values):
        select(values, event=event)["monotonic_ns"] = timestamp
        reorder_trace(values)
    ledger(directory / "history.jsonl", change)


def modify_query_result(directory):
    request, _ = http_call(directory, "b_while_a_blocked")
    def change(values):
        row = select(values, event="http_response", call_id=request["call_id"])
        body = json.loads(base64.b64decode(row["body"]))
        raw = bytearray(base64.b64decode(body["value"]["result"]))
        input_value = select(oracle.rows(directory, "isolation-inputs.jsonl"), name="b")
        original = json.loads(input_value["request"])["statements"][1]["params"][0]["base64"]
        raw[raw.index(base64.b64decode(original))] ^= 1
        body["value"]["result"] = base64.b64encode(raw).decode()
        encoded = json.dumps(body, separators=(",", ":")).encode()
        row["body"], row["body_sha256"] = base64.b64encode(encoded).decode(), hashlib.sha256(encoded).hexdigest()
    ledger(directory / "http-client-ledger.jsonl", change)


def additional_get(directory, label, name, *, missing=False):
    request, response = http_call(directory, label)
    def change(values):
        prefix = f"/scap-test/scap-object/v1/1/7/{'101' if missing else '101' if name == 'a' else '202'}/"
        candidate = next(row for row in values if row["event"] == "object_response" and row["method"] == "GET" and
                         row["path"].startswith(prefix) and row["status"] == 200 and
                         (row["path"].endswith("/head") if missing else "/objects/" in row["path"]))
        original = candidate["request_serial"]
        serial = max(row.get("request_serial", 0) for row in values) + 1
        selected = [copy.deepcopy(select(values, event=event, request_serial=original)) for event in
                    ("object_request", "object_forwarded", "object_response", "object_response_delivered")]
        clock = int(request["monotonic_ns"]) + 10
        assert clock+4 < int(response["monotonic_ns"])
        for index, row in enumerate(selected):
            row.update(request_serial=serial, phase=request["phase"], monotonic_ns=clock+index)
            if missing:
                row["path"] = "/scap-test/scap-object/v1/1/7/303/head"
                if "status" in row:
                    # This is a deliberately corrupted copy, not an added real
                    # backend call. A fresh conditional create need not issue a
                    # missing-key GET, so no original 404 sample is assumed.
                    row.update(status=404, response_body="", response_bytes=0,
                               response_sha256=hashlib.sha256(b"").hexdigest(), etag=None,
                               head_response_bytes=[])
        values.extend(selected)
        reorder_trace(values)
    ledger(directory / "history.jsonl", change)


def omit_cold_chunk(directory):
    request, response = http_call(directory, "a_cold_open")
    mapping = {}
    def change(values):
        gate = select(values, event="transport_fault_observed")["request_serial"]
        victim = next(row["request_serial"] for row in values if row["event"] == "object_response" and
                      row["method"] == "GET" and "/objects/" in row["path"] and "/101/" in row["path"] and
                      row["request_serial"] != gate and int(request["monotonic_ns"]) < row["monotonic_ns"] < int(response["monotonic_ns"]) and
                      oracle.envelope(base64.b64decode(row["response_body"]), row["path"])[0]["kind"] == "chunk")
        values[:] = [row for row in values if row.get("request_serial") != victim]
        serials = sorted({row["request_serial"] for row in values if "request_serial" in row})
        mapping.update({serial: index for index, serial in enumerate(serials, 1)})
        for row in values:
            if "request_serial" in row:
                row["request_serial"] = mapping[row["request_serial"]]
        reorder_trace(values)
    ledger(directory / "history.jsonl", change)
    ledger(directory / "process-ledger.jsonl", lambda values: select(values, event="cold_gate_arrived").update(
        request_serial=mapping[select(values, event="cold_gate_arrived")["request_serial"]]))


def cargo_profile(directory):
    def change(values):
        row = next(row for row in values if row.get("reason") == "compiler-artifact" and row.get("executable"))
        row["profile"]["debug_assertions"] = True
    path = directory / "build-cargo.stdout.jsonl"
    ledger(path, change)
    document(directory / "build-receipt.json", lambda value: value.update(
        {"cargo.stdout.jsonl_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}))


def cases():
    return {
        "widened_hot_deadline": lambda path: document(path/"isolation-plan.json", lambda value: value["deadlines"].update(hot_probe_ms=60000)),
        "too_short_actual_s3_timeout": lambda path: document(path/"isolation-service-config.json", lambda value: value["s3"].update(timeout_ms=2000)),
        "omitted_original_call": lambda path: ledger(path/"isolation-calls.jsonl", lambda values: values.__setitem__(slice(None), [row for row in values if row["label"] != "b_keep_5"])),
        "hidden_sdk_retry": lambda path: ledger(path/"isolation-phases.jsonl", lambda values: values[0].update(sdk_http_attempts=7)),
        "altered_original_blob_result": modify_query_result,
        "hot_b_downloaded_data": lambda path: additional_get(path, "b_while_a_blocked", "b"),
        "post_open_a_downloaded_again": lambda path: additional_get(path, "a_resident_query", "a"),
        "capacity_refusal_touched_s3": lambda path: additional_get(path, "c_at_capacity", "c", missing=True),
        "status_downloaded_data_during_hold": lambda path: additional_get(path, "a_control_while_blocked", "a"),
        "incomplete_full_cold_open": omit_cold_chunk,
        "gate_armed_on_unrelated_object": lambda path: ledger(path/"history.jsonl", lambda values: select(values, event="transport_fault_armed").update(path="/scap-test/unrelated")),
        "hot_responses_after_release": lambda path: move_event(path, "gate_released", int(http_call(path, "b_while_a_blocked")[0]["monotonic_ns"])+1),
        "get_forwarded_before_release": lambda path: move_event(path, "gate_released", select(oracle.rows(path, "history.jsonl"), event="gate_released")["monotonic_ns"]+1000000000),
        "unsigned_backend_accepted": lambda path: ledger(path/"process-ledger.jsonl", lambda values: select(values, event="unsigned_backend_response").update(status=200)),
        "missing_kernel_wait4": lambda path: ledger(path/"process-ledger.jsonl", lambda values: select(values, event="service_stopped")["kernel_usage"].update(available=False)),
        "different_actual_daemon_binary": lambda path: ledger(path/"process-ledger.jsonl", lambda values: select(values, event="service_started")["binary"].update(sha256="0"*64)),
        "different_actual_config_bytes": lambda path: ledger(path/"process-ledger.jsonl", lambda values: select(values, event="service_started").update(configuration_sha256="0"*64)),
        "altered_client_process_output": lambda path: save(path/"cold_a.stdout.log", b"forged stdout\n"),
        "original_release_profile_changed": cargo_profile,
        "original_native_archive_changed": lambda path: document(path/"build-receipt.json", lambda value: value["native_archives"].update({next(iter(value["native_archives"])):"0"*64})),
        "truncated_original_source_archive": lambda path: save(path/"build-source.tar", (path/"build-source.tar").read_bytes()[:-512]),
    }


def main(args):
    evidence, output = args.evidence.resolve(), args.output.resolve()
    baseline = oracle.audit(evidence)
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    report = {"schema": 1, "status": "failed", "profile": "real-evidence-corruption-controls",
              "baseline_evidence": str(evidence), "baseline_sha256": baseline["evidence_sha256"],
              "denominator": len(cases())+1, "negative_controls": [], "positive_controls": []}
    try:
        for name, mutate in cases().items():
            path = output/name
            shutil.copytree(evidence, path, copy_function=os.link)
            mutate(path)
            try:
                oracle.audit(path)
            except (ValueError, KeyError, TypeError, AssertionError) as error:
                report["negative_controls"].append({"case": name, "outcome": "rejected", "reason": str(error)})
            else:
                raise AssertionError("corrupted real evidence incorrectly passed: "+name)
        path = output/"controller_summary_is_not_authority"
        shutil.copytree(evidence, path, copy_function=os.link)
        save(path/"summary.json", b'{"status":"invented","http_invocations":0}\n')
        oracle.audit(path)
        report["positive_controls"].append({"case": path.name, "outcome": "passed_without_controller_summary"})
        require = len(report["negative_controls"])+len(report["positive_controls"])
        assert require == report["denominator"]
        report["status"] = "passed"
    except BaseException as error:
        report["error"] = repr(error)
        raise
    finally:
        save(output/"controls.json", (json.dumps(report, indent=2, sort_keys=True)+"\n").encode())
        print(json.dumps({key: report.get(key) for key in ("status", "denominator", "error")}), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    main(parser.parse_args())
