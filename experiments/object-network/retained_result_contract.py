#!/usr/bin/env python3
"""Real S3 semantic-result-corruption cases for PR #23.

Only a private loopback fixture may publish these deliberately inconsistent
objects. Production algorithms run in the recorded Rust release worker. Python
unit tests of this harness are NOT Rust, native SQLite, or S3 acceptance evidence.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import sys
import tempfile

MAGIC = b"SCAPOBJ2"
FRAME_SIZE = 20
MAX_BYTES = 64 * 1024 * 1024 + 64 * 1024
MUTATIONS = ("bad_magic", "truncated_footer", "trailing_byte", "unknown_tag",
             "nonfinite_real", "invalid_utf8")
PROBES = ("lookup_identity", "cancel_identity", "activate", "activate_session", "session_open", "query")
SCENARIOS = tuple(f"result_{epoch}_{damage}" for epoch in ("current", "closed") for damage in MUTATIONS)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def no_constant(_value):
    raise ValueError("nonfinite JSON literal")


def load_json(data):
    return json.loads(data, object_pairs_hook=unique, parse_constant=no_constant)


def json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def unpack(data):
    require(FRAME_SIZE <= len(data) <= MAX_BYTES, "fixture frame length")
    require(data[:8] == MAGIC, "fixture frame version")
    metadata_size, raw_size = struct.unpack("<IQ", data[8:FRAME_SIZE])
    require(FRAME_SIZE + metadata_size + raw_size == len(data), "fixture frame bounds")
    metadata = load_json(data[FRAME_SIZE:FRAME_SIZE + metadata_size])
    require(isinstance(metadata, dict) and metadata.get("format") == 2, "fixture metadata version")
    return metadata, data[FRAME_SIZE + metadata_size:]


def pack(metadata, raw):
    encoded = json_bytes(metadata)
    require(FRAME_SIZE + len(encoded) + len(raw) <= MAX_BYTES, "fixture frame too large")
    return MAGIC + struct.pack("<IQ", len(encoded), len(raw)) + encoded + raw


def mutate(raw, damage):
    require(raw.startswith(b"SCAPRES1") and len(raw) >= 12, "original result needs a valid header")
    if damage == "bad_magic":
        return bytes([raw[0] ^ 1]) + raw[1:]
    if damage == "truncated_footer":
        return raw[:-1]
    if damage == "trailing_byte":
        return raw + b"\x00"
    # Independent result-vector assembly: one statement, column x, one row.
    prefix = b"SCAPRES1" + struct.pack("<III", 1, 1, 1) + b"x" + struct.pack("<I", 1)
    variants = {
        "unknown_tag": b"\xff",
        "nonfinite_real": b"\x02" + struct.pack("<Q", 0x7ff0000000000000),
        "invalid_utf8": b"\x03" + struct.pack("<I", 1) + b"\xff",
    }
    require(damage in variants, "unknown corruption selector")
    return prefix + variants[damage] + bytes(16)


def object_key(scope, root):
    require(len(root) == 64 and all(c in "0123456789abcdef" for c in root), "fixture root hash")
    return (f"scap-object/v1/{scope['deployment']}/{scope['tenant']}/{scope['database']}"
            f"/inc/{scope['incarnation']}/gen/{scope['generation']}/objects/{root}")


def rewrite(head_bytes, index_bytes, result_bytes, epoch, damage):
    """Rehash the complete chain and preserve the exact aggregate byte count.

    Without the counter adjustment an old verify_results would reject the
    fixture for a different reason, creating a false positive regression.
    """
    head = load_json(head_bytes)
    require(head["format"] == 4, "fixture HEAD version")
    selected = [window for window in head["windows"] if window["epoch"] == epoch]
    require(len(selected) == 1, "exact retained window required")
    window = selected[0]
    require(sha(index_bytes) == window["root"], "original index hash mismatch")
    index, index_raw = unpack(index_bytes)
    require(not index_raw and index["payload"]["kind"] == "index", "fixture index kind")
    result, raw = unpack(result_bytes)
    require(result["payload"]["kind"] == "result", "fixture result kind")
    require(index["scope"] == result["scope"] == head["scope"], "fixture scope mismatch")
    stored = result["payload"]["value"]
    require(stored["bytes"] == [], "result must use v2 raw bytes")
    require(stored["request"]["epoch"] == epoch, "fixture request epoch mismatch")
    node = index["payload"]["value"]
    require(set(node) == {"kind", "epoch", "entries"} and node["kind"] == "leaf" and node["epoch"] == epoch, "fixture requires one explicit epoch-bound leaf")
    entries = node["entries"]
    require(len(entries) == window["count"] and len(entries) <= 128, "fixture index count mismatch")
    require(sum(entry["result_bytes"] for entry in entries) == window["result_bytes"], "fixture leaf aggregate mismatch")
    matches = [entry for entry in entries if entry["request"] == stored["request"]]
    require(len(matches) == 1, "exact request reference required")
    outcome = matches[0]["outcome"]
    require(outcome == {"state": "committed", "result": sha(result_bytes)}, "original result link mismatch")
    changed_raw = mutate(raw, damage)
    changed_result = pack(result, changed_raw)
    new_result_root = sha(changed_result)
    outcome["result"] = new_result_root
    require(matches[0]["result_bytes"] == len(raw), "original result leaf length differs")
    matches[0]["result_bytes"] = len(changed_raw)
    changed_index = pack(index, b"")
    window["root"] = sha(changed_index)
    before_count = window["result_bytes"]
    require(type(before_count) is int and before_count >= len(raw), "fixture result byte total")
    window["result_bytes"] = before_count - len(raw) + len(changed_raw)
    require(window["result_bytes"] <= head["retention"]["max_result_bytes"], "fixture retention overflow")
    require(window["result_bytes"] <= window["count"] * 64 * 1024 * 1024, "fixture format counter overflow")
    return {"head": json_bytes(head), "index": changed_index, "result": changed_result,
            "result_key": object_key(head["scope"], new_result_root),
            "index_key": object_key(head["scope"], window["root"]),
            "request": copy.deepcopy(stored["request"]), "raw": changed_raw,
            "original_result_sha256": sha(result_bytes), "original_raw_sha256": sha(raw),
            "raw_sha256": sha(changed_raw), "counter_before": before_count,
            "counter_after": window["result_bytes"]}


def value(response):
    require(response.get("ok") is True, f"worker operation failed: {response.get('error')}")
    return response["value"]


def require_refusal(response, before, after, trace, corrupt_key, corrupt_hash):
    require(response.get("ok") is False and response.get("error") == "Corrupt",
            "expected semantic Corrupt, not outer hash failure, success or a transport error")
    require(before == after, "rejected operation changed HEAD body or ETag")
    reads = [entry for entry in trace if entry.get("event") == "object_response"
             and entry.get("method") == "GET" and entry.get("path") == "/scap-test/" + corrupt_key]
    require(any(entry.get("status") == 200 and entry.get("response_sha256") == corrupt_hash
                for entry in reads), "no real backend 200 for the correctly hashed corrupt Result")
    require(not any(entry.get("event") == "object_request" and entry.get("method") == "PUT"
                    and entry.get("path", "").endswith("/head") for entry in trace),
            "rejected operation attempted HEAD publication")


def run_case(suite, epoch_kind, damage):
    case = suite.fixture(f"result_{epoch_kind}_{damage}")
    owner = case["owner"]
    current = epoch_kind == "current"
    if current:
        suite.ack(case, case["invocation"], owner.finish(suite.begin(case)))
    head = value(owner.call("status"))
    taken = value(owner.call("takeover", revision=head["revision"], nonce=800))
    before = suite.snapshot(case, owner, "recovering_before_semantic_damage")
    epoch = 2 if current else 1
    selected = next(window for window in taken["windows"] if window["epoch"] == epoch)
    index_bytes = bytes(value(owner.call("store_get", key=object_key(case["scope"], selected["root"])))["bytes"])
    index, _ = unpack(index_bytes)
    entry = next(entry for entry in reversed(index["payload"]["value"]["entries"]) if entry["outcome"]["state"] == "committed")
    result_bytes = bytes(value(owner.call("store_get", key=object_key(case["scope"], entry["outcome"]["result"])))["bytes"])
    original_metadata, original_raw = unpack(result_bytes)
    value(owner.call("decode_result", encoded=list(original_raw)))
    plan = rewrite(bytes(before["bytes"]), index_bytes, result_bytes, epoch, damage)
    # Official object codec proves the envelope remains valid, while the
    # official SQL decoder proves the selected inner payload is invalid.
    for role in ("result", "index"):
        inspected = value(owner.call("inspect_object", bytes=list(plan[role])))
        require(inspected["role"] == role and inspected["sha256"] == sha(plan[role]), "native envelope rejected fixture")
        key = plan[role + "_key"]
        value(owner.call("store_put", key=key, bytes=list(plan[role])))
        require(value(owner.call("store_get", key=key))["bytes"] == list(plan[role]), "fixture dependency readback failed")
    require(owner.call("decode_result", encoded=list(plan["raw"]))["ok"] is False, "selected corruption is decodable")
    value(owner.call("store_put", key=case["head_key"], bytes=list(plan["head"]), etag=before["etag"]))
    damaged = suite.snapshot(case, owner, "semantic_damage_published")
    require(damaged["bytes"] == list(plan["head"]) and damaged["etag"] != before["etag"], "fixture HEAD mutation not observed")
    suite.event(case, "trusted_semantic_damage_published", damage=damage, epoch=epoch,
                request=plan["request"], result_key=plan["result_key"], result_sha256=sha(plan["result"]),
                index_key=plan["index_key"], index_sha256=sha(plan["index"]),
                original_result_sha256=plan["original_result_sha256"], original_raw_sha256=plan["original_raw_sha256"],
                raw_sha256=plan["raw_sha256"], result_bytes_before=plan["counter_before"],
                result_bytes_after=plan["counter_after"], official_outer_decode_passed=True,
                official_inner_decode_rejected=True, trusted_admin_injection=True)
    logical_owner = owner.config["worker"]
    suite.lose_compute(case)
    for operation in PROBES:
        probe = suite.spawn(case, logical_worker=logical_owner)
        phase = suite.phase(case, operation)
        arguments = {"identity": plan["request"]} if operation.endswith("identity") else {"directory": operation}
        if operation in ("activate", "activate_session"):
            arguments.update(revision=taken["revision"], nonce=801)
        if operation == "query":
            arguments["sql"] = "SELECT 1"
        response = probe.call(operation, **arguments)
        after = suite.snapshot(case, probe, "after_" + operation)
        require_refusal(response, damaged, after, suite.trace(phase), plan["result_key"], sha(plan["result"]))
        require(not (case["directory"] / operation).exists(), "failed recovery leaked an owned cache")
        suite.event(case, "semantic_result_refused", operation=operation, response=response,
                    head_unchanged=True, actual_result_get=True, recovery_directory_absent=True)
        suite.stop(case, probe)
    repairer = suite.spawn(case, logical_worker=logical_owner)
    observed = suite.snapshot(case, repairer, "before_trusted_repair")
    require(observed == damaged, "corrupt HEAD changed before fixture repair")
    value(repairer.call("store_put", key=case["head_key"], bytes=before["bytes"], etag=observed["etag"]))
    suite.event(case, "trusted_original_head_restored", original_head_sha256=sha(bytes(before["bytes"])),
                product_repair_api=False, no_immutable_object_overwritten=True)
    suite.stop(case, repairer)
    recovered = suite.spawn(case, logical_worker=logical_owner)
    value(recovered.call("activate_session", revision=taken["revision"], nonce=802, directory="repaired"))
    suite.audit(case, recovered, current, session_open=True)
    suite.passed(case, epoch_kind=epoch_kind, damage=damage, entrypoints=list(PROBES),
                 original_result_and_data_audited=True)


def check_final(suite):
    results = suite.summary["case_results"]
    require(len(results) == len(SCENARIOS) and {row["case"] for row in results} == set(SCENARIOS), "incomplete semantic scenario inventory")
    require(all(row["status"] == "passed" and row["entrypoints"] == list(PROBES) for row in results), "incomplete entrypoint checks")
    records = [load_json(line) for line in suite.acks.read_text().splitlines()]
    require([row["ordinal"] for row in records] == list(range(1, 31)), "all 30 fixture execute ACKs must remain")
    require(suite.audited == set(range(1, 31)), "not every original ACK was audited")
    require(suite.summary["ack_mismatch_count"] == suite.summary["outcome_mismatch_count"] == 0, "an original result changed")
    require(not suite.proxy.errors, "proxy errors make the scenario inconclusive")


def finish_json(path, result):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", type=Path, required=True)
    parser.add_argument("--weed", type=Path, required=True)
    parser.add_argument("--build-record", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    arguments = parser.parse_args(argv)
    evidence = arguments.evidence.resolve()
    evidence.mkdir(parents=True, mode=0o700, exist_ok=False)
    summary = {"status": "blocked", "scope": "private-loopback-real-S3-and-Rust-worker",
               "production_slo_passed": False, "planned_scenarios": list(SCENARIOS),
               "planned_probes_per_scenario": list(PROBES), "real_worker_started": False,
               "aws_standard": "NOT_RUN", "native_unit_coverage": "separate_required_gate"}
    backend = proxy = suite = None
    workers = []
    cleanup = []
    try:
        require(not sys.flags.optimize, "fixture assertions must be enabled")
        require("LLVM_PROFILE_FILE" not in os.environ, "integration cannot contribute unit coverage")
        for name in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"):
            require("instrument-coverage" not in os.environ.get(name, ""), "integration cannot inherit instrumentation")
        for path in (arguments.worker, arguments.weed, arguments.build_record):
            require(path.is_file(), "missing prerequisite: " + str(path))
        import build
        import run as support
        compiled = build.capture_receipt(arguments.build_record, arguments.worker, evidence)
        summary.update(worker_sha256=compiled["binary"]["sha256"], build_inputs_sha256=compiled["input_sha256"],
                       source_commit=compiled["source_commit"], harness_sha256=sha(Path(__file__).read_bytes()))
        private = Path(tempfile.mkdtemp(prefix="scap-result-integrity-private-"))
        compute = private / "compute"
        compute.mkdir(mode=0o700)
        backend = support.Backend(arguments.weed.resolve(), private / "backend")
        proxy = support.Proxy(backend.port, evidence)
        proxy.capture = True
        config = {"endpoint": proxy.endpoint, "region": "us-east-1", "bucket": "scap-test",
                  "access_key": backend.access, "secret_key": backend.secret, "worker": 1,
                  "principal": 17, "cache_root": str(compute),
                  "scope": {"deployment": 79, "tenant": 88, "database": 1, "incarnation": 1, "generation": 1}}
        suite = support.FaultSuite(arguments, evidence, private, compute, backend, proxy, workers, config)
        backend.start()
        summary["status"] = "running"
        for epoch in ("current", "closed"):
            for damage in MUTATIONS:
                run_case(suite, epoch, damage)
        check_final(suite)
        build.verify(arguments.build_record, arguments.worker)
        summary.update(status="passed", real_worker_started=True,
                       case_results=suite.summary["case_results"], verified_entrypoint_checks=len(SCENARIOS) * len(PROBES),
                       ack_recorded_count=suite.ack_number, ack_audited_count=len(suite.audited),
                       ack_mismatch_count=0, outcome_mismatch_count=0)
    except BaseException as error:
        summary.update(status="blocked" if summary["status"] == "blocked" else "failed",
                       error_type=type(error).__name__, error=str(error))
    finally:
        if proxy is not None:
            try:
                proxy.clear()
            except BaseException as error:
                cleanup.append({"phase": "release_proxy", "error_type": type(error).__name__})
        for worker in list(workers):
            try:
                worker.kill()
            except BaseException as error:
                cleanup.append({"phase": "stop_worker", "error_type": type(error).__name__})
        for phase, item, method in (("close_proxy", proxy, "close"), ("stop_backend", backend, "stop")):
            if item is not None:
                try:
                    getattr(item, method)()
                except BaseException as error:
                    cleanup.append({"phase": phase, "error_type": type(error).__name__})
        if proxy is not None and proxy.errors:
            cleanup.append({"phase": "proxy_errors", "count": len(proxy.errors)})
        if suite is not None:
            summary.update(real_worker_started=suite.number > 100, ack_recorded_count=suite.ack_number,
                           ack_audited_count=len(suite.audited), case_results=suite.summary["case_results"])
        summary["cleanup_errors"] = cleanup
        if cleanup:
            summary["status"] = "failed"
        summary["artifacts"] = {p.name: sha(p.read_bytes()) for p in sorted(evidence.iterdir()) if p.is_file()}
        finish_json(evidence / "summary.json", summary)
    print(json.dumps({"status": summary["status"], "evidence": str(evidence)}))
    return 0 if summary["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
