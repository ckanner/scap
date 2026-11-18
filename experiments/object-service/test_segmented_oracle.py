"""Synthetic strict-codec/oracle controls; these are not real S3 evidence."""
import copy
import json
from pathlib import Path
import struct
import tempfile
import unittest

import segmented_oracle as oracle
from segmented_spec import CALLS, DEADLINES, PHASES, PLAN, SCOPE
from segmented_tree_audit import HEAD, PREFIX, SCOPE as NATIVE_SCOPE, Trees, envelope, head, sha


def frame(kind, value, raw=b""):
    encoded = json.dumps({"format": 2, "scope": NATIVE_SCOPE, "payload": {"kind": kind, "value": value}}, separators=(",", ":")).encode()
    raw = b"SCAPOBJ2" + struct.pack("<IQ", len(encoded), len(raw)) + encoded + raw
    return PREFIX + sha(raw), raw


def cancelled(identifier):
    return {"request": {"epoch": 1, "id": identifier, "principal": 11, "fingerprint": "a"*64},
            "outcome": {"state": "cancelled", "transition": {"revision": identifier + 2, "nonce": identifier}}, "result_bytes": 0}


def two_leaves():
    objects, children = {}, []
    for first in (1, 65):
        key, raw = frame("index", {"kind": "leaf", "epoch": 1, "entries": [cancelled(i) for i in range(first, first + 64)]})
        objects[key] = raw
        children.append({"hash": key[len(PREFIX):], "summary": {"first": first, "last": first + 63, "count": 64, "result_bytes": 0}})
    node = {"kind": "branch", "epoch": 1, "level": 1, "children": children}
    key, raw = frame("index", node); objects[key] = raw
    window = {"epoch": 1, "root": key[len(PREFIX):], "count": 128, "result_bytes": 0}
    return objects, node, window


def replace_root(objects, node, window):
    key, raw = frame("index", node); objects[key] = raw; window["root"] = key[len(PREFIX):]


class SegmentedTreeControls(unittest.TestCase):
    def test_all_original_cancelled_entries_and_child_dependencies_are_walked(self):
        objects, _, window = two_leaves()
        proof = Trees(objects).index(window, {"sequence": 1, "revision": 130})
        self.assertEqual(proof["entries"], tuple(cancelled(i) for i in range(1, 129)))
        self.assertEqual(len(proof["dependencies"]), 3)
        self.assertEqual(proof["level"], 1)

    def test_non_target_missing_and_corrupt_children_cannot_be_skipped(self):
        for damage in ("missing", "magic", "hash"):
            with self.subTest(damage=damage):
                objects, root, window = two_leaves(); key = PREFIX + root["children"][-1]["hash"]
                if damage == "missing": del objects[key]
                else:
                    raw = bytearray(objects[key]); raw[0 if damage == "magic" else -1] ^= 1; objects[key] = bytes(raw)
                with self.assertRaises((ValueError, KeyError)): Trees(objects).index(window, {"sequence": 1, "revision": 130})

    def test_false_parent_summaries_overlap_duplicate_child_and_level_are_rejected(self):
        for damage in ("count", "bytes", "first", "last", "overlap", "repeat", "level", "flat", "epoch", "extra"):
            with self.subTest(damage=damage):
                objects, root, window = two_leaves()
                if damage == "count": root["children"][0]["summary"]["count"] += 1
                elif damage == "bytes": root["children"][0]["summary"]["result_bytes"] = 1
                elif damage == "first": root["children"][0]["summary"]["first"] = 2
                elif damage == "last": root["children"][0]["summary"]["last"] = 65
                elif damage == "overlap": root["children"][1]["summary"]["first"] = 64
                elif damage == "repeat": root["children"][1]["hash"] = root["children"][0]["hash"]
                elif damage == "level": root["level"] = 2
                elif damage == "flat": root = [cancelled(1)]
                elif damage == "epoch": root["epoch"] = 2
                elif damage == "extra": root["children"][0]["summary"]["ignored"] = True
                replace_root(objects, root, window)
                with self.assertRaises((ValueError, TypeError)): Trees(objects).index(window, {"sequence": 1, "revision": 130})

    def test_cancel_bytes_epoch_identity_order_underfull_and_local_bounds(self):
        for damage in ("bytes", "epoch", "duplicate", "zero_id", "principal", "underfull", "overflow", "unknown", "future"):
            with self.subTest(damage=damage):
                objects, root, window = two_leaves(); key = PREFIX + root["children"][1]["hash"]
                _, leaf, _ = envelope(objects[key], key); leaf = copy.deepcopy(leaf)
                if damage == "bytes": leaf["entries"][0]["result_bytes"] = 1
                elif damage == "epoch": leaf["entries"][0]["request"]["epoch"] = 2
                elif damage == "duplicate": leaf["entries"][1]["request"]["id"] = 65
                elif damage == "zero_id": leaf["entries"][0]["request"]["id"] = 0
                elif damage == "principal": leaf["entries"][0]["request"]["principal"] = 0
                elif damage == "underfull": leaf["entries"].pop()
                elif damage == "overflow": leaf["entries"] += [cancelled(i) for i in range(129, 194)]
                elif damage == "unknown": leaf["entries"][0]["outcome"]["state"] = "unknown"
                else: leaf["entries"][0]["outcome"]["transition"]["revision"] = 1000
                key, raw = frame("index", leaf); objects[key] = raw; root["children"][1]["hash"] = key[len(PREFIX):]
                replace_root(objects, root, window)
                with self.assertRaises(ValueError): Trees(objects).index(window, {"sequence": 1, "revision": 130})

    def test_actual_result_bytes_full_identity_and_sequence_are_checked(self):
        raw_result = b"SCAPRES1" + struct.pack("<I", 0)
        base_request = cancelled(1)["request"]
        stored = {"request": base_request, "sequence": 1, "transition": {"revision": 3, "nonce": 1}, "data_root": "b"*64, "bytes": []}
        for damage in (None, "length", "request", "sequence", "transition", "raw", "missing"):
            with self.subTest(damage=damage):
                objects = {}; value = copy.deepcopy(stored); raw = raw_result
                if damage == "request": value["request"]["principal"] = 12
                elif damage == "sequence": value["sequence"] = 2
                elif damage == "transition": value["transition"]["nonce"] = 2
                elif damage == "raw": raw = b"garbage"
                key, encoded = frame("result", value, raw); objects[key] = encoded
                entry = {"request": base_request, "outcome": {"state": "committed", "result": key[len(PREFIX):]}, "result_bytes": len(raw) + (damage == "length")}
                if damage == "missing": objects.clear()
                key, encoded = frame("index", {"kind": "leaf", "epoch": 1, "entries": [entry]}); objects[key] = encoded
                window = {"epoch": 1, "root": key[len(PREFIX):], "count": 1, "result_bytes": entry["result_bytes"]}
                if damage is None: self.assertEqual(Trees(objects).index(window, {"sequence": 1, "revision": 3})["summary"]["count"], 1)
                else:
                    with self.assertRaises(ValueError): Trees(objects).index(window, {"sequence": 1, "revision": 3})

    def test_strict_head_six_rejects_legacy_unknown_and_false_counters(self):
        value = {"format": 6, "head_serial": 1, "storage": {"active_generation": 1, "allocated_through": 1, "plan": None, "sweep": None},
                 "scope": NATIVE_SCOPE, "revision": 1, "transition": {"revision": 1, "nonce": 1}, "sequence": 0,
                 "owner_epoch": 1, "owner_instance": 8871, "active": False, "auth_epoch": 1,
                 "policy": [{"principal": 11, "read": True, "write": True, "admin": True}], "lifecycle": "ready", "creation": None, "deletion": None,
                 "data_root": "a"*64, "quota": {"max_bytes": None}, "retention": {"max_entries": 4096, "max_result_bytes": 2**28},
                 "request_epoch": 1, "windows": [{"epoch": 1, "root": "b"*64, "count": 0, "result_bytes": 0}]}
        self.assertEqual(head(json.dumps(value)), value)
        for damage in ("old", "future", "bool", "extra", "bytes", "epoch", "scope"):
            modified = copy.deepcopy(value)
            if damage in ("old", "future", "bool"): modified["format"] = {"old": 5, "future": 7, "bool": True}[damage]
            elif damage == "extra": modified["ignored"] = True
            elif damage == "bytes": modified["windows"][0]["result_bytes"] = 1
            elif damage == "epoch": modified["windows"][0]["epoch"] = 2
            else: modified["scope"]["generation"] = 2
            with self.subTest(damage=damage), self.assertRaises(ValueError): head(json.dumps(modified))


class SegmentedCallControls(unittest.TestCase):
    def test_frozen_invocation_denominator_has_no_retry_or_omitted_label(self):
        self.assertEqual(PLAN["http_invocations"], 2145)
        calls, ledger, phases, moment = {}, [], [], 1_000_000
        for phase in PHASES:
            for ordinal, (label, operation) in enumerate(CALLS[phase], 1):
                call_id = f"{phase}:123:{ordinal}"; code = "ok"
                if label == "conflict": code = "REQUEST_CONFLICT"
                if phase in ("corrupt", "missing", "summary") and operation in ("open", "query"):
                    code = "MISSING" if phase == "missing" else "CORRUPT"
                value = {"ok": True, "value": {}} if code == "ok" else {"ok": False, "error": {"code": code, "message": code}}
                calls[call_id] = {"request": {"call_id": call_id, "phase": phase, "client": "index", "monotonic_ns": moment + 1},
                                  "response": {"status": 200 if code == "ok" else 409, "monotonic_ns": moment + 2},
                                  "body": {"scope": SCOPE, "operation": operation}, "value": value}
                ledger += [{"phase": phase, "event": "call_started", "label": label, "operation": operation, "monotonic_ns": moment},
                           {"phase": phase, "event": "call_finished", "label": label, "call_id": call_id, "outcome": code, "monotonic_ns": moment + 3}]
                moment += 100
            phases.append({"phase": phase, "calls": len(CALLS[phase]), "sdk_http_attempts": len(CALLS[phase])})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            def save():
                for name, values in (("segmented-calls.jsonl", ledger), ("segmented-phases.jsonl", phases)):
                    (path / name).write_text("".join(json.dumps(row) + "\n" for row in values))
            save(); self.assertEqual(len(oracle.labeled(path, calls)), 2145)
            phases[0]["sdk_http_attempts"] += 1; save()
            with self.assertRaises(ValueError): oracle.labeled(path, calls)
            phases[0]["sdk_http_attempts"] -= 1; ledger.pop(); save()
            with self.assertRaises(ValueError): oracle.labeled(path, calls)


class SegmentedStartupControls(unittest.TestCase):
    """The startup adapter must audit each exchange before subtracting it."""

    def fixture(self, directory):
        bodies = directory / "s3-bodies"
        bodies.mkdir()
        (bodies / sha(b"")).write_bytes(b"")
        access = sha(b"fixture-access")
        facts = [{"event": "backend_started", "access_key_sha256": access}]
        history = []
        for ordinal, worker in enumerate(PLAN["worker_instances"], 1):
            moment = ordinal * 1000
            identity = {"pid": ordinal + 100, "spawn_monotonic_ns": moment,
                        "pid_source": "owned_Popen_child"}
            facts.extend([{"event": "service_started", "owner_instance": worker, "identity": identity,
                           "spawn_requested_ns": moment - 1, "monotonic_ns": moment + 1},
                          {"event": "service_ready", "owner_instance": worker, "identity": identity,
                           "monotonic_ns": moment + 80}])
            value = b"SCAP-WORKER-INSTANCE-v1\0" + worker.to_bytes(8, "big")
            (bodies / sha(value)).write_bytes(value)
            for operation, method in enumerate(("PUT", "GET")):
                sent, received = (value, b"") if method == "PUT" else (b"", value)
                common = {"schema": 1, "request_serial": ordinal * 2 - 1 + operation,
                          "phase": "bootstrap", "method": method,
                          "path": "/scap-test/scap-worker/v1/instances/" + str(worker),
                          "request_bytes": len(sent), "request_sha256": sha(sent),
                          "if_match": None, "if_none_match": "*" if method == "PUT" else None,
                          "signing": {"algorithm": "AWS4-HMAC-SHA256", "access_key_sha256": access,
                                      "credential_scope": "20261118/us-east-1/s3/aws4_request",
                                      "date": "20261118T000000Z", "signature_sha256": "a" * 64,
                                      "signed_headers": ["host", "x-amz-content-sha256", "x-amz-date"],
                                      "host": "127.0.0.1:8123", "payload_sha256": sha(sent)}}
                for offset, event in enumerate(("object_request", "object_forwarded", "object_response", "object_response_delivered")):
                    row = {**copy.deepcopy(common), "event": event,
                           "monotonic_ns": moment + 10 + operation * 40 + offset * 5}
                    if offset >= 2:
                        row.update(status=200, response_origin="backend", response_bytes=len(received),
                                   response_sha256=sha(received), etag='"claim-' + str(worker) + '"')
                    history.append(row)
        phases = ["seed", "warm", "inspection", "cold"]
        for damage in PLAN["damage_cases"]:
            phases += ["damage_" + damage, damage, "repair_" + damage]
        phases += ["repaired"]
        history.extend({"schema": 1, "event": "phase_started", "phase": phase,
                        "monotonic_ns": 10000 + ordinal} for ordinal, phase in enumerate(phases))
        self.renumber(history)
        return history, facts, {"s3": {"endpoint": "http://127.0.0.1:8123"}}

    @staticmethod
    def renumber(history):
        history.sort(key=lambda row: row["monotonic_ns"])
        serials = {row["request_serial"]: index for index, row in enumerate(
            (row for row in history if row["event"] == "object_request"), 1)}
        for index, row in enumerate(history, 1):
            row["sequence"] = index
            if "request_serial" in row:
                row["request_serial"] = serials[row["request_serial"]]

    def test_exact_owned_pairs_are_separate_and_late_callbacks_are_legal(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            history, facts, config = self.fixture(directory)
            # Delivery completion is a logging callback, not the cross-thread
            # causal boundary. Backend responses still precede GET and ready.
            for row in history:
                if row.get("request_serial") == 1 and row["event"] == "object_response_delivered":
                    row["monotonic_ns"] = 1051
                if row.get("request_serial") == 2 and row["event"] == "object_response_delivered":
                    row["monotonic_ns"] = 1081
            self.renumber(history)
            ordered, by_call, fixture, objects, claimed = oracle.original_network(directory, history, {}, facts, config)
            self.assertEqual((ordered, dict(by_call), fixture, objects), ([], {}, {}, {}))
            self.assertEqual(claimed, 2 * PLAN["service_processes"])

    def test_unowned_incomplete_ambiguous_or_changed_claims_are_rejected(self):
        for damage in ("duplicate_worker", "missing_readback", "missing_delivery", "unknown_path", "unconditional",
                       "different_etag", "wrong_marker", "early_ready", "different_signature", "extra_readback"):
            with self.subTest(damage=damage), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                history, facts, config = self.fixture(directory)
                if damage == "duplicate_worker":
                    for row in facts:
                        if row.get("owner_instance") == PLAN["worker_instances"][1]:
                            row["owner_instance"] = PLAN["worker_instances"][0]
                elif damage in ("missing_readback", "missing_delivery"):
                    history[:] = [row for row in history if not (row.get("request_serial") == 2 and
                                  (damage == "missing_readback" or row["event"] == "object_response_delivered"))]
                elif damage == "early_ready":
                    facts[2]["monotonic_ns"] = 1059
                elif damage == "extra_readback":
                    for row in list(history):
                        if row.get("request_serial") == 2:
                            duplicate = copy.deepcopy(row)
                            duplicate.update(request_serial=100, monotonic_ns=row["monotonic_ns"] + 1)
                            history.append(duplicate)
                else:
                    replacement = b"SCAP-WORKER-INSTANCE-v1\0" + (9999).to_bytes(8, "big")
                    (directory / "s3-bodies" / sha(replacement)).write_bytes(replacement)
                    for row in history:
                        serial = row.get("request_serial")
                        if serial not in (1, 2):
                            continue
                        if damage == "unknown_path": row["path"] += "/extra"
                        elif damage == "unconditional" and serial == 1: row["if_none_match"] = None
                        elif damage == "different_etag" and serial == 2 and "etag" in row: row["etag"] = '"other"'
                        elif damage == "different_signature": row["signing"]["access_key_sha256"] = "b" * 64
                        elif damage == "wrong_marker":
                            if serial == 1:
                                row["request_sha256"] = row["signing"]["payload_sha256"] = sha(replacement)
                            elif "response_sha256" in row: row["response_sha256"] = sha(replacement)
                self.renumber(history)
                with self.assertRaises(ValueError):
                    oracle.original_network(directory, history, {}, facts, config)


if __name__ == "__main__": unittest.main()
