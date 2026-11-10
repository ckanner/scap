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


if __name__ == "__main__": unittest.main()
