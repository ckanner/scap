"""Synthetic verifier controls; these tests do not execute SQLite/HTTP/S3."""
from __future__ import annotations

import base64
import copy
from email.message import Message
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest

import isolation_oracle as oracle
import isolation_controls as controls
from isolation_proxy import signing
from isolation_spec import CALLS, PHASES, SCOPES


def frame(kind, value, raw=b"", database=101):
    metadata = {"format": 2, "scope": {"deployment": 1, "tenant": 7, "database": database, "incarnation": 1, "generation": 1},
                "payload": {"kind": kind, "value": value}}
    encoded = json.dumps(metadata, separators=(",", ":")).encode()
    data = b"SCAPOBJ2" + struct.pack("<IQ", len(encoded), len(raw)) + encoded + raw
    return "/scap-test/scap-object/v1/1/7/101/inc/1/gen/1/storage/1/objects/" + hashlib.sha256(data).hexdigest(), data


def synthetic_tree():
    objects, children = {}, []
    for index in range(4):
        raw = bytearray(32 * 4096)
        if index == 0:
            raw[:18] = b"SQLite format 3\0\x10\0"
        key, body = frame("chunk", {"first_page": index*32+1, "bytes": []}, bytes(raw))
        objects[key] = body
        children.append(key.rsplit("/", 1)[1])
    key, body = frame("node", {"level": 0, "first_chunk": 0, "children": children})
    objects[key] = body
    key, body = frame("manifest", {"page_count": 128, "root": key.rsplit("/", 1)[1]})
    objects[key] = body
    return objects, key.rsplit("/", 1)[0] + "/", key.rsplit("/", 1)[1]


def synthetic_calls():
    calls, ledger, phases, now = {}, [], [], 1000000
    for phase in PHASES:
        for index, (label, name, operation) in enumerate(CALLS[phase], 1):
            call_id = f"{phase}:123:{index}"
            base = {"schema": 1, "phase": phase}
            ledger.append({**base, "event": "call_started", "monotonic_ns": str(now), "label": label, "name": name, "operation": operation})
            response = {"ok": True, "value": {}}
            if label == "c_at_capacity":
                response = {"ok": False, "error": {"code": "BACKPRESSURE", "message": "BACKPRESSURE"}}
            calls[call_id] = {"request": {**base, "client": name, "call_id": call_id, "monotonic_ns": str(now+1)},
                              "body": {"scope": SCOPES[name], "operation": operation},
                              "response": {"monotonic_ns": str(now+2), "status": 200 if response["ok"] else 429},
                              "value": response}
            ledger.append({**base, "event": "call_finished", "monotonic_ns": str(now+3), "label": label,
                           "call_id": call_id, "outcome": "ok" if response["ok"] else "BACKPRESSURE"})
            now += 1000000
        phases.append({"phase": phase, "calls": len(CALLS[phase]), "sdk_http_attempts": len(CALLS[phase])})
    return calls, ledger, phases


class IsolationWireControls(unittest.TestCase):
    def test_numbered_trace_accepts_original_order(self):
        oracle.numbered([{"schema": 1, "sequence": 1, "monotonic_ns": 10}, {"schema": 1, "sequence": 2, "monotonic_ns": 11}])

    def test_numbered_trace_rejects_gaps_reorder_and_boolean_schema(self):
        for rows in ([{"schema": 1, "sequence": 2, "monotonic_ns": 10}],
                     [{"schema": True, "sequence": 1, "monotonic_ns": 10}],
                     [{"schema": 1, "sequence": 1, "monotonic_ns": 11}, {"schema": 1, "sequence": 2, "monotonic_ns": 10}]):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                oracle.numbered(rows)

    def test_original_object_frame(self):
        key, data = frame("chunk", {"first_page": 1, "bytes": []}, b"raw")
        self.assertEqual(oracle.envelope(data, key), ({"kind": "chunk", "value": {"first_page": 1, "bytes": []}}, b"raw"))

    def test_frame_rejects_hash_length_and_scope_mismatch(self):
        key, data = frame("chunk", {"first_page": 1, "bytes": []}, b"raw")
        wrong = data[:12] + struct.pack("<Q", 99) + data[20:]
        other_key, other = frame("chunk", {"first_page": 1, "bytes": []}, b"raw", database=202)
        for actual, path in ((data[:-1]+b"x", key), (wrong, key.rsplit("/", 1)[0]+"/"+hashlib.sha256(wrong).hexdigest()), (other, other_key)):
            with self.subTest(path=path), self.assertRaises(ValueError):
                oracle.envelope(actual, path)

    def test_tree_reconstructs_all_four_chunks(self):
        objects, prefix, root = synthetic_tree()
        keys, first, size, chunks = oracle.tree(objects, prefix, root)
        self.assertEqual((len(keys), size, chunks), (6, 128*4096, 4))
        self.assertEqual(oracle.envelope(objects[first], first)[0]["value"]["first_page"], 1)

    def test_tree_rejects_incomplete_original_extent(self):
        objects, prefix, root = synthetic_tree()
        payload, _ = oracle.envelope(objects[prefix+root], prefix+root)
        key, body = frame("manifest", {"page_count": 127, "root": payload["value"]["root"]})
        objects[key] = body
        with self.assertRaisesRegex(ValueError, "extent"):
            oracle.tree(objects, prefix, key.rsplit("/", 1)[1])

    def test_tree_rejects_wrong_typed_root(self):
        objects, prefix, _ = synthetic_tree()
        root = next(iter(objects)).rsplit("/", 1)[1]
        with self.assertRaisesRegex(ValueError, "typed"):
            oracle.tree(objects, prefix, root)

    def test_window_requires_both_original_boundaries(self):
        call = {"request": {"monotonic_ns": "10"}, "response": {"monotonic_ns": "20"}}
        self.assertTrue(oracle.window(call, 15))
        for value in (9, 10, 20, 21):
            self.assertFalse(oracle.window(call, value))

    def test_child_can_announce_before_parent_identity_or_logger(self):
        child = {"spawn_requested_ns": 10, "identity": {"spawn_monotonic_ns": 30}, "monotonic_ns": 50}
        oracle.client_hello(child, {"pid_source": "node_process.pid", "self_pid": 123, "monotonic_ns": 20}, {"monotonic_ns": 100})

    def test_child_cannot_announce_before_launch_or_after_exit(self):
        child = {"spawn_requested_ns": 10}
        for when in (9, 10, 100, 101):
            with self.subTest(when=when), self.assertRaisesRegex(ValueError, "lifetime"):
                oracle.client_hello(child, {"pid_source": "node_process.pid", "self_pid": 123, "monotonic_ns": when}, {"monotonic_ns": 100})

    def headers(self, names="host;x-amz-content-sha256;x-amz-date"):
        headers = Message()
        headers["Authorization"] = "AWS4-HMAC-SHA256 Credential=secret-id/20261108/us-east-1/s3/aws4_request, SignedHeaders="+names+", Signature="+"a"*64
        headers["Host"], headers["X-Amz-Date"], headers["X-Amz-Content-Sha256"] = "127.0.0.1:123", "20261108T000000Z", "b"*64
        return headers

    def test_signature_capture_never_keeps_authorization_or_access_bytes(self):
        value = signing(self.headers())
        self.assertEqual(value["access_key_sha256"], hashlib.sha256(b"secret-id").hexdigest())
        self.assertNotIn("secret-id", json.dumps(value))
        self.assertNotIn("a"*64, json.dumps(value))

    def test_signature_rejects_unsigned_unsorted_and_incomplete_headers(self):
        for headers in (Message(), self.headers("x-amz-date;host;x-amz-content-sha256"), self.headers("host;x-amz-date")):
            with self.subTest(headers=headers), self.assertRaises(ValueError):
                signing(headers)


class IsolationCallControls(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.calls, self.ledger, self.phases = synthetic_calls()

    def tearDown(self):
        self.directory.cleanup()

    def audit(self):
        for name, rows in (("isolation-calls.jsonl", self.ledger), ("isolation-phases.jsonl", self.phases)):
            (self.root/name).write_text("".join(json.dumps(row)+"\n" for row in rows))
        return oracle.labeled_calls(self.root, self.calls)

    def test_all_twenty_one_invocations_are_accounted(self):
        self.assertEqual(len(self.audit()), 21)

    def test_rejects_omitted_call_even_if_success_counter_is_smaller(self):
        self.ledger = [row for row in self.ledger if row["label"] != "b_keep_5"]
        with self.assertRaisesRegex(ValueError, "denominator"):
            self.audit()

    def test_rejects_extra_retry(self):
        self.calls["unaccounted"] = copy.deepcopy(next(iter(self.calls.values())))
        with self.assertRaisesRegex(ValueError, "invocation"):
            self.audit()

    def test_rejects_result_from_another_scope(self):
        self.calls["cold_a:123:1"]["body"]["scope"] = SCOPES["b"]
        with self.assertRaisesRegex(ValueError, "database"):
            self.audit()

    def test_rejects_wrong_operation(self):
        self.calls["cold_a:123:1"]["body"]["operation"] = "status"
        with self.assertRaisesRegex(ValueError, "operation"):
            self.audit()

    def test_rejects_controller_relabeling_prior_phase_response(self):
        final = next(row for row in self.ledger if row["label"] == "a_cold_open" and row["event"] == "call_finished")
        final["call_id"] = "seed:123:1"
        with self.assertRaisesRegex(ValueError, "client"):
            self.audit()

    def test_rejects_failure_presented_as_capacity_refusal(self):
        self.calls["during_cold:123:2"]["value"]["error"]["code"] = "UNKNOWN"
        with self.assertRaisesRegex(ValueError, "typed HTTP"):
            self.audit()

    def test_rejects_result_at_invocation_boundary(self):
        self.calls["cold_a:123:1"]["response"]["monotonic_ns"] = self.calls["cold_a:123:1"]["request"]["monotonic_ns"]
        with self.assertRaisesRegex(ValueError, "interval"):
            self.audit()

    def test_rejects_http_retry_counter_hiding(self):
        self.phases[0]["sdk_http_attempts"] += 1
        with self.assertRaisesRegex(ValueError, "retried"):
            self.audit()

    def test_capacity_corruption_needs_no_original_missing_key_get(self):
        call_id = "during_cold:123:2"
        def save(name, rows):
            (self.root/name).write_text("".join(json.dumps(row)+"\n" for row in rows))
        save("isolation-calls.jsonl", [{"event": "call_finished", "label": "c_at_capacity", "call_id": call_id}])
        save("http-client-ledger.jsonl", [{"event": "http_request", "call_id": call_id, "phase": "during_cold", "monotonic_ns": "1000"},
                                           {"event": "http_response", "call_id": call_id, "monotonic_ns": "2000"}])
        wire = []
        for index, event in enumerate(("object_request", "object_forwarded", "object_response", "object_response_delivered")):
            row = {"event": event, "request_serial": 1, "sequence": index+1, "monotonic_ns": 10+index,
                   "method": "GET", "path": "/scap-test/scap-object/v1/1/7/101/head", "phase": "seed"}
            if "response" in event:
                row.update(status=200, response_body="e30=", response_bytes=2, head_response_bytes=[123, 125], etag="old")
            wire.append(row)
        save("history.jsonl", wire)
        controls.additional_get(self.root, "c_at_capacity", "c", missing=True)
        changed = oracle.rows(self.root, "history.jsonl")
        self.assertEqual(len(changed), 8)
        self.assertEqual([row["status"] for row in changed if row["event"] == "object_response"], [200, 404])
        injected = next(row for row in changed if row["event"] == "object_response" and row["request_serial"] == 2)
        self.assertEqual((injected["path"], injected["response_body"], injected["head_response_bytes"]),
                         ("/scap-test/scap-object/v1/1/7/303/head", "", []))


if __name__ == "__main__":
    unittest.main()
