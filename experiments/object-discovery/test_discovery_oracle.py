"""Handwritten audit behavior controls, never real S3/native acceptance."""
from __future__ import annotations

import copy
from email.message import Message
import hashlib
import hmac
import json
from pathlib import Path
import sqlite3
import struct
import tempfile
import unittest
from urllib.parse import quote

from deployment_recovery_imports import local

oracle = local("discovery_oracle")
catalogue = local("discovery_audit_sources").catalogue
Metadata = local("discovery_metadata_audit").Metadata
signature = local("discovery_proxy").signature
tree = local("discovery_tree_audit")
Trees, envelope, head, object_prefix = tree.Trees, tree.envelope, tree.head, tree.object_prefix


def raw(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def authority(scope=None):
    return {"format": 5, "head_serial": 3, "storage": {"active_generation": 1, "allocated_through": 1}, "scope": scope or {"deployment": 7, "tenant": 2, "database": 13, "incarnation": 1, "generation": 1},
            "revision": 3, "transition": {"revision": 3, "nonce": 1}, "sequence": 1, "owner_epoch": 1,
            "owner_instance": 42, "active": True, "auth_epoch": 1,
            "policy": [{"principal": 17, "read": True, "write": True, "admin": True}], "lifecycle": "ready",
            "creation": None, "deletion": None, "data_root": "a" * 64, "quota": {"max_bytes": 8 * 1024 * 1024},
            "retention": {"max_entries": 4, "max_result_bytes": 128 * 1024 * 1024}, "request_epoch": 1,
            "windows": [{"epoch": 1, "root": "b" * 64, "count": 0, "result_bytes": 0}]}


def frame(authority, kind, value, body=b""):
    metadata = raw({"format": 2, "scope": authority["scope"], "payload": {"kind": kind, "value": value}})
    encoded = b"SCAPOBJ2" + struct.pack("<IQ", len(metadata), len(body)) + metadata + body
    return object_prefix(authority) + oracle.sha(encoded), encoded


class OriginalInputsAndAuthentication(unittest.TestCase):
    def signed(self):
        request = {"method": "PUT", "path": "/scap-test/scap-object/v1/7/2/13/head", "if_none_match": "*", "if_match": None}
        payload = b"original conditional bytes"
        values = {"host": "127.0.0.1:14444", "if-none-match": "*", "x-amz-content-sha256": oracle.sha(payload), "x-amz-date": "20261108T100000Z"}
        names = sorted(values); scope = "20261108/us-east-1/s3/aws4_request"
        canonical = "\n".join((request["method"], request["path"], "", "".join(k + ":" + values[k] + "\n" for k in names),
                               ";".join(names), oracle.sha(payload)))
        signing_key = b"AWS4unit-secret"
        for part in scope.split("/"):
            signing_key = hmac.new(signing_key, part.encode(), hashlib.sha256).digest()
        string_to_sign = "AWS4-HMAC-SHA256\n20261108T100000Z\n" + scope + "\n" + oracle.sha(canonical.encode())
        mac = hmac.new(signing_key, string_to_sign.encode(), hashlib.sha256).hexdigest()
        headers = Message()
        for name, value in values.items(): headers[name] = value
        headers["Authorization"] = f"AWS4-HMAC-SHA256 Credential=unit-access/{scope}, SignedHeaders={';'.join(names)}, Signature={mac}"
        request["signing"] = signature("PUT", request["path"], headers, payload, "unit-access", "unit-secret")
        return request, payload, {oracle.sha(b"unit-access"): ("unit-access", "unit-secret")}

    def test_original_mac_is_recomputed_for_method_path_body_condition_and_headers(self):
        request, payload, keys = self.signed()
        oracle.authenticated(request, payload, set(keys), keys, full=True)
        for fault in ("path", "method", "body", "condition", "header", "signature", "scope", "missing_header", "boolean"):
            modified, changed = copy.deepcopy(request), payload
            if fault == "path": modified["path"] = modified["path"].replace("/13/", "/14/")
            elif fault == "method": modified["method"] = "GET"
            elif fault == "body": changed += b"!"
            elif fault == "condition": modified["if_none_match"] = None
            elif fault == "header":
                modified["signing"]["host"] = "127.0.0.1:15555"
                modified["signing"]["signed_header_values"]["host"] = "127.0.0.1:15555"
            elif fault == "signature": modified["signing"]["signature_sha256"] = "0" * 64
            elif fault == "scope": modified["signing"]["credential_scope"] = "20261107/us-east-1/s3/aws4_request"
            elif fault == "missing_header": del modified["signing"]["signed_header_values"]["if-none-match"]
            else: modified["signing"]["verified_at_relay"] = 1
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                oracle.authenticated(modified, changed, set(keys), keys, full=True)

    def test_missing_signing_key_is_only_allowed_in_explicit_partial_scope(self):
        request, payload, keys = self.signed()
        with self.assertRaisesRegex(ValueError, "credential bytes unavailable"):
            oracle.authenticated(request, payload, set(keys), {}, full=True)
        oracle.authenticated(request, payload, set(keys), {}, full=False)

    def test_every_invocation_has_one_original_terminal_and_no_sequence_gaps(self):
        rows = [{"schema": 1, "sequence": 1, "event": "invoked", "monotonic_ns": 10, "call_id": 1, "label": "a"},
                {"schema": 1, "sequence": 2, "event": "lost_with_process", "monotonic_ns": 20, "call_id": 1}]
        self.assertEqual(len(oracle.calls(rows)[0]), 1)
        for changed in (rows[:1], rows + [rows[1]], [dict(rows[0], call_id=2), rows[1]],
                        [rows[0], dict(rows[1], event="unknown")], [dict(rows[0], sequence=2), rows[1]]):
            with self.assertRaises(ValueError): oracle.calls(changed)

    def test_new_ack_dependency_requires_durable_complete_readback_before_head(self):
        upload = {"monotonic_ns": 20, "call_id": 1, "method": "PUT", "path": "object", "if_none_match": "*", "request_sha256": "a" * 64}
        response = {"monotonic_ns": 30, "status": 200, "etag": '"v1"'}
        read = ({"monotonic_ns": 40, "path": "object"},
                {"monotonic_ns": 50, "status": 200, "etag": '"v1"', "response_sha256": "a" * 64})
        wire = {"births": {"object": 30}, "requests": {1: upload}, "responses": {1: response}, "reads": {1: [read]}}
        call, publication = {"monotonic_ns": 10, "call_id": 1}, {"monotonic_ns": 60}
        oracle.durable_closure({"object"}, publication, call, wire)
        for fault in ("missing_upload", "missing_read", "etag", "bytes", "late_read", "late_birth"):
            changed = copy.deepcopy(wire)
            if fault == "missing_upload": changed["requests"] = {}
            elif fault == "missing_read": changed["reads"][1] = []
            elif fault == "etag": changed["reads"][1][0][1]["etag"] = '"another-version"'
            elif fault == "bytes": changed["reads"][1][0][1]["response_sha256"] = "b" * 64
            elif fault == "late_read": changed["reads"][1][0][1]["monotonic_ns"] = 70
            else: changed["births"]["object"] = 70
            with self.subTest(fault=fault), self.assertRaises(ValueError): oracle.durable_closure({"object"}, publication, call, changed)


class ListAndGateControls(unittest.TestCase):
    def listing(self, count=35):
        prefix = "scap-object/v1/7/"
        names = [prefix + f"{n:03}/" for n in range(count)]
        keys = {"/scap-test/" + name + "catalogue/v1/create/17/1" for name in names}
        request = {"path": "/scap-test?list-type=2&max-keys=32&delimiter=%2F&prefix=" + quote(prefix, safe="")}
        xml = ('<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
               '<Name>scap-test</Name><Prefix>' + prefix + '</Prefix><MaxKeys>32</MaxKeys><Delimiter>/</Delimiter>'
               '<KeyCount>' + str(min(32, count)) + '</KeyCount><IsTruncated>' + str(count > 32).lower() + '</IsTruncated>'
               + ''.join('<CommonPrefixes><Prefix>' + name + '</Prefix></CommonPrefixes>' for name in names[:32])
               + ('<NextContinuationToken>original-backend-token</NextContinuationToken>' if count > 32 else '') + '</ListBucketResult>')
        return request, xml.encode(), keys

    def test_root_list_complete_original_key_denominator_and_continuation(self):
        request, encoded, keys = self.listing()
        result = oracle.list_page(encoded, request, keys)
        self.assertTrue(result["more"]); self.assertEqual(len(result["entries"]), 32)
        for mutation in (lambda raw: raw.replace(b"true", b"false"),
                         lambda raw: raw.replace(b"<KeyCount>32", b"<KeyCount>31"),
                         lambda raw: raw.replace(b"/000/", b"/099/"),
                         lambda raw: raw.replace(b"<NextContinuationToken>original-backend-token</NextContinuationToken>", b""),
                         lambda raw: raw.replace(b"/031/", b"/030/"),
                         lambda raw: raw.replace(b"<Name>scap-test</Name>", b"<Name>scap-test</Name><Name>scap-test</Name>")):
            with self.assertRaises(ValueError): oracle.list_page(mutation(encoded), request, keys)
        request, encoded, keys = self.listing(1)
        self.assertFalse(oracle.list_page(encoded, request, keys)["more"])

    def gate(self):
        request = {"request_serial": 1, "monotonic_ns": 20, "path": "/old/head", "method": "PUT"}
        history = [{"event": "transport_fault_armed", "monotonic_ns": 10, "method": "PUT", "path": "/old/head", "stage": "before_forward", "mode": "hold", "occurrence": 1},
                   {"event": "transport_fault_observed", "request_serial": 1, "monotonic_ns": 30, "stage": "before_forward", "mode": "hold"},
                   {"event": "gate_released", "request_serial": 1, "monotonic_ns": 90, "abort": False},
                   {"event": "object_forwarded", "request_serial": 1, "monotonic_ns": 100}]
        second = {"request_serial": 2, "monotonic_ns": 40, "path": "/new/head", "method": "PUT"}
        responses = {1: {"monotonic_ns": 110}, 2: {"monotonic_ns": 80}}
        return history, {1: request, 2: second}, responses

    def test_late_candidate_is_linearized_after_barrier_without_rewriting_timestamps(self):
        history, requests, responses = self.gate()
        oracle.gates(history, requests, responses)
        for fault in ("early_release", "no_arm", "no_release", "wrong_occurrence", "cut", "overlap"):
            rows, reqs, replies = copy.deepcopy((history, requests, responses))
            if fault == "early_release": rows[2]["monotonic_ns"] = 25
            elif fault == "no_arm": rows.pop(0)
            elif fault == "no_release": rows.pop(2)
            elif fault == "wrong_occurrence": rows[0]["occurrence"] = 2
            elif fault == "cut": rows[2]["abort"] = True
            else: replies[2]["monotonic_ns"] = 95
            with self.subTest(fault=fault), self.assertRaises(ValueError): oracle.gates(rows, reqs, replies)


class FullDataAndResultControls(unittest.TestCase):
    def test_full_native_image_uses_all_physical_pages_and_scope_bound_objects(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "db.sqlite"
            with sqlite3.connect(path) as database:
                database.execute("PRAGMA page_size=4096")
                database.execute("CREATE TABLE data(id INTEGER PRIMARY KEY,value BLOB)")
                database.execute("INSERT INTO data VALUES(1,?)", (b"all original bytes" * 1000,))
            image = path.read_bytes()
        h = authority(); objects = {}; chunks = []
        for start in range(0, len(image), 32 * 4096):
            key, encoded = frame(h, "chunk", {"first_page": start // 4096 + 1, "bytes": []}, image[start:start + 32 * 4096])
            objects[key] = encoded; chunks.append(key.rsplit("/", 1)[1])
        key, encoded = frame(h, "node", {"level": 0, "first_chunk": 0, "children": chunks}); objects[key] = encoded
        key, encoded = frame(h, "manifest", {"page_count": len(image) // 4096, "root": key.rsplit("/", 1)[1]}); objects[key] = encoded
        root = key.rsplit("/", 1)[1]
        dependencies, restored = Trees(objects, h).data(root)
        self.assertEqual(restored, image); self.assertEqual(dependencies, set(objects))
        for fault in ("missing_chunk", "changed_bytes", "foreign_scope"):
            changed = dict(objects)
            target = object_prefix(h) + chunks[-1]
            if fault == "missing_chunk": del changed[target]
            elif fault == "changed_bytes": changed[target] = changed[target][:-1] + bytes([changed[target][-1] ^ 1])
            else:
                foreign = copy.deepcopy(h); foreign["scope"]["generation"] = 2
                target, encoded = frame(foreign, "chunk", {"first_page": 1, "bytes": []}, image)
                with self.assertRaises(ValueError): envelope(encoded, target, h)
                continue
            with self.subTest(fault=fault), self.assertRaises(ValueError): Trees(changed, h).data(root)

    def test_all_retained_results_are_read_even_when_not_the_latest_request(self):
        h = authority(); objects = {}; entries = []
        encoded_result = b"SCAPRES1" + struct.pack("<I", 0)
        for identifier in (1, 2):
            identity = {"epoch": 1, "id": identifier, "principal": 17, "fingerprint": "a" * 64}
            key, encoded = frame(h, "result", {"request": identity, "sequence": 1, "transition": {"revision": 3, "nonce": identifier},
                                               "data_root": "b" * 64, "bytes": []}, encoded_result)
            objects[key] = encoded
            entries.append({"request": identity, "outcome": {"state": "committed", "result": key.rsplit("/", 1)[1]}, "result_bytes": len(encoded_result)})
        key, encoded = frame(h, "index", {"kind": "leaf", "epoch": 1, "entries": entries}); objects[key] = encoded
        window = {"epoch": 1, "root": key.rsplit("/", 1)[1], "count": 2, "result_bytes": 2 * len(encoded_result)}
        self.assertEqual(len(Trees(objects, h).index(window, h)["dependencies"]), 3)
        missing = object_prefix(h) + entries[0]["outcome"]["result"]
        del objects[missing]
        with self.assertRaisesRegex(ValueError, "missing full graph dependency"):
            Trees(objects, h).index(window, h)

    def test_object_key_uses_only_captured_head_storage_generation(self):
        h = authority()
        key, encoded = frame(h, "manifest", {"page_count": 0, "root": None})
        self.assertIn("/storage/1/objects/", key)
        self.assertEqual(envelope(encoded, key, h)[0], "manifest")
        for changed in (key.replace("/storage/1/", "/storage/2/"),
                        key.replace("/storage/1/", "/"),
                        key.replace("/gen/1/", "/gen/2/")):
            with self.subTest(key=changed), self.assertRaisesRegex(ValueError, "captured scope"):
                envelope(encoded, changed, h)
        changed = copy.deepcopy(h); changed["storage"]["active_generation"] = 2
        with self.assertRaisesRegex(ValueError, "storage generation"):
            object_prefix(changed)

    def test_strict_head_format_physical_slot_and_closed_windows(self):
        h = authority(); path = catalogue.head_path(h["scope"])
        self.assertEqual(head(raw(h), path), h)
        for fault in ("legacy", "future", "bool", "physical", "quota", "unclosed"):
            changed = copy.deepcopy(h)
            if fault in ("legacy", "future", "bool"): changed["format"] = {"legacy": 4, "future": 6, "bool": True}[fault]
            elif fault == "physical": changed["scope"]["database"] += 1
            elif fault == "quota": changed["quota"]["max_bytes"] += 1
            else:
                changed["request_epoch"] = 2
                changed["windows"] = [dict(changed["windows"][0], epoch=2), changed["windows"][0]]
            with self.subTest(fault=fault), self.assertRaises(ValueError): head(raw(changed), path)


class StableMetadataControls(unittest.TestCase):
    def source(self, operation=41, previous=None):
        c = {"creator": 17, "operation": operation, "name": "未知名称", "scope": catalogue.derive_scope(7, 2, 17, operation), "expected_name_revision": previous}
        descriptor = {"format": 1, "creation": c, "options": {"quota": {"kind": "default"}}, "initial_quota": {"max_bytes": 8 * 1024 * 1024},
                      "retention": {"max_entries": 4, "max_result_bytes": 128 * 1024 * 1024}}
        return c, descriptor

    def control(self, c, descriptor, kind):
        return {"format": 1, "creation": c, "origin": catalogue.origin(descriptor, raw(descriptor)), "kind": kind,
                "principal": 17, "operation": 77, "expected_name_revision": 1 if kind == "abort" else 2,
                "expected_head_revision": None if kind == "abort" else 3, "nonce": 88}

    def fixture(self):
        c, descriptor = self.source()
        binding = {"format": 1, "creation": c, "origin": catalogue.origin(descriptor, raw(descriptor)), "revision": 1,
                   "state": "reserved", "control": None, "proof": None}
        objects = {catalogue.descriptor_path(c): raw(descriptor), catalogue.name_path(c): raw(binding)}
        metadata = Metadata(objects, 7); observation = metadata.expected()[catalogue.name_path(c)]
        reads = []
        for n, path in enumerate((catalogue.name_path(c), catalogue.descriptor_path(c), catalogue.proof_path(c), catalogue.head_path(c["scope"]), catalogue.name_path(c)), 1):
            status = 200 if path in objects else 404
            reads.append(({"path": path, "monotonic_ns": n * 10}, {"status": status, "monotonic_ns": n * 10 + 1,
                          "etag": '"v1"' if status == 200 else None, "response_sha256": oracle.sha(objects.get(path, b"missing"))}))
        return metadata, observation, reads

    def test_stable_view_requires_name_proof_head_name_with_same_response_identity(self):
        metadata, observation, reads = self.fixture()
        self.assertEqual(observation["state"], "Reserved")
        metadata.witnessed(observation, reads)
        for fault in ("missing_descriptor", "missing_proof", "missing_head", "missing_final_name", "etag", "body", "out_of_order"):
            changed = copy.deepcopy(reads)
            if fault.startswith("missing_"): changed.pop({"missing_descriptor": 1, "missing_proof": 2, "missing_head": 3, "missing_final_name": 4}[fault])
            elif fault == "etag": changed[-1][1]["etag"] = '"v2"'
            elif fault == "body": changed[-1][1]["response_sha256"] = "f" * 64
            else: changed[2][0]["monotonic_ns"] = 5
            with self.subTest(fault=fault), self.assertRaises(ValueError): metadata.witnessed(observation, changed)

    def test_absent_binding_allows_distinct_error_ids_but_never_a_presence_change(self):
        previous, _, reads = self.fixture()
        c, _ = self.source()
        objects = dict(previous.objects); del objects[catalogue.name_path(c)]
        metadata = Metadata(objects, 7)
        observation = metadata.expected()[catalogue.descriptor_path(c)]
        for position, request_id in ((0, "first-request"), (-1, "last-request")):
            envelope = ("<Error><Code>NoSuchKey</Code><Resource>" + catalogue.name_path(c) +
                        "</Resource><RequestId>" + request_id + "</RequestId></Error>").encode()
            reads[position][1].update(status=404, etag=None, response_sha256=oracle.sha(envelope))
        self.assertNotEqual(reads[0][1]["response_sha256"], reads[-1][1]["response_sha256"])
        metadata.witnessed(observation, reads)
        for fault in ("absent_to_present", "present_to_absent", "first_etag", "last_etag", "missing_last", "foreign_last"):
            changed = copy.deepcopy(reads)
            if fault == "absent_to_present": changed[-1][1].update(status=200, etag='"v1"')
            elif fault == "present_to_absent": changed[0][1].update(status=200, etag='"v1"')
            elif fault == "first_etag": changed[0][1]["etag"] = '"unexpected-version"'
            elif fault == "last_etag": changed[-1][1]["etag"] = '"unexpected-version"'
            elif fault == "missing_last": changed.pop()
            else: changed[-1][0]["path"] += "another-name"
            with self.subTest(fault=fault), self.assertRaises(ValueError): metadata.witnessed(observation, changed)

    def test_unknown_physical_prefix_is_an_explicit_orphan_not_an_empty_database(self):
        h = authority(); key = object_prefix(h) + "a" * 64
        metadata = Metadata({key: b"unreachable bytes"}, h["scope"]["deployment"])
        observation = next(iter(metadata.expected().values()))
        self.assertEqual((observation["kind"], observation["state"], observation["scope"]), ("OrphanPrefix", "Orphan", None))
        with self.assertRaises(ValueError): metadata.witnessed(observation, [])
        metadata.witnessed(observation, [({"path": catalogue.head_path(h["scope"])}, {"status": 404})])

    def test_reused_name_preserves_old_physical_identity_and_original_control_conditions(self):
        old, first = self.source(); new, second = self.source(42, 3)
        control = self.control(old, first, "delete")
        retired = authority(old["scope"])
        retired.update(active=False, lifecycle="deleted", revision=4, head_serial=4, transition={"revision": 4, "nonce": 88},
                       creation=catalogue.origin(first, raw(first)), deletion=catalogue.mark(control, raw(control)))
        current = authority(new["scope"]); current["creation"] = catalogue.origin(second, raw(second))
        binding = {"format": 1, "creation": new, "origin": current["creation"], "revision": 5,
                   "state": "bound", "control": None, "proof": None}
        objects = {catalogue.descriptor_path(old): raw(first), catalogue.descriptor_path(new): raw(second),
                   catalogue.control_path(control): raw(control), catalogue.name_path(new): raw(binding),
                   catalogue.head_path(old["scope"]): raw(retired), catalogue.head_path(new["scope"]): raw(current)}
        observed = Metadata(objects, 7).expected()
        self.assertEqual(observed[catalogue.descriptor_path(old)]["state"], "Deleted")
        self.assertIsNone(observed[catalogue.descriptor_path(old)]["binding_revision"])
        self.assertEqual(observed[catalogue.head_path(old["scope"])]["scope"], old["scope"])
        self.assertEqual(observed[catalogue.name_path(new)]["scope"], new["scope"])
        self.assertEqual(observed[catalogue.control_path(control)]["control"],
                         {key: control[key] for key in ("kind", "principal", "operation", "expected_name_revision", "expected_head_revision", "nonce")})
        for fault in ("missing_source", "missing_control", "changed_nonce", "advanced_binding_without_barrier"):
            changed = dict(objects)
            if fault == "missing_source": del changed[catalogue.descriptor_path(old)]
            elif fault == "missing_control": del changed[catalogue.control_path(control)]
            elif fault == "changed_nonce": changed[catalogue.control_path(control)] = raw({**control, "nonce": 89})
            else: changed[catalogue.head_path(old["scope"])] = raw({**retired, "deletion": None})
            with self.subTest(fault=fault), self.assertRaises(ValueError): Metadata(changed, 7).expected()

    def test_admitted_abort_and_completed_abort_require_distinct_durable_evidence(self):
        metadata, _, _ = self.fixture(); objects = dict(metadata.objects)
        c, descriptor = self.source(); control = self.control(c, descriptor, "abort")
        objects[catalogue.control_path(control)] = raw(control)
        self.assertEqual(Metadata(objects, 7).expected()[catalogue.control_path(control)]["state"], "ControlAdmitted")
        deleted = authority(c["scope"])
        deleted.update(active=False, lifecycle="deleted", sequence=0, revision=1, transition={"revision": 1, "nonce": 88},
                       creation=catalogue.origin(descriptor, raw(descriptor)), deletion=catalogue.mark(control, raw(control)))
        proof = {"format": 1, "control": control, "barrier": {"kind": "own_deleted", "transition": deleted["transition"]}}
        objects[catalogue.proof_path(c)] = raw(proof)
        objects[catalogue.head_path(c["scope"])] = raw(deleted)
        objects[catalogue.name_path(c)] = raw({"format": 1, "creation": c, "origin": deleted["creation"], "revision": 3,
                                              "state": "tombstone", "control": control, "proof": oracle.sha(raw(proof))})
        values = Metadata(objects, 7).expected()
        self.assertEqual(values[catalogue.control_path(control)]["state"], "Aborted")
        self.assertIsNone(values[catalogue.control_path(control)]["control"]["expected_head_revision"])
        self.assertEqual(values[catalogue.head_path(c["scope"])]["state"], "Deleted")
        for missing in (catalogue.proof_path(c), catalogue.head_path(c["scope"]), catalogue.control_path(control)):
            changed = dict(objects); del changed[missing]
            with self.subTest(missing=missing), self.assertRaises(ValueError): Metadata(changed, 7).expected()


if __name__ == "__main__": unittest.main()
