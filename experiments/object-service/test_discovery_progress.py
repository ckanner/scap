"""Synthetic verifier controls; no daemon, SQLite, SDK or S3 is executed here."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import unittest
import xml.etree.ElementTree as ET
from urllib.parse import parse_qsl, urlsplit

import discovery_oracle as audit


def encoded(value):
    return json.dumps(value, separators=(",", ":")).encode()


class Evidence:
    def __init__(self):
        self.objects = {}
        self.now = 10_000_000

    def get(self, key, raw=b"", status=200, query=None):
        serial = len(self.objects) + 1
        request = {"monotonic_ns": self.now, "request_serial": serial, "method": "GET",
                   "key": key, "query": query or {}, "fault": None}
        delivery = {"monotonic_ns": self.now + 100, "status": status, "etag": '"body"' if status == 200 else None}
        value = {"request": request, "backend": dict(delivery), "delivery": delivery,
                 "terminal": {"monotonic_ns": self.now + 200, "event": "delivery_finished"},
                 "outgoing": raw, "upstream": raw}
        self.objects[serial] = value
        self.now += 1_000_000
        return value

    def listing(self, prefix, entries, *, after="", delimiter=None, truncated=False):
        root = ET.Element("ListBucketResult")
        ET.SubElement(root, "IsTruncated").text = str(truncated).lower()
        for key in entries:
            node = ET.SubElement(root, "CommonPrefixes" if delimiter else "Contents")
            ET.SubElement(node, "Prefix" if delimiter else "Key").text = key
        query = {"prefix": prefix, "list-type": "2", "max-keys": "32"}
        if after:
            query["start-after"] = after
        if delimiter:
            query["delimiter"] = delimiter
        return self.get("/scap-test", ET.tostring(root), query=query)

    def ready(self, creation, *, read=False):
        # Five semantic witnesses intentionally differ from production's eight
        # current reads: the audit must prove authority, not implementation count.
        scope = creation["scope"]
        prefix = f"scap-object/v1/{scope['deployment']}/{scope['tenant']}/"
        name = prefix + "catalogue/v1/name/" + audit.sha(creation["name"].encode())
        descriptor = encoded({"creation": creation})
        origin = {"descriptor_hash": hashlib.sha256(descriptor).hexdigest()}
        binding = encoded({"creation": creation, "state": "bound", "origin": origin, "revision": 2})
        head = encoded({"scope": scope, "creation": origin, "revision": 7, "lifecycle": "ready",
                        "policy": [{"principal": 12, "read": read}]})
        self.get(name, binding)
        self.get(prefix + f"catalogue/v1/create/{creation['creator']}/{creation['operation']}", descriptor)
        self.get(prefix + f"catalogue/v1/abort-proof/{creation['creator']}/{creation['operation']}", b"missing", 404)
        self.get(prefix + scope["database"] + "/head", head)
        self.get(name, binding)
        return {"creation": creation, "binding_revision": "2", "head_revision": "7"}

    def absent(self, creation, authority):
        scope = creation["scope"]
        prefix = f"scap-object/v1/{scope['deployment']}/{scope['tenant']}/"
        descriptor = prefix + f"catalogue/v1/create/{creation['creator']}/{creation['operation']}"
        name = prefix + "catalogue/v1/name/" + audit.sha(creation["name"].encode())
        self.get(authority, encoded({"creation": creation}))
        if authority != descriptor:
            self.get(descriptor, encoded({"creation": creation}))
        self.get(name, b"missing", 404)
        self.get(prefix + f"catalogue/v1/abort-proof/{creation['creator']}/{creation['operation']}", b"missing", 404)
        self.get(prefix + scope["database"] + "/head", b"missing", 404)
        return self.get(name, b"missing", 404)


def creations():
    values = [{"name": f"fixture-{index}", "creator": "11", "operation": str(100 + index),
               "scope": {"deployment": "1", "tenant": "7", "database": str(900 + index), "incarnation": "1", "generation": "1"},
               "expected_name_revision": None} for index in range(3)]
    return sorted(values, key=lambda value: audit.sha(value["name"].encode()))


def call(start, end, cursor, value, *, inventory=False, label="synthetic"):
    return {"label": label, "request": {"monotonic_ns": start}, "response": {"monotonic_ns": end},
            "identity": {"deployment": "1", "tenant": "7", "principal": "12", "deployment_inventory": inventory},
            "body": {"operation": "deployment_inventory" if inventory else "list_names", "cursor": cursor},
            "value": {"ok": True, "value": value}}


def names_fixture():
    evidence, ordered = Evidence(), creations()
    prefix = "scap-object/v1/1/7/catalogue/v1/name/"
    keys = [prefix + audit.sha(value["name"].encode()) for value in ordered]
    evidence.listing(prefix, keys, truncated=True)
    visible = evidence.ready(ordered[0], read=True)
    evidence.now = 3_950_000_000
    evidence.get(keys[1], encoded({"creation": ordered[1], "state": "bound", "origin": {}, "revision": 2}))
    first = call(1_000, 4_010_000_000, None,
                 {"names": [visible], "cursor": "original-sealed-token", "traversal_exhausted": False, "stopped": "UNKNOWN"})
    evidence.now = 5_010_000_000
    following = evidence.listing(prefix, keys[1:], after=keys[0])
    for creation in ordered[1:]:
        evidence.ready(creation)
    last = call(5_000_000_000, 5_100_000_000, "original-sealed-token",
                {"names": [], "cursor": None, "traversal_exhausted": True, "stopped": None})
    return evidence, ordered, [first, last], following


def inventory_fixture():
    evidence, creation = Evidence(), creations()[0]
    root, tenant = "scap-object/v1/1/", "scap-object/v1/1/7/"
    key = tenant + "catalogue/v1/name/" + audit.sha(creation["name"].encode())
    descriptor = tenant + f"catalogue/v1/create/{creation['creator']}/{creation['operation']}"
    head = tenant + creation["scope"]["database"] + "/head"
    published = {key, descriptor, head}
    evidence.listing(root, [tenant], delimiter="/")
    evidence.listing(tenant + "catalogue/v1/name/", [key])
    evidence.ready(creation)
    evidence.now = 3_950_000_000
    evidence.listing(tenant + "catalogue/v1/create/", [descriptor])
    evidence.get(descriptor, encoded({"creation": creation}))

    def record(kind, physical):
        return {"key": physical, "kind": kind, "state": "ready", "creation": creation, "scope": creation["scope"],
                "binding_revision": "2", "head_revision": "7", "control": None}

    first = call(1_000, 4_010_000_000, None, {"records": [record("name", key)], "cursor": "inventory-1",
                 "completion": {"traversal_exhausted": False}, "stopped": "UNKNOWN", "usage": {"candidates": 3}}, inventory=True)
    evidence.now = 5_010_000_000
    evidence.listing(tenant + "catalogue/v1/create/", [descriptor])
    evidence.get(descriptor, encoded({"creation": creation}))
    evidence.ready(creation)
    evidence.listing(tenant + "catalogue/v1/control/", [])
    evidence.listing(tenant + "catalogue/v1/abort-proof/", [])
    evidence.listing(tenant, [head[:-4], tenant + "catalogue/"], delimiter="/")
    evidence.get(head, encoded({"scope": creation["scope"], "revision": 7, "lifecycle": "ready",
                               "creation": {"descriptor_hash": audit.sha(encoded({"creation": creation}))}, "policy": []}))
    evidence.ready(creation)
    middle = call(5_000_000_000, 5_100_000_000, "inventory-1", {"records": [record("create", descriptor), record("head", head)],
                  "cursor": "inventory-2", "completion": {"traversal_exhausted": False}, "stopped": "LIMIT",
                  "usage": {"candidates": 3}}, inventory=True)
    evidence.now = 6_010_000_000
    evidence.listing(root, [], after=tenant, delimiter="/")
    final = call(6_000_000_000, 6_100_000_000, "inventory-2", {"records": [], "cursor": None,
                 "completion": {"traversal_exhausted": True}, "stopped": None, "usage": {"candidates": 0}}, inventory=True)
    return evidence, published, [first, middle, final]


class NaturalContinuationControls(unittest.TestCase):
    def test_original_unknown_prefix_continues_after_revocation(self):
        evidence, ordered, scan, _ = names_fixture()
        report = audit.name_progress(scan, evidence.objects, ordered)
        self.assertEqual(report, {"pages": 2, "natural_unknown_pages": 1, "classified_candidates": 3, "complete": True})

    def test_false_complete_unknown_cannot_hide_unclassified_suffix(self):
        evidence, ordered, scan, _ = names_fixture()
        scan[0]["value"]["value"].update(cursor=None, stopped=None, traversal_exhausted=True)
        with self.assertRaisesRegex(ValueError, "exhausted final LIST"):
            audit.name_progress(scan[:1], evidence.objects, ordered)

    def test_real_next_start_after_cannot_skip_unclassified_candidate(self):
        evidence, ordered, scan, following = names_fixture()
        following["request"]["query"]["start-after"] = "scap-object/v1/1/7/catalogue/v1/name/" + audit.sha(ordered[1]["name"].encode())
        with self.assertRaisesRegex(ValueError, "unclassified name"):
            audit.name_progress(scan, evidence.objects, ordered)

    def test_changed_opaque_token_cannot_prove_progress(self):
        evidence, ordered, scan, following = names_fixture()
        following["request"]["query"].pop("start-after")
        with self.assertRaisesRegex(ValueError, "without classified progress"):
            audit.name_progress(scan, evidence.objects, ordered)

    def test_resume_must_use_original_authenticated_token(self):
        evidence, ordered, scan, _ = names_fixture()
        scan[1]["body"]["cursor"] = "replacement"
        with self.assertRaisesRegex(ValueError, "original authenticated cursor"):
            audit.name_progress(scan, evidence.objects, ordered)

    def test_fresh_denial_cannot_be_overridden_by_prior_read_grant(self):
        evidence, ordered, scan, _ = names_fixture()
        scan[1]["value"]["value"]["names"] = [{"creation": ordered[-1], "binding_revision": "2", "head_revision": "7"}]
        with self.assertRaisesRegex(ValueError, "READ-denied"):
            audit.name_progress(scan, evidence.objects, ordered)

    def test_stable_prefix_requires_original_absent_proof(self):
        evidence, ordered, scan, _ = names_fixture()
        proof = next(obj for obj in evidence.objects.values() if "/abort-proof/" in obj["request"]["key"])
        proof["delivery"]["status"] = 403
        with self.assertRaisesRegex(ValueError, "unclassified name"):
            audit.name_progress(scan, evidence.objects, ordered)

    def test_page_bound_applies_to_entire_scan_including_first(self):
        with self.assertRaisesRegex(ValueError, "fixed total page bound"):
            audit.scan_sequence([{}] * 129)

    def test_distinct_fault_names_cannot_merge_continuation_denominators(self):
        labels = ("after_fault_missing_0", "after_fault_missing_1", "after_fault_missing_truncation_0")
        observed = {label: {"label": label} for label in labels}
        self.assertEqual(audit.numbered_pages(observed, "after_fault_missing_"), [observed[label] for label in labels[:2]])
        self.assertEqual(audit.numbered_pages(observed, "after_fault_missing_truncation_"), [observed[labels[-1]]])
        observed.pop(labels[0])
        with self.assertRaisesRegex(ValueError, "gap or reorder"):
            audit.numbered_pages(observed, "after_fault_missing_")

    def test_unknown_keeps_original_five_second_deadline(self):
        evidence, _, scan, _ = names_fixture()
        original = {key: obj for key, obj in evidence.objects.items() if audit.window(scan[0], audit.stamp(obj["request"]))}
        scan[0]["response"]["monotonic_ns"] = 5_100_000_000
        with self.assertRaisesRegex(ValueError, "five-second deadline"):
            audit.page_budget(original, scan[0])

    def test_read_work_cannot_renew_four_second_cutoff(self):
        evidence, _, scan, _ = names_fixture()
        last = list(evidence.objects.values())[6]
        last["request"]["monotonic_ns"] = 4_500_000_000
        last["delivery"]["monotonic_ns"] = 4_500_000_100
        scan[0]["response"]["monotonic_ns"] = 4_900_000_000
        with self.assertRaisesRegex(ValueError, "external four-second read bound"):
            audit.page_budget(evidence.objects, scan[0])

    def test_read_count_cannot_renew_exact_get_budget(self):
        evidence, _, scan, _ = names_fixture()
        evidence.now = 2_000_000_000
        for _ in range(513):
            evidence.get("scap-object/v1/1/7/catalogue/v1/name/excess", b"x")
        with self.assertRaisesRegex(ValueError, "LIST/exact-GET budget"):
            audit.page_budget(evidence.objects, scan[0])

    def test_only_final_original_deadline_get_has_two_exact_refunds(self):
        evidence, _, scan, _ = names_fixture()
        gets = [obj for obj in audit.page_requests(evidence.objects, scan[0]) if not obj["request"]["query"]]
        last = gets[-1]["request"]["request_serial"]
        exact = audit.metadata_reservation_options(gets)
        choices = audit.metadata_reservation_options(gets, last)
        self.assertEqual(len(choices), 2)
        self.assertTrue(exact < choices)
        self.assertEqual(max(choices) - min(choices), 64 * 1024 - len(gets[-1]["outgoing"]))
        self.assertNotIn((min(choices) + max(choices)) // 2, choices)
        early_head = next(obj for obj in gets if obj["request"]["key"].endswith("/head"))
        early_reservation = 256 * 1024 - len(early_head["outgoing"])
        self.assertNotIn(min(choices) + early_reservation, choices)
        self.assertNotIn(max(choices) + early_reservation, choices)
        with self.assertRaisesRegex(ValueError, "single final GET"):
            audit.metadata_reservation_options(gets, gets[0]["request"]["request_serial"])

    def test_causally_classified_tail_does_not_get_an_ambiguous_refund(self):
        evidence, _, scan, _ = names_fixture()
        budget = audit.page_budget(evidence.objects, scan[0], classified_through=4_000_000_000)
        self.assertIsNone(budget["uncertain_final_get"])
        self.assertEqual(len(budget["metadata_options"]), 1)

    def test_refund_negatives_stay_distinct_without_an_uncertain_tail(self):
        evidence, _, scan, _ = names_fixture()
        gets = [obj for obj in audit.page_requests(evidence.objects, scan[0]) if not obj["request"]["query"]]
        head = next(obj for obj in gets if obj["request"]["key"].endswith("/head"))
        options = audit.metadata_reservation_options(gets)
        changed = audit.metadata_control_counts(options, [head, gets[0]])
        self.assertEqual(len(set(changed)), 3)
        self.assertTrue(all(value not in options for value in changed))
        self.assertGreater(changed[1], changed[0])
        with self.assertRaisesRegex(ValueError, "one earlier GET"):
            audit.metadata_control_counts(options, [head, head])

    def test_non_deadline_final_get_keeps_exact_refund(self):
        evidence, _, scan, _ = names_fixture()
        budget = audit.page_budget(evidence.objects, scan[1])
        self.assertIsNone(budget["uncertain_final_get"])
        self.assertEqual(len(budget["metadata_options"]), 1)

    def test_declared_corrupt_head_transport_keeps_exact_body_refund(self):
        evidence, _, scan, _ = names_fixture()
        head = next(obj for obj in evidence.objects.values() if obj["request"]["key"].endswith("/head"))
        head["request"]["fault"] = "head_corrupt_head"
        head["outgoing"] = b"{}"
        scan[0]["value"]["value"]["stopped"] = "CORRUPT"
        budget = audit.page_budget(evidence.objects, scan[0], natural=False)
        gets = [obj for obj in audit.page_requests(evidence.objects, scan[0]) if not obj["request"]["query"]]
        expected = sum(len(obj["outgoing"]) if obj["delivery"]["status"] == 200 else 64 * 1024 for obj in gets)
        self.assertEqual(budget["metadata_options"], {expected})
        with self.assertRaisesRegex(ValueError, "unverified successful metadata body"):
            audit.metadata_reservation_options(gets)

    def test_natural_page_cannot_use_declared_corruption_exception(self):
        evidence, _, scan, _ = names_fixture()
        head = next(obj for obj in evidence.objects.values() if obj["request"]["key"].endswith("/head"))
        head["request"]["fault"] = "head_corrupt_head"
        head["outgoing"] = b"{}"
        with self.assertRaisesRegex(ValueError, "natural page contains an injected fault"):
            audit.page_budget(evidence.objects, scan[0])

    def test_inventory_classifies_original_records_and_empty_phase_progress(self):
        evidence, published, scan = inventory_fixture()
        audit.inventory_progress(scan, evidence.objects, published)
        for value in scan:
            for entry in value["value"]["value"]["records"]:
                self.assertGreater(audit.inventory_record(evidence.objects, value, entry), 0)

    def test_same_creation_records_have_their_own_admitting_list_and_final_get(self):
        evidence, _, scan = inventory_fixture()
        current = scan[1]
        create, head = current["value"]["value"]["records"]
        phase = next(obj for obj in audit.page_requests(evidence.objects, current)
                     if obj["request"]["query"].get("prefix") == "scap-object/v1/1/7/")
        self.assertLess(audit.inventory_record(evidence.objects, current, create), audit.stamp(phase["request"]))
        self.assertGreater(audit.inventory_record(evidence.objects, current, head), audit.stamp(phase["delivery"]))

    def test_head_record_cannot_borrow_create_phase_authority(self):
        evidence, _, scan = inventory_fixture()
        current = scan[1]
        phase = next(obj for obj in audit.page_requests(evidence.objects, current)
                     if obj["request"]["query"].get("prefix") == "scap-object/v1/1/7/")
        evidence.objects = {serial: obj for serial, obj in evidence.objects.items()
                            if not (audit.stamp(phase["delivery"]) < audit.stamp(obj["request"]) < audit.stamp(current["response"]))}
        with self.assertRaisesRegex(ValueError, "own exact authority GET"):
            audit.inventory_record(evidence.objects, current, current["value"]["value"]["records"][-1])

    def test_returned_head_final_get_has_only_its_exact_refund(self):
        evidence, _, scan = inventory_fixture()
        current = scan[1]
        evidence.objects = {serial: obj for serial, obj in evidence.objects.items() if audit.window(current, audit.stamp(obj["request"]))}
        final = audit.page_requests(evidence.objects, current)[-1]
        final["request"]["monotonic_ns"] = audit.stamp(current["request"]) + 3_950_000_000
        final["delivery"]["monotonic_ns"] = audit.stamp(final["request"]) + 100
        current["response"]["monotonic_ns"] = audit.stamp(current["request"]) + 4_010_000_000
        current["value"]["value"]["stopped"] = "UNKNOWN"
        through = max(audit.inventory_record(evidence.objects, current, entry) for entry in current["value"]["value"]["records"])
        self.assertEqual(through, audit.stamp(final["delivery"]))
        budget = audit.page_budget(evidence.objects, current, through)
        self.assertIsNone(budget["uncertain_final_get"])
        self.assertEqual(len(budget["metadata_options"]), 1)

    def test_inventory_cannot_skip_a_physical_record(self):
        evidence, published, scan = inventory_fixture()
        scan[1]["value"]["value"]["records"].pop(0)
        with self.assertRaisesRegex(ValueError, "unclassified physical record"):
            audit.inventory_progress(scan, evidence.objects, published)

    def test_inventory_cannot_skip_an_empty_phase_without_list_evidence(self):
        evidence, published, scan = inventory_fixture()
        evidence.objects = {key: value for key, value in evidence.objects.items()
                            if not value["request"]["query"].get("prefix", "").endswith("/control/")}
        with self.assertRaisesRegex(ValueError, "unobserved traversal phase"):
            audit.inventory_progress(scan, evidence.objects, published)

    def test_inventory_cannot_claim_exhaustion_from_truncated_list(self):
        evidence, published, scan = inventory_fixture()
        final = list(evidence.objects.values())[-1]
        final["upstream"] = final["outgoing"] = b"<ListBucketResult><IsTruncated>true</IsTruncated></ListBucketResult>"
        with self.assertRaisesRegex(ValueError, "actual exhausted LIST"):
            audit.inventory_progress(scan, evidence.objects, published)

    def test_inventory_candidate_budget_cannot_exclude_already_classified_entries(self):
        evidence, published, scan = inventory_fixture()
        scan[0]["value"]["value"]["usage"]["candidates"] = 1
        with self.assertRaisesRegex(ValueError, "candidate budget differs"):
            audit.inventory_progress(scan, evidence.objects, published)

    def test_dormant_descriptor_and_control_need_stable_absence(self):
        evidence, creation = Evidence(), creations()[0]
        creation["name"] = "discovery-descriptor-only"
        prefix = "scap-object/v1/1/7/"
        descriptor = prefix + f"catalogue/v1/create/{creation['creator']}/{creation['operation']}"
        control = prefix + "catalogue/v1/control/11/30002"
        invocation = call(1, 100_000_000, None, {}, inventory=True)
        for kind, physical, state in (("create", descriptor, "descriptor_only"), ("control", control, "control_admitted")):
            evidence.listing(prefix + "catalogue/v1/" + kind + "/", [physical])
            after = evidence.absent(creation, physical)
            entry = {"key": physical, "kind": kind, "state": state, "creation": creation, "scope": creation["scope"],
                     "binding_revision": None, "head_revision": None, "control": None}
            self.assertEqual(audit.inventory_record(evidence.objects, invocation, entry), audit.stamp(after["delivery"]))
        after["delivery"]["status"] = 403
        with self.assertRaisesRegex(ValueError, "stable absent view"):
            audit.inventory_record(evidence.objects, invocation, entry)

    def test_same_creation_control_cannot_borrow_previous_candidate_in_same_list(self):
        evidence, creation = Evidence(), creations()[0]
        creation["name"] = "discovery-descriptor-only"
        prefix = "scap-object/v1/1/7/catalogue/v1/control/"
        keys = [prefix + "11/30002", prefix + "11/30004"]
        evidence.listing(prefix, keys)
        original = evidence.absent(creation, keys[0])
        evidence.get(keys[1], encoded({"creation": creation}))
        current = call(1, 100_000_000, None, {}, inventory=True)
        entry = {"key": keys[0], "kind": "control", "state": "control_admitted", "creation": creation,
                 "scope": creation["scope"], "binding_revision": None, "head_revision": None, "control": None}
        self.assertEqual(audit.inventory_record(evidence.objects, current, entry), audit.stamp(original["delivery"]))
        entry["key"] = keys[1]
        with self.assertRaisesRegex(ValueError, "stable absent view"):
            audit.inventory_record(evidence.objects, current, entry)

    def test_frontier_negative_rewrites_a_coherent_full_original_list(self):
        prefix = "scap-object/v1/1/7/catalogue/v1/name/"
        keys = [prefix + f"{index:064x}" for index in range(40)]
        trace = []
        for index, key in enumerate(keys, 1):
            trace.extend([{"event": "request", "request_serial": index, "monotonic_ns": index * 10,
                           "method": "PUT", "key": key},
                          {"event": "backend_response", "request_serial": index, "monotonic_ns": index * 10 + 1, "status": 200}])
        root = ET.Element("ListBucketResult")
        ET.SubElement(root, "Prefix").text = prefix
        ET.SubElement(root, "MaxKeys").text = "32"
        ET.SubElement(root, "IsTruncated").text = "true"
        ET.SubElement(root, "KeyCount").text = "32"
        for key in keys[:32]:
            ET.SubElement(ET.SubElement(root, "Contents"), "Key").text = key
        raw = ET.tostring(root)
        body = {"bytes": len(raw), "sha256": audit.sha(raw), "base64": base64.b64encode(raw).decode()}
        trace.extend([{"event": "request", "request_serial": 41, "monotonic_ns": 1000, "method": "GET", "key": "/scap-test",
                       "path": "/scap-test?list-type=2&max-keys=32", "query": {"list-type": "2", "max-keys": "32", "prefix": prefix}},
                      {"event": "backend_response", "request_serial": 41, "monotonic_ns": 1001, "status": 200, "body": copy.deepcopy(body)},
                      {"event": "delivery_started", "request_serial": 41, "monotonic_ns": 1002, "status": 200, "body": copy.deepcopy(body)}])
        data = {"discovery-s3.jsonl": trace}
        audit.control_list_frontier(data, 41, keys[5])
        request = trace[-3]
        self.assertEqual(dict(parse_qsl(urlsplit(request["path"]).query)), request["query"])
        upstream = audit.raw(trace[-2]["body"])
        self.assertEqual(upstream, audit.raw(trace[-1]["body"]))
        parsed = ET.fromstring(upstream)
        self.assertEqual(parsed.findtext("StartAfter"), keys[5])
        self.assertEqual([node.findtext("Key") for node in parsed.findall("Contents")], keys[6:38])
        self.assertEqual(parsed.findtext("IsTruncated"), "true")
        audit.control_list_frontier(data, 41, "")
        parsed = ET.fromstring(audit.raw(trace[-2]["body"]))
        self.assertIsNone(parsed.find("StartAfter"))
        self.assertEqual([node.findtext("Key") for node in parsed.findall("Contents")], keys[:32])


if __name__ == "__main__":
    unittest.main()
