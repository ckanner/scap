"""Synthetic observer counterexamples; these are not actual S3 executions.

Frames are assembled from the public byte format independently of product code.
The interval tests use observer facts with deliberately controlled clocks, so a
changed verdict must come from the targeted rule rather than timing a process.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import sqlite3
import struct
import unittest

import controls
import oracle
import protocol
from spec import COMMANDS, GROUPS, HEAD, PHASES, PREFIX, SCOPE, WORKERS


def encode(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()


def scalar_result(value):
    return (b"SCAPRES1" + struct.pack("<III", 1, 1, 1) + b"n"
            + struct.pack("<IBqQq", 1, 1, value, 1, value))


class Frames:
    def __init__(self):
        self.objects = {}

    def add(self, kind, value, raw=b""):
        metadata = encode({"format": 2, "scope": protocol.NATIVE_SCOPE,
                           "payload": {"kind": kind, "value": value}})
        frame = b"SCAPOBJ2" + struct.pack("<IQ", len(metadata), len(raw)) + metadata + raw
        digest = hashlib.sha256(frame).hexdigest()
        self.objects[PREFIX + digest] = frame
        return digest

    def data(self, raw):
        chunk = self.add("chunk", {"first_page": 1, "bytes": []}, raw)
        node = self.add("node", {"level": 0, "first_chunk": 0, "children": [chunk]})
        return self.add("manifest", {"page_count": len(raw) // 4096, "root": node})

    def entry(self, identifier, sequence, revision, data_root):
        request = {"epoch": 1, "id": identifier, "principal": 11,
                   "fingerprint": hashlib.sha256(str(identifier).encode()).hexdigest()}
        value = {"request": request, "sequence": sequence,
                 "transition": {"revision": revision, "nonce": identifier},
                 "data_root": data_root, "bytes": []}
        raw = scalar_result(identifier)
        digest = self.add("result", value, raw)
        return {"request": request, "outcome": {"state": "committed", "result": digest},
                "result_bytes": len(raw)}

    def head(self, entries, data_root, revision, nonce, sequence):
        root = self.add("index", {"kind": "leaf", "epoch": 1, "entries": entries})
        return {"format": 6, "scope": deepcopy(protocol.NATIVE_SCOPE), "head_serial": revision,
                "storage": {"active_generation": 1, "allocated_through": 1, "plan": None, "sweep": None},
                "revision": revision, "transition": {"revision": revision, "nonce": nonce},
                "sequence": sequence, "owner_epoch": 1, "owner_instance": 9201,
                "active": True, "auth_epoch": 1,
                "policy": [{"principal": 11, "read": True, "write": True, "admin": True}],
                "lifecycle": "ready", "creation": None, "deletion": None, "data_root": data_root,
                "quota": {"max_bytes": 10737418240},
                "retention": {"max_entries": 4096, "max_result_bytes": 268435456},
                "request_epoch": 1, "windows": [{"epoch": 1, "root": root,
                    "count": len(entries), "result_bytes": sum(entry["result_bytes"] for entry in entries)}]}


def publication_fixture(width=4):
    frames = Frames()
    connection = sqlite3.connect(":memory:")
    try:
        connection.execute("PRAGMA page_size=4096")
        connection.execute("CREATE TABLE witness(n INTEGER PRIMARY KEY)")
        connection.execute("INSERT INTO witness VALUES(1)")
        connection.commit()
        root = frames.data(connection.serialize())
        entries = [frames.entry(1, 1, 3, root)]
        previous = frames.head(deepcopy(entries), root, 3, 1, 1)
        for offset in range(1, width + 1):
            identifier = 10 + offset
            connection.execute("INSERT INTO witness VALUES(?)", (identifier,))
            connection.commit()
            root = frames.data(connection.serialize())
            entries.append(frames.entry(identifier, 1 + offset, 3 + offset, root))
        candidate = frames.head(entries, root, 3 + width, 10 + width, 1 + width)
    finally:
        connection.close()
    before = protocol.closure(frames.objects, previous)
    after = protocol.closure(frames.objects, candidate)
    return frames, previous, candidate, before, after


def receipt(stored):
    value = stored["metadata"]
    return {"scope": deepcopy(SCOPE), "request": {key: str(item) if key != "fingerprint" else item
            for key, item in value["request"].items()}, "sequence": str(value["sequence"]),
            "transition": {key: str(item) for key, item in value["transition"].items()},
            "data_root": value["data_root"], "result_hash": stored["hash"]}


def interval_fixture():
    events, history, calls, by_command = [], [], {}, {}

    def call(command, start, finish):
        serial = len(calls) + 1
        calls[serial] = {"request": {"monotonic_ns": start}, "response": {"monotonic_ns": finish}}
        by_command[command] = [serial]

    for offset, phase in enumerate(PHASES, 1):
        base = offset * 1000
        call(phase + "_blocker", base + 10, base + 900)
        history.append({"event": "object_request", "request_serial": offset, "worker": "primary",
                        "method": "GET", "path": HEAD, "monotonic_ns": base + 20})
        events.extend([
            {"event": "fault_entered", "id": phase + "_queue_gate", "request_serial": offset,
             "monotonic_ns": base + 30},
            {"event": "fault_released", "id": phase + "_queue_gate", "request_serial": offset,
             "monotonic_ns": base + 500},
        ])
        for index, command in enumerate(GROUPS[phase]):
            call(command["id"], base + 100 + index * 20, base + 700 + index * 20)
        call(phase + "_overflow", base + 300, base + 350)
        if phase == "cancel_race":
            events.extend([
                {"event": "fault_entered", "id": "group_candidate", "monotonic_ns": base + 550},
                {"event": "fault_released", "id": "group_candidate", "monotonic_ns": base + 580},
            ])
            call("cancel_member", base + 560, base + 570)
    return events, history, calls, by_command


def inventory_fixture():
    events = [{"event": "probe_started", "monotonic_ns": 2, "spawn_requested_ns": 1}]
    for offset, worker in enumerate(WORKERS):
        events.append({"event": "service_ready", "worker": worker, "monotonic_ns": 3 + offset})
    events.extend({"event": "command_sent", "command": command["id"], "monotonic_ns": 10 + offset}
                  for offset, command in enumerate(COMMANDS))
    rules = {phase + "_queue_gate": {"channel": "s3", "worker": "primary", "method": "GET", "path": HEAD, "kind": "hold"}
             for phase in PHASES}
    rules["group_candidate"] = {"channel": "s3", "worker": "primary", "method": "PUT", "path": HEAD, "nonce": "74", "kind": "hold"}
    rules["lost_member_reply"] = {"channel": "http", "worker": "primary", "command": "response_loss_b", "kind": "drop"}
    for offset, (identifier, rule) in enumerate(rules.items()):
        for stage, event in enumerate(("fault_armed", "fault_entered", "fault_released")):
            if event == "fault_released" and rule["kind"] == "drop":
                continue
            events.append({"event": event, "id": identifier, "monotonic_ns": 300 + 10 * offset + stage, **rule})
    events.append({"event": "probe_stopped", "monotonic_ns": 10000})
    for offset, worker in enumerate(WORKERS):
        events.append({"event": "service_stopped", "worker": worker, "monotonic_ns": 10001 + offset})
    history = [{"event": "phase_started", "phase": phase, "monotonic_ns": 10 + offset}
               for offset, phase in enumerate(("seed", *PHASES, "restart", "lookup"))]
    for rows in (events, history):
        for sequence, row in enumerate(rows, 1):
            row.update(schema=1, sequence=sequence)
    ledger = [{"event": "client_process_hello", "phase": command["id"], "monotonic_ns": str(500 + offset)}
              for offset, command in enumerate(COMMANDS)]
    probe = [{"event": event, "command": command["id"], "monotonic_ns": str(1000 + 2 * offset + step)}
             for offset, command in enumerate(COMMANDS) for step, event in enumerate(("command_started", "command_finished"))]
    return events, history, ledger, probe


class GroupProtocolTests(unittest.TestCase):
    def test_one_to_four_members_have_independent_revisions_and_original_results(self):
        for width in range(1, 5):
            with self.subTest(width=width):
                _, previous, candidate, before, after = publication_fixture(width)
                members = protocol.publication(previous, candidate, before, after)
                self.assertEqual(len(members), width)
                self.assertEqual(candidate["head_serial"], previous["head_serial"] + width)
                self.assertEqual([member["metadata"]["sequence"] for member in members],
                                 list(range(previous["sequence"] + 1, candidate["sequence"] + 1)))
                self.assertEqual(candidate["data_root"], members[-1]["metadata"]["data_root"])
                for member in members:
                    protocol.receipt_matches(receipt(member), member["raw"], member)
                    self.assertEqual(protocol.result(member["raw"])[0]["rows"],
                                     [[member["metadata"]["request"]["id"]]])

    def test_sequence_jump_requires_exactly_the_fresh_successful_members(self):
        cases = ("missing", "extra", "cancelled", "sequence", "revision")
        for name in cases:
            with self.subTest(name=name):
                _, previous, candidate, before, after = publication_fixture()
                expected = "logical group width differs from fresh identities"
                if name == "missing":
                    after["entries"].pop(12)
                elif name == "extra":
                    after["entries"][99] = deepcopy(after["entries"][14])
                elif name == "cancelled":
                    after["entries"][12]["outcome"] = {"state": "cancelled", "transition": {"revision": 5, "nonce": 12}}
                    expected = "group replaced a cancellation barrier"
                else:
                    value = after["stored"][12]["metadata"]
                    if name == "sequence":
                        value["sequence"] = previous["sequence"] + 1
                    else:
                        value["transition"]["revision"] = previous["revision"] + 1
                    expected = "member sequence/revision is not its independent transaction"
                with self.assertRaisesRegex(ValueError, expected):
                    protocol.publication(previous, candidate, before, after)

    def test_existing_outcomes_cannot_be_removed_rewritten_or_replaced_by_a_group(self):
        for removed in (False, True):
            _, previous, candidate, before, after = publication_fixture()
            if removed:
                after["entries"].pop(1)
            else:
                after["entries"][1]["outcome"]["result"] = "f" * 64
            with self.assertRaisesRegex(ValueError, "group removed retained identities" if removed
                                        else "group rewrote a retained identity"):
                protocol.publication(previous, candidate, before, after)

    def test_group_step_and_all_protected_authority_fields_remain_bound(self):
        mutations = {
            "one_serial_for_many_members": lambda head: head.update(head_serial=head["head_serial"] - 3),
            "one_revision_for_many_members": lambda head: head.update(revision=head["revision"] - 3),
            "owner": lambda head: head.update(owner_instance=9202),
            "owner_epoch": lambda head: head.update(owner_epoch=2),
            "auth_epoch": lambda head: head.update(auth_epoch=2),
            "policy": lambda head: head["policy"][0].update(write=False),
            "active": lambda head: head.update(active=False),
            "lifecycle": lambda head: head.update(lifecycle="maintenance"),
            "quota": lambda head: head["quota"].update(max_bytes=4096),
            "retention": lambda head: head["retention"].update(max_entries=4000),
            "epoch": lambda head: head.update(request_epoch=2),
            "storage": lambda head: head["storage"].update(allocated_through=2),
            "scope": lambda head: head["scope"].update(tenant=8),
            "creation": lambda head: head.update(creation={"operation": 100}),
            "deletion": lambda head: head.update(deletion={"kind": "delete"}),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                _, previous, candidate, before, after = publication_fixture()
                mutate(candidate)
                with self.assertRaisesRegex(ValueError, "group changed protected authority or final member root"):
                    protocol.publication(previous, candidate, before, after)

    def test_final_head_must_name_last_member_root_and_transition(self):
        for field in ("data_root", "transition"):
            _, previous, candidate, before, after = publication_fixture()
            candidate[field] = deepcopy(after["stored"][11]["metadata"][field])
            with self.assertRaisesRegex(ValueError, "group changed protected authority or final member root"):
                protocol.publication(previous, candidate, before, after)

    def test_receipt_proves_full_identity_original_bytes_and_intermediate_root(self):
        _, _, candidate, _, after = publication_fixture()
        stored = after["stored"][11]
        original = receipt(stored)
        self.assertNotEqual(original["data_root"], candidate["data_root"])
        changes = (
            ("scope", lambda value: value["scope"].update(tenant="8"), "receipt changed logical scope"),
            ("identity", lambda value: value["request"].update(id="12"), "receipt changed original full identity"),
            ("principal", lambda value: value["request"].update(principal="12"), "receipt changed original full identity"),
            ("fingerprint", lambda value: value["request"].update(fingerprint="f" * 64), "receipt changed original full identity"),
            ("transition", lambda value: value["transition"].update(revision="7"), "receipt changed independent transition"),
            ("sequence", lambda value: value.update(sequence="999"), "receipt differs from original stored result"),
            ("root", lambda value: value.update(data_root=candidate["data_root"]), "receipt differs from original stored result"),
            ("hash", lambda value: value.update(result_hash="f" * 64), "receipt differs from original stored result"),
        )
        for name, mutate, expected in changes:
            with self.subTest(name=name):
                changed = deepcopy(original)
                mutate(changed)
                with self.assertRaisesRegex(ValueError, expected):
                    protocol.receipt_matches(changed, stored["raw"], stored)
        with self.assertRaisesRegex(ValueError, "receipt differs from original stored result"):
            protocol.receipt_matches(original, after["stored"][12]["raw"], stored)

    def test_complete_closure_requires_real_hashed_frames_and_retained_result_lengths(self):
        frames, _, candidate, _, after = publication_fixture()
        for key in after["dependencies"]:
            with self.subTest(missing=key):
                objects = dict(frames.objects)
                objects.pop(key)
                with self.assertRaisesRegex(ValueError, "missing complete immutable dependency"):
                    protocol.closure(objects, candidate)
        objects = dict(frames.objects)
        key = PREFIX + after["stored"][11]["hash"]
        objects[key] = objects[key][:-1] + bytes([objects[key][-1] ^ 1])
        with self.assertRaisesRegex(ValueError, "immutable object body/key changed"):
            protocol.closure(objects, candidate)
        changed = deepcopy(candidate)
        changed["windows"][0]["result_bytes"] += 1
        with self.assertRaisesRegex(ValueError, "complete retained byte count changed"):
            protocol.closure(frames.objects, changed)

    def test_ordinary_activation_takeover_and_cancel_keep_the_single_step_rule(self):
        frames, previous, _, before, _ = publication_fixture()
        for nonce in (2, 2001, 2002, 72):
            with self.subTest(nonce=nonce):
                base, proof = deepcopy(previous), deepcopy(before)
                if nonce in (2, 2002):
                    base["active"] = False
                candidate = deepcopy(base)
                candidate.update(revision=base["revision"] + 1, head_serial=base["head_serial"] + 1,
                                 transition={"revision": base["revision"] + 1, "nonce": nonce})
                if nonce == 2001:
                    candidate.update(active=False, owner_epoch=base["owner_epoch"] + 1, owner_instance=9202)
                elif nonce == 72:
                    identity = {"epoch": 1, "id": 72, "principal": 11, "fingerprint": "7" * 64}
                    proof["entries"][72] = {"request": identity, "outcome": {"state": "cancelled",
                        "transition": candidate["transition"]}, "result_bytes": 0}
                    candidate["windows"][0]["count"] += 1
                else:
                    candidate["active"] = True
                self.assertEqual(protocol.publication(base, candidate, before, proof), [])
                candidate["head_serial"] += 1
                with self.assertRaisesRegex(ValueError, "ordinary control did not advance exactly once"):
                    protocol.publication(base, candidate, before, proof)


class GroupIntervalTests(unittest.TestCase):
    def test_every_member_is_queued_and_queue_full_refusal_precedes_actor_release(self):
        facts = interval_fixture()
        oracle.intervals(*facts)
        for phase in PHASES:
            for command in GROUPS[phase]:
                changed = deepcopy(facts)
                events, _, calls, by_command = changed
                released = oracle.one(events, "fault_released", id=phase + "_queue_gate")
                calls[by_command[command["id"]][0]]["request"]["monotonic_ns"] = released["monotonic_ns"] + 1
                with self.subTest(phase=phase, member=command["id"]), self.assertRaisesRegex(
                        ValueError, "group member was not queued before original actor release"):
                    oracle.intervals(*changed)
            changed = deepcopy(facts)
            events, _, calls, by_command = changed
            released = oracle.one(events, "fault_released", id=phase + "_queue_gate")
            calls[by_command[phase + "_overflow"][0]]["response"]["monotonic_ns"] = released["monotonic_ns"] + 1
            with self.subTest(phase=phase), self.assertRaisesRegex(
                    ValueError, "queue-full refusal did not precede group execution"):
                oracle.intervals(*changed)

    def test_gate_is_bound_to_original_head_get_and_cancel_wins_inside_the_hold(self):
        facts = interval_fixture()
        for field, value in (("method", "PUT"), ("path", HEAD + "/other"), ("worker", "restarted")):
            changed = deepcopy(facts)
            changed[1][0][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(
                    ValueError, "queue gate did not hold the original actor operation"):
                oracle.intervals(*changed)
        changed = deepcopy(facts)
        events, _, calls, by_command = changed
        release = oracle.one(events, "fault_released", id="group_candidate")
        calls[by_command["cancel_member"][0]]["response"]["monotonic_ns"] = release["monotonic_ns"] + 1
        with self.assertRaisesRegex(ValueError, "cancel did not win while original group CAS was held"):
            oracle.intervals(*changed)

    def test_overlap_can_linearize_without_inventing_response_order_as_cas_order(self):
        requests = {1: {"monotonic_ns": 10}, 2: {"monotonic_ns": 20}, 3: {"monotonic_ns": 30}}
        responses = {1: {"monotonic_ns": 100}, 2: {"monotonic_ns": 40}, 3: {"monotonic_ns": 80}}
        oracle.linearize(requests, responses, set(requests), {(1, 2), (2, 3)})
        requests[1]["monotonic_ns"] = 50
        with self.assertRaisesRegex(ValueError, "HEAD has no legal real-time linearization"):
            oracle.linearize(requests, responses, set(requests), {(1, 2), (2, 3)})

    def test_cycles_and_self_dependencies_cannot_validate_a_head_history(self):
        requests = {1: {"monotonic_ns": 10}, 2: {"monotonic_ns": 10}}
        responses = {1: {"monotonic_ns": 20}, 2: {"monotonic_ns": 20}}
        for edges, expected in (({(1, 1)}, "self-referential HEAD effect"),
                                ({(1, 2), (2, 1)}, "cyclic HEAD authority history")):
            with self.subTest(edges=edges), self.assertRaisesRegex(ValueError, expected):
                oracle.linearize(requests, responses, set(requests), edges)


class CounterfactualControlTests(unittest.TestCase):
    def test_full_inventory_rejects_extra_unobserved_work_and_changed_fault_rules(self):
        original = [{}, *inventory_fixture(), [], [], []]
        oracle.inventory(*original[1:5])
        names = ("unknown_original_event", "extra_offered_command", "extra_sdk_command",
                 "extra_armed_fault", "changed_fixed_fault_rule", "extra_s3_phase")
        for name in names:
            with self.subTest(name=name):
                changed, references = controls.raw_mutation(original, {}, name)
                outcome = controls.rejection(name, "synthetic-unit-row-mutation", controls.RAW_CASES[name],
                    lambda: oracle.inventory(*changed[1:5]), original, changed, references)
                self.assertEqual(outcome["status"], "passed", outcome)
                self.assertTrue(references)
        oracle.inventory(*original[1:5])

    def test_process_lifetimes_bound_both_sdk_and_actual_http_facts(self):
        for outside_sdk in (False, True):
            facts = inventory_fixture()
            if outside_sdk:
                facts[3][0]["monotonic_ns"] = "10001"
                expected = "SDK evidence escaped owned process lifetime"
            else:
                facts[0].append({"event": "http_request", "worker": "primary", "monotonic_ns": 10002})
                expected = "HTTP escaped owned worker lifetime"
            with self.subTest(sdk=outside_sdk), self.assertRaisesRegex(ValueError, expected):
                oracle.inventory(*facts)

    def test_projection_controls_fail_for_their_named_semantic_rules(self):
        _, previous, candidate, before, after = publication_fixture()
        original = {"previous": previous, "candidate": candidate, "before": before, "after": after}
        for name, expected in controls.PUBLICATION_CASES.items():
            with self.subTest(name=name):
                changed = controls.publication_mutation(original, name)
                outcome = controls.rejection(name, "synthetic-unit-projection", expected,
                    lambda: protocol.publication(**changed), original, changed, [])
                self.assertEqual(outcome["status"], "passed", outcome)
                self.assertEqual(outcome["additional_actual_executions"], 0)
        self.assertEqual(protocol.publication(**original)[-1]["metadata"]["request"]["id"], 14)

    def test_interval_controls_retain_original_facts_and_target_the_selected_boundary(self):
        original = interval_fixture()
        before = controls.digest(original)
        for name, expected in controls.INTERVAL_CASES.items():
            with self.subTest(name=name):
                changed = controls.interval_mutation(original, name)
                outcome = controls.rejection(name, "synthetic-unit-projection", expected,
                    lambda: oracle.intervals(*changed), original, changed, [])
                self.assertEqual(outcome["status"], "passed", outcome)
        self.assertEqual(controls.digest(original), before)
        oracle.intervals(*original)

    def test_accepted_mutations_wrong_rules_and_parser_exceptions_are_failed_controls(self):
        for error in (None, ValueError("another rule"), KeyError("target rule"), RuntimeError("target rule")):
            with self.subTest(error=error):
                def check():
                    if error is not None:
                        raise error
                outcome = controls.rejection("counterexample", "synthetic-unit-projection", "target rule",
                    check, {"original": True}, {"original": False}, [])
                self.assertEqual(outcome["status"], "failed")
                self.assertEqual(outcome["additional_actual_executions"], 0)
        with self.assertRaisesRegex(ValueError, "counterfactual did not change the audited facts"):
            controls.rejection("identity", "synthetic-unit-projection", "rule", lambda: None, {}, {}, [])


if __name__ == "__main__":
    unittest.main()
