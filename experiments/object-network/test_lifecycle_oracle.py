"""Negative controls for the offline oracle; synthetic observations, never S3 evidence."""

import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

import lifecycle_oracle as oracle


SCOPE = {"deployment": 7, "tenant": 1, "database": 1, "incarnation": 1, "generation": 1}
SQL = [{"sql": "INSERT INTO events VALUES(1,?,random()) RETURNING id,label,token",
        "parameters": [{"type": "text", "value": "LC-01-seed"}]}]
IDENTITY = {"epoch": 1, "id": 2, "principal": 17, "fingerprint": oracle.fingerprint(SQL)}


def encoded(statements):
    """Small literal wire builder used only to assemble corruptible test vectors."""
    raw = bytearray(b"SCAPRES1" + struct.pack("<I", len(statements)))
    for statement in statements:
        raw.extend(struct.pack("<I", len(statement["columns"])))
        for column in statement["columns"]:
            text = column.encode()
            raw.extend(struct.pack("<I", len(text)) + text)
        raw.extend(struct.pack("<I", len(statement["rows"])))
        for row in statement["rows"]:
            for value in row:
                if value is None:
                    raw.append(0)
                elif type(value) is int:
                    raw.extend(b"\1" + struct.pack("<q", value))
                elif type(value) is float:
                    raw.extend(b"\2" + struct.pack("<d", value))
                elif isinstance(value, str):
                    text = value.encode()
                    raw.extend(b"\3" + struct.pack("<I", len(text)) + text)
                else:
                    blob = bytes(value["blob"])
                    raw.extend(b"\4" + struct.pack("<I", len(blob)) + blob)
        raw.extend(struct.pack("<Qq", statement["affected_rows"], statement["last_insert_rowid"]))
    return list(raw)


def original():
    statements = [{"columns": ["id", "label", "token"], "rows": [[1, "LC-01-seed", -(2 ** 63)]],
                   "affected_rows": 1, "last_insert_rowid": 1}]
    value = {"receipt": {"scope": SCOPE, "request": IDENTITY, "sequence": 2,
                         "transition": {"revision": 5, "nonce": 2}, "data_root": "a" * 64,
                         "result_hash": "b" * 64},
             "result": {"encoded": encoded(statements), "statements": statements}}
    value["receipt"]["result_hash"] = oracle.result_hash(value["receipt"], value["result"]["encoded"])
    return value


def empty_data():
    return {"plan": {}, "inputs": [], "clients": [], "acks": [], "facts": [], "history": [], "build": {}}


def inventory_data():
    """Only an inventory unit fixture; intentionally not a full twelve-case run."""
    data = empty_data()
    data["plan"] = {"version": 1, "case_ids": oracle.CASE_IDS, "fixture_limits": oracle.PROFILE,
                    "s3_timeout_ms": 8000, "aws_endpoint_gate": "NOT_RUN",
                    "production_slo_passed": False, "unit_coverage_contribution": False,
                    "cases": [{"id": case, "scope": {**SCOPE, "database": index},
                               "head_key": f"scap-object/v1/7/1/{index}/head"}
                              for index, case in enumerate(oracle.CASE_IDS, 1)]}
    data["facts"] = [{"event": "worker_started", "case": "LC-01", "worker": 101,
                      "principal": 17, "scope": SCOPE, "identity": {}}]
    intent = {"event": "input", "intent_id": "LC-01/seed", "case": "LC-01", "name": "seed",
              "scope": SCOPE, "principal": 17, "epoch": 1, "id": 2, "statements": SQL, "monotonic_ns": 1}
    data["inputs"] = [intent, {"event": "prepared", "intent_id": "LC-01/seed", "identity": IDENTITY, "monotonic_ns": 6}]
    for call_id, label, op, started, observed, result in (
        (1, "prepare.seed", "prepare_request", 2, 5, IDENTITY),
        (2, "seed", "execute", 7, 10, original()),
        (3, "repeat", "execute", 12, 15, original()),
    ):
        command = {"op": op, "epoch": 1, "id": 2, "statements": SQL}
        call = {"event": "call", "call_id": call_id, "case": "LC-01", "label": label,
                "phase": "LC-01/" + label, "worker": 101, "principal": 17, "scope": SCOPE,
                "intent_id": "LC-01/seed", "command": command, "monotonic_ns": started}
        response = {"ok": True, "value": result}
        data["clients"].extend([call, {"event": "response", "call_id": call_id, "response": response,
                                      "monotonic_ns": observed}])
        data["history"].extend([
            {"event": "client_invoked", "worker": 101, "operation": op, "request_id": 2, "monotonic_ns": started + 1},
            {"event": "client_observed", "worker": 101, "operation": op, "ok": True, "error": None, "monotonic_ns": observed - 1}])
        if op == "execute":
            data["acks"].append({"event": "ack", "call_id": call_id, "case": "LC-01", "intent_id": "LC-01/seed",
                                 "response": response, "observed_ns": observed, "monotonic_ns": observed + 1})
    return copy.deepcopy(data)


def race_fixture(commit_first=False, cancel=False):
    path = "/scap-test/scap-object/v1/7/1/1/head"
    before = list(json.dumps({"format": 2, "revision": 5, "scope": SCOPE}).encode())
    candidate_bytes = list(json.dumps({"format": 2, "revision": 6, "scope": SCOPE}).encode())
    barrier_bytes = list(json.dumps({"format": 2, "revision": 7, "scope": SCOPE}).encode())
    history = []

    def fields(serial, phase, method, body, etag=None):
        return {"request_serial": serial, "phase": phase, "method": method, "path": path,
                "head_request_bytes": body, "request_bytes": len(body), "request_sha256": hashlib.sha256(bytes(body)).hexdigest(),
                "if_match": etag, "if_none_match": None}

    old_read = fields(1, "LC-01/candidate", "GET", [])
    candidate = fields(2, "LC-01/candidate", "PUT", candidate_bytes, '"old"')
    control = fields(3, "LC-01/barrier", "GET" if cancel else "PUT", [] if cancel else barrier_bytes, None if cancel else '"new"')

    def event(kind, source, when, **values):
        history.append({"event": kind, **source, "monotonic_ns": when, **values})

    def response(source, when, status, body=None, etag=None):
        raw = [] if body is None else body
        event("object_response", source, when, status=status, response_origin="backend", etag=etag,
              head_response_bytes=raw, response_sha256=hashlib.sha256(bytes(raw)).hexdigest(), suppressed=False)

    event("object_request", old_read, 11); event("object_forwarded", old_read, 12)
    response(old_read, 13, 200, before, '"old"')
    event("object_request", candidate, 40)
    if commit_first:
        event("object_forwarded", candidate, 41); response(candidate, 42, 200, etag='"new"')
    stage = "after_upstream_response" if commit_first else "before_forward"
    event("transport_fault_observed", candidate, 45, mode="hold", stage=stage)
    event("object_request", control, 60); event("object_forwarded", control, 61)
    response(control, 62, 200, candidate_bytes if cancel else [], '"new"' if cancel else '"control"')
    event("object_response_delivered", control, 63, status=200)
    if not commit_first:
        event("object_forwarded", candidate, 71); response(candidate, 72, 412)
    event("object_response_delivered", candidate, 73, status=200 if commit_first else 412)
    return {"history": history,
            "candidate": {"label": "candidate", "phase": "LC-01/candidate", "monotonic_ns": 10},
            "barrier": {"label": "barrier", "phase": "LC-01/barrier", "monotonic_ns": 50},
            "boundary": {"payload": candidate_bytes, "observation": {"request_serial": 2, "if_match": '"old"'}, "monotonic_ns": 46},
            "release": {"request_serial": 2, "monotonic_ns": 70}}


def check_race(data, commit_first=False, cancel=False):
    return oracle.race_order(oracle.Network(data["history"]), data["candidate"], data["barrier"],
                             data["boundary"], data["release"], commit_first=commit_first, cancel_observation=cancel)


class WireAndOriginalTests(unittest.TestCase):
    def test_whole_result_frame_has_a_fixed_digest_and_binds_all_bytes(self):
        receipt = {"scope": {"deployment": 1, "tenant": 2, "database": 3, "incarnation": 4, "generation": 5},
                   "request": {"epoch": 1, "id": 9, "principal": 17, "fingerprint": "f" * 64}, "sequence": 2,
                   "transition": {"revision": 3, "nonce": 9}, "data_root": "a" * 64, "result_hash": "0" * 64}
        raw = list(b"SCAPRES1\0\0\0\0")
        self.assertEqual(oracle.result_hash(receipt, raw), "525fe7e71f298e4793df34b35d0c9d3b8733527a19f9b893fec9238676a28a6e")
        self.assertNotEqual(oracle.result_hash(receipt, raw), hashlib.sha256(bytes(raw)).hexdigest())
        value = original()
        value["result"]["statements"][0]["rows"][0][2] += 1
        value["result"]["encoded"] = encoded(value["result"]["statements"])
        with self.assertRaisesRegex(ValueError, "Result digest"):
            oracle.validate_original(value)

    def test_fixed_scap_sql1_vector_and_exact_parameter_order(self):
        vector = [{"sql": "SELECT ?1", "parameters": [{"type": "integer", "value": 42}]}]
        self.assertEqual(oracle.fingerprint(vector), "b54f2e7183aec5e5afd80dd1f40ac21b6db3232b0070936ca8d1eb905ac3d5bb")
        text = [{"sql": "SELECT ?,?", "parameters": [{"type": "text", "value": "原\0结果"}, {"type": "real", "value": -0.0}]}]
        changed = copy.deepcopy(text); changed[0]["parameters"].reverse()
        self.assertNotEqual(oracle.fingerprint(text), oracle.fingerprint(changed))
        changed = copy.deepcopy(text); changed[0]["parameters"][1]["value"] = 0.0
        self.assertNotEqual(oracle.fingerprint(text), oracle.fingerprint(changed))
        for value in (float("nan"), float("inf"), True):
            with self.assertRaises(ValueError):
                oracle.fingerprint([{"sql": "SELECT ?", "parameters": [{"type": "real", "value": value}]}])

    def test_fixed_result_vector_and_all_wire_value_kinds(self):
        fixed = list(b"SCAPRES1\1\0\0\0\1\0\0\0\1\0\0\0x\1\0\0\0\1" + struct.pack("<qQq", 42, 0, 0))
        self.assertEqual(oracle.decoded_result(fixed), [{"columns": ["x"], "rows": [[42]], "affected_rows": 0, "last_insert_rowid": 0}])
        statements = [{"columns": ["same"] * 5, "rows": [[None, -(2 ** 63), -0.0, "原\0结果", {"blob": [0, 255]}]],
                       "affected_rows": 2 ** 64 - 1, "last_insert_rowid": 2 ** 63 - 1}]
        self.assertEqual(oracle.canonical(oracle.decoded_result(encoded(statements))), oracle.canonical(statements))
        self.assertEqual(oracle.decoded_result(list(b"SCAPRES1\0\0\0\0")), [])

    def test_truncated_trailing_unknown_utf8_nonfinite_and_bomb_results_fail(self):
        good = encoded([{"columns": ["x"], "rows": [[0.0]], "affected_rows": 0, "last_insert_rowid": 0}])
        bad = [good[:-1], good + [0], list(b"SCAPRES1garbage"), list(b"SCAPRES2\0\0\0\0"),
               list(b"SCAPRES1\xff\xff\xff\xff")]
        wrong_tag = good.copy(); wrong_tag[25] = 9; bad.append(wrong_tag)
        nan = good.copy(); nan[26:34] = struct.pack("<d", float("nan")); bad.append(nan)
        utf8 = good.copy(); utf8[20] = 255; bad.append(utf8)
        for result in bad:
            with self.subTest(result=result), self.assertRaises((ValueError, UnicodeDecodeError)):
                oracle.decoded_result(result)

    def test_complete_receipt_bytes_and_typed_result_cannot_be_reduced_to_hash(self):
        source = original()
        lookup = {"state": "committed", "receipt": copy.deepcopy(source["receipt"]), "encoded": source["result"]["encoded"]}
        oracle.original_matches(source, lookup)
        oracle.original_matches(source, copy.deepcopy(source), replay=True)
        for field in oracle.RECEIPT_FIELDS:
            changed = copy.deepcopy(lookup); changed["receipt"][field] = None
            with self.subTest(field=field), self.assertRaises(ValueError): oracle.original_matches(source, changed)
        for payload in ([0], source["result"]["encoded"] + [0], {"sha256": "b" * 64}):
            changed = {**lookup, "encoded": payload}
            with self.assertRaises(ValueError): oracle.original_matches(source, changed)
        altered = copy.deepcopy(source); altered["result"]["statements"][0]["rows"][0][2] += 1
        with self.assertRaises(ValueError): oracle.original_matches(altered, altered, replay=True)
        garbage = copy.deepcopy(source); garbage["result"]["encoded"] = list(b"SCAPRES1garbage")
        with self.assertRaises(ValueError): oracle.original_matches(garbage, garbage, replay=True)

    def test_duplicate_acks_do_not_duplicate_expected_effects(self):
        checker = oracle.Audit(empty_data())
        checker.intents = {"LC-01/seed": {"name": "seed"}}
        checker.acks = [{"case": "LC-01", "intent_id": "LC-01/seed", "response": {"value": original()}}] * 3
        self.assertEqual(oracle.expected_rows("LC-01", checker.originals_for("LC-01")), [[1, "LC-01-seed", -(2 ** 63)]])
        changed = original(); changed["result"]["statements"][0]["rows"][0][1] = "wrong input"
        with self.assertRaises(ValueError): oracle.expected_rows("LC-01", {"seed": changed})


class InventoryTests(unittest.TestCase):
    def test_all_success_responses_and_duplicate_ack_observations_are_counted(self):
        checker = oracle.Audit(inventory_data()); checker.inventory()
        self.assertEqual(len(checker.acks), 2)
        self.assertEqual(len(checker.originals), 1)

    def test_missing_extra_changed_and_jointly_removed_ack_records_fail(self):
        mutations = []
        data = inventory_data(); data["acks"].pop(); mutations.append(data)
        data = inventory_data(); data["acks"].append(copy.deepcopy(data["acks"][0])); mutations.append(data)
        data = inventory_data(); data["acks"][0]["case"] = "LC-02"; mutations.append(data)
        data = inventory_data(); data["clients"] = data["clients"][:-2]; data["acks"].pop(); mutations.append(data)
        data = inventory_data(); data["acks"][0]["response"]["value"]["result"]["encoded"][-1] ^= 1; mutations.append(data)
        data = inventory_data(); data["clients"][2]["command"]["statements"] = [{"sql": "SELECT 9"}]; mutations.append(data)
        data = inventory_data(); data["inputs"][1]["identity"]["fingerprint"] = "0" * 64; mutations.append(data)
        for index, data in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises(ValueError): oracle.Audit(data).inventory()

    def test_inventory_alone_cannot_report_twelve_real_cases_passed(self):
        with self.assertRaises(ValueError): oracle.Audit(inventory_data()).run()

    def test_unknown_retired_closed_cancelled_are_not_interchangeable(self):
        checker = oracle.Audit(empty_data())
        call = {"call_id": 1, "case": "LC-11", "label": "outcome", "phase": "x"}
        checker.labels["LC-11", "outcome"] = call
        for actual in ("unknown", "retired", "closed", "cancelled"):
            checker.responses[1] = {"response": {"ok": True, "value": {"state": actual}}}
            for expected in ("unknown", "retired", "closed", "cancelled"):
                if actual != expected:
                    with self.subTest(actual=actual, expected=expected), self.assertRaises(ValueError):
                        checker.state("LC-11", "outcome", expected)
        checker.responses[1] = {"response": {"ok": False, "error": "Store(Unknown)"}}
        with self.assertRaises(ValueError): checker.failure("LC-11", "outcome", "Conflict")

    def test_first_execute_ack_requires_real_publication_not_assumed_replay(self):
        checker = oracle.Audit(inventory_data()); checker.inventory()
        with self.assertRaisesRegex(ValueError, "first execute ACK"):
            checker.transitions()


def network_checker():
    checker = oracle.Audit(empty_data())
    path = "/scap-test/scap-object/v1/7/1/1/head"
    serial = 0
    def exchange(phase, method, when, payload, etag=None, previous=None):
        nonlocal serial
        serial += 1
        request_bytes = payload if method == "PUT" else []
        fields = {"request_serial": serial, "phase": phase, "method": method, "path": path,
                  "head_request_bytes": request_bytes, "request_bytes": len(request_bytes),
                  "request_sha256": hashlib.sha256(bytes(request_bytes)).hexdigest(),
                  "if_match": previous, "if_none_match": "*" if method == "PUT" and previous is None else None}
        checker.history.append({"event": "object_request", "monotonic_ns": when, **fields})
        checker.history.append({"event": "object_forwarded", "monotonic_ns": when + 1, **fields})
        response_bytes = payload if method == "GET" else []
        response = {"status": 200, "response_origin": "backend", "etag": etag,
                    "head_response_bytes": response_bytes, "response_sha256": hashlib.sha256(bytes(response_bytes)).hexdigest()}
        checker.history.append({"event": "object_response", "monotonic_ns": when + 2, **fields, **response})
        checker.history.append({"event": "object_response_delivered", "monotonic_ns": when + 3, **fields, **response})
    heads = [list(json.dumps({"format": 2, "scope": SCOPE, "revision": number}).encode()) for number in (1, 2, 3)]
    for index, label, operation in ((1, "create", "create"), (2, "takeover", "takeover"), (3, "activate", "activate")):
        start = 10 * index
        phase = "LC-01/" + label
        checker.calls[index] = {"call_id": index, "case": "LC-01", "label": label, "phase": phase,
                                "scope": SCOPE, "command": {"op": operation}, "monotonic_ns": start}
        checker.responses[index] = {"monotonic_ns": start + 9}
        if index > 1:
            exchange(phase, "GET", start + 1, heads[index - 2], etag=str(index - 1))
        exchange(phase, "PUT", start + 5, heads[index - 1], etag=str(index), previous=str(index - 1) if index > 1 else None)
    checker.network = oracle.Network(checker.history)
    return checker


class NetworkOrderTests(unittest.TestCase):
    def test_global_head_history_has_no_omitted_transition_or_orphan_request(self):
        network_checker().network_bindings()
        checker = network_checker()
        checker.calls.pop(2)
        checker.responses.pop(2)
        checker.history = [row for row in checker.history if row["phase"] != "LC-01/takeover"]
        checker.network = oracle.Network(checker.history)
        with self.assertRaisesRegex(ValueError, "missing/refreshed predecessor|unobserved authority revision"):
            checker.network_bindings()
        checker = network_checker()
        orphan = copy.deepcopy(checker.history[0]); orphan["request_serial"] = 100; orphan["phase"] = "unrecorded"
        checker.history.append(orphan)
        checker.network = oracle.Network(checker.history)
        with self.assertRaisesRegex(ValueError, "outside a recorded invocation"):
            checker.network_bindings()

    def test_control_first_commit_first_and_committed_cancel_observation(self):
        check_race(race_fixture())
        check_race(race_fixture(True), True)
        check_race(race_fixture(True, True), True, True)

    def test_missing_fake_injected_wrong_status_and_wrong_order_412_fail(self):
        mutations = []
        data = race_fixture(); data["history"] = [row for row in data["history"] if not (row["event"] == "object_response" and row["request_serial"] == 2)]; mutations.append(data)
        for key, value in (("response_origin", "proxy"), ("status", 409), ("status", 200)):
            data = race_fixture()
            next(row for row in data["history"] if row["event"] == "object_response" and row["request_serial"] == 2)[key] = value
            mutations.append(data)
        data = race_fixture(); data["history"].append({**data["history"][3], "event": "injected_response", "status": 412}); mutations.append(data)
        data = race_fixture(); forward = next(row for row in data["history"] if row["event"] == "object_forwarded" and row["request_serial"] == 2)
        data["history"].remove(forward); data["history"].insert(5, forward); mutations.append(data)
        for data in mutations:
            with self.assertRaises(ValueError): check_race(data)

    def test_original_condition_same_get_bytes_and_saved_candidate_are_required(self):
        for mutation in ("condition", "get_etag", "get_bytes", "saved_bytes", "retry", "early_delivery"):
            data = race_fixture()
            if mutation == "condition":
                for row in data["history"]:
                    if row["request_serial"] == 2: row["if_match"] = None
            elif mutation == "get_etag":
                next(row for row in data["history"] if row["event"] == "object_response" and row["request_serial"] == 1)["etag"] = '"new"'
            elif mutation == "get_bytes":
                next(row for row in data["history"] if row["event"] == "object_response" and row["request_serial"] == 1)["head_response_bytes"] = [0]
            elif mutation == "saved_bytes": data["boundary"]["payload"] = [0]
            elif mutation == "retry":
                data["history"].append({**data["history"][3], "request_serial": 99, "if_match": '"fresh"'})
            else: data["release"]["monotonic_ns"] = 100
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): check_race(data)

    def test_network_path_phase_and_call_interval_are_not_optional(self):
        for mutation in ("path", "phase", "time"):
            data = race_fixture()
            checker = oracle.Audit(empty_data())
            checker.history = data["history"]
            candidate = {**data["candidate"], "call_id": 1, "scope": SCOPE, "command": {"op": "execute"}}
            barrier = {**data["barrier"], "call_id": 2, "scope": SCOPE, "command": {"op": "set_lifecycle"}}
            checker.calls = {1: candidate, 2: barrier}
            checker.responses = {1: {"monotonic_ns": 80}, 2: {"monotonic_ns": 65}}
            if mutation == "path":
                for row in checker.history: row["path"] = row["path"].replace("/7/1/1/", "/7/1/999/")
            elif mutation == "phase": checker.history[0]["phase"] = "unrecorded"
            else: checker.history[0]["monotonic_ns"] = 1
            checker.network = oracle.Network(checker.history)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): checker.network_bindings()

    def test_tombstone_cannot_be_reactivated_with_a_successful_control(self):
        data = race_fixture()
        before = {"format": 2, "revision": 5, "scope": SCOPE, "lifecycle": "deleted"}
        after = {"format": 2, "revision": 6, "scope": SCOPE, "lifecycle": "ready"}
        for row in data["history"]:
            if row["request_serial"] == 1 and row["event"] == "object_response":
                row["head_response_bytes"] = list(json.dumps(before).encode())
                row["response_sha256"] = hashlib.sha256(bytes(row["head_response_bytes"])).hexdigest()
            if row["request_serial"] == 2:
                row["head_request_bytes"] = list(json.dumps(after).encode())
                row["request_sha256"] = hashlib.sha256(bytes(row["head_request_bytes"])).hexdigest()
                if row["event"] == "object_response": row["status"] = 200
        checker = oracle.Audit(empty_data())
        checker.calls = {1: {**data["candidate"], "call_id": 1, "command": {"op": "set_lifecycle"}}}
        checker.responses = {1: {"response": {"ok": True, "value": after}}}
        checker.network = oracle.Network(data["history"])
        with self.assertRaisesRegex(ValueError, "deleted identity"): checker.transitions()


def process_checker():
    """Fixed process observations only; no SQLite or authority algorithm double."""
    checker = oracle.Audit(empty_data())
    checker.plan = {"binary_sha256": "a" * 64, "input_sha256": "b" * 64}
    checker.data["build"] = {"status": "passed", "profile": "release", "native_archives": {"libsql.a": "c" * 64},
                             "binary": {"sha256": "a" * 64}, "input_sha256": "b" * 64}
    checker.workers = {}

    def fact(case, event, when, **values):
        checker.facts.append({"event": event, "case": case, "monotonic_ns": when, **values})

    def worker(case, number, started, ended):
        identity = {"pid": number + 1000, "spawn_monotonic_ns": started - 1, "pid_source": "owned_Popen_child",
                    "self_proc_pid": number + 10000, "self_start_ticks": number + 100000}
        record = {"event": "worker_started", "case": case, "worker": number, "principal": 17,
                  "scope": SCOPE, "identity": identity, "monotonic_ns": started + 1}
        checker.facts.append(record)
        checker.workers[number] = record
        checker.history.append({"event": "worker_started", "worker": number, "monotonic_ns": started, **identity})
        stopped = {"worker": number, **identity, "wait_status": -9,
                   "kernel_usage": {"available": True, "source": "kernel_wait4_owned_child", "maxrss_bytes": 8192}}
        checker.history.append({"event": "worker_stopped", "fault": True, "monotonic_ns": ended, **stopped})
        return stopped

    def recovery(case, stage, number, started):
        fact(case, "recovery_started", started + 2, stage=stage, worker=number)
        call_id = len(checker.calls) + 1
        checker.calls[call_id] = {"call_id": call_id, "case": case, "worker": number,
                                  "label": stage + ".rows", "monotonic_ns": started + 3}
        checker.responses[call_id] = {"monotonic_ns": started + 4,
                                      "response": {"resources": {"namespace_pid": number + 1000,
                                                                  "proc_pid": number + 10000,
                                                                  "start_ticks": number + 100000}}}

    for index, case in enumerate(oracle.CASE_IDS, 1):
        base = 100 * index
        first = worker(case, index * 10, base, base + 10)
        fact(case, "compute_lost", base + 11, stage="compute_recovery", stopped=[first], existed_before=True, exists_after=False)
        second = worker(case, index * 10 + 1, base + 20, base + 30)
        recovery(case, "compute_recovery", index * 10 + 1, base + 20)
        fact(case, "compute_lost", base + 31, stage="before_backend", stopped=[second], existed_before=True, exists_after=False)
        third = worker(case, index * 10 + 2, base + 3000, base + 3010)
        recovery(case, "backend_recovery", index * 10 + 2, base + 3000)
        fact(case, "compute_lost", base + 3011, stage="final_cleanup", stopped=[third], existed_before=True, exists_after=False)
    roles = ["master", "volume", "filer", "s3"]
    old = [{"role": role, "pid": 500 + index, "spawn_monotonic_ns": 1, "pid_source": "owned_Popen_child"}
           for index, role in enumerate(roles)]
    new = [{"role": role, "pid": 600 + index, "spawn_monotonic_ns": 2015, "pid_source": "owned_Popen_child"}
           for index, role in enumerate(roles)]
    def dead(items):
        return [{**item, "wait_status": -9, "kernel_usage": {"available": True, "source": "kernel_wait4_owned_child"}}
                for item in items]
    fact(None, "backend_started", 5, identities=old)
    fact(None, "backend_stopping", 2000, live_compute_workers=0)
    fact(None, "backend_stopped", 2010, identities=dead(old), live_compute_workers=0)
    fact(None, "backend_restarted", 2020, identities=new)
    fact(None, "backend_cleanup", 5000, identities=dead(new))
    fact(None, "build_verified", 2, stage="before", **checker.plan)
    fact(None, "build_verified", 5010, stage="after", **checker.plan)
    fact(None, "cleanup_observed", 5020, proxy_errors=[], cleanup_errors=[])
    return checker


class ProcessEvidenceTests(unittest.TestCase):
    def test_both_actual_loss_cycles_new_workers_backend_restart_and_final_exit_are_required(self):
        process_checker().process_and_build()

    def test_backend_restart_cannot_be_moved_after_recovery_or_before_compute_loss(self):
        checker = process_checker()
        checker.fact(None, "backend_restarted")["monotonic_ns"] = 9000
        with self.assertRaisesRegex(ValueError, "recovery preceded actual restart"): checker.process_and_build()
        checker = process_checker()
        checker.fact("LC-01", "compute_lost", stage="before_backend")["monotonic_ns"] = 2005
        with self.assertRaisesRegex(ValueError, "backend cut preceded complete compute loss"): checker.process_and_build()

    def test_worker_facts_must_match_original_start_wait4_and_actual_recovery_calls(self):
        checker = process_checker()
        checker.workers[10]["identity"]["pid"] += 1
        with self.assertRaisesRegex(ValueError, "start identities differ"): checker.process_and_build()
        checker = process_checker()
        loss = checker.fact("LC-01", "compute_lost", stage="compute_recovery")
        loss["stopped"][0] = copy.deepcopy(loss["stopped"][0])
        loss["stopped"][0]["kernel_usage"]["maxrss_bytes"] += 1
        with self.assertRaisesRegex(ValueError, "wait4/identity facts differ"): checker.process_and_build()
        checker = process_checker()
        checker.fact("LC-01", "recovery_started", stage="compute_recovery")["worker"] = 10
        with self.assertRaisesRegex(ValueError, "different worker from actual calls"): checker.process_and_build()
        checker = process_checker()
        checker.responses[1]["response"]["resources"]["namespace_pid"] = 1
        with self.assertRaisesRegex(ValueError, "another process"): checker.process_and_build()

    def test_missing_cache_deletion_or_final_backend_exit_cannot_pass(self):
        checker = process_checker()
        checker.fact("LC-01", "compute_lost", stage="final_cleanup")["exists_after"] = True
        with self.assertRaisesRegex(ValueError, "directory deletion"): checker.process_and_build()
        checker = process_checker()
        checker.fact(None, "backend_cleanup")["identities"][0]["wait_status"] = 0
        with self.assertRaisesRegex(ValueError, "final backend process exit"): checker.process_and_build()


class ReadOnlyEntrypointTests(unittest.TestCase):
    def test_missing_duplicate_key_and_partial_json_evidence_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            before = list(path.iterdir())
            self.assertEqual(oracle.audit(path)["status"], "failed")
            self.assertEqual(list(path.iterdir()), before)
            for raw in (b'{"version":1,"version":1}\n', b'{"version":1}'):
                (path / "lifecycle-plan.json").write_bytes(raw)
                self.assertEqual(oracle.audit(path)["status"], "failed")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(oracle.main(["--evidence", directory]), 1)
            self.assertEqual([item.name for item in path.iterdir()], ["lifecycle-plan.json"])


if __name__ == "__main__":
    unittest.main()
