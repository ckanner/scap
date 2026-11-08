"""Hand-built wire witnesses and negative controls; never real S3 acceptance."""
from __future__ import annotations

import ast
import copy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest

import catalogue_oracle as oracle


def raw(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def intent(operation=41, name="目录-fixture", previous=None):
    return {"creator": 17, "operation": operation, "name": name,
            "scope": oracle.derive_scope(7, 1, 17, operation), "expected_name_revision": previous}


def descriptor(c):
    return {"format": 1, "creation": c, "options": {"quota": {"kind": "default"}},
            "initial_quota": {"max_bytes": 4194304},
            "retention": {"max_entries": 32, "max_result_bytes": 134217728}}


def binding(c, state="reserved", control=None, proof=None):
    return {"format": 1, "creation": c, "origin": oracle.origin(descriptor(c), raw(descriptor(c))),
            "revision": (c["expected_name_revision"] or 0) + {"reserved": 1, "bound": 2, "aborting": 2, "tombstone": 3}[state],
            "state": state, "control": control, "proof": proof}


def initial_head(c, *, named=True, lifecycle="provisioning", nonce=None, changed_scope=None):
    return {"format": 3, "scope": changed_scope or c["scope"], "revision": 1,
            "transition": {"revision": 1, "nonce": nonce or c["operation"]}, "sequence": 0,
            "owner_epoch": 1, "owner_instance": 50001, "active": False, "auth_epoch": 1,
            "policy": [{"principal": 17, "read": True, "write": True, "admin": True}],
            "lifecycle": lifecycle, "creation": oracle.origin(descriptor(c), raw(descriptor(c))) if named else None,
            "deletion": None, "data_root": oracle.digest(b"manifest"), "quota": {"max_bytes": 4194304},
            "retention": {"max_entries": 32, "max_result_bytes": 134217728}, "request_epoch": 1,
            "windows": [{"epoch": 1, "root": oracle.digest(b"index"), "count": 0, "result_bytes": 0}]}


def control(c, kind="abort", principal=17):
    return {"format": 1, "creation": c, "origin": oracle.origin(descriptor(c), raw(descriptor(c))),
            "kind": kind, "principal": principal, "operation": 77,
            "expected_name_revision": (c["expected_name_revision"] or 0) + (1 if kind == "abort" else 2),
            "expected_head_revision": None if kind == "abort" else 2, "nonce": 88}


class Trace:
    """A handwritten backend history, unrelated to controller or model code."""
    def __init__(self):
        self.time = 10
        self.serial = 0
        self.stored = {}
        self.a = SimpleNamespace(history=[], facts=[], calls={}, phases={}, ends={}, lost={})
        self.a.prepared_creation = lambda call: intent(call["command"]["input"]["operation"], call["command"]["input"]["name"], call["command"]["input"]["expected_name_revision"])
        self.a.control_for = lambda call: {"format": 1, **call["command"]["input"],
            "origin": oracle.origin(descriptor(call["command"]["input"]["creation"]), raw(descriptor(call["command"]["input"]["creation"]))),
            "kind": call["command"]["op"].split("_")[-1], "principal": call["principal"],
            "expected_head_revision": call["command"]["input"].get("expected_head_revision")}

    def event(self, event, **values):
        self.time += 10
        row = {"event": event, "monotonic_ns": self.time, **copy.deepcopy(values)}
        self.a.history.append(row)
        return row

    def begin(self, c, op, **values):
        self.time += 10
        number = len(self.a.calls) + 1
        call = {"call_id": number, "phase": "unit/call" + str(number), "case": "unit", "label": "call" + str(number),
                "worker": 50001, "principal": 17, "scope": c["scope"], "monotonic_ns": self.time,
                "command": {"op": op, **values}}
        self.a.calls[number] = call; self.a.phases[call["phase"]] = call
        return call

    def end(self, call):
        self.time += 10
        self.a.ends[call["call_id"]] = {"monotonic_ns": self.time}

    def exchange(self, call, method, path, body=b"", *, status=None, etag=None, condition=None, returned=None):
        self.serial += 1
        stored = self.stored.get(path)
        if status is None: status = 200 if method == "PUT" or stored else 404
        if method == "PUT":
            condition = condition if condition is not None else (stored[0] if stored else "*")
            if status == 200:
                etag = etag or f'"version-{self.serial}"'
                self.stored[path] = (etag, body)
            returned = b"" if returned is None else returned
        else:
            etag = etag if etag is not None else (stored[0] if stored and status == 200 else None)
            returned = returned if returned is not None else (stored[1] if stored and status == 200 else b"missing")
        fields = {"request_serial": self.serial, "phase": call["phase"], "method": method, "path": path,
                  "request_bytes": len(body), "request_sha256": oracle.digest(body),
                  "if_none_match": "*" if condition == "*" else None, "if_match": condition if condition not in (None, "*") else None}
        prefix = "head" if path.endswith("/head") else "catalogue" if "/catalogue/v1/" in path else None
        if prefix: fields[prefix + "_request_bytes"] = list(body)
        request = self.event("object_request", **fields)
        self.event("object_forwarded", **fields)
        received = {"status": status, "etag": etag, "response_bytes": len(returned), "response_sha256": oracle.digest(returned)}
        if prefix: received[prefix + "_response_bytes"] = list(returned)
        self.event("object_response", **fields, **received, response_origin="backend", suppressed=False)
        self.event("object_response_delivered", **fields, **received)
        return request

    def get(self, call, path): return self.exchange(call, "GET", path)

    def put(self, call, path, value, **options):
        return self.exchange(call, "PUT", path, value if isinstance(value, bytes) else raw(value), **options)

    def prepare(self, c):
        call = self.begin(c, "catalogue_prepare", input={"name": c["name"], "operation": c["operation"],
                          "expected_name_revision": c["expected_name_revision"], "options": {"quota": {"kind": "default"}}})
        self.put(call, oracle.descriptor_path(c), descriptor(c))
        self.get(call, oracle.descriptor_path(c)); self.end(call)

    def view(self, call, c):
        self.get(call, oracle.name_path(c)); self.get(call, oracle.proof_path(c))
        self.get(call, oracle.head_path(c["scope"]))
        if self.stored.get(oracle.head_path(c["scope"])):
            h = json.loads(self.stored[oracle.head_path(c["scope"])][1])
            if h.get("creation"):
                self.get(call, oracle.base(c["scope"]) + f"/catalogue/v1/create/{h['creation']['creator']}/{h['creation']['operation']}")
        self.get(call, oracle.name_path(c))

    def roots(self, call, s):
        for content in (b"manifest", b"index"):
            path = oracle.object_prefix(s) + oracle.digest(content)
            if path not in self.stored: self.put(call, path, content)
            self.get(call, path)

    def resume(self, c, *, until="ready"):
        call = self.begin(c, "catalogue_resume", creation=c)
        self.get(call, oracle.descriptor_path(c)); self.view(call, c)
        self.put(call, oracle.name_path(c), binding(c))
        if until == "reserved": self.end(call); return
        self.view(call, c); self.roots(call, c["scope"])
        head = initial_head(c)
        self.put(call, oracle.head_path(c["scope"]), head)
        if until == "provisioning": self.end(call); return
        self.view(call, c); self.put(call, oracle.name_path(c), binding(c, "bound"))
        if until == "bound": self.end(call); return
        self.view(call, c); self.roots(call, c["scope"])
        head.update(revision=2, transition={"revision": 2, "nonce": c["operation"]}, lifecycle="ready")
        self.put(call, oracle.head_path(c["scope"]), head); self.end(call)

    def abort(self, c, *, until="tombstone", foreign=False):
        ctl = control(c)
        inputs = {key: ctl[key] for key in ("creation", "operation", "expected_name_revision", "nonce")}
        call = self.begin(c, "catalogue_abort", input=inputs)
        self.get(call, oracle.descriptor_path(c)); self.get(call, oracle.control_path(ctl))
        self.put(call, oracle.control_path(ctl), ctl); self.get(call, oracle.control_path(ctl))
        self.view(call, c); self.put(call, oracle.name_path(c), binding(c, "aborting", ctl))
        if until == "aborting": self.end(call); return
        self.view(call, c)
        if foreign:
            h = json.loads(self.stored[oracle.head_path(c["scope"])][1])
            barrier = {"kind": "foreign_occupied", "scope": h["scope"], "creation": h["creation"]}
        else:
            old = self.stored.get(oracle.head_path(c["scope"]))
            if old:
                head = json.loads(old[1]); head["revision"] += 1; head["owner_epoch"] += 1
                head["transition"] = {"revision": head["revision"], "nonce": ctl["nonce"]}
                head["lifecycle"] = "deleted"
            else:
                self.roots(call, c["scope"])
                head = initial_head(c, lifecycle="deleted", nonce=ctl["nonce"])
            head["deletion"] = oracle.mark(ctl, raw(ctl))
            self.put(call, oracle.head_path(c["scope"]), head)
            self.view(call, c)
            barrier = {"kind": "own_deleted", "transition": head["transition"]}
        proof = {"format": 1, "control": ctl, "barrier": barrier}
        self.put(call, oracle.proof_path(c), proof); self.get(call, oracle.proof_path(c))
        if until == "proof": self.end(call); return
        self.view(call, c)
        self.put(call, oracle.name_path(c), binding(c, "tombstone", ctl, oracle.digest(raw(proof))))
        self.end(call)

    def direct_foreign(self, c):
        other = copy.deepcopy(c); other["scope"]["incarnation"] += 1
        call = self.begin(other, "create", nonce=91)
        self.roots(call, other["scope"])
        self.put(call, oracle.head_path(c["scope"]), initial_head(c, named=False, lifecycle="ready", nonce=91, changed_scope=other["scope"]))
        self.end(call)

    def wire(self):
        wire = oracle.Wire(self.a)
        wire.inventory(); wire.transitions()
        return wire


def ledger():
    c = intent()
    request = {"op": "catalogue_prepare", "input": {"name": c["name"], "operation": c["operation"],
               "expected_name_revision": None, "options": {"quota": {"kind": "default"}}}}
    value = {k: descriptor(c)[k] for k in ("creation", "initial_quota", "retention")}
    response = {"ok": True, "value": value}
    return {"plan": {"version": 1, "head_format": 3, "immutable_format": 2, "catalogue_record_bytes": 65536,
                     "fixture_limits": oracle.PROFILE, "pilot_profiles": list(oracle.PILOTS), "cut_stages": list(oracle.CUTS)},
            "history": [], "facts": [{"event": "case_started", "case": "unit", "input": request["input"]},
                                       {"event": "worker_started", "case": "unit", "worker": 50001, "scope": c["scope"], "principal": 17}],
            "inputs": [{"event": "catalogue_input", "monotonic_ns": 2, "intent_id": "unit/create", "case": "unit",
                        "context": {"deployment": 7, "tenant": 1, "principal": 17}, "command": request}],
            "clients": [{"event": "call", "monotonic_ns": 3, "call_id": 1, "case": "unit", "label": "prepare", "phase": "unit/prepare",
                         "worker": 50001, "principal": 17, "scope": c["scope"], "intent_id": "unit/create", "command": request},
                        {"event": "response", "monotonic_ns": 4, "call_id": 1, "response": response}],
            "acks": [{"event": "catalogue_ack", "monotonic_ns": 5, "call_id": 1, "case": "unit", "intent_id": "unit/create", "response": response}]}


class CatalogueOracleTests(unittest.TestCase):
    def test_missing_name_views_allow_distinct_backend_error_bodies(self):
        trace = Trace(); c = intent(); trace.prepare(c)
        call = trace.begin(c, "catalogue_inspect", create_operation=c["operation"])
        trace.view(call, c); trace.end(call)
        names = [r for r in trace.a.history if r["event"] == "object_response"
                 and r["phase"] == call["phase"] and r["path"] == oracle.name_path(c)]
        for number, response in enumerate(names):
            payload = f"<Error><RequestId>{number}</RequestId></Error>".encode()
            for row in trace.a.history:
                if row["request_serial"] == response["request_serial"] and row["event"] in ("object_response", "object_response_delivered"):
                    row.update(catalogue_response_bytes=list(payload), response_bytes=len(payload), response_sha256=oracle.digest(payload))
        auditor = object.__new__(oracle.Auditor); auditor.wire = trace.wire()
        self.assertEqual(auditor.view(call, c), (None, None, None))

    def test_fresh_view_requires_proof_before_its_head_dependency(self):
        trace = Trace(); c = intent(); trace.prepare(c)
        call = trace.begin(c, "catalogue_inspect", create_operation=c["operation"])
        trace.view(call, c); trace.end(call)
        auditor = object.__new__(oracle.Auditor); auditor.wire = trace.wire()
        self.assertEqual(auditor.view(call, c), (None, None, None))

    def test_old_head_then_new_proof_order_is_rejected(self):
        trace = Trace(); c = intent(); trace.prepare(c)
        call = trace.begin(c, "catalogue_inspect", create_operation=c["operation"])
        for path in (oracle.name_path(c), oracle.head_path(c["scope"]),
                     oracle.proof_path(c), oracle.name_path(c)):
            trace.get(call, path)
        trace.end(call)
        auditor = object.__new__(oracle.Auditor); auditor.wire = trace.wire()
        with self.assertRaisesRegex(ValueError, "proof before HEAD"):
            auditor.view(call, c)

    def test_scope_derivation_golden(self):
        # OpenSSL SHA-256 of literal bytes, independently of oracle.derive_scope:
        # 7b617686f61ec1e1c9f41512c320193c093d63545c4ebfe590eef960f86727b8.
        self.assertEqual(oracle.derive_scope(7, 1, 17, 41), {
            "deployment": 7, "tenant": 1, "database": 8890517461432975841,
            "incarnation": 14552279466268170556, "generation": 1})

    def test_complete_prepare_ready_chain(self):
        trace = Trace(); c = intent(); trace.prepare(c); trace.resume(c)
        wire = trace.wire()
        self.assertEqual(wire.current[oracle.head_path(c["scope"])]["value"]["lifecycle"], "ready")
        self.assertEqual(wire.current[oracle.name_path(c)]["value"]["state"], "bound")

    def test_absent_abort_requires_durable_barrier_and_proof(self):
        trace = Trace(); c = intent(); trace.prepare(c); trace.resume(c, until="reserved"); trace.abort(c)
        wire = trace.wire()
        self.assertEqual(wire.current[oracle.head_path(c["scope"])]["value"]["lifecycle"], "deleted")
        self.assertEqual(wire.current[oracle.name_path(c)]["value"]["state"], "tombstone")

    def test_provisioning_abort(self):
        trace = Trace(); c = intent(); trace.prepare(c); trace.resume(c, until="provisioning"); trace.abort(c)
        wire = trace.wire()
        self.assertEqual(wire.records[oracle.proof_path(c)]["value"]["barrier"]["transition"]["revision"], 2)

    def test_formal_direct_foreign_barrier(self):
        trace = Trace(); c = intent(); trace.prepare(c); trace.resume(c, until="reserved")
        trace.direct_foreign(c); before = trace.stored[oracle.head_path(c["scope"])]; trace.abort(c, foreign=True)
        wire = trace.wire()
        self.assertEqual(trace.stored[oracle.head_path(c["scope"])], before)
        self.assertEqual(wire.records[oracle.proof_path(c)]["value"]["barrier"]["kind"], "foreign_occupied")

    def test_name_reuse_preserves_abort_proof(self):
        trace = Trace(); c = intent(); trace.prepare(c); trace.resume(c, until="reserved"); trace.abort(c)
        next_c = intent(42, c["name"], 3); trace.prepare(next_c); trace.resume(next_c)
        wire = trace.wire()
        self.assertEqual(wire.current[oracle.name_path(c)]["value"]["creation"], next_c)
        self.assertIn(oracle.proof_path(c), wire.records)

    def test_full_ack_denominator(self):
        oracle.Auditor(ledger()).inventory()

    def test_ack_omission_rejected(self):
        data = ledger(); data["acks"] = []
        with self.assertRaisesRegex(ValueError, "all-ACK"): oracle.Auditor(data).inventory()

    def test_ack_duplicate_rejected(self):
        data = ledger(); data["acks"] *= 2
        with self.assertRaisesRegex(ValueError, "duplicated"): oracle.Auditor(data).inventory()

    def test_ack_full_response_mismatch_rejected(self):
        data = ledger(); data["acks"] = copy.deepcopy(data["acks"])
        data["acks"][0]["response"]["value"]["retention"]["max_entries"] += 1
        with self.assertRaisesRegex(ValueError, "complete original successful response"): oracle.Auditor(data).inventory()

    def test_lost_invocation_is_not_success(self):
        data = ledger(); data["clients"][1] = {"event": "lost", "call_id": 1, "monotonic_ns": 4,
            "worker": 50001, "response_observed": False, "outcome": "unknown", "reason": "verified_compute_sigkill"}
        data["acks"] = []
        auditor = oracle.Auditor(data); auditor.inventory()
        self.assertEqual(set(auditor.lost), {1})
        data["acks"] = ledger()["acks"]
        with self.assertRaises(ValueError): oracle.Auditor(data).inventory()

    def test_saved_intent_reentry_cannot_change_input(self):
        data = ledger(); data["clients"] = copy.deepcopy(data["clients"])
        data["clients"][0]["command"]["input"]["name"] = "another"
        with self.assertRaisesRegex(ValueError, "saved input"): oracle.Auditor(data).inventory()

    def test_input_must_precede_transport(self):
        data = ledger(); data["inputs"][0]["monotonic_ns"] = 10
        with self.assertRaisesRegex(ValueError, "after transport"): oracle.Auditor(data).inventory()

    def test_descriptor_origin_digest_is_actual_bytes(self):
        trace = Trace(); c = intent(); trace.prepare(c); trace.resume(c, until="reserved")
        target = next(r for r in trace.a.history if r["event"] == "object_request" and r["method"] == "PUT" and "/name/" in r["path"])
        mutated = json.loads(bytes(target["catalogue_request_bytes"])); mutated["origin"]["descriptor_hash"] = "0" * 64
        self.rewrite_exchange_request(trace, target["request_serial"], raw(mutated))
        with self.assertRaisesRegex(ValueError, "origin/hash"): trace.wire()

    def test_conditional_publication_cannot_rebase(self):
        trace = Trace(); c = intent(); trace.prepare(c); trace.resume(c)
        target = [r for r in trace.a.history if r["event"] == "object_request" and r["method"] == "PUT" and r["path"].endswith("/head")][-1]
        for row in trace.a.history:
            if row.get("request_serial") == target["request_serial"]: row["if_match"] = '"another-version"'
        with self.assertRaisesRegex(ValueError, "original ETag"): trace.wire()

    def test_ready_cannot_follow_winning_aborting(self):
        trace = Trace(); c = intent(); trace.prepare(c); trace.resume(c, until="provisioning"); trace.abort(c, until="aborting")
        call = trace.begin(c, "catalogue_resume", creation=c)
        trace.get(call, oracle.descriptor_path(c)); trace.view(call, c); trace.roots(call, c["scope"])
        h = initial_head(c); h.update(revision=2, transition={"revision": 2, "nonce": c["operation"]}, lifecycle="ready")
        trace.put(call, oracle.head_path(c["scope"]), h); trace.end(call)
        with self.assertRaisesRegex(ValueError, "winning Bound"): trace.wire()

    def test_tombstone_cannot_omit_abort_proof(self):
        trace = Trace(); c = intent(); trace.prepare(c); trace.resume(c, until="reserved"); trace.abort(c, until="aborting")
        ctl = control(c); call = trace.begin(c, "catalogue_abort", input={k: ctl[k] for k in ("creation", "operation", "expected_name_revision", "nonce")})
        trace.get(call, oracle.descriptor_path(c)); trace.get(call, oracle.control_path(ctl)); trace.view(call, c)
        trace.put(call, oracle.name_path(c), binding(c, "tombstone", ctl, "0" * 64)); trace.end(call)
        with self.assertRaisesRegex(ValueError, "permanent AbortProof"): trace.wire()

    def test_immutable_control_cannot_change_nonce(self):
        trace = Trace(); c = intent(); trace.prepare(c); trace.resume(c, until="reserved"); trace.abort(c)
        wire = trace.wire(); changed = control(c); changed["nonce"] += 1
        with self.assertRaisesRegex(ValueError, "changed complete intent"): wire.known_control(changed)

    def test_own_proof_cannot_use_foreign_identity(self):
        trace = Trace(); c = intent(); trace.prepare(c); trace.resume(c, until="reserved"); trace.abort(c)
        wire = trace.wire(); proof = wire.records[oracle.proof_path(c)]["value"]
        other = copy.deepcopy(wire.current[oracle.head_path(c["scope"])])
        other["value"]["scope"]["generation"] += 1
        with self.assertRaisesRegex(ValueError, "own Deleted"): wire.barrier(proof, other)

    def test_foreign_proof_cannot_change_full_generation(self):
        trace = Trace(); c = intent(); trace.prepare(c); trace.resume(c, until="reserved"); trace.direct_foreign(c); trace.abort(c, foreign=True)
        wire = trace.wire(); proof = copy.deepcopy(wire.records[oracle.proof_path(c)]["value"])
        proof["barrier"]["scope"]["generation"] += 1
        with self.assertRaisesRegex(ValueError, "full Scope"): wire.barrier(proof, wire.current[oracle.head_path(c["scope"])])

    def test_readback_body_and_etag_are_one_observation(self):
        trace = Trace(); c = intent(); trace.prepare(c)
        get = next(r for r in trace.a.history if r["event"] == "object_response" and r["method"] == "GET")
        for row in trace.a.history:
            if row.get("request_serial") == get["request_serial"] and row["event"] in ("object_response", "object_response_delivered"):
                row["etag"] = '"unseen"'
        with self.assertRaisesRegex(ValueError, "omitted from accepted history"): trace.wire()

    def test_capture_digest_mismatch_rejected(self):
        trace = Trace(); c = intent(); trace.prepare(c)
        trace.a.history[0]["catalogue_request_bytes"].append(32)
        with self.assertRaisesRegex(ValueError, "length/hash"): trace.wire()

    def test_network_cannot_move_outside_call_interval(self):
        trace = Trace(); c = intent(); trace.prepare(c)
        trace.a.ends[1]["monotonic_ns"] = 31
        with self.assertRaisesRegex(ValueError, "invocation"): trace.wire()

    def test_network_cannot_move_to_another_name(self):
        trace = Trace(); c = intent(); trace.prepare(c); trace.resume(c, until="reserved")
        for row in trace.a.history:
            if "/name/" in row.get("path", ""): row["path"] = row["path"].rsplit("/", 1)[0] + "/" + "0" * 64
        with self.assertRaisesRegex(ValueError, "escaped invocation"): trace.wire()

    def test_backend_serial_cannot_be_omitted(self):
        trace = Trace(); c = intent(); trace.prepare(c)
        trace.a.history = [r for r in trace.a.history if r.get("request_serial") != 1]
        with self.assertRaisesRegex(ValueError, "serial denominator"): trace.wire()

    def test_socket_delivery_is_not_consumption_proof(self):
        call = {"call_id": 1, "phase": "unit/cut"}
        request, received, delivered = {"request_serial": 2}, {"monotonic_ns": 20}, {"monotonic_ns": 30}
        consumed = {"call_id": 1, "request_serial": 2, "monotonic_ns": 50, "proof": "socket_sent"}
        with self.assertRaisesRegex(ValueError, "socket delivery alone"):
            oracle.consumed_put(None, call, request, received, delivered, consumed, {"monotonic_ns": 60})
        consumed.update(proof="subsequent_get", subsequent={"request_serial": 3})
        next_request = {"method": "GET", "phase": "unit/cut", "monotonic_ns": 40}
        wire = SimpleNamespace(only=lambda serial, event: next_request)
        oracle.consumed_put(wire, call, request, received, delivered, consumed, {"monotonic_ns": 60})
        next_request["phase"] = "unit/unrelated"
        with self.assertRaisesRegex(ValueError, "this client"):
            oracle.consumed_put(wire, call, request, received, delivered, consumed, {"monotonic_ns": 60})

    def test_complete_response_consumption_preserves_raw_response(self):
        response = {"ok": True, "value": {"phase": "ready"}}
        consumed = {"call_id": 1, "request_serial": 2, "monotonic_ns": 50,
                    "proof": "complete_worker_response", "response": response}
        args = (None, {"call_id": 1, "phase": "unit/cut"}, {"request_serial": 2},
                {"monotonic_ns": 20}, {"monotonic_ns": 30}, consumed, {"monotonic_ns": 60})
        oracle.consumed_put(*args, complete={"monotonic_ns": 40, "response": response})
        with self.assertRaisesRegex(ValueError, "witness changed"):
            oracle.consumed_put(*args, complete={"monotonic_ns": 40, "response": {"ok": False, "error": "Unknown"}})

    def test_json_record_rejects_trailing_whitespace_duplicate_and_oversize(self):
        for value in (b'{"format":1,"format":1}', b'{"format":1}\n', b"x" * 65537):
            with self.subTest(value=value[:30]), self.assertRaises((ValueError, TypeError)):
                oracle.json_record(value)

    def test_lifecycle_decoder_is_only_imported_wire_dependency(self):
        tree = ast.parse(Path(oracle.__file__).read_text())
        imports = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        self.assertFalse({"catalogue_contract", "run", "named_catalogue_model", "named_catalogue_oracle"} & imports)
        self.assertIn("lifecycle_oracle", imports)
        shared = next(node for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module == "lifecycle_oracle")
        self.assertEqual({item.name for item in shared.names}, {"byte_string", "decoded_result", "fingerprint", "original_matches", "parse", "validate_original", "validate_result"})

    @staticmethod
    def rewrite_exchange_request(trace, serial, replacement):
        for row in trace.a.history:
            if row.get("request_serial") == serial:
                row["catalogue_request_bytes"] = list(replacement)
                row["request_bytes"] = len(replacement)
                row["request_sha256"] = oracle.digest(replacement)


if __name__ == "__main__": unittest.main()
