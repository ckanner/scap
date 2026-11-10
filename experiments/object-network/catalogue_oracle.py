#!/usr/bin/env python3
"""Read-only native catalogue oracle over original HTTP, input and process logs.

This module never imports the controller, the authority model or production
transition code. Only the independently implemented SCAPSQL1/SCAPRES1/SCAPOBJ2
wire readers are shared with lifecycle_oracle. A final resolve, a controller
phase label or a summary's `passed` field is never sufficient evidence.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import heapq
import json
from pathlib import Path
import struct
import sys

import head5_audit

from lifecycle_oracle import (byte_string, decoded_result, fingerprint,
                              original_matches, parse, validate_original,
                              validate_result)


FILES = {"plan": "catalogue-plan.json", "cuts": "catalogue-cut-plan.json",
         "inputs": "catalogue-input-ledger.jsonl", "clients": "catalogue-client-ledger.jsonl",
         "acks": "catalogue-ack-ledger.jsonl", "facts": "catalogue-facts.jsonl",
         "history": "history.jsonl", "build": "build-receipt.json"}
PILOTS = ("prepare", "resume", "abort_missing", "abort_provisioning", "abort_foreign", "delete")
CUTS = ("before_forward", "after_backend", "after_consumed")
STAGES = ("compute_recovery", "backend_recovery")
MUTATIONS = {"catalogue_prepare", "catalogue_resume", "catalogue_abort", "catalogue_delete"}
SCOPE = ("deployment", "tenant", "database", "incarnation", "generation")
CREATION = ("creator", "operation", "name", "scope", "expected_name_revision")
ORIGIN = ("creator", "operation", "name_hash", "descriptor_hash")
CONTROL = ("format", "creation", "origin", "kind", "principal", "operation",
           "expected_name_revision", "expected_head_revision", "nonce")
HEAD_FIELDS = head5_audit.HEAD_FIELDS
PROFILE = {"quota_bytes": 4194304, "retention_entries": 32, "retention_result_bytes": 134217728}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def equal(left, right, message):
    if isinstance(left, (bytes, set, frozenset)) or isinstance(right, (bytes, set, frozenset)):
        require(type(left) is type(right) and left == right, message)
    else:
        require(canonical(left) == canonical(right), message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def u64(value, *, zero=False):
    require(type(value) is int and (0 if zero else 1) <= value < 2 ** 64, "invalid lossless u64")
    return value


def hash_value(value):
    require(isinstance(value, str) and len(value) == 64
            and all(c in "0123456789abcdef" for c in value), "invalid SHA-256 value")
    return value


def fields(value, names, message):
    require(isinstance(value, dict) and set(value) == set(names), message)


def scope(value):
    fields(value, SCOPE, "incomplete full Scope")
    for item in value.values(): u64(item)
    return value


def derive_scope(deployment, tenant, creator, operation):
    raw = b"SCAP-NAMED-ID-v1\0" + b"".join(struct.pack(">Q", u64(n))
                                               for n in (deployment, tenant, creator, operation))
    hashed = hashlib.sha256(raw).digest()
    return scope({"deployment": deployment, "tenant": tenant,
                  "database": int.from_bytes(hashed[:8], "big"),
                  "incarnation": int.from_bytes(hashed[8:16], "big"), "generation": 1})


def creation(value):
    fields(value, CREATION, "incomplete Creation identity")
    scope(value["scope"])
    name = value["name"]
    require(isinstance(name, str) and 0 < len(name.encode("utf-8")) <= 128
            and not any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in name), "invalid catalogue name")
    previous = value["expected_name_revision"]
    if previous is not None: u64(previous)
    require((previous or 0) + 3 < 2 ** 64, "name revision overflows")
    s = value["scope"]
    equal(s, derive_scope(s["deployment"], s["tenant"], value["creator"], value["operation"]),
          "Creation differs from fixed creator/operation Scope derivation")
    return value


def base(s):
    return "/scap-test/scap-object/v1/{deployment}/{tenant}".format(**s)


def head_path(s):
    return base(s) + f"/{s['database']}/head"


def object_prefix(s, storage_generation):
    return head5_audit.object_prefix(s, storage_generation)


def immutable_address(path):
    """Validate even orphan, missing and raw-fixture object request keys.

    A content hash alone cannot prove a captured physical namespace. Foundation
    HEAD6 admits only storage generation one, including pre-HEAD bootstrap.
    """
    require(type(path) is str, "invalid immutable physical path")
    parts = path.split("/")
    require(len(parts) == 15 and parts[:4] == ["", "scap-test", "scap-object", "v1"]
            and [parts[7], parts[9], parts[11], parts[13]] == ["inc", "gen", "storage", "objects"],
            "immutable path does not use the complete HEAD6 namespace")
    numbers = [parts[index] for index in (4, 5, 6, 8, 10, 12)]
    require(all(1 <= len(number) <= 20 and number[0] in "123456789" and
                all(character in "0123456789" for character in number) for number in numbers),
            "immutable path contains a noncanonical unsigned identity")
    values = [u64(int(number)) for number in numbers]
    captured = dict(zip(SCOPE, values[:5])); generation = values[5]
    require(generation == 1, "immutable path uses unsupported storage generation")
    root = hash_value(parts[14])
    equal(path, object_prefix(captured, generation) + root, "immutable physical path differs")
    return captured, generation, root


def descriptor_path(c):
    return base(c["scope"]) + f"/catalogue/v1/create/{c['creator']}/{c['operation']}"


def name_path(c):
    return base(c["scope"]) + "/catalogue/v1/name/" + digest(c["name"].encode("utf-8"))


def proof_path(c):
    return base(c["scope"]) + f"/catalogue/v1/abort-proof/{c['creator']}/{c['operation']}"


def control_path(control):
    return base(control["creation"]["scope"]) + "/catalogue/v1/control/{principal}/{kind}/{operation}".format(**control)


def origin(descriptor, raw):
    c = descriptor["creation"]
    return {"creator": c["creator"], "operation": c["operation"],
            "name_hash": digest(c["name"].encode("utf-8")), "descriptor_hash": digest(raw)}


def mark(control, raw):
    return {key: control[key] for key in ("kind", "principal", "operation", "expected_name_revision",
                                         "expected_head_revision", "nonce")} | {"descriptor_hash": digest(raw)}


def quota(value):
    fields(value, ("max_bytes",), "invalid database quota")
    if value["max_bytes"] is not None:
        require(u64(value["max_bytes"]) >= 4096, "quota below one SQLite page")


def retention(value):
    fields(value, ("max_entries", "max_result_bytes"), "invalid result retention")
    require(type(value["max_entries"]) is int and 1 <= value["max_entries"] <= 65536, "invalid retention entries")
    require(u64(value["max_result_bytes"]) >= 64 * 1024 * 1024, "retention below one maximal result")


def json_record(raw):
    require(0 < len(raw) <= 65536, "catalogue authority body missing or over capture bound")
    value = parse(raw)
    require(isinstance(value, dict), "catalogue record is not an object")
    equal(json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode(),
          raw, "catalogue record was not captured as complete canonical bytes")
    return value


def head_record(raw, path):
    require(0 < len(raw) <= head5_audit.MAX_HEAD, "HEAD body missing or over capture bound")
    value = head5_audit.validate(parse(raw))
    equal(head_path(value["scope"]), path, "HEAD lies under another physical key")
    return value


def permission(head, principal, field):
    return any(item["principal"] == principal and item[field] for item in head["policy"])


def consumed_put(wire, call, request, received, delivered, consumed, loss, complete=None):
    """A later same-call GET or complete worker response proves consumption."""
    require(delivered is not None, "consumed response was never actually delivered")
    require(consumed["call_id"] == call["call_id"] and consumed["request_serial"] == request["request_serial"]
            and delivered["monotonic_ns"] < consumed["monotonic_ns"] < loss["monotonic_ns"],
            "response consumption marker has wrong invocation/order")
    if consumed["proof"] == "subsequent_get":
        later = wire.only(consumed["subsequent"]["request_serial"], "object_request")
        require(later["phase"] == call["phase"] and later["method"] == "GET"
                and received["monotonic_ns"] < later["monotonic_ns"] < consumed["monotonic_ns"],
                "next request does not prove this client consumed original PUT response")
    else:
        require(consumed["proof"] == "complete_worker_response" and complete is not None,
                "socket delivery alone claimed response consumption")
        equal(consumed["response"], complete["response"], "complete response consumption witness changed")
        require(complete["monotonic_ns"] <= consumed["monotonic_ns"], "consumption marker preceded actual response")


class Wire:
    """One immutable identity, one byte string; current versions use original CAS."""
    def __init__(self, auditor):
        self.a = auditor
        self.serials, self.calls = defaultdict(list), defaultdict(list)
        self.versions, self.current, self.records, self.states = {}, {}, {}, []
        self.accepted = []
        self.gets = []
        self.counts = Counter()

    def only(self, serial, event, required=True):
        found = [r for r in self.serials[serial] if r["event"] == event]
        require(len(found) == (1 if required else min(1, len(found))), f"serial {serial}: missing/duplicate {event}")
        return found[0] if found else None

    def events(self, call, event="object_request", method=None, path=None):
        return [r for r in self.calls[call["call_id"]] if r["event"] == event
                and (method is None or r.get("method") == method) and (path is None or r.get("path") == path)]

    def body(self, row, response=False):
        prefix = "head" if row["path"].endswith("/head") else "catalogue"
        return byte_string(row[prefix + ("_response_bytes" if response else "_request_bytes")])

    def observed(self, call, path, before=None, *, status=200):
        return [r for r in self.events(call, "object_response", "GET", path)
                if r["status"] == status and (before is None or r["monotonic_ns"] < before)]

    def readback(self, call, path, raw, before):
        matches = [r for r in self.observed(call, path, before)
                   if r["response_sha256"] == digest(raw) and r["response_bytes"] == len(raw)]
        require(matches, "authority dependency lacks same-call exact GET readback before publication: " + path)
        return matches[-1]

    def record(self, path, raw):
        value = json_record(raw)
        require(value.get("format") == 1, "catalogue record has wrong format")
        if "/create/" in path:
            fields(value, ("format", "creation", "options", "initial_quota", "retention"), "Descriptor incomplete")
            c = creation(value["creation"])
            equal(path, descriptor_path(c), "Descriptor stored under another identity")
            fields(value["options"], ("quota",), "CreateOptions incomplete")
            choice = value["options"]["quota"]
            require(choice.get("kind") in ("default", "unlimited", "limited"), "unknown quota choice")
            fields(choice, ("kind", "max_bytes") if choice["kind"] == "limited" else ("kind",), "quota choice has extra/missing fields")
            quota(value["initial_quota"]); retention(value["retention"])
            if choice["kind"] != "default":
                equal(value["initial_quota"], {"max_bytes": choice.get("max_bytes")}, "Descriptor changed explicit quota")
        elif "/control/" in path:
            fields(value, CONTROL, "ControlDescriptor incomplete")
            self.control(value)
            equal(path, control_path(value), "ControlDescriptor stored under another caller/kind/operation")
        elif "/name/" in path:
            fields(value, ("format", "creation", "origin", "revision", "state", "control", "proof"), "NameBinding incomplete")
            c = creation(value["creation"])
            self.check_origin(c, value["origin"])
            equal(path, name_path(c), "NameBinding stored under another exact UTF-8 name")
            state = value["state"]
            require(state in ("reserved", "bound", "aborting", "tombstone"), "unknown NameBinding state")
            delta = {"reserved": 1, "bound": 2, "aborting": 2, "tombstone": 3}[state]
            equal(value["revision"], (c["expected_name_revision"] or 0) + delta, "NameBinding revision detached from saved condition")
            if state in ("reserved", "bound"):
                require(value["control"] is None and value["proof"] is None, "creation phase contains a control proof")
            else:
                self.control(value["control"])
                equal(value["control"]["creation"], c, "NameBinding control redirected identity")
                equal(value["control"]["origin"], value["origin"], "NameBinding control changed origin")
                kind = value["control"]["kind"]
                equal(value["control"]["expected_name_revision"], (c["expected_name_revision"] or 0) + (1 if kind == "abort" else 2),
                      "NameBinding control rebased its original expected revision")
                require(kind == "abort" or state == "tombstone", "delete used abort-only state")
                if state == "tombstone" and kind == "abort": hash_value(value["proof"])
                else: require(value["proof"] is None, "unexpected AbortProof reference")
        elif "/abort-proof/" in path:
            fields(value, ("format", "control", "barrier"), "AbortProof incomplete")
            self.control(value["control"])
            require(value["control"]["kind"] == "abort", "AbortProof claims delete intent")
            equal(path, proof_path(value["control"]["creation"]), "AbortProof stored under another creation")
            barrier = value["barrier"]
            if barrier.get("kind") == "own_deleted":
                fields(barrier, ("kind", "transition"), "OwnDeleted proof incomplete")
                fields(barrier["transition"], ("revision", "nonce"), "OwnDeleted transition incomplete")
                require(barrier["transition"]["revision"] in (1, 2)
                        and barrier["transition"]["nonce"] == value["control"]["nonce"], "OwnDeleted proof changed transition")
            else:
                fields(barrier, ("kind", "scope", "creation"), "ForeignOccupied proof incomplete")
                require(barrier["kind"] == "foreign_occupied", "unknown abort barrier")
                scope(barrier["scope"])
                equal(head_path(barrier["scope"]), head_path(value["control"]["creation"]["scope"]), "foreign proof lies under another physical slot")
                require(barrier["scope"] != value["control"]["creation"]["scope"]
                        or barrier["creation"] != value["control"]["origin"], "own identity passed as foreign")
        else:
            raise ValueError("unknown catalogue authority path")
        return value

    def descriptor(self, c):
        item = self.records.get(descriptor_path(c))
        require(item is not None, "named authority lacks a permanent accepted CreateDescriptor")
        equal(item["value"]["creation"], c, "named authority points at another descriptor")
        return item

    def check_origin(self, c, observed):
        item = self.descriptor(c)
        equal(observed, origin(item["value"], item["raw"]), "named authority origin/hash differs from actual Descriptor bytes")
        return item

    def control(self, value):
        fields(value, CONTROL, "ControlDescriptor incomplete")
        require(value["format"] == 1, "ControlDescriptor format changed")
        c = creation(value["creation"])
        self.check_origin(c, value["origin"])
        for key in ("principal", "operation", "expected_name_revision", "nonce"): u64(value[key])
        require(value["kind"] in ("abort", "delete"), "invalid control kind")
        if value["kind"] == "abort":
            require(value["principal"] == c["creator"] and value["expected_head_revision"] is None,
                    "abort control is not fixed to creator/absence of HEAD condition")
        else:
            u64(value["expected_head_revision"])

    def known_control(self, value):
        item = self.records.get(control_path(value))
        require(item is not None, "mutable authority preceded permanent ControlDescriptor")
        equal(item["value"], value, "control operation was reused with changed complete intent")
        return item

    def own(self, c, head):
        return head is not None and head["scope"] == c["scope"] and head["creation"] == origin(self.descriptor(c)["value"], self.descriptor(c)["raw"])

    def barrier(self, proof, current):
        require(current is not None and not current.get("damaged"), "abort proof lacks an actual durable HEAD barrier")
        head, control, barrier = current["value"], proof["control"], proof["barrier"]
        if barrier["kind"] == "own_deleted":
            require(self.own(control["creation"], head) and head["lifecycle"] == "deleted", "OwnDeleted proof lacks own Deleted HEAD")
            equal(head["transition"], barrier["transition"], "OwnDeleted transition was replaced")
            item = self.known_control(control)
            equal(head["deletion"], mark(control, item["raw"]), "OwnDeleted does not bind complete original abort intent")
        else:
            equal(head["scope"], barrier["scope"], "ForeignOccupied changed full Scope")
            equal(head["creation"], barrier["creation"], "ForeignOccupied changed permanent origin")
            if head["creation"] is not None:
                referenced = {"scope": head["scope"], "creator": head["creation"]["creator"], "operation": head["creation"]["operation"]}
                item = self.records.get(descriptor_path(referenced))
                require(item is not None, "foreign named origin lacks actual Descriptor")
                equal(item["value"]["creation"]["scope"], head["scope"], "foreign Descriptor has another complete Scope")
                equal(origin(item["value"], item["raw"]), head["creation"], "foreign Descriptor digest differs")

    def inventory(self):
        phases = {c["phase"]: c for c in self.a.calls.values()}
        for position, row in enumerate(self.a.history):
            row["position"] = position
            if "request_serial" in row: self.serials[row["request_serial"]].append(row)
        equal(sorted(self.serials), list(range(1, len(self.serials) + 1)), "HTTP serial denominator has a gap")
        require(self.serials, "catalogue experiment has no actual object HTTP")
        for serial in self.serials:
            request = self.only(serial, "object_request")
            require(request["phase"] in phases, "object HTTP has no exact invoking call")
            call = phases[request["phase"]]
            for row in self.serials[serial]: self.calls[call["call_id"]].append(row)
            require(request["method"] in ("GET", "PUT") and "?" not in request["path"], "LIST or unplanned transport operation")
            require(call["monotonic_ns"] <= request["monotonic_ns"] < self.a.ends[call["call_id"]]["monotonic_ns"],
                    "object request outside original invocation interval")
            captured = request["path"].endswith("/head") or "/catalogue/v1/" in request["path"]
            if captured:
                raw = self.body(request)
                require(len(raw) == request["request_bytes"] and digest(raw) == request["request_sha256"],
                        "captured request bytes do not match actual HTTP length/hash")
                if "/catalogue/v1/" in request["path"]: require(len(raw) <= 65536, "directory request capture exceeded bound")
            if request["method"] == "GET":
                require(request["request_bytes"] == 0 and request["request_sha256"] == digest(b"")
                        and request["if_match"] is None and request["if_none_match"] is None, "GET acquired fabricated body/condition")
            else:
                require((request["if_none_match"] == "*" and request["if_match"] is None)
                        or (request["if_none_match"] is None and isinstance(request["if_match"], str) and request["if_match"]),
                        "unconditional or ambiguous authority write")
            forwarded = self.only(serial, "object_forwarded", False)
            response = self.only(serial, "object_response", False)
            delivered = self.only(serial, "object_response_delivered", False)
            aborted = self.only(serial, "request_aborted_before_forward", False)
            require(not any(r["event"] == "injected_response" for r in self.serials[serial]), "proxy-generated status cannot prove backend CAS")
            if response is None:
                require(forwarded is None and delivered is None and aborted is not None
                        and call["call_id"] in self.a.lost, "missing actual backend exchange without a verified before-forward cut")
            else:
                require(forwarded is not None and aborted is None and response["response_origin"] == "backend",
                        "backend result lacks actual forwarding")
                require(request["position"] < forwarded["position"] < response["position"]
                        and request["monotonic_ns"] <= forwarded["monotonic_ns"] < response["monotonic_ns"]
                        <= self.a.ends[call["call_id"]]["monotonic_ns"], "HTTP event order differs from original invocation")
                require(response["status"] in (200, 404, 412), "unplanned backend response")
                if captured:
                    raw = self.body(response, True)
                    require(len(raw) == response["response_bytes"] and digest(raw) == response["response_sha256"],
                            "captured response body differs from actual HTTP length/hash")
                    if "/catalogue/v1/" in request["path"]: require(len(raw) <= 65536, "directory response capture exceeded bound")
                if delivered:
                    require(response["position"] < delivered["position"]
                            and response["monotonic_ns"] < delivered["monotonic_ns"],
                            "delivery marker preceded actual backend response")
                    # The proxy records this marker after writing the socket.
                    # The client can consume it and finish before the proxy
                    # thread gets scheduled again. Consumption requires its
                    # own subsequent-GET or complete-response witness.
                else:
                    faults = [r for r in self.serials[serial] if r["event"] == "transport_fault_observed"]
                    require(faults and any(r["mode"] in ("drop", "cut", "hold") for r in faults),
                            "suppressed backend response lacks explicit observed fault")
                self.counts[f"backend_{response['status']}"] += 1
            common = ("phase", "method", "path", "request_bytes", "request_sha256", "if_match", "if_none_match",
                      "head_request_bytes", "catalogue_request_bytes")
            for row in (forwarded, response, delivered, aborted):
                if row is not None:
                    for key in common: equal(row.get(key), request.get(key), "HTTP serial changed original request field " + key)
            if delivered:
                for key in ("status", "response_bytes", "response_sha256", "etag", "head_response_bytes", "catalogue_response_bytes"):
                    equal(delivered.get(key), response.get(key), "delivery changed actual backend response")
        self.bind_paths()

    def bind_paths(self):
        descriptors = []
        for request in [r for r in self.a.history if r["event"] == "object_request" and "/catalogue/v1/create/" in r.get("path", "")]:
            if request["method"] == "PUT":
                try: candidate = parse(self.body(request))
                except (ValueError, TypeError): continue
                if isinstance(candidate, dict) and "creation" in candidate: descriptors.append(candidate["creation"])
        for call in self.a.calls.values():
            command, operation = call["command"], call["command"]["op"]
            requests = self.events(call)
            for request in requests:
                path = request["path"]
                if not path.endswith("/head") and "/catalogue/v1/" not in path:
                    immutable_address(path)
            if operation in ("store_get", "store_put"):
                for request in requests:
                    equal(request["path"], "/scap-test/" + command["key"], "fixture raw operation changed its explicit key")
                continue
            if not operation.startswith("catalogue_"):
                for request in requests:
                    path = request["path"]
                    require(path == head_path(call["scope"]) or path.startswith(object_prefix(call["scope"], 1)),
                            "ordinary database request escaped its complete Scope")
                continue
            context = call["scope"]
            prefix = base(context)
            target = command.get("creation", command.get("input", {}).get("creation"))
            if operation == "catalogue_prepare":
                allowed = {prefix + f"/catalogue/v1/create/{call['principal']}/{command['input']['operation']}"}
                for request in requests: require(request["path"] in allowed, "prepare reached mutable authority or another descriptor")
                continue
            if operation == "catalogue_inspect":
                matches = [c for c in descriptors if c["creator"] == call["principal"]
                           and c["operation"] == command["create_operation"]
                           and c["scope"]["deployment"] == context["deployment"] and c["scope"]["tenant"] == context["tenant"]]
                target = matches[0] if matches else None
            name = command.get("name") if operation == "catalogue_resolve" else (target or {}).get("name")
            related = [c for c in descriptors if c["name"] == name and base(c["scope"]) == prefix]
            if target is not None: related.append(target)
            paths = set()
            object_roots = set()
            for c in related:
                paths.update((descriptor_path(c), name_path(c), proof_path(c), head_path(c["scope"])))
                object_roots.add(object_prefix(c["scope"], 1))
            for row in self.events(call, "object_response", "GET"):
                if row["status"] != 200: continue
                if row["path"].endswith("/head"):
                    try: h = parse(self.body(row, True))
                    except (ValueError, TypeError): continue
                    if isinstance(h, dict) and h.get("creation") is not None:
                        o = h["creation"]
                        paths.add(prefix + f"/catalogue/v1/create/{o['creator']}/{o['operation']}")
                    if isinstance(h, dict) and h.get("deletion") is not None:
                        d = h["deletion"]
                        paths.add(prefix + f"/catalogue/v1/control/{d['principal']}/{d['kind']}/{d['operation']}")
                elif "/catalogue/v1/name/" in row["path"] or "/catalogue/v1/abort-proof/" in row["path"]:
                    value = parse(self.body(row, True))
                    if value.get("control"): paths.add(control_path(value["control"]))
            if operation in ("catalogue_abort", "catalogue_delete"):
                paths.add(prefix + f"/catalogue/v1/control/{call['principal']}/{operation.split('_')[-1]}/{command['input']['operation']}")
            for request in requests:
                require(request["path"].startswith(prefix + "/")
                        and (request["path"] in paths or any(request["path"].startswith(root) for root in object_roots)),
                        "catalogue transport escaped invocation's name, fixed intent or observed permanent origin")
            if operation in ("catalogue_inspect", "catalogue_resolve"):
                require(all(r["method"] == "GET" for r in requests), "read-only catalogue lookup mutated authority")

    def linearized(self):
        """Find a legal order inside the original operation intervals.

        Backend response receipt is not the object's linearization point.
        Opaque ETags identify a unique accepted CAS chain. A successful GET
        must occur between its version's publication and its successor; a
        failed saved-ETag CAS must follow the winning successor. Solve those
        constraints before checking the cross-key catalogue protocol below.
        No observation timestamp or response body is rewritten.
        """
        rows = {r["request_serial"]: r for r in self.a.history if r["event"] == "object_response"}
        requests = {serial: self.only(serial, "object_request") for serial in rows}
        starts = {serial: r["monotonic_ns"] for serial, r in requests.items()}
        ends = {serial: r["monotonic_ns"] for serial, r in rows.items()}
        paths, versions = defaultdict(list), defaultdict(dict)
        for serial, row in rows.items():
            path = row["path"]
            paths[path].append(serial)
            if row["method"] == "PUT" and row["status"] == 200:
                require(isinstance(row["etag"], str) and row["etag"], "accepted PUT lacks backend ETag")
                require(row["etag"] not in versions[path], "accepted immutable/authority ETag was reused")
                versions[path][row["etag"]] = serial
        # Fixture deletion deliberately corrupts an otherwise permanent key.
        # It runs while that key is idle and is followed only by read/refusal
        # probes. Its separately recorded interval must prove this restriction.
        deletions = [f for f in self.a.facts if f["event"] == "damage_observed" and f.get("kind") == "delete"]
        deleted = {}
        for serial, row in enumerate(deletions, 1):
            serial = -serial
            path = "/scap-test/" + row["key"]
            require(path not in deleted, "fixture deleted the same authority more than once")
            invocations = [f for f in self.a.facts if f["event"] == "damage_invoked"
                           and f.get("kind") == "delete" and f["case"] == row["case"] and f["key"] == row["key"]]
            require(len(invocations) == 1, "fixture deletion lacks one original invocation")
            rows[serial] = row
            starts[serial], ends[serial] = invocations[0]["monotonic_ns"], row["monotonic_ns"]
            require(starts[serial] < ends[serial], "fixture deletion completion preceded invocation")
            for other in paths[path]:
                require(ends[other] < starts[serial] or ends[serial] < starts[other],
                        "fixture deletion overlapped an object call outside the damage contract")
            deleted[path] = serial
        edges = set()
        for path, serials in paths.items():
            accepted = versions[path]
            roots, successors = [], {}
            for etag, serial in accepted.items():
                request = requests[serial]
                if request["if_none_match"] == "*":
                    roots.append(serial)
                else:
                    previous = accepted.get(request["if_match"])
                    require(previous is not None and previous != serial,
                            "accepted replacement did not consume an original ETag")
                    require(previous not in successors, "two successful replacements consumed the same original ETag")
                    successors[previous] = serial
                    edges.add((previous, serial))
            require(not accepted or len(roots) == 1, "authority history lacks one conditional-create root")
            if roots:
                seen, current = set(), roots[0]
                while current is not None and current not in seen:
                    seen.add(current)
                    current = successors.get(current)
                require(current is None and len(seen) == len(accepted), "authority ETag chain is disconnected or cyclic")
            deletion = deleted.get(path)
            if deletion is not None:
                require(roots, "fixture deleted an unobserved HEAD")
                for serial in accepted.values():
                    require(ends[serial] < starts[deletion], "corrupt authority was silently republished after fixture deletion")
                    edges.add((serial, deletion))
            for serial in serials:
                request, row = requests[serial], rows[serial]
                if request["method"] == "GET":
                    if row["status"] == 404:
                        if deletion is not None and starts[serial] > ends[deletion]:
                            edges.add((deletion, serial))
                        elif roots:
                            edges.add((serial, roots[0]))
                        continue
                    require(row["status"] == 200, "GET had an unplanned non-missing failure")
                    previous = accepted.get(row["etag"])
                    require(previous is not None, "GET exposed a version omitted from accepted history")
                    edges.add((previous, serial))
                    if previous in successors:
                        edges.add((serial, successors[previous]))
                    elif deletion is not None:
                        edges.add((serial, deletion))
                elif row["status"] == 412:
                    if request["if_none_match"] == "*":
                        require(roots, "backend 412 lacks an occupied physical key")
                        edges.add((roots[0], serial))
                    else:
                        previous = accepted.get(request["if_match"])
                        require(previous is not None, "failed CAS condition has no original ETag")
                        call = self.a.phases[request["phase"]]
                        observed = [r for r in self.observed(call, path, request["monotonic_ns"])
                                    if r["etag"] == request["if_match"]]
                        if call["command"]["op"] == "store_put":
                            # This fixture-only entrypoint delivers a saved
                            # old candidate after the public call has ended.
                            # Bind its explicit input to an actual earlier GET
                            # in this case. The controller preserves that
                            # candidate across verified worker loss as well.
                            equal(call["command"]["etag"], request["if_match"], "saved fixture candidate changed ETag")
                            observed = [r for r in rows.values() if r["event"] == "object_response"
                                        and r["method"] == "GET" and r["status"] == 200
                                        and r["path"] == path and r["etag"] == request["if_match"]
                                        and r["monotonic_ns"] < request["monotonic_ns"]
                                        and self.a.phases[r["phase"]]["case"] == call["case"]]
                        require(observed, "failed mutable candidate did not retain its same-call exact GET ETag")
                        require(previous in successors, "backend 412 rejected the still-current exact ETag")
                        edges.add((successors[previous], serial))
                    if deletion is not None:
                        edges.add((serial, deletion))
        # Rational logical instants allow several effects between adjacent
        # nanosecond observations without inventing elapsed wall-clock time.
        scale = len(rows) + 1
        earliest = {serial: moment * scale for serial, moment in starts.items()}
        following, indegree = defaultdict(set), Counter({serial: 0 for serial in rows})
        for before, after in edges:
            following[before].add(after)
            indegree[after] += 1
        ready = [(earliest[serial], serial) for serial in rows if indegree[serial] == 0]
        heapq.heapify(ready)
        result = []
        while ready:
            _, serial = heapq.heappop(ready)
            require(earliest[serial] <= ends[serial] * scale,
                    "object history has no legal order inside original invocation/response intervals")
            result.append(rows[serial])
            for later in following[serial]:
                earliest[later] = max(earliest[later], earliest[serial] + 1)
                indegree[later] -= 1
                if indegree[later] == 0:
                    heapq.heappush(ready, (earliest[later], later))
        require(len(result) == len(rows), "object history has cyclic read/CAS ordering")
        self.counts["linearization_constraints"] = len(edges)
        return result

    def transitions(self):
        for row in self.linearized():
            if row["event"] == "damage_observed":
                path = "/scap-test/" + row["key"]
                require(path in self.current, "fixture deleted an unobserved HEAD")
                self.current[path] = {"path": path, "monotonic_ns": row["monotonic_ns"], "missing": True}
                self.states.append(self.current[path]); continue
            request = self.only(row["request_serial"], "object_request")
            call = self.a.phases[request["phase"]]
            path = row["path"]
            authoritative = path.endswith("/head") or "/catalogue/v1/" in path
            if row["method"] == "GET":
                if row["status"] == 200:
                    require(isinstance(row["etag"], str) and row["etag"], "exact GET lacks ETag")
                    require((path, row["etag"]) in self.versions, "GET exposed a version omitted from accepted history")
                    version = self.versions[path, row["etag"]]
                    equal([row["response_bytes"], row["response_sha256"]], [version["bytes"], version["sha256"]],
                          "same exact GET ETag does not identify complete original body")
                    if authoritative: equal(self.body(row, True), version["raw"], "GET body differs from accepted bytes for same ETag")
                    current = self.current[path]
                    require(not current.get("missing") and current["etag"] == row["etag"], "fresh GET returned a superseded authority version")
                    self.gets.append({**row, "call_id": call["call_id"], "version": version})
                else:
                    require(row["status"] == 404, "GET had an unplanned non-missing failure")
                    require(path not in self.current or self.current[path].get("missing"), "GET falsely reported existing authority missing")
                continue
            if row["status"] != 200:
                require(row["status"] == 412 and path in self.current and not self.current[path].get("missing"),
                        "backend 412 lacks an occupied physical key")
                require(request["if_none_match"] == "*" or request["if_match"] != self.current[path]["etag"],
                        "backend 412 rejected the still-current exact ETag")
                if path.endswith("/head") or "/catalogue/v1/name/" in path:
                    require(not [r for r in self.events(call) if r["monotonic_ns"] > row["monotonic_ns"]],
                            "failed mutable candidate refreshed authority or retried inside the same public call")
                continue
            require(isinstance(row["etag"], str) and row["etag"], "accepted PUT lacks backend ETag")
            previous = self.current.get(path)
            if previous and not previous.get("missing"):
                equal(request["if_match"], previous["etag"], "accepted replacement did not consume current original ETag")
                require(request["if_none_match"] is None, "accepted replacement used absent condition")
            else:
                require(request["if_none_match"] == "*" and request["if_match"] is None, "first version was not conditional create")
            require((path, row["etag"]) not in self.versions, "accepted immutable/authority ETag was reused")
            item = {"path": path, "etag": row["etag"], "bytes": row["request_bytes"],
                    "sha256": row["request_sha256"], "monotonic_ns": row["monotonic_ns"],
                    "call_id": call["call_id"], "request": request, "response": row}
            if authoritative:
                item["raw"] = self.body(request)
                damaged = call["command"]["op"] == "store_put" and call["label"] in ("damage.put", "provenance.damage")
                item["damaged"] = damaged
                if damaged:
                    fact = self.a.fact(call["case"], "damage_invoked")
                    equal(item["raw"], byte_string(fact["payload"]), "damage marker differs from actual raw PUT")
                    equal(path, "/scap-test/" + fact["key"], "damage targeted another physical key")
                    item["value"] = None
                elif path.endswith("/head"):
                    item["value"] = head_record(item["raw"], path)
                    self.head_transition(call, item, previous)
                else:
                    item["value"] = self.record(path, item["raw"])
                    if "/name/" in path: self.binding_transition(call, item, previous)
                    else:
                        require(previous is None, "permanent catalogue record was replaced")
                        self.immutable_transition(call, item)
                        self.records[path] = item
            else:
                require("/objects/" in path and request["if_none_match"] == "*" and previous is None,
                        "non-authority object was not immutable create")
                equal(path.rsplit("/", 1)[-1], request["request_sha256"], "immutable object key does not bind actual uploaded bytes")
            self.current[path] = item
            self.versions[path, item["etag"]] = item
            self.states.append(item); self.accepted.append(item)

    def immutable_transition(self, call, item):
        path, value = item["path"], item["value"]
        command = call["command"]
        if "/create/" in path:
            require(command["op"] == "catalogue_prepare", "CreateDescriptor was written outside prepare")
            expected = self.a.prepared_creation(call)
            equal(value["creation"], expected, "Descriptor publication changed saved client creation intent")
            equal(value["options"], command["input"]["options"], "Descriptor publication changed saved quota option")
            equal(value["retention"], {"max_entries": PROFILE["retention_entries"], "max_result_bytes": PROFILE["retention_result_bytes"]},
                  "Descriptor publication changed configured retention")
            if value["options"]["quota"]["kind"] == "default":
                equal(value["initial_quota"], {"max_bytes": PROFILE["quota_bytes"]}, "effective default quota changed before first admission")
        elif "/control/" in path:
            equal(value, self.a.control_for(call), "permanent control differs from complete originally invoked intent")
            descriptor = self.descriptor(value["creation"])
            self.readback(call, descriptor["path"], descriptor["raw"], item["request"]["monotonic_ns"])
        else:
            control = self.known_control(value["control"])
            require(command["op"] == "catalogue_abort", "AbortProof published outside abort")
            equal(control["value"], self.a.control_for(call), "AbortProof bound another abort intent")
            self.readback(call, control["path"], control["raw"], item["request"]["monotonic_ns"])
            binding = self.current.get(name_path(value["control"]["creation"]))
            require(binding is not None and binding["value"]["state"] == "aborting", "AbortProof preceded winning Aborting name CAS")
            equal(binding["value"]["control"], value["control"], "AbortProof came from another winning abort")
            current = self.current.get(head_path(value["control"]["creation"]["scope"]))
            self.barrier(value, current)
            self.readback(call, current["path"], current["raw"], item["request"]["monotonic_ns"])

    def binding_transition(self, call, item, previous):
        value, command = item["value"], call["command"]
        descriptor = self.check_origin(value["creation"], value["origin"])
        when = item["request"]["monotonic_ns"]
        self.readback(call, descriptor["path"], descriptor["raw"], when)
        old = previous["value"] if previous else None
        state = value["state"]
        if previous:
            self.readback(call, previous["path"], previous["raw"], when)
            require(value["revision"] == old["revision"] + 1, "NameBinding revision chain has an omitted authority transition")
        if state == "reserved":
            require(command["op"] == "catalogue_resume", "Reserved published outside explicit resume")
            equal(command["creation"], value["creation"], "Reserved redirected original Creation")
            if old:
                require(old["state"] == "tombstone" and old["creation"] != value["creation"]
                        and value["creation"]["expected_name_revision"] == old["revision"], "name reused without exact previous Tombstone condition")
                self.tombstone(old)
            else:
                require(value["revision"] == 1 and value["creation"]["expected_name_revision"] is None,
                        "first reservation invented a previous name revision")
        elif state in ("bound", "aborting"):
            require(old is not None and old["state"] == "reserved" and old["creation"] == value["creation"],
                    "bind/abort did not exclusively consume the same Reserved identity")
            if state == "bound":
                require(command["op"] == "catalogue_resume", "Bound published outside resume")
                head = self.current.get(head_path(value["creation"]["scope"]))
                require(head is not None and self.own(value["creation"], head["value"])
                        and head["value"]["lifecycle"] == "provisioning", "Bound lacks same-origin Provisioning HEAD")
                self.readback(call, head["path"], head["raw"], when)
            else:
                require(command["op"] == "catalogue_abort", "Aborting published outside abort")
                control = self.known_control(value["control"])
                equal(control["value"], self.a.control_for(call), "Aborting changed complete original control input")
                self.readback(call, control["path"], control["raw"], when)
        else:
            require(old is not None and old["creation"] == value["creation"], "Tombstone moved another creation")
            control = self.known_control(value["control"])
            equal(control["value"], self.a.control_for(call), "Tombstone changed complete original control input")
            self.readback(call, control["path"], control["raw"], when)
            require(old["state"] == ("aborting" if value["control"]["kind"] == "abort" else "bound"),
                    "Tombstone skipped its exclusive bind/abort decision")
            self.tombstone(value)
            if value["control"]["kind"] == "abort":
                proof = self.records[proof_path(value["creation"])]
                self.readback(call, proof["path"], proof["raw"], when)

    def tombstone(self, binding):
        control = self.known_control(binding["control"])
        c = binding["creation"]
        current = self.current.get(head_path(c["scope"]))
        if binding["control"]["kind"] == "abort":
            proof = self.records.get(proof_path(c))
            require(proof is not None and digest(proof["raw"]) == binding["proof"], "Tombstone lacks exact permanent AbortProof")
            equal(proof["value"]["control"], control["value"], "Tombstone used another operation's proof")
            self.barrier(proof["value"], current)
        else:
            require(current is not None and not current.get("damaged") and self.own(c, current["value"])
                    and current["value"]["lifecycle"] == "deleted", "delete Tombstone lacks same-origin permanent Deleted HEAD")
            equal(current["value"]["deletion"], mark(control["value"], control["raw"]), "delete Tombstone used another control's barrier")

    def head_transition(self, call, item, previous):
        value, command, when = item["value"], call["command"], item["request"]["monotonic_ns"]
        old = previous["value"] if previous and not previous.get("missing") else None
        head5_audit.advance(old, value)
        if old is None:
            require(value["revision"] == 1 and value["sequence"] == 0, "first HEAD did not begin at initial revision/sequence")
        else:
            require(not previous.get("damaged") and value["revision"] == old["revision"] + 1,
                    "HEAD revision chain skipped a version or repaired corruption")
            equal(value["scope"], old["scope"], "physical HEAD identity was replaced")
            equal(value["creation"], old["creation"], "HEAD changed immutable named origin")
            require(old["lifecycle"] != "deleted", "permanent Deleted identity was reactivated")
            self.readback(call, previous["path"], previous["raw"], when)
        prior_roots = set() if old is None else {old["data_root"], *[window["root"] for window in old["windows"]]}
        roots = {value["data_root"], *[window["root"] for window in value["windows"]]}
        if old is not None and old["lifecycle"] == "provisioning" and value["lifecycle"] == "ready":
            prior_roots = set()
        for root in roots - prior_roots:
            reads = self.observed(call, object_prefix(value["scope"], value["storage"]["active_generation"]) + root, when)
            require(any(row["response_sha256"] == root for row in reads), "HEAD publication preceded immutable root/index readback")
        if value["creation"] is None:
            require(not command["op"].startswith("catalogue_"), "catalogue published an unnamed HEAD")
            return
        reference = {"scope": value["scope"], "creator": value["creation"]["creator"], "operation": value["creation"]["operation"]}
        descriptor = self.records.get(descriptor_path(reference))
        require(descriptor is not None, "named HEAD preceded permanent descriptor")
        c = descriptor["value"]["creation"]
        equal(c["scope"], value["scope"], "named HEAD full Scope differs from actual descriptor")
        equal(origin(descriptor["value"], descriptor["raw"]), value["creation"], "named HEAD changed actual Descriptor digest")
        binding = self.current.get(name_path(c))
        if command["op"].startswith("catalogue_"):
            self.readback(call, descriptor["path"], descriptor["raw"], when)
            require(binding is not None and binding["value"]["creation"] == c, "catalogue HEAD has no winning name identity")
            if value["lifecycle"] == "provisioning":
                require(command["op"] == "catalogue_resume" and old is None
                        and binding["value"]["state"] in ("reserved", "aborting"), "Provisioning escaped original reserved/late-aborting interval")
                observed = self.observed(call, binding["path"], when)
                require(any(parse(self.body(r, True)).get("state") == "reserved" and parse(self.body(r, True)).get("creation") == c for r in observed),
                        "Provisioning had no original exact Reserved observation")
            elif value["lifecycle"] == "ready":
                require(command["op"] == "catalogue_resume" and old is not None and old["lifecycle"] == "provisioning"
                        and binding["value"]["state"] == "bound", "Ready preceded winning Bound or followed cancellation")
                for field in HEAD_FIELDS - {"head_serial", "revision", "transition", "lifecycle"}:
                    equal(value[field], old[field], "Ready completion reset existing " + field)
            else:
                require(value["lifecycle"] == "deleted" and command["op"] in ("catalogue_abort", "catalogue_delete"),
                        "catalogue published an unplanned lifecycle")
                control_value = self.a.control_for(call)
                control = self.known_control(control_value)
                self.readback(call, control["path"], control["raw"], when)
                equal(value["deletion"], mark(control_value, control["raw"]), "Deleted HEAD changed fixed original control")
                equal(value["transition"]["nonce"], control_value["nonce"], "Deleted HEAD changed control nonce")
                if control_value["kind"] == "abort":
                    require(binding["value"]["state"] == "aborting" and (old is None or old["lifecycle"] == "provisioning"),
                            "abort deleted an already Bound/Ready database")
                else:
                    require(old is not None and binding["value"]["state"] == "bound"
                            and old["revision"] == control_value["expected_head_revision"]
                            and binding["value"]["revision"] == control_value["expected_name_revision"],
                            "normal deletion rebased original HEAD/name conditions")
                    require(permission(old, control_value["principal"], "admin"), "normal deletion lacked current ADMIN")
                if old is not None:
                    for field in HEAD_FIELDS - {"head_serial", "revision", "transition", "owner_epoch", "active", "lifecycle", "deletion"}:
                        equal(value[field], old[field], "deletion changed unrelated " + field)
                    require(value["owner_epoch"] == old["owner_epoch"] + 1, "deletion did not fence previous owner")
        else:
            require(old is not None and old["lifecycle"] != "provisioning", "ordinary database entry modified Provisioning")


class Auditor:
    def __init__(self, data):
        self.data = data
        self.plan, self.history, self.facts = data["plan"], data["history"], data["facts"]
        self.calls, self.responses, self.lost, self.ends, self.phases = {}, {}, {}, {}, {}
        self.inputs, self.sql, self.prepared, self.workers, self.cases = {}, {}, {}, {}, {}
        self.originals, self.descriptors, self.ack_classes = {}, {}, Counter()
        self.case_results = []
        self.wire = Wire(self)

    def fact(self, case, event, **values):
        found = [f for f in self.facts if f["case"] == case and f["event"] == event
                 and all(f.get(key) == value for key, value in values.items())]
        require(len(found) == 1, f"{case}: missing/duplicate fact {event} {values}")
        return found[0]

    def call(self, case, label):
        found = [c for c in self.calls.values() if c["case"] == case and c["label"] == label]
        require(len(found) == 1, f"{case}: missing/duplicate required original call {label}")
        return found[0]

    def response(self, call):
        require(call["call_id"] in self.responses, "required complete response was lost")
        return self.responses[call["call_id"]]["response"]

    def value(self, case, label):
        call = self.call(case, label)
        result = self.response(call)
        require(result["ok"] is True, f"{case}/{label}: expected success, observed {result.get('error')}")
        return result["value"]

    def failure(self, case, label, error, *, no_mutable=True):
        call = self.call(case, label)
        result = self.response(call)
        require(result["ok"] is False and result.get("error") == error,
                f"{case}/{label}: expected exact {error}")
        if no_mutable:
            require(not [r for r in self.wire.events(call, method="PUT")
                         if r["path"].endswith("/head") or "/catalogue/v1/name/" in r["path"]],
                    f"{case}/{label}: refused call attempted mutable authority")
        return call

    def snapshot(self, case, label):
        call = self.call(case, label)
        value = self.value(case, label)
        responses = self.wire.events(call, "object_response", "GET")
        require(len(responses) == 1 and responses[0]["status"] == 200, "store_get lacks exact complete GET")
        row = responses[0]
        equal(value, {"bytes": list(self.wire.body(row, True)), "etag": row["etag"]}, "raw store_get result differs from original body/ETag pair")
        return value

    def prepared_creation(self, call):
        request = call["command"]["input"]
        s = call["scope"]
        return creation({"creator": call["principal"], "operation": request["operation"], "name": request["name"],
                         "scope": derive_scope(s["deployment"], s["tenant"], call["principal"], request["operation"]),
                         "expected_name_revision": request["expected_name_revision"]})

    def control_for(self, call):
        command = call["command"]
        require(command["op"] in ("catalogue_abort", "catalogue_delete"), "control published outside control API")
        saved = command["input"]
        descriptor = self.wire.descriptor(saved["creation"])
        return {"format": 1, "creation": saved["creation"], "origin": origin(descriptor["value"], descriptor["raw"]),
                "kind": command["op"].split("_")[-1], "principal": call["principal"], "operation": saved["operation"],
                "expected_name_revision": saved["expected_name_revision"],
                "expected_head_revision": saved.get("expected_head_revision"), "nonce": saved["nonce"]}

    def inventory(self):
        require(self.plan["version"] == 1 and self.plan["head_format"] == 6 and self.plan["immutable_format"] == 2
                and self.plan["catalogue_record_bytes"] == 65536, "catalogue wire/capture plan changed")
        equal(self.plan["fixture_limits"], PROFILE, "fixture resource profile changed")
        equal(self.plan["pilot_profiles"], list(PILOTS), "pilot denominator changed")
        equal(self.plan["cut_stages"], list(CUTS), "fault-stage denominator changed")
        for row in self.facts:
            if row["event"] == "case_started":
                require(row["case"] not in self.cases, "duplicate case identity")
                self.cases[row["case"]] = row
            elif row["event"] == "worker_started":
                require(row["worker"] not in self.workers, "duplicate compute worker identity")
                self.workers[row["worker"]] = row
        require(self.cases and self.workers, "missing original case/process denominator")
        for row in self.data["inputs"]:
            event, identity = row["event"], row["intent_id"]
            if event == "prepared":
                require(identity in self.sql and identity not in self.prepared, "prepared SQL lacks one independent input")
                intent = self.sql[identity]
                expected = {"epoch": intent["epoch"], "id": intent["id"], "principal": intent["principal"],
                            "fingerprint": fingerprint(intent["statements"])}
                equal(row["identity"], expected, "prepared request does not bind complete independent SCAPSQL1 input")
                self.prepared[identity] = row
            elif event in ("input", "catalogue_input"):
                require(identity not in self.inputs and row["case"] in self.cases, "duplicate/unplanned original intent")
                self.inputs[identity] = row
                if event == "input": self.sql[identity] = row
                else:
                    fields(row["context"], ("deployment", "tenant", "principal"), "catalogue intent lost trusted namespace/caller")
                    for number in row["context"].values(): u64(number)
                    require(row["command"]["op"] in MUTATIONS | {"catalogue_inspect", "catalogue_resolve"}, "saved intent is not a catalogue command")
            else:
                raise ValueError("unplanned input ledger event")
        equal(set(self.sql), set(self.prepared), "some SQL input never received exact prepared identity")
        for row in self.data["clients"]:
            number = row["call_id"]
            if row["event"] == "call":
                require(number not in self.calls and row["case"] in self.cases and row["worker"] in self.workers,
                        "duplicate/unplanned client invocation")
                require(row["phase"] == row["case"] + "/" + row["label"] and row["phase"] not in self.phases,
                        "duplicate/misattributed invocation phase")
                self.calls[number] = row; self.phases[row["phase"]] = row
                worker = self.workers[row["worker"]]
                equal([row["scope"], row["principal"], row["case"]], [worker["scope"], worker["principal"], worker["case"]],
                      "invocation changed configured full Scope/principal/process case")
                if row["intent_id"] is not None:
                    require(row["intent_id"] in self.inputs, "invocation has no previously persisted independent intent")
                    original = self.inputs[row["intent_id"]]
                    require(original["monotonic_ns"] < row["monotonic_ns"] and original["case"] == row["case"],
                            "input was recorded after transport or under another case")
                    if original["event"] == "catalogue_input":
                        equal(original["command"], row["command"], "explicit catalogue reentry changed complete saved input")
                        equal(original["context"], {"deployment": row["scope"]["deployment"], "tenant": row["scope"]["tenant"], "principal": row["principal"]},
                              "explicit catalogue reentry changed namespace/caller")
                    else:
                        equal([row["scope"], row["principal"]], [original["scope"], original["principal"]], "SQL request moved full Scope or principal")
                        if row["command"]["op"] in ("execute", "prepare_request"):
                            for key in ("epoch", "id", "statements"): equal(row["command"][key], original[key], "SQL call changed original " + key)
                        else:
                            equal(row["command"]["identity"], self.prepared[row["intent_id"]]["identity"], "resolution changed fixed request identity")
            elif row["event"] in ("response", "lost"):
                require(number in self.calls and number not in self.ends, "response/loss lacks unique prior invocation")
                require(self.calls[number]["monotonic_ns"] < row["monotonic_ns"], "response/loss preceded invocation")
                self.ends[number] = row
                if row["event"] == "response":
                    require(type(row["response"].get("ok")) is bool, "response lacks explicit success bit")
                    require("value" in row["response"] if row["response"]["ok"] else isinstance(row["response"].get("error"), str),
                            "incomplete complete response")
                    self.responses[number] = row
                else:
                    require(row["response_observed"] is False and row["outcome"] == "unknown"
                            and row["reason"] == "verified_compute_sigkill" and row["worker"] == self.calls[number]["worker"],
                            "compute loss was silently called a failure or success")
                    self.lost[number] = row
            else:
                raise ValueError("transport failure or unplanned event in completed client ledger")
        equal(sorted(self.calls), list(range(1, len(self.calls) + 1)), "client call denominator has a gap")
        equal(set(self.calls), set(self.ends), "some invoked call lacks complete response or explicit UNKNOWN loss")
        expected = {number for number, call in self.calls.items() if number in self.responses
                    and self.response(call)["ok"] and call["command"]["op"] in MUTATIONS | {"execute", "session_execute"}}
        observed = set()
        for ack in self.data["acks"]:
            number = ack["call_id"]
            require(number in expected and number not in observed, "ACK missing from real successful denominator or duplicated")
            observed.add(number)
            call = self.calls[number]
            equal([ack["case"], ack["intent_id"], ack["response"]], [call["case"], call["intent_id"], self.response(call)],
                  "ACK changed complete original successful response")
            require(self.responses[number]["monotonic_ns"] <= ack["monotonic_ns"], "ACK ledger preceded client receipt")
            if call["command"]["op"] in MUTATIONS:
                require(ack["event"] == "catalogue_ack", "catalogue success misclassified as SQL ACK")
            else:
                require(ack["event"] == "ack" and call["intent_id"] in self.sql, "successful SQL lacks original independent input")
                intent = self.sql[call["intent_id"]]
                original = ack["response"]["value"]
                validate_original(original)
                equal(original["receipt"]["scope"], intent["scope"], "SQL ACK changed complete Scope")
                equal(original["receipt"]["request"], self.prepared[call["intent_id"]]["identity"], "SQL ACK changed request identity")
                identity = canonical([intent["scope"], self.prepared[call["intent_id"]]["identity"]])
                previous = self.originals.setdefault(identity, {"intent_id": call["intent_id"], "value": original, "first_call": number})
                require(previous["intent_id"] == call["intent_id"], "two independent SQL inputs alias the same durable request")
                original_matches(previous["value"], original, replay=True)
        equal(observed, expected, "successful response was omitted from the all-ACK denominator")
        for case, started in self.cases.items():
            original = self.inputs.get(case + "/create")
            require(original is not None, "case omitted its fixed original creation input")
            equal(original["command"]["input"], started["input"], "case plan differs from pre-transport saved creation input")
            self.descriptors[case] = self.prepared_creation(next(c for c in self.calls.values() if c["intent_id"] == case + "/create"))

    def last_read(self, call, path):
        rows = self.wire.events(call, "object_response", "GET", path)
        require(rows, "successful catalogue response has no exact GET for " + path)
        return rows[-1]

    def view(self, call, c):
        names = self.wire.events(call, "object_response", "GET", name_path(c))
        require(len(names) >= 2, "successful catalogue response lacks second exact NameBinding observation")
        left, right = names[-2:]
        equal(left["status"], right["status"], "successful catalogue response ignored a changing name presence")
        if right["status"] == 200:
            equal([left["etag"], left["response_sha256"], left["response_bytes"]],
                  [right["etag"], right["response_sha256"], right["response_bytes"]],
                  "successful catalogue response ignored a changing body/ETag name pair")
        else:
            # S3 404 XML contains per-request diagnostic IDs/timestamps. Its
            # bytes are not an object version; the wire checker separately
            # proves both missing observations against actual publications.
            equal(right["status"], 404, "successful catalogue response used an invalid missing-name witness")
        def between(path):
            found = [r for r in self.wire.events(call, "object_response", "GET", path)
                     if left["monotonic_ns"] < r["monotonic_ns"] < right["monotonic_ns"]]
            require(len(found) == 1, "catalogue view lacks one exact intermediate authority GET")
            return found[0]
        head = between(head_path(c["scope"]))
        proof = between(proof_path(c))
        # A permanent proof is published after its HEAD barrier. Reading it
        # first prevents an old missing/Provisioning HEAD being paired with a
        # newer proof while both surrounding name reads remain Aborting.
        require(left["monotonic_ns"] < proof["monotonic_ns"] < head["monotonic_ns"] < right["monotonic_ns"],
                "catalogue response did not observe proof before HEAD between exact name reads")
        binding = parse(self.wire.body(right, True)) if right["status"] == 200 else None
        h = head_record(self.wire.body(head, True), head["path"]) if head["status"] == 200 else None
        p = parse(self.wire.body(proof, True)) if proof["status"] == 200 else None
        if h is not None and h["creation"] is not None:
            o = h["creation"]
            path = base(h["scope"]) + f"/catalogue/v1/create/{o['creator']}/{o['operation']}"
            source = self.last_read(call, path)
            require(source["status"] == 200, "named HEAD source Descriptor missing in same fresh observation")
            raw = self.wire.body(source, True)
            descriptor = parse(raw)
            equal(descriptor["creation"]["scope"], h["scope"], "fresh named HEAD Descriptor has another full Scope")
            equal(origin(descriptor, raw), o, "fresh named HEAD origin/hash differs from exact Descriptor GET")
        if p is not None:
            item = {"value": h, "damaged": False} if h is not None else None
            self.wire.barrier(p, item)
        return binding, h, p

    def revisions(self, c, binding, head):
        return (binding["revision"] if binding is not None and binding["creation"] == c else None,
                head["revision"] if self.wire.own(c, head) else None)

    def deleted_witness(self, call, c, head, *, kind="delete"):
        require(self.wire.own(c, head) and head["lifecycle"] == "deleted" and head["deletion"] is not None,
                "terminal observation lacks own permanent Deleted HEAD")
        observed = head["deletion"]
        equal(observed["kind"], kind, "terminal observation used another kind of control barrier")
        path = base(c["scope"]) + f"/catalogue/v1/control/{observed['principal']}/{observed['kind']}/{observed['operation']}"
        control = self.wire.records.get(path)
        require(control is not None, "Deleted HEAD lacks permanent original control")
        equal(control["value"]["creation"], c, "Deleted HEAD control targets another Creation")
        equal(observed, mark(control["value"], control["raw"]), "Deleted HEAD changed original conditions/nonce/control digest")
        self.wire.readback(call, path, control["raw"], self.ends[call["call_id"]]["monotonic_ns"])

    def creation_phase(self, c, binding, head, proof):
        own = head if self.wire.own(c, head) else None
        if binding is None:
            require(own is None and proof is None, "unreserved creation still exposes own HEAD/proof")
            return "name_conflict" if c["expected_name_revision"] is not None else "not_reserved"
        if binding["creation"] != c:
            if proof is not None:
                require(binding["revision"] > (c["expected_name_revision"] or 0) + 3, "old abort proof redirected to unadvanced name")
                return "aborted"
            if own is not None:
                require(own["lifecycle"] == "deleted" and own["deletion"]["kind"] == "delete"
                        and binding["revision"] > (c["expected_name_revision"] or 0) + 3, "old identity was redirected without permanent delete")
                return "deleted"
            return "not_reserved" if binding["state"] == "tombstone" and c["expected_name_revision"] == binding["revision"] else "name_conflict"
        if binding["state"] == "reserved":
            require(proof is None, "Reserved already has abort proof")
            if head is None: return "reserved"
            if own is None: return "identity_conflict"
            require(own["lifecycle"] == "provisioning", "Reserved exposes ready/deleted own HEAD")
            return "provisioning"
        if binding["state"] == "bound":
            require(proof is None and own is not None, "Bound lost its own HEAD or acquired abort proof")
            require(own["lifecycle"] != "maintenance", "successful creation lookup silently accepted Maintenance")
            return {"provisioning": "bound", "ready": "ready", "deleted": "deleting"}[own["lifecycle"]]
        if binding["state"] == "aborting":
            require(own is None or own["lifecycle"] in ("provisioning", "deleted"), "Aborting exposes active own HEAD")
            return "aborting"
        require(binding["state"] == "tombstone", "unrecognized observed name state")
        if binding["control"]["kind"] == "abort":
            require(proof is not None, "Aborted claimed without permanent AbortProof")
            equal(digest(self.wire.records[proof_path(c)]["raw"]), binding["proof"], "Aborted changed exact proof hash")
            equal(binding["control"], proof["control"], "Aborted claimed another control's proof")
            return "aborted"
        require(own is not None and own["lifecycle"] == "deleted", "Deleted name lacks own permanent HEAD barrier")
        return "deleted"

    def catalogue_responses(self):
        descriptor_returns = {}
        for call in self.calls.values():
            if call["call_id"] not in self.responses: continue
            response, command = self.response(call), call["command"]
            operation = command["op"]
            if not operation.startswith("catalogue_") or not response["ok"]: continue
            value = response["value"]
            require(self.workers[call["worker"]]["provision"] is True or operation in ("catalogue_delete", "catalogue_resolve"),
                    "create/control lookup succeeded without fresh provision authorization")
            if operation == "catalogue_prepare":
                fields(value, ("creation", "initial_quota", "retention"), "PreparedCreate response incomplete")
                c = self.prepared_creation(call)
                equal(value["creation"], c, "prepare ACK changed full fixed Creation")
                descriptor = self.wire.descriptor(c)
                equal(descriptor["value"]["options"], command["input"]["options"], "same prepare ID changed raw options")
                self.wire.readback(call, descriptor["path"], descriptor["raw"], self.ends[call["call_id"]]["monotonic_ns"])
                equal(value, {k: descriptor["value"][k] for k in ("creation", "initial_quota", "retention")},
                      "prepare ACK differs from actual durable descriptor")
                old = descriptor_returns.setdefault(call["intent_id"], value)
                equal(old, value, "same prepare reentry changed original effective defaults/identity")
                continue
            if operation == "catalogue_inspect":
                path = base(call["scope"]) + f"/catalogue/v1/create/{call['principal']}/{command['create_operation']}"
                raw = self.last_read(call, path)
                require(raw["status"] == 200, "successful inspect lacks actual fixed Descriptor")
                c = parse(self.wire.body(raw, True))["creation"]
            elif operation == "catalogue_resolve":
                c = value["creation"]
                require(c["name"] == command["name"], "resolve returned a different UTF-8 name")
            else:
                c = command.get("creation", command.get("input", {}).get("creation"))
            creation(c)
            descriptor = self.wire.descriptor(c)
            self.wire.readback(call, descriptor["path"], descriptor["raw"], self.ends[call["call_id"]]["monotonic_ns"])
            binding, head, proof = self.view(call, c)
            binding_revision, head_revision = self.revisions(c, binding, head)
            equal(value["creation"], c, "catalogue ACK changed original complete Creation")
            if operation == "catalogue_resolve":
                fields(value, ("creation", "binding_revision", "head"), "Named response incomplete")
                require(binding is not None and binding["creation"] == c and binding["state"] == "bound"
                        and self.wire.own(c, head) and head["lifecycle"] == "ready" and proof is None,
                        "resolve returned an unbound/unready or cancelled identity")
                require(permission(head, call["principal"], "read"), "resolve bypassed fresh READ permission")
                equal(value["head"], head, "Named exposed another HEAD than its exact GET")
                equal(value["binding_revision"], binding_revision, "Named binding revision changed")
                continue
            equal([value["binding_revision"], value["head_revision"]], [binding_revision, head_revision], "progress borrowed another identity's revision")
            if operation in ("catalogue_resume", "catalogue_inspect"):
                fields(value, ("creation", "phase", "binding_revision", "head_revision", "initial_quota", "retention"), "CreationProgress incomplete")
                require(call["principal"] == c["creator"], "creation progress exposed another caller's operation")
                expected = self.creation_phase(c, binding, head, proof)
                for field in ("initial_quota", "retention"): equal(value[field], descriptor["value"][field], "progress changed immutable initial " + field)
                if expected in ("ready", "deleted", "deleting"):
                    require(permission(head, c["creator"], "read"), "creation progress bypassed current READ permission")
                    if expected != "ready": self.deleted_witness(call, c, head)
            else:
                fields(value, ("creation", "operation", "nonce", "phase", "binding_revision", "head_revision"), "control progress incomplete")
                control = self.control_for(call)
                stored = self.wire.known_control(control)
                self.wire.readback(call, stored["path"], stored["raw"], self.ends[call["call_id"]]["monotonic_ns"])
                equal([value["operation"], value["nonce"]], [control["operation"], control["nonce"]], "control progress changed operation/nonce")
                if operation == "catalogue_delete":
                    require(self.wire.own(c, head) and permission(head, call["principal"], "admin"), "normal delete progress bypassed fresh ADMIN/full identity")
                    if head["lifecycle"] != "deleted": expected = "not_deleted"
                    else:
                        equal(head["deletion"], mark(control, stored["raw"]), "delete progress appropriated another control's success")
                        require(proof is None and binding is not None, "normal delete adopted an abort proof or lost its binding")
                        if binding["creation"] == c:
                            require(binding["state"] in ("bound", "tombstone"), "normal delete claimed success from Reserved/Aborting")
                            if binding["state"] == "tombstone": equal(binding["control"], control, "normal delete adopted another Tombstone control")
                            expected = "deleting" if binding["state"] == "bound" else "deleted"
                        else:
                            require(binding["revision"] > (c["expected_name_revision"] or 0) + 3, "old delete progress used unadvanced replacement binding")
                            expected = "deleted"
                else:
                    require(call["principal"] == c["creator"], "non-creator aborted creation")
                    if binding is None: expected = "not_reserved"
                    elif binding["creation"] != c:
                        if proof is not None:
                            equal(proof["control"], control, "different abort intent appropriated permanent proof")
                            expected = "aborted"
                        elif self.wire.own(c, head):
                            self.deleted_witness(call, c, head)
                            require(permission(head, c["creator"], "read"), "old CannotAbortBound bypassed current READ")
                            expected = "cannot_abort_bound"
                        else: expected = "not_reserved"
                    elif binding["state"] == "bound" or binding["control"] and binding["control"]["kind"] == "delete":
                        require(self.wire.own(c, head), "CannotAbortBound accepted missing/foreign HEAD")
                        if head["lifecycle"] != "provisioning":
                            require(permission(head, c["creator"], "read"), "CannotAbortBound bypassed current creator READ")
                            if head["lifecycle"] == "deleted": self.deleted_witness(call, c, head)
                        expected = "cannot_abort_bound"
                    else:
                        require(binding["state"] in ("aborting", "tombstone"), "successful abort returned unresolved Reserved")
                        equal(binding["control"], control, "abort progress appropriated another accepted control")
                        expected = "aborting" if binding["state"] == "aborting" else "aborted"
                        if expected == "aborted": require(proof is not None, "abort ACK preceded permanent proof")
            equal(value["phase"], expected, "public progress phase differs from independent exact-GET authority observation")
        self.descriptor_returns = descriptor_returns

    def sql_responses(self):
        first = {item["first_call"]: item for item in self.originals.values()}
        for number, call in self.calls.items():
            if number not in self.responses: continue
            response, op = self.response(call), call["command"]["op"]
            if op == "store_get" and response["ok"]: self.snapshot(call["case"], call["label"])
            if op == "prepare_request":
                require(response["ok"] is True, "fixed SQL preparation failed")
                equal(response["value"], self.prepared[call["intent_id"]]["identity"], "prepare response differs from independently encoded SCAPSQL1")
            if op in ("execute", "session_execute") and response["ok"]:
                value = response["value"]
                heads = self.wire.events(call, "object_response", "PUT", head_path(call["scope"]))
                if number in first:
                    require(len(heads) == 1 and heads[0]["status"] == 200, "first SQL ACK lacks actual accepted HEAD publication")
                    observed = heads[0]
                    candidate = head_record(self.wire.body(observed), observed["path"])
                    for key in ("scope", "sequence", "transition", "data_root"):
                        equal(candidate[key], value["receipt"][key], "SQL receipt does not bind exact published " + key)
                    require(candidate["lifecycle"] == "ready" and candidate["active"]
                            and candidate["owner_instance"] == call["worker"], "SQL ACK lacks active current owner publication")
                    request = self.wire.only(observed["request_serial"], "object_request")
                    result_path = object_prefix(candidate["scope"], candidate["storage"]["active_generation"]) + value["receipt"]["result_hash"]
                    witnessed = self.wire.observed(call, result_path, request["monotonic_ns"])
                    require(any(r["response_sha256"] == value["receipt"]["result_hash"] for r in witnessed),
                            "SQL ACK's complete encoded result lacks actual durable object readback before HEAD")
                    for dependency in [candidate["data_root"], *[window["root"] for window in candidate["windows"]]]:
                        reads = self.wire.observed(call, object_prefix(candidate["scope"], candidate["storage"]["active_generation"]) + dependency, request["monotonic_ns"])
                        require(any(r["response_sha256"] == dependency for r in reads), "published SQL dependency lacks original readback")
                else:
                    require(not heads, "duplicate execute republished HEAD or reran SQL")
            if op in ("lookup_identity", "cancel_identity") and response["ok"]:
                intent = self.sql[call["intent_id"]]
                identity = canonical([intent["scope"], self.prepared[call["intent_id"]]["identity"]])
                require(identity in self.originals, "catalogue profile resolved an unacknowledged/unplanned SQL identity")
                original_matches(self.originals[identity]["value"], response["value"])
            if op in ("query", "session_query") and response["ok"]:
                validate_result(response["value"])
            if op in ("takeover", "activate", "activate_session", "set_quota", "set_policy", "set_lifecycle", "close_full") and response["ok"]:
                rows = self.wire.events(call, "object_response", "PUT", head_path(call["scope"]))
                require(len(rows) == 1 and rows[0]["status"] == 200, "ordinary control ACK lacks one real accepted HEAD")
                value = head_record(self.wire.body(rows[0]), rows[0]["path"])
                equal(value, response["value"], "ordinary control returned another HEAD")
                equal(value["revision"], call["command"]["revision"] + 1, "ordinary control changed fixed revision")
                equal(value["transition"], {"revision": value["revision"], "nonce": call["command"]["nonce"]},
                      "ordinary control changed fixed nonce")
        for item in self.originals.values():
            intent, value = self.sql[item["intent_id"]], item["value"]
            statements = intent["statements"]
            if intent["name"].endswith(".schema"):
                equal(statements, [{"sql": "CREATE TABLE events(id INTEGER PRIMARY KEY,label TEXT NOT NULL,token INTEGER NOT NULL)"}],
                      "schema input changed")
                require(len(value["result"]["statements"]) == 1 and value["result"]["statements"][0]["rows"] == [],
                        "schema ACK changed its original empty result")
            else:
                require(intent["name"].endswith(".seed"), "unplanned successful SQL input")
                label = intent["case"] + ":" + intent["name"].rsplit(".", 1)[0]
                equal(statements, [{"sql": "INSERT INTO events VALUES(1,?,random()) RETURNING id,label,token",
                                    "parameters": [{"type": "text", "value": label}]}], "seed SQL/input label changed")
                results = value["result"]["statements"]
                require(len(results) == 1, "RETURNING statement denominator changed")
                result = results[0]
                equal(result["columns"], ["id", "label", "token"], "RETURNING column order changed")
                require(len(result["rows"]) == 1 and len(result["rows"][0]) == 3, "RETURNING row denominator changed")
                equal(result["rows"][0][:2], [1, label], "RETURNING does not match independent original SQL input")
                token = result["rows"][0][2]
                require(type(token) is int and -(2 ** 63) <= token < 2 ** 63 and result["affected_rows"] == 1,
                        "random() first ACK is not a complete int64 witness")

    def case_calls(self, case):
        return [c for c in self.calls.values() if c["case"] == case]

    def matrix(self):
        equal(self.data["cuts"]["cut_stages"], list(CUTS), "cut plan changed stage denominator")
        pilots = self.data["cuts"]["pilots"]
        equal([p["profile"] for p in pilots], list(PILOTS), "pilot profile denominator changed")
        expected_cases = set()
        cut_count = 0
        for pilot in pilots:
            profile, case = pilot["profile"], pilot["case"]
            equal(case, "PILOT-" + profile, "pilot case identity changed")
            expected_cases.add(case)
            call = self.call(case, "pilot")
            require(self.response(call)["ok"], "pilot did not complete production call")
            equal(pilot["call_id"], call["call_id"], "pilot plan identifies another call")
            puts = self.wire.events(call, method="PUT")
            require(0 < len(puts) <= 32, "empty/unbounded real pilot PUT denominator")
            actual = [{"ordinal": n, "path": row["path"], "request_serial": row["request_serial"],
                       "request_sha256": row["request_sha256"], "if_match": row["if_match"], "if_none_match": row["if_none_match"]}
                      for n, row in enumerate(puts, 1)]
            equal(pilot["puts"], actual, "cut plan omitted or fabricated a pilot PUT")
            for ordinal, pilot_request in enumerate(puts, 1):
                for stage in CUTS:
                    target = f"CUT-{profile}-{ordinal:02d}-{stage}"
                    expected_cases.add(target); cut_count += 1
                    started = self.cases.get(target)
                    require(started is not None and started["profile"] == profile and started["kind"] == "cut"
                            and started["put_ordinal"] == ordinal and started["cut_stage"] == stage, "missing exact Cartesian pilot PUT cut")
                    cut = self.call(target, "cut")
                    requests = self.wire.events(cut, method="PUT")
                    require(len(requests) >= ordinal, "cut call never reached actual requested PUT ordinal")
                    request = requests[ordinal - 1]
                    selected = self.fact(target, "cut_observed")
                    require(selected["call_id"] == cut["call_id"] and selected["stage"] == stage, "cut marker refers to another invocation/stage")
                    equal(selected["observation"]["request_serial"], request["request_serial"], "cut marker selected another real PUT")
                    equal(selected["payload"], list(self.wire.body(request)) if request["path"].endswith("/head") or "/catalogue/v1/" in request["path"]
                          else selected["payload"], "cut payload differs from actual captured authority candidate")
                    require(digest(byte_string(selected["payload"])) == request["request_sha256"], "cut payload digest differs from actual transport")
                    self.same_slot_role(pilot_request, request)
                    fault = self.wire.only(request["request_serial"], "transport_fault_observed")
                    equal(fault["matched_ordinal"], ordinal, "fault ordinal differs from actual call PUT denominator")
                    loss = self.fact(target, "compute_lost", stage="fault")
                    require(selected["monotonic_ns"] < loss["monotonic_ns"], "compute lost before actual boundary was observed")
                    received = self.wire.only(request["request_serial"], "object_response", False)
                    delivered = self.wire.only(request["request_serial"], "object_response_delivered", False)
                    if stage == "before_forward":
                        require(received is None and delivered is None and fault["stage"] == "before_forward"
                                and cut["call_id"] in self.lost, "before-forward cut already reached backend/client")
                    else:
                        require(received is not None and received["status"] == 200 and fault["stage"] == "after_upstream_response",
                                "accepted-response cut lacks actual backend success")
                        if stage == "after_backend":
                            require(delivered is None and cut["call_id"] in self.lost, "lost backend response was delivered to client")
                            self.wire.only(request["request_serial"], "response_suppressed_after_backend")
                        else:
                            consumed = self.fact(target, "response_consumed")
                            consumed_put(self.wire, cut, request, received, delivered, consumed, loss,
                                         self.responses.get(cut["call_id"]))
                    reentry = self.fact(target, "explicit_reentry", stage="after_fault")
                    require(reentry["monotonic_ns"] > loss["monotonic_ns"]
                            and self.workers[reentry["worker"]]["monotonic_ns"] > loss["monotonic_ns"], "fault recovery reused old computation")
        expected_cases.update(self.structural_ids())
        equal(set(self.cases), expected_cases, "case matrix omitted or added an unreviewed scenario")
        self.cut_count = cut_count

    @staticmethod
    def same_slot_role(left, right):
        def role(row):
            path = row["path"]
            if path.endswith("/head"):
                value = parse(byte_string(row["head_request_bytes"]))
                return "head", value["lifecycle"], value["revision"]
            if "/catalogue/v1/" in path:
                value = parse(byte_string(row["catalogue_request_bytes"]))
                return path.split("/catalogue/v1/", 1)[1].split("/", 1)[0], value.get("state")
            return ("immutable",)
        # Scope-derived hashes vary by case; role/order and original condition
        # class, not an unrelated pilot's content hash, define this cut.
        equal(role(left), role(right), "cut PUT ordinal drifted to another production record role")
        equal(bool(left["if_none_match"]), bool(right["if_none_match"]), "cut PUT changed condition class")

    @staticmethod
    def structural_ids():
        ids = {"CAT-01-" + suffix for suffix in ("same", "different")}
        ids |= {"CAT-02-" + suffix for suffix in ("bind", "abort")}
        ids |= {"CAT-03-" + suffix for suffix in ("provision", "tombstone")}
        ids |= {f"CAT-04-{kind}-{outcome}" for kind in ("abort", "delete") for outcome in ("conflict", "unknown")}
        ids |= {f"CAT-05-{variant}-{state}" for variant in ("incarnation", "generation", "direct") for state in ("ready", "maintenance", "deleted")}
        ids |= {"CAT-05-provenance-" + damage for damage in ("missing_descriptor", "descriptor_hash", "descriptor_scope")}
        ids |= {"CAT-06-" + damage for damage in ("missing", "malformed", "format", "physical_key")}
        ids |= {"CAT-07-boundaries", "CAT-08-authorization", "CAT-09-reuse", "CAT-10-ready-reentry", "CAT-11-provisioning", "CAT-12-invalid"}
        return ids

    def race_put(self, case, label, suffix, status):
        call = self.call(case, label)
        rows = [r for r in self.wire.events(call, method="PUT") if r["path"].endswith(suffix)]
        require(rows, "race candidate lacks actual selected mutable PUT")
        request = rows[0]
        response = self.wire.only(request["request_serial"], "object_response")
        equal(response["status"], status, "race condition status differs from original backend")
        return request, response

    def held(self, case, label, request):
        call = self.call(case, label)
        boundary = self.fact(case, "boundary", label=label)
        equal(boundary["call_id"], call["call_id"], "held candidate attributed to another invocation")
        equal(boundary["observation"]["request_serial"], request["request_serial"], "held candidate selected another HTTP request")
        equal(byte_string(boundary["payload"]), self.wire.body(request), "held candidate bytes changed after observation")
        released = self.fact(case, "release", call_id=call["call_id"])
        equal(released["request_serial"], request["request_serial"], "release selected another original candidate")
        require(boundary["monotonic_ns"] < released["monotonic_ns"], "candidate released before held observation")
        return boundary, released

    def refusal_without_new_authority(self, case, label, error):
        call = self.failure(case, label, error)
        require(not [r for r in self.wire.events(call, "object_response", "PUT") if r["status"] == 200],
                "refused fixed intent created new persistent authority")

    def structural(self):
        for same in (False, True):
            case = "CAT-01-" + ("same" if same else "different")
            path = name_path(self.descriptors[case])
            left, accepted = self.race_put(case, "left.reserve", path, 200)
            right, refused = self.race_put(case, "right.reserve", path, 412)
            require(left["if_none_match"] == right["if_none_match"] == "*", "reservation race did not share an absent physical name")
            b1, release1 = self.held(case, "left.reserve", left)
            b2, release2 = self.held(case, "right.reserve", right)
            require(max(b1["monotonic_ns"], b2["monotonic_ns"]) < release1["monotonic_ns"]
                    < accepted["monotonic_ns"] < release2["monotonic_ns"] < refused["monotonic_ns"], "reservation winner/loser actual ordering changed")
            equal(self.value(case, "right.explicit_reentry")["phase"], "ready" if same else "name_conflict", "reservation loser reentry redirected name")
            self.failure(case, "right.reserve", "Conflict", no_mutable=False)
        for winner in ("bind", "abort"):
            case = "CAT-02-" + winner
            path = name_path(self.descriptors[case])
            bind, br = self.race_put(case, "bind.candidate", path, 200 if winner == "bind" else 412)
            abort, ar = self.race_put(case, "abort.candidate", path, 200 if winner == "abort" else 412)
            require(bind["if_match"] and bind["if_match"] == abort["if_match"], "bind/abort did not consume exact same Reserved ETag")
            bb, rb = self.held(case, "bind.candidate", bind)
            ba, ra = self.held(case, "abort.candidate", abort)
            success, failed = (br, ar) if winner == "bind" else (ar, br)
            first_release, last_release = (rb, ra) if winner == "bind" else (ra, rb)
            require(max(bb["monotonic_ns"], ba["monotonic_ns"]) < first_release["monotonic_ns"]
                    < success["monotonic_ns"] < last_release["monotonic_ns"] < failed["monotonic_ns"], "bind/abort linearization order not proven")
            label = "abort.after_bound" if winner == "bind" else "resume.after_abort"
            equal(self.value(case, label)["phase"], "cannot_abort_bound" if winner == "bind" else "aborted", "bind/abort exclusivity failed")
        for winner in ("provision", "tombstone"):
            case = "CAT-03-" + winner
            path = head_path(self.descriptors[case]["scope"])
            request, result = self.race_put(case, "provision.candidate", path, 200 if winner == "provision" else 412)
            boundary, release = self.held(case, "provision.candidate", request)
            require(request["if_none_match"] == "*", "late provision changed absent HEAD condition")
            if winner == "tombstone":
                barrier, durable = self.race_put(case, "abort.wins", path, 200)
                require(barrier["if_none_match"] == "*" and boundary["monotonic_ns"] < durable["monotonic_ns"] < release["monotonic_ns"] < result["monotonic_ns"],
                        "late provision was not fenced by actual accepted absent tombstone")
            else:
                barrier, rejected = self.race_put(case, "tombstone.candidate", path, 412)
                other_boundary, other_release = self.held(case, "tombstone.candidate", barrier)
                require(barrier["if_none_match"] == "*" and other_boundary["monotonic_ns"] < result["monotonic_ns"]
                        < other_release["monotonic_ns"] < rejected["monotonic_ns"], "absent provision/tombstone competing conditions not preserved")
                equal(self.value(case, "abort.explicit_reentry")["phase"], "aborted", "late Provisioning did not converge under original cancellation")
            require(not [item for item in self.wire.accepted if item["path"] == path and not item.get("damaged")
                         and item.get("value", {}).get("lifecycle") == "ready"], "cancelled late provision ever became Ready")
        self.control_scenarios()
        self.foreign_scenarios()
        self.corruption_scenarios()
        self.boundary_scenarios()

    def control_scenarios(self):
        for kind in ("abort", "delete"):
            for outcome in ("conflict", "unknown"):
                case = f"CAT-04-{kind}-{outcome}"
                target = name_path(self.descriptors[case]) if kind == "abort" else head_path(self.descriptors[case]["scope"])
                label = "control.candidate" if outcome == "conflict" else "control.lost"
                request, response = self.race_put(case, label, target, 412 if outcome == "conflict" else 200)
                candidate = self.call(case, label)
                fixed = self.control_for(candidate)
                descriptor = self.wire.known_control(fixed)
                require(descriptor["monotonic_ns"] < request["monotonic_ns"], "fixed control was admitted after first target CAS")
                self.wire.readback(candidate, descriptor["path"], descriptor["raw"], request["monotonic_ns"])
                if outcome == "unknown":
                    self.failure(case, label, "Unknown", no_mutable=False)
                    require(self.wire.only(request["request_serial"], "object_response_delivered", False) is None,
                            "UNKNOWN fixture actually delivered target result")
                    fault = self.wire.only(request["request_serial"], "transport_fault_observed")
                    require(fault["mode"] == "drop" and response["suppressed"] is True, "UNKNOWN is not a real accepted-but-lost S3 response")
                else:
                    self.failure(case, label, "Conflict", no_mutable=False)
                    boundary, release = self.held(case, label, request)
                    competitor = self.call(case, "control.conflicting_bind" if kind == "abort" else "control.conflicting_quota")
                    changed = [r for r in self.wire.events(competitor, "object_response", "PUT", target) if r["status"] == 200]
                    require(changed and boundary["monotonic_ns"] < changed[0]["monotonic_ns"] < release["monotonic_ns"] < response["monotonic_ns"],
                            "control conflict lacks actual competing accepted mutation before stale CAS")
                fields_changed = ["nonce", "expected_name_revision"] + (["expected_head_revision"] if kind == "delete" else [])
                for field in fields_changed:
                    call = self.call(case, "changed." + field)
                    expected = dict(candidate["command"]["input"])
                    expected[field] += 1
                    equal(call["command"]["input"], expected, "changed-condition negative control changed another input")
                    self.refusal_without_new_authority(case, "changed." + field, "Conflict")
                    self.wire.readback(call, descriptor["path"], descriptor["raw"], self.ends[call["call_id"]]["monotonic_ns"])
                target_changed = self.call(case, "changed.creation")
                auxiliary = self.value(case, "changed.target.prepare")["creation"]
                equal(target_changed["command"]["input"], {**candidate["command"]["input"], "creation": auxiliary},
                      "changed-target negative control did not preserve original control ID/conditions")
                require(auxiliary != fixed["creation"], "changed-target negative control reused original target")
                self.refusal_without_new_authority(case, "changed.creation", "Conflict")
                self.wire.readback(target_changed, descriptor["path"], descriptor["raw"], self.ends[target_changed["call_id"]]["monotonic_ns"])
                final = self.call(case, "control.fixed_reentry")
                equal(final["command"], candidate["command"], "explicit control recovery changed original input")
                if kind == "delete" and outcome == "conflict": self.failure(case, "control.fixed_reentry", "Conflict")
                else:
                    expected = "cannot_abort_bound" if outcome == "conflict" else "aborted" if kind == "abort" else "deleted"
                    equal(self.value(case, "control.fixed_reentry")["phase"], expected, "fixed control recovery changed outcome")

    def foreign_scenarios(self):
        for variant in ("incarnation", "generation", "direct"):
            for lifecycle in ("ready", "maintenance", "deleted"):
                case = f"CAT-05-{variant}-{lifecycle}"
                c = self.descriptors[case]
                before = self.snapshot(case, "foreign.before")
                h = head_record(byte_string(before["bytes"]), head_path(c["scope"]))
                expected = dict(c["scope"])
                if variant != "direct": expected[variant] = 2 if expected[variant] != 2 else 3
                equal(h["scope"], expected, "ForeignOccupied did not use intended full identity variant")
                require(h["creation"] is None and h["deletion"] is None and h["lifecycle"] == lifecycle,
                        "legal foreign fixture was not a formal unnamed production create")
                creator = self.call(case, "foreign.create")
                require(creator["command"]["op"] == "create" and self.response(creator)["ok"], "ForeignOccupied was fabricated by raw upload")
                require(self.value(case, "foreign.resume")["phase"] == "identity_conflict", "foreign valid slot was mistaken for own creation")
                require(self.value(case, "foreign.abort")["phase"] == "aborted"
                        and self.value(case, "foreign.old_abort")["phase"] == "aborted", "old cancellation lost permanent result after reuse")
                proof = self.wire.records.get(proof_path(c))
                require(proof is not None, "foreign cancellation omitted permanent AbortProof")
                equal(proof["value"]["barrier"], {"kind": "foreign_occupied", "scope": h["scope"], "creation": None},
                      "ForeignOccupied proof changed full identity/source")
                after_time = self.ends[self.call(case, "foreign.before")["call_id"]]["monotonic_ns"]
                require(not [item for item in self.wire.accepted if item["path"] == head_path(c["scope"])
                             and item["monotonic_ns"] > after_time], "foreign abort overwrote legitimate occupied HEAD")
                equal(self.snapshot(case, "successor.before_old"), self.snapshot(case, "successor.after_old"),
                      "old abort changed successor HEAD after name reuse")
                self.failure(case, "foreign.other_abort", "Conflict")
                alternate = self.call(case, "foreign.other_abort")
                original = self.call(case, "foreign.abort")
                expected_input = dict(original["command"]["input"])
                expected_input["operation"] += 1000000; expected_input["nonce"] += 1000000
                equal(alternate["command"]["input"], expected_input, "different abort-control negative control was not independent")
                for stage in STAGES:
                    equal(self.snapshot(case, stage + ".foreign"), before, "foreign HEAD bytes/ETag changed across cold recovery")
        for damage in ("missing_descriptor", "descriptor_hash", "descriptor_scope"):
            case = "CAT-05-provenance-" + damage
            candidate = self.call(case, "provenance.damage")
            c = self.descriptors[case]
            damaged = head_record(byte_string(candidate["command"]["bytes"]), head_path(c["scope"]))
            require(damaged["creation"] is not None and damaged["scope"] != c["scope"], "foreign provenance negative control did not change named origin")
            o = damaged["creation"]
            path = base(c["scope"]) + f"/catalogue/v1/create/{o['creator']}/{o['operation']}"
            if damage == "missing_descriptor":
                missing = self.failure(case, "provenance.missing_descriptor", "Missing")
                equal("/scap-test/" + missing["command"]["key"], path, "missing origin probe looked at another Descriptor")
                require(path not in self.wire.records, "missing origin negative control actually had a Descriptor")
            else:
                raw = self.snapshot(case, "provenance.real_descriptor")
                descriptor = parse(byte_string(raw["bytes"]))
                equal(descriptor["creation"], self.value(case, "provenance.real_prepare")["creation"], "origin source was not a real formal prepare")
                if damage == "descriptor_hash": require(digest(byte_string(raw["bytes"])) != o["descriptor_hash"], "origin hash negative control did not corrupt hash")
                else:
                    equal(origin(descriptor, byte_string(raw["bytes"])), o, "Scope mismatch fixture also changed origin digest")
                    require(descriptor["creation"]["scope"] != damaged["scope"], "foreign Descriptor Scope mismatch was not exercised")
            for label in ("provenance.inspect", "provenance.resume", "provenance.abort", "provenance.resolve"):
                self.failure(case, label, "Corrupt")
            require(proof_path(c) not in self.wire.records, "corrupt foreign provenance manufactured permanent cancellation proof")

    def corruption_scenarios(self):
        for damage in ("missing", "malformed", "format", "physical_key"):
            case = "CAT-06-" + damage
            c = self.descriptors[case]
            before = self.snapshot(case, "damage.before")
            if damage == "missing":
                invocation = self.fact(case, "damage_invoked")
                observed = self.fact(case, "damage_observed")
                missing = self.failure(case, "damage.missing_get", "Missing")
                require(invocation["monotonic_ns"] < observed["monotonic_ns"] < missing["monotonic_ns"], "fixture deletion lacks ordered missing GET witness")
                request = self.wire.events(missing, "object_response", "GET")
                require(len(request) == 1 and request[0]["status"] == 404 and request[0]["path"] == head_path(c["scope"]),
                        "fixture deletion did not produce real backend HEAD 404")
            else:
                call = self.call(case, "damage.put")
                raw = byte_string(call["command"]["bytes"])
                equal(call["command"]["etag"], before["etag"], "damage was not tied to original HEAD ETag")
                if damage == "malformed": require(raw == b"not-a-valid-head", "malformed fixture changed its explicit damage")
                elif damage == "format":
                    value = parse(raw); original = parse(byte_string(before["bytes"]))
                    equal(value, {**original, "format": 999}, "format fixture changed another HEAD field")
                else:
                    source = self.snapshot(case, "damage.other_head")
                    equal(raw, byte_string(source["bytes"]), "wrong-key fixture was not an actual formal foreign HEAD")
                    require(parse(raw)["scope"]["database"] != c["scope"]["database"], "wrong-key fixture did not change physical database")
            for label in ("damage.inspect", "damage.resume", "damage.resolve", "damage.delete"):
                self.failure(case, label, "Corrupt")
            changed = [item for item in self.wire.accepted if item["path"] == name_path(c)
                       and item["monotonic_ns"] > self.ends[self.call(case, "damage.before")["call_id"]]["monotonic_ns"]]
            require(not changed, "corrupt Bound identity advanced or released its name")

    def boundary_scenarios(self):
        case = "CAT-07-boundaries"
        equal(self.value(case, "abort.not_reserved")["phase"], "not_reserved", "descriptor-only abort claimed permanent cancellation")
        equal(self.value(case, "abort.bound")["phase"], "cannot_abort_bound", "Bound identity became abortable")
        equal(self.value(case, "bound.complete")["phase"], "ready", "Bound could not finish after refused abort")
        call = self.call(case, "abort.not_reserved")
        control = self.wire.known_control(self.control_for(call))
        require(control["monotonic_ns"] < self.ends[call["call_id"]]["monotonic_ns"], "NotReserved omitted permanent fixed control admission")
        require(not [r for r in self.wire.events(call, method="PUT") if r["path"].endswith("/head") or "/name/" in r["path"]],
                "NotReserved cancelled a name without winning Reserved")
        case = "CAT-08-authorization"
        for label in ("delete.denied", "resume.no_provision", "abort.non_creator"):
            self.failure(case, label, "Denied")
        call = self.call(case, "delete.other_admin")
        require(call["principal"] == 18 and self.workers[call["worker"]]["provision"] is False
                and call["command"]["input"]["creation"]["creator"] == 17, "normal delete silently replaced original creator or used provision grant")
        equal(self.value(case, "delete.other_admin")["phase"], "deleted", "fresh non-creator ADMIN did not delete")
        case = "CAT-09-reuse"
        equal(self.value(case, "old.resume")["phase"], "deleted", "old create replay redirected to new named incarnation")
        equal(self.value(case, "old.delete")["phase"], "deleted", "old delete intent lost its terminal result")
        equal(self.snapshot(case, "reuse.before_old"), self.snapshot(case, "reuse.after_old"), "old intents changed successor HEAD")
        c = self.descriptors[case]
        for label, state in (("reserved", "reserved"), ("bound", "bound"), ("complete", "ready")):
            call = self.failure(case, "old." + label, "Conflict", no_mutable=False)
            request, response = self.race_put(case, "old." + label, "/scap-test/" + call["command"]["key"], 412)
            raw = self.wire.body(request)
            value = parse(raw)
            require(value.get("state", value.get("lifecycle")) == state, "old candidate role changed")
            originals = [r for r in self.history if r["event"] == "object_request" and r["method"] == "PUT"
                         and r["path"] == request["path"] and r["monotonic_ns"] < self.call(case, "delete.original")["monotonic_ns"]
                         and r["request_sha256"] == request["request_sha256"] and r["if_match"] == request["if_match"]
                         and r["if_none_match"] == request["if_none_match"]]
            require(originals, "late raw candidate refreshed bytes/condition after name reuse")
        old_sql = [call for call in self.case_calls(case) if call["label"].startswith("old.sql.")]
        require(len(old_sql) == 2, "old SQL replay denominator changed after reuse")
        for call in old_sql: self.failure(case, call["label"], "Lifecycle")
        successor = self.value(case, "successor.prepare")["creation"]
        require(successor["scope"] != c["scope"] and successor["expected_name_revision"] == (c["expected_name_revision"] or 0) + 3,
                "name reuse failed to allocate fixed new identity from exact Tombstone revision")
        case = "CAT-10-ready-reentry"
        before, after = self.snapshot(case, "reentry.before"), self.snapshot(case, "reentry.after")
        equal(before, after, "Ready reentry reset data, permissions, quota or immutable origin")
        head = parse(byte_string(before["bytes"]))
        require(head["sequence"] == 2 and head["quota"]["max_bytes"] == 8388608
                and permission(head, 17, "admin") and permission(head, 18, "admin"), "Ready reentry omitted original business/policy/quota mutations")
        for label in ("identity.changed_name", "identity.changed_quota"):
            self.refusal_without_new_authority(case, label, "Conflict")
        for label, error in (("identity.changed_scope", "Invalid"), ("identity.other_principal", "Denied"), ("identity.other_tenant", "Invalid")):
            self.refusal_without_new_authority(case, label, error)
        case = "CAT-11-provisioning"
        required = ("status", "query", "session_open", "takeover", "activate", "activate_session", "set_policy",
                    "set_quota", "set_lifecycle", "close_full", "execute", "lookup_identity", "cancel_identity")
        for op in required: self.failure(case, "blocked." + op, "Lifecycle")
        create = self.failure(case, "blocked.create", "Store(Conflict)", no_mutable=False)
        self.race_put(case, "blocked.create", head_path(self.descriptors[case]["scope"]), 412)
        require(self.value(case, "provisioning.abort")["phase"] == "aborted", "Provisioning refusal fixture did not finish permanent abort")
        case = "CAT-12-invalid"
        for label, error in (("empty", "Invalid"), ("control_char", "Invalid"), ("long", "Limit"), ("zero", "Invalid"), ("overflow", "Limit")):
            self.refusal_without_new_authority(case, "invalid." + label, error)
        deadline = self.call(case, "invalid.deadline")
        require(deadline["command"]["budget_ms"] == 0 and not self.response(deadline)["ok"]
                and self.response(deadline)["error"] == "Unknown", "expired deadline incorrectly acknowledged complete create")
        require(not self.wire.events(deadline), "expired operation reached S3 instead of enforcing bounded call budget")

    def terminal_phase(self, case):
        started = self.cases[case]
        if started["kind"] in ("pilot", "cut"):
            return "aborted" if started["profile"].startswith("abort_") else "deleted" if started["profile"] == "delete" else "ready"
        kind = started["kind"]
        if kind in ("foreign_provenance", "corruption"): return "corrupt"
        if kind in ("foreign", "absent_head_race", "provisioning"): return "aborted"
        if kind in ("authorization", "reuse"): return "deleted"
        if kind == "binding_race": return "ready" if started["winner"] == "bind" else "aborted"
        if kind == "control_admission":
            if started["outcome"] == "conflict": return "ready"
            return "aborted" if started["control_kind"] == "abort" else "deleted"
        require(kind in ("creation_race", "abort_boundaries", "ready_reentry", "invalid"), "unreviewed terminal scenario")
        return "ready"

    def recovery(self):
        for case in self.cases:
            terminal = self.terminal_phase(case)
            equal(self.fact(case, "case_terminal")["phase"], terminal, "controller terminal label differs from fixed scenario")
            originals = [item for item in self.originals.values() if self.sql[item["intent_id"]]["case"] == case]
            prepared = {identity: value for identity, value in self.descriptor_returns.items() if self.inputs[identity]["case"] == case}
            successor_calls = [c for c in self.case_calls(case) if c["label"] == "successor.prepare"]
            successor = self.response(successor_calls[0])["value"]["creation"] if successor_calls else None
            active = successor if successor is not None else self.descriptors[case] if terminal == "ready" else None
            classes = {}
            for item in originals:
                intent = self.sql[item["intent_id"]]
                classification = "retained" if active is not None and active["scope"] == intent["scope"] else "deleted"
                require(classification == "retained" or terminal == "deleted", "ACK was treated as inaccessible without permanent deletion")
                classes[item["intent_id"]] = classification
            for stage in STAGES:
                beginning = self.fact(case, "recovery_started", stage=stage)
                ending = self.fact(case, "recovery_observed", stage=stage)
                require(beginning["monotonic_ns"] < ending["monotonic_ns"], "cold recovery completion preceded beginning")
                stage_calls = [c for c in self.case_calls(case) if c["label"].startswith(stage + ".")]
                require(stage_calls and all(beginning["monotonic_ns"] <= c["monotonic_ns"]
                        < self.ends[c["call_id"]]["monotonic_ns"] < ending["monotonic_ns"] for c in stage_calls),
                        "recovery stage omitted or misordered actual client calls")
                for identity, expected in prepared.items():
                    calls = [c for c in stage_calls if c["intent_id"] == identity and c["command"]["op"] == "catalogue_prepare"]
                    require(len(calls) == 1, "cold recovery omitted a unique previously acknowledged CreateDescriptor")
                    equal(self.response(calls[0])["value"], expected, "cold prepare changed complete original ACK/defaults")
                if terminal == "corrupt":
                    require(not originals, "corruption scenario silently discarded an acknowledged SQL identity")
                    for label in ("inspect", "resolve", "resume_corrupt", "control_corrupt"):
                        self.failure(case, stage + "." + label, "Corrupt")
                    continue
                inspected = self.value(case, stage + ".inspect")
                equal([inspected["creation"], inspected["phase"]], [self.descriptors[case], terminal], "cold creation lookup changed identity/terminal")
                if active is None:
                    self.failure(case, stage + ".resolve", "NotFound")
                else:
                    resolved = self.value(case, stage + ".resolve")
                    equal(resolved["creation"], active, "cold name lookup redirected old/new identity")
                    query = [c for c in stage_calls if c["command"]["op"] == "session_query"]
                    require(len(query) == 1 and query[0]["scope"] == active["scope"], "cold business query scope/denominator changed")
                    equal(query[0]["command"]["sql"], "SELECT id,label,token FROM events ORDER BY id", "cold query omitted or filtered business rows")
                    seed = [o for o in originals if self.sql[o["intent_id"]]["scope"] == active["scope"]
                            and self.sql[o["intent_id"]]["name"].endswith(".seed")]
                    require(len(seed) == 1, "cold business query lacks independent first-ACK random witness")
                    result = self.response(query[0])["value"]
                    validate_result(result)
                    require(len(result["statements"]) == 1, "cold business query result denominator changed")
                    equal(result["statements"][0]["columns"], ["id", "label", "token"], "cold business query column order changed")
                    equal(result["statements"][0]["rows"], seed[0]["value"]["result"]["statements"][0]["rows"],
                          "cold business rows differ from original input and first actual ACK")
                control_input = self.inputs.get(case + "/control")
                if control_input is not None:
                    control = self.call(case, stage + ".control")
                    equal(control["command"], control_input["command"], "cold control recovery changed original complete intent")
                    started = self.cases[case]
                    if started["kind"] == "control_admission" and started["control_kind"] == "delete" and started["outcome"] == "conflict":
                        self.failure(case, stage + ".control", "Conflict")
                    else:
                        expected = "cannot_abort_bound" if terminal == "ready" else terminal
                        equal(self.value(case, stage + ".control")["phase"], expected, "cold control progress changed permanent original outcome")
                for item in originals:
                    identity, original = item["intent_id"], item["value"]
                    calls = [c for c in stage_calls if c["intent_id"] == identity and c["command"]["op"] in ("lookup_identity", "execute")]
                    if classes[identity] == "retained":
                        require(len(calls) == 2 and {c["command"]["op"] for c in calls} == {"lookup_identity", "execute"},
                                "cold retained ACK omitted exact lookup or explicit duplicate execute")
                        for call in calls:
                            require(self.response(call)["ok"], "cold retained identity did not resolve")
                            original_matches(original, self.response(call)["value"], replay=call["command"]["op"] == "execute")
                    else:
                        require(len(calls) == 1 and calls[0]["command"]["op"] == "lookup_identity", "Deleted ACK classification omitted exact lookup refusal")
                        self.failure(case, calls[0]["label"], "Lifecycle")
            case_acks = [ack for ack in self.data["acks"] if ack["case"] == case]
            for ack in case_acks:
                if ack["event"] == "ack": self.ack_classes[classes[ack["intent_id"]]] += 1
                else: self.ack_classes["catalogue_progress"] += 1
            self.case_results.append({"id": case, "status": "passed", "terminal": terminal,
                                      "ack_responses": len(case_acks), "sql_identities": len(originals),
                                      "descriptor_identities": len(prepared), "recovery_stages": list(STAGES)})

    def process_and_build(self):
        from audit_build import OwnedChildren, receipt
        build_audit=receipt(self.data["_evidence_directory"],profile="network",
                            require_artifacts=self.data.get("_require_artifacts",True))
        equal(build_audit["binary"],self.data["build"]["binary"],"archived receipt differs from loaded original build")
        children=OwnedChildren()
        identity_fields = ("pid", "spawn_monotonic_ns", "pid_source", "self_proc_pid", "self_start_ticks")
        lifetimes, stopped = {}, set()
        for number, started in self.workers.items():
            fields(started["identity"], identity_fields, "compute process lacks complete original identity")
            require(started["identity"]["pid_source"] == "owned_Popen_child", "compute identity is not an owned child")
            raw = [r for r in self.history if r["event"] == "worker_started" and r["worker"] == number]
            require(len(raw) == 1, "worker fact has no unique original process-start observation")
            equal(raw[0]["binary"],build_audit["binary"],"actual owned worker used another release executable")
            equal(started["binary"],raw[0]["binary"],"worker fact changed original executable identity")
            equal(started["identity"], {key: raw[0][key] for key in identity_fields}, "worker fact identifies another process incarnation")
            require(started["identity"]["spawn_monotonic_ns"] <= raw[0]["monotonic_ns"] <= started["monotonic_ns"], "worker start observation order changed")
            lifetimes[number] = [started["monotonic_ns"], None]
        losses = [f for f in self.facts if f["event"] == "compute_lost"]
        for loss in losses:
            require(loss["case"] in self.cases and loss["existed_before"] is True and loss["exists_after"] is False and loss["stopped"],
                    "cache deletion or all-compute-loss denominator missing")
            require(Path(loss["directory"]).name == loss["case"], "cache loss selected another case directory")
            for process in loss["stopped"]:
                number = process["worker"]
                require(number in self.workers and number not in stopped and self.workers[number]["case"] == loss["case"],
                        "compute loss omitted/duplicated a process or stopped another case")
                require(process["wait_status"] == -9 and process["kernel_usage"].get("available") is True
                        and process["kernel_usage"].get("source") == "kernel_wait4_owned_child", "compute SIGKILL lacks actual owned-child wait4")
                require(type(process["kernel_usage"].get("maxrss_bytes")) is int and process["kernel_usage"]["maxrss_bytes"]>0,
                        "compute wait4 lacks actual kernel resource witness")
                equal({key: process[key] for key in identity_fields}, self.workers[number]["identity"], "stopped process incarnation differs from original spawn")
                raw = [r for r in self.history if r["event"] == "worker_stopped" and r["worker"] == number]
                require(len(raw) == 1 and raw[0]["fault"] is True, "compute stop fact lacks original verified kill observation")
                equal(process, {key: raw[0][key] for key in process}, "kernel termination evidence changed between ledgers")
                require(lifetimes[number][0] < raw[0]["monotonic_ns"] < loss["monotonic_ns"], "directory removed before actual worker termination")
                lifetimes[number][1] = raw[0]["monotonic_ns"]; stopped.add(number)
                children.register(self.workers[number]["identity"],raw[0]["monotonic_ns"])
        equal(stopped, set(self.workers), "not every compute incarnation lost its complete local cache")
        raw_started = [r["worker"] for r in self.history if r["event"] == "worker_started"]
        equal(set(raw_started), set(self.workers), "unrecorded original compute process hidden from facts")
        require(len(raw_started) == len(self.workers), "raw process start duplicated")
        raw_invoked = [r for r in self.history if r["event"] == "client_invoked"]
        raw_observed = [r for r in self.history if r["event"] == "client_observed"]
        raw_lost = [r for r in self.history if r["event"] == "client_invocation_lost_with_process"]
        require(len(raw_invoked) == len(self.calls) and len(raw_observed) == len(self.responses) and len(raw_lost) == len(self.lost),
                "raw client process history differs from complete invocation/outcome denominator")
        for number, call in self.calls.items():
            start, stop = lifetimes[call["worker"]]
            end = self.ends[number]
            require(start <= call["monotonic_ns"] < stop, "client call outside actual compute process lifetime")
            original = [r for r in raw_invoked if r["worker"] == call["worker"]
                        and call["monotonic_ns"] <= r["monotonic_ns"] < end["monotonic_ns"]]
            require(len(original) == 1 and original[0]["operation"] == call["command"]["op"], "client ledger does not match actual stdin invocation")
            equal(original[0]["pid"], self.workers[call["worker"]]["identity"]["pid"], "client invocation used another child PID")
            if number in self.responses:
                require(end["monotonic_ns"] <= stop, "complete response observed after process death")
                original = [r for r in raw_observed if r["worker"] == call["worker"]
                            and call["monotonic_ns"] < r["monotonic_ns"] <= end["monotonic_ns"]]
                require(len(original) == 1, "complete response lacks original process observation")
                response = end["response"]
                equal([original[0]["ok"], original[0]["error"], original[0]["resources"]],
                      [response["ok"], response.get("error"), response["resources"]], "raw process response changed success/error/resources")
                identity = self.workers[call["worker"]]["identity"]
                equal([response["resources"]["namespace_pid"], response["resources"]["proc_pid"], response["resources"]["start_ticks"]],
                      [identity["pid"], identity["self_proc_pid"], identity["self_start_ticks"]], "response came from another process incarnation")
            else:
                require(stop < end["monotonic_ns"], "UNKNOWN loss record preceded actual kernel termination")
                original = [r for r in raw_lost if r["worker"] == call["worker"]
                            and call["monotonic_ns"] < r["monotonic_ns"] < end["monotonic_ns"]]
                require(len(original) == 1 and original[0]["operation"] == call["command"]["op"]
                        and original[0]["wait_status"] == -9 and original[0]["client_response_observed"] is False
                        and original[0]["fault_requested"] is True and original[0]["cleanup_aborted"] is False,
                        "lost invocation lacks actual killed-pending-client evidence")
        old = self.fact(None, "backend_started")
        stopping = self.fact(None, "backend_stopping")
        gone = self.fact(None, "backend_stopped")
        new = self.fact(None, "backend_restarted")
        final = self.fact(None, "backend_cleanup")
        require(stopping["live_compute_workers"] == gone["live_compute_workers"] == 0
                and old["monotonic_ns"] < stopping["monotonic_ns"] < gone["monotonic_ns"] < new["monotonic_ns"] < final["monotonic_ns"],
                "backend stop/restart order or declared zero-compute boundary changed")
        require(not any(start <= stopping["monotonic_ns"] <= stop for start, stop in lifetimes.values()),
                "actual worker lifetimes contradict zero compute at backend cut")
        roles = ["master", "volume", "filer", "s3"]
        for group in (old, gone, new, final): equal([row["role"] for row in group["identities"]], roles, "four backend process denominator changed")
        for before, killed, after, cleaned in zip(old["identities"], gone["identities"], new["identities"], final["identities"]):
            for born, ended in ((before, killed), (after, cleaned)):
                for key in ("role", "pid", "spawn_monotonic_ns", "pid_source"):
                    equal(born[key], ended[key], "backend cleanup stopped another process incarnation")
                require(ended["wait_status"] == -9 and ended["kernel_usage"].get("available") is True
                        and ended["kernel_usage"].get("source") == "kernel_wait4_owned_child", "backend termination lacks actual owned-child wait4")
                require(type(ended["kernel_usage"].get("maxrss_bytes")) is int and ended["kernel_usage"]["maxrss_bytes"]>0,
                        "backend wait4 lacks actual kernel resource witness")
            require((before["pid"], before["spawn_monotonic_ns"]) != (after["pid"], after["spawn_monotonic_ns"])
                    and gone["monotonic_ns"] < after["spawn_monotonic_ns"] < new["monotonic_ns"]
                    and after["pid_source"] == "owned_Popen_child", "replacement backend was not spawned after verified complete cut")
            require(before["spawn_monotonic_ns"]<old["monotonic_ns"],"backend start preceded owned spawn")
            children.register(before,gone["monotonic_ns"])
            children.register(after,final["monotonic_ns"])
        for case in self.cases:
            before = self.fact(case, "compute_lost", stage="before_backend")
            cleanup = self.fact(case, "compute_lost", stage="final_cleanup")
            require(before["monotonic_ns"] < stopping["monotonic_ns"] and cleanup["monotonic_ns"] < final["monotonic_ns"],
                    "backend restart/cleanup preceded complete per-case compute/cache loss")
            directory = before["directory"]
            for loss in losses:
                if loss["case"] == case: equal(loss["directory"], directory, "same case lost a different local execution tree")
            for stage in STAGES:
                recovery = self.fact(case, "recovery_started", stage=stage)
                loss = self.fact(case, "compute_lost", stage="compute_recovery" if stage == "compute_recovery" else "before_backend")
                if stage == "backend_recovery": require(new["monotonic_ns"] < recovery["monotonic_ns"], "cold recovery preceded backend restart")
                for call in self.case_calls(case):
                    if call["label"].startswith(stage + "."):
                        require(self.workers[call["worker"]]["monotonic_ns"] > loss["monotonic_ns"], "cold recovery reused old computation")
        require(not any(r["event"] in ("transport_fixture_failed", "client_transport_failed") for r in self.history),
                "raw transport/process failure was hidden by summary")
        cleanup = self.fact(None, "cleanup_observed")
        equal([cleanup["proxy_errors"], cleanup["cleanup_errors"]], [[], []], "cleanup errors cannot pass")
        build = self.data["build"]
        equal(digest(json.dumps(build["inputs"], sort_keys=True, separators=(",", ":")).encode()), build["input_sha256"], "build manifest input digest differs")
        equal([build["binary"]["sha256"], build["input_sha256"]], [self.plan["binary_sha256"], self.plan["input_sha256"]], "runtime changed exact built source/binary")
        for stage in ("before", "after"):
            checked = self.fact(None, "build_verified", stage=stage)
            equal([checked["binary_sha256"], checked["input_sha256"]], [self.plan["binary_sha256"], self.plan["input_sha256"]], "before/after build verification changed identity")
        self.process_counts = {"compute_incarnations": len(self.workers), "verified_cache_loss_observations": len(losses),
                               "backend_processes_killed": 4, "backend_replacements": 4, "lost_invocations": len(self.lost),
                               "unique_child_incarnations":len(children.incarnations),"build":build_audit}

    def run(self):
        self.inventory()
        self.wire.inventory()
        self.wire.transitions()
        self.catalogue_responses()
        self.sql_responses()
        self.matrix()
        self.structural()
        self.recovery()
        self.process_and_build()
        equal(sum(self.ack_classes.values()), len(self.data["acks"]), "final ACK classifications omitted a successful response")
        return {"status": "passed", "checked_cases": len(self.case_results), "case_results": self.case_results,
                "pilot_profiles": len(PILOTS), "put_cut_cases": self.cut_count, "structural_cases": len(self.structural_ids()),
                "invoked_calls": len(self.calls), "complete_responses": len(self.responses), "explicit_lost_unknown": len(self.lost),
                "saved_catalogue_intents": len(self.inputs) - len(self.sql), "sql_inputs": len(self.sql),
                "ack_responses": len(self.data["acks"]), "ack_classifications": dict(self.ack_classes),
                "sql_ack_identities": len(self.originals), "descriptor_ack_identities": len(self.descriptor_returns),
                "actual_http_statuses": dict(self.wire.counts), "processes": self.process_counts,
                "mismatch_count": 0, "recovery_stages": list(STAGES),
                "aws_endpoint_gate": "NOT_RUN", "production_slo_passed": False, "unit_coverage_contribution": False,
                "limits": ["real loopback SeaweedFS 4.51 is not AWS Standard acceptance",
                           "cache removal is a source-bound controller stat/rmtree observation, not external filesystem attestation",
                           "valid foreign named hash collisions are not manufactured; direct foreign identities and invalid provenance are separate",
                           "no general all-stage 403/5xx matrix, namespace inventory, garbage collection or operational SLO claim"]}


def read_sources(evidence):
    data, hashes = {}, {}
    for key, name in FILES.items():
        raw = (evidence / name).read_bytes()
        require(raw and raw.endswith(b"\n"), "missing/truncated original evidence: " + name)
        hashes[name] = digest(raw)
        data[key] = [parse(line) for line in raw.splitlines()] if name.endswith(".jsonl") else parse(raw)
    data["_evidence_directory"]=Path(evidence)
    return data, hashes


def audit(evidence, *, require_artifacts=True):
    source = Path(__file__).resolve()
    report = {"status": "failed", "checked_cases": 0, "oracle_sha256": digest(source.read_bytes()),
              "wire_reader_sha256": digest(source.with_name("lifecycle_oracle.py").read_bytes()),
              "aws_endpoint_gate": "NOT_RUN", "unit_coverage_contribution": False}
    try:
        data, hashes = read_sources(Path(evidence))
        data["_require_artifacts"]=require_artifacts
        report["source_artifacts"] = hashes
        report.update(Auditor(data).run())
        if report["processes"]["build"]["verification_scope"]!="full":report["status"]="partial"
    except (KeyError, ValueError, TypeError, OSError, UnicodeError, StopIteration) as error:
        report.update(status="failed", error_type=type(error).__name__, error=str(error))
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--allow-unavailable-artifacts",action="store_true",help="explicit partial offline audit; never a full release gate")
    arguments = parser.parse_args(argv)
    result = audit(arguments.evidence,require_artifacts=not arguments.allow_unavailable_artifacts)
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__": sys.exit(main())
