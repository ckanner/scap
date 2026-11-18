"""Finite proposal model. No production imports and no oracle predicates.

The storage machine separates candidate preparation, invocation, durable effect
and response. An invoked request can take effect after its process crashes.
Only explicitly listed scheduling points are exhaustively interleaved.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def key(scope, generation, identifier):
    return f"data/{scope}/{generation}/{identifier}"


def frame(scope, number, value):
    return {"kind": "page", "scope": scope, "number": number, "value": value}


def manifest(scope, pages):
    return {"kind": "manifest", "scope": scope, "count": len(pages),
            "pages": [{"number": item["number"], "hash": digest(item)} for item in pages]}


class Rejected(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


class Model:
    def __init__(self, maximum=63, source_pages=2):
        self.maximum = maximum
        self.store = {}
        self.events = []
        self.calls = {}
        self.reads = {}
        self.attempts = {}
        self.process = {"admin": 0, "a": 0, "b": 0, "c": 0}
        self.principal = {"admin": 1, "a": 2, "b": 2, "c": 3}
        self.provision_rights = {1: True, 2: True, 3: True}
        self.serial = 0
        self.counter = 0
        self.source_latched = set()
        pages = [frame("source", i + 1, f"original-{i + 1}") for i in range(source_pages)]
        root = manifest("source", pages)
        for item in [*pages, root]:
            self._initial(key("source", 1, digest(item)), item)
        head = {"kind": "source_head", "format": 9, "scope": "source", "serial": 1,
                "revision": 1, "sequence": 0, "A": 1, "M": 1,
                "root": digest(root), "pages": source_pages, "quota": 3,
                "policy": {"1": {"admin": True, "read": True},
                           "2": {"admin": True, "read": True}, "3": {"admin": True, "read": True}},
                "lifecycle": "ready", "snapshots": [], "plan": None, "sweep": None,
                "limits": {"max_points": 2, "max_pages": 6}, "terminal": None,
                "requests": [9001], "owner_pending": False, "restore_origin": None}
        self._initial("head/source", head)
        self.events.append({"event": "initial", "maximum": maximum,
                            "objects": deepcopy(self.store), "principals": dict(self.principal),
                            "provision_rights": deepcopy(self.provision_rights)})

    def _initial(self, object_key, body):
        self.serial += 1
        self.store[object_key] = {"body": deepcopy(body), "etag": f"e{self.serial}"}

    def event(self, event_name, **fields):
        row = {"event": event_name, "index": len(self.events), **deepcopy(fields)}
        self.events.append(row)
        return row["index"]

    def unique(self, prefix):
        self.counter += 1
        return f"{prefix}-{self.counter}"

    def fail(self, code, operation, **evidence):
        self.event("rejected", code=code, operation=operation, **evidence)
        raise Rejected(code)

    def read_invoke(self, object_key, actor="admin", label=None):
        identifier = label or self.unique("get")
        assert identifier not in self.reads
        self.reads[identifier] = {"key": object_key, "actor": actor,
                                  "process": self.process[actor], "effect": None, "response": None}
        self.event("get_invoke", id=identifier, key=object_key, actor=actor, process=self.process[actor])
        return identifier

    def read_effect(self, identifier, fault=None):
        read = self.reads[identifier]
        assert read["effect"] is None
        if fault:
            response = {"status": fault}
        elif read["key"] in self.store:
            response = {"status": "present", **deepcopy(self.store[read["key"]])}
        else:
            response = {"status": "missing"}
        read["effect"] = response
        self.event("get_effect", id=identifier, result=response)

    def read_response(self, identifier, lost=False):
        read = self.reads[identifier]
        assert read["response"] is None
        response = {"status": "unknown"} if lost else deepcopy(read["effect"])
        assert response is not None
        read["response"] = response
        self.event("get_response", id=identifier, result=response)
        return response

    def get(self, object_key, actor="admin", fault=None):
        identifier = self.read_invoke(object_key, actor)
        self.read_effect(identifier, fault)
        value = self.read_response(identifier)
        return identifier, value

    def present(self, object_key, actor="admin"):
        identifier, result = self.get(object_key, actor)
        if result["status"] != "present":
            self.fail("Missing" if result["status"] == "missing" else "Unknown", "exact_get", read=identifier)
        return identifier, result

    def auth(self, observation, actor="admin", read=False):
        grant = observation["body"]["policy"].get(str(self.principal[actor]), {})
        if not grant.get("admin") or (read and not grant.get("read")):
            self.fail("Denied", "permission", actor=actor, head=observation)

    def target_gate(self, creator, scope, actor, operation):
        allowed = self.principal[actor] == creator and self.provision_rights.get(creator, False)
        gate = self.event("target_admission", creator=creator, scope=scope, actor=actor,
                          process=self.process[actor], operation=operation, allowed=allowed)
        if not allowed:
            self.fail("Denied", "target_permission", admission=gate)
        return gate

    def provision_right(self, principal, allowed):
        self.provision_rights[principal] = allowed
        self.event("provision_right", principal=principal, allowed=allowed)

    def candidate(self, kind, object_key, body, condition, actor="admin", evidence=None, inputs=None):
        identifier = self.unique(kind)
        call = {"id": identifier, "kind": kind, "key": object_key, "body": deepcopy(body),
                "condition": condition, "actor": actor, "process": self.process[actor],
                "evidence": deepcopy(evidence or {}), "inputs": deepcopy(inputs or {}),
                "invoked": False, "effect": None, "response": None}
        self.calls[identifier] = call
        self.event("candidate", **{name: value for name, value in call.items()
                                    if name not in ("invoked", "effect", "response")})
        return identifier

    def invoke(self, identifier):
        call = self.calls[identifier]
        if call["process"] != self.process[call["actor"]]:
            self.fail("StaleProcess", "invoke", id=identifier)
        assert not call["invoked"]
        call["invoked"] = True
        self.event("put_invoke", id=identifier)

    def effect(self, identifier):
        call = self.calls[identifier]
        assert call["invoked"] and call["effect"] is None
        old = self.store.get(call["key"])
        matches = (old is None if call["condition"] == "absent"
                   else old is not None and old["etag"] == call["condition"])
        if matches:
            self.serial += 1
            result = {"status": "applied", "etag": f"e{self.serial}"}
            if call["body"] is None:
                self.store.pop(call["key"], None)
            else:
                self.store[call["key"]] = {"body": deepcopy(call["body"]), "etag": result["etag"]}
        else:
            result = {"status": "conflict"}
        call["effect"] = result
        self.event("put_effect", id=identifier, result=result)
        return result

    def respond(self, identifier, lost=False):
        call = self.calls[identifier]
        assert call["response"] is None
        result = {"status": "unknown"} if lost else deepcopy(call["effect"])
        assert result is not None
        call["response"] = result
        self.event("put_response", id=identifier, result=result)
        return result

    def run(self, identifier, lost=False):
        self.invoke(identifier)
        self.effect(identifier)
        return self.respond(identifier, lost)

    def immutable(self, kind, object_key, body, actor="admin", evidence=None, inputs=None):
        call = self.candidate(kind, object_key, body, "absent", actor, evidence, inputs)
        self.run(call)
        read, durable = self.present(object_key, actor)
        if durable["body"] != body:
            self.fail("Conflict", "immutable", read=read)
        return read, durable

    def crash(self, actor):
        self.process[actor] += 1
        for attempt in self.attempts.values():
            if attempt["actor"] == actor:
                attempt["alive"] = False
        self.event("crash", actor=actor, process=self.process[actor])

    def fresh_head(self, actor="admin"):
        read, head = self.present("head/source", actor)
        self.auth(head, actor)
        return read, head

    def room(self, head):
        pending = int(head.get("owner_pending", False))
        delete = int(head["lifecycle"] != "deleted")
        seal = int(head["terminal"] is None)
        revision_debt = pending + delete
        sweep = head.get("sweep")
        q = 0 if sweep is None else 2 if any(item["disposition"] == "pending" for item in sweep["entries"]) else 1
        serial_debt = len(head.get("snapshots", [])) + pending + int(head.get("plan") is not None) + q + delete + seal
        return (head["revision"] + revision_debt <= self.maximum
                and head["serial"] + serial_debt <= self.maximum)

    def change(self, kind, head_read, snapshot, next_head, actor="admin", evidence=None, inputs=None,
               unsafe=False):
        if not unsafe and not self.room(next_head):
            self.fail("Limit", "cleanup_reserve", head=head_read)
        proof = {"head": head_read, **(evidence or {})}
        return self.candidate(kind, f"head/{next_head['scope']}", next_head, snapshot["etag"], actor, proof, inputs)

    def write_payload(self, scope, generation, body, actor="admin", evidence=None):
        return self.immutable("payload", key(scope, generation, digest(body)), body, actor,
                              evidence, {"scope": scope, "generation": generation})

    def snapshot_prepare(self, operation, label="point", actor="admin", hook=None,
                         refresh_hook=None, proof_hook=None, faults=None, unsafe=None):
        faults = faults or {}
        descriptor_key = f"snapshot/source/{self.principal[actor]}/{operation}"
        initial, old = self.get(descriptor_key, actor, fault=faults.get("initial"))
        descriptor_read = initial
        if hook:
            hook()
        head_read, head = self.fresh_head(actor)
        self.auth(head, actor, read=True)
        head2 = None
        if old["status"] == "missing" and unsafe != "stale_missing":
            # The initial absence can precede another process's accepted point.
            # Only an observation after this HEAD can diagnose its dependency.
            descriptor_read, old = self.get(descriptor_key, actor, fault=faults.get("refresh"))
            if refresh_hook:
                refresh_hook()
            head2, refreshed = self.fresh_head(actor)
            self.auth(refreshed, actor, read=True)
            if refreshed != head:
                self.fail("Conflict", "snapshot_prepare_barrier", actor=actor,
                          head1=head_read, head2=head2)
        view = self.event("snapshot_prepare_view", actor=actor, process=self.process[actor],
                          creator=self.principal[actor], operation=operation, initial=initial,
                          head1=head_read, descriptor=descriptor_read, head2=head2)
        if old["status"] == "present":
            if old["body"]["label"] != label:
                self.fail("Conflict", "snapshot_prepare", descriptor=descriptor_read, head=head_read)
            self.event("snapshot_prepared", view=view, descriptor=descriptor_read, label=label)
            return old["body"]
        if old["status"] != "missing":
            self.fail("Unknown", "snapshot_prepare", read=descriptor_read)
        body = head["body"]
        if proof_hook:
            proof_hook()
        proof_read, proof = self.get(f"accepted/source/{self.principal[actor]}/{operation}", actor,
                                     fault=faults.get("proof"))
        if proof["status"] == "present":
            proof_head = None
            if unsafe != "late_proof":
                proof_head, refreshed = self.fresh_head(actor)
                self.auth(refreshed, actor, read=True)
                if refreshed != head:
                    self.fail("Conflict", "snapshot_prepare_barrier", actor=actor,
                              head1=head_read, head2=proof_head)
            self.fail("Corrupt", "descriptor_dependency", view=view, proof=proof_read, proof_head=proof_head)
        if any(item["ref"]["operation"] == operation and item["ref"]["creator"] == self.principal[actor]
               for item in body["snapshots"]):
            self.fail("Corrupt", "descriptor_dependency", view=view, proof=proof_read, proof_head=None)
        if proof["status"] != "missing" and unsafe != "unknown_proof":
            self.fail("Unknown", "snapshot_prepare", read=proof_read)
        if body["lifecycle"] != "ready" or body["terminal"] is not None:
            self.fail("Lifecycle", "snapshot_prepare", head=head_read)
        if body["plan"] is not None or body["sweep"] is not None or body["owner_pending"]:
            self.fail("Fenced", "snapshot_prepare", head=head_read)
        if len(body["snapshots"]) >= body["limits"]["max_points"] or (
                sum(item["point"]["pages"] for item in body["snapshots"]) + body["pages"]
                > body["limits"]["max_pages"]):
            self.fail("Budget", "snapshot_limit", head=head_read)
        if any(item["label"] == label for item in body["snapshots"]):
            self.fail("Conflict", "snapshot_label", head=head_read)
        root_read, root = self.present(key("source", body["A"], body["root"]), actor)
        if root["body"]["count"] != body["pages"]:
            self.fail("Corrupt", "manifest", read=root_read)
        descriptor = {"kind": "snapshot_descriptor", "scope": "source", "creator": self.principal[actor],
                      "operation": operation, "label": label, "base": deepcopy(body), "etag": head["etag"],
                      "point": {"root": body["root"], "pages": body["pages"], "sequence": body["sequence"],
                                "revision": body["revision"]}, "capture_serial": body["serial"] + 1}
        accepted, _ = self.immutable("snapshot_descriptor", descriptor_key, descriptor, actor,
                       {"head": head_read, "root": root_read, "prior": descriptor_read, "proof": proof_read,
                        "prepare_view": view})
        self.event("snapshot_prepared", view=view, descriptor=accepted, label=label)
        return descriptor

    def s1_open(self, actor="admin", unsafe=False):
        """Only the staged reader boundary; this does not implement a wire codec."""
        head_read, head = self.fresh_head(actor)
        if not unsafe and ("restore_origin" not in head["body"] or head["body"]["restore_origin"] is not None):
            self.fail("Corrupt", "s1_origin_boundary", head=head_read)
        self.event("s1_source_admission", head=head_read, actor=actor, process=self.process[actor])
        return head["body"]

    @staticmethod
    def entry(descriptor):
        return {"ref": {"creator": descriptor["creator"], "operation": descriptor["operation"],
                         "capture_serial": descriptor["capture_serial"], "descriptor_hash": digest(descriptor)},
                "label": descriptor["label"], "point": deepcopy(descriptor["point"])}

    def snapshot_capture(self, descriptor, actor="admin", unsafe=False):
        desc_read, durable = self.present(f"snapshot/source/{descriptor['creator']}/{descriptor['operation']}", actor)
        head_read, head = self.fresh_head(actor)
        self.auth(head, actor, read=True)
        if durable["body"] != descriptor:
            self.fail("Conflict", "snapshot_descriptor", descriptor=desc_read)
        if not unsafe and (head["body"] != descriptor["base"] or head["etag"] != descriptor["etag"]):
            self.fail("Fenced", "snapshot_capture", head=head_read, descriptor=desc_read)
        next_head = deepcopy(head["body"])
        next_head["serial"] += 1
        next_head["snapshots"].append(self.entry(descriptor))
        return self.change("snapshot_capture", head_read, head, next_head, actor,
                           {"descriptor": desc_read}, unsafe=unsafe)

    def capture(self, operation, label="point"):
        descriptor = self.snapshot_prepare(operation, label)
        self.run(self.snapshot_capture(descriptor))
        return self.entry(descriptor)

    def snapshot_release(self, entry, actor="admin", unsafe=False):
        head_read, head = self.fresh_head(actor)
        body = head["body"]
        if body["plan"] is not None or body["sweep"] is not None or body["owner_pending"]:
            self.fail("Fenced", "snapshot_release", head=head_read)
        if entry not in body["snapshots"]:
            self.fail("Conflict", "snapshot_release", head=head_read)
        evidence = {}
        if not unsafe:
            proof = {"kind": "snapshot_accepted", "scope": "source", "entry": deepcopy(entry)}
            proof_read, _ = self.immutable("snapshot_accepted",
                  f"accepted/source/{entry['ref']['creator']}/{entry['ref']['operation']}", proof, actor,
                  {"head": head_read})
            evidence["proof"] = proof_read
        next_head = deepcopy(body)
        next_head["serial"] += 1
        next_head["snapshots"].remove(entry)
        return self.change("snapshot_release", head_read, head, next_head, actor, evidence)

    def snapshot_observe(self, entry, actor="admin", hook=None):
        first, before = self.present("head/source", actor)
        ref = entry["ref"]
        descriptor_read, descriptor = self.get(f"snapshot/source/{ref['creator']}/{ref['operation']}", actor)
        proof_read, proof = self.get(f"accepted/source/{ref['creator']}/{ref['operation']}", actor)
        if hook:
            hook()
        second, after = self.present("head/source", actor)
        if before != after:
            self.fail("Conflict", "snapshot_observe", head1=first, head2=second)
        self.auth(after, actor)
        if descriptor["status"] != "present" or self.entry(descriptor["body"]) != entry:
            self.fail("Corrupt", "snapshot_observe", descriptor=descriptor_read, head2=second)
        if entry in after["body"]["snapshots"]:
            result = "retained"
        elif proof["status"] == "present" and proof["body"].get("entry") == entry and after["body"]["serial"] > ref["capture_serial"]:
            result = "released_observed"
        else:
            result = "fenced_unknown"
        self.event("snapshot_observation", entry=entry, result=result, actor=actor,
                   head1=first, head2=second, descriptor=descriptor_read, proof=proof_read,
                   historical_ack=False)
        return result

    def source_update(self, action, value=None, unsafe=False):
        head_read, head = self.fresh_head()
        body = head["body"]
        if body["terminal"] is not None or body["lifecycle"] == "deleted":
            self.fail("Lifecycle", action, head=head_read)
        if body["plan"] is not None and action not in ("revoke", "grant"):
            self.fail("Fenced", action, head=head_read)
        next_head = deepcopy(body)
        next_head["serial"] += 1
        next_head["revision"] += 1
        evidence = {}
        if action == "sql":
            pages = [frame("source", i + 1, item) for i, item in enumerate(value)]
            root = manifest("source", pages)
            evidence["payload"] = [self.write_payload("source", body["A"], item)[0] for item in [*pages, root]]
            next_head.update(root=digest(root), pages=len(pages), sequence=body["sequence"] + 1)
        elif action in ("revoke", "grant"):
            next_head["policy"]["2"]["admin"] = action == "grant"
            next_head["policy"]["2"]["read"] = action == "grant"
        elif action == "delete":
            next_head["lifecycle"] = "deleted"
        elif action == "quota":
            if value < body["pages"]:
                self.fail("Budget", "current_quota", head=head_read)
            next_head["quota"] = value
        elif action == "limits":
            if (value["max_points"] < len(body["snapshots"]) or
                    value["max_pages"] < sum(item["point"]["pages"] for item in body["snapshots"])):
                self.fail("Budget", "retained_limits", head=head_read)
            next_head["limits"] = value
        else:
            raise ValueError(action)
        return self.change(action, head_read, head, next_head, evidence=evidence, unsafe=unsafe)

    def begin(self):
        read, head = self.fresh_head()
        body = head["body"]
        if body["plan"] is not None or body["sweep"] is not None or body["lifecycle"] != "ready" or body["terminal"] is not None:
            self.fail("Fenced", "compact_begin", head=read)
        next_head = deepcopy(body)
        next_head["serial"] += 1
        next_head["M"] += 1
        next_head["plan"] = {"source": body["A"], "target": next_head["M"], "phase": "copying",
                              "basis": {name: deepcopy(body[name]) for name in
                                        ("root", "pages", "sequence", "snapshots", "limits", "quota")}}
        return self.change("compact_begin", read, head, next_head)

    def roots(self, head):
        return [{"root": head["root"], "pages": head["pages"]}, *[item["point"] for item in head["snapshots"]]]

    def verify_tree(self, scope, generation, point, actor="admin"):
        reads = []
        root_read, root = self.present(key(scope, generation, point["root"]), actor)
        reads.append(root_read)
        body = root["body"]
        if (digest(body) != point["root"] or body["scope"] != scope or body["kind"] != "manifest"
                or body["count"] != point["pages"] or len(body["pages"]) != point["pages"]):
            self.fail("Corrupt", "tree", read=root_read)
        pages = []
        for number, edge in enumerate(body["pages"], 1):
            read, page = self.present(key(scope, generation, edge["hash"]), actor)
            reads.append(read)
            if (edge["number"] != number or digest(page["body"]) != edge["hash"] or
                    page["body"]["scope"] != scope or page["body"]["number"] != number):
                self.fail("Corrupt", "tree", read=read)
            pages.append(page["body"])
        return reads, [*pages, body]

    def copy_generation(self, omit_snapshot=False):
        head_read, head = self.fresh_head()
        plan = head["body"]["plan"]
        if plan is None:
            self.fail("Fenced", "compact_copy", head=head_read)
        roots = self.roots(head["body"])
        if omit_snapshot:
            roots = roots[:1]
        for point in roots:
            reads, frames = self.verify_tree("source", plan["source"], point)
            for item in frames:
                self.write_payload("source", plan["target"], item, evidence={"source": reads})

    def seal(self, unsafe=False):
        head_read, head = self.fresh_head()
        body = head["body"]
        plan = body["plan"]
        if plan is None or plan["phase"] != "copying":
            self.fail("Fenced", "compact_seal", head=head_read)
        verified = []
        for point in self.roots(body)[:1] if unsafe else self.roots(body):
            reads, _ = self.verify_tree("source", plan["target"], point)
            verified.extend(reads)
        next_head = deepcopy(body)
        next_head["serial"] += 1
        next_head["plan"]["phase"] = "sealed"
        return self.change("compact_seal", head_read, head, next_head, evidence={"closure": verified})

    def promote(self):
        read, head = self.fresh_head()
        body = head["body"]
        if body["plan"] is None or body["plan"]["phase"] != "sealed":
            self.fail("Fenced", "compact_promote", head=read)
        next_head = deepcopy(body)
        next_head["serial"] += 1
        next_head["A"] = body["plan"]["target"]
        next_head["plan"] = None
        return self.change("compact_promote", read, head, next_head)

    def compact_abort(self):
        read, head = self.fresh_head()
        if head["body"]["plan"] is None:
            self.fail("Fenced", "compact_abort", head=read)
        next_head = deepcopy(head["body"])
        next_head["serial"] += 1
        next_head["plan"] = None
        return self.change("compact_abort", read, head, next_head)

    def terminal(self, scope="source", unsafe=False):
        actor = "admin" if scope == "source" else "a"
        read, head = self.present(f"head/{scope}", actor)
        body = head["body"]
        if body["lifecycle"] != "deleted" or body["terminal"] is not None:
            self.fail("Lifecycle", "terminal", head=read)
        if not unsafe and (body.get("snapshots") or body.get("plan") is not None or body.get("sweep") is not None):
            self.fail("Fenced", "terminal", head=read)
        next_head = deepcopy(body)
        next_head["serial"] += 1
        next_head["terminal"] = next_head["serial"]
        evidence = {}
        if scope != "source":
            proof_read, proof = self.present(f"abort/{body['origin']['descriptor']}", actor)
            if proof["body"]["barrier"] != "own_deleted" or proof["body"]["head"] != self.abort_barrier(body):
                self.fail("Corrupt", "terminal_source", proof=proof_read)
            evidence["proof"] = proof_read
        return self.change("terminal", read, head, next_head, actor, evidence, unsafe=unsafe)

    @staticmethod
    def retired(head, generation):
        return 0 < generation <= head["M"] and (head["terminal"] is not None or
               (generation != head["A"] and (head.get("plan") is None or generation != head["plan"]["target"])))

    def deletion(self, scope, generation, object_key):
        head_read, head = self.present(f"head/{scope}")
        if not self.retired(head["body"], generation):
            self.fail("Fenced", "gc", head=head_read)
        object_read, obj = self.present(object_key)
        return self.candidate("gc_delete", object_key, None, obj["etag"],
                              evidence={"head": head_read, "object": object_read},
                              inputs={"scope": scope, "generation": generation})

    def sweep(self, scope, generation):
        # Explicit finite exact-key inventory. LIST/checkpoint pagination is not modeled.
        for object_key in sorted(list(self.store)):
            if object_key.startswith(f"data/{scope}/{generation}/"):
                self.run(self.deletion(scope, generation, object_key))

    def checkpoint(self, scope, generation, count=1, unsafe=False):
        actor = "admin" if scope == "source" else "a"
        read, head = self.present(f"head/{scope}", actor)
        body = head["body"]
        if (not self.retired(body, generation) or body.get("sweep") is not None
                or body.get("plan") is not None or not (body["lifecycle"] == "ready" or body["terminal"] is not None)):
            self.fail("Fenced", "checkpoint", head=read)
        entries, inspected = [], []
        for path in sorted(path for path in self.store if path.startswith(f"data/{scope}/{generation}/"))[:count]:
            object_read, value = self.present(path, actor)
            inspected.append(object_read)
            entries.append({"key": path, "etag": value["etag"], "disposition": "pending"})
        if not entries:
            self.fail("Empty", "checkpoint", head=read)
        next_head = deepcopy(body); next_head["serial"] += 1
        next_head["sweep"] = {"serial": next_head["serial"], "generation": generation, "entries": entries}
        return self.change("checkpoint", read, head, next_head, actor, {"objects": inspected}, unsafe=unsafe)

    def settle_checkpoint(self, scope, unknown_first=False):
        actor = "admin" if scope == "source" else "a"
        read, head = self.present(f"head/{scope}", actor)
        checkpoint = head["body"].get("sweep")
        if checkpoint is None or not any(item["disposition"] == "pending" for item in checkpoint["entries"]):
            self.fail("Conflict", "settle", head=read)
        disposed, outcomes = deepcopy(checkpoint), []
        for entry in disposed["entries"]:
            if entry["disposition"] != "pending":
                continue
            object_read, obj = self.get(entry["key"], actor)
            if obj["status"] == "missing":
                entry["disposition"] = "absent"
                outcomes.append({"read": object_read, "delete": None})
            else:
                call = self.candidate("gc_delete", entry["key"], None, entry["etag"], actor,
                           {"head": read, "object": object_read, "checkpoint": read},
                           {"scope": scope, "generation": checkpoint["generation"]})
                result = self.run(call, lost=unknown_first)
                if result["status"] == "unknown":
                    self.fail("Unknown", "settle", delete=call)
                entry["disposition"] = "applied" if result["status"] == "applied" else "mismatch"
                outcomes.append({"read": object_read, "delete": call})
        next_head = deepcopy(head["body"]); next_head["serial"] += 1; next_head["sweep"] = disposed
        return self.change("settle", read, head, next_head, actor, {"outcomes": outcomes})

    def clear_checkpoint(self, scope):
        actor = "admin" if scope == "source" else "a"
        read, head = self.present(f"head/{scope}", actor)
        checkpoint = head["body"].get("sweep")
        if checkpoint is None or any(item["disposition"] == "pending" for item in checkpoint["entries"]):
            self.fail("Conflict", "clear", head=read)
        next_head = deepcopy(head["body"]); next_head["serial"] += 1; next_head["sweep"] = None
        return self.change("clear", read, head, next_head, actor)

    def restore_prepare(self, entry, operation=100, actor="a", name="backup", scope="target", quota=3,
                        expected_name_revision=None):
        admission = self.target_gate(self.principal[actor], scope, actor, "restore_prepare")
        object_key = f"creation/{self.principal[actor]}/{operation}"
        old_read, old = self.get(object_key, actor)
        input_value = {"operation": operation, "name": name, "scope": scope, "source": entry,
                       "creator": self.principal[actor], "quota": quota, "recipe": "restore",
                       "expected_name_revision": expected_name_revision}
        if old["status"] == "present":
            if old["body"]["input"] != input_value:
                self.fail("Conflict", "restore_prepare", descriptor=old_read)
            return old["body"]
        if old["status"] != "missing":
            self.fail("Unknown", "restore_prepare", descriptor=old_read)
        source_read, source = self.present("head/source", actor)
        self.auth(source, actor, read=True)
        if entry not in source["body"]["snapshots"] or source["body"]["terminal"] is not None:
            self.fail("Released", "restore_prepare", head=source_read)
        if quota < entry["point"]["pages"]:
            self.fail("Budget", "target_quota", head=source_read)
        descriptor_read, descriptor = self.present(
            f"snapshot/source/{entry['ref']['creator']}/{entry['ref']['operation']}", actor)
        if self.entry(descriptor["body"]) != entry:
            self.fail("Corrupt", "restore_prepare", descriptor=descriptor_read)
        value = {"kind": "restore_descriptor", "input": input_value, "target_acl": self.principal[actor],
                 "target_sequence": 0, "target_request_epoch": 1}
        self.immutable("restore_descriptor", object_key, value, actor,
                       {"source": source_read, "snapshot_descriptor": descriptor_read, "prior": old_read,
                        "target_admission": admission})
        return value

    def view(self, descriptor, actor="a"):
        name = descriptor["input"]["name"]
        scope = descriptor["input"]["scope"]
        descriptor_read, durable = self.present(
            f"creation/{descriptor['input']['creator']}/{descriptor['input']['operation']}", actor)
        if durable["body"] != descriptor:
            self.fail("Conflict", "target_descriptor", read=descriptor_read)
        first, before = self.get(f"name/{name}", actor)
        head_read, head = self.get(f"head/{scope}", actor)
        second, after = self.get(f"name/{name}", actor)
        if before != after:
            self.fail("Conflict", "target_view", name1=first, name2=second)
        return {"name1": first, "name2": second, "target": head_read, "target_descriptor": descriptor_read}, after, head

    def reserve(self, descriptor, actor="a"):
        admission = self.target_gate(descriptor["input"]["creator"], descriptor["input"]["scope"], actor, "reserve")
        descriptor_read, durable = self.present(
            f"creation/{descriptor['input']['creator']}/{descriptor['input']['operation']}", actor)
        if durable["body"] != descriptor:
            self.fail("Conflict", "restore_reserve", descriptor=descriptor_read)
        name_read, name = self.get(f"name/{descriptor['input']['name']}", actor)
        expected = descriptor["input"]["expected_name_revision"]
        if ((name["status"] == "present" and (name["body"]["state"] != "tombstone" or name["body"]["revision"] != expected))
                or (name["status"] == "missing" and expected is not None)):
            self.fail("Conflict", "name_reserved", name=name_read)
        body = {"kind": "name", "name": descriptor["input"]["name"], "scope": descriptor["input"]["scope"],
                "descriptor": digest(descriptor), "state": "reserved", "revision": 1 if name["status"] == "missing"
                else name["body"]["revision"] + 1}
        return self.candidate("reserve", f"name/{body['name']}", body,
                              "absent" if name["status"] == "missing" else name["etag"], actor,
                              {"descriptor": descriptor_read, "name": name_read, "target_admission": admission})

    def provision(self, descriptor, actor="a"):
        admission = self.target_gate(descriptor["input"]["creator"], descriptor["input"]["scope"], actor, "provision")
        evidence, name, head = self.view(descriptor, actor)
        if (name["status"] != "present" or name["body"]["state"] != "reserved"
                or name["body"]["descriptor"] != digest(descriptor)):
            self.fail("Fenced", "provision", **evidence)
        if head["status"] != "missing":
            self.fail("Conflict", "provision", **evidence)
        scope = descriptor["input"]["scope"]
        empty = manifest(scope, [])
        payload_read, _ = self.write_payload(scope, 1, empty, actor)
        body = {"kind": "target_head", "format": 9, "scope": scope, "serial": 1, "revision": 1,
                "sequence": 0, "request_epoch": 1, "requests": [], "owner": 0, "active": False,
                "creator": self.principal[actor], "A": 1, "M": 1, "terminal": None,
                "lifecycle": "provisioning", "root": digest(empty), "pages": 0,
                "origin": {"descriptor": digest(descriptor), "phase": "copying", "completion": None}}
        return self.candidate("provision", f"head/{scope}", body, "absent", actor,
                              {**evidence, "empty": payload_read, "target_admission": admission}, {"descriptor": descriptor})

    def start_copy(self, descriptor, actor="a", budget=10, name=None):
        admission = self.target_gate(descriptor["input"]["creator"], descriptor["input"]["scope"], actor, "copy")
        evidence, binding, target = self.view(descriptor, actor)
        if (binding["status"] != "present" or binding["body"]["state"] != "reserved"
                or binding["body"]["descriptor"] != digest(descriptor)
                or target["status"] != "present" or target["body"]["lifecycle"] != "provisioning"
                or target["body"]["origin"]["phase"] != "copying"):
            self.fail("Fenced", "start_copy", **evidence)
        source_read, source = self.present("head/source", actor)
        self.auth(source, actor, read=True)
        entry = descriptor["input"]["source"]
        if source["body"]["terminal"] is not None or entry not in source["body"]["snapshots"]:
            self.fail("Released", "start_copy", source=source_read)
        identifier = name or self.unique("attempt")
        assert identifier not in self.attempts
        attempt = {"actor": actor, "process": self.process[actor], "alive": True, "failed": False,
                   "descriptor": deepcopy(descriptor), "source": source_read, "source_head": deepcopy(source), "admission": admission,
                   "target": evidence["target"], "budget": budget, "closed": False, "source_reads": [], "target_reads": [],
                   "pages": {}, "root": None, "validation": None}
        self.attempts[identifier] = attempt
        self.event("copy_start", id=identifier, actor=actor, process=self.process[actor],
                   descriptor=descriptor, source=source_read, budget=budget, target_admission=admission, **evidence)
        return identifier

    def attempt(self, identifier):
        attempt = self.attempts[identifier]
        if (not attempt["alive"] or attempt["failed"] or attempt["closed"] or
                attempt["process"] != self.process[attempt["actor"]]):
            self.fail("ExpiredAttempt", "copy", attempt=identifier)
        return attempt

    def abandon(self, identifier, code, operation, **evidence):
        self.attempts[identifier]["failed"] = True
        self.event("copy_abandoned", attempt=identifier, reason=code)
        self.fail(code, operation, attempt=identifier, **evidence)

    def read_source_root(self, identifier):
        attempt = self.attempt(identifier)
        entry = attempt["descriptor"]["input"]["source"]
        read, root = self.source_get(identifier, key("source", attempt["source_head"]["body"]["A"], entry["point"]["root"]))
        body = root["body"]
        if (digest(body) != entry["point"]["root"] or body["scope"] != "source"
                or body["count"] != entry["point"]["pages"] or len(body["pages"]) != body["count"]):
            attempt["failed"] = True
            self.fail("Corrupt", "source_manifest", read=read, attempt=identifier)
        attempt["root"] = body

    def source_get(self, identifier, object_key, fault=None):
        attempt = self.attempt(identifier)
        if attempt["budget"] <= 0:
            attempt["failed"] = True
            self.event("copy_failure", attempt=identifier, domain="local", cause="budget", result="Budget", probe=None)
            raise Rejected("Budget")
        attempt["budget"] -= 1
        read, result = self.get(object_key, attempt["actor"], fault)
        attempt["source_reads"].append(read)
        if result["status"] != "present":
            self.project_failure(identifier, "source", "physical", read)
        return read, result

    def project_failure(self, identifier, domain, cause, read=None, unsafe=None):
        attempt = self.attempts[identifier]
        attempt["failed"] = True
        result, probe = ("Budget" if cause == "budget" else "Corrupt" if cause == "semantic" else "Missing"), None
        if domain == "source" and cause == "physical":
            probe, current = self.get("head/source", attempt["actor"])
            if (current["status"] == "present" and current["body"]["serial"] >= attempt["source_head"]["body"]["serial"]
                    and current["body"]["A"] >= attempt["source_head"]["body"]["A"]
                    and self.retired(current["body"], attempt["source_head"]["body"]["A"])):
                result = "SnapshotExpired"
            elif current["status"] == "present":
                # A protected namespace's missing immutable dependency is not a
                # successful expiry. The finite model uses Corrupt as its
                # fail-closed class, not as a claim about the first wire errno.
                result = "Corrupt"
        if unsafe:
            result = unsafe
        self.event("copy_failure", attempt=identifier, domain=domain, cause=cause, read=read, probe=probe, result=result)
        raise Rejected(result)

    def copy_page(self, identifier, number):
        attempt = self.attempt(identifier)
        if attempt["root"] is None:
            self.read_source_root(identifier)
        edge = attempt["root"]["pages"][number - 1]
        read, source_page = self.source_get(identifier, key("source", attempt["source_head"]["body"]["A"], edge["hash"]))
        body = source_page["body"]
        if (digest(body) != edge["hash"] or body["scope"] != "source" or body["number"] != number):
            self.project_failure(identifier, "source", "semantic", read)
        target_page = frame(attempt["descriptor"]["input"]["scope"], number, body["value"])
        target_read, _ = self.write_payload(target_page["scope"], 1, target_page, attempt["actor"],
                                           {"source": [read], "attempt": identifier})
        attempt["target_reads"].append(target_read)
        attempt["pages"][number] = target_page

    def validate_copy(self, identifier, unsafe=False):
        attempt = self.attempt(identifier)
        point = attempt["descriptor"]["input"]["source"]["point"]
        if not unsafe and len(attempt["pages"]) != point["pages"]:
            self.abandon(identifier, "Incomplete", "copy_validation")
        pages = [attempt["pages"][number] for number in sorted(attempt["pages"])]
        root = manifest(attempt["descriptor"]["input"]["scope"], pages)
        target_read, _ = self.write_payload(root["scope"], 1, root, attempt["actor"],
                                          {"source": attempt["source_reads"], "attempt": identifier})
        attempt["target_reads"].append(target_read)
        attempt["target_root"] = digest(root)
        validation = self.event("copy_validated", attempt=identifier,
                   source_reads=attempt["source_reads"], target_reads=attempt["target_reads"],
                   root=digest(root), pages=len(pages), native="symbolic_valid_image")
        attempt["validation"] = validation
        return validation

    def completion(self, identifier, hook=None, unsafe=False):
        attempt = self.attempt(identifier)
        if attempt["validation"] is None:
            self.abandon(identifier, "Incomplete", "completion")
        actor = attempt["actor"]
        entry = attempt["descriptor"]["input"]["source"]
        first, before = self.present("head/source", actor)
        if not unsafe:
            try:
                self.auth(before, actor, read=True)
            except Rejected:
                attempt["failed"] = True
                self.event("copy_abandoned", attempt=identifier, reason="Denied")
                raise
        descriptor_read, descriptor = self.get(f"snapshot/source/{entry['ref']['creator']}/{entry['ref']['operation']}", actor)
        proof_read, proof = self.get(f"accepted/source/{entry['ref']['creator']}/{entry['ref']['operation']}", actor)
        if hook:
            hook()
        second, after = self.present("head/source", actor)
        if not unsafe:
            try:
                self.auth(after, actor, read=True)
            except Rejected:
                attempt["failed"] = True
                self.event("copy_abandoned", attempt=identifier, reason="Denied")
                raise
        if before != after:
            self.abandon(identifier, "Conflict", "completion_barrier", actor=actor, head1=first, head2=second)
        if descriptor["status"] != "present" or self.entry(descriptor["body"]) != entry:
            self.abandon(identifier, "Corrupt", "completion_descriptor", descriptor=descriptor_read, head2=second)
        same_identity = [item for item in after["body"]["snapshots"] if
                         (item["ref"]["creator"], item["ref"]["operation"]) ==
                         (entry["ref"]["creator"], entry["ref"]["operation"])]
        if same_identity and same_identity != [entry]:
            self.abandon(identifier, "Corrupt", "completion_identity", descriptor=descriptor_read, head2=second)
        retained = entry in after["body"]["snapshots"]
        released = (proof["status"] == "present" and proof["body"].get("entry") == entry
                    and after["body"]["serial"] > entry["ref"]["capture_serial"])
        if not retained and not released:
            self.abandon(identifier, "Corrupt", "completion_release", proof=proof_read, head2=second)
        value = {"kind": "completion", "descriptor": digest(attempt["descriptor"]),
                 "source": entry, "scope": attempt["descriptor"]["input"]["scope"],
                 "root": attempt["target_root"], "pages": entry["point"]["pages"],
                 "request_epoch": 1, "requests": [], "rewrap_version": 1}
        attempt["closed"] = True
        return self.candidate("completion", f"completion/{value['scope']}/{value['descriptor']}", value,
                              "absent", actor, {"attempt": identifier, "validation": attempt["validation"],
                               "head1": first, "head2": second, "descriptor": descriptor_read, "proof": proof_read,
                               "target_admission": attempt["admission"]})

    def copy_all(self, descriptor, actor="a", budget=10):
        attempt = self.start_copy(descriptor, actor, budget)
        for number in range(1, descriptor["input"]["source"]["point"]["pages"] + 1):
            self.copy_page(attempt, number)
        self.validate_copy(attempt)
        call = self.completion(attempt)
        self.run(call)
        return attempt

    def install_copied(self, descriptor, actor="a", unsafe=False):
        admission = self.target_gate(descriptor["input"]["creator"], descriptor["input"]["scope"], actor, "install_copied")
        evidence, binding, target = self.view(descriptor, actor)
        if (target["status"] != "present" or binding["status"] != "present"
                or binding["body"]["state"] != "reserved" or binding["body"]["descriptor"] != digest(descriptor)
                or target["body"]["lifecycle"] != "provisioning" or target["body"]["origin"]["phase"] != "copying"):
            self.fail("Fenced", "install_copied", **evidence)
        scope = descriptor["input"]["scope"]
        completion_read, completion = self.present(f"completion/{scope}/{digest(descriptor)}", actor)
        reads, _ = self.verify_tree(scope, 1, {"root": completion["body"]["root"],
                                              "pages": completion["body"]["pages"]}, actor)
        second, after = self.present(f"head/{scope}", actor)
        if after != target:
            self.fail("Conflict", "install_copied", head1=evidence["target"], head2=second)
        next_head = deepcopy(target["body"])
        next_head["serial"] += 1
        next_head["root"] = completion["body"]["root"]
        next_head["pages"] = completion["body"]["pages"]
        next_head["origin"].update(phase="copied", completion=digest(completion["body"]))
        return self.change("install_copied", evidence["target"], target, next_head, actor,
                           {**evidence, "completion": completion_read, "closure": reads, "head2": second,
                            "target_admission": admission})

    def bind(self, descriptor, actor="a", unsafe=False):
        admission = self.target_gate(descriptor["input"]["creator"], descriptor["input"]["scope"], actor, "bind")
        evidence, binding, target = self.view(descriptor, actor)
        if (binding["status"] != "present" or binding["body"]["state"] != "reserved"
                or binding["body"]["descriptor"] != digest(descriptor)
                or target["status"] != "present" or target["body"]["lifecycle"] != "provisioning"
                or (not unsafe and target["body"]["origin"]["phase"] != "copied")):
            self.fail("Fenced", "bind", **evidence)
        if not unsafe:
            evidence["completion"] = self.referenced_completion(descriptor, target, actor)
        next_name = deepcopy(binding["body"])
        next_name["revision"] += 1
        next_name["state"] = "bound"
        return self.candidate("bind", f"name/{next_name['name']}", next_name, binding["etag"], actor,
                              {**evidence, "target_admission": admission})

    def ready(self, descriptor, actor="a", unsafe=False):
        admission = self.target_gate(descriptor["input"]["creator"], descriptor["input"]["scope"], actor, "ready")
        evidence, binding, target = self.view(descriptor, actor)
        if (binding["status"] != "present" or binding["body"]["state"] != "bound"
                or binding["body"]["descriptor"] != digest(descriptor)
                or target["status"] != "present" or target["body"]["lifecycle"] != "provisioning"
                or (not unsafe and target["body"]["origin"]["phase"] != "copied")):
            self.fail("Fenced", "ready", **evidence)
        if not unsafe:
            evidence["completion"] = self.referenced_completion(descriptor, target, actor)
        closure, _ = self.verify_tree(target["body"]["scope"], 1, target["body"], actor)
        next_head = deepcopy(target["body"])
        next_head["serial"] += 1
        next_head["revision"] += 1
        next_head["lifecycle"] = "ready"
        return self.change("ready", evidence["target"], target, next_head, actor,
                           {**evidence, "closure": closure, "target_admission": admission})

    def referenced_completion(self, descriptor, target, actor):
        read, record = self.get(f"completion/{descriptor['input']['scope']}/{digest(descriptor)}", actor)
        if (record["status"] != "present" or digest(record["body"]) != target["body"]["origin"]["completion"]
                or record["body"]["descriptor"] != digest(descriptor)):
            self.fail("Corrupt", "referenced_completion", read=read)
        return read

    def abort_accept(self, descriptor, actor="a"):
        admission = self.target_gate(descriptor["input"]["creator"], descriptor["input"]["scope"], actor, "abort_accept")
        evidence, binding, target = self.view(descriptor, actor)
        if binding["status"] != "present" or binding["body"]["descriptor"] != digest(descriptor):
            self.fail("Conflict", "abort_accept", **evidence)
        if binding["body"]["state"] == "bound":
            self.fail("CannotAbortBound", "abort_accept", **evidence)
        if binding["body"]["state"] != "reserved":
            self.fail("Fenced", "abort_accept", **evidence)
        next_name = deepcopy(binding["body"])
        next_name["revision"] += 1
        next_name["state"] = "aborting"
        return self.candidate("abort_accept", f"name/{next_name['name']}", next_name, binding["etag"], actor,
                              {**evidence, "target_admission": admission})

    def abort_fence(self, descriptor, actor="a"):
        admission = self.target_gate(descriptor["input"]["creator"], descriptor["input"]["scope"], actor, "abort_fence")
        evidence, binding, target = self.view(descriptor, actor)
        evidence["target_admission"] = admission
        if (binding["status"] != "present" or binding["body"]["state"] != "aborting"
                or binding["body"]["descriptor"] != digest(descriptor)):
            self.fail("Fenced", "abort_fence", **evidence)
        if target["status"] == "missing":
            # The empty bootstrap is the existing small FenceAbsent allocation.
            scope = descriptor["input"]["scope"]
            empty = manifest(scope, [])
            empty_read, _ = self.write_payload(scope, 1, empty, actor)
            body = {"kind": "target_head", "format": 9, "scope": scope, "serial": 1, "revision": 1,
                    "sequence": 0, "request_epoch": 1, "requests": [], "owner": 0, "active": False,
                    "creator": self.principal[actor], "A": 1, "M": 1, "terminal": None,
                    "lifecycle": "deleted", "root": digest(empty), "pages": 0,
                    "origin": {"descriptor": digest(descriptor), "phase": "copying", "completion": None}}
            return self.candidate("abort_absent", f"head/{scope}", body, "absent", actor,
                                  {**evidence, "empty": empty_read})
        if target["body"].get("origin", {}).get("descriptor") != digest(descriptor):
            self.fail("ForeignOccupied", "abort_fence", **evidence)
        if target["body"]["lifecycle"] != "provisioning":
            self.fail("Fenced", "abort_fence", **evidence)
        body = deepcopy(target["body"])
        body["serial"] += 1
        body["revision"] += 1
        body["lifecycle"] = "deleted"
        return self.change("abort_fence", evidence["target"], target, body, actor, evidence)

    def abort_release(self, descriptor, actor="a"):
        admission = self.target_gate(descriptor["input"]["creator"], descriptor["input"]["scope"], actor, "abort_release")
        evidence, binding, target = self.view(descriptor, actor)
        evidence["target_admission"] = admission
        if (binding["status"] != "present" or binding["body"]["state"] != "aborting" or target["status"] != "present"
                or binding["body"]["descriptor"] != digest(descriptor)):
            self.fail("Fenced", "abort_release", **evidence)
        own = target["body"].get("origin", {}).get("descriptor") == digest(descriptor)
        if own and target["body"]["lifecycle"] != "deleted":
            self.fail("Fenced", "abort_release", **evidence)
        proof = {"kind": "abort_proof", "descriptor": digest(descriptor), "scope": descriptor["input"]["scope"],
                 "barrier": "own_deleted" if own else "foreign_occupied", "head": self.abort_barrier(target["body"])}
        proof_read, _ = self.immutable("abort_proof", f"abort/{digest(descriptor)}", proof, actor, evidence)
        next_name = deepcopy(binding["body"])
        next_name["revision"] += 1
        next_name["state"] = "tombstone"
        next_name["proof"] = digest(proof)
        return self.candidate("abort_release", f"name/{next_name['name']}", next_name, binding["etag"], actor,
                              {**evidence, "proof": proof_read})

    @staticmethod
    def abort_barrier(head):
        # HEAD7's actual proof preserves business deletion identity; technical
        # terminal/GC serial changes are not part of this stable fact.
        return {field: deepcopy(head[field]) for field in
                ("scope", "revision", "lifecycle", "origin", "root", "pages", "creator")}

    def cold_target(self, descriptor, actor="b"):
        evidence, binding, target = self.view(descriptor, actor)
        if (binding["status"] != "present" or binding["body"]["state"] != "bound"
                or binding["body"]["descriptor"] != digest(descriptor)
                or target["status"] != "present" or target["body"]["lifecycle"] != "ready"):
            self.fail("Lifecycle", "cold_target", **evidence)
        if target["body"]["creator"] != self.principal[actor]:
            self.fail("Denied", "cold_target", **evidence)
        reads, frames = self.verify_tree(target["body"]["scope"], target["body"]["A"], target["body"], actor)
        self.event("cold_target", actor=actor, descriptor=descriptor, closure=reads, values=[item["value"] for item in frames[:-1]],
                   requests=target["body"]["requests"], **evidence)
        return frames

    def operator(self, object_key, body):
        self.serial += 1
        if body is None:
            self.store.pop(object_key, None)
        else:
            self.store[object_key] = {"body": deepcopy(body), "etag": f"e{self.serial}"}
        self.event("operator_fault", key=object_key, value=deepcopy(self.store.get(object_key)))

    def trace(self, name):
        return {"schema": 1, "name": name, "events": deepcopy(self.events),
                "summary": {"not_authority": True, "objects": len(self.store)}}
