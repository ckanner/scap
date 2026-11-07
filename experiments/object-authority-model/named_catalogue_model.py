"""Bounded named-catalogue protocol experiment, never production code.

Only exact GET and atomic conditional PUT are assumed.  A request is prepared,
invoked, effected by the object service, and received separately.  Compute loss
cannot retract an invoked request.  Scope values are finite symbolic inputs so
that physical-key collisions can be forced; this is not the production ID hash,
wire format, credential layer, SQLite recovery or an S3 implementation.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import itertools
import json
import platform
from collections import Counter
from dataclasses import asdict, dataclass
from functools import wraps
from pathlib import Path
from typing import Any, Iterator


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


class ModelError(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def require(condition: bool, code: str) -> None:
    if not condition:
        raise ModelError(code)


def record_transport_failure(method):
    @wraps(method)
    def recorded(self, attempt, *args, **kwargs):
        try:
            return method(self, attempt, *args, **kwargs)
        except ModelError as error:
            self.emit("transport_rejected", action=method.__name__, attempt=attempt,
                      generation=self.generation, code=error.code)
            raise
    return recorded


@dataclass(frozen=True)
class Limits:
    max_records: int = 32
    max_revision: int = 31
    max_attempts: int = 64
    max_pending: int = 8
    max_events: int = 1024


def create_intent(operation=1, database=1, *, incarnation=1, generation=1,
                  principal=1, name="app", previous=None, quota=10, retention=2) -> dict:
    return dict(operation=operation, principal=principal, name=name,
                scope=[1, 1, database, incarnation, generation],
                previous=previous, quota=quota, retention=retention)


def descriptor_key(create: dict) -> str:
    return f"descriptor/{create['scope'][0]}/{create['scope'][1]}/{create['principal']}/{create['operation']}"


def name_key(create: dict) -> str:
    return f"name/{create['scope'][0]}/{create['scope'][1]}/{create['name']}"


def head_key(scope: list) -> str:
    return "head/" + "/".join(map(str, scope[:3]))


def root_body(create: dict) -> dict:
    return dict(kind="root", scope=create["scope"], empty=True)


def root_key(create: dict) -> str:
    return "root/" + digest(root_body(create))


def origin(create: dict) -> dict:
    return dict(key=descriptor_key(create), digest=digest(dict(kind="descriptor", intent=create)))


def proof_key(create: dict) -> str:
    return descriptor_key(create).replace("descriptor/", "abort-proof/", 1)


def control_intent(create: dict, kind="abort", *, operation=11,
                   name_revision=1, head_revision=None, nonce=21, caller=None) -> dict:
    return dict(kind=kind, principal=create["principal"] if caller is None else caller, operation=operation,
                create=origin(create), scope=create["scope"], name=create["name"],
                expected_name_revision=name_revision,
                expected_head_revision=head_revision, nonce=nonce)


def control_key(create: dict, control: dict) -> str:
    return f"control/{create['scope'][0]}/{create['scope'][1]}/{control['principal']}/{control['kind']}/{control['operation']}"


def foreign_seed(*, incarnation=9, state="ready", same_scope=False) -> dict:
    """A permanently occupied HEAD slot, from another trusted creation path."""
    scope = [1, 1, 1, 1 if same_scope else incarnation, 1]
    root = dict(kind="root", scope=scope, empty=True)
    key = "root/" + digest(root)
    head = dict(kind="head", scope=scope, origin={"direct": "foreign-creation"},
                revision=1, state=state, active=False, owner_epoch=1,
                data=key, abort=None, delete=None, quota=10, retention=2, admins=[2])
    return {key: root, head_key(scope): head}


class CatalogueModel:
    """Trusted candidate builder around a storage service with no protocol logic."""

    def __init__(self, *, seed=None, limits: Limits | None = None):
        self.limits = limits or Limits()
        require(all(type(v) is int and v > 0 for v in asdict(self.limits).values()), "invalid_limits")
        self._objects: dict[str, dict] = {}
        self._tokens: dict[str, str] = {}
        self._attempts: dict[str, dict] = {}
        self.generation = 0
        self.read_sequence = 0
        self.events: list[dict] = []
        for key, body in (seed or {}).items():
            self._objects[key] = dict(body=copy.deepcopy(body), etag=self._etag(body))
        require(len(self._objects) <= self.limits.max_records, "limit")
        self.emit("genesis", limits=asdict(self.limits), objects=self._objects)

    def emit(self, event_type: str, **fields) -> None:
        require(len(self.events) < self.limits.max_events, "event_limit")
        self.events.append(copy.deepcopy(dict(type=event_type, **fields)))

    def _etag(self, body: dict) -> str:
        encoded = canonical(body)
        return self._tokens.setdefault(encoded, f"opaque-{len(self._tokens) + 1}")

    def current(self, key: str) -> dict | None:
        record = self._objects.get(key)
        return copy.deepcopy(None if record is None else record["body"])

    def snapshot(self) -> dict:
        return copy.deepcopy(dict(objects=self._objects, attempts=self._attempts,
                                  generation=self.generation, reads=self.read_sequence))

    def _read(self, key: str, reads: list[str]) -> tuple[dict | None, str | None]:
        self.read_sequence += 1
        read_id = f"read-{self.read_sequence}"
        item = self._objects.get(key)
        body, etag = (None, None) if item is None else (item["body"], item["etag"])
        self.emit("get", read_id=read_id, key=key, body=body, etag=etag, generation=self.generation)
        reads.append(read_id)
        return copy.deepcopy(body), etag

    def _validate_create(self, create: dict) -> None:
        require(set(create) == {"operation", "principal", "name", "scope", "previous", "quota", "retention"}, "invalid")
        scope = create["scope"]
        require(isinstance(scope, list) and len(scope) == 5 and
                all(type(v) is int and 1 <= v <= 255 for v in scope), "invalid")
        require(type(create["operation"]) is int and 1 <= create["operation"] <= 255 and
                type(create["principal"]) is int and 1 <= create["principal"] <= 255, "invalid")
        require(create["previous"] is None or (type(create["previous"]) is int and
                1 <= create["previous"] <= self.limits.max_revision), "invalid")
        require(isinstance(create["name"], str) and 1 <= len(create["name"].encode()) <= 128
                and all(ord(c) >= 32 and not 127 <= ord(c) <= 159 for c in create["name"]), "invalid")
        require(type(create["quota"]) is int and create["quota"] > 0 and create["retention"] == 2, "invalid")

    def _control(self, create: dict, control: dict | None, kind: str) -> dict:
        require(isinstance(control, dict) and set(control) == {
            "kind", "principal", "operation", "create", "scope", "name",
            "expected_name_revision", "expected_head_revision", "nonce"}, "invalid_control")
        require(control["kind"] == kind and (kind == "delete" or control["principal"] == create["principal"])
                and control["create"] == origin(create) and control["scope"] == create["scope"]
                and control["name"] == create["name"], "control_identity")
        require(all(type(control[k]) is int and 1 <= control[k] <= 255
                    for k in ("principal", "operation", "nonce", "expected_name_revision")), "invalid_control")
        require((kind == "abort" and control["expected_head_revision"] is None) or
                (kind == "delete" and type(control["expected_head_revision"]) is int
                 and control["expected_head_revision"] > 0), "invalid_control")
        return copy.deepcopy(control)

    def _own(self, record: dict | None, create: dict) -> bool:
        return record is not None and record.get("origin") == origin(create) and record.get("scope") == create["scope"]

    def _binding(self, record: dict | None, create: dict, state: str) -> None:
        require(self._own(record, create) and record.get("name") == create["name"], "name_conflict")
        require(record["state"] == state, "phase")

    def _valid_head(self, record: dict | None, create: dict) -> None:
        if record is None:
            return
        require(record.get("kind") == "head" and record.get("scope", [])[:3] == create["scope"][:3]
                and len(record.get("scope", [])) == 5
                and record.get("state") in {"provisioning", "ready", "maintenance", "deleted"}
                and isinstance(record.get("origin"), dict), "corrupt")

    def _barrier(self, head: dict | None, create: dict, control: dict) -> dict:
        require(head is not None, "missing_barrier")
        self._valid_head(head, create)
        if self._own(head, create):
            require(head["state"] == "deleted" and head["abort"] == control, "missing_barrier")
            return dict(kind="own_deleted", scope=head["scope"], origin=head["origin"],
                        revision=head["revision"], abort=head["abort"])
        return dict(kind="foreign_occupied", scope=head["scope"], origin=head["origin"])

    def _new_head(self, create: dict, state="provisioning", abort=None) -> dict:
        return dict(kind="head", scope=create["scope"], origin=origin(create), revision=1,
                    state=state, active=False, owner_epoch=1, data=root_key(create),
                    abort=abort, delete=None, quota=create["quota"], retention=create["retention"],
                    admins=[create["principal"]])

    def prepare(self, attempt: str, action: str, create: dict, control=None, *, actor=None) -> dict:
        """Take exact observations and seal one candidate; never loop on a CAS."""
        reads: list[str] = []
        default_actor = control.get("principal", create.get("principal")) if isinstance(control, dict) else create.get("principal")
        actor = default_actor if actor is None else actor
        try:
            self._validate_create(create)
            if action not in {"delete_descriptor", "delete_head", "release_delete", "grant_admin"}:
                require(actor == create["principal"], "denied")
            require(attempt not in self._attempts, "attempt_reused")
            require(len(self._attempts) < self.limits.max_attempts, "limit")
            get = lambda key: self._read(key, reads)
            descriptor, descriptor_etag = get(descriptor_key(create))
            target, expected, body = "", None, {}
            if action == "descriptor":
                body = dict(kind="descriptor", intent=copy.deepcopy(create))
                if descriptor is not None:
                    require(descriptor == body, "intent_conflict")
                    raise ModelError("already_durable")
                target, expected = descriptor_key(create), descriptor_etag
            else:
                require(descriptor == dict(kind="descriptor", intent=create), "intent_conflict")
                if action in {"abort_descriptor", "delete_descriptor"}:
                    control = self._control(create, control, action.split("_")[0])
                    require(actor == control["principal"], "denied")
                    if action == "delete_descriptor":
                        selected, _ = get(head_key(create["scope"]))
                        require(self._own(selected, create) and actor in selected["admins"], "denied")
                    target = control_key(create, control)
                    found, expected = get(target)
                    body = dict(kind="control_descriptor", intent=control)
                    if found is not None:
                        require(found == body, "control_conflict")
                        raise ModelError("already_durable")
                elif action == "root":
                    target, body = root_key(create), root_body(create)
                    found, expected = get(target)
                    if found is not None:
                        require(found == body, "corrupt")
                        raise ModelError("already_durable")
                else:
                    binding, binding_etag = get(name_key(create))
                    if action in {"accept_abort", "fence_abort", "prove_abort", "release_abort", "delete_head", "release_delete"}:
                        selected_kind = "delete" if action in {"delete_head", "release_delete"} else "abort"
                        control = self._control(create, control, selected_kind)
                        require(actor == control["principal"], "denied")
                        frozen, _ = get(control_key(create, control))
                        require(frozen is not None, "control_not_prepared")
                        require(frozen == dict(kind="control_descriptor", intent=control), "control_conflict")
                    if action == "reserve":
                        revision = 1
                        if binding is None:
                            require(create["previous"] is None, "missing_authority")
                        else:
                            require(binding["state"] == "tombstone" and
                                    binding["revision"] == create["previous"], "name_conflict")
                            require(binding["scope"][2] != create["scope"][2], "identity_reuse")
                            revision = binding["revision"] + 1
                        body = dict(kind="binding", name=create["name"], scope=create["scope"],
                                    origin=origin(create), revision=revision, state="reserved",
                                    abort=None, delete=None, proof=None)
                        target, expected = name_key(create), binding_etag
                    elif action == "accept_abort":
                        control = self._control(create, control, "abort")
                        if self._own(binding, create) and binding["state"] == "bound":
                            raise ModelError("cannot_abort_bound")
                        if binding is None:
                            raise ModelError("not_reserved")
                        self._binding(binding, create, "reserved")
                        require(binding["revision"] == control["expected_name_revision"], "conflict")
                        body = dict(binding, state="aborting", revision=binding["revision"] + 1,
                                    abort=control)
                        target, expected = name_key(create), binding_etag
                    else:
                        head, head_etag = get(head_key(create["scope"]))
                        self._valid_head(head, create)
                        if action == "grant_admin":
                            self._binding(binding, create, "bound")
                            require(self._own(head, create) and head["state"] == "ready" and actor in head["admins"], "denied")
                            require(isinstance(control, dict) and set(control) == {"grant"}
                                    and type(control["grant"]) is int and 1 <= control["grant"] <= 255, "invalid_control")
                            target, expected = head_key(create["scope"]), head_etag
                            body = dict(head, admins=sorted(set(head["admins"]) | {control["grant"]}),
                                        revision=head["revision"] + 1)
                        elif action in {"provision", "bind", "complete"}:
                            self._binding(binding, create, "bound" if action == "complete" else "reserved")
                            if action == "provision":
                                require(head is None, "identity_conflict")
                                root, _ = get(root_key(create))
                                require(root == root_body(create), "closure")
                                target, expected, body = head_key(create["scope"]), None, self._new_head(create)
                            else:
                                require(self._own(head, create), "identity_conflict")
                                require(head["state"] == "provisioning", "phase")
                                if action == "bind":
                                    target, expected = name_key(create), binding_etag
                                    body = dict(binding, state="bound", revision=binding["revision"] + 1)
                                else:
                                    root, _ = get(head["data"])
                                    require(root == root_body(create), "closure")
                                    target, expected = head_key(create["scope"]), head_etag
                                    body = dict(head, state="ready", revision=head["revision"] + 1)
                        elif action in {"fence_abort", "prove_abort", "release_abort"}:
                            control = self._control(create, control, "abort")
                            self._binding(binding, create, "aborting")
                            require(binding["abort"] == control and binding["revision"] ==
                                    control["expected_name_revision"] + 1, "control_identity")
                            if action == "fence_abort":
                                if head is None:
                                    root, _ = get(root_key(create))
                                    require(root == root_body(create), "closure")
                                    body = self._new_head(create, "deleted", control)
                                else:
                                    require(self._own(head, create), "foreign_occupied")
                                    require(head["state"] == "provisioning", "phase")
                                    body = dict(head, state="deleted", revision=head["revision"] + 1,
                                                active=False, owner_epoch=head["owner_epoch"] + 1, abort=control)
                                target, expected = head_key(create["scope"]), head_etag
                            else:
                                barrier = self._barrier(head, create, control)
                                proof_body = dict(kind="abort_proof", create=origin(create),
                                                  scope=create["scope"], control=control, barrier=barrier)
                                proof, proof_etag = get(proof_key(create))
                                if action == "prove_abort":
                                    if proof is not None:
                                        require(proof == proof_body, "control_identity")
                                        raise ModelError("already_durable")
                                    target, expected, body = proof_key(create), proof_etag, proof_body
                                else:
                                    require(proof == proof_body, "missing_proof")
                                    target, expected = name_key(create), binding_etag
                                    body = dict(binding, state="tombstone", revision=binding["revision"] + 1,
                                                proof=dict(key=proof_key(create), digest=digest(proof)))
                        elif action in {"delete_head", "release_delete"}:
                            control = self._control(create, control, "delete")
                            self._binding(binding, create, "bound")
                            require(binding["revision"] == control["expected_name_revision"], "conflict")
                            require(self._own(head, create), "identity_conflict")
                            require(actor in head["admins"], "denied")
                            if action == "delete_head":
                                require(head["state"] in {"ready", "maintenance"}, "phase")
                                require(head["revision"] == control["expected_head_revision"], "conflict")
                                target, expected = head_key(create["scope"]), head_etag
                                body = dict(head, state="deleted", revision=head["revision"] + 1,
                                            active=False, owner_epoch=head["owner_epoch"] + 1, delete=control)
                            else:
                                require(head["state"] == "deleted" and head["delete"] == control and
                                        head["revision"] == control["expected_head_revision"] + 1, "control_identity")
                                target, expected = name_key(create), binding_etag
                                body = dict(binding, state="tombstone", revision=binding["revision"] + 1,
                                            delete=control)
                        else:
                            raise ModelError("invalid_action")
            for field in ("revision", "owner_epoch"):
                require(field not in body or 1 <= body[field] <= self.limits.max_revision, "counter_limit")
            wire = dict(key=target, expected=expected, body=copy.deepcopy(body))
            data = dict(action=action, create=copy.deepcopy(create), control=copy.deepcopy(control),
                        actor=actor, reads=reads, wire=wire, generation=self.generation,
                        phase="prepared", effect=None)
            self._attempts[attempt] = copy.deepcopy(data)
            self.emit("prepare", attempt=attempt, **{k: v for k, v in data.items() if k not in {"phase", "effect"}})
            return copy.deepcopy(wire)
        except ModelError as error:
            self.emit("rejected", attempt=attempt, action=action, create=create, control=control,
                      actor=actor, reads=reads, code=error.code)
            raise

    @record_transport_failure
    def invoke(self, attempt: str) -> None:
        selected = self._attempts[attempt]
        require(selected["phase"] == "prepared" and selected["generation"] == self.generation, "phase")
        require(sum(a["phase"] in {"invoked", "effected"} for a in self._attempts.values()) < self.limits.max_pending, "limit")
        selected["phase"] = "invoked"
        self.emit("invoke", attempt=attempt, wire=selected["wire"], generation=self.generation)

    @record_transport_failure
    def effect(self, attempt: str) -> str:
        selected = self._attempts[attempt]
        require(selected["phase"] == "invoked", "phase")
        wire = selected["wire"]
        old = self._objects.get(wire["key"])
        before = None if old is None else old["etag"]
        if before != wire["expected"]:
            outcome, after = "conflict", before
        elif old is None and len(self._objects) >= self.limits.max_records:
            outcome, after = "limit", None
        else:
            outcome, after = "applied", self._etag(wire["body"])
            self._objects[wire["key"]] = dict(body=copy.deepcopy(wire["body"]), etag=after)
        selected.update(phase="effected", effect=outcome)
        self.emit("effect", attempt=attempt, wire=wire, before=before, after=after, outcome=outcome)
        return outcome

    @record_transport_failure
    def receive(self, attempt: str, *, lost=False) -> str:
        selected = self._attempts[attempt]
        require(selected["phase"] == "effected", "phase")
        lost = lost or selected["generation"] != self.generation
        outcome = "unknown" if lost else selected["effect"]
        selected["phase"] = "received"
        self.emit("receive", attempt=attempt, generation=self.generation, lost=lost, outcome=outcome)
        return outcome

    def crash(self) -> None:
        self.generation += 1
        self.emit("crash", generation=self.generation)

    def observe(self, create: dict, *, kind="create", control=None, actor=None, lost=False) -> dict:
        """Fresh, read-only operation progress. No retry or identity allocation."""
        reads: list[str] = []
        default_actor = control.get("principal", create["principal"]) if isinstance(control, dict) else create["principal"]
        actor = default_actor if actor is None else actor
        try:
            self._validate_create(create)
            require(actor == (control.get("principal") if kind == "delete" and isinstance(control, dict) else create["principal"]), "denied")
            if kind in {"abort", "delete"}:
                control = self._control(create, control, kind)
            require(kind in {"create", "abort", "delete"}, "invalid")
            get = lambda key: self._read(key, reads)[0]
            descriptor = get(descriptor_key(create))
            if descriptor is None:
                result = dict(state="not_prepared")
            else:
                require(descriptor == dict(kind="descriptor", intent=create), "intent_conflict")
                binding = get(name_key(create))
                head = get(head_key(create["scope"]))
                proof = get(proof_key(create))
                self._valid_head(head, create)
                if kind == "delete":
                    require(self._own(head, create) and actor in head["admins"], "denied")
                if kind in {"abort", "delete"}:
                    frozen = get(control_key(create, control))
                    require(frozen is not None, "not_admitted")
                    require(frozen == dict(kind="control_descriptor", intent=control), "conflict")
                own_binding, own_head = self._own(binding, create), self._own(head, create)
                abort = proof["control"] if proof is not None else None
                if proof is not None:
                    require(proof == dict(kind="abort_proof", create=origin(create), scope=create["scope"],
                            control=abort, barrier=self._barrier(head, create, abort)), "corrupt")
                aborted = proof is not None and binding is not None and (
                    (own_binding and binding["state"] == "tombstone" and binding["abort"] == abort
                     and binding["proof"] == dict(key=proof_key(create), digest=digest(proof))) or
                    (not own_binding and binding["revision"] > abort["expected_name_revision"] + 2))
                deletion = head.get("delete") if own_head and head["state"] == "deleted" else None
                deleted = deletion is not None and binding is not None and (
                    (own_binding and binding["state"] == "tombstone" and binding["delete"] == deletion) or
                    (not own_binding and binding["revision"] > deletion["expected_name_revision"] + 1))
                if kind == "abort" and proof is not None and abort != control:
                    result = dict(state="conflict")
                elif kind == "delete" and deletion is not None and deletion != control:
                    result = dict(state="conflict")
                elif aborted and kind != "delete":
                    result = dict(state="aborted", scope=create["scope"], control=abort)
                elif deleted and kind != "abort":
                    result = dict(state="deleted", scope=create["scope"], control=deletion)
                elif binding is None:
                    require(proof is None and deletion is None, "missing_authority")
                    result = dict(state="not_reserved")
                elif not own_binding:
                    result = dict(state="name_conflict")
                elif binding["state"] == "aborting":
                    if kind == "abort" and binding["abort"] != control:
                        result = dict(state="conflict")
                    else:
                        result = dict(state="aborting")
                elif binding["state"] == "reserved":
                    result = dict(state="identity_conflict" if head is not None and not own_head else "reserved")
                elif binding["state"] == "bound":
                    require(own_head, "corrupt")
                    if kind == "abort":
                        result = dict(state="cannot_abort_bound")
                    elif kind == "delete":
                        result = dict(state="deleting" if deletion == control else "not_deleted")
                    elif head["state"] == "ready":
                        result = dict(state="ready", scope=create["scope"], origin=origin(create))
                    else:
                        result = dict(state="bound" if head["state"] == "provisioning" else "unavailable")
                else:
                    raise ModelError("corrupt")
        except ModelError as error:
            result = dict(state=error.code)
        observed = dict(state="unknown") if lost else copy.deepcopy(result)
        self.emit("observe", kind=kind, create=create, control=control, actor=actor,
                  reads=reads, result=result, delivered=not lost, observed=observed)
        return observed

    def resolve(self, create: dict, *, lost=False) -> dict:
        reads: list[str] = []
        binding = self._read(name_key(create), reads)[0]
        head = None
        if binding is not None and binding["state"] == "bound":
            head = self._read(head_key(binding["scope"]), reads)[0]
        if (head is not None and head["state"] == "ready" and head["scope"] == binding["scope"]
                and head["origin"] == binding["origin"]):
            result = dict(state="ready", scope=head["scope"], origin=head["origin"])
        else:
            result = dict(state="unavailable")
        observed = dict(state="unknown") if lost else copy.deepcopy(result)
        self.emit("resolve", name_key=name_key(create), reads=reads, result=result,
                  delivered=not lost, observed=observed)
        return observed


class Graph:
    """Actual context-qualified scheduler snapshots, not an unbounded state space."""
    def __init__(self):
        self.states: set[str] = set()
        self.storage_states: set[str] = set()
        self.edges: set[tuple[str, str, str]] = set()
        self.steps = 0
        self.latest: Trace | None = None


class Trace:
    def __init__(self, name, *, graph=None, seed=None, limits=None):
        self.name, self.graph = name, graph or Graph()
        self.model = CatalogueModel(seed=seed, limits=limits)
        self.serial = 0
        self.notes: dict = {}
        self.graph.latest = self
        self._record_state()

    def _record_state(self):
        snapshot = self.model.snapshot()
        signature = digest(dict(scenario=self.name, state=snapshot))
        self.graph.states.add(signature)
        self.graph.storage_states.add(digest(snapshot["objects"]))
        return signature

    def call(self, method, *args, **kwargs):
        # The harness explicitly persists the control-admission step before a
        # mutating control action. Its PUT has the same separately logged phases.
        if method == "prepare" and len(args) >= 4 and args[1] in {
                "accept_abort", "fence_abort", "prove_abort", "release_abort", "delete_head", "release_delete"}:
            create, control = args[2], args[3]
            if isinstance(control, dict) and self.model.current(control_key(create, control)) is None:
                self.perform(control["kind"] + "_descriptor", create, control, actor=kwargs.get("actor"))
        before = self._record_state()
        try:
            return getattr(self.model, method)(*args, **kwargs)
        finally:
            self.graph.edges.add((before, canonical([method, args, kwargs]), self._record_state()))
            self.graph.steps += 1

    def reject(self, code, method, *args, **kwargs):
        try:
            self.call(method, *args, **kwargs)
        except ModelError as error:
            if error.code != code:
                raise AssertionError(f"{self.name}: expected {code}, got {error.code}") from error
            return
        raise AssertionError(f"{self.name}: {method} unexpectedly succeeded")

    def perform(self, action, create, control=None, *, lost=False, actor=None):
        self.serial += 1
        attempt = f"step-{self.serial}-{action}"
        self.call("prepare", attempt, action, create, control, actor=actor)
        self.call("invoke", attempt)
        effect = self.call("effect", attempt)
        self.call("receive", attempt, lost=lost)
        if effect != "applied":
            raise AssertionError(f"{self.name}: explicit step {action} returned {effect}")
        return attempt

    def setup(self, create, state="reserved"):
        for action in ("descriptor", "reserve"):
            self.perform(action, create)
        if self.model.current(root_key(create)) is None:
            self.perform("root", create)
        if state in {"provisioning", "bound", "ready"}:
            self.perform("provision", create)
        if state in {"bound", "ready"}:
            self.perform("bind", create)
        if state == "ready":
            self.perform("complete", create)

    def resume_create(self, create):
        """Explicit harness re-entry; every actual candidate takes new exact GETs."""
        model = self.model
        if model.current(descriptor_key(create)) is None:
            self.perform("descriptor", create)
        binding = model.current(name_key(create))
        if binding is None or binding["state"] == "tombstone":
            self.perform("reserve", create)
        if model.current(root_key(create)) is None:
            self.perform("root", create)
        if model.current(head_key(create["scope"])) is None:
            self.perform("provision", create)
        binding = model.current(name_key(create))
        if binding["state"] == "reserved":
            self.perform("bind", create)
        if model.current(head_key(create["scope"]))["state"] == "provisioning":
            self.perform("complete", create)
        result = self.call("observe", create)
        if result["state"] != "ready":
            raise AssertionError((self.name, result))

    def resume_abort(self, create, control):
        model = self.model
        binding = model.current(name_key(create))
        if binding["state"] == "reserved":
            self.perform("accept_abort", create, control)
        binding = model.current(name_key(create))
        if binding["state"] == "aborting":
            head = model.current(head_key(create["scope"]))
            if head is None or (head["origin"] == origin(create) and head["state"] == "provisioning"):
                if model.current(root_key(create)) is None:
                    self.perform("root", create)
                self.perform("fence_abort", create, control)
            if model.current(proof_key(create)) is None:
                self.perform("prove_abort", create, control)
            self.perform("release_abort", create, control)
        result = self.call("observe", create, kind="abort", control=control)
        if result["state"] != "aborted":
            raise AssertionError((self.name, result))

    def resume_delete(self, create, control):
        head = self.model.current(head_key(create["scope"]))
        if head["state"] in {"ready", "maintenance"}:
            self.perform("delete_head", create, control)
        binding = self.model.current(name_key(create))
        if binding["state"] == "bound":
            self.perform("release_delete", create, control)
        result = self.call("observe", create, kind="delete", control=control)
        if result["state"] != "deleted":
            raise AssertionError((self.name, result))

    def history(self):
        return copy.deepcopy(self.model.events)


def schedules(left=3, right=3) -> Iterator[tuple[str, ...]]:
    if not left and not right:
        yield ()
    if left:
        for tail in schedules(left - 1, right):
            yield ("left",) + tail
    if right:
        for tail in schedules(left, right - 1):
            yield ("right",) + tail


RACES = ("double_descriptor", "double_create", "same_intent_provision", "bind_abort",
         "late_provision_absent_cancel", "same_intent_abort", "same_intent_complete", "two_deletes",
         "same_abort_descriptor", "changed_abort_descriptor")
RESPONSE_MODES = tuple(itertools.product((False, True), repeat=2))
CUTS = ("before_invoke_crash", "before_effect_crash", "after_effect_crash", "lost_response")


def race(kind, order, modes, *, index=0, graph=None):
    r = Trace(f"race_{kind}_{index:02}_{int(modes[0])}{int(modes[1])}", graph=graph)
    first, second = create_intent(), create_intent(2, 2, principal=2)
    abort = control_intent(first)
    left, right = (None, first, None), (None, first, None)
    if kind == "double_descriptor":
        left = right = ("descriptor", first, None)
    elif kind in {"same_abort_descriptor", "changed_abort_descriptor"}:
        r.setup(first)
        left = ("abort_descriptor", first, abort)
        right = ("abort_descriptor", first, abort if kind == "same_abort_descriptor" else dict(abort, nonce=22))
    elif kind == "double_create":
        r.perform("descriptor", first)
        r.perform("descriptor", second)
        left, right = ("reserve", first, None), ("reserve", second, None)
    elif kind in {"same_intent_provision", "same_intent_abort", "late_provision_absent_cancel"}:
        r.setup(first)
        if kind == "same_intent_provision":
            left = right = ("provision", first, None)
        elif kind == "same_intent_abort":
            left = right = ("accept_abort", first, abort)
        else:
            r.call("prepare", "left", "provision", first)
            r.perform("accept_abort", first, abort)
            left, right = ("provision", first, None), ("fence_abort", first, abort)
    elif kind == "bind_abort":
        r.setup(first, "provisioning")
        left, right = ("bind", first, None), ("accept_abort", first, abort)
    elif kind == "same_intent_complete":
        r.setup(first, "bound")
        left = right = ("complete", first, None)
    elif kind == "two_deletes":
        r.setup(first, "ready")
        left = ("delete_head", first, control_intent(first, "delete", operation=31, name_revision=2, head_revision=2))
        right = ("delete_head", first, control_intent(first, "delete", operation=32, name_revision=2, head_revision=2))
    else:
        raise ValueError(kind)
    if kind != "late_provision_absent_cancel":
        r.call("prepare", "left", *left)
    r.call("prepare", "right", *right)
    positions = {"left": 0, "right": 0}
    effects = {}
    for who in order:
        position = positions[who]
        if position == 0:
            r.call("invoke", who)
        elif position == 1:
            effects[who] = r.call("effect", who)
        else:
            r.call("receive", who, lost=modes[0 if who == "left" else 1])
        positions[who] += 1
    if positions != {"left": 3, "right": 3} or sorted(effects.values()) != ["applied", "conflict"]:
        raise AssertionError((kind, order, positions, effects))
    winner = next(who for who, effect in effects.items() if effect == "applied")
    if kind == "double_create":
        chosen, rejected = (first, second) if winner == "left" else (second, first)
        r.resume_create(chosen)
        assert r.call("observe", rejected)["state"] == "name_conflict"
        assert r.call("resolve", chosen)["scope"] == chosen["scope"]
    elif kind in {"same_abort_descriptor", "changed_abort_descriptor"}:
        selected = left[2] if winner == "left" else right[2]
        r.resume_abort(first, selected)
        if kind == "changed_abort_descriptor":
            rejected = right[2] if winner == "left" else left[2]
            r.reject("control_conflict", "prepare", "changed-control", "accept_abort", first, rejected)
    elif kind in {"same_intent_abort", "late_provision_absent_cancel"} or (kind == "bind_abort" and winner == "right"):
        r.resume_abort(first, abort)
        assert r.call("resolve", first)["state"] == "unavailable"
    elif kind == "two_deletes":
        winning, losing = (left[2], right[2]) if winner == "left" else (right[2], left[2])
        r.resume_delete(first, winning)
        assert r.call("observe", first, kind="delete", control=losing)["state"] == "conflict"
    else:
        r.resume_create(first)
        if kind == "bind_abort":
            assert r.call("observe", first, kind="abort", control=abort)["state"] == "cannot_abort_bound"
            r.reject("cannot_abort_bound", "prepare", "late-abort", "accept_abort", first, abort)
    r.notes = dict(race=kind, schedule=list(order), response_lost=list(modes), winner=winner,
                   network_steps=6, prepared_candidates=2)
    return r


def _cut(r, action, create, control, cut):
    r.call("prepare", "cut", action, create, control)
    if cut == "before_invoke_crash":
        r.call("crash")
        r.reject("phase", "invoke", "cut")
        return
    r.call("invoke", "cut")
    if cut == "before_effect_crash":
        r.call("crash")
    r.call("effect", "cut")
    if cut == "after_effect_crash":
        r.call("crash")
    assert r.call("receive", "cut", lost=cut == "lost_response") == "unknown"


def directed(*, graph=None) -> Iterator[Trace]:
    first = create_intent()
    creation_steps = ("descriptor", "reserve", "root", "provision", "bind", "complete")
    for position, action in enumerate(creation_steps):
        for cut in CUTS:
            r = Trace(f"direct_create_{action}_{cut}", graph=graph)
            for prior in creation_steps[:position]:
                r.perform(prior, first)
            _cut(r, action, first, None, cut)
            r.call("observe", first)
            r.resume_create(first)
            r.notes = dict(cut=action, mode=cut, explicit_resume=True)
            yield r
    abort = control_intent(first)
    abort_steps = ("abort_descriptor", "accept_abort", "fence_abort", "prove_abort", "release_abort")
    for position, action in enumerate(abort_steps):
        for cut in CUTS:
            r = Trace(f"direct_abort_{action}_{cut}", graph=graph)
            r.setup(first)
            for prior in abort_steps[:position]:
                r.perform(prior, first, abort)
            _cut(r, action, first, abort, cut)
            r.call("observe", first, kind="abort", control=abort)
            r.resume_abort(first, abort)
            r.notes = dict(cut=action, mode=cut, explicit_resume=True)
            yield r
    deletion = control_intent(first, "delete", operation=31, name_revision=2, head_revision=2)
    delete_steps = ("delete_descriptor", "delete_head", "release_delete")
    for position, action in enumerate(delete_steps):
        for cut in CUTS:
            r = Trace(f"direct_delete_{action}_{cut}", graph=graph)
            r.setup(first, "ready")
            for prior in delete_steps[:position]:
                r.perform(prior, first, deletion)
            _cut(r, action, first, deletion, cut)
            r.call("observe", first, kind="delete", control=deletion)
            r.resume_delete(first, deletion)
            yield r

    r = Trace("direct_not_reserved_not_cancelled", graph=graph)
    r.perform("descriptor", first)
    r.perform("abort_descriptor", first, abort)
    r.call("prepare", "late-reserve", "reserve", first)
    r.call("invoke", "late-reserve")
    assert r.call("observe", first, kind="abort", control=abort)["state"] == "not_reserved"
    r.reject("not_reserved", "prepare", "too-early-abort", "accept_abort", first, abort)
    r.call("effect", "late-reserve")
    r.call("receive", "late-reserve", lost=True)
    r.resume_abort(first, abort)
    yield r

    r = Trace("direct_bound_must_complete", graph=graph)
    r.setup(first, "bound")
    r.perform("abort_descriptor", first, abort)
    assert r.call("observe", first, kind="abort", control=abort)["state"] == "cannot_abort_bound"
    r.reject("cannot_abort_bound", "prepare", "abort-bound", "accept_abort", first, abort)
    r.reject("phase", "prepare", "delete-provisioning", "delete_head", first, deletion)
    r.perform("complete", first)
    r.resume_delete(first, deletion)
    yield r

    for state in ("provisioning", "ready", "maintenance", "deleted"):
        for same_scope in (False, True):
            suffix = "same_scope" if same_scope else "other_incarnation"
            r = Trace(f"direct_foreign_reuse_{state}_{suffix}", graph=graph,
                      seed=foreign_seed(state=state, same_scope=same_scope))
            foreign = r.model.current(head_key(first["scope"]))
            r.setup(first)
            r.reject("identity_conflict", "prepare", "collision", "provision", first)
            assert r.call("observe", first)["state"] == "identity_conflict"
            r.perform("accept_abort", first, abort)
            r.reject("foreign_occupied", "prepare", "cannot-delete-foreign", "fence_abort", first, abort)
            r.resume_abort(first, abort)
            successor = create_intent(3, 2, previous=3)
            r.resume_create(successor)
            r.call("crash")
            assert r.call("observe", first, kind="abort", control=abort)["state"] == "aborted"
            other = control_intent(first, operation=12)
            r.perform("abort_descriptor", first, other)
            assert r.call("observe", first, kind="abort", control=other)["state"] == "conflict"
            assert r.call("resolve", first)["scope"] == successor["scope"]
            assert r.model.current(head_key(first["scope"])) == foreign
            yield r

    r = Trace("direct_own_reuse_late_if_none", graph=graph)
    r.setup(first)
    r.call("prepare", "late-provision", "provision", first)
    r.call("invoke", "late-provision")
    r.resume_abort(first, abort)
    successor = create_intent(3, 2, previous=3)
    r.resume_create(successor)
    r.call("crash")
    assert r.call("effect", "late-provision") == "conflict"
    assert r.call("receive", "late-provision") == "unknown"
    assert r.call("observe", first, kind="abort", control=abort)["state"] == "aborted"
    assert r.call("resolve", first)["scope"] == successor["scope"]
    yield r

    r = Trace("direct_late_bind_after_reuse", graph=graph)
    r.setup(first, "provisioning")
    r.call("prepare", "late-bind", "bind", first)
    r.call("invoke", "late-bind")
    r.resume_abort(first, abort)
    r.resume_create(successor)
    assert r.call("effect", "late-bind") == "conflict"
    r.call("receive", "late-bind", lost=True)
    yield r

    r = Trace("direct_deleted_reuse_late_complete", graph=graph)
    r.setup(first, "bound")
    r.call("prepare", "late-complete", "complete", first)
    r.call("invoke", "late-complete")
    r.perform("complete", first)
    r.resume_delete(first, deletion)
    r.resume_create(successor)
    assert r.call("effect", "late-complete") == "conflict"
    r.call("receive", "late-complete", lost=True)
    assert r.call("observe", first, kind="delete", control=deletion)["state"] == "deleted"
    other_delete = control_intent(first, "delete", operation=32, name_revision=2, head_revision=2)
    r.perform("delete_descriptor", first, other_delete)
    assert r.call("observe", first, kind="delete", control=other_delete)["state"] == "conflict"
    redirected = control_intent(successor, "delete", operation=31, name_revision=5, head_revision=2)
    r.reject("control_conflict", "prepare", "redirect-control", "delete_descriptor", successor, redirected)
    yield r

    for lost in (False, True):
        r = Trace(f"direct_admitted_delete_conflict_{'lost' if lost else 'known'}", graph=graph)
        r.setup(first, "ready")
        r.call("prepare", "original-delete", "delete_head", first, deletion)
        r.call("invoke", "original-delete")
        r.perform("grant_admin", first, {"grant": 2})
        assert r.call("effect", "original-delete") == "conflict"
        assert r.call("receive", "original-delete", lost=lost) == ("unknown" if lost else "conflict")
        changed = dict(deletion, expected_head_revision=3)
        r.reject("control_conflict", "prepare", "changed-expected", "delete_head", first, changed)
        r.reject("control_conflict", "prepare", "changed-nonce", "delete_descriptor", first, dict(deletion, nonce=22))
        r.reject("conflict", "prepare", "original-still-stale", "delete_head", first, deletion)
        fresh = control_intent(first, "delete", operation=32, name_revision=2, head_revision=3)
        r.resume_delete(first, fresh)
        yield r

    r = Trace("direct_noncreator_admin_delete", graph=graph)
    r.setup(first, "ready")
    outsider = control_intent(first, "delete", operation=41, name_revision=2, head_revision=3, caller=2)
    r.reject("denied", "prepare", "not-yet-admin", "delete_descriptor", first, outsider)
    r.perform("grant_admin", first, {"grant": 2})
    r.reject("denied", "prepare", "admin-not-creator", "abort_descriptor", first,
             control_intent(first, caller=2))
    r.resume_delete(first, outsider)
    assert r.model.current(head_key(first["scope"]))["delete"]["principal"] == 2
    assert r.model.current(descriptor_key(first))["intent"]["principal"] == 1
    yield r

    for phase, steps in (("accepted_without_fence", ("accept_abort",)),
                         ("fence_before_proof", ("accept_abort", "fence_abort")),
                         ("proof_before_name_release", ("accept_abort", "fence_abort", "prove_abort"))):
        r = Trace(f"direct_abort_{phase}", graph=graph)
        r.setup(first)
        for action in steps:
            r.perform(action, first, abort)
        assert r.call("observe", first, kind="abort", control=abort)["state"] == "aborting"
        assert r.call("resolve", first)["state"] == "unavailable"
        yield r

    r = Trace("direct_bound_only", graph=graph)
    r.setup(first, "bound")
    assert r.call("observe", first)["state"] == "bound"
    assert r.call("resolve", first)["state"] == "unavailable"
    yield r

    for kind in ("create", "abort", "delete"):
        r = Trace(f"direct_lost_business_reply_{kind}", graph=graph)
        selected_control = None
        if kind == "abort":
            r.setup(first)
            r.resume_abort(first, abort)
            selected_control = abort
        else:
            r.setup(first, "ready")
            if kind == "delete":
                r.resume_delete(first, deletion)
                selected_control = deletion
        assert r.call("observe", first, kind=kind, control=selected_control, lost=True) == {"state": "unknown"}
        r.call("crash")
        assert r.call("observe", first, kind=kind, control=selected_control)["state"] in {"ready", "aborted", "deleted"}
        yield r

    r = Trace("direct_fixed_intent_conflicts", graph=graph)
    r.setup(first, "ready")
    for field, value in (("name", "different"), ("scope", [1, 1, 2, 1, 1]), ("quota", 100)):
        changed = dict(first, **{field: value})
        r.reject("intent_conflict", "prepare", f"changed-{field}", "descriptor", changed)
        assert r.call("observe", changed)["state"] == "intent_conflict"
    r.reject("denied", "prepare", "impersonated", "reserve", first, actor=2)
    assert r.call("observe", first)["state"] == "ready"
    yield r

    r = Trace("direct_reject_reused_database", graph=graph)
    r.setup(first)
    r.resume_abort(first, abort)
    reused = create_intent(3, 1, incarnation=2, previous=3)
    r.perform("descriptor", reused)
    r.reject("identity_reuse", "prepare", "reuse-database", "reserve", reused)
    yield r

    r = Trace("direct_record_budget", graph=graph, limits=Limits(max_records=3))
    r.setup(first)
    r.call("prepare", "full", "provision", first)
    r.call("invoke", "full")
    assert r.call("effect", "full") == "limit"
    assert r.call("receive", "full") == "limit"
    assert r.call("observe", first)["state"] == "reserved"
    yield r

    r = Trace("direct_abort_proof_budget", graph=graph, limits=Limits(max_records=5))
    r.setup(first)
    r.perform("accept_abort", first, abort)
    r.perform("fence_abort", first, abort)
    r.call("prepare", "proof-full", "prove_abort", first, abort)
    r.call("invoke", "proof-full")
    assert r.call("effect", "proof-full") == "limit"
    r.call("receive", "proof-full")
    assert r.call("observe", first, kind="abort", control=abort)["state"] == "aborting"
    r.reject("missing_proof", "prepare", "no-budget-release", "release_abort", first, abort)
    yield r

    r = Trace("direct_revision_budget", graph=graph, limits=Limits(max_revision=1))
    r.setup(first, "provisioning")
    r.reject("counter_limit", "prepare", "cannot-wrap", "bind", first)
    assert r.call("resolve", first)["state"] == "unavailable"
    yield r

    r = Trace("direct_fresh_resolution_after_delete", graph=graph)
    r.setup(first, "bound")
    r.call("resolve", first)
    r.perform("complete", first)
    r.call("resolve", first)
    r.perform("delete_head", first, deletion)
    assert r.call("resolve", first)["state"] == "unavailable"
    yield r


def negatives(histories: dict[str, list[dict]]) -> Iterator[tuple[str, str, list[dict]]]:
    """Deliberate raw-evidence corruptions, not alternative model transitions."""
    def clone(name="direct_create_complete_lost_response"):
        return copy.deepcopy(histories[name])

    def first(history, kind, **matches):
        return next(e for e in history if e["type"] == kind and all(e.get(k) == v for k, v in matches.items()))

    h = clone()
    first(h, "prepare", action="provision")["wire"]["body"]["scope"][3] = 2
    yield "scope_changed_after_fixed_descriptor", "SCOPE", h

    h = clone()
    first(h, "prepare", action="provision")["wire"]["body"]["origin"] = {"direct": "borrowed"}
    yield "bad_creation_source", "ORIGIN", h

    h = clone()
    first(h, "prepare", action="descriptor")["wire"]["body"]["intent"]["scope"][2] = 2
    yield "descriptor_reassigned_scope", "IDENTITY", h

    h = clone()
    first(h, "prepare", action="provision")["wire"]["body"]["state"] = "ready"
    yield "skipped_provisioning", "PROVISIONING", h

    h = clone()
    selected = first(h, "prepare", action="complete")["attempt"]
    first(h, "invoke", attempt=selected)["wire"]["expected"] = "fresh-but-not-original"
    yield "old_candidate_given_new_etag", "SEALED_CANDIDATE", h

    h = clone()
    selected = first(h, "prepare", action="complete")["attempt"]
    h.remove(first(h, "invoke", attempt=selected))
    yield "effect_without_invoke", "ORDER", h

    h = clone()
    first(h, "receive", lost=True)["outcome"] = "conflict"
    yield "lost_response_misreported_as_failure", "RESPONSE", h

    h = clone("direct_bound_only")
    event = first(h, "observe")
    event["result"] = event["observed"] = dict(state="ready", scope=create_intent()["scope"], origin=origin(create_intent()))
    yield "bound_not_ready_but_reported_ready", "OBSERVATION", h

    h = clone("direct_abort_fence_before_proof")
    event = first(h, "observe")
    event["result"] = event["observed"] = dict(state="aborted", scope=event["create"]["scope"], control=event["control"])
    yield "aborted_without_abort_proof", "ABORT_PROOF", h

    h = clone("direct_abort_proof_before_name_release")
    event = first(h, "observe")
    event["result"] = event["observed"] = dict(state="aborted", scope=event["create"]["scope"], control=event["control"])
    yield "proof_exists_but_release_unobserved", "ABORT_ACK", h

    h = clone("direct_abort_proof_before_name_release")
    fence = first(h, "prepare", action="fence_abort")
    selected = fence["attempt"]
    h = [e for e in h if e.get("attempt") != selected]
    for event in h:
        if event["type"] == "get" and event["key"] == head_key(create_intent()["scope"]):
            event["body"], event["etag"] = None, None
    yield "proof_without_permanent_head_barrier", "BARRIER", h

    foreign = "direct_foreign_reuse_ready_other_incarnation"
    h = clone(foreign)
    selected = first(h, "prepare", action="prove_abort")["attempt"]
    h = [e for e in h if e.get("attempt") != selected]
    yield "removed_permanent_abort_proof_object", "FRESH_GET", h

    h = clone(foreign)
    first(h, "prepare", action="release_abort")["wire"]["body"]["proof"] = None
    yield "released_name_omits_proof_reference", "ABORT_PROOF", h

    h = clone(foreign)
    event = next(e for e in h if e["type"] == "observe" and e["kind"] == "abort" and e["result"]["state"] == "conflict")
    event["result"] = event["observed"] = dict(state="aborted", scope=event["create"]["scope"], control=event["control"])
    yield "different_old_abort_claimed_after_name_reuse", "CONTROL_ID", h

    h = clone(foreign)
    first(h, "prepare", action="prove_abort")["wire"]["body"]["barrier"]["revision"] = 1
    yield "foreign_proof_depends_on_mutable_revision", "BARRIER", h

    h = clone(foreign)
    event = first(h, "prepare", action="prove_abort")
    observations = {e["read_id"]: e for e in h if e["type"] == "get"}
    head_read = next(observations[r] for r in event["reads"] if observations[r]["key"] == head_key(event["create"]["scope"]))
    bad_head = dict(head_read["body"], scope=event["create"]["scope"], origin=origin(event["create"]),
                    state="deleted", revision=2, owner_epoch=2, abort=event["control"])
    event["action"] = "fence_abort"
    event["wire"] = dict(key=head_read["key"], expected=head_read["etag"], body=bad_head)
    h = h[:h.index(event) + 1]
    yield "abort_deletes_foreign_head", "FOREIGN_HEAD", h

    h = clone("direct_lost_business_reply_abort")
    event = first(h, "observe", delivered=False)
    event["observed"] = copy.deepcopy(event["result"])
    yield "lost_business_reply_counted_as_ack", "RECEIPT", h

    h = clone("direct_fresh_resolution_after_delete")
    reads = [e for e in h if e["type"] == "get" and e["key"] == head_key(create_intent()["scope"])]
    old = next(e for e in reads if e["body"] is not None and e["body"]["state"] == "ready")
    reads[-1]["body"], reads[-1]["etag"] = copy.deepcopy(old["body"]), old["etag"]
    yield "cached_head_after_delete", "FRESH_GET", h

    h = clone("direct_reject_reused_database")
    rejected = h[-1]
    observations = {e["read_id"]: e for e in h if e["type"] == "get"}
    create = rejected["create"]
    binding = next(observations[r] for r in rejected["reads"] if observations[r]["key"] == name_key(create))
    body = dict(kind="binding", name=create["name"], scope=create["scope"], origin=origin(create),
                revision=4, state="reserved", abort=None, delete=None, proof=None)
    h[-1] = dict(type="prepare", attempt="forged-reuse", action="reserve", create=create, control=None,
                 actor=create["principal"], reads=rejected["reads"], generation=0,
                 wire=dict(key=name_key(create), expected=binding["etag"], body=body))
    yield "new_incarnation_reuses_physical_database_id", "ID_REUSE", h

    h = clone("direct_admitted_delete_conflict_known")
    rejected = first(h, "rejected", attempt="changed-expected")
    index = h.index(rejected)
    grant = first(h, "prepare", action="grant_admin")
    persisted = first(h, "effect", attempt=grant["attempt"])
    h = h[:index]
    read_id = "forged-fresh-head"
    selected = copy.deepcopy(persisted["wire"]["body"])
    h.append(dict(type="get", read_id=read_id, key=persisted["wire"]["key"],
                  body=selected, etag=persisted["after"], generation=0))
    changed = rejected["control"]
    body = dict(selected, state="deleted", revision=selected["revision"] + 1,
                owner_epoch=selected["owner_epoch"] + 1, delete=changed)
    h.append(dict(type="prepare", attempt="forged-rebase", action="delete_head", create=rejected["create"],
                  control=changed, actor=changed["principal"], reads=rejected["reads"] + [read_id], generation=0,
                  wire=dict(key=persisted["wire"]["key"], expected=persisted["after"], body=body)))
    yield "control_conditions_changed_after_target_412", "CONTROL_DESCRIPTOR", h

    h = clone("direct_abort_fence_before_proof")
    selected = first(h, "prepare", action="abort_descriptor")["attempt"]
    h = [e for e in h if e.get("attempt") != selected]
    for event in h:
        if event["type"] == "get" and event["key"].startswith("control/"):
            event["body"], event["etag"] = None, None
    yield "control_action_without_persistent_admission", "CONTROL_DESCRIPTOR", h

    h = clone("direct_delete_delete_descriptor_lost_response")
    event = first(h, "prepare", action="delete_descriptor")
    old_key = event["wire"]["key"]
    event["actor"] = event["control"]["principal"] = event["wire"]["body"]["intent"]["principal"] = 2
    new_key = control_key(event["create"], event["control"])
    event["wire"]["key"] = new_key
    for read in h:
        if read["type"] == "get" and read["read_id"] in event["reads"] and read["key"] == old_key:
            read["key"] = new_key
    h = h[:h.index(event) + 1]
    yield "noncreator_without_current_admin_deletes", "AUTH", h

    h = clone("direct_deleted_reuse_late_complete")
    rejected = first(h, "rejected", attempt="redirect-control")
    reads = {e["read_id"]: e for e in h if e["type"] == "get"}
    frozen = next(reads[r] for r in rejected["reads"] if reads[r]["key"].startswith("control/"))
    h = h[:h.index(rejected)]
    h.append(dict(type="prepare", attempt="forged-target-change", action="delete_descriptor",
                  create=rejected["create"], control=rejected["control"], actor=rejected["actor"],
                  reads=rejected["reads"], generation=0,
                  wire=dict(key=frozen["key"], expected=frozen["etag"],
                            body=dict(kind="control_descriptor", intent=rejected["control"]))))
    yield "control_operation_redirected_after_name_reuse", "CONTROL_DESCRIPTOR", h

    h = clone()
    event = [e for e in h if e["type"] == "observe"][-1]
    h.insert(h.index(event), dict(type="crash", generation=1))
    yield "old_ready_observations_survive_compute_loss", "READ_GENERATION", h

    h = clone()
    candidate = first(h, "prepare", action="descriptor")
    response = first(h, "receive", attempt=candidate["attempt"])
    h = h[:h.index(response) + 1]
    h.insert(h.index(candidate), dict(type="crash", generation=1))
    for event in h:
        if event["type"] in {"prepare", "invoke", "receive"}:
            event["generation"] = 1
    yield "old_absent_get_relabelled_as_new_process", "READ_GENERATION", h


def explore(output: Path | None = None) -> dict:
    from named_catalogue_oracle import OracleError, audit

    if output is not None:
        if not output.is_absolute():
            raise ValueError("evidence output must be an absolute new directory")
        output.mkdir(parents=True, exist_ok=False)
    graph = Graph()
    positive, negative, failures = [], [], []
    negative_event_count = 0
    directed_histories: dict[str, list[dict]] = {}
    event_counts, record_counts, attempt_counts = [], [], []

    def save(category, name, events):
        item = dict(name=name, events=events)
        encoded = canonical(item) + "\n"
        filename = f"{category}-{name}.json"
        if output is not None:
            (output / filename).write_text(encoded)
        return dict(path=filename, sha256=hashlib.sha256(encoded.encode()).hexdigest())

    def check(run, category):
        events = run.history()
        entry = dict(name=run.name, category=category, notes=run.notes, **save("positive", run.name, events))
        event_counts.append(len(events))
        record_counts.append(len(run.model._objects))
        attempt_counts.append(len(run.model._attempts))
        try:
            entry["audit"] = audit(events)
            entry["accepted"] = True
        except OracleError as error:
            entry.update(accepted=False, code=error.code, step=error.step, detail=error.detail)
            failures.append(run.name)
        positive.append(entry)
        if category == "directed":
            directed_histories[run.name] = events

    try:
        orders = tuple(schedules())
        for kind in RACES:
            for index, order in enumerate(orders):
                for modes in RESPONSE_MODES:
                    check(race(kind, order, modes, index=index, graph=graph), "race")
        for run in directed(graph=graph):
            check(run, "directed")
        for name, expected, events in negatives(directed_histories):
            negative_event_count += len(events)
            entry = dict(name=name, expected_code=expected, **save("negative", name, events))
            try:
                audit(events)
            except OracleError as error:
                entry.update(rejected=True, actual_code=error.code, step=error.step, detail=error.detail)
                if error.code != expected:
                    failures.append(name)
            else:
                entry.update(rejected=False, actual_code=None)
                failures.append(name)
            negative.append(entry)
    except Exception as error:
        failed = graph.latest
        entry = dict(name="scheduler_failure", detail=repr(error))
        if failed is not None:
            entry.update(save("failed", failed.name, failed.history()))
        failures.append(entry)
    sources = {}
    for name in ("named_catalogue_model.py", "named_catalogue_oracle.py",
                 "test_named_catalogue_model.py", "test_named_catalogue_oracle.py", "README.md"):
        path = Path(__file__).with_name(name)
        if path.exists():
            sources[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    summary = dict(
        accepted=not failures, python=platform.python_version(), source_sha256=sources,
        scope=dict(races=list(RACES), candidates_per_race=2, actors_per_race=2,
                   network_phases=["invoke", "effect", "receive"], network_steps_per_race=6,
                   linear_extensions_per_race=len(tuple(schedules())),
                   response_variants=[list(pair) for pair in RESPONSE_MODES],
                   distinct_create_intents_per_history_at_most=3, names_per_history=1,
                   limits=asdict(Limits()), actual_max_events=max(event_counts, default=0),
                   actual_max_records=max(record_counts, default=0), actual_max_attempts=max(attempt_counts, default=0),
                   note="All 20 linear extensions of two prepared 3-phase chains; separate directed cuts. Not arbitrary-state exhaustive exploration."),
        counts=dict(positive_histories=len(positive), race_histories=sum(e["category"] == "race" for e in positive),
                    directed_histories=sum(e["category"] == "directed" for e in positive),
                    negative_histories=len(negative), rejected_negatives=sum(e["rejected"] for e in negative),
                    observed_scheduler_states=len(graph.states), observed_storage_states=len(graph.storage_states),
                    observed_edges=len(graph.edges), executed_commands=graph.steps,
                    positive_recorded_events=sum(event_counts),
                    negative_recorded_events=negative_event_count),
        failures=failures, positive=positive, negative=negative,
        exclusions=["production Rust and SDK", "S3/AWS contract", "SQLite/data closure beyond symbolic empty root",
                    "production identity hash/format", "credential revocation races", "all within-prepare GET interleavings",
                    "timeout returned before later storage effect", "business reply queued across compute crash",
                    "complete rejection-reason/nonterminal-status classification",
                    "unbounded liveness", "LIST/full inventory", "GC/PITR"])
    if output is not None:
        (output / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="new absolute evidence directory; never overwritten")
    args = parser.parse_args()
    summary = explore(args.output)
    concise = {key: value for key, value in summary.items() if key not in {"positive", "negative"}}
    print(json.dumps(concise, indent=2, sort_keys=True))
    return 0 if summary["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
