"""Finite protocol model, never a product dependency or an S3/SQLite adapter.

Only exact-key GET and atomic conditional PUT are storage assumptions.  Stored
ETags are opaque: writing identical bytes can reuse one, so ABA prevention must
come from the trusted protocol.  JSON below is a deterministic model encoding,
not the proposed wire format.  The integer data value and expanded result index
stand in for immutable data/index objects.  No GC, pin, PITR or directory exists;
all objects, including orphans, count towards a hard budget and are never deleted.
"""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import asdict, dataclass, field, is_dataclass
from functools import wraps
from typing import Any


def plain(value: Any) -> Any:
    if is_dataclass(value):
        return plain(asdict(value))
    if isinstance(value, dict):
        return {str(k): plain(v) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [plain(v) for v in value]
    return value


def canonical(value: Any) -> str:
    return json.dumps(plain(value), sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


class ModelError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code
        self.logged = False


def require(condition: bool, code: str) -> None:
    if not condition:
        raise ModelError(code)


def observed(method):
    """Keep failed actions in the raw history as well as successful actions."""
    @wraps(method)
    def invoke(self, *args, **kwargs):
        try:
            return method(self, *args, **kwargs)
        except ModelError as error:
            if not error.logged:
                self.emit("rejected", action=method.__name__, arguments=plain(args),
                          options=plain(kwargs), code=error.code)
                error.logged = True
            raise
    return invoke


@dataclass(frozen=True)
class Limits:
    window_limit: int = 2
    keep_closed: int = 2
    max_objects: int = 96
    max_counter: int = 255
    max_attempts: int = 8
    max_principals: int = 4
    max_token_chars: int = 64
    max_value: int = 65535


@dataclass(frozen=True)
class Request:
    scope: str
    epoch: int
    request_id: str
    principal: str
    fingerprint: str

    @property
    def key(self) -> str:
        return f"{self.epoch}:{self.request_id}"


@dataclass(frozen=True)
class ControlIntent:
    scope: str
    expected_revision: int
    control_id: str
    kind: str
    principal: str
    parameters_json: str = "{}"

    @classmethod
    def make(cls, scope, expected_revision, control_id, kind, principal="alice", **params):
        return cls(scope, expected_revision, control_id, kind, principal, canonical(params))

    @property
    def parameters(self) -> dict:
        try:
            value = json.loads(self.parameters_json)
            require(isinstance(value, dict) and canonical(value) == self.parameters_json,
                    "invalid_control_intent")
            return value
        except (TypeError, ValueError) as error:
            raise ModelError("invalid_control_intent") from error


@dataclass(frozen=True)
class Snapshot:
    read_id: str
    head: dict
    etag: str


@dataclass
class Attempt:
    op_id: str
    kind: str
    actor: str
    snapshot: Snapshot
    intent: dict
    request: Request | None = None
    phase: str = "prepared"
    candidate: dict | None = None
    objects: tuple = ()
    uploaded: list = field(default_factory=list)
    resolved: dict | None = None
    effect: bool | None = None
    uncertain: bool = False
    materialized: bool = False
    crashed: bool = False
    source_seal: str = ""
    candidate_seal: str = ""


class Store:
    """An atomic object service. It deliberately knows no business rules."""
    def __init__(self, max_objects: int):
        self.max_objects = max_objects
        self.objects: dict[str, tuple[dict, str]] = {}
        self.tokens: dict[str, str] = {}
        self.available = True

    def get(self, key: str) -> tuple[dict, str]:
        require(self.available, "unavailable")
        require(key in self.objects, "missing_object")
        return copy.deepcopy(self.objects[key])

    def put(self, key: str, body: dict, expected_etag: str | None) -> tuple[bool, str | None]:
        require(self.available, "unavailable")
        current = self.objects.get(key)
        if (None if current is None else current[1]) != expected_etag:
            return False, None if current is None else current[1]
        require(current is not None or len(self.objects) < self.max_objects,
                "resource_exhausted")
        encoded = canonical(body)
        token = self.tokens.setdefault(encoded, f"opaque-{len(self.tokens) + 1}")
        self.objects[key] = (copy.deepcopy(body), token)
        return True, token


class Model:
    CONTROL_KINDS = {"takeover", "activate", "auth", "maintenance", "delete", "close"}

    def __init__(self, *, scope="deployment/tenant/database/1", store=None, **limits):
        self.limits = Limits(**limits)
        require(1 <= self.limits.window_limit <= 128 and self.limits.keep_closed == 2,
                "invalid_contract")
        require(self.limits.max_objects >= 3 and self.limits.max_counter >= 1
                and self.limits.max_attempts >= 1, "invalid_limits")
        self.scope = scope
        self.head_key = f"{scope}/HEAD"
        self.store = store if store is not None else Store(self.limits.max_objects)
        self.events: list[dict] = []
        self._attempts: dict[str, Attempt] = {}
        self._readers: dict[str, dict] = {}
        self._recoveries: dict[str, dict] = {}
        self._pending: dict[str, dict] = {}
        if store is None:
            data = self.object("data", seq=0, value=0, base_root=None, delta=0,
                               transition_id="genesis")
            index = self.object("requests", records={})
            data_key, index_key = self.key(data), self.key(index)
            for key, body in ((data_key, data), (index_key, index)):
                ok, tag = self.store.put(key, body, None)
                self.emit("object_put", op_id="genesis", key=key, body=body,
                          applied=ok, etag=tag)
            head = dict(format=1, scope=scope, revision=0, transition_id="genesis", last_control_digest=None,
                        db_seq=0, data_root=data_key, request_root=index_key,
                        owner=dict(instance="writer-1", epoch=1, state="active"),
                        auth_epoch=1, grants={"alice": ["admin", "read", "write"],
                                              "bob": ["read", "write"]},
                        lifecycle="ready", request_epoch=1, retired_floor=0,
                        closed_epochs=[], retention=self.contract)
            self.store.put(self.head_key, head, None)
        head, etag = self.store.get(self.head_key)
        self.validate_head(head)
        self.emit("genesis", head=head, etag=etag, config=asdict(self.limits),
                  reopened=store is not None)

    @property
    def contract(self):
        return {"window_limit": self.limits.window_limit, "keep_closed": 2}

    @property
    def head(self):
        return self.store.get(self.head_key)[0]

    @property
    def etag(self):
        return self.store.get(self.head_key)[1]

    @property
    def attempts(self):
        return copy.deepcopy(self._attempts)

    @property
    def readers(self):
        return copy.deepcopy(self._readers)

    @property
    def pending(self):
        return copy.deepcopy(self._pending)

    def emit(self, event_type, **fields):
        self.events.append(dict(seq=len(self.events) + 1, type=event_type,
                                **copy.deepcopy(plain(fields))))

    def object(self, kind, *, deps=(), **fields):
        return dict(format=1, kind=kind, scope=self.scope, deps=list(deps), **fields)

    def key(self, body):
        return f"{self.scope}/objects/{digest(body)}"

    def number(self, value, *, minimum=0):
        return type(value) is int and minimum <= value <= self.limits.max_counter

    def token(self, value):
        return isinstance(value, str) and 0 < len(value) <= self.limits.max_token_chars

    def increment(self, value):
        require(self.number(value) and value < self.limits.max_counter, "exhausted")
        return value + 1

    def validate_head(self, head):
        try:
            require(set(head) == {"format", "scope", "revision", "transition_id", "last_control_digest",
                                 "db_seq", "data_root", "request_root", "owner", "auth_epoch", "grants",
                                 "lifecycle", "request_epoch", "retired_floor", "closed_epochs", "retention"},
                    "corrupt")
            require(head["format"] == 1 and head["scope"] == self.scope, "scope_or_format")
            require(head["retention"] == self.contract, "contract_mismatch")
            for name in ("revision", "db_seq", "retired_floor"):
                require(self.number(head[name]), "corrupt")
            for name in ("auth_epoch", "request_epoch"):
                require(self.number(head[name], minimum=1), "corrupt")
            owner = head["owner"]
            require(self.number(owner["epoch"], minimum=1) and self.token(owner["instance"])
                    and owner["state"] in ("recovering", "active"), "corrupt")
            require(head["lifecycle"] in ("ready", "maintenance", "deleted"), "corrupt")
            transition = head["transition_id"]
            if head["revision"] == 0:
                require(transition == "genesis", "corrupt")
            else:
                require(isinstance(transition, str), "corrupt")
                prefix, separator, nonce = transition.partition(":")
                require(separator == ":" and prefix == str(head["revision"])
                        and self.token(nonce), "corrupt")
            require(head["last_control_digest"] is None or
                    (isinstance(head["last_control_digest"], str) and
                     len(head["last_control_digest"]) == 64), "corrupt")
            self.validate_grants(head["grants"])
            current = head["request_epoch"]
            require(head["retired_floor"] == max(0, current - 3), "corrupt")
            require(head["closed_epochs"] == list(range(max(1, current - 2), current)),
                    "corrupt")
        except (KeyError, TypeError, ValueError) as error:
            raise ModelError("corrupt") from error

    def validate_grants(self, grants):
        require(isinstance(grants, dict) and 0 < len(grants) <= self.limits.max_principals,
                "invalid_policy")
        require(all(self.token(p) and p != "coordinator" and isinstance(rights, list)
                    and rights == sorted(set(rights))
                    and set(rights) <= {"read", "write", "admin"}
                    for p, rights in grants.items()), "invalid_policy")
        require(any("admin" in rights for rights in grants.values()), "invalid_policy")

    @observed
    def read_head(self, actor="alice", **intent):
        head, etag = self.store.get(self.head_key)
        read_id = f"read-{len(self.events) + 1}"
        self.emit("head_read", read_id=read_id, actor=actor, head=head, etag=etag,
                  intent=dict(actor=actor, **intent))
        self.validate_head(head)
        return Snapshot(read_id, head, etag)

    def authorize(self, head, actor, auth_epoch, rights):
        require(auth_epoch == head["auth_epoch"], "auth_fenced")
        require(set(rights) <= set(head["grants"].get(actor, [])), "forbidden")
        require(head["lifecycle"] != "deleted", "deleted")

    def read_object(self, key, kind=None):
        body, _ = self.store.get(key)
        try:
            require(self.key(body) == key and body["format"] == 1
                    and body["scope"] == self.scope and isinstance(body["deps"], list),
                    "corrupt")
            require(kind is None or body["kind"] == kind, "corrupt")
        except (KeyError, TypeError, ValueError) as error:
            raise ModelError("corrupt") from error
        return body

    def records(self, head):
        index = self.read_object(head["request_root"], "requests")
        require(isinstance(index.get("records"), dict), "corrupt")
        return index["records"]

    def closure(self, head):
        seen, pending = set(), [head["data_root"], head["request_root"]]
        while pending:
            key = pending.pop()
            if key in seen:
                continue
            seen.add(key)
            require(len(seen) <= self.limits.max_objects, "resource_exhausted")
            pending.extend(self.read_object(key)["deps"])
        data = self.read_object(head["data_root"], "data")
        require(data["seq"] == head["db_seq"] and type(data["value"]) is int
                and abs(data["value"]) <= self.limits.max_value, "corrupt")
        records = self.records(head)
        counts = {}
        for key, record in records.items():
            epoch = record["epoch"]
            require(head["retired_floor"] < epoch <= head["request_epoch"]
                    and key == f"{epoch}:{record['request_id']}", "corrupt")
            counts[epoch] = counts.get(epoch, 0) + 1
            require(counts[epoch] <= self.limits.window_limit, "corrupt")
            require(record["state"] in ("committed", "cancelled"), "corrupt")
            if record["state"] == "committed":
                result = self.read_object(record["result_root"], "result")
                identity = {name: record[name] for name in
                            ("scope", "epoch", "request_id", "principal", "fingerprint")}
                require(result["request"] == identity and result["seq"] == record["seq"]
                        and result["transition_id"] == record["transition_id"], "corrupt")
        require(all(counts.get(epoch, 0) == self.limits.window_limit
                    for epoch in head["closed_epochs"]), "corrupt")
        return sorted(seen)

    def resolve(self, head, request, actor):
        require(isinstance(request, Request) and request.scope == self.scope, "scope")
        require(request.principal == actor, "principal_mismatch")
        require(self.number(request.epoch, minimum=1) and self.token(request.request_id)
                and self.token(request.principal) and self.token(request.fingerprint),
                "invalid_request")
        if request.epoch <= head["retired_floor"]:
            return {"state": "retired", "retired_floor": head["retired_floor"]}
        require(request.epoch <= head["request_epoch"], "future_epoch")
        record = self.records(head).get(request.key)
        if record is not None:
            if record["principal"] != actor or record["fingerprint"] != request.fingerprint:
                return {"state": "conflict"}
            result = copy.deepcopy(record)
            if record["state"] == "committed":
                result["result"] = self.read_object(record["result_root"], "result")["result"]
            return result
        return {"state": "epoch_closed" if request.epoch < head["request_epoch"] else "unknown"}

    @observed
    def lookup(self, request, *, actor="alice", auth_epoch=1):
        snapshot = self.read_head(actor, action="lookup", auth_epoch=auth_epoch,
                                  request=plain(request))
        self.authorize(snapshot.head, actor, auth_epoch, ["read"])
        self.closure(snapshot.head)
        result = self.resolve(snapshot.head, request, actor)
        self.emit("lookup", read_id=snapshot.read_id, request=plain(request), actor=actor,
                  auth_epoch=auth_epoch, outcome=result)
        return result

    @observed
    def prepare(self, op_id, kind, *, request=None, control=None, actor="alice",
                auth_epoch=1, owner="writer-1", owner_epoch=1, base_seq=None, base_root=None):
        require(self.token(op_id) and op_id not in self._attempts and op_id not in self._pending,
                "attempt_identity")
        require(len(self._attempts) < self.limits.max_attempts, "resource_exhausted")
        require(kind in self.CONTROL_KINDS | {"commit", "cancel"}, "invalid_kind")
        intent = dict(request=plain(request), control=plain(control), actor=actor,
                      auth_epoch=auth_epoch, owner=owner, owner_epoch=owner_epoch,
                      base_seq=base_seq, base_root=base_root)
        snapshot = self.read_head(actor, action="prepare", kind=kind, op_id=op_id,
                                  **{key: value for key, value in intent.items() if key != "actor"})
        head = snapshot.head
        params = {}
        if kind == "close":
            require(actor == "coordinator", "forbidden")
            require(head["lifecycle"] != "deleted", "deleted")
        else:
            self.authorize(head, actor, auth_epoch,
                           ["read", "write"] if kind in ("commit", "cancel") else ["admin"])
        self.closure(head)
        resolved = None
        if kind in ("commit", "cancel"):
            require(control is None, "invalid_control_intent")
            result = self.resolve(head, request, actor)
            state = result["state"]
            if state in ("committed", "cancelled"):
                resolved = result
            else:
                require(state == "unknown", state)
                count = sum(r["epoch"] == head["request_epoch"] for r in self.records(head).values())
                require(count < self.limits.window_limit, "resource_exhausted")
                if kind == "commit":
                    require(head["lifecycle"] == "ready", "maintenance")
                    require(head["owner"] == dict(instance=owner, epoch=owner_epoch, state="active"),
                            "owner_fenced")
                    require(base_seq == head["db_seq"] and base_root == head["data_root"], "base_fenced")
        else:
            require(request is None and isinstance(control, ControlIntent), "control_required")
            require(control.scope == self.scope and control.control_id == op_id
                    and control.kind == kind and control.principal == actor, "control_identity")
            require(self.number(control.expected_revision)
                    and control.expected_revision == head["revision"], "control_fenced")
            params = control.parameters
            expected = {"takeover": {"new_owner"}, "activate": {"recovery"},
                        "auth": {"grants"}, "maintenance": {"enabled"},
                        "delete": set(), "close": {"expected_epoch"}}[kind]
            require(set(params) == expected, "invalid_control_intent")
            if kind in ("takeover", "activate"):
                require(head["lifecycle"] == "ready", "maintenance")
            if kind == "takeover":
                require(self.token(params["new_owner"]), "invalid_owner")
            elif kind == "activate":
                proof = params["recovery"]
                require(isinstance(proof, dict) and self._recoveries.get(proof.get("id")) == proof
                        and {key: proof.get(key) for key in self.recovery_identity(head)} ==
                        self.recovery_identity(head) and head["owner"]["state"] == "recovering",
                        "recovery_fenced")
            elif kind == "auth":
                self.validate_grants(params["grants"])
            elif kind == "maintenance":
                require(type(params["enabled"]) is bool, "invalid_control_intent")
            elif kind == "close":
                require(params["expected_epoch"] == head["request_epoch"], "epoch_fenced")
                count = sum(r["epoch"] == head["request_epoch"] for r in self.records(head).values())
                require(count == self.limits.window_limit, "window_not_full")
        intent["parameters"] = params
        attempt = Attempt(op_id, kind, actor, snapshot, intent, request=request,
                          phase="resolved" if resolved is not None else "prepared", resolved=resolved)
        attempt.source_seal = self.source_seal(attempt)
        self._attempts[op_id] = attempt
        self.emit("prepared", op_id=op_id, kind=kind, read_id=snapshot.read_id, intent=intent,
                  outcome=attempt.phase, result=resolved)
        return copy.deepcopy(attempt)

    def source_seal(self, attempt):
        return digest((attempt.op_id, attempt.kind, attempt.actor, attempt.snapshot,
                       attempt.intent, attempt.request, attempt.resolved))

    def check_seal(self, attempt, *, staged=True):
        require(attempt.source_seal == self.source_seal(attempt), "unsealed")
        if staged:
            require(attempt.candidate_seal == digest((attempt.source_seal, attempt.candidate,
                                                      attempt.objects)), "unsealed")

    def _attempt(self, op_id, *phases, allow_crashed=False):
        require(op_id in self._attempts, "missing_attempt")
        attempt = self._attempts[op_id]
        require(allow_crashed or not attempt.crashed, "crashed")
        require(not phases or attempt.phase in phases, "phase")
        return attempt

    @observed
    def stage(self, op_id, *, delta=1, result="result"):
        attempt = self._attempt(op_id, "prepared")
        self.check_seal(attempt, staged=False)
        head = copy.deepcopy(attempt.snapshot.head)
        head["revision"] = self.increment(head["revision"])
        head["transition_id"] = f"{head['revision']}:{op_id}"
        head["last_control_digest"] = (digest(attempt.intent["control"])
                                       if attempt.kind in self.CONTROL_KINDS else None)
        records = self.records(head)
        objects = []
        kind, params = attempt.kind, attempt.intent["parameters"]
        if kind in ("commit", "cancel"):
            record = dict(plain(attempt.request), state="cancelled", transition_id=head["transition_id"])
            if kind == "commit":
                require(type(delta) is int and -16 <= delta <= 16 and self.token(result), "staging_budget")
                old_data = self.read_object(head["data_root"], "data")
                seq, value = self.increment(head["db_seq"]), old_data["value"] + delta
                require(abs(value) <= self.limits.max_value, "staging_budget")
                data = self.object("data", seq=seq, value=value, delta=delta,
                                   base_root=head["data_root"], transition_id=head["transition_id"],
                                   deps=[head["data_root"]])
                outcome = self.object("result", request=plain(attempt.request), seq=seq,
                                      result=result, transition_id=head["transition_id"])
                objects.extend(((self.key(data), data), (self.key(outcome), outcome)))
                head.update(db_seq=seq, data_root=self.key(data))
                record.update(state="committed", seq=seq, result_root=self.key(outcome))
            records[attempt.request.key] = record
        elif kind == "takeover":
            head["owner"] = dict(instance=params["new_owner"],
                                 epoch=self.increment(head["owner"]["epoch"]), state="recovering")
        elif kind == "activate":
            head["owner"]["state"] = "active"
        elif kind == "auth":
            head.update(auth_epoch=self.increment(head["auth_epoch"]), grants=params["grants"])
        elif kind == "maintenance":
            head["lifecycle"] = "maintenance" if params["enabled"] else "ready"
        elif kind == "delete":
            head["lifecycle"] = "deleted"
        elif kind == "close":
            current = self.increment(head["request_epoch"])
            floor = max(0, current - 3)
            head.update(request_epoch=current, retired_floor=floor,
                        closed_epochs=list(range(max(1, current - 2), current)))
            records = {key: record for key, record in records.items() if record["epoch"] > floor}
        if kind in ("commit", "cancel", "close"):
            index = self.object("requests", records=records,
                                deps=sorted(r["result_root"] for r in records.values()
                                            if r["state"] == "committed"))
            objects.append((self.key(index), index))
            head["request_root"] = self.key(index)
        self.validate_head(head)
        attempt.candidate, attempt.objects, attempt.phase = head, tuple(objects), "staged"
        attempt.candidate_seal = digest((attempt.source_seal, head, attempt.objects))
        self.emit("staged", op_id=op_id, candidate=head, objects=objects, delta=delta, result=result)
        return copy.deepcopy(attempt)

    @observed
    def upload(self, op_id, index):
        attempt = self._attempt(op_id, "staged")
        self.check_seal(attempt)
        require(type(index) is int and 0 <= index < len(attempt.objects), "object_index")
        key, body = attempt.objects[index]
        applied, tag = self.store.put(key, body, None)
        self.emit("object_put", op_id=op_id, key=key, body=body, applied=applied, etag=tag)
        require(self.read_object(key) == body, "corrupt")
        if index not in attempt.uploaded:
            attempt.uploaded.append(index)
        return key

    @observed
    def verify(self, op_id):
        attempt = self._attempt(op_id, "staged")
        self.check_seal(attempt)
        dependencies = self.closure(attempt.candidate)
        attempt.phase = "verified"
        self.emit("closure", op_id=op_id, roots=[attempt.candidate["data_root"],
                  attempt.candidate["request_root"]], dependencies=dependencies)

    @observed
    def invoke_cas(self, op_id):
        attempt = self._attempt(op_id, "verified", "unknown", "conflict")
        self.check_seal(attempt)
        require(op_id not in self._pending, "pending")
        # No refresh, rebase, or reconstruction on retransmission.
        self.closure(attempt.candidate)
        self._pending[op_id] = dict(candidate=copy.deepcopy(attempt.candidate),
                                  expected_etag=attempt.snapshot.etag, read_id=attempt.snapshot.read_id,
                                  kind=attempt.kind, intent=copy.deepcopy(attempt.intent), effect=None)
        attempt.phase = "sent"
        self.emit("cas_sent", op_id=op_id, **self._pending[op_id])

    @observed
    def deliver_cas(self, op_id):
        require(op_id in self._pending and self._pending[op_id]["effect"] is None, "phase")
        message = self._pending[op_id]
        # The Store checks ONLY the ETag. It is not a second protocol validator.
        applied, tag = self.store.put(self.head_key, message["candidate"], message["expected_etag"])
        message["effect"] = applied
        if op_id in self._attempts:
            self._attempts[op_id].effect = applied
        self.emit("cas_effect", op_id=op_id, applied=applied, head=self.head, etag=tag)
        return applied

    @observed
    def receive_cas(self, op_id, *, lost=False):
        require(op_id in self._pending and self._pending[op_id]["effect"] is not None, "phase")
        message = self._pending.pop(op_id)
        attempt = self._attempts.get(op_id)
        dropped = lost or attempt is None or attempt.crashed
        if dropped:
            outcome = "unknown"
            if attempt is not None:
                attempt.uncertain, attempt.phase = True, "unknown"
        elif message["effect"]:
            outcome, attempt.phase = "applied", "applied"
        else:
            outcome = "unknown" if attempt.uncertain else "conflict"
            attempt.phase = outcome
        self.emit("cas_response", op_id=op_id, outcome=outcome, delivered=not dropped)
        return outcome

    @observed
    def publish(self, op_id, *, fail=False):
        attempt = self._attempt(op_id, "applied")
        self.check_seal(attempt)
        require(attempt.kind == "commit", "phase")
        if not fail:
            self.closure(attempt.candidate)
        attempt.materialized, attempt.phase = not fail, "native_failed" if fail else "published"
        self.emit("publish", op_id=op_id, ok=not fail)

    @observed
    def reply(self, op_id, *, lost=False):
        attempt = self._attempt(op_id, "resolved", "applied", "published", "native_failed", "unknown", "conflict")
        self.check_seal(attempt, staged=attempt.phase != "resolved")
        result = attempt.resolved
        if attempt.phase == "resolved":
            outcome = result["state"]
        elif attempt.phase in ("unknown", "conflict"):
            outcome = attempt.phase
        elif attempt.kind == "commit":
            require(attempt.phase in ("published", "native_failed"), "not_materialized")
            outcome = "committed" if attempt.materialized else "committed_unavailable"
            record = self.records(attempt.candidate)[attempt.request.key]
            result = dict(record, result=self.read_object(record["result_root"], "result")["result"])
        else:
            outcome = "cancelled" if attempt.kind == "cancel" else "applied"
        self.emit("reply", op_id=op_id, outcome=outcome, result=result,
                  materialized=attempt.materialized, delivered=not lost)
        attempt.phase = "unknown" if lost or outcome == "unknown" else "replied"
        attempt.uncertain |= lost
        return {"state": "unknown" if lost else outcome, "result": result if not lost else None}

    @observed
    def forget(self, op_id):
        attempt = self._attempt(op_id, "replied")
        require(op_id not in self._pending, "pending")
        del self._attempts[op_id]
        self.emit("forgotten", op_id=op_id, outcome=attempt.resolved)

    @observed
    def crash(self, op_id):
        attempt = self._attempt(op_id, allow_crashed=True)
        attempt.crashed = True
        self.emit("crash", op_id=op_id)

    @observed
    def restart(self, **contract):
        require(all(self.contract.get(k) == v for k, v in contract.items()), "contract_mismatch")
        head, _ = self.store.get(self.head_key)
        self.validate_head(head)
        self._attempts.clear()
        self._readers.clear()
        self._recoveries.clear()
        # Already sent messages live in the network, not on the failed machines.
        self.emit("restart", head=head, pending=list(self._pending))

    @observed
    def corrupt(self, key):
        body, etag = self.store.get(key)
        damaged = dict(body, damage="injected")
        self.store.objects[key] = (damaged, etag)
        self.emit("corrupt", key=key, body=damaged, etag=etag)

    @observed
    def begin_read(self, read_id, *, actor="alice", auth_epoch=1):
        require(self.token(read_id) and read_id not in self._readers, "read_identity")
        snapshot = self.read_head(actor, action="read", auth_epoch=auth_epoch)
        self.authorize(snapshot.head, actor, auth_epoch, ["read"])
        self.closure(snapshot.head)
        self._readers[read_id] = dict(snapshot=snapshot, actor=actor, auth_epoch=auth_epoch)
        self.emit("read_started", id=read_id, read_id=snapshot.read_id, actor=actor)
        return copy.deepcopy(snapshot)

    @observed
    def finish_read(self, read_id):
        require(read_id in self._readers, "missing_read")
        reader = self._readers[read_id]
        snapshot = reader["snapshot"]
        self.closure(snapshot.head)
        value = self.read_object(snapshot.head["data_root"], "data")["value"]
        self.emit("read_result", id=read_id, read_id=snapshot.read_id,
                  actor=reader["actor"], auth_epoch=reader["auth_epoch"], head=snapshot.head, value=value)
        del self._readers[read_id]
        return value

    def recovery_identity(self, head):
        return dict(scope=self.scope, owner=copy.deepcopy(head["owner"]),
                    db_seq=head["db_seq"], data_root=head["data_root"])

    @observed
    def recover(self, *, owner, owner_epoch, actor="alice", auth_epoch=1):
        snapshot = self.read_head(actor, action="recover", auth_epoch=auth_epoch)
        self.authorize(snapshot.head, actor, auth_epoch, ["admin"])
        require(snapshot.head["lifecycle"] == "ready" and snapshot.head["owner"] ==
                dict(instance=owner, epoch=owner_epoch, state="recovering"), "owner_fenced")
        self.closure(snapshot.head)
        proof = self.recovery_identity(snapshot.head)
        proof.update(id=f"recovery-{len(self.events) + 1}",
                     value=self.read_object(snapshot.head["data_root"], "data")["value"])
        self._recoveries[proof["id"]] = copy.deepcopy(proof)
        self.emit("recovered", read_id=snapshot.read_id, proof=proof)
        return proof

    @observed
    def lookup_control(self, control, *, actor="alice", auth_epoch=1):
        require(isinstance(control, ControlIntent) and control.scope == self.scope
                and control.principal == actor, "control_identity")
        require(self.number(control.expected_revision) and self.token(control.control_id)
                and control.kind in self.CONTROL_KINDS, "invalid_control_intent")
        control.parameters
        snapshot = self.read_head(actor, action="lookup_control", auth_epoch=auth_epoch,
                                  control=plain(control))
        if actor != "coordinator":
            self.authorize(snapshot.head, actor, auth_epoch, ["admin"])
        else:
            require(control.kind == "close", "forbidden")
            require(snapshot.head["lifecycle"] != "deleted", "deleted")
        head = snapshot.head
        if head["revision"] == control.expected_revision + 1 and head["transition_id"] == f"{control.expected_revision + 1}:{control.control_id}":
            outcome = "applied" if head["last_control_digest"] == digest(control) else "conflict"
        else:
            outcome = "superseded" if head["revision"] > control.expected_revision else "unknown"
        self.emit("control_lookup", read_id=snapshot.read_id, control=plain(control),
                  actor=actor, outcome=outcome)
        return {"state": outcome}

    def snapshot_state(self):
        return plain(dict(objects=self.store.objects, available=self.store.available,
                          attempts=self._attempts, readers=self._readers, recoveries=self._recoveries,
                          pending=self._pending))
