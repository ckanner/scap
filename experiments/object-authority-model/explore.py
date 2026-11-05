"""Deterministic, explicitly bounded interleavings of the N0 protocol model.

No S3, SQL engine, network, wall clock, or random scheduler is used. The race
matrix enumerates all 20 linear extensions of two invoke/effect/receive chains
after both candidates are durably staged. Upload/crash and other boundaries are
separate directed cases, not an assertion of exhaustive arbitrary executions.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import itertools
import json
import platform
import sys
from collections import Counter
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

from model import ControlIntent, Model, ModelError, Request
from oracle import OracleError, audit


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


def sha(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


class Graph:
    """Exact accounting for observed, context-qualified scheduler snapshots."""

    def __init__(self) -> None:
        self.states: set[str] = set()
        self.edges: set[tuple[str, str, str]] = set()
        self.executed_steps = 0


class Run:
    def __init__(self, name: str, *, graph: Graph | None = None, variant: Any = None, **limits) -> None:
        self.name, self.variant = name, variant
        self.model = Model(**limits)
        self.graph = graph if graph is not None else Graph()
        self.notes: dict[str, Any] = {}
        self.graph.states.add(self.signature())

    def signature(self) -> str:
        return sha({"scenario": self.name, "response_choices": self.variant,
                    "model": self.model.snapshot_state(), "next_event_seq": len(self.model.events) + 1})

    def call(self, method: str, *args, **kwargs):
        before = self.signature()
        try:
            return getattr(self.model, method)(*args, **kwargs)
        finally:
            after = self.signature()
            self.graph.states.update((before, after))
            self.graph.edges.add((before, canonical([method, args, kwargs]), after))
            self.graph.executed_steps += 1

    def reject(self, code: str | tuple[str, ...], method: str, *args, **kwargs) -> str:
        expected = (code,) if isinstance(code, str) else code
        try:
            self.call(method, *args, **kwargs)
        except ModelError as error:
            if error.code not in expected:
                raise AssertionError(f"{self.name}: expected {expected}, got {error.code}") from error
            return error.code
        raise AssertionError(f"{self.name}: {method} unexpectedly succeeded")

    def request(self, name: str, *, epoch: int | None = None, actor="alice", fingerprint=None) -> Request:
        return Request(self.model.scope, self.model.head["request_epoch"] if epoch is None else epoch,
                       name, actor, fingerprint or f"fingerprint-{name}")

    def prepare(self, op_id: str, kind: str, request: Request | None = None, **options):
        h = self.model.head
        options.setdefault("auth_epoch", h["auth_epoch"])
        if request is not None:
            options.setdefault("actor", request.principal)
        if kind == "commit":
            options.setdefault("owner", h["owner"]["instance"])
            options.setdefault("owner_epoch", h["owner"]["epoch"])
            options.setdefault("base_seq", h["db_seq"])
            options.setdefault("base_root", h["data_root"])
        return self.call("prepare", op_id, kind, request=request, **options)

    def control(self, op_id: str, kind: str, *, actor="alice", **params) -> ControlIntent:
        selected = self.call("read_head", actor, action="create_control_intent")
        ci = ControlIntent.make(self.model.scope, selected.head["revision"], op_id, kind, actor, **params)
        self.prepare(op_id, kind, control=ci, actor=actor)
        return ci

    def durable(self, op_id: str, *, delta=1, result="original-result") -> None:
        attempt = self.call("stage", op_id, delta=delta, result=result)
        for index in range(len(attempt.objects)):
            self.call("upload", op_id, index)
        self.call("verify", op_id)

    def response(self, op_id: str, mode="ok", *, forget=False) -> dict:
        outcome = self.call("receive_cas", op_id, lost=mode == "lost_cas")
        if outcome == "applied" and self.model.attempts[op_id].kind == "commit":
            self.call("publish", op_id, fail=mode == "native_fail")
        answer = self.call("reply", op_id, lost=mode == "lost_reply")
        if forget and answer["state"] != "unknown":
            self.call("forget", op_id)
        return answer

    def finish(self, op_id: str, mode="ok", *, forget=False) -> dict:
        self.call("invoke_cas", op_id)
        self.call("deliver_cas", op_id)
        return self.response(op_id, mode, forget=forget)

    def write(self, op_id: str, request: Request | None = None, *, delta=1,
              result="original-result", mode="ok", forget=True) -> Request:
        request = request or self.request(op_id)
        attempt = self.prepare(op_id, "commit", request)
        if attempt.phase == "resolved":
            self.call("reply", op_id)
            if forget:
                self.call("forget", op_id)
        else:
            self.durable(op_id, delta=delta, result=result)
            self.finish(op_id, mode, forget=forget)
        return request

    def cancel(self, op_id: str, request: Request, *, forget=True) -> None:
        attempt = self.prepare(op_id, "cancel", request)
        if attempt.phase == "resolved":
            self.call("reply", op_id)
            if forget:
                self.call("forget", op_id)
        else:
            self.durable(op_id)
            self.finish(op_id, forget=forget)

    def change(self, op_id: str, kind: str, *, actor="alice", mode="ok", forget=True, **params) -> ControlIntent:
        ci = self.control(op_id, kind, actor=actor, **params)
        self.durable(op_id)
        self.finish(op_id, mode, forget=forget)
        return ci

    def close(self, op_id: str) -> None:
        self.change(op_id, "close", actor="coordinator", expected_epoch=self.model.head["request_epoch"])

    def history(self) -> list[dict[str, Any]]:
        return copy.deepcopy(self.model.events)


def interleavings(left=3, right=3):
    if not left and not right:
        yield ()
    if left:
        for tail in interleavings(left - 1, right):
            yield ("left",) + tail
    if right:
        for tail in interleavings(left, right - 1):
            yield ("right",) + tail


RACES = ("commit", "cancel", "takeover", "auth", "maintenance", "delete", "close_takeover", "activate_auth")
RESPONSE_CHOICES = tuple(itertools.product(("ok", "lost_cas"), repeat=2))


def race(kind: str, schedule: tuple[str, ...], modes: tuple[str, str], graph=None) -> Run:
    r = Run(f"race_{kind}", graph=graph, variant=modes)
    if kind == "close_takeover":
        r.write("fill-0")
        r.write("fill-1")
        r.control("left", "close", actor="coordinator", expected_epoch=1)
        r.control("right", "takeover", new_owner="writer-2")
    elif kind == "activate_auth":
        r.change("claim", "takeover", new_owner="writer-2")
        proof = r.call("recover", owner="writer-2", owner_epoch=2)
        r.control("left", "activate", recovery=proof)
        r.control("right", "auth", grants={"bob": ["admin", "read", "write"]})
    else:
        request = r.request("original")
        r.prepare("left", "commit", request)
        if kind == "commit":
            r.prepare("right", "commit", r.request("competitor"))
        elif kind == "cancel":
            r.prepare("right", "cancel", request)
        else:
            parameters = {"takeover": {"new_owner": "writer-2"},
                          "auth": {"grants": {"bob": ["admin", "read", "write"]}},
                          "maintenance": {"enabled": True}, "delete": {}}[kind]
            r.control("right", kind, **parameters)
    r.durable("left", delta=1, result="left-result")
    r.durable("right", delta=7, result="right-result")
    indices = {"left": 0, "right": 0}
    for actor in schedule:
        position = indices[actor]
        if position == 0:
            r.call("invoke_cas", actor)
        elif position == 1:
            r.call("deliver_cas", actor)
        else:
            r.response(actor, modes[0 if actor == "left" else 1])
        indices[actor] += 1
    effects = [event for event in r.model.events if event["type"] == "cas_effect" and event["op_id"] in indices]
    winners = [event["op_id"] for event in effects if event["applied"]]
    assert indices == {"left": 3, "right": 3} and len(winners) == 1
    if kind == "cancel":
        outcome = r.call("lookup", r.request("original", epoch=1))
        assert outcome["state"] == ("committed" if winners[0] == "left" else "cancelled")
    r.notes.update(winner=winners[0], schedule=list(schedule), response_choices=list(modes))
    return r


def directed(graph=None):
    r = Run("single_commit", graph=graph)
    request = r.write("write", delta=3, result="original-three")
    r.call("lookup", request)
    r.call("begin_read", "read")
    assert r.call("finish_read", "read") == 3
    yield r

    r = Run("absent_inflight_then_lost_response", graph=graph)
    request = r.request("unknown")
    r.prepare("write", "commit", request)
    r.durable("write")
    r.call("invoke_cas", "write")
    assert r.call("lookup", request)["state"] == "unknown"
    r.call("deliver_cas", "write")
    assert r.response("write", "lost_cas")["state"] == "unknown"
    assert r.call("lookup", request)["state"] == "committed"
    r.reject("phase", "forget", "write")
    yield r

    r = Run("lost_success_exact_transport_retry", graph=graph)
    request = r.write("write", mode="lost_cas", forget=False)
    r.call("invoke_cas", "write")
    assert r.call("deliver_cas", "write") is False
    assert r.response("write")["state"] == "unknown"
    assert r.call("lookup", request)["state"] == "committed"
    yield r

    for mode in ("native_fail", "lost_reply"):
        r = Run(mode, graph=graph)
        request = r.write("write", mode=mode, forget=False)
        r.call("restart")
        assert r.call("lookup", request)["state"] == "committed"
        r.call("begin_read", "after-restart")
        assert r.call("finish_read", "after-restart") == 1
        yield r

    r = Run("crash_does_not_cancel_inflight_cas", graph=graph)
    request = r.request("unknown")
    r.prepare("write", "commit", request)
    r.durable("write")
    r.call("invoke_cas", "write")
    r.call("restart")
    assert r.call("lookup", request)["state"] == "unknown"
    assert r.call("deliver_cas", "write") is True
    assert r.call("receive_cas", "write") == "unknown"
    assert r.call("lookup", request)["state"] == "committed"
    yield r

    for uploaded in range(4):
        r = Run(f"crash_after_{uploaded}_of_3_uploads", graph=graph)
        request = r.request("unpublished")
        r.prepare("write", "commit", request)
        staged = r.call("stage", "write")
        assert len(staged.objects) == 3
        for index in range(uploaded):
            r.call("upload", "write", index)
        r.call("crash", "write")
        r.call("restart")
        assert r.call("lookup", request)["state"] == "unknown"
        assert r.model.head["db_seq"] == 0
        yield r

    r = Run("full_window_cancel_close_and_late_candidate", graph=graph)
    r.write("first")
    late = r.request("late")
    r.prepare("late", "commit", late)
    r.durable("late")
    r.call("invoke_cas", "late")
    r.write("second")
    absent = r.request("absent")
    r.reject("resource_exhausted", "prepare", "cancel-absent", "cancel", request=absent)
    assert r.call("lookup", absent)["state"] == "unknown"
    r.close("close-1")
    assert r.call("deliver_cas", "late") is False
    r.response("late")
    assert r.call("lookup", late)["state"] == "epoch_closed"
    r.reject("epoch_closed", "prepare", "late-again", "cancel", request=late)
    yield r

    r = Run("nonfull_close_rejected", graph=graph)
    for suffix in ("empty", "partial"):
        if suffix == "partial":
            r.write("one")
        h = r.model.head
        ci = ControlIntent.make(r.model.scope, h["revision"], suffix, "close", "coordinator", expected_epoch=1)
        r.reject("window_not_full", "prepare", suffix, "close", actor="coordinator", control=ci)
    assert r.model.head["request_epoch"] == 1
    yield r

    r = Run("lost_result_retained_for_two_closed_epochs", graph=graph)
    r.write("first")
    original = r.write("original", delta=5, result="lost-original-five", mode="lost_cas", forget=False)
    r.close("close-1")
    assert r.call("lookup", original)["state"] == "committed"
    for epoch in (2, 3):
        for slot in range(2):
            r.cancel(f"bob-{epoch}-{slot}", r.request(f"bob-{slot}", epoch=epoch, actor="bob"))
        if epoch == 3:
            assert r.call("lookup", original)["result"] == "lost-original-five"
        r.close(f"close-{epoch}")
    assert r.model.head["request_epoch"] == 4 and r.model.head["retired_floor"] == 1
    assert r.call("lookup", original) == {"state": "retired", "retired_floor": 1}
    r.reject("retired", "prepare", "old-cancel", "cancel", request=original)
    r.call("begin_read", "retained-effect")
    assert r.call("finish_read", "retained-effect") == 6
    yield r

    r = Run("principal_fingerprint_scope_and_auth", graph=graph)
    original = r.write("original")
    r.reject("principal_mismatch", "lookup", original, actor="bob")
    other = Request(r.model.scope, 1, original.request_id, "bob", original.fingerprint)
    assert r.call("lookup", other, actor="bob")["state"] == "conflict"
    r.reject("conflict", "prepare", "other-cancel", "cancel", request=other, actor="bob")
    changed = Request(r.model.scope, 1, original.request_id, "alice", "different")
    assert r.call("lookup", changed)["state"] == "conflict"
    alien = Request("another/tenant/database/1", 1, "alien", "alice", "f")
    r.reject("scope", "lookup", alien)
    r.call("begin_read", "admitted-before-revoke")
    r.change("revoke", "auth", grants={"bob": ["admin", "read", "write"]})
    assert r.call("finish_read", "admitted-before-revoke") == 1
    r.reject("auth_fenced", "lookup", original)
    r.reject("forbidden", "lookup", original, auth_epoch=2)
    yield r

    r = Run("new_reader_selects_new_head", graph=graph)
    r.call("begin_read", "old-snapshot")
    r.write("write")
    assert r.call("finish_read", "old-snapshot") == 0
    r.call("begin_read", "new-snapshot")
    assert r.call("finish_read", "new-snapshot") == 1
    yield r

    r = Run("takeover_recovery_then_new_writer", graph=graph)
    r.write("before")
    r.change("takeover", "takeover", new_owner="writer-2")
    request = r.request("after")
    h = r.model.head
    r.reject("owner_fenced", "prepare", "old-writer", "commit", request=request,
             base_seq=h["db_seq"], base_root=h["data_root"])
    proof = r.call("recover", owner="writer-2", owner_epoch=2)
    r.change("activate", "activate", recovery=proof)
    r.write("after", request, delta=4)
    r.call("begin_read", "reader")
    assert r.call("finish_read", "reader") == 5
    yield r

    r = Run("control_unknown_stable_across_restart", graph=graph)
    original = r.change("claim", "takeover", new_owner="writer-2", mode="lost_cas", forget=False)
    assert r.call("lookup_control", original)["state"] == "applied"
    r.change("authorization", "auth", grants={"alice": ["admin", "read", "write"], "bob": ["read"]})
    r.call("restart")
    assert r.call("lookup_control", original, auth_epoch=2)["state"] == "superseded"
    r.reject("control_fenced", "prepare", "claim", "takeover", control=original, auth_epoch=2)
    yield r

    r = Run("maintenance_is_not_gc", graph=graph)
    original = r.write("original")
    r.change("enter", "maintenance", enabled=True)
    assert r.call("lookup", original)["state"] == "committed"
    r.call("begin_read", "reader")
    assert r.call("finish_read", "reader") == 1
    r.cancel("cancel", r.request("cancel"))
    r.close("close")
    h = r.model.head
    r.reject("maintenance", "prepare", "blocked", "commit", request=r.request("blocked"),
             base_seq=h["db_seq"], base_root=h["data_root"])
    r.change("leave", "maintenance", enabled=False)
    r.write("after")
    yield r

    r = Run("deleted_does_not_become_cancelled", graph=graph)
    original = r.write("original")
    r.change("delete", "delete")
    r.reject("deleted", "lookup", original)
    r.reject("deleted", "begin_read", "deleted-reader")
    r.reject("deleted", "prepare", "cancel", "cancel", request=original)
    ci = ControlIntent.make(r.model.scope, r.model.head["revision"], "close", "close", "coordinator", expected_epoch=1)
    r.reject("deleted", "lookup_control", ci, actor="coordinator")
    yield r

    r = Run("contract_drift_rejected", graph=graph)
    r.write("original")
    r.reject("contract_mismatch", "restart", window_limit=3)
    r.reject("contract_mismatch", "restart", keep_closed=1)
    r.call("restart")
    assert r.model.head["retention"] == {"window_limit": 2, "keep_closed": 2}
    yield r

    r = Run("all_orphans_consume_budget", graph=graph, max_objects=5)
    request = r.request("unpublished")
    r.prepare("write", "commit", request)
    r.call("stage", "write")
    r.call("upload", "write", 0)
    r.call("upload", "write", 1)
    r.reject("resource_exhausted", "upload", "write", 2)
    r.reject("missing_object", "verify", "write")
    r.call("restart")
    assert r.call("lookup", request)["state"] == "unknown"
    assert len(r.model.store.objects) == 5 and r.model.head["db_seq"] == 0
    yield r

    r = Run("counter_exhaustion_fails_closed", graph=graph, max_counter=1)
    r.write("first")
    r.prepare("second", "commit", r.request("second"))
    r.reject("exhausted", "stage", "second")
    assert r.model.head["revision"] == 1
    yield r

    r = Run("corrupt_dependency_fails_closed", graph=graph)
    original = r.write("original")
    r.call("corrupt", r.model.head["data_root"])
    r.reject("corrupt", "lookup", original)
    r.reject("corrupt", "begin_read", "damaged-reader")
    yield r

    r = Run("forget_and_reuse_local_nonce", graph=graph)
    first = r.write("same", r.request("first"), result="first-result")
    second = r.write("same", r.request("second"), result="second-result")
    a, b = r.call("lookup", first), r.call("lookup", second)
    assert a["transition_id"] == "1:same" and b["transition_id"] == "2:same"
    yield r


def examples() -> dict[str, list[dict[str, Any]]]:
    histories = {run.name: run.history() for run in directed()}
    histories["race_cancel_commit_first"] = race("cancel", ("left",) * 3 + ("right",) * 3, ("ok", "ok")).history()
    histories["race_cancel_cancel_first"] = race("cancel", ("right",) * 3 + ("left",) * 3, ("ok", "ok")).history()
    return histories


def resequence(history: list[dict]) -> list[dict]:
    for number, event in enumerate(history, 1):
        event["seq"] = number
    return history


def first(history, event_type, **fields):
    return next(event for event in history if event["type"] == event_type
                and all(event.get(k) == v for k, v in fields.items()))


def map_heads(value, revision: int, change) -> None:
    if isinstance(value, dict):
        if {"revision", "data_root", "request_root", "owner"} <= value.keys() and value["revision"] == revision:
            change(value)
        for child in value.values():
            map_heads(child, revision, change)
    elif isinstance(value, list):
        for child in value:
            map_heads(child, revision, change)


def refresh_closures(history: list[dict]) -> None:
    """Keep a malformed fixture structurally coherent to test its intended flaw."""
    objects, candidates = {}, {}
    for event in history:
        if event["type"] == "object_put" and event["applied"]:
            objects[event["key"]] = event["body"]
        elif event["type"] == "staged":
            candidates[event["op_id"]] = event["candidate"]
        elif event["type"] == "closure":
            head = candidates[event["op_id"]]
            roots = [head["data_root"], head["request_root"]]
            seen, pending = set(), roots[:]
            while pending:
                key = pending.pop()
                if key not in seen:
                    seen.add(key)
                    pending.extend(objects[key]["deps"])
            event["roots"], event["dependencies"] = roots, sorted(seen)


def change_object(history: list[dict], target: str, change) -> list[dict]:
    """Change valid content-addressed bytes and all dependent addresses.

    The original staged delta/result input is deliberately left fixed, so these
    controls test business/result binding, rather than merely a broken checksum.
    """
    keys: dict[str, str] = {}
    bodies: dict[str, dict] = {}

    def references(value):
        if isinstance(value, str):
            return keys.get(value, value)
        if isinstance(value, list):
            return [references(x) for x in value]
        if isinstance(value, dict):
            return {k: references(v) for k, v in value.items()}
        return value

    for event in history:
        if event["type"] != "object_put":
            continue
        key = event["key"]
        if key in bodies:
            continue
        body = references(copy.deepcopy(event["body"]))
        if key == target:
            change(body)
        bodies[key] = body
        keys[key] = f"{body['scope']}/objects/{sha(body)}"

    def replace(value):
        if isinstance(value, dict):
            if {"kind", "scope", "deps", "format"} <= value.keys():
                key = f"{value['scope']}/objects/{sha(value)}"
                if key in bodies:
                    return copy.deepcopy(bodies[key])
            return {k: replace(v) for k, v in value.items()}
        if isinstance(value, list):
            return [replace(x) for x in value]
        if isinstance(value, str):
            return keys.get(value, value)
        return value

    altered = replace(history)
    for event in altered:
        if event["type"] == "closure":
            event["dependencies"].sort()
    return altered


def negative_controls(samples: dict[str, list[dict]]):
    """Named invalid raw histories with a specified reason they must be rejected."""
    def clone(name="single_commit"):
        return copy.deepcopy(samples[name])

    def case(name, code, history):
        return {"name": name, "expected_invariant": code, "events": resequence(history)}

    for event_type, name, code in (("reply", "ack_before_authority", "ACK"),
                                  ("publish", "local_publish_before_authority", "EARLY_VISIBLE")):
        h = clone()
        h.insert(h.index(first(h, "cas_effect")), copy.deepcopy(first(h, event_type)))
        yield case(name, code, h)

    h = clone("race_cancel_commit_first")
    effect = first(h, "cas_effect", op_id="right")
    effect.update(applied=True, head=copy.deepcopy(first(h, "cas_sent", op_id="right")["candidate"]), etag="illegal-second-winner")
    yield case("two_winners_for_one_etag", "CAS", h)

    for name, state in (("uploaded_result_is_not_committed", "committed"), ("absence_is_not_cancelled", "cancelled")):
        h = clone("absent_inflight_then_lost_response")
        observation = first(h, "lookup")
        observation["outcome"] = {"state": state, "transition_id": "invented"}
        yield case(name, "LOOKUP", h)

    for source, old, name in (("full_window_cancel_close_and_late_candidate", "epoch_closed", "closed_absence_is_not_cancelled"),
                              ("lost_result_retained_for_two_closed_epochs", "retired", "retired_is_not_cancelled")):
        h = clone(source)
        event = next(e for e in h if e["type"] == "lookup" and e["outcome"]["state"] == old)
        event["outcome"] = {"state": "cancelled", "transition_id": "invented"}
        yield case(name, "LOOKUP", h)

    h = clone()
    observed = first(h, "lookup")
    read = first(h, "head_read", read_id=observed["read_id"])
    read["actor"] = read["intent"]["actor"] = "bob"
    yield case("lookup_cannot_switch_original_caller", "AUTH", h)

    h = clone("principal_fingerprint_scope_and_auth")
    read = [e for e in h if e["type"] == "head_read"][-1]
    h.append(dict(type="lookup", read_id=read["read_id"], request=read["intent"]["request"],
                  actor="alice", auth_epoch=2, outcome=copy.deepcopy(first(h, "reply")["result"])))
    yield case("revoked_principal_cannot_read_old_result", "AUTH", h)

    h = clone("new_reader_selects_new_head")
    first(h, "read_result", id="new-snapshot")["value"] = 0
    yield case("new_read_cannot_serve_old_cache", "READ_VALUE", h)

    h = clone("new_reader_selects_new_head")
    start = first(h, "read_started", id="new-snapshot")
    read = first(h, "head_read", read_id=start["read_id"])
    genesis = first(h, "genesis")
    read["head"], read["etag"] = copy.deepcopy(genesis["head"]), genesis["etag"]
    yield case("new_get_cannot_select_stale_head", "FRESH_READ", h)

    h = clone()
    initial = first(h, "genesis")["head"]
    map_heads(h, 1, lambda head: head.update(request_root=initial["request_root"]))
    refresh_closures(h)
    yield case("data_without_atomic_request_result", "ATOMIC_RESULT", h)

    h = clone()
    initial = first(h, "genesis")["head"]
    map_heads(h, 1, lambda head: head.update(data_root=initial["data_root"], db_seq=0))
    refresh_closures(h)
    yield case("result_without_atomic_data", "BASE", h)

    h = clone()
    put = next(e for e in h if e["type"] == "object_put" and e["op_id"] == "write" and e["body"]["kind"] == "result")
    h.remove(put)
    yield case("publication_with_missing_dependency", "CLOSURE", h)

    h = clone()
    put = next(e for e in h if e["type"] == "object_put" and e["op_id"] == "write" and e["body"]["kind"] == "data")
    h = change_object(h, put["key"], lambda body: body.update(delta=4, value=4))
    yield case("self_consistent_wrong_business_delta", "BUSINESS_EFFECT", h)

    h = clone()
    put = next(e for e in h if e["type"] == "object_put" and e["op_id"] == "write" and e["body"]["kind"] == "result")
    h = change_object(h, put["key"], lambda body: body.update(result="not-the-original-result"))
    yield case("self_consistent_wrong_original_result", "ORIGINAL_RESULT", h)

    h = clone()
    overwritten = copy.deepcopy(first(h, "object_put"))
    overwritten["body"]["value"] = 99
    h.append(overwritten)
    yield case("immutable_bytes_overwritten", "INTEGRITY", h)

    for name, changes, code in (("old_writer_accepted_on_fresh_head", {"owner": "writer-1", "owner_epoch": 1}, "OWNER"),
                                ("old_difference_rebased_on_new_sql_base", {"base_seq": 0}, "BASE")):
        h = clone("takeover_recovery_then_new_writer")
        for event in h:
            if event["type"] in {"prepared", "cas_sent"} and event["op_id"] == "after":
                event["intent"].update(changes)
            elif event["type"] == "head_read" and event["intent"].get("op_id") == "after":
                event["intent"].update(changes)
        yield case(name, code, h)

    h = clone("race_cancel_commit_first")
    send = first(h, "cas_sent", op_id="right")
    send["expected_etag"] = first(h, "cas_effect", op_id="left")["etag"]
    yield case("old_candidate_rebound_to_fresh_etag", "REBASE", h)

    h = clone("takeover_recovery_then_new_writer")
    h.remove(first(h, "recovered"))
    yield case("activation_without_recovery_observation", "RECOVERY", h)

    h = clone()
    map_heads(h, 1, lambda head: head.update(retention={"window_limit": 2, "keep_closed": 1}))
    yield case("retention_contract_drift", "RETENTION", h)

    h = clone("lost_result_retained_for_two_closed_epochs")
    old_index = first(h, "genesis")["head"]["request_root"]
    map_heads(h, 3, lambda head: head.update(retired_floor=1, closed_epochs=[], request_root=old_index))
    refresh_closures(h)
    yield case("result_retired_before_two_closed_epochs", "RETENTION", h)

    h = clone("lost_result_retained_for_two_closed_epochs")
    old_index = first(h, "genesis")["head"]["request_root"]
    map_heads(h, 3, lambda head: head.update(request_root=old_index))
    refresh_closures(h)
    yield case("closed_retained_result_disappears", "RETENTION", h)

    h = clone("control_unknown_stable_across_restart")
    read = [e for e in h if e["type"] == "head_read"][-1]
    prepared = copy.deepcopy(first(h, "prepared", op_id="claim"))
    prepared["read_id"] = read["read_id"]
    prepared["intent"] = {k: copy.deepcopy(v) for k, v in read["intent"].items() if k not in {"action", "op_id", "kind"}}
    prepared["intent"]["parameters"] = json.loads(prepared["intent"]["control"]["parameters_json"])
    h.append(prepared)
    yield case("unknown_control_rebuilt_at_fresh_revision", "CONTROL_REBASE", h)

    for field in ("expected_revision", "parameters_json"):
        h = clone("control_unknown_stable_across_restart")
        observation = first(h, "control_lookup")
        if field == "expected_revision":
            observation["control"][field] += 1
            observation["outcome"] = "unknown"
        else:
            observation["control"][field] = canonical({"new_owner": "another-writer"})
            observation["outcome"] = "conflict"
        yield case(f"control_query_changes_original_{field}", "CONTROL_LOOKUP", h)

    h = clone("lost_success_exact_transport_retry")
    [e for e in h if e["type"] == "cas_response"][-1]["outcome"] = "conflict"
    yield case("later_412_cannot_erase_unknown", "UNKNOWN", h)

    h = clone()
    map_heads(h, 1, lambda head: head.update(transition_id="0:write"))
    yield case("transition_uses_old_revision_prefix", "IDENTITY", h)

    # A forged empty Close is internally well formed, but violates the full-only
    # acceptance rule. It is deliberately not produced through model.prepare.
    h = clone()[:3]
    initial = copy.deepcopy(first(h, "genesis")["head"])
    ci = plain(ControlIntent.make(initial["scope"], 0, "empty", "close", "coordinator", expected_epoch=1))
    intent = dict(request=None, control=ci, actor="coordinator", auth_epoch=1,
                  owner="writer-1", owner_epoch=1, base_seq=None, base_root=None,
                  parameters={"expected_epoch": 1})
    candidate = {**copy.deepcopy(initial), "revision": 1, "transition_id": "1:empty",
                 "last_control_digest": sha(ci), "request_epoch": 2, "closed_epochs": [1]}
    read_intent = {k: v for k, v in intent.items() if k != "parameters"}
    h += [dict(type="head_read", read_id="empty-read", actor="coordinator", head=initial,
               etag=first(h, "genesis")["etag"], intent={**read_intent, "action": "prepare", "kind": "close", "op_id": "empty"}),
          dict(type="prepared", op_id="empty", kind="close", read_id="empty-read", intent=intent, outcome="prepared", result=None),
          dict(type="staged", op_id="empty", candidate=candidate, objects=[], delta=1, result="unused"),
          dict(type="closure", op_id="empty", roots=[candidate["data_root"], candidate["request_root"]],
               dependencies=sorted([candidate["data_root"], candidate["request_root"]]))]
    yield case("empty_epoch_close_accepted", "RETENTION", h)


def source_manifest() -> list[dict]:
    directory = Path(__file__).resolve().parent
    return [{"path": str(path), "bytes": path.stat().st_size,
             "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            for path in sorted(directory.glob("*.py"))]


def execute(output: Path) -> dict:
    output.mkdir(parents=True, exist_ok=False)
    history_dir, negative_dir = output / "histories", output / "counterexamples"
    history_dir.mkdir()
    negative_dir.mkdir()
    before = source_manifest()
    graph, counts, raw_counts, witnesses, inventory = Graph(), Counter(), Counter(), {}, []
    summaries = []
    maxima = Counter()

    def save_case(run: Run, suffix=""):
        events = run.history()
        label = run.name + suffix
        path = history_dir / f"{label}.jsonl"
        path.write_text("".join(canonical(event) + "\n" for event in events))
        inventory.append(path)
        try:
            checked = audit(events)
        except Exception as error:
            (output / "failure.json").write_text(json.dumps({"case": label, "error": str(error),
                                                           "history": str(path)}, indent=2) + "\n")
            raise
        counts[run.name] += 1
        raw_counts.update(event["type"] for event in events)
        summaries.append({"case": label, **checked, **run.notes})
        maxima["events_per_history"] = max(maxima["events_per_history"], len(events))
        maxima["objects_including_head_and_orphans"] = max(maxima["objects_including_head_and_orphans"], len(run.model.store.objects))
        maxima["metadata_revision"] = max(maxima["metadata_revision"], run.model.head["revision"])
        if not suffix:
            witnesses[run.name] = events
        if run.name == "race_cancel" and run.variant == ("ok", "ok"):
            if run.notes["schedule"] == ["left"] * 3 + ["right"] * 3:
                witnesses["race_cancel_commit_first"] = events
            if run.notes["schedule"] == ["right"] * 3 + ["left"] * 3:
                witnesses["race_cancel_cancel_first"] = events

    try:
        for run in directed(graph):
            save_case(run)
        for kind in RACES:
            for mode_index, modes in enumerate(RESPONSE_CHOICES):
                for schedule_index, schedule in enumerate(interleavings()):
                    save_case(race(kind, schedule, modes, graph), f"-{mode_index}-{schedule_index:02d}")
        negative = []
        for control in negative_controls(witnesses):
            path = negative_dir / f"{control['name']}.jsonl"
            path.write_text("".join(canonical(event) + "\n" for event in control["events"]))
            inventory.append(path)
            try:
                audit(control["events"])
            except OracleError as error:
                if error.code != control["expected_invariant"]:
                    raise AssertionError(f"{control['name']}: wrong rejection {error}") from error
                negative.append({"name": control["name"], "invariant": error.code, "first_rejected_event": error.step,
                                 "reason": error.detail, "history": str(path.relative_to(output))})
            else:
                raise AssertionError(f"negative control escaped: {control['name']}")
        after = source_manifest()
        if before != after:
            raise AssertionError("source changed during exploration; preserve and rerun in a fresh directory")
        summary = {
            "version": 1, "passed": True, "experiment": "object-authority-n0-bounded-model",
            "positive_cases": sum(counts.values()), "race_cases": sum(counts[k] for k in counts if k.startswith("race_")),
            "directed_cases": sum(counts[k] for k in counts if not k.startswith("race_")),
            "negative_controls": len(negative), "negative_controls_rejected": len(negative),
            "context_qualified_scheduler_states": len(graph.states), "distinct_scheduler_transitions": len(graph.edges),
            "executed_scheduler_steps": graph.executed_steps, "raw_events": sum(raw_counts.values()),
            "raw_event_counts": dict(raw_counts), "cases_by_scenario": dict(counts), "observed_maxima": dict(maxima),
            "enumeration": {"random_seed": None, "ordering": "fixed scenario order, lexicographic response choices, left-first depth-first linear extensions",
                            "race_scenarios": list(RACES), "actors_per_race": 2, "stages_per_actor": ["invoke", "effect", "receive"],
                            "linear_extensions_per_response_choice": 20, "response_choices": plain(RESPONSE_CHOICES),
                            "candidate_preparation": "both candidates and all dependencies completed before the six-stage race; receive expands to native publication and application reply without another scheduler actor between them",
                            "state_identity": "scenario + response choices + complete model.snapshot_state() + next raw event ordinal; this is not a count of all possible protocol states",
                            "window_limit": 2, "product_candidate_window_limit": 128, "keep_closed": 2,
                            "default_max_objects_including_head_and_orphans": 96, "default_max_counter": 255, "default_max_attempts": 8},
            "negative_results": negative, "source_inputs": before, "python": platform.python_version(),
            "case_results": summaries,
            "artifacts": [{"path": str(path.relative_to(output)), "bytes": path.stat().st_size,
                           "sha256": hashlib.sha256(path.read_bytes()).hexdigest()} for path in inventory],
            "limitations": ["Finite two-actor schedule matrix plus named directed cases, not an exhaustive or unbounded proof.",
                            "Atomic exact-key GET and opaque-ETag conditional PUT are assumptions of the in-memory Store, not verified AWS S3 behavior.",
                            "Integer effects and result tokens are synthetic; no SQLite, HTTP, wire codec, checksum adapter, time, scheduling fairness or throughput is exercised.",
                            "Upload interleavings, arbitrary numbers of concurrent clients, deadlines, real outages and every crash boundary are not exhaustively enumerated.",
                            "Two slots exercise boundaries but do not validate production sizing for 128 slots; the retention guarantee counts closed epochs and has no positive wall-clock minimum.",
                            "No object is deleted; HEAD, immutable objects and orphans consume the bounded budget. GC, pin, PITR, catalogue and multi-database coordination are not implemented."],
            "production_slo_passed": False, "real_s3_tested": False, "real_sqlite_tested": False,
        }
        (output / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n")
        return summary
    except Exception as error:
        (output / "failure-summary.json").write_text(json.dumps({"passed": False, "error": str(error),
                                                               "completed_positive_cases": sum(counts.values()),
                                                               "source_inputs": before}, indent=2) + "\n")
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new absolute directory; existing directories are never overwritten")
    args = parser.parse_args()
    if not args.output.is_absolute() or args.output.exists():
        parser.error("--output must be an absolute path to a directory that does not exist")
    summary = execute(args.output)
    print(json.dumps({key: summary[key] for key in
                      ("passed", "positive_cases", "race_cases", "directed_cases", "negative_controls_rejected",
                       "context_qualified_scheduler_states", "distinct_scheduler_transitions", "executed_scheduler_steps")}, indent=2))
    print(f"Raw histories and summary: {args.output}")


if __name__ == "__main__":
    main()
