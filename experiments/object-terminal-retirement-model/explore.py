"""Exhaust specified finite schedules and retain independently checked histories.

The scheduler only interleaves the explicitly named action boundaries. Macro
operations are not a claim to enumerate every production I/O or thread step.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import time

from counterexamples import examples
from model import Model, Rejected, fingerprint, head_key, payload_key
from oracle import audit, Violation


PRODUCT_BASE = "66f452ec73111f8c9dc7509883717828ba883e8a"
OWNED = ("direct", "delete", "abort", "abort_absent")
LOSS = ((), ("a",), ("b",), ("a", "b"))


def interleave(left, right):
    if not left:
        yield tuple(right)
    elif not right:
        yield tuple(left)
    else:
        for tail in interleave(left[1:], right):
            yield (left[0],) + tail
        for tail in interleave(left, right[1:]):
            yield (right[0],) + tail


class Walk:
    def __init__(self, model):
        self.model = model
        self.states = {fingerprint(model.snapshot())}
        self.edges = set()
        self.last = fingerprint(model.snapshot())

    def step(self, label, action):
        action()
        after = fingerprint(self.model.snapshot())
        self.states.add(after)
        self.edges.add((self.last, label, after))
        self.last = after


def pipe(model, action):
    if action == "seal":
        model.run(model.prepare_terminal("seal"))
    elif action == "batch":
        model.run(model.prepare_checkpoint("batch"))
    elif action == "delete":
        model.run(model.prepare_delete("delete"))
    elif action == "settle":
        model.run(model.prepare_settle("settle", delete_call="delete"))
    elif action == "clear":
        model.run(model.prepare_clear("clear"))
    else:
        raise ValueError(action)


def network(model, identifier, action, lost=False):
    if action == "invoke":
        model.invoke(identifier)
    elif action == "effect":
        model.effect(identifier)
    elif action == "response":
        model.respond(identifier, lost=lost)
    elif action == "materialize":
        if model.reader_reply() == "missing":
            model.diagnose()
    else:
        raise ValueError(action)


def scenario(profile, inputs, walk, **postconditions):
    history = walk.model.history()
    return {"profile": profile, "inputs": inputs, "history": history, "postconditions": postconditions,
            "states": walk.states, "edges": walk.edges}


def schedules(smoke=False):
    pairs = list(interleave(("a.invoke", "a.effect", "a.response"), ("b.invoke", "b.effect", "b.response")))
    assert len(pairs) == 20
    for mode in OWNED:
        for lost in LOSS:
            for order in pairs[:1] if smoke else pairs:
                model = Model(mode)
                model.prepare_terminal("a")
                model.prepare_terminal("b")
                walk = Walk(model)
                for step in order:
                    identifier, action = step.split(".")
                    walk.step(step, lambda identifier=identifier, action=action: network(model, identifier, action, identifier in lost))
                yield scenario("terminal-race", {"mode": mode, "lost": lost, "order": order}, walk,
                               exactly_one_applied=sum(model.calls[name].result == "applied" for name in ("a", "b")) == 1)

    pipeline = ("seal", "batch", "delete", "settle", "clear")
    put_orders = list(interleave(("old-put.invoke", "old-put.effect", "old-put.response"), pipeline))
    assert len(put_orders) == 56
    for etags in ("fresh", "content"):
        for lost in (False, True):
            for order in put_orders[:1] if smoke else put_orders:
                model, walk = Model(object_etags=etags), None
                walk = Walk(model)
                for step in order:
                    if "." in step:
                        identifier, action = step.split(".")
                        walk.step(step, lambda identifier=identifier, action=action: network(model, identifier, action, lost))
                    else:
                        walk.step(step, lambda step=step: pipe(model, step))
                if payload_key() in model.store:
                    walk.step("new-round-batch", lambda: model.run(model.prepare_checkpoint("batch-2")))
                    walk.step("new-round-delete", lambda: model.run(model.prepare_delete("delete-2")))
                    walk.step("new-round-settle", lambda: model.run(model.prepare_settle("settle-2", delete_call="delete-2")))
                    walk.step("new-round-clear", lambda: model.run(model.prepare_clear("clear-2")))
                yield scenario("late-put", {"etags": etags, "lost": lost, "order": order}, walk,
                               finite_orphan_collected=payload_key() not in model.store)

    read_orders = list(interleave(("old-read.invoke", "old-read.effect", "old-read.response", "old-read.materialize"), pipeline))
    assert len(read_orders) == 126
    for mode in ("direct", "delete"):
        for order in read_orders[:1] if smoke else read_orders:
            model = Model(mode)
            walk = Walk(model)
            for step in order:
                if "." in step:
                    identifier, action = step.split(".")
                    walk.step(step, lambda identifier=identifier, action=action: network(model, identifier, action))
                else:
                    walk.step(step, lambda step=step: pipe(model, step))
            yield scenario("late-get", {"mode": mode, "order": order}, walk,
                           ordinary_read_outcome=model.reader["outcome"] in ("value", "snapshot_expired"))

    for mode in OWNED:
        for identifier in (("old-create",) if mode == "abort_absent" else ("old-create", "old-head")):
            orders = list(interleave(tuple(identifier + "." + step for step in ("invoke", "effect", "response")), pipeline))
            for order in orders[:1] if smoke else orders:
                model = Model(mode)
                walk = Walk(model)
                for step in order:
                    if "." in step:
                        call, action = step.split(".")
                        walk.step(step, lambda call=call, action=action: network(model, call, action))
                    else:
                        walk.step(step, lambda step=step: pipe(model, step))
                yield scenario("late-head", {"mode": mode, "call": identifier, "order": order}, walk,
                               old_head_fenced=model.calls[identifier].reply == "conflict")

    for mode in OWNED:
        for crash_after in range(4):
            model = Model(mode)
            model.prepare_terminal("seal")
            walk = Walk(model)
            phases = ("invoke", "effect", "response")
            for step in phases[:crash_after]:
                walk.step("seal." + step, lambda step=step: network(model, "seal", step))
            walk.step("crash", model.crash)
            if crash_after == 0:
                def stale():
                    try:
                        model.invoke("seal")
                    except Rejected as error:
                        assert error.reason == "stale_or_already_invoked"
                walk.step("reject-old-unsent", stale)
                walk.step("independent-new-call", lambda: model.run(model.prepare_terminal("new-seal")))
            else:
                for step in phases[crash_after:]:
                    walk.step("late-seal." + step, lambda step=step: network(model, "seal", step))
            walk.step("fresh-terminal-state", model.terminal_status)
            yield scenario("restart-terminal", {"mode": mode, "crash_after": crash_after}, walk,
                           terminal_observed=model.store[head_key()]["body"]["terminal"] is not None)

    for etags in ("fresh", "content"):
        for original_first in (False, True):
            model = Model(object_etags=etags)
            walk = Walk(model)
            walk.step("seal", lambda: pipe(model, "seal"))
            walk.step("batch", lambda: pipe(model, "batch"))
            walk.step("invoke-old-delete", lambda: model.invoke(model.prepare_delete("old-delete")))
            walk.step("unknown-original", lambda: model.timeout("old-delete"))
            walk.step("crash", model.crash)
            if original_first:
                walk.step("old-effect", lambda: model.effect("old-delete"))
                absent = model.prepare_delete("probe")
                walk.step("typed-absence-settle", lambda: model.run(model.prepare_settle("settle", absent=absent)))
            else:
                walk.step("new-resume-delete", lambda: model.run(model.prepare_delete("new-delete")))
                walk.step("new-known-settle", lambda: model.run(model.prepare_settle("settle", delete_call="new-delete")))
            walk.step("clear", lambda: pipe(model, "clear"))
            if not original_first:
                walk.step("late-old-effect", lambda: model.effect("old-delete"))
            yield scenario("restart-gc", {"etags": etags, "original_first": original_first}, walk,
                           original_unknown_preserved=model.calls["old-delete"].reply == "unknown")

    for crash_after in range(4):
        model = Model("foreign")
        foreign = fingerprint(model.store[head_key()])
        model.release_foreign_abort("release")
        walk = Walk(model)
        phases = ("invoke", "effect", "response")
        for step in phases[:crash_after]:
            walk.step("release." + step, lambda step=step: network(model, "release", step))
        walk.step("crash", model.crash)
        if crash_after == 0:
            walk.step("new-metadata-attempt", lambda: model.run(model.release_foreign_abort("fresh-release")))
        else:
            for step in phases[crash_after:]:
                walk.step("late-release." + step, lambda step=step: network(model, "release", step))
        walk.step("original-abort-progress", model.recover_foreign_abort)
        yield scenario("foreign-abort", {"crash_after": crash_after}, walk,
                       foreign_head_unchanged=fingerprint(model.store[head_key()]) == foreign)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    content = json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    path.write_text(content)
    return {"path": str(path), "sha256": hashlib.sha256(content.encode()).hexdigest(), "bytes": len(content.encode())}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--smoke", action="store_true", help="only first schedule per parameter profile; not exhaustive")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    repo = root.parent.parent
    output = args.out.resolve()
    if output.is_relative_to(repo):
        parser.error("evidence must be outside the source repository")
    output.mkdir(parents=True, exist_ok=False)
    (output / "positive").mkdir()
    (output / "counterexamples").mkdir()
    sources = {str(path.relative_to(repo)): sha(path) for path in sorted(root.glob("*.py"))}
    manifest = {"schema": 1, "started_utc": datetime.now(timezone.utc).isoformat(), "product_base": PRODUCT_BASE,
                "source_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip(),
                "python": platform.python_version(), "smoke": args.smoke, "sources": sources,
                "positive": [], "counterexamples": [], "ok": False}
    started = time.monotonic()
    profiles = defaultdict(lambda: {"histories": 0, "events": 0})
    states, edges = set(), set()
    try:
        for number, item in enumerate(schedules(args.smoke), 1):
            if number > 1300:
                raise RuntimeError("declared history budget exceeded")
            entry = save(output / "positive" / f"{number:04d}.json", item["history"])
            entry.update(profile=item["profile"], inputs=item["inputs"], postconditions=item["postconditions"])
            manifest["positive"].append(entry)
            entry["counts"] = audit(item["history"])
            if not all(item["postconditions"].values()):
                raise RuntimeError("profile postcondition failed: " + item["profile"])
            profiles[item["profile"]]["histories"] += 1
            profiles[item["profile"]]["events"] += entry["counts"]["events"]
            states.update((item["profile"], value) for value in item["states"])
            edges.update((item["profile"], *value) for value in item["edges"])
        for case in examples():
            entry = save(output / "counterexamples" / (case["name"] + ".json"), case["history"])
            entry.update(name=case["name"], kind=case["kind"], expected_rule=case["expected_rule"])
            try:
                audit(case["history"])
            except Violation as error:
                entry.update(observed_rule=error.rule, violating_event=error.sequence)
            manifest["counterexamples"].append(entry)
            if entry.get("observed_rule") != case["expected_rule"]:
                raise RuntimeError("counterexample was not rejected by its expected rule: " + case["name"])
        expected = 53 if args.smoke else 1212
        if len(manifest["positive"]) != expected or len(manifest["counterexamples"]) != 19:
            raise RuntimeError("unexpected explored profile cardinality")
        if sources != {str(path.relative_to(repo)): sha(path) for path in sorted(root.glob("*.py"))}:
            raise RuntimeError("source changed during exploration")
        manifest["ok"] = True
    except Exception as error:
        manifest["error"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        manifest.update(finished_utc=datetime.now(timezone.utc).isoformat(), elapsed_seconds=time.monotonic() - started,
                        profiles=dict(profiles), distinct_macro_states=len(states), distinct_macro_edges=len(edges),
                        total_history_bytes=sum(row["bytes"] for key in ("positive", "counterexamples") for row in manifest[key]))
        save(output / "manifest.json", manifest)
    print(json.dumps({key: manifest[key] for key in ("ok", "smoke", "profiles", "distinct_macro_states", "distinct_macro_edges", "total_history_bytes", "elapsed_seconds")}, sort_keys=True))


if __name__ == "__main__":
    main()
