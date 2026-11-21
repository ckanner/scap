"""Finite interleaving model for one original-ETag group and one control.

This is a protocol experiment, not a SQLite emulator, throughput measurement,
or proof of an S3 implementation. Local member values stand in for independently
committed private transactions; immutable dependency verification is explicit.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from itertools import product


@dataclass
class Authority:
    etag: int = 1
    revision: int = 5
    serial: int = 7
    sequence: int = 3
    owner: int = 1
    auth: int = 1
    epoch: int = 1
    active: bool = True
    results: dict = field(default_factory=dict)
    cancelled: set = field(default_factory=set)


def audit(history):
    """Independent trace rules: no knowledge of the stepper's state objects."""
    captured = None
    staged, durable, verified = [], set(), set()
    accepted = adopted = cas_seen = False
    calls, member_failed, rejected, blocked = set(), False, False, False
    previous = Authority()
    for row in history:
        event = row["event"]
        if event == "capture":
            assert captured is None, "candidate recaptured authority"
            captured = row["head"]
            assert captured == previous, "body and ETag were not one exact observation"
        elif event == "execute":
            assert captured and not member_failed and not rejected, "executed after failed member or conflict"
            assert row["id"] not in calls, "SQL replayed within original attempt"
            calls.add(row["id"])
        elif event == "staged":
            assert row["id"] in calls and not member_failed, "staged unexecuted member"
            staged.append(row["id"])
        elif event == "member_failed":
            assert row["id"] in calls and row["id"] not in staged, "failed member was published as successful"
            member_failed = True
        elif event == "persist":
            assert row["id"] in staged, "persisted unexecuted result"
            durable.add(row["id"])
        elif event == "verify":
            assert row["id"] in durable, "verified before persistence"
            verified.add(row["id"])
        elif event == "control":
            head = row["head"]
            assert head.etag == previous.etag + 1 and head.serial == previous.serial + 1
            assert head.revision == previous.revision + 1 and head.sequence == previous.sequence
            previous = head
        elif event == "cas":
            assert not cas_seen, "candidate retried its original CAS"
            cas_seen = True
            assert not blocked, "fatal native or dependency failure cannot publish a prefix"
            assert captured and staged and row["if_match"] == captured.etag, "old candidate obtained a fresh ETag"
            assert durable == verified == set(staged), "HEAD published unverified dependencies"
            candidate = row["head"]
            width = len(staged)
            assert candidate.sequence == captured.sequence + width
            assert candidate.revision == captured.revision + width, "members share a transaction revision"
            assert candidate.serial == captured.serial + width
            assert (candidate.owner, candidate.auth, candidate.epoch, candidate.active) == (
                captured.owner, captured.auth, captured.epoch, captured.active), "group changed protected authority"
            expected = dict(captured.results)
            for offset, identity in enumerate(staged, 1):
                expected[identity] = (captured.sequence + offset, captured.revision + offset, identity * 31)
            assert candidate.results == expected and candidate.cancelled == captured.cancelled
            assert row["accepted"] == (previous.etag == captured.etag), "CAS did not compare original authority"
            if row["accepted"]:
                assert not set(staged).intersection(previous.cancelled), "group crossed a cancellation barrier"
                previous, accepted = candidate, True
            else:
                rejected = True
        elif event == "adopt":
            assert accepted and not adopted, "private candidate adopted before durable acceptance"
            adopted = True
        elif event == "reply":
            if row["outcome"] == "ack":
                assert accepted and adopted and row["id"] in staged, "ACK preceded publication/native adoption"
            if row["outcome"] == "committed_unavailable":
                assert accepted and row["id"] in staged, "known-commit error lost its receipt"
            if row["outcome"] == "conflict":
                assert rejected, "412 invented without original CAS"
        elif event == "cold_lookup":
            assert row["results"] == previous.results and row["cancelled"] == previous.cancelled, "cold lookup regenerated results"
        elif event in ("declined", "fatal", "dependency_failed"):
            blocked = True
        elif event not in ("lost_response", "control_observe"):
            raise AssertionError("unknown model event")
    return {"executed": len(calls), "staged": len(staged), "accepted": accepted, "rejected": rejected}


def run(width, failed=None, control=None, control_at=0, fault=None):
    head = Authority()
    trace, staged = [], []
    step, controlled = 0, False

    def emit(event, **fields):
        trace.append({"event": event, **deepcopy(fields)})

    def boundary():
        nonlocal step, controlled, head
        if control is not None and step == control_at and not controlled:
            if control == "cancel" and 2 in head.results:
                controlled = True
                emit("control_observe")
                step += 1
                return
            changed = deepcopy(head)
            changed.etag += 1
            changed.serial += 1
            changed.revision += 1
            if control == "cancel":
                if 2 not in changed.results:
                    changed.cancelled.add(2)
            elif control == "owner":
                changed.owner += 1
            elif control == "acl":
                changed.auth += 1
            elif control == "epoch":
                changed.epoch += 1
            else:
                changed.active = False
            head, controlled = changed, True
            emit("control", head=head)
        step += 1

    boundary()
    base = deepcopy(head)
    emit("capture", head=base)
    if base.owner != 1 or base.auth != 1 or base.epoch != 1 or not base.active or base.cancelled:
        emit("declined")
    else:
        for identity in range(1, width + 1):
            boundary()
            emit("execute", id=identity)
            if identity == failed:
                emit("member_failed", id=identity)
                break
            staged.append(identity)
            emit("staged", id=identity)
        boundary()
        if fault == "native_fatal":
            emit("fatal")
        elif staged:
            for identity in staged:
                emit("persist", id=identity)
                if fault != "dependency":
                    emit("verify", id=identity)
            if fault == "dependency":
                emit("dependency_failed")
            else:
                boundary()
                candidate = deepcopy(base)
                candidate.etag = head.etag + 1
                candidate.serial += len(staged)
                candidate.revision += len(staged)
                candidate.sequence += len(staged)
                for offset, identity in enumerate(staged, 1):
                    candidate.results[identity] = (base.sequence + offset, base.revision + offset, identity * 31)
                accepted = head.etag == base.etag
                emit("cas", if_match=base.etag, head=candidate, accepted=accepted)
                if accepted:
                    head = candidate
                boundary()
                if not accepted:
                    outcome = "conflict"
                elif fault == "lost_cas_response":
                    emit("lost_response")
                    outcome = "unknown"
                elif fault == "native_adoption":
                    outcome = "committed_unavailable"
                else:
                    emit("adopt")
                    outcome = "ack"
                for identity in staged:
                    emit("reply", id=identity, outcome=outcome)
    emit("cold_lookup", results=head.results, cancelled=head.cancelled)
    audit(trace)
    return trace


def explore():
    total, accepted, rejected, declined = 0, 0, 0, 0
    for width in (2, 3, 4):
        for failed in (None, *range(1, width + 1)):
            for control, at, fault in product((None, "cancel", "owner", "acl", "epoch", "delete"),
                    range(width + 5), (None, "native_fatal", "dependency", "lost_cas_response", "native_adoption")):
                trace = run(width, failed, control, at, fault)
                proof = audit(trace)
                total += 1
                accepted += proof["accepted"]
                rejected += proof["rejected"]
                declined += any(row["event"] == "declined" for row in trace)
    return {"schedules": total, "accepted": accepted, "conflicted": rejected, "declined_before_sql": declined}


if __name__ == "__main__":
    import json
    print(json.dumps(explore(), sort_keys=True))
