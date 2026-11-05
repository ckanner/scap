"""Independent safety oracle for the finite object-authority experiment.

Only recorded objects, HEAD observations, CAS effects and client observations are
trusted as inputs.  This module deliberately does not import the model, its
prepare function, or its state-transition helpers.  It checks every publication,
not just the last HEAD.  A passing history is conditional on the model's atomic
opaque-ETag store and trusted-component assumptions; it is not an S3/SQL test.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any


class OracleError(AssertionError):
    """A rejected raw-history prefix, with a stable invariant identifier."""

    def __init__(self, code: str, message: str, step: int) -> None:
        self.code = code
        self.step = step
        self.detail = message
        super().__init__(f"{code} at event {step}: {message}")


def _request_key(request: dict[str, Any]) -> str:
    return f"{request['epoch']}:{request['request_id']}"


def _digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(encoded.encode()).hexdigest()


class HistoryOracle:
    """Check a complete history or a prefix without inferring missing replies."""

    def __init__(self) -> None:
        self.step = -1
        self.objects: dict[str, dict[str, Any]] = {}
        self.head: dict[str, Any] | None = None
        self.etag: str | None = None
        self.config: dict[str, Any] = {}
        self.reads: dict[str, dict[str, Any]] = {}
        self.attempts: dict[str, dict[str, Any]] = {}
        self.used_etags: set[str] = set()
        self.transitions: set[str] = set()
        self.accepted: dict[str, dict[str, Any]] = {}
        self.controls: dict[str, dict[str, Any]] = {}
        self.proofs: dict[str, dict[str, Any]] = {}
        self.pending: dict[str, dict[str, Any]] = {}
        self.readers: dict[str, dict[str, Any]] = {}
        self.counts: Counter[str] = Counter()

    def need(self, condition: bool, code: str, message: str) -> None:
        if not condition:
            raise OracleError(code, message, self.step)

    def closure(self, root: str, scope: str) -> dict[str, Any]:
        seen: set[str] = set()
        visiting: set[str] = set()

        def visit(key: str) -> None:
            self.need(key not in visiting, "CLOSURE", "cyclic immutable dependency")
            if key in seen:
                return
            self.need(key in self.objects, "CLOSURE", f"missing dependency {key}")
            body = self.objects[key]
            self.need(body.get("scope") == scope, "SCOPE", "cross-scope dependency")
            self.need(key == f"{scope}/objects/{_digest(body)}", "INTEGRITY", "immutable content no longer matches its key")
            self.need(isinstance(body.get("deps"), list), "CLOSURE", "missing dependency list")
            visiting.add(key)
            for dependency in body["deps"]:
                visit(dependency)
            visiting.remove(key)
            seen.add(key)

        visit(root)
        return self.objects[root]

    def roots(self, head: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        data = self.closure(head["data_root"], head["scope"])
        index = self.closure(head["request_root"], head["scope"])
        self.need(data.get("kind") == "data" and data.get("seq") == head["db_seq"],
                  "DATA", "data root does not describe the published SQL sequence")
        self.need(index.get("kind") == "requests" and isinstance(index.get("records"), dict),
                  "RESULTS", "request root is not a complete result index")
        roots = []
        counts: Counter[int] = Counter()
        for key, record in index["records"].items():
            counts[record["epoch"]] += 1
            self.need(head["retired_floor"] < record["epoch"] <= head["request_epoch"],
                      "RETENTION", "record lies outside the retained epochs")
            self.need(key == _request_key(record), "IDENTITY", "misindexed request identity")
            self.need(record["state"] in {"committed", "cancelled"}, "RESULTS", "nonterminal index entry")
            if record["state"] == "committed":
                result = self.closure(record["result_root"], head["scope"])
                roots.append(record["result_root"])
                self.need(result.get("kind") == "result", "RESULTS", "result reference is not a result")
                self.need(result.get("seq") == record["seq"] and result.get("transition_id") == record["transition_id"],
                          "RESULTS", "receipt and original result are separated")
                identity = result.get("request", {})
                self.need(all(identity.get(k) == record.get(k) for k in
                              ("epoch", "request_id", "principal", "fingerprint")),
                          "IDENTITY", "result belongs to another original request")
                self.need(identity.get("scope") == head["scope"], "SCOPE", "result request has another scope")
        self.need(set(index["deps"]) == set(roots), "CLOSURE", "index does not declare its exact result dependencies")
        self.need(all(n <= head["retention"]["window_limit"] for n in counts.values()),
                  "CAPACITY", "published epoch exceeds its slot budget")
        self.need(all(counts[e] == head["retention"]["window_limit"] for e in head["closed_epochs"]),
                  "RETENTION", "a closed retained window lost a terminal result")
        return data, index["records"]

    def authorize(self, head: dict[str, Any], intent: dict[str, Any], permissions: set[str]) -> None:
        self.need(intent.get("auth_epoch") == head["auth_epoch"], "AUTH", "stale authorization epoch")
        actor = intent.get("actor")
        self.need(permissions <= set(head["grants"].get(actor, [])), "AUTH", "current principal lacks permission")
        self.need(head["lifecycle"] != "deleted", "LIFECYCLE", "deleted authority served an operation")

    def lookup(self, head: dict[str, Any], request: dict[str, Any], actor: str) -> dict[str, Any]:
        self.need(request["scope"] == head["scope"], "SCOPE", "request belongs to another authority")
        self.need(actor == request["principal"], "IDENTITY", "another principal borrowed an original identity")
        _, records = self.roots(head)
        epoch = request["epoch"]
        if epoch <= head["retired_floor"]:
            return {"state": "retired", "retired_floor": head["retired_floor"]}
        self.need(epoch <= head["request_epoch"], "RETENTION", "future identity interpreted as current")
        record = records.get(_request_key(request))
        if record is not None:
            if any(record[k] != request[k] for k in ("principal", "fingerprint")):
                return {"state": "conflict"}
            if record["state"] == "cancelled":
                return copy.deepcopy(record)
            result = self.objects[record["result_root"]]
            return {**copy.deepcopy(record), "result": result["result"]}
        return {"state": "epoch_closed" if epoch < head["request_epoch"] else "unknown"}

    def transition(self, old: dict[str, Any], new: dict[str, Any], attempt: dict[str, Any]) -> None:
        """Check invariant deltas; do not construct the model's next HEAD."""
        kind, intent = attempt["kind"], attempt["intent"]
        params = intent.get("parameters", {})
        old_data, before = self.roots(old)
        data, after = self.roots(new)
        self.need(new["scope"] == old["scope"] and new["format"] == old["format"],
                  "SCOPE", "authority identity or format changed")
        self.need(new["retention"] == old["retention"], "RETENTION", "creation-time retention contract changed")
        counters = [new[k] for k in ("revision", "db_seq", "auth_epoch", "request_epoch", "retired_floor")]
        counters.append(new["owner"]["epoch"])
        self.need(all(type(n) is int and 0 <= n <= self.config["max_counter"] for n in counters),
                  "CAPACITY", "bounded counter wrapped or exceeded its modeled range")
        self.need(type(data["value"]) is int and abs(data["value"]) <= self.config["max_value"],
                  "CAPACITY", "modeled data budget exceeded")
        self.need(new["revision"] == old["revision"] + 1, "ORDER", "metadata revision did not advance exactly once")
        self.need(new["transition_id"] not in self.transitions, "ORDER", "transition identity reused")
        self.need(old["lifecycle"] != "deleted", "LIFECYCLE", "tombstone resurrected")
        allowed = {"revision", "transition_id", "last_control_digest"}
        self.need(new["transition_id"] == f"{new['revision']}:{attempt['op_id']}",
                  "IDENTITY", "publication changed its revision-qualified transition identity")
        if kind in {"commit", "cancel"}:
            self.need(new["last_control_digest"] is None, "CONTROL", "SQL publication forged a control receipt")
        else:
            control = intent["control"]
            self.need(control["expected_revision"] == old["revision"], "CONTROL_REBASE", "old control intent rebound to a new HEAD")
            self.need(control["scope"] == old["scope"] and control["kind"] == kind
                      and control["principal"] == intent["actor"] and control["control_id"] == attempt["op_id"],
                      "CONTROL", "published control differs from its original identity")
            self.need(json.loads(control["parameters_json"]) == params, "CONTROL", "control parameters changed after admission")
            self.need(new["last_control_digest"] == _digest(control), "CONTROL", "control receipt does not bind the complete original intent")
        if kind in {"commit", "cancel"}:
            self.authorize(old, intent, {"read", "write"})
            request = intent["request"]
            self.need(self.lookup(old, request, intent["actor"]) == {"state": "unknown"},
                      "IDENTITY", "new acceptance of an existing or closed request")
            self.need(request["epoch"] == old["request_epoch"], "RETENTION", "new acceptance outside the current epoch")
            current = [r for r in before.values() if r["epoch"] == old["request_epoch"]]
            self.need(len(current) < old["retention"]["window_limit"], "CAPACITY", "current request window overflow")
            key = _request_key(request)
            self.need(set(after) == set(before) | {key} and all(after[k] == r for k, r in before.items()),
                      "ATOMIC_RESULT", "acceptance dropped or changed an earlier terminal result")
            record = after[key]
            self.need(all(record[k] == request[k] for k in ("epoch", "request_id", "principal", "fingerprint")),
                      "IDENTITY", "published request differs from the original intent")
            self.need(record["transition_id"] == new["transition_id"], "ATOMIC_RESULT", "data and result have different transitions")
            allowed.add("request_root")
            if kind == "commit":
                self.need(old["lifecycle"] == "ready", "LIFECYCLE", "business write admitted during maintenance")
                self.need(old["owner"] == {"instance": intent["owner"], "epoch": intent["owner_epoch"], "state": "active"},
                          "OWNER", "stale or inactive writer accepted")
                self.need(intent["base_seq"] == old["db_seq"] and intent["base_root"] == old["data_root"],
                          "BASE", "old staged difference rebased onto another predecessor")
                self.need(new["db_seq"] == old["db_seq"] + 1 and data["base_root"] == old["data_root"],
                          "BASE", "physical successor does not extend the exact selected base")
                self.need(data["value"] == old_data["value"] + data["delta"], "DATA", "physical effect lost or invented")
                self.need(data["delta"] == attempt["staged"]["delta"], "BUSINESS_EFFECT", "published effect differs from the original staged operation")
                self.need(record["state"] == "committed" and record["seq"] == new["db_seq"],
                          "ATOMIC_RESULT", "data accepted without the original committed result")
                self.need(set(data["deps"]) == {old["data_root"]}, "CLOSURE", "data difference omits its predecessor")
                result = self.objects[record["result_root"]]
                self.need(result["result"] == attempt["staged"]["result"], "ORIGINAL_RESULT", "original result payload was changed")
                allowed |= {"db_seq", "data_root"}
                self.accepted[key] = copy.deepcopy(record)
            else:
                self.need(record["state"] == "cancelled", "CANCEL", "cancellation does not publish a terminal fence")
        elif kind == "close":
            self.need(intent["actor"] == "coordinator" and params["expected_epoch"] == old["request_epoch"],
                      "RETENTION", "window close has no original coordinator epoch")
            current = [r for r in before.values() if r["epoch"] == old["request_epoch"]]
            self.need(len(current) == old["retention"]["window_limit"], "RETENTION", "empty or partial window closed")
            self.need(new["request_epoch"] == old["request_epoch"] + 1, "RETENTION", "epoch skipped or reused")
            keep = old["retention"]["keep_closed"]
            floor = max(0, new["request_epoch"] - keep - 1)
            self.need(new["retired_floor"] == floor and new["closed_epochs"] == list(range(floor + 1, new["request_epoch"])),
                      "RETENTION", "minimum closed-epoch retention violated")
            self.need(after == {k: r for k, r in before.items() if r["epoch"] > floor},
                      "RETENTION", "close dropped a retained result or invented a result")
            allowed |= {"request_root", "request_epoch", "retired_floor", "closed_epochs"}
        else:
            self.need("admin" in old["grants"].get(intent["actor"], []) and intent["auth_epoch"] == old["auth_epoch"],
                      "AUTH", "control transition lacks current administrator authorization")
            if kind == "takeover":
                self.need(old["lifecycle"] == "ready", "LIFECYCLE", "takeover during maintenance")
                self.need(new["owner"] == {"instance": params["new_owner"], "epoch": old["owner"]["epoch"] + 1, "state": "recovering"},
                          "OWNER", "takeover did not establish a new recovering writer")
                allowed.add("owner")
            elif kind == "activate":
                proof = params["recovery"]
                self.need(old["lifecycle"] == "ready", "LIFECYCLE", "activation during maintenance")
                self.need(proof.get("id") in self.proofs and self.proofs[proof["id"]] == proof,
                          "RECOVERY", "activation used an invented or lost local recovery proof")
                self.need(all(proof[k] == old[k] for k in ("scope", "db_seq", "data_root", "owner"))
                          and proof["value"] == old_data["value"], "RECOVERY", "recovery proof describes a different selected state")
                self.need(old["owner"]["state"] == "recovering" and new["owner"] == {**old["owner"], "state": "active"},
                          "OWNER", "activation did not preserve the recovering owner")
                allowed.add("owner")
            elif kind == "auth":
                self.need(new["auth_epoch"] == old["auth_epoch"] + 1 and new["grants"] == params["grants"],
                          "AUTH", "authorization update not atomically fenced")
                allowed |= {"auth_epoch", "grants"}
            elif kind in {"maintenance", "delete"}:
                target = "deleted" if kind == "delete" else ("maintenance" if params["enabled"] else "ready")
                self.need(new["lifecycle"] == target, "LIFECYCLE", "wrong lifecycle successor")
                allowed.add("lifecycle")
            else:
                self.need(False, "SCHEMA", f"unknown transition kind {kind}")
        changed = {key for key in set(old) | set(new) if old.get(key) != new.get(key)}
        self.need(changed <= allowed, "ISOLATION", f"transition changed unrelated fields {sorted(changed - allowed)}")
        if kind not in {"commit", "cancel", "close"}:
            self.need(before == after, "RESULTS", "control transition lost retained original results")
        self.transitions.add(new["transition_id"])


def _audit_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    oracle = HistoryOracle()
    o = oracle
    o.need(isinstance(events, list) and bool(events), "SCHEMA", "empty history")
    for number, event in enumerate(events, 1):
        o.step = number
        try:
            o.need(event["seq"] == number, "SCHEMA", "missing or duplicated event ordinal")
            kind = event["type"]
            o.counts[kind] += 1
            if kind == "object_put":
                key, body = event["key"], event["body"]
                o.need(key == f"{body['scope']}/objects/{_digest(body)}", "INTEGRITY", "PUT key does not identify its bytes")
                if event["applied"]:
                    o.need(key not in o.objects, "IMMUTABLE", "immutable object was overwritten")
                    o.objects[key] = copy.deepcopy(body)
                else:
                    o.need(key in o.objects, "STORE", "conditional create failed without an existing object")
                if o.config:
                    o.need(len(o.objects) + 1 <= o.config["max_objects"], "CAPACITY", "total object budget bypassed")
            elif kind == "genesis":
                o.need(o.head is None, "ORDER", "second authority genesis")
                o.head, o.etag, o.config = copy.deepcopy(event["head"]), event["etag"], event["config"]
                o.need(o.head["revision"] == 0 and o.head["transition_id"] == "genesis", "ORDER", "unaccounted prehistory")
                o.need(o.head["retention"] == {"window_limit": o.config["window_limit"], "keep_closed": 2}
                       and o.config["keep_closed"] == 2, "RETENTION", "genesis does not bind the retention contract")
                o.need(o.head["db_seq"] == 0 and o.head["request_epoch"] == 1
                       and o.head["retired_floor"] == 0 and o.head["closed_epochs"] == [], "ORDER", "invalid initial authority")
                data, records = o.roots(o.head)
                o.need(data["value"] == 0 and not records, "DATA", "genesis contains unaccounted effects")
                o.used_etags.add(o.etag)
                o.transitions.add("genesis")
                o.need(len(o.objects) + 1 <= o.config["max_objects"], "CAPACITY", "genesis exceeds object budget")
            elif kind == "head_read":
                o.need(event["head"] == o.head and event["etag"] == o.etag, "FRESH_READ", "fresh exact-key GET returned a stale or mixed HEAD/ETag")
                o.need(event["actor"] == event["intent"]["actor"], "AUTH", "HEAD observation changed its original caller")
                o.need(event["read_id"] not in o.reads, "IDENTITY", "HEAD read identity reused")
                o.reads[event["read_id"]] = copy.deepcopy(event)
            elif kind == "prepared":
                read = o.reads[event["read_id"]]
                intent = event["intent"]
                previous = o.attempts.get(event["op_id"])
                o.need(previous is None or not previous.get("live", True), "IDENTITY", "active attempt handle replaced")
                o.need(event["op_id"] not in o.pending, "RETRY", "in-flight candidate replaced")
                original = read["intent"]
                o.need(original["op_id"] == event["op_id"] and original["kind"] == event["kind"]
                       and all(intent.get(k) == value for k, value in original.items()
                               if k not in {"action", "op_id", "kind"}), "IDENTITY", "prepare changed caller identity after HEAD selection")
                if intent["control"] is not None:
                    control = intent["control"]
                    identity = json.dumps([control["scope"], control["expected_revision"], control["control_id"]])
                    o.need(identity not in o.controls or o.controls[identity] == control, "CONTROL_REBASE", "original control parameters replaced")
                    o.controls[identity] = copy.deepcopy(control)
                    o.need(control["expected_revision"] == read["head"]["revision"], "CONTROL_REBASE", "old control intent admitted against a fresh revision")
                o.attempts[event["op_id"]] = {**copy.deepcopy(event), "snapshot": read, "live": True,
                                             "uncertain": False, "response": None, "materialized": None}
            elif kind == "staged":
                attempt = o.attempts[event["op_id"]]
                o.need(attempt.get("live") and "staged" not in attempt and attempt["outcome"] != "resolved",
                       "RETRY", "staged operation was re-executed or had a known terminal result")
                attempt["staged"] = copy.deepcopy(event)
            elif kind == "closure":
                attempt = o.attempts[event["op_id"]]
                candidate = attempt["staged"]["candidate"]
                roots = [candidate["data_root"], candidate["request_root"]]
                o.need(event["roots"] == roots, "CLOSURE", "verified another candidate's roots")
                o.roots(candidate)
                seen, remaining = set(), roots[:]
                while remaining:
                    key = remaining.pop()
                    if key not in seen:
                        seen.add(key)
                        remaining.extend(o.objects[key]["deps"])
                o.need(event["dependencies"] == sorted(seen), "CLOSURE", "incomplete recovery closure verification")
                attempt["verified"] = True
            elif kind == "cas_sent":
                attempt = o.attempts[event["op_id"]]
                o.need(attempt.get("live") and attempt.get("verified") and not attempt.get("crashed"),
                       "PUBLICATION", "CAS sent without verified staged dependencies")
                o.need(event["op_id"] not in o.pending, "RETRY", "overlapping transport retry")
                o.need(event["read_id"] == attempt["read_id"] and event["expected_etag"] == attempt["snapshot"]["etag"]
                       and event["candidate"] == attempt["staged"]["candidate"] and event["kind"] == attempt["kind"]
                       and event["intent"] == attempt["intent"], "REBASE", "staged candidate, base or intent rebound before CAS")
                o.roots(event["candidate"])
                message = {key: copy.deepcopy(event[key]) for key in
                           ("read_id", "expected_etag", "candidate", "kind", "intent")}
                o.need("first_cas" not in attempt or attempt["first_cas"] == message, "RETRY", "transport retry changed the original conditional request")
                attempt["first_cas"] = message
                o.pending[event["op_id"]] = {"message": message, "attempt": attempt, "effect": None}
            elif kind == "cas_effect":
                pending = o.pending[event["op_id"]]
                o.need(pending["effect"] is None, "STORE", "same in-flight CAS took effect twice")
                if event["applied"]:
                    message, attempt = pending["message"], pending["attempt"]
                    o.need(message["expected_etag"] == o.etag, "CAS", "two successors won the same predecessor ETag")
                    o.need(attempt["snapshot"]["head"] == o.head, "REBASE", "ETag did not bind the exact selected predecessor")
                    o.need(event["head"] == message["candidate"], "PUBLICATION", "store applied bytes other than the original candidate")
                    o.need(event["etag"] not in o.used_etags, "ABA", "published HEAD reuses an earlier opaque ETag")
                    o.transition(o.head, event["head"], attempt)
                    o.head, o.etag = copy.deepcopy(event["head"]), event["etag"]
                    o.used_etags.add(o.etag)
                    o.counts["publications"] += 1
                else:
                    o.need(event["head"] == o.head and event["etag"] == o.etag, "CAS", "failed CAS changed the authority")
                pending["effect"] = bool(event["applied"])
            elif kind == "cas_response":
                pending = o.pending.pop(event["op_id"])
                attempt, effect, outcome = pending["attempt"], pending["effect"], event["outcome"]
                o.need(effect is not None, "PUBLICATION", "response precedes the CAS effect decision")
                o.need(outcome in {"applied", "conflict", "unknown"}, "SCHEMA", "invalid CAS response")
                o.need(event["delivered"] or outcome == "unknown", "UNKNOWN", "lost CAS response interpreted as definite")
                if outcome == "applied":
                    o.need(effect is True and event["delivered"] and not attempt.get("crashed"), "ACK", "CAS success is not observed")
                elif outcome == "conflict":
                    o.need(effect is False and not attempt["uncertain"], "UNKNOWN", "later 412 erased an earlier ambiguous attempt")
                attempt["response"] = outcome
                attempt["uncertain"] |= outcome == "unknown"
            elif kind == "publish":
                attempt = o.attempts[event["op_id"]]
                o.need(attempt["kind"] == "commit" and attempt["response"] == "applied" and not attempt.get("crashed"),
                       "EARLY_VISIBLE", "local effect exposed before observed authority publication")
                if event["ok"]:
                    o.roots(attempt["staged"]["candidate"])
                attempt["materialized"] = bool(event["ok"])
            elif kind == "reply":
                attempt = o.attempts[event["op_id"]]
                o.need(attempt.get("live") and not attempt.get("crashed"), "ACK", "dead caller replied")
                outcome = event["outcome"]
                if attempt["outcome"] == "resolved":
                    o.authorize(attempt["snapshot"]["head"], attempt["intent"], {"read", "write"})
                    result = o.lookup(attempt["snapshot"]["head"], attempt["intent"]["request"], attempt["intent"]["actor"])
                    o.need(result["state"] in {"committed", "cancelled"} and outcome == result["state"]
                           and event["result"] == result and attempt["result"] == result, "ACK", "known-result reply has no original terminal proof")
                elif attempt["response"] in {"unknown", "conflict"}:
                    o.need(outcome == attempt["response"] and event["result"] is None, "UNKNOWN", "ambiguous or conflicting publication invented a terminal result")
                else:
                    o.need(attempt["response"] == "applied", "ACK", "reply precedes observed authority publication")
                    if attempt["kind"] == "commit":
                        result = o.lookup(attempt["staged"]["candidate"], attempt["intent"]["request"], attempt["intent"]["actor"])
                        expected = "committed" if attempt["materialized"] else "committed_unavailable"
                        o.need(attempt["materialized"] is not None and event["materialized"] == attempt["materialized"]
                               and outcome == expected and event["result"] == result, "EARLY_VISIBLE", "SQL success lacks local publication or its original result")
                    else:
                        expected = "cancelled" if attempt["kind"] == "cancel" else "applied"
                        o.need(outcome == expected and event["result"] is None, "ACK", "control/cancel reply has no corresponding publication")
                attempt["last_reply"] = copy.deepcopy(event)
                attempt["uncertain"] |= not event["delivered"]
                if event["delivered"] and outcome == "committed":
                    o.counts["sql_success_replies"] += 1
            elif kind == "lookup":
                read = o.reads[event["read_id"]]
                o.need(read["intent"].get("action") == "lookup" and read["intent"].get("request") == event["request"], "FRESH_READ", "lookup reused a different operation's snapshot")
                o.need(event["actor"] == read["intent"]["actor"] and event["auth_epoch"] == read["intent"]["auth_epoch"],
                       "AUTH", "lookup changed the caller or authorization after fresh admission")
                o.authorize(read["head"], {"actor": event["actor"], "auth_epoch": event["auth_epoch"]}, {"read"})
                expected = o.lookup(read["head"], event["request"], event["actor"])
                o.need(event["outcome"] == expected, "LOOKUP", "absence, retirement, or original result misclassified")
            elif kind == "read_started":
                read = o.reads[event["read_id"]]
                o.need(read["intent"].get("action") == "read" and event["id"] not in o.readers
                       and event["actor"] == read["intent"]["actor"], "FRESH_READ", "read has no fresh admission")
                o.authorize(read["head"], read["intent"], {"read"})
                o.roots(read["head"])
                o.readers[event["id"]] = copy.deepcopy(event)
            elif kind == "read_result":
                admitted = o.readers.pop(event["id"])
                read = o.reads[admitted["read_id"]]
                o.need(event["read_id"] == admitted["read_id"] and event["head"] == read["head"]
                       and event["actor"] == read["intent"]["actor"] and event["auth_epoch"] == read["intent"]["auth_epoch"], "FRESH_READ", "reader mixed snapshots or caller authorization")
                data, _ = o.roots(read["head"])
                o.need(event["value"] == data["value"], "READ_VALUE", "read returned staged or stale local data")
            elif kind == "recovered":
                read, proof = o.reads[event["read_id"]], event["proof"]
                o.need(read["intent"].get("action") == "recover", "RECOVERY", "recovery reused a different admission")
                o.authorize(read["head"], read["intent"], {"admin"})
                data, _ = o.roots(read["head"])
                o.need(read["head"]["lifecycle"] == "ready" and read["head"]["owner"]["state"] == "recovering",
                       "RECOVERY", "recovery served outside a recovering Ready owner")
                o.need(all(proof[k] == read["head"][k] for k in ("scope", "owner", "db_seq", "data_root"))
                       and proof["value"] == data["value"], "RECOVERY", "recovery did not materialize the selected complete closure")
                o.proofs[proof["id"]] = copy.deepcopy(proof)
            elif kind == "control_lookup":
                read, control = o.reads[event["read_id"]], event["control"]
                head = read["head"]
                o.need(read["intent"].get("action") == "lookup_control" and event["actor"] == read["intent"]["actor"],
                       "AUTH", "control lookup changed the caller after fresh admission")
                o.need(read["intent"].get("control") == control, "CONTROL_LOOKUP", "control query changed its original intent after HEAD selection")
                o.need(control["scope"] == head["scope"] and control["principal"] == event["actor"], "CONTROL", "control receipt disclosed to another principal")
                if event["actor"] != "coordinator":
                    o.authorize(head, read["intent"], {"admin"})
                else:
                    o.need(control["kind"] == "close", "AUTH", "coordinator queried a non-close control intent")
                o.need(head["lifecycle"] != "deleted", "LIFECYCLE", "deleted authority served a control lookup")
                if head["revision"] == control["expected_revision"] + 1 and head["transition_id"] == f"{head['revision']}:{control['control_id']}":
                    expected = "applied" if head["last_control_digest"] == _digest(control) else "conflict"
                else:
                    expected = "superseded" if head["revision"] > control["expected_revision"] else "unknown"
                o.need(event["outcome"] == expected, "CONTROL_LOOKUP", "bounded control lookup invented historical certainty")
            elif kind == "crash":
                o.attempts[event["op_id"]]["crashed"] = True
            elif kind == "forgotten":
                attempt = o.attempts[event["op_id"]]
                reply = attempt.get("last_reply", {})
                o.need(reply.get("delivered") and reply.get("outcome") != "unknown"
                       and event["op_id"] not in o.pending, "UNKNOWN", "unresolved identity forgotten")
                attempt["live"] = False
            elif kind == "restart":
                o.need(event["head"] == o.head and set(event["pending"]) == set(o.pending), "RESTART", "local state loss changed authority or erased in-flight CAS")
                for attempt in o.attempts.values():
                    attempt["live"] = False
                    attempt["crashed"] = True
                o.readers.clear()
                o.proofs.clear()
            elif kind == "corrupt":
                o.need(event["key"] in o.objects, "SCHEMA", "unsupported fault target")
                o.objects[event["key"]] = copy.deepcopy(event["body"])
            elif kind == "rejected":
                o.need(isinstance(event["code"], str) and bool(event["code"]), "SCHEMA", "rejection lost its reason")
            else:
                o.need(False, "SCHEMA", f"unsupported event type {kind}")
        except OracleError:
            raise
        except (KeyError, TypeError, ValueError, AttributeError) as error:
            raise OracleError("SCHEMA", f"incomplete or invalid raw event: {error}", number) from error
    o.need(o.head is not None, "SCHEMA", "history has no genesis")
    return {"passed": True, "events": len(events), "publications": o.counts["publications"],
            "accepted_writes": len(o.accepted), "sql_success_replies": o.counts["sql_success_replies"],
            "lookups": o.counts["lookup"], "rejected_actions": o.counts["rejected"],
            "pending_cas": len(o.pending), "final_revision": o.head["revision"],
            "final_request_epoch": o.head["request_epoch"], "production_slo_passed": False}


def audit(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Validate raw JSON events without calling the protocol implementation."""
    return _audit_events(events)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("history", type=Path)
    args = parser.parse_args()
    raw = args.history.read_text()
    document = json.loads(raw) if raw.lstrip().startswith("[") else None
    events = document if document is not None else [json.loads(line) for line in raw.splitlines() if line.strip()]
    print(json.dumps(audit(events), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
