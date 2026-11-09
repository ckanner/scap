"""Independent acceptance rules. Never import the producer or its derived graph."""

import copy
import hashlib
import json


def require(condition, message):
    if not condition:
        raise ValueError(message)


def encoded(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=True).encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def etag(body):
    return '"head:' + digest(body) + '"'


class Rules:
    def __init__(self, inputs, profile):
        self.inputs, self.profile = inputs, profile
        self.scope = inputs["scope"]
        s = self.scope
        self.head_key = f"scap-object/v1/{s['deployment']}/{s['tenant']}/{s['database']}/head"
        self.storage_prefix = (f"scap-object/v1/{s['deployment']}/{s['tenant']}/{s['database']}"
                               f"/inc/{s['incarnation']}/gen/{s['generation']}/storage/")
        self.frames, self.names = {}, {}
        for name, item in inputs["frames"].items():
            raw = bytes.fromhex(item["raw"])
            actual = hashlib.sha256(raw).hexdigest()
            require(actual == item["hash"], "input raw frame hash mismatch")
            require(raw.startswith(b"MODELFRAME1\n"), "input frame marker mismatch")
            body = json.loads(raw[len(b"MODELFRAME1\n"):])
            require(body["scope"] == self.scope and body["kind"] in ("data", "result"), "input frame Scope/kind mismatch")
            require(body["references"] == item["references"], "input declared edges disagree with original raw bytes")
            require(body["kind"] != "result" or body["references"] == [], "receipt metadata must not become a data reference")
            self.frames[actual] = {"body": body, "raw": item["raw"]}
            self.names[name] = actual
        require(len(self.frames) <= inputs["bounds"]["frames"], "input frame bound exceeded")
        for value in self.frames.values():
            require(len(value["body"]["references"]) <= inputs["bounds"]["references_per_frame"], "input reference bound exceeded")
            require(all(ref in self.frames for ref in value["body"]["references"]), "input reference escaped fixed objects")

    def key(self, generation, value):
        return f"{self.storage_prefix}{generation}/objects/{value}"

    def closure(self, roots):
        found, todo = set(), [(root, 1) for root in roots]
        while todo:
            value, depth = todo.pop()
            require(value in self.frames, "closure references an undeclared frame")
            require(depth <= self.inputs["bounds"]["graph_depth"], "closure depth exceeds frozen bound")
            if value not in found:
                found.add(value)
                todo.extend((ref, depth + 1) for ref in self.frames[value]["body"]["references"])
        return found

    @staticmethod
    def roots(head):
        return [head["data"], *head["results"]]

    @staticmethod
    def retired(head, generation):
        protected = {head["A"]}
        if head["plan"] is not None:
            protected.add(head["plan"]["identity"]["target"])
        if head["hold"] is not None:
            protected.add(head["hold"]["generation"])
        return 0 < generation <= head["M"] and generation not in protected

    def validate_head(self, head):
        require(head["scope"] == self.scope, "authority Scope mismatch")
        require(type(head["serial"]) is int and type(head["revision"]) is int
                and 1 <= head["revision"] <= head["serial"] < 2**64, "authority serial/revision invalid")
        require(1 <= head["A"] <= head["M"] <= self.inputs["bounds"]["generations"], "authority generation invalid")
        require(head["life"] in ("ready", "provisioning", "deleted"), "authority lifecycle invalid")
        require(head["plan"] is None or head["checkpoint"] is None, "copy and sweep authority overlap")
        self.closure(self.roots(head))
        require(self.frames[head["data"]]["body"]["kind"] == "data"
                and all(self.frames[value]["body"]["kind"] == "result" for value in head["results"]),
                "HEAD root roles disagree with raw frame kinds")
        if head["plan"] is not None:
            identity = head["plan"]["identity"]
            require(identity["scope"] == self.scope and identity["source"] == head["A"]
                    and head["A"] < identity["target"] == head["M"], "copy plan physical identity invalid")
            require(identity["roots"] == self.roots(head) and head["plan"]["phase"] in ("copying", "sealed")
                    and not head["active"], "copy plan roots/phase invalid")
        if head["checkpoint"] is not None:
            cp = head["checkpoint"]
            require(self.retired(head, cp["generation"]), "checkpoint protects a live generation")
            require(1 <= len(cp["entries"]) <= self.inputs["bounds"]["candidates"], "checkpoint candidate bound invalid")
            require(len({entry["key"] for entry in cp["entries"]}) == len(cp["entries"]), "checkpoint duplicates exact key")
            for entry in cp["entries"]:
                require(entry["generation"] == cp["generation"] and entry["key"] == self.key(cp["generation"], entry["hash"]),
                        "checkpoint key differs from captured generation/Scope")
                require(entry["disposition"] in ("pending", "applied", "observed_absent", "condition_mismatch"),
                        "checkpoint disposition invalid")
        if head["hold"] is not None:
            require(1 <= head["hold"]["generation"] <= head["M"], "retained hold generation invalid")
            self.closure(head["hold"]["roots"])

    def observed(self, state, token_id, kind):
        token = state["tokens"].get(token_id)
        require(token is not None and token["kind"] == kind and token["stage"] == "applied"
                and token["observed"] == "known", "evidence is not an original known response")
        return token

    def authority(self, state, token_id):
        token = self.observed(state, token_id, "head_get")
        require(token["request"]["key"] == self.head_key and token["response"]["outcome"] == "FOUND", "authority lacks exact original HEAD GET")
        view = token["response"]["snapshot"]
        self.validate_head(view["body"])
        require(view["etag"] == etag(view["body"]), "HEAD body and ETag are not one exact observation")
        return view

    def allowed_admin(self, state, owner, token_id, ready=False):
        view = self.authority(state, token_id)
        principal = str(self.profile["actors"][owner]["principal"])
        require(view["body"]["acl"].get(principal, {}).get("admin", False), "fresh maintenance skipped current admin permission")
        require(not ready or view["body"]["life"] == "ready", "fresh maintenance skipped Ready lifecycle")
        return view

    def context(self, state, owner, context):
        require(context is not None and context["scope"] == self.scope, "operation context Scope missing")
        actor = self.profile["actors"][owner]
        require(context["principal"] == actor["principal"], "operation context principal rebound")
        if context["mode"] == "bootstrap":
            require(context["generation"] == 1 and context["base"] is None and context["head_token"] is None
                    and context["roots"] == self.inputs["initial_roots"] and actor["principal"] == self.inputs["creator"],
                    "invalid explicit bootstrap context")
            return
        view = self.authority(state, context["head_token"])
        require(view == context["base"], "operation Snapshot rebound")
        head = view["body"]
        mode = context["mode"]
        require(mode in ("read", "write", "complete", "abort"), "unknown operation mode")
        if mode in ("complete", "abort"):
            require(head["life"] == "provisioning" and head["creation"] == self.inputs["creation"]
                    and actor["principal"] == self.inputs["creator"], "Provisioning exact identity missing")
        else:
            right = head["acl"].get(str(actor["principal"]), {})
            require(head["life"] == "ready" and right.get("read", False), "ordinary admission bypassed original READ/lifecycle")
            if mode == "write":
                require(right.get("write", False) and head["active"] and head["owner"] == actor["worker"]
                        and head["plan"] is None, "write admission bypassed original owner/fence")
        roots = [head["data"]] if mode == "read" else self.roots(head)
        ordinary = context["generation"] == head["A"] and context["roots"] == roots
        hold = head["hold"]
        retained = mode == "read" and hold is not None and context["generation"] == hold["generation"] and context["roots"] == hold["roots"]
        require(ordinary or retained, "operation generation/roots were rebound")

    def immutable_evidence(self, state, token_id, generation, expected, purpose=None, protection=None):
        token = self.observed(state, token_id, "object_get")
        request, response = token["request"], token["response"]
        require(request["generation"] == generation and request["hash"] == expected
                and request["key"] == self.key(generation, expected), "immutable evidence reads a different physical object")
        require(response["outcome"] == "FOUND" and response["raw"] == self.frames[expected]["raw"]
                and hashlib.sha256(bytes.fromhex(response["raw"])).hexdigest() == expected, "immutable evidence lacks complete original hash-valid bytes")
        require(purpose is None or request["purpose"] == purpose, "immutable evidence purpose rebound")
        require(protection is None or request["protection"] == protection, "immutable evidence protection rebound")
        return response

    def checkpoint(self, state, owner, proof, ready=False):
        require(proof is not None, "DELETE lacks a fresh exact own batch observation")
        view = self.allowed_admin(state, owner, proof["head_token"], ready=ready)
        require(view["body"]["checkpoint"] == proof["body"], "checkpoint capability fabricated from RAM/PUT receipt")
        require(self.retired(view["body"], proof["body"]["generation"]), "DELETE checkpoint generation is still protected")
        return proof["body"]

    def disposition(self, state, entry, kind, token_id):
        token = state["tokens"].get(token_id)
        require(token is not None and token["observed"] == "known" and token["stage"] == "applied"
                and token["request"]["key"] == entry["key"], "disposition lacks exact known original key evidence")
        outcome = token["response"]["outcome"]
        if token["kind"] == "candidate_get":
            require(kind == "observed_absent" and outcome == "NO_SUCH_KEY", "NoSuchBucket/UNKNOWN is not exact-key absence")
        else:
            require(token["kind"] == "delete" and token["request"]["etag"] == entry["etag"], "disposition replaced original DELETE condition")
            expected = {"APPLIED": "applied", "NO_SUCH_KEY": "observed_absent", "CONFLICT": "condition_mismatch"}.get(outcome)
            require(expected is not None and kind == expected, "disposition rewrote caller outcome knowledge")

    def head_request(self, state, owner, request):
        require(request["key"] == self.head_key, "HEAD CAS escaped permanent exact key")
        body, base, kind = request["body"], request["base"], request["transition"]
        self.validate_head(body)
        evidence = request["evidence"]
        if base is None:
            require(kind in ("create", "absent_abort") and request["base_token"] is None, "replacement lost original ETag")
            context = evidence["context"]
            self.context(state, owner, context)
            require(context["mode"] == "bootstrap" and body["serial"] == body["revision"] == 1, "initial HEAD is not bootstrap serial1")
            expected = copy.deepcopy(self.inputs["initial_head"])
            expected["life"] = "deleted" if kind == "absent_abort" else body["life"]
            expected["active"] = expected["life"] == "ready"
            require(body == expected, "initial HEAD changed bootstrap roots/identity")
            for value in self.closure(context["roots"]):
                self.immutable_evidence(state, evidence["readbacks"].get(value), 1, value, "readback", context)
            return
        observed = self.authority(state, request["base_token"])
        require(base == observed, "CAS changed its original exact body/ETag")
        old = base["body"]
        expected = copy.deepcopy(old)
        expected["serial"] += 1
        if kind in ("write", "complete", "abort", "acl", "owner", "delete"):
            expected["revision"] += 1
        require(body["serial"] == expected["serial"] and body["revision"] == expected["revision"], "serial/business revision successor invalid")
        if kind in ("write", "complete", "abort"):
            context = evidence["context"]
            self.context(state, owner, context)
            require(context["base"] == base and context["head_token"] == request["base_token"] and context["mode"] == kind,
                    "business publication rebased its original admission")
            if kind == "write":
                require(state["actors"][owner]["native"] == "executed", "SQL replay or missing native execution")
                require(len(body["results"]) == len(old["results"]) + 1 and body["results"][:-1] == old["results"], "write discarded retained result")
                required = self.closure([body["data"], body["results"][-1]])
                for value in required:
                    self.immutable_evidence(state, evidence["readbacks"].get(value), context["generation"], value, "readback", context)
                expected.update(data=body["data"], results=body["results"], sequence=old["sequence"] + 1)
            else:
                for value in self.closure(context["roots"]):
                    item = evidence["frames"].get(value)
                    require(item is not None, "Provisioning published incomplete immutable verification")
                    self.immutable_evidence(state, item["token"], context["generation"], value, "read", context)
                expected.update(life="ready" if kind == "complete" else "deleted", active=kind == "complete")
        else:
            self.allowed_admin(state, owner, request["base_token"])
            if kind == "freeze":
                require(old["life"] == "ready" and old["plan"] is None and old["checkpoint"] is None, "new copy skipped current admission")
                identity = body["plan"]["identity"]
                expected.update(M=old["M"] + 1, active=False, plan={"phase": "copying", "identity": {
                    "scope": self.scope, "source": old["A"], "target": old["M"] + 1,
                    "roots": self.roots(old), "started_serial": expected["serial"], "nonce": identity["nonce"]}})
            elif kind in ("seal", "promote", "abort_plan"):
                require(old["life"] == "ready" and old["plan"] is not None and evidence["plan"] == old["plan"]["identity"], "copy publication uses obsolete plan")
                identity = old["plan"]["identity"]
                if kind == "seal":
                    require(old["plan"]["phase"] == "copying", "seal is not Copying")
                    for value in self.closure(identity["roots"]):
                        item = evidence["verified"].get(value)
                        require(item is not None, "sealed new plan from incomplete/stale target evidence")
                        self.immutable_evidence(state, item["token"], identity["target"], value, "copy_verify", identity)
                    expected["plan"]["phase"] = "sealed"
                elif kind == "promote":
                    require(old["plan"]["phase"] == "sealed", "promoted unsealed plan")
                    expected.update(A=identity["target"], active=True, plan=None)
                else:
                    expected["plan"] = None
            elif kind == "acl":
                require(old["life"] == "ready" and set(old["acl"]) == set(body["acl"]), "ACL transition lifecycle/principal set invalid")
                expected["acl"] = body["acl"]
            elif kind == "owner":
                require(old["life"] == "ready" and old["plan"] is None, "owner change skipped copy fence")
                expected.update(owner=body["owner"], owner_epoch=old["owner_epoch"] + 1, active=False)
            elif kind == "delete":
                require(old["life"] == "ready", "Delete skipped original Ready lifecycle")
                expected.update(life="deleted", active=False, plan=None)
            elif kind == "hold_add":
                require(old["life"] == "ready" and old["hold"] is None, "new retained hold skipped admission")
                expected["hold"] = {"id": body["hold"]["id"], "generation": old["A"], "roots": self.roots(old)}
            elif kind == "hold_release":
                require(old["hold"] is not None, "retained hold release has no original hold")
                expected["hold"] = None
            elif kind == "fence":
                pass
            elif kind == "checkpoint":
                cp = body["checkpoint"]
                require(old["life"] == "ready" and old["plan"] is None and old["checkpoint"] is None
                        and self.retired(old, cp["generation"]) and cp["captured_serial"] == old["serial"], "new checkpoint skipped current authority")
                for entry in cp["entries"]:
                    token = self.observed(state, entry["get"], "candidate_get")
                    require(token["request"]["key"] == entry["key"] and token["request"]["generation"] == cp["generation"]
                            and token["response"]["outcome"] == "FOUND" and token["response"]["etag"] == entry["etag"], "checkpoint replaced exact candidate ETag without observation")
                    require(entry["disposition"] == "pending" and entry["evidence"] is None, "new batch invented candidate disposition")
                expected["checkpoint"] = cp
            elif kind in ("dispositions", "clear"):
                cp = old["checkpoint"]
                require(cp is not None and self.retired(old, cp["generation"]), "checkpoint close lost original retired batch")
                if kind == "clear":
                    require(cp == evidence["checkpoint"] and all(entry["disposition"] != "pending" for entry in cp["entries"]), "cleared an unsettled/different batch")
                    for entry in cp["entries"]:
                        self.disposition(state, entry, entry["disposition"], entry["evidence"])
                    expected["checkpoint"] = None
                else:
                    for index, value in evidence["dispositions"].items():
                        entry = expected["checkpoint"]["entries"][int(index)]
                        require(entry["disposition"] == "pending", "disposition overwrote an already settled candidate")
                        self.disposition(state, entry, value["kind"], value["token"])
                        entry.update(disposition=value["kind"], evidence=value["token"])
            else:
                raise ValueError("unrecognized HEAD transition " + kind)
        require(body == expected, "HEAD transition changed unrelated authority/roots or reused serial")
        for generation in range(1, old["M"] + 1):
            require(not self.retired(old, generation) or self.retired(body, generation), "permanently retired generation was revived or re-held")

    def dispatch(self, state, owner, token):
        request, kind, local = token["request"], token["kind"], state["actors"][owner]
        require(not local["local_stop"], "new request dispatched after local gate closure")
        if kind == "head_get":
            require(request["key"] == self.head_key, "exact HEAD GET escaped Scope")
            if request["purpose"] in state["tokens"]:
                require(local["failure"] is not None and request["purpose"] == local["failure"]["token"],
                        "retirement investigation preceded its actual original failure")
        elif kind == "head_cas":
            require(request == local["candidate"], "sent HEAD differs from immutable prepared request")
            self.head_request(state, owner, request)
        elif kind == "candidate_get":
            view = self.allowed_admin(state, owner, request["authority"], ready=True)
            require(self.retired(view["body"], request["generation"]), "candidate GET admitted active/held/target generation")
            require(request["key"] == self.key(request["generation"], request["hash"]), "candidate GET changed physical key")
        elif kind == "delete":
            cp = self.checkpoint(state, owner, request["checkpoint"], ready=True)
            require(any(entry["key"] == request["key"] and entry["etag"] == request["etag"]
                        and entry["generation"] == request["generation"] and entry["hash"] == request["hash"]
                        and entry["disposition"] == "pending" for entry in cp["entries"]), "DELETE condition was not durably observed in its original batch")
        elif kind in ("object_get", "object_put"):
            require(request["hash"] in self.frames and request["key"] == self.key(request["generation"], request["hash"]), "immutable request changed full Scope/generation/hash key")
            protection = request["protection"]
            if "mode" in protection:
                self.context(state, owner, protection)
                require(protection == local["context"] and request["generation"] == protection["generation"], "immutable request rebound operation context")
                if kind == "object_get" and request["purpose"] != "readback":
                    require(request["hash"] in self.closure(protection["roots"]), "read followed identity field instead of actual graph edge")
            else:
                require(local["plan"] == protection and protection["scope"] == self.scope, "copy request uses stale/different captured plan")
                require(request["hash"] in self.closure(protection["roots"]), "copy request escaped raw closure")
                generation = protection["source"] if request.get("purpose") == "copy_source" else protection["target"]
                require(request["generation"] == generation, "copy request changed source/target generation")
                if kind == "object_put":
                    source = self.immutable_evidence(state, request["source"], protection["source"], request["hash"], "copy_source", protection)
                    require(source["raw"] == request["raw"], "copy reencoded or truncated original raw frame")
            if kind == "object_put":
                require(request["condition"] == "absent" and request["raw"] == self.frames[request["hash"]]["raw"], "immutable PUT lacks original bytes/Absent condition")
        else:
            raise ValueError("unrecognized network request kind " + kind)

    def state(self, state):
        if state["head"] is not None:
            self.validate_head(state["head"])
        require(len(state["tokens"]) <= self.inputs["bounds"]["tokens"], "network token bound exceeded")
        for owner, local in state["actors"].items():
            if local["context"] is not None:
                self.context(state, owner, local["context"])
            if local["checkpoint"] is not None:
                cp = self.checkpoint(state, owner, local["checkpoint"])
                for index, value in local["dispositions"].items():
                    self.disposition(state, cp["entries"][int(index)], value["kind"], value["token"])
            if local["materialized"] is not None:
                result = local["materialized"]
                context = result["context"]
                self.context(state, owner, context)
                require(context == local["context"] and set(result["frames"]) == self.closure(context["roots"]), "materialized result lacks exact complete original closure")
                for value, item in result["frames"].items():
                    response = self.immutable_evidence(state, item["token"], context["generation"], value, "read", context)
                    require(item["raw"] == response["raw"], "materialized result copied different bytes")
            for destination, purpose in (("sources", "copy_source"), ("verified", "copy_verify")):
                for value, item in local[destination].items():
                    require(local["plan"] is not None, "copy proof exists without captured plan")
                    generation = local["plan"]["source" if destination == "sources" else "target"]
                    self.immutable_evidence(state, item["token"], generation, value, purpose, local["plan"])
            failure = local["failure"]
            if failure is not None:
                token = self.observed(state, failure["token"], "object_get")
                request, response = token["request"], token["response"]
                require(failure["scope"] == self.scope and failure["generation"] == request["generation"]
                        and failure["hash"] == request["hash"] and failure["protection"] == request["protection"], "failure capsule changed original context")
                require(response["outcome"] != "FOUND" or response["raw"] != self.frames[request["hash"]]["raw"], "valid read invented a failure capsule")
                require(failure["reason"] == ("MISSING" if response["outcome"] == "NO_SUCH_KEY" else "CORRUPT"),
                        "failure capsule changed the observed failure type")
            outcome = local["outcome"]
            if outcome is None:
                continue
            kind = outcome["kind"]
            if kind == "read_success":
                require(local["materialized"] is not None and outcome["result"] == local["materialized"],
                        "public read lacks its original complete materialization")
            elif kind == "expired":
                require(failure is not None and outcome["failure"] == failure, "SnapshotExpired lacks original object failure")
                proof = self.authority(state, outcome["proof"])
                require(state["tokens"][outcome["proof"]]["request"]["purpose"] == failure["token"], "SnapshotExpired borrowed a stale authority observation")
                require(self.retired(proof["body"], failure["generation"]), "active/target/held generation corruption misclassified expired")
            elif kind in ("write_ack", "committed_unavailable"):
                receipt = outcome["receipt"]
                token = self.observed(state, receipt["original"], "head_cas")
                require(token["response"]["outcome"] == "APPLIED" and token["request"]["transition"] == "write"
                        and receipt["head"] == token["request"]["body"], "ACK invented known durable publication")
                require(local["native"] == ("commit" if kind == "write_ack" else "fail"), "ACK preceded required native publication")
            elif kind == "transition_ack":
                token = self.observed(state, outcome["original"], "head_cas")
                require(token["response"]["outcome"] == "APPLIED", "public transition ACK without original known CAS")
            elif kind == "metadata_ready":
                head = self.authority(state, outcome["head_token"])["body"]
                principal = str(self.profile["actors"][owner]["principal"])
                require(head["life"] == "ready" and head["creation"] == self.inputs["creation"]
                        and head["acl"].get(principal, {}).get("read", False), "already-Ready metadata result invented new permission")
            elif kind == "withheld":
                if "receipt" in outcome:
                    require(outcome["receipt"] == local["receipt"] and local["commit_known"]
                            and local["native"] in ("commit", "fail"), "withheld response fabricated private durable/native knowledge")
                    token = self.observed(state, outcome["receipt"]["original"], "head_cas")
                    require(token["response"]["outcome"] == "APPLIED", "withheld receipt fabricated publication")
                elif "original" in outcome:
                    require(self.observed(state, outcome["original"], "head_cas")["response"]["outcome"] == "APPLIED",
                            "withheld transition fabricated publication")
                elif "result" in outcome:
                    require(outcome["result"] == local["materialized"] and local["materialized"] is not None,
                            "withheld read fabricated complete materialization")
                elif "head_token" in outcome:
                    head = self.authority(state, outcome["head_token"])["body"]
                    principal = str(self.profile["actors"][owner]["principal"])
                    require(head["life"] == "ready" and head["creation"] == self.inputs["creation"]
                            and head["acl"].get(principal, {}).get("read", False), "withheld metadata fabricated permission")

    def network_edge(self, before, after, identifier, choice):
        token = before["tokens"][identifier]
        require(token["stage"] == "pending", "network redelivered an already settled token")
        expected = copy.deepcopy(before)
        target = expected["tokens"][identifier]
        if choice == "discard":
            target["stage"] = "discarded"
            require(after == expected, "discard changed remote state or caller knowledge")
            return
        require(choice == "apply", "unknown network choice")
        request, kind = token["request"], token["kind"]
        if kind == "head_get":
            if before["authority_fault"] == "unavailable":
                response = {"outcome": "UNAVAILABLE"}
            elif before["head"] is None:
                response = {"outcome": "NO_SUCH_KEY"}
            else:
                body = copy.deepcopy(before["head"])
                if before["authority_fault"] == "wrong_scope":
                    body["scope"]["tenant"] += 1
                view = {"body": body, "etag": etag(body)}
                if before["authority_fault"] == "malformed":
                    view["etag"] = '"not-the-body-etag"'
                response = {"outcome": "FOUND", "snapshot": view}
        elif kind == "head_cas":
            base = request["base"]
            matches = before["head"] is None if base is None else before["head"] is not None and etag(before["head"]) == base["etag"]
            response = {"outcome": "APPLIED" if matches else "CONFLICT"}
            if matches:
                expected["head"] = copy.deepcopy(request["body"])
                response["etag"] = etag(expected["head"])
                if before["head"] is not None:
                    for generation in range(1, before["head"]["M"] + 1):
                        require(not self.retired(before["head"], generation) or self.retired(expected["head"], generation), "backend CAS revived retired generation")
                transition = request["transition"]
                if transition in ("write", "create", "complete", "seal", "promote"):
                    head = expected["head"]
                    generation = head["plan"]["identity"]["target"] if transition == "seal" else head["A"]
                    for value in self.closure(self.roots(head)):
                        obj = before["objects"].get(self.key(generation, value))
                        require(obj is not None and obj["raw"] == self.frames[value]["raw"], "publication exposed missing/corrupt dependency closure")
        elif kind in ("object_get", "candidate_get"):
            value = before["objects"].get(request["key"])
            if kind == "candidate_get" and before["candidate_fault"] is not None:
                response = {"outcome": before["candidate_fault"]}
            else:
                response = {"outcome": "NO_SUCH_KEY"} if value is None else {"outcome": "FOUND", **value}
        elif kind == "object_put":
            if request["key"] in before["objects"]:
                response = {"outcome": "CONFLICT"}
            else:
                tag = '"object:' + digest([identifier, request["key"], request["raw"]]) + '"'
                expected["objects"][request["key"]] = {"raw": request["raw"], "etag": tag}
                response = {"outcome": "APPLIED", "etag": tag}
        elif kind == "delete":
            require(before["head"] is not None and self.retired(before["head"], request["generation"]), "late DELETE reached active/target/retained namespace")
            value = before["objects"].get(request["key"])
            if value is None:
                response = {"outcome": "NO_SUCH_KEY"}
            elif value["etag"] != request["etag"]:
                response = {"outcome": "CONFLICT"}
            else:
                del expected["objects"][request["key"]]
                response = {"outcome": "APPLIED"}
        else:
            raise ValueError("unknown backend request")
        target.update(stage="applied", response=response)
        require(after == expected, "backend changed original token/condition/outcome or unrelated state")

    def client_edge(self, before, after, owner, choice):
        local, new = before["actors"][owner], after["actors"][owner]
        step = self.profile["actors"][owner]["program"][local["pc"]]
        op = step["op"]
        self.allowed_delta(before, after, owner, step, choice)
        for actor in before["actors"]:
            require(actor == owner or before["actors"][actor] == after["actors"][actor], "client changed another actor's knowledge")
        require(before["head"] == after["head"], "client fabricated persistent HEAD effect")
        if op != "fault_object":
            require(before["objects"] == after["objects"], "client fabricated immutable backend effect")
        else:
            require(self.profile["actors"][owner]["role"] == "fixture", "undeclared external corruption actor")
            expected_objects = copy.deepcopy(before["objects"])
            key = self.key(step["generation"], self.names[step["name"]])
            if step["mode"] == "missing":
                expected_objects.pop(key, None)
            elif key in expected_objects:
                expected_objects[key]["raw"] += "00"
            require(after["objects"] == expected_objects, "fixture fault changed an undeclared object")
        if local["context"] is not None:
            require(local["context"] == new["context"], "captured operation context mutated")
        health_changes = {key for key in set(before["health"]) | set(after["health"])
                          if before["health"].get(key) != after["health"].get(key)}
        incident_generation = None
        if op == "classify_failure" and local["failure"] is not None:
            incident_generation = local["failure"]["generation"]
            if str(incident_generation) in before["health"] and str(incident_generation) not in after["health"]:
                proof = self.authority(before, local["view_token"])
                require(self.retired(proof["body"], incident_generation), "cleared active incident without permanent retirement")
        elif op == "observe" and new["failure"] is not None and local["failure"] != new["failure"]:
            incident_generation = new["failure"]["generation"]
        elif op == "admit" and local["view"] is not None:
            body = local["view"]["body"]
            incident_generation = body["hold"]["generation"] if step.get("retained") and body["hold"] else body["A"]
        require(health_changes <= ({str(incident_generation)} if incident_generation is not None else set()),
                "captured failure poisoned a different current generation")
        if op == "admit" and health_changes:
            generation = str(incident_generation)
            require(generation in before["health"] and after["health"][generation] == "corrupt"
                    and new["stopped"] == "CORRUPT" and new["context"] == local["context"],
                    "admission fabricated or bypassed an unresolved generation incident")
        require(not before["authority_corrupt"] or after["authority_corrupt"], "client silently cleared malformed authority quarantine")
        require((new["stopped"] is None and new["pc"] == local["pc"] + 1)
                or (new["stopped"] is not None and new["pc"] == local["pc"]), "client skipped/replayed frozen program instruction")
        additions = set(after["tokens"]) - set(before["tokens"])
        require(set(before["tokens"]) <= set(after["tokens"]), "client dropped original pending network token")
        for identifier, token in before["tokens"].items():
            replacement = after["tokens"][identifier]
            if replacement == token:
                continue
            require(op == "observe" and token["owner"] == owner and token["observed"] is None,
                    "client rewrote an original request or prior UNKNOWN observation")
            expected = copy.deepcopy(token)
            expected["observed"] = choice
            require(replacement == expected and choice in ("known", "unknown"), "observation modified original network request/result")
            require(choice != "known" or token["stage"] == "applied", "known observation preceded backend outcome")
            require(choice != "unknown" or token["uncertain"] or token["stage"] == "discarded", "UNKNOWN invented outside frozen transport boundary")
        require(len(additions) <= 1, "one instruction dispatched multiple unbounded requests")
        for identifier in additions:
            token = after["tokens"][identifier]
            require(identifier == f"{owner}:{local['pc']}" and token["owner"] == owner and token["stage"] == "pending"
                    and token["response"] is None and token["observed"] is None, "dispatch invented backend application/knowledge")
            self.dispatch(before, owner, token)
        if op == "capture_plan" and new["stopped"] is None:
            view = self.allowed_admin(before, owner, local["view_token"], ready=True)
            require(view["body"]["plan"] is not None and new["plan"] == view["body"]["plan"]["identity"]
                    and new["sources"] == {} and new["verified"] == {}, "fresh plan capture adopted stale copy evidence")
            require("nonce" not in step or new["plan"]["nonce"] == step["nonce"], "capture accepted another plan's acquisition identity")
        if op == "observe_checkpoint" and new["stopped"] is None:
            view = self.allowed_admin(before, owner, local["view_token"])
            require(local["intent"] is not None, "checkpoint observation has no original full intent")
            if view["body"]["checkpoint"] == local["intent"]:
                require(new["checkpoint"] == {"body": local["intent"], "head_token": local["view_token"]}
                        and new["checkpoint_knowledge"] == "observed_own", "own batch observation changed full identity")
            else:
                knowledge = "pending_absent" if view["body"]["serial"] == local["intent_base_serial"] else "higher_fence"
                require(new["checkpoint"] is None and new["checkpoint_knowledge"] == knowledge,
                        "same-serial absence falsely settled an UNKNOWN conditional")
        if op == "classify_failure" and new["stopped"] is None:
            failure = local["failure"]
            require(failure is not None, "failure classification has no captured incident")
            if local["view"] is None:
                require(new["outcome"] == {"kind": "unknown", "reason": "RETIREMENT_UNVERIFIED", "failure": failure}
                        and after["health"] == before["health"], "unavailable authority invented expiry or healthy state")
            else:
                view = self.authority(before, local["view_token"])
                require(before["tokens"][local["view_token"]]["request"]["purpose"] == failure["token"],
                        "classification borrowed a stale authority GET")
                if self.retired(view["body"], failure["generation"]):
                    require(new["outcome"] == {"kind": "expired", "failure": failure, "proof": local["view_token"]}
                            and str(failure["generation"]) not in after["health"],
                            "permanently retired target was misclassified by active ordering")
                else:
                    require(new["outcome"] == {"kind": "error", "code": "CORRUPT", "failure": failure}
                            and after["health"].get(str(failure["generation"])) == "corrupt",
                            "active/target/held incident weakened instead of Corrupt")
        if op == "native_publish":
            require(local["native"] == "executed", "native publication replayed an already finalized local transaction")
            require(choice in (("commit", "fail") if local["commit_known"] else ("abort",)), "native publication before known durable CAS")
            require(new["native"] == choice, "native outcome changed")
        if op == "native_execute" and new["stopped"] is None:
            require(local["native"] is None and local["context"] is not None and local["context"]["mode"] == "write"
                    and new["native"] == "executed", "native execution replayed SQL or skipped original admission")
        if new["stopped"] == "DENIED" and (op.startswith("prepare_") or op in ("capture_plan", "observe_checkpoint", "candidate_get")):
            view = self.authority(before, local["view_token"])
            principal = str(self.profile["actors"][owner]["principal"])
            require(not view["body"]["acl"].get(principal, {}).get("admin", False),
                    "owner change falsely revoked independently retained admin permission")
        if new["stopped"] == "FENCED":
            require(op == "admit" and step.get("mode") == "write", "owner fence incorrectly denied an admin-only verb")
            body = self.authority(before, local["view_token"])["body"]
            require(not body["active"] or body["owner"] != self.profile["actors"][owner]["worker"] or body["plan"] is not None,
                    "ordinary owner admission was falsely fenced")
        if op in ("materialize", "return_read") and new["stopped"] is None:
            require(not local["local_stop"] and local["failure"] is None, "materialization/read return survived local abort/failure")
        if op in ("return_read", "ack_write", "ack_transition", "metadata_ready") and new["stopped"] is None:
            require(not local["local_stop"], "public return crossed a previously closed local gate")
            if local["detached"]:
                require(new["outcome"] is not None and new["outcome"]["kind"] in ("withheld", "unknown"),
                        "detached caller received a new public success")
        self.state(after)

    def allowed_delta(self, before, after, owner, step, choice):
        """Effect ownership, not a second reducer: each fact has one writer.

        Original public outcomes are historical. Later stop/detach cannot
        invalidate a return which was already observed on an earlier edge.
        """
        op = step["op"]
        old, new = before["actors"][owner], after["actors"][owner]
        require(set(before) == set(after) and set(old) == set(new), "transition changed the frozen state schema")
        require(set(before["actors"]) == set(after["actors"]) == set(self.profile["actors"]), "transition changed the frozen actor inventory")
        for field, instruction in (("authority_fault", "fault_authority"), ("candidate_fault", "fault_candidate")):
            if before[field] != after[field]:
                require(op == instruction and self.profile["actors"][owner]["role"] == "fixture",
                        "nonfixture instruction modified injected backend fault")
                require(after[field] == (step["mode"] if "mode" in step else choice), "fixture changed an undeclared fault mode")
        if before["authority_corrupt"] != after["authority_corrupt"]:
            require(op == "observe" and not before["authority_corrupt"] and after["authority_corrupt"],
                    "instruction forged authority quarantine state")
            identifier = old["labels"].get(step["label"]) if "label" in step else old["last"]
            token = before["tokens"].get(identifier)
            require(token is not None and token["kind"] == "head_get" and choice == "known"
                    and token["response"]["outcome"] == "FOUND", "authority quarantine has no original bad HEAD response")
            view = token["response"]["snapshot"]
            require(view["body"]["scope"] != self.scope or view["etag"] != etag(view["body"]), "valid authority observation falsely quarantined")
        allowed = {"pc", "stopped", "outcome"}
        dispatch_ops = {"head_get", "object_get", "object_put", "send_head", "copy_source", "copy_put", "copy_verify", "candidate_get", "delete"}
        if op in dispatch_ops:
            allowed.update(("last", "last_result", "labels"))
        if op in ("object_get", "copy_source", "copy_put", "copy_verify"):
            allowed.add("no_work")
        if op == "observe":
            allowed.update(("last_result", "view", "view_token", "commit_known", "receipt", "failure", "sources", "verified", "readbacks", "frames"))
        if op in ("admit", "bootstrap"):
            allowed.add("context")
        if op == "mark":
            allowed.add("marks")
        if op == "detach":
            allowed.add("detached")
        if op == "stop_local":
            allowed.add("local_stop")
        if op in ("native_execute", "native_publish"):
            allowed.add("native")
        if op == "materialize":
            allowed.add("materialized")
        if op.startswith("prepare_"):
            allowed.add("candidate")
        if op == "prepare_checkpoint":
            allowed.update(("intent", "intent_base_serial", "checkpoint"))
        if op == "prepare_dispositions":
            allowed.add("intent")
        if op == "prepare_clear":
            allowed.add("clear_serial")
        if op == "capture_plan":
            allowed.update(("plan", "sources", "verified"))
        if op == "capture_candidate":
            allowed.add("candidates")
        if op == "observe_checkpoint":
            allowed.update(("checkpoint", "checkpoint_knowledge"))
        if op == "record_disposition":
            allowed.add("dispositions")
        if op == "confirm_clear":
            allowed.update(("checkpoint", "checkpoint_knowledge", "dispositions"))
        changed = {field for field in old if old[field] != new[field]}
        require(changed <= allowed, "instruction modified a fact owned by another operation: " + ','.join(sorted(changed-allowed)))
        require(not old["local_stop"] or new["local_stop"], "closed local gate reopened")
        require(not old["detached"] or new["detached"], "detached caller was reattached")
        require(not old["commit_known"] or new["commit_known"], "known durable publication was forgotten")
        if op == "mark" and new["stopped"] is None:
            require(new["marks"] == {**old["marks"], step["name"]: True}, "fixture pause marks were forged/replaced")
        if op == "detach" and new["stopped"] is None:
            require(new["detached"], "detach did not record caller exit")
        if op == "stop_local" and new["stopped"] is None:
            require(new["local_stop"], "stop did not close the local gate")
        additions = set(after["tokens"]) - set(before["tokens"])
        if additions:
            identifier = next(iter(additions))
            token = after["tokens"][identifier]
            require(set(token) == {"owner", "kind", "request", "uncertain", "stage", "response", "observed"}
                    and token["uncertain"] == step.get("uncertain", False), "dispatch changed its frozen uncertainty/token shape")
            require(new["last"] == identifier and new["last_result"] is None, "dispatch forged last request/result knowledge")
            expected_labels = {**old["labels"], step["label"]: identifier} if "label" in step else old["labels"]
            require(new["labels"] == expected_labels, "dispatch rebound original token labels")
        else:
            require(new["labels"] == old["labels"], "instruction changed labels without an original dispatch")
        if old["failure"] is not None:
            require(new["failure"] == old["failure"], "original failure capsule replaced")
        if op == "observe":
            identifier = old["labels"].get(step["label"]) if "label" in step else old["last"]
            token = before["tokens"].get(identifier)
            if token is not None and token["observed"] is None:
                expected_result = {"outcome": "UNKNOWN", "token": identifier} if choice == "unknown" else {**token["response"], "token": identifier}
                require(new["last_result"] == expected_result, "observation fabricated a different response/outcome")
                if token["kind"] == "head_get":
                    value = None if choice == "unknown" or token["response"]["outcome"] != "FOUND" else token["response"]["snapshot"]
                    valid = value is not None and value["body"]["scope"] == self.scope and value["etag"] == etag(value["body"])
                    require(new["view"] == (value if valid else None) and new["view_token"] == (identifier if valid else None),
                            "HEAD observation substituted another view or token")
                else:
                    require(new["view"] == old["view"] and new["view_token"] == old["view_token"], "non-HEAD response replaced observed authority")
                acquired_commit = token["kind"] == "head_cas" and token["request"]["transition"] == "write" and choice == "known" and token["response"]["outcome"] == "APPLIED"
                require(new["commit_known"] == (old["commit_known"] or acquired_commit), "observation invented known durable publication")
                if not acquired_commit:
                    require(new["receipt"] == old["receipt"], "unrelated response fabricated a durable receipt")
                else:
                    require(new["receipt"] == {"head": token["request"]["body"], "request": token["request"]["evidence"]["request"], "original": identifier},
                            "known response fabricated another durable receipt identity")
                if token["kind"] != "object_get":
                    require(all(new[field] == old[field] for field in ("failure", "sources", "verified", "readbacks", "frames")), "non-object response fabricated immutable evidence")
                else:
                    expected_maps = {field: copy.deepcopy(old[field]) for field in ("sources", "verified", "readbacks", "frames")}
                    request = token["request"]
                    valid = choice == "known" and token["response"]["outcome"] == "FOUND" and token["response"]["raw"] == self.frames[request["hash"]]["raw"]
                    if valid and new["stopped"] is None:
                        if request["purpose"] in ("copy_source", "copy_verify"):
                            require(request["protection"] == old["plan"], "response adopted evidence from an obsolete plan")
                            destination = "sources" if request["purpose"] == "copy_source" else "verified"
                        else:
                            require(request["protection"] == old["context"], "response adopted another operation's bytes")
                            destination = "readbacks" if request["purpose"] == "readback" else "frames"
                        expected_maps[destination][request["hash"]] = identifier if destination == "readbacks" else {"raw": token["response"]["raw"], "token": identifier}
                    require(all(new[field] == value for field, value in expected_maps.items()),
                            "object observation changed an unrelated or unobserved proof map")
            else:
                require(all(new[field] == old[field] for field in ("last_result", "view", "view_token", "commit_known", "receipt", "failure", "sources", "verified", "readbacks", "frames")),
                        "missing/repeated response changed original knowledge")
        if new["outcome"] != old["outcome"]:
            if new["stopped"] is not None:
                observed_unknown = op == "observe" and choice == "unknown" and token is not None and token["kind"] == "head_cas" and token["request"]["transition"] == "write" and new["outcome"] == {"kind": "unknown", "original": identifier}
                require(old["outcome"] is None and (new["outcome"] == {"kind": "error", "code": new["stopped"]} or observed_unknown),
                        "error overwrote an earlier public outcome")
            else:
                require(op in ("return_read", "classify_failure", "ack_write", "ack_transition", "metadata_ready", "observe"),
                        "instruction invented a public outcome")
                if op == "observe":
                    require(choice == "unknown" and token is not None and token["kind"] == "head_cas"
                            and token["request"]["transition"] == "write"
                            and new["outcome"] == {"kind": "unknown", "original": identifier},
                            "transport observation fabricated a public success instead of original UNKNOWN")
                else:
                    kinds = {"return_read": {"read_success", "withheld"},
                             "ack_write": {"write_ack", "committed_unavailable", "withheld", "unknown"},
                             "ack_transition": {"transition_ack", "withheld"},
                             "metadata_ready": {"metadata_ready", "withheld"},
                             "classify_failure": {"expired", "unknown", "error"}}
                    require(new["outcome"] is not None and new["outcome"]["kind"] in kinds[op],
                            "public outcome came from the wrong return operation")
