"""Finite abortable-generation producer; no production imports or acceptance claim.

Client admission, immutable request identity, backend application and caller
knowledge are separate. All pending requests remain schedulable after local exit.
"""

import copy
import hashlib
import json


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def fingerprint(value):
    return hashlib.sha256(wire(value)).hexdigest()


def head_tag(head):
    return '"head:' + fingerprint(head) + '"'


def snapshot(head):
    return None if head is None else {"body": copy.deepcopy(head), "etag": head_tag(head)}


class Rejected(Exception):
    pass


class Model:
    def __init__(self, spec, profile):
        self.spec, self.profile = spec, profile
        self.frames = spec["frames"]
        self.by_hash = {value["hash"]: value for value in self.frames.values()}
        s = spec["scope"]
        self.slot = f"scap-object/v1/{s['deployment']}/{s['tenant']}/{s['database']}/head"
        self.prefix = (f"scap-object/v1/{s['deployment']}/{s['tenant']}/{s['database']}"
                       f"/inc/{s['incarnation']}/gen/{s['generation']}/storage/")

    def key(self, generation, digest):
        return self.prefix + str(generation) + "/objects/" + digest

    def require(self, value, reason):
        if not value:
            raise Rejected(reason)

    def closure(self, roots):
        found, pending = set(), list(roots)
        while pending:
            digest = pending.pop()
            self.require(digest in self.by_hash, "UNDECLARED_FRAME")
            if digest not in found:
                found.add(digest)
                pending.extend(self.by_hash[digest]["references"])
        return sorted(found)

    @staticmethod
    def roots(head):
        return [head["data"], *head["results"]]

    @staticmethod
    def retired(head, generation):
        return (head is not None and 1 <= generation <= head["M"] and generation != head["A"]
                and (head["plan"] is None or generation != head["plan"]["identity"]["target"])
                and (head["hold"] is None or generation != head["hold"]["generation"]))

    def condition(self, state, condition):
        head = state["head"]
        if "all" in condition:
            return all(self.condition(state, part) for part in condition["all"])
        if "head" in condition:
            return head is not None and all(head.get(k) == v for k, v in condition["head"].items())
        if "plan" in condition:
            return head is not None and head["plan"] is not None and all(
                head["plan"]["identity"].get(k) == v for k, v in condition["plan"].items())
        if "actor" in condition:
            local = state["actors"][condition["actor"]]
            return all(local.get(k) == v for k, v in condition["fields"].items())
        if "mark" in condition:
            owner, mark = condition["mark"].split("/", 1)
            return state["actors"][owner]["marks"].get(mark, False)
        if "outcome" in condition:
            value = state["actors"][condition["outcome"]["actor"]]["outcome"]
            return value is not None and value["kind"] == condition["outcome"]["kind"]
        if "object" in condition:
            value = condition["object"]
            key = self.key(value["generation"], self.frames[value["name"]]["hash"])
            return (key in state["objects"]) == value["present"]
        if "token" in condition:
            owner, label = condition["token"].split("/", 1)
            identifier = state["actors"][owner]["labels"].get(label)
            token = state["tokens"].get(identifier)
            return token is not None and all(token.get(k) == v for k, v in condition["fields"].items())
        raise ValueError("unknown fixture barrier: " + repr(condition))

    def actions(self, state):
        actions = []
        for name, local in state["actors"].items():
            program = self.profile["actors"][name]["program"]
            if local["stopped"] is not None or local["pc"] == len(program):
                continue
            step = program[local["pc"]]
            if step["op"] == "await":
                if self.condition(state, step["condition"]):
                    actions.append({"actor": name, "choice": "step"})
            elif step["op"] == "observe":
                identifier = local["labels"].get(step.get("label")) if "label" in step else local["last"]
                token = state["tokens"].get(identifier)
                if token is None:
                    actions.append({"actor": name, "choice": "step"})
                elif token["observed"] is not None:
                    actions.append({"actor": name, "choice": "step"})
                else:
                    if token["stage"] == "applied":
                        actions.append({"actor": name, "choice": "known"})
                    if token["uncertain"] or token["stage"] == "discarded":
                        actions.append({"actor": name, "choice": "unknown"})
            elif step["op"] == "native_publish":
                choices = ("commit", "fail") if local["commit_known"] else ("abort",)
                actions.extend({"actor": name, "choice": value} for value in choices)
            elif step["op"] in ("fault_authority", "fault_candidate") and "choices" in step:
                actions.extend({"actor": name, "choice": value} for value in step["choices"])
            else:
                actions.append({"actor": name, "choice": "step"})
        for identifier, token in state["tokens"].items():
            if token["stage"] == "pending":
                actions.extend({"network": identifier, "choice": choice} for choice in ("apply", "discard"))
        return sorted(actions, key=wire)

    def successor(self, previous, action):
        state = copy.deepcopy(previous)
        if "network" in action:
            self.network(state, action["network"], action["choice"])
            return state
        name = action["actor"]
        local = state["actors"][name]
        step = self.profile["actors"][name]["program"][local["pc"]]
        try:
            self.client(state, name, step, action["choice"])
        except Rejected as error:
            local["stopped"] = str(error)
            if local["outcome"] is None:
                local["outcome"] = {"kind": "error", "code": str(error)}
        else:
            local["pc"] += 1
        return state

    def request(self, state, name, kind, request, step):
        local = state["actors"][name]
        self.require(not local["local_stop"], "LOCAL_GATE_CLOSED")
        if len(state["tokens"]) == self.spec["bounds"]["tokens"]:
            raise RuntimeError("frozen token resource bound exceeded")
        identifier = f"{name}:{local['pc']}"
        self.require(identifier not in state["tokens"], "TOKEN_REUSE")
        state["tokens"][identifier] = {
            "owner": name, "kind": kind, "request": copy.deepcopy(request),
            "uncertain": step.get("uncertain", False), "stage": "pending",
            "response": None, "observed": None,
        }
        local["last"] = identifier
        local["last_result"] = None
        if "label" in step:
            self.require(step["label"] not in local["labels"], "LABEL_REUSE")
            local["labels"][step["label"]] = identifier
        return identifier

    def fresh(self, local):
        self.require(local["view"] is not None, "AUTHORITY_UNAVAILABLE")
        view = local["view"]
        self.require(view["body"]["scope"] == self.spec["scope"] and view["etag"] == head_tag(view["body"]),
                     "AUTHORITY_CORRUPT")
        return copy.deepcopy(view["body"])

    def next_head(self, head, *, business=False):
        value = copy.deepcopy(head)
        self.require(value["serial"] < (1 << 64) - 1, "SERIAL_LIMIT")
        value["serial"] += 1
        if business:
            self.require(value["revision"] < (1 << 64) - 1, "REVISION_LIMIT")
            value["revision"] += 1
        return value

    def admin(self, local, actor):
        head = self.fresh(local)
        self.require(str(actor["principal"]) in head["acl"] and head["acl"][str(actor["principal"])]["admin"], "DENIED")
        return head

    def candidate(self, local, head, kind, *, base=None, base_token=None, evidence=None):
        base = local["view"] if base is None else base
        local["candidate"] = {"key": self.slot, "body": head, "base": copy.deepcopy(base),
                              "base_token": local["view_token"] if base_token is None else base_token,
                              "transition": kind, "evidence": copy.deepcopy(evidence)}

    def valid_raw(self, raw, expected):
        if hashlib.sha256(bytes.fromhex(raw)).hexdigest() != expected:
            return False
        try:
            body = json.loads(bytes.fromhex(raw).split(b"\n", 1)[1])
            return body["scope"] == self.spec["scope"] and raw == self.by_hash[expected]["raw"]
        except (ValueError, KeyError, IndexError):
            return False

    def observe(self, state, name, step, choice):
        local = state["actors"][name]
        identifier = local["labels"].get(step.get("label")) if "label" in step else local["last"]
        token = state["tokens"].get(identifier)
        if token is None:
            self.require(local["no_work"], "NO_ORIGINAL_REQUEST")
            return
        self.require(token["observed"] is None, "REPEATED_OBSERVATION")
        token["observed"] = choice
        if choice == "unknown":
            local["last_result"] = {"outcome": "UNKNOWN", "token": identifier}
            if token["kind"] == "head_get":
                local["view"], local["view_token"] = None, None
            if token["kind"] == "head_cas" and token["request"]["transition"] == "write":
                local["outcome"] = {"kind": "unknown", "original": identifier}
            if not step.get("allow_unknown", False):
                raise Rejected("UNKNOWN")
            return
        response = copy.deepcopy(token["response"])
        local["last_result"] = {**response, "token": identifier}
        if token["kind"] == "head_get":
            if response["outcome"] != "FOUND":
                local["view"], local["view_token"] = None, None
                if not step.get("allow_failure", False):
                    raise Rejected("AUTHORITY_UNAVAILABLE")
                return
            view = response["snapshot"]
            if view["body"]["scope"] != self.spec["scope"] or view["etag"] != head_tag(view["body"]):
                state["authority_corrupt"] = True
                local["view"], local["view_token"] = None, None
                raise Rejected("AUTHORITY_CORRUPT")
            local["view"], local["view_token"] = view, identifier
            return
        if token["kind"] == "head_cas":
            if token["request"]["transition"] == "write" and response["outcome"] == "APPLIED":
                local["commit_known"] = True
                local["receipt"] = {"head": token["request"]["body"], "request": token["request"]["evidence"]["request"],
                                    "original": identifier}
            if response["outcome"] == "CONFLICT" and not step.get("allow_failure", False):
                raise Rejected("CONFLICT")
            return
        if token["kind"] in ("candidate_get", "delete"):
            return
        if token["kind"] == "object_put":
            if response["outcome"] not in ("APPLIED", "CONFLICT"):
                raise Rejected("UNKNOWN")
            return
        if token["kind"] == "object_get":
            request = token["request"]
            if response["outcome"] != "FOUND" or not self.valid_raw(response["raw"], request["hash"]):
                reason = "MISSING" if response["outcome"] == "NO_SUCH_KEY" else "CORRUPT"
                local["failure"] = {"token": identifier, "generation": request["generation"], "hash": request["hash"],
                                    "scope": self.spec["scope"], "protection": request["protection"], "reason": reason}
                state["health"].setdefault(str(request["generation"]), "unresolved")
                if not step.get("allow_failure", False):
                    raise Rejected("OBJECT_FAILURE_UNCLASSIFIED")
                return
            self.require(not local["local_stop"], "LATE_RESPONSE_AFTER_LOCAL_STOP")
            if request["purpose"] in ("copy_source", "copy_verify"):
                self.require(local["plan"] == request["protection"], "OLD_PLAN_RESPONSE")
                destination = "sources" if request["purpose"] == "copy_source" else "verified"
                local[destination][request["hash"]] = {"raw": response["raw"], "token": identifier}
            elif request["purpose"] == "readback":
                self.require(local["context"] == request["protection"], "CONTEXT_REBOUND")
                local["readbacks"][request["hash"]] = identifier
            else:
                self.require(local["context"] == request["protection"], "CONTEXT_REBOUND")
                local["frames"][request["hash"]] = {"raw": response["raw"], "token": identifier}

    def client(self, state, name, step, choice):
        local = state["actors"][name]
        actor = self.profile["actors"][name]
        op = step["op"]
        if op == "await":
            return
        if op == "mark":
            local["marks"][step["name"]] = True
            return
        if op == "detach":
            local["detached"] = True
            return
        if op == "stop_local":
            local["local_stop"] = True
            return
        if op == "head_get":
            purpose = local["failure"]["token"] if step.get("purpose") == "failure" and local["failure"] else step.get("purpose", "admit")
            self.request(state, name, "head_get", {"key": self.slot, "purpose": purpose}, step)
            return
        if op == "observe":
            self.observe(state, name, step, choice)
            return
        if op == "admit":
            head = self.fresh(local)
            self.require(not state["authority_corrupt"], "AUTHORITY_CORRUPT")
            self.require(local["context"] is None, "CONTEXT_REUSE")
            mode = step.get("mode", "read")
            if mode in ("complete", "abort"):
                self.require(head["life"] == "provisioning" and head["creation"] == self.spec["creation"]
                             and actor["principal"] == self.spec["creator"], "PROVISIONING_IDENTITY")
            else:
                self.require(head["life"] == "ready", "LIFECYCLE")
                permission = head["acl"].get(str(actor["principal"]), {})
                self.require(permission.get("read", False), "DENIED")
                if mode == "write":
                    self.require(permission.get("write", False), "DENIED")
                    self.require(head["active"] and head["owner"] == actor["worker"] and head["plan"] is None, "FENCED")
            generation = head["A"]
            roots = self.roots(head) if mode in ("complete", "abort", "write") else [head["data"]]
            if step.get("retained", False):
                self.require(head["hold"] is not None, "NO_RETAINED_ROOT")
                generation, roots = head["hold"]["generation"], head["hold"]["roots"]
            if str(generation) in state["health"]:
                state["health"][str(generation)] = "corrupt"
                raise Rejected("CORRUPT")
            local["context"] = {"mode": mode, "scope": self.spec["scope"], "generation": generation,
                                "roots": roots, "base": copy.deepcopy(local["view"]),
                                "head_token": local["view_token"], "principal": actor["principal"]}
            return
        if op == "bootstrap":
            self.require(local["context"] is None, "CONTEXT_REUSE")
            local["context"] = {"mode": "bootstrap", "scope": self.spec["scope"], "generation": 1,
                                "roots": self.spec["initial_roots"], "base": None, "head_token": None,
                                "principal": actor["principal"]}
            return
        if op == "object_get":
            context = local["context"]
            self.require(context is not None and local["failure"] is None, "NO_USABLE_CONTEXT")
            hashes = self.closure(context["roots"])
            digest = self.frames[step["name"]]["hash"] if "name" in step else hashes[step["index"]] if step["index"] < len(hashes) else None
            local["no_work"] = digest is None
            if digest is None:
                local["last"] = None
                return
            purpose = step.get("purpose", "read")
            if purpose != "readback":
                self.require(digest in hashes, "UNREFERENCED_READ")
            self.request(state, name, "object_get", {"key": self.key(context["generation"], digest),
                         "generation": context["generation"], "hash": digest, "purpose": purpose,
                         "protection": context}, step)
            return
        if op == "object_put":
            context = local["context"]
            self.require(context is not None and local["failure"] is None, "NO_USABLE_CONTEXT")
            value = self.frames[step["name"]]
            self.request(state, name, "object_put", {"key": self.key(context["generation"], value["hash"]),
                         "generation": context["generation"], "hash": value["hash"], "raw": value["raw"],
                         "protection": context, "condition": "absent"}, step)
            return
        if op == "materialize":
            context = local["context"]
            self.require(context is not None and local["failure"] is None and not local["local_stop"], "INCOMPLETE_READ")
            required = self.closure(context["roots"])
            self.require(all(value in local["frames"] for value in required), "INCOMPLETE_READ")
            local["materialized"] = {"context": copy.deepcopy(context),
                                     "frames": {key: local["frames"][key] for key in required}}
            return
        if op == "return_read":
            self.require(local["materialized"] is not None and local["failure"] is None and not local["local_stop"], "INCOMPLETE_READ")
            local["outcome"] = {"kind": "withheld" if local["detached"] else "read_success", "result": local["materialized"]}
            return
        if op == "classify_failure":
            failure = local["failure"]
            self.require(failure is not None, "NO_OBJECT_FAILURE")
            if local["view"] is None:
                local["outcome"] = {"kind": "unknown", "reason": "RETIREMENT_UNVERIFIED", "failure": failure}
                return
            view_token = state["tokens"][local["view_token"]]
            self.require(view_token["request"]["purpose"] == failure["token"], "NOT_A_FRESH_FAILURE_INVESTIGATION")
            head = self.fresh(local)
            generation = failure["generation"]
            if self.retired(head, generation):
                state["health"].pop(str(generation), None)
                local["outcome"] = {"kind": "expired", "failure": failure, "proof": local["view_token"]}
            else:
                state["health"][str(generation)] = "corrupt"
                local["outcome"] = {"kind": "error", "code": "CORRUPT", "failure": failure}
            return
        if op == "native_execute":
            self.require(local["context"] is not None and local["context"]["mode"] == "write"
                         and local["native"] is None, "SQL_REPLAY_OR_NO_ADMISSION")
            local["native"] = "executed"
            return
        if op == "prepare_write":
            context = local["context"]
            self.require(context is not None and context["mode"] == "write" and local["native"] == "executed", "NO_WRITE_ADMISSION")
            dependencies = [self.frames[value]["hash"] for value in step["dependencies"]]
            self.require(all(value in local["readbacks"] for value in dependencies), "UNVERIFIED_DEPENDENCIES")
            head = self.next_head(context["base"]["body"], business=True)
            head["sequence"] += 1
            head["data"] = self.frames[step["data"]]["hash"]
            head["results"].append(self.frames[step["result"]]["hash"])
            self.candidate(local, head, "write", base=context["base"],
                           base_token=context["head_token"],
                           evidence={"context": context, "request": step["request"],
                                     "readbacks": {key: local["readbacks"][key] for key in dependencies}})
            return
        if op == "send_head":
            self.require(local["candidate"] is not None, "NO_PREPARED_HEAD")
            self.request(state, name, "head_cas", local["candidate"], step)
            return
        if op == "native_publish":
            local["native"] = choice
            return
        if op == "ack_write":
            self.require(not local["local_stop"], "LOCAL_GATE_CLOSED")
            if local["commit_known"]:
                local["outcome"] = {"kind": "withheld" if local["detached"] else "write_ack" if local["native"] == "commit" else "committed_unavailable",
                                    "receipt": local["receipt"]}
            else:
                local["outcome"] = local["outcome"] or {"kind": "unknown"}
            return
        if op == "ack_transition":
            self.require(not local["local_stop"], "LOCAL_GATE_CLOSED")
            result = local["last_result"]
            self.require(result is not None and result["outcome"] == "APPLIED"
                         and state["tokens"][result["token"]]["kind"] == "head_cas", "NO_KNOWN_PUBLICATION")
            local["outcome"] = {"kind": "withheld" if local["detached"] else "transition_ack", "original": result["token"]}
            return
        if op.startswith("prepare_"):
            self.prepare(state, name, step)
            return
        if op.startswith("copy_") or op == "capture_plan":
            self.copy_step(state, name, step)
            return
        if op in ("candidate_get", "capture_candidate", "observe_checkpoint", "delete", "record_disposition", "confirm_clear"):
            self.sweep_step(state, name, step)
            return
        if op == "metadata_ready":
            self.require(not local["local_stop"], "LOCAL_GATE_CLOSED")
            head = self.fresh(local)
            self.require(head["life"] == "ready" and head["creation"] == self.spec["creation"], "NOT_READY_METADATA")
            self.require(head["acl"].get(str(actor["principal"]), {}).get("read", False), "DENIED")
            local["outcome"] = {"kind": "withheld" if local["detached"] else "metadata_ready", "head_token": local["view_token"]}
            return
        if op == "fault_object":
            self.require(actor["role"] == "fixture", "NOT_A_FIXTURE_ACTOR")
            key = self.key(step["generation"], self.frames[step["name"]]["hash"])
            if step["mode"] == "missing":
                state["objects"].pop(key, None)
            else:
                self.require(key in state["objects"], "FIXTURE_OBJECT_ABSENT")
                state["objects"][key]["raw"] += "00"
            return
        if op == "fault_authority":
            self.require(actor["role"] == "fixture", "NOT_A_FIXTURE_ACTOR")
            state["authority_fault"] = step["mode"] if "mode" in step else choice
            return
        if op == "fault_candidate":
            self.require(actor["role"] == "fixture", "NOT_A_FIXTURE_ACTOR")
            state["candidate_fault"] = step["mode"] if "mode" in step else choice
            return
        raise ValueError("unknown client instruction " + op)

    # Metadata transition and sweep definitions are deliberately in this
    # producer only. The acceptance oracle must not import these functions.
    def prepare(self, state, name, step):
        local, actor = state["actors"][name], self.profile["actors"][name]
        op = step["op"][8:]
        if op in ("create", "absent_abort"):
            context = local["context"]
            self.require(context is not None and context["mode"] == "bootstrap"
                         and actor["principal"] == self.spec["creator"] and local["failure"] is None, "NO_BOOTSTRAP")
            self.require(all(digest in local["readbacks"] for digest in self.closure(context["roots"])),
                         "UNVERIFIED_BOOTSTRAP")
            head = copy.deepcopy(self.spec["initial_head"])
            head["life"] = step.get("life", "ready") if op == "create" else "deleted"
            head["active"] = head["life"] == "ready"
            local["candidate"] = {"key": self.slot, "body": head, "base": None, "base_token": None,
                                  "transition": op, "evidence": {"context": context, "readbacks": local["readbacks"]}}
            return
        if op in ("complete", "abort"):
            context = local["context"]
            self.require(context is not None and context["mode"] == op and local["failure"] is None,
                         "NO_PROVISIONING_ADMISSION")
            self.require(all(digest in local["frames"] for digest in self.closure(context["roots"])),
                         "UNVERIFIED_PROVISIONING")
            head = self.next_head(context["base"]["body"], business=True)
            head["life"], head["active"] = ("ready", True) if op == "complete" else ("deleted", False)
            self.candidate(local, head, op, base=context["base"], base_token=context["head_token"],
                           evidence={"context": context, "frames": local["frames"]})
            return
        original = self.admin(local, actor)
        head = self.next_head(original, business=op in ("delete", "acl", "owner"))
        evidence = {"authority": local["view_token"]}
        if op == "freeze":
            self.require(head["life"] == "ready" and head["plan"] is None and head["checkpoint"] is None,
                         "COPY_ADMISSION_BLOCKED")
            self.require(head["M"] < self.spec["bounds"]["generations"], "GENERATION_LIMIT")
            head["M"] += 1
            head["active"] = False
            identity = {"scope": self.spec["scope"], "source": head["A"], "target": head["M"],
                        "nonce": step["nonce"], "roots": self.roots(original), "started_serial": head["serial"]}
            head["plan"] = {"identity": identity, "phase": "copying"}
        elif op in ("seal", "promote", "abort_plan"):
            self.require(head["life"] == "ready" and head["plan"] is not None, "NO_COPY_PLAN")
            self.require(local["plan"] == head["plan"]["identity"], "PLAN_REPLACED")
            evidence["plan"] = local["plan"]
            if op == "abort_plan":
                head["plan"] = None
            elif op == "seal":
                self.require(head["plan"]["phase"] == "copying", "NOT_COPYING")
                closure = self.closure(head["plan"]["identity"]["roots"])
                self.require(all(digest in local["verified"] for digest in closure), "INCOMPLETE_COPY")
                evidence["verified"] = local["verified"]
                head["plan"]["phase"] = "sealed"
            else:
                self.require(head["plan"]["phase"] == "sealed", "NOT_SEALED")
                head["A"], head["active"], head["plan"] = head["plan"]["identity"]["target"], True, None
        elif op == "acl":
            self.require(head["life"] == "ready", "LIFECYCLE")
            for right in ("read", "write", "admin"):
                if right in step:
                    head["acl"][str(step["principal"])][right] = step[right]
        elif op == "owner":
            self.require(head["life"] == "ready" and head["plan"] is None, "OWNER_CHANGE_BLOCKED")
            head["owner"], head["owner_epoch"], head["active"] = step["worker"], head["owner_epoch"] + 1, False
        elif op == "delete":
            self.require(head["life"] == "ready", "LIFECYCLE")
            head["life"], head["active"], head["plan"] = "deleted", False, None
        elif op == "hold_add":
            self.require(head["life"] == "ready" and head["hold"] is None, "HOLD_ADMISSION_BLOCKED")
            head["hold"] = {"id": step["id"], "generation": head["A"], "roots": self.roots(head)}
        elif op == "hold_release":
            self.require(head["hold"] is not None and head["hold"]["id"] == step["id"], "NO_OWN_HOLD")
            head["hold"] = None
        elif op == "fence":
            # Metadata serial alone changes the body-derived conditional token.
            pass
        elif op == "checkpoint":
            self.require(head["life"] == "ready" and head["plan"] is None and head["checkpoint"] is None,
                         "SWEEP_ADMISSION_BLOCKED")
            candidates = copy.deepcopy(local["candidates"])
            self.require(1 <= len(candidates) <= self.spec["bounds"]["candidates"], "CANDIDATE_BOUND")
            generation = candidates[0]["generation"]
            self.require(all(item["generation"] == generation for item in candidates) and self.retired(head, generation),
                         "GENERATION_PROTECTED")
            self.require(len({item["key"] for item in candidates}) == len(candidates), "DUPLICATE_CANDIDATE")
            checkpoint = {"plan": step["plan"], "batch": step["batch"], "sequence": step.get("sequence", 1),
                          "generation": generation, "captured_serial": original["serial"], "entries": candidates}
            head["checkpoint"] = checkpoint
            local["intent"] = copy.deepcopy(checkpoint)
            local["intent_base_serial"] = original["serial"]
            local["checkpoint"] = None
            evidence["candidate_gets"] = [item["get"] for item in candidates]
        elif op in ("dispositions", "clear"):
            expected = local["checkpoint"]
            self.require(expected is not None and head["checkpoint"] == expected["body"], "CHECKPOINT_REPLACED")
            self.require(self.retired(head, head["checkpoint"]["generation"]), "GENERATION_PROTECTED")
            if op == "dispositions":
                for index, disposition in local["dispositions"].items():
                    entry = head["checkpoint"]["entries"][int(index)]
                    self.require(entry["disposition"] == "pending", "ALREADY_DISPOSED")
                    entry["disposition"] = disposition["kind"]
                    entry["evidence"] = disposition["token"]
                self.require(bool(local["dispositions"]), "NO_DISPOSITION")
                local["intent"] = copy.deepcopy(head["checkpoint"])
                evidence["dispositions"] = copy.deepcopy(local["dispositions"])
            else:
                self.require(all(item["disposition"] in ("applied", "observed_absent", "condition_mismatch")
                                 for item in head["checkpoint"]["entries"]), "UNSETTLED_CANDIDATE")
                evidence["checkpoint"] = copy.deepcopy(head["checkpoint"])
                head["checkpoint"] = None
                local["clear_serial"] = head["serial"]
        else:
            raise ValueError("unknown metadata preparation " + op)
        self.candidate(local, head, op, evidence=evidence)

    def copy_step(self, state, name, step):
        local = state["actors"][name]
        op = step["op"]
        if op == "capture_plan":
            head = self.admin(local, self.profile["actors"][name])
            self.require(head["life"] == "ready" and head["plan"] is not None, "NO_COPY_PLAN")
            if "nonce" in step:
                self.require(head["plan"]["identity"]["nonce"] == step["nonce"], "NOT_OWN_PLAN")
            local["plan"] = copy.deepcopy(head["plan"]["identity"])
            local["sources"], local["verified"] = {}, {}
            return
        plan = local["plan"]
        self.require(plan is not None and local["failure"] is None, "NO_USABLE_PLAN")
        closure = self.closure(plan["roots"])
        digest = self.frames[step["name"]]["hash"] if "name" in step else closure[step["index"]] if step["index"] < len(closure) else None
        local["no_work"] = digest is None
        if digest is None:
            local["last"] = None
            return
        self.require(digest in closure, "UNREFERENCED_COPY")
        generation = plan["source"] if op == "copy_source" else plan["target"]
        request = {"key": self.key(generation, digest), "generation": generation, "hash": digest,
                   "protection": plan}
        if op == "copy_put":
            self.require(digest in local["sources"], "UNVERIFIED_COPY_SOURCE")
            request.update(raw=local["sources"][digest]["raw"], condition="absent", source=local["sources"][digest]["token"])
            self.request(state, name, "object_put", request, step)
        else:
            self.require(op in ("copy_source", "copy_verify"), "INVALID_COPY_OPERATION")
            request["purpose"] = op
            self.request(state, name, "object_get", request, step)

    def sweep_step(self, state, name, step):
        local = state["actors"][name]
        op = step["op"]
        if op == "candidate_get":
            head = self.admin(local, self.profile["actors"][name])
            self.require(head["life"] == "ready", "LIFECYCLE")
            if "name" in step:
                generation, digest = step["generation"], self.frames[step["name"]]["hash"]
                key = self.key(generation, digest)
            else:
                self.require(local["checkpoint"] is not None, "NO_OBSERVED_CHECKPOINT")
                entry = local["checkpoint"]["body"]["entries"][step.get("index", 0)]
                generation, digest, key = entry["generation"], entry["hash"], entry["key"]
            self.require(self.retired(head, generation), "GENERATION_PROTECTED")
            self.request(state, name, "candidate_get", {"key": key, "generation": generation, "hash": digest,
                         "authority": local["view_token"]}, step)
        elif op == "capture_candidate":
            result = local["last_result"]
            self.require(result is not None and result["outcome"] == "FOUND", "NO_EXACT_CANDIDATE")
            token = state["tokens"][result["token"]]
            self.require(token["kind"] == "candidate_get", "NO_EXACT_CANDIDATE")
            request = token["request"]
            if step.get("reset", False):
                local["candidates"] = []
            local["candidates"].append({"key": request["key"], "generation": request["generation"],
                                        "hash": request["hash"], "etag": result["etag"], "get": result["token"],
                                        "disposition": "pending", "evidence": None})
            self.require(len(local["candidates"]) <= self.spec["bounds"]["candidates"], "CANDIDATE_BOUND")
        elif op == "observe_checkpoint":
            head = self.admin(local, self.profile["actors"][name])
            self.require(local["intent"] is not None, "NO_ORIGINAL_INTENT")
            if head["checkpoint"] == local["intent"]:
                self.require(self.retired(head, head["checkpoint"]["generation"]), "GENERATION_PROTECTED")
                local["checkpoint"] = {"body": copy.deepcopy(head["checkpoint"]), "head_token": local["view_token"]}
                local["checkpoint_knowledge"] = "observed_own"
            else:
                local["checkpoint"] = None
                local["checkpoint_knowledge"] = "pending_absent" if head["serial"] == local["intent_base_serial"] else "higher_fence"
        elif op == "delete":
            proof = local["checkpoint"]
            self.require(proof is not None, "NO_OBSERVED_CHECKPOINT")
            authority = state["tokens"][proof["head_token"]]["response"]["snapshot"]["body"]
            self.require(authority["life"] == "ready", "LIFECYCLE")
            entry = proof["body"]["entries"][step.get("index", 0)]
            self.require(entry["disposition"] == "pending", "ALREADY_DISPOSED")
            self.request(state, name, "delete", {"key": entry["key"], "etag": entry["etag"],
                         "generation": entry["generation"], "hash": entry["hash"], "checkpoint": proof}, step)
        elif op == "record_disposition":
            self.require(local["checkpoint"] is not None, "NO_OBSERVED_CHECKPOINT")
            result = local["last_result"]
            self.require(result is not None and result["outcome"] != "UNKNOWN", "UNKNOWN_IS_NOT_DISPOSITION")
            token = state["tokens"][result["token"]]
            index = step.get("index", 0)
            entry = local["checkpoint"]["body"]["entries"][index]
            self.require(token["request"]["key"] == entry["key"], "WRONG_DISPOSITION_KEY")
            if token["kind"] == "candidate_get" and result["outcome"] == "NO_SUCH_KEY":
                disposition = "observed_absent"
            elif token["kind"] == "delete" and token["request"]["etag"] == entry["etag"]:
                mapping = {"APPLIED": "applied", "NO_SUCH_KEY": "observed_absent", "CONFLICT": "condition_mismatch"}
                self.require(result["outcome"] in mapping, "INVALID_DELETE_DISPOSITION")
                disposition = mapping[result["outcome"]]
            else:
                raise Rejected("NOT_TYPED_EXACT_ABSENCE")
            local["dispositions"][str(index)] = {"kind": disposition, "token": result["token"]}
        elif op == "confirm_clear":
            head = self.fresh(local)
            self.require(head["checkpoint"] is None and local["clear_serial"] is not None
                         and head["serial"] >= local["clear_serial"], "CLEAR_UNOBSERVED")
            local["checkpoint"] = None
            local["checkpoint_knowledge"] = "observed_clear"
            local["dispositions"] = {}
        else:
            raise ValueError("unknown sweep instruction " + op)

    def network(self, state, identifier, choice):
        token = state["tokens"][identifier]
        self.require(token["stage"] == "pending", "REQUEST_ALREADY_DELIVERED")
        if choice == "discard":
            token["stage"] = "discarded"
            return
        request = token["request"]
        kind = token["kind"]
        if kind == "head_get":
            if state["authority_fault"] == "unavailable":
                response = {"outcome": "UNAVAILABLE"}
            elif state["head"] is None:
                response = {"outcome": "NO_SUCH_KEY"}
            else:
                view = snapshot(state["head"])
                if state["authority_fault"] == "wrong_scope":
                    view["body"]["scope"]["tenant"] += 1
                    view["etag"] = head_tag(view["body"])
                elif state["authority_fault"] == "malformed":
                    view["etag"] = '"not-the-body-etag"'
                response = {"outcome": "FOUND", "snapshot": view}
        elif kind == "head_cas":
            base = request["base"]
            matches = state["head"] is None if base is None else state["head"] is not None and head_tag(state["head"]) == base["etag"]
            response = {"outcome": "APPLIED" if matches else "CONFLICT"}
            if matches:
                state["head"] = copy.deepcopy(request["body"])
                response["etag"] = head_tag(state["head"])
        elif kind in ("object_get", "candidate_get"):
            value = state["objects"].get(request["key"])
            if kind == "candidate_get" and state["candidate_fault"] is not None:
                response = {"outcome": state["candidate_fault"]}
            else:
                response = {"outcome": "NO_SUCH_KEY"} if value is None else {"outcome": "FOUND", **copy.deepcopy(value)}
        elif kind == "object_put":
            if request["key"] in state["objects"]:
                response = {"outcome": "CONFLICT"}
            else:
                # Object tags are opaque and can differ on identical recreation.
                tag = '"object:' + fingerprint([identifier, request["key"], request["raw"]]) + '"'
                state["objects"][request["key"]] = {"raw": request["raw"], "etag": tag}
                response = {"outcome": "APPLIED", "etag": tag}
        elif kind == "delete":
            value = state["objects"].get(request["key"])
            if value is None:
                response = {"outcome": "NO_SUCH_KEY"}
            elif value["etag"] != request["etag"]:
                response = {"outcome": "CONFLICT"}
            else:
                del state["objects"][request["key"]]
                response = {"outcome": "APPLIED"}
        else:
            raise ValueError("unknown request kind " + kind)
        token["stage"], token["response"] = "applied", response
