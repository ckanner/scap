"""Independent raw-history observer for the HEAD9 finite proposal.

This file imports neither the transition model nor its scheduler. It rebuilds
exact object contents, original conditions, process knowledge, closure edges,
authorization observations and accepted records from the event stream.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


class Violation(Exception):
    def __init__(self, rule, index, detail=""):
        self.rule, self.index = rule, index
        super().__init__(f"event {index}: {rule}: {detail}")


def audit(history):
    objects, calls, reads, processes, attempts, validations = {}, {}, {}, {}, {}, {}
    principals, maximum, seen_etags, provision_rights, target_admissions = {}, 0, set(), {}, {}
    accepted_points, complete_records, active_targets = {}, set(), set()
    terminal_scopes = set()
    index = 0
    counts = {"events": 0, "head_effects": 0, "completed_copies": 0, "target_ready": 0,
              "cold_reads": 0, "expired_reads": 0, "budget_failures": 0, "unknown": 0}

    def need(condition, rule, detail=""):
        if not condition:
            raise Violation(rule, index, detail)

    def observation(identifier, call=None, present=True):
        need(identifier in reads and reads[identifier].get("response") is not None, "known_observation", str(identifier))
        read = reads[identifier]
        if call is not None:
            need(read["actor"] == call["actor"] and read["process"] == call["process"], "same_process_knowledge")
        result = read["response"]
        if present:
            need(result["status"] == "present", "exact_dependency", read["key"])
        return result

    def body(identifier, call=None):
        return observation(identifier, call)["body"]

    def permissions(head, actor, read=False):
        grant = head.get("policy", {}).get(str(principals[actor]), {})
        need(grant.get("admin") and (not read or grant.get("read")), "current_permission")

    def point_entry(descriptor):
        return {"ref": {"creator": descriptor["creator"], "operation": descriptor["operation"],
                         "capture_serial": descriptor["capture_serial"], "descriptor_hash": sha(descriptor)},
                "label": descriptor["label"], "point": descriptor["point"]}

    def check_head(head):
        need(0 < head["revision"] <= head["serial"] <= maximum, "head_counters")
        need(0 < head["A"] <= head["M"] <= head["serial"], "generation_counters")
        sweep = head.get("sweep")
        q = 0 if sweep is None else 2 if any(item["disposition"] == "pending" for item in sweep["entries"]) else 1
        pending, delete, seal = int(head.get("owner_pending", False)), int(head["lifecycle"] != "deleted"), int(head["terminal"] is None)
        need(head["revision"] + pending + delete <= maximum and head["serial"] +
             len(head.get("snapshots", [])) + pending + int(head.get("plan") is not None) + q + delete + seal <= maximum,
             "cleanup_reserve")
        if head["kind"] == "source_head":
            entries = head["snapshots"]
            serials = [entry["ref"]["capture_serial"] for entry in entries]
            need(serials == sorted(set(serials)), "snapshot_identity")
            need(len({entry["label"] for entry in entries}) == len(entries), "snapshot_label")
            need(all(0 < entry["point"]["revision"] < entry["ref"]["capture_serial"] <= head["serial"]
                     and entry["point"]["sequence"] <= head["sequence"] for entry in entries), "snapshot_point")
            need(len(entries) <= head["limits"]["max_points"] <= 2 and
                 sum(entry["point"]["pages"] for entry in entries) <= head["limits"]["max_pages"] <= 6,
                 "persisted_snapshot_limits")
            need(head["plan"] is None or sweep is None, "copy_checkpoint_exclusion")
            if head["plan"]:
                plan = head["plan"]
                need(plan["source"] == head["A"] < plan["target"] == head["M"], "copy_namespace")
                need(plan["basis"] == {name: head[name] for name in
                     ("root", "pages", "sequence", "snapshots", "limits", "quota")}, "copy_basis")
            if head["terminal"] is not None:
                need(not entries and head["plan"] is None, "terminal_retained_roots")
        else:
            need(head["requests"] == [] and head["request_epoch"] == 1 and head["sequence"] == 0
                 and not head["active"] and head["owner"] == 0, "new_identity")
        if head["terminal"] is not None:
            need(head["lifecycle"] == "deleted" and max(head["M"], head["revision"]) < head["terminal"] <= head["serial"],
                 "terminal_monotonicity")

    def tree(scope, generation, point, read_ids=None, actor_call=None, after=-1):
        frames = {}
        if read_ids is not None:
            for identifier in read_ids:
                value = observation(identifier, actor_call)
                need(reads[identifier]["response_index"] > after, "fresh_copy_prefix")
                object_key = reads[identifier]["key"]
                prefix = f"data/{scope}/{generation}/"
                need(object_key.startswith(prefix), "closure_scope")
                need(object_key == prefix + sha(value["body"]), "content_hash")
                frames[sha(value["body"])] = value["body"]
        else:
            prefix = f"data/{scope}/{generation}/"
            frames = {object_key.removeprefix(prefix): value["body"] for object_key, value in objects.items()
                      if object_key.startswith(prefix)}
        root = frames.get(point["root"])
        need(root is not None, "complete_tree", "manifest")
        need(root["kind"] == "manifest" and root["scope"] == scope and root["count"] == point["pages"]
             and len(root["pages"]) == point["pages"], "per_root_geometry")
        values = []
        for number, edge in enumerate(root["pages"], 1):
            page = frames.get(edge["hash"])
            need(page is not None, "complete_tree", str(number))
            need(edge["number"] == number and page["kind"] == "page" and page["scope"] == scope
                 and page["number"] == number and sha(page) == edge["hash"], "per_root_geometry")
            values.append(page["value"])
        return values

    def source_roots(head):
        return [{"root": head["root"], "pages": head["pages"]}, *[entry["point"] for entry in head["snapshots"]]]

    def view(evidence, call):
        first = observation(evidence["name1"], call, present=False)
        second = observation(evidence["name2"], call, present=False)
        target = observation(evidence["target"], call, present=False)
        need(first == second and reads[evidence["name1"]]["response_index"] <
             reads[evidence["target"]]["invoke_index"] < reads[evidence["name2"]]["invoke_index"], "stable_target_view")
        return second, target

    def original_head(call):
        value = observation(call["evidence"]["head"], call)
        need(call["key"] == reads[call["evidence"]["head"]]["key"] and call["condition"] == value["etag"],
             "original_head_etag")
        need(call["body"]["serial"] == value["body"]["serial"] + 1, "one_head_step")
        check_head(call["body"])
        return value["body"]

    def preserved(old, new, fields):
        expected = deepcopy(old)
        for field in fields:
            expected[field] = new[field]
        need(expected == new, "preserved_authority_fields", ",".join(fields))

    def stable_source(evidence, call):
        first, second = observation(evidence["head1"], call), observation(evidence["head2"], call)
        need(first == second, "stable_source_barrier")
        need(reads[evidence["head1"]]["response_index"] < reads[evidence["descriptor"]]["invoke_index"]
             and reads[evidence["proof"]]["response_index"] < reads[evidence["head2"]]["invoke_index"], "stable_source_barrier")
        return second["body"]

    def retained_or_released(entry, head, descriptor, proof):
        need(descriptor["status"] == "present" and point_entry(descriptor["body"]) == entry, "snapshot_descriptor_binding")
        same_identity = [item for item in head["snapshots"] if
                         (item["ref"]["creator"], item["ref"]["operation"]) ==
                         (entry["ref"]["creator"], entry["ref"]["operation"])]
        need(not same_identity or same_identity == [entry], "snapshot_descriptor_binding")
        if entry in head["snapshots"]:
            return "retained"
        if (proof["status"] == "present" and proof["body"] ==
            {"kind": "snapshot_accepted", "scope": "source", "entry": entry}
                and head["serial"] > entry["ref"]["capture_serial"]):
            return "released_observed"
        return "fenced_unknown"

    def check_candidate(call):
        kind, value, evidence, actor = call["kind"], call["body"], call["evidence"], call["actor"]
        need(call["process"] == processes[actor], "fresh_process_candidate")
        if kind in ("restore_descriptor", "reserve", "provision", "completion", "install_copied", "bind", "ready",
                    "abort_accept", "abort_fence", "abort_absent", "abort_proof", "abort_release"):
            admission = target_admissions.get(evidence.get("target_admission"))
            need(admission is not None and admission["allowed"] and admission["actor"] == actor
                 and admission["process"] == call["process"], "fresh_target_permission")
            if kind == "restore_descriptor":
                target_descriptor = value
            elif kind == "completion":
                need(evidence["attempt"] in attempts, "full_copy_capability")
                target_descriptor = attempts[evidence["attempt"]]["descriptor"]
            else:
                target_descriptor = body(evidence["descriptor"] if kind == "reserve" else evidence["target_descriptor"], call)
            need(target_descriptor["input"]["creator"] == admission["creator"] == principals[actor]
                 and target_descriptor["input"]["scope"] == admission["scope"], "fresh_target_permission")
        if kind == "payload":
            scope, generation = call["inputs"]["scope"], call["inputs"]["generation"]
            need(call["condition"] == "absent" and value["scope"] == scope
                 and call["key"] == f"data/{scope}/{generation}/{sha(value)}", "payload_scope")
            return
        if kind == "gc_delete":
            head = body(evidence["head"], call)
            obj = observation(evidence["object"], call)
            generation, scope = call["inputs"]["generation"], call["inputs"]["scope"]
            need(0 < generation <= head["M"] and (head["terminal"] is not None or
                 (generation != head["A"] and (head.get("plan") is None or generation != head["plan"]["target"]))),
                 "permanent_retirement")
            original = obj["etag"]
            if "checkpoint" in evidence:
                checkpoint = body(evidence["checkpoint"], call)["sweep"]
                matches = [item for item in checkpoint["entries"] if item["key"] == call["key"]]
                need(len(matches) == 1 and checkpoint["generation"] == generation, "original_checkpoint")
                original = matches[0]["etag"]
            need(call["key"].startswith(f"data/{scope}/{generation}/") and value is None
                 and call["condition"] == original and reads[evidence["object"]]["key"] == call["key"], "original_delete_etag")
            return
        if kind in ("checkpoint", "settle", "clear"):
            old = original_head(call)
            if kind == "checkpoint":
                sweep = value["sweep"]
                g = sweep["generation"]
                need(old.get("sweep") is None and old.get("plan") is None and sweep["serial"] == value["serial"]
                     and 0 < g <= old["M"] and (old["terminal"] is not None or g != old["A"]), "original_checkpoint")
                expected = [{"key": reads[identifier]["key"], "etag": observation(identifier, call)["etag"],
                             "disposition": "pending"} for identifier in evidence["objects"]]
                need(expected == sweep["entries"] and expected, "original_checkpoint")
            elif kind == "settle":
                expected = deepcopy(old["sweep"])
                pending_entries = [item for item in expected["entries"] if item["disposition"] == "pending"]
                need(len(pending_entries) == len(evidence["outcomes"]), "whole_batch_settle")
                for item, outcome in zip(pending_entries, evidence["outcomes"]):
                    observed = observation(outcome["read"], call, False)
                    if outcome["delete"] is None:
                        need(observed["status"] == "missing", "typed_disposition")
                        item["disposition"] = "absent"
                    else:
                        deleted = calls[outcome["delete"]]
                        need(deleted.get("response", {}).get("status") in ("applied", "conflict")
                             and deleted["condition"] == item["etag"], "unknown_not_disposition")
                        item["disposition"] = "applied" if deleted["response"]["status"] == "applied" else "mismatch"
                need(expected == value["sweep"], "whole_batch_settle")
            else:
                need(old["sweep"] is not None and not any(item["disposition"] == "pending" for item in old["sweep"]["entries"])
                     and value["sweep"] is None, "settled_before_clear")
            preserved(old, value, ("serial", "sweep"))
            return
        if kind == "snapshot_descriptor":
            head = observation(evidence["head"], call)
            permissions(head["body"], actor, True)
            need(call["condition"] == "absent" and value["base"] == head["body"] and value["etag"] == head["etag"], "snapshot_original_basis")
            need(value["capture_serial"] == head["body"]["serial"] + 1 and value["point"] ==
                 {"root": head["body"]["root"], "pages": head["body"]["pages"], "sequence": head["body"]["sequence"],
                  "revision": head["body"]["revision"]}, "snapshot_original_basis")
            need(observation(evidence["prior"], call, False)["status"] == "missing"
                 and observation(evidence["proof"], call, False)["status"] == "missing", "missing_is_not_rebuild")
            need(head["body"]["lifecycle"] == "ready" and not head["body"]["owner_pending"] and head["body"]["plan"] is None,
                 "snapshot_admission")
            return
        if kind == "snapshot_accepted":
            head = body(evidence["head"], call)
            permissions(head, actor)
            need(call["condition"] == "absent" and value["entry"] in head["snapshots"]
                 and value == {"kind": "snapshot_accepted", "scope": "source", "entry": value["entry"]}, "accepted_snapshot_proof")
            return
        if kind in ("snapshot_capture", "snapshot_release", "sql", "quota", "limits", "delete", "revoke", "grant",
                    "compact_begin", "compact_seal", "compact_promote", "compact_abort", "terminal"):
            old = original_head(call)
            if old["kind"] == "source_head":
                permissions(old, actor, kind == "snapshot_capture")
            need(old["terminal"] is None, "terminal_monotonicity")
            if kind == "snapshot_capture":
                descriptor = body(evidence["descriptor"], call)
                need(old == descriptor["base"] and call["condition"] == descriptor["etag"], "snapshot_original_basis")
                entry = point_entry(descriptor)
                need(value["snapshots"] == old["snapshots"] + [entry], "snapshot_identity")
                preserved(old, value, ("serial", "snapshots"))
            elif kind == "snapshot_release":
                removed = [item for item in old["snapshots"] if item not in value["snapshots"]]
                need(len(removed) == 1 and value["snapshots"] == [item for item in old["snapshots"] if item != removed[0]], "snapshot_release_exact")
                need("proof" in evidence, "release_proof_before_remove")
                need(body(evidence["proof"], call) == {"kind": "snapshot_accepted", "scope": "source", "entry": removed[0]}, "release_proof_before_remove")
                need(old["plan"] is None and not old["owner_pending"], "copy_freezes_roots")
                preserved(old, value, ("serial", "snapshots"))
            elif kind in ("revoke", "grant", "quota", "limits", "delete", "sql"):
                need(value["revision"] == old["revision"] + 1, "business_revision")
                field = {"revoke": "policy", "grant": "policy", "quota": "quota", "limits": "limits", "delete": "lifecycle"}.get(kind)
                if kind == "sql":
                    need(value["sequence"] == old["sequence"] + 1 and value["pages"] <= value["quota"], "business_root")
                    tree("source", value["A"], value, evidence["payload"], call)
                    preserved(old, value, ("serial", "revision", "sequence", "root", "pages"))
                else:
                    preserved(old, value, ("serial", "revision", field))
                if kind not in ("revoke", "grant"):
                    need(old["plan"] is None, "copy_freezes_roots")
            elif kind == "compact_begin":
                need(old["plan"] is None and old["lifecycle"] == "ready" and value["M"] == old["M"] + 1
                     and value["plan"]["phase"] == "copying", "copy_allocation")
                preserved(old, value, ("serial", "M", "plan"))
            elif kind == "compact_seal":
                need(old["plan"] and old["plan"]["phase"] == "copying" and value["plan"]["phase"] == "sealed", "copy_phase")
                for point in source_roots(old):
                    tree("source", old["plan"]["target"], point, evidence["closure"], call)
                old_plan = deepcopy(old["plan"])
                old_plan["phase"] = "sealed"
                need(value["plan"] == old_plan, "copy_basis")
                preserved(old, value, ("serial", "plan"))
            elif kind == "compact_promote":
                need(old["plan"] and old["plan"]["phase"] == "sealed" and value["plan"] is None
                     and value["A"] == old["plan"]["target"], "complete_before_promote")
                preserved(old, value, ("serial", "A", "plan"))
            elif kind == "compact_abort":
                need(old["plan"] is not None and value["plan"] is None, "copy_abort")
                preserved(old, value, ("serial", "plan"))
            elif kind == "terminal":
                need(old["lifecycle"] == "deleted" and not old.get("snapshots"), "terminal_retained_roots")
                if old["kind"] == "target_head":
                    proof = body(evidence["proof"], call)
                    need(old["creator"] == principals[actor] and proof["barrier"] == "own_deleted"
                         and proof["descriptor"] == old["origin"]["descriptor"] and proof["head"] ==
                         {field: old[field] for field in ("scope", "revision", "lifecycle", "origin", "root", "pages", "creator")},
                         "actual_terminal_source")
                need(value["terminal"] == value["serial"], "terminal_monotonicity")
                preserved(old, value, ("serial", "terminal"))
            return
        if kind == "restore_descriptor":
            source = body(evidence["source"], call)
            permissions(source, actor, True)
            need(call["condition"] == "absent" and value["input"]["source"] in source["snapshots"], "restore_source_admission")
            need(point_entry(body(evidence["snapshot_descriptor"], call)) == value["input"]["source"], "snapshot_descriptor_binding")
            need(value["target_acl"] == principals[actor] == value["input"]["creator"]
                 and value["target_sequence"] == 0 and value["target_request_epoch"] == 1, "new_identity")
            return
        if kind == "reserve":
            descriptor = body(evidence["descriptor"], call)
            previous = observation(evidence["name"], call, False)
            need(value["descriptor"] == sha(descriptor) and value["scope"] == descriptor["input"]["scope"]
                 and value["state"] == "reserved", "first_winner_recipe")
            need((previous["status"] == "missing" and call["condition"] == "absent" and value["revision"] == 1)
                 or (previous["status"] == "present" and previous["body"]["state"] == "tombstone"
                     and call["condition"] == previous["etag"] and value["revision"] == previous["body"]["revision"] + 1),
                 "original_name_etag")
            need(descriptor["input"]["expected_name_revision"] ==
                 (None if previous["status"] == "missing" else previous["body"]["revision"]), "original_name_revision")
            return
        if kind in ("provision", "abort_absent"):
            name, target = view(evidence, call)
            need(target["status"] == "missing" and call["condition"] == "absent", "original_head_absent")
            need(name["status"] == "present" and name["body"]["state"] ==
                 ("reserved" if kind == "provision" else "aborting") and value["origin"]["descriptor"] == name["body"]["descriptor"],
                 "target_name_authority")
            need(value["origin"]["phase"] == "copying" and value["pages"] == 0
                 and value["lifecycle"] == ("provisioning" if kind == "provision" else "deleted"), "provisioning_not_ready")
            check_head(value)
            return
        if kind == "completion":
            need(evidence["attempt"] in attempts and evidence["validation"] in validations, "full_copy_capability")
            attempt = attempts[evidence["attempt"]]
            need(attempt["actor"] == actor and attempt["process"] == call["process"] and not attempt["failed"], "fresh_copy_prefix")
            validation = validations[evidence["validation"]]
            need(validation["attempt"] == evidence["attempt"] and evidence["validation"] < reads[evidence["head1"]]["invoke_index"], "authorization_after_copy")
            head = stable_source(evidence, call)
            permissions(head, actor, True)
            entry = attempt["descriptor"]["input"]["source"]
            state = retained_or_released(entry, head, observation(evidence["descriptor"], call, False),
                                        observation(evidence["proof"], call, False))
            need(state in ("retained", "released_observed"), "accepted_source_point")
            need(value == {"kind": "completion", "descriptor": sha(attempt["descriptor"]), "source": entry,
                           "scope": attempt["descriptor"]["input"]["scope"], "root": validation["root"],
                           "pages": entry["point"]["pages"], "request_epoch": 1, "requests": [], "rewrap_version": 1}, "completion_binding")
            need(call["condition"] == "absent", "immutable_control")
            return
        if kind in ("install_copied", "ready", "abort_fence"):
            name, target = view(evidence, call)
            old = original_head(call)
            need(target["status"] == "present" and target["body"] == old and old["lifecycle"] == "provisioning", "target_phase")
            need(name["status"] == "present" and name["body"]["descriptor"] == old["origin"]["descriptor"], "first_winner_recipe")
            if kind == "install_copied":
                completion = body(evidence["completion"], call)
                need(name["body"]["state"] == "reserved" and old["origin"]["phase"] == "copying", "target_abort_barrier")
                need(sha(completion) in complete_records and completion["descriptor"] == old["origin"]["descriptor"], "accepted_completion")
                need(observation(evidence["head2"], call) == target, "stable_target_head")
                tree(value["scope"], 1, completion, evidence["closure"], call)
                need(value["root"] == completion["root"] and value["pages"] == completion["pages"] and value["origin"] ==
                     {"descriptor": old["origin"]["descriptor"], "phase": "copied", "completion": sha(completion)}, "completion_binding")
                preserved(old, value, ("serial", "root", "pages", "origin"))
            elif kind == "ready":
                need(name["body"]["state"] == "bound" and old["origin"]["phase"] == "copied"
                     and old["origin"]["completion"] in complete_records, "restore_recipe_before_ready")
                need("completion" in evidence and sha(body(evidence["completion"], call)) == old["origin"]["completion"], "referenced_completion")
                tree(value["scope"], 1, value, evidence["closure"], call)
                need(value["revision"] == 2 and value["lifecycle"] == "ready", "target_phase")
                preserved(old, value, ("serial", "revision", "lifecycle"))
            else:
                need(name["body"]["state"] == "aborting" and value["lifecycle"] == "deleted"
                     and value["revision"] == old["revision"] + 1, "target_abort_barrier")
                preserved(old, value, ("serial", "revision", "lifecycle"))
            return
        if kind in ("bind", "abort_accept", "abort_release"):
            name, target = view(evidence, call)
            need(name["status"] == "present" and call["condition"] == name["etag"]
                 and value["revision"] == name["body"]["revision"] + 1, "original_name_etag")
            if kind == "bind":
                need(name["body"]["state"] == "reserved" and target["status"] == "present"
                     and target["body"]["origin"]["phase"] == "copied"
                     and target["body"]["origin"]["completion"] in complete_records, "restore_recipe_before_bind")
                need("completion" in evidence and sha(body(evidence["completion"], call)) == target["body"]["origin"]["completion"], "referenced_completion")
                need(value["state"] == "bound", "target_name_authority")
            elif kind == "abort_accept":
                need(name["body"]["state"] == "reserved" and value["state"] == "aborting", "target_abort_barrier")
            else:
                proof = body(evidence["proof"], call)
                need(name["body"]["state"] == "aborting" and value["state"] == "tombstone"
                     and value["proof"] == sha(proof) and proof["descriptor"] == value["descriptor"], "actual_abort_proof")
            preserved(name["body"], value, ("revision", "state") if kind != "abort_release" else ("revision", "state", "proof"))
            return
        if kind == "abort_proof":
            name, target = view(evidence, call)
            need(name["status"] == "present" and name["body"]["state"] == "aborting" and target["status"] == "present", "actual_abort_proof")
            if value["barrier"] == "own_deleted":
                need(target["body"]["lifecycle"] == "deleted" and target["body"]["origin"]["descriptor"] == value["descriptor"], "actual_abort_proof")
            else:
                need(target["body"].get("origin", {}).get("descriptor") != value["descriptor"], "foreign_not_owned")
            need(value["head"] == {field: target["body"][field] for field in
                 ("scope", "revision", "lifecycle", "origin", "root", "pages", "creator")}
                 and call["condition"] == "absent", "actual_abort_proof")
            return
        need(False, "known_candidate", kind)

    for index, event in enumerate(history["events"]):
        counts["events"] += 1
        kind = event["event"]
        if kind == "initial":
            need(index == 0, "single_initial")
            objects = deepcopy(event["objects"])
            principals, maximum = event["principals"], event["maximum"]
            provision_rights = {int(principal): allowed for principal, allowed in event["provision_rights"].items()}
            processes = {actor: 0 for actor in principals}
            seen_etags = {value["etag"] for value in objects.values()}
            for object_key, value in objects.items():
                if object_key.startswith("head/"):
                    check_head(value["body"])
            continue
        if kind == "get_invoke":
            need(event["id"] not in reads and event["process"] == processes[event["actor"]], "fresh_get")
            reads[event["id"]] = {**deepcopy(event), "invoke_index": index}
        elif kind == "get_effect":
            need(event["id"] in reads and "effect" not in reads[event["id"]], "one_get_effect")
            read, result = reads[event["id"]], event["result"]
            actual = objects.get(read["key"])
            if result["status"] not in ("unknown", "transport", "budget", "semantic"):
                expected = {"status": "missing"} if actual is None else {"status": "present", **actual}
                need(result == expected, "exact_get", read["key"])
            read["effect"] = deepcopy(result)
        elif kind == "get_response":
            need(event["id"] in reads and "response" not in reads[event["id"]], "one_get_response")
            read, result = reads[event["id"]], event["result"]
            need(result == {"status": "unknown"} or result == read.get("effect"), "get_delivery")
            read.update(response=deepcopy(result), response_index=index)
        elif kind == "candidate":
            need(event["id"] not in calls, "unique_candidate")
            calls[event["id"]] = deepcopy(event)
            check_candidate(calls[event["id"]])
        elif kind == "put_invoke":
            need(event["id"] in calls and not calls[event["id"]].get("invoked"), "single_invocation")
            call = calls[event["id"]]
            need(call["process"] == processes[call["actor"]], "fresh_process_invocation")
            call["invoked"] = index
        elif kind == "put_effect":
            need(event["id"] in calls and calls[event["id"]].get("invoked") and "effect" not in calls[event["id"]], "single_effect")
            call, result = calls[event["id"]], event["result"]
            old = objects.get(call["key"])
            match = (old is None if call["condition"] == "absent" else old is not None and old["etag"] == call["condition"])
            need(result["status"] == ("applied" if match else "conflict"), "conditional_effect")
            if match:
                need(result["etag"] not in seen_etags, "etag_no_aba")
                seen_etags.add(result["etag"])
                if call["body"] is None:
                    objects.pop(call["key"], None)
                else:
                    objects[call["key"]] = {"body": deepcopy(call["body"]), "etag": result["etag"]}
                if call["key"].startswith("head/"):
                    counts["head_effects"] += 1
                    head = call["body"]
                    check_head(head)
                    if old:
                        need(head["A"] >= old["body"]["A"] and head["M"] >= old["body"]["M"], "generation_monotonicity")
                    if head["scope"] in terminal_scopes:
                        need(head["terminal"] is not None, "terminal_monotonicity")
                    if head["terminal"] is not None:
                        terminal_scopes.add(head["scope"])
                    if call["kind"] == "compact_promote":
                        for point in source_roots(head):
                            tree("source", head["A"], point)
                    if call["kind"] == "snapshot_capture":
                        for entry in head["snapshots"]:
                            identity = canonical(entry["ref"])
                            need(identity not in accepted_points or accepted_points[identity] == entry, "snapshot_identity")
                            accepted_points[identity] = deepcopy(entry)
                    if call["kind"] == "ready":
                        counts["target_ready"] += 1
                        active_targets.add(head["scope"])
                if call["kind"] == "completion":
                    complete_records.add(sha(call["body"]))
            call["effect"] = deepcopy(result)
        elif kind == "put_response":
            need(event["id"] in calls and "response" not in calls[event["id"]], "one_put_response")
            call, result = calls[event["id"]], event["result"]
            need(result == {"status": "unknown"} or result == call.get("effect"), "unknown_not_ack")
            call["response"] = deepcopy(result)
            counts["unknown"] += int(result["status"] == "unknown")
        elif kind == "crash":
            need(event["process"] == processes[event["actor"]] + 1, "process_epoch")
            processes[event["actor"]] = event["process"]
        elif kind == "provision_right":
            provision_rights[event["principal"]] = event["allowed"]
        elif kind == "target_admission":
            allowed = principals[event["actor"]] == event["creator"] and provision_rights.get(event["creator"], False)
            need(event["process"] == processes[event["actor"]] and event["allowed"] == allowed, "fresh_target_permission")
            target_admissions[index] = deepcopy(event)
        elif kind == "copy_start":
            need(event["id"] not in attempts and event["process"] == processes[event["actor"]], "fresh_copy_prefix")
            source = body(event["source"])
            permissions(source, event["actor"], True)
            admission = target_admissions.get(event.get("target_admission"))
            need(admission is not None and admission["allowed"] and admission["actor"] == event["actor"]
                 and admission["process"] == event["process"], "fresh_target_permission")
            need(body(event["target_descriptor"], event) == event["descriptor"] and
                 admission["creator"] == event["descriptor"]["input"]["creator"] and
                 admission["scope"] == event["descriptor"]["input"]["scope"], "fresh_target_permission")
            need(event["descriptor"]["input"]["source"] in source["snapshots"] and source["terminal"] is None, "restore_source_admission")
            pseudo = {"actor": event["actor"], "process": event["process"]}
            name, target = view(event, pseudo)
            need(name["status"] == "present" and name["body"]["state"] == "reserved"
                 and target["status"] == "present" and target["body"]["lifecycle"] == "provisioning"
                 and target["body"]["origin"]["phase"] == "copying"
                 and name["body"]["descriptor"] == target["body"]["origin"]["descriptor"] == sha(event["descriptor"]),
                 "own_slot_before_large_copy")
            attempts[event["id"]] = {**deepcopy(event), "start_index": index, "failed": False}
        elif kind == "copy_validated":
            need(event["attempt"] in attempts, "fresh_copy_prefix")
            attempt = attempts[event["attempt"]]
            need(attempt["process"] == processes[attempt["actor"]] and not attempt["failed"], "fresh_copy_prefix")
            source = body(attempt["source"])
            point = attempt["descriptor"]["input"]["source"]["point"]
            scope = attempt["descriptor"]["input"]["scope"]
            source_values = tree("source", source["A"], point, event["source_reads"], attempt, attempt["start_index"])
            target_values = tree(scope, 1, {"root": event["root"], "pages": event["pages"]},
                                 event["target_reads"], attempt, attempt["start_index"])
            need(event["pages"] == point["pages"] and source_values == target_values, "complete_independent_copy")
            need(len(event["source_reads"]) <= attempt["budget"], "payload_budget")
            validations[index] = deepcopy(event)
            counts["completed_copies"] += 1
        elif kind == "copy_failure":
            need(event["attempt"] in attempts, "fresh_copy_prefix")
            attempt = attempts[event["attempt"]]
            attempt["failed"] = True
            domain, cause, result = event["domain"], event["cause"], event["result"]
            if cause == "budget":
                need(result == "Budget" and event["probe"] is None, "budget_not_corruption")
                counts["budget_failures"] += 1
            elif cause == "semantic":
                need(result == "Corrupt" and event["probe"] is None, "semantic_not_expired")
            elif domain != "source":
                need(result != "SnapshotExpired" and event["probe"] is None, "failure_provenance")
            elif result == "SnapshotExpired":
                need(event["read"] is not None and observation(event["read"], present=False)["status"] in ("missing", "transport"), "physical_before_expiry")
                old = body(attempt["source"])
                fresh = body(event["probe"])
                need(reads[event["probe"]]["invoke_index"] > reads[event["read"]]["response_index"], "fresh_retirement_proof")
                need(fresh["serial"] >= old["serial"] and fresh["M"] >= old["M"] and fresh["A"] >= old["A"]
                     and old["A"] <= fresh["M"] and (fresh["terminal"] is not None or
                     (old["A"] != fresh["A"] and (fresh["plan"] is None or old["A"] != fresh["plan"]["target"]))), "fresh_retirement_proof")
                counts["expired_reads"] += 1
        elif kind == "copy_abandoned":
            need(event["attempt"] in attempts and event["reason"] in ("Denied", "Conflict", "Corrupt", "Incomplete"), "known_abandoned_attempt")
            attempts[event["attempt"]]["failed"] = True
        elif kind == "snapshot_observation":
            pseudo = {"actor": event["actor"], "process": processes[event["actor"]]}
            head = stable_source(event, pseudo)
            permissions(head, event["actor"])
            expected = retained_or_released(event["entry"], head, observation(event["descriptor"], present=False),
                                            observation(event["proof"], present=False))
            need(event["result"] == expected and not event["historical_ack"], "historical_observation_not_ack")
        elif kind == "cold_target":
            name = observation(event["name2"])
            target = observation(event["target"])["body"]
            need(name["body"]["state"] == "bound" and target["lifecycle"] == "ready"
                 and target["scope"] in active_targets, "target_ready_authority")
            need(target["creator"] == principals[event["actor"]] and
                 name["body"]["descriptor"] == target["origin"]["descriptor"] == sha(event["descriptor"]), "fresh_target_permission")
            actual = tree(target["scope"], target["A"], target, event["closure"])
            need(actual == event["values"] and event["requests"] == [], "cold_independent_target")
            counts["cold_reads"] += 1
        elif kind == "operator_fault":
            if event["value"] is None:
                objects.pop(event["key"], None)
            else:
                objects[event["key"]] = deepcopy(event["value"])
                seen_etags.add(event["value"]["etag"])
        elif kind == "rejected":
            # Candidate-level successes are proven above. These negative API
            # observations are checked only for the explicitly modeled barrier.
            if event["operation"] in ("completion_barrier", "snapshot_observe") and "head1" in event:
                need(observation(event["head1"]) != observation(event["head2"]) and event["code"] == "Conflict", "barrier_before_corrupt")
        else:
            need(False, "known_event", kind)
    need(history["events"] and history["events"][0]["event"] == "initial", "single_initial")
    return counts


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("history", type=Path)
    args = parser.parse_args()
    print(canonical(audit(json.loads(args.history.read_text()))))


if __name__ == "__main__":
    main()
