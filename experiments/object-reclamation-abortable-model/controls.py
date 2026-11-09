"""Adversarial actual-prefix controls; accepted PR41 controls remain untouched.

Protocol controls replay an independently accepted original prefix and alter
only its final effect. Separate graph controls alter raw completeness metadata.
"""

import argparse
import copy
import gzip
import hashlib
import json
from pathlib import Path
import re
import shutil
import traceback

from oracle import audit_profile, check_edge, enabled
from oracle_protocol import Rules, encoded, etag, require


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Originals:
    def __init__(self, root, inputs):
        self.root, self.inputs, self.cache = root, inputs, None

    def read(self, name):
        if self.cache is None or self.cache[0]["id"] != name:
            fixture = next(value for value in self.inputs["profiles"] if value["id"] == name)
            with gzip.open(self.root / name / "states.jsonl.gz", "rt") as handle:
                states = [json.loads(line)["state"] for line in handle]
            with gzip.open(self.root / name / "edges.jsonl.gz", "rt") as handle:
                edges = [json.loads(line) for line in handle]
            parents = [None] * len(states)
            for edge in edges:
                if parents[edge["target"]] is None:
                    parents[edge["target"]] = edge
            self.cache = fixture, states, edges, parents
        return self.cache

    def select(self, name, predicate):
        fixture, states, edges, parents = self.read(name)
        for edge in edges:
            before, after = states[edge["source"]], states[edge["target"]]
            owner = edge["action"].get("actor")
            op = None if owner is None else fixture["actors"][owner]["program"][before["actors"][owner]["pc"]]["op"]
            context = {"before": before, "after": after, "action": edge["action"], "owner": owner, "op": op, "fixture": fixture, "edge": edge}
            if predicate(context):
                prefix, current = [], edge["source"]
                while current:
                    prior = parents[current]
                    prefix.append({"action": prior["action"], "state": states[prior["target"]]})
                    current = prior["source"]
                prefix.reverse()
                return context, prefix
        raise ValueError("control lacks an original eligible boundary: " + name)


def added(context):
    values = set(context["after"]["tokens"]) - set(context["before"]["tokens"])
    return next(iter(values)) if len(values) == 1 else None


def client(op, predicate=lambda value: True, issued=False):
    return lambda value: value["op"] == op and (not issued or added(value) is not None) and predicate(value)


def request_after(changed, context):
    return changed["tokens"][added(context)]["request"]


def local(changed, context):
    return changed["actors"][context["owner"]]


def force_request(changed, context, kind, request):
    owner = context["owner"]
    before = context["before"]["actors"][owner]
    identifier = f"{owner}:{before['pc']}"
    local(changed, context).update(pc=before["pc"] + 1, stopped=None, outcome=None, last=identifier, last_result=None)
    changed["tokens"][identifier] = {"owner": owner, "kind": kind, "request": request, "uncertain": False,
                                    "stage": "pending", "response": None, "observed": None}


def variants(inputs):
    def move_key(changed, context):
        request_after(changed, context)["key"] = request_after(changed, context)["key"].replace("/storage/1/", "/storage/2/")

    def rebind_context(changed, context):
        local(changed, context)["context"]["generation"] = 2

    def incomplete_read(changed, context):
        result = copy.deepcopy(local(changed, context)["materialized"])
        result["frames"].pop(next(iter(result["frames"])))
        local(changed, context)["outcome"]["result"] = copy.deepcopy(result)

    def active_expired(changed, context):
        actor = local(changed, context)
        actor["outcome"] = {"kind": "expired", "failure": actor["failure"], "proof": actor["view_token"]}

    def unavailable_expired(changed, context):
        actor = local(changed, context)
        actor["outcome"] = {"kind": "expired", "failure": actor["failure"], "proof": actor["context"]["head_token"]}

    def poisoned_source(changed, context):
        changed["health"]["1"] = "corrupt"

    def wrong_retirement_order(changed, context):
        actor = local(changed, context)
        actor["outcome"] = {"kind": "error", "code": "CORRUPT", "failure": actor["failure"]}
        changed["health"][str(actor["failure"]["generation"])] = "corrupt"

    def raw_reencode(changed, context):
        request = request_after(changed, context)
        body = json.loads(bytes.fromhex(request["raw"]).split(b"\n", 1)[1])
        request["raw"] = (b"MODELFRAME1\n" + encoded(body)).hex()

    def stale_copy(changed, context):
        actor = local(changed, context)
        before = context["before"]["actors"][context["owner"]]
        identifier = before["labels"]["old_verify"]
        token = changed["tokens"][identifier]
        actor.update(pc=before["pc"] + 1, stopped=None, outcome=None)
        actor["verified"][token["request"]["hash"]] = {"raw": token["response"]["raw"], "token": identifier}

    def unpublished_checkpoint(changed, context):
        before = context["before"]["actors"][context["owner"]]
        cp = before["intent"]
        entry = cp["entries"][0]
        force_request(changed, context, "delete", {"key": entry["key"], "generation": entry["generation"],
                      "hash": entry["hash"], "etag": entry["etag"],
                      "checkpoint": {"body": cp, "head_token": before["view_token"]}})

    def absent_means_fenced(changed, context):
        local(changed, context)["checkpoint_knowledge"] = "higher_fence"

    def rewrite_unknown(changed, context):
        original = next(value for value in changed["tokens"].values() if value["kind"] == "head_cas" and value["observed"] == "unknown")
        original["observed"] = "known"

    def bucket_absence(changed, context):
        actor, before = local(changed, context), context["before"]["actors"][context["owner"]]
        actor.update(pc=before["pc"] + 1, stopped=None, outcome=None)
        actor["dispositions"]["0"] = {"kind": "observed_absent", "token": before["last_result"]["token"]}

    def replacement_etag(changed, context):
        request_after(changed, context)["etag"] = '"unpersisted-new-version"'

    def rebase(changed, context):
        current = copy.deepcopy(context["before"]["head"])
        request_after(changed, context)["base"] = {"body": current, "etag": etag(current)}

    def fake_native_ack(changed, context):
        local(changed, context)["outcome"]["kind"] = "write_ack"

    def held_candidate(changed, context):
        actor = context["before"]["actors"][context["owner"]]
        rules = Rules(inputs, context["fixture"])
        force_request(changed, context, "candidate_get", {"generation": 1, "hash": rules.names["A"],
                      "key": rules.key(1, rules.names["A"]), "authority": actor["view_token"]})

    def skipped_admin(changed, context):
        actor, before = local(changed, context), context["before"]["actors"][context["owner"]]
        actor.update(pc=before["pc"] + 1, stopped=None, outcome=None,
                     checkpoint={"body": before["intent"], "head_token": before["view_token"]}, checkpoint_knowledge="observed_own")

    def false_owner_denial(changed, context):
        actor, before = local(changed, context), context["before"]["actors"][context["owner"]]
        actor.update(pc=before["pc"], stopped="DENIED", outcome={"kind": "error", "code": "DENIED"}, candidate=before["candidate"])

    def new_generation_delete_effect(changed, context):
        rules = Rules(inputs, context["fixture"])
        changed["objects"].pop(rules.key(context["before"]["head"]["A"], rules.names["A"]), None)

    def delete_pending_lost(changed, context):
        owner = context["before"]["actors"]["g"]
        changed["tokens"].pop(owner["labels"]["original_delete"])

    def wrong_scope_expired(changed, context):
        actor = local(changed, context)
        actor.update(stopped=None, pc=context["before"]["actors"][context["owner"]]["pc"]+1)
        actor["outcome"] = {"kind": "expired", "failure": actor["failure"], "proof": context["before"]["actors"]["r"]["last"]}

    def forge_success_after_stop(changed, context):
        actor = local(changed, context)
        before = context["before"]["actors"][context["owner"]]
        actor.update(pc=before["pc"]+1, stopped=None)
        if context["op"] == "ack_write":
            actor["outcome"] = {"kind": "write_ack", "receipt": actor["receipt"]}
        elif context["op"] == "ack_transition":
            actor["outcome"] = {"kind": "transition_ack", "original": before["last_result"]["token"]}
        else:
            actor["outcome"] = {"kind": "metadata_ready", "head_token": before["view_token"]}

    def forge_detached_ack(changed, context):
        local(changed, context)["outcome"]["kind"] = "write_ack"

    def inject_fault(field):
        return lambda changed, context: changed.__setitem__(field, "unavailable" if field == "authority_fault" else "UNAVAILABLE")

    def forge_quarantine(changed, context):
        changed["authority_corrupt"] = True

    def forge_mark(changed, context):
        local(changed, context)["marks"]["forged_pause"] = True

    def forge_gate(changed, context):
        local(changed, context)["local_stop"] = True

    def rebind_view(changed, context):
        local(changed, context)["view"] = None
        local(changed, context)["view_token"] = None

    def rebind_label(changed, context):
        local(changed, context)["labels"]["forged"] = next(iter(changed["tokens"]))

    def reopen_gate(changed, context):
        local(changed, context)["local_stop"] = False

    def unrelated_proof(changed, context):
        actor = local(changed, context)
        rules = Rules(inputs, context["fixture"])
        value = rules.names["C"]
        actor["frames"][value] = {"raw": rules.frames[value]["raw"], "token": context["before"]["actors"][context["owner"]]["last"]}

    def native_reexecution(changed, context):
        local(changed, context)["native"] = "executed"

    def unknown_native_commit(changed, context):
        local(changed, context)["native"] = "commit"
        context["mutation_action"] = {**context["action"], "choice": "commit"}

    cases = [
        ("A01", "full_physical_key_changed", client("object_get", issued=True), move_key, "full Scope/generation/hash key"),
        ("A01", "captured_generation_rebound", client("object_get", issued=True), rebind_context, "fact owned by another operation: context"),
        ("A01", "partial_materialized_read_success", client("return_read"), incomplete_read, "original complete materialization"),
        ("A06", "active_corruption_falsely_expired", client("classify_failure"), active_expired, "active/target/held incident weakened"),
        ("A08", "unavailable_authority_falsely_expired", client("classify_failure"), unavailable_expired, "unavailable authority invented expiry"),
        ("C01", "retired_target_poisoned_current_source", client("classify_failure", lambda c: c['after']['actors']['old']['outcome']['kind']=='expired'), poisoned_source, "poisoned a different current generation"),
        ("C01", "generation_less_than_active_only", client("classify_failure", lambda c: c['after']['actors']['old']['outcome']['kind']=='expired'), wrong_retirement_order, "retired target was misclassified"),
        ("C03", "old_target_response_adopted_into_new_plan", client("observe", lambda c: c['after']['actors']['old']['stopped']=='OLD_PLAN_RESPONSE'), stale_copy, "obsolete plan"),
        ("CP01", "delete_from_unobserved_ram_checkpoint", client("delete", lambda c: c['after']['actors']['g']['stopped']=='NO_OBSERVED_CHECKPOINT'), unpublished_checkpoint, "capability fabricated from RAM/PUT receipt"),
        ("CP02", "same_serial_absence_claimed_settled", client("observe_checkpoint", lambda c: c['after']['actors']['g']['checkpoint_knowledge']=='pending_absent'), absent_means_fenced, "same-serial absence falsely settled"),
        ("CP03", "higher_fence_rewrites_original_unknown", client("observe_checkpoint", lambda c: c['after']['actors']['g']['checkpoint_knowledge']=='higher_fence' and any(t['kind']=='head_cas' and t['observed']=='unknown' for t in c['before']['tokens'].values())), rewrite_unknown, "rewrote an original request or prior UNKNOWN"),
        ("CP04", "no_such_bucket_as_exact_absence", client("record_disposition", lambda c: c['before']['candidate_fault']=='NO_SUCH_BUCKET'), bucket_absence, "not exact-key absence"),
        ("CP04", "unavailable_as_exact_absence", client("record_disposition", lambda c: c['before']['candidate_fault']=='UNAVAILABLE'), bucket_absence, "not exact-key absence"),
        ("CP04", "clear_drops_pending_original_delete", client("confirm_clear", lambda c: c['before']['tokens'].get(c['before']['actors']['g']['labels'].get('original_delete'),{}).get('stage')=='pending'), delete_pending_lost, "dropped original pending network token"),
        ("CP04", "late_old_delete_targets_new_active", lambda c: 'network' in c['action'] and c['action']['choice']=='apply' and c['before']['tokens'][c['action']['network']]['kind']=='delete' and c['before']['actors']['g']['marks'].get('new_plan'), new_generation_delete_effect, "backend changed original token/condition/outcome"),
        ("CP05", "new_etag_deleted_without_persisted_candidate", client("delete", issued=True), replacement_etag, "not durably observed in its original batch"),
        ("H01", "retained_hold_ignored_for_sweep", client("candidate_get", lambda c: c['after']['actors'][c['owner']]['stopped']=='GENERATION_PROTECTED'), held_candidate, "admitted active/held/target generation"),
        ("T01", "fresh_checkpoint_skips_revoked_admin", client("observe_checkpoint", lambda c: c['after']['actors']['g']['stopped']=='DENIED'), skipped_admin, "skipped current admin permission"),
        ("T02", "owner_change_erases_independent_admin", client("prepare_freeze", lambda c: c['before']['head']['owner']==22 and c['after']['actors']['g']['stopped'] is None), false_owner_denial, "falsely revoked independently retained admin"),
        ("W02", "old_sql_candidate_rebased", client("send_head", lambda c: c['owner']=='w', issued=True), rebase, "differs from immutable prepared request"),
        ("W05", "native_failure_reported_as_ack", client("ack_write", lambda c: c['after']['actors']['w']['outcome']['kind']=='committed_unavailable'), fake_native_ack, "ACK preceded required native publication"),
        ("X02", "copy_reencoded_noncanonical_frame", client("copy_put", lambda c: added(c) is not None and c['after']['tokens'][added(c)]['request']['hash']==Rules(inputs,c['fixture']).names['C']), raw_reencode, "reencoded or truncated original raw frame"),
        ("X03", "wrong_scope_response_fabricates_expiry", client("observe", lambda c: c['after']['actors']['r']['stopped']=='AUTHORITY_CORRUPT' and c['before']['authority_fault']=='wrong_scope'), wrong_scope_expired, "transport observation fabricated a public success"),
        ("S01", "known_native_ack_after_local_stop", client("ack_write", lambda c: c['before']['actors']['w']['native']=='commit'), forge_success_after_stop, "public return crossed a previously closed local gate"),
        ("S02", "detached_caller_given_new_ack", client("ack_write", lambda c: c['before']['actors']['w']['native']=='commit'), forge_detached_ack, "detached caller received a new public success"),
        ("S03", "complete_ack_after_local_stop", client("ack_transition"), forge_success_after_stop, "public return crossed a previously closed local gate"),
        ("S04", "metadata_ready_after_local_stop", client("metadata_ready", lambda c: c['owner']=='r'), forge_success_after_stop, "public return crossed a previously closed local gate"),
        ("A01", "ordinary_step_changes_authority_fault", client("mark"), inject_fault('authority_fault'), "nonfixture instruction modified injected backend fault"),
        ("A01", "ordinary_step_changes_candidate_fault", client("mark"), inject_fault('candidate_fault'), "nonfixture instruction modified injected backend fault"),
        ("A01", "ordinary_step_forges_authority_quarantine", client("mark"), forge_quarantine, "instruction forged authority quarantine state"),
        ("A01", "ordinary_step_forges_pause_mark", client("object_get", issued=True), forge_mark, "fact owned by another operation: marks"),
        ("A01", "ordinary_step_forges_local_gate", client("object_get", issued=True), forge_gate, "fact owned by another operation: local_stop"),
        ("A01", "ordinary_step_rebinds_observed_view", client("object_get", issued=True), rebind_view, "fact owned by another operation: view,view_token"),
        ("A01", "ordinary_step_rebinds_token_label", client("mark"), rebind_label, "fact owned by another operation: labels"),
        ("X01", "closed_gate_reopened_to_dispatch", client("object_get", lambda c: c['before']['actors']['r']['local_stop']), reopen_gate, "fact owned by another operation: local_stop"),
        ("A01", "response_forges_unrelated_proof_entry", client("observe", lambda c: c['action']['choice']=='known' and c['before']['tokens'].get(c['before']['actors'][c['owner']]['last'],{}).get('kind')=='object_get'), unrelated_proof, "unrelated or unobserved proof map"),
        ("W01", "native_reexecution_after_finalization", client("ack_write", lambda c: c['before']['actors']['w']['native']=='commit'), native_reexecution, "fact owned by another operation: native"),
        ("W03", "native_commit_before_known_publication", client("native_publish", lambda c: not c['before']['actors']['w']['commit_known']), unknown_native_commit, "native publication before known durable CAS"),
    ]
    return cases


def run(graph, output, inputs):
    output.mkdir(parents=True, exist_ok=False)
    original = Originals(graph, inputs)
    manifest = {str(path.relative_to(graph)): sha(path) for path in graph.glob('*/result.json')}
    reports = []
    for profile_name, name, select, mutate, boundary in variants(inputs):
        context, prefix = original.select(profile_name, select)
        rules = Rules(inputs, context["fixture"])
        previous = context["fixture"]["initial"]
        for record in prefix:
            require(encoded(record["action"]) in enabled(rules, previous), "original control prefix was not enabled")
            check_edge(rules, previous, record["state"], record["action"])
            previous = record["state"]
        require(previous == context["before"], "original control prefix bound another state")
        check_edge(rules, previous, context["after"], context["action"])
        changed = copy.deepcopy(context["after"])
        mutate(changed, context)
        altered_action = context.get("mutation_action", context["action"])
        require(changed != context["after"], "negative control did not alter its original effect: " + name)
        trace = {"profile": profile_name, "control": name, "original_edge": context["edge"],
                 "prefix": prefix, "mutation": {"action": altered_action, "state": changed},
                 "expected_rejection": boundary}
        trace_path = output / (name + '.json')
        save(trace_path, trace)
        try:
            check_edge(rules, previous, changed, altered_action)
        except ValueError as error:
            require(re.search(boundary, str(error)) is not None, "control rejected at unrelated boundary: " + name + ": " + str(error))
            reports.append({"name": name, "profile": profile_name, "status": "REJECTED_AT_EXPECTED_BOUNDARY", "reason": str(error),
                            "trace_sha256": sha(trace_path), "prefix_steps": len(prefix)})
            save(output/'progress.json', {'status':'RUNNING_CONTROLS','completed':reports})
        else:
            raise ValueError("semantic counterexample was accepted: " + name)
    graph_reports = []
    fixture = next(value for value in inputs['profiles'] if value['id'] == 'X01')
    for mode in ('missing_late_network_delivery', 'duplicate_enabled_choice', 'incomplete_producer_run', 'positive_reordered_edges'):
        dest = output / mode
        shutil.copytree(graph / 'X01', dest)
        result = json.loads((dest/'result.json').read_text())
        with gzip.open(dest/'edges.jsonl.gz','rt') as handle:
            edges = [json.loads(line) for line in handle]
        if mode == 'missing_late_network_delivery':
            states = original.read('X01')[1]
            index = next(index for index, edge in enumerate(edges) if 'network' in edge['action'] and edge['action']['choice']=='apply'
                         and states[edge['source']]['actors']['r']['local_stop'])
            edges.pop(index)
        elif mode == 'duplicate_enabled_choice':
            edges.append(copy.deepcopy(edges[0]))
        elif mode == 'incomplete_producer_run':
            result['status'] = 'INCOMPLETE'
        else:
            edges.reverse()
        with gzip.open(dest/'edges.jsonl.gz','wt') as handle:
            for edge in edges:
                handle.write(json.dumps(edge,separators=(',',':'))+'\n')
        result.update(edges=len(edges), edge_file_sha256=sha(dest/'edges.jsonl.gz'))
        save(dest/'result.json',result)
        expected = None if mode == 'positive_reordered_edges' else 'producer profile is capped' if mode == 'incomplete_producer_run' else 'omitted/duplicated enabled'
        try:
            audited = audit_profile(inputs, fixture, dest, output/(mode+'-audit'))
        except ValueError as error:
            require(expected is not None and expected in str(error), "graph control rejected at unrelated boundary: "+mode+': '+str(error))
            graph_reports.append({'name':mode,'status':'REJECTED_AT_EXPECTED_BOUNDARY','reason':str(error)})
        else:
            require(expected is None, 'incomplete graph counterexample accepted: '+mode)
            graph_reports.append({'name':mode,'status':'POSITIVE_PASS','states':audited['states'],'edges':audited['edges']})
    require(manifest == {str(path.relative_to(graph)):sha(path) for path in graph.glob('*/result.json')}, 'controls altered original graph receipts')
    return {'status':'PASS_CONTROLS','semantic_negative_controls':reports,'graph_controls':graph_reports,
            'negative_count':len(reports)+3,'positive_count':1,'producer_original_unmodified':True,
            'control_scope':'original reachable prefixes plus one altered final effect; independent graph closure controls',
            'accepted_PR41_controls_changed':False}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--graph',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args()
    source=Path(__file__).resolve().parent
    inputs=json.loads((source/'inputs.json').read_text())
    require(sha(source/'inputs.json')==sha(args.graph/'source/inputs.json'),'controls use another frozen program inventory')
    source_hashes={p.name:sha(p) for p in [source/'controls.py',*source.glob('oracle*.py')]}
    try:
        report=run(args.graph,args.out,inputs)
        require(source_hashes=={name:sha(source/name) for name in source_hashes},'control/oracle source changed')
    except Exception as error:
        report={'status':'FAILED_CONTROLS','error':str(error),'traceback':traceback.format_exc()}
    report['source_sha256']=source_hashes
    save(args.out/'result.json',report)
    print(json.dumps(report,indent=2,sort_keys=True))
    raise SystemExit(0 if report['status']=='PASS_CONTROLS' else 1)


if __name__=='__main__':
    main()
