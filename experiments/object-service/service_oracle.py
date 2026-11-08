#!/usr/bin/env python3
"""Independent read-only HTTP/result/process audit; no controller imports."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import importlib.util
import json
from pathlib import Path
import signal
import sys
from urllib.parse import urlparse

from audit_wire import b64, committed, decimal, equal, fingerprint, object_exchanges, object_versions, parse, require, result

PHASES = ("initialize", "concurrent_create", "unknown_write", "resolve_unknown", "blackhole", "takeover", "recover")
FILES = ("http-client-ledger.jsonl", "process-ledger.jsonl", "inputs.jsonl", "data-inputs.jsonl",
         "acks.jsonl", "duplicate-acks.jsonl", "recoveries.jsonl", "outcomes.jsonl", "history.jsonl")


def rows(directory, name):
    raw = (directory / name).read_bytes()
    require(raw and raw.endswith(b"\n"), name + ": incomplete ledger")
    return [parse(line) for line in raw.splitlines()]


def stamp(row):
    value = row["monotonic_ns"]
    require(type(value) is int or isinstance(value, str) and value.isdecimal(), "invalid monotonic timestamp")
    value = int(value)
    require(value > 0, "invalid monotonic clock")
    return value


def only(values, message):
    require(len(values) == 1, message)
    return values[0]


def identity(value):
    require(value.get("pid_source") == "owned_Popen_child" and type(value.get("pid")) is int and value["pid"] > 0,
            "missing owned process identity")
    require(type(value.get("spawn_monotonic_ns")) is int and value["spawn_monotonic_ns"] > 0, "missing spawn clock")
    return {key: value[key] for key in ("pid", "spawn_monotonic_ns", "pid_source")}


def exited(value, status):
    require(value["wait_status"] == status, "wrong child exit status")
    usage = value["kernel_usage"]
    require(usage.get("available") is True and usage.get("source") == "kernel_wait4_owned_child", "missing kernel wait4 witness")
    require(type(usage.get("maxrss_bytes")) is int and usage["maxrss_bytes"] > 0, "invalid kernel usage")


def processes(facts, http, *, phases=PHASES, ordered=True):
    require(Counter(row["phase"] for row in http if row["event"] == "client_process_hello") == Counter(phases), "client phase self-observation set")
    require(all(row["phase"] in phases for row in http), "orphan HTTP phase")
    require([row["sequence"] for row in facts] == list(range(1, len(facts) + 1)), "missing process fact")
    require(all(stamp(left) <= stamp(right) for left, right in zip(facts, facts[1:])), "process facts reordered")
    by_event = defaultdict(list)
    for row in facts:
        by_event[row["event"]].append(row)
    # Owner names and backend role labels do not prove independent processes.
    # Count unique kernel child incarnations across every service, backend and
    # client process, including the replacement set after complete compute loss.
    incarnations, pid_lifetimes = set(), defaultdict(list)
    def register(value, end):
        observed = identity(value)
        key = (observed["pid"], observed["spawn_monotonic_ns"])
        require(key not in incarnations, "one child incarnation impersonates multiple processes")
        start=observed["spawn_monotonic_ns"]
        require(start<end and all(end<=lower or upper<=start for lower,upper in pid_lifetimes[observed["pid"]]),
                "one child PID claims overlapping independent lifetimes")
        incarnations.add(key)
        pid_lifetimes[observed["pid"]].append((start,end))
    starts = by_event["service_started"]
    require({row["owner_instance"] for row in starts} == {5001, 5002, 5003} and len(starts) == 3, "unexpected compute inventory")
    live = {}
    intervals = {}
    for row in starts:
        owner = row["owner_instance"]
        ident = identity(row["identity"])
        require(ident["spawn_monotonic_ns"] <= stamp(row), "start precedes spawn")
        ready = only([item for item in by_event["service_ready"] if item["owner_instance"] == owner], "service ready inventory")
        requested = only([item for item in by_event["service_stop_requested"] if item["owner_instance"] == owner], "service stop request inventory")
        stopped = only([item for item in by_event["service_stopped"] if item["owner_instance"] == owner], "service stop inventory")
        register(ident,stamp(stopped))
        for item in (ready, requested):
            equal(identity(item["identity"]), ident, "wrong service incarnation")
        equal(identity(stopped), ident, "wait4 belongs to another service")
        require(stamp(row) <= stamp(ready) < stamp(requested) <= stamp(stopped), "service lifetime order")
        exited(stopped, -signal.SIGKILL)
        intervals.setdefault(row["endpoint"], []).append((stamp(ready), stamp(requested), owner))
        live[owner] = (row, stopped)
    lost = only(by_event["all_compute_lost"], "all compute loss inventory")
    require(lost["live_service_processes"] == 0 and lost["all_cache_directories_removed"] is True, "missing complete cache loss")
    cut = only(by_event["compute_loss_started"], "missing compute cut")
    equal(sorted(cut["processes"], key=lambda item: item["pid"]),
          sorted([live[owner][0]["identity"] for owner in (5001, 5002)], key=lambda item: item["pid"]), "compute cut set changed")
    for owner in (5001, 5002):
        start, stopped = live[owner]
        require(stamp(cut) < stamp(stopped) < stamp(lost) and stopped["reason"] == "compute_loss", "compute survived cut")
        removed = only([row for row in by_event["cache_directory_removed"] if row["owner_instance"] == owner], "cache deletion inventory")
        equal(identity(removed["identity"]), identity(start["identity"]), "wrong deleted cache owner")
        require(removed["cache_directory"] == start["cache_directory"] and removed["exists"] is False,
                "cache deletion path/status differs")
        require(stamp(stopped) < stamp(removed) < stamp(lost), "cache deleted before process loss")
    require(stamp(lost) < live[5003][0]["identity"]["spawn_monotonic_ns"], "replacement existed during compute cut")

    old = only(by_event["backend_started"], "backend start inventory")
    stopped = only(by_event["backend_stopped"], "backend loss inventory")
    requested = only(by_event["backend_stop_requested"], "backend stop request inventory")
    restarted = only(by_event["backend_restarted"], "backend restart inventory")
    cleaned = only(by_event["backend_cleanup"], "backend cleanup inventory")
    require(stamp(lost) < stamp(requested) <= stamp(stopped) < stamp(restarted) < stamp(live[5003][0]), "cold recovery order")
    require(old["directory_identity"] == requested["directory_identity"] == stopped["directory_identity"] == restarted["directory_identity"], "backend durable directory changed")
    for inventory in (old, requested, stopped, restarted, cleaned):
        require(Counter(item["role"] for item in inventory["processes"]) == Counter({"master":1,"volume":1,"filer":1,"s3":1}), "backend role inventory")
    for inventory,end in ((old,stamp(stopped)), (restarted,stamp(cleaned))):
        for process in inventory["processes"]:
            register(process,end)
    for role in ("master", "volume", "filer", "s3"):
        def member(row):
            return only([item for item in row["processes"] if item["role"] == role], "backend role")
        prior, request, gone, replacement, final = map(member, (old, requested, stopped, restarted, cleaned))
        equal(identity(prior), identity(request), "backend stop targets another incarnation")
        equal(identity(prior), identity(gone), "backend cut wait4 identity differs")
        equal(identity(replacement), identity(final), "backend cleanup wait4 identity differs")
        exited(gone, -signal.SIGKILL)
        exited(final, -signal.SIGKILL)
        require(identity(prior)["spawn_monotonic_ns"] < stamp(old), "backend start precedes spawn")
        require(stamp(stopped) < identity(replacement)["spawn_monotonic_ns"] < stamp(restarted), "backend replacement existed before cut")

    require([row["phase"] for row in by_event["client_phase_started"]] == list(phases), "client phase start set/order")
    finished_phases = [row["phase"] for row in by_event["client_phase_finished"]]
    require(finished_phases == list(phases) if ordered else Counter(finished_phases) == Counter(phases), "client phase finish set/order")
    for phase in phases:
        begun = only([row for row in by_event["client_phase_started"] if row["phase"] == phase], "phase start")
        child = only([row for row in by_event["client_process_started"] if row["phase"] == phase], "client process start")
        finished = only([row for row in by_event["client_phase_finished"] if row["phase"] == phase], "phase finish")
        register(child["identity"],stamp(finished))
        equal(identity(child["identity"]), identity(finished["identity"]), "client wait4 belongs to another process")
        exited(finished, 0)
        require(stamp(begun) <= child["identity"]["spawn_monotonic_ns"] <= stamp(child) < stamp(finished), "client lifetime order")
        hello = only([row for row in http if row["event"] == "client_process_hello" and row["phase"] == phase], "client self-observation inventory")
        require(hello["pid_source"] == "node_process.pid" and type(hello["self_pid"]) is int and hello["self_pid"] > 0, "client self PID source")
        require(stamp(child) < stamp(hello) < stamp(finished), "client hello outside process lifetime")
        for row in [row for row in http if row["phase"] == phase and row["event"] != "client_process_hello"]:
            require(stamp(hello) <= stamp(row) <= stamp(finished), "HTTP event outside client lifetime")
            require(row["call_id"].startswith(f"{phase}:{hello['self_pid']}:"), "call ID belongs to another client")
            if row["event"] == "http_request":
                parsed = urlparse(row["url"])
                endpoint = f"{parsed.scheme}://{parsed.netloc}"
                require(endpoint in intervals, "HTTP target has no observed service")
                lower, upper, owner = only([interval for interval in intervals[endpoint]
                                           if interval[0] < stamp(row) < interval[1]], "HTTP request outside service lifetime")
                require(identity(begun["primary"]) == identity(live[owner][0]["identity"]) or
                        identity(begun["secondary"]) == identity(live[owner][0]["identity"]), "phase points at another service")
                if phase == "recover":
                    require(owner == 5003 and stamp(row) > stamp(restarted), "recovery used old compute/backend")
    cleanup = only(by_event["cleanup_finished"], "cleanup fact")
    require(cleanup["errors"] == [] and stamp(cleanup) > stamp(cleaned), "process cleanup incomplete")
    require(all(stamp(cleanup) > stamp(stopped) for _, stopped in live.values()), "service remains alive after cleanup")
    return {"services": len(starts), "original_backend_processes": 4, "replacement_backend_processes": 4,
            "unique_child_incarnations": len(incarnations),
            "complete_cache_loss": True, "kernel_wait4_verified": True}


def exchanges(http, *, paths=("/v1",)):
    calls = {}
    expected = defaultdict(int)
    for row in http:
        if row["event"] == "client_process_hello":
            continue
        call_id = row["call_id"]
        if row["event"] == "http_request":
            require(call_id not in calls, "duplicate HTTP call ID")
            expected[row["phase"]] += 1
            require(call_id.rsplit(":",1)[1] == str(expected[row["phase"]]), "missing HTTP invocation")
            require(row["method"] == "POST" and row["headers"]["content-type"] == "application/json", "unexpected HTTP request")
            require(set(row["headers"]) == {"content-type","x-scap-admission"}, "unexpected public request headers")
            raw = b64(row["body"])
            require(hashlib.sha256(raw).hexdigest() == row["body_sha256"], "request bytes/hash mismatch")
            body = parse(raw)
            url=urlparse(row["url"])
            require(type(body["version"]) is int and body["version"] == 1 and url.path in paths, "wrong API route/version")
            require(url.hostname=="127.0.0.1" and url.username is None and url.password is None and not url.query and not url.fragment,
                    "HTTP target escaped the private loopback fixture")
            expected_class = "catalogue" if url.path == "/v1/catalogue" else (
                "recovery" if body["operation"] in ("open","activate") else "data" if body["operation"] in ("create","query","execute") else "control")
            require(row["headers"]["x-scap-admission"]==expected_class,"HTTP admission differs from its operation")
            calls[call_id] = {"request": row, "body": body}
        else:
            require(row["event"] in ("http_response","http_transport_error"), "unplanned HTTP event")
            require(call_id in calls and "response" not in calls[call_id], "missing invocation or duplicate HTTP result")
            call = calls[call_id]
            require(row["phase"] == call["request"]["phase"] and row["client"] == call["request"]["client"], "response binds another client")
            require(stamp(call["request"]) < stamp(row), "response precedes invocation")
            call["response"] = row
            if row["event"] == "http_response":
                content_type=row.get("headers",{}).get("content-type")
                require(isinstance(content_type,str) and content_type.split(";")[0].strip().lower()=="application/json","non-JSON HTTP response headers")
                raw = b64(row["body"])
                require(hashlib.sha256(raw).hexdigest() == row["body_sha256"], "response bytes/hash mismatch")
                call["value"] = parse(raw)
                require(type(call["value"].get("ok")) is bool, "missing HTTP envelope")
                require((row["status"] == 200) == call["value"]["ok"], "HTTP status/envelope differs")
                if call["value"]["ok"] and call["body"]["operation"] in ("execute","lookup","cancel"):
                    value = call["value"]["value"]
                    if value["state"] == "committed":
                        committed(value)
    require(all("response" in call for call in calls.values()), "HTTP attempt has no terminal outcome")
    return calls


def value_of(call):
    require(call.get("value",{}).get("ok") is True, "expected successful full HTTP response")
    return call["value"]["value"]


def results(directory, calls):
    inputs = rows(directory, "inputs.jsonl")
    originals = {}
    for row in inputs:
        saved = parse(row["request"])
        require(set(saved) == {"scope","request","statements"}, "saved input shape")
        require(fingerprint(saved["statements"]) == saved["request"]["fingerprint"], "input fingerprint differs")
        require(row["request"] not in originals, "duplicate prepared input")
        originals[row["request"]] = row
    acks, duplicates = rows(directory,"acks.jsonl"), rows(directory,"duplicate-acks.jsonl")
    require(len(acks) == 10 and len(duplicates) == 8, "successful execute denominator changed")
    observed_ids = set()
    primary_ids = set()
    for ack in acks + duplicates:
        require(ack["call_id"] not in observed_ids and ack["call_id"] in calls, "duplicate/missing execute ACK call")
        observed_ids.add(ack["call_id"])
        call = calls[ack["call_id"]]
        require(call["body"]["operation"] == "execute", "ACK does not bind execute")
        require(ack["request"] in originals, "ACK without independent input")
        saved = parse(ack["request"])
        equal(call["body"], {"version":1,"operation":"execute",**saved}, "execute input changed")
        require(stamp(originals[ack["request"]]) < stamp(call["request"]) < stamp(call["response"]) <= stamp(ack), "input/HTTP/ACK order")
        value = value_of(call)
        equal(value,{"state":"committed","receipt":ack["receipt"],"result":ack["raw"]},"ACK changed full HTTP result")
        raw, decoded = committed(value)
        require(hashlib.sha256(raw).hexdigest() == ack["raw_sha256"],"ACK raw hash differs")
        equal(ack["receipt"]["scope"],saved["scope"],"receipt scope differs")
        equal(ack["receipt"]["request"],saved["request"],"receipt request differs")
        if ack in acks:
            identity_key=json.dumps([saved["scope"],saved["request"]],sort_keys=True)
            require(identity_key not in primary_ids,"duplicate unique ACK identity")
            primary_ids.add(identity_key)
        if saved["scope"]["tenant"] == "7" and saved["request"]["id"] != "1":
            require(len(saved["statements"]) == 1 and saved["statements"][0]["sql"] == "INSERT INTO records VALUES(?1,?2,?3,?4) RETURNING id, random(), payload, label, large_integer", "fixed INSERT changed")
            parameters = saved["statements"][0]["params"]
            require(len(decoded)==1 and decoded[0]["columns"]==["id","random()","payload","label","large_integer"],"INSERT result columns changed")
            require(len(decoded[0]["rows"])==1,"INSERT result row count changed")
            returned=decoded[0]["rows"][0]
            require(returned[0]==int(parameters[0]["value"]) and returned[2]==b64(parameters[1]["base64"]) and returned[3]==parameters[2]["value"] and returned[4]==9223372036854775807,"INSERT result differs from independent input")
            require(type(returned[1]) is int and -(2**63)<=returned[1]<2**63 and decoded[0]["affected_rows"]==1,"missing original random witness")
    successful={key for key,call in calls.items() if call["body"]["operation"]=="execute" and call.get("value",{}).get("ok") is True}
    equal(sorted(observed_ids),sorted(successful),"successful execute omitted from ACK denominator")
    fields=("request","receipt","raw","raw_sha256")
    for duplicate in duplicates:
        require(any(all(duplicate[field]==ack[field] for field in fields) for ack in acks),"duplicate execute changed original")

    recovery=rows(directory,"recoveries.jsonl")
    recovered=[row for row in recovery if row["kind"]=="ack"]
    require([row["ordinal"] for row in recovered]==list(range(1,19)),"recovery denominator omitted/reordered")
    for original,observed in zip(acks+duplicates,recovered):
        require(observed["original_call_id"]==original["call_id"],"recovery changed original ACK identity")
        for field in fields: equal(observed[field],original[field],"recovery changed original receipt/raw")
        call=calls[observed["call_id"]]
        require(call["body"]["operation"]=="lookup" and call["request"]["phase"]=="recover","recovery did not use original lookup")
        saved=parse(original["request"])
        equal(call["body"],{"version":1,"operation":"lookup","scope":saved["scope"],"request":saved["request"]},"lookup retargeted original identity")
        equal(value_of(call),{"state":"committed","receipt":original["receipt"],"result":original["raw"]},"raw HTTP recovery differs")
        require(stamp(call["response"])<=stamp(observed),"recovery recorded before response")

    outcomes=rows(directory,"outcomes.jsonl")
    require(len(outcomes)==2,"UNKNOWN outcome inventory")
    unknown,resolved=outcomes
    require(unknown["execute"]=="UNKNOWN" and resolved["resolved"]=="committed" and unknown["request"]==resolved["request"],"unknown identity changed")
    attempts=[call for call in calls.values() if call["request"]["phase"]=="unknown_write"]
    require(len(attempts)==1 and attempts[0] is calls[unknown["call_id"]],"uncertain SQL was retried")
    require(attempts[0].get("value",{}).get("error",{}).get("code")=="UNKNOWN","uncertain execute reported definite failure")
    first=calls[resolved["call_id"]]
    equal(value_of(first),{"state":"committed","receipt":resolved["receipt"],"result":resolved["raw"]},"unknown resolution raw changed")
    uncertain=only([row for row in recovery if row["kind"]=="unknown"],"unknown recovery inventory")
    equal(value_of(calls[uncertain["call_id"]]),value_of(first),"unknown original result lost across restart")
    equal(uncertain["receipt"],resolved["receipt"],"unknown receipt differs")
    require(uncertain["raw"]==resolved["raw"],"unknown raw differs")

    expected=[]
    for input in inputs:
        saved=parse(input["request"])
        if saved["scope"]["tenant"]!="7" or saved["request"]["id"] in ("1","50"):continue
        params=saved["statements"][0]["params"]
        expected.append([int(params[0]["value"]),b64(params[1]["base64"]),params[2]["value"],int(params[3]["value"])]) if saved["request"]["id"]!="99" else expected.append([99,b64(params[0]["base64"]),params[1]["value"],int(params[2]["value"])])
    expected.sort(key=lambda row:row[0]);require(len(expected)==9,"business input inventory")
    queries=[call for call in calls.values() if call["request"]["phase"]=="recover" and call["body"]["operation"]=="query"]
    require(len(queries)==3,"recovery query inventory")
    seen=set()
    for call in queries:
        value=value_of(call);require(set(value)=={"result"},"query response shape")
        decoded=result(b64(value["result"]));require(len(decoded)==1,"recovery query statements")
        sql=call["body"]["statements"][0]["sql"];seen.add(sql)
        if sql=="SELECT id, payload, label, large_integer FROM records ORDER BY id":
            require(decoded[0]["columns"]==["id","payload","label","large_integer"] and decoded[0]["rows"]==expected,"recovered business rows differ from inputs")
        elif sql=="SELECT count(*) FROM cancelled_effect":
            require(decoded[0]["rows"]==[[0]],"cancelled SQL appeared")
        elif sql=="SELECT x FROM isolated":
            require(decoded[0]["rows"]==[[77]],"other tenant lost data")
        else:raise ValueError("unexpected recovery query")
    require(len(seen)==3,"recovery omitted a data database/barrier query")
    return {"unique_acknowledged_requests":10,"successful_execute_responses":18,"recovery_lookup_responses":18,
            "unknown_execute_attempts":1,"unknown_original_result_preserved":True,"rows_by_tenant":{"7":9,"8":1}}


def network(history,calls):
    requests,responses=object_exchanges(history,phases=PHASES,blackhole_phases=("blackhole",))
    bindings={}
    for serial,request in requests.items():
        matching=set()
        for call_id,call in calls.items():
            if not stamp(call["request"])<stamp(request)<stamp(call["response"]):continue
            scope=call["body"]["scope"]
            prefix=f"/scap-test/scap-object/v1/{scope['deployment']}/{scope['tenant']}/{scope['database']}/"
            if request["path"]==prefix+"head" or request["path"].startswith(
                    prefix+f"inc/{scope['incarnation']}/gen/{scope['generation']}/objects/"):
                matching.add(call_id)
        require(matching,"S3 request has no matching authenticated HTTP Scope/call interval")
        bindings[serial]=matching
    versions=object_versions(requests,responses,calls=calls,bindings=bindings)
    accepted=[]
    for serial,response in responses.items():
        request=requests[serial]
        if request["path"].endswith("/head") and request["method"]=="PUT" and response["status"]==200:
            accepted.append((request,response,parse(bytes(request["head_request_bytes"]))))
    for call in calls.values():
        if call["body"]["operation"]!="execute" or call.get("value",{}).get("ok") is not True:continue
        receipt=value_of(call)["receipt"]
        scope=receipt["scope"]
        path=f"/scap-test/scap-object/v1/{scope['deployment']}/{scope['tenant']}/{scope['database']}/head"
        witnesses=[]
        for request,response,head in accepted:
            if request["path"]==path and head["sequence"]==decimal(receipt["sequence"]) and head["transition"]["nonce"]==decimal(receipt["transition"]["nonce"]):
                equal(head["scope"],{key:decimal(value) for key,value in scope.items()},"ACK HEAD scope changed")
                require(head["data_root"]==receipt["data_root"] and head["revision"]==decimal(receipt["transition"]["revision"]),"ACK HEAD binding differs")
                require(stamp(response)<stamp(call["response"]),"ACK precedes durable HEAD")
                witnesses.append(response)
        require(len(witnesses)==1,"successful execute missing unique original durable HEAD")
    uncertain=[(request,response,head) for request,response,head in accepted if request["phase"]=="unknown_write"]
    require(len(uncertain)==1 and uncertain[0][1]["suppressed"] is True,"UNKNOWN lacks real accepted HEAD/response loss")
    return {"s3_requests":len(requests),"accepted_head_publications":len(accepted),"head_format":3,"result_format":2,
            "object_version_audit":versions}


def build_receipt(directory, required, *, require_artifacts=True, source_root=None):
    # Load by exact source path: the sibling network controller also has modules
    # named build/run, so module search order must not select another verifier.
    specification=importlib.util.spec_from_file_location("scap_independent_build_audit",
        Path(__file__).resolve().parent.parent/"object-network"/"audit_build.py")
    module=importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module.receipt(directory,required,profile="service",require_artifacts=require_artifacts,source_root=source_root)


def process_build_binding(facts, build):
    if build["status"]=="NOT_PROVIDED":return {"status":"NOT_PROVIDED","diagnostic":True}
    starts=[row for row in facts if row["event"]=="service_started"]
    require(len(starts)==3,"build binding lacks all three service children")
    for row in starts:equal(row["binary"],build["binary"],"owned service child executed another release binary")
    return {"services_bound_to_original_executable":len(starts),"binary_sha256":build["binary"]["sha256"]}


def audit(directory, *, require_build=True, require_artifacts=True):
    directory=Path(directory)
    http=rows(directory,"http-client-ledger.jsonl")
    calls=exchanges(http)
    facts=rows(directory,"process-ledger.jsonl")
    build=build_receipt(directory,require_build,require_artifacts=require_artifacts)
    output={"schema":1,"status":"partial" if build.get("verification_scope")=="archived_source_and_cargo_only" else "passed",
            "http_calls":len(calls),"build":build,"process_build_binding":process_build_binding(facts,build),
            "processes":processes(facts,http),
            "results":results(directory,calls),"network":network(rows(directory,"history.jsonl"),calls)}
    output["source_sha256"]={name:hashlib.sha256((directory/name).read_bytes()).hexdigest() for name in FILES}
    return output


if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("evidence",type=Path)
    parser.add_argument("--allow-unavailable-artifacts",action="store_true",help="explicit partial offline audit; never a full release gate")
    args=parser.parse_args()
    outcome=audit(args.evidence,require_artifacts=not args.allow_unavailable_artifacts)
    print(json.dumps(outcome,indent=2,sort_keys=True))
    sys.exit(0 if outcome["status"]=="passed" else 1)
