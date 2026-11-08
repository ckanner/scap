#!/usr/bin/env python3
"""Read-only catalogue HTTP/SDK acceptance audit, independent of its controller."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
import sys
from pathlib import Path
import unicodedata
from urllib.parse import urlparse

from audit_wire import b64, committed, decimal, equal, fingerprint, object_exchanges as wire_exchanges, object_versions, parse, require, result
from service_oracle import build_receipt, exchanges, only, process_build_binding, processes, rows, stamp, value_of

PHASES=("initial","saturation_held","saturation_probe","abort_prepare","abort_resume_held","abort_win","abort_finish",
        "descriptor_unknown","descriptor_recover","ready_unknown","ready_recover","delete_unknown","delete_recover","reuse","recover")
CONTRACTS=("strict_original_intent_and_current_provision","reserved_abort_and_late_provision_fence",
           "descriptor_ready_delete_unknown_preserve_intent","admin_only_delete_and_name_reuse",
           "isolated_catalogue_capacity_and_all_process_recovery")
SOURCE_FILES=("catalogue-plan.json","http-client-ledger.jsonl","process-ledger.jsonl","catalogue-inputs.jsonl",
              "catalogue-outcomes.jsonl","catalogue-sql-inputs.jsonl","catalogue-sql-acks.jsonl",
              "catalogue-sql-recoveries.jsonl","catalogue-capacity.jsonl","catalogue-phases.jsonl","history.jsonl")


def reference(value):
    require(set(value)=={"creator","operation","name","scope","expected_name_revision"},"Creation fields changed")
    decimal(value["creator"]);decimal(value["operation"])
    name=value["name"]
    require(isinstance(name,str) and 1<=len(name.encode("utf-8",errors="strict"))<=128 and
            not any(unicodedata.category(char)=="Cc" for char in name),"invalid exact name")
    require(set(value["scope"])=={"deployment","tenant","database","incarnation","generation"},"Scope fields changed")
    for number in value["scope"].values():decimal(number)
    if value["expected_name_revision"] is not None:decimal(value["expected_name_revision"])


def optional_revision(value):
    if value is not None:decimal(value)


def progress(value, kind):
    reference(value["creation"])
    if kind in ("prepare_create","resume_create","inspect_create_operation"):
        require(set(value["initial_quota"])=={"max_bytes"},"initial quota fields")
        optional_revision(value["initial_quota"]["max_bytes"])
        require(set(value["retention"])=={"max_entries","max_result_bytes"},"retention fields")
        require(type(value["retention"]["max_entries"]) is int and 0<value["retention"]["max_entries"]<2**32,"retention integer changed")
        decimal(value["retention"]["max_result_bytes"])
    if kind=="prepare_create":
        require(set(value)=={"creation","initial_quota","retention"},"PreparedCreate is not Ready")
    elif kind=="resolve_name":
        require(set(value)=={"creation","binding_revision","head"},"Named fields")
        decimal(value["binding_revision"])
        equal(value["head"]["scope"],value["creation"]["scope"],"resolved HEAD changed Scope")
        require(value["head"]["lifecycle"] in ("ready","maintenance"),"nonserviceable HEAD leaked")
        require(not set(value["head"])&{"creation","deletion","etag","source","proof","policy"},"internal authority proof leaked")
    else:
        optional_revision(value["binding_revision"]);optional_revision(value["head_revision"])
        if kind in ("resume_create","inspect_create_operation"):
            fields={"creation","initial_quota","retention","phase","binding_revision","head_revision"}
            phases={"not_reserved","reserved","provisioning","bound","ready","aborting","aborted","deleting","deleted","name_conflict","identity_conflict"}
        else:
            fields={"creation","operation","nonce","phase","binding_revision","head_revision"}
            decimal(value["operation"]);decimal(value["nonce"])
            phases={"not_reserved","cannot_abort_bound","aborting","aborted"} if kind=="abort_create" else {"not_deleted","deleting","deleted"}
        require(set(value)==fields and value["phase"] in phases,"progress phase/fields changed")


def catalogue_calls(directory,calls):
    inputs=rows(directory,"catalogue-inputs.jsonl")
    require(len({row["input_id"] for row in inputs})==len(inputs),"duplicate input record")
    labels={}
    for row in inputs:
        require(row["label"] not in labels,"duplicate directory input label")
        intent=parse(row["intent"])
        require(set(intent)=={"version","deployment","tenant","principal","action"} and type(intent["version"]) is int and intent["version"]==1,"saved intent shape")
        for key in ("deployment","tenant","principal"):decimal(intent[key])
        require(intent["deployment"]=="1" and intent["tenant"]=="7","unexpected authority")
        labels[row["label"]]=(row,intent)
    outcomes=rows(directory,"catalogue-outcomes.jsonl")
    require(len(outcomes)==len(labels) and len({row["label"] for row in outcomes})==len(labels),"missing/duplicate directory outcome")
    observed={}
    for row in outcomes:
        require(row["label"] in labels and row["call_id"] in calls,"outcome without input/HTTP attempt")
        original,intent=labels[row["label"]]
        require(row["intent"]==original["intent"],"outcome changed original intent")
        call=calls[row["call_id"]]
        require(urlparse(call["request"]["url"]).path=="/v1/catalogue" and call["request"]["headers"]["x-scap-admission"]=="catalogue","directory borrowed another admission class")
        equal(call["body"],{"version":1,**intent["action"]},"HTTP replaced original catalogue intent")
        require(stamp(original)<stamp(call["request"])<stamp(call["response"])<=stamp(row),"directory input/HTTP/outcome order")
        if "value" in row:
            equal(value_of(call),row["value"],"SDK result differs from complete raw HTTP")
            progress(row["value"],intent["action"]["operation"])
            for field in ("deployment","tenant"):
                equal(row["value"]["creation"]["scope"][field],intent[field],"response escaped authenticated authority")
            if "creation" in intent["action"]:
                equal(row["value"]["creation"],intent["action"]["creation"],"response retargeted frozen Creation")
        else:
            require(call.get("value",{}).get("ok") is False,"SDK error without HTTP failure")
            require(row["error"]["code"]==call["value"]["error"]["code"],"SDK changed error semantics")
            if row["error"]["code"]=="UNKNOWN":
                equal(row["error"]["reference"]["intent"],intent,"UNKNOWN lost full original intent")
        observed[row["label"]]={"outcome":row,"intent":intent,"call":call}
    exact={row["call_id"] for row in outcomes}
    actual={key for key,call in calls.items() if urlparse(call["request"]["url"]).path=="/v1/catalogue"}
    equal(sorted(exact),sorted(actual),"directory HTTP retry or omitted terminal response")

    def value(label):return observed[label]["outcome"]["value"]
    def phase(label,expected):require(value(label)["phase"]==expected,label+": wrong terminal/progress semantics")
    for label,expected in {"provision_denied":"DENIED","same_id_changed_name":"CONFLICT","same_id_changed_quota":"CONFLICT",
                           "case_sensitive_name":"NOT_FOUND","admin_is_not_read":"DENIED","directory_backpressure":"BACKPRESSURE",
                           "late_provision_candidate":"CONFLICT","descriptor_unknown":"UNKNOWN","ready_unknown":"UNKNOWN","delete_unknown":"UNKNOWN",
                           "same_delete_id_changed_nonce":"CONFLICT","deleted_name_unresolvable":"NOT_FOUND"}.items():
        require(observed[label]["outcome"]["error"]["code"]==expected,label+": wrong error")
    for label,expected in {"main_descriptor_only":"not_reserved","descriptor_only_abort":"not_reserved","main_ready":"ready",
                           "bound_cannot_abort":"cannot_abort_bound","rival_resume":"name_conflict","held_reserved_inspect":"reserved",
                           "abort_winner":"aborted","aborted_inspect":"aborted","late_resume_after_abort":"aborted","abort_original_reentry":"aborted",
                           "descriptor_resolved":"not_reserved","ready_resolved":"ready","ready_original_reentry":"ready","delete_original_reentry":"deleted",
                           "replacement_ready":"ready","old_creation_after_reuse":"deleted","cold_aborted_inspect":"aborted","cold_deleted_inspect":"deleted"}.items():
        phase(label,expected)
    require(value("old_creation_after_reuse")["binding_revision"] is None and value("cold_deleted_inspect")["binding_revision"] is None,"old operation exposes successor revision")
    main=value("main_prepare")["creation"]
    surviving=value("descriptor_original_reentry")["creation"]
    replacement=value("replacement_prepare")["creation"]
    cancelled=value("abort_prepare")["creation"]
    for label in ("main_prepare","abort_prepare","descriptor_original_reentry","replacement_prepare"):
        equal(value(label)["initial_quota"],{"max_bytes":"10737418240"},"initial default quota changed")
        equal(value(label)["retention"],{"max_entries":4096,"max_result_bytes":"268435456"},"persisted initial retention changed")
    for creation,name,operation in [(main,"目录 Main","1001"),(surviving,"surviving-name","3001"),(replacement,"目录 Main","5001"),(cancelled,"cancelled-name","2001")]:
        require(creation["name"]==name and creation["operation"]==operation and creation["creator"]=="11","fixed Creation identity changed")
    require(main["scope"]!=replacement["scope"],"name reuse recycled the old database identity")
    equal(value("descriptor_resolved")["creation"],surviving,"descriptor recovery allocated another Scope")
    equal(value("ready_original_reentry"),value("ready_resolved"),"Ready reentry reset persisted state")
    equal(value("abort_original_reentry"),value("abort_winner"),"abort reentry changed original outcome")
    for original,reentry in [("descriptor_unknown","descriptor_original_reentry"),("ready_unknown","ready_original_reentry"),("delete_unknown","delete_original_reentry")]:
        equal(observed[original]["intent"],observed[reentry]["intent"],"UNKNOWN reentry changed the complete intent")
        original_phase=observed[original]["call"]["request"]["phase"]
        require(sum(call["request"]["phase"]==original_phase for call in calls.values())==1,"SDK retried an unknown mutation")
    deletion=observed["delete_unknown"]["intent"]
    require(deletion["principal"]=="12" and deletion["action"]["creation"]["creator"]=="11","ADMIN-only delete replaced original creator")
    require(deletion["action"]["control_operation"]=="4001" and deletion["action"]["nonce"]=="4002","delete intent changed")
    changed=observed["same_delete_id_changed_nonce"]["intent"]
    equal({**changed["action"],"nonce":"4002"},deletion["action"],"control ID conflict probe changed unrelated fields")
    equal(value("cold_resolve_3001")["creation"],surviving,"cold resolve changed surviving identity")
    equal(value("cold_resolve_5001")["creation"],replacement,"cold resolve retargeted replacement")
    return observed,{"deleted-main":main,"surviving":surviving,"replacement":replacement,"cancelled":cancelled}


def sql_results(directory,calls,creations):
    inputs=rows(directory,"catalogue-sql-inputs.jsonl")
    require(Counter(row["label"] for row in inputs)==Counter({"deleted-main":1,"surviving":1,"replacement":1}),"SQL independent inputs changed")
    by_saved={row["request"]:row for row in inputs}
    for row in inputs:
        saved=parse(row["request"])
        equal(saved["scope"],creations[row["label"]]["scope"],"SQL was retargeted by name")
        require(saved["request"]["fingerprint"]==fingerprint(saved["statements"]),"SQL fingerprint/input differs")
        require([item["sql"] for item in saved["statements"]]==["CREATE TABLE witness(id INTEGER PRIMARY KEY, payload BLOB, label TEXT)",
                  "INSERT INTO witness VALUES(1,?1,?2) RETURNING id,payload,label,random()"],"fixed SQL statements changed")
        require(saved["request"]["epoch"]=="1" and saved["request"]["id"]=="1" and saved["request"]["principal"]=="11","SQL identity changed")
    acks=rows(directory,"catalogue-sql-acks.jsonl")
    require(Counter((row["label"],row["kind"]) for row in acks)==Counter((label,kind) for label in ("deleted-main","surviving","replacement") for kind in ("original","duplicate")),"SQL ACK denominator changed")
    require(len({row["call_id"] for row in acks})==6,"duplicate SQL ACK call")
    success={key for key,call in calls.items() if call["body"]["operation"]=="execute" and call.get("value",{}).get("ok") is True}
    equal(sorted(success),sorted(row["call_id"] for row in acks),"successful SQL omitted from ACK denominator")
    primary={}
    for ack in acks:
        require(ack["request"] in by_saved,"ACK without fixed SQL input")
        saved=parse(ack["request"]);call=calls[ack["call_id"]]
        equal(call["body"],{"version":1,"operation":"execute",**saved},"SQL HTTP input differs")
        require(stamp(by_saved[ack["request"]])<stamp(call["request"])<stamp(call["response"])<=stamp(ack),"SQL input/ACK order")
        equal(value_of(call),{"state":"committed","receipt":ack["receipt"],"result":ack["raw"]},"SQL ACK differs from raw HTTP")
        raw,decoded=committed(value_of(call))
        require(hashlib.sha256(raw).hexdigest()==ack["raw_sha256"],"SQL ACK digest differs")
        equal(ack["receipt"]["scope"],saved["scope"],"receipt scope differs")
        equal(ack["receipt"]["request"],saved["request"],"receipt request differs")
        require(len(decoded)==2 and decoded[0]["columns"]==[] and decoded[0]["rows"]==[],"schema result changed")
        require(decoded[1]["columns"]==["id","payload","label","random()"] and len(decoded[1]["rows"])==1,"INSERT RETURNING shape changed")
        returned=decoded[1]["rows"][0]
        require(returned[:3]==[1,("payload-"+ack["label"]).encode(),ack["label"]] and type(returned[3]) is int and -(2**63)<=returned[3]<2**63,"original random/BLOB result differs")
        if ack["kind"]=="original":primary[ack["label"]]=ack
        else:
            original=primary[ack["label"]]
            for field in ("request","receipt","raw","raw_sha256"):equal(ack[field],original[field],"duplicate SQL changed original outcome")
    recovered=rows(directory,"catalogue-sql-recoveries.jsonl")
    require(len(recovered)==6 and len({row["original_call_id"] for row in recovered})==6,"recovery ACK denominator shrank")
    for ack,observed in zip(acks,recovered):
        require(observed["original_call_id"]==ack["call_id"] and observed["request"]==ack["request"],"recovery changed original ACK")
        call=calls[observed["call_id"]];saved=parse(ack["request"])
        equal(call["body"],{"version":1,"operation":"lookup","scope":saved["scope"],"request":saved["request"]},"recovery lookup retargeted by name")
        require(call["request"]["phase"]=="recover" and stamp(call["response"])<=stamp(observed),"recovery timing changed")
        if ack["label"]=="deleted-main":
            require(observed["classification"]=="deleted" and call["value"]["ok"] is False and call["value"]["error"]["code"]=="LIFECYCLE","deleted ACK silently discarded or claimed committed")
        else:
            require(observed["classification"]=="committed","retained ACK misclassified")
            for field in ("receipt","raw","raw_sha256"):equal(observed[field],ack[field],"retained original result changed")
            equal(value_of(call),{"state":"committed","receipt":ack["receipt"],"result":ack["raw"]},"recovery HTTP lost original result")
    queries=[call for call in calls.values() if call["body"]["operation"]=="query" and call["request"]["phase"]=="recover"]
    require(len(queries)==2,"cold query inventory changed")
    for label in ("surviving","replacement"):
        call=only([call for call in queries if call["body"]["scope"]==creations[label]["scope"]],"missing surviving database query")
        equal(call["body"]["statements"],[{"sql":"SELECT id,payload,label FROM witness ORDER BY id","params":[]}],"cold query changed")
        decoded=result(b64(value_of(call)["result"]))
        require(len(decoded)==1 and decoded[0]["columns"]==["id","payload","label"] and decoded[0]["rows"]==[[1,("payload-"+label).encode(),label]],"cold SQL effects differ")
    return acks,{"unique_sql_requests":3,"successful_sql_responses":6,"retained_original_results":4,"deleted_access_checks":2}


def bind_requests(requests,calls,observed,creations,*,responses=None):
    directory_context={item["outcome"]["call_id"]:item["intent"] for item in observed.values()}
    prefix="/scap-test/scap-object/v1/"
    def database_path(scope,target):
        return target==scope["database"]+"/head" or target.startswith(
            f"{scope['database']}/inc/{scope['incarnation']}/gen/{scope['generation']}/objects/")
    def prior_tombstone_proof(call,request,creation,authority,key):
        # Reusing a name verifies the former permanent identity. Only an
        # actually read tombstone within this HTTP call can authorize reading
        # its old proof; a same-name entry elsewhere in the ledger is not one.
        if responses is None or call["body"]["operation"]!="resume_create" or creation["expected_name_revision"] is None:
            return False
        name=creation["name"]
        name_path=prefix+authority+"catalogue/v1/name/"+hashlib.sha256(name.encode()).hexdigest()
        for serial,read in requests.items():
            response=responses.get(serial)
            if read["method"]!="GET" or read["path"]!=name_path or response is None or response["status"]!=200:
                continue
            if not stamp(call["request"])<stamp(read)<stamp(response)<stamp(request):continue
            binding=parse(bytes(response["catalogue_response_bytes"]))
            if type(binding.get("format")) is not int or binding["format"]!=1 or binding.get("state")!="tombstone" or \
                    type(binding.get("revision")) is not int or binding["revision"]!=decimal(creation["expected_name_revision"]):
                continue
            for prior in creations.values():
                if prior["name"]!=name or authority!=f"{prior['scope']['deployment']}/{prior['scope']['tenant']}/":continue
                original={"creator":decimal(prior["creator"]),"operation":decimal(prior["operation"]),"name":name,
                          "scope":{field:decimal(value) for field,value in prior["scope"].items()},
                          "expected_name_revision":None if prior["expected_name_revision"] is None else decimal(prior["expected_name_revision"])}
                if json.dumps(binding.get("creation"),sort_keys=True)==json.dumps(original,sort_keys=True) and \
                        key==f"abort-proof/{prior['creator']}/{prior['operation']}":return True
        return False
    bindings={}
    for serial,request in requests.items():
        require(request["path"].startswith(prefix),"object request escaped authority prefix")
        path=request["path"][len(prefix):]
        matching=set()
        for call_id,call in calls.items():
            if not stamp(call["request"])<stamp(request)<stamp(call["response"]):continue
            matched=False
            action=call["body"]
            if "scope" in action:
                scope=action["scope"]
                expected=f"{scope['deployment']}/{scope['tenant']}/"
                if path.startswith(expected) and database_path(scope,path[len(expected):]):matching.add(call_id)
                continue
            if call_id not in directory_context:continue
            if action["operation"] in ("resolve_name","inspect_create_operation") and request["method"]!="GET":continue
            context=directory_context[call_id]
            authority=f"{context['deployment']}/{context['tenant']}/"
            if not path.startswith(authority):continue
            target=path[len(authority):]
            creation=action.get("creation")
            response=call.get("value",{}).get("value",{})
            if creation is None:creation=response.get("creation")
            name=action.get("name",creation["name"] if creation else None)
            if target.startswith("catalogue/v1/"):
                key=target[len("catalogue/v1/"):]
                if key.startswith("name/"):
                    matched=name is not None and key=="name/"+hashlib.sha256(name.encode()).hexdigest()
                elif key.startswith("create/"):
                    creator=creation["creator"] if creation else context["principal"]
                    operation=action.get("create_operation",creation["operation"] if creation else None)
                    matched=operation is not None and key==f"create/{creator}/{operation}"
                    if not matched and request["method"]=="GET":
                        matched=any(value["name"]==name and key==f"create/{value['creator']}/{value['operation']}" for value in creations.values())
                elif key.startswith("control/"):
                    kind={"abort_create":"abort","delete_name":"delete"}.get(action["operation"])
                    matched=kind is not None and key==f"control/{context['principal']}/{kind}/{action['control_operation']}"
                    if not matched and request["method"]=="GET":
                        for original in directory_context.values():
                            control=original["action"]
                            kind={"abort_create":"abort","delete_name":"delete"}.get(control["operation"])
                            if kind is not None and control["creation"]["name"]==name and key==f"control/{original['principal']}/{kind}/{control['control_operation']}":
                                matched=True;break
                elif key.startswith("abort-proof/"):
                    matched=creation is not None and key==f"abort-proof/{creation['creator']}/{creation['operation']}"
                    if not matched and request["method"]=="GET" and creation is None:
                        matched=any(value["name"]==name and key==f"abort-proof/{value['creator']}/{value['operation']}" for value in creations.values())
                    if not matched and request["method"]=="GET" and creation is not None:
                        matched=prior_tombstone_proof(call,request,creation,authority,key)
            else:
                scopes=[creation["scope"]] if creation else [value["scope"] for value in creations.values() if value["name"]==name]
                matched=any(database_path(scope,target) for scope in scopes)
                if not matched and request["method"]=="GET":
                    # Reusing a tombstone proves its former physical identity
                    # remains Deleted. This is an exact HEAD read, never an
                    # authorization to write the prior HEAD or load its data.
                    matched=any(value["name"]==name and target==value["scope"]["database"]+"/head" for value in creations.values())
            if matched:matching.add(call_id)
        require(matching,"object path/time has no matching authenticated HTTP intent")
        bindings[serial]=matching
    return bindings


def object_exchanges(history):
    return wire_exchanges(history,phases=PHASES)


def network(directory,history,facts,calls,observed,creations,acks):
    requests,responses=object_exchanges(history)
    bindings=bind_requests(requests,calls,observed,creations,responses=responses)
    versions=object_versions(requests,responses,calls=calls,bindings=bindings)
    faults={row["label"]:row for row in facts if row["event"]=="catalogue_fault_observed"}
    require(set(faults)=={"saturation","late_provision","descriptor_response_loss","ready_response_loss","delete_response_loss"},"fault plan changed")
    for label,fault in faults.items():
        snapshot=fault["observation"];serial=snapshot["request_serial"]
        request=requests[serial]
        for key in ("method","path","phase","request_sha256","if_match","if_none_match"):
            equal(snapshot[key],request[key],"observed fault moved to another request")
        raw=b64(fault["payload"])
        require(hashlib.sha256(raw).hexdigest()==fault["payload_sha256"]==request["request_sha256"],"fault raw payload changed")
        if label.endswith("response_loss"):
            require(responses[serial]["status"]==200 and responses[serial]["suppressed"] is True,"UNKNOWN did not follow backend acceptance/response loss")
    provision=faults["late_provision"];serial=provision["observation"]["request_serial"]
    require(responses[serial]["status"]==412 and provision["observation"]["if_none_match"]=="*","late original create did not fail backend conditional create")
    candidate=parse(b64(provision["payload"]))
    require(candidate["format"]==4 and candidate["lifecycle"]=="provisioning","hold missed original provisioning HEAD")
    equal(candidate["scope"],{key:decimal(value) for key,value in creations["cancelled"]["scope"].items()},"held candidate targets another identity")
    path=provision["observation"]["path"]
    cancelled_heads=[parse(bytes(request["head_request_bytes"])) for key,request in requests.items()
                     if request["method"]=="PUT" and request["path"]==path and responses[key]["status"]==200]
    require(cancelled_heads and all(head["lifecycle"]=="deleted" for head in cancelled_heads),"cancelled creation became serviceable")
    for label,lifecycle in (("ready_response_loss","ready"),("delete_response_loss","deleted")):
        head=parse(b64(faults[label]["payload"]))
        require(head["format"]==4 and head["lifecycle"]==lifecycle,"response loss at wrong HEAD stage")
    delete_head=parse(b64(faults["delete_response_loss"]["payload"]))
    require(delete_head["deletion"]["principal"]==12 and delete_head["creation"]["creator"]==11,"delete proof confused creator and ADMIN")

    releases={row["label"]:row for row in facts if row["event"]=="catalogue_hold_release"}
    require(set(releases)=={"saturation","late_provision"},"hold release inventory")
    saturation=faults["saturation"];lower=stamp(saturation);upper=stamp(releases["saturation"])
    require(lower<upper,"hold released before observation")
    backpressure=observed["directory_backpressure"]["call"]
    require(lower<stamp(backpressure["request"])<stamp(backpressure["response"])<upper and backpressure["response"]["status"]==429,"catalogue saturation not observed within hold")
    capacity=rows(directory,"catalogue-capacity.jsonl")
    require(Counter(row["operation"] for row in capacity)==Counter({"lookup":1,"cancel":1}),"lookup/cancel isolation probes missing")
    for row in capacity:
        call=calls[row["call_id"]];saved=parse(row["original"])
        equal(call["body"],{"version":1,"operation":row["operation"],"scope":saved["scope"],"request":saved["request"]},"ordinary recovery operation retargeted")
        require(lower<stamp(call["request"])<stamp(call["response"])<upper,"ordinary operation did not finish during directory hold")
        require(call["request"]["headers"]["x-scap-admission"]=="control","ordinary operation used catalogue pool")
        value=value_of(call)
        require(value["state"]==("committed" if row["operation"]=="lookup" else "cancelled"),"ordinary operation did not complete")
    late_release=stamp(releases["late_provision"])
    require(stamp(observed["abort_winner"]["call"]["response"])<late_release<stamp(responses[serial]),"late original provisioning forwarded before abort won")

    # Bind every retained SQL result to an actual accepted HEAD and exact object
    # readback. A regenerated random result with matching final rows is invalid.
    for ack in acks:
        receipt=ack["receipt"];scope=receipt["scope"]
        key=f"/scap-test/scap-object/v1/{scope['deployment']}/{scope['tenant']}/{scope['database']}/head"
        matches=[]
        for serial,request in requests.items():
            if request["method"]!="PUT" or request["path"]!=key or responses[serial]["status"]!=200:continue
            head=parse(bytes(request["head_request_bytes"]))
            if head["sequence"]==decimal(receipt["sequence"]) and head["revision"]==decimal(receipt["transition"]["revision"]):
                equal(head["scope"],{key:decimal(value) for key,value in scope.items()},"SQL HEAD incarnation/generation differs")
                require(head["data_root"]==receipt["data_root"] and head["transition"]["nonce"]==decimal(receipt["request"]["id"]),"SQL HEAD result binding differs")
                matches.append(request)
        publication=only(matches,"missing/duplicate SQL HEAD publication")
        result_key=f"/scap-test/scap-object/v1/{scope['deployment']}/{scope['tenant']}/{scope['database']}/inc/{scope['incarnation']}/gen/{scope['generation']}/objects/{receipt['result_hash']}"
        readbacks=[response for serial,response in responses.items() if requests[serial]["method"]=="GET" and
                   requests[serial]["path"]==result_key and response["status"]==200 and
                   response["response_sha256"]==receipt["result_hash"] and stamp(response)<stamp(publication)]
        require(readbacks,"ACK lacks exact original Result object readback")
        require(stamp(responses[publication["request_serial"]])<stamp(calls[ack["call_id"]]["response"]),"ACK before durable HEAD")
    return {"object_requests":len(requests),"real_late_provision_412":True,"unknown_accepted_responses":3,
            "lookup_cancel_completed_during_catalogue_hold":True,"head_format":4,"result_format":2,
            "object_version_audit":versions}


def audit(directory, *, require_build=True, require_artifacts=True):
    directory=Path(directory)
    plan=parse((directory/"catalogue-plan.json").read_bytes())
    equal(plan["phases"],list(PHASES),"frozen phases changed")
    equal(plan["contracts"],list(CONTRACTS),"contract inventory changed")
    equal(plan["admission"],{"workers":1,"queued_total":4,"queued_per_tenant":3,"queued_per_name":2,"intake":1,"max_body_bytes":65536,"timeout_ms":10000},"bounded fixture profile changed")
    require(plan["successful_sql_responses"]==6 and plan["unique_sql_requests"]==3 and plan["deleted_sql_responses"]==2 and
            plan["retained_sql_responses"]==4 and plan["unknown_directory_responses"]==3 and plan["known_original_intents_only"] is True,"frozen denominators changed")
    http=rows(directory,"http-client-ledger.jsonl");facts=rows(directory,"process-ledger.jsonl")
    calls=exchanges(http,paths=("/v1","/v1/catalogue"))
    build=build_receipt(directory,require_build,require_artifacts=require_artifacts)
    process_audit=processes(facts,http,phases=PHASES,ordered=False)
    observed,creations=catalogue_calls(directory,calls)
    acks,result_audit=sql_results(directory,calls,creations)
    network_audit=network(directory,rows(directory,"history.jsonl"),facts,calls,observed,creations,acks)
    phases=rows(directory,"catalogue-phases.jsonl")
    require(Counter(row["phase"] for row in phases)==Counter(PHASES) and all(row["status"]=="completed" for row in phases),"phase completion inventory")
    for row in phases:
        require(row["http_attempts"]==sum(call["request"]["phase"]==row["phase"] for call in calls.values()),"phase attempted-count differs from full ledger")
    return {"schema":1,"status":"partial" if build.get("verification_scope")=="archived_source_and_cargo_only" else "passed",
            "checked_contracts":list(CONTRACTS),"http_calls":len(calls),"build":build,"process_build_binding":process_build_binding(facts,build),
            "processes":process_audit,"results":result_audit,"network":network_audit,"known_original_intents_only":True,
            "complete_catalogue_enumeration":"NOT_IMPLEMENTED","core_cut_matrix":"SEPARATE_CONTRACT",
            "source_sha256":{name:hashlib.sha256((directory/name).read_bytes()).hexdigest() for name in SOURCE_FILES}}


if __name__=="__main__":
    parser=argparse.ArgumentParser();parser.add_argument("evidence",type=Path)
    parser.add_argument("--allow-unavailable-artifacts",action="store_true",help="explicit partial offline audit; never a full release gate")
    args=parser.parse_args()
    outcome=audit(args.evidence,require_artifacts=not args.allow_unavailable_artifacts)
    print(json.dumps(outcome,indent=2,sort_keys=True))
    sys.exit(0 if outcome["status"]=="passed" else 1)
