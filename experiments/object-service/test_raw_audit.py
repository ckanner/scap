"""Synthetic negative controls; never evidence of a real HTTP/S3 execution."""
import base64
import copy
import hashlib
import json
import struct
import unittest

import audit_wire as wire
import service_oracle as oracle


class WireWitnessControls(unittest.TestCase):
    def test_statement_fingerprint_covers_every_typed_parameter_and_raw_bits(self):
        statements=[{"sql":"SELECT ?1,?2,?3,?4,?5","params":[{"type":"null"},{"type":"integer","value":"9223372036854775807"},
                    {"type":"real","bits":"8000000000000000"},{"type":"text","value":"\ufeffx\0😀"},{"type":"blob","base64":"AP8="}]}]
        original=wire.fingerprint(statements)
        for index in range(5):
            changed=copy.deepcopy(statements);changed[0]["params"][index]={"type":"integer","value":"1"}
            self.assertNotEqual(wire.fingerprint(changed),original)
        for value in [{"type":"integer","value":"01"},{"type":"integer","value":"9223372036854775808"},
                      {"type":"real","bits":"7ff0000000000000"},{"type":"blob","base64":"AB=="},{"type":"wrong"}]:
            with self.subTest(value=value),self.assertRaises((ValueError,KeyError)):
                wire.fingerprint([{"sql":"SELECT ?1","params":[value]}])

    def test_decoder_rejects_truncation_trailing_bytes_and_invalid_scalar_encodings(self):
        def encoded(tag):
            return b"SCAPRES1"+struct.pack("<II",1,1)+struct.pack("<I",1)+b"x"+struct.pack("<I",1)+tag+struct.pack("<Qq",0,0)
        valid=encoded(b"\1"+struct.pack("<q",-9223372036854775808))
        self.assertEqual(wire.result(valid)[0]["rows"],[[-9223372036854775808]])
        for raw in [valid+b"tail",valid[:-1],encoded(b"\2"+struct.pack("<d",float("nan"))),encoded(b"\xff"),encoded(b"\3\1\0\0\0\xff")]:
            with self.subTest(raw=raw),self.assertRaises((ValueError,UnicodeDecodeError)):
                wire.result(raw)
        for tag,expected in [(b"\0",None),(b"\2"+struct.pack("<d",1.5),1.5),(b"\3\1\0\0\0x","x"),(b"\4\2\0\0\0\0\xff",b"\0\xff")]:
            self.assertEqual(wire.result(encoded(tag))[0]["rows"],[[expected]])

    def test_result_digest_binds_scope_request_transition_and_complete_result_bytes(self):
        raw=b"SCAPRES1\0\0\0\0"
        receipt={"scope":{"deployment":"1","tenant":"2","database":"3","incarnation":"4","generation":"5"},
                 "request":{"epoch":"1","id":"7","principal":"8","fingerprint":"a"*64},"sequence":"1",
                 "transition":{"revision":"2","nonce":"7"},"data_root":"b"*64,"result_hash":"0"*64}
        receipt["result_hash"]=wire.receipt_hash(receipt,raw)
        value={"state":"committed","receipt":receipt,"result":base64.b64encode(raw).decode()}
        self.assertEqual(wire.committed(value),(raw,[]))
        for field in ["sequence","data_root","scope","request","transition"]:
            changed=copy.deepcopy(value)
            if field=="sequence":changed["receipt"][field]="2"
            elif field=="data_root":changed["receipt"][field]="c"*64
            else:changed["receipt"][field][next(iter(changed["receipt"][field]))]="9"
            with self.subTest(field=field),self.assertRaises(ValueError):wire.committed(changed)
        with self.assertRaises(ValueError):wire.parse('{"x":1,"x":2}')
        with self.assertRaises(ValueError):wire.parse('{"x":NaN}')


def http_fixture():
    body={"version":1,"scope":{"deployment":"1","tenant":"2","database":"3","incarnation":"4","generation":"5"},"operation":"status"}
    def packet(event,time,value):
        raw=json.dumps(value).encode()
        return {"event":event,"phase":"initialize","monotonic_ns":str(time),"call_id":"initialize:100:1","client":"1",
                "body":base64.b64encode(raw).decode(),"body_sha256":hashlib.sha256(raw).hexdigest()}
    request=packet("http_request",10,body)
    request.update(method="POST",url="http://127.0.0.1:8001/v1",headers={"content-type":"application/json","x-scap-admission":"control"})
    response=packet("http_response",20,{"ok":True,"value":{"revision":"1"}});response.update(status=200,headers={"content-type":"application/json"})
    return [request,response]


class HttpLedgerControls(unittest.TestCase):
    def test_full_request_and_response_are_bound_by_unique_call_id(self):
        self.assertEqual(len(oracle.exchanges(http_fixture())),1)
        for fault in ("omit_request","omit_response","duplicate_request","duplicate_response","hash","time","phase","client","status","call_gap","headers","authority","admission"):
            rows=http_fixture()
            if fault=="omit_request":rows.pop(0)
            elif fault=="omit_response":rows.pop()
            elif fault=="duplicate_request":rows.insert(1,copy.deepcopy(rows[0]))
            elif fault=="duplicate_response":rows.append(copy.deepcopy(rows[1]))
            elif fault=="hash":rows[1]["body_sha256"]="0"*64
            elif fault=="time":rows[1]["monotonic_ns"]="9"
            elif fault=="phase":rows[1]["phase"]="recover"
            elif fault=="client":rows[1]["client"]="2"
            elif fault=="status":rows[1]["status"]=503
            elif fault=="call_gap":rows[0]["call_id"]="initialize:100:2"
            elif fault=="headers":rows[1]["headers"]["content-type"]="text/html"
            elif fault=="authority":rows[0]["url"]="https://remote.invalid/v1"
            else:rows[0]["headers"]["x-scap-admission"]="data"
            with self.subTest(fault=fault),self.assertRaises(ValueError):oracle.exchanges(rows)


def process_fixture():
    facts=[];http=[]
    usage={"available":True,"source":"kernel_wait4_owned_child","maxrss_bytes":4096}
    def ident(pid,spawn):return {"pid":pid,"spawn_monotonic_ns":spawn,"pid_source":"owned_Popen_child"}
    def emit(event,time,**fields):
        row={"event":event,"monotonic_ns":time,**fields};facts.append(row);return row
    old=[{"role":role,**ident(100+index,index+1)} for index,role in enumerate(("master","volume","filer","s3"))]
    new=[{"role":role,**ident(200+index,510+index)} for index,role in enumerate(("master","volume","filer","s3"))]
    emit("backend_started",5,processes=copy.deepcopy(old),directory_identity="fixed")
    services={5001:ident(301,10),5002:ident(302,20),5003:ident(303,515)}
    for owner in (5001,5002,5003):
        identity=services[owner]
        emit("service_started",identity["spawn_monotonic_ns"]+1,owner_instance=owner,identity=copy.deepcopy(identity),endpoint=f"http://127.0.0.1:{owner}",cache_directory=f"/private/{owner}")
        emit("service_ready",identity["spawn_monotonic_ns"]+2,owner_instance=owner,identity=copy.deepcopy(identity))
    for index,phase in enumerate(oracle.PHASES):
        lower=600 if phase=="recover" else 100+index*40
        owner=5003 if phase=="recover" else 5001
        secondary=5003 if phase=="recover" else 5002
        child=ident(1000+index,lower+1)
        emit("client_phase_started",lower,phase=phase,primary=copy.deepcopy(services[owner]),secondary=copy.deepcopy(services[secondary]))
        emit("client_process_started",lower+2,phase=phase,identity=copy.deepcopy(child))
        emit("client_phase_finished",lower+6,phase=phase,identity=copy.deepcopy(child),wait_status=0,kernel_usage=copy.deepcopy(usage))
        http.append({"event":"client_process_hello","phase":phase,"monotonic_ns":str(lower+3),"self_pid":2000+index,"pid_source":"node_process.pid"})
        http.append({"event":"http_request","phase":phase,"monotonic_ns":str(lower+4),"call_id":f"{phase}:{2000+index}:1","url":f"http://127.0.0.1:{owner}/v1"})
        http.append({"event":"http_response","phase":phase,"monotonic_ns":str(lower+5),"call_id":f"{phase}:{2000+index}:1"})
    emit("compute_loss_started",500,processes=[copy.deepcopy(services[owner]) for owner in (5001,5002)])
    for owner,start,stop in ((5001,501,503),(5002,502,504),(5003,701,702)):
        reason="cleanup" if owner==5003 else "compute_loss"
        emit("service_stop_requested",start,owner_instance=owner,identity=copy.deepcopy(services[owner]),reason=reason)
        emit("service_stopped",stop,owner_instance=owner,**services[owner],reason=reason,wait_status=-9,kernel_usage=copy.deepcopy(usage))
        if owner!=5003:
            emit("cache_directory_removed",stop+2,owner_instance=owner,identity=copy.deepcopy(services[owner]),cache_directory=f"/private/{owner}",exists=False)
    emit("all_compute_lost",507,live_service_processes=0,all_cache_directories_removed=True)
    emit("backend_stop_requested",508,processes=copy.deepcopy(old),directory_identity="fixed")
    emit("backend_stopped",509,processes=[{**value,"wait_status":-9,"kernel_usage":copy.deepcopy(usage)} for value in old],directory_identity="fixed")
    emit("backend_restarted",514,processes=copy.deepcopy(new),directory_identity="fixed")
    emit("backend_cleanup",703,processes=[{**value,"wait_status":-9,"kernel_usage":copy.deepcopy(usage)} for value in new])
    emit("cleanup_finished",704,errors=[])
    facts.sort(key=lambda row:row["monotonic_ns"])
    for index,row in enumerate(facts,1):row["sequence"]=index
    return facts,http


class ProcessTimelineControls(unittest.TestCase):
    def test_consistently_relabelled_duplicate_service_backend_and_client_incarnations_fail(self):
        def replace(value,old,new):
            if isinstance(value,list):
                for item in value:replace(item,old,new)
            elif isinstance(value,dict):
                if value.get("pid")==old["pid"] and value.get("spawn_monotonic_ns")==old["spawn_monotonic_ns"]:
                    value.update(new)
                for item in value.values():replace(item,old,new)
        for category in ("service","backend","client","cross_role"):
            facts,http=process_fixture()
            if category=="service":
                values=[row["identity"] for row in facts if row["event"]=="service_started"]
            elif category=="backend":values=next(row for row in facts if row["event"]=="backend_started")["processes"]
            elif category=="client":values=[row["identity"] for row in facts if row["event"]=="client_process_started"]
            else:
                values=[next(row for row in facts if row["event"]=="backend_started")["processes"][0],
                        next(row for row in facts if row["event"]=="service_started")["identity"]]
            old=oracle.identity(copy.deepcopy(values[1]));new=oracle.identity(copy.deepcopy(values[0]))
            replace(facts,old,new)
            with self.subTest(category=category),self.assertRaisesRegex(ValueError,"impersonates multiple processes"):
                oracle.processes(facts,http)

    def test_reusing_pid_requires_a_disjoint_process_lifetime(self):
        facts,http=process_fixture()
        for row in facts:
            for value in [row]+[item for item in row.values() if isinstance(item,dict)]:
                if value.get("pid")==302:value["pid"]=301
            for value in row.get("processes",[]):
                if value.get("pid")==302:value["pid"]=301
        with self.assertRaisesRegex(ValueError,"overlapping independent lifetimes"):
            oracle.processes(facts,http)
        facts,http=process_fixture()
        for row in facts:
            for value in [row]+[item for item in row.values() if isinstance(item,dict)]:
                if value.get("pid")==303:value["pid"]=301
        # The old PID can be allocated to a new child after the kernel wait4.
        self.assertEqual(oracle.processes(facts,http)["services"],3)

    def test_complete_owned_process_incarnations_cache_loss_and_recovery_are_recomputed(self):
        facts,http=process_fixture()
        self.assertTrue(oracle.processes(facts,http)["kernel_wait4_verified"])
        # A newly allocated loopback port may legitimately reuse an old stopped
        # endpoint; its service incarnation and lifetime remain distinct.
        next(row for row in facts if row["event"]=="service_started" and row["owner_instance"]==5003)["endpoint"]="http://127.0.0.1:5001"
        next(row for row in http if row["event"]=="http_request" and row["phase"]=="recover")["url"]="http://127.0.0.1:5001/v1"
        self.assertTrue(oracle.processes(facts,http)["kernel_wait4_verified"])

    def test_changed_incarnations_non_kernel_exits_early_replacements_and_missing_events_fail(self):
        for fault in ("backend_incarnation","backend_source","replacement_before_cut","restart_after_recovery","service_incarnation","service_source",
                      "cache_still_exists","cache_wrong_path","old_compute_recovery","wrong_client_child","http_before_start","orphan_phase","missing_stop"):
            facts,http=process_fixture()
            def event(name):return next(row for row in facts if row["event"]==name)
            if fault=="backend_incarnation":event("backend_stopped")["processes"][0]["spawn_monotonic_ns"]+=1
            elif fault=="backend_source":event("backend_cleanup")["processes"][0]["kernel_usage"]["source"]="summary_claim"
            elif fault=="replacement_before_cut":
                event("backend_restarted")["processes"][0]["spawn_monotonic_ns"]=1
                event("backend_cleanup")["processes"][0]["spawn_monotonic_ns"]=1
            elif fault=="restart_after_recovery":event("backend_restarted")["monotonic_ns"]=699
            elif fault=="service_incarnation":event("service_stopped")["spawn_monotonic_ns"]+=1
            elif fault=="service_source":event("service_stopped")["kernel_usage"]["source"]="not_kernel"
            elif fault=="cache_still_exists":event("cache_directory_removed")["exists"]=True
            elif fault=="cache_wrong_path":event("cache_directory_removed")["cache_directory"]="/unrelated"
            elif fault=="old_compute_recovery":next(row for row in http if row["event"]=="http_request" and row["phase"]=="recover")["url"]="http://127.0.0.1:5001/v1"
            elif fault=="wrong_client_child":event("client_phase_finished")["identity"]["pid"]+=1
            elif fault=="http_before_start":next(row for row in http if row["event"]=="http_request")["monotonic_ns"]="1"
            elif fault=="orphan_phase":http.append({"event":"http_request","phase":"unplanned"})
            else:facts.remove(event("service_stopped"))
            with self.subTest(fault=fault),self.assertRaises(ValueError):oracle.processes(facts,http)


if __name__=="__main__":unittest.main()
