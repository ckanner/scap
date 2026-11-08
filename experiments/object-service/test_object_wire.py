"""Synthetic raw-wire mutation controls, never evidence of a real S3 run."""
import copy
import hashlib
import json
import unittest

import audit_wire as wire


HEAD = "/scap-test/scap-object/v1/1/7/10/head"


def body(revision):
    return json.dumps({"format":3,"revision":revision},separators=(",",":")).encode()


class Trace:
    def __init__(self):
        self.history=[]
        self.serial=0

    def exchange(self,method,*,begin,end,status=200,request=b"",response=b"",etag=None,
                 match=None,create=None,phase="initial",path=HEAD,fault=None,delivery=None):
        self.serial+=1
        prefix="head" if path.endswith("/head") else "catalogue" if "/catalogue/v1/" in path else None
        common={"request_serial":self.serial,"phase":phase,"method":method,"path":path,
                "request_bytes":len(request),"request_sha256":hashlib.sha256(request).hexdigest(),
                "if_match":match,"if_none_match":create}
        if prefix:common[prefix+"_request_bytes"]=list(request)
        self.history.append({**common,"event":"object_request","monotonic_ns":begin})
        if fault:
            self.history.append({**common,"event":"transport_fault_observed","monotonic_ns":begin+1,
                                 "mode":fault,"stage":"before_forward","matched_ordinal":1})
        if fault=="blackhole":return self.serial
        self.history.append({**common,"event":"object_forwarded","monotonic_ns":begin+2})
        received={"status":status,"response_bytes":len(response),"response_sha256":hashlib.sha256(response).hexdigest(),"etag":etag}
        if prefix:received[prefix+"_response_bytes"]=list(response)
        self.history.append({**common,**received,"event":"object_response","monotonic_ns":end,
                             "response_origin":"backend","suppressed":fault=="drop"})
        if fault!="drop":
            self.history.append({**common,**received,"event":"object_response_delivered","monotonic_ns":delivery or end+1})
        return self.serial

    def audit(self,**options):
        requests,responses=wire.object_exchanges(self.history,phases=("initial","blackhole"),blackhole_phases=("blackhole",))
        return wire.object_versions(requests,responses,**options)


def version_trace():
    trace=Trace()
    trace.exchange("GET",begin=10,end=15,status=404,response=b"not found")
    trace.exchange("PUT",begin=20,end=30,request=body(1),etag='"opaque-v1"',create="*")
    trace.exchange("GET",begin=40,end=45,response=body(1),etag='"opaque-v1"')
    trace.exchange("PUT",begin=50,end=60,request=body(2),etag='"opaque-v2"',match='"opaque-v1"')
    trace.exchange("GET",begin=70,end=75,response=body(2),etag='"opaque-v2"')
    return trace


class OriginalExchangeControls(unittest.TestCase):
    def test_complete_original_bytes_etags_and_conditional_versions_pass(self):
        result=version_trace().audit()
        self.assertEqual(result["accepted_versions"],2)
        self.assertEqual(result["exact_get_body_etag_pairs"],2)

    def test_missing_or_changed_original_events_etags_bodies_and_conditions_fail(self):
        for fault in ("missing_delivery","delivery_body","delivery_etag","delivery_call","missing_forward",
                      "missing_response","missing_serial","injected","get_etag","get_body","request_body",
                      "unconditional","double_condition","gap","duplicate","early_delivery","wrong_origin"):
            trace=version_trace()
            def event(serial,kind):return next(row for row in trace.history if row["request_serial"]==serial and row["event"]==kind)
            if fault=="missing_delivery":trace.history=[row for row in trace.history if row["event"]!="object_response_delivered"]
            elif fault=="delivery_body":event(3,"object_response_delivered")["head_response_bytes"]=list(body(2))
            elif fault=="delivery_etag":event(3,"object_response_delivered")["etag"]='"different"'
            elif fault=="delivery_call":event(3,"object_response_delivered")["request_serial"]=4
            elif fault=="missing_forward":trace.history.remove(event(3,"object_forwarded"))
            elif fault=="missing_response":trace.history.remove(event(3,"object_response"))
            elif fault=="missing_serial":del event(3,"object_request")["request_serial"]
            elif fault=="injected":event(3,"object_response")["event"]="injected_response"
            elif fault=="get_etag":
                for kind in ("object_response","object_response_delivered"):event(3,kind)["etag"]=None
            elif fault=="get_body":
                for kind in ("object_response","object_response_delivered"):
                    row=event(3,kind);row["head_response_bytes"]=list(body(2));row["response_sha256"]=hashlib.sha256(body(2)).hexdigest()
            elif fault=="request_body":event(2,"object_request")["head_request_bytes"]=list(body(2))
            elif fault in ("unconditional","double_condition"):
                for row in trace.history:
                    if row["request_serial"]==4:row["if_none_match"]="*" if fault=="double_condition" else None;row["if_match"]='"opaque-v1"' if fault=="double_condition" else None
            elif fault=="gap":trace.history=[row for row in trace.history if row["request_serial"]!=3]
            elif fault=="duplicate":trace.history.append(copy.deepcopy(event(3,"object_request")))
            elif fault=="early_delivery":event(3,"object_response_delivered")["monotonic_ns"]=44
            else:event(3,"object_response")["response_origin"]="proxy"
            with self.subTest(fault=fault),self.assertRaises((ValueError,KeyError)):trace.audit()

    def test_complete_catalogue_body_capture_is_required_too(self):
        trace=Trace();raw=b'{"format":1,"state":"reserved"}'
        trace.exchange("PUT",begin=10,end=20,path="/scap-test/scap-object/v1/1/7/catalogue/v1/name/"+"a"*64,
                       request=raw,create="*",etag='"name-v1"')
        trace.audit()
        for row in trace.history:row.pop("catalogue_request_bytes",None)
        with self.assertRaises(KeyError):trace.audit()

    def test_accepted_response_loss_and_explicit_before_forward_blackhole_stay_distinct(self):
        trace=Trace();trace.exchange("PUT",begin=10,end=20,request=body(1),create="*",etag='"v1"',fault="drop")
        trace.exchange("GET",begin=30,end=50,phase="blackhole",fault="blackhole")
        self.assertEqual(trace.audit()["blackholed_before_forward"],1)
        for fault in ("missing_fault","wrong_drop_status","unsuppressed","wrong_blackhole_phase"):
            changed=copy.deepcopy(trace)
            if fault=="missing_fault":changed.history=[row for row in changed.history if row["event"]!="transport_fault_observed"]
            elif fault=="wrong_drop_status":next(row for row in changed.history if row["event"]=="object_response")["status"]=412
            elif fault=="unsuppressed":next(row for row in changed.history if row["event"]=="object_response")["suppressed"]=False
            else:
                for row in changed.history:
                    if row["request_serial"]==2:row["phase"]="initial"
            with self.subTest(fault=fault),self.assertRaises(ValueError):changed.audit()


class VersionIntervalControls(unittest.TestCase):
    def test_legal_delayed_get_and_delayed_put_responses_are_not_linearization_points(self):
        for old_read_end,new_write_end,new_read_begin,new_read_end in ((90,60,70,75),(45,100,70,75)):
            trace=version_trace()
            if old_read_end==90:
                # The CAS consumes the promptly delivered second exact read;
                # an independent older GET can legally finish much later.
                trace.exchange("GET",begin=35,end=90,response=body(1),etag='"opaque-v1"')
            else:
                for row in trace.history:
                    if row["request_serial"]==4 and row["event"] in ("object_response","object_response_delivered"):
                        row["monotonic_ns"]=new_write_end+(row["event"]=="object_response_delivered")
            self.assertEqual(trace.audit()["accepted_versions"],2)
        trace=Trace()
        trace.exchange("PUT",begin=10,end=90,request=body(1),create="*",etag='"v1"')
        trace.exchange("GET",begin=20,end=30,response=body(1),etag='"v1"')
        trace.audit()

    def test_true_stale_read_false_absence_and_future_read_are_rejected(self):
        for fault in ("stale","false_404","future","false_before_root"):
            trace=version_trace()
            if fault=="stale":trace.exchange("GET",begin=80,end=90,response=body(1),etag='"opaque-v1"')
            elif fault=="false_404":trace.exchange("GET",begin=80,end=90,status=404,response=b"absent")
            elif fault=="future":trace.exchange("GET",begin=31,end=36,response=body(2),etag='"opaque-v2"')
            else:
                for row in trace.history:
                    if row["request_serial"]==1:row["monotonic_ns"]+=65
            with self.subTest(fault=fault),self.assertRaises(ValueError):trace.audit()

    def test_successful_and_failed_cas_follow_the_observed_predecessor_version(self):
        trace=version_trace()
        trace.exchange("PUT",begin=80,end=90,status=412,request=body(3),match='"opaque-v1"')
        trace.exchange("PUT",begin=100,end=110,status=412,request=body(3),create="*")
        trace.audit()
        for fault in ("reject_current","reject_empty","accept_stale","wrong_etag","reject_before_successor"):
            changed=version_trace()
            if fault=="reject_current":changed.exchange("PUT",begin=80,end=90,status=412,request=body(3),match='"opaque-v2"')
            elif fault=="reject_empty":
                changed=Trace();changed.exchange("PUT",begin=10,end=20,status=412,request=body(1),create="*")
            elif fault=="accept_stale":changed.exchange("PUT",begin=80,end=90,request=body(3),match='"opaque-v1"',etag='"v3"')
            elif fault=="wrong_etag":changed.exchange("PUT",begin=80,end=90,request=body(3),match='"missing"',etag='"v3"')
            else:changed.exchange("PUT",begin=46,end=49,status=412,request=body(3),match='"opaque-v1"')
            with self.subTest(fault=fault),self.assertRaises(ValueError):changed.audit()

    def test_cas_cannot_borrow_an_exact_get_from_another_http_call(self):
        trace=version_trace()
        calls={"a":{"request":{"monotonic_ns":1},"response":{"monotonic_ns":49}},
               "b":{"request":{"monotonic_ns":49},"response":{"monotonic_ns":100}}}
        with self.assertRaisesRegex(ValueError,"same-call exact GET"):trace.audit(calls=calls)
        combined={"all":{"request":{"monotonic_ns":1},"response":{"monotonic_ns":100}}}
        trace.audit(calls=combined)
        bindings={number:{"all"} for number in range(1,6)};bindings[3]=set()
        with self.assertRaisesRegex(ValueError,"invoking HTTP call"):trace.audit(calls=combined,bindings=bindings)

    def test_late_delivery_logger_is_legal_but_backend_after_http_return_is_not(self):
        trace=version_trace()
        calls={"all":{"request":{"monotonic_ns":1},"response":{"monotonic_ns":100}}}
        delivery=next(row for row in trace.history if row["request_serial"]==5 and row["event"]=="object_response_delivered")
        delivery["monotonic_ns"]=110
        trace.audit(calls=calls)
        response=next(row for row in trace.history if row["request_serial"]==5 and row["event"]=="object_response")
        response["monotonic_ns"]=105
        with self.assertRaisesRegex(ValueError,"backend response"):trace.audit(calls=calls)


if __name__=="__main__":unittest.main()
