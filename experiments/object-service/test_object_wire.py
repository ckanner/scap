"""Synthetic raw-wire mutation controls, never evidence of a real S3 run."""
import copy
import hashlib
import json
import unittest

import audit_wire as wire


HEAD = "/scap-test/scap-object/v1/1/7/10/head"


def body(revision):
    value = {"format": 5, "head_serial": revision,
             "storage": {"active_generation": 1, "allocated_through": 1},
             "scope": {"deployment": 1, "tenant": 7, "database": 10, "incarnation": 1, "generation": 1},
             "revision": revision, "transition": {"revision": revision, "nonce": revision}, "sequence": 0,
             "owner_epoch": 1, "owner_instance": 7, "active": False, "auth_epoch": 1,
             "policy": [{"principal": 11, "read": True, "write": True, "admin": True}],
             "lifecycle": "ready", "creation": None, "deletion": None, "data_root": "a" * 64,
             "quota": {"max_bytes": None}, "retention": {"max_entries": 4096, "max_result_bytes": 2**28},
             "request_epoch": 1, "windows": [{"epoch": 1, "root": "b" * 64, "count": 0, "result_bytes": 0}]}
    return json.dumps(value, separators=(",", ":")).encode()


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
        trace.exchange("PUT",begin=80,end=90,status=412,request=body(2),match='"opaque-v1"')
        trace.exchange("PUT",begin=100,end=110,status=412,request=body(1),create="*")
        trace.audit()
        for fault in ("reject_current","reject_empty","accept_stale","wrong_etag","reject_before_successor"):
            changed=version_trace()
            if fault=="reject_current":changed.exchange("PUT",begin=80,end=90,status=412,request=body(3),match='"opaque-v2"')
            elif fault=="reject_empty":
                changed=Trace();changed.exchange("PUT",begin=10,end=20,status=412,request=body(1),create="*")
            elif fault=="accept_stale":changed.exchange("PUT",begin=80,end=90,request=body(2),match='"opaque-v1"',etag='"v3"')
            elif fault=="wrong_etag":changed.exchange("PUT",begin=80,end=90,request=body(3),match='"missing"',etag='"v3"')
            else:changed.exchange("PUT",begin=46,end=49,status=412,request=body(2),match='"opaque-v1"')
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


class HeadFiveBoundaryControls(unittest.TestCase):
    def test_strict_required_metadata_rejects_legacy_missing_null_bool_and_future_storage(self):
        original = wire.parse(body(2))
        wire.head5_profile(original)
        changes = [
            ("legacy", lambda h: h.update(format=4), "HEAD is not format 5"),
            ("future", lambda h: h.update(format=6), "HEAD is not format 5"),
            ("serial_missing", lambda h: h.pop("head_serial"), "HEAD5 fields"),
            ("storage_missing", lambda h: h.pop("storage"), "HEAD5 fields"),
            ("storage_null", lambda h: h.update(storage=None), "incomplete HEAD5 storage"),
            ("storage_empty", lambda h: h.update(storage={}), "incomplete HEAD5 storage"),
            ("unsupported_pins", lambda h: h.update(pins=[]), "HEAD5 fields"),
            ("unsupported_stage", lambda h: h["storage"].update(staging=None), "incomplete HEAD5 storage"),
            ("active_zero", lambda h: h["storage"].update(active_generation=0), "invalid HEAD unsigned integer"),
            ("active_bool", lambda h: h["storage"].update(active_generation=True), "invalid HEAD unsigned integer"),
            ("allocated_two", lambda h: h["storage"].update(allocated_through=2), "unsupported HEAD5 storage generation"),
            ("both_two", lambda h: h.update(storage={"active_generation": 2, "allocated_through": 2}), "unsupported HEAD5 storage generation"),
            ("serial_zero", lambda h: h.update(head_serial=0), "invalid HEAD unsigned integer"),
            ("serial_bool", lambda h: h.update(head_serial=True), "invalid HEAD unsigned integer"),
            ("serial_overflow", lambda h: h.update(head_serial=2**64), "invalid HEAD unsigned integer"),
            ("serial_behind", lambda h: h.update(head_serial=1), "serial precedes logical revision"),
        ]
        for name, change, reason in changes:
            candidate = copy.deepcopy(original); change(candidate)
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, reason):
                wire.head5_profile(candidate)

    def test_acl_bound_matches_production_1024_without_lowering_it(self):
        head = wire.parse(body(1))
        head["policy"] = [{"principal": n, "read": True, "write": False, "admin": n == 1}
                          for n in range(1, 1025)]
        wire.head5_profile(head)
        head["policy"].append({"principal": 1025, "read": True, "write": False, "admin": False})
        with self.assertRaisesRegex(ValueError, "1024-principal bound"):
            wire.head5_profile(head)

    def test_serial_and_business_revision_are_checked_separately_against_original_base(self):
        previous = wire.parse(body(2)); previous["head_serial"] = 8
        candidate = wire.parse(body(3)); candidate["head_serial"] = 9
        wire.head5_publication(candidate, previous)
        for serial in (8, 10):
            changed = copy.deepcopy(candidate); changed["head_serial"] = serial
            with self.subTest(serial=serial), self.assertRaisesRegex(ValueError, "original head serial"):
                wire.head5_publication(changed, previous)
        changed = copy.deepcopy(candidate); changed["revision"] = 4
        changed["transition"]["revision"] = 4
        with self.assertRaisesRegex(ValueError, "business publication revision"):
            wire.head5_publication(changed, previous)
        changed = copy.deepcopy(candidate); changed["scope"]["generation"] = 2
        with self.assertRaisesRegex(ValueError, "logical Scope"):
            wire.head5_publication(changed, previous)
        with self.assertRaisesRegex(ValueError, "initial authority"):
            wire.head5_publication(candidate)

    def test_consistent_raw_wire_hashes_do_not_hide_a_skipped_head_serial(self):
        trace = version_trace()
        modified = wire.parse(body(2)); modified["head_serial"] = 3
        raw = json.dumps(modified, separators=(",", ":")).encode()
        for row in trace.history:
            if row["request_serial"] == 4:
                row.update(request_bytes=len(raw), request_sha256=hashlib.sha256(raw).hexdigest(),
                           head_request_bytes=list(raw))
            if row["request_serial"] == 5 and row["event"] in ("object_response", "object_response_delivered"):
                row.update(response_bytes=len(raw), response_sha256=hashlib.sha256(raw).hexdigest(),
                           head_response_bytes=list(raw))
        with self.assertRaisesRegex(ValueError, "original head serial"):
            trace.audit()

    def test_consistent_raw_wire_hashes_do_not_bypass_nested_head_schema(self):
        for name, change, reason in (
            ("scope", lambda h: h["scope"].update(incarnation=0), "invalid HEAD unsigned integer"),
            ("transition", lambda h: h["transition"].update(revision=1), "revision/transition mismatch"),
            ("policy", lambda h: h["policy"][0].update(admin=False), "HEAD has no ADMIN"),
            ("duplicate_principal", lambda h: h["policy"].append(copy.deepcopy(h["policy"][0])),
             "invalid or duplicate HEAD permission"),
            ("window", lambda h: h["windows"][0].update(epoch=2), "HEAD window epoch changed"),
            ("quota", lambda h: h["quota"].update(max_bytes=4097), "quota page alignment/bound"),
        ):
            trace = version_trace()
            modified = wire.parse(body(2)); change(modified)
            raw = json.dumps(modified, separators=(",", ":")).encode()
            for row in trace.history:
                if row["request_serial"] == 4:
                    row.update(request_bytes=len(raw), request_sha256=hashlib.sha256(raw).hexdigest(),
                               head_request_bytes=list(raw))
                if row["request_serial"] == 5 and row["event"] in ("object_response", "object_response_delivered"):
                    row.update(response_bytes=len(raw), response_sha256=hashlib.sha256(raw).hexdigest(),
                               head_response_bytes=list(raw))
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, reason):
                trace.audit()

    def test_flat_or_unimplemented_storage_paths_are_not_valid_object_witnesses(self):
        path = "/scap-test/scap-object/v1/1/7/10/inc/1/gen/1/storage/1/objects/" + hashlib.sha256(b"frame").hexdigest()
        good = Trace(); good.exchange("PUT", begin=10, end=20, path=path, request=b"frame", create="*", etag='"obj"')
        good.audit()
        for invalid in (path.replace("/storage/1", ""), path.replace("/storage/1", "/storage/2")):
            trace = Trace(); trace.exchange("PUT", begin=10, end=20, path=invalid, request=b"frame", create="*", etag='"obj"')
            with self.subTest(path=invalid), self.assertRaisesRegex(ValueError, "physical namespace"):
                trace.audit()


if __name__=="__main__":unittest.main()
