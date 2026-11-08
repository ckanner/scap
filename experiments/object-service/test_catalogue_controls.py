"""Synthetic catalogue oracle controls, never real service acceptance evidence."""
import copy
import hashlib
import unittest

import catalogue_oracle as oracle
import test_controls as controls
from test_object_wire import Trace


def creation():
    return {"creator":"11","operation":"1001","name":"目录 Main",
            "scope":{"deployment":"1","tenant":"7","database":"10","incarnation":"20","generation":"30"},
            "expected_name_revision":None}


class CatalogueWireControls(unittest.TestCase):
    def test_required_nullable_revisions_and_all_progress_phases_survive_without_collapsing(self):
        initial={"creation":creation(),"initial_quota":{"max_bytes":"10737418240"},
                 "retention":{"max_entries":4096,"max_result_bytes":"268435456"}}
        oracle.progress(initial,"prepare_create")
        for phase in ("not_reserved","reserved","provisioning","bound","ready","aborting","aborted","deleting","deleted","name_conflict","identity_conflict"):
            value={**copy.deepcopy(initial),"phase":phase,"binding_revision":None,"head_revision":"18446744073709551615"}
            oracle.progress(value,"inspect_create_operation")
            for field in ("binding_revision","head_revision","initial_quota","retention"):
                changed=copy.deepcopy(value);del changed[field]
                with self.subTest(phase=phase,field=field),self.assertRaises((ValueError,KeyError)):oracle.progress(changed,"inspect_create_operation")
        for kind,phases in (("abort_create",("not_reserved","cannot_abort_bound","aborting","aborted")),("delete_name",("not_deleted","deleting","deleted"))):
            for phase in phases:
                value={"creation":creation(),"operation":"9","nonce":"10","phase":phase,"binding_revision":None,"head_revision":None}
                oracle.progress(value,kind)
                changed={**value,"phase":"ready"}
                with self.assertRaises(ValueError):oracle.progress(changed,kind)

    def test_lossy_numbers_invalid_unicode_control_and_proof_fields_are_rejected(self):
        for change in (lambda value:value.update(creator=11),lambda value:value.update(operation="01"),
                       lambda value:value.update(expected_name_revision="0"),lambda value:value.update(name="\x85"),
                       lambda value:value.update(name="é"*65),lambda value:value.update(proof={}),
                       lambda value:value["scope"].update(generation=30)):
            value=creation();change(value)
            with self.assertRaises(ValueError):oracle.reference(value)
        value={"creation":creation(),"binding_revision":"2","head":{"scope":creation()["scope"],"lifecycle":"ready"}}
        oracle.progress(value,"resolve_name")
        for field in ("creation","deletion","source","proof","etag","policy"):
            changed=copy.deepcopy(value);changed["head"][field]=None
            with self.subTest(field=field),self.assertRaises(ValueError):oracle.progress(changed,"resolve_name")
        changed=copy.deepcopy(value);changed["head"]["lifecycle"]="provisioning"
        with self.assertRaises(ValueError):oracle.progress(changed,"resolve_name")


class CatalogueNetworkBindingControls(unittest.TestCase):
    def fixture(self):
        reference=creation()
        intent={"deployment":"1","tenant":"7","principal":"11","action":{"operation":"resume_create","creation":reference}}
        call={"request":{"monotonic_ns":10},"response":{"monotonic_ns":100},"body":{"version":1,**intent["action"]}}
        calls={"call-1":call}
        observed={"resume":{"outcome":{"call_id":"call-1"},"intent":intent}}
        return calls,observed,{"main":reference}

    def test_exact_name_scope_generation_and_original_call_interval_bind_every_object_request(self):
        calls,observed,known=self.fixture()
        digest=hashlib.sha256(creation()["name"].encode()).hexdigest()
        prefix="/scap-test/scap-object/v1/1/7/"
        paths=[prefix+"catalogue/v1/name/"+digest,prefix+"catalogue/v1/create/11/1001",
               prefix+"catalogue/v1/abort-proof/11/1001",prefix+"10/head",prefix+"10/inc/20/gen/30/objects/"+"a"*64]
        for path in paths:oracle.bind_requests({1:{"monotonic_ns":50,"path":path,"method":"GET"}},calls,observed,known)
        for path in [prefix+"catalogue/v1/name/"+"a"*64,prefix+"catalogue/v1/create/12/1001",
                     prefix+"11/head",prefix+"10/inc/20/gen/31/objects/"+"a"*64,
                     prefix+"catalogue/v1/control/12/delete/99","/scap-test/scap-object/v1/1/8/10/head"]:
            with self.subTest(path=path),self.assertRaises(ValueError):
                oracle.bind_requests({1:{"monotonic_ns":50,"path":path,"method":"GET"}},calls,observed,known)
        for time in (9,10,100,101):
            with self.subTest(time=time),self.assertRaises(ValueError):
                oracle.bind_requests({1:{"monotonic_ns":time,"path":paths[0],"method":"GET"}},calls,observed,known)

    def test_reading_persisted_control_proof_does_not_authorize_rewriting_it(self):
        calls,observed,known=self.fixture()
        control={"deployment":"1","tenant":"7","principal":"12","action":{"operation":"delete_name","creation":creation(),"control_operation":"99"}}
        observed["delete"]={"outcome":{"call_id":"delete"},"intent":control}
        calls["delete"]={"request":{"monotonic_ns":1},"response":{"monotonic_ns":5},"body":control["action"]}
        request={"monotonic_ns":50,"path":"/scap-test/scap-object/v1/1/7/catalogue/v1/control/12/delete/99","method":"GET"}
        oracle.bind_requests({1:request},calls,observed,known)
        with self.assertRaises(ValueError):oracle.bind_requests({1:{**request,"method":"PUT"}},calls,observed,known)

    def test_failed_resolve_can_read_same_name_abort_proof_without_exposing_creation(self):
        calls,observed,known=self.fixture()
        action={"operation":"resolve_name","name":creation()["name"]}
        calls["call-1"]["body"]={"version":1,**action}
        calls["call-1"]["value"]={"ok":False,"error":{"code":"DENIED"}}
        observed["resume"]["intent"]["action"]=action
        request={"monotonic_ns":50,"path":"/scap-test/scap-object/v1/1/7/catalogue/v1/abort-proof/11/1001","method":"GET"}
        oracle.bind_requests({1:request},calls,observed,known)
        for change in ({"method":"PUT"},{"path":request["path"].replace("1001","1002")},
                       {"path":request["path"].replace("/1/7/","/1/8/")},{"monotonic_ns":101}):
            with self.subTest(change=change),self.assertRaises(ValueError):
                oracle.bind_requests({1:{**request,**change}},calls,observed,known)
        for target in ("10/head","catalogue/v1/name/"+hashlib.sha256(creation()["name"].encode()).hexdigest()):
            changed={**request,"method":"PUT","path":"/scap-test/scap-object/v1/1/7/"+target}
            with self.assertRaises(ValueError):oracle.bind_requests({1:changed},calls,observed,known)
        known["main"]["name"]="another name"
        with self.assertRaises(ValueError):oracle.bind_requests({1:request},calls,observed,known)

    def test_reuse_reads_same_name_prior_head_but_cannot_write_it_or_read_prior_data(self):
        calls,observed,known=self.fixture()
        prior=copy.deepcopy(creation());prior["operation"]="900";prior["scope"]["database"]="9"
        known["prior"]=prior
        request={"monotonic_ns":50,"path":"/scap-test/scap-object/v1/1/7/9/head","method":"GET"}
        oracle.bind_requests({1:request},calls,observed,known)
        for change in ({"method":"PUT"},{"path":"/scap-test/scap-object/v1/1/7/9/inc/20/gen/30/objects/"+"a"*64},
                       {"path":request["path"].replace("/1/7/","/1/8/")},{"monotonic_ns":101}):
            with self.subTest(change=change),self.assertRaises(ValueError):
                oracle.bind_requests({1:{**request,**change}},calls,observed,known)
        known["prior"]["name"]="another name"
        with self.assertRaises(ValueError):oracle.bind_requests({1:request},calls,observed,known)

    def test_global_object_serial_inventory_cannot_silently_omit_an_exchange(self):
        trace=Trace()
        for serial in (1,2,3):
            trace.exchange("GET",begin=serial*10,end=serial*10+4,status=404,response=b"absent")
        history=trace.history
        requests,responses=oracle.object_exchanges(history)
        self.assertEqual(set(requests),{1,2,3});self.assertEqual(set(responses),{1,2,3})
        for changed in ([row for row in history if row["request_serial"]!=2],
                        [row for row in history if row["event"]!="object_forwarded"],
                        history+[copy.deepcopy(history[0])]):
            with self.assertRaises(ValueError):oracle.object_exchanges(changed)


class CatalogueCliControls(unittest.TestCase):
    def test_directory_run_refuses_unit_profiles_before_any_child(self):
        for variable,value in (("LLVM_PROFILE_FILE","forbidden"),("NODE_V8_COVERAGE","forbidden"),
                               ("RUSTFLAGS","-Cinstrument-coverage"),("CARGO_ENCODED_RUSTFLAGS","-C\x1finstrument-coverage")):
            with self.subTest(variable=variable):controls.CliPreflightControls.poison_case(self,"catalogue_contract.py",variable,value)


if __name__=="__main__":unittest.main()
