"""Synthetic original receipt/process controls; no native or S3 acceptance."""
import copy
import hashlib
import io
import json
from pathlib import Path
import tarfile
import unittest
from unittest import mock

import audit_build
import catalogue_oracle
import lifecycle_oracle
import test_build


def build_fixture(test):
    fixture=test_build.NetworkBuildEvidenceTests(methodName="test_complete_build_syncs_both_logs_before_reading_and_syncs_the_receipt")
    fixture.setUp()
    test.addCleanup(fixture.doCleanups)
    record=fixture.invoke()
    evidence=fixture.directory/"captured"
    evidence.mkdir()
    fixture.builder.capture_receipt(fixture.evidence/"build.json",fixture.binary,evidence)
    return fixture,record,evidence


class OriginalBuildControls(unittest.TestCase):
    def setUp(self):
        self.fixture,self.record,self.evidence=build_fixture(self)

    def audit(self,**options):
        return audit_build.receipt(self.evidence,profile="network",**options)

    def mutate_receipt(self,action):
        path=self.evidence/"build-receipt.json"
        value=json.loads(path.read_text());action(value)
        path.write_text(json.dumps(value)+"\n")

    def mutate_cargo(self,action):
        path=self.evidence/"build-cargo.stdout.jsonl"
        events=[json.loads(line) for line in path.read_text().splitlines()]
        action(events);path.write_text("".join(json.dumps(event)+"\n" for event in events))
        self.mutate_receipt(lambda value:value.update(build_stdout_sha256=hashlib.sha256(path.read_bytes()).hexdigest()))

    def test_original_compiler_native_link_source_archive_and_binary_are_all_verified(self):
        result=self.audit()
        self.assertEqual(result["verification_scope"],"full")
        self.assertEqual(result["source_files_verified"],len(self.record["inputs"]))
        self.assertEqual(result["executable_native_bytes"],"verified")

    def test_rebound_manifest_cannot_omit_a_real_source_input(self):
        name="crates/scap-sql/src/lib.rs"
        def omit(value):
            del value["inputs"][name]
            value["input_sha256"]=hashlib.sha256(json.dumps(value["inputs"],sort_keys=True,separators=(",",":")).encode()).hexdigest()
            manifest=self.evidence/"build-source-manifest.json"
            manifest.write_text(json.dumps({"schema":1,"source_commit":value["source_commit"],"inputs":value["inputs"]}))
            value["archived_evidence"]["source_manifest_sha256"]=hashlib.sha256(manifest.read_bytes()).hexdigest()
            target=self.evidence/"build-source.tar"
            with tarfile.open(target) as source:
                kept=[(member,source.extractfile(member).read()) for member in source.getmembers() if member.name!=name]
            with tarfile.open(target,"w") as archive:
                for member,raw in kept:archive.addfile(member,io.BytesIO(raw))
            value["archived_evidence"]["source_archive_sha256"]=hashlib.sha256(target.read_bytes()).hexdigest()
        self.mutate_receipt(omit)
        with self.assertRaisesRegex(ValueError,"source manifest differs"):self.audit()

    def test_nonzero_or_boolean_exit_is_not_success_even_with_passed_claim(self):
        for code in (101,False):
            self.mutate_receipt(lambda value:value.update(exit_code=code))
            with self.subTest(code=code),self.assertRaisesRegex(ValueError,"Cargo process"):
                self.audit()

    def test_changed_cargo_command_compiler_and_raw_bytes_are_rejected(self):
        original=(self.evidence/"build-receipt.json").read_bytes()
        for fault in ("command","rustc","cargo","stdout_digest"):
            (self.evidence/"build-receipt.json").write_bytes(original)
            def change(value):
                if fault=="command":value["command"]=["not-cargo","--debug"]
                elif fault=="rustc":value["versions"]["rustc"]="arbitrary compiler"
                elif fault=="cargo":value["versions"]["cargo"]="cargo 9.9.9"
                else:value["build_stdout_sha256"]="0"*64
            self.mutate_receipt(change)
            with self.subTest(fault=fault),self.assertRaises(ValueError):self.audit()

    def test_same_hash_claim_does_not_substitute_an_unrelated_file_for_native_or_binary(self):
        original=(self.evidence/"build-receipt.json").read_bytes()
        path=self.fixture.source/"Cargo.toml";digest=hashlib.sha256(path.read_bytes()).hexdigest()
        for kind in ("binary","native"):
            (self.evidence/"build-receipt.json").write_bytes(original)
            self.mutate_receipt(lambda value:value.update(**({"binary":{"path":str(path),"sha256":digest}} if kind=="binary" else
                                                            {"native_archives":{str(path):digest}})))
            with self.subTest(kind=kind),self.assertRaises(ValueError):self.audit()

    def test_cargo_events_must_identify_original_source_release_and_static_native_link(self):
        receipt=(self.evidence/"build-receipt.json").read_bytes()
        raw=(self.evidence/"build-cargo.stdout.jsonl").read_bytes()
        for fault in ("source","manifest","profile","filenames","link_library","link_path","native_record","finished","tail"):
            (self.evidence/"build-receipt.json").write_bytes(receipt)
            (self.evidence/"build-cargo.stdout.jsonl").write_bytes(raw)
            def change(events):
                if fault=="source":events[1]["target"]["src_path"]="/other/main.rs"
                elif fault=="manifest":events[1]["manifest_path"]="/other/Cargo.toml"
                elif fault=="profile":events[1]["profile"]["test"]=True
                elif fault=="filenames":events[1]["filenames"]=["/other/scap-object-network"]
                elif fault=="link_library":events[0]["linked_libs"]=["dylib=sqlite3"]
                elif fault=="link_path":events[0]["linked_paths"]=["native=/unrelated"]
                elif fault=="native_record":events.insert(0,copy.deepcopy(events[0]))
                elif fault=="finished":events[-1]["success"]=False
                else:events.append({"reason":"compiler-artifact","executable":None})
            self.mutate_cargo(change)
            with self.subTest(fault=fault),self.assertRaises(ValueError):self.audit()

    def test_partial_offline_scope_is_explicit_when_original_machine_paths_are_gone(self):
        self.fixture.target.rename(self.fixture.directory/"moved-target")
        with self.assertRaisesRegex(ValueError,"unavailable"):self.audit()
        result=self.audit(require_artifacts=False)
        self.assertEqual(result["verification_scope"],"archived_source_and_cargo_only")
        self.assertEqual(result["executable_native_bytes"],"NOT_AVAILABLE")

    def test_cleaned_archive_in_a_retained_directory_is_partial_without_hiding_changed_bytes(self):
        self.fixture.archive.unlink()
        self.assertTrue(self.fixture.native.is_dir())
        with self.assertRaisesRegex(ValueError,"unavailable"):self.audit()
        result=self.audit(require_artifacts=False)
        self.assertEqual(result["verification_scope"],"archived_source_and_cargo_only")
        self.assertEqual(result["unavailable_artifacts"],[str(self.fixture.archive)])
        self.assertEqual(result["retrieved_artifacts"],[str(self.fixture.binary)])
        self.fixture.archive.write_bytes(b"different native bytes")
        with self.assertRaisesRegex(ValueError,"bytes differ"):self.audit(require_artifacts=False)

    def test_both_offline_cli_wrappers_return_nonzero_for_partial_audits(self):
        for module in (catalogue_oracle,lifecycle_oracle):
            with (self.subTest(module=module.__name__),mock.patch.object(module,"audit",return_value={"status":"partial"}) as called,
                    mock.patch("sys.stdout",new_callable=io.StringIO)):
                self.assertEqual(module.main(["--evidence",str(self.evidence),"--allow-unavailable-artifacts"]),1)
                self.assertFalse(called.call_args.kwargs["require_artifacts"])


class OwnedProcessControls(unittest.TestCase):
    def identity(self,pid,spawn):return {"pid":pid,"spawn_monotonic_ns":spawn,"pid_source":"owned_Popen_child"}

    def test_role_and_owner_labels_cannot_duplicate_incarnations_or_overlap_one_pid(self):
        for kind in ("duplicate","overlap","source","zero","bool_pid","bool_spawn"):
            inventory=audit_build.OwnedChildren();inventory.register(self.identity(10,100),200)
            changed=self.identity(10,100 if kind=="duplicate" else 150)
            if kind=="source":changed["pid_source"]="summary"
            elif kind=="zero":changed["pid"]=0
            elif kind=="bool_pid":changed["pid"]=True
            elif kind=="bool_spawn":changed["spawn_monotonic_ns"]=True
            with self.subTest(kind=kind),self.assertRaises(ValueError):inventory.register(changed,220)
        inventory=audit_build.OwnedChildren();inventory.register(self.identity(10,100),200)
        inventory.register(self.identity(10,210),220)
        self.assertEqual(len(inventory.incarnations),2)


if __name__=="__main__":unittest.main()
