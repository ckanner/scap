#!/usr/bin/env python3
"""Real catalogue HTTP/SDK contracts; exact known identities, not full enumeration."""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
import tempfile

if not __debug__:
    raise RuntimeError("validation requires Python assertions; disable -O/PYTHONOPTIMIZE")

import build
import catalogue_oracle

HERE = Path(__file__).resolve().parent
specification = importlib.util.spec_from_file_location("scap_catalogue_service_fixture", HERE / "run.py")
fixture = importlib.util.module_from_spec(specification)
specification.loader.exec_module(fixture)
ROOT = HERE.parents[1]
PHASES = ("initial", "saturation_held", "saturation_probe", "abort_prepare", "abort_resume_held", "abort_win", "abort_finish",
          "descriptor_unknown", "descriptor_recover", "ready_unknown", "ready_recover", "delete_unknown", "delete_recover", "reuse", "recover")
ADMISSION = {"workers":1,"queued_total":4,"queued_per_tenant":3,"queued_per_name":2,
             "intake":1,"max_body_bytes":65536,"timeout_ms":10000}
CONTRACTS = ("strict_original_intent_and_current_provision", "reserved_abort_and_late_provision_fence",
             "descriptor_ready_delete_unknown_preserve_intent", "admin_only_delete_and_name_reuse",
             "isolated_catalogue_capacity_and_all_process_recovery")


class Suite:
    def __init__(self, args, evidence, private, node):
        self.args, self.evidence, self.private, self.node = args, evidence, private, node
        self.facts = fixture.Facts(evidence)
        self.backend = self.proxy = None
        self.services, self.children = [], {}
        self.started = []

    def start_service(self, owner):
        service = fixture.Service(self.args.server.resolve(), self.private, owner, self.proxy.endpoint,
                                  self.tokens, self.backend, self.facts, catalogue=ADMISSION)
        self.services.append(service)
        return service

    def setup(self):
        self.backend = fixture.Backend(self.args.weed.resolve(), self.private / "backend")
        self.backend.start()
        self.backend_directory = fixture.sha(str(self.backend.directory.resolve()))
        self.facts.emit("backend_started", processes=self.backend.identities(), directory_identity=self.backend_directory)
        self.proxy = fixture.Proxy(self.backend.port, self.evidence)
        self.proxy.capture = True
        self.proxy.capture_catalogue = True
        self.tokens = {key:secrets.token_hex(32) for key in ("admin","reader","other","rival")}
        self.first, self.second = self.start_service(5001), self.start_service(5002)

    def state(self):
        return json.loads((self.evidence / "catalogue-state.json").read_text())

    def begin(self, phase, primary=None, secondary=None):
        assert phase not in self.started, "duplicate client phase"
        self.started.append(phase)
        primary, secondary = primary or self.first, secondary or self.second
        self.proxy.set_phase(phase)
        configuration = self.private / (phase + ".client.private.json")
        configuration.write_text(json.dumps({"endpoint":primary.endpoint,"secondary":secondary.endpoint,"tokens":self.tokens}))
        configuration.chmod(0o600)
        self.facts.emit("client_phase_started", phase=phase, primary=primary.identity, secondary=secondary.identity)
        with (self.evidence / (phase + ".stdout.log")).open("wb") as stdout, (self.evidence / (phase + ".stderr.log")).open("wb") as stderr:
            child = subprocess.Popen([str(self.node),str(HERE / "catalogue_probe.mjs"),phase,str(configuration),str(self.evidence)],
                                     cwd=ROOT,stdout=stdout,stderr=stderr)
        identity = fixture.process_identity(child)
        self.children[phase] = (child, identity)
        self.facts.emit("client_process_started", phase=phase, identity=identity)

    def finish(self, phase):
        child, identity = self.children[phase]
        status, usage = fixture.wait_child(child,90)
        del self.children[phase]
        self.facts.emit("client_phase_finished", phase=phase, identity=identity, wait_status=status, kernel_usage=usage)
        assert status == 0, f"catalogue SDK phase failed: {phase}"

    def phase(self, name, primary=None, secondary=None):
        self.begin(name,primary,secondary)
        self.finish(name)

    def observed_fault(self, name, rule):
        assert rule.arrived.is_set() and rule.used == 1
        self.facts.emit("catalogue_fault_observed", label=name, observation=rule.observation,
                        payload=base64.b64encode(rule.payload).decode(), payload_sha256=hashlib.sha256(rule.payload).hexdigest())

    @staticmethod
    def head(creation):
        scope=creation["scope"]
        return f"scap-object/v1/{scope['deployment']}/{scope['tenant']}/{scope['database']}/head"

    def run(self):
        self.setup()
        self.phase("initial")
        # Freeze the directory exact-read key from the observed successful
        # resolve call, not an in-memory routing authority or bucket listing.
        candidates=[row for row in self.proxy.observations if row.get("event")=="object_request" and row.get("method")=="GET"
                    and row.get("phase")=="initial" and "/catalogue/" in row.get("path","") and "/name/" in row.get("path","")]
        assert candidates, "formal catalogue name GET was not observed"
        name_hash=hashlib.sha256(self.state()["main"]["name"].encode()).hexdigest()
        targets={row["path"] for row in candidates if name_hash in row["path"]}
        assert len(targets)==1, "ambiguous exact name key"
        key=targets.pop().removeprefix("/scap-test/")
        held=self.proxy.arm("hold",method="GET",key=key)
        self.begin("saturation_held")
        assert held.arrived.wait(5), "directory read never reached hold"
        self.observed_fault("saturation",held)
        self.phase("saturation_probe")
        self.facts.emit("catalogue_hold_release",label="saturation",request_serial=held.observation["request_serial"])
        held.release.set();self.finish("saturation_held")
        assert held.finished.wait(3)
        self.proxy.clear()

        self.phase("abort_prepare")
        held=self.proxy.arm("hold",method="PUT",key=self.head(self.state()["aborting"]))
        self.begin("abort_resume_held")
        assert held.arrived.wait(5), "provisioning create never reached hold"
        self.observed_fault("late_provision",held)
        self.phase("abort_win")
        self.facts.emit("catalogue_hold_release",label="late_provision",request_serial=held.observation["request_serial"])
        held.release.set();self.finish("abort_resume_held")
        assert held.finished.wait(3)
        self.proxy.clear();self.phase("abort_finish")

        lost=self.proxy.arm("drop",method="PUT")
        self.phase("descriptor_unknown");self.observed_fault("descriptor_response_loss",lost)
        self.proxy.clear();self.phase("descriptor_recover")
        lost=self.proxy.arm("drop",method="PUT",key=self.head(self.state()["surviving"]),occurrence=2)
        self.phase("ready_unknown");self.observed_fault("ready_response_loss",lost)
        self.proxy.clear();self.phase("ready_recover")
        lost=self.proxy.arm("drop",method="PUT",key=self.head(self.state()["main"]))
        self.phase("delete_unknown");self.observed_fault("delete_response_loss",lost)
        self.proxy.clear();self.phase("delete_recover");self.phase("reuse")

        self.facts.emit("compute_loss_started",processes=[service.identity for service in self.services])
        for service in self.services:
            observed=service.stop(reason="compute_loss")
            assert observed["wait_status"]==-signal.SIGKILL
            shutil.rmtree(service.cache);assert not service.cache.exists()
            self.facts.emit("cache_directory_removed",owner_instance=service.owner,identity=service.identity,
                            cache_directory=str(service.cache),exists=False)
        self.services.clear()
        self.facts.emit("all_compute_lost",live_service_processes=0,all_cache_directories_removed=True)
        self.facts.emit("backend_stop_requested",processes=self.backend.identities(),directory_identity=self.backend_directory)
        killed=self.backend.stop(verify=True)
        self.facts.emit("backend_stopped",processes=killed,directory_identity=self.backend_directory)
        self.backend.start()
        self.facts.emit("backend_restarted",processes=self.backend.identities(),directory_identity=self.backend_directory)
        recovered=self.start_service(5003)
        self.phase("recover",recovered,recovered)
        assert self.started==list(PHASES)
        assert not self.proxy.errors,self.proxy.errors

    def cleanup(self):
        errors=[]
        for phase,(child,identity) in self.children.items():
            try:
                if child.poll() is None:child.kill()
                status,usage=fixture.wait_child(child,10)
                self.facts.emit("client_forced_cleanup",phase=phase,identity=identity,wait_status=status,kernel_usage=usage)
            except BaseException as error:errors.append(repr(error))
        if self.proxy is not None:
            try:self.proxy.close()
            except BaseException as error:errors.append(repr(error))
        for service in self.services:
            try:service.stop()
            except BaseException as error:errors.append(repr(error))
        if self.backend is not None:
            try:self.facts.emit("backend_cleanup",processes=self.backend.stop())
            except BaseException as error:errors.append(repr(error))
        self.facts.emit("cleanup_finished",errors=errors)
        return errors


def main(args):
    evidence=args.evidence.resolve();evidence.mkdir(parents=True,exist_ok=False,mode=0o700)
    private=Path(tempfile.mkdtemp(prefix="scap-catalogue-service-private-",dir=evidence.parent))
    summary={"schema":1,"status":"blocked","diagnostic":False,"aws_standard":"NOT_RUN","complete_catalogue_enumeration":"NOT_IMPLEMENTED",
             "known_original_intents_only":True,"core_cut_matrix":"SEPARATE_CONTRACT","private_fixture_path":str(private),"private_fixture_removed":False}
    suite=None
    try:
        assert "LLVM_PROFILE_FILE" not in os.environ and "NODE_V8_COVERAGE" not in os.environ
        assert not any("instrument-coverage" in os.environ.get(key,"") for key in ("RUSTFLAGS","CARGO_ENCODED_RUSTFLAGS"))
        assert args.server.is_file() and args.weed.is_file()
        before=build.inputs()
        node=Path(shutil.which(args.node) or args.node).resolve()
        version=subprocess.check_output([str(node),"--version"],text=True).strip()
        assert version=="v22.16.0"
        tools={"node":build.digest(node),"weed":build.digest(args.weed)}
        receipt=build.capture_receipt(args.build_record,args.server,evidence)
        assert receipt["node"]==version
        plan={"schema":1,"phases":list(PHASES),"contracts":list(CONTRACTS),"admission":ADMISSION,
              "successful_sql_responses":6,"unique_sql_requests":3,"deleted_sql_responses":2,
              "retained_sql_responses":4,"unknown_directory_responses":3,"known_original_intents_only":True}
        build.save_receipt(evidence/"catalogue-plan.json",plan)
        summary.update(status="running",inputs=before,tools=tools,binary_sha256=build.digest(args.server))
        suite=Suite(args,evidence,private,node);suite.run()
        build.verify(args.build_record,args.server)
        assert build.inputs()==before
        assert build.digest(node)==tools["node"] and build.digest(args.weed)==tools["weed"]
        summary["status"]="passed"
    except BaseException as error:
        if summary["status"]=="running":summary["status"]="failed"
        summary["error"]=repr(error)
    finally:
        errors=suite.cleanup() if suite else []
        summary["cleanup_errors"]=errors
        if errors:summary["status"]="failed"
        if summary["status"]=="passed":
            try:summary["audit"]=catalogue_oracle.audit(evidence)
            except BaseException as error:
                summary["status"]="failed";summary["audit_error"]=repr(error)
        if summary["status"]=="passed":
            shutil.rmtree(private);summary["private_fixture_removed"]=True
        build.save_receipt(evidence/"summary.json",summary)
    print(json.dumps({key:summary.get(key) for key in ("status","diagnostic","error","audit_error","audit","cleanup_errors")},sort_keys=True))
    return 0 if summary["status"]=="passed" else 1


if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--server",type=Path,required=True)
    parser.add_argument("--weed",type=Path,required=True)
    parser.add_argument("--node",default="node")
    parser.add_argument("--build-record",type=Path,required=True)
    parser.add_argument("--evidence",type=Path,required=True)
    raise SystemExit(main(parser.parse_args()))
