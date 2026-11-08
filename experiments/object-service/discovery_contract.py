#!/usr/bin/env python3
"""Real discovery HTTP/Node SDK contract against an owned signed Seaweed fixture."""
from __future__ import annotations

import argparse
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import time

if not __debug__:
    raise RuntimeError("validation requires Python assertions; disable -O/PYTHONOPTIMIZE")

import build
import discovery_oracle
from discovery_proxy import Proxy

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
specification = importlib.util.spec_from_file_location("scap_discovery_service_fixture", HERE / "run.py")
fixture = importlib.util.module_from_spec(specification)
specification.loader.exec_module(fixture)

ROLES = {
    "admin": {"deployment": "1", "tenant": "7", "principal": "11", "provision": True, "deployment_inventory": False},
    "reader": {"deployment": "1", "tenant": "7", "principal": "12", "provision": False, "deployment_inventory": False},
    "operator": {"deployment": "1", "tenant": "7", "principal": "13", "provision": False, "deployment_inventory": True},
    "other": {"deployment": "1", "tenant": "8", "principal": "22", "provision": True, "deployment_inventory": False},
    "third": {"deployment": "1", "tenant": "9", "principal": "33", "provision": False, "deployment_inventory": False},
    "foreign": {"deployment": "2", "tenant": "7", "principal": "44", "provision": True, "deployment_inventory": True},
}
CATALOGUE = {"workers": 2, "queued_total": 16, "queued_per_tenant": 12, "queued_per_name": 4,
             "intake": 4, "max_body_bytes": 65536, "timeout_ms": 10000}


def write(path, value):
    with path.open("w", encoding="utf-8") as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    path.chmod(0o600)


class Service(fixture.Service):
    def __init__(self, suite, owner):
        self.owner, self.facts, self.stopped = owner, suite.facts, None
        self.port = fixture.free_port(set())
        self.cache = suite.private / f"compute-{owner}"
        self.cache.mkdir(mode=0o700)
        self.configuration = suite.private / f"service-{owner}.private.json"
        configuration = fixture.config(self.port, owner, self.cache, suite.proxy.endpoint, suite.tokens)
        configuration["credentials"] = [{"sha256": fixture.sha(suite.tokens[role]), **value} for role, value in ROLES.items()]
        configuration["catalogue"] = CATALOGUE
        configuration["discovery"] = {"cursor_key_env": "SCAP_TEST_CURSOR_KEY"}
        configuration["s3"]["timeout_ms"] = 5000
        write(self.configuration, configuration)
        self.endpoint = f"http://127.0.0.1:{self.port}"
        suite.facts.emit("service_configuration", owner_instance=owner, configuration=configuration,
                         configuration_sha256=build.digest(self.configuration),
                         cursor_master_sha256=fixture.sha(suite.cursor_key))
        environment = dict(os.environ, SCAP_TEST_ACCESS=suite.backend.access,
                           SCAP_TEST_SECRET=suite.backend.secret, SCAP_TEST_CURSOR_KEY=suite.cursor_key)
        binary = suite.args.server.resolve()
        executable = {"path": str(binary), "sha256": build.digest(binary)}
        self.log = suite.private / f"service-{owner}.private.log"
        command = [str(binary), str(self.configuration)]
        requested = time.monotonic_ns()
        with self.log.open("wb") as stream:
            self.process = subprocess.Popen(command, env=environment, stdout=stream, stderr=stream)
        self.identity = fixture.process_identity(self.process)
        self.facts.emit("service_started", owner_instance=owner, identity=self.identity,
                        endpoint=self.endpoint, cache_directory=str(self.cache), binary=executable,
                        command=command, spawn_requested_ns=requested)
        try:
            assert build.digest(binary) == executable["sha256"], "daemon changed across Popen"
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                assert self.process.poll() is None, "daemon exited before liveness"
                connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=0.5)
                try:
                    connection.request("GET", "/healthz")
                    response = connection.getresponse()
                    if response.status == 200 and json.loads(response.read(4096)) == {"status": "alive", "protocol": 1}:
                        self.facts.emit("service_ready", owner_instance=owner, identity=self.identity)
                        return
                except (OSError, ValueError, http.client.HTTPException):
                    pass
                finally:
                    connection.close()
                time.sleep(0.05)
            raise TimeoutError("discovery daemon liveness deadline")
        except BaseException:
            self.stop()
            raise


class Suite:
    def __init__(self, args, evidence, private, node):
        self.args, self.evidence, self.private, self.node = args, evidence, private, node
        self.facts = fixture.Facts(evidence)
        self.backend = self.proxy = None
        self.services, self.children, self.started = [], {}, []
        self.tokens = {role: secrets.token_hex(32) for role in ROLES}
        self.cursor_key = secrets.token_hex(32)

    def state(self):
        return json.loads((self.evidence / "discovery-state.json").read_text())

    def service(self, owner):
        service = Service(self, owner)
        self.services.append(service)
        return service

    def begin(self, name, **extra):
        assert name not in self.started, "duplicate discovery phase"
        self.started.append(name)
        configuration = self.private / f"{name}.client.private.json"
        write(configuration, {"endpoint": self.first.endpoint, "secondary": self.second.endpoint,
                              "roles": ROLES, "tokens": self.tokens, **extra})
        self.facts.emit("client_phase_started", phase=name, primary=self.first.identity,
                        secondary=self.second.identity, primary_endpoint=self.first.endpoint,
                        secondary_endpoint=self.second.endpoint)
        command = [str(self.node), str(HERE / "discovery_probe.mjs"), name, str(configuration), str(self.evidence)]
        requested = time.monotonic_ns()
        with (self.evidence / f"{name}.stdout.log").open("wb") as out, (self.evidence / f"{name}.stderr.log").open("wb") as err:
            process = subprocess.Popen(command, cwd=ROOT, stdout=out, stderr=err)
        identity = fixture.process_identity(process)
        self.children[name] = (process, identity)
        self.facts.emit("client_process_started", phase=name, identity=identity,
                        command=command, spawn_requested_ns=requested)

    def finish(self, name):
        process, identity = self.children[name]
        status, usage = fixture.wait_child(process, 240)
        del self.children[name]
        self.facts.emit("client_phase_finished", phase=name, identity=identity, wait_status=status, kernel_usage=usage)
        assert status == 0, f"discovery SDK phase failed: {name}; inspect original stderr"

    def phase(self, name, **extra):
        self.begin(name, **extra)
        self.finish(name)

    def run(self):
        self.backend = fixture.Backend(self.args.weed.resolve(), self.private / "backend")
        self.backend.start()
        self.facts.emit("backend_started", processes=self.backend.identities(),
                        directory_identity=fixture.sha(str(self.backend.directory.resolve())))
        self.proxy = Proxy(self.backend, self.evidence)
        self.facts.emit("fixture_roles", roles={role: {**value, "sha256": fixture.sha(self.tokens[role])} for role, value in ROLES.items()},
                        proxy_endpoint=self.proxy.endpoint, backend_endpoint=self.backend.endpoint)
        self.first, self.second = self.service(7001), self.service(7002)
        for name in ("setup", "reader_first", "revoke_continue", "capabilities", "cursor_bindings"):
            self.phase(name)
        prefix = "scap-object/v1/1/7/catalogue/v1/name/"
        for mode, stopped in (("denied", "DENIED"), ("missing", "UNKNOWN"),
                              ("missing_truncation", "CORRUPT"), ("no_progress", "CORRUPT")):
            rule = self.proxy.arm(mode, mode, prefix=prefix)
            self.phase("fault_" + mode, expectedStop=stopped)
            assert rule.arrived.is_set() and rule.used == 1 and rule.finished.wait(3), "LIST fault did not execute"
            self.phase("after_fault_" + mode)
        scope = self.state()["second"]["scope"]
        key = f"scap-object/v1/{scope['deployment']}/{scope['tenant']}/{scope['database']}/head"
        for mode in ("missing", "corrupt_head"):
            label = "head_" + mode
            rule = self.proxy.arm(label, mode, key=key)
            self.phase("fault_" + label, expectedStop="CORRUPT")
            assert rule.arrived.is_set() and rule.used == 1 and rule.finished.wait(3), "exact HEAD fault did not execute"
            self.phase("after_fault_" + label)

        timeout = self.proxy.arm("slot_timeout", "hold", prefix=prefix)
        abort = self.proxy.arm("slot_abort", "hold", prefix="scap-object/v1/1/8/catalogue/v1/name/")
        self.begin("hold_timeout")
        assert timeout.arrived.wait(3), "timeout request did not reach the held LIST"
        self.finish("hold_timeout")
        self.phase("one_held_probe")
        self.begin("hold_abort")
        assert abort.arrived.wait(3), "abort request did not reach the second held LIST"
        self.finish("hold_abort")
        self.phase("held_probes")
        assert not timeout.release.is_set() and not abort.release.is_set()
        self.proxy.release(timeout)
        self.proxy.release(abort)
        assert timeout.finished.wait(5) and abort.finished.wait(5), "held backend requests failed to finish"
        self.phase("release_recovered")
        self.phase("cursor_before_loss")

        original = [self.first, self.second]
        self.facts.emit("compute_loss_started", processes=[service.identity for service in original])
        for service in original:
            service.stop("compute_loss")
            shutil.rmtree(service.cache)
            assert not service.cache.exists()
            self.facts.emit("cache_directory_removed", owner_instance=service.owner, identity=service.identity,
                            cache_directory=str(service.cache), exists=False)
        self.facts.emit("all_compute_lost", live_service_processes=0, all_cache_directories_removed=True)
        self.first = self.second = self.service(7003)
        self.phase("restart")
        assert not self.proxy.errors, self.proxy.errors

    def close(self):
        failures = []
        for name, (process, identity) in list(self.children.items()):
            try:
                process.kill()
                status, usage = fixture.wait_child(process, 10)
                self.facts.emit("client_phase_finished", phase=name, identity=identity, wait_status=status, kernel_usage=usage)
                del self.children[name]
            except BaseException as error:
                failures.append(repr(error))
        for service in self.services:
            try:
                service.stop()
            except BaseException as error:
                failures.append(repr(error))
        if self.proxy is not None:
            try:
                self.proxy.close()
            except BaseException as error:
                failures.append(repr(error))
        if self.backend is not None:
            try:
                self.facts.emit("backend_cleanup", processes=self.backend.stop())
            except BaseException as error:
                failures.append(repr(error))
        return failures


def main(args):
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=False, mode=0o700)
    private = Path(tempfile.mkdtemp(prefix="scap-discovery-private-", dir=evidence.parent))
    report = {"schema": 1, "status": "failed", "diagnostic": args.diagnostic,
              "aws_standard": "NOT_RUN", "production_slo_passed": False, "data_recovery_complete": False}
    suite = None
    before = build.inputs()
    try:
        assert "LLVM_PROFILE_FILE" not in os.environ and "NODE_V8_COVERAGE" not in os.environ
        assert not any("instrument-coverage" in os.environ.get(key, "") for key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"))
        node = Path(shutil.which(args.node) or args.node).resolve()
        tools = {"node": {"path": str(node), "sha256": build.digest(node),
                          "version": subprocess.check_output([str(node), "--version"], text=True).strip()},
                 "weed": {"path": str(args.weed.resolve()), "sha256": build.digest(args.weed),
                          "version": subprocess.check_output([str(args.weed), "version"], text=True).strip()},
                 "server": {"path": str(args.server.resolve()), "sha256": build.digest(args.server)}}
        assert tools["node"]["version"] == "v22.16.0"
        write(evidence / "discovery-tools.json", tools)
        write(evidence / "discovery-source-before.json", before)
        if not args.diagnostic:
            assert args.build_record, "formal run requires the actual frozen release build receipt"
            build.capture_receipt(args.build_record, args.server, evidence)
        suite = Suite(args, evidence, private, node)
        suite.run()
        report["cleanup_errors"] = suite.close()
        assert not report["cleanup_errors"], report["cleanup_errors"]
        assert build.inputs() == before, "source changed during real discovery run"
        for value in tools.values():
            assert build.digest(value["path"]) == value["sha256"], "actual executable changed during run"
        write(evidence / "discovery-source-after.json", build.inputs())
        report["audit"] = discovery_oracle.audit(evidence, require_build=not args.diagnostic)
        report["negative_controls"] = discovery_oracle.controls(evidence)
        report["status"] = "diagnostic_passed" if args.diagnostic else "passed"
    except BaseException as error:
        report["error"] = repr(error)
    finally:
        if suite is not None and "cleanup_errors" not in report:
            report["cleanup_errors"] = suite.close()
        if report.get("cleanup_errors"):
            report["status"] = "failed"
        if not args.keep_private:
            shutil.rmtree(private)
        else:
            report["private_fixture_directory"] = str(private)
        write(evidence / "discovery-oracle.json", report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] in ("passed", "diagnostic_passed") else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--weed", type=Path, required=True)
    parser.add_argument("--node", default="node")
    parser.add_argument("--build-record", type=Path)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--diagnostic", action="store_true")
    parser.add_argument("--keep-private", action="store_true")
    raise SystemExit(main(parser.parse_args()))
