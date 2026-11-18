#!/usr/bin/env python3
"""Actual daemon/SDK/native/S3 bounded actor isolation, with independently audited evidence."""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import struct
import subprocess
import tempfile
import time

import build
import isolation_oracle
from isolation_proxy import Proxy, sha
from isolation_spec import ADMISSION, BACKEND_VERSION, CACHE, DEADLINES, PLAN

if not __debug__:
    raise RuntimeError("the acceptance controller requires Python assertions")

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
specification = importlib.util.spec_from_file_location("scap_isolation_service_fixture", HERE / "run.py")
fixture = importlib.util.module_from_spec(specification)
specification.loader.exec_module(fixture)


class Service:
    def __init__(self, binary, private, proxy, backend, token, facts, evidence):
        self.facts, self.stopped = facts, False
        self.cache = private / "compute"
        self.cache.mkdir(mode=0o700)
        self.port = fixture.free_port(set())
        self.endpoint = f"http://127.0.0.1:{self.port}"
        configuration = fixture.config(self.port, PLAN["owner_instance"], self.cache, proxy.endpoint,
                                       {"admin": token, "reader": secrets.token_hex(32), "other": secrets.token_hex(32)})
        configuration.update(admission=ADMISSION, cache=CACHE)
        configuration["s3"]["timeout_ms"] = DEADLINES["s3_request_ms"]
        path = private / "service.private.json"
        build.save_receipt(path, configuration)
        path.chmod(0o600)
        # This exact file has token hashes and environment variable names only.
        shutil.copyfile(path, evidence / "isolation-service-config.json")
        self.log = evidence / "scapd.stdout.log"
        environment = dict(os.environ, SCAP_TEST_ACCESS=backend.access, SCAP_TEST_SECRET=backend.secret)
        command = [str(binary), str(path)]
        executable = {"path": str(binary), "sha256": build.digest(binary)}
        with self.log.open("wb") as stream:
            spawn_requested_ns = time.monotonic_ns()
            self.process = subprocess.Popen(command, cwd=ROOT, env=environment, stdout=stream, stderr=stream)
        self.identity = fixture.process_identity(self.process)
        facts.emit("service_started", owner_instance=PLAN["owner_instance"], identity=self.identity,
                   spawn_requested_ns=spawn_requested_ns,
                   endpoint=self.endpoint, cache_directory=str(self.cache), command=command,
                   configuration_sha256=build.digest(path), binary=executable)
        try:
            assert build.digest(binary) == executable["sha256"], "daemon executable changed across Popen"
            bound = time.monotonic() + DEADLINES["service_ready_ms"] / 1000
            while time.monotonic() < bound:
                assert self.process.poll() is None, "daemon exited before liveness"
                connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=0.5)
                try:
                    connection.request("GET", "/healthz")
                    response = connection.getresponse()
                    body = response.read(4096)
                    if response.status == 200 and json.loads(body) == {"status": "alive", "protocol": 1}:
                        facts.emit("service_ready", owner_instance=PLAN["owner_instance"],
                                   identity=self.identity, response_status=200,
                                   response_body=base64.b64encode(body).decode(), response_sha256=sha(body))
                        return
                except (OSError, ValueError, http.client.HTTPException):
                    pass
                finally:
                    connection.close()
                time.sleep(0.05)
            raise TimeoutError("original service readiness deadline")
        except BaseException:
            self.stop()
            raise

    def stop(self):
        if self.stopped:
            return
        self.facts.emit("service_stop_requested", identity=self.identity)
        if self.process.poll() is None:
            self.process.kill()
        status, usage = fixture.wait_child(self.process, 10)
        self.facts.emit("service_stopped", **self.identity, wait_status=status, kernel_usage=usage,
                        stdout_sha256=build.digest(self.log))
        self.stopped = True


class Suite:
    def __init__(self, args, evidence, private, node):
        self.args, self.evidence, self.private, self.node = args, evidence, private, node
        self.facts = fixture.Facts(evidence)
        self.backend = self.proxy = self.service = None
        self.children, self.started = {}, []

    def setup(self):
        self.backend = fixture.Backend(self.args.weed.resolve(), self.private / "backend")
        self.backend.start()
        self.facts.emit("backend_started", processes=self.backend.identities(),
                        binary={"path": str(self.args.weed.resolve()), "sha256": build.digest(self.args.weed)},
                        access_key_sha256=sha(self.backend.access.encode()))
        self.proxy = Proxy(self.backend.port, self.evidence)
        self.token = secrets.token_hex(32)
        self.service = Service(self.args.server.resolve(), self.private, self.proxy, self.backend,
                               self.token, self.facts, self.evidence)

    def begin(self, phase):
        assert phase not in self.started
        self.started.append(phase)
        self.proxy.set_phase(phase)
        path = self.private / (phase + ".client.private.json")
        build.save_receipt(path, {"endpoint": self.service.endpoint, "token": self.token})
        path.chmod(0o600)
        self.facts.emit("client_phase_started", phase=phase, service=self.service.identity,
                        deadline_ms=DEADLINES["client_phase_ms"])
        command = [str(self.node), str(HERE / "isolation_probe.mjs"), phase, str(path), str(self.evidence)]
        executable = {"path": str(self.node), "sha256": build.digest(self.node)}
        with (self.evidence / (phase + ".stdout.log")).open("wb") as out, \
                (self.evidence / (phase + ".stderr.log")).open("wb") as err:
            spawn_requested_ns = time.monotonic_ns()
            child = subprocess.Popen(command, cwd=ROOT, stdout=out, stderr=err)
        identity = fixture.process_identity(child)
        self.children[phase] = (child, identity)
        self.facts.emit("client_process_started", phase=phase, identity=identity, command=command,
                        spawn_requested_ns=spawn_requested_ns, binary=executable)
        assert build.digest(self.node) == executable["sha256"], "Node executable changed across Popen"

    def finish(self, phase):
        child, identity = self.children[phase]
        status, usage = fixture.wait_child(child, DEADLINES["client_phase_ms"] / 1000)
        del self.children[phase]
        self.facts.emit("client_phase_finished", phase=phase, identity=identity, wait_status=status, kernel_usage=usage,
                        stdout_sha256=build.digest(self.evidence / (phase + ".stdout.log")),
                        stderr_sha256=build.digest(self.evidence / (phase + ".stderr.log")))
        assert status == 0, "actual SDK phase failed: " + phase

    def phase(self, name):
        self.begin(name)
        self.finish(name)

    def gate_key(self):
        # Select from actual original committed immutable bytes, never a later
        # HEAD refresh. The independent oracle reconstructs the same tree itself.
        state = json.loads((self.evidence / "isolation-state.json").read_text())
        prefix = "/scap-test/scap-object/v1/1/7/101/inc/1/gen/1/storage/1/objects/"
        key = prefix + state["a"]["receipt"]["data_root"]
        while True:
            raw = self.proxy.objects[key]
            assert raw.startswith(b"SCAPOBJ2")
            length, _ = struct.unpack_from("<IQ", raw, 8)
            payload = json.loads(raw[20:20 + length])["payload"]
            if payload["kind"] == "manifest":
                key = prefix + payload["value"]["root"]
            elif payload["kind"] == "node":
                key = prefix + payload["value"]["children"][0]
            else:
                assert payload["kind"] == "chunk" and payload["value"]["first_page"] == 1
                return key

    def check_backend_auth(self, path):
        # A separate original, unsigned backend read must be rejected. The
        # product's successful reads of this same key use SigV4 through the proxy.
        connection = http.client.HTTPConnection("127.0.0.1", self.backend.port, timeout=2)
        self.facts.emit("unsigned_backend_request", method="GET", path=path, authorization_present=False)
        try:
            connection.request("GET", path)
            response = connection.getresponse()
            raw = response.read(65537)
            self.facts.emit("unsigned_backend_response", status=response.status,
                            response_body=base64.b64encode(raw).decode(), response_sha256=sha(raw))
            assert response.status == 403 and len(raw) <= 65536, "backend did not enforce authentication"
        finally:
            connection.close()

    def run(self):
        self.setup()
        self.phase("seed")
        key = self.gate_key()
        self.check_backend_auth(key)
        self.phase("keep_b_hot")
        self.proxy.arm(key)
        self.begin("cold_a")
        assert self.proxy.arrived.wait(DEADLINES["gate_arrival_ms"] / 1000), "A never attempted its full cold data GET"
        self.facts.emit("cold_gate_arrived", path=key, request_serial=self.proxy.gated_serial)
        started = time.monotonic_ns()
        self.phase("during_cold")
        assert time.monotonic_ns() - started <= DEADLINES["hot_probe_ms"] * 1000000, "original hot/control probe deadline"
        assert self.children["cold_a"][0].poll() is None, "A finished before release"
        self.proxy.release_gate()
        self.finish("cold_a")
        self.phase("after_release")
        assert not self.proxy.errors, self.proxy.errors

    def cleanup(self):
        errors = []
        if self.proxy:
            self.proxy.release.set()
        for phase, (child, identity) in list(self.children.items()):
            try:
                if child.poll() is None:
                    child.kill()
                status, usage = fixture.wait_child(child, 5)
                self.facts.emit("unfinished_client_stopped", phase=phase, identity=identity, wait_status=status, kernel_usage=usage)
            except BaseException as error:
                errors.append(repr(error))
        if self.service:
            try:
                self.service.stop()
            except BaseException as error:
                errors.append(repr(error))
        if self.proxy:
            try:
                self.proxy.close()
                self.facts.emit("proxy_stopped", errors=list(self.proxy.errors))
            except BaseException as error:
                errors.append(repr(error))
        if self.backend:
            try:
                stopped = self.backend.stop()
                for role in ("master", "volume", "filer", "s3"):
                    shutil.copyfile(self.backend.directory / (role + ".private.log"), self.evidence / ("backend-" + role + ".log"))
                self.facts.emit("backend_stopped", processes=stopped)
            except BaseException as error:
                errors.append(repr(error))
        self.facts.emit("cleanup_finished", errors=errors)
        return errors


def main(args):
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=False, mode=0o700)
    private = Path(tempfile.mkdtemp(prefix="scap-isolation-private-", dir=evidence.parent))
    summary = {"schema": 1, "status": "blocked", "aws_standard": "NOT_RUN", "production_tps": "NOT_MEASURED",
               "private_fixture_path": str(private), "private_fixture_removed": False}
    suite = None
    try:
        assert "LLVM_PROFILE_FILE" not in os.environ and "NODE_V8_COVERAGE" not in os.environ
        assert not any("instrument-coverage" in os.environ.get(key, "") for key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"))
        assert args.server.is_file() and args.weed.is_file()
        node = Path(shutil.which(args.node) or args.node).resolve()
        tools = {"node": {"path": str(node), "sha256": build.digest(node),
                          "version": subprocess.check_output([str(node), "--version"], text=True).strip()},
                 "weed": {"path": str(args.weed.resolve()), "sha256": build.digest(args.weed),
                          "version": subprocess.check_output([str(args.weed), "version"], text=True).strip()}}
        assert tools["node"]["version"] == "v22.16.0" and BACKEND_VERSION in tools["weed"]["version"]
        before = build.inputs()
        receipt = build.verify(args.build_record, args.server)
        assert receipt["node"] == tools["node"]["version"]
        build.capture_receipt(args.build_record, args.server, evidence)
        build.save_receipt(evidence / "isolation-plan.json", PLAN)
        build.save_receipt(evidence / "isolation-tools.json", tools)
        summary["status"] = "running"
        suite = Suite(args, evidence, private, node)
        suite.facts.emit("plan_frozen", sha256=build.digest(evidence / "isolation-plan.json"))
        suite.run()
        build.verify(args.build_record, args.server)
        assert before == build.inputs()
        assert all(build.digest(Path(tool["path"])) == tool["sha256"] for tool in tools.values())
        summary["status"] = "passed"
    except BaseException as error:
        if summary["status"] == "running":
            summary["status"] = "failed"
        summary["error"] = repr(error)
    finally:
        errors = suite.cleanup() if suite else []
        summary["cleanup_errors"] = errors
        if errors:
            summary["status"] = "failed"
        if summary["status"] == "passed":
            try:
                summary["audit"] = isolation_oracle.audit(evidence)
            except BaseException as error:
                summary.update(status="failed", audit_error=repr(error))
        if summary["status"] == "passed":
            shutil.rmtree(private)
            summary["private_fixture_removed"] = True
        build.save_receipt(evidence / "summary.json", summary)
    print(json.dumps({key: summary.get(key) for key in ("status", "error", "audit_error", "audit", "cleanup_errors")}, sort_keys=True))
    return 0 if summary["status"] == "passed" else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--weed", type=Path, required=True)
    parser.add_argument("--node", default="node")
    parser.add_argument("--build-record", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    raise SystemExit(main(parser.parse_args()))
