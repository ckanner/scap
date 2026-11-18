#!/usr/bin/env python3
"""Real daemon/native/HTTP/S3 index splits, cold recovery, and non-target damage."""
from __future__ import annotations

import argparse
import base64
import copy
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
import segmented_oracle
from segmented_proxy import Proxy, sha
from segmented_spec import BACKEND_VERSION, DEADLINES, PLAN, SCOPE

if not __debug__: raise RuntimeError("acceptance requires Python assertions")
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
spec = importlib.util.spec_from_file_location("scap_segmented_service_fixture", HERE / "run.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
PREFIX = "/scap-test/scap-object/v1/1/7/991/inc/1/gen/1/storage/1/objects/"
HEAD = "/scap-test/scap-object/v1/1/7/991/head"


def unpack(raw):
    assert raw[:8] == b"SCAPOBJ2"
    metadata, length = struct.unpack_from("<IQ", raw, 8)
    assert len(raw) == 20 + metadata + length
    return json.loads(raw[20:20 + metadata]), raw[20 + metadata:]


def pack(value):
    metadata = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()
    return b"SCAPOBJ2" + struct.pack("<IQ", len(metadata), 0) + metadata


class Service:
    def __init__(self, suite, ordinal):
        self.suite, self.ordinal, self.stopped = suite, ordinal, False
        self.cache = suite.private / f"compute-{ordinal}"
        self.cache.mkdir(mode=0o700)
        self.port = fixture.free_port(set())
        self.endpoint = f"http://127.0.0.1:{self.port}"
        self.worker = PLAN["worker_instances"][ordinal - 1]
        config = fixture.config(self.port, self.worker, self.cache, suite.proxy.endpoint,
            {"admin": suite.token, "reader": secrets.token_hex(32), "other": secrets.token_hex(32)})
        config["s3"]["timeout_ms"] = DEADLINES["s3_request_ms"]
        config["admission"].update(timeout_ms=DEADLINES["ordinary_service_ms"],
                                   recovery_timeout_ms=DEADLINES["recovery_service_ms"])
        path = suite.private / f"service-{ordinal}.private.json"
        build.save_receipt(path, config); path.chmod(0o600)
        shutil.copyfile(path, suite.evidence / f"service-config-{ordinal}.json")
        self.log = suite.evidence / f"service-{ordinal}.stdout.log"
        binary = suite.args.server.resolve()
        executable = {"path": str(binary), "sha256": build.digest(binary)}
        environment = dict(os.environ, SCAP_TEST_ACCESS=suite.backend.access, SCAP_TEST_SECRET=suite.backend.secret)
        command = [str(binary), str(path)]
        with self.log.open("wb") as output:
            requested = time.monotonic_ns()
            self.process = subprocess.Popen(command, cwd=ROOT, env=environment, stdout=output, stderr=output)
        self.identity = fixture.process_identity(self.process)
        suite.facts.emit("service_started", ordinal=ordinal, owner_instance=self.worker,
                         identity=self.identity, spawn_requested_ns=requested,
                         endpoint=self.endpoint, cache_directory=str(self.cache), command=command,
                         configuration_sha256=build.digest(path), binary=executable)
        try:
            assert build.digest(binary) == executable["sha256"]
            bound = time.monotonic() + DEADLINES["service_ready_ms"] / 1000
            while time.monotonic() < bound:
                assert self.process.poll() is None, "daemon exited before readiness"
                connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=.5)
                try:
                    connection.request("GET", "/healthz")
                    response = connection.getresponse(); raw = response.read(4096)
                    if response.status == 200 and json.loads(raw) == {"status": "alive", "protocol": 1}:
                        suite.facts.emit("service_ready", ordinal=ordinal, owner_instance=self.worker, identity=self.identity,
                                         response_status=200, response_body=base64.b64encode(raw).decode())
                        return
                except (OSError, ValueError, http.client.HTTPException): pass
                finally: connection.close()
                time.sleep(.05)
            raise TimeoutError("original readiness deadline")
        except BaseException:
            self.stop(); raise

    def stop(self):
        if self.stopped: return
        self.suite.facts.emit("service_stop_requested", ordinal=self.ordinal, identity=self.identity)
        if self.process.poll() is None: self.process.kill()
        status, usage = fixture.wait_child(self.process, 10)
        self.suite.facts.emit("service_stopped", ordinal=self.ordinal, **self.identity,
                             wait_status=status, kernel_usage=usage, stdout_sha256=build.digest(self.log))
        self.stopped = True
        shutil.rmtree(self.cache)
        self.suite.facts.emit("cache_removed", ordinal=self.ordinal, path=str(self.cache), exists=self.cache.exists())


class Suite:
    def __init__(self, args, evidence, private, tools):
        self.args, self.evidence, self.private, self.tools = args, evidence, private, tools
        self.facts = fixture.Facts(evidence)
        self.backend = self.proxy = self.service = None
        self.children, self.services, self.curl_ordinal = [], [], 0
        self.token = secrets.token_hex(32)
        (evidence / "curl").mkdir()

    def start_service(self):
        self.service = Service(self, len(self.services) + 1)
        self.services.append(self.service)

    def phase(self, name):
        self.proxy.set_phase(name)
        config = self.private / (name + ".client.private.json")
        build.save_receipt(config, {"endpoint": self.service.endpoint, "token": self.token}); config.chmod(0o600)
        budget = DEADLINES["seed_phase_ms"] if name == "seed" else DEADLINES["other_phase_ms"]
        self.facts.emit("client_phase_started", phase=name, service_ordinal=self.service.ordinal, deadline_ms=budget)
        command = [self.tools["node"]["path"], str(HERE / "segmented_probe.mjs"), name, str(config), str(self.evidence)]
        with (self.evidence / (name + ".stdout.log")).open("wb") as out, (self.evidence / (name + ".stderr.log")).open("wb") as err:
            requested = time.monotonic_ns()
            process = subprocess.Popen(command, cwd=ROOT, stdout=out, stderr=err)
        self.children.append(process)
        identity = fixture.process_identity(process)
        self.facts.emit("client_process_started", phase=name, identity=identity, spawn_requested_ns=requested,
                        binary=self.tools["node"], command=command)
        assert build.digest(Path(self.tools["node"]["path"])) == self.tools["node"]["sha256"]
        status, usage = fixture.wait_child(process, budget / 1000)
        self.children.remove(process)
        self.facts.emit("client_phase_finished", phase=name, identity=identity, wait_status=status, kernel_usage=usage,
                        stdout_sha256=build.digest(self.evidence / (name + ".stdout.log")),
                        stderr_sha256=build.digest(self.evidence / (name + ".stderr.log")))
        assert status == 0, "actual SDK phase failed: " + name

    def curl(self, label, method, path, body=b"", etag=None, create=False):
        assert path == HEAD or path.startswith(PREFIX)
        self.curl_ordinal += 1; number = self.curl_ordinal
        response_path = self.evidence / "curl" / f"{number}.body"
        headers_path = self.evidence / "curl" / f"{number}.headers"
        payload_path = self.private / "curl-payload.private"
        payload_path.write_bytes(body)
        command = [self.tools["curl"]["path"], "--silent", "--show-error", "--noproxy", "*",
                   "--max-time", str(DEADLINES["curl_ms"] / 1000), "--aws-sigv4", "aws:amz:us-east-1:s3",
                   "--config", "-", "--request", method, "--header", "x-amz-content-sha256: " + sha(body),
                   "--dump-header", str(headers_path), "--output", str(response_path), "--write-out", "%{http_code}"]
        if method == "PUT": command.extend(["--data-binary", "@" + str(payload_path), "--header", "Content-Type: application/octet-stream"])
        if etag is not None: command.extend(["--header", "If-Match: " + etag])
        if create: command.extend(["--header", "If-None-Match: *"])
        command.append(self.proxy.endpoint + path)
        self.facts.emit("fixture_request", ordinal=number, label=label, phase=self.proxy.phase, method=method, path=path,
                        request_sha256=self.proxy.store(body), request_bytes=len(body), if_match=etag,
                        if_none_match="*" if create else None)
        requested = time.monotonic_ns()
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        identity = fixture.process_identity(process)
        self.children.append(process)
        self.facts.emit("fixture_process_started", ordinal=number, identity=identity, spawn_requested_ns=requested,
                        binary=self.tools["curl"], command=command)
        assert build.digest(Path(self.tools["curl"]["path"])) == self.tools["curl"]["sha256"]
        process.stdin.write(f'user = "{self.backend.access}:{self.backend.secret}"\n'.encode())
        process.stdin.close()
        status, usage = fixture.wait_child(process, DEADLINES["curl_ms"] / 1000 + 2)
        stdout, stderr = process.stdout.read(), process.stderr.read()
        process.stdout.close(); process.stderr.close(); self.children.remove(process)
        (self.evidence / "curl" / f"{number}.stdout").write_bytes(stdout)
        (self.evidence / "curl" / f"{number}.stderr").write_bytes(stderr)
        raw, headers = response_path.read_bytes(), headers_path.read_bytes()
        etags = [line.split(b":", 1)[1].strip().decode() for line in headers.splitlines() if line.lower().startswith(b"etag:")]
        observed = {"status": int(stdout), "body": raw, "etag": etags[-1] if etags else None}
        self.facts.emit("fixture_response", ordinal=number, identity=identity, wait_status=status, kernel_usage=usage,
                        status=observed["status"], response_sha256=sha(raw), response_bytes=len(raw), etag=observed["etag"],
                        headers_sha256=sha(headers), stdout_sha256=sha(stdout), stderr_sha256=sha(stderr))
        assert status == 0 and not stderr, "actual signed fixture operation failed"
        return observed

    def right_path(self):
        path, selected = PREFIX + self.head["windows"][0]["root"], []
        while True:
            raw = self.proxy.objects[path]; metadata, trailing = unpack(raw)
            assert not trailing and metadata["payload"]["kind"] == "index"
            selected.append((path, raw, metadata))
            node = metadata["payload"]["value"]
            if node["kind"] == "leaf": return selected
            path = PREFIX + node["children"][-1]["hash"]

    def auth_control(self, path):
        self.facts.emit("unsigned_backend_request", method="GET", path=path, authorization_present=False)
        connection = http.client.HTTPConnection("127.0.0.1", self.backend.port, timeout=2)
        try:
            connection.request("GET", path); response = connection.getresponse(); raw = response.read(65537)
            self.facts.emit("unsigned_backend_response", status=response.status,
                            response_body=base64.b64encode(raw).decode(), response_sha256=sha(raw))
            assert response.status == 403 and len(raw) <= 65536
        finally: connection.close()

    def mutation(self, damage):
        self.proxy.set_phase("damage_" + damage)
        if damage == "corrupt":
            old = self.curl("corrupt_before", "GET", self.target)
            replacement = bytes([old["body"][0] ^ 128]) + old["body"][1:]
            assert self.curl("corrupt_put", "PUT", self.target, replacement, etag=old["etag"])["status"] == 200
            assert self.curl("corrupt_observed", "GET", self.target)["body"] == replacement
        elif damage == "missing":
            assert self.curl("missing_delete", "DELETE", self.target)["status"] in (200, 204)
            assert self.curl("missing_observed", "GET", self.target)["status"] == 404
        else:
            path = self.right_path(); replacement = None
            for depth, (_, _, original) in enumerate(reversed(path)):
                metadata = copy.deepcopy(original); node = metadata["payload"]["value"]
                if depth == 0:
                    assert node["kind"] == "leaf"
                    node["entries"][-1]["result_bytes"] += 1
                else:
                    node["children"][-1]["hash"] = replacement
                encoded = pack(metadata); replacement = sha(encoded); key = PREFIX + replacement
                assert self.curl(f"summary_node_{depth}_put", "PUT", key, encoded, create=True)["status"] == 200
                assert self.curl(f"summary_node_{depth}_get", "GET", key)["body"] == encoded
            old = self.curl("summary_head_before", "GET", HEAD)
            changed = copy.deepcopy(self.head); changed["windows"][0]["root"] = replacement
            encoded = json.dumps(changed, separators=(",", ":")).encode()
            assert self.curl("summary_head_put", "PUT", HEAD, encoded, etag=old["etag"])["status"] == 200
            assert self.curl("summary_head_observed", "GET", HEAD)["body"] == encoded

    def repair(self, damage):
        self.proxy.set_phase("repair_" + damage)
        if damage == "summary":
            current = self.curl("summary_restore_before", "GET", HEAD)
            assert self.curl("summary_restore_put", "PUT", HEAD, self.head_bytes, etag=current["etag"])["status"] == 200
            assert self.curl("summary_restored", "GET", HEAD)["body"] == self.head_bytes
        else:
            values = {"create": True}
            if damage == "corrupt": values = {"etag": self.curl("corrupt_restore_before", "GET", self.target)["etag"]}
            assert self.curl(damage + "_restore_put", "PUT", self.target, self.original_leaf, **values)["status"] == 200
            assert self.curl(damage + "_restored", "GET", self.target)["body"] == self.original_leaf

    def run(self):
        self.backend = fixture.Backend(self.args.weed.resolve(), self.private / "backend")
        self.backend.start()
        self.facts.emit("backend_started", processes=self.backend.identities(), binary=self.tools["weed"],
                        access_key_sha256=sha(self.backend.access.encode()))
        self.proxy = Proxy(self.backend.port, self.evidence)
        self.start_service(); self.phase("seed"); self.phase("warm")
        self.proxy.set_phase("inspection")
        captured = self.curl("original_head", "GET", HEAD)
        self.head_bytes = captured["body"]; self.head = json.loads(self.head_bytes)
        assert self.head["format"] == 6 and self.head["windows"][0]["count"] == PLAN["retained_entries"]
        right = self.right_path(); self.target, self.original_leaf, _ = right[-1]
        self.auth_control(self.target)
        self.service.stop(); self.start_service(); self.phase("cold"); self.service.stop()
        for damage in PLAN["damage_cases"]:
            self.mutation(damage)
            self.start_service(); self.phase(damage); self.service.stop()
            self.repair(damage)
        self.start_service(); self.phase("repaired")

    def cleanup(self):
        errors = []
        for process in self.children:
            try:
                if process.poll() is None: process.kill()
                status, usage = fixture.wait_child(process, 5)
                self.facts.emit("unfinished_child_stopped", pid=process.pid, wait_status=status, kernel_usage=usage)
            except BaseException as error: errors.append(repr(error))
        for service in self.services:
            try: service.stop()
            except BaseException as error: errors.append(repr(error))
        if self.proxy:
            try:
                self.proxy.close(); self.facts.emit("proxy_stopped", errors=self.proxy.errors)
            except BaseException as error: errors.append(repr(error))
        if self.backend:
            try:
                stopped = self.backend.stop()
                for role in ("master", "volume", "filer", "s3"):
                    shutil.copyfile(self.backend.directory / (role + ".private.log"), self.evidence / ("backend-" + role + ".log"))
                self.facts.emit("backend_stopped", processes=stopped)
            except BaseException as error: errors.append(repr(error))
        self.facts.emit("cleanup_finished", errors=errors)
        return errors


def main(args):
    evidence = args.evidence.resolve(); evidence.mkdir(parents=True, exist_ok=False, mode=0o700)
    private = Path(tempfile.mkdtemp(prefix="scap-segmented-private-", dir=evidence.parent))
    summary = {"status": "blocked", "aws_standard": "NOT_RUN", "production_tps": "NOT_MEASURED",
               "private_fixture_path": str(private), "private_fixture_removed": False}
    suite = None
    try:
        assert not os.environ.get("LLVM_PROFILE_FILE") and not os.environ.get("NODE_V8_COVERAGE")
        assert not any("instrument-coverage" in os.environ.get(key, "") for key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"))
        tools = {}
        for name, executable, option in (("node", args.node, "--version"), ("curl", args.curl, "--version"), ("weed", str(args.weed), "version")):
            path = Path(shutil.which(executable) or executable).resolve()
            tools[name] = {"path": str(path), "sha256": build.digest(path),
                           "version": subprocess.check_output([str(path), option], text=True).strip()}
        assert tools["node"]["version"] == "v22.16.0" and BACKEND_VERSION in tools["weed"]["version"]
        before = build.inputs(); build.verify(args.build_record, args.server)
        build.capture_receipt(args.build_record, args.server, evidence)
        build.save_receipt(evidence / "segmented-plan.json", PLAN)
        build.save_receipt(evidence / "segmented-tools.json", tools)
        suite = Suite(args, evidence, private, tools)
        suite.facts.emit("plan_frozen", sha256=build.digest(evidence / "segmented-plan.json"))
        summary["status"] = "running"; suite.run()
        build.verify(args.build_record, args.server); assert before == build.inputs()
        assert all(build.digest(Path(tool["path"])) == tool["sha256"] for tool in tools.values())
        summary["status"] = "passed"
    except BaseException as error:
        summary.update(status="failed" if summary["status"] == "running" else "blocked", error=repr(error))
    finally:
        errors = suite.cleanup() if suite else []
        summary["cleanup_errors"] = errors
        if errors: summary["status"] = "failed"
        if summary["status"] == "passed":
            try: summary["audit"] = segmented_oracle.audit(evidence)
            except BaseException as error: summary.update(status="failed", audit_error=repr(error))
        if summary["status"] == "passed": shutil.rmtree(private); summary["private_fixture_removed"] = True
        build.save_receipt(evidence / "summary.json", summary)
    print(json.dumps({key: summary.get(key) for key in ("status", "error", "audit_error", "audit", "cleanup_errors")}, sort_keys=True))
    return 0 if summary["status"] == "passed" else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--weed", type=Path, required=True)
    parser.add_argument("--node", default="node")
    parser.add_argument("--curl", default="curl")
    parser.add_argument("--build-record", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    raise SystemExit(main(parser.parse_args()))
