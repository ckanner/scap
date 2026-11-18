#!/usr/bin/env python3
"""Real read-pool service/SDK/S3 execution; never contributes to unit coverage."""
from __future__ import annotations

import argparse
import hashlib
import http.client
import importlib.util
import io
import json
import os
from pathlib import Path
import queue
import secrets
import signal
import subprocess
import sys
import tarfile
import tempfile
import threading
import time

if not __debug__:
    raise RuntimeError("validation requires assertions")

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "experiments/object-service"))
from owner_proxy import Hub, Trace  # noqa: E402
import build  # noqa: E402
from spec import COMMANDS, HEAD, OTHER_HEAD, PROFILE, SCOPES  # noqa: E402

_spec = importlib.util.spec_from_file_location("read_pool_backend", ROOT / "experiments/object-network/run.py")
NET = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(NET)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source():
    paths = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().split("\0")
    return {name: sha(ROOT / name) for name in paths if name}


def archive_source(evidence, manifest):
    build.save_receipt(evidence / "source.json", manifest)
    with (evidence / "source.tar").open("xb") as stream:
        with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for name, expected in sorted(manifest.items()):
                raw = (ROOT / name).read_bytes()
                assert hashlib.sha256(raw).hexdigest() == expected, "source changed while archiving"
                member = tarfile.TarInfo(name)
                member.size, member.mode, member.mtime = len(raw), 0o644, 0
                archive.addfile(member, io.BytesIO(raw))
        build.sync(stream)


class Probe:
    def __init__(self, node, config, private, events):
        self.events, self.rows = events, []
        self.messages = queue.Queue()
        self.log = (private / "probe.stderr.log").open("wb")
        self.child = subprocess.Popen([str(node), str(Path(__file__).with_name("probe.mjs")), str(config)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.log, text=True, bufsize=1)
        self.identity = NET.process_identity(self.child)
        events.emit("probe_started", identity=self.identity, node_sha256=sha(node))

        def collect():
            for line in self.child.stdout:
                self.messages.put(json.loads(line))

        self.thread = threading.Thread(target=collect)
        self.thread.start()

    def send(self, command):
        self.events.emit("command_sent", command=command)
        self.child.stdin.write(json.dumps({"command": command}) + "\n")
        self.child.stdin.flush()

    def wait(self, command):
        deadline = time.monotonic() + 35
        while True:
            for row in self.rows:
                if row.get("command") == command and row["event"] == "command_finished":
                    return row
                assert row["event"] != "command_failed", row
            assert time.monotonic() < deadline, "SDK command deadline: " + command
            self.rows.append(self.messages.get(timeout=max(.001, deadline - time.monotonic())))

    def call(self, command):
        self.send(command)
        return self.wait(command)

    def finish(self):
        self.child.stdin.close()
        status, usage = NET.wait_child(self.child, 10)
        self.thread.join(timeout=3)
        self.log.close()
        self.events.emit("probe_stopped", identity=self.identity, status=status, usage=usage)
        assert status == 0 and not self.thread.is_alive(), "SDK process did not finish cleanly"


def wait_forwarded(events_path, command):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        rows = [json.loads(line) for line in events_path.read_text().splitlines()]
        if any(row["event"] == "http_forwarded" and row["command"] == command for row in rows):
            return
        time.sleep(.01)
    raise TimeoutError("SDK request was not delivered to service: " + command)


def configuration(port, cache, endpoint, tokens):
    return {
        "version": 1, "listen": f"127.0.0.1:{port}", "worker_instance": "9101",
        "cache_directory": str(cache),
        "s3": {"endpoint": endpoint, "region": "us-east-1", "bucket": "scap-test",
               "access_key_env": "SCAP_TEST_ACCESS", "secret_key_env": "SCAP_TEST_SECRET",
               "session_token_env": None, "allow_http": True, "timeout_ms": 10000},
        "admission": {"read_pool": PROFILE, "active_database_actors": 2,
            "active_database_actors_per_tenant": 1, "actor_idle_timeout_ms": 60000,
            "control_workers": 1, "queued_total": 24, "queued_per_tenant": 12,
            "queued_per_database": 8, "reserved_controls": 2, "data_intake": 12,
            "control_intake": 4, "recovery_intake": 4, "max_body_bytes": 65536,
            "timeout_ms": 15000, "recovery_timeout_ms": 30000},
        "cache": {"pages_per_actor": 8192, "parallel_recoveries": 4},
        "credentials": [{"sha256": hashlib.sha256(tokens[name].encode()).hexdigest(),
            "deployment": "1", "tenant": tenant, "principal": principal, "provision": provision}
            for name, tenant, principal, provision in (("admin", "7", "11", True),
                ("reader", "7", "12", False), ("other", "8", "22", True))],
    }


def run(args):
    assert "LLVM_PROFILE_FILE" not in os.environ and "NODE_V8_COVERAGE" not in os.environ
    assert not any("instrument-coverage" in os.environ.get(key, "")
                   for key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"))
    for name in ("binary", "build_record", "weed", "node"):
        setattr(args, name, getattr(args, name).resolve())
    evidence = args.evidence.resolve()
    evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    before = source()
    events = Trace(evidence / "events.jsonl")
    report = {"schema": 1, "status": "failed", "source_commit": subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(), "profile": PROFILE,
        "binary_sha256": sha(args.binary), "build_record_sha256": sha(args.build_record),
        "aws": "NOT_RUN", "production_slo": "NOT_RUN"}
    (evidence / "plan.json").write_text(json.dumps({"profile": PROFILE, "scopes": SCOPES,
        "commands": COMMANDS, "http_count": sum(command["http"] for command in COMMANDS)}, indent=2) + "\n")
    service = probe = hub = backend = None
    temporary = tempfile.TemporaryDirectory(prefix="scap-read-pool-")
    try:
        private = Path(temporary.name)
        assert subprocess.check_output([str(args.node), "--version"], text=True).strip() == "v22.16.0"
        archive_source(evidence, before)
        (evidence / "build").mkdir()
        receipt = build.capture_receipt(args.build_record, args.binary, evidence / "build")
        build.save_receipt(evidence / "inputs.json", {
            "source_commit": report["source_commit"], "source_manifest_sha256": sha(evidence / "source.json"),
            "source_archive_sha256": sha(evidence / "source.tar"), "build_source_commit": receipt["source_commit"],
            "build_receipt_sha256": sha(evidence / "build/build-receipt.json"),
            "tools": {name: {"path": str(path), "sha256": sha(path)}
                      for name, path in (("scapd", args.binary), ("node", args.node), ("weed", args.weed))}})
        backend = NET.Backend(args.weed, private / "backend")
        backend.start()
        events.emit("backend_started", identities=backend.identities(), binary_sha256=sha(args.weed))
        hub = Hub(backend.port, evidence, events)
        s3_endpoint = hub.s3("pool")
        cache = private / "cache"
        cache.mkdir(mode=0o700)
        tokens = {name: secrets.token_hex(24) for name in ("admin", "reader", "other")}
        port = NET.free_port(set())
        config = private / "service.json"
        config.write_text(json.dumps(configuration(port, cache, s3_endpoint, tokens)))
        config.chmod(0o600)
        (evidence / "service-config.json").write_bytes(config.read_bytes())
        with (private / "service.log").open("wb") as log:
            spawn_requested_ns = time.monotonic_ns()
            service = subprocess.Popen([str(args.binary), str(config)], stdout=log, stderr=log,
                stdin=subprocess.DEVNULL, env=dict(os.environ, SCAP_TEST_ACCESS=backend.access,
                                                SCAP_TEST_SECRET=backend.secret))
        identity = NET.process_identity(service)
        events.emit("service_started", worker="pool", identity=identity,
                    spawn_requested_ns=spawn_requested_ns, cache_directory=str(cache), binary_sha256=sha(args.binary),
                    configuration_sha256=sha(config))
        deadline = time.monotonic() + 20
        while True:
            assert time.monotonic() < deadline, "read-pool startup deadline"
            assert service.poll() is None, "service exited during startup"
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=.3)
            try:
                connection.request("GET", "/healthz")
                response = connection.getresponse()
                if response.status == 200 and json.loads(response.read()) == {"status": "alive", "protocol": 1}:
                    break
            except (OSError, ValueError, http.client.HTTPException):
                assert time.monotonic() < deadline, "read-pool startup deadline"
                time.sleep(.02)
            finally:
                connection.close()
        events.emit("service_ready", worker="pool", identity=identity)
        endpoint = hub.http("pool", port)
        client = private / "client.json"
        client.write_text(json.dumps({"evidence": str(evidence), "endpoint": endpoint,
            "tokens": tokens, "scopes": SCOPES, "commands": COMMANDS}))
        client.chmod(0o600)
        events.emit("configuration", s3_endpoint=s3_endpoint, endpoint=endpoint,
                    access_key_sha256=hashlib.sha256(backend.access.encode()).hexdigest(),
                    credential_hashes={name: hashlib.sha256(value.encode()).hexdigest() for name, value in tokens.items()})
        probe = Probe(args.node, client, private, events)
        hub.phase_to("seed")
        probe.call("seed_a")
        probe.call("seed_b")
        hub.phase_to("overlap")
        hub.arm("first", channel="s3", worker="pool", method="GET", path=HEAD, kind="hold")
        probe.send("first")
        hub.wait("first")
        hub.arm("second", channel="s3", worker="pool", method="GET", path=HEAD, kind="hold")
        probe.send("second")
        hub.wait("second")
        probe.send("queued")
        wait_forwarded(evidence / "events.jsonl", "queued")
        probe.call("other")
        probe.call("write")
        probe.call("control")
        events.emit("both_reads_held_with_independent_progress")
        hub.release("first")
        probe.wait("first")
        probe.wait("queued")
        hub.release("second")
        probe.wait("second")
        hub.phase_to("refresh")
        # Park two other-tenant workers at actual S3 calls, leaving exactly one
        # reader for both warm and refresh. A cold different worker cannot
        # accidentally satisfy the stale-private-image refresh contract.
        for command in ("park_first", "park_second"):
            hub.arm(command, channel="s3", worker="pool", method="GET", path=OTHER_HEAD, kind="hold")
            probe.send(command)
            hub.wait(command)
        for command in ("warm", "write_again", "refresh"):
            probe.call(command)
        for command in ("park_first", "park_second"):
            hub.release(command)
            probe.wait(command)
        hub.phase_to("unknown")
        hub.arm("unavailable", channel="s3", worker="pool", method="GET", path=HEAD, kind="blackhole")
        probe.call("unknown")
        hub.wait("unavailable")
        hub.phase_to("read_only")
        probe.call("query_write")
        hub.phase_to("revoke")
        probe.call("revoke")
        probe.call("denied")
        hub.phase_to("receipts")
        for command in ("lookup_seed_a", "lookup_write", "lookup_write_again", "final"):
            probe.call(command)
        probe.finish()
        probe = None
        images = [{"path": str(path.relative_to(cache)), "device": path.stat().st_dev,
                   "inode": path.stat().st_ino, "bytes": path.stat().st_size}
                  for path in sorted(cache.glob("scap-worker-*/session-*/database.sqlite"))]
        assert images and len({(row["device"], row["inode"]) for row in images}) == len(images)
        events.emit("private_images", images=images)
        events.emit("shutdown_requested", worker="pool", identity=identity)
        service.send_signal(signal.SIGINT)
        status, usage = NET.wait_child(service, 15)
        events.emit("service_stopped", worker="pool", identity=identity, status=status, usage=usage)
        assert status == 0 and not list(cache.iterdir()), "reader threads/cache survived shutdown"
        service = None
        events.emit("cache_cleaned", entries=[])
        hub.close()
        assert not hub.errors, hub.errors
        hub = None
        stopped = backend.stop(verify=True)
        events.emit("backend_stopped", processes=stopped)
        backend = None
        after = source()
        build.save_receipt(evidence / "source-after.json", after)
        assert after == before, "source changed during actual execution"
        import oracle
        report["oracle"] = oracle.verify(evidence)
        import controls
        report["controls"] = controls.check(evidence)
        report["status"] = "passed"
    except BaseException as error:
        report["error"] = repr(error)
        raise
    finally:
        if hub is not None:
            for rule in hub.rules.values():
                rule.released.set()
        if probe is not None:
            if probe.child.poll() is None:
                probe.child.kill()
            NET.wait_child(probe.child, 10)
            probe.thread.join(timeout=3)
            probe.log.close()
        if service is not None:
            if service.poll() is None:
                service.kill()
            NET.wait_child(service, 10)
        if hub is not None:
            hub.close()
        if backend is not None:
            backend.stop()
        for name in ("service.log", "probe.stderr.log"):
            path = Path(temporary.name) / name
            if path.exists():
                (evidence / name).write_bytes(path.read_bytes())
        temporary.cleanup()
        (evidence / "result.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("binary", "build-record", "weed", "node", "evidence"):
        parser.add_argument("--" + name, type=Path, required=True)
    run(parser.parse_args())
