#!/usr/bin/env python3
"""Exercise the production GC port against a private, pinned S3 backend."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import select
import subprocess
import tempfile
import time

import build
from plan import BUCKET, PREFIX, cases
from proxy import Call, Proxy, NS
from support import Log, body_record, body_value, digest, fixture, header, signed_request


class Worker:
    def __init__(self, binary, private, bucket, backend, endpoint, evidence, log, owned):
        config = private / (bucket + ".private.json")
        config.write_text(json.dumps({"endpoint": endpoint, "bucket": bucket, "deployment": 1,
                                     "access_key": backend.access, "secret_key": backend.secret}))
        config.chmod(0o600)
        self.bucket, self.log = bucket, log
        self.input = (evidence / (bucket + ".stdin.jsonl")).open("ab")
        self.output = (evidence / (bucket + ".stdout.jsonl")).open("ab")
        self.errors = (evidence / (bucket + ".stderr.log")).open("wb")
        binary_sha256 = digest(binary)
        self.process = subprocess.Popen([str(binary), str(config)], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=self.errors)
        # No filesystem operation is allowed between a successful Popen and
        # registration in the caller's finally-owned child collection.
        self.identity = fixture.process_identity(self.process)
        owned[bucket] = self
        log.write("worker_started", bucket=bucket, **self.identity, binary_sha256=binary_sha256)

    def send(self, command):
        raw = json.dumps(command, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        self.input.write(raw)
        self.input.flush()
        self.process.stdin.write(raw)
        self.process.stdin.flush()

    def read(self):
        assert select.select([self.process.stdout], [], [], 8)[0], "worker response deadline"
        raw = self.process.stdout.readline(65537)
        self.output.write(raw)
        self.output.flush()
        assert raw.endswith(b"\n") and len(raw) <= 65536
        return json.loads(raw)

    def close(self):
        self.process.stdin.close()
        try:
            code, usage = fixture.wait_child(self.process, 8)
        except TimeoutError:
            self.process.kill()
            code, usage = fixture.wait_child(self.process, 8)
        self.process.stdout.close()
        for stream in (self.input, self.output, self.errors):
            stream.close()
        self.log.write("worker_stopped", bucket=self.bucket, **self.identity,
                       wait_status=code, kernel_usage=usage)
        return code


def run(args):
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    binary = args.worker.resolve()
    receipt = build.verify(args.build_receipt.resolve(), binary)
    plan = cases()
    (evidence / "plan.json").write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n")
    private = Path(tempfile.mkdtemp(prefix="scap-gc-transport-private-"))
    private.chmod(0o700)
    log = Log(evidence / "history.jsonl")
    backend, proxy, workers = None, None, {}
    report = {"schema": 1, "status": "failed", "scope": "GC-transport-only", "aws": "NOT_RUN",
              "product_gc": "OFF", "build_receipt": str(args.build_receipt.resolve()),
              "build_receipt_sha256": digest(args.build_receipt), "private_directory": str(private),
              "source_commit": receipt["source_commit"], "binary": receipt["binary"],
              "backend_binary": {"path": str(args.weed.resolve()), "sha256": digest(args.weed)},
              "planned_cases": len(plan)}
    previous = None

    def observe(case, bucket, key, label):
        response = signed_request(backend, "GET", f"/{bucket}/{key}")
        log.write("object_observation", case=case, bucket=bucket, key=key, label=label, **response)
        return response

    def candidate(case, bucket, index):
        payload = ("GC transport fixture\n" + case + "\n" + str(index) + "\n").encode()
        hash_value = hashlib.sha256(payload).hexdigest()
        key = PREFIX + hash_value
        response = signed_request(backend, "PUT", f"/{bucket}/{key}", payload,
                                  {"if-none-match": "*"})
        log.write("fixture_create", case=case, bucket=bucket, key=key, payload=body_record(payload), **response)
        assert response["status"] == 200
        original = observe(case, bucket, key, "before")
        assert original["status"] == 200 and body_value(original["body"]) == payload
        tag = header(original, "ETag")
        assert tag and tag.startswith('"') and tag.endswith('"')
        return {"hash": hash_value, "etag": tag}

    def versioning(case, bucket, value):
        payload = b"<VersioningConfiguration" + NS + b"><Status>" + value.encode() + b"</Status></VersioningConfiguration>"
        result = signed_request(backend, "PUT", f"/{bucket}?versioning", payload)
        log.write("configuration_change", case=case, bucket=bucket, value=value, payload=body_record(payload), **result)
        assert result["status"] == 200

    try:
        backend = fixture.Backend(args.weed.resolve(), private / "backend", volume_size_mib=16, max_volumes=8)
        backend.start()
        log.write("backend_started", children=backend.identities(), capacity=backend.capacity)
        for bucket in ("scap-gc-versioned", "scap-gc-race"):
            response = signed_request(backend, "PUT", "/" + bucket)
            log.write("bucket_created", bucket=bucket, **response)
            assert response["status"] == 200
        (private / "oracle.private.json").write_text(json.dumps({"access": backend.access, "secret": backend.secret}))
        (private / "oracle.private.json").chmod(0o600)
        proxy = Proxy(backend, log)
        for number, spec in enumerate(plan, 1):
            name, kind = spec["name"], spec["kind"]
            bucket = spec.get("bucket", BUCKET)
            if bucket not in workers:
                Worker(binary, private, bucket, backend, proxy.endpoint, evidence, log, workers)
                assert workers[bucket].read() == {"ready": True, "max_delete_batch": 32, "max_gc_response_bytes": 32768}
            worker = workers[bucket]
            if kind in ("enabled", "suspended"):
                versioning(name, bucket, kind.capitalize())
            count = 33 if kind == "budget" else 2 if kind in ("delete_fault", "race") else 1
            choices = []
            if kind in ("exact", "wrong", "budget", "bad_hash", "bad_etag", "delete_fault", "race"):
                choices = [candidate(name, bucket, index) for index in range(count)]
            elif kind == "repeat":
                assert previous is not None
                choices = [dict(previous)]
                observe(name, bucket, PREFIX + choices[0]["hash"], "before")
            originals = [dict(value) for value in choices]
            if kind == "wrong":
                choices[0]["etag"] = '"wrong-original-etag"'
            elif kind == "bad_hash":
                choices.insert(0, {"hash": "HEAD", "etag": choices[0]["etag"]})
            elif kind == "bad_etag":
                choices.insert(0, {"hash": choices[0]["hash"], "etag": "*"})
            command = {"id": number, "prefix": spec.get("prefix", PREFIX), "deadline_ms": 5000,
                       "candidates": choices}
            if kind == "expired":
                command["deadline_ms"] = 0
            if spec.get("mode") in ("drop_before", "drop_after", "late_before"):
                command["deadline_ms"] = 750
            call = Call(name, spec.get("stage"), spec.get("mode"))
            proxy.current = call
            log.write("invoke", case=name, bucket=bucket, command=command)
            worker.send(command)
            mode = spec.get("mode")
            if mode in ("drop_before", "drop_after", "late_before", "config_race"):
                assert call.arrived.wait(5), "planned transport fault not reached"
            if mode == "config_race":
                versioning(name, bucket, "Enabled")
                call.release.set()
            result = worker.read()
            log.write("return", case=name, bucket=bucket, result=result)
            call.release.set()
            call.idle()
            assert not proxy.errors, proxy.errors
            log.write("case_transport_closed", case=name, requests=call.requests, injected=call.used)
            for choice in originals:
                observe(name, bucket, PREFIX + choice["hash"], "after")
            if kind == "race":
                response = signed_request(backend, "GET", f"/{bucket}?versions&prefix={PREFIX}")
                log.write("versions_observation", case=name, bucket=bucket, **response)
            if kind == "exact":
                previous = dict(originals[0])
        report["workload_completed"] = True
    except BaseException as error:
        report["error"] = repr(error)
        raise
    finally:
        failures = []
        if proxy is not None:
            try:
                proxy.close()
            except BaseException as error:
                failures.append(repr(error))
        for worker in workers.values():
            try:
                assert worker.close() == 0
            except BaseException as error:
                failures.append(repr(error))
        if backend is not None:
            try:
                log.write("backend_stopped", children=backend.stop())
            except BaseException as error:
                failures.append(repr(error))
        report["cleanup_errors"] = failures
        report["source_and_binary_unchanged"] = build.verify(args.build_receipt.resolve(), binary) == receipt
        report["raw_files"] = {path.name: digest(path) for path in sorted(evidence.iterdir()) if path.is_file()}
        (evidence / "run.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    assert not report["cleanup_errors"], report["cleanup_errors"]
    import oracle
    audit = oracle.audit_directory(evidence, private / "oracle.private.json")
    (evidence / "audit.json").write_text(json.dumps(audit, indent=2, sort_keys=True) + "\n")
    report["status"] = "passed"
    report["audit_sha256"] = digest(evidence / "audit.json")
    (evidence / "run.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": "passed", "scope": report["scope"], **audit}), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", type=Path, required=True)
    parser.add_argument("--build-receipt", type=Path, required=True)
    parser.add_argument("--weed", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    run(parser.parse_args())
