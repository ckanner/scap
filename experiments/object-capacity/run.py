#!/usr/bin/env python3
"""Capacity observations of the production implementation over real S3 TCP.

No persistence, transaction, identity, or recovery algorithm lives here. The
shared thin worker performs those operations through the production crates.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import threading
import time


NETWORK = Path(__file__).resolve().parents[1] / "object-network"
sys.path.insert(0, str(NETWORK))
SPEC = importlib.util.spec_from_file_location("object_network_fixture", NETWORK / "run.py")
net = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(net)

MIB = 1024 * 1024
GIB = 1024 * MIB
PAGE = 4096
BLOB = 64 * 1024
BATCH_ROWS = 512
QUERY_ROWS = 64
OPERATION_MS = 30_000
RECOVERY_MS = 1_800_000
FREE_DISK_GUARD = 4 * GIB


def append_synced(path, value):
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(value, sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def file_sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def json_lines(path):
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            yield json.loads(line)


def tree_usage(path):
    logical = allocated = files = 0
    for directory, _subdirectories, names in os.walk(path):
        for name in names:
            item = (Path(directory) / name).stat()
            logical += item.st_size
            allocated += item.st_blocks * 512
            files += 1
    return {"logical_bytes": logical, "allocated_bytes": allocated, "files": files}


class Resources:
    """Combine self-reported worker procfs samples and owned-child wait4."""

    def __init__(self, evidence, filesystem):
        self.evidence = evidence
        self.filesystem = filesystem
        self.lock = threading.Lock()
        self.targets = {}
        self.errors = []
        self.samples = 0
        self.minimum_free = shutil.disk_usage(filesystem).free
        self.maximum_cgroup_current = 0
        self.stop = threading.Event()
        self.path = evidence / "resource-samples.jsonl"
        self.path.touch(mode=0o600, exist_ok=False)
        self.thread = threading.Thread(target=self.loop, name="capacity-resources", daemon=False)
        self.thread.start()

    def add(self, role, identity):
        with self.lock:
            self.targets[(identity["pid"], identity["spawn_monotonic_ns"])] = {"role": role, **identity}

    def sample(self):
        with self.lock:
            targets = list(self.targets.values())
        free = shutil.disk_usage(self.filesystem).free
        self.minimum_free = min(self.minimum_free, free)
        cgroup = Path("/sys/fs/cgroup/memory.current")
        cgroup_current = int(cgroup.read_text()) if cgroup.exists() else None
        if cgroup_current is not None:
            self.maximum_cgroup_current = max(self.maximum_cgroup_current, cgroup_current)
        value = {"monotonic_ns": time.monotonic_ns(), "wall_time_ns": time.time_ns(),
                 "owned_processes": targets, "individual_rss_source": "worker-resources-*.jsonl",
                 "filesystem_free_bytes": free, "shared_cgroup_memory_current": cgroup_current}
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(value, sort_keys=True) + "\n")
        self.samples += 1

    def loop(self):
        try:
            while not self.stop.wait(0.1):
                self.sample()
        except BaseException as error:
            self.errors.append(repr(error))
            net.record(self.evidence, "resource_sampler_failed", error=repr(error))

    def close(self):
        self.stop.set()
        self.thread.join(timeout=5)
        assert not self.thread.is_alive()
        self.sample()
        with self.path.open("ab") as stream:
            stream.flush()
            os.fsync(stream.fileno())
        worker_hwm = {}
        expected_workers = {entry["role"].removeprefix("worker-"): entry for entry in self.targets.values()
                            if entry["role"].startswith("worker-")}
        sampled_workers = set()
        for path in sorted(self.evidence.glob("worker-resources-*.jsonl")):
            count = 0
            for value in json_lines(path):
                identity = str(value["worker"])
                expected = expected_workers[identity]
                assert value["resources"]["namespace_pid"] == expected["pid"]
                assert value["resources"]["proc_pid"] == expected["self_proc_pid"]
                assert value["resources"]["start_ticks"] == expected["self_start_ticks"]
                assert value["resources"]["hwm_kib"] >= value["resources"]["rss_kib"] > 0
                sampled_workers.add(identity)
                worker_hwm[identity] = max(worker_hwm.get(identity, 0), value["resources"]["hwm_kib"] * 1024)
                count += 1
            assert count > 0, f"missing worker self-samples: {path.name}"
        assert sampled_workers == set(expected_workers), "every live worker must have valid self RSS/HWM samples"
        kernel = []
        for event in json_lines(self.evidence / "history.jsonl"):
            if event["event"] in ("worker_started", "client_observed") and event.get("resources"):
                identity = str(event["worker"])
                worker_hwm[identity] = max(worker_hwm.get(identity, 0), event["resources"]["hwm_kib"] * 1024)
            if event["event"] == "worker_stopped":
                kernel.append({"role": f"worker-{event['worker']}", "pid": event["pid"], **event["kernel_usage"]})
            if event["event"] in ("backend_processes_killed", "backend_stopped"):
                kernel.extend({"role": "backend-" + process["role"], "pid": process["pid"], **process["kernel_usage"]}
                              for process in event["processes"])
        return {"samples": self.samples, "worker_self_procfs_hwm_bytes": worker_hwm,
                "kernel_child_usage": kernel,
                "external_procfs_child_rss": "NOT_USED_self_sampling_avoids_namespace_ambiguity",
                "minimum_filesystem_free_bytes": self.minimum_free,
                "maximum_shared_cgroup_memory_current": self.maximum_cgroup_current,
                "shared_cgroup_includes_other_processes_and_page_cache": True,
                "errors": self.errors}


class Capacity:
    def __init__(self, arguments):
        self.arguments = arguments
        self.evidence = arguments.evidence.resolve()
        self.evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
        build = None
        if arguments.build_record:
            from build import capture_receipt
            build = capture_receipt(arguments.build_record, arguments.worker, self.evidence)
        self.private = Path(tempfile.mkdtemp(prefix="scap-object-capacity-private-"))
        self.compute = self.private / "compute"
        self.compute.mkdir(mode=0o700)
        self.backend = net.Backend(arguments.weed.resolve(), self.private / "backend", 1024, 32)
        self.proxy = net.Proxy(self.backend.port, self.evidence)
        self.resources = Resources(self.evidence, self.private)
        self.workers = []
        self.scope = {"deployment": 177, "tenant": 188, "database": 199,
                      "incarnation": 1, "generation": 1}
        self.config = {"endpoint": self.proxy.endpoint, "region": "us-east-1", "bucket": "scap-test",
                       "access_key": self.backend.access, "secret_key": self.backend.secret,
                       "scope": self.scope, "worker": 1, "principal": 17, "cache_root": str(self.compute)}
        self.input_ledger = self.evidence / "input-ledger.jsonl"
        self.ack_ledger = self.evidence / "ack-ledger.jsonl"
        self.input_ledger.touch(mode=0o600, exist_ok=False)
        self.ack_ledger.touch(mode=0o600, exist_ok=False)
        self.request_serial = 0
        self.worker_serial = 0
        self.ack_count = 0
        self.row_count = 0
        self.padding_count = 0
        self.nonce = 2
        self.summary = {"schema": 1, "status": "failed", "profile": arguments.profile,
                        "diagnostic": arguments.diagnostic, "aws_endpoint_gate": "NOT_RUN",
                        "production_slo_passed": False, "unit_coverage_contribution": False,
                        "lazy_database_reads": False, "full_initial_materialization": True,
                        "default_options_unchanged": True, "default_quota_bytes": 10 * GIB,
                        "payload_generator": "independent os.urandom bytes persisted and hashed before invocation",
                        "blob_bytes": BLOB, "maximum_bulk_rows": BATCH_ROWS,
                        "maximum_bulk_payload_bytes": BATCH_ROWS * BLOB, "query_batch_rows": QUERY_ROWS,
                        "operation_budget_ms": OPERATION_MS, "recovery_budget_ms": RECOVERY_MS,
                        "backend_version": net.VERSION, "backend_capacity": self.backend.capacity,
                        "backend_binary_sha256": file_sha256(arguments.weed),
                        "worker_binary_sha256": file_sha256(arguments.worker),
                        "build_record_verified": build is not None,
                        "build_input_sha256": build["input_sha256"] if build else None,
                        "private_fixture": str(self.private), "ack_audit_complete": False,
                        "blob_audit_complete": False, "gc_enabled": False,
                        "completed_checks": []}

    def phase(self, name):
        self.proxy.set_phase(name)

    def checked(self, name, **observations):
        self.summary["completed_checks"].append(name)
        net.record(self.evidence, "capacity_check_passed", name=name, **observations)

    def new_worker(self, principal=17):
        self.worker_serial += 1
        worker = net.Worker(self.arguments.worker.resolve(),
                            {**self.config, "worker": self.worker_serial, "principal": principal,
                             "resource_log": str(self.evidence / f"worker-resources-{self.worker_serial}.jsonl")},
                            self.private, self.worker_serial, self.evidence)
        self.resources.add(f"worker-{self.worker_serial}", worker.identity)
        self.workers.append(worker)
        return worker

    def guard(self):
        assert not self.resources.errors, self.resources.errors
        available = shutil.disk_usage(self.private).free
        assert available >= FREE_DISK_GUARD, {"free_disk_bytes": available, "required": FREE_DISK_GUARD}
        assert not self.proxy.errors, self.proxy.errors

    def data(self, identifiers):
        path = self.private / "current-input.private.bin"
        assert not path.exists()
        changes = []
        parameters = []
        with path.open("xb") as stream:
            os.chmod(path, 0o600)
            for offset, identity in enumerate(identifiers):
                value = os.urandom(BLOB)
                digest = hashlib.sha256(value).hexdigest()
                stream.write(value)
                changes.append({"id": identity, "bytes": BLOB, "sha256": digest})
                parameters.append({"type": "integer", "value": identity})
                parameters.append({"type": "blob_file", "path": str(path), "offset": offset * BLOB,
                                   "length": BLOB, "sha256": digest})
            stream.flush()
            os.fsync(stream.fileno())
        return path, changes, parameters

    def prepare(self, worker, statements, changes, operation, batch_file=None):
        self.request_serial += 1
        identity = self.request_serial
        # The input oracle is durable before even asking the production codec
        # for a request fingerprint; returned receipts cannot define this set.
        append_synced(self.input_ledger, {"event": "input_prepared", "id": identity,
            "scope": self.scope, "principal": worker.config["principal"], "epoch": 1,
            "operation": operation, "changes": changes,
            "sql": [statement["sql"] for statement in statements],
            "input_file_bytes": batch_file.stat().st_size if batch_file else 0,
            "input_file_sha256": file_sha256(batch_file) if batch_file else None})
        request = net.success(worker.call("prepare_request", epoch=1, id=identity,
                                          statements=statements, budget_ms=OPERATION_MS))
        assert request["id"] == identity and request["epoch"] == 1
        assert request["principal"] == worker.config["principal"]
        invocation = {"scope": self.scope, "principal": worker.config["principal"],
                      "epoch": 1, "id": identity, "request": request}
        append_synced(self.input_ledger, {"event": "invocation_prepared", "invocation": invocation})
        return invocation

    def ack(self, invocation, receipt, encoded, observed, resolution):
        assert receipt["scope"] == invocation["scope"]
        assert receipt["request"] == invocation["request"]
        self.ack_count += 1
        entry = {"ordinal": self.ack_count, "invocation": invocation, "receipt": receipt,
                 "encoded_result": encoded, "observed_statements": observed, "first_observed_via": resolution}
        append_synced(self.ack_ledger, entry)
        net.record(self.evidence, "client_ack_recorded", ordinal=self.ack_count,
                   request=invocation["request"], result_sha256=hashlib.sha256(bytes(encoded)).hexdigest(),
                   first_observed_via=resolution)

    def mutation(self, worker, statements, changes, operation, batch_file=None, lose_response=False, expect_failure=False):
        self.guard()
        invocation = self.prepare(worker, statements, changes, operation, batch_file)
        rule = self.proxy.arm("drop", "/head") if lose_response else None
        try:
            response = worker.call("session_execute", epoch=1, id=invocation["id"],
                                   statements=statements, budget_ms=OPERATION_MS)
            if lose_response:
                net.failure(response, "Store(Unknown)", "Unknown")
                assert rule.used == 1
                value = net.success(worker.call("lookup_identity", identity=invocation["request"], budget_ms=OPERATION_MS))
                assert value["state"] == "committed", value
                self.ack(invocation, value["receipt"], value["encoded"], None, "lookup_after_unknown")
                return value
            if expect_failure:
                assert not response["ok"], response
                net.record(self.evidence, "expected_capacity_rejection", invocation=invocation,
                           error=response["error"])
                return {**response, "invocation": invocation}
            value = net.success(response)
            self.ack(invocation, value["receipt"], value["result"]["encoded"],
                     value["result"]["statements"], "execute")
            return value
        finally:
            if batch_file:
                batch_file.unlink()

    @staticmethod
    def nonce_statement():
        return {"sql": "SELECT random() AS original_nonce"}

    def create_table(self, worker):
        self.mutation(worker, [{"sql": "CREATE TABLE payloads(id INTEGER PRIMARY KEY, payload BLOB NOT NULL)"},
                               self.nonce_statement()], [], "create_payloads")

    def append_rows(self, worker, count, phase):
        self.phase(phase)
        identifiers = range(self.row_count + 1, self.row_count + count + 1)
        path, changes, parameters = self.data(identifiers)
        sql = "INSERT INTO payloads(id,payload) VALUES " + ",".join("(?,?)" for _ in changes)
        self.mutation(worker, [{"sql": sql, "parameters": parameters}, self.nonce_statement()],
                      changes, "insert", path)
        self.row_count += count

    def point(self, worker, identity, phase, lose_response=False):
        self.phase(phase)
        path, changes, parameters = self.data([identity])
        self.mutation(worker, [{"sql": "UPDATE payloads SET payload=? WHERE id=?",
                               "parameters": [parameters[1], parameters[0]]}, self.nonce_statement()],
                      changes, "update", path, lose_response=lose_response)
        metrics = self.proxy.metrics()[phase]
        self.summary.setdefault("point_mutations", {})[phase] = {
            **metrics, "logical_changed_payload_bytes": BLOB,
            "put_body_amplification": metrics["put_request_bytes"] / BLOB,
            "get_body_amplification": metrics["get_response_bytes"] / BLOB,
            "database_payload_bytes": self.row_count * BLOB}
        return metrics

    def authority(self, worker):
        return net.success(worker.call("authority_info", budget_ms=OPERATION_MS))

    def pages(self, worker):
        return net.success(worker.call("session_info"))["page_count"]

    def policy(self, worker, reader):
        head = net.success(worker.call("status"))
        self.nonce += 1
        policy = [{"principal": 17, "read": True, "write": True, "admin": True}]
        if reader:
            policy.append({"principal": 18, "read": True, "write": False, "admin": False})
        return net.success(worker.call("set_policy", revision=head["revision"], nonce=self.nonce, policy=policy))

    def gib1(self, writer):
        required = GIB // BLOB
        while self.row_count < required:
            self.append_rows(writer, min(BATCH_ROWS, required - self.row_count), f"load_{self.row_count // BATCH_ROWS + 1:04}")
            if self.row_count == 2 * BATCH_ROWS:
                self.point(writer, 1, "point_64mib")
        assert self.row_count * BLOB == GIB
        self.checked("one_gib_independent_payload_committed", payload_bytes=self.row_count * BLOB)
        for name, identity in (("beginning", 1), ("middle", self.row_count // 2), ("end", self.row_count)):
            metrics = self.point(writer, identity, f"point_1gib_{name}")
            # Includes fresh HEAD, changed chunks/tree paths, retained result
            # verification and immutable readback, not only chosen requests.
            assert metrics["get_response_bytes"] < 8 * MIB, metrics
            assert metrics["put_request_bytes"] < 8 * MIB, metrics
            assert metrics["get_requests"] < 512 and metrics["put_requests"] < 64, metrics
        self.checked("warm_point_updates_do_not_transfer_whole_gib")

        self.phase("reader_recovery")
        self.policy(writer, True)
        reader = self.new_worker(principal=18)
        net.success(reader.call("session_open", directory="reader-cache", budget_ms=RECOVERY_MS))
        self.phase("revoked_reader")
        self.policy(writer, False)
        net.failure(reader.call("session_query", sql="SELECT count(*) FROM payloads"), "Denied")
        self.policy(writer, True)
        assert net.success(reader.call("session_query", sql="SELECT count(*) FROM payloads"))["statements"][0]["rows"] == [[self.row_count]]
        self.point(writer, 2, "root_change")
        net.failure(reader.call("session_query", sql="SELECT count(*) FROM payloads"), "StaleSnapshot")
        self.checked("warm_session_rechecks_permission_and_exact_root")
        # The stopped cache is no longer useful; graceful drop is deliberately
        # not the later all-compute-loss fault.
        net.success(reader.call("session_close"))
        self.point(writer, 3, "lost_head_result", lose_response=True)
        self.checked("unknown_resolved_without_sql_replay")

    def default_quota(self, writer):
        maximum = 10 * GIB // PAGE
        # Conservative allocation estimate includes a row's overflow and
        # B-tree overhead. Close the final small gap with real schema pages.
        while True:
            remaining = maximum - self.pages(writer)
            count = min(BATCH_ROWS, max(0, (remaining - 32) // 18))
            if count == 0:
                break
            self.append_rows(writer, count, f"quota_load_{self.request_serial:04}")
        assert self.row_count * BLOB > 9 * GIB
        while self.pages(writer) < maximum:
            self.padding_count += 1
            assert self.padding_count <= 64, "conservative tail must stay a small metadata fraction"
            self.phase("quota_metadata_tail")
            name = f"padding_{self.padding_count:03}"
            self.mutation(writer, [{"sql": f"CREATE TABLE {name}(value INTEGER)"}, self.nonce_statement()],
                          [], "create_" + name)
        assert self.pages(writer) == maximum
        head_at_cap = self.authority(writer)
        assert head_at_cap["head"]["quota"]["max_bytes"] == 10 * GIB
        assert head_at_cap["database_bytes"] == 10 * GIB
        self.summary["quota_boundary"] = {"maximum_bytes": 10 * GIB, "observed_page_count": maximum,
                                          "metadata_tail_tables": self.padding_count}
        self.checked("default_ten_gib_physical_boundary_reached", page_count=maximum,
                     independent_blob_bytes=self.row_count * BLOB)
        metrics = self.point(writer, self.row_count // 2, "point_at_default_quota")
        assert metrics["get_response_bytes"] < 8 * MIB and metrics["put_request_bytes"] < 8 * MIB, metrics
        assert metrics["get_requests"] < 512 and metrics["put_requests"] < 64, metrics
        assert self.pages(writer) == maximum
        before = self.authority(writer)
        self.phase("quota_rejection")
        rejected = self.mutation(writer, [{"sql": "CREATE TABLE beyond_default_quota(value INTEGER)"},
                                         self.nonce_statement()], [], "beyond_default_quota", expect_failure=True)
        assert "SqliteFailure" in rejected["error"] and "code: DiskFull, extended_code: 13" in rejected["error"], rejected
        after = self.authority(writer)
        assert after == before
        self.summary["quota_boundary"]["rejection"] = rejected["error"]
        self.summary["quota_boundary"]["rejected_request"] = rejected["invocation"]["request"]
        self.checked("quota_rejects_new_page_without_head_change")

    def allocation(self, stage):
        databases = []
        for path in self.compute.rglob("database.sqlite"):
            item = path.stat()
            databases.append({"directory": path.parent.name, "logical_bytes": item.st_size,
                              "allocated_bytes": item.st_blocks * 512})
        value = {"stage": stage, "compute": tree_usage(self.compute),
                 "backend": tree_usage(self.backend.directory), "database_files": databases}
        assert len(databases) == 1, value
        assert databases[0]["allocated_bytes"] >= self.row_count * BLOB, value
        assert value["backend"]["allocated_bytes"] >= self.row_count * BLOB, value
        self.summary.setdefault("disk_observations", []).append(value)
        net.record(self.evidence, "disk_allocation_observed", **value)

    def recover(self):
        self.phase("compute_and_backend_loss")
        self.allocation("before_compute_loss")
        killed = [worker.kill(verify=True) for worker in self.workers]
        self.workers.clear()
        shutil.rmtree(self.compute)
        self.compute.mkdir(mode=0o700)
        assert not list(self.compute.iterdir())
        net.record(self.evidence, "all_compute_and_local_cache_lost", processes=killed,
                   process_signal="SIGKILL", local_cache_deleted=True)
        backend_identity = hashlib.sha256(str(self.backend.directory.resolve()).encode()).hexdigest()
        stopped = self.backend.stop(verify=True)
        net.record(self.evidence, "backend_processes_killed", processes=stopped, signal="SIGKILL",
                   directory_identity=backend_identity)
        self.backend.start()
        for identity in self.backend.identities():
            self.resources.add("backend-" + identity["role"], identity)
        net.record(self.evidence, "backend_restarted", processes=self.backend.identities(),
                   directory_identity=backend_identity)
        recovered = self.new_worker()
        self.phase("cold_recovery")
        head = net.success(recovered.call("status"))
        self.nonce += 1
        head = net.success(recovered.call("takeover", revision=head["revision"], nonce=self.nonce))
        self.nonce += 1
        net.success(recovered.call("activate_session", revision=head["revision"], nonce=self.nonce,
                                   directory="recovered-cache", budget_ms=RECOVERY_MS))
        self.allocation("after_s3_only_recovery")
        self.checked("all_compute_and_backend_process_loss_recovered_from_s3")
        return recovered

    def audit_acks(self, worker):
        self.phase("ack_audit")
        acknowledgements = list(json_lines(self.ack_ledger))
        assert len(acknowledgements) == self.ack_count and self.ack_count > 0
        assert [entry["ordinal"] for entry in acknowledgements] == list(range(1, self.ack_count + 1))
        inputs = list(json_lines(self.input_ledger))
        prepared = {entry["invocation"]["id"]: entry["invocation"] for entry in inputs if entry["event"] == "invocation_prepared"}
        operations = {entry["id"]: entry for entry in inputs if entry["event"] == "input_prepared"}
        mismatches = []
        expected = {}
        expected_tables = []
        seen = set()
        for entry in acknowledgements:
            invocation = entry["invocation"]
            identity = invocation["id"]
            assert identity not in seen
            seen.add(identity)
            assert invocation == prepared[identity]
            assert invocation["scope"] == self.scope and invocation["principal"] == 17
            observed = worker.call("lookup_identity", identity=invocation["request"], budget_ms=OPERATION_MS)
            value = observed.get("value", {})
            matches = (observed["ok"] and value.get("state") == "committed"
                       and value.get("receipt") == entry["receipt"]
                       and value.get("encoded") == entry["encoded_result"])
            net.record(self.evidence, "ack_audited", ordinal=entry["ordinal"], request=invocation["request"],
                       matches=matches, observed=observed)
            if not matches:
                mismatches.append({"ordinal": entry["ordinal"], "observed": observed})
            for change in operations[identity]["changes"]:
                expected[change["id"]] = {"blob_bytes": change["bytes"], "sha256": change["sha256"]}
            if operations[identity]["operation"].startswith("create_padding_"):
                expected_tables.append(operations[identity]["operation"].removeprefix("create_"))
        self.summary.update(ack_audited_count=len(acknowledgements), ack_mismatch_count=len(mismatches),
                            ack_mismatches=mismatches, ack_audit_complete=True,
                            ack_ledger_sha256=file_sha256(self.ack_ledger),
                            input_ledger_sha256=file_sha256(self.input_ledger))
        assert not mismatches, mismatches
        assert len(expected) == self.row_count
        self.checked("every_client_ack_retains_exact_receipt_and_original_result", count=len(acknowledgements))
        return expected, expected_tables

    def audit_blobs(self, worker, expected, expected_tables):
        self.phase("blob_audit")
        last = count = payload_bytes = 0
        mismatches = []
        aggregate = hashlib.sha256()
        while True:
            value = net.success(worker.call("session_query", hash_blobs=True, budget_ms=OPERATION_MS,
                sql=f"SELECT id,payload FROM payloads WHERE id > {last} ORDER BY id LIMIT {QUERY_ROWS}"))
            rows = value["statements"][0]["rows"]
            if not rows:
                break
            for identity, observed in rows:
                assert identity > last, {"previous": last, "observed": identity}
                last = identity
                matches = observed == expected.get(identity)
                if not matches:
                    mismatches.append({"id": identity, "expected": expected.get(identity), "observed": observed})
                count += 1
                payload_bytes += observed["blob_bytes"]
                aggregate.update(json.dumps([identity, observed], sort_keys=True, separators=(",", ":")).encode() + b"\n")
            net.record(self.evidence, "blob_batch_audited", first_id=rows[0][0], last_id=last,
                       count=len(rows), rows=rows, cumulative_count=count, mismatch_count=len(mismatches))
        if count != len(expected):
            mismatches.append({"expected_row_count": len(expected), "observed_row_count": count})
        tables = net.success(worker.call("session_query", sql="SELECT name FROM sqlite_schema WHERE name GLOB 'padding_*' ORDER BY name"))
        assert [row[0] for row in tables["statements"][0]["rows"]] == sorted(expected_tables)
        if "quota_boundary" in self.summary:
            rejected = net.success(worker.call("lookup_identity",
                identity=self.summary["quota_boundary"]["rejected_request"], budget_ms=OPERATION_MS))
            assert rejected["state"] == "unknown", rejected
            absent = net.success(worker.call("session_query",
                sql="SELECT name FROM sqlite_schema WHERE name='beyond_default_quota'"))
            assert absent["statements"][0]["rows"] == []
            net.record(self.evidence, "rejected_quota_request_has_no_effect", resolution=rejected,
                       table_absent=True)
        self.summary.update(blob_audited_count=count, blob_audited_bytes=payload_bytes,
                            blob_mismatch_count=len(mismatches), blob_mismatches=mismatches,
                            blob_audit_complete=True, observed_blob_hashes_sha256=aggregate.hexdigest())
        assert not mismatches, mismatches
        assert payload_bytes == self.row_count * BLOB
        self.checked("every_blob_matches_independent_preinvocation_hash", rows=count, bytes=payload_bytes)

    def hot_blackhole(self, worker):
        self.phase("hot_cache_head_blackhole")
        before = self.proxy.metrics().get("hot_cache_head_blackhole", {"get_requests": 0})["get_requests"]
        rule = self.proxy.arm("blackhole")
        started = time.monotonic()
        try:
            net.failure(worker.call("session_query", sql="SELECT count(*) FROM payloads", budget_ms=200), "Store(Unknown)")
            assert rule.used == 1
            assert self.proxy.metrics()["hot_cache_head_blackhole"]["get_requests"] == before + 1
            elapsed = time.monotonic() - started
            assert elapsed < 2.0, elapsed
        finally:
            self.proxy.clear()
        self.summary["hot_cache_blackhole_elapsed_seconds"] = elapsed
        self.checked("hot_cache_cannot_bypass_unavailable_fresh_head", elapsed_seconds=elapsed)

    def run(self):
        writer = None
        try:
            self.guard()
            net.record(self.evidence, "capacity_run_started", profile=self.arguments.profile,
                       default_options_unchanged=True, backend_capacity=self.backend.capacity)
            self.backend.start()
            for identity in self.backend.identities():
                self.resources.add("backend-" + identity["role"], identity)
            net.record(self.evidence, "backend_started", processes=self.backend.identities(),
                       directory_identity=hashlib.sha256(str(self.backend.directory.resolve()).encode()).hexdigest())
            writer = self.new_worker()
            head = net.success(writer.call("create", nonce=1))
            assert head["quota"]["max_bytes"] == 10 * GIB
            assert head["retention"] == {"max_entries": 4096, "max_result_bytes": 256 * MIB}
            net.success(writer.call("activate_session", revision=head["revision"], nonce=2,
                                    directory="writer-cache", budget_ms=RECOVERY_MS))
            self.create_table(writer)
            if self.arguments.profile == "gib1":
                self.gib1(writer)
            else:
                self.default_quota(writer)
            self.summary["acknowledged_payload_bytes"] = self.row_count * BLOB
            self.summary["pre_loss_authority"] = self.authority(writer)
            recovered = self.recover()
            expected, expected_tables = self.audit_acks(recovered)
            self.audit_blobs(recovered, expected, expected_tables)
            self.hot_blackhole(recovered)
            self.guard()
            self.summary["status"] = "checks_completed"
        except BaseException as error:
            self.summary["error"] = repr(error)
            net.record(self.evidence, "capacity_verification_failed", error=repr(error),
                       acknowledged_rows=self.row_count, completed_checks=self.summary["completed_checks"])
            raise
        finally:
            self.proxy.clear()
            cleanup_errors = []
            for worker in self.workers:
                try:
                    worker.kill()
                except BaseException as error:
                    cleanup_errors.append(repr(error))
            try:
                self.proxy.close()
            except BaseException as error:
                cleanup_errors.append(repr(error))
            try:
                stopped = self.backend.stop()
                net.record(self.evidence, "backend_stopped", processes=stopped)
            except BaseException as error:
                cleanup_errors.append(repr(error))
            try:
                self.summary["resources"] = self.resources.close()
            except BaseException as error:
                cleanup_errors.append(repr(error))
            self.summary["object_metrics"] = self.proxy.metrics()
            self.summary["proxy_errors"] = self.proxy.errors
            self.summary["cleanup_errors"] = cleanup_errors
            if self.resources.errors or self.proxy.errors or cleanup_errors:
                self.summary["status"] = "failed"
            elif self.summary["status"] == "checks_completed":
                self.summary["status"] = "passed"
                net.record(self.evidence, "capacity_verification_passed", checks=len(self.summary["completed_checks"]))
            self.summary["acknowledged_payload_bytes"] = self.row_count * BLOB
            self.summary["history_sha256"] = file_sha256(self.evidence / "history.jsonl")
            (self.evidence / "summary.json").write_text(json.dumps(self.summary, indent=2, sort_keys=True) + "\n")
        assert self.summary["status"] == "passed", self.summary.get("error", "fixture failure")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker", type=Path, required=True)
    parser.add_argument("--weed", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--profile", choices=("gib1", "default-quota"), required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--build-record", type=Path)
    mode.add_argument("--diagnostic", action="store_true")
    assert "LLVM_PROFILE_FILE" not in os.environ
    Capacity(parser.parse_args()).run()
