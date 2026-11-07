"""ALTER, retained results and cold recovery through the real S3/SQLite worker.

This controller only supplies SQL, kills its own processes, and checks an
independent client ledger. It does not implement schema migration or recovery.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import sys
import tempfile


MODES = ("execute", "session_execute")
CONTRACT = "alter_schema_original_results_and_all_compute_loss"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def plan(first, second):
    """Inputs are recorded before any invocation; random() comes from SQLite."""
    return [
        [
            {"sql": "CREATE TABLE items(id INTEGER PRIMARY KEY, payload TEXT NOT NULL, obsolete TEXT, nonce INTEGER NOT NULL)"},
            {"sql": "CREATE TABLE child(item_id INTEGER PRIMARY KEY REFERENCES items(id))"},
            {"sql": "CREATE TABLE audit(item_id INTEGER NOT NULL, payload TEXT NOT NULL)"},
            {"sql": "CREATE INDEX items_payload ON items(payload)"},
            {"sql": "CREATE VIEW item_view AS SELECT id,payload AS shown_payload,nonce FROM items"},
            {"sql": "CREATE TRIGGER item_insert AFTER INSERT ON items BEGIN INSERT INTO audit VALUES(NEW.id,NEW.payload); END"},
        ],
        [
            {"sql": "INSERT INTO items VALUES(1,?,'discarded',random()) RETURNING id,payload,nonce",
             "parameters": [{"type": "text", "value": first}]},
            {"sql": "INSERT INTO child VALUES(1)"},
        ],
        [{"sql": "ALTER TABLE items RENAME TO renamed_items"}],
        [{"sql": "ALTER TABLE renamed_items RENAME COLUMN payload TO body"}],
        [{"sql": "ALTER TABLE renamed_items DROP COLUMN obsolete"}],
        [
            {"sql": "INSERT INTO renamed_items VALUES(2,?,random()) RETURNING id,body,nonce",
             "parameters": [{"type": "text", "value": second}]},
            {"sql": "INSERT INTO child VALUES(2)"},
        ],
    ]


def original_matches(entry, observed, *, replay=False):
    if replay:
        return (observed.get("receipt") == entry["receipt"]
                and observed.get("result", {}).get("encoded") == entry["encoded_result"]
                and observed.get("result", {}).get("statements") == entry["observed_statements"])
    return (observed.get("state") == "committed" and observed.get("receipt") == entry["receipt"]
            and observed.get("encoded") == entry["encoded_result"])


def expected_state(entries, payloads):
    require(len(entries) == 6, "all six schema/seed/late-write ACKs are required")
    require([row["invocation"]["id"] for row in entries] == list(range(1, 7)),
            "schema ACK identity inventory changed")
    rows = []
    for ordinal, identity in ((1, 2), (2, 6)):
        observed = entries[identity - 1]["observed_statements"][0]["rows"]
        require(len(observed) == 1 and len(observed[0]) == 3, "unexpected original RETURNING shape")
        row = observed[0]
        require(row[:2] == [ordinal, payloads[ordinal - 1]] and type(row[2]) is int,
                "original RETURNING disagrees with the independent input")
        rows.append(list(row))
    return [
        ("table", "SELECT * FROM renamed_items ORDER BY id", ["id", "body", "nonce"], rows),
        ("view", "SELECT id,shown_payload,nonce FROM item_view ORDER BY id",
         ["id", "shown_payload", "nonce"], rows),
        ("trigger", "SELECT item_id,payload FROM audit ORDER BY item_id",
         ["item_id", "payload"], [row[:2] for row in rows]),
        ("foreign_key", "SELECT child.item_id,r.body FROM child JOIN renamed_items AS r ON child.item_id=r.id ORDER BY child.item_id",
         ["item_id", "body"], [row[:2] for row in rows]),
        ("schema", "SELECT type,name,tbl_name FROM sqlite_schema WHERE name IN ('items','renamed_items','audit','child','items_payload','item_view','item_insert') ORDER BY type,name",
         ["type", "name", "tbl_name"], [
             ["index", "items_payload", "renamed_items"],
             ["table", "audit", "audit"], ["table", "child", "child"],
             ["table", "renamed_items", "renamed_items"],
             ["trigger", "item_insert", "renamed_items"], ["view", "item_view", "item_view"],
         ]),
    ]


def unchanged(before, after, trace):
    require(before == after, "lookup, replay or refused SQL changed HEAD body/ETag")
    require(not any(row.get("event") == "object_request" and row.get("method") == "PUT"
                    for row in trace), "lookup, replay or refused SQL attempted a PUT")


class SchemaSuite:
    def __init__(self, support, arguments, evidence, private, compute, proxy, workers, config):
        self.support, self.arguments = support, arguments
        self.evidence, self.private, self.compute = evidence, private, compute
        self.proxy, self.workers, self.config = proxy, workers, config
        self.worker_number, self.query_number, self.ack_number = 20000, 0, 0
        self.started_worker_count = 0
        self.audited, self.replayed = set(), set()
        self.inputs = evidence / "schema-input-ledger.jsonl"
        self.acks = evidence / "schema-ack-ledger.jsonl"
        self.audits = evidence / "schema-audit.jsonl"
        for path in (self.inputs, self.acks, self.audits):
            path.touch(mode=0o600, exist_ok=False)
        self.summary = {"status": "running", "planned_modes": list(MODES), "case_results": [],
                        "ack_recorded_count": 0, "ack_audited_count": 0,
                        "ack_replayed_count": 0, "ack_mismatch_count": 0,
                        "aws_endpoint_gate": "NOT_RUN", "unit_coverage_contribution": False}

    def event(self, case, event, **values):
        entry = {"case": case["mode"], "scope": case["scope"], "event": event, **values}
        self.support.append_synced(self.audits, entry)
        self.support.record(self.evidence, event, case=case["mode"], **values)

    def spawn(self, case):
        self.worker_number += 1
        config = {**self.config, "scope": case["scope"], "worker": self.worker_number,
                  "cache_root": str(case["directory"]), "resource_log": None,
                  "fixture_limits": {"quota_bytes": 2 * 1024 * 1024, "retention_entries": 16,
                                     "retention_result_bytes": 128 * 1024 * 1024}}
        worker = self.support.Worker(self.arguments.worker.resolve(), config, self.private,
                                     self.worker_number, self.evidence)
        self.started_worker_count += 1
        self.workers.append(worker)
        case["workers"].append(worker)
        return worker

    def stop(self, case, worker, *, fault=False):
        result = worker.kill(verify=fault)
        case["workers"].remove(worker)
        self.workers.remove(worker)
        return result

    def phase(self, case, label):
        phase = "schema/" + case["mode"] + "/" + label
        self.proxy.set_phase(phase)
        return phase

    def trace(self, phase):
        with self.proxy.lock:
            return [dict(row) for row in self.proxy.observations if row.get("phase") == phase]

    def snapshot(self, case, worker):
        return self.support.success(worker.call("store_get", key=case["head_key"]))

    def prepare(self, case, worker, identity, statements):
        invocation = {"scope": case["scope"], "mode": case["mode"], "epoch": 1, "id": identity,
                      "principal": worker.config["principal"], "statements": statements}
        self.support.append_synced(self.inputs, {"event": "input_prepared", **invocation})
        request = self.support.success(worker.call("prepare_request", epoch=1, id=identity, statements=statements))
        require(all(request[key] == invocation[key] for key in ("epoch", "id", "principal")),
                "prepared request identity differs from invocation")
        invocation["request"] = request
        self.support.append_synced(self.inputs, {"event": "invocation_prepared", **invocation})
        return invocation

    def execute(self, case, worker, invocation):
        self.query_number += 1
        return worker.call(case["mode"], epoch=invocation["epoch"], id=invocation["id"],
                           statements=invocation["statements"], directory=f"schema-execute-{self.query_number}")

    def entries(self, case):
        return [row for row in (json.loads(line) for line in self.acks.read_text().splitlines())
                if row["invocation"]["scope"] == case["scope"]]

    def audit_requests(self, case, worker, label, *, replay=False, cold=False):
        phase = self.phase(case, label)
        before = self.snapshot(case, worker)
        for entry in self.entries(case):
            invocation = entry["invocation"]
            response = (self.execute(case, worker, invocation) if replay else
                        worker.call("lookup_identity", identity=invocation["request"]))
            matches = response["ok"] and original_matches(entry, response.get("value", {}), replay=replay)
            self.summary["ack_mismatch_count"] += not matches
            self.event(case, "schema_original_ack_audited", ordinal=entry["ordinal"], phase=label,
                       replay=replay, matches=matches, observed=response)
            require(matches, "schema receipt or original result changed")
            if cold:
                (self.replayed if replay else self.audited).add(entry["ordinal"])
        unchanged(before, self.snapshot(case, worker), self.trace(phase))
        self.event(case, "schema_original_ack_audit_complete", phase=label,
                   head_unchanged=True, object_puts=0, from_independent_synced_ledger=True)

    def audit_state(self, case, worker, label, *, session=False):
        for name, sql, columns, rows in expected_state(self.entries(case), case["payloads"]):
            self.query_number += 1
            observed = self.support.success(worker.call("session_query" if session else "query", sql=sql,
                                           directory=f"schema-query-{self.query_number}"))["statements"][0]
            matches = observed["columns"] == columns and observed["rows"] == rows
            self.event(case, "schema_state_audited", phase=label, component=name, matches=matches,
                       expected_columns=columns, expected_rows=rows, observed=observed)
            require(matches, "recovered schema or values differ from the client oracle")

    def reopen_after_refusal(self, case, worker):
        # The native writer deliberately stops after any SQL execution error.
        # The failed FK statement is never replayed; establish a fresh cache
        # from the unchanged authority before inspecting its committed state.
        phase = self.phase(case, "stopped_session_after_refusal")
        before = self.snapshot(case, worker)
        response = worker.call("session_query", sql="SELECT 1")
        require(response.get("ok") is False and response.get("error") == "StaleSnapshot",
                "failed native session must refuse further work")
        unchanged(before, self.snapshot(case, worker), self.trace(phase))
        self.event(case, "schema_failed_session_stopped", response=response,
                   head_unchanged=True, object_puts=0)
        phase = self.phase(case, "fresh_session_after_refusal")
        self.support.success(worker.call("session_open", directory="schema-after-refusal"))
        unchanged(before, self.snapshot(case, worker), self.trace(phase))
        self.event(case, "schema_failed_session_reopened", head_unchanged=True, object_puts=0,
                   failed_sql_replayed=False, source="fresh_authorized_head_and_data_root")

    def run_case(self, mode, number):
        directory = self.compute / ("schema-" + mode)
        directory.mkdir(mode=0o700)
        case = {"mode": mode, "scope": {"deployment": 80, "tenant": 88, "database": number,
                                        "incarnation": 1, "generation": 1},
                "directory": directory, "workers": [], "payloads": [secrets.token_hex(16), secrets.token_hex(16)]}
        self.phase(case, "setup")
        writer = self.spawn(case)
        created = self.support.success(writer.call("create", nonce=1))
        self.support.success(writer.call("activate_session" if mode == "session_execute" else "activate",
                             revision=created["revision"], nonce=2, directory="schema-warm"))
        case["head_key"] = self.support.success(writer.call("authority_keys"))["head"]
        for identity, statements in enumerate(plan(*case["payloads"]), 1):
            self.phase(case, "write-" + str(identity))
            invocation = self.prepare(case, writer, identity, statements)
            value = self.support.success(self.execute(case, writer, invocation))
            require(value["receipt"]["scope"] == case["scope"] and value["receipt"]["request"] == invocation["request"],
                    "schema ACK scope/request differs from invocation")
            self.ack_number += 1
            self.support.append_synced(self.acks, {"ordinal": self.ack_number, "invocation": invocation,
                                       "receipt": value["receipt"], "encoded_result": value["result"]["encoded"],
                                       "observed_statements": value["result"]["statements"]})
            self.event(case, "schema_client_ack_recorded", ordinal=self.ack_number, request=invocation["request"],
                       result_sha256=hashlib.sha256(bytes(value["result"]["encoded"])).hexdigest())
        observer = self.spawn(case)
        self.audit_requests(case, observer, "before_loss")
        self.audit_state(case, writer, "before_loss", session=mode == "session_execute")
        killed = [self.stop(case, worker, fault=True) for worker in list(case["workers"])]
        shutil.rmtree(directory)
        require(not directory.exists(), "entire schema cache was not deleted")
        self.event(case, "schema_all_compute_lost", processes=killed, signal="SIGKILL",
                   complete_cache_directory_deleted=True)
        directory.mkdir(mode=0o700)
        recovered = self.spawn(case)
        self.phase(case, "fresh_activation")
        head = self.support.success(recovered.call("status"))
        taken = self.support.success(recovered.call("takeover", revision=head["revision"], nonce=10))
        self.support.success(recovered.call("activate_session", revision=taken["revision"], nonce=11,
                                            directory="schema-cold"))
        self.audit_requests(case, recovered, "after_loss", cold=True)
        self.audit_requests(case, recovered, "replay_after_loss", replay=True, cold=True)
        self.audit_state(case, recovered, "after_loss", session=True)
        # The FK must still point to the renamed table after S3 recovery. An
        # absent table or generic SQL error cannot satisfy this negative probe.
        invocation = self.prepare(case, recovered, 7, [{"sql": "INSERT INTO child VALUES(999)"}])
        phase = self.phase(case, "foreign_key_refusal")
        before = self.snapshot(case, recovered)
        refused = self.execute(case, recovered, invocation)
        error = refused.get("error", "")
        require(refused["ok"] is False and "ConstraintViolation" in error and "FOREIGN KEY constraint failed" in error,
                "expected the actual FK constraint after schema recovery")
        unknown = self.support.success(recovered.call("lookup_identity", identity=invocation["request"]))
        require(unknown == {"state": "unknown"}, "refused FK request gained an outcome")
        unchanged(before, self.snapshot(case, recovered), self.trace(phase))
        self.event(case, "schema_foreign_key_refused", response=refused, head_unchanged=True, object_puts=0,
                   request_unknown=True)
        if mode == "session_execute":
            self.reopen_after_refusal(case, recovered)
        self.audit_state(case, recovered, "after_refusal", session=True)
        self.summary["case_results"].append({"mode": mode, "status": "passed", "scope": case["scope"],
                                            "ack_count": len(self.entries(case)), "all_compute_lost": True,
                                            "original_result_replayed_without_put": True, "foreign_key_preserved": True,
                                            "session_reopened_after_refusal": mode == "session_execute",
                                            "refused_sql_replayed": False})
        self.stop(case, recovered)

    def run(self):
        require(not sys.flags.optimize, "schema fixture assertions must be enabled")
        previous = self.proxy.capture
        self.proxy.capture = True
        try:
            for number, mode in enumerate(MODES, 1):
                self.run_case(mode, number)
            entries = [json.loads(line) for line in self.acks.read_text().splitlines()]
            require([row["ordinal"] for row in entries] == list(range(1, 13)), "expected twelve independently recorded ACKs")
            require(self.audited == self.replayed == set(range(1, 13)), "cold ACK/replay audit is incomplete")
            require(not self.proxy.errors, "schema transport errors make the observation inconclusive")
            self.summary["status"] = "passed"
        except BaseException as error:
            self.summary.update(status="failed", error=repr(error))
            raise
        finally:
            self.proxy.capture = previous
            self.summary.update(ack_recorded_count=self.ack_number, ack_audited_count=len(self.audited),
                                ack_replayed_count=len(self.replayed))
            self.summary["ledger_sha256"] = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                                              for path in (self.inputs, self.acks, self.audits)}
        return self.summary


def finish_json(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", type=Path, required=True)
    parser.add_argument("--weed", type=Path, required=True)
    parser.add_argument("--build-record", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    arguments = parser.parse_args(argv)
    evidence = arguments.evidence.resolve()
    evidence.mkdir(parents=True, mode=0o700, exist_ok=False)
    summary = {"status": "blocked", "scope": "private-loopback-real-S3-and-Rust-worker",
               "planned_modes": list(MODES), "production_slo_passed": False,
               "aws_endpoint_gate": "NOT_RUN", "unit_coverage_contribution": False,
               "real_worker_started": False, "build_record_verified": False}
    backend = proxy = suite = None
    workers, cleanup = [], []
    try:
        require(not sys.flags.optimize, "fixture assertions must be enabled")
        require("LLVM_PROFILE_FILE" not in os.environ, "integration cannot contribute unit coverage")
        for name in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"):
            require("instrument-coverage" not in os.environ.get(name, ""), "integration cannot inherit instrumentation")
        for path in (arguments.worker, arguments.weed, arguments.build_record):
            require(path.is_file(), "missing prerequisite: " + str(path))
        import build
        import run as support
        compiled = build.verify(arguments.build_record, arguments.worker)
        summary.update(worker_sha256=compiled["binary"]["sha256"], build_inputs_sha256=compiled["input_sha256"],
                       source_commit=compiled["source_commit"],
                       harness_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
        shutil.copyfile(arguments.build_record, evidence / "build-receipt.json")
        private = Path(tempfile.mkdtemp(prefix="scap-schema-private-"))
        compute = private / "compute"
        compute.mkdir(mode=0o700)
        backend = support.Backend(arguments.weed.resolve(), private / "backend")
        proxy = support.Proxy(backend.port, evidence)
        config = {"endpoint": proxy.endpoint, "region": "us-east-1", "bucket": "scap-test",
                  "access_key": backend.access, "secret_key": backend.secret, "principal": 17}
        suite = SchemaSuite(support, arguments, evidence, private, compute, proxy, workers, config)
        suite.summary.update(summary)
        summary = suite.summary
        backend.start()
        summary["status"] = "running"
        suite.run()
        build.verify(arguments.build_record, arguments.worker)
        summary.update(status="passed", build_record_verified=True)
    except BaseException as error:
        summary.update(status="blocked" if summary["status"] == "blocked" else "failed",
                       error_type=type(error).__name__, error=str(error))
    finally:
        if proxy is not None:
            try:
                proxy.clear()
            except BaseException as error:
                cleanup.append({"phase": "release_proxy", "error_type": type(error).__name__})
        for worker in list(workers):
            try:
                worker.kill()
            except BaseException as error:
                cleanup.append({"phase": "stop_worker", "error_type": type(error).__name__})
        for phase, item, method in (("close_proxy", proxy, "close"), ("stop_backend", backend, "stop")):
            if item is not None:
                try:
                    getattr(item, method)()
                except BaseException as error:
                    cleanup.append({"phase": phase, "error_type": type(error).__name__})
        if proxy is not None:
            summary["object_metrics"] = proxy.metrics()
            summary["proxy_errors"] = proxy.errors
            if proxy.errors:
                cleanup.append({"phase": "proxy_errors", "count": len(proxy.errors)})
        if suite is not None:
            summary["real_worker_started"] = suite.started_worker_count > 0
        summary["cleanup_errors"] = cleanup
        if cleanup:
            summary["status"] = "failed"
        summary["artifacts"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                for p in sorted(evidence.iterdir()) if p.is_file()}
        finish_json(evidence / "summary.json", summary)
    print(json.dumps({"status": summary["status"], "evidence": str(evidence)}))
    return 0 if summary["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
